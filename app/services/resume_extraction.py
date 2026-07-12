"""RSK-002 — Résumé text-extraction service (PDF/DOCX → plain text).

Dependency-free / stdlib-only. Supports:
- DOCX: zipfile + regex on <w:t> elements
- PDF: minimal content-stream parser (Tj/TJ operators, optional FlateDecode)
- Plain text: UTF-8 passthrough

All DDB writes go through T.candidates. No dev_mode branch (SECOPS-007 parity).
"""
from __future__ import annotations

import io
import logging
import re
import zlib
import zipfile
from typing import Optional

from app.core.aws_clients import s3_client as _s3_factory
from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Module-level S3 singleton (same pattern as filemanager.py:58)
_s3 = _s3_factory()


# ─────────────────────────────────────────────────────────────────────────────
# Format detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_format(data: bytes) -> str:
    """Return 'pdf', 'docx', or 'text' based on magic bytes."""
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:4] == b"PK\x03\x04":
        # Check for DOCX by presence of word/ member
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    if name.startswith("word/"):
                        return "docx"
        except Exception:
            pass
        return "text"  # valid ZIP but not DOCX
    return "text"


# ─────────────────────────────────────────────────────────────────────────────
# DOCX extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_docx_text(data: bytes) -> str:
    """Extract plain text from a DOCX file using zipfile + regex."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        xml_bytes = zf.read("word/document.xml")

    xml = xml_bytes.decode("utf-8", errors="replace")
    # Paragraph breaks
    xml = xml.replace("</w:p>", "\n")
    # Extract run text
    runs = re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL)
    text = " ".join(runs)
    # Normalize whitespace
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# ─────────────────────────────────────────────────────────────────────────────
# PDF extraction
# ─────────────────────────────────────────────────────────────────────────────

def _unescape_pdf_string(s: str) -> str:
    """Unescape PDF string escape sequences."""
    s = s.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
    return s


def _extract_pdf_text(data: bytes) -> str:
    """Minimal PDF content-stream parser supporting Tj, TJ, and FlateDecode.

    Uses regex to find stream...endstream blocks to avoid the split-on-"stream"
    problem (the word "endstream" itself contains "stream").
    """
    collected: list[str] = []

    # Find all stream blocks using regex (handles "endstream" correctly)
    # Pattern: find "stream\n" ... "\nendstream" boundaries
    stream_pattern = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
    # Also find the stream dict that precedes each stream block
    block_pattern = re.compile(
        rb"(<<[^>]*?>>)\s*\r?\nstream\r?\n(.*?)\r?\nendstream", re.DOTALL
    )

    for m in block_pattern.finditer(data):
        stream_dict_bytes = m.group(1)
        stream_bytes = m.group(2)

        # Check for FlateDecode in stream dict
        if b"/FlateDecode" in stream_dict_bytes or b"/Fl " in stream_dict_bytes:
            try:
                stream_bytes = zlib.decompress(stream_bytes)
                if len(stream_bytes) > S.ats_resume_extract_max_bytes:
                    continue  # Decompression bomb guard
            except zlib.error:
                continue

        try:
            stream_text = stream_bytes.decode("latin-1", errors="replace")
        except Exception:
            continue

        # Extract Tj strings: (text) Tj
        tj_matches = re.findall(
            r"\(([^)\\]*(?:\\.[^)\\]*)*)\)\s+Tj", stream_text, re.DOTALL
        )
        for mt in tj_matches:
            collected.append(_unescape_pdf_string(mt))

        # Extract TJ array strings: [(text) ...] TJ
        tj_arrays = re.findall(r"\[([^\]]*)\]\s+TJ", stream_text)
        for arr in tj_arrays:
            arr_strs = re.findall(
                r"\(([^)\\]*(?:\\.[^)\\]*)*)\)", arr, re.DOTALL
            )
            for s in arr_strs:
                collected.append(_unescape_pdf_string(s))

    # Fallback: if block_pattern didn't match (stream dict on same line), try
    # simpler stream extraction with a raw stream search
    if not collected:
        for m in stream_pattern.finditer(data):
            stream_bytes = m.group(1)
            try:
                stream_text = stream_bytes.decode("latin-1", errors="replace")
            except Exception:
                continue
            tj_matches = re.findall(
                r"\(([^)\\]*(?:\\.[^)\\]*)*)\)\s+Tj", stream_text, re.DOTALL
            )
            for mt in tj_matches:
                collected.append(_unescape_pdf_string(mt))

    text = " ".join(collected)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Normalization + truncation
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_extracted_text(text: str, max_chars: int) -> str:
    """Collapse whitespace and truncate."""
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()
    return text[:max_chars]


# ─────────────────────────────────────────────────────────────────────────────
# Primary entry point
# ─────────────────────────────────────────────────────────────────────────────

def extract_resume_text(
    candidate_id: str,
    attachment_id: str,
    *,
    s3_key: Optional[str] = None,
    s3_bucket: Optional[str] = None,
    raw_bytes: Optional[bytes] = None,
    actor_sub: str,
) -> dict:
    """Extract plain text from a résumé attachment.

    Returns {"extraction_status": str, "char_count": int}.
    Never raises — all exceptions are caught and stored as extraction_status="error".
    """
    from app.core.tables import T
    from app.services.alerts import audit_event

    # Flag guard
    if not S.candidates_enabled:
        return {"extraction_status": "disabled", "char_count": 0}

    status = "error"
    text = ""
    byte_len = 0

    try:
        # 1. Obtain bytes
        bytes_: Optional[bytes] = None
        if raw_bytes is not None:
            bytes_ = raw_bytes
        elif s3_key and s3_bucket:
            bytes_ = _s3.get_object(Bucket=s3_bucket, Key=s3_key)["Body"].read()
        else:
            # Neither provided — misconfigured call site
            _write_result(T, candidate_id, attachment_id, "", "error", 0, 0)
            audit_event(
                "ats.resume.extracted",
                actor_sub,
                candidate_id=candidate_id,
                attachment_id=attachment_id,
                status="error",
                chars=0,
            )
            return {"extraction_status": "error", "char_count": 0}

        byte_len = len(bytes_)

        # 2. Size guard
        if byte_len > S.ats_resume_extract_max_bytes:
            _write_result(T, candidate_id, attachment_id, "", "unsupported", now_ts(), byte_len)
            audit_event(
                "ats.resume.extracted", actor_sub,
                candidate_id=candidate_id, attachment_id=attachment_id,
                status="unsupported", chars=0,
            )
            return {"extraction_status": "unsupported", "char_count": 0}

        # 3. Detect format and extract
        fmt = _detect_format(bytes_)
        raw_text = ""
        if fmt == "pdf":
            raw_text = _extract_pdf_text(bytes_)
        elif fmt == "docx":
            try:
                raw_text = _extract_docx_text(bytes_)
            except Exception:
                status = "error"
                raw_text = ""
        else:
            raw_text = bytes_.decode("utf-8", errors="replace")

        # 4. Normalize and truncate
        stored_text = _normalize_extracted_text(raw_text, S.ats_resume_extract_max_chars)
        char_count = len(stored_text)
        status = "ok" if stored_text else "unsupported"

        # 5. Write to DDB
        ts = now_ts()
        _write_result(T, candidate_id, attachment_id, stored_text, status, ts, byte_len)

        # 6. Call RSK-003 index writer (best-effort)
        if status == "ok":
            try:
                # Fetch candidate META for name + owner_sub
                meta_resp = T.candidates.get_item(  # type: ignore[attr-defined]
                    Key={"pk": f"CANDIDATE#{candidate_id}", "sk": "META"}
                )
                meta = meta_resp.get("Item", {})
                candidate_name = (
                    f"{meta.get('first_name', '')} {meta.get('last_name', '')}".strip()
                    or meta.get("name", "")
                )
                owner_sub = meta.get("owner_sub", actor_sub)
                from app.services.resume_search import _write_resume_index
                _write_resume_index(candidate_id, candidate_name, owner_sub, stored_text)
            except Exception:
                logger.debug("resume index write failed; continuing", exc_info=True)

        audit_event(
            "ats.resume.extracted", actor_sub,
            candidate_id=candidate_id, attachment_id=attachment_id,
            status=status, chars=char_count,
        )
        return {"extraction_status": status, "char_count": char_count}

    except Exception:
        logger.debug("resume extraction error", exc_info=True)
        try:
            from app.core.tables import T
            _write_result(T, candidate_id, attachment_id, "", "error", now_ts(), byte_len)
        except Exception:
            pass
        try:
            audit_event(
                "ats.resume.extracted", actor_sub,
                candidate_id=candidate_id, attachment_id=attachment_id,
                status="error", chars=0,
            )
        except Exception:
            pass
        return {"extraction_status": "error", "char_count": 0}


def _write_result(
    T: object,
    candidate_id: str,
    attachment_id: str,
    text: str,
    status: str,
    ts: int,
    byte_len: int,
) -> None:
    """Write extraction result attributes to the attachment sub-item."""
    getattr(T, "candidates").update_item(  # type: ignore[call-overload]
        Key={
            "pk": f"CANDIDATE#{candidate_id}",
            "sk": f"ATTACHMENT#{attachment_id}",
        },
        UpdateExpression=(
            "SET extracted_text = :txt, extraction_status = :st, "
            "extracted_at = :ts, extracted_bytes = :b"
        ),
        ExpressionAttributeValues={
            ":txt": text,
            ":st": status,
            ":ts": ts,
            ":b": byte_len,
        },
    )
