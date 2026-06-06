"""Audit export pipeline: create jobs, process exports, generate files (ENTERPRISE-004)."""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.audit_adapters import ADAPTERS, VALID_CATEGORIES
from app.services.audit_export import UnifiedAuditEvent

logger = logging.getLogger(__name__)

CSV_COLUMNS = [
    "event_id", "event_type", "event_action", "timestamp", "timestamp_unix",
    "actor_user_id", "actor_role", "actor_ip", "actor_user_agent",
    "target_user_id", "target_resource_type", "target_resource_id",
    "outcome", "metadata", "source_table",
]


def _gen_export_id() -> str:
    return f"exp_{uuid.uuid4().hex}"


# ----- PDF rendering (GAP-0209) ---------------------------------------------
#
# FIN-016 requires an audit-grade PDF: cover page with export metadata + content
# SHA-256, sequential row numbers across pages (to detect row removal), per-page
# subtotals for billing-category amounts, and a tamper-evident running SHA-256 in
# each page footer.  We render this with a self-contained, pure-Python PDF writer
# (the same dependency-free approach already used by ``app/services/receipts.py``)
# rather than pulling in ``reportlab``.  This keeps dev and prod on the identical
# code path with no new system/package dependency (SECOPS-007 parity).

_PDF_ROWS_PER_PAGE = 28  # data rows per page (excluding the cover page)


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_clean(text: Any, max_len: int) -> str:
    """Coerce to printable ASCII (WinAnsi-safe) and truncate."""
    s = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(text))
    if len(s) > max_len:
        s = s[: max_len - 1] + "~"
    return s


def _build_pdf(pages: list[list[str]]) -> bytes:
    """Assemble a multi-page PDF from a list of pages, each a list of text lines.

    Each line is rendered with a monospaced font at 8pt so the column layout in
    the audit table stays aligned.  Pure-Python — no external dependencies.
    """
    catalog_obj = 1
    pages_obj = 2
    font_obj = 3
    # Page objects start at 4, with each page using two objects (page + content).
    first_page_obj = 4

    objects: dict[int, bytes] = {}
    page_obj_ids: list[int] = []

    next_id = first_page_obj
    for page_lines in pages:
        page_id = next_id
        content_id = next_id + 1
        next_id += 2
        page_obj_ids.append(page_id)

        content_lines = ["BT", "/F1 8 Tf", "12 TL", "36 756 Td"]
        for line in page_lines:
            content_lines.append(f"({_pdf_escape(line)}) Tj")
            content_lines.append("T*")
        content_lines.append("ET")
        stream = "\n".join(content_lines).encode("latin-1", "replace")

        objects[page_id] = (
            f"{page_id} 0 obj\n"
            f"<< /Type /Page /Parent {pages_obj} 0 R /MediaBox [0 0 612 792] "
            f"/Contents {content_id} 0 R /Resources << /Font << /F1 {font_obj} 0 R >> >> >>\n"
            f"endobj\n"
        ).encode("latin-1")
        objects[content_id] = (
            f"{content_id} 0 obj\n<< /Length {len(stream)} >>\nstream\n".encode("latin-1")
            + stream
            + b"\nendstream\nendobj\n"
        )

    kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects[catalog_obj] = (
        f"{catalog_obj} 0 obj\n<< /Type /Catalog /Pages {pages_obj} 0 R >>\nendobj\n"
    ).encode("latin-1")
    objects[pages_obj] = (
        f"{pages_obj} 0 obj\n<< /Type /Pages /Count {len(page_obj_ids)} "
        f"/Kids [{kids}] >>\nendobj\n"
    ).encode("latin-1")
    objects[font_obj] = (
        f"{font_obj} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"
    ).encode("latin-1")

    max_id = next_id - 1
    pdf = bytearray(b"%PDF-1.4\n")
    offsets: dict[int, int] = {}
    for obj_id in range(1, max_id + 1):
        body = objects.get(obj_id)
        if body is None:
            continue
        offsets[obj_id] = len(pdf)
        pdf.extend(body)

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {max_id + 1}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for obj_id in range(1, max_id + 1):
        off = offsets.get(obj_id)
        if off is None:
            pdf.extend(b"0000000000 00000 f \n")
        else:
            pdf.extend(f"{off:010d} 00000 n \n".encode("latin-1"))
    pdf.extend(
        f"trailer\n<< /Size {max_id + 1} /Root {catalog_obj} 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("latin-1")
    )
    return bytes(pdf)


def _render_audit_pdf(
    events: list[UnifiedAuditEvent],
    export_id: str,
    job: dict,
    file_hash: str,
) -> bytes:
    """Render audit events to a tamper-evident, audit-grade PDF (FIN-016).

    Layout:
      - Cover page: export metadata + content SHA-256.
      - Data pages: sequential row numbers, timestamp, actor, action, outcome.
      - Per-page footer: cumulative SHA-256 of all rows up to that page and, for
        billing exports, the running amount_cents subtotal.
    """
    from_ts = int(job.get("from_date", 0))
    to_ts = int(job.get("to_date", 0))
    categories = list(job.get("categories", []))

    pages: list[list[str]] = []

    # --- Cover page ---
    cover = [
        "FINANCIAL AUDIT EXPORT",
        "=" * 72,
        "",
        f"Export ID        : {export_id}",
        f"Created by        : {_pdf_clean(job.get('created_by', ''), 60)}",
        f"Generated at      : {datetime.fromtimestamp(now_ts(), tz=timezone.utc).isoformat()}",
        f"Date range (from) : {datetime.fromtimestamp(from_ts, tz=timezone.utc).isoformat()}",
        f"Date range (to)   : {datetime.fromtimestamp(to_ts, tz=timezone.utc).isoformat()}",
        f"Categories        : {_pdf_clean(', '.join(categories), 60)}",
        f"Total events      : {len(events)}",
        f"Content SHA-256   : {file_hash}",
        "",
        "This document is a sealed audit record. Rows are numbered",
        "sequentially; each page footer carries the cumulative SHA-256 of",
        "all rows up to that page. Any removed or altered row changes the",
        "footer hash and the content SHA-256 above.",
    ]
    pages.append(cover)

    # --- Data pages ---
    header = f"{'#':>5}  {'TIMESTAMP (UTC)':<20}  {'ACTOR':<22}  {'ACTION':<20}  {'OUTCOME':<8}"
    running_hash = hashlib.sha256()
    amount_total = 0
    has_amounts = False

    chunk: list[str] = []
    page_amount = 0

    def _flush_page() -> None:
        nonlocal chunk, page_amount
        if not chunk:
            return
        body = [header, "-" * len(header)] + chunk + [""]
        footer = f"Cumulative row SHA-256: {running_hash.hexdigest()}"
        body.append(footer)
        if has_amounts:
            body.append(
                f"Page subtotal: {page_amount} cents | "
                f"Running total: {amount_total} cents"
            )
        pages.append(body)
        chunk = []
        page_amount = 0

    for row_num, ev in enumerate(events, start=1):
        meta = ev.metadata or {}
        amount_cents = meta.get("amount_cents", 0)
        if isinstance(amount_cents, (int, float)):
            ac = int(amount_cents)
            if ac:
                has_amounts = True
            amount_total += ac
            page_amount += ac
        ts_str = datetime.fromtimestamp(
            int(ev.timestamp_unix), tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = (
            f"{row_num:>5}  "
            f"{_pdf_clean(ts_str, 20):<20}  "
            f"{_pdf_clean(ev.actor_user_id or '', 22):<22}  "
            f"{_pdf_clean(ev.event_action or '', 20):<20}  "
            f"{_pdf_clean(ev.outcome or '', 8):<8}"
        )
        chunk.append(line)
        # Hash the canonical row representation for the tamper-evident footer.
        running_hash.update(
            json.dumps(
                [row_num, ts_str, ev.actor_user_id, ev.event_action, ev.outcome],
                default=str,
            ).encode("utf-8")
        )
        if len(chunk) >= _PDF_ROWS_PER_PAGE:
            _flush_page()

    _flush_page()

    if len(pages) == 1:  # no data rows — still emit an empty data page
        pages.append([header, "-" * len(header), "", "(no events in range)"])

    return _build_pdf(pages)


def _merge_sorted_events(
    categories: list[str],
    from_ts: int,
    to_ts: int,
    actor: Optional[str] = None,
    target: Optional[str] = None,
    event_actions: Optional[list[str]] = None,
    limit: int = 10_000_000,
) -> Iterator[UnifiedAuditEvent]:
    """Query all adapters and yield events sorted by timestamp ascending."""
    import heapq

    heap: list[tuple[int, int, UnifiedAuditEvent]] = []
    counter = 0

    for category in categories:
        adapter = ADAPTERS.get(category)
        if not adapter:
            continue
        try:
            for event in adapter.query(
                from_ts=from_ts,
                to_ts=to_ts,
                actor=actor,
                target=target,
                event_actions=event_actions,
                limit=limit,
            ):
                heapq.heappush(heap, (event.timestamp_unix, counter, event))
                counter += 1
        except Exception:
            logger.exception("Adapter %s query failed", category)

    yielded = 0
    while heap and yielded < limit:
        _, _, event = heapq.heappop(heap)
        yield event
        yielded += 1


def create_export_job(
    categories: list[str],
    format: str,
    from_ts: int,
    to_ts: int,
    created_by: str,
    actor_user_id: Optional[str] = None,
    target_user_id: Optional[str] = None,
    event_actions: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create an export job record in DynamoDB and immediately process it (dev mode)."""
    export_id = _gen_export_id()
    now = now_ts()

    item: dict[str, Any] = {
        "export_id": export_id,
        "sk": "META",
        "status": "pending",
        "categories": categories,
        "format": format,
        "from_date": from_ts,
        "to_date": to_ts,
        "created_by": created_by,
        "created_at": now,
        "actor_filter": actor_user_id or "",
        "target_filter": target_user_id or "",
        "event_actions_filter": event_actions or [],
        "event_count": 0,
        "file_size_bytes": 0,
        "events_scanned": 0,
        "events_written": 0,
        "attempt_count": 0,
        "max_attempts": 3,
    }
    T.audit_exports.put_item(Item=item)

    # In dev mode, process the export synchronously and store content inline
    if S.dev_mode:
        _process_export_inline(export_id, item)
        # Re-read the item after processing
        resp = T.audit_exports.get_item(Key={"export_id": export_id, "sk": "META"})
        return resp.get("Item", item)

    return item


def _process_export_inline(export_id: str, job: dict) -> None:
    """Process an export job inline (dev mode): store content as DDB attribute.

    NOTE: DynamoDB has a 400KB item size limit. We cap inline exports at
    _DEV_INLINE_MAX_EVENTS events to stay under this limit.  In production
    the content would be written to S3, not stored in the DDB item.
    """
    _DEV_INLINE_MAX_EVENTS = 500
    # PDF output is far larger per event than CSV/NDJSON; cap tighter so the
    # base64-encoded inline copy stays under the 400KB DynamoDB item limit.
    _DEV_INLINE_MAX_PDF_EVENTS = 200

    try:
        categories = list(job.get("categories", []))
        fmt = job.get("format", "ndjson")
        from_ts = int(job.get("from_date", 0))
        to_ts = int(job.get("to_date", 0))
        actor = job.get("actor_filter") or None
        target = job.get("target_filter") or None
        event_actions = job.get("event_actions_filter") or None
        if isinstance(event_actions, list) and len(event_actions) == 0:
            event_actions = None

        event_count = 0
        sha256 = hashlib.sha256()
        content_parts: list[str] = []
        pdf_bytes: Optional[bytes] = None

        if fmt == "pdf":
            events_list = list(_merge_sorted_events(
                categories, from_ts, to_ts, actor, target, event_actions,
                limit=_DEV_INLINE_MAX_PDF_EVENTS,
            ))
            event_count = len(events_list)
            # Content hash is computed over the canonical NDJSON representation
            # so a PDF and an NDJSON export of the same events share the same
            # file_sha256 and the hash is reproducible/verifiable.
            for event in events_list:
                sha256.update((event.to_ndjson_line() + "\n").encode("utf-8"))
            file_hash = sha256.hexdigest()
            pdf_bytes = _render_audit_pdf(events_list, export_id, job, file_hash)
            file_size = len(pdf_bytes)
        elif fmt == "csv":
            bom = "﻿"
            content_parts.append(bom)
            sha256.update(bom.encode("utf-8"))
            header_buf = io.StringIO()
            csv.writer(header_buf).writerow(CSV_COLUMNS)
            header_line = header_buf.getvalue()
            content_parts.append(header_line)
            sha256.update(header_line.encode("utf-8"))

            for event in _merge_sorted_events(
                categories, from_ts, to_ts, actor, target, event_actions,
                limit=_DEV_INLINE_MAX_EVENTS,
            ):
                row_buf = io.StringIO()
                csv.writer(row_buf).writerow(event.to_csv_row(CSV_COLUMNS))
                line = row_buf.getvalue()
                content_parts.append(line)
                sha256.update(line.encode("utf-8"))
                event_count += 1
            content = "".join(content_parts)
            file_size = len(content.encode("utf-8"))
            file_hash = sha256.hexdigest()
        else:
            for event in _merge_sorted_events(
                categories, from_ts, to_ts, actor, target, event_actions,
                limit=_DEV_INLINE_MAX_EVENTS,
            ):
                line = event.to_ndjson_line() + "\n"
                content_parts.append(line)
                sha256.update(line.encode("utf-8"))
                event_count += 1
            content = "".join(content_parts)
            file_size = len(content.encode("utf-8"))
            file_hash = sha256.hexdigest()

        # Build manifest
        manifest = {
            "export_id": export_id,
            "schema_version": "1.0",
            "format": fmt,
            "event_count": event_count,
            "date_range": {
                "from": datetime.fromtimestamp(from_ts, tz=timezone.utc).isoformat(),
                "to": datetime.fromtimestamp(to_ts, tz=timezone.utc).isoformat(),
            },
            "categories": categories,
            "filters": {
                "actor_user_id": actor,
                "target_user_id": target,
                "event_actions": event_actions,
            },
            "file_sha256": file_hash,
            "file_size_bytes": file_size,
            "created_at": datetime.fromtimestamp(now_ts(), tz=timezone.utc).isoformat(),
            "created_by": job.get("created_by", ""),
            "signing_key_id": S.audit_export_signing_key_id,
            "contains_pii": True,
        }
        manifest["signature"] = _compute_manifest_signature(manifest)

        # PDF is binary → store base64 under a distinct attribute and serve it via
        # a binary-safe Response in the download endpoint. CSV/NDJSON stay textual.
        if fmt == "pdf":
            content_attr = "export_content_b64"
            content_value = base64.b64encode(pdf_bytes or b"").decode("ascii")
        else:
            content_attr = "export_content"
            content_value = content

        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression=(
                "SET #st = :st, completed_at = :ca, event_count = :ec, "
                "file_size_bytes = :fs, manifest_sha256 = :ms, events_written = :ew, "
                f"{content_attr} = :content, export_manifest = :manifest"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "completed",
                ":ca": now_ts(),
                ":ec": event_count,
                ":fs": file_size,
                ":ms": file_hash,
                ":ew": event_count,
                ":content": content_value,
                ":manifest": json.dumps(manifest),
            },
        )
    except Exception as exc:
        logger.exception("Inline export job %s failed", export_id)
        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression="SET #st = :st, error_message = :em",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "failed",
                ":em": str(exc)[:500],
            },
        )


def _process_export_s3(export_id: str, job: dict) -> None:
    """Process an export job for production: generate content and upload to S3.

    GAP-0179: the previous pipeline had no production storage path. This streams
    the generated export into an in-memory buffer, uploads it to S3 (real S3 in
    prod, moto in-process in dev with DEV_MODE=0), writes an HMAC-signed manifest,
    and marks the job ``completed`` with the S3 location recorded on the DDB item.
    """
    from app.core.aws_clients import s3_client

    try:
        categories = list(job.get("categories", []))
        fmt = job.get("format", "ndjson")
        from_ts = int(job.get("from_date", 0))
        to_ts = int(job.get("to_date", 0))
        actor = job.get("actor_filter") or None
        target = job.get("target_filter") or None
        event_actions = job.get("event_actions_filter") or None
        if isinstance(event_actions, list) and len(event_actions) == 0:
            event_actions = None

        # Stream content into an in-memory buffer to avoid materialising the
        # entire export as a Python string before upload.
        buf = io.BytesIO()
        event_count = 0
        sha256 = hashlib.sha256()

        if fmt == "pdf":
            # Collect events, hash the canonical NDJSON form (reproducible
            # content hash, identical to an NDJSON export of the same events),
            # then render the audit-grade PDF into the buffer.
            events_list = list(_merge_sorted_events(
                categories, from_ts, to_ts, actor, target, event_actions,
            ))
            event_count = len(events_list)
            for event in events_list:
                sha256.update((event.to_ndjson_line() + "\n").encode("utf-8"))
            file_hash = sha256.hexdigest()
            buf.write(_render_audit_pdf(events_list, export_id, job, file_hash))
        elif fmt == "csv":
            bom = "﻿".encode("utf-8")
            buf.write(bom)
            sha256.update(bom)
            header_buf = io.StringIO()
            csv.writer(header_buf).writerow(CSV_COLUMNS)
            header_bytes = header_buf.getvalue().encode("utf-8")
            buf.write(header_bytes)
            sha256.update(header_bytes)
            for event in _merge_sorted_events(
                categories, from_ts, to_ts, actor, target, event_actions,
            ):
                row_buf = io.StringIO()
                csv.writer(row_buf).writerow(event.to_csv_row(CSV_COLUMNS))
                line_bytes = row_buf.getvalue().encode("utf-8")
                buf.write(line_bytes)
                sha256.update(line_bytes)
                event_count += 1
            file_hash = sha256.hexdigest()
        else:
            for event in _merge_sorted_events(
                categories, from_ts, to_ts, actor, target, event_actions,
            ):
                line_bytes = (event.to_ndjson_line() + "\n").encode("utf-8")
                buf.write(line_bytes)
                sha256.update(line_bytes)
                event_count += 1
            file_hash = sha256.hexdigest()

        file_size = buf.tell()
        _EXT = {"csv": "csv", "pdf": "pdf"}
        _CT = {"csv": "text/csv", "pdf": "application/pdf"}
        file_extension = _EXT.get(fmt, "ndjson")
        content_type = _CT.get(fmt, "application/x-ndjson")
        s3_key = f"audit-exports/{export_id}/{export_id}.{file_extension}"

        buf.seek(0)
        s3 = s3_client()
        s3.upload_fileobj(
            buf,
            S.audit_export_s3_bucket,
            s3_key,
            ExtraArgs={
                "ContentType": content_type,
                "ServerSideEncryption": "AES256",
            },
        )

        manifest = {
            "export_id": export_id,
            "schema_version": "1.0",
            "format": fmt,
            "event_count": event_count,
            "date_range": {
                "from": datetime.fromtimestamp(from_ts, tz=timezone.utc).isoformat(),
                "to": datetime.fromtimestamp(to_ts, tz=timezone.utc).isoformat(),
            },
            "categories": categories,
            "filters": {
                "actor_user_id": actor,
                "target_user_id": target,
                "event_actions": event_actions,
            },
            "s3_bucket": S.audit_export_s3_bucket,
            "s3_key": s3_key,
            "file_sha256": file_hash,
            "file_size_bytes": file_size,
            "created_at": datetime.fromtimestamp(now_ts(), tz=timezone.utc).isoformat(),
            "created_by": job.get("created_by", ""),
            "signing_key_id": S.audit_export_signing_key_id,
            "contains_pii": True,
        }
        manifest["signature"] = _compute_manifest_signature(manifest)

        logger.info(
            "audit export %s uploaded to s3://%s/%s (%d events, %d bytes)",
            export_id, S.audit_export_s3_bucket, s3_key, event_count, file_size,
        )

        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression=(
                "SET #st = :st, completed_at = :ca, event_count = :ec, "
                "file_size_bytes = :fs, manifest_sha256 = :ms, events_written = :ew, "
                "s3_key = :s3k, s3_bucket = :s3b, export_manifest = :manifest"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "completed",
                ":ca": now_ts(),
                ":ec": event_count,
                ":fs": file_size,
                ":ms": file_hash,
                ":ew": event_count,
                ":s3k": s3_key,
                ":s3b": S.audit_export_s3_bucket,
                ":manifest": json.dumps(manifest),
            },
        )
    except Exception as exc:
        logger.exception("S3 export job %s failed", export_id)
        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression="SET #st = :st, error_message = :em",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "failed",
                ":em": str(exc)[:500],
            },
        )


def process_export_job(export_id: str, job: dict) -> None:
    """Process an export job, dispatching by deployment mode (dev/prod parity).

    Dev (``S.dev_mode=True``): inline storage in the DDB item (capped at 500
    events). Production: stream to S3 via :func:`_process_export_s3`. This is the
    public entry point called by the background worker (GAP-0178).
    """
    if S.dev_mode:
        _process_export_inline(export_id, job)
    else:
        _process_export_s3(export_id, job)


def _compute_manifest_signature(manifest: dict) -> str:
    signable = {k: v for k, v in manifest.items() if k != "signature"}
    payload = json.dumps(signable, sort_keys=True, default=str)
    sig = hmac.new(
        S.audit_export_signing_key.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{sig}"


def verify_manifest_signature(manifest: dict) -> bool:
    expected_sig = _compute_manifest_signature(manifest)
    actual_sig = manifest.get("signature", "")
    return hmac.compare_digest(expected_sig, actual_sig)
