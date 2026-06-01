from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

from app.metrics import record_signature_packet_render_job, record_signature_packet_render_latency
from app.services.filemanager import download_file
from app.services.signature_packet_store import (
    append_packet_event,
    get_packet,
    get_packet_artifact,
    list_completed_packets,
    list_packet_events,
    list_packet_fields,
    list_packet_signers,
    put_packet_artifact,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SignaturePacketRenderError(Exception):
    message: str
    retryable: bool = True

    def __str__(self) -> str:
        return self.message


RenderFn = Callable[[bytes, List[Dict[str, Any]]], bytes]


def _render_payload_for_overlay(field: Dict[str, Any]) -> Dict[str, Any]:
    """Build the overlay render payload for a filled field.

    For ``notary_stamp`` fields we draw an explicit stamp block (image ref, number,
    expiry) so the flattened PDF marker records the official certification. Other
    field types pass through their stored render_payload unchanged.
    """
    payload = dict(field.get("render_payload") or {})
    if str(field.get("field_type") or "") == "notary_stamp":
        return {
            "kind": "notary_stamp",
            "stamp_image_ref": str(payload.get("stamp_image_ref") or ""),
            "stamp_number": str(payload.get("stamp_number") or ""),
            "stamp_expiry": str(payload.get("stamp_expiry") or ""),
            "stamped_at": int(payload.get("stamped_at") or 0),
            "draw": "stamp_box",
        }
    return payload


def render_signature_packet_pdf_overlay(source_pdf_bytes: bytes, fields: List[Dict[str, Any]]) -> bytes:
    if not source_pdf_bytes.startswith(b"%PDF"):
        raise SignaturePacketRenderError("source_not_pdf", retryable=False)

    overlays = [
        {
            "field_id": str(field.get("field_id") or ""),
            "page": int(field.get("page") or 1),
            "field_type": str(field.get("field_type") or ""),
            "value": str(field.get("value") or ""),
            "capture_mode": str(field.get("capture_mode") or ""),
            "render_payload": _render_payload_for_overlay(field),
            "filled_at": str(field.get("filled_at") or ""),
        }
        for field in fields
        if field.get("filled_at")
    ]

    marker = ("% signature-overlay-flat=" + json.dumps(overlays, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    eof = b"%%EOF"
    idx = source_pdf_bytes.rfind(eof)
    if idx == -1:
        return source_pdf_bytes + b"\n" + marker
    return source_pdf_bytes[:idx] + marker + source_pdf_bytes[idx:]


def _build_audit_appendix(*, packet: Dict[str, Any], signers: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    sent_at = ""
    for evt in events:
        if str(evt.get("event_type") or "") == "packet_sent":
            sent_at = str(evt.get("created_at") or evt.get("timestamp") or "")
            break

    signer_timeline: List[Dict[str, Any]] = []
    for signer in sorted(signers, key=lambda s: str(s.get("signer_id") or "")):
        signer_timeline.append(
            {
                "signer_id": str(signer.get("signer_id") or ""),
                "completed_at": str(signer.get("completed_at") or ""),
                "source_ip": str(signer.get("completed_ip") or ""),
            }
        )

    return {
        "packet_id": str(packet.get("packet_id") or ""),
        "first_sent_at": sent_at,
        "packet_completed_at": str(packet.get("completed_at") or ""),
        "signer_timeline": signer_timeline,
        "source_record_types": ["packet_events", "signer_completion_metadata"],
    }


def _append_audit_appendix_marker(pdf_bytes: bytes, appendix: Dict[str, Any]) -> bytes:
    marker = ("% signature-audit-appendix=" + json.dumps(appendix, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    eof = b"%%EOF"
    idx = pdf_bytes.rfind(eof)
    if idx == -1:
        return pdf_bytes + b"\n" + marker
    return pdf_bytes[:idx] + marker + pdf_bytes[idx:]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def render_completed_packet(
    packet_id: str,
    *,
    renderer: RenderFn | None = None,
    max_attempts: int = 5,
) -> Dict[str, Any]:
    packet = get_packet(packet_id)
    if not packet:
        raise ValueError("packet_not_found")
    if str(packet.get("status") or "") != "completed":
        raise ValueError("packet_not_completed")

    existing = get_packet_artifact(packet_id) or {}
    if str(existing.get("status") or "") == "ready":
        return {"packet_id": packet_id, "status": "already_finalized", "artifact": existing}

    render_func = renderer or render_signature_packet_pdf_overlay
    owner_user_id = str(packet.get("owner_user_id") or "")
    source_path = str(packet.get("source_path") or "")

    started_at = time.monotonic()
    try:
        source = download_file(owner_user_id, source_path)
        source_bytes = bytes(source.get("content") or b"")
        fields = list_packet_fields(packet_id)
        signers = list_packet_signers(packet_id)
        events = list_packet_events(packet_id)
        final_pdf = render_func(source_bytes, fields)
        audit_appendix = _build_audit_appendix(packet=packet, signers=signers, events=events)
        final_pdf = _append_audit_appendix_marker(final_pdf, audit_appendix)
        sha256 = hashlib.sha256(final_pdf).hexdigest()
        now = _now_iso()
        artifact = put_packet_artifact(
            packet_id,
            {
                "status": "ready",
                "finalized_at": now,
                "updated_at": now,
                "content_type": "application/pdf",
                "sha256": sha256,
                "render_version": "v1",
                "hash_algorithm": "sha256",
                "immutable": True,
                "source_packet_status": str(packet.get("status") or ""),
                "rendered_field_count": len([f for f in fields if f.get("filled_at")]),
                "audit_appendix": audit_appendix,
                "retry_count": int(existing.get("retry_count") or 0),
                "size_bytes": len(final_pdf),
                "final_pdf_base64": base64.b64encode(final_pdf).decode("ascii"),
            },
        )
        append_packet_event(
            packet_id=packet_id,
            actor_user_id="system",
            event_type="packet_finalized",
            event_payload={"sha256": sha256, "size_bytes": len(final_pdf)},
        )
        record_signature_packet_render_job(outcome="success", reason="none")
        record_signature_packet_render_latency(outcome="success", elapsed_seconds=time.monotonic() - started_at)
        return {"packet_id": packet_id, "status": "ready", "artifact": artifact}
    except Exception as exc:  # noqa: BLE001
        retry_count = int(existing.get("retry_count") or 0) + 1
        retryable = getattr(exc, "retryable", True)
        status = "retry_pending" if retryable and retry_count < max_attempts else "failed"
        now = _now_iso()
        artifact = put_packet_artifact(
            packet_id,
            {
                "status": status,
                "updated_at": now,
                "last_attempt_at": now,
                "last_error": str(exc),
                "retry_count": retry_count,
            },
        )
        append_packet_event(
            packet_id=packet_id,
            actor_user_id="system",
            event_type="packet_finalize_failed",
            event_payload={"error": str(exc), "retryable": bool(retryable), "retry_count": retry_count},
        )
        record_signature_packet_render_job(outcome="failed", reason=str(exc) or "unknown")
        record_signature_packet_render_latency(outcome="failed", elapsed_seconds=time.monotonic() - started_at)
        logger.warning("signature_packet_finalize_failed", extra={"packet_id": packet_id, "retry_count": retry_count, "retryable": bool(retryable)})
        return {"packet_id": packet_id, "status": status, "artifact": artifact}


def process_completed_packet_finalization_jobs(*, limit: int = 25) -> Dict[str, int]:
    packets = list_completed_packets(limit=limit)
    processed = 0
    succeeded = 0
    retriable = 0
    failed = 0
    for packet in packets:
        packet_id = str(packet.get("packet_id") or "")
        if not packet_id:
            continue
        processed += 1
        result = render_completed_packet(packet_id)
        status = str(result.get("status") or "")
        if status in {"ready", "already_finalized"}:
            succeeded += 1
        elif status == "retry_pending":
            retriable += 1
        else:
            failed += 1
    return {"processed": processed, "succeeded": succeeded, "retry_pending": retriable, "failed": failed}
