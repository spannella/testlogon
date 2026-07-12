"""TKA-001/002/003 — Ticket file attachments.

Two-step presign + confirm upload flow (mirrors the messaging image-upload
pattern), plus list / download-URL / soft-delete. Entirely additive and gated
behind ``S.ticket_attachments_enabled`` (default off). Attachment metadata rows
live in the existing single-table ``T.tickets`` partition under an
``ATTACHMENT#`` sort-key prefix — no schema change, no new table.

Row shape (pk=TICKET#{ticket_id}):
    sk            = ATTACHMENT#{created_at:013d}#{attachment_id}
    attachment_id, ticket_id, filename, content_type, size_bytes,
    s3_bucket, s3_key, uploaded_by, created_at, sha256 (optional), deleted (bool)

S3 keys are always ``tickets/{ticket_id}/attachments/{attachment_id}/{filename}``
— deterministic, so ``confirm`` reconstructs the key rather than trusting a
client-supplied value (prevents writing metadata that points at an arbitrary
object). Dev mode returns ``/mock/s3/...`` proxy URLs; prod returns real
presigned URLs (SECOPS-007 parity — same code path, no business-logic fork).
"""
from __future__ import annotations

from typing import Any, Optional
from urllib.parse import quote as _url_quote
from uuid import uuid4

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_ATTACHMENT_SK_PREFIX = "ATTACHMENT#"


def _require_enabled() -> None:
    """404 when the feature flag is off — both endpoints become invisible."""
    if not getattr(S, "ticket_attachments_enabled", False):
        raise HTTPException(status_code=404, detail={"code": "ticket_attachments_not_enabled", "message": "ticket attachments are not enabled"})


def _bucket() -> str:
    return getattr(S, "ticket_attachments_s3_bucket", "") or getattr(S, "filemgr_bucket", "") or "filemgr"


def _ticket_pk(ticket_id: str) -> str:
    return f"TICKET#{ticket_id}"


def _attachment_sk(created_at: int, attachment_id: str) -> str:
    return f"{_ATTACHMENT_SK_PREFIX}{created_at:013d}#{attachment_id}"


def _object_key(ticket_id: str, attachment_id: str, filename: str) -> str:
    """Deterministic S3 key — recomputed on confirm so the client cannot point
    a metadata row at an unrelated object."""
    return f"tickets/{ticket_id}/attachments/{attachment_id}/{filename}"


def _s3():
    from app.core.aws_clients import s3_client
    return s3_client()


def _project(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "attachment_id": item["attachment_id"],
        "ticket_id": item.get("ticket_id", ""),
        "filename": item.get("filename", ""),
        "content_type": item.get("content_type", "application/octet-stream"),
        "size_bytes": int(item.get("size_bytes", 0) or 0),
        "uploaded_by": item.get("uploaded_by", ""),
        "created_at": int(item.get("created_at", 0) or 0),
        "sha256": item.get("sha256"),
    }


# --- TKA-001: presign + confirm -------------------------------------------------


def presign_attachment(*, ticket_id: str, filename: str, content_type: str) -> dict[str, Any]:
    """Mint a time-limited S3 PUT URL for a new attachment. Stores nothing yet."""
    _require_enabled()
    attachment_id = uuid4().hex
    bucket = _bucket()
    key = _object_key(ticket_id, attachment_id, filename)
    ttl = int(getattr(S, "ticket_attachments_presign_ttl_seconds", 900) or 900)
    if S.dev_mode:
        upload_url = f"/mock/s3/{bucket}/{_url_quote(key, safe='/')}"
    else:
        upload_url = _s3().generate_presigned_url(
            ClientMethod="put_object",
            Params={"Bucket": bucket, "Key": key, "ContentType": content_type},
            ExpiresIn=ttl,
        )
    return {
        "attachment_id": attachment_id,
        "upload_url": upload_url,
        "bucket": bucket,
        "key": key,
        "content_type": content_type,
    }


def confirm_attachment(
    *,
    ticket_id: str,
    attachment_id: str,
    filename: str,
    content_type: str,
    size_bytes: int,
    uploaded_by: str,
    sha256: Optional[str] = None,
) -> dict[str, Any]:
    """Record attachment metadata after the client has uploaded to S3.

    Idempotent guard: a second confirm of the same attachment_id raises 409.
    """
    _require_enabled()
    created_at = now_ts()
    bucket = _bucket()
    key = _object_key(ticket_id, attachment_id, filename)
    item = {
        "pk": _ticket_pk(ticket_id),
        "sk": _attachment_sk(created_at, attachment_id),
        "attachment_id": attachment_id,
        "ticket_id": ticket_id,
        "filename": filename,
        "content_type": content_type,
        "size_bytes": int(size_bytes),
        "s3_bucket": bucket,
        "s3_key": key,
        "uploaded_by": uploaded_by,
        "created_at": created_at,
        "deleted": False,
    }
    if sha256:
        item["sha256"] = sha256
    try:
        T.tickets.put_item(Item=item, ConditionExpression="attribute_not_exists(sk)")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail={"code": "attachment_already_exists", "message": "attachment already confirmed"})
        raise
    return _project(item)


# --- TKA-002: list / download / delete ------------------------------------------


def _query_attachment_rows(ticket_id: str) -> list[dict[str, Any]]:
    resp = T.tickets.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": _ticket_pk(ticket_id), ":sk": _ATTACHMENT_SK_PREFIX},
        ScanIndexForward=True,
    )
    return resp.get("Items", [])


def list_attachments(ticket_id: str) -> list[dict[str, Any]]:
    """Active (non-deleted) attachment metadata for a ticket, oldest-first."""
    _require_enabled()
    return [_project(r) for r in _query_attachment_rows(ticket_id) if not r.get("deleted")]


def list_attachments_for_projection(ticket_id: str) -> list[dict[str, Any]]:
    """Same as list_attachments but never raises and returns [] when the flag is
    off — used by get_ticket so the ticket projection is always safe."""
    if not getattr(S, "ticket_attachments_enabled", False):
        return []
    try:
        return [_project(r) for r in _query_attachment_rows(ticket_id) if not r.get("deleted")]
    except Exception:
        return []


def _get_attachment_row(ticket_id: str, attachment_id: str) -> Optional[dict[str, Any]]:
    for r in _query_attachment_rows(ticket_id):
        if r.get("attachment_id") == attachment_id and not r.get("deleted"):
            return r
    return None


def get_download_url(*, ticket_id: str, attachment_id: str) -> str:
    """Presigned GET URL (prod) or /mock/s3 proxy URL (dev) for an attachment."""
    _require_enabled()
    row = _get_attachment_row(ticket_id, attachment_id)
    if not row:
        raise HTTPException(status_code=404, detail={"code": "attachment_not_found", "message": "attachment not found"})
    bucket = row.get("s3_bucket") or _bucket()
    key = row["s3_key"]
    if S.dev_mode:
        return f"/mock/s3/{bucket}/{_url_quote(key, safe='/')}"
    ttl = int(getattr(S, "ticket_attachments_download_ttl_seconds", 300) or 300)
    return _s3().generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=ttl,
    )


def delete_attachment(*, ticket_id: str, attachment_id: str, actor_sub: str, is_admin: bool) -> dict[str, Any]:
    """Soft-delete a metadata row + best-effort S3 object removal. Only the
    original uploader or an admin may delete."""
    _require_enabled()
    row = _get_attachment_row(ticket_id, attachment_id)
    if not row:
        raise HTTPException(status_code=404, detail={"code": "attachment_not_found", "message": "attachment not found"})
    if not is_admin and row.get("uploaded_by") != actor_sub:
        raise HTTPException(status_code=403, detail={"code": "attachment_delete_forbidden", "message": "only the uploader or an admin may delete this attachment"})
    T.tickets.update_item(
        Key={"pk": row["pk"], "sk": row["sk"]},
        UpdateExpression="SET deleted = :t, deleted_at = :ts, deleted_by = :by",
        ExpressionAttributeValues={":t": True, ":ts": now_ts(), ":by": actor_sub},
    )
    # Best-effort S3 removal — a failure here never blocks the soft-delete.
    try:
        if not S.dev_mode:
            _s3().delete_object(Bucket=row.get("s3_bucket") or _bucket(), Key=row["s3_key"])
    except Exception:
        pass
    return {"ok": True, "attachment_id": attachment_id}
