"""DynamoDB operations for call recording metadata (CALL-009)."""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Literal, Optional

from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)

RecordingStatus = Literal[
    "pending_consent", "recording", "uploading", "ready", "failed", "deleted"
]

_VALID_TRANSITIONS: dict[str, set[str]] = {
    "pending_consent": {"recording", "deleted", "failed"},
    "recording": {"uploading", "failed", "deleted"},
    "uploading": {"ready", "failed", "deleted"},
    "ready": {"deleted"},
    "failed": {"deleted"},
    "deleted": set(),
}


def _table():
    from app.core.aws import ddb
    return ddb.Table(S.call_recordings_table_name or "CallRecordings")


@dataclass
class CallRecordingRecord:
    recording_id: str
    call_id: str
    conversation_id: str
    initiated_by: str
    participants: list[str] = field(default_factory=list)
    status: str = "pending_consent"
    s3_key: str = ""
    s3_bucket: str = ""
    mime_type: str = "video/webm"
    duration_seconds: float = 0.0
    file_size_bytes: int = 0
    consent_ts: int = 0
    started_at: int = 0
    completed_at: int = 0
    created_at: int = 0
    updated_at: int = 0
    upload_ticket_id: str = ""
    download_count: int = 0
    error_message: str = ""
    ttl: int = 0


def _record_to_item(record: CallRecordingRecord) -> dict:
    item: dict = {
        "recording_id": record.recording_id,
        "call_id": record.call_id,
        "conversation_id": record.conversation_id,
        "initiated_by": record.initiated_by,
        "participants": record.participants,
        "status": record.status,
        "mime_type": record.mime_type,
        "duration_seconds": Decimal(str(record.duration_seconds)),
        "file_size_bytes": record.file_size_bytes,
        "consent_ts": record.consent_ts,
        "started_at": record.started_at,
        "completed_at": record.completed_at,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "download_count": record.download_count,
        "ttl": record.ttl,
    }
    if record.s3_key:
        item["s3_key"] = record.s3_key
    if record.s3_bucket:
        item["s3_bucket"] = record.s3_bucket
    if record.upload_ticket_id:
        item["upload_ticket_id"] = record.upload_ticket_id
    if record.error_message:
        item["error_message"] = record.error_message
    return item


def _record_from_item(item: dict) -> CallRecordingRecord:
    return CallRecordingRecord(
        recording_id=str(item.get("recording_id") or ""),
        call_id=str(item.get("call_id") or ""),
        conversation_id=str(item.get("conversation_id") or ""),
        initiated_by=str(item.get("initiated_by") or ""),
        participants=list(item.get("participants") or []),
        status=str(item.get("status") or "pending_consent"),
        s3_key=str(item.get("s3_key") or ""),
        s3_bucket=str(item.get("s3_bucket") or ""),
        mime_type=str(item.get("mime_type") or "video/webm"),
        duration_seconds=float(item.get("duration_seconds") or 0),
        file_size_bytes=int(item.get("file_size_bytes") or 0),
        consent_ts=int(item.get("consent_ts") or 0),
        started_at=int(item.get("started_at") or 0),
        completed_at=int(item.get("completed_at") or 0),
        created_at=int(item.get("created_at") or 0),
        updated_at=int(item.get("updated_at") or 0),
        upload_ticket_id=str(item.get("upload_ticket_id") or ""),
        download_count=int(item.get("download_count") or 0),
        error_message=str(item.get("error_message") or ""),
        ttl=int(item.get("ttl") or 0),
    )


def _generate_recording_id() -> str:
    return f"rec_{uuid.uuid4().hex}"


def create_recording(
    *,
    call_id: str,
    conversation_id: str,
    initiated_by: str,
    participants: list[str],
) -> CallRecordingRecord:
    ts = int(now_ts())
    retention_ttl = ts + S.call_recording_retention_days * 86400
    record = CallRecordingRecord(
        recording_id=_generate_recording_id(),
        call_id=call_id,
        conversation_id=conversation_id,
        initiated_by=initiated_by,
        participants=participants,
        status="pending_consent",
        created_at=ts,
        updated_at=ts,
        ttl=retention_ttl,
    )
    _table().put_item(
        Item=_record_to_item(record),
        ConditionExpression="attribute_not_exists(recording_id)",
    )
    return record


def get_recording(recording_id: str) -> Optional[CallRecordingRecord]:
    resp = _table().get_item(Key={"recording_id": recording_id})
    item = resp.get("Item")
    if not item:
        return None
    return _record_from_item(item)


def get_recordings_for_call(call_id: str, *, limit: int = 50) -> list[CallRecordingRecord]:
    resp = _table().query(
        IndexName="ByCallIdCreatedAt",
        KeyConditionExpression="call_id = :cid",
        ExpressionAttributeValues={":cid": call_id},
        ScanIndexForward=False,
        Limit=limit,
    )
    return [_record_from_item(item) for item in (resp.get("Items") or [])]


def get_active_recording_for_call(call_id: str) -> Optional[CallRecordingRecord]:
    """Return a recording in pending_consent or recording status for this call, if any."""
    recs = get_recordings_for_call(call_id, limit=10)
    for rec in recs:
        if rec.status in ("pending_consent", "recording", "uploading"):
            return rec
    return None


def get_recordings_for_conversation(
    conversation_id: str, *, limit: int = 50, status_filter: Optional[str] = None,
) -> list[CallRecordingRecord]:
    resp = _table().query(
        IndexName="ByConversationCreatedAt",
        KeyConditionExpression="conversation_id = :cid",
        ExpressionAttributeValues={":cid": conversation_id},
        ScanIndexForward=False,
        Limit=limit,
    )
    records = [_record_from_item(item) for item in (resp.get("Items") or [])]
    if status_filter:
        records = [r for r in records if r.status == status_filter]
    return records


def update_recording_status(
    recording_id: str,
    new_status: str,
    **fields,
) -> Optional[CallRecordingRecord]:
    existing = get_recording(recording_id)
    if not existing:
        return None
    allowed = _VALID_TRANSITIONS.get(existing.status, set())
    if new_status not in allowed:
        raise ValueError(
            f"Invalid status transition: {existing.status} -> {new_status}"
        )
    ts = int(now_ts())
    updated = CallRecordingRecord(
        recording_id=existing.recording_id,
        call_id=existing.call_id,
        conversation_id=existing.conversation_id,
        initiated_by=existing.initiated_by,
        participants=fields.get("participants", existing.participants),
        status=new_status,
        s3_key=fields.get("s3_key", existing.s3_key),
        s3_bucket=fields.get("s3_bucket", existing.s3_bucket),
        mime_type=fields.get("mime_type", existing.mime_type),
        duration_seconds=fields.get("duration_seconds", existing.duration_seconds),
        file_size_bytes=fields.get("file_size_bytes", existing.file_size_bytes),
        consent_ts=fields.get("consent_ts", existing.consent_ts),
        started_at=fields.get("started_at", existing.started_at),
        completed_at=fields.get("completed_at", existing.completed_at),
        created_at=existing.created_at,
        updated_at=ts,
        upload_ticket_id=fields.get("upload_ticket_id", existing.upload_ticket_id),
        download_count=fields.get("download_count", existing.download_count),
        error_message=fields.get("error_message", existing.error_message),
        ttl=existing.ttl,
    )
    _table().put_item(Item=_record_to_item(updated))
    return updated


def consent_recording(recording_id: str, consenter_user_id: str) -> Optional[CallRecordingRecord]:
    """Transition from pending_consent to recording after second party consents."""
    ts = int(now_ts())
    return update_recording_status(
        recording_id,
        "recording",
        consent_ts=ts,
        started_at=ts,
    )


def start_upload(recording_id: str) -> Optional[CallRecordingRecord]:
    ticket_id = f"tkt_{uuid.uuid4().hex}"
    return update_recording_status(
        recording_id,
        "uploading",
        upload_ticket_id=ticket_id,
    )


def complete_upload(
    recording_id: str,
    *,
    s3_key: str,
    s3_bucket: str,
    file_size_bytes: int,
    duration_seconds: float,
    mime_type: str = "video/webm",
) -> Optional[CallRecordingRecord]:
    ts = int(now_ts())
    return update_recording_status(
        recording_id,
        "ready",
        s3_key=s3_key,
        s3_bucket=s3_bucket,
        file_size_bytes=file_size_bytes,
        duration_seconds=duration_seconds,
        mime_type=mime_type,
        completed_at=ts,
    )


def fail_recording(recording_id: str, error_message: str = "") -> Optional[CallRecordingRecord]:
    return update_recording_status(
        recording_id,
        "failed",
        error_message=error_message,
    )


def soft_delete_recording(recording_id: str) -> Optional[CallRecordingRecord]:
    return update_recording_status(recording_id, "deleted")
