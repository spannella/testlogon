"""Broadcast Recording Service (BCAST-006).

Manages VOD recording lifecycle for broadcast sessions.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T


def _now_ts() -> int:
    return int(time.time())


@dataclass
class RecordingRecord:
    recording_id: str
    session_id: str
    profile_id: str
    created_by: str
    status: str  # pending, processing, ready, failed, expired
    s3_archive_prefix: str = ""
    s3_manifest_key: str = ""
    s3_thumbnail_key: str = ""
    duration_seconds: float = 0.0
    segment_count: int = 0
    total_bytes: int = 0
    renditions: List[Dict[str, Any]] = field(default_factory=list)
    error_code: str = ""
    error_message: str = ""
    retention_days: int = 30
    scope: str = "ALL"  # partition key for ByExpiresAt GSI
    created_at: int = 0
    completed_at: int = 0
    expires_at: int = 0
    # Download fields (BCAST-008)
    allow_download: bool = True
    allow_viewer_download: bool = False
    mp4_s3_key: str = ""
    mp4_size_bytes: int = 0
    mp4_generated_at: int = 0
    s3_concatenated_key: str = ""


def _record_from_item(item: Dict[str, Any]) -> RecordingRecord:
    return RecordingRecord(
        recording_id=item["recording_id"],
        session_id=item["session_id"],
        profile_id=item.get("profile_id", ""),
        created_by=item.get("created_by", ""),
        status=item.get("status", "pending"),
        s3_archive_prefix=item.get("s3_archive_prefix", ""),
        s3_manifest_key=item.get("s3_manifest_key", ""),
        s3_thumbnail_key=item.get("s3_thumbnail_key", ""),
        duration_seconds=float(item.get("duration_seconds", 0)),
        segment_count=int(item.get("segment_count", 0)),
        total_bytes=int(item.get("total_bytes", 0)),
        renditions=item.get("renditions", []),
        error_code=item.get("error_code", ""),
        error_message=item.get("error_message", ""),
        retention_days=int(item.get("retention_days", 30)),
        scope=item.get("scope", "ALL"),
        created_at=int(item.get("created_at", 0)),
        completed_at=int(item.get("completed_at", 0)),
        expires_at=int(item.get("expires_at", 0)),
        # Download fields (BCAST-008)
        allow_download=item.get("allow_download", True),
        allow_viewer_download=item.get("allow_viewer_download", False),
        mp4_s3_key=item.get("mp4_s3_key", ""),
        mp4_size_bytes=int(item.get("mp4_size_bytes", 0)),
        mp4_generated_at=int(item.get("mp4_generated_at", 0)),
        s3_concatenated_key=item.get("s3_concatenated_key", ""),
    )


def _record_to_item(rec: RecordingRecord) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "recording_id": rec.recording_id,
        "session_id": rec.session_id,
        "profile_id": rec.profile_id,
        "created_by": rec.created_by,
        "status": rec.status,
        "s3_archive_prefix": rec.s3_archive_prefix,
        "s3_manifest_key": rec.s3_manifest_key,
        "s3_thumbnail_key": rec.s3_thumbnail_key,
        "duration_seconds": int(rec.duration_seconds) if rec.duration_seconds == int(rec.duration_seconds) else rec.duration_seconds,
        "segment_count": rec.segment_count,
        "total_bytes": rec.total_bytes,
        "renditions": rec.renditions,
        "error_code": rec.error_code,
        "error_message": rec.error_message,
        "retention_days": rec.retention_days,
        "scope": rec.scope,
        "created_at": rec.created_at,
        "completed_at": rec.completed_at,
        "expires_at": rec.expires_at,
        # Download fields (BCAST-008)
        "allow_download": rec.allow_download,
        "allow_viewer_download": rec.allow_viewer_download,
        "mp4_s3_key": rec.mp4_s3_key,
        "mp4_size_bytes": rec.mp4_size_bytes,
        "mp4_generated_at": rec.mp4_generated_at,
        "s3_concatenated_key": rec.s3_concatenated_key,
    }
    # Remove empty strings for non-key attributes to keep items lean
    return {k: v for k, v in item.items() if v != "" and v != [] or k in ("recording_id", "session_id", "status", "scope", "created_at")}


def create_recording(
    *,
    session_id: str,
    profile_id: str,
    created_by: str,
    s3_archive_prefix: str = "",
    retention_days: int = 30,
) -> RecordingRecord:
    """Create a new recording record with status=pending."""
    now = _now_ts()
    expires_at = now + (retention_days * 86400)
    rec = RecordingRecord(
        recording_id=f"rec_{uuid4().hex}",
        session_id=session_id,
        profile_id=profile_id,
        created_by=created_by,
        status="pending",
        s3_archive_prefix=s3_archive_prefix,
        retention_days=retention_days,
        scope="ALL",
        created_at=now,
        expires_at=expires_at,
    )
    T.broadcast_recordings.put_item(Item=_record_to_item(rec))
    return rec


def get_recording(recording_id: str) -> Optional[RecordingRecord]:
    """Get recording by primary key."""
    resp = T.broadcast_recordings.get_item(Key={"recording_id": recording_id})
    item = resp.get("Item")
    if not item:
        return None
    return _record_from_item(item)


def get_recording_by_session(session_id: str) -> Optional[RecordingRecord]:
    """Get the latest recording for a session via BySessionId GSI."""
    resp = T.broadcast_recordings.query(
        IndexName="BySessionId",
        KeyConditionExpression=Key("session_id").eq(session_id),
        ScanIndexForward=False,
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _record_from_item(items[0])


def update_recording_status(recording_id: str, status: str, **extra_fields: Any) -> Optional[RecordingRecord]:
    """Update recording status and optional extra fields."""
    update_expr_parts = ["#st = :status"]
    expr_names: Dict[str, str] = {"#st": "status"}
    expr_values: Dict[str, Any] = {":status": status}

    for key, value in extra_fields.items():
        safe_key = f"#{key}"
        expr_names[safe_key] = key
        expr_values[f":{key}"] = value
        update_expr_parts.append(f"{safe_key} = :{key}")

    T.broadcast_recordings.update_item(
        Key={"recording_id": recording_id},
        UpdateExpression="SET " + ", ".join(update_expr_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )
    return get_recording(recording_id)


def list_recordings_by_status(status: str, limit: int = 50) -> List[RecordingRecord]:
    """Query ByStatusCreatedAt GSI."""
    resp = T.broadcast_recordings.query(
        IndexName="ByStatusCreatedAt",
        KeyConditionExpression=Key("status").eq(status),
        ScanIndexForward=False,
        Limit=limit,
    )
    return [_record_from_item(item) for item in resp.get("Items", [])]


def list_expired_recordings(now_ts: int, limit: int = 100) -> List[RecordingRecord]:
    """Query ByExpiresAt GSI for records where expires_at <= now_ts."""
    resp = T.broadcast_recordings.query(
        IndexName="ByExpiresAt",
        KeyConditionExpression=Key("scope").eq("ALL") & Key("expires_at").lte(now_ts),
        Limit=limit,
    )
    return [_record_from_item(item) for item in resp.get("Items", [])]


def mint_recording_playback_url(recording: RecordingRecord) -> Dict[str, Any]:
    """Generate a signed playback URL for a ready recording."""
    ttl = S.broadcast_recording_playback_ttl_seconds
    expires_at = _now_ts() + ttl
    # In dev/local mode, generate a mock URL pattern
    bucket = S.broadcast_recording_vod_bucket
    manifest_key = recording.s3_manifest_key or f"{recording.session_id}/recording/master.m3u8"
    playback_url = f"/mock/s3/{bucket}/{manifest_key}?expires={expires_at}"
    return {
        "playback_url": playback_url,
        "playback_expires_at": expires_at,
    }


def mint_recording_thumbnail_url(recording: RecordingRecord) -> Optional[str]:
    """Generate thumbnail URL for a ready recording."""
    if not recording.s3_thumbnail_key:
        return None
    bucket = S.broadcast_recording_vod_bucket
    return f"/mock/s3/{bucket}/{recording.s3_thumbnail_key}"


def mint_recording_download_url(recording: RecordingRecord) -> Dict[str, Any]:
    """Generate a presigned S3 download URL for the recording MP4.

    The URL includes Content-Disposition: attachment to force browser download.
    """
    ttl = S.broadcast_recording_download_ttl_seconds
    expires_at = _now_ts() + ttl
    bucket = S.broadcast_recording_vod_bucket
    filename = f"recording-{recording.session_id[:12]}.mp4"

    if S.dev_mode:
        # Dev mode: return mock URL
        download_url = f"/mock/s3/{bucket}/{recording.mp4_s3_key}?expires={expires_at}&disposition=attachment"
    else:
        # Production: generate real S3 presigned URL
        import boto3
        s3_client = boto3.client("s3")
        download_url = s3_client.generate_presigned_url(
            ClientMethod="get_object",
            Params={
                "Bucket": bucket,
                "Key": recording.mp4_s3_key,
                "ResponseContentDisposition": f'attachment; filename="{filename}"',
                "ResponseContentType": "video/mp4",
            },
            ExpiresIn=ttl,
        )

    return {
        "download_url": download_url,
        "download_expires_at": expires_at,
        "file_size_bytes": recording.mp4_size_bytes,
        "filename": filename,
        "content_type": "video/mp4",
    }
