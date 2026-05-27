"""VOD-020: Watermarked Downloads — Service Layer.

Provides watermark payload encoding/decoding, DynamoDB job management,
mock watermark completion (dev mode), and FFmpeg-based watermark embedding
(production mode).
"""

from __future__ import annotations

import binascii
import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ─── Payload Encode / Decode ─────────────────────────────────────────────────


def build_watermark_payload(user_id: str, timestamp: int) -> str:
    """Build a compact watermark payload string.

    Format: ``WM:v1:{user_id_hash}:{timestamp_hex}:{checksum}``
    """
    user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    ts_hex = format(timestamp, "08X")
    check_input = f"WM:v1:{user_hash}:{ts_hex}"
    checksum = format(binascii.crc_hqx(check_input.encode(), 0), "04X")
    return f"{check_input}:{checksum}"


def decode_watermark_payload(payload: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a watermark payload string.

    Returns ``None`` if the payload is malformed or the checksum is invalid.
    """
    match = re.match(
        r"^WM:v1:([a-f0-9]{16}):([a-fA-F0-9]{8}):([a-fA-F0-9]{4})$",
        payload,
    )
    if not match:
        return None

    user_hash, ts_hex, checksum = match.group(1), match.group(2), match.group(3)
    check_input = f"WM:v1:{user_hash}:{ts_hex}"
    expected_crc = format(binascii.crc_hqx(check_input.encode(), 0), "04X")
    if checksum.upper() != expected_crc:
        return None

    timestamp = int(ts_hex, 16)
    return {
        "version": "v1",
        "user_id_hash": user_hash,
        "download_timestamp": timestamp,
        "download_datetime": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
    }


# ─── Job Management ─────────────────────────────────────────────────────────


def create_watermark_job(
    video_id: str,
    user_id: str,
    source_mp4_key: str,
) -> Dict[str, Any]:
    """Create a new watermark job record in DynamoDB."""
    job_id = f"wj_{uuid.uuid4().hex}"
    now = now_ts()
    payload = build_watermark_payload(user_id, now)

    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    output_key = f"{prefix}/watermarked/{video_id}/{user_id}/{job_id}.mp4"

    item: Dict[str, Any] = {
        "job_id": job_id,
        "video_id": video_id,
        "user_id": user_id,
        "status": "queued",
        "source_mp4_key": source_mp4_key,
        "output_mp4_key": output_key,
        "watermark_payload": payload,
        "created_at": now,
        "ttl_epoch": now + S.watermark_cache_ttl_seconds,
        "GSI1PK": f"WM#{video_id}#{user_id}",
        "GSI1SK": now,
    }
    T.watermark_jobs.put_item(Item=item)
    return item


def find_cached_watermark(video_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Find a recent (< TTL) watermark job for the given video+user pair.

    Queries GSI1 (``WM#{video_id}#{user_id}``) descending by ``created_at``
    and returns the most recent job if it is still valid (within the TTL window).
    """
    cutoff = now_ts() - S.watermark_cache_ttl_seconds
    resp = T.watermark_jobs.query(
        IndexName="GSI1",
        KeyConditionExpression="GSI1PK = :pk AND GSI1SK > :cutoff",
        ExpressionAttributeValues={
            ":pk": f"WM#{video_id}#{user_id}",
            ":cutoff": cutoff,
        },
        ScanIndexForward=False,
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return items[0]


def complete_watermark_job_mock(job: Dict[str, Any]) -> None:
    """Complete a watermark job in dev/mock mode (no FFmpeg).

    Simply marks the job as ``completed`` with a mock output size.
    """
    now = now_ts()
    T.watermark_jobs.update_item(
        Key={"job_id": job["job_id"]},
        UpdateExpression="SET #s = :s, completed_at = :ca, duration_ms = :dm, output_size_bytes = :os",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "completed",
            ":ca": now,
            ":dm": 50,
            ":os": 1024,
        },
    )
    job["status"] = "completed"
    job["completed_at"] = now
    job["duration_ms"] = 50
    job["output_size_bytes"] = 1024


def get_watermark_job(job_id: str) -> Optional[Dict[str, Any]]:
    """Get a watermark job by its primary key."""
    resp = T.watermark_jobs.get_item(Key={"job_id": job_id})
    return resp.get("Item")


def count_active_jobs(user_id: str) -> int:
    """Count queued or running watermark jobs for a user.

    Uses a scan with FilterExpression — acceptable because the table is small
    and this is called only at download request time.
    """
    resp = T.watermark_jobs.scan(
        FilterExpression="user_id = :uid AND (#s = :q OR #s = :r)",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":uid": user_id,
            ":q": "queued",
            ":r": "running",
        },
        Select="COUNT",
    )
    return resp.get("Count", 0)


def mint_watermarked_download_url(output_mp4_key: str, ttl: int) -> str:
    """Generate a presigned download URL for the watermarked file.

    In dev mode returns a ``/mock/s3/...`` URL; in production uses
    S3 presigned URL generation.
    """
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    expires_at = now_ts() + ttl

    if S.dev_mode:
        return f"/mock/s3/{bucket}/{output_mp4_key}?expires={expires_at}&disposition=attachment"

    from app.core.aws import get_s3_client

    _s3 = get_s3_client()
    return _s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={
            "Bucket": bucket,
            "Key": output_mp4_key,
            "ResponseContentDisposition": 'attachment; filename="watermarked.mp4"',
            "ResponseContentType": "video/mp4",
        },
        ExpiresIn=ttl,
    )


def list_download_history(video_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List completed watermark jobs for a specific video (creator view)."""
    resp = T.watermark_jobs.scan(
        FilterExpression="video_id = :vid AND #s = :completed",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":vid": video_id,
            ":completed": "completed",
        },
        Limit=limit,
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return items[:limit]


def list_user_downloads(user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List the user's own completed watermark downloads."""
    resp = T.watermark_jobs.query(
        IndexName="GSI1",
        KeyConditionExpression="begins_with(GSI1PK, :prefix)",
        ExpressionAttributeValues={
            ":prefix": f"WM#",
        },
        ScanIndexForward=False,
        Limit=200,
    )
    # Filter client-side for the specific user (GSI1PK contains user_id)
    items = [
        item for item in resp.get("Items", [])
        if item.get("user_id") == user_id and item.get("status") == "completed"
    ]
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return items[:limit]
