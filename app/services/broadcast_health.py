"""Stream health metrics collection, storage, and classification."""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.broadcast_viewers import get_viewer_count


SNAPSHOT_TTL_DAYS = 7

# Connection quality thresholds
# (max_dropped_frames_pct, min_bitrate_kbps, max_input_loss_seconds)
QUALITY_THRESHOLDS = {
    "excellent": (0.1, 4000, 0),
    "good": (0.5, 2000, 0),
    "fair": (2.0, 1000, 2),
    "poor": (5.0, 500, 5),
    # anything worse = "critical"
}


def classify_connection_quality(
    dropped_frames_pct: float,
    ingest_bitrate_kbps: int,
    input_loss_seconds: float,
) -> str:
    """Classify stream quality into a color-coded tier."""
    for level, (max_drop, min_bitrate, max_loss) in QUALITY_THRESHOLDS.items():
        if (
            dropped_frames_pct <= max_drop
            and ingest_bitrate_kbps >= min_bitrate
            and input_loss_seconds <= max_loss
        ):
            return level
    return "critical"


def store_health_snapshot(
    session_id: str,
    *,
    ingest_bitrate_kbps: int,
    ingest_framerate: float,
    dropped_frames: int,
    dropped_frames_pct: float,
    output_errors: int = 0,
    input_loss_seconds: float = 0,
) -> Dict[str, Any]:
    """Store a health snapshot and publish via SSE."""
    now = now_ts()
    viewer_count = get_viewer_count(session_id)
    quality = classify_connection_quality(dropped_frames_pct, ingest_bitrate_kbps, input_loss_seconds)

    item = {
        "session_id": session_id,
        "snapshot_ts": now,
        "viewer_count": viewer_count,
        "ingest_bitrate_kbps": ingest_bitrate_kbps,
        "ingest_framerate": Decimal(str(ingest_framerate)),
        "dropped_frames": dropped_frames,
        "dropped_frames_pct": Decimal(str(dropped_frames_pct)),
        "connection_quality": quality,
        "output_errors": output_errors,
        "input_loss_seconds": Decimal(str(input_loss_seconds)),
        "ttl": now + (SNAPSHOT_TTL_DAYS * 86400),
    }
    T.broadcast_health_snapshots.put_item(Item=item)

    # Publish health update to all SSE subscribers
    broadcast_sse_publish(session_id, {
        "_type": "health_update",
        "session_id": session_id,
        "viewer_count": viewer_count,
        "ingest_bitrate_kbps": ingest_bitrate_kbps,
        "ingest_framerate": float(ingest_framerate),
        "dropped_frames": dropped_frames,
        "dropped_frames_pct": float(dropped_frames_pct),
        "connection_quality": quality,
        "output_errors": output_errors,
        "input_loss_seconds": float(input_loss_seconds),
        "updated_at": now,
    })

    return {
        "session_id": session_id,
        "snapshot_ts": now,
        "viewer_count": viewer_count,
        "ingest_bitrate_kbps": ingest_bitrate_kbps,
        "ingest_framerate": float(ingest_framerate),
        "dropped_frames": dropped_frames,
        "dropped_frames_pct": float(dropped_frames_pct),
        "connection_quality": quality,
        "output_errors": output_errors,
        "input_loss_seconds": float(input_loss_seconds),
        "updated_at": now,
    }


def get_latest_health(session_id: str) -> Optional[Dict[str, Any]]:
    """Get the most recent health snapshot for a session."""
    resp = T.broadcast_health_snapshots.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        ScanIndexForward=False,
        Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    item = items[0]
    return _snapshot_to_dict(item)


def get_health_history(
    session_id: str,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    limit: int = 60,
) -> List[Dict[str, Any]]:
    """Get health snapshot history for a session within a time range."""
    kce = Key("session_id").eq(session_id)
    if from_ts and to_ts:
        kce = kce & Key("snapshot_ts").between(from_ts, to_ts)
    elif from_ts:
        kce = kce & Key("snapshot_ts").gte(from_ts)
    elif to_ts:
        kce = kce & Key("snapshot_ts").lte(to_ts)

    resp = T.broadcast_health_snapshots.query(
        KeyConditionExpression=kce,
        ScanIndexForward=False,
        Limit=limit,
    )
    return [_snapshot_to_dict(item) for item in resp.get("Items", [])]


def _snapshot_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DynamoDB item (with Decimals) to a plain dict."""
    return {
        "session_id": item["session_id"],
        "snapshot_ts": int(item["snapshot_ts"]),
        "viewer_count": int(item.get("viewer_count", 0)),
        "ingest_bitrate_kbps": int(item.get("ingest_bitrate_kbps", 0)),
        "ingest_framerate": float(item.get("ingest_framerate", 0)),
        "dropped_frames": int(item.get("dropped_frames", 0)),
        "dropped_frames_pct": float(item.get("dropped_frames_pct", 0)),
        "connection_quality": item.get("connection_quality", "critical"),
        "output_errors": int(item.get("output_errors", 0)),
        "input_loss_seconds": float(item.get("input_loss_seconds", 0)),
        "updated_at": int(item.get("snapshot_ts", 0)),
    }
