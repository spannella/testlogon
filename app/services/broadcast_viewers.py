"""Viewer count tracking for live broadcast sessions."""

from __future__ import annotations

from typing import Any, Dict, List
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish


VIEWER_TTL_SECONDS = 60  # Viewer record expires 60s after last heartbeat
HEARTBEAT_INTERVAL_SECONDS = 30  # Client should heartbeat every 30s


def register_viewer(session_id: str, user_sub: str, user_agent: str = "") -> Dict[str, Any]:
    """Register a new viewer for a broadcast session. Returns viewer record."""
    connection_id = uuid4().hex[:12]
    viewer_id = f"{user_sub}#{connection_id}"
    now = now_ts()

    item = {
        "session_id": session_id,
        "viewer_id": viewer_id,
        "user_sub": user_sub,
        "joined_at": now,
        "last_heartbeat": now,
        "expires_at": now + VIEWER_TTL_SECONDS,
        "user_agent": user_agent,
    }
    T.broadcast_viewers.put_item(Item=item)

    count = get_viewer_count(session_id)
    broadcast_sse_publish(session_id, {
        "_type": "viewer_count",
        "session_id": session_id,
        "viewer_count": count,
        "delta": 1,
    })
    return {"viewer_id": viewer_id, "session_id": session_id, "viewer_count": count}


def touch_viewer(session_id: str, viewer_id: str) -> int:
    """Update heartbeat timestamp and extend TTL. Returns current viewer count."""
    now = now_ts()
    T.broadcast_viewers.update_item(
        Key={"session_id": session_id, "viewer_id": viewer_id},
        UpdateExpression="SET last_heartbeat = :hb, expires_at = :exp",
        ExpressionAttributeValues={":hb": now, ":exp": now + VIEWER_TTL_SECONDS},
        ConditionExpression="attribute_exists(viewer_id)",
    )
    return get_viewer_count(session_id)


def unregister_viewer(session_id: str, viewer_id: str) -> int:
    """Remove viewer record explicitly. Returns updated viewer count."""
    T.broadcast_viewers.delete_item(
        Key={"session_id": session_id, "viewer_id": viewer_id}
    )
    count = get_viewer_count(session_id)
    broadcast_sse_publish(session_id, {
        "_type": "viewer_count",
        "session_id": session_id,
        "viewer_count": count,
        "delta": -1,
    })
    return count


def get_viewer_count(session_id: str) -> int:
    """Count active viewers for a session (DDB Select=COUNT query)."""
    resp = T.broadcast_viewers.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def list_viewers(session_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """List active viewers for a session (for admin display)."""
    resp = T.broadcast_viewers.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Limit=limit,
        ScanIndexForward=False,
    )
    return resp.get("Items", [])
