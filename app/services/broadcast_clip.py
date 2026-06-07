"""Broadcast clip service -- viewer-initiated clipping (ENGAGE-005)."""

from __future__ import annotations

import logging
import threading
import time
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key, Attr
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish
from app.services.broadcast_recording import get_recording_by_session

logger = logging.getLogger(__name__)

# --- Rate Limiting ---
_CLIP_RATE_LOCK = threading.Lock()
_CLIP_RATE_BUCKETS: Dict[str, int] = {}  # "{session_id}#{user_id}" -> last_clip_ts_ms
_CLIP_RATE_LIMIT_MS = 30_000  # 1 clip per 30 seconds

# Quotas
_MAX_CLIPS_PER_BROADCAST = 10
_MIN_CLIP_DURATION = 5.0
_MAX_CLIP_DURATION = 60.0
_CAPTURE_WINDOW_SECONDS = 90


def _enforce_clip_rate_limit(session_id: str, user_id: str) -> None:
    key = f"clip#{session_id}#{user_id}"
    now_ms = int(time.time() * 1000)
    with _CLIP_RATE_LOCK:
        last = _CLIP_RATE_BUCKETS.get(key, 0)
        if now_ms - last < _CLIP_RATE_LIMIT_MS:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "CLIP_RATE_LIMITED",
                    "message": "You can create one clip every 30 seconds.",
                    "retry_after_ms": _CLIP_RATE_LIMIT_MS - (now_ms - last),
                },
            )
        _CLIP_RATE_BUCKETS[key] = now_ms


def create_broadcast_clip(
    *,
    session_id: str,
    creator_user_id: str,
    creator_display_name: str,
    start_seconds: float,
    end_seconds: float,
    title: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a clip from a live broadcast.

    Validates all constraints, creates clip record, and returns immediately
    with clip_id and status=processing.
    """
    from app.services.broadcast_store import get_session

    # Validate session
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Broadcast session not found")

    # Check clips enabled
    if not session.clips_enabled:
        raise HTTPException(403, {
            "code": "CLIPPING_DISABLED",
            "message": "Clip creation is disabled for this broadcast.",
        })

    # Session must be live or have a recording
    session_status = session.status
    recording = get_recording_by_session(session_id)
    if session_status != "live" and (not recording or recording.status != "ready"):
        raise HTTPException(400, "No recording available for clipping")

    # Duration validation
    clip_duration = end_seconds - start_seconds
    if start_seconds >= end_seconds:
        raise HTTPException(400, "start_seconds must be less than end_seconds")
    if clip_duration < _MIN_CLIP_DURATION:
        raise HTTPException(400, f"Minimum clip duration is {_MIN_CLIP_DURATION} seconds")
    if clip_duration > _MAX_CLIP_DURATION:
        raise HTTPException(400, f"Maximum clip duration is {_MAX_CLIP_DURATION} seconds")

    # Capture window validation (for live broadcasts)
    if session_status == "live" and recording:
        broadcast_duration = float(recording.duration_seconds) if recording.duration_seconds else 0
        if broadcast_duration > 0 and start_seconds < max(0, broadcast_duration - _CAPTURE_WINDOW_SECONDS):
            raise HTTPException(400, f"Can only clip from the last {_CAPTURE_WINDOW_SECONDS} seconds")

    # Rate limit
    _enforce_clip_rate_limit(session_id, creator_user_id)

    # Quota check
    existing_clips = _count_user_clips_for_session(session_id, creator_user_id)
    if existing_clips >= _MAX_CLIPS_PER_BROADCAST:
        raise HTTPException(429, {
            "code": "CLIP_QUOTA_EXCEEDED",
            "message": f"Maximum {_MAX_CLIPS_PER_BROADCAST} clips per broadcast.",
        })

    # Create clip record
    clip_id = f"bclip_{uuid4().hex}"
    video_id = f"v_{uuid4().hex}"
    ts = now_ts()

    # Get profile name for auto-title
    profile_name = "broadcast"
    try:
        from app.services.broadcast_store import get_profile
        profile = get_profile(session.profile_id)
        profile_name = profile.name
    except Exception:
        pass

    auto_title = title or f"Clip from {profile_name}"

    clip_item: Dict[str, Any] = {
        "clip_id": clip_id,
        "session_id": session_id,
        "broadcaster_user_id": session.created_by,
        "creator_user_id": creator_user_id,
        "creator_display_name": creator_display_name,
        "video_id": video_id,
        "title": auto_title[:100],  # Max 100 chars
        "start_seconds": Decimal(str(start_seconds)),
        "end_seconds": Decimal(str(end_seconds)),
        "duration_seconds": Decimal(str(clip_duration)),
        "status": "processing",
        "view_count": 0,
        "share_count": 0,
        "created_at": ts,
        "GSI1PK": f"SESSION#{session_id}",
        "GSI1SK": ts,
        "GSI2PK": f"CREATOR#{creator_user_id}",
        "GSI2SK": ts,
        "GSI3PK": "GALLERY",
        "GSI3SK": f"00000000#{ts}",  # Initial view count = 0
    }

    T.broadcast_clips.put_item(Item=clip_item)

    # In dev mode, mark as ready immediately
    if S.dev_mode:
        _mark_clip_ready(clip_id, clip_duration)

    # Publish SSE event to broadcaster
    out = _clip_out(clip_item)
    broadcast_sse_publish(session_id, {
        "_type": "clip:created",
        **out,
    })

    logger.info(
        "Broadcast clip created: clip=%s session=%s creator=%s range=%.1f-%.1fs",
        clip_id, session_id, creator_user_id, start_seconds, end_seconds,
    )

    return out


def get_clip(clip_id: str) -> Dict[str, Any]:
    """Get clip details."""
    resp = T.broadcast_clips.get_item(Key={"clip_id": clip_id})
    item = resp.get("Item")
    if not item or item.get("status") == "deleted":
        raise HTTPException(404, "Clip not found")
    return _clip_out(item)


def get_public_clip(clip_id: str) -> Dict[str, Any]:
    """Get a clip for the public shareable page (no auth).

    Returns the clip plus broadcaster attribution (display name + profile id)
    so that the public clip view can link back to the original broadcast.
    """
    resp = T.broadcast_clips.get_item(Key={"clip_id": clip_id})
    item = resp.get("Item")
    if not item or item.get("status") == "deleted":
        raise HTTPException(404, "Clip not found")

    out = _clip_out(item)

    # Resolve broadcaster attribution from the source session's profile.
    broadcaster_display_name = ""
    profile_id = ""
    try:
        from app.services.broadcast_store import get_session, get_profile

        session = get_session(out["session_id"])
        profile_id = session.profile_id
        profile = get_profile(session.profile_id)
        broadcaster_display_name = profile.name
    except Exception:
        # Source session/profile may be gone (expired recording); attribution
        # degrades gracefully -- the clip itself remains viewable.
        pass

    out["broadcaster_display_name"] = broadcaster_display_name
    out["profile_id"] = profile_id
    return out


def list_clips_for_session(session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List clips for a broadcast session, newest first."""
    resp = T.broadcast_clips.query(
        IndexName="BySession",
        KeyConditionExpression=Key("GSI1PK").eq(f"SESSION#{session_id}"),
        ScanIndexForward=False,
        FilterExpression=Attr("status").ne("deleted"),
        Limit=limit,
    )
    return [_clip_out(item) for item in resp.get("Items", [])]


def list_my_clips(user_sub: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List clips created by the current user, newest first."""
    resp = T.broadcast_clips.query(
        IndexName="ByCreator",
        KeyConditionExpression=Key("GSI2PK").eq(f"CREATOR#{user_sub}"),
        ScanIndexForward=False,
        FilterExpression=Attr("status").ne("deleted"),
        Limit=limit,
    )
    return [_clip_out(item) for item in resp.get("Items", [])]


def list_gallery(
    limit: int = 50,
    sort: str = "popular",
    cursor: Optional[str] = None,
) -> tuple[List[Dict[str, Any]], Optional[str]]:
    """List clips in the public gallery.

    sort: "popular" (by view_count) or "recent" (by created_at)
    """
    from app.core.cursor import encode_cursor, decode_cursor

    kwargs: Dict[str, Any] = {
        "IndexName": "ByGallery",
        "KeyConditionExpression": Key("GSI3PK").eq("GALLERY"),
        "ScanIndexForward": False,
        "FilterExpression": Attr("status").eq("ready"),
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = T.broadcast_clips.query(**kwargs)
    items = [_clip_out(item) for item in resp.get("Items", [])]

    next_cursor = None
    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        next_cursor = encode_cursor(last_key)

    return items, next_cursor


def delete_clip(clip_id: str, actor: str, role: Any = None) -> Dict[str, Any]:
    """Delete a clip (soft delete).

    Authorized for: clip creator, broadcaster, or platform admin/root.

    GAP-0169: previously the authorization check only compared ``actor`` against
    the stored creator/broadcaster IDs, so platform admins/root operators could
    not moderate clips. ``role`` is normalized (accepts a ``Role`` enum or its
    string value) and ADMIN/ROOT callers are permitted to delete any clip. The
    parameter defaults to ``None`` (treated as USER) so existing callers that do
    not pass a role remain restricted to creator/broadcaster.
    """
    from app.auth.roles import Role, normalize_role

    resp = T.broadcast_clips.get_item(Key={"clip_id": clip_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "Clip not found")

    # Authorization: creator, broadcaster, or platform admin/root
    is_admin = normalize_role(role) in (Role.ADMIN, Role.ROOT)
    if (
        not is_admin
        and actor != item.get("creator_user_id")
        and actor != item.get("broadcaster_user_id")
    ):
        raise HTTPException(403, "Not authorized to delete this clip")

    T.broadcast_clips.update_item(
        Key={"clip_id": clip_id},
        UpdateExpression="SET #s = :deleted",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":deleted": "deleted"},
    )

    if is_admin:
        logger.info(
            "clip: admin-moderated delete clip_id=%s actor=%s role=%s reason=moderation",
            clip_id, actor, normalize_role(role).value,
        )

    return {"ok": True, "clip_id": clip_id, "status": "deleted"}


def record_view(clip_id: str) -> Dict[str, Any]:
    """Atomically increment view count."""
    resp = T.broadcast_clips.update_item(
        Key={"clip_id": clip_id},
        UpdateExpression="SET view_count = if_not_exists(view_count, :zero) + :one",
        ExpressionAttributeValues={":one": 1, ":zero": 0},
        ReturnValues="ALL_NEW",
    )
    new_count = int(resp["Attributes"].get("view_count", 0))

    # Update gallery sort key with new view count
    padded = str(new_count).zfill(8)
    created_at = int(resp["Attributes"].get("created_at", 0))
    T.broadcast_clips.update_item(
        Key={"clip_id": clip_id},
        UpdateExpression="SET GSI3SK = :sk",
        ExpressionAttributeValues={":sk": f"{padded}#{created_at}"},
    )

    return {"ok": True, "view_count": new_count}


def record_share(clip_id: str) -> Dict[str, Any]:
    """Atomically increment share count and return share URL."""
    resp = T.broadcast_clips.update_item(
        Key={"clip_id": clip_id},
        UpdateExpression="SET share_count = if_not_exists(share_count, :zero) + :one",
        ExpressionAttributeValues={":one": 1, ":zero": 0},
        ReturnValues="ALL_NEW",
    )
    return {
        "ok": True,
        "share_count": int(resp["Attributes"].get("share_count", 0)),
        "share_url": f"/clips/{clip_id}",
    }


# --- Internal helpers ---

def _count_user_clips_for_session(session_id: str, user_id: str) -> int:
    """Count non-deleted clips created by a user for a specific session.

    Paginates through all DDB pages via ``LastEvaluatedKey`` so the
    ``FilterExpression`` never silently under-counts on high-volume sessions.
    DynamoDB applies ``FilterExpression`` only after reading up to 1 MB of raw
    items per page; a single ``query()`` would miss this user's clips that fall
    beyond the first page, letting them exceed the per-broadcast quota
    (GAP-0168).
    """
    total = 0
    kwargs: Dict[str, Any] = {
        "IndexName": "BySession",
        "KeyConditionExpression": Key("GSI1PK").eq(f"SESSION#{session_id}"),
        "FilterExpression": (
            Attr("creator_user_id").eq(user_id) & Attr("status").ne("deleted")
        ),
        "Select": "COUNT",
    }
    while True:
        resp = T.broadcast_clips.query(**kwargs)
        total += resp.get("Count", 0)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
    return total


def _mark_clip_ready(clip_id: str, duration: float) -> None:
    """Mark clip as ready after successful processing."""
    T.broadcast_clips.update_item(
        Key={"clip_id": clip_id},
        UpdateExpression="SET #s = :ready, duration_seconds = :dur",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":ready": "ready",
            ":dur": Decimal(str(duration)),
        },
    )


def _clip_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB clip item to output dict."""
    return {
        "clip_id": item.get("clip_id", ""),
        "session_id": item.get("session_id", ""),
        "broadcaster_user_id": item.get("broadcaster_user_id", ""),
        "creator_user_id": item.get("creator_user_id", ""),
        "creator_display_name": item.get("creator_display_name", ""),
        "video_id": item.get("video_id", ""),
        "title": item.get("title", ""),
        "start_seconds": float(item.get("start_seconds", 0)),
        "end_seconds": float(item.get("end_seconds", 0)),
        "duration_seconds": float(item.get("duration_seconds", 0)),
        "status": item.get("status", "processing"),
        "view_count": int(item.get("view_count", 0)),
        "share_count": int(item.get("share_count", 0)),
        "thumbnail_url": item.get("thumbnail_url", ""),
        "created_at": int(item.get("created_at", 0)),
    }
