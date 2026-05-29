"""Content calendar aggregation service.

Queries scheduled posts, broadcasts, and VOD releases and returns them
as normalized CalendarItem dicts sorted by scheduled_at.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional, Set

from boto3.dynamodb.conditions import Key

from app.core.aws import ddb
from app.core.settings import S
import os
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ─── Constants ──────────────────────────────────────────────────

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
MAX_RANGE_SECONDS = 90 * 86400  # 90 days maximum query window
CONFLICT_BUFFER_MINUTES = 30

ContentType = Literal["post", "broadcast", "vod"]

CONTENT_COLORS: Dict[str, str] = {
    "post": "#3B82F6",       # blue-500
    "broadcast": "#EF4444",  # red-500
    "vod": "#8B5CF6",        # violet-500
}

CONTENT_ICONS: Dict[str, str] = {
    "post": "file-text",
    "broadcast": "radio",
    "vod": "video",
}


# ─── Scheduled Post Retrieval ───────────────────────────────────

def _get_scheduled_posts(
    user_id: str,
    from_ts: int,
    to_ts: int,
    *,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Retrieve scheduled posts for a user within the time window.

    Uses the user's ScheduledPostRef records (PK=USER#{user_id},
    SK begins_with SCHEDULEDPOST#) which are sorted by publish_at.
    Then batch-fetches the full post records.
    """
    tbl = ddb.Table(APP_TABLE)
    # ScheduledPostRef SK format: SCHEDULEDPOST#{publish_at:012d}#{post_id}
    sk_lower = f"SCHEDULEDPOST#{from_ts:012d}"
    sk_upper = f"SCHEDULEDPOST#{to_ts:012d}~"

    resp = tbl.query(
        KeyConditionExpression=(
            Key("pk").eq(f"USER#{user_id}")
            & Key("sk").between(sk_lower, sk_upper)
        ),
        Limit=limit,
        ScanIndexForward=True,
    )
    refs = resp.get("Items", [])

    if not refs:
        return []

    # Batch-fetch actual post records
    post_ids = [str(r.get("post_id", "")).strip() for r in refs if r.get("post_id")]
    if not post_ids:
        return []

    keys = [{"pk": f"POST#{pid}", "sk": "META"} for pid in post_ids]
    raw = ddb.batch_get_item(RequestItems={APP_TABLE: {"Keys": keys}})
    posts = raw.get("Responses", {}).get(APP_TABLE, [])

    # Filter to only scheduled posts owned by user
    return [
        p for p in posts
        if str(p.get("status", "")).strip().lower() == "scheduled"
        and p.get("user_id") == user_id
    ]


# ─── Scheduled Broadcast Retrieval ─────────────────────────────

def _get_scheduled_broadcasts(
    user_id: str,
    from_ts: int,
    to_ts: int,
) -> list:
    """Retrieve scheduled broadcasts for a user within the time window.

    Uses list_scheduled_sessions_by_creator (ByCreatorCreatedAt GSI
    with FilterExpression on schedule_status='scheduled'), then
    filters client-side by scheduled_at range.
    """
    from app.services.broadcast_store import list_scheduled_sessions_by_creator

    sessions = list_scheduled_sessions_by_creator(user_id, limit=200)
    return [
        s for s in sessions
        if s.scheduled_at is not None
        and from_ts <= s.scheduled_at <= to_ts
    ]


# ─── Scheduled VOD Retrieval ───────────────────────────────────

def _get_scheduled_vod(
    user_id: str,
    from_ts: int,
    to_ts: int,
) -> List[Dict[str, Any]]:
    """Retrieve videos with a scheduled_publish_at within the time window.

    Uses ByOwnerCreatedAt GSI, then client-side filter for
    scheduled_publish_at in range.
    """
    from app.services.video_metadata_store import list_videos_by_owner

    result = list_videos_by_owner(user_id, limit=200)
    videos = result.get("items", [])

    scheduled = []
    for v in videos:
        spa = getattr(v, "scheduled_publish_at", None)
        if spa is not None and from_ts <= spa <= to_ts:
            scheduled.append({
                "video_id": v.id,
                "title": v.title,
                "scheduled_publish_at": spa,
                "duration_seconds": v.duration_seconds,
                "thumbnail_url": v.thumbnail_url,
                "status": v.status,
                "visibility": v.visibility,
            })
    return scheduled


# ─── Normalization ──────────────────────────────────────────────

def _truncate(text: str, max_len: int = 60) -> str:
    """Truncate a string to max_len, adding ellipsis if needed."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _post_to_calendar_item(post: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a scheduled post DDB item to a calendar item dict."""
    publish_at = int(post.get("publish_at", 0))
    now = now_ts()
    is_overdue = publish_at < now

    return {
        "id": post.get("post_id", ""),
        "type": "post",
        "title": _truncate(post.get("body_plain") or post.get("body", "") or "Untitled Post", 60),
        "scheduled_at": publish_at,
        "timezone": post.get("schedule_timezone"),
        "local_time": post.get("scheduled_at_local"),
        "status": "overdue" if is_overdue else post.get("status", "scheduled"),
        "color": CONTENT_COLORS["post"],
        "icon": CONTENT_ICONS["post"],
        "has_images": bool(post.get("image_urls")),
        "has_video": bool(post.get("video")),
        "visibility": post.get("visibility", "followers"),
        "locked": bool(post.get("locked")),
        "unlock_price_cents": int(post["unlock_price_cents"]) if post.get("unlock_price_cents") is not None else 0,
    }


def _broadcast_to_calendar_item(session: Any) -> Dict[str, Any]:
    """Convert a BroadcastSessionModel to a calendar item dict."""
    scheduled_at = session.scheduled_at or 0
    now = now_ts()
    is_overdue = scheduled_at < now

    return {
        "id": session.id,
        "type": "broadcast",
        "title": session.name or f"Broadcast {session.id[:8]}",
        "scheduled_at": scheduled_at,
        "timezone": None,
        "local_time": None,
        "status": "overdue" if is_overdue else (session.schedule_status or "scheduled"),
        "color": CONTENT_COLORS["broadcast"],
        "icon": CONTENT_ICONS["broadcast"],
        "description": session.description,
        "profile_id": session.profile_id,
        "has_announcement": bool(getattr(session, "announcement_post_id", None)),
    }


def _vod_to_calendar_item(video: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a scheduled VOD dict to a calendar item dict."""
    scheduled_at = int(video.get("scheduled_publish_at", 0))
    now = now_ts()
    is_overdue = scheduled_at < now

    return {
        "id": video["video_id"],
        "type": "vod",
        "title": video.get("title", "Untitled Video"),
        "scheduled_at": scheduled_at,
        "timezone": None,
        "local_time": None,
        "status": "overdue" if is_overdue else "scheduled",
        "color": CONTENT_COLORS["vod"],
        "icon": CONTENT_ICONS["vod"],
        "duration_seconds": video.get("duration_seconds"),
        "thumbnail_url": video.get("thumbnail_url"),
    }


# ─── Aggregation ────────────────────────────────────────────────

def get_content_calendar(
    user_id: str,
    from_ts: int,
    to_ts: int,
    type_filter: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    """Aggregate all scheduled content for a creator within a time range.

    Returns a dict with items sorted by scheduled_at, plus conflict data.
    """
    if to_ts - from_ts > MAX_RANGE_SECONDS:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail=f"Time range exceeds maximum of {MAX_RANGE_SECONDS // 86400} days",
        )

    types = type_filter or {"post", "broadcast", "vod"}
    items: List[Dict[str, Any]] = []

    if "post" in types:
        posts = _get_scheduled_posts(user_id, from_ts, to_ts)
        items.extend(_post_to_calendar_item(p) for p in posts)

    if "broadcast" in types:
        broadcasts = _get_scheduled_broadcasts(user_id, from_ts, to_ts)
        items.extend(_broadcast_to_calendar_item(b) for b in broadcasts)

    if "vod" in types:
        vod_items = _get_scheduled_vod(user_id, from_ts, to_ts)
        items.extend(_vod_to_calendar_item(v) for v in vod_items)

    items.sort(key=lambda x: x["scheduled_at"])

    conflicts = detect_conflicts(items)

    return {
        "items": items,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "count": len(items),
        "conflicts": conflicts,
    }


# ─── Conflict Detection ────────────────────────────────────────

def detect_conflicts(
    items: List[Dict[str, Any]],
    buffer_minutes: int = CONFLICT_BUFFER_MINUTES,
) -> List[Dict[str, Any]]:
    """Find items that are scheduled too close together.

    Two items conflict if they are scheduled within buffer_minutes of
    each other. Returns a list of conflict dicts describing each pair.
    """
    conflicts: List[Dict[str, Any]] = []
    sorted_items = sorted(items, key=lambda x: x["scheduled_at"])
    buffer_seconds = buffer_minutes * 60

    for i in range(len(sorted_items) - 1):
        a = sorted_items[i]
        b = sorted_items[i + 1]
        gap = b["scheduled_at"] - a["scheduled_at"]
        if gap < buffer_seconds:
            conflicts.append({
                "item_a_id": a["id"],
                "item_a_type": a["type"],
                "item_b_id": b["id"],
                "item_b_type": b["type"],
                "gap_seconds": gap,
                "gap_minutes": round(gap / 60, 1),
            })
    return conflicts


# ─── Today's Agenda ─────────────────────────────────────────────

def get_today_agenda(user_id: str) -> Dict[str, Any]:
    """Get scheduled content for today and tomorrow.

    Convenience method for the mobile agenda view.
    Returns items partitioned into 'today' and 'tomorrow' lists.
    """
    from datetime import datetime, timezone, timedelta

    now_dt = datetime.now(timezone.utc)
    today_start = int(now_dt.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    tomorrow_end = int((now_dt + timedelta(days=2)).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())

    result = get_content_calendar(user_id, today_start, tomorrow_end)
    items = result["items"]

    today_end = today_start + 86400
    today_items = [i for i in items if i["scheduled_at"] < today_end]
    tomorrow_items = [i for i in items if today_end <= i["scheduled_at"] < tomorrow_end]

    return {
        "today": today_items,
        "tomorrow": tomorrow_items,
        "today_count": len(today_items),
        "tomorrow_count": len(tomorrow_items),
        "conflicts": result["conflicts"],
    }


# ─── Reschedule Dispatch ───────────────────────────────────────

def reschedule_item(
    user_id: str,
    item_id: str,
    item_type: str,
    new_scheduled_at: int,
) -> Dict[str, Any]:
    """Dispatch a reschedule request to the appropriate content system.

    Validates ownership and constraints for each content type.
    Returns the updated item as a calendar item dict.
    """
    now = now_ts()
    if new_scheduled_at <= now:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail="Cannot schedule content in the past",
        )

    if item_type == "post":
        return _reschedule_post(user_id, item_id, new_scheduled_at)
    elif item_type == "broadcast":
        return _reschedule_broadcast(user_id, item_id, new_scheduled_at)
    elif item_type == "vod":
        return _reschedule_vod(user_id, item_id, new_scheduled_at)
    else:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unknown item type: {item_type}")


def _reschedule_post(user_id: str, post_id: str, new_ts: int) -> Dict[str, Any]:
    """Reschedule a newsfeed post by updating publish_at.

    Updates:
    1. The post record (publish_at, GSI_SCHEDULE_SK)
    2. The ScheduledPostRef record (delete old, write new)
    """
    from fastapi import HTTPException

    tbl = ddb.Table(APP_TABLE)
    post = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    if str(post.get("status", "")).strip().lower() != "scheduled":
        raise HTTPException(status_code=409, detail="Post is not in scheduled status")

    old_publish_at = int(post.get("publish_at", 0))

    # Update the post record
    new_schedule_sk = f"{new_ts:012d}#POST#{post_id}"
    tbl.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression="SET publish_at = :new_ts, GSI_SCHEDULE_SK = :new_sk, updated_at = :now",
        ExpressionAttributeValues={
            ":new_ts": new_ts,
            ":new_sk": new_schedule_sk,
            ":now": now_ts(),
        },
    )

    # Delete old ScheduledPostRef, write new one
    old_ref_sk = f"SCHEDULEDPOST#{old_publish_at:012d}#{post_id}"
    new_ref_sk = f"SCHEDULEDPOST#{new_ts:012d}#{post_id}"
    try:
        tbl.delete_item(Key={"pk": f"USER#{user_id}", "sk": old_ref_sk})
    except Exception:
        logger.warning("Failed to delete old ScheduledPostRef", extra={"post_id": post_id})

    tbl.put_item(Item={
        "pk": f"USER#{user_id}",
        "sk": new_ref_sk,
        "Entity": "ScheduledPostRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "status": "scheduled",
        "publish_at": new_ts,
        "schedule_timezone": post.get("schedule_timezone"),
        "scheduled_at_local": None,  # clear since time changed
        "created_at": post.get("created_at"),
    })

    # Return updated calendar item
    post["publish_at"] = new_ts
    return _post_to_calendar_item(post)


def _reschedule_broadcast(user_id: str, session_id: str, new_ts: int) -> Dict[str, Any]:
    """Reschedule a broadcast session via the broadcast store."""
    from app.services.broadcast_store import get_session, update_session_fields
    from app.services.broadcast_reminders import cancel_reminders_for_session
    from fastapi import HTTPException

    session = get_session(session_id)
    if session.created_by != user_id:
        raise HTTPException(status_code=403, detail="Not your broadcast")
    if session.schedule_status != "scheduled":
        raise HTTPException(status_code=409, detail="Broadcast is not in scheduled status")

    # Enforce minimum lead time
    min_lead = S.broadcast_schedule_min_lead_time_seconds
    now = now_ts()
    if new_ts < now + min_lead:
        raise HTTPException(
            status_code=400,
            detail=f"scheduled_at must be at least {min_lead} seconds in the future",
        )

    cancel_reminders_for_session(session_id)
    updated = update_session_fields(session_id, {"scheduled_at": new_ts})
    return _broadcast_to_calendar_item(updated)


def _reschedule_vod(user_id: str, video_id: str, new_ts: int) -> Dict[str, Any]:
    """Reschedule a VOD release by updating scheduled_publish_at."""
    from app.services.video_metadata_store import get_video
    from fastapi import HTTPException

    video = get_video(video_id)
    if video.owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="Not your video")

    spa = getattr(video, "scheduled_publish_at", None)
    if spa is None:
        raise HTTPException(status_code=409, detail="Video does not have a scheduled publish time")

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET scheduled_publish_at = :ts, updated_at = :now",
        ExpressionAttributeValues={":ts": new_ts, ":now": now_ts()},
    )

    return _vod_to_calendar_item({
        "video_id": video_id,
        "title": video.title,
        "scheduled_publish_at": new_ts,
        "duration_seconds": video.duration_seconds,
        "thumbnail_url": video.thumbnail_url,
        "status": video.status,
        "visibility": video.visibility,
    })


# ─── Cancel Dispatch ────────────────────────────────────────────

def cancel_item(
    user_id: str,
    item_id: str,
    item_type: str,
) -> Dict[str, str]:
    """Cancel a scheduled content item.

    Dispatches to the appropriate cancel logic for the content type.
    """
    if item_type == "post":
        return _cancel_post(user_id, item_id)
    elif item_type == "broadcast":
        return _cancel_broadcast(user_id, item_id)
    elif item_type == "vod":
        return _cancel_vod(user_id, item_id)
    else:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unknown item type: {item_type}")


def _cancel_post(user_id: str, post_id: str) -> Dict[str, str]:
    """Cancel a scheduled post."""
    from fastapi import HTTPException

    tbl = ddb.Table(APP_TABLE)
    post = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "META"}).get("Item")
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Not your post")
    if str(post.get("status", "")).strip().lower() != "scheduled":
        raise HTTPException(status_code=409, detail="Post is not in scheduled status")

    publish_at = int(post.get("publish_at", 0))

    # Update status to cancelled, remove GSI attrs
    tbl.update_item(
        Key={"pk": f"POST#{post_id}", "sk": "META"},
        UpdateExpression=(
            "SET #status = :cancelled, updated_at = :now "
            "REMOVE publish_at, schedule_timezone, scheduled_at_local, "
            "GSI_SCHEDULE_PK, GSI_SCHEDULE_SK"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":cancelled": "cancelled",
            ":now": now_ts(),
        },
    )

    # Delete ScheduledPostRef
    ref_sk = f"SCHEDULEDPOST#{publish_at:012d}#{post_id}"
    try:
        tbl.delete_item(Key={"pk": f"USER#{user_id}", "sk": ref_sk})
    except Exception:
        logger.warning("Failed to delete ScheduledPostRef on cancel", extra={"post_id": post_id})

    return {"ok": "true", "id": post_id, "type": "post"}


def _cancel_broadcast(user_id: str, session_id: str) -> Dict[str, str]:
    """Cancel a scheduled broadcast."""
    from app.services.broadcast_store import get_session, transition_session_status, now_iso
    from app.services.broadcast_reminders import cancel_reminders_for_session
    from fastapi import HTTPException

    session = get_session(session_id)
    if session.created_by != user_id:
        raise HTTPException(status_code=403, detail="Not your broadcast")
    if session.schedule_status != "scheduled":
        raise HTTPException(status_code=409, detail="Broadcast is not in scheduled status")

    cancel_reminders_for_session(session_id)
    transition_session_status(
        session_id=session_id,
        to_status="cancelled",
        reason="calendar-cancel",
        actor=user_id,
        extra_fields={
            "schedule_status": "cancelled",
            "cancelled_at": now_iso(),
        },
    )
    return {"ok": "true", "id": session_id, "type": "broadcast"}


def _cancel_vod(user_id: str, video_id: str) -> Dict[str, str]:
    """Cancel a scheduled VOD release (remove scheduled_publish_at)."""
    from app.services.video_metadata_store import get_video
    from fastapi import HTTPException

    video = get_video(video_id)
    if video.owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="Not your video")

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="REMOVE scheduled_publish_at SET updated_at = :now",
        ExpressionAttributeValues={":now": now_ts()},
    )
    return {"ok": "true", "id": video_id, "type": "vod"}
