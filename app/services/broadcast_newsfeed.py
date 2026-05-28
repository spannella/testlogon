"""Broadcast newsfeed promotion -- auto-create/update/delete posts on broadcast lifecycle events.

BCAST-010: When a broadcast is scheduled, goes live, or has a recording ready, this module
creates corresponding newsfeed posts. When a scheduled broadcast is cancelled, the
announcement post is deleted.

All operations are non-fatal: broadcast lifecycle events succeed even if post creation fails.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Key

from app.core.aws import ddb
from app.core.time import now_ts

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)


def _pk_post(post_id: str) -> str:
    return f"POST#{post_id}"


def _write_broadcast_post(
    *,
    post_id: str,
    user_id: str,
    text: str,
    post_type: str,
    broadcast_meta: Dict[str, Any],
    image_url: Optional[str] = None,
    visibility: str = "public",
    created_at_ts: Optional[int] = None,
) -> None:
    """Write a broadcast post item + feed reference to DDB.

    Follows the same schema as _write_feed_ref_for_published_post() and
    the post item write in create_post() (newsfeed.py).
    """
    ts = created_at_ts or now_ts()
    created_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    # 1. Write post item
    post_item: Dict[str, Any] = {
        "pk": _pk_post(post_id),
        "sk": "META",
        "Entity": "Post",
        "post_id": post_id,
        "user_id": user_id,
        "text": text,
        "body": text,
        "body_plain": text,
        "body_format": "plain",
        "post_type": post_type,
        "broadcast_meta": broadcast_meta,
        "visibility": visibility,
        "status": "published",
        "published_at": created_at,
        "created_at": created_at,
        "updated_at": created_at,
        "like_count": 0,
        "comment_count": 0,
        # GSI2: author index
        "GSI2PK": f"POST_AUTHOR#{user_id}",
        "GSI2SK": f"{created_at}#POST#{post_id}",
    }
    if image_url:
        post_item["image_url"] = image_url
        post_item["image_urls"] = [image_url]

    tbl.put_item(Item=post_item)

    # 2. Write author's feed reference
    feed_ref = {
        "pk": _pk_post(post_id),
        "sk": f"FEEDREF#{user_id}",
        "Entity": "FeedRef",
        "post_id": post_id,
        "owner_user_id": user_id,
        "created_at": created_at,
        "GSI1PK": f"FEED#{user_id}",
        "GSI1SK": f"{created_at}#POST#{post_id}",
    }
    tbl.put_item(Item=feed_ref)

    # 3. Fan-out to followers (SOC-002)
    try:
        from app.services.newsfeed_fanout import fan_out_post_to_followers

        fan_out_post_to_followers(
            author_id=user_id,
            post_id=post_id,
            created_at=created_at,
        )
    except Exception:
        logger.exception("Fan-out failed for broadcast post %s (non-fatal)", post_id)


def _update_broadcast_post(
    *,
    post_id: str,
    user_id: str,
    text: str,
    post_type: str,
    broadcast_meta: Dict[str, Any],
) -> None:
    """Update an existing broadcast post (e.g., announcement -> live).

    Only updates text, post_type, broadcast_meta, and updated_at.
    Feed references are not modified (post remains in the same feed position).
    """
    updated_at = datetime.now(timezone.utc).isoformat()

    tbl.update_item(
        Key={"pk": _pk_post(post_id), "sk": "META"},
        UpdateExpression="SET #text = :text, body = :text, body_plain = :text, post_type = :pt, broadcast_meta = :bm, updated_at = :ua",
        ExpressionAttributeNames={"#text": "text"},
        ExpressionAttributeValues={
            ":text": text,
            ":pt": post_type,
            ":bm": broadcast_meta,
            ":ua": updated_at,
        },
    )


def _delete_broadcast_post_item(*, post_id: str) -> None:
    """Delete a broadcast post and its feed references."""
    # Delete post item
    tbl.delete_item(Key={"pk": _pk_post(post_id), "sk": "META"})

    # Delete all FEEDREF items (author + fan-out)
    try:
        from app.services.newsfeed_fanout import fan_out_delete_post

        fan_out_delete_post(post_id=post_id)
    except Exception:
        logger.exception("Failed to delete fan-out refs for broadcast post %s", post_id)


# ─── Public API ────────────────────────────────────────────────────


def create_announcement_post(
    *,
    session_id: str,
    creator_id: str,
    session_name: Optional[str] = None,
    session_description: Optional[str] = None,
    thumbnail_url: Optional[str] = None,
    scheduled_at: Optional[int] = None,
    visibility: str = "public",
) -> Optional[str]:
    """Create a 'broadcast_announcement' post when a session is scheduled.

    Returns the post_id of the created post, or None on failure.
    """
    post_id = f"bcast_{uuid.uuid4().hex[:16]}"
    ts_now = now_ts()

    # Build human-readable text
    name = session_name or "Broadcast"
    if scheduled_at:
        dt = datetime.fromtimestamp(scheduled_at, tz=timezone.utc)
        time_str = dt.strftime("%B %d, %Y at %I:%M %p UTC")
        text = f"Upcoming broadcast: {name}\n\nScheduled for {time_str}"
    else:
        text = f"New broadcast: {name}"

    if session_description:
        text += f"\n\n{session_description}"

    broadcast_meta = {
        "session_id": session_id,
        "post_type": "broadcast_announcement",
        "session_name": name,
        "session_description": session_description,
        "thumbnail_url": thumbnail_url,
        "scheduled_at": scheduled_at,
        "is_live": False,
        "broadcast_url": f"/broadcast/{session_id}",
    }

    try:
        _write_broadcast_post(
            post_id=post_id,
            user_id=creator_id,
            text=text,
            post_type="broadcast_announcement",
            broadcast_meta=broadcast_meta,
            image_url=thumbnail_url,
            visibility=visibility,
            created_at_ts=ts_now,
        )
        logger.info("Created broadcast announcement post %s for session %s", post_id, session_id)
        return post_id
    except Exception:
        logger.exception("Failed to create announcement post for session %s", session_id)
        return None


def create_live_post(
    *,
    session_id: str,
    creator_id: str,
    announcement_post_id: Optional[str] = None,
    session_name: Optional[str] = None,
    session_description: Optional[str] = None,
    thumbnail_url: Optional[str] = None,
) -> Optional[str]:
    """Create a 'broadcast_live' post when a session goes live.

    If an announcement_post_id exists, update that post to show "LIVE NOW".
    Otherwise, create a new post.

    Returns the post_id (new or existing).
    """
    name = session_name or "Broadcast"
    text = f"LIVE NOW: {name}\n\nWatch live now!"
    if session_description:
        text += f"\n\n{session_description}"

    broadcast_meta = {
        "session_id": session_id,
        "post_type": "broadcast_live",
        "session_name": name,
        "session_description": session_description,
        "thumbnail_url": thumbnail_url,
        "is_live": True,
        "broadcast_url": f"/broadcast/{session_id}",
    }

    try:
        if announcement_post_id:
            _update_broadcast_post(
                post_id=announcement_post_id,
                user_id=creator_id,
                text=text,
                post_type="broadcast_live",
                broadcast_meta=broadcast_meta,
            )
            logger.info("Updated announcement post %s to live for session %s", announcement_post_id, session_id)
            return announcement_post_id
        else:
            post_id = f"bcast_{uuid.uuid4().hex[:16]}"
            _write_broadcast_post(
                post_id=post_id,
                user_id=creator_id,
                text=text,
                post_type="broadcast_live",
                broadcast_meta=broadcast_meta,
                image_url=thumbnail_url,
                visibility="public",
                created_at_ts=now_ts(),
            )
            logger.info("Created live post %s for session %s", post_id, session_id)
            return post_id
    except Exception:
        logger.exception("Failed to create/update live post for session %s", session_id)
        return None


def create_vod_post(
    *,
    session_id: str,
    creator_id: str,
    session_name: Optional[str] = None,
    recording_id: Optional[str] = None,
    recording_duration_seconds: Optional[float] = None,
    recording_playback_url: Optional[str] = None,
    peak_viewer_count: Optional[int] = None,
    thumbnail_url: Optional[str] = None,
) -> Optional[str]:
    """Create a 'broadcast_vod' post when a recording is ready.

    Returns the post_id of the VOD post, or None on failure.
    """
    name = session_name or "Broadcast"
    parts = [f"Watch recording: {name}"]

    if recording_duration_seconds:
        hours = int(recording_duration_seconds // 3600)
        minutes = int((recording_duration_seconds % 3600) // 60)
        if hours > 0:
            parts.append(f"Duration: {hours}h {minutes}m")
        else:
            parts.append(f"Duration: {minutes}m")

    if peak_viewer_count:
        parts.append(f"{peak_viewer_count:,} live viewers")

    text = "\n".join(parts)

    broadcast_meta = {
        "session_id": session_id,
        "post_type": "broadcast_vod",
        "session_name": name,
        "thumbnail_url": thumbnail_url,
        "recording_id": recording_id,
        "recording_duration_seconds": recording_duration_seconds,
        "recording_playback_url": recording_playback_url,
        "peak_viewer_count": peak_viewer_count,
        "is_live": False,
        "broadcast_url": f"/broadcast/{session_id}",
    }

    try:
        post_id = f"bcast_vod_{uuid.uuid4().hex[:12]}"
        _write_broadcast_post(
            post_id=post_id,
            user_id=creator_id,
            text=text,
            post_type="broadcast_vod",
            broadcast_meta=broadcast_meta,
            image_url=thumbnail_url,
            visibility="public",
            created_at_ts=now_ts(),
        )
        logger.info("Created VOD post %s for session %s", post_id, session_id)
        return post_id
    except Exception:
        logger.exception("Failed to create VOD post for session %s", session_id)
        return None


def delete_broadcast_post(
    *,
    post_id: str,
    user_id: str,
) -> bool:
    """Delete the announcement post when a broadcast is cancelled.

    Uses fan_out_delete_post to clean up all FEEDREF items.
    """
    try:
        _delete_broadcast_post_item(post_id=post_id)
        logger.info("Deleted broadcast post %s", post_id)
        return True
    except Exception:
        logger.exception("Failed to delete broadcast post %s", post_id)
        return False
