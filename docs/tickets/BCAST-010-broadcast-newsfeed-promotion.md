# BCAST-010: Broadcast Newsfeed Promotion — Auto-Post Announcements for Scheduled and Live Broadcasts

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-27  
**Priority**: High  
**Estimated effort**: 5-7 days

---

## 1. Overview & Motivation

### The Gap

The broadcast system (BCAST-001 through BCAST-009) handles session lifecycle, streaming, recording, product shelves, and scheduling. The newsfeed system (`app/routers/newsfeed.py`, 4000+ lines) handles posts with text, images, video, locking, tipping, reactions, and fan-out to followers (SOC-002). However, **there is no integration between broadcast lifecycle events and the newsfeed**. When a creator schedules or starts a broadcast, no newsfeed post is created. Viewers must independently discover broadcasts through the broadcast dashboard, which has no organic discovery path via the social feed.

### Why This Is Needed

1. **Viewer discovery via feed**: The newsfeed is the primary content surface. If broadcasts don't appear in the feed, they are invisible to followers who aren't actively checking the broadcast dashboard.
2. **Fan-out amplification**: With SOC-002 feed fan-out, a broadcast announcement post automatically appears in all followers' feeds — the same mechanism that surfaces regular posts.
3. **Engagement lifecycle**: Three distinct moments drive viewership:
   - **Scheduled**: "This is happening at X time" — drives calendar adds and reminders
   - **Live**: "This is happening NOW" — drives immediate tune-in
   - **VOD available**: "Watch the recording" — captures viewers who missed the live event
4. **Content reuse**: Broadcast announcements with thumbnails, descriptions, and CTAs serve as evergreen content in the feed even after the broadcast ends.
5. **Creator convenience**: Manually creating separate newsfeed posts for each broadcast is tedious and error-prone. Auto-posting ensures consistent promotion without extra creator effort.

### Architecture After This Change

```
Broadcast Lifecycle → Newsfeed Integration

  Session Created                    Session Goes Live               Session Stopped + Recording
  (with scheduled_at)               (status → "live")                (BCAST-006 complete)
       |                                  |                                |
       v                                  v                                v
  +------------------+            +------------------+            +------------------+
  | create_post()    |            | update_post()    |            | create_post()    |
  | type:            |            | OR create_post() |            | type:            |
  | broadcast_       |            | type:            |            | broadcast_vod    |
  | announcement     |            | broadcast_live   |            |                  |
  +--------+---------+            +--------+---------+            +--------+---------+
           |                               |                               |
           v                               v                               v
  +------------------+            +------------------+            +------------------+
  | fan_out_post_to_ |            | fan_out or       |            | fan_out_post_to_ |
  | followers()      |            | update existing  |            | followers()      |
  | (SOC-002)        |            | fan-out refs     |            | (SOC-002)        |
  +------------------+            +------------------+            +------------------+
           |                               |                               |
           v                               v                               v
  ┌──────────────────┐            ┌──────────────────┐            ┌──────────────────┐
  │ Follower Feeds   │            │ Follower Feeds   │            │ Follower Feeds   │
  │                  │            │                  │            │                  │
  │ ┌──────────────┐ │            │ ┌──────────────┐ │            │ ┌──────────────┐ │
  │ │ Announcement │ │            │ │  LIVE NOW    │ │            │ │ Watch        │ │
  │ │ Card         │ │            │ │  Badge       │ │            │ │ Recording    │ │
  │ │              │ │            │ │              │ │            │ │              │ │
  │ │ 📅 May 27    │ │            │ │ 🔴 Watch Now │ │            │ │ ⏱ 1h 23m     │ │
  │ │ Set Reminder │ │            │ │              │ │            │ │ 1.2K viewers │ │
  │ └──────────────┘ │            │ └──────────────┘ │            │ └──────────────┘ │
  └──────────────────┘            └──────────────────┘            └──────────────────┘
```

---

## 2. Current State Analysis

### 2.1 Newsfeed Post Creation (`app/routers/newsfeed.py`)

The `create_post()` function (at line 2863) handles post creation with fields including `text`, `image_url`, `video_url`, `visibility`, `lock_price_cents`, and `send_at` (for scheduling). Posts are stored in `app_single_table` with `PK=POST#{post_id}`, `SK=POST`. The function writes:

1. Post item with `GSI2PK=POST_AUTHOR#{user_id}`
2. Feed reference via `_write_feed_ref_for_published_post()` with `GSI1PK=FEED#{user_id}`
3. Fan-out refs via `fan_out_post_to_followers()` from `app/services/newsfeed_fanout.py` (SOC-002)

The existing post model does **not** have a `post_type` field — a grep for `post_type` in `app/routers/newsfeed.py` returns zero results. This field must be **added** as part of this ticket (or as a prerequisite). There are no broadcast-specific post types.

> **Corrected**: The original text claimed `post_type` already exists on the post model. This is wrong — the field does not exist in `app/routers/newsfeed.py` and must be added as a new attribute on post items.

### 2.2 Feed Fan-Out (`app/services/newsfeed_fanout.py`)

The `fan_out_post_to_followers()` function queries GSI5 for `FOLLOWERS#{author_id}` and writes `FEEDREF` items for each follower with `GSI1PK=FEED#{follower_id}`. This is the mechanism that ensures broadcast announcements appear in follower feeds.

### 2.3 Post Rendering (`frontend/src/pages/feed/PostCard.tsx`)

`PostCard` renders posts based on their content. It handles text, images, video, locked content, tips, reactions, and comments. There is no broadcast-specific rendering — no countdown timers, live badges, or "Watch Now" CTAs. A new `BroadcastAnnouncementCard` component (or conditional rendering within `PostCard`) is needed.

### 2.4 Broadcast Session Model (`app/models_broadcast.py`)

From BCAST-009, the session model gains:
- `scheduled_at: Optional[int]` — Unix timestamp of scheduled start
- `name: Optional[str]` — Session name/title
- `description: Optional[str]` — Session description
- `thumbnail_url: Optional[str]` — Thumbnail image URL
- `announcement_post_id: Optional[str]` — Newsfeed post ID (this ticket uses this field)

### 2.5 Broadcast Orchestrator (`app/services/broadcast_orchestrator.py`)

The orchestrator manages state transitions:
- `start_session_with_provider()`: `draft -> provisioning -> ready -> live`
- `stop_session_with_provider()`: `live -> stopping -> stopped`

Both functions are the integration points for auto-posting. After `start_session_with_provider()` transitions to `"live"`, a live announcement post should be created or the existing announcement post should be updated. After `stop_session_with_provider()` triggers recording creation (BCAST-006), a VOD post should be created when the recording is ready.

### 2.6 Broadcast Recording Worker (`app/services/broadcast_recording_worker.py`)

The recording worker processes recordings after a session stops. When `process_recording()` completes and the recording status is `"ready"`, this is the trigger point for the VOD announcement post.

### 2.7 Broadcast Store (`app/services/broadcast_store.py`)

`session_to_item()` and `session_from_item()` persist and read session fields. The `announcement_post_id` field (added by BCAST-009) stores the link between the session and its newsfeed post.

### 2.8 Post Types in DynamoDB

Posts in `app_single_table` use `PK=POST#{post_id}`, `SK=POST`. The post item does **not** currently have a `post_type` attribute — this field must be added as part of this ticket. Once added, new broadcast-specific `post_type` values can be stored without DDB schema changes (DynamoDB is schemaless for non-key attributes).

> **Corrected**: The original text stated the `post_type` attribute "is currently either absent (defaults to 'text') or 'image' / 'video'". This is wrong — `post_type` does not exist anywhere in the current newsfeed code. It must be added as a new field.

---

## 3. Technical Design

### 3.1 New Post Types

Three new `post_type` values:

| Post Type | Created When | Content |
|-----------|-------------|---------|
| `broadcast_announcement` | Session transitions to `"scheduled"` (BCAST-009) | Session name, description, thumbnail, scheduled time, "Set Reminder" CTA |
| `broadcast_live` | Session transitions to `"live"` | Session name, "LIVE NOW" badge, "Watch Now" CTA, viewer count |
| `broadcast_vod` | Recording reaches `"ready"` status (BCAST-006) | Session name, recording duration, viewer count from live, "Watch Recording" CTA |

All three types are stored as regular newsfeed posts with additional metadata. They appear in the feed alongside regular text/image/video posts. The creator can edit or delete them like any other post.

### 3.2 Post Metadata Schema

Each broadcast post includes a `broadcast_meta` JSON field on the post item:

```python
class BroadcastPostMeta(BaseModel):
    """Metadata stored on a newsfeed post linked to a broadcast session."""
    session_id: str
    post_type: Literal["broadcast_announcement", "broadcast_live", "broadcast_vod"]
    session_name: Optional[str] = None
    session_description: Optional[str] = None
    thumbnail_url: Optional[str] = None
    scheduled_at: Optional[int] = None
    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    recording_id: Optional[str] = None
    recording_duration_seconds: Optional[float] = None
    recording_playback_url: Optional[str] = None
    peak_viewer_count: Optional[int] = None
    is_live: bool = False
    broadcast_url: Optional[str] = None  # /broadcast/{session_id}
```

This metadata is stored as a map attribute on the post DDB item under the key `broadcast_meta`. It is included in the post response and used by the frontend to render broadcast-specific UI.

### 3.3 Service Layer — `app/services/broadcast_newsfeed.py`

New file implementing the integration logic:

```python
"""Broadcast newsfeed promotion — auto-create/update posts on broadcast lifecycle events."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.core.time import now_ts

logger = logging.getLogger(__name__)


def create_broadcast_announcement_post(
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
    The post_id is stored on the broadcast session as `announcement_post_id`.
    """
    import uuid
    from datetime import datetime, timezone

    post_id = f"bcast_{uuid.uuid4().hex[:16]}"
    ts_now = now_ts()

    # Build human-readable text
    name = session_name or "Broadcast"
    if scheduled_at:
        dt = datetime.fromtimestamp(scheduled_at, tz=timezone.utc)
        time_str = dt.strftime("%B %d, %Y at %I:%M %p UTC")
        text = f"📅 Upcoming broadcast: {name}\n\nScheduled for {time_str}"
    else:
        text = f"📡 New broadcast: {name}"

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
        from app.services.broadcast_newsfeed_writer import write_broadcast_post
        write_broadcast_post(
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


def create_or_update_live_post(
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
    import uuid

    name = session_name or "Broadcast"
    text = f"🔴 LIVE NOW: {name}\n\nWatch live now!"
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
            from app.services.broadcast_newsfeed_writer import update_broadcast_post
            update_broadcast_post(
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
            from app.services.broadcast_newsfeed_writer import write_broadcast_post
            write_broadcast_post(
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

    Returns the post_id of the VOD post.
    """
    import uuid

    name = session_name or "Broadcast"
    parts = [f"📹 Watch recording: {name}"]

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
        from app.services.broadcast_newsfeed_writer import write_broadcast_post
        write_broadcast_post(
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


def delete_announcement_post(
    *,
    post_id: str,
    user_id: str,
) -> bool:
    """Delete the announcement post when a broadcast is cancelled.

    Uses the existing newsfeed post deletion mechanism.
    """
    try:
        from app.services.broadcast_newsfeed_writer import delete_broadcast_post
        delete_broadcast_post(post_id=post_id, user_id=user_id)
        logger.info("Deleted announcement post %s", post_id)
        return True
    except Exception:
        logger.exception("Failed to delete announcement post %s", post_id)
        return False
```

### 3.4 Post Writer — `app/services/broadcast_newsfeed_writer.py`

New file that interfaces with the newsfeed DDB tables directly, following the same patterns as `create_post()` in the newsfeed router:

```python
"""Low-level DDB writer for broadcast newsfeed posts.

Follows the same DDB item schema as create_post() in app/routers/newsfeed.py:
  PK=POST#{post_id}, SK=POST
  GSI1PK=FEED#{user_id}, GSI1SK={created_at}#POST#{post_id}
  GSI2PK=POST_AUTHOR#{user_id}, GSI2SK={created_at}#POST#{post_id}
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Key

from app.core.aws import ddb
from app.core.time import now_ts

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")
tbl = ddb.Table(APP_TABLE)


def pk_post(post_id: str) -> str:
    return f"POST#{post_id}"


def write_broadcast_post(
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
    the post item write in create_post() (newsfeed.py ~line 3076).
    """
    ts = created_at_ts or now_ts()
    created_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    # 1. Write post item
    post_item: Dict[str, Any] = {
        "pk": pk_post(post_id),
        "sk": "POST",
        "Entity": "Post",
        "post_id": post_id,
        "user_id": user_id,
        "text": text,
        "post_type": post_type,
        "broadcast_meta": broadcast_meta,
        "visibility": visibility,
        "status": "published",
        "created_at": created_at,
        "updated_at": created_at,
        # GSI2: author index
        "GSI2PK": f"POST_AUTHOR#{user_id}",
        "GSI2SK": f"{created_at}#POST#{post_id}",
    }
    if image_url:
        post_item["image_url"] = image_url

    tbl.put_item(Item=post_item)

    # 2. Write author's feed reference
    feed_ref = {
        "pk": pk_post(post_id),
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


def update_broadcast_post(
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
        Key={"pk": pk_post(post_id), "sk": "POST"},
        UpdateExpression="SET #text = :text, post_type = :pt, broadcast_meta = :bm, updated_at = :ua",
        ExpressionAttributeNames={"#text": "text"},
        ExpressionAttributeValues={
            ":text": text,
            ":pt": post_type,
            ":bm": broadcast_meta,
            ":ua": updated_at,
        },
    )


def delete_broadcast_post(*, post_id: str, user_id: str) -> None:
    """Delete a broadcast post and its feed references.

    Follows the same pattern as the newsfeed post delete handler:
    removes the post item and all FEEDREF items under POST#{post_id}.
    """
    # Delete post item
    tbl.delete_item(Key={"pk": pk_post(post_id), "sk": "POST"})

    # Delete all FEEDREF items (author + fan-out)
    try:
        from app.services.newsfeed_fanout import fan_out_delete_post
        fan_out_delete_post(post_id=post_id)
    except Exception:
        logger.exception("Failed to delete fan-out refs for broadcast post %s", post_id)

    # > **Corrected**: The original code passed `author_id=user_id` to `fan_out_delete_post()`.
    # The actual signature is `def fan_out_delete_post(*, post_id: str) -> int:` —
    # it takes only `post_id`. Passing `author_id` would cause a TypeError.
```

### 3.5 Integration Points — Lifecycle Hooks

#### 3.5.1 On Schedule (BCAST-009 `create_session_route`)

In `app/routers/broadcast.py`, after transitioning session to `"scheduled"`:

```python
# After transition to "scheduled" status
if session.scheduled_at:
    from app.services.broadcast_newsfeed import create_broadcast_announcement_post
    announcement_post_id = create_broadcast_announcement_post(
        session_id=session.id,
        creator_id=ctx["user_sub"],
        session_name=body.name,
        session_description=body.description,
        thumbnail_url=None,  # Thumbnail set later
        scheduled_at=session.scheduled_at,
    )
    if announcement_post_id:
        # Store post_id on session for lifecycle tracking
        T.broadcast_sessions.update_item(
            Key={"session_id": session.id},
            UpdateExpression="SET announcement_post_id = :pid",
            ExpressionAttributeValues={":pid": announcement_post_id},
        )
```

#### 3.5.2 On Go-Live (`start_session_with_provider`)

In `app/services/broadcast_orchestrator.py`, after transitioning to `"live"`:

```python
# After: current = transition_session_status(session_id, to_status="live", ...)
# Create/update live post
try:
    from app.services.broadcast_newsfeed import create_or_update_live_post
    live_post_id = create_or_update_live_post(
        session_id=session_id,
        creator_id=current.created_by,
        announcement_post_id=current.announcement_post_id,
        session_name=current.name,
        session_description=current.description,
        thumbnail_url=current.thumbnail_url,
    )
    if live_post_id and live_post_id != current.announcement_post_id:
        T.broadcast_sessions.update_item(
            Key={"session_id": session_id},
            UpdateExpression="SET announcement_post_id = :pid",
            ExpressionAttributeValues={":pid": live_post_id},
        )
except Exception:
    logger.exception("Live post creation failed for session %s (non-fatal)", session_id)
```

#### 3.5.3 On Recording Ready (`process_recording`)

In `app/services/broadcast_recording_worker.py`, after recording reaches `"ready"`:

```python
# After recording status is set to "ready"
try:
    from app.services.broadcast_newsfeed import create_vod_post
    from app.services.broadcast_store import get_session
    from app.services.broadcast_viewers import get_viewer_count

    session = get_session(recording.session_id)
    # NOTE: get_peak_viewer_count() does not exist. Only get_viewer_count(session_id: str) -> int
    # is available in broadcast_viewers.py. For a stopped session, this returns the last known
    # viewer count, not the peak. A new get_peak_viewer_count() function needs to be added
    # if peak tracking is desired (requires storing peak count during the live session).
    peak_count = get_viewer_count(recording.session_id)

    create_vod_post(
        session_id=recording.session_id,
        creator_id=session.created_by,
        session_name=session.name,
        recording_id=recording.recording_id,
        recording_duration_seconds=recording.duration_seconds,
        recording_playback_url=None,  # Minted on demand
        peak_viewer_count=peak_count,
        thumbnail_url=session.thumbnail_url,
    )
except Exception:
    logger.exception("VOD post creation failed for session %s (non-fatal)", recording.session_id)
```

> **Corrected**: The original code imported `get_peak_viewer_count` from `broadcast_viewers.py`. This function does not exist. Only `get_viewer_count(session_id: str) -> int` exists (at line 73). For peak viewer tracking, either a new `get_peak_viewer_count()` function must be added (which requires storing the peak count during the live session), or `get_viewer_count()` can be used as a fallback (returns the current/last viewer count, not the peak).

#### 3.5.4 On Cancel (`cancel_scheduled_session`)

In the cancel endpoint (BCAST-009), after transitioning from `"scheduled"` to `"draft"`:

```python
# After cancellation
if session.announcement_post_id:
    from app.services.broadcast_newsfeed import delete_announcement_post
    delete_announcement_post(
        post_id=session.announcement_post_id,
        user_id=ctx["user_sub"],
    )
    # Clear the reference
    T.broadcast_sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression="REMOVE announcement_post_id",
    )
```

### 3.6 API Endpoint — Customize Announcement

```
PATCH /broadcast/sessions/{session_id}/announcement
```

**Auth**: `require_ui_session` — only session creator.

**Request model**:

```python
class BroadcastAnnouncementUpdateIn(BaseModel):
    text: Optional[str] = Field(default=None, max_length=2000)
    visibility: Optional[str] = Field(default=None, pattern="^(public|followers|private)$")
```

**Behavior**:

1. Validate session exists and caller is creator.
2. Look up `announcement_post_id` on the session.
3. If no announcement post exists, return 404.
4. Update the post's `text` and/or `visibility` via `update_broadcast_post()`.
5. Return `{"ok": True, "post_id": announcement_post_id}`.

This allows the creator to customize the auto-generated announcement text before or after it's posted.

### 3.7 Frontend Component — `BroadcastAnnouncementCard`

New component rendered by `PostCard` when `post.post_type` starts with `"broadcast_"`:

```typescript
interface BroadcastAnnouncementCardProps {
  post: FeedPost;
  broadcastMeta: BroadcastPostMeta;
}
```

**Rendering logic by post type**:

| Post Type | Visual Elements |
|-----------|----------------|
| `broadcast_announcement` | Thumbnail image, session name, scheduled date/time, countdown timer (if < 24h), "Set Reminder" button, "Add to Calendar" link |
| `broadcast_live` | Thumbnail with pulsing red "LIVE" badge, session name, viewer count (updated via polling), "Watch Now" button (links to `/broadcast/{session_id}`) |
| `broadcast_vod` | Recording thumbnail, session name, duration badge, viewer count from live session, "Watch Recording" button (links to `/broadcast/{session_id}`) |

**Component hierarchy within PostCard**:

```
PostCard
├── PostHeader (author, timestamp)
├── PostContent
│   ├── [if broadcast_announcement]
│   │   └── BroadcastAnnouncementCard
│   │       ├── ThumbnailImage (with calendar icon overlay)
│   │       ├── SessionName (heading)
│   │       ├── ScheduledTime (formatted date)
│   │       ├── CountdownTimer (if < 24h away)
│   │       ├── SetReminderButton
│   │       └── AddToCalendarLink (.ics download)
│   ├── [if broadcast_live]
│   │   └── BroadcastLiveCard
│   │       ├── ThumbnailImage (with LIVE badge)
│   │       ├── SessionName (heading)
│   │       ├── ViewerCountBadge (real-time)
│   │       └── WatchNowButton (primary CTA)
│   └── [if broadcast_vod]
│       └── BroadcastVodCard
│           ├── ThumbnailImage (with play icon overlay)
│           ├── SessionName (heading)
│           ├── DurationBadge
│           ├── ViewerCountBadge (peak from live)
│           └── WatchRecordingButton
├── PostActions (like, comment, share — same as regular posts)
└── CommentsThread (if expanded)
```

### 3.8 Frontend Types

```typescript
// frontend/src/api/types.ts — additions

interface BroadcastPostMeta {
  session_id: string;
  post_type: "broadcast_announcement" | "broadcast_live" | "broadcast_vod";
  session_name?: string;
  session_description?: string;
  thumbnail_url?: string;
  scheduled_at?: number;
  started_at?: string;
  stopped_at?: string;
  recording_id?: string;
  recording_duration_seconds?: number;
  recording_playback_url?: string;
  peak_viewer_count?: number;
  is_live: boolean;
  broadcast_url?: string;
}

// Extend existing FeedPost:
interface FeedPost {
  // ... existing fields ...
  post_type?: string;
  broadcast_meta?: BroadcastPostMeta;
}
```

### 3.9 Post Response Changes

The feed query (`GET /feed`) and post detail (`GET /posts/{post_id}`) responses must include both `post_type` and `broadcast_meta`. Both fields are **new additions** to `_post_to_dict()` in `app/routers/newsfeed.py`:

```python
def _post_to_dict(item: Dict[str, Any], *, viewer_id: str = "") -> Dict[str, Any]:
    out = {
        # ... existing fields ...
        "post_type": item.get("post_type", "text"),      # NEW — field does not currently exist
        "broadcast_meta": item.get("broadcast_meta"),      # NEW — broadcast-specific metadata
    }
    return out
```

> **Corrected**: Both `post_type` and `broadcast_meta` are new additions to `_post_to_dict()`. The `post_type` field does not currently exist anywhere in the newsfeed code and must be added to both the DDB item schema and the response dict.

### 3.10 SSE Events for Live Status Updates

When a broadcast goes live, the announcement post's `broadcast_meta.is_live` changes to `True`. To update the feed UI in real time, the feed SSE stream (if one exists) or a polling mechanism can be used. For simplicity, the frontend polls `GET /posts/{post_id}` every 30 seconds for posts with `post_type="broadcast_announcement"` to check if `is_live` has changed.

Alternatively, on the broadcast SSE stream (`GET /broadcast/sessions/{id}/stream`), a new event type:

| Event Type | Payload | Trigger |
|------------|---------|---------|
| `post:updated` | `{post_id, post_type, is_live}` | Announcement post updated to live |
| `post:created` | `{post_id, post_type}` | VOD post created |

---

## 4. Implementation Plan

### Phase 1: Service Layer (2 days)

| File | Change |
|------|--------|
| `app/services/broadcast_newsfeed.py` | New: `create_broadcast_announcement_post()`, `create_or_update_live_post()`, `create_vod_post()`, `delete_announcement_post()` |
| `app/services/broadcast_newsfeed_writer.py` | New: `write_broadcast_post()`, `update_broadcast_post()`, `delete_broadcast_post()` |

### Phase 2: Lifecycle Integration (1 day)

| File | Change |
|------|--------|
| `app/routers/broadcast.py` | Hook announcement post creation into schedule flow (BCAST-009); hook deletion into cancel flow. Add `PATCH /sessions/{id}/announcement` endpoint. |
| `app/services/broadcast_orchestrator.py` | Hook live post creation into `start_session_with_provider()`. |
| `app/services/broadcast_recording_worker.py` | Hook VOD post creation into `process_recording()` completion. |

### Phase 3: Feed Response Changes (0.5 days)

| File | Change |
|------|--------|
| `app/routers/newsfeed.py` | Add `broadcast_meta` to `_post_to_dict()` output. |

### Phase 4: Frontend (2 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add `BroadcastPostMeta` interface, extend `FeedPost`. |
| `frontend/src/pages/feed/PostCard.tsx` | Conditional rendering for broadcast post types. |
| `frontend/src/pages/feed/BroadcastAnnouncementCard.tsx` | New: announcement card with countdown + reminder CTA. |
| `frontend/src/pages/feed/BroadcastLiveCard.tsx` | New: live card with LIVE badge + Watch Now CTA. |
| `frontend/src/pages/feed/BroadcastVodCard.tsx` | New: VOD card with duration + Watch Recording CTA. |

### Phase 5: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/broadcast-newsfeed.spec.ts` | New: sections 121-122. |

### Summary of All Files

| File | Type | Estimated Lines |
|------|------|-----------------|
| `app/services/broadcast_newsfeed.py` | Create | ~250 |
| `app/services/broadcast_newsfeed_writer.py` | Create | ~150 |
| `app/services/broadcast_orchestrator.py` | Modify | +20 |
| `app/services/broadcast_recording_worker.py` | Modify | +20 |
| `app/routers/broadcast.py` | Modify | +40 |
| `app/routers/newsfeed.py` | Modify | +5 |
| `frontend/src/api/types.ts` | Modify | +20 |
| `frontend/src/pages/feed/PostCard.tsx` | Modify | +30 |
| `frontend/src/pages/feed/BroadcastAnnouncementCard.tsx` | Create | ~120 |
| `frontend/src/pages/feed/BroadcastLiveCard.tsx` | Create | ~80 |
| `frontend/src/pages/feed/BroadcastVodCard.tsx` | Create | ~80 |
| `frontend/e2e/broadcast-newsfeed.spec.ts` | Create | ~250 |
| **Total** | | **~1065** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_broadcast_newsfeed.py`)

New file, ~300 lines. Tests the service layer with moto-mocked DynamoDB.

```python
import pytest
from moto import mock_dynamodb
from unittest.mock import patch, MagicMock

from app.services.broadcast_newsfeed import (
    create_broadcast_announcement_post,
    create_or_update_live_post,
    create_vod_post,
    delete_announcement_post,
)
from app.services.broadcast_newsfeed_writer import (
    write_broadcast_post,
    update_broadcast_post,
    delete_broadcast_post,
)

def test_announcement_post_created_with_correct_fields(newsfeed_tables):
    """Verify announcement post has correct post_type and broadcast_meta."""
    post_id = create_broadcast_announcement_post(
        session_id="s1",
        creator_id="alice",
        session_name="Test Stream",
        session_description="A test broadcast",
        scheduled_at=1700000000,
    )
    assert post_id is not None
    # Verify DDB item
    item = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "POST"}).get("Item")
    assert item is not None
    assert item["post_type"] == "broadcast_announcement"
    assert item["broadcast_meta"]["session_id"] == "s1"
    assert item["broadcast_meta"]["scheduled_at"] == 1700000000
    assert item["broadcast_meta"]["is_live"] is False

def test_announcement_post_text_includes_schedule(newsfeed_tables):
    """Verify auto-generated text includes scheduled time."""
    post_id = create_broadcast_announcement_post(
        session_id="s1", creator_id="alice", session_name="Demo",
        scheduled_at=1700000000,
    )
    item = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "POST"}).get("Item")
    assert "Upcoming broadcast" in item["text"]
    assert "Demo" in item["text"]

def test_announcement_post_text_without_schedule(newsfeed_tables):
    """Verify text when no scheduled_at is set."""
    post_id = create_broadcast_announcement_post(
        session_id="s1", creator_id="alice", session_name="Quick Live",
    )
    item = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "POST"}).get("Item")
    assert "New broadcast" in item["text"]

def test_announcement_post_creates_feed_ref(newsfeed_tables):
    """Verify a FEEDREF item is created for the author."""
    post_id = create_broadcast_announcement_post(
        session_id="s1", creator_id="alice", session_name="Demo",
    )
    ref = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "FEEDREF#alice"}).get("Item")
    assert ref is not None
    assert ref["GSI1PK"] == "FEED#alice"

def test_announcement_post_triggers_fanout(newsfeed_tables):
    """Verify fan_out_post_to_followers is called."""
    with patch("app.services.broadcast_newsfeed_writer.fan_out_post_to_followers") as mock_fo:
        post_id = create_broadcast_announcement_post(
            session_id="s1", creator_id="alice", session_name="Demo",
        )
        mock_fo.assert_called_once()
        assert mock_fo.call_args[1]["author_id"] == "alice"

def test_live_post_updates_existing_announcement(newsfeed_tables):
    """When announcement_post_id is set, update that post instead of creating new."""
    # Create announcement first
    ann_id = create_broadcast_announcement_post(
        session_id="s1", creator_id="alice", session_name="Demo",
        scheduled_at=1700000000,
    )
    # Go live — should update the same post
    live_id = create_or_update_live_post(
        session_id="s1", creator_id="alice",
        announcement_post_id=ann_id, session_name="Demo",
    )
    assert live_id == ann_id  # Same post ID
    item = tbl.get_item(Key={"pk": f"POST#{ann_id}", "sk": "POST"}).get("Item")
    assert item["post_type"] == "broadcast_live"
    assert "LIVE NOW" in item["text"]
    assert item["broadcast_meta"]["is_live"] is True

def test_live_post_creates_new_when_no_announcement(newsfeed_tables):
    """Without announcement_post_id, create a new post."""
    live_id = create_or_update_live_post(
        session_id="s1", creator_id="alice", session_name="Demo",
    )
    assert live_id is not None
    item = tbl.get_item(Key={"pk": f"POST#{live_id}", "sk": "POST"}).get("Item")
    assert item["post_type"] == "broadcast_live"

def test_vod_post_includes_duration_and_viewers(newsfeed_tables):
    """VOD post text includes duration and peak viewer count."""
    post_id = create_vod_post(
        session_id="s1", creator_id="alice", session_name="Demo",
        recording_duration_seconds=4980, peak_viewer_count=1234,
    )
    item = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "POST"}).get("Item")
    assert item["post_type"] == "broadcast_vod"
    assert "1h 23m" in item["text"]
    assert "1,234" in item["text"]

def test_vod_post_meta_has_recording_fields(newsfeed_tables):
    """VOD post broadcast_meta includes recording_id and duration."""
    post_id = create_vod_post(
        session_id="s1", creator_id="alice",
        recording_id="rec_123", recording_duration_seconds=3600,
    )
    item = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "POST"}).get("Item")
    meta = item["broadcast_meta"]
    assert meta["recording_id"] == "rec_123"
    assert meta["recording_duration_seconds"] == 3600

def test_delete_announcement_removes_post_and_refs(newsfeed_tables):
    """Deleting announcement post removes the post item and feed refs."""
    post_id = create_broadcast_announcement_post(
        session_id="s1", creator_id="alice", session_name="Demo",
    )
    result = delete_announcement_post(post_id=post_id, user_id="alice")
    assert result is True
    item = tbl.get_item(Key={"pk": f"POST#{post_id}", "sk": "POST"}).get("Item")
    assert item is None

def test_announcement_failure_is_nonfatal(newsfeed_tables):
    """If DDB write fails, create_broadcast_announcement_post returns None."""
    with patch("app.services.broadcast_newsfeed_writer.tbl") as mock_tbl:
        mock_tbl.put_item.side_effect = Exception("DDB timeout")
        post_id = create_broadcast_announcement_post(
            session_id="s1", creator_id="alice", session_name="Demo",
        )
        assert post_id is None  # Non-fatal

def test_update_broadcast_post_preserves_feed_refs(newsfeed_tables):
    """Updating a post (announcement -> live) does not create new FEEDREF items."""
    post_id = "test_post_1"
    write_broadcast_post(
        post_id=post_id, user_id="alice", text="Original",
        post_type="broadcast_announcement", broadcast_meta={"session_id": "s1"},
    )
    # Count feed refs before update
    refs_before = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"POST#{post_id}"),
        FilterExpression="begins_with(sk, :prefix)",
        ExpressionAttributeValues={":prefix": "FEEDREF#"},
    )
    count_before = refs_before.get("Count", 0)

    update_broadcast_post(
        post_id=post_id, user_id="alice", text="Updated",
        post_type="broadcast_live", broadcast_meta={"session_id": "s1", "is_live": True},
    )

    refs_after = tbl.query(
        KeyConditionExpression=Key("pk").eq(f"POST#{post_id}"),
        FilterExpression="begins_with(sk, :prefix)",
        ExpressionAttributeValues={":prefix": "FEEDREF#"},
    )
    assert refs_after.get("Count", 0) == count_before  # No new refs
```

### 5.2 E2E Tests (`frontend/e2e/broadcast-newsfeed.spec.ts`)

New file, ~250 lines.

**Section 121: Broadcast Announcement Auto-Post (4 tests)**:

1. `Scheduling a broadcast creates an announcement post in the feed` — Schedule a broadcast via API, query the creator's feed, verify a post with `post_type: "broadcast_announcement"` exists with correct `broadcast_meta`.
2. `Announcement post includes session name and scheduled time` — Verify post text contains the session name and a human-readable time string.
3. `Cancelling a scheduled broadcast deletes the announcement post` — Cancel the scheduled session, query the feed, verify the announcement post is gone.
4. `Announcement post includes broadcast_meta with session_id and scheduled_at` — Verify the full `broadcast_meta` structure in the API response.

**Section 122: Live Notification Post (3 tests)**:

1. `Starting a broadcast updates the announcement post to live` — Schedule a session, start it (manual early start), verify the announcement post's `post_type` changes to `"broadcast_live"` and `broadcast_meta.is_live` is `true`.
2. `Starting an unscheduled broadcast creates a new live post` — Create a session without `scheduled_at`, start it, verify a new `broadcast_live` post appears in the feed.
3. `Live post text includes LIVE NOW and session name` — Verify the post text contains "LIVE NOW" and the session name.

**Test Setup (beforeAll)**:

```typescript
let rootPage: Page;
const TS = Date.now();
let profileId: string;

test.beforeAll(async ({ browser }) => {
  rootPage = await browser.newPage();
  await injectAuth(rootPage, "root");

  // Create broadcast profile
  const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
    name: `news-test-profile-${TS}`,
    region: "us-east-1",
    rendition_preset: "720p",
  });
  profileId = profileResp.id;
});
```

### 5.3 Edge Cases

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Creator deletes announcement post manually | Session's `announcement_post_id` becomes stale; live transition creates a new post instead of updating |
| Creator edits announcement text before go-live | Edited text is preserved until go-live, when it's overwritten with "LIVE NOW" text |
| Session goes live without prior scheduling | No announcement post exists; a new `broadcast_live` post is created |
| Recording fails (never reaches "ready") | No VOD post is created; announcement/live post remains |
| Two broadcasts go live simultaneously | Each gets its own live post; no interference |
| Session is deleted while announcement post exists | Announcement post becomes orphaned but remains visible in feed (acceptable; creator can delete it manually) |
| `create_broadcast_announcement_post` fails | Returns `None`; session continues normally without a post; failure is logged but non-fatal |
| Fan-out fails during post creation | Author's feed ref is already written; followers miss the post until next backfill; failure is logged |
| Announcement post edited via `PATCH /announcement` | Only text and visibility are updated; `broadcast_meta` remains unchanged |

### 5.4 Flakiness Mitigations

| Risk | Mitigation |
|------|------------|
| Feed query timing (post not yet visible) | After creating scheduled session, sleep 500ms then query feed with retry (up to 3 attempts) |
| Post ordering in feed | Use unique session names with `TS` to identify posts; don't rely on position |
| Announcement post ID retrieval | After scheduling, re-fetch session to get `announcement_post_id` from the response |
| Live transition timing | For section 122, manually start the session (not auto-start) for deterministic timing |
| DDB eventual consistency | Use direct `GET /posts/{post_id}` instead of feed query when checking post updates |

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- **Auto-posted content**: Created with `user_id=session.created_by`. The post is attributed to the creator, not the system. This ensures correct ownership for editing/deleting.
- **Announcement customization endpoint**: Only the session creator can modify the announcement text. Same ownership model as shelf management.
- **Feed visibility**: Announcement posts follow the creator's default visibility setting (`"public"` by default). Followers see them via fan-out. Non-followers see them only if visibility is `"public"`.

### 6.2 Content Moderation

- Broadcast announcement posts are subject to the same moderation rules as regular posts (content filtering, reporting, moderation_removed flag).
- The auto-generated text uses the session `name` and `description` provided by the creator. If these contain prohibited content, the same moderation pipeline catches it.
- System-generated text ("Upcoming broadcast:", "LIVE NOW:") is safe and does not require moderation.

### 6.3 Abuse Vectors

- **Post spam via rapid schedule/cancel cycling**: Each schedule creates a post; each cancel deletes it. The session creation rate limit (existing) prevents abuse. The fan-out cost of create+delete is bounded by the follower count.
- **Announcement post for private broadcast**: The post visibility defaults to `"public"`. Creators can set visibility to `"followers"` or `"private"` via the `PATCH /announcement` endpoint if they want to restrict who sees the announcement.
- **Stale live badges**: If a session crashes without clean stop, the announcement post retains `is_live: True`. The frontend should poll the session status and update the badge locally. A background job could also clean up stale live posts (sessions in `"stopped"` or `"error"` state with `is_live: True` posts).

### 6.4 Data Integrity

- **`announcement_post_id` consistency**: The session stores the post ID. If the post is manually deleted, the ID becomes stale. The live transition handles this by creating a new post if the existing one is not found.
- **Fan-out atomicity**: Post creation and fan-out are not in a DDB transaction. If fan-out fails, the author still sees the post. Followers eventually see it via backfill-on-follow (SOC-002) or feed browse.

---

## 7. Migration & Rollback Plan

### 7.1 No DDB Schema Changes Required

This ticket uses the existing `app_single_table` for posts (same `PK=POST#{post_id}`, `SK=POST` schema). Both `broadcast_meta` and `post_type` are new map/string attributes on post items — no DDB schema change is needed (DynamoDB is schemaless for non-key attributes), but both are new fields that do not currently exist in the codebase.

### 7.2 Feature Flag

```
BROADCAST_NEWSFEED_PROMOTION_ENABLED=true  (default)
```

If set to `"false"`, all `create_broadcast_*_post()` functions return `None` immediately without writing to DDB. Existing posts are unaffected.

### 7.3 Rollback Steps

1. Set `BROADCAST_NEWSFEED_PROMOTION_ENABLED=false` to stop new auto-posts.
2. Existing broadcast posts remain in the feed (they are regular posts with extra metadata). They can be deleted manually or via a cleanup script.
3. Revert frontend components. Posts with `broadcast_meta` render as regular text posts (the `text` field always contains human-readable content).
4. Revert backend hooks in orchestrator and recording worker. No data migration needed.

### 7.4 Backward Compatibility

- Existing posts without `broadcast_meta` are unaffected. `_post_to_dict()` returns `broadcast_meta: None` for them.
- Frontend `PostCard` falls through to existing rendering when `broadcast_meta` is absent.
- The new `post_type` values (`broadcast_announcement`, `broadcast_live`, `broadcast_vod`) are only set on system-generated posts. Existing user-created posts have no `post_type` attribute; `_post_to_dict()` defaults to `"text"` via `item.get("post_type", "text")`.

---

## 8. Operational Runbook

### 8.1 Metrics

```python
record_broadcast_newsfeed_announcement_created  # Counter
record_broadcast_newsfeed_live_post_created      # Counter
record_broadcast_newsfeed_live_post_updated      # Counter (announcement -> live)
record_broadcast_newsfeed_vod_post_created       # Counter
record_broadcast_newsfeed_announcement_deleted   # Counter (on cancel)
record_broadcast_newsfeed_post_error             # Counter (by error_type)
record_broadcast_newsfeed_fanout_latency_ms      # Histogram
```

### 8.2 Alerting Thresholds

| Metric | Threshold | Action |
|--------|-----------|--------|
| `post_error` rate | > 10% of attempts | Check DDB health, app_single_table throughput |
| `fanout_latency_ms_p95` | > 2000ms | Check SOC-002 fan-out health; may indicate large follower counts |
| `announcement_created` without matching `live_post_created` within 24h | > 50% | Scheduled sessions may not be auto-starting (check BCAST-009 scheduler) |

### 8.3 Common Debugging

**Announcement post not appearing in follower feeds**:
1. Check `BROADCAST_NEWSFEED_PROMOTION_ENABLED` is `"true"`.
2. Verify post exists: `GET /posts/{announcement_post_id}`.
3. Check fan-out occurred: query `POST#{post_id}` partition for `FEEDREF#*` items.
4. Check follower has a `FEEDREF` item: `GET /feed` as the follower.
5. Check post visibility: if `"followers"`, non-followers won't see it.

**Live badge stuck after session stopped**:
1. Check session status: `GET /broadcast/sessions/{id}`.
2. Check post's `broadcast_meta.is_live`: it may still be `true` if the stop hook failed.
3. Manually update: `update_broadcast_post()` with `is_live=False`.

**VOD post not created after recording ready**:
1. Check recording status: `GET /broadcast/sessions/{id}/recording`.
2. Check recording worker logs: `grep "broadcast_recording_worker" .logs/uvicorn.log`.
3. Check VOD post creation logs: `grep "broadcast_newsfeed" .logs/uvicorn.log`.

### 8.4 Log Patterns

```
INFO  broadcast_newsfeed.create_broadcast_announcement_post post_id=bcast_a1b2c3 session_id=s_123
INFO  broadcast_newsfeed.create_or_update_live_post post_id=bcast_a1b2c3 session_id=s_123 action=updated
INFO  broadcast_newsfeed.create_vod_post post_id=bcast_vod_d4e5f6 session_id=s_123
ERROR broadcast_newsfeed.create_broadcast_announcement_post session_id=s_456 ClientError: ...
WARN  broadcast_newsfeed_writer.write_broadcast_post fanout failed for post bcast_a1b2c3 (non-fatal)
```

---

## 9. Performance & Capacity Planning

### 9.1 Write Volume

| Event | DDB Writes per Event |
|-------|---------------------|
| Schedule broadcast (create announcement post) | 2 (post item + author FEEDREF) + N (fan-out) |
| Go live (update existing post) | 1 (update_item) |
| Go live (create new post, no announcement) | 2 + N (fan-out) |
| Recording ready (create VOD post) | 2 + N (fan-out) |
| Cancel (delete post + refs) | 1 + M (FEEDREF deletes) |

Where N = follower count and M = total FEEDREF items for the post.

### 9.2 Expected Throughput

| Scenario | Broadcasts/day | Posts Generated/day | Fan-out Writes/day |
|----------|---------------|--------------------|--------------------|
| 100 creators, avg 1 broadcast/day, 500 followers | 100 | 200-300 | 50K-150K |
| 1000 creators, avg 2 broadcasts/day, 1000 followers | 2000 | 4000-6000 | 2M-6M |

### 9.3 Latency Impact

Post creation is non-blocking for the broadcast lifecycle. All `create_*_post()` calls are wrapped in try/except and are non-fatal. The broadcast session transition completes regardless of whether the post was created.

| Operation | Added Latency to Lifecycle Event |
|-----------|----------------------------------|
| Create announcement post | +50-200ms (varies by follower count fan-out) |
| Update post to live | +10-30ms (single update_item) |
| Create VOD post | +50-200ms (fan-out) |

### 9.4 Hot Partition

Broadcast posts use the same `app_single_table` as regular posts. Each post has a unique `PK=POST#{post_id}`, so writes distribute across partitions. The fan-out writes target different `GSI1PK=FEED#{follower_id}` partitions. No hot partition risk.

---

## 10. Dependency Analysis

### 10.1 Tickets This Is Blocked By

| Ticket | Dependency | Detail |
|--------|-----------|--------|
| BCAST-009 | `scheduled_at` field, `"scheduled"` status | Announcement posts require the scheduling system |
| SOC-002 | Fan-out on write | Posts must fan out to follower feeds for discovery |

### 10.2 Tickets This Blocks

| Ticket | Dependency | Detail |
|--------|-----------|--------|
| None | — | BCAST-010 is a leaf feature |

### 10.3 Integration Points

- **`app/services/broadcast_orchestrator.py::start_session_with_provider()`** — hook for live post creation (modify)
- **`app/services/broadcast_recording_worker.py::process_recording()`** — hook for VOD post creation (modify)
- **`app/routers/broadcast.py`** — hook for announcement post on schedule, deletion on cancel (modify)
- **`app/services/newsfeed_fanout.py::fan_out_post_to_followers()`** — called by writer for follower distribution (read-only)
- **`app/services/newsfeed_fanout.py::fan_out_delete_post()`** — called on cancel for cleanup (read-only)
- **`app/routers/newsfeed.py::_post_to_dict()`** — add `broadcast_meta` to response (modify)

---

## 11. Post Lifecycle State Machine

### 11.1 State Diagram

```
                               ┌──────────────────────────────┐
                               │                              │
                               ▼                              │
  ┌────────┐   schedule    ┌──────────────────┐   cancel    ┌─┴──────┐
  │ (none) │──────────────>│ broadcast_       │────────────>│ deleted│
  │        │               │ announcement     │             │        │
  └────┬───┘               │                  │             └────────┘
       │                   │ • post_type =    │
       │                   │   "broadcast_    │
       │ go live           │   announcement"  │
       │ (no prior         │ • is_live = false│
       │  schedule)        │                  │
       │                   └────────┬─────────┘
       │                            │
       │                            │ go live
       │                            │ (UPDATE existing post)
       │                            ▼
       │                   ┌──────────────────┐
       └──────────────────>│ broadcast_live   │
          go live          │                  │
          (CREATE new)     │ • post_type =    │
                           │   "broadcast_    │
                           │   live"          │
                           │ • is_live = true │
                           └────────┬─────────┘
                                    │
                                    │ session stops +
                                    │ recording ready
                                    │
                                    ▼
                           ┌──────────────────┐
                           │ broadcast_vod    │
                           │ (NEW post)       │
                           │                  │
                           │ • post_type =    │
                           │   "broadcast_vod"│
                           │ • is_live = false│
                           │ • recording_id   │
                           └────────┬─────────┘
                                    │
                                    │ creator or
                                    │ moderator delete
                                    ▼
                           ┌──────────────────┐
                           │ deleted          │
                           └──────────────────┘
```

### 11.2 Transition Rules

| From | To | Trigger | Action |
|------|----|---------|--------|
| (none) | `broadcast_announcement` | Session scheduled with `scheduled_at` | `create_broadcast_announcement_post()` creates new post + fan-out |
| (none) | `broadcast_live` | Session goes live without prior scheduling | `create_or_update_live_post()` creates new post + fan-out |
| `broadcast_announcement` | `broadcast_live` | Session goes live | `update_broadcast_post()` modifies existing post in-place (same post_id, same feed position) |
| `broadcast_announcement` | deleted | Session cancelled | `delete_announcement_post()` removes post + all FEEDREF items |
| `broadcast_live` | (live post stays) + `broadcast_vod` created | Recording reaches "ready" | New `broadcast_vod` post created alongside the live post (live post is NOT deleted) |
| Any | deleted | Creator manually deletes post | Standard newsfeed delete flow |
| Any | deleted | Moderator removes post | `moderation_removed` flag set; post hidden from feeds |

### 11.3 Likes, Comments, and Reactions During Transitions

When an announcement post is **updated** to a live post (`broadcast_announcement` -> `broadcast_live`):

- **Likes are preserved**. The post item's `reactions` map and `tip_total_cents` remain unchanged because `update_broadcast_post()` only modifies `text`, `post_type`, `broadcast_meta`, and `updated_at`. The `PK=POST#{post_id}` is the same item.
- **Comments are preserved**. Comment items are stored under `PK=COMMENT#{post_id}` (separate partition), so they survive the post type transition.
- **Feed position is preserved**. FEEDREF items use `GSI1SK={created_at}#POST#{post_id}` which does not change during update. The post stays at its original position in follower feeds.
- **Reactions are preserved**. The `reactions` attribute (DDB map of `{emoji: {user_id: True}}`) is not modified by `update_broadcast_post()`.

When a broadcast is **cancelled** and the announcement post is **deleted**:

- All likes, comments, reactions, and tips on the deleted post are orphaned. Comment items under `PK=COMMENT#{post_id}` remain in DDB but are inaccessible (no parent post). They are effectively garbage and do not cause issues. A future cleanup job can purge orphaned comments.
- FEEDREF items are deleted by `fan_out_delete_post()`, so followers no longer see the post.

When a **VOD post** is created after a live session:

- The VOD post is a brand-new post with a new `post_id`. It starts with zero likes, comments, and reactions. The live post (if any) retains its own engagement independently.

### 11.4 Invalid Transitions (No-Ops)

| Attempted Transition | Behavior |
|---------------------|----------|
| `broadcast_live` -> `broadcast_announcement` | Never happens; live sessions cannot revert to scheduled |
| `broadcast_vod` -> `broadcast_live` | Never happens; recordings cannot go back to live |
| Double `create_broadcast_announcement_post()` for same session | Idempotent — second call creates a second post with a different post_id; session stores only the latest `announcement_post_id` |
| `create_vod_post()` when recording is not "ready" | Caller checks recording status before calling; function is not called |

---

## 12. Fan-Out Performance

### 12.1 Follower Scale Considerations

For creators with large follower counts, the fan-out write volume is significant. The `fan_out_post_to_followers()` function from SOC-002 queries `GSI5: FOLLOWERS#{author_id}` and writes one `FEEDREF` item per follower.

| Creator Follower Count | Fan-Out Writes per Announcement | Estimated Latency (at 3000 WCU) | Notes |
|------------------------|--------------------------------|----------------------------------|-------|
| 100 | 100 | < 100ms | Synchronous is fine |
| 1,000 | 1,000 | ~500ms | Borderline; may cause visible latency on schedule endpoint |
| 10,000 | 10,000 | ~5s | Must be asynchronous |
| 100,000 | 100,000 | ~50s | Must be asynchronous + batched |

### 12.2 Batch Processing

For creators with >1,000 followers, fan-out MUST be asynchronous. The implementation uses the existing SOC-002 fan-out pattern with these parameters:

```python
# app/services/newsfeed_fanout.py — fan_out_post_to_followers()

FANOUT_BATCH_SIZE = 25           # DDB batch_write_item max is 25 items
FANOUT_MAX_CONCURRENT_BATCHES = 4 # Parallel batch writes
FANOUT_PAGE_SIZE = 500           # Followers query page size
FANOUT_MAX_FOLLOWERS = 200_000   # Safety cap
```

**Batch write flow for 100K followers:**

1. Query `FOLLOWERS#{author_id}` in pages of 500 (200 pages total).
2. For each page, chunk into batches of 25 FEEDREF items.
3. Submit batches via `batch_write_item` with up to 4 concurrent writes.
4. On `UnprocessedItems`, retry with exponential backoff (100ms, 200ms, 400ms, max 3 retries).
5. Log warning for any items that fail after all retries (non-fatal).

**Estimated throughput at on-demand DDB pricing:**

- On-demand tables burst up to 4,000 WCUs initially, then 2x the previous peak.
- 100K FEEDREF writes at 25/batch = 4,000 batch_write calls.
- At 4 concurrent batches with 25ms DDB latency: ~25 seconds wall-clock time.
- Total WCUs consumed: 100,000 (one per FEEDREF item).

### 12.3 Backpressure Handling

When DDB throttles writes (`ProvisionedThroughputExceededException` on provisioned tables, or burst-limit on on-demand tables):

1. **Immediate retry with jitter**: `batch_write_item` returns `UnprocessedItems`. Re-submit after `random.uniform(0.05, 0.15)` seconds.
2. **Exponential backoff**: If retry also returns `UnprocessedItems`, double the wait (max 2 seconds).
3. **Max retry cap**: After 5 retries per batch, log the failed items and continue. The affected followers miss the post in their feed until the next `backfill-on-follow` event (SOC-002).
4. **Circuit breaker**: If >20% of batches fail in a single fan-out run, abort the remaining fan-out and log a critical alert. The author's own feed ref is already written, so the post is visible to the author.

### 12.4 Dead-Letter Queue for Failed Fan-Outs

When a fan-out batch fails after all retries, the failed follower IDs are written to a dead-letter item in DDB:

```python
{
    "pk": f"FANOUT_DLQ#{post_id}",
    "sk": f"BATCH#{batch_index}",
    "post_id": post_id,
    "author_id": author_id,
    "failed_follower_ids": ["user_1", "user_2", ...],
    "error": "ProvisionedThroughputExceededException",
    "created_at": now_ts(),
    "ttl": now_ts() + 7 * 86400,  # Auto-expire after 7 days
}
```

A background job (`fan_out_dlq_processor`) runs every 5 minutes, queries `pk begins_with FANOUT_DLQ#`, and retries failed writes. After successful retry, the DLQ item is deleted. After 7 days, the TTL expires the item automatically (the post is old enough that backfill-on-follow will eventually deliver it).

### 12.5 Monitoring Fan-Out Health

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `fanout_total_followers` | Histogram of follower counts per fan-out | p99 > 50,000 (capacity planning) |
| `fanout_batch_retries` | Counter of retried batches | > 100/min |
| `fanout_dlq_items` | Gauge of pending DLQ items | > 50 |
| `fanout_wall_clock_ms` | Histogram of total fan-out duration | p99 > 30,000ms |
| `fanout_dropped_followers` | Counter of followers that could not be reached | > 0 triggers alert |

---

## 13. Content Moderation Integration

### 13.1 Auto-Generated Post Moderation

Even though broadcast announcement posts are auto-generated, the text content originates from the creator (session `name` and `description`). These fields must go through the same content moderation pipeline as regular newsfeed posts.

**Moderation check points:**

| Check Point | When | What is Checked | Blocking? |
|-------------|------|-----------------|-----------|
| Session creation | Creator submits broadcast name + description | `name` and `description` fields | Yes — session creation fails if moderation rejects |
| Announcement post creation | `create_broadcast_announcement_post()` | The auto-generated `text` (which includes name + description) | No — post is created but flagged for review |
| Announcement customization | `PATCH /sessions/{id}/announcement` | The custom `text` field | Yes — update fails if moderation rejects |
| Live post update | `create_or_update_live_post()` | Updated text | No — non-blocking; post is updated but flagged |

### 13.2 Moderation Flow for Auto-Posts

> **Corrected**: The code below references `from app.services.content_moderation import check_text_content`. This module (`app/services/content_moderation.py`) does not currently exist in the codebase and must be created as a new file. It is not an existing service being imported.

```python
# In broadcast_newsfeed_writer.py::write_broadcast_post()

def write_broadcast_post(...) -> None:
    # ... existing code ...

    # Run content moderation check (if enabled)
    # NOTE: app/services/content_moderation.py does NOT currently exist and must be
    # created as part of this ticket (or as a prerequisite). The module and the
    # check_text_content() function are new additions.
    from app.services.content_moderation import check_text_content
    moderation_result = check_text_content(text)

    if moderation_result.flagged:
        post_item["moderation_status"] = "flagged"
        post_item["moderation_flags"] = moderation_result.flags  # e.g., ["profanity", "spam"]
        post_item["moderation_reviewed"] = False
        logger.warning(
            "Broadcast announcement post flagged by moderation",
            extra={"post_id": post_id, "flags": moderation_result.flags},
        )
    else:
        post_item["moderation_status"] = "approved"

    tbl.put_item(Item=post_item)
    # ... fan-out code ...
```

### 13.3 Moderator Actions on Broadcast Announcements

A moderator can take the following actions on broadcast announcement posts through the existing moderation endpoints:

| Action | Endpoint | Effect on Post | Effect on Broadcast |
|--------|----------|---------------|-------------------|
| Remove post | `POST /admin/moderation/posts/{id}/remove` | Sets `moderation_removed=true`, hidden from all feeds | Broadcast session continues; viewers can still access via direct URL |
| Warn creator | `POST /admin/moderation/posts/{id}/warn` | Post stays visible; creator receives moderation warning | No effect on broadcast |
| Suspend creator | `POST /admin/moderation/users/{id}/suspend` | All posts hidden; creator account suspended | Broadcast session is force-stopped (existing BCAST suspension logic) |
| Block broadcast announcement | `POST /admin/moderation/posts/{id}/block` | Post permanently removed; `announcement_post_id` cleared on session | Future lifecycle events (go-live, VOD) do not create new posts for this session |

### 13.4 Blocking a Broadcast Announcement

When a moderator blocks a broadcast announcement post, the system:

1. Deletes the post and all FEEDREF items (same as `delete_announcement_post()`).
2. Sets `announcement_blocked=true` on the broadcast session.
3. Clears `announcement_post_id` on the session.
4. When the session goes live, `create_or_update_live_post()` checks `announcement_blocked`. If true, no live post is created.
5. When the recording is ready, `create_vod_post()` also checks `announcement_blocked`. If true, no VOD post is created.
6. The creator can appeal the block through the existing moderation appeals flow (MOD-003).

### 13.5 Broadcast Description Changes After Moderation

If a creator edits the broadcast description after the announcement post was already moderated:

- The `PATCH /sessions/{id}/announcement` endpoint re-runs the moderation check on the new text.
- If the new text passes, `moderation_status` is updated to `"approved"`.
- If the new text is flagged, the post reverts to `"flagged"` status and enters the moderation queue.
- The original `broadcast_meta.session_description` is also updated to match.

---

## 14. Frontend Component Specifications

### 14.1 BroadcastAnnouncementCard

```typescript
interface BroadcastAnnouncementCardProps {
  post: FeedPost;
  broadcastMeta: BroadcastPostMeta;
}

interface BroadcastAnnouncementCardState {
  countdownText: string | null;       // "2h 15m" or null if > 24h away
  countdownIntervalId: number | null; // setInterval handle for countdown
  reminderSet: boolean;               // Whether current user has set a reminder
  reminderLoading: boolean;           // Loading state for reminder toggle
}
```

**Countdown Timer Logic:**

```typescript
function useCountdown(scheduledAt: number | undefined): string | null {
  const [text, setText] = useState<string | null>(null);

  useEffect(() => {
    if (!scheduledAt) return;

    const update = () => {
      const diff = scheduledAt * 1000 - Date.now();
      if (diff <= 0) {
        setText("Starting soon...");
        return;
      }
      if (diff > 24 * 60 * 60 * 1000) {
        setText(null); // More than 24h away — show date instead
        return;
      }
      const hours = Math.floor(diff / (60 * 60 * 1000));
      const minutes = Math.floor((diff % (60 * 60 * 1000)) / (60 * 1000));
      const seconds = Math.floor((diff % (60 * 1000)) / 1000);
      if (hours > 0) {
        setText(`${hours}h ${minutes}m`);
      } else {
        setText(`${minutes}m ${seconds}s`);
      }
    };

    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [scheduledAt]);

  return text;
}
```

**Rendered elements:**

| Element | Condition | Visual |
|---------|-----------|--------|
| Thumbnail image | `broadcastMeta.thumbnail_url` present | 16:9 aspect ratio image with calendar icon overlay in bottom-right |
| Session name | Always | `<h3>` heading, 2-line clamp |
| Scheduled date/time | `broadcastMeta.scheduled_at` present | Formatted date: "May 27, 2026 at 3:00 PM UTC" |
| Countdown timer | `scheduledAt` is within 24 hours | Animated badge: "Starts in 2h 15m", updates every second when < 1h, every minute otherwise |
| "Starting soon..." | Countdown reaches 0 but `is_live` is still false | Pulsing yellow text |
| Set Reminder button | Always (when not live) | Toggle button: "Set Reminder" / "Reminder Set" with bell icon |
| Add to Calendar link | Always | `.ics` file download link (generates iCal event with broadcast URL) |

### 14.2 ReminderButton

```typescript
interface ReminderButtonProps {
  sessionId: string;
  scheduledAt?: number;
  initialReminderSet?: boolean;
}

// Internal state
interface ReminderButtonState {
  isSet: boolean;
  isLoading: boolean;
}

// API calls
// POST /broadcast/sessions/{sessionId}/reminders — subscribe
// DELETE /broadcast/sessions/{sessionId}/reminders — unsubscribe
// GET /broadcast/sessions/{sessionId}/reminders/status — check if current user has reminder

// Visual states:
// isSet=false: outline button with bell icon, text "Set Reminder"
// isSet=true: filled button with bell-ring icon, text "Reminder Set", checkmark
// isLoading: spinner replaces bell icon, button disabled
// scheduledAt in past: button hidden (broadcast already started)
```

**Reminder delivery mechanism:** When `scheduledAt` arrives, the existing notification system (SOC-004) sends a push notification to all users who subscribed to the reminder. The notification text is: ""{session_name}" is starting now! Watch live at {broadcast_url}". Reminders are stored as `REMINDER#{session_id}#{user_id}` items in the notifications table.

### 14.3 BroadcastLiveCard

```typescript
interface BroadcastLiveCardProps {
  post: FeedPost;
  broadcastMeta: BroadcastPostMeta;
}

// Visual elements:
// - Thumbnail with pulsing red "LIVE" badge (CSS animation: scale 1.0 → 1.1, opacity 0.8 → 1.0)
// - Session name heading
// - Viewer count badge (updates via polling GET /broadcast/sessions/{id}/stats every 15s)
// - "Watch Now" primary CTA button (large, red background, links to /broadcast/{session_id})
// - Session description (truncated, expandable)
```

**Viewer count polling:**

```typescript
const { data: stats } = useQuery({
  queryKey: ["broadcast-stats", broadcastMeta.session_id],
  queryFn: () => getBroadcastStats(broadcastMeta.session_id),
  refetchInterval: 15_000,           // Poll every 15 seconds
  enabled: broadcastMeta.is_live,    // Only poll while live
});
```

### 14.4 BroadcastVodCard

```typescript
interface BroadcastVodCardProps {
  post: FeedPost;
  broadcastMeta: BroadcastPostMeta;
}

// Visual elements:
// - Thumbnail with play icon overlay (triangle in circle, semi-transparent white)
// - Session name heading
// - Duration badge: "1h 23m" (bottom-right of thumbnail, dark semi-transparent background)
// - Peak viewer count from live session: "1,234 live viewers" (subtle text below title)
// - "Watch Recording" primary CTA button (links to /broadcast/{session_id} or VOD player)
// - If price_cents > 0: price badge overlaying thumbnail ("$4.99 PPV")
```

### 14.5 LiveNowBanner (Global Notification Bar)

```typescript
interface LiveNowBannerProps {
  // No props — component queries for active live broadcasts from followed creators
}

interface LiveBroadcast {
  session_id: string;
  session_name: string;
  creator_id: string;
  creator_display_name: string;
  viewer_count: number;
  started_at: number;
}

// Placement: Fixed bar at the top of the page, below the main header, above content.
// Shows only when a followed creator has an active live broadcast.
// Multiple live broadcasts: horizontal scroll or "2 creators are live" summary.
// Dismissible: click X to hide for this session. State stored in sessionStorage.
// Re-appears for new live sessions.

// Polling:
// GET /broadcast/following/live — returns LiveBroadcast[] of currently live sessions
//   from creators the current user follows.
// Polled every 30 seconds. Only active when the app is in the foreground (visibility API).
```

```typescript
function LiveNowBanner() {
  const { data: liveSessions } = useQuery({
    queryKey: ["following-live"],
    queryFn: () => getFollowingLiveBroadcasts(),
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });

  const [dismissed, setDismissed] = useState<Set<string>>(new Set());

  const visible = (liveSessions ?? []).filter(s => !dismissed.has(s.session_id));

  if (visible.length === 0) return null;

  return (
    <div className="fixed top-14 left-0 right-0 z-40 bg-red-600 text-white px-4 py-2 flex items-center gap-3">
      <span className="animate-pulse inline-block w-2 h-2 rounded-full bg-white" />
      {visible.length === 1 ? (
        <a href={`/broadcast/${visible[0].session_id}`} className="font-medium hover:underline">
          {visible[0].creator_display_name} is live: {visible[0].session_name}
        </a>
      ) : (
        <span>{visible.length} creators you follow are live</span>
      )}
      <button onClick={() => setDismissed(prev => {
        const next = new Set(prev);
        visible.forEach(s => next.add(s.session_id));
        return next;
      })} className="ml-auto">
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
```

---

## 15. Acceptance Criteria (Expanded)

1. When a broadcast is scheduled (BCAST-009), a `broadcast_announcement` post is automatically created in the creator's feed and fanned out to followers.
2. The announcement post includes the session name, description, scheduled time, and a link to the broadcast page.
3. When a broadcast goes live, the announcement post is updated to `broadcast_live` with "LIVE NOW" badge, or a new live post is created if no announcement exists.
4. When a recording is ready (BCAST-006), a `broadcast_vod` post is created with duration and peak viewer count.
5. When a scheduled broadcast is cancelled, the announcement post is deleted from the creator's feed and all follower feeds.
6. The creator can customize the announcement text before it's posted via `PATCH /broadcast/sessions/{id}/announcement`.
7. Broadcast posts appear in the feed alongside regular posts, with special rendering for each type.
8. The "Set Reminder" button on announcement cards opens the reminder subscription flow (BCAST-009).
9. The "Watch Now" button on live cards links to the broadcast viewer page.
10. All auto-post operations are non-fatal — broadcast lifecycle events complete successfully even if post creation fails.
11. All 7 E2E tests pass with 0 flakes on 3 consecutive runs.
12. **Likes and comments on an announcement post are preserved when it transitions to a live post.**
13. **The countdown timer on announcement cards updates in real time (every second when < 1 hour, every minute otherwise) and shows "Starting soon..." when the scheduled time passes without a go-live event.**
14. **Fan-out for creators with 10K+ followers completes within 30 seconds without blocking the broadcast lifecycle response.**
15. **Failed fan-out batches are written to a dead-letter queue and retried by a background job within 5 minutes.**
16. **Content moderation checks run on the auto-generated announcement text. Flagged posts enter the moderation review queue and are visible but marked as "under review".**
17. **A moderator can block a broadcast announcement, which prevents live and VOD posts from being auto-created for that session.**
18. **The LiveNowBanner component appears at the top of the page when a followed creator goes live, polls every 30 seconds, and is dismissible per-session.**
19. **The VOD post includes `recording_playback_url` when the recording is ready and the "Watch Recording" button navigates to the VOD player.**
20. **The Add to Calendar link on announcement cards generates a valid `.ics` file containing the broadcast name, description, scheduled time, and broadcast URL.**

---

## 16. Edge Cases (Expanded)

### 16.1 Creator Edits Broadcast Description After Announcement Posted

**Scenario**: Creator schedules a broadcast, announcement post is created and fanned out, then creator edits the broadcast session `description` via `PATCH /broadcast/sessions/{id}`.

**Expected behavior**: The announcement post text is NOT automatically updated. The `broadcast_meta.session_description` on the post becomes stale. Two options for the implementor:

- **Option A (recommended)**: Add a hook in the session update endpoint that calls `update_broadcast_post()` to sync the new description. This keeps the announcement and session in sync. The `broadcast_meta.session_description` is also updated.
- **Option B**: Do nothing. The creator can manually update the announcement text via `PATCH /sessions/{id}/announcement`. This is simpler but risks stale content.

**Chosen approach**: Option A. The session update endpoint checks if `announcement_post_id` is set and the description changed, then calls `update_broadcast_post()` with the new text.

### 16.2 Broadcast Cancelled While Live Post Is Active

**Scenario**: A broadcast goes live, the announcement post is updated to `broadcast_live`. Then the session is force-stopped (e.g., moderator action or system error) and the session status goes to `"error"` or `"cancelled"`.

**Expected behavior**:
1. The live post retains `broadcast_meta.is_live = true` until explicitly updated.
2. The stop hook in `stop_session_with_provider()` calls `update_broadcast_post()` with `is_live = false` and `post_type` changed to either `"broadcast_announcement"` (if reverting) or kept as `"broadcast_live"` with `is_live = false` (ended state).
3. The frontend checks both `broadcast_meta.is_live` and polls `GET /broadcast/sessions/{id}/status`. If the session is stopped/error but the post says `is_live: true`, the frontend locally overrides the badge to "Ended".
4. A background cleanup job runs every 5 minutes and queries for posts with `is_live=true` whose corresponding sessions are not in `"live"` status. It updates those posts to `is_live=false`.

### 16.3 VOD Post When Recording Fails

**Scenario**: A broadcast completes, the recording worker starts processing, but the recording fails (transcoding error, S3 write failure, etc.) and never reaches `"ready"` status.

**Expected behavior**:
1. `create_vod_post()` is never called because the recording worker only invokes it on `status="ready"`.
2. The live post (if any) remains in the feed with `is_live=false` (set by the stop hook).
3. No VOD post appears. This is acceptable — not all broadcasts produce recordings.
4. If the recording is retried and eventually succeeds, `create_vod_post()` is called at that point (may be hours or days later). The VOD post appears with the original session name and description.
5. If the creator manually retries the recording via `POST /broadcast/sessions/{id}/retry-recording`, the recording worker runs again. On success, the VOD post is created normally.

### 16.4 Announcement for a Broadcast That Never Starts

**Scenario**: A creator schedules a broadcast for 3:00 PM but never clicks "Go Live". The `scheduled_at` time passes.

**Expected behavior**:
1. The announcement post remains in the feed with the original `post_type=broadcast_announcement`. No automatic update occurs.
2. The countdown timer on the frontend reaches zero and displays "Starting soon..." indefinitely.
3. After 1 hour past `scheduled_at`, the frontend changes the display to "Broadcast delayed" (client-side logic based on `scheduled_at` vs current time).
4. The post is NOT automatically deleted. The creator can manually delete it, cancel the session (which triggers deletion), or start the broadcast late.
5. A background job could optionally mark stale announcements (>24h past scheduled time without go-live) with `is_stale=true`, which the frontend renders as "This broadcast was not started."

### 16.5 Rapid Schedule/Cancel Cycling (Spam)

**Scenario**: A malicious creator rapidly schedules and cancels broadcasts to trigger fan-out writes and deletions.

**Expected behavior**:
1. The existing session creation rate limit (5 per hour per user) prevents rapid cycling.
2. Each cycle costs `2 + N` writes (create) + `1 + M` writes (delete) where N/M = follower count. At 5/hour with 10K followers, this is 100K writes/hour — within DDB on-demand limits but worth monitoring.
3. The fan-out delete is eventually consistent. A follower may briefly see the announcement in their feed before the FEEDREF deletion propagates.
4. The dead-letter queue handles any failed deletes.

### 16.6 Multiple Broadcasts Scheduled Simultaneously

**Scenario**: A creator schedules two broadcasts at the same time (or overlapping times).

**Expected behavior**:
1. Each session gets its own announcement post. They coexist in the feed.
2. When one goes live, only its announcement post is updated. The other remains as an announcement.
3. Followers see both posts in their feed, ordered by creation time.
4. This is valid behavior — a creator may have multiple channels or topics.

---

## 17. Error Handling Matrix

| Error Condition | HTTP Status | Error Code | User Message | Recovery |
|----------------|-------------|------------|--------------|----------|
| Post creation DDB failure | N/A (non-fatal, logged) | N/A | N/A (broadcast succeeds) | Manual post creation or retry |
| Fan-out failure during post creation | N/A (non-fatal, logged) | N/A | N/A (author's feed ref written) | Followers see post on next backfill |
| Announcement post not found during live update | N/A (creates new post) | N/A | N/A | New post created automatically |
| Announcement post not found during cancel | N/A (logged, no-op) | N/A | N/A | Nothing to delete |
| `PATCH /announcement` on non-existent post | 404 | POST_NOT_FOUND | "Announcement post not found" | Schedule a broadcast first |
| `PATCH /announcement` by non-creator | 403 | FORBIDDEN | "Only the broadcaster can edit the announcement" | Use the creator's account |
| VOD post creation fails (recording_worker) | N/A (non-fatal, logged) | N/A | N/A (recording still available) | Manual post creation |
| Feature flag disabled | N/A (all functions return None) | N/A | N/A | Enable `BROADCAST_NEWSFEED_PROMOTION_ENABLED` |

---

## Appendix A: API Reference Summary

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| PATCH | `/broadcast/sessions/{id}/announcement` | Session creator | Customize announcement text |

All other post creation/update/deletion is triggered automatically by broadcast lifecycle events (no direct API calls from the frontend).

## Appendix B: Post Type Rendering Reference

| Post Type | Text Pattern | Key UI Elements |
|-----------|-------------|----------------|
| `broadcast_announcement` | "📅 Upcoming broadcast: {name}\nScheduled for {time}" | Countdown timer, Set Reminder button, Add to Calendar link |
| `broadcast_live` | "🔴 LIVE NOW: {name}\nWatch live now!" | Pulsing LIVE badge, Watch Now button, viewer count |
| `broadcast_vod` | "📹 Watch recording: {name}\nDuration: {duration}\n{viewers} live viewers" | Play icon, Watch Recording button, duration badge |

## Appendix C: Configuration

| Setting | Default | Purpose |
|---------|---------|---------|
| `BROADCAST_NEWSFEED_PROMOTION_ENABLED` | `true` | Enable/disable auto-posting |
| `BROADCAST_NEWSFEED_DEFAULT_VISIBILITY` | `public` | Default visibility for auto-posts |

## Appendix D: Related Tickets

- **BCAST-009**: Broadcast scheduling — provides the `scheduled_at` field and schedule lifecycle events
- **BCAST-006**: Recording archive — provides the recording-ready trigger for VOD posts
- **SOC-002**: Feed fan-out — distributes broadcast posts to follower feeds
- **SOC-001**: Follow system — provides the follower list for fan-out
- **LCOM-001**: Product shelf — product shelf can be mentioned in announcement posts (future enhancement)
