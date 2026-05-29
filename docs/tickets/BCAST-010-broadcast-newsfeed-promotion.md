# BCAST-010: Broadcast Newsfeed Promotion — Auto-Post Announcements for Scheduled and Live Broadcasts

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-27  
**Priority**: High  
**Estimated effort**: 5-7 days

---

## 1. Overview & Motivation

### The Gap

The broadcast system (BCAST-001 through BCAST-009) handles session lifecycle, streaming, recording, product shelves, and scheduling. The newsfeed system (`app/routers/newsfeed.py`, 4000+ lines) handles posts with text, images, video, locking, tipping, reactions, and fan-out to followers (SOC-002). However, **there is no integration between broadcast lifecycle events and the newsfeed**.
<!-- NOTE: This claim is NOW OUTDATED. Newsfeed promotion service exists:
  `app/services/broadcast_newsfeed.py`,
  `app/core/settings.py:1200` (broadcast_newsfeed_promotion_enabled),
  `frontend/e2e/broadcast-newsfeed.spec.ts` --> When a creator schedules or starts a broadcast, no newsfeed post is created. Viewers must independently discover broadcasts through the broadcast dashboard, which has no organic discovery path via the social feed.

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

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_newsfeed.py`

**Mock setup**: moto mock for DynamoDB (broadcast tables). Mock broadcast provider for instant state transitions.

| Test Function | Description |
|---|---|
| `test_create_bcast010_resource` | Create primary resource; verify stored in DDB with correct fields |
| `test_get_bcast010_resource` | Get resource by ID; verify all fields returned |
| `test_list_bcast010_resources` | List resources; verify pagination and filtering |
| `test_update_bcast010_resource` | Update resource; verify changed fields persisted |
| `test_delete_bcast010_resource` | Delete resource; verify removed from DDB |
| `test_validation_rejects_invalid_input` | Missing required fields returns 422; invalid values return 400 |
| `test_authorization_enforced` | Non-owner/non-admin access returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle: create -> read -> update -> delete through real DDB
2. Cross-service integration with broadcast session store
3. Concurrent operations do not corrupt shared state

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcast-newsfeed.spec.ts`

**Auth pattern**: `injectAuth(page, "root")` for admin operations; `injectAuth(page, "alice")` for viewer operations; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates resource successfully | POST returns 200/201 with resource ID |
| 2 | API returns resource by ID | GET returns full resource with all expected fields |
| 3 | API lists resources with pagination | GET list returns array; supports cursor pagination |
| 4 | API updates resource fields | PATCH/PUT returns updated resource |
| 5 | API deletes resource | DELETE returns 200; subsequent GET returns 404 |
| 6 | UI page loads with expected heading | Navigate to page; heading visible |
| 7 | UI form creates new resource | Fill form; submit; resource appears in list |
| 8 | UI shows error for invalid input | Submit empty form; validation messages visible |
| 9 | Unauthenticated request returns 401 | No session cookies -> 401 |
| 10 | Non-owner access returns 403 | Wrong user -> 403 |
| 11 | Non-existent resource returns 404 | GET invalid ID -> 404 |
| 12 | Duplicate creation returns 409 | Create same resource twice -> 409 or idempotent success |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 not found, 409 conflict/duplicate, 422 validation

**Edge cases**: Empty state (no resources), concurrent mutations, resource with max-length fields, Unicode content

### Test Data Requirements

Seed broadcast session in `beforeAll`. Create test resources via API with unique `Date.now()` suffixed names.

**Test users**: Root (ROOT, admin operations), Alice (USER, standard operations), Bob (USER, cross-user isolation)

### CI/Pipeline

Serial execution. `BROADCAST_PROVIDER=local`. Retry-safe with unique resource names.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| BCAST-009 | Scheduled broadcast sessions for announcement posts | Implemented | Yes |
| SOC-002 | Newsfeed fan-out infrastructure for post distribution | Implemented | Yes |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Sequential after BCAST-009. Integrates broadcast lifecycle events with newsfeed post creation. Feature-flag-gated via `broadcast_newsfeed_promotion_enabled`.

### Merge Checklist

- [ ] DDB table/fields added to `scripts/local-ddb-init.py` (if new table needed)
- [ ] Settings added to `app/core/settings.py`
- [ ] Service and router files created/modified
- [ ] Frontend components and API wrappers created
- [ ] E2E test passes in CI
- [ ] No breaking changes to existing endpoints

---

## Codebase References

| File | Line(s) | Status | Notes |
|------|---------|--------|-------|
| `app/services/broadcast_newsfeed.py` | — | EXISTS | Newsfeed promotion service |
| `app/core/settings.py` | 1200 | EXISTS | `broadcast_newsfeed_promotion_enabled` |
| `frontend/e2e/broadcast-newsfeed.spec.ts` | — | EXISTS | E2E tests |
| `app/services/broadcast_scheduler.py` | — | EXISTS | Scheduler (triggers promotion on start) |
| `app/services/broadcast_recording.py` | — | EXISTS | Recording (triggers VOD post on completion) |
