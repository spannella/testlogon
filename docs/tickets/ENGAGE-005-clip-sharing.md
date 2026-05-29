# ENGAGE-005: Viewer Clip Creation from Broadcasts

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-28  
**Priority**: High  
**Estimated effort**: 12-16 days

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform has a robust **creator-side clipping tool** (`app/services/video_clipper.py`, 388 lines) that allows video owners to extract time-range segments from their own published videos. <!-- CORRECTED: was "389 lines", actually 388 lines --> However, **viewers cannot create clips from live broadcasts**. When a memorable moment happens during a broadcast -- a funny reaction, a gameplay highlight, a music performance peak -- it is ephemeral. Viewers cannot capture and share it without:

1. Using third-party screen recording software (quality loss, copyright ambiguity).
2. Waiting for the broadcast recording to be published, then asking the creator to clip it.
3. Relying on the creator to manually clip highlights from their own recordings (high friction, often never happens).

Competitor platforms solve this with viewer-initiated clipping: Twitch Clips (30s/60s), YouTube Live Clipping (5-60s), and Kick Clips. These features are among the most powerful organic growth tools on those platforms because clips are inherently shareable, discoverable, and attributable to the original broadcaster.

### 1.2 How It Works

1. During a live broadcast, viewers see a "Clip" button (scissors icon) in the player controls.
2. Clicking it opens a clip creation dialog with a timeline showing the last 90 seconds of the broadcast.
3. The viewer drags start/end handles to select a range (minimum 5 seconds, maximum 60 seconds).
4. Optionally, the viewer adds a title for the clip.
5. Clicking "Create Clip" sends a request to the backend with the timestamp range.
6. The backend maps the timestamps to the broadcast recording segments, enqueues a clip extraction job, and returns immediately with a clip ID.
7. The clip job runs asynchronously using the existing FFmpeg clipping infrastructure (`video_clipper.py`).
8. Once ready, the clip appears in the **Clip Gallery** and is shareable via a direct URL.
9. The clip is attributed to the original broadcast and broadcaster, with a link back.

### 1.3 Design Principles

- **Viewer-initiated, creator-controlled**: Viewers can create clips, but creators can disable clipping on their broadcasts or delete individual clips.
- **Attribution**: Every clip links back to the original broadcast session and broadcaster profile.
- **Time-limited capture window**: Viewers can only clip from the most recent 90 seconds of the live broadcast (configurable). This prevents viewers from clipping the entire broadcast.
- **Reuse existing pipeline**: Clip extraction, transcoding, and HLS packaging reuse the `video_clipper.py` and transcode pipeline. No new media processing infrastructure is needed.
- **Discoverability**: Clips appear in a searchable gallery, can be shared to the newsfeed, and can be embedded in messages.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Viewer | As a viewer, I want to clip a 30-second highlight during a live broadcast. | Clip dialog shows timeline; after creation, clip ID returned; clip processes asynchronously. |
| Viewer | As a viewer, I want to share my clip with a direct URL. | Clip page renders at `/clips/{clip_id}` with embedded player, attribution, and share buttons. |
| Viewer | As a viewer, I want to post my clip to the newsfeed. | "Share to Feed" button creates a newsfeed post with the clip embedded. |
| Broadcaster | As a broadcaster, I want to disable clip creation on my broadcast. | Session setting `clips_enabled: false`; "Clip" button hidden for viewers. |
| Broadcaster | As a broadcaster, I want to delete a viewer's clip from my broadcast. | DELETE endpoint removes the clip; returns 200. |
| Any user | As a user, I want to browse popular clips in a gallery. | Clip gallery page shows clips sorted by view count or recency. |
| Viewer | As a viewer, I want to see all clips I have created. | "My Clips" tab shows personal clip history. |
| Broadcaster | As a broadcaster, I want to see all clips created from my broadcasts in real-time. | Dashboard panel shows clips as they are created with creator names and titles. |

---

## 2. Current State Analysis

### 2.1 Video Clipper (`app/services/video_clipper.py`) <!-- VERIFIED: app/services/video_clipper.py exists, 388 lines -->

The existing clipping service handles the full extraction pipeline. The `create_clip` function (line 51) validates the source, creates a new video record, and enqueues a job: <!-- VERIFIED: app/services/video_clipper.py:51 create_clip -->

```python
def create_clip(
    *, owner_user_id: str, source_video_id: str,
    start_seconds: float, end_seconds: float, title: Optional[str] = None,
) -> Dict[str, Any]:
    source = get_video(source_video_id)

    # Authorization
    if source.owner_user_id != owner_user_id:
        raise HTTPException(status_code=403, detail="forbidden")

    # Status check
    if source.status not in ("published", "approved"):
        raise HTTPException(status_code=400, detail="video must be published or approved")

    # Duration validation
    if start_seconds >= end_seconds:
        raise HTTPException(status_code=400, detail="start_seconds must be less than end_seconds")

    clip_duration = end_seconds - start_seconds
    min_dur = S.video_clip_min_duration_seconds
    if clip_duration < min_dur:
        raise HTTPException(status_code=400, detail=f"minimum clip length is {min_dur} seconds")
```

The key limitation is the authorization check: `source.owner_user_id != owner_user_id` restricts clipping to the video owner. For broadcast clips, we need a **viewer-initiated variant** that authorizes based on whether clipping is enabled on the broadcast session, not on video ownership.

### 2.2 FFmpeg Execution (`app/services/video_clipper.py`) <!-- VERIFIED: app/services/video_clipper.py:161 execute_clip -->

The `execute_clip` function (line 161) runs FFmpeg with stream copy first, falling back to re-encode:

```python
async def execute_clip(
    *, source_path: Path, output_path: Path,
    start_seconds: float, end_seconds: float, timeout_seconds: int = 300,
) -> ClipResult:
    expected_duration = end_seconds - start_seconds
    tolerance = getattr(S, "video_clip_copy_tolerance_seconds", 2.0) or 2.0

    # Phase 1: Try stream copy
    copy_result = await _run_clip_ffmpeg(
        source_path=source_path, output_path=output_path,
        start_seconds=start_seconds, end_seconds=end_seconds,
        stream_copy=True, timeout_seconds=timeout_seconds,
    )

    if copy_result.success:
        actual_duration = await _probe_duration(output_path)
        if actual_duration is not None and abs(actual_duration - expected_duration) <= tolerance:
            return ClipResult(output_path=output_path, duration_seconds=actual_duration, method="copy")

    # Phase 2: Re-encode fallback
    reencode_result = await _run_clip_ffmpeg(
        source_path=source_path, output_path=output_path,
        start_seconds=start_seconds, end_seconds=end_seconds,
        stream_copy=False, timeout_seconds=timeout_seconds,
    )
```

The FFmpeg command uses `-ss` (start) and `-to` (end) flags (line 331): <!-- VERIFIED: app/services/video_clipper.py:331 cmd array -->

```python
cmd = [
    ffmpeg_bin,
    "-hide_banner", "-loglevel", "warning", "-y",
    "-ss", str(start_seconds),
    "-to", str(end_seconds),
    "-i", str(source_path),
]
if stream_copy:
    cmd.extend(["-c", "copy", "-avoid_negative_ts", "make_zero"])
else:
    cmd.extend(["-c:v", "libx264", "-preset", "medium", "-crf", "22", "-c:a", "aac", "-b:a", "128k"])
cmd.extend(["-movflags", "+faststart", str(output_path)])
```

This will be reused directly for broadcast clip extraction. The source will be the recording segments rather than an uploaded video file.

### 2.3 Broadcast Recording (`app/services/broadcast_recording.py`) <!-- VERIFIED: app/services/broadcast_recording.py exists -->

Recordings are stored as `RecordingRecord` dataclass instances (line 23): <!-- VERIFIED: app/services/broadcast_recording.py:23 RecordingRecord -->

```python
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
    ...
    # Download fields (BCAST-008)
    allow_download: bool = True
    mp4_s3_key: str = ""
    mp4_size_bytes: int = 0
    s3_concatenated_key: str = ""
```

For live broadcast clipping, the `s3_archive_prefix` points to the HLS segment files on S3. The clip job needs to download the relevant segments, concatenate them, and extract the desired time range.

The `get_recording_by_session` function (line 152) retrieves the recording for a broadcast session: <!-- VERIFIED: app/services/broadcast_recording.py:152 get_recording_by_session -->

```python
def get_recording_by_session(session_id: str) -> Optional[RecordingRecord]:
    resp = T.broadcast_recordings.query(
        IndexName="BySessionId",
        KeyConditionExpression=Key("session_id").eq(session_id),
        ScanIndexForward=False, Limit=1,
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _record_from_item(items[0])
```

### 2.4 Video Listing and Publishing (`app/routers/video_listing.py`) <!-- VERIFIED: app/routers/video_listing.py exists, VideoDetailOut at line 67 -->

Published videos appear in listings and detail views. The `VideoDetailOut` model (line 67) includes fields relevant for clips:

```python
class VideoDetailOut(BaseModel):
    video_id: str
    owner_user_id: str
    title: str
    description: Optional[str] = None
    status: str
    visibility: str
    duration_seconds: Optional[float] = None
    thumbnail_url: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    ...
```

Clips will be stored as standard video metadata records with additional provenance fields (`source_broadcast_session_id`, `clip_creator_user_id`, `created_via: "broadcast_clip"`), making them playable through the same video detail and playback infrastructure.

### 2.5 Broadcast Session Outputs (`app/routers/broadcast.py`) <!-- VERIFIED: app/routers/broadcast.py:105 BroadcastSessionOut -->

The broadcast session model (line 105) already includes configuration fields:

```python
class BroadcastSessionOut(BaseModel):
    id: str
    profile_id: str
    status: str
    ...
    tip_enabled: bool = True
    tip_min_cents: int = 100
    tip_max_cents: int = 100000
```

A new `clips_enabled` field will be added, defaulting to `True`, allowing broadcasters to opt out.

### 2.6 Tip Goal SSE Pattern (`app/services/broadcast_tip_goals.py`) <!-- VERIFIED: app/services/broadcast_tip_goals.py exists -->

When a goal is created, an SSE event is published (line 59): <!-- VERIFIED: app/services/broadcast_tip_goals.py:59 approximate (SSE publish in create_goal) -->

```python
out = _goal_out(item)
broadcast_sse_publish(session_id, {"_type": "goal:created", **out})
```

Clip creation will follow the same pattern, publishing `clip:created` events to the broadcast SSE channel so the broadcaster can see clips being created in real-time.

### 2.7 Broadcast Session Fields Update (`app/services/broadcast_store.py`) <!-- VERIFIED: app/services/broadcast_store.py:459 update_session_fields -->

The `update_session_fields` function (line 459) is used to set various session configuration flags. The `clips_enabled` field will be toggled through this same mechanism: <!-- CORRECTED: was "update_session_fields(session_id, clips_enabled=False)" kwargs pattern, actual signature is update_session_fields(session_id: str, fields: Dict[str, Any]) taking a single dict -->

```python
update_session_fields(session_id, {"clips_enabled": False})
```

### 2.8 Open Graph / Social Share Meta Tags

For the public clip page (`/clips/{clip_id}`), the server needs to render Open Graph meta tags in the HTML response so that social media platforms can generate rich previews when clips are shared. The existing broadcast share page pattern can be followed.

---

## 3. Technical Design

### 3.1 DynamoDB Schema

**Table: `broadcast_clips`**

| Field | Type | Key | Description |
|-------|------|-----|-------------|
| `clip_id` | S | PK | Unique ID: `bclip_{uuid4().hex}` |
| `session_id` | S | | Source broadcast session |
| `broadcaster_user_id` | S | | Who was broadcasting |
| `creator_user_id` | S | | Who created the clip (viewer) |
| `creator_display_name` | S | | Clip creator's display name |
| `video_id` | S | | Generated video record for playback |
| `title` | S | | Clip title (viewer-provided or auto-generated) |
| `start_seconds` | N | | Start position in broadcast timeline |
| `end_seconds` | N | | End position in broadcast timeline |
| `duration_seconds` | N | | Clip duration |
| `status` | S | | `processing`, `ready`, `failed`, `deleted` |
| `error_message` | S | | Error details if status=failed |
| `view_count` | N | | Number of views |
| `share_count` | N | | Number of shares |
| `thumbnail_url` | S | | Auto-generated thumbnail |
| `playback_url` | S | | HLS manifest URL (generated on access) |
| `created_at` | N | | Creation timestamp |
| `ttl` | N | | Optional expiry (7 days for free users, permanent for subscribers) |
| `GSI1PK` | S | GSI | `SESSION#{session_id}` for listing clips per broadcast |
| `GSI1SK` | N | GSI | `{created_at}` for chronological ordering |
| `GSI2PK` | S | GSI | `CREATOR#{creator_user_id}` for listing a user's clips |
| `GSI2SK` | N | GSI | `{created_at}` |
| `GSI3PK` | S | GSI | `GALLERY` for global clip gallery |
| `GSI3SK` | S | GSI | `{view_count_padded}#{created_at}` for popularity sorting |

DynamoDB table definition for `scripts/local-ddb-init.py`:

```python
TableDef(
    "broadcast_clips",
    "clip_id",
    gsi=[
        {"index_name": "BySession", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
        {"index_name": "ByCreator", "partition_key": "GSI2PK", "sort_key": "GSI2SK"},
        {"index_name": "ByGallery", "partition_key": "GSI3PK", "sort_key": "GSI3SK"},
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N"},
),
```

### 3.2 Clip Creation Flow

```
Viewer clicks "Clip"
        |
        v
POST /broadcast/sessions/{id}/clips
  { start_seconds, end_seconds, title? }
        |
        v
Backend validates:
  - Session is live or has a recording
  - Clips are enabled for this session
  - Time range is within the last 90s of live broadcast
  - Duration is between 5s and 60s
  - User has not exceeded clip quota (10 per broadcast)
  - User is authenticated and not muted
        |
        v
Create clip record (status=processing)
Create video metadata record (status=pending_encoding)
Enqueue clip job
        |
        v
Return { clip_id, status: "processing" }
        |
        v
SSE: { _type: "clip:created", clip_id, creator_display_name, title }
        |
        v  (async job)
Download relevant S3 segments
Extract time range via FFmpeg
Upload clip MP4 to S3
Enqueue ABR transcode job
        |
        v
Update clip record (status=ready)
SSE: { _type: "clip:ready", clip_id }
```

### 3.3 Service Layer (`app/services/broadcast_clip.py`)

```python
"""Broadcast clip service -- viewer-initiated clipping (ENGAGE-005)."""

from __future__ import annotations

import logging
import threading
import time
from decimal import Decimal
from pathlib import Path
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

# ─── Rate Limiting ───────────────────────────────────────
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

    Validates all constraints, creates clip + video records, enqueues job.
    Returns immediately with clip_id and status=processing.
    """
    from app.services.broadcast_store import get_session

    # Validate session
    session = get_session(session_id)
    if not session:
        raise HTTPException(404, "Broadcast session not found")

    # Check clips enabled
    if not session.get("clips_enabled", True):
        raise HTTPException(403, {
            "code": "CLIPPING_DISABLED",
            "message": "Clip creation is disabled for this broadcast.",
        })

    # Session must be live or have a recording
    session_status = session.get("status", "")
    recording = get_recording_by_session(session_id)
    if session_status != "live" and (not recording or recording.status != "ready"):
        raise HTTPException(400, "No recording available for clipping")

    # Rate limit
    _enforce_clip_rate_limit(session_id, creator_user_id)

    # Duration validation
    clip_duration = end_seconds - start_seconds
    if start_seconds >= end_seconds:
        raise HTTPException(400, "start_seconds must be less than end_seconds")
    if clip_duration < _MIN_CLIP_DURATION:
        raise HTTPException(400, f"Minimum clip duration is {_MIN_CLIP_DURATION} seconds")
    if clip_duration > _MAX_CLIP_DURATION:
        raise HTTPException(400, f"Maximum clip duration is {_MAX_CLIP_DURATION} seconds")

    # Capture window validation (for live broadcasts)
    if session_status == "live":
        broadcast_duration = float(recording.duration_seconds) if recording else 0
        if broadcast_duration > 0 and start_seconds < max(0, broadcast_duration - _CAPTURE_WINDOW_SECONDS):
            raise HTTPException(400, f"Can only clip from the last {_CAPTURE_WINDOW_SECONDS} seconds")

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
    auto_title = title or f"Clip from {session.get('profile_name', 'broadcast')}"

    clip_item = {
        "clip_id": clip_id,
        "session_id": session_id,
        "broadcaster_user_id": session.get("created_by", ""),
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

    # Optional TTL for free-tier clips
    if not _is_subscriber(creator_user_id):
        clip_item["ttl"] = ts + 7 * 86400  # 7-day expiry

    T.broadcast_clips.put_item(Item=clip_item)

    # Create video metadata record (for the standard video pipeline)
    _create_clip_video_record(
        video_id=video_id,
        owner_user_id=creator_user_id,
        title=auto_title,
        source_session_id=session_id,
        clip_id=clip_id,
    )

    # Enqueue clip extraction job
    _enqueue_clip_job({
        "clip_id": clip_id,
        "session_id": session_id,
        "video_id": video_id,
        "start_seconds": start_seconds,
        "end_seconds": end_seconds,
    })

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
        "ScanIndexForward": False if sort == "popular" else False,
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


def delete_clip(clip_id: str, actor: str) -> Dict[str, Any]:
    """Delete a clip (soft delete).

    Authorized for: clip creator, broadcaster, or admin.
    """
    resp = T.broadcast_clips.get_item(Key={"clip_id": clip_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, "Clip not found")

    # Authorization
    if (
        actor != item.get("creator_user_id")
        and actor != item.get("broadcaster_user_id")
    ):
        # Could also check admin role here
        raise HTTPException(403, "Not authorized to delete this clip")

    T.broadcast_clips.update_item(
        Key={"clip_id": clip_id},
        UpdateExpression="SET #s = :deleted",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":deleted": "deleted"},
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


# ─── Internal helpers ─────────────────────────────────────

def _count_user_clips_for_session(session_id: str, user_id: str) -> int:
    """Count clips created by a user for a specific session."""
    resp = T.broadcast_clips.query(
        IndexName="BySession",
        KeyConditionExpression=Key("GSI1PK").eq(f"SESSION#{session_id}"),
        FilterExpression=Attr("creator_user_id").eq(user_id) & Attr("status").ne("deleted"),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def _create_clip_video_record(
    video_id: str,
    owner_user_id: str,
    title: str,
    source_session_id: str,
    clip_id: str,
) -> None:
    """Create a video metadata record for the clip output."""
    from app.services.video_metadata_store import create_video
    create_video(
        video_id=video_id,
        owner_user_id=owner_user_id,
        title=title,
        status="pending_encoding",
        visibility="public",
        source_type="broadcast_clip",
        extra_fields={
            "source_broadcast_session_id": source_session_id,
            "clip_id": clip_id,
            "created_via": "broadcast_clip",
        },
    )


def _enqueue_clip_job(job: Dict[str, Any]) -> None:
    """Enqueue a clip extraction job for async processing.

    In dev mode, this runs synchronously. In production, this would
    publish to an SQS queue or invoke a Lambda.
    """
    if S.dev_mode:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_process_clip_job_async(job))
        except RuntimeError:
            # No event loop -- run synchronously
            asyncio.run(_process_clip_job_async(job))
    else:
        # Production: publish to SQS
        logger.info("Would enqueue clip job: %s", job)


async def _process_clip_job_async(job: Dict[str, Any]) -> None:
    """Process a clip extraction from a broadcast recording."""
    import tempfile
    from app.services.video_clipper import execute_clip

    clip_id = job["clip_id"]
    session_id = job["session_id"]
    start_seconds = float(job["start_seconds"])
    end_seconds = float(job["end_seconds"])
    video_id = job["video_id"]

    try:
        # Get recording for session
        recording = get_recording_by_session(session_id)
        if not recording:
            raise ClipProcessingError("No recording found for session")

        # In dev mode, create a placeholder clip
        if S.dev_mode:
            _mark_clip_ready(clip_id, end_seconds - start_seconds)
            return

        # Production: download segments, extract, upload
        with tempfile.TemporaryDirectory() as scratch_dir:
            scratch = Path(scratch_dir)
            source_path = await _download_broadcast_segments(
                recording, start_seconds, end_seconds, scratch,
            )
            clip_path = scratch / f"{clip_id}.mp4"

            result = await execute_clip(
                source_path=source_path,
                output_path=clip_path,
                start_seconds=0,  # Segments already trimmed
                end_seconds=end_seconds - start_seconds,
                timeout_seconds=300,
            )

            # Upload to S3
            clip_s3_key = f"clips/{session_id}/{clip_id}/clip.mp4"
            from app.core.aws_clients import s3_client
            s3 = s3_client()
            bucket = S.vod_output_bucket or "vod-output"
            s3.upload_file(str(clip_path), bucket, clip_s3_key)

            # Update video metadata
            T.video_metadata.update_item(
                Key={"video_id": video_id},
                UpdateExpression=(
                    "SET source_s3_key = :sk, #s = :status, "
                    "duration_seconds = :dur"
                ),
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":sk": clip_s3_key,
                    ":status": "pending_encoding",
                    ":dur": Decimal(str(result.duration_seconds)),
                },
            )

            _mark_clip_ready(clip_id, result.duration_seconds)

    except Exception as exc:
        logger.error("Clip job failed: clip=%s error=%s", clip_id, exc)
        T.broadcast_clips.update_item(
            Key={"clip_id": clip_id},
            UpdateExpression="SET #s = :failed, error_message = :err",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":failed": "failed",
                ":err": str(exc)[:500],
            },
        )


def _mark_clip_ready(clip_id: str, duration: float) -> None:
    """Mark clip as ready after successful processing."""
    T.broadcast_clips.update_item(
        Key={"clip_id": clip_id},
        UpdateExpression=(
            "SET #s = :ready, duration_seconds = :dur"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":ready": "ready",
            ":dur": Decimal(str(duration)),
        },
    )


async def _download_broadcast_segments(
    recording: Any,
    start_seconds: float,
    end_seconds: float,
    scratch_dir: Path,
) -> Path:
    """Download relevant HLS segments from S3 and concatenate.

    Returns path to concatenated source file.
    """
    # Implementation would:
    # 1. Parse HLS manifest to find segment files covering the time range
    # 2. Download relevant .ts segments
    # 3. Concatenate them using FFmpeg concat demuxer
    # 4. Return path to concatenated file
    raise NotImplementedError("Production implementation needed")


def _is_subscriber(user_sub: str) -> bool:
    """Check if user has an active subscription (for TTL exemption)."""
    try:
        from app.services.subscription_access import has_active_subscription
        return has_active_subscription(user_sub)
    except Exception:
        return False


class ClipProcessingError(Exception):
    pass


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
```

### 3.4 Pydantic Models

```python
# Request/response models for clip endpoints

class CreateClipIn(BaseModel):
    start_seconds: float = Field(..., ge=0)
    end_seconds: float = Field(..., ge=0)
    title: Optional[str] = Field(default=None, max_length=100)

class ClipOut(BaseModel):
    clip_id: str
    session_id: str
    broadcaster_user_id: str
    creator_user_id: str
    creator_display_name: str
    video_id: str
    title: str
    start_seconds: float
    end_seconds: float
    duration_seconds: float
    status: Literal["processing", "ready", "failed", "deleted"]
    view_count: int
    share_count: int
    thumbnail_url: str
    created_at: int

class ClipListOut(BaseModel):
    clips: List[ClipOut]
    next_cursor: Optional[str] = None
```

### 3.5 Clip Gallery

The clip gallery is a browseable feed of clips, sorted by popularity (view count) or recency. It queries `GSI3PK = "GALLERY"` with `ScanIndexForward=False` for most-popular-first.

Clips can be filtered by:
- Broadcaster (all clips from a specific creator's broadcasts)
- Broadcast session (all clips from a specific broadcast)
- Time window (clips created in the last 24 hours, week, month)

### 3.6 Clip Sharing

Clips can be shared via:
1. **Direct URL**: `/clips/{clip_id}` -- a public page with embedded player, attribution, and share buttons.
2. **Newsfeed post**: "Share to Feed" creates a post with `video_id` pointing to the clip's video record.
3. **DM message**: Share as a `kind: "video_share"` message in a conversation.

### 3.7 Open Graph Meta Tags

The public clip page returns HTML with Open Graph tags for social media previews:

```python
@router.get("/clips/{clip_id}", response_class=HTMLResponse)
def clip_public_page(clip_id: str):
    clip = get_clip(clip_id)
    og_tags = f"""
    <meta property="og:title" content="{escape(clip['title'])}" />
    <meta property="og:description" content="Clip from {escape(clip.get('broadcaster_display_name', 'broadcast'))}" />
    <meta property="og:image" content="{clip.get('thumbnail_url', '')}" />
    <meta property="og:type" content="video.other" />
    <meta property="og:video" content="/api/clips/{clip_id}/playback" />
    <meta name="twitter:card" content="player" />
    """
    # Return SPA shell with OG tags injected
```

---

## 4. API Endpoints

### 4.1 Clip Creation

```
POST /broadcast/sessions/{session_id}/clips
```

Auth: `Depends(require_ui_session)` -- any authenticated, non-muted user.

Request:
```json
{
  "start_seconds": 45.0,
  "end_seconds": 75.0,
  "title": "Amazing play!"
}
```

Response (200):
```json
{
  "clip_id": "bclip_abc123def456",
  "session_id": "sess_xyz",
  "broadcaster_user_id": "creator123",
  "creator_user_id": "viewer456",
  "creator_display_name": "ViewerName",
  "video_id": "v_abc123",
  "title": "Amazing play!",
  "start_seconds": 45.0,
  "end_seconds": 75.0,
  "duration_seconds": 30.0,
  "status": "processing",
  "view_count": 0,
  "share_count": 0,
  "thumbnail_url": "",
  "created_at": 1748400000
}
```

Error responses:
- 400: Duration out of range, start >= end, not within capture window
- 403: Clipping disabled for this broadcast
- 404: Session not found
- 429: Rate limited or quota exceeded

### 4.2 Clip Retrieval

```
GET /broadcast/clips/{clip_id}                    -- Get clip details
GET /broadcast/sessions/{session_id}/clips        -- List clips for a broadcast
GET /ui/clips                                     -- Gallery (public, paginated)
GET /ui/clips/mine                                -- User's own clips
```

**GET /ui/clips** -- Gallery listing.

Query params:
- `sort`: `popular` | `recent` (default `popular`)
- `limit`: int (default 50, max 100)
- `cursor`: Optional[str]

Response (200):
```json
{
  "clips": [
    {
      "clip_id": "bclip_abc123",
      "title": "Amazing play!",
      "duration_seconds": 30.0,
      "view_count": 1250,
      "thumbnail_url": "...",
      "creator_display_name": "ViewerName",
      "broadcaster_user_id": "creator123",
      "created_at": 1748400000
    }
  ],
  "next_cursor": "eyJwayI6Li4u"
}
```

### 4.3 Clip Management

```
DELETE /broadcast/clips/{clip_id}                 -- Delete clip (creator or broadcaster)
POST  /broadcast/clips/{clip_id}/view             -- Record a view
POST  /broadcast/clips/{clip_id}/share            -- Record a share (and return share URL)
```

### 4.4 Clip Settings on Broadcast Session

```
PATCH /broadcast/sessions/{session_id}
```

Request: `{ "clips_enabled": false }`

### 4.5 Clip Page (Public)

```
GET /clips/{clip_id}                              -- Public clip page (no auth required)
```

Returns HTML page with embedded player, broadcaster attribution, and social share meta tags (Open Graph, Twitter Card).

---

## 5. Frontend Components

### 5.1 New Components

| Component | Path | Description |
|-----------|------|-------------|
| `ClipButton` | `pages/broadcast/ClipButton.tsx` | Scissors icon button in viewer player controls |
| `ClipCreatorDialog` | `pages/broadcast/ClipCreatorDialog.tsx` | Timeline with draggable handles for start/end; title input; "Create Clip" button |
| `ClipTimeline` | `pages/broadcast/ClipTimeline.tsx` | Visual timeline showing last 90 seconds with frame previews |
| `ClipGalleryPage` | `pages/clips/ClipGalleryPage.tsx` | Browseable gallery with filter/sort controls |
| `ClipCard` | `pages/clips/ClipCard.tsx` | Thumbnail, title, broadcaster name, view count, share button |
| `ClipPlayerPage` | `pages/clips/ClipPlayerPage.tsx` | Public clip page with player, attribution, share buttons |
| `ClipFeed` | `pages/clips/ClipFeed.tsx` | Infinite-scroll list of clip cards (used in gallery and per-broadcaster views) |
| `BroadcasterClipPanel` | `pages/broadcast/BroadcasterClipPanel.tsx` | Dashboard panel showing clips being created during live broadcast |

### 5.2 TypeScript Types

```typescript
// frontend/src/api/types.ts additions

export interface BroadcastClip {
  clip_id: string;
  session_id: string;
  broadcaster_user_id: string;
  creator_user_id: string;
  creator_display_name: string;
  video_id: string;
  title: string;
  start_seconds: number;
  end_seconds: number;
  duration_seconds: number;
  status: "processing" | "ready" | "failed" | "deleted";
  view_count: number;
  share_count: number;
  thumbnail_url: string;
  created_at: number;
}

export interface ClipListResponse {
  clips: BroadcastClip[];
  next_cursor?: string;
}
```

### 5.3 API Endpoints

```typescript
// frontend/src/api/endpoints/clips.ts

import client from "../client";
import type { BroadcastClip, ClipListResponse } from "../types";

export const createClip = async (sessionId: string, data: { start_seconds: number; end_seconds: number; title?: string }) =>
  client.post<BroadcastClip>(`/broadcast/sessions/${sessionId}/clips`, data).then(r => r.data);

export const getClip = async (clipId: string) =>
  client.get<BroadcastClip>(`/broadcast/clips/${clipId}`).then(r => r.data);

export const listSessionClips = async (sessionId: string) =>
  client.get<{ clips: BroadcastClip[] }>(`/broadcast/sessions/${sessionId}/clips`).then(r => r.data);

export const listGallery = async (params?: { sort?: string; limit?: number; cursor?: string }) =>
  client.get<ClipListResponse>("/ui/clips", { params }).then(r => r.data);

export const listMyClips = async () =>
  client.get<{ clips: BroadcastClip[] }>("/ui/clips/mine").then(r => r.data);

export const deleteClip = async (clipId: string) =>
  client.delete(`/broadcast/clips/${clipId}`).then(r => r.data);

export const recordClipView = async (clipId: string) =>
  client.post(`/broadcast/clips/${clipId}/view`).then(r => r.data);

export const recordClipShare = async (clipId: string) =>
  client.post<{ share_url: string }>(`/broadcast/clips/${clipId}/share`).then(r => r.data);
```

### 5.4 Viewer Player Integration

The "Clip" button appears in the player controls when `clips_enabled` is true:

```tsx
{session.clips_enabled && (
    <Button variant="ghost" size="icon" onClick={() => setClipDialogOpen(true)} title="Create Clip">
        <Scissors className="h-5 w-5" />
    </Button>
)}
```

### 5.5 Clip Creator Dialog

```tsx
// frontend/src/pages/broadcast/ClipCreatorDialog.tsx
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createClip } from "@/api/endpoints/clips";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import { Scissors } from "lucide-react";
import { toast } from "sonner";

interface ClipCreatorDialogProps {
  sessionId: string;
  broadcastDuration: number;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ClipCreatorDialog({ sessionId, broadcastDuration, open, onOpenChange }: ClipCreatorDialogProps) {
  const captureWindow = 90; // seconds
  const windowStart = Math.max(0, broadcastDuration - captureWindow);

  const [range, setRange] = useState([windowStart + 30, windowStart + 60]);
  const [title, setTitle] = useState("");

  const queryClient = useQueryClient();
  const createMut = useMutation({
    mutationFn: () => createClip(sessionId, {
      start_seconds: range[0],
      end_seconds: range[1],
      title: title || undefined,
    }),
    onSuccess: (data) => {
      toast.success(`Clip "${data.title}" is being created!`);
      queryClient.invalidateQueries({ queryKey: ["clips", sessionId] });
      onOpenChange(false);
    },
    onError: (err: any) => {
      const detail = err?.response?.data?.detail;
      const code = typeof detail === "object" ? detail?.code : detail;
      if (code === "CLIP_QUOTA_EXCEEDED") {
        toast.error("You have reached the maximum number of clips for this broadcast.");
      } else if (code === "CLIP_RATE_LIMITED") {
        toast.error("Please wait before creating another clip.");
      } else {
        toast.error(typeof detail === "string" ? detail : "Failed to create clip.");
      }
    },
  });

  const clipDuration = range[1] - range[0];
  const isValid = clipDuration >= 5 && clipDuration <= 60;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Scissors className="h-5 w-5" /> Create Clip
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <label className="text-sm font-medium">
              Select range ({clipDuration.toFixed(1)}s)
            </label>
            <Slider
              value={range}
              min={windowStart}
              max={broadcastDuration}
              step={0.5}
              onValueChange={setRange}
              className="mt-2"
            />
            <div className="flex justify-between text-xs text-muted-foreground mt-1">
              <span>{formatTime(range[0])}</span>
              <span>{formatTime(range[1])}</span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-sm">
            {clipDuration < 5 && (
              <span className="text-destructive">Minimum 5 seconds</span>
            )}
            {clipDuration > 60 && (
              <span className="text-destructive">Maximum 60 seconds</span>
            )}
            {isValid && (
              <span className="text-muted-foreground">
                Duration: {clipDuration.toFixed(1)}s
              </span>
            )}
          </div>

          <Input
            placeholder="Clip title (optional)"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            maxLength={100}
          />

          <Button
            onClick={() => createMut.mutate()}
            disabled={!isValid || createMut.isPending}
            className="w-full"
          >
            {createMut.isPending ? "Creating..." : "Create Clip"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${s.toString().padStart(2, "0")}`;
}
```

### 5.6 ClipCard Component

```tsx
// frontend/src/pages/clips/ClipCard.tsx
import { Card, CardContent } from "@/components/ui/card";
import { Eye, Share2, Clock } from "lucide-react";
import type { BroadcastClip } from "@/api/types";

interface ClipCardProps {
  clip: BroadcastClip;
  onClick?: () => void;
}

export function ClipCard({ clip, onClick }: ClipCardProps) {
  return (
    <Card
      className="cursor-pointer hover:shadow-md transition-shadow overflow-hidden"
      onClick={onClick}
    >
      <div className="relative aspect-video bg-muted">
        {clip.thumbnail_url ? (
          <img src={clip.thumbnail_url} alt={clip.title} className="w-full h-full object-cover" />
        ) : (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {clip.status === "processing" ? "Processing..." : "No thumbnail"}
          </div>
        )}
        <span className="absolute bottom-1 right-1 bg-black/70 text-white text-xs px-1 rounded">
          {clip.duration_seconds.toFixed(0)}s
        </span>
      </div>
      <CardContent className="p-3">
        <p className="text-sm font-medium line-clamp-1">{clip.title}</p>
        <p className="text-xs text-muted-foreground mt-0.5">
          by {clip.creator_display_name}
        </p>
        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Eye className="h-3 w-3" /> {clip.view_count}
          </span>
          <span className="flex items-center gap-1">
            <Share2 className="h-3 w-3" /> {clip.share_count}
          </span>
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" /> {formatRelativeTime(clip.created_at)}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

function formatRelativeTime(ts: number): string {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
```

### 5.7 Clip Gallery Route

```tsx
// In App.tsx
const ClipGalleryPage = lazy(() => import("./pages/clips/ClipGalleryPage"));
const ClipPlayerPage = lazy(() => import("./pages/clips/ClipPlayerPage"));

<Route path="/clips" element={<ClipGalleryPage />} />
<Route path="/clips/:clipId" element={<ClipPlayerPage />} />
```

### 5.8 Broadcaster Dashboard Panel

During a live broadcast, the dashboard shows a "Clips" tab with real-time notifications as viewers create clips:

```tsx
// SSE handler
case "clip:created":
    setNewClips(prev => [event, ...prev]);
    toast.success(`${event.creator_display_name} created a clip: "${event.title}"`);
    queryClient.invalidateQueries({ queryKey: ["clips", sessionId] });
    break;
case "clip:ready":
    queryClient.invalidateQueries({ queryKey: ["clips", sessionId] });
    break;
```

---

## 6. E2E Test Plan

### Section 98: Broadcast Clip Creation API

| # | Test | Assertion |
|---|------|-----------|
| 98.1 | Viewer creates a clip during a live broadcast | 200, clip_id, status="processing" |
| 98.2 | Clip with duration < 5s rejected | 400, "Minimum clip duration" |
| 98.3 | Clip with duration > 60s rejected | 400, "Maximum clip duration" |
| 98.4 | Clip when clips_enabled=false rejected | 403, "CLIPPING_DISABLED" |
| 98.5 | Clip quota exceeded (>10 per broadcast) | 429, "CLIP_QUOTA_EXCEEDED" |
| 98.6 | Clip start_seconds >= end_seconds rejected | 400, "start_seconds must be less than end_seconds" |
| 98.7 | Clip rate limit (1 per 30s) | 429 on second clip within 30s |
| 98.8 | Clip with title | 200, title matches input |
| 98.9 | Clip without title gets auto-generated title | 200, title contains broadcast name |
| 98.10 | Clip title truncated at 100 chars | Title capped at 100 |

### Section 99: Clip Retrieval API

| # | Test | Assertion |
|---|------|-----------|
| 99.1 | Get clip by ID | 200, clip details with attribution |
| 99.2 | List clips for a broadcast session | 200, array of clips |
| 99.3 | Gallery listing returns clips sorted by views | Descending view_count order |
| 99.4 | "My clips" listing returns only creator's clips | All clips have creator_user_id matching |
| 99.5 | Gallery pagination with cursor | Next page returns different clips |
| 99.6 | Deleted clip not returned in listings | status="deleted" clips filtered out |
| 99.7 | Non-existent clip returns 404 | 404 |

### Section 100: Clip Management API

| # | Test | Assertion |
|---|------|-----------|
| 100.1 | Clip creator can delete their clip | 200, status="deleted" |
| 100.2 | Broadcaster can delete any clip from their broadcast | 200, status="deleted" |
| 100.3 | Random user cannot delete another's clip | 403 |
| 100.4 | Record a view increments view_count | view_count increases by 1 |
| 100.5 | Record a share increments share_count | share_count increases by 1, share_url returned |
| 100.6 | Multiple views from same user all count | view_count = N after N calls |

### Section 101: Clip Gallery UI

| # | Test | Assertion |
|---|------|-----------|
| 101.1 | Gallery page renders clip cards | ClipCard elements visible |
| 101.2 | Clip card shows thumbnail, title, view count | Correct data displayed |
| 101.3 | Clicking clip card navigates to clip player | URL changes to /clips/{clipId} |
| 101.4 | Clip player page shows embedded player with attribution | Player + broadcaster name visible |
| 101.5 | "Clip" button visible when clips_enabled=true | Scissors icon button visible |
| 101.6 | "Clip" button hidden when clips_enabled=false | Button not rendered |
| 101.7 | Clip creator dialog shows timeline and duration | Slider + duration text visible |

---

## 7. Edge Cases

1. **Clipping during live vs. from recording**: During a live broadcast, the "source" is the live recording archive (HLS segments accumulating in S3). The clip job must handle the case where segments are still being written. Solution: the clip job waits for the segment covering the end timestamp to appear (with a timeout of 60 seconds).

2. **Broadcast without recording enabled**: If the broadcaster has recording disabled, there are no S3 segments to clip from. In this case, clipping is unavailable and the "Clip" button is hidden. The backend checks for an active recording before allowing clip creation.

3. **Time range beyond current broadcast duration**: A viewer might attempt to clip a range that extends beyond the current broadcast time (e.g., seeking forward in a delayed stream). The backend validates against the recording's current duration.

4. **Concurrent clip jobs**: Multiple viewers clipping the same moment generate separate jobs but may download the same S3 segments. This is acceptable -- the segments are read-only and can be downloaded in parallel without conflict.

5. **Clip of clipped content**: Clips are standard video records. A viewer could technically clip someone else's clip via the VOD clipping tool. This is allowed -- the provenance chain is maintained through `source_video_id`.

6. **Broadcaster deletes recording**: If the recording is deleted (expired or manually removed), existing clips remain playable because they are independent video records with their own S3 assets. The `source_broadcast_session_id` link becomes a dead reference.

7. **Storage costs**: Each clip generates a new video with full ABR renditions. For a popular broadcast with 100 clips of 30 seconds each, this is ~50 minutes of video at multiple renditions. The `ttl` field on free-tier clips (7-day expiry) prevents unbounded growth.

8. **Clip processing failure**: If FFmpeg fails (corrupt segments, I/O error), the clip status transitions to `failed` with an error message. The viewer sees "Clip failed" in their clip list. No automatic retry -- the viewer can create a new clip attempt.

9. **Broadcast ends during clip creation**: If the broadcast ends while a clip job is in progress, the recording segments are still available (recordings persist after broadcast end). The clip job completes normally.

10. **Gallery sort key update race**: When multiple views happen simultaneously, each update to `GSI3SK` (view_count_padded) may use a stale value. This is acceptable for a popularity ranking -- eventual consistency in sort order does not affect correctness.

---

## 8. Security Considerations

1. **Authorization model**: Viewers can create clips from broadcasts where `clips_enabled=true`. Creators can disable clipping via session settings. Creators and clip authors can delete clips. Admins can delete any clip via the moderation API.

2. **Content moderation**: Clips inherit the broadcaster's content policy. An admin can delete any clip via the moderation API. Clips flagged for review follow the same moderation queue as uploaded videos.

3. **Rate limiting**: Per-user clip creation is rate-limited to 10 clips per broadcast and 1 clip every 30 seconds (prevents abuse during high-viewer broadcasts). Rate limits use the same in-memory bucket pattern as broadcast chat.

4. **DMCA / takedown**: Clips maintain provenance. If a broadcast recording is subject to a takedown, all clips derived from it can be identified via `session_id` and bulk-removed:
   ```python
   # Bulk takedown for a session
   clips = list_clips_for_session(session_id)
   for clip in clips:
       delete_clip(clip["clip_id"], actor="admin")
   ```

5. **Playback URL signing**: Clip playback URLs are signed the same way as regular VOD URLs via `mint_vod_playback_url()`. No unsigned public access.

6. **Clip title content**: Titles are plain text, max 100 characters, HTML-escaped on render. No markdown or rich text in clip titles.

7. **S3 bucket isolation**: Clips are stored in the same bucket as regular videos but under a `clips/` prefix. IAM policies can be scoped to prevent cross-tenant access.

8. **View count inflation**: View counts are incremented atomically via DDB, but there is no deduplication per viewer. A determined user could inflate view counts by calling the endpoint repeatedly. Mitigation options: IP-based dedup (future), or accept that view counts are approximate engagement signals.

---

## 9. Rollout Plan

1. **Phase 1** (days 1-4): Backend -- DDB table, broadcast_clip.py service (create, get, list, delete, view/share counters), rate limiting, quota enforcement. Session `clips_enabled` field.

2. **Phase 2** (days 5-8): Clip processing pipeline -- segment download, FFmpeg extraction using video_clipper.py, S3 upload, video metadata record creation, async job queue. Dev mode placeholder.

3. **Phase 3** (days 9-11): Frontend -- ClipButton, ClipCreatorDialog, ClipTimeline, ClipGalleryPage, ClipCard, ClipPlayerPage, BroadcasterClipPanel. SSE handlers for clip:created/clip:ready.

4. **Phase 4** (days 12-16): E2E tests (sections 98-101), Open Graph meta tags for public clip page, clip sharing to newsfeed/DM, integration testing with real FFmpeg, QA.

Feature flag: `BROADCAST_CLIPS_ENABLED` (default `false`). When disabled, the `clips_enabled` field defaults to `false` on all sessions, and the ClipButton is hidden in the frontend.
