# VOD-006: Video Listing API + Pagination

**Ticket**: VOD-006
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-24

---

## 1. Overview & Motivation

### 1.1 Purpose

VOD-006 provides the HTTP API layer that allows creators to browse, filter, and manage their video library, and enables viewers to discover and access public or entitled video content. Without these endpoints, the video metadata records created by VOD-001 and populated by the transcode pipeline (VOD-003 through VOD-005) are unreachable from both the frontend and external API consumers.

### 1.2 User Stories

| Actor | Story | Acceptance |
|-------|-------|------------|
| Creator | As a creator, I want to list all my uploaded videos sorted by newest first, so I can monitor processing status and manage my library. | Paginated list, filterable by status, cursor-based navigation. |
| Creator | As a creator, I want to view a single video's full details including playback URL, so I can preview or share it. | Detail endpoint returns metadata + signed playback URL with entitlement token. |
| Creator | As a creator, I want to update my video's title, description, and visibility, so I can correct metadata or publish/unpublish content. | PATCH endpoint with partial updates. |
| Creator | As a creator, I want to soft-delete a video, so it disappears from listings without immediately destroying S3 assets. | DELETE sets `status=deleted` + `deleted_at`; hidden from all future listings. |
| Viewer | As a viewer, I want to browse publicly available videos from a creator, so I can discover content. | Public listing endpoint returns only `published` + `visibility=public` videos. |
| Viewer | As a viewer, I want to watch a video I'm entitled to, receiving a time-limited playback URL. | Detail endpoint checks entitlement, issues playback token via `playback_entitlements.py`. |
| Admin | As an admin, I want to list videos by processing status, so I can investigate stuck/failed jobs and moderate content. | Admin listing endpoint queries `ByStatusCreatedAt` GSI. |

### 1.3 Why This Is Needed Now

The VOD pipeline produces encoded video assets (VOD-003 through VOD-005) and stores their metadata in the `VideoMetadata` table (VOD-001), but there is currently no HTTP interface to read that data. The frontend video library page (VOD-007) and video player page (VOD-008) both depend on these endpoints. Additionally, the admin moderation workflow requires listing videos by status to approve or reject content before publication.

---

## 2. Current State Analysis

### 2.1 Video Metadata Table (from VOD-001)

The `VideoMetadata` DynamoDB table is defined with:

- **Primary Key**: `video_id` (String) -- UUID format `v_<uuid4_hex>`
- **GSI `ByOwnerCreatedAt`**: PK = `owner_user_id` (S), SK = `created_at` (N) -- creator's video library listing
- **GSI `ByStatusCreatedAt`**: PK = `status` (S), SK = `created_at` (N) -- admin/worker status queries
- **GSI `BySourceBroadcast`**: PK = `source_broadcast_session_id` (S) -- broadcast archive lookup

The `attr_types={"created_at": "N"}` declaration enables integer sort key queries. Videos use `now_ts()` (integer Unix seconds) for timestamps.

### 2.2 Existing Listing Patterns in the Codebase

**Pattern A: Broadcast Store** (`app/services/broadcast_store.py`, lines 306-343)

The most directly applicable pattern. `list_sessions_by_creator` and `list_sessions_by_status` both:
1. Accept `limit` (1-200) and `cursor` (raw DDB `LastEvaluatedKey` dict)
2. Query a named GSI with `ScanIndexForward=False` (newest first)
3. Return `{"items": [Model, ...], "cursor": <LastEvaluatedKey or None>}`

```python
def list_sessions_by_creator(created_by: str, *, limit: int = 50, cursor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "IndexName": "ByCreatorCreatedAt",
        "KeyConditionExpression": Key("created_by").eq(created_by),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor
    resp = T.broadcast_sessions.query(**kwargs)
    items = [session_from_item(i) for i in resp.get("Items", [])]
    return {"items": items, "cursor": resp.get("LastEvaluatedKey")}
```

**Pattern B: Projects Router** (`app/routers/projects.py`, lines 173-222)

The router-level cursor encoding pattern used for external API exposure:
1. `_encode_cursor(dict)` serializes DDB `LastEvaluatedKey` to URL-safe base64 string
2. `_decode_cursor(str)` deserializes back, raising 400 on invalid input
3. Query param: `cursor: Optional[str] = Query(default=None)`
4. Response model includes `cursor: Optional[str]`

**Pattern C: Signed Cursor** (`app/core/cursor.py`)

A more secure cursor implementation that HMAC-signs the payload to prevent cursor tampering. Uses format `v2.<payload_b64>.<signature>`. This is the recommended approach for public-facing APIs where clients could forge pagination cursors to access data outside their partition.

**Pattern D: File Manager Paginated Listing** (`app/services/filemanager.py`, lines 469-514)

`list_children_page` demonstrates multi-index fallback and tuple return `(items, cursor)`.

**Pattern E: Catalog Item Listing** (`app/routers/catalog.py`, lines 344-376)

Demonstrates paginated listing with access control checks (subscription gating) and `next_token` naming convention for the cursor parameter.

### 2.3 Playback Entitlement Integration

`app/services/playback_entitlements.py` provides `issue_playback_entitlement()` which generates a signed JWT token with:
- `tenant_id`, `asset_id`, `session_id`, `device_id`, `profile`
- `aud` (audience -- the playback endpoint URL)
- `exp` (expiration epoch)
- Configurable TTL (max from `S.playback_entitlement_max_ttl_seconds`)

The video detail endpoint must call this function to generate a time-limited playback URL for authorized viewers.

### 2.4 Auth Patterns

All UI endpoints use `require_ui_session` from `app/services/sessions.py` (cookie-based auth with CSRF). Admin endpoints use `require_admin_session`. The session context returns `{"user_sub": str, "role": Role, "admin_profile": AdminProfile | None}`.

### 2.5 Gaps

1. **No router exists** for video metadata -- `app/routers/video_metadata.py` does not exist yet.
2. **No public/viewer listing** -- the `ByOwnerCreatedAt` GSI returns all videos regardless of visibility/status; a viewer-facing endpoint needs additional filtering.
3. **No `ByVisibilityPublishedAt` GSI** -- listing public videos across all creators requires either a new GSI or a scan with filter (unacceptable at scale). Design must address this.
4. **No video metadata store** -- `app/services/video_metadata_store.py` must be created as part of VOD-001 implementation; this spec assumes it exists.

---

## 3. Technical Design

### 3.1 Endpoint Summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/videos` | `require_ui_session` | List caller's own videos (paginated, filterable) |
| GET | `/ui/videos/{video_id}` | `require_ui_session` | Get video detail + playback URL |
| PATCH | `/ui/videos/{video_id}` | `require_ui_session` | Update title/description/visibility |
| DELETE | `/ui/videos/{video_id}` | `require_ui_session` | Soft-delete video |
| GET | `/ui/videos/public` | `require_ui_session` | Browse public/published videos (viewer discovery) |
| GET | `/ui/videos/creator/{creator_id}` | `require_ui_session` | List a specific creator's public videos |
| GET | `/ui/videos/admin/by-status/{status}` | `require_admin_session` | Admin: list by processing/review status |

### 3.2 Request/Response Models

File: `app/models_video.py` (additions to the models defined in VOD-001)

```python
# --- Listing / Pagination ---

class VideoListQuery(BaseModel):
    """Query parameters for video listing endpoints."""
    limit: int = Field(default=50, ge=1, le=200)
    cursor: Optional[str] = None
    status: Optional[VideoStatus] = None
    visibility: Optional[VideoVisibility] = None
    sort_order: Literal["asc", "desc"] = "desc"


class VideoListItem(BaseModel):
    """Lightweight video item for list responses (omits large fields)."""
    video_id: str
    title: str
    status: VideoStatus
    visibility: VideoVisibility
    created_at: int
    updated_at: int
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    thumbnail_url: Optional[str] = None
    file_size_bytes: Optional[int] = None
    review_status: Optional[VideoReviewStatus] = None


class VideoListOut(BaseModel):
    """Paginated list response."""
    items: List[VideoListItem]
    cursor: Optional[str] = None
    total_hint: Optional[int] = None  # Optional count hint (not guaranteed accurate)


class VideoDetailOut(BaseModel):
    """Full video detail response including playback URL."""
    video_id: str
    owner_user_id: str
    title: str
    description: Optional[str] = None
    status: VideoStatus
    visibility: VideoVisibility
    created_at: int
    updated_at: int

    # Technical properties
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    frame_rate: Optional[float] = None
    video_codec: Optional[str] = None
    audio_codec: Optional[str] = None
    file_size_bytes: Optional[int] = None
    container_format: Optional[str] = None
    renditions: List[VideoRendition] = Field(default_factory=list)

    # Outputs
    thumbnail_url: Optional[str] = None
    hls_manifest_url: Optional[str] = None

    # Playback (populated for authorized viewers)
    playback_token: Optional[str] = None
    playback_expires_at: Optional[int] = None

    # Encoding status
    encoding_job_id: Optional[str] = None
    encoding_error_message: Optional[str] = None

    # Review
    review_status: Optional[VideoReviewStatus] = None
    published_at: Optional[int] = None


class UpdateVideoIn(BaseModel):
    """Partial update request for video metadata."""
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    visibility: Optional[VideoVisibility] = None
```

### 3.3 DynamoDB Query Strategies

#### 3.3.1 Creator's Own Videos (`GET /ui/videos`)

Query: `ByOwnerCreatedAt` GSI with `owner_user_id = <caller_user_sub>`

```python
kwargs = {
    "IndexName": "ByOwnerCreatedAt",
    "KeyConditionExpression": Key("owner_user_id").eq(user_sub),
    "Limit": limit,
    "ScanIndexForward": sort_order == "asc",  # default False = newest first
}
if cursor:
    kwargs["ExclusiveStartKey"] = cursor
if status_filter:
    kwargs["FilterExpression"] = Attr("status").eq(status_filter)
```

**Important caveat (from CLAUDE.md)**: DDB `FilterExpression` does not reduce the page size read from the index. If the user has many videos but filters to a sparse status (e.g., `status=encoding`), the first page may return fewer than `limit` items while `LastEvaluatedKey` is still present. The service layer must loop until either `limit` items are collected or `LastEvaluatedKey` is exhausted:

```python
def list_videos_by_owner(
    owner_user_id: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
    status_filter: Optional[str] = None,
    visibility_filter: Optional[str] = None,
) -> Dict[str, Any]:
    collected: List[VideoMetadataModel] = []
    current_cursor = cursor
    max_pages = 10  # Safety cap to prevent runaway loops

    for _ in range(max_pages):
        kwargs: Dict[str, Any] = {
            "IndexName": "ByOwnerCreatedAt",
            "KeyConditionExpression": Key("owner_user_id").eq(owner_user_id),
            "Limit": min(limit * 3, 200),  # Over-fetch to compensate for filtering
            "ScanIndexForward": False,
        }
        if current_cursor:
            kwargs["ExclusiveStartKey"] = current_cursor

        filters = []
        if status_filter:
            filters.append(Attr("status").eq(status_filter))
        if visibility_filter:
            filters.append(Attr("visibility").eq(visibility_filter))
        # Always exclude soft-deleted
        filters.append(Attr("status").ne("deleted"))

        if filters:
            combined = filters[0]
            for f in filters[1:]:
                combined = combined & f
            kwargs["FilterExpression"] = combined

        resp = T.video_metadata.query(**kwargs)
        items = [video_from_item(i) for i in resp.get("Items", [])]
        collected.extend(items)
        current_cursor = resp.get("LastEvaluatedKey")

        if len(collected) >= limit or not current_cursor:
            break

    # Trim to requested limit
    result_items = collected[:limit]
    # If we have more items than limit, there are more pages
    next_cursor = current_cursor if len(collected) > limit or current_cursor else None

    return {"items": result_items, "cursor": next_cursor}
```

#### 3.3.2 Public Video Discovery (`GET /ui/videos/public`)

**Challenge**: There is no GSI with `visibility` as partition key. Options:

1. **New GSI `ByVisibilityPublishedAt`** -- PK = `visibility` (S), SK = `published_at` (N). This enables efficient queries for `visibility=public` sorted by publication date.
2. **Query `ByStatusCreatedAt`** with `status=published` + `FilterExpression` on `visibility=public`. This works because all public videos must be in `published` status, and the `ByStatusCreatedAt` GSI already exists.

**Chosen approach**: Option 2. Query `ByStatusCreatedAt` with `status="published"` and filter on `visibility="public"`. This avoids adding a new GSI and is efficient because most published videos will be public (low filter ratio). The same FilterExpression looping pattern applies.

For per-creator public listings (`GET /ui/videos/creator/{creator_id}`), query `ByOwnerCreatedAt` with `owner_user_id=creator_id` and filter on `status="published" AND visibility="public"`.

#### 3.3.3 Admin Status Listing (`GET /ui/videos/admin/by-status/{status}`)

Direct query on `ByStatusCreatedAt` GSI with no additional filtering:

```python
kwargs = {
    "IndexName": "ByStatusCreatedAt",
    "KeyConditionExpression": Key("status").eq(status),
    "Limit": limit,
    "ScanIndexForward": False,
}
```

#### 3.3.4 Single Video Detail (`GET /ui/videos/{video_id}`)

Direct `get_item` on primary key. No GSI needed:

```python
resp = T.video_metadata.get_item(Key={"video_id": video_id}, ConsistentRead=True)
```

### 3.4 Cursor Encoding Strategy

Use the signed cursor from `app/core/cursor.py` (`encode_cursor` / `decode_cursor`). This prevents clients from forging cursors to skip to arbitrary positions in another user's video list. The router layer encodes/decodes:

```python
from app.core.cursor import encode_cursor, decode_cursor

@router.get("", response_model=VideoListOut)
def list_my_videos(
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    status: Optional[VideoStatus] = Query(default=None),
    visibility: Optional[VideoVisibility] = Query(default=None),
    ctx=Depends(require_ui_session),
):
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_by_owner(
        ctx["user_sub"],
        limit=limit,
        cursor=decoded_cursor,
        status_filter=status,
        visibility_filter=visibility,
    )
    return VideoListOut(
        items=[_to_list_item(v) for v in result["items"]],
        cursor=encode_cursor(result.get("cursor")),
    )
```

### 3.5 Playback URL Generation

The detail endpoint generates a playback URL with entitlement token for authorized access:

```python
from app.services.playback_entitlements import issue_playback_entitlement, PlaybackEntitlementError

def _generate_playback_url(video: VideoMetadataModel, user_sub: str) -> tuple[Optional[str], Optional[int]]:
    """Generate a signed playback URL for the video if it's ready for playback."""
    if video.status not in ("approved", "published"):
        return None, None
    if not video.hls_manifest_url:
        return None, None

    ttl = getattr(S, "video_playback_token_ttl_seconds", 300)
    try:
        result = issue_playback_entitlement(
            tenant_id=user_sub,
            asset_id=video.id,
            session_id=f"vod-{user_sub}-{video.id}",
            device_id="browser",
            profile="default",
            audience=video.hls_manifest_url,
            ttl_seconds=ttl,
        )
        return result["token"], result["expires_at_epoch"]
    except PlaybackEntitlementError:
        return None, None
```

### 3.6 Authorization Rules

| Endpoint | Who Can Access | Enforcement |
|----------|---------------|-------------|
| `GET /ui/videos` | Any authenticated user (sees only own videos) | `owner_user_id = ctx["user_sub"]` in GSI query |
| `GET /ui/videos/{video_id}` | Owner always; others only if `published` + `public` or entitled | Check `owner_user_id == ctx["user_sub"]` OR (`status == "published"` AND `visibility in ("public", "unlisted")`) |
| `PATCH /ui/videos/{video_id}` | Owner only | Fetch, verify `owner_user_id == ctx["user_sub"]`, else 403 |
| `DELETE /ui/videos/{video_id}` | Owner only | Same ownership check |
| `GET /ui/videos/public` | Any authenticated user | Queries only `published` + `public` videos |
| `GET /ui/videos/creator/{creator_id}` | Any authenticated user | Queries only that creator's `published` + `public` videos |
| `GET /ui/videos/admin/by-status/{status}` | Admin/Root only | `require_admin_session` dependency |

### 3.7 Soft-Delete Behavior

`DELETE /ui/videos/{video_id}` performs a soft-delete:
1. Verify ownership
2. Set `status = "deleted"`, `deleted_at = now_ts()`, `updated_at = now_ts()`
3. All listing queries include `FilterExpression: Attr("status").ne("deleted")` to exclude deleted videos
4. A separate background cleanup job (out of scope for this ticket) will purge S3 assets for videos deleted more than 30 days ago

### 3.8 Error Responses

| Scenario | Status Code | Detail |
|----------|-------------|--------|
| Video not found | 404 | `{"detail": "video not found"}` |
| Not owner (PATCH/DELETE) | 403 | `{"detail": "forbidden"}` |
| Not authorized to view (private video, not owner) | 403 | `{"detail": "forbidden"}` |
| Invalid cursor | 400 | `{"detail": "invalid cursor"}` |
| Invalid status filter | 422 | Pydantic validation error |
| Video not ready for playback (detail) | 200 | Returns video with `playback_token: null` |

---

## 4. Implementation Plan

### 4.1 Prerequisites

- **VOD-001** must be implemented first: `VideoMetadata` table, `app/models_video.py`, `app/services/video_metadata_store.py`, `app/core/settings.py` and `app/core/tables.py` changes.
- **VOD-005** must be complete for playback URLs to be populated (though endpoints work without them, returning `null` manifest URLs).

### 4.2 Files to Create

| File | Purpose |
|------|---------|
| `app/routers/video_listing.py` | FastAPI router with all 7 listing/detail/update/delete endpoints |

### 4.3 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `video_listing_router` with prefix `/ui/videos` |
| `app/models_video.py` | Add `VideoListItem`, `VideoListOut`, `VideoDetailOut`, `VideoListQuery` models |
| `app/services/video_metadata_store.py` | Add `list_videos_by_owner`, `list_videos_public`, `list_videos_by_creator_public`, helper functions |
| `app/core/settings.py` | Add `video_playback_token_ttl_seconds` setting |

### 4.4 Step-by-Step Implementation

**Step 1: Add listing functions to `app/services/video_metadata_store.py`**

```python
from boto3.dynamodb.conditions import Attr, Key
from app.core.tables import T
from app.core.time import now_ts
from app.models_video import VideoMetadataModel, VideoStatus, VideoVisibility

def list_videos_by_owner(
    owner_user_id: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
    status_filter: Optional[str] = None,
    visibility_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """List videos owned by a user, newest first, with optional filters."""
    # Implementation as described in Section 3.3.1
    ...

def list_videos_public(
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """List all published+public videos for viewer discovery."""
    # Query ByStatusCreatedAt with status="published", filter visibility="public"
    ...

def list_videos_by_creator_public(
    creator_id: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """List a specific creator's published+public videos."""
    # Query ByOwnerCreatedAt, filter status="published" AND visibility="public"
    ...

def list_videos_by_status(
    status: str,
    *,
    limit: int = 50,
    cursor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Admin: list videos by processing/review status."""
    # Direct query on ByStatusCreatedAt GSI
    ...
```

**Step 2: Add response models to `app/models_video.py`**

Add `VideoListItem`, `VideoListOut`, `VideoDetailOut` as specified in Section 3.2.

**Step 3: Create `app/routers/video_listing.py`**

```python
from __future__ import annotations

import json
import base64
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from app.services.sessions import require_admin_session
from app.core.cursor import encode_cursor, decode_cursor
from app.core.settings import S
from app.models_video import (
    VideoDetailOut,
    VideoListItem,
    VideoListOut,
    VideoMetadataModel,
    VideoStatus,
    VideoVisibility,
    UpdateVideoIn,
)
from app.services.video_metadata_store import (
    get_video,
    update_video,
    delete_video,
    list_videos_by_owner,
    list_videos_public,
    list_videos_by_creator_public,
    list_videos_by_status,
)
from app.services.playback_entitlements import (
    issue_playback_entitlement,
    PlaybackEntitlementError,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/videos", tags=["videos"])


def _to_list_item(video: VideoMetadataModel) -> VideoListItem:
    return VideoListItem(
        video_id=video.id,
        title=video.title,
        status=video.status,
        visibility=video.visibility,
        created_at=video.created_at,
        updated_at=video.updated_at,
        duration_seconds=video.duration_seconds,
        width=video.width,
        height=video.height,
        thumbnail_url=video.thumbnail_url,
        file_size_bytes=video.file_size_bytes,
        review_status=video.review_status,
    )


def _to_detail(video: VideoMetadataModel, playback_token=None, playback_expires=None) -> VideoDetailOut:
    return VideoDetailOut(
        video_id=video.id,
        owner_user_id=video.owner_user_id,
        title=video.title,
        description=video.description,
        status=video.status,
        visibility=video.visibility,
        created_at=video.created_at,
        updated_at=video.updated_at,
        duration_seconds=video.duration_seconds,
        width=video.width,
        height=video.height,
        frame_rate=video.frame_rate,
        video_codec=video.video_codec,
        audio_codec=video.audio_codec,
        file_size_bytes=video.file_size_bytes,
        container_format=video.container_format,
        renditions=video.renditions,
        thumbnail_url=video.thumbnail_url,
        hls_manifest_url=video.hls_manifest_url,
        playback_token=playback_token,
        playback_expires_at=playback_expires,
        encoding_job_id=video.encoding_job_id,
        encoding_error_message=video.encoding_error_message,
        review_status=video.review_status,
        published_at=video.published_at,
    )


def _generate_playback_token(video: VideoMetadataModel, user_sub: str):
    if video.status not in ("approved", "published"):
        return None, None
    if not video.hls_manifest_url:
        return None, None
    ttl = int(getattr(S, "video_playback_token_ttl_seconds", 300) or 300)
    try:
        result = issue_playback_entitlement(
            tenant_id=user_sub,
            asset_id=video.id,
            session_id=f"vod-{user_sub}-{video.id}",
            device_id="browser",
            profile="default",
            audience=video.hls_manifest_url,
            ttl_seconds=ttl,
        )
        return result["token"], result["expires_at_epoch"]
    except PlaybackEntitlementError:
        return None, None


@router.get("", response_model=VideoListOut)
def list_my_videos(
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    status: Optional[VideoStatus] = Query(default=None),
    visibility: Optional[VideoVisibility] = Query(default=None),
    ctx=Depends(require_ui_session),
):
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_by_owner(
        ctx["user_sub"],
        limit=limit,
        cursor=decoded_cursor,
        status_filter=status,
        visibility_filter=visibility,
    )
    return VideoListOut(
        items=[_to_list_item(v) for v in result["items"]],
        cursor=encode_cursor(result.get("cursor")),
    )


@router.get("/public", response_model=VideoListOut)
def list_public_videos(
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx=Depends(require_ui_session),
):
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_public(limit=limit, cursor=decoded_cursor)
    return VideoListOut(
        items=[_to_list_item(v) for v in result["items"]],
        cursor=encode_cursor(result.get("cursor")),
    )


@router.get("/creator/{creator_id}", response_model=VideoListOut)
def list_creator_videos(
    creator_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx=Depends(require_ui_session),
):
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_by_creator_public(creator_id, limit=limit, cursor=decoded_cursor)
    return VideoListOut(
        items=[_to_list_item(v) for v in result["items"]],
        cursor=encode_cursor(result.get("cursor")),
    )


@router.get("/admin/by-status/{status}", response_model=VideoListOut)
def list_videos_by_status_admin(
    status: VideoStatus,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx=Depends(require_admin_session),
):
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_by_status(status, limit=limit, cursor=decoded_cursor)
    return VideoListOut(
        items=[_to_list_item(v) for v in result["items"]],
        cursor=encode_cursor(result.get("cursor")),
    )


@router.get("/{video_id}", response_model=VideoDetailOut)
def get_video_detail(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    video = get_video(video_id)
    user_sub = ctx["user_sub"]

    # Authorization check
    is_owner = video.owner_user_id == user_sub
    is_viewable = video.status == "published" and video.visibility in ("public", "unlisted")

    if not is_owner and not is_viewable:
        raise HTTPException(status_code=403, detail="forbidden")

    # Generate playback token if video is ready
    token, expires = _generate_playback_token(video, user_sub)
    return _to_detail(video, playback_token=token, playback_expires=expires)


@router.patch("/{video_id}", response_model=VideoDetailOut)
def update_video_detail(
    video_id: str,
    body: UpdateVideoIn,
    ctx=Depends(require_ui_session),
):
    video = get_video(video_id)
    if video.owner_user_id != ctx["user_sub"]:
        raise HTTPException(status_code=403, detail="forbidden")

    updated = update_video(video_id, body)
    return _to_detail(updated)


@router.delete("/{video_id}")
def delete_video_endpoint(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    video = get_video(video_id)
    if video.owner_user_id != ctx["user_sub"]:
        raise HTTPException(status_code=403, detail="forbidden")

    delete_video(video_id)
    return {"ok": True, "video_id": video_id}
```

**Step 4: Register router in `app/main.py`**

Add after existing router registrations:

```python
from app.routers.video_listing import router as video_listing_router
app.include_router(video_listing_router)
```

**Step 5: Add settings**

In `app/core/settings.py`:

```python
video_playback_token_ttl_seconds: int = int(os.environ.get("VIDEO_PLAYBACK_TOKEN_TTL", "300"))
```

### 4.5 Dependency Graph

```
VOD-001 (table + models + store)
    |
    v
VOD-006 (this ticket: router + listing logic)
    |
    v
VOD-007 (frontend video page) + VOD-008 (frontend player)
```

VOD-006 can be implemented independently of VOD-002 through VOD-005 (the upload/transcode pipeline). The listing endpoints will work correctly even when no videos exist -- they simply return empty lists. Once the pipeline populates video records, the listings surface them automatically.

---

## 5. Testing Strategy

### 5.1 Unit Tests: `tests/test_video_listing.py`

Using the `_FakeTable` in-memory pattern from `tests/test_broadcast_store.py`:

| Test | What It Validates |
|------|-------------------|
| `test_list_own_videos_returns_only_own` | Insert 3 videos for user A, 2 for user B. List for A returns exactly 3. |
| `test_list_own_videos_newest_first` | Insert videos with different `created_at`. Assert list is sorted descending. |
| `test_list_own_videos_pagination` | Insert 5 videos, list with `limit=2`. Assert first page has 2 items + cursor. Second page with cursor returns next 2. Third page returns last 1 + no cursor. |
| `test_list_own_videos_filter_by_status` | Insert videos with mixed statuses. Filter by `status=encoding`. Assert only matching videos returned. |
| `test_list_own_videos_filter_by_visibility` | Insert private + public videos. Filter by `visibility=public`. Assert correct filtering. |
| `test_list_own_videos_excludes_deleted` | Insert a deleted video. List without filter. Assert deleted video not in results. |
| `test_list_public_videos` | Insert published+public, published+private, encoding+public videos. Public listing returns only published+public. |
| `test_list_creator_public_videos` | Insert published+public videos for two creators. Creator listing returns only the specified creator's public videos. |
| `test_list_by_status_admin` | Insert videos with various statuses. Admin query for `pending_review` returns correct subset. |
| `test_get_video_owner_can_access_any_status` | Owner can access their video regardless of status/visibility. |
| `test_get_video_non_owner_published_public` | Non-owner can access published+public video. |
| `test_get_video_non_owner_published_unlisted` | Non-owner can access published+unlisted video. |
| `test_get_video_non_owner_private_403` | Non-owner gets 403 for private video. |
| `test_get_video_non_owner_unpublished_403` | Non-owner gets 403 for non-published video (even if public visibility set). |
| `test_get_video_generates_playback_token` | Video with status=published and hls_manifest_url set returns non-null playback_token and expires. |
| `test_get_video_no_playback_for_processing` | Video with status=encoding returns null playback fields. |
| `test_update_video_owner_only` | Non-owner PATCH returns 403. Owner PATCH succeeds. |
| `test_update_video_partial` | PATCH with only title updates title, leaves description unchanged. |
| `test_delete_video_owner_only` | Non-owner DELETE returns 403. Owner DELETE succeeds. |
| `test_delete_video_sets_status` | After DELETE, get_video shows status=deleted and deleted_at set. |
| `test_invalid_cursor_returns_400` | Pass malformed cursor string, assert 400. |
| `test_filter_loop_exhausts_pages` | Insert 100 videos where only 3 match the filter. Assert all 3 are returned despite being spread across multiple DDB pages. |

### 5.2 Integration Tests: `tests/test_video_listing_integration.py`

Using the FastAPI test client with moto-mocked DynamoDB:

| Test | What It Validates |
|------|-------------------|
| `test_list_endpoint_200_empty` | GET `/ui/videos` with no videos returns `{"items": [], "cursor": null}`. |
| `test_list_endpoint_with_videos` | Create 3 videos via store, GET `/ui/videos`, assert 3 items returned with correct fields. |
| `test_list_endpoint_pagination_integration` | Create 5 videos, paginate with limit=2, verify all 5 are reachable across pages. |
| `test_get_endpoint_200` | Create video, GET `/ui/videos/{id}`, assert all fields populated correctly. |
| `test_get_endpoint_404` | GET `/ui/videos/nonexistent`, assert 404. |
| `test_get_endpoint_403_not_owner` | Create video for user A, request as user B, assert 403. |
| `test_patch_endpoint_200` | PATCH title, verify response has new title and updated_at advanced. |
| `test_delete_endpoint_200` | DELETE video, verify response. Then GET confirms status=deleted. |
| `test_public_endpoint_filters_correctly` | Create mix of public/private/published/draft videos. GET `/ui/videos/public` returns only published+public. |
| `test_admin_endpoint_requires_admin_role` | Regular user calls admin endpoint, assert 403. |
| `test_csrf_required` | POST/PATCH/DELETE without CSRF header returns 403. |

### 5.3 E2E Tests: `frontend/e2e/video-listing.spec.ts`

Following the project's `injectAuth` + `page.request` pattern:

```typescript
// Section: Video CRUD API
test("Alice creates a video, lists it, gets details", async ({ page }) => {
    await injectAuth(page, "alice");
    // POST to create, GET list to verify, GET detail to verify full payload
});

test("Alice updates video title", async ({ page }) => {
    // PATCH with new title, GET to verify
});

test("Alice deletes video, no longer in listing", async ({ page }) => {
    // DELETE, then GET list verifies exclusion
});

// Section: Pagination
test("Pagination returns correct pages with cursor", async ({ page }) => {
    // Create 5 videos, list with limit=2, follow cursors
});

// Section: Public Discovery
test("Published public videos appear in public listing", async ({ page }) => {
    // Admin transitions video to published, verify in public listing
});

test("Private videos do not appear in public listing", async ({ page }) => {
    // Create private video, verify NOT in public listing
});

// Section: Authorization
test("Non-owner cannot access private video", async ({ page }) => {
    // Bob requests Alice's private video, assert 403
});

test("Non-owner CAN access published public video", async ({ page }) => {
    // Bob requests Alice's published+public video, assert 200
});

// Section: Admin Listing
test("Root can list videos by status", async ({ page }) => {
    await injectAuth(page, "root");
    // GET /ui/videos/admin/by-status/pending_review
});

test("Regular user cannot access admin listing", async ({ page }) => {
    await injectAuth(page, "alice");
    // GET admin endpoint, assert 403
});
```

### 5.4 Edge Cases to Test

| Edge Case | Expected Behavior |
|-----------|-------------------|
| Empty video library | Returns `{"items": [], "cursor": null}` (200, not 404) |
| Cursor from different user's listing | Signed cursor validation fails; returns 400 or empty results (cursor is bound to GSI partition) |
| Tampered cursor | `decode_cursor` returns None (HMAC verification fails), treated as first page |
| Video in `deleted` status accessed by owner via direct GET | Returns 200 with full details (owner can always see their own videos, including deleted ones) |
| Concurrent delete + list | Eventually consistent; deleted video may briefly appear in listings (acceptable) |
| Very large video library (10,000+ videos) | Pagination handles correctly; max 10 DDB round-trips per request (safety cap) |
| Filter that matches zero videos | Returns empty list, not 404 |
| `limit=0` or `limit=201` | Rejected by Pydantic `ge=1, le=200` validation (422) |
| Playback token generation when `playback_entitlement_secret` not configured | Returns video detail with `playback_token: null` (graceful degradation) |
| Unicode in title/description | Stored and returned correctly; no encoding issues in cursor |

### 5.5 Performance Considerations

| Concern | Mitigation |
|---------|-----------|
| FilterExpression on sparse data | Loop with max 10 pages; over-fetch 3x limit per page |
| Large response payloads | `VideoListItem` is lightweight (omits description, renditions, codec details) |
| Playback token generation on every detail request | Token generation is pure computation (HMAC); sub-millisecond; no DDB call |
| Public listing hot partition | `status="published"` partition may grow large; acceptable for cursor-based pagination (DDB handles hot partitions via adaptive capacity) |

---

## Appendix: File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `app/routers/video_listing.py` | **New** | Router with 7 endpoints (list own, list public, list creator, list admin, get detail, patch, delete) |
| `app/main.py` | Modify | Register `video_listing_router` |
| `app/models_video.py` | Modify | Add `VideoListItem`, `VideoListOut`, `VideoDetailOut` response models |
| `app/services/video_metadata_store.py` | Modify | Add `list_videos_by_owner`, `list_videos_public`, `list_videos_by_creator_public`, `list_videos_by_status` with filter-loop pagination |
| `app/core/settings.py` | Modify | Add `video_playback_token_ttl_seconds` setting |
| `.env.local.example` | Modify | Add `VIDEO_PLAYBACK_TOKEN_TTL=300` |
| `tests/test_video_listing.py` | **New** | 22 unit tests for listing/detail/update/delete logic |
| `tests/test_video_listing_integration.py` | **New** | 11 integration tests with FastAPI test client |
| `frontend/e2e/video-listing.spec.ts` | **New** | ~12 E2E tests covering CRUD, pagination, authorization, admin |
