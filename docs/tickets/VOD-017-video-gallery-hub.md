# VOD-017: Video Gallery Hub — YouTube-Style Publishing & Discovery

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-27  
**Priority**: High  
**Estimated effort**: 8-12 days  
**Dependencies**: MON-001 (VOD pay-per-view), MON-005 (subscription-gated VOD), VOD-014 (file bridge), BCAST-006 (broadcast recordings)

---

## 1. Overview & Motivation

### The Gap

The VOD system supports video upload, transcoding, playback, pay-per-view purchasing (MON-001), and subscription gating (MON-005), but there is **no unified discovery surface**. Videos exist in isolation — a viewer must know the exact video ID or navigate to a specific creator's page to find content. There is no browsable gallery, no trending feed, no category-based navigation, and no cross-creator search.

Additionally, videos can originate from multiple sources — direct upload (`app/routers/vod.py`), file manager import (VOD-014), broadcast recordings (BCAST-006), clips (VOD-015), and concatenations (VOD-016) — but each source is its own silo. A broadcast recording lives in the broadcast archive; a file manager video lives in the file tree; a clipped video exists only in the VOD metadata table. There is no single "publish to gallery" action that makes content from any source discoverable in a unified hub.

The `VideoMetadataModel` (`app/models_video.py`, line 36) has `visibility` (private/unlisted/public) and `status` (created → published), but no `category`, `tags`, `view_count`, or `like_count` fields. The existing `list_videos_public()` function (`app/services/video_metadata_store.py`) returns all published+public videos ordered by `created_at`, but there is no relevance ranking, trending algorithm, or full-text search.

### Why This Is Needed

1. **Content discovery**: Creators need their published content to be discoverable by viewers who do not already follow them. A gallery hub with categories, trending, and search is the standard platform pattern (YouTube, Vimeo, TikTok).

2. **Multi-source unification**: Videos arrive from five different sources. Without a "publish to gallery" action, creators must mentally track which videos are discoverable and which are stranded in source-specific silos.

3. **Engagement metrics**: View counts, likes, and comments are table-stakes for creator motivation and viewer engagement. The platform currently tracks none of these on videos.

4. **Creator analytics**: The earnings dashboard (MON-003) shows revenue but not engagement. Creators need views-over-time, top-performing videos, and audience signals.

5. **Monetization leverage**: A gallery with trending rankings incentivizes creators to produce more content. Higher content volume increases subscription and PPV revenue.

### Architecture After This Change

```
                          ┌────────────────────────────┐
                          │     VIDEO GALLERY HUB      │
                          │   /gallery (new route)     │
                          └────────────┬───────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
    ┌─────────▼─────────┐   ┌─────────▼─────────┐   ┌─────────▼─────────┐
    │  Browse/Filter     │   │   Trending Feed   │   │   Full-Text       │
    │  - By category     │   │   - Views in 24h  │   │   Search          │
    │  - By creator      │   │   - Algorithmic   │   │   - Title/desc    │
    │  - By duration     │   │     ranking       │   │   - Tags          │
    │  - Sort (new/pop)  │   │                   │   │                   │
    └─────────┬─────────┘   └─────────┬─────────┘   └─────────┬─────────┘
              │                        │                        │
              └────────────────────────┼────────────────────────┘
                                       │
                          ┌────────────▼───────────────┐
                          │   VideoMetadata Table      │
                          │  + category, tags          │
                          │  + view_count, like_count  │
                          │  + GSIs: ByCategory,       │
                          │    ByTrending              │
                          └────────────┬───────────────┘
                                       │
          ┌───────────────┬────────────┼────────────┬─────────────┐
          │               │            │            │             │
    ┌─────▼─────┐  ┌──────▼─────┐ ┌───▼────┐ ┌────▼────┐ ┌──────▼──────┐
    │  Direct   │  │ File Mgr   │ │ BCAST  │ │ Clips  │ │ Messenger  │
    │  Upload   │  │ Publish    │ │ Record │ │ VOD-15 │ │ Save       │
    │  VOD-002  │  │ VOD-014    │ │ BCAST-6│ │        │ │            │
    └───────────┘  └────────────┘ └────────┘ └────────┘ └────────────┘
```

### Detailed Data Flow — Gallery Browse

```
Browser                            Backend                              DynamoDB
  │                                   │                                    │
  │── GET /ui/videos/gallery ────────>│                                    │
  │   ?category=tutorials             │                                    │
  │   &sort=trending                  │                                    │
  │   &duration_min=60                │                                    │
  │   &duration_max=600               │                                    │
  │   &limit=24                       │                                    │
  │                                   │── query VideoMetadata ────────────>│
  │                                   │   GSI: ByCategory                  │
  │                                   │   PK = "tutorials"                 │
  │                                   │   SK = created_at (desc)           │
  │                                   │<── {items, cursor} ───────────────│
  │                                   │                                    │
  │                                   │── [if sort=trending]               │
  │                                   │   query VideoViews (24h window) ──>│
  │                                   │   GSI: ByViewDate                  │
  │                                   │<── view counts per video_id ──────│
  │                                   │                                    │
  │                                   │── rank by 24h views, filter        │
  │                                   │   by duration range                │
  │                                   │                                    │
  │<── 200 { videos: [...],           │                                    │
  │     categories: [...],            │                                    │
  │     cursor }                      │                                    │
```

### Detailed Data Flow — Record View

```
Browser                            Backend                              DynamoDB
  │                                   │                                    │
  │── POST /ui/videos/{id}/view ─────>│                                    │
  │                                   │── get_item VideoViews ────────────>│
  │                                   │   PK = VIDEO#{video_id}            │
  │                                   │   SK = VIEW#{user_id}#{date}       │
  │                                   │<── Item or None ──────────────────│
  │                                   │                                    │
  │                                   │── [if None: first view today]      │
  │                                   │   put_item VideoViews ────────────>│
  │                                   │   + update_item VideoMetadata      │
  │                                   │     SET view_count += 1            │
  │                                   │<── ok ────────────────────────────│
  │                                   │                                    │
  │<── 200 { view_count }             │                                    │
```

### Detailed Data Flow — Publish From Source

```
Browser                            Backend                              DynamoDB
  │                                   │                                    │
  │── POST /ui/videos/{id}/           │                                    │
  │   publish-to-gallery              │                                    │
  │   { category, tags: [],           │                                    │
  │     title, description }          │                                    │
  │                                   │── get_video(id) ─────────────────>│
  │                                   │<── VideoMetadataModel ────────────│
  │                                   │                                    │
  │                                   │── validate ownership               │
  │                                   │── validate status in               │
  │                                   │   (approved, published)            │
  │                                   │                                    │
  │                                   │── update_item VideoMetadata ──────>│
  │                                   │   SET visibility = "public"        │
  │                                   │   SET status = "published"         │
  │                                   │   SET category = :cat              │
  │                                   │   SET tags = :tags                 │
  │                                   │   SET published_at = :now          │
  │                                   │   SET gallery_published = true     │
  │                                   │<── ok ────────────────────────────│
  │                                   │                                    │
  │<── 200 { video_id, status,        │                                    │
  │     gallery_published }           │                                    │
```

---

## 2. Current State Analysis

### 2.1 VideoMetadataModel (`app/models_video.py`, lines 36-109)

The model currently has no gallery-specific fields. Relevant existing fields:

- `visibility: VideoVisibility = "private"` (line 99) — controls listing, not discovery
- `status: VideoStatus = "created"` (line 41) — lifecycle state
- `published_at: Optional[int] = None` (line 100) — set when published, but not used for gallery ranking
- `price_cents: Optional[int] = None` (line 93) — MON-001 pricing
- `access_mode: Optional[str] = None` (line 94) — MON-001/MON-005 access control
- `purchase_count: int = 0` (line 95) — sales counter

Missing: `category`, `tags`, `view_count`, `like_count`, `gallery_published`.

### 2.2 Video Listing Endpoints (`app/routers/video_listing.py`)

Current listing endpoints:

- `GET /ui/videos/public` (line 252) — all published+public videos, paginated by `created_at`
- `GET /ui/videos/creator/{creator_id}` (line 265) — one creator's public videos
- `GET /ui/videos/by-creator/{creator_id}` (line 633) — MON-005 subscription-aware list
- `GET /ui/videos/{video_id}` (line 293) — single video detail with entitlement check
- `GET /ui/videos` (line 420) — caller's own videos

None support category filtering, trending sort, full-text search, or duration filtering.

### 2.3 Video Metadata Store (`app/services/video_metadata_store.py`)

- `list_videos_public()` — queries `ByStatusCreatedAt` GSI with `status=published`, no category filter
- `list_videos_by_creator_public()` — queries `ByOwnerCreatedAt` GSI
- `video_to_item()` / `video_from_item()` — serialize/deserialize `VideoMetadataModel` to/from DDB item

The store has no support for category-based queries, tag filtering, or view-count-based sorting.

### 2.4 VideoMetadata DDB Table (`scripts/local-ddb-init.py`, lines 689-709)

```python
TableDef(
    _resolve_table_name(S.video_metadata_table_name, "VideoMetadata"),
    "video_id",
    gsi=[
        {"index_name": "ByOwnerCreatedAt", "partition_key": "owner_user_id", "sort_key": "created_at"},
        {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "BySourceBroadcast", "partition_key": "source_broadcast_session_id"},
    ],
    attr_types={"created_at": "N"},
)
```

No GSI for category or trending. All existing GSIs sort by `created_at`.

### 2.5 Existing Source Integration Points

- **File manager bridge** (VOD-014, `app/services/vod_file_bridge.py`): Creates a `VideoMetadataModel` from a file node, linking `source_file_node_id`. The video starts as `status="created"` and must go through encoding before it can be published.
- **Broadcast recording** (BCAST-006): Creates a `VideoMetadataModel` with `source_broadcast_session_id` and `source_type="broadcast_archive"`.
- **Clips** (VOD-015) and **Concatenations** (VOD-016): Create new `VideoMetadataModel` entries linked to source videos.
- **Messenger video sharing** (VOD-013): Videos shared in messages use existing video IDs but do not create new metadata entries.

All these sources produce `VideoMetadataModel` entries but none set `gallery_published=true` or assign categories/tags.

---

## 3. Technical Design

### 3.1 VideoMetadataModel Changes

Add gallery fields to `VideoMetadataModel`:

```python
class VideoMetadataModel(BaseModel):
    # ... existing fields ...

    # Gallery (VOD-017)
    gallery_published: bool = False              # True when explicitly published to gallery
    category: Optional[str] = None               # Predefined category slug
    tags: List[str] = Field(default_factory=list) # Free-form tags, max 10
    view_count: int = 0                          # Deduplicated view count
    like_count: int = 0                          # Like count
    comment_count: int = 0                       # Comment count (reuses newsfeed comments)
    trending_score: int = 0                      # Cached score: views in last 24h window
    trending_updated_at: int = 0                 # Last time trending_score was recalculated
```

Add to `CreateVideoIn`:
```python
class CreateVideoIn(BaseModel):
    # ... existing fields ...
    category: Optional[str] = Field(default=None, max_length=50)
    tags: List[str] = Field(default_factory=list, max_length=10)
```

Add validation:
```python
@model_validator(mode="after")
def _validate_tags(self) -> "CreateVideoIn":
    if len(self.tags) > 10:
        raise ValueError("Maximum 10 tags allowed")
    for tag in self.tags:
        if len(tag) > 50 or len(tag) < 1:
            raise ValueError("Each tag must be 1-50 characters")
    return self
```

### 3.2 Predefined Categories

```python
# app/services/video_gallery.py

GALLERY_CATEGORIES = [
    {"slug": "tutorials", "label": "Tutorials & How-To"},
    {"slug": "entertainment", "label": "Entertainment"},
    {"slug": "fitness", "label": "Fitness & Wellness"},
    {"slug": "music", "label": "Music & Performance"},
    {"slug": "cooking", "label": "Cooking & Food"},
    {"slug": "gaming", "label": "Gaming"},
    {"slug": "education", "label": "Education"},
    {"slug": "vlog", "label": "Vlogs & Lifestyle"},
    {"slug": "tech", "label": "Tech & Reviews"},
    {"slug": "art", "label": "Art & Design"},
    {"slug": "comedy", "label": "Comedy"},
    {"slug": "other", "label": "Other"},
]

VALID_CATEGORY_SLUGS = {c["slug"] for c in GALLERY_CATEGORIES}
```

### 3.3 VideoViews Table (View Deduplication)

New DDB table for per-user per-day view tracking:

```python
TableDef(
    "video_views",
    "pk",    # VIDEO#{video_id}
    "sk",    # VIEW#{user_id}#{YYYY-MM-DD}
    gsi=[
        {
            "index_name": "ByViewDate",
            "partition_key": "video_id",
            "sort_key": "view_date_ts",
        },
    ],
    attr_types={"view_date_ts": "N"},
)
```

View item schema:
```python
{
    "pk": f"VIDEO#{video_id}",
    "sk": f"VIEW#{user_id}#{date_str}",    # e.g., VIEW#alice#2026-05-27
    "video_id": video_id,
    "user_id": user_id,
    "view_date": date_str,                  # YYYY-MM-DD
    "view_date_ts": date_ts,                # Unix timestamp of midnight UTC
    "created_at": ts,                       # Exact view timestamp
    "ttl": ts + 90 * 86400,                 # Auto-expire after 90 days
}
```

**Deduplication logic**: A user's view of a given video is counted at most once per calendar day (UTC). The composite SK `VIEW#{user_id}#{date}` enforces uniqueness. A `put_item` with `ConditionExpression="attribute_not_exists(pk)"` attempts to write; if it fails (already viewed today), the view is not double-counted.

### 3.4 VideoLikes Table

New DDB table for like tracking:

```python
TableDef(
    "video_likes",
    "pk",    # VIDEO#{video_id}
    "sk",    # LIKE#{user_id}
    gsi=[
        {
            "index_name": "ByUser",
            "partition_key": "user_id",
            "sort_key": "created_at",
        },
    ],
    attr_types={"created_at": "N"},
)
```

Like item schema:
```python
{
    "pk": f"VIDEO#{video_id}",
    "sk": f"LIKE#{user_id}",
    "video_id": video_id,
    "user_id": user_id,
    "created_at": ts,
}
```

**Like/unlike toggle**: `POST /ui/videos/{video_id}/like` checks if the like exists. If yes, deletes it and decrements `like_count` on video metadata. If no, writes it and increments `like_count`. Uses `get_item` + conditional `put_item` / `delete_item` to handle races.

### 3.5 Video Comments (Bridge to Newsfeed)

Video comments cannot directly reuse the existing newsfeed comment endpoints as-is. The newsfeed uses a module-level table handle (`tbl = ddb.Table("app_single_table")`) — there is no `T.newsfeed` in `app/core/tables.py`. Comments are keyed with PK `POST#{post_id}#COMMENTS` (see `pk_post_comments()` at `newsfeed.py` line 759-760), and `create_comment` (line 4320-4322) validates that a post record exists via `ddb_get_item({"pk": pk_post(post_id), "sk": sk_post()})`. Passing a `video_id` as the `post_id` would 404 because no matching post record exists in `app_single_table`.

**Bridge approach required**: To reuse the newsfeed comment infrastructure for videos, one of these adapter patterns is needed:

1. **Shadow post record**: When a video is published to the gallery, create a corresponding post record in `app_single_table` with `pk=POST#{video_id}`, `sk=POST_META`, and a `post_type=video` marker. This lets `create_comment` find the "post" and all existing comment endpoints work unchanged.
2. **Separate video comment endpoints**: Build new `POST /ui/videos/{video_id}/comments` and `GET /ui/videos/{video_id}/comments` endpoints that write to the same `app_single_table` using the same `POST#{video_id}#COMMENTS` PK format, but skip the post-existence validation (or use a video-existence check instead).

Option 1 (shadow post) is recommended because it requires zero changes to the comment system itself — only a single `put_item` call during `publish_to_gallery()`.

The `app_single_table` already supports pagination, tips, and reactions on comments.

### 3.6 New Service: `app/services/video_gallery.py`

```python
"""Video gallery hub service (VOD-017).

Handles gallery browsing, view tracking, like tracking,
trending computation, and multi-source publishing.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.video_metadata_store import get_video, video_from_item

logger = logging.getLogger(__name__)

GALLERY_CATEGORIES = [
    {"slug": "tutorials", "label": "Tutorials & How-To"},
    {"slug": "entertainment", "label": "Entertainment"},
    {"slug": "fitness", "label": "Fitness & Wellness"},
    {"slug": "music", "label": "Music & Performance"},
    {"slug": "cooking", "label": "Cooking & Food"},
    {"slug": "gaming", "label": "Gaming"},
    {"slug": "education", "label": "Education"},
    {"slug": "vlog", "label": "Vlogs & Lifestyle"},
    {"slug": "tech", "label": "Tech & Reviews"},
    {"slug": "art", "label": "Art & Design"},
    {"slug": "comedy", "label": "Comedy"},
    {"slug": "other", "label": "Other"},
]

VALID_CATEGORY_SLUGS = {c["slug"] for c in GALLERY_CATEGORIES}


def record_view(*, video_id: str, user_id: str) -> Dict[str, Any]:
    """Record a video view, deduplicated per user per day.

    Steps:
    1. Compute today's date string (UTC).
    2. Attempt put_item with condition (dedup).
    3. If new view: increment view_count on VideoMetadata.
    4. Return current view_count.

    Returns:
        {"view_count": int, "is_new_view": bool}
    """
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    date_ts = int(datetime(now.year, now.month, now.day, tzinfo=timezone.utc).timestamp())
    ts = now_ts()

    is_new = False
    try:
        T.video_views.put_item(
            Item={
                "pk": f"VIDEO#{video_id}",
                "sk": f"VIEW#{user_id}#{date_str}",
                "video_id": video_id,
                "user_id": user_id,
                "view_date": date_str,
                "view_date_ts": date_ts,
                "created_at": ts,
                "ttl": ts + 90 * 86400,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        is_new = True
    except T.video_views.meta.client.exceptions.ConditionalCheckFailedException:
        pass  # Already viewed today — not a new view
    except Exception:
        logger.warning("view_record_failed", extra={"video_id": video_id, "user_id": user_id})

    # Increment view_count on video metadata (only for new views)
    view_count = 0
    if is_new:
        try:
            resp = T.video_metadata.update_item(
                Key={"video_id": video_id},
                UpdateExpression="SET view_count = if_not_exists(view_count, :z) + :one",
                ExpressionAttributeValues={":z": 0, ":one": 1},
                ReturnValues="UPDATED_NEW",
            )
            view_count = int(resp.get("Attributes", {}).get("view_count", 0))
        except Exception:
            logger.warning("view_count_increment_failed", extra={"video_id": video_id})
    else:
        # Fetch current count
        try:
            item = T.video_metadata.get_item(
                Key={"video_id": video_id},
                ProjectionExpression="view_count",
            ).get("Item", {})
            view_count = int(item.get("view_count", 0))
        except Exception:
            pass

    return {"view_count": view_count, "is_new_view": is_new}


def toggle_like(*, video_id: str, user_id: str) -> Dict[str, Any]:
    """Toggle like on a video. Returns new like state and count.

    If user has already liked: remove like, decrement like_count.
    If user has not liked: add like, increment like_count.

    Returns:
        {"liked": bool, "like_count": int}
    """
    pk = f"VIDEO#{video_id}"
    sk = f"LIKE#{user_id}"
    ts = now_ts()

    existing = T.video_likes.get_item(Key={"pk": pk, "sk": sk}).get("Item")

    if existing:
        # Unlike
        T.video_likes.delete_item(Key={"pk": pk, "sk": sk})
        try:
            resp = T.video_metadata.update_item(
                Key={"video_id": video_id},
                UpdateExpression="SET like_count = if_not_exists(like_count, :one) - :one",
                ExpressionAttributeValues={":one": 1},
                ReturnValues="UPDATED_NEW",
            )
            like_count = max(0, int(resp.get("Attributes", {}).get("like_count", 0)))
        except Exception:
            like_count = 0
        return {"liked": False, "like_count": like_count}
    else:
        # Like
        T.video_likes.put_item(
            Item={
                "pk": pk,
                "sk": sk,
                "video_id": video_id,
                "user_id": user_id,
                "created_at": ts,
            }
        )
        try:
            resp = T.video_metadata.update_item(
                Key={"video_id": video_id},
                UpdateExpression="SET like_count = if_not_exists(like_count, :z) + :one",
                ExpressionAttributeValues={":z": 0, ":one": 1},
                ReturnValues="UPDATED_NEW",
            )
            like_count = int(resp.get("Attributes", {}).get("like_count", 0))
        except Exception:
            like_count = 1
        return {"liked": True, "like_count": like_count}


def check_liked(*, video_id: str, user_id: str) -> bool:
    """Check if a user has liked a video."""
    pk = f"VIDEO#{video_id}"
    sk = f"LIKE#{user_id}"
    item = T.video_likes.get_item(Key={"pk": pk, "sk": sk}).get("Item")
    return item is not None


def list_gallery_videos(
    *,
    category: Optional[str] = None,
    sort: str = "newest",
    duration_min: Optional[int] = None,
    duration_max: Optional[int] = None,
    search: Optional[str] = None,
    limit: int = 24,
    cursor: Optional[dict] = None,
) -> Dict[str, Any]:
    """Browse gallery videos with filtering and sorting.

    Args:
        category: Filter by category slug. If None, all categories.
        sort: "newest" (default), "popular" (by view_count), "trending" (24h views).
        duration_min: Minimum duration in seconds (inclusive).
        duration_max: Maximum duration in seconds (inclusive).
        search: Full-text search query (title, description, tags).
        limit: Page size (default 24, max 100).
        cursor: DDB pagination cursor.

    Returns:
        {"items": List[VideoMetadataModel], "cursor": Optional[dict]}
    """
    if category and category not in VALID_CATEGORY_SLUGS:
        raise HTTPException(400, f"Invalid category: {category}")

    # Choose query strategy based on filters
    if category:
        # Use ByCategory GSI
        kce = Key("category").eq(category)
        if sort == "newest":
            kce = kce & Key("published_at").gte(0)  # all published
        resp = T.video_metadata.query(
            IndexName="ByCategory",
            KeyConditionExpression=kce,
            FilterExpression="gallery_published = :gp AND #st = :pub AND visibility = :vis",
            ExpressionAttributeValues={
                ":gp": True,
                ":pub": "published",
                ":vis": "public",
            },
            ExpressionAttributeNames={"#st": "status"},
            ScanIndexForward=False,
            Limit=limit,
            **({"ExclusiveStartKey": cursor} if cursor else {}),
        )
    else:
        # Use ByGalleryPublished GSI (gallery_published=true, sort by published_at)
        resp = T.video_metadata.query(
            IndexName="ByGalleryPublished",
            KeyConditionExpression=Key("gallery_published_flag").eq("Y"),
            FilterExpression="#st = :pub AND visibility = :vis",
            ExpressionAttributeValues={
                ":pub": "published",
                ":vis": "public",
            },
            ExpressionAttributeNames={"#st": "status"},
            ScanIndexForward=False,
            Limit=limit,
            **({"ExclusiveStartKey": cursor} if cursor else {}),
        )

    items_raw = resp.get("Items", [])
    items = [video_from_item(i) for i in items_raw]

    # Apply duration filter in memory (DDB doesn't support range filters on non-key attrs efficiently)
    if duration_min is not None:
        items = [v for v in items if v.duration_seconds and v.duration_seconds >= duration_min]
    if duration_max is not None:
        items = [v for v in items if v.duration_seconds and v.duration_seconds <= duration_max]

    # Apply search filter in memory (MVP — future: DDB full-text search or OpenSearch)
    if search:
        q = search.lower()
        items = [
            v for v in items
            if q in (v.title or "").lower()
            or q in (v.description or "").lower()
            or any(q in tag.lower() for tag in (v.tags if hasattr(v, "tags") else []))
        ]

    # Sort
    if sort == "popular":
        items.sort(key=lambda v: getattr(v, "view_count", 0), reverse=True)
    elif sort == "trending":
        items.sort(key=lambda v: getattr(v, "trending_score", 0), reverse=True)
    # "newest" is default (already sorted by published_at desc from DDB)

    new_cursor = resp.get("LastEvaluatedKey")
    return {"items": items[:limit], "cursor": new_cursor}


def get_trending_videos(*, limit: int = 24) -> List:
    """Get videos ranked by views in the last 24 hours.

    Queries the video_views table for views in the last 24h,
    aggregates by video_id, and returns the top N.

    Performance note: This is expensive for large view tables.
    In production, trending_score should be pre-computed by a
    background job and cached on the VideoMetadata record.
    """
    # MVP: query ByGalleryPublished GSI, sort by trending_score (pre-computed)
    resp = T.video_metadata.query(
        IndexName="ByGalleryPublished",
        KeyConditionExpression=Key("gallery_published_flag").eq("Y"),
        FilterExpression="#st = :pub AND visibility = :vis",
        ExpressionAttributeValues={
            ":pub": "published",
            ":vis": "public",
        },
        ExpressionAttributeNames={"#st": "status"},
        ScanIndexForward=False,
        Limit=200,  # Fetch more, sort in-memory
    )
    items = [video_from_item(i) for i in resp.get("Items", [])]
    items.sort(key=lambda v: getattr(v, "trending_score", 0), reverse=True)
    return items[:limit]


def publish_to_gallery(
    *,
    video_id: str,
    user_id: str,
    category: str,
    tags: List[str],
    title: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Publish a video to the gallery from any source.

    Validates ownership and status, then updates metadata fields:
    visibility -> public, status -> published (if approved),
    gallery_published -> True, category, tags, published_at.

    Args:
        video_id: The video to publish.
        user_id: Must match video.owner_user_id.
        category: Must be a valid category slug.
        tags: Up to 10 free-form tags.
        title: Optional new title (overrides existing).
        description: Optional new description.

    Raises:
        HTTPException 404: Video not found.
        HTTPException 403: Not the video owner.
        HTTPException 400: Invalid category or video not in publishable state.
    """
    video = get_video(video_id)

    if video.owner_user_id != user_id:
        raise HTTPException(403, "Not your video")

    if video.status not in ("approved", "published"):
        raise HTTPException(400, "Video must be approved or published before gallery publishing")

    if category not in VALID_CATEGORY_SLUGS:
        raise HTTPException(400, f"Invalid category: {category}")

    if len(tags) > 10:
        raise HTTPException(400, "Maximum 10 tags allowed")

    ts = now_ts()

    update_parts = [
        "gallery_published = :gp",
        "gallery_published_flag = :gpf",
        "category = :cat",
        "tags = :tags",
        "visibility = :vis",
        "updated_at = :ua",
    ]
    values: Dict[str, Any] = {
        ":gp": True,
        ":gpf": "Y",
        ":cat": category,
        ":tags": tags,
        ":vis": "public",
        ":ua": ts,
    }

    if video.status == "approved":
        update_parts.append("#st = :pub")
        values[":pub"] = "published"

    if not video.published_at:
        update_parts.append("published_at = :pa")
        values[":pa"] = ts

    if title:
        update_parts.append("title = :t")
        values[":t"] = title

    if description is not None:
        update_parts.append("description = :d")
        values[":d"] = description

    names: Dict[str, str] = {}
    if "#st" in " ".join(update_parts):
        names["#st"] = "status"

    kwargs: dict = {
        "Key": {"video_id": video_id},
        "UpdateExpression": "SET " + ", ".join(update_parts),
        "ExpressionAttributeValues": values,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names

    T.video_metadata.update_item(**kwargs)

    return {
        "video_id": video_id,
        "gallery_published": True,
        "category": category,
        "tags": tags,
        "published_at": video.published_at or ts,
    }
```

### 3.7 DDB GSI Additions to VideoMetadata Table

Add two new GSIs to support gallery browsing:

```python
# In scripts/local-ddb-init.py, update VideoMetadata TableDef:
TableDef(
    _resolve_table_name(S.video_metadata_table_name, "VideoMetadata"),
    "video_id",
    gsi=[
        # Existing GSIs
        {"index_name": "ByOwnerCreatedAt", "partition_key": "owner_user_id", "sort_key": "created_at"},
        {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "BySourceBroadcast", "partition_key": "source_broadcast_session_id"},
        # New GSIs (VOD-017)
        {"index_name": "ByCategory", "partition_key": "category", "sort_key": "published_at"},
        {"index_name": "ByGalleryPublished", "partition_key": "gallery_published_flag", "sort_key": "published_at"},
    ],
    attr_types={"created_at": "N", "published_at": "N"},
)
```

**ByCategory GSI**: Partitioned by category slug, sorted by `published_at` descending. Supports category-filtered browsing.

**ByGalleryPublished GSI**: Partitioned by `gallery_published_flag` (string "Y"), sorted by `published_at`. The flag is a string (not boolean) because DynamoDB cannot use boolean as a partition key. All gallery-published videos share the same partition key "Y", which creates a hot partition — acceptable for read-heavy browse patterns at current scale (on-demand billing absorbs spikes).

### 3.8 DDB Table Additions

```python
# video_views table
TableDef(
    "video_views",
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByViewDate", "partition_key": "video_id", "sort_key": "view_date_ts"},
    ],
    attr_types={"view_date_ts": "N"},
),

# video_likes table
TableDef(
    "video_likes",
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByUser", "partition_key": "user_id", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

Settings additions (`app/core/settings.py`):
```python
video_views_table_name: str = os.environ.get("VIDEO_VIEWS_TABLE_NAME", "video_views")
video_likes_table_name: str = os.environ.get("VIDEO_LIKES_TABLE_NAME", "video_likes")
```

Table handles (`app/core/tables.py`):
```python
video_views: Any
video_likes: Any
# In T = Tables(...):
video_views=ddb.Table(S.video_views_table_name),
video_likes=ddb.Table(S.video_likes_table_name),
```

### 3.9 API Endpoints

#### 3.9.1 Browse Gallery

```
GET /ui/videos/gallery
```

Query parameters:
- `category` (optional): Category slug filter
- `sort` (optional): `"newest"` (default) | `"popular"` | `"trending"`
- `duration_min` (optional): Minimum duration in seconds
- `duration_max` (optional): Maximum duration in seconds
- `search` (optional): Full-text search query
- `limit` (optional): Page size, default 24, max 100
- `cursor` (optional): Pagination cursor

Response model:
```python
class GalleryVideoItem(BaseModel):
    video_id: str
    title: str
    description: Optional[str] = None
    thumbnail_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    view_count: int = 0
    like_count: int = 0
    comment_count: int = 0
    owner_user_id: str
    price_cents: Optional[int] = None
    access_mode: Optional[str] = None
    created_at: int
    published_at: Optional[int] = None

class GalleryListOut(BaseModel):
    videos: List[GalleryVideoItem]
    categories: List[dict]    # All valid categories for filter UI
    cursor: Optional[str] = None
```

#### 3.9.2 Trending Videos

```
GET /ui/videos/gallery/trending
```

Query parameters:
- `limit` (optional): Default 24, max 100

Returns the same `GalleryListOut` model, but sorted by `trending_score` (views in last 24h).

#### 3.9.3 Creator Gallery Page

```
GET /ui/videos/gallery/creator/{creator_id}
```

Returns a creator's gallery-published videos. Reuses the existing `CreatorVideoListOut` response model from `video_listing.py` (line 627), filtered to `gallery_published=true`.

#### 3.9.4 Record View

```
POST /ui/videos/{video_id}/view
```

Response:
```python
class ViewRecordOut(BaseModel):
    view_count: int
    is_new_view: bool
```

#### 3.9.5 Like/Unlike Toggle

```
POST /ui/videos/{video_id}/like
```

Response:
```python
class LikeToggleOut(BaseModel):
    liked: bool
    like_count: int
```

#### 3.9.6 Publish to Gallery

```
POST /ui/videos/{video_id}/publish-to-gallery
```

Request:
```python
class PublishToGalleryIn(BaseModel):
    category: str = Field(min_length=1, max_length=50)
    tags: List[str] = Field(default_factory=list, max_length=10)
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
```

Response:
```python
class PublishToGalleryOut(BaseModel):
    video_id: str
    gallery_published: bool
    category: str
    tags: List[str]
    published_at: int
```

### 3.10 Frontend Types

```typescript
// frontend/src/api/types.ts

export interface GalleryVideoItem {
  video_id: string;
  title: string;
  description?: string;
  thumbnail_url?: string;
  duration_seconds?: number;
  category?: string;
  tags: string[];
  view_count: number;
  like_count: number;
  comment_count: number;
  owner_user_id: string;
  price_cents?: number;
  access_mode?: string;
  created_at: number;
  published_at?: number;
}

export interface GalleryListResponse {
  videos: GalleryVideoItem[];
  categories: Array<{ slug: string; label: string }>;
  cursor?: string;
}

export interface ViewRecordResponse {
  view_count: number;
  is_new_view: boolean;
}

export interface LikeToggleResponse {
  liked: boolean;
  like_count: number;
}

export interface PublishToGalleryRequest {
  category: string;
  tags: string[];
  title?: string;
  description?: string;
}

export interface PublishToGalleryResponse {
  video_id: string;
  gallery_published: boolean;
  category: string;
  tags: string[];
  published_at: number;
}
```

### 3.11 Frontend Pages

#### Video Gallery Page (`/gallery`)

```
GalleryPage
├── useQuery(["gallery", filters], () => listGalleryVideos(filters))
├── CategoryFilter (pill bar with all categories)
├── SortSelector (dropdown: Newest / Popular / Trending)
├── DurationFilter (range slider: 0-60min)
├── SearchInput (debounced text input)
├── VideoGrid
│   └── GalleryVideoCard (repeated)
│       ├── thumbnail + duration badge
│       ├── title (2-line clamp)
│       ├── creator name + avatar
│       ├── view_count + like_count
│       ├── price badge (if PPV)
│       └── Link to /videos/{video_id}
└── LoadMore / InfiniteScroll
```

#### Video Detail Page (updated)

```
VideoDetailPage (updated)
├── ... existing video player + access gate ...
├── EngagementBar
│   ├── ViewCount display
│   ├── LikeButton (heart toggle)
│   │   └── useMutation(toggleLike, { onSuccess: invalidate ["video", id] })
│   ├── CommentCount display
│   └── ShareButton
│       ├── Copy Link
│       ├── Share to Messenger (opens ComposeBar with video link)
│       └── Share to Feed (opens CreatePost with video link)
├── CommentsSection
│   ├── useInfiniteQuery(["video-comments", videoId])
│   ├── CommentInput
│   └── CommentThread (reuses newsfeed CommentRow)
└── RelatedVideosSidebar
    └── useQuery(["related", videoId], () => getRelatedVideos(videoId))
```

### 3.12 Frontend Route Addition

```typescript
// frontend/src/App.tsx
{ path: "/gallery", lazy: () => import("./pages/gallery/GalleryPage") },
```

Sidebar addition in `Sidebar.tsx` and `AppShell.tsx`:
```typescript
{ label: "Gallery", href: "/gallery", icon: PlaySquare }
```

---

## 4. Implementation Plan

<!-- NOTE: The gallery feature is FULLY IMPLEMENTED. Key existing files:
     - `app/services/video_gallery.py` — `publish_to_gallery()` (line 49), `unpublish_from_gallery()` (line 133), `record_view()` (line 152), `toggle_like()` (line 208), `browse_gallery()` (line 264), `search_gallery()` (line 312), `compute_trending_score()` (line 368), `update_trending_score()` (line 381)
     - `app/services/video_comments.py` — `add_comment()` (line 22), `list_comments()` (line 70), `delete_comment()` (line 112)
     - `app/routers/video_listing.py` — Gallery-related models: `GalleryVideoItem` (line 358), `GalleryListOut` (line 376), `GallerySearchOut` (line 382), `PublishToGalleryIn` (line 387), `PublishToGalleryOut` (line 394), `ViewRecordOut` (line 402), `LikeToggleOut` (line 407), `VideoCommentIn` (line 416), `VideoCommentOut` (line 420), `CategoriesOut` (line 433)
     - DDB tables: VideoViews (line 811), VideoLikes (line 821) in local-ddb-init.py
     - GSIs on VideoMetadata: ByCategory (line 731), ByGalleryPublished (line 735)
     - Settings: video_views_table_name (1234), video_likes_table_name (1235)
     - Frontend: GalleryPage.tsx, GalleryVideoCard.tsx, VideoDetailPage.tsx in frontend/src/pages/gallery/
     - E2E: frontend/e2e/video-gallery.spec.ts
-->

### Step 1: Extend VideoMetadataModel

**File**: `app/models_video.py`

Add fields after `download_count` (line 108):
```python
# Gallery (VOD-017)
gallery_published: bool = False
category: Optional[str] = None
tags: List[str] = Field(default_factory=list)
view_count: int = 0
like_count: int = 0
comment_count: int = 0
trending_score: int = 0
trending_updated_at: int = 0
```

### Step 2: Update Video Metadata Store Serialization

**File**: `app/services/video_metadata_store.py`

Add `"category"` to `_optional_str_fields`, add `"view_count"`, `"like_count"`, `"comment_count"`, `"trending_score"`, `"trending_updated_at"` to `_optional_num_fields`. Handle `tags` (list of strings) and `gallery_published` (bool) in serialization/deserialization.

### Step 3: Create New DDB Tables

**File**: `scripts/local-ddb-init.py`

Add `video_views` and `video_likes` tables. Add `ByCategory` and `ByGalleryPublished` GSIs to the existing `VideoMetadata` table.

### Step 4: Add Settings + Table Handles

**File**: `app/core/settings.py` — Add `video_views_table_name`, `video_likes_table_name`  
**File**: `app/core/tables.py` — Add `video_views`, `video_likes` table handles

### Step 5: Create Gallery Service

**File**: `app/services/video_gallery.py` (new, ~350 lines)

Functions: `record_view()`, `toggle_like()`, `check_liked()`, `list_gallery_videos()`, `get_trending_videos()`, `publish_to_gallery()`.

### Step 6: Add Router Endpoints

**File**: `app/routers/video_listing.py` (extend existing)

Add gallery browse, trending, view, like, and publish-to-gallery endpoints after the existing MON-005 section. Import from `video_gallery` service.

### Step 7: Register Routes

**File**: `app/main.py` — No new router needed (endpoints added to existing `video_listing.router`).

### Step 8: Frontend Types and API

**File**: `frontend/src/api/types.ts` — Add gallery types  
**File**: `frontend/src/api/endpoints/gallery.ts` (new) — API wrappers

### Step 9: Frontend Gallery Page

**File**: `frontend/src/pages/gallery/GalleryPage.tsx` (new)  
**File**: `frontend/src/pages/gallery/GalleryVideoCard.tsx` (new)

### Step 10: Update Video Detail Page

**File**: `frontend/src/pages/vod/VideoPlayerPage.tsx` (modify) — Add engagement bar, comments, related videos

### Step 11: Add Route + Sidebar

**File**: `frontend/src/App.tsx` — Add `/gallery` route  
**File**: `frontend/src/components/layout/Sidebar.tsx` — Add Gallery link  
**File**: `frontend/src/components/layout/AppShell.tsx` — Add to mobile sidebar  
**File**: `frontend/src/components/layout/MobileNav.tsx` — Add to MORE_LINKS

### Summary of Files Modified

| File | Change Type | Estimated Lines |
|------|-------------|-----------------|
| `app/models_video.py` | Add gallery fields | ~15 |
| `app/services/video_metadata_store.py` | Serialize new fields | ~30 |
| `app/services/video_gallery.py` | New service | ~350 |
| `app/routers/video_listing.py` | Add 6 endpoints + models | ~250 |
| `app/core/settings.py` | Add table name settings | ~5 |
| `app/core/tables.py` | Add table handles | ~5 |
| `scripts/local-ddb-init.py` | Add tables + GSIs | ~30 |
| `frontend/src/api/types.ts` | Add TypeScript types | ~50 |
| `frontend/src/api/endpoints/gallery.ts` | New API wrappers | ~60 |
| `frontend/src/pages/gallery/GalleryPage.tsx` | New gallery page | ~200 |
| `frontend/src/pages/gallery/GalleryVideoCard.tsx` | New card component | ~60 |
| `frontend/src/pages/vod/VideoPlayerPage.tsx` | Engagement bar + comments | ~150 |
| `frontend/src/App.tsx` | Add route | ~3 |
| `frontend/src/components/layout/Sidebar.tsx` | Add link | ~3 |
| `frontend/src/components/layout/AppShell.tsx` | Add mobile link | ~3 |
| `frontend/src/components/layout/MobileNav.tsx` | Add MORE_LINKS entry | ~3 |
| **Total** | | **~1217** |

---

## 5. Testing Strategy

### 5.1 Unit Tests (`tests/test_video_gallery.py`)

New file, ~500 lines. Moto-mocked DynamoDB.

**Test function signatures:**

```python
def test_record_view_new_user(ddb_tables, seed_video):
    """First view from a user increments view_count."""
    result = record_view(video_id=seed_video, user_id="alice")
    assert result["is_new_view"] is True
    assert result["view_count"] == 1

def test_record_view_dedup_same_day(ddb_tables, seed_video):
    """Second view same user same day does NOT increment."""
    record_view(video_id=seed_video, user_id="alice")
    result = record_view(video_id=seed_video, user_id="alice")
    assert result["is_new_view"] is False
    assert result["view_count"] == 1

def test_record_view_different_users(ddb_tables, seed_video):
    """Views from different users both count."""
    record_view(video_id=seed_video, user_id="alice")
    result = record_view(video_id=seed_video, user_id="bob")
    assert result["view_count"] == 2

def test_toggle_like_on(ddb_tables, seed_video):
    """First like sets liked=True."""
    result = toggle_like(video_id=seed_video, user_id="alice")
    assert result["liked"] is True
    assert result["like_count"] == 1

def test_toggle_like_off(ddb_tables, seed_video):
    """Second toggle removes like."""
    toggle_like(video_id=seed_video, user_id="alice")
    result = toggle_like(video_id=seed_video, user_id="alice")
    assert result["liked"] is False
    assert result["like_count"] == 0

def test_publish_to_gallery_sets_fields(ddb_tables, seed_approved_video):
    """Publish sets gallery_published, category, tags, visibility."""
    result = publish_to_gallery(
        video_id=seed_approved_video, user_id="alice",
        category="tutorials", tags=["python", "fastapi"],
    )
    assert result["gallery_published"] is True
    assert result["category"] == "tutorials"

def test_publish_to_gallery_invalid_category(ddb_tables, seed_approved_video):
    """Invalid category returns 400."""
    with pytest.raises(HTTPException) as exc:
        publish_to_gallery(
            video_id=seed_approved_video, user_id="alice",
            category="invalid_cat", tags=[],
        )
    assert exc.value.status_code == 400

def test_publish_to_gallery_not_owner(ddb_tables, seed_approved_video):
    """Non-owner cannot publish."""
    with pytest.raises(HTTPException) as exc:
        publish_to_gallery(
            video_id=seed_approved_video, user_id="bob",
            category="tutorials", tags=[],
        )
    assert exc.value.status_code == 403

def test_publish_to_gallery_unapproved(ddb_tables, seed_encoding_video):
    """Cannot publish video that is not approved/published."""
    with pytest.raises(HTTPException) as exc:
        publish_to_gallery(
            video_id=seed_encoding_video, user_id="alice",
            category="tutorials", tags=[],
        )
    assert exc.value.status_code == 400

def test_gallery_list_returns_published_only(ddb_tables, seed_gallery_videos):
    """Gallery list only returns gallery_published + published + public videos."""
    result = list_gallery_videos()
    assert all(v.gallery_published for v in result["items"])

def test_gallery_filter_by_category(ddb_tables, seed_gallery_videos):
    """Category filter narrows results."""
    result = list_gallery_videos(category="tutorials")
    assert all(v.category == "tutorials" for v in result["items"])

def test_tags_max_10(ddb_tables, seed_approved_video):
    """More than 10 tags returns 400."""
    with pytest.raises(HTTPException) as exc:
        publish_to_gallery(
            video_id=seed_approved_video, user_id="alice",
            category="tutorials",
            tags=["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11"],
        )
    assert exc.value.status_code == 400
```

### 5.2 E2E Tests (`frontend/e2e/video-gallery.spec.ts`)

New file, ~600 lines.

**Section 131: Gallery Browsing API (5 tests)**

1. `Alice publishes a video to the gallery` — POST publish-to-gallery, verify 200
2. `Gallery lists published video` — GET /gallery, verify video appears
3. `Gallery filters by category` — GET /gallery?category=tutorials, verify filter
4. `Gallery returns categories list` — GET /gallery, verify categories array in response
5. `Non-gallery videos excluded` — Verify private/unlisted videos do not appear

**Section 132: Video Engagement API (5 tests)**

1. `Bob views Alice's video — view counted` — POST /view, verify view_count=1
2. `Bob views again same day — deduplicated` — POST /view, verify view_count=1
3. `Bob likes video — like_count increments` — POST /like, verify liked=true, count=1
4. `Bob unlikes video — like_count decrements` — POST /like again, verify liked=false, count=0
5. `Video comments via newsfeed endpoint` — POST /posts/{video_id}/comments, verify 200 (requires shadow post record — see section 3.5)

**Section 133: Multi-Source Publishing (4 tests)**

1. `Publish uploaded video to gallery` — Upload → publish → verify in gallery
2. `Publish with title override` — POST publish-to-gallery with new title, verify
3. `Publish with tags` — POST with tags=["a","b","c"], verify in detail response
4. `Non-owner cannot publish` — POST as Bob for Alice's video, verify 403

**Test setup (beforeAll):**
- Seed sessions for Alice (creator) and Bob (viewer)
- Create a video as Alice via upload presign + complete
- Transition video to published/approved status

---

## 6. Security Considerations

### 6.1 Authentication & Authorization

- **Gallery browse** (`GET /ui/videos/gallery`): Requires `require_ui_session`. Authenticated users only. No anonymous gallery access.
- **View recording** (`POST /ui/videos/{id}/view`): Requires auth. The `user_id` for dedup comes from the session, not the request body — a client cannot forge view counts for other users.
- **Like toggle** (`POST /ui/videos/{id}/like`): Requires auth. Like records are keyed by authenticated `user_sub`.
- **Publish to gallery** (`POST /ui/videos/{id}/publish-to-gallery`): Validates `video.owner_user_id == user_sub`. Non-owners get 403.

### 6.2 Input Validation

- `category`: Validated against `VALID_CATEGORY_SLUGS`. Arbitrary strings rejected.
- `tags`: Max 10 tags, each 1-50 characters. Validated via Pydantic model.
- `search`: Free-text, max 200 characters. Used for in-memory `str.contains()` — no SQL/NoSQL injection risk (DDB queries do not use search input).
- `sort`: Validated against enum `{"newest", "popular", "trending"}`.
- `duration_min/duration_max`: Integers >=0, validated by Pydantic.

### 6.3 Rate Limiting

- View recording: 60 requests per minute per user (one per video per second is generous).
- Like toggle: 30 requests per minute per user.
- Gallery browse: Standard API rate limit (100 rpm).
- Publish to gallery: 10 per minute per user.

### 6.4 Abuse Vectors

- **View count inflation**: Deduplicated per user per day. A single user can only contribute 1 view per video per day. Botnet attacks require many authenticated accounts.
- **Like farming**: One like per user per video. Cannot inflate beyond the number of registered accounts.
- **Tag spam**: Limited to 10 tags, 50 chars each. No HTML/script injection risk (tags stored as plain strings in DDB, rendered as text in React).

---

## 7. Migration & Rollback Plan

### 7.1 DDB Table/GSI Creation

New tables (`video_views`, `video_likes`) are additive. New GSIs (`ByCategory`, `ByGalleryPublished`) are added to the existing `VideoMetadata` table — in production, this requires an online GSI creation (DDB supports up to 5 concurrent GSI backfills).

### 7.2 Data Backfill

No backfill needed. Existing videos default to `gallery_published=False`, `view_count=0`, `like_count=0`. They will not appear in the gallery until explicitly published.

### 7.3 Feature Flag

```python
vod_gallery_enabled: bool = os.environ.get("VOD_GALLERY_ENABLED", "0") not in ("0", "false", "False")
```

When disabled, gallery endpoints return 404. The feature can be enabled incrementally.

### 7.4 Rollback

Set `VOD_GALLERY_ENABLED=0`. Gallery endpoints return 404. New tables and GSIs remain but are unused. No data loss.

---

## 8. Performance & Capacity Planning

### 8.1 Expected Throughput

| Operation | Estimate | Components |
|-----------|----------|------------|
| Gallery browse/sec | 50 | Main discovery flow |
| View records/sec | 100 | Every video play triggers a view |
| Like toggles/sec | 10 | Less frequent than views |
| Publish actions/sec | 1 | Infrequent creator action |

### 8.2 DDB Capacity

**video_views table (on-demand):**
- Write: 1 WCU per new view (conditional put). ~100 writes/sec worst case.
- Read: Negligible (view dedup check is a get_item before write).
- TTL: Auto-expire after 90 days, keeping table size bounded.

**video_likes table (on-demand):**
- Write: 1 WCU per like/unlike. ~10 writes/sec.
- Read: 1 RCU per like check. ~10 reads/sec.

**VideoMetadata table (additional load):**
- 1 additional update_item per new view (increment view_count).
- ByGalleryPublished GSI: Hot partition on "Y" key. At 50 browse requests/sec, this is 50 RCUs — within on-demand limits.

### 8.3 Latency Budget

| Operation | Target p99 | Components |
|-----------|-----------|------------|
| GET /videos/gallery | 100ms | GSI query (25ms) + in-memory filter (5ms) + serialize (5ms) |
| POST /videos/{id}/view | 50ms | Conditional put (15ms) + counter increment (15ms) |
| POST /videos/{id}/like | 50ms | Get+put/delete (20ms) + counter update (15ms) |
| GET /videos/gallery/trending | 150ms | GSI query (25ms) + sort (10ms) |

---

## 9. Dependency Analysis

### 9.1 Blocked By

| Ticket | Dependency |
|--------|-----------|
| MON-001 | Price/access_mode fields on VideoMetadataModel |
| MON-005 | Subscription-aware entitlement cascade |

### 9.2 Blocks

No downstream tickets blocked by VOD-017. This is a leaf feature.

### 9.3 Integration Points

- **Video metadata table** (`T.video_metadata`): Adds `gallery_published`, `category`, `tags`, `view_count`, `like_count`, `comment_count`, `trending_score` fields. Must not break existing `video_from_item()`.
- **Newsfeed comments** (`app/routers/newsfeed.py`): Requires a bridge/adapter — either a shadow post record created during `publish_to_gallery()` (recommended) or separate video comment endpoints that bypass the post-existence check. See section 3.5 for details. The comment PK format is `POST#{post_id}#COMMENTS`, and the table is accessed via a module-level `tbl = ddb.Table("app_single_table")` (not via `T.*`).
- **File manager bridge** (VOD-014): Videos imported via file bridge can be published to gallery after encoding/approval.
- **Broadcast recordings** (BCAST-006): Recordings can be published to gallery via the same `publish-to-gallery` endpoint.

---

## 10. Search Architecture

### 10.1 DDB-Based Prefix Search (MVP)

Full-text search in the gallery uses DDB-based prefix token indexing, following the same pattern as message search (`app/services/message_search.py`). This avoids introducing a dedicated search service (OpenSearch/Elasticsearch) for v1.

**Token generation for titles, descriptions, and tags:**

```python
# app/services/video_search.py

import re
from typing import List, Set

_STOP_WORDS = {"the", "a", "an", "is", "are", "was", "were", "in", "on", "at", "to",
               "for", "of", "with", "and", "or", "but", "not", "this", "that", "it"}
_MAX_PREFIX_LEN = 8  # Prefix tokens capped at 8 chars (matches message search)
_MIN_TOKEN_LEN = 2   # Tokens shorter than 2 chars are ignored


def tokenize(text: str) -> Set[str]:
    """Split text into normalized, lowercased tokens. Removes stop words."""
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {w for w in words if len(w) >= _MIN_TOKEN_LEN and w not in _STOP_WORDS}


def build_prefix_tokens(token: str) -> Set[str]:
    """Generate prefix tokens for a word: 'python' -> {'py', 'pyt', 'pyth', 'pytho', 'python'}."""
    return {token[:i] for i in range(_MIN_TOKEN_LEN, min(len(token), _MAX_PREFIX_LEN) + 1)}


def build_search_index_tokens(*, title: str, description: str = "", tags: List[str] = []) -> Set[str]:
    """Generate the full set of prefix tokens for a video's searchable fields.

    Title tokens get 3x weight (appear in index 3 times — not literally,
    but ranking uses title-match boosting at query time).
    """
    all_tokens: Set[str] = set()

    # Title tokens
    for token in tokenize(title):
        all_tokens.update(build_prefix_tokens(token))

    # Description tokens
    for token in tokenize(description):
        all_tokens.update(build_prefix_tokens(token))

    # Tag tokens (tags are already individual terms)
    for tag in tags:
        for token in tokenize(tag):
            all_tokens.update(build_prefix_tokens(token))

    return all_tokens
```

**Search index storage:**

Each video's search tokens are stored as a `search_tokens` attribute (String Set) on the `VideoMetadata` DDB item. When a video is published to the gallery, `build_search_index_tokens()` generates the token set and writes it via `update_item`.

```python
# In publish_to_gallery():
tokens = build_search_index_tokens(
    title=title or video.title or "",
    description=description or video.description or "",
    tags=tags,
)
# Add to the update expression:
update_parts.append("search_tokens = :st")
values[":st"] = tokens  # DynamoDB String Set
```

**Query execution:**

```python
def search_gallery(query: str, *, limit: int = 24, cursor: dict = None) -> dict:
    """Search gallery videos by prefix-matching query tokens against search_tokens.

    1. Tokenize the query string.
    2. Generate prefix tokens for each query token.
    3. Scan ByGalleryPublished GSI with FilterExpression checking
       that search_tokens CONTAINS each query prefix token.
    4. Rank results by match quality.
    """
    query_tokens = tokenize(query)
    if not query_tokens:
        return {"items": [], "cursor": None}

    # Build filter: all query tokens must match (AND semantics)
    filter_parts = []
    attr_values = {":gp": "Y", ":pub": "published", ":vis": "public"}
    for i, token in enumerate(query_tokens):
        # Use the shortest valid prefix for the filter
        prefix = token[:_MAX_PREFIX_LEN]
        filter_parts.append(f"contains(search_tokens, :qt{i})")
        attr_values[f":qt{i}"] = prefix

    filter_expr = " AND ".join([
        "#st = :pub",
        "visibility = :vis",
    ] + filter_parts)

    resp = T.video_metadata.query(
        IndexName="ByGalleryPublished",
        KeyConditionExpression=Key("gallery_published_flag").eq("Y"),
        FilterExpression=filter_expr,
        ExpressionAttributeValues=attr_values,
        ExpressionAttributeNames={"#st": "status"},
        ScanIndexForward=False,
        Limit=limit * 3,  # Over-fetch to compensate for filter
        **({"ExclusiveStartKey": cursor} if cursor else {}),
    )
    # ... rank and return ...
```

### 10.2 Search Ranking

Results are ranked by a composite score:

```python
def _rank_search_results(items: list, query_tokens: Set[str]) -> list:
    """Rank search results by match quality.

    Scoring:
      - Exact title match:      100 points per token
      - Title prefix match:      50 points per token
      - Tag exact match:         30 points per token
      - Description match:       10 points per token
      - Partial (any field):      5 points per token
      - Engagement bonus:        log2(view_count + 1)
    """
    scored = []
    for item in items:
        score = 0
        title_tokens = tokenize(item.title or "")
        tag_tokens = set()
        for tag in (item.tags or []):
            tag_tokens.update(tokenize(tag))
        desc_tokens = tokenize(item.description or "")

        for qt in query_tokens:
            if qt in title_tokens:
                score += 100  # Exact title match
            elif any(tt.startswith(qt) for tt in title_tokens):
                score += 50   # Title prefix match
            elif qt in tag_tokens:
                score += 30   # Tag exact match
            elif qt in desc_tokens:
                score += 10   # Description match
            else:
                score += 5    # Partial match (matched via search_tokens)

        # Engagement bonus
        import math
        score += math.log2(getattr(item, "view_count", 0) + 1)

        scored.append((score, item))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [item for _, item in scored]
```

### 10.3 Query Syntax

| Syntax | Example | Behavior |
|--------|---------|----------|
| Plain words | `python tutorial` | AND match: both "python" AND "tutorial" must match |
| Quoted phrase | `"python tutorial"` | Not supported in v1. Treated as two separate words. Future: phrase matching via positional tokens. |
| Tag filter | `tag:cooking` | Filters results to videos with the exact tag "cooking". Implemented as an additional `contains(tags, :tag)` filter. |
| Creator filter | `creator:alice` | Filters results to videos owned by user "alice". Implemented as `owner_user_id = :cid` filter. |
| Mixed | `pasta tag:cooking creator:alice` | Search for "pasta" in title/description, restrict to tag "cooking" and creator "alice". |

### 10.4 Limitations and Future Improvements

| Limitation | Impact | Future Fix |
|-----------|--------|------------|
| DDB scan-based search with FilterExpression | Slow for large catalogs (>100K videos). FilterExpression applies AFTER 1MB page fetch. | Migrate to OpenSearch for full-text search. |
| No phrase matching | `"learn python"` matches any video with both "learn" and "python", not the exact phrase. | Add positional token indices. |
| No typo tolerance | "pythn" returns no results. | Add edit-distance fuzzy matching or n-gram tokens. |
| No relevance decay | Old videos rank equally to new videos at the same match score. | Add recency boost: `score += max(0, 30 - days_since_published)`. |
| search_tokens stored on video item | Increases item size by ~1-5KB per video. | Move to a separate search index table. |

---

## 11. Trending Algorithm

### 11.1 Score Formula

```
trending_score = views_24h * 1.0
               + likes_24h * 5.0
               + comments_24h * 3.0
               + shares_24h * 4.0
```

Where:
- `views_24h`: Number of unique views in the last 24 hours (from `video_views` table, filtering by `view_date_ts >= now - 86400`).
- `likes_24h`: Number of new likes in the last 24 hours (from `video_likes` table, filtering by `created_at >= now - 86400`).
- `comments_24h`: Number of new comments in the last 24 hours (from newsfeed comments with `post_id=video_id`, filtering by `created_at`).
- `shares_24h`: Number of times the video was shared via messenger or newsfeed in the last 24 hours (from `video_shares` counter or message `kind=video_share` items). In v1, shares are not tracked separately, so `shares_24h = 0`.

### 11.2 Decay Function

To prevent a single viral burst from dominating trending indefinitely, the score decays over time:

```python
import math

def compute_trending_score(
    views_24h: int,
    likes_24h: int,
    comments_24h: int,
    shares_24h: int,
    hours_since_published: float,
) -> float:
    """Compute trending score with time decay.

    The decay factor reduces the score for older videos:
    - Published 0h ago: decay = 1.0
    - Published 12h ago: decay = 0.707
    - Published 24h ago: decay = 0.5
    - Published 48h ago: decay = 0.354
    - Published 7d ago: decay = 0.0773
    """
    raw_score = (
        views_24h * 1.0
        + likes_24h * 5.0
        + comments_24h * 3.0
        + shares_24h * 4.0
    )

    # Half-life decay: score halves every 24 hours since publication
    decay = math.pow(0.5, hours_since_published / 24.0)

    return raw_score * decay
```

### 11.3 Score Recalculation — Background Job

The `trending_score` on each video's `VideoMetadata` record is updated by a background job that runs every 15 minutes.

```python
# app/services/video_trending_worker.py

import logging
from datetime import datetime, timezone
from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

RECALC_INTERVAL_SECONDS = 900  # 15 minutes
MAX_VIDEOS_PER_RUN = 5000      # Safety cap


def recalculate_trending_scores() -> int:
    """Recalculate trending_score for all gallery-published videos.

    Steps:
    1. Query all gallery-published videos (ByGalleryPublished GSI).
    2. For each video, count views/likes/comments in the last 24h.
    3. Compute trending_score with decay.
    4. Write updated score to VideoMetadata.

    Returns the number of videos updated.
    """
    now = now_ts()
    cutoff_24h = now - 86400
    count = 0

    # Page through all gallery-published videos
    last_key = None
    while count < MAX_VIDEOS_PER_RUN:
        kwargs = {
            "IndexName": "ByGalleryPublished",
            "KeyConditionExpression": Key("gallery_published_flag").eq("Y"),
            "ProjectionExpression": "video_id, published_at",
            "Limit": 100,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        resp = T.video_metadata.query(**kwargs)
        items = resp.get("Items", [])
        if not items:
            break

        for item in items:
            video_id = item["video_id"]
            published_at = int(item.get("published_at", now))

            # Count 24h views
            views_24h = _count_views_since(video_id, cutoff_24h)
            likes_24h = _count_likes_since(video_id, cutoff_24h)
            comments_24h = _count_comments_since(video_id, cutoff_24h)

            hours_since = max(0, (now - published_at) / 3600)
            score = compute_trending_score(views_24h, likes_24h, comments_24h, 0, hours_since)

            # Write score
            T.video_metadata.update_item(
                Key={"video_id": video_id},
                UpdateExpression="SET trending_score = :ts, trending_updated_at = :ua",
                ExpressionAttributeValues={":ts": int(score), ":ua": now},
            )
            count += 1

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    logger.info("Trending recalculation complete: %d videos updated", count)
    return count


def _count_views_since(video_id: str, since_ts: int) -> int:
    """Count unique views for a video since the given timestamp."""
    resp = T.video_views.query(
        IndexName="ByViewDate",
        KeyConditionExpression=Key("video_id").eq(video_id) & Key("view_date_ts").gte(since_ts),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def _count_likes_since(video_id: str, since_ts: int) -> int:
    """Count likes for a video since the given timestamp."""
    resp = T.video_likes.query(
        KeyConditionExpression=Key("pk").eq(f"VIDEO#{video_id}"),
        FilterExpression="created_at >= :since",
        ExpressionAttributeValues={":since": since_ts},
        Select="COUNT",
    )
    return resp.get("Count", 0)


def _count_comments_since(video_id: str, since_ts: int) -> int:
    """Count comments on a video since the given timestamp.

    Queries the newsfeed comments in app_single_table.
    Note: There is no `T.app_single_table` handle in `app/core/tables.py`.
    The newsfeed router accesses this table via a module-level variable:
        `tbl = ddb.Table("app_single_table")`
    This worker must do the same, or a new table handle should be added
    to `app/core/tables.py` for it.

    Comment PK format is `POST#{post_id}#COMMENTS` (see `pk_post_comments()`
    in newsfeed.py line 759-760), NOT `COMMENT#{video_id}`.
    This requires the shadow-post bridge from section 3.5 so that
    video_id is used as post_id.
    """
    from app.core.aws import ddb as _ddb
    _app_table = _ddb.Table(os.environ.get("APP_TABLE", "app_single_table"))
    try:
        resp = _app_table.query(
            KeyConditionExpression=Key("pk").eq(f"POST#{video_id}#COMMENTS"),
            FilterExpression="created_at >= :since",
            ExpressionAttributeValues={":since": since_ts},
            Select="COUNT",
        )
        return resp.get("Count", 0)
    except Exception:
        return 0
```

### 11.4 DDB Storage

The `trending_score` is stored as an integer on the `VideoMetadata` item:

| Field | Type | Description |
|-------|------|-------------|
| `trending_score` | Number (int) | Pre-computed trending score, updated every 15 minutes |
| `trending_updated_at` | Number (int) | Unix timestamp of the last recalculation |

The gallery browse endpoint sorts by `trending_score` in memory after fetching from the `ByGalleryPublished` GSI. This is acceptable because the GSI query returns at most a few hundred items per page, and in-memory sort of 200 items is <1ms.

### 11.5 Trending Display Tiers

| Tier | Score Range | Visual Treatment |
|------|-------------|-----------------|
| Hot | Score > 500 | Fire emoji badge, featured in "Trending" carousel |
| Rising | Score 100-500 | Upward arrow badge, included in trending results |
| Active | Score 10-100 | No badge, included in trending results if limit allows |
| Cold | Score < 10 | Excluded from trending results |

---

## 12. View Deduplication

### 12.1 Dedup Logic

A view is counted **at most once per user per video per calendar day (UTC)**. The dedup is enforced by the composite sort key in the `video_views` table:

```
PK = VIDEO#{video_id}
SK = VIEW#{user_id}#{YYYY-MM-DD}
```

**Conditional write:**

```python
T.video_views.put_item(
    Item={...},
    ConditionExpression="attribute_not_exists(pk)",
)
```

If the item already exists (same user, same video, same date), `ConditionalCheckFailedException` is raised and caught. The view is silently ignored. No error is returned to the client.

### 12.2 Why Calendar Day and Not Rolling 24h Window

A rolling 24-hour window (`created_at > now - 86400`) would require a query before each write to check for recent views. This is 2x the DDB operations (read + write) compared to the calendar day approach (1x conditional write). At 100 views/sec, this doubles DDB costs.

The calendar day approach has a minor edge case: a user who watches at 11:59 PM UTC and again at 12:01 AM UTC gets 2 views counted. This is acceptable for analytics purposes and is the same approach used by YouTube.

### 12.3 Bot Detection — Minimum Watch Duration

To prevent bots and accidental clicks from inflating view counts, the view endpoint requires a `watch_duration_seconds` parameter:

```python
class RecordViewIn(BaseModel):
    watch_duration_seconds: float = Field(ge=0)

# Minimum watch duration to count as a view:
# min(30 seconds, 10% of video duration)
# If video duration is unknown, use 5 seconds.

def _meets_minimum_watch(watch_duration: float, video_duration: float | None) -> bool:
    if video_duration is None:
        return watch_duration >= 5.0
    threshold = min(30.0, video_duration * 0.1)
    return watch_duration >= threshold
```

**Frontend implementation:**

The video player tracks watch time via a `useRef` counter. When the player fires a `timeupdate` event, accumulated watch time is compared to the threshold. The `POST /ui/videos/{id}/view` call is made only once, when the threshold is first crossed.

```typescript
function useViewTracking(videoId: string, videoDuration: number | undefined) {
  const viewRecorded = useRef(false);
  const watchTime = useRef(0);

  const threshold = videoDuration
    ? Math.min(30, videoDuration * 0.1)
    : 5;

  const onTimeUpdate = useCallback((currentTime: number) => {
    watchTime.current = currentTime;
    if (!viewRecorded.current && watchTime.current >= threshold) {
      viewRecorded.current = true;
      recordView(videoId, watchTime.current);
    }
  }, [videoId, threshold]);

  return { onTimeUpdate };
}
```

### 12.4 View Count Consistency

The `view_count` on `VideoMetadata` is eventually consistent with the actual count of view records:

1. **Normal flow**: `record_view()` conditionally writes the view record AND increments `view_count` atomically (DDB `SET view_count = if_not_exists(view_count, :z) + :one`).
2. **Race condition**: Two requests for the same user+video+day arrive simultaneously. Both attempt the conditional write. One succeeds (increments count). The other gets `ConditionalCheckFailedException` (does NOT increment). Result: correct.
3. **Counter drift**: If the increment fails after the view record is written (network error, throttle), the count drifts by -1. A background reconciliation job can periodically count view records and sync `view_count`:

```python
def reconcile_view_count(video_id: str) -> int:
    """Count all unique view records and update view_count on VideoMetadata."""
    total = 0
    last_key = None
    while True:
        kwargs = {
            "KeyConditionExpression": Key("pk").eq(f"VIDEO#{video_id}"),
            "Select": "COUNT",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.video_views.query(**kwargs)
        total += resp.get("Count", 0)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET view_count = :vc",
        ExpressionAttributeValues={":vc": total},
    )
    return total
```

### 12.5 Anonymous Views

Unauthenticated users cannot record views (the view endpoint requires `require_ui_session`). This is a deliberate design choice:

- Prevents bot abuse without implementing CAPTCHAs.
- Ensures dedup is reliable (keyed by authenticated `user_sub`).
- Trade-off: View counts may undercount total actual views if unauthenticated viewers exist (e.g., public gallery pages in the future).

---

## 13. Category Taxonomy

### 13.1 Predefined Categories

| Slug | Label | Description | Example Content |
|------|-------|-------------|-----------------|
| `tutorials` | Tutorials & How-To | Step-by-step instructional content | "How to set up FastAPI", "Beginner yoga poses" |
| `entertainment` | Entertainment | General entertainment, shows, performances | Variety shows, talent performances, skits |
| `fitness` | Fitness & Wellness | Exercise, health, and wellness content | Workout routines, meditation guides, nutrition talks |
| `music` | Music & Performance | Musical performances, covers, lessons | Live concerts, instrument tutorials, DJ sets |
| `cooking` | Cooking & Food | Recipes, cooking techniques, food reviews | Recipe walkthroughs, restaurant reviews, food science |
| `gaming` | Gaming | Game playthroughs, reviews, esports | Let's plays, game reviews, tournament highlights |
| `education` | Education | Academic and professional learning | Lectures, course content, certification prep |
| `vlog` | Vlogs & Lifestyle | Personal vlogs, daily life, travel | Day-in-the-life, travel vlogs, hauls |
| `tech` | Tech & Reviews | Technology reviews, unboxings, tutorials | Product reviews, software tutorials, tech news |
| `art` | Art & Design | Visual art, graphic design, crafts | Drawing tutorials, design critiques, craft projects |
| `comedy` | Comedy | Comedy sketches, stand-up, humor | Sketch comedy, reaction videos, parodies |
| `other` | Other | Content that does not fit other categories | Miscellaneous content |

### 13.2 Category-to-GSI Mapping

Categories map directly to the `ByCategory` GSI partition key:

```
ByCategory GSI:
  Partition Key: category (String) = category slug (e.g., "tutorials")
  Sort Key: published_at (Number) = Unix timestamp

Example query: All tutorial videos, newest first:
  KeyConditionExpression: category = "tutorials"
  ScanIndexForward: False
```

Each category slug becomes a DDB partition. DDB distributes partitions across storage nodes. Categories with many videos (e.g., "entertainment") may become hot partitions, but on-demand capacity handles this automatically.

### 13.3 Category Management

**Admin category operations** (future enhancement, not in v1):

| Operation | Endpoint | Effect |
|-----------|----------|--------|
| Add category | `POST /admin/gallery/categories` | Adds to `GALLERY_CATEGORIES` list in config. Does NOT require DDB schema changes (new partition key value). |
| Rename category | `PATCH /admin/gallery/categories/{slug}` | Updates the `label` (display name). The `slug` (partition key) is immutable. |
| Merge categories | `POST /admin/gallery/categories/{slug}/merge-into/{target_slug}` | Batch-updates all videos in the source category to the target category. Deletes source slug from config. This is a heavy operation (scan + batch update) and should be queued. |
| Hide category | `PATCH /admin/gallery/categories/{slug}` with `visible: false` | Category is excluded from the filter UI and gallery browse. Existing videos remain but are not discoverable via category filter. |

**v1 implementation**: Categories are hardcoded in `GALLERY_CATEGORIES`. No admin endpoint. Adding a new category requires a code change and deployment. This is acceptable for launch — the initial list covers the most common content types.

### 13.4 Multi-Category Support (Future)

v1 supports a single category per video. Future enhancement: allow up to 3 categories per video. This requires:

- Changing `category` from a string to a list of strings on the model.
- Writing multiple GSI entries (one per category) per video, or using a separate category-mapping table.
- The `ByCategory` GSI would then have duplicate entries for the same video (one per category).

---

## 14. Recommendation Engine

### 14.1 v1 Recommendations (No ML)

The recommendation engine in v1 uses three simple strategies based on DDB queries. No machine learning model is required.

**Strategy 1: "More from this creator"**

```python
def get_more_from_creator(*, video_id: str, creator_id: str, limit: int = 6) -> list:
    """Return other gallery-published videos by the same creator.

    Query: ByOwnerCreatedAt GSI with owner_user_id = creator_id,
    filter gallery_published = true, exclude current video_id.
    Sort by published_at descending.
    """
    resp = T.video_metadata.query(
        IndexName="ByOwnerCreatedAt",
        KeyConditionExpression=Key("owner_user_id").eq(creator_id),
        FilterExpression="gallery_published = :gp AND video_id <> :vid",
        ExpressionAttributeValues={":gp": True, ":vid": video_id},
        ScanIndexForward=False,
        Limit=limit + 1,  # Over-fetch in case current video is in results
    )
    items = [video_from_item(i) for i in resp.get("Items", [])]
    return [v for v in items if v.video_id != video_id][:limit]
```

**Strategy 2: "Popular in same category"**

```python
def get_popular_in_category(*, category: str, exclude_video_id: str, limit: int = 6) -> list:
    """Return top videos in the same category by view_count.

    Query: ByCategory GSI with category = slug.
    Sort by view_count in memory (GSI sorts by published_at).
    """
    resp = T.video_metadata.query(
        IndexName="ByCategory",
        KeyConditionExpression=Key("category").eq(category),
        FilterExpression="gallery_published = :gp AND video_id <> :vid",
        ExpressionAttributeValues={":gp": True, ":vid": exclude_video_id},
        Limit=100,  # Fetch a batch, sort in memory
    )
    items = [video_from_item(i) for i in resp.get("Items", [])]
    items.sort(key=lambda v: getattr(v, "view_count", 0), reverse=True)
    return items[:limit]
```

**Strategy 3: "Recently watched creators"**

```python
def get_from_recently_watched_creators(*, user_id: str, exclude_video_id: str, limit: int = 6) -> list:
    """Return videos from creators the user has recently watched.

    Steps:
    1. Query video_views for user's recent views (last 7 days).
    2. Extract unique creator IDs from those videos.
    3. For each creator, get their latest gallery video.
    4. Return up to `limit` videos.
    """
    cutoff = now_ts() - 7 * 86400
    # Query user's recent views
    resp = T.video_views.query(
        IndexName="ByUser" if hasattr(T.video_views, "ByUser") else None,
        # Fallback: scan with filter (acceptable for per-user queries)
        KeyConditionExpression=Key("pk").begins_with("VIDEO#"),
        FilterExpression="user_id = :uid AND created_at >= :since",
        ExpressionAttributeValues={":uid": user_id, ":since": cutoff},
        Limit=50,
    )
    # ... extract creator_ids, fetch latest videos ...
```

### 14.2 Recommendation Composition

The video detail page's "Related Videos" sidebar combines all three strategies:

```python
def get_related_videos(*, video_id: str, user_id: str, limit: int = 12) -> list:
    """Compose related video recommendations from multiple strategies.

    Allocation:
    - 4 videos from "More from this creator"
    - 4 videos from "Popular in same category"
    - 4 videos from "Recently watched creators"

    Deduplication: If a video appears in multiple strategies, it is shown only once.
    Fallback: If a strategy returns fewer than its allocation, the others fill the gap.
    """
    video = get_video(video_id)

    from_creator = get_more_from_creator(
        video_id=video_id, creator_id=video.owner_user_id, limit=4
    )
    from_category = get_popular_in_category(
        category=video.category or "other", exclude_video_id=video_id, limit=4
    )
    from_recent = get_from_recently_watched_creators(
        user_id=user_id, exclude_video_id=video_id, limit=4
    )

    # Deduplicate
    seen = {video_id}
    combined = []
    for source in [from_creator, from_category, from_recent]:
        for v in source:
            if v.video_id not in seen:
                seen.add(v.video_id)
                combined.append(v)

    return combined[:limit]
```

### 14.3 Future: Collaborative Filtering Placeholder

v1 does not include collaborative filtering ("users who watched X also watched Y"). The data model supports it:

- `video_views` table tracks user-video pairs.
- A batch job could compute co-occurrence matrices: for each video pair (A, B), count users who viewed both.
- Results would be stored in a `video_recommendations` table with `PK=VIDEO#{video_id}`, `SK=REC#{rank}`, `recommended_video_id`.
- The `get_related_videos()` function would add a fourth strategy reading from this table.

This is explicitly deferred to v2. The v1 strategies (creator, category, recently-watched) cover the most common recommendation patterns without ML infrastructure.

---

## 15. Frontend Page Specifications

### 15.1 GalleryPage

```typescript
interface GalleryPageState {
  category: string | null;           // Selected category slug, null = all
  sort: "newest" | "popular" | "trending";
  durationRange: [number, number];   // [min_seconds, max_seconds]
  searchQuery: string;               // Debounced search input
  viewMode: "grid" | "list";         // Grid (default) or list view
}

// React Query hook
const {
  data,
  fetchNextPage,
  hasNextPage,
  isFetchingNextPage,
} = useInfiniteQuery({
  queryKey: ["gallery", category, sort, durationRange, searchQuery],
  queryFn: ({ pageParam }) => listGalleryVideos({
    category,
    sort,
    duration_min: durationRange[0] || undefined,
    duration_max: durationRange[1] || undefined,
    search: searchQuery || undefined,
    cursor: pageParam,
  }),
  getNextPageParam: (lastPage) => lastPage.cursor,
  staleTime: 30_000,
});
```

**Layout specification:**

```
┌──────────────────────────────────────────────────────────────────┐
│ GalleryPage                                                      │
│                                                                  │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ SearchInput (w-full, debounce 300ms)                        │ │
│ │ Placeholder: "Search videos by title, description, or tag"  │ │
│ └──────────────────────────────────────────────────────────────┘ │
│                                                                  │
│ ┌──────────────────────────────────────────┐ ┌────────────────┐ │
│ │ CategoryFilter (horizontal pill bar)     │ │ SortSelector   │ │
│ │ [All] [Tutorials] [Entertainment] ...    │ │ [Newest ▼]     │ │
│ │ (scrollable on mobile)                   │ │                │ │
│ └──────────────────────────────────────────┘ └────────────────┘ │
│                                                                  │
│ ┌──────────────────────────────────────┐ ┌──────────────────┐   │
│ │ DurationFilter (range slider)        │ │ ViewMode toggle  │   │
│ │ 0m ────●────────●──── 60m+          │ │ [Grid] [List]    │   │
│ └──────────────────────────────────────┘ └──────────────────┘   │
│                                                                  │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ VideoGrid (CSS Grid: 1 col mobile, 2 col tablet, 4 col lg) │ │
│ │                                                              │ │
│ │ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │ │
│ │ │VideoCard│ │VideoCard│ │VideoCard│ │VideoCard│           │ │
│ │ └─────────┘ └─────────┘ └─────────┘ └─────────┘           │ │
│ │ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │ │
│ │ │VideoCard│ │VideoCard│ │VideoCard│ │VideoCard│           │ │
│ │ └─────────┘ └─────────┘ └─────────┘ └─────────┘           │ │
│ │                                                              │ │
│ │ [Load More] or InfiniteScroll trigger                        │ │
│ └──────────────────────────────────────────────────────────────┘ │
│                                                                  │
│ (Empty state: "No videos found. Try adjusting your filters.")   │
└──────────────────────────────────────────────────────────────────┘
```

### 15.2 VideoCard (GalleryVideoCard)

```typescript
interface GalleryVideoCardProps {
  video: GalleryVideoItem;
  viewMode: "grid" | "list";
}
```

**Grid mode layout:**

```
┌──────────────────────────────┐
│  ┌────────────────────────┐  │
│  │                        │  │
│  │     THUMBNAIL          │  │
│  │     (16:9 aspect)      │  │
│  │                        │  │
│  │              ┌───────┐ │  │
│  │              │ 1:23  │ │  │  ← Duration badge (bottom-right)
│  │              └───────┘ │  │
│  └────────────────────────┘  │
│                              │
│  Video Title Goes Here and   │  ← 2-line clamp, font-semibold
│  Can Wrap to Two Lines       │
│                              │
│  ┌──┐ Creator Name           │  ← Avatar (24px) + display name
│  └──┘ 2.3K views · 3d ago   │  ← Muted text, compact format
│                              │
│  ┌──────┐                    │  ← Price badge (only if PPV)
│  │$4.99 │                    │
│  └──────┘                    │
└──────────────────────────────┘
```

**List mode layout:**

```
┌─────────────────────────────────────────────────────────────────────┐
│ ┌──────────┐                                                        │
│ │THUMBNAIL │  Video Title Goes Here                                 │
│ │  (16:9)  │  Creator Name · 2.3K views · 3d ago                   │
│ │   1:23   │  Description text truncated to one line...             │
│ └──────────┘  👍 156  💬 23  [Tutorials]  [$4.99]                   │
└─────────────────────────────────────────────────────────────────────┘
```

**TypeScript component:**

```typescript
function GalleryVideoCard({ video, viewMode }: GalleryVideoCardProps) {
  const durationText = useMemo(() => {
    if (!video.duration_seconds) return null;
    const m = Math.floor(video.duration_seconds / 60);
    const s = Math.floor(video.duration_seconds % 60);
    return m > 59
      ? `${Math.floor(m / 60)}:${String(m % 60).padStart(2, "0")}:${String(s).padStart(2, "0")}`
      : `${m}:${String(s).padStart(2, "0")}`;
  }, [video.duration_seconds]);

  const viewCountText = useMemo(() => {
    if (video.view_count >= 1_000_000) return `${(video.view_count / 1_000_000).toFixed(1)}M views`;
    if (video.view_count >= 1_000) return `${(video.view_count / 1_000).toFixed(1)}K views`;
    return `${video.view_count} views`;
  }, [video.view_count]);

  const timeAgo = useMemo(() => {
    if (!video.published_at) return "";
    const diff = Date.now() / 1000 - video.published_at;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return new Date(video.published_at * 1000).toLocaleDateString();
  }, [video.published_at]);

  // ... render based on viewMode ...
}
```

### 15.3 VideoDetailPage (Engagement Bar + Related Videos)

```typescript
interface VideoEngagementBarProps {
  videoId: string;
  viewCount: number;
  likeCount: number;
  commentCount: number;
  isLiked: boolean;
}

// Engagement bar layout:
// ┌──────────────────────────────────────────────────────────────┐
// │  👁 2.3K views   │   👍 156 Like   │   💬 23 Comments   │   ↗ Share  │
// └──────────────────────────────────────────────────────────────┘
//
// Like button: toggles on click, optimistic update via useMutation
// Comment count: scrolls to comments section on click
// Share button: opens ShareMenu dropdown (Copy Link, Share to Messenger, Share to Feed)

interface RelatedVideosSidebarProps {
  videoId: string;
  // Uses useQuery(["related", videoId], () => getRelatedVideos(videoId))
}

// Related videos sidebar layout:
// ┌─────────────────────────┐
// │ Related Videos           │
// │                         │
// │ ┌─────┐ Title           │
// │ │THUMB│ Creator · 1.2K  │
// │ └─────┘ 2:34            │
// │                         │
// │ ┌─────┐ Title           │
// │ │THUMB│ Creator · 890   │
// │ └─────┘ 5:12            │
// │                         │
// │ ... (up to 12 items)    │
// └─────────────────────────┘
```

**React Query integration for engagement:**

```typescript
// View tracking (automatic on video play)
const viewMutation = useMutation({
  mutationFn: (watchDuration: number) =>
    recordView(videoId, watchDuration),
  onSuccess: (data) => {
    queryClient.setQueryData(["video", videoId], (old: any) => ({
      ...old,
      view_count: data.view_count,
    }));
  },
});

// Like toggle
const likeMutation = useMutation({
  mutationFn: () => toggleLike(videoId),
  onMutate: async () => {
    // Optimistic update
    await queryClient.cancelQueries({ queryKey: ["video", videoId] });
    const previous = queryClient.getQueryData(["video", videoId]);
    queryClient.setQueryData(["video", videoId], (old: any) => ({
      ...old,
      liked: !old.liked,
      like_count: old.liked ? old.like_count - 1 : old.like_count + 1,
    }));
    return { previous };
  },
  onError: (_, __, context) => {
    queryClient.setQueryData(["video", videoId], context?.previous);
  },
  onSettled: () => {
    queryClient.invalidateQueries({ queryKey: ["video", videoId] });
  },
});
```

---

## 16. Acceptance Criteria (Expanded)

1. A creator can publish an approved/published video to the gallery via `POST /ui/videos/{id}/publish-to-gallery` with a category and tags.
2. Published gallery videos appear in `GET /ui/videos/gallery` for all authenticated users.
3. Gallery supports filtering by category and sorting by newest, popular, and trending.
4. Views are recorded via `POST /ui/videos/{id}/view` and deduplicated per user per day.
5. Likes are toggled via `POST /ui/videos/{id}/like`, incrementing/decrementing `like_count`.
6. Comments on videos use the existing newsfeed comment system via a shadow post record bridge (see section 3.5).
7. Videos from any source (upload, file bridge, broadcast recording, clip, concat) can be published to gallery.
8. Non-owners cannot publish another creator's video (403).
9. Only approved/published videos can be published to gallery (400 for other statuses).
10. Maximum 10 tags per video, each 1-50 characters.
11. Categories are validated against the predefined list.
12. The frontend gallery page displays video cards with thumbnail, title, creator, view/like counts, and price badge.
13. The video detail page shows an engagement bar with view count, like button, and comment section.
14. All 14 E2E tests pass.
15. **Search by title prefix returns matching videos within 200ms for catalogs up to 10K videos.**
16. **Search by tag returns only videos with that exact tag (case-insensitive).**
17. **Trending sort returns videos ordered by `trending_score` (views_24h * 1.0 + likes_24h * 5.0 + comments_24h * 3.0 + shares_24h * 4.0), with time decay applied.**
18. **The trending background job recalculates scores for all gallery-published videos every 15 minutes without exceeding 30 seconds of wall-clock time for up to 5,000 videos.**
19. **A second view from the same user on the same calendar day (UTC) does NOT increment `view_count`.**
20. **Views require a minimum watch duration of min(30 seconds, 10% of video duration) before counting.**
21. **The gallery page supports grid and list view modes with a toggle button.**
22. **The gallery page supports infinite scroll (useInfiniteQuery) with cursor-based pagination.**
23. **The Related Videos sidebar on the detail page shows up to 12 videos from three strategies: same creator, same category, and recently watched creators.**
24. **The Like button on the detail page uses optimistic update (instant UI feedback) with rollback on error.**
25. **Category filter pills are horizontally scrollable on mobile viewports.**
26. **The duration filter slider accepts ranges from 0 to 60+ minutes and correctly filters videos by `duration_seconds`.**
27. **Admin can add, rename, and merge categories without DDB schema changes (v2 feature flag gated).**
28. **Gallery search supports `tag:cooking` and `creator:alice` filter syntax in the search input.**

---

## 17. Related Tickets

- **MON-001**: VOD pay-per-view (price badge on gallery cards)
- **MON-005**: Subscription-gated VOD (access_mode badge on gallery cards)
- **MON-003**: Creator earnings dashboard (will aggregate gallery analytics alongside revenue)
- **VOD-014**: File manager bridge (source for gallery publishing)
- **BCAST-006**: Broadcast recordings (source for gallery publishing)
- **VOD-015**: Clips (auto-appear in gallery when published)
- **VOD-016**: Concatenations (auto-appear in gallery when published)
- **SOC-001**: Follow system (gallery may surface followed creators' content in future)
