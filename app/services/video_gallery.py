"""Video gallery hub service (VOD-017).

Handles gallery browsing, view tracking, like tracking,
trending computation, and multi-source publishing.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.video_metadata_store import get_video, video_from_item

logger = logging.getLogger(__name__)


# ─── Categories ─────────────────────────────────────────────────────────────

GALLERY_CATEGORIES: List[Dict[str, str]] = [
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


# ─── Publish / Unpublish ────────────────────────────────────────────────────


def publish_to_gallery(
    *,
    video_id: str,
    user_id: str,
    category: str,
    tags: List[str] | None = None,
    title: str | None = None,
    description: str | None = None,
) -> Dict[str, Any]:
    """Publish a video to the gallery.

    Validates ownership and status, then updates metadata fields.
    """
    tags = tags or []
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
        "gallery_status = :gs",
        "category = :cat",
        "tags = :tags",
        "visibility = :vis",
        "updated_at = :ua",
    ]
    values: Dict[str, Any] = {
        ":gp": True,
        ":gs": "published",
        ":cat": category,
        ":tags": tags,
        ":vis": "public",
        ":ua": ts,
    }
    names: Dict[str, str] = {}

    if video.status == "approved":
        update_parts.append("#st = :pub")
        values[":pub"] = "published"
        names["#st"] = "status"

    if not video.published_at:
        update_parts.append("published_at = :pa")
        values[":pa"] = ts

    if title:
        update_parts.append("title = :t")
        values[":t"] = title

    if description is not None:
        update_parts.append("description = :d")
        values[":d"] = description

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


def unpublish_from_gallery(*, video_id: str, user_id: str) -> Dict[str, Any]:
    """Remove a video from the gallery."""
    video = get_video(video_id)

    if video.owner_user_id != user_id:
        raise HTTPException(403, "Not your video")

    ts = now_ts()
    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET gallery_published = :gp, updated_at = :ua REMOVE gallery_status, category",
        ExpressionAttributeValues={":gp": False, ":ua": ts},
    )
    return {"video_id": video_id, "gallery_published": False}


# ─── View Tracking ──────────────────────────────────────────────────────────


def record_view(*, video_id: str, user_id: str) -> Dict[str, Any]:
    """Record a video view, deduplicated per user per day."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    ts = now_ts()
    viewed_at = ts

    is_new = False
    try:
        T.video_views.put_item(
            Item={
                "pk": f"VIDEO#{video_id}",
                "sk": f"VIEW#{user_id}#{date_str}",
                "video_id": video_id,
                "user_id": user_id,
                "view_date": date_str,
                "viewed_at": viewed_at,
                "created_at": ts,
                "ttl": ts + 90 * 86400,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        is_new = True
    except T.video_views.meta.client.exceptions.ConditionalCheckFailedException:
        pass
    except Exception:
        logger.warning("view_record_failed", extra={"video_id": video_id, "user_id": user_id})

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
        try:
            item = T.video_metadata.get_item(
                Key={"video_id": video_id},
                ProjectionExpression="view_count",
            ).get("Item", {})
            view_count = int(item.get("view_count", 0))
        except Exception:
            pass

    return {"view_count": view_count, "is_new_view": is_new}


# ─── Like Tracking ──────────────────────────────────────────────────────────


def toggle_like(*, video_id: str, user_id: str) -> Dict[str, Any]:
    """Toggle like on a video. Returns new like state and count."""
    pk = f"VIDEO#{video_id}"
    sk = f"LIKE#{user_id}"
    ts = now_ts()

    existing = T.video_likes.get_item(Key={"pk": pk, "sk": sk}).get("Item")

    if existing:
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
        T.video_likes.put_item(
            Item={
                "pk": pk,
                "sk": sk,
                "video_id": video_id,
                "user_id": user_id,
                "liked_at": ts,
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


# ─── Gallery Browsing ───────────────────────────────────────────────────────


def browse_gallery(
    *,
    category: str | None = None,
    cursor: Dict[str, Any] | None = None,
    limit: int = 24,
) -> Dict[str, Any]:
    """Browse gallery videos, optionally filtered by category."""
    if category and category not in VALID_CATEGORY_SLUGS:
        raise HTTPException(400, f"Invalid category: {category}")

    limit = min(limit, 100)

    if category:
        resp = T.video_metadata.query(
            IndexName="ByCategory",
            KeyConditionExpression=Key("category").eq(category),
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
        resp = T.video_metadata.query(
            IndexName="ByGalleryPublished",
            KeyConditionExpression=Key("gallery_status").eq("published"),
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
    new_cursor = resp.get("LastEvaluatedKey")
    return {"items": items[:limit], "cursor": new_cursor}


def search_gallery(
    *,
    query: str,
    cursor: Dict[str, Any] | None = None,
    limit: int = 24,
) -> Dict[str, Any]:
    """Simple in-memory search over gallery-published videos.

    MVP approach: query ByGalleryPublished GSI, filter in memory by title match.
    """
    limit = min(limit, 100)
    q = query.lower().strip()
    if not q:
        return {"items": [], "cursor": None}

    collected = []
    last_key = cursor
    max_pages = 5

    for _ in range(max_pages):
        kwargs: Dict[str, Any] = {
            "IndexName": "ByGalleryPublished",
            "KeyConditionExpression": Key("gallery_status").eq("published"),
            "FilterExpression": "#st = :pub AND visibility = :vis",
            "ExpressionAttributeValues": {
                ":pub": "published",
                ":vis": "public",
            },
            "ExpressionAttributeNames": {"#st": "status"},
            "ScanIndexForward": False,
            "Limit": limit * 3,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        resp = T.video_metadata.query(**kwargs)
        for item_raw in resp.get("Items", []):
            v = video_from_item(item_raw)
            title_lower = (v.title or "").lower()
            desc_lower = (v.description or "").lower()
            tags_lower = " ".join(v.tags).lower() if v.tags else ""
            if q in title_lower or q in desc_lower or q in tags_lower:
                collected.append(v)
                if len(collected) >= limit:
                    break

        last_key = resp.get("LastEvaluatedKey")
        if len(collected) >= limit or not last_key:
            break

    return {"items": collected[:limit], "cursor": last_key}


# ─── Trending ───────────────────────────────────────────────────────────────


def compute_trending_score(
    views_24h: int,
    likes_24h: int,
    comments_24h: int,
    hours_since_published: float,
) -> float:
    """Compute trending score with time decay."""
    raw_score = views_24h * 1.0 + likes_24h * 5.0 + comments_24h * 3.0
    decay_hours = S.video_gallery_trending_decay_hours or 72
    decay = math.pow(0.5, hours_since_published / decay_hours)
    return raw_score * decay


def update_trending_score(video_id: str) -> int:
    """Recompute and store trending score for a single video.

    Returns the new score as int.
    """
    ts = now_ts()
    cutoff_24h = ts - 86400

    video = get_video(video_id)

    views_24h = _count_views_since(video_id, cutoff_24h)
    likes_24h = _count_likes_since(video_id, cutoff_24h)

    hours_since = max(0, (ts - (video.published_at or ts)) / 3600)
    score = compute_trending_score(views_24h, likes_24h, 0, hours_since)
    score_int = int(score)

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET trending_score = :ts, trending_score_sort = :tss",
        ExpressionAttributeValues={
            ":ts": Decimal(str(score)),
            ":tss": score_int,
        },
    )
    return score_int


def _count_views_since(video_id: str, since_ts: int) -> int:
    """Count unique views for a video since the given timestamp."""
    try:
        resp = T.video_views.query(
            IndexName="ByVideoViewedAt",
            KeyConditionExpression=Key("video_id").eq(video_id) & Key("viewed_at").gte(since_ts),
            Select="COUNT",
        )
        return resp.get("Count", 0)
    except Exception:
        return 0


def _count_likes_since(video_id: str, since_ts: int) -> int:
    """Count likes for a video since the given timestamp."""
    try:
        resp = T.video_likes.query(
            IndexName="ByVideoLikedAt",
            KeyConditionExpression=Key("video_id").eq(video_id) & Key("liked_at").gte(since_ts),
            Select="COUNT",
        )
        return resp.get("Count", 0)
    except Exception:
        return 0
