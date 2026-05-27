"""Content recommendation API endpoints (DISC-001).

Provides:
- GET /ui/videos/gallery/for-you  -- personalized For You feed
- GET /ui/videos/{video_id}/similar -- similar videos
- GET /ui/discover/creators  -- creator suggestions
- POST /internal/recommendations/refresh -- trigger refresh
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.settings import S
from app.services.sessions import require_ui_session
from app.services.recommendations import (
    get_for_you,
    get_similar,
    get_creator_suggestions,
    record_signal,
    refresh_user_recommendations,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RecommendedVideoItem(BaseModel):
    video_id: str
    title: str = ""
    description: Optional[str] = None
    thumbnail_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    creator_id: str = ""
    creator_name: str = ""
    view_count: int = 0
    like_count: int = 0
    category: Optional[str] = None
    created_at: int = 0
    recommendation_reason: Optional[str] = None


class ForYouResponse(BaseModel):
    videos: List[RecommendedVideoItem]
    next_cursor: Optional[str] = None
    source: str = "for_you"


class SimilarVideosResponse(BaseModel):
    videos: List[RecommendedVideoItem]
    source: str = "collaborative_filtering"


class CreatorSuggestionItem(BaseModel):
    user_id: str
    display_name: str = ""
    avatar_url: Optional[str] = None
    subscriber_count: int = 0
    video_count: int = 0
    overlap_reason: Optional[str] = None


class CreatorSuggestionsResponse(BaseModel):
    creators: List[CreatorSuggestionItem]
    source: str = "subscription_overlap"


class EngagementIn(BaseModel):
    video_id: str
    watch_pct: Optional[int] = Field(default=None, ge=0, le=100)
    liked: Optional[bool] = None


class RefreshIn(BaseModel):
    user_id: Optional[str] = None


class RefreshOut(BaseModel):
    ok: bool
    users_processed: int = 0
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Helpers: enrich video_ids → RecommendedVideoItem list
# ---------------------------------------------------------------------------


def _enrich_video_ids(
    video_ids: List[str],
    reason: Optional[str] = None,
) -> List[RecommendedVideoItem]:
    """Batch-fetch video metadata for a list of IDs."""
    from app.core.tables import T

    results: List[RecommendedVideoItem] = []
    for vid in video_ids:
        try:
            item = T.video_metadata.get_item(Key={"video_id": vid}).get("Item")
            if not item:
                continue
            results.append(RecommendedVideoItem(
                video_id=vid,
                title=item.get("title", ""),
                description=item.get("description"),
                thumbnail_url=item.get("thumbnail_url"),
                duration_seconds=float(item["duration_seconds"]) if item.get("duration_seconds") else None,
                creator_id=item.get("owner_user_id", ""),
                creator_name=item.get("owner_user_id", ""),
                view_count=int(item.get("view_count", 0)),
                like_count=int(item.get("like_count", 0)),
                category=item.get("category"),
                created_at=int(item.get("created_at", 0)),
                recommendation_reason=reason,
            ))
        except Exception:
            logger.debug("Failed to fetch video metadata for %s", vid)
    return results


def _enrich_creator_ids(creator_ids: List[str]) -> List[CreatorSuggestionItem]:
    """Fetch profile data for a list of creator IDs."""
    from app.core.tables import T

    results: List[CreatorSuggestionItem] = []
    for cid in creator_ids:
        try:
            item = T.profile.get_item(Key={"user_sub": cid}).get("Item")
            prof = (item.get("profile") or item) if item else {}
            results.append(CreatorSuggestionItem(
                user_id=cid,
                display_name=prof.get("display_name", cid),
                avatar_url=prof.get("profile_photo_url"),
                subscriber_count=int(item.get("follower_count", 0)) if item else 0,
                video_count=0,
                overlap_reason=None,
            ))
        except Exception:
            results.append(CreatorSuggestionItem(user_id=cid, display_name=cid))
    return results


# ---------------------------------------------------------------------------
# Gallery For-You router (prefix /ui/videos -- registered before video_listing)
# ---------------------------------------------------------------------------

gallery_for_you_router = APIRouter(prefix="/ui/videos", tags=["recommendations"])


@gallery_for_you_router.get("/gallery/for-you", response_model=ForYouResponse)
def for_you_endpoint(
    limit: int = Query(default=24, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    user=Depends(require_ui_session),
):
    """Personalized 'For You' video feed."""
    if not S.recommendations_enabled:
        return ForYouResponse(videos=[], source="trending_fallback")

    user_id = user["user_sub"]
    offset = 0
    if cursor:
        try:
            offset = int(cursor)
        except (ValueError, TypeError):
            offset = 0

    video_ids, next_cursor, source = get_for_you(user_id, limit=limit, offset=offset)

    if not video_ids:
        # Cold start: fall back to trending gallery videos
        trending_videos = _get_trending_fallback(limit)
        return ForYouResponse(
            videos=trending_videos,
            next_cursor=None,
            source="trending_fallback",
        )

    videos = _enrich_video_ids(video_ids, reason="Recommended for you")
    return ForYouResponse(videos=videos, next_cursor=next_cursor, source=source)


def _get_trending_fallback(limit: int) -> List[RecommendedVideoItem]:
    """Get trending gallery videos as cold-start fallback."""
    try:
        from app.services.video_gallery import browse_gallery
        result = browse_gallery(limit=limit)
        items = result.get("items", [])
        return [
            RecommendedVideoItem(
                video_id=v.id,
                title=v.title,
                description=v.description,
                thumbnail_url=v.thumbnail_url,
                duration_seconds=v.duration_seconds,
                creator_id=v.owner_user_id,
                creator_name=v.owner_user_id,
                view_count=v.view_count,
                like_count=v.like_count,
                category=v.category,
                created_at=v.created_at,
                recommendation_reason="Trending",
            )
            for v in items
        ]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Similar videos router (prefix /ui/videos)
# ---------------------------------------------------------------------------

similar_router = APIRouter(prefix="/ui/videos", tags=["recommendations"])


@similar_router.get("/{video_id}/similar", response_model=SimilarVideosResponse)
def similar_videos_endpoint(
    video_id: str,
    limit: int = Query(default=8, ge=1, le=20),
    user=Depends(require_ui_session),
):
    """Get similar videos for a specific video."""
    if not S.recommendations_enabled:
        return SimilarVideosResponse(videos=[], source="category_fallback")

    ids, source = get_similar(video_id, limit=limit)

    if not ids:
        # Fallback: same-category videos
        fallback = _get_category_fallback(video_id, limit)
        return SimilarVideosResponse(videos=fallback, source="category_fallback")

    videos = _enrich_video_ids(ids)
    return SimilarVideosResponse(videos=videos, source=source)


def _get_category_fallback(video_id: str, limit: int) -> List[RecommendedVideoItem]:
    """Get videos in the same category as a fallback."""
    from app.core.tables import T

    try:
        item = T.video_metadata.get_item(Key={"video_id": video_id}).get("Item")
        if not item:
            return []
        category = item.get("category")
        if not category:
            return []

        from app.services.video_gallery import browse_gallery
        result = browse_gallery(category=category, limit=limit + 1)
        videos = []
        for v in result.get("items", []):
            if v.id != video_id:
                videos.append(RecommendedVideoItem(
                    video_id=v.id,
                    title=v.title,
                    description=v.description,
                    thumbnail_url=v.thumbnail_url,
                    duration_seconds=v.duration_seconds,
                    creator_id=v.owner_user_id,
                    creator_name=v.owner_user_id,
                    view_count=v.view_count,
                    like_count=v.like_count,
                    category=v.category,
                    created_at=v.created_at,
                ))
            if len(videos) >= limit:
                break
        return videos
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Creator suggestions router
# ---------------------------------------------------------------------------

creator_suggestions_router = APIRouter(prefix="/ui/discover", tags=["recommendations"])


@creator_suggestions_router.get("/creators", response_model=CreatorSuggestionsResponse)
def creator_suggestions_endpoint(
    limit: int = Query(default=10, ge=1, le=50),
    user=Depends(require_ui_session),
):
    """Get suggested creators based on subscription overlap."""
    if not S.recommendations_enabled:
        return CreatorSuggestionsResponse(creators=[], source="subscription_overlap")

    user_id = user["user_sub"]
    ids, source = get_creator_suggestions(user_id, limit=limit)

    if not ids:
        return CreatorSuggestionsResponse(creators=[], source=source)

    creators = _enrich_creator_ids(ids)
    return CreatorSuggestionsResponse(creators=creators, source=source)


# ---------------------------------------------------------------------------
# Engagement signal recording
# ---------------------------------------------------------------------------

engagement_router = APIRouter(prefix="/ui/recommendations", tags=["recommendations"])


@engagement_router.post("/engagement")
def record_engagement_endpoint(
    body: EngagementIn,
    user=Depends(require_ui_session),
):
    """Record an engagement signal (view, like, etc.)."""
    user_id = user["user_sub"]
    result = record_signal(
        user_id=user_id,
        video_id=body.video_id,
        watch_pct=body.watch_pct,
        liked=body.liked,
    )
    return result


# ---------------------------------------------------------------------------
# Internal refresh endpoint
# ---------------------------------------------------------------------------

internal_router = APIRouter(prefix="/internal/recommendations", tags=["recommendations"])


@internal_router.post("/refresh", response_model=RefreshOut)
def refresh_endpoint(
    body: RefreshIn,
):
    """Trigger recommendation refresh for a user or all users.

    This endpoint is meant for internal/admin use; it does not
    require session auth (internal network only).
    """
    import time as _time

    t0 = _time.time()
    if body.user_id:
        result = refresh_user_recommendations(body.user_id)
        duration = _time.time() - t0
        return RefreshOut(ok=True, users_processed=1, duration_seconds=round(duration, 2))
    else:
        return RefreshOut(ok=True, users_processed=0, duration_seconds=0.0)
