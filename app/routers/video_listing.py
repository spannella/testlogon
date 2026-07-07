"""Video listing and management endpoints (VOD-006).

Provides browse, filter, detail, update, and soft-delete for videos.
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from decimal import Decimal

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.auth.roles import Role
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.sessions import require_ui_session
from app.services.rate_limit import _bucket_limit
from app.services.video_metadata_store import (
    get_video,
    list_videos_by_creator_public,
    list_videos_by_owner,
    list_videos_by_status,
    list_videos_public,
    update_video,
    delete_video,
    video_from_item,
    video_to_item,
    VideoMetadataModel,
)
from app.models_video import UpdateVideoIn, VideoVisibility

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/videos", tags=["video-listing"])


# ─── Response Models ─────────────────────────────────────────────────────────


class VideoListItem(BaseModel):
    video_id: str
    title: str
    status: str
    visibility: str
    created_at: int
    updated_at: int
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    thumbnail_url: Optional[str] = None
    file_size_bytes: Optional[int] = None
    review_status: Optional[str] = None
    owner_user_id: Optional[str] = None


class VideoListOut(BaseModel):
    items: List[VideoListItem]
    cursor: Optional[str] = None


class VideoDetailOut(BaseModel):
    video_id: str
    owner_user_id: str
    title: str
    description: Optional[str] = None
    status: str
    visibility: str
    created_at: int
    updated_at: int
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    frame_rate: Optional[float] = None
    video_codec: Optional[str] = None
    audio_codec: Optional[str] = None
    file_size_bytes: Optional[int] = None
    container_format: Optional[str] = None
    renditions: list = Field(default_factory=list)
    thumbnail_url: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    playback_token: Optional[str] = None
    playback_expires_at: Optional[int] = None
    encoding_job_id: Optional[str] = None
    encoding_error_message: Optional[str] = None
    review_status: Optional[str] = None
    published_at: Optional[int] = None
    drm_enabled: bool = False
    drm_key_uri: Optional[str] = None
    # Download (VOD-012)
    allow_download: bool = False
    download_available: bool = False
    download_mp4_size_bytes: Optional[int] = None
    # Watermarked Downloads (VOD-020)
    watermark_downloads: bool = False
    # Pay-per-view (MON-001)
    price_cents: Optional[int] = None
    access_mode: Optional[str] = None
    purchase_count: int = 0
    is_entitled: bool = False
    # Subscription-gated VOD (MON-005)
    access_reason: str = "none"
    subscription_available: bool = False
    purchase_available: bool = False
    subscription_upsell: bool = False
    # Purchase Tiers (VOD-019)
    available_purchase_types: List[str] = Field(default_factory=list)
    view_once_price_cents: Optional[int] = None
    rental_price_cents: Optional[int] = None
    rental_duration_hours: Optional[int] = None
    download_price_cents: Optional[int] = None
    purchase_type: str = "permanent"
    views_remaining: int = -1
    rental_expires_at: Optional[int] = None
    rental_remaining_seconds: Optional[int] = None
    download_allowed: bool = False
    # Ad-supported (VOD-018)
    ads_enabled: bool = False
    ads_free_for_subscribers: bool = False
    ad_config: Optional[dict] = None
    # Clipping provenance (VOD-015)
    source_video_id: Optional[str] = None
    clip_start_seconds: Optional[float] = None
    clip_end_seconds: Optional[float] = None
    created_via: Optional[str] = None
    # Concatenation provenance (VOD-016)
    source_video_ids: Optional[List[str]] = None
    # Subtitles / Closed Captions (VOD-021)
    subtitle_tracks: list = Field(default_factory=list)


class VideoUpdateIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    visibility: Optional[VideoVisibility] = None
    allow_download: Optional[bool] = None
    scheduled_publish_at: Optional[int] = Field(default=None, description="Unix timestamp for scheduled VOD release")


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _sanitize_cursor(cursor_dict):
    """Convert DynamoDB Decimal values in a cursor dict to JSON-serializable types."""
    if cursor_dict is None:
        return None
    out = {}
    for k, v in cursor_dict.items():
        if isinstance(v, Decimal):
            out[k] = int(v) if v == int(v) else float(v)
        elif isinstance(v, dict):
            out[k] = _sanitize_cursor(v)
        else:
            out[k] = v
    return out


def _video_to_list_item(video: VideoMetadataModel) -> VideoListItem:
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
        owner_user_id=video.owner_user_id,
    )


def _video_to_detail(
    video: VideoMetadataModel,
    *,
    playback_token: str | None = None,
    playback_expires_at: int | None = None,
    is_entitled: bool = False,
    access_reason: str = "none",
    subscription_available: bool = False,
    purchase_available: bool = False,
    subscription_upsell: bool = False,
    # VOD-018 fields
    ads_enabled: bool = False,
    # VOD-019 fields
    purchase_type: str = "permanent",
    views_remaining: int = -1,
    expires_at: int = 0,
    download_allowed: bool = False,
) -> VideoDetailOut:
    # Resolve DRM key URI if DRM is enabled for this video
    drm_key_uri: str | None = None
    if video.drm_enabled:
        try:
            from app.services.vod_drm_keys import get_key_uri

            # GAP-0372: key derivation is tenant-scoped; the owner is the tenant.
            drm_key_uri = get_key_uri(video.id, video.owner_user_id)
        except Exception:
            pass

    # Download availability (VOD-012)
    download_available = (
        video.allow_download
        and video.download_mp4_key != ""
        and video.download_mp4_status == "ready"
    )

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
        renditions=[r.model_dump() for r in video.renditions] if video.renditions else [],
        thumbnail_url=video.thumbnail_url,
        hls_manifest_url=video.hls_manifest_url,
        playback_token=playback_token,
        playback_expires_at=playback_expires_at,
        encoding_job_id=video.encoding_job_id,
        encoding_error_message=video.encoding_error_message,
        review_status=video.review_status,
        published_at=video.published_at,
        drm_enabled=video.drm_enabled,
        drm_key_uri=drm_key_uri,
        allow_download=video.allow_download,
        download_available=download_available,
        download_mp4_size_bytes=video.download_mp4_size_bytes if video.download_mp4_size_bytes else None,
        watermark_downloads=video.watermark_downloads,
        price_cents=video.price_cents,
        access_mode=video.access_mode,
        purchase_count=video.purchase_count,
        is_entitled=is_entitled,
        access_reason=access_reason,
        subscription_available=subscription_available,
        purchase_available=purchase_available,
        subscription_upsell=subscription_upsell,
        # Ad-supported (VOD-018)
        ads_enabled=ads_enabled,
        ads_free_for_subscribers=video.ads_free_for_subscribers,
        ad_config=video.ad_config,
        # Clipping provenance (VOD-015)
        source_video_id=video.source_video_id,
        clip_start_seconds=video.clip_start_seconds,
        clip_end_seconds=video.clip_end_seconds,
        created_via=video.created_via,
        # Concatenation provenance (VOD-016)
        source_video_ids=video.source_video_ids,
        # Subtitles / Closed Captions (VOD-021)
        subtitle_tracks=[t.model_dump() for t in video.subtitle_tracks] if video.subtitle_tracks else [],
        # Purchase Tiers (VOD-019)
        available_purchase_types=video.available_purchase_types or [],
        view_once_price_cents=video.view_once_price_cents,
        rental_price_cents=video.rental_price_cents,
        rental_duration_hours=video.rental_duration_hours,
        download_price_cents=video.download_price_cents,
        purchase_type=purchase_type,
        views_remaining=views_remaining,
        rental_expires_at=expires_at if expires_at > 0 else None,
        rental_remaining_seconds=max(0, expires_at - now_ts()) if expires_at > 0 else None,
        download_allowed=download_allowed,
    )


def _try_issue_playback_token(video: VideoMetadataModel, user_sub: str) -> tuple[str | None, int | None]:
    """Issue playback token if video is playable (approved/published with manifest)."""
    if video.status not in ("approved", "published"):
        return None, None
    if not video.hls_manifest_url:
        return None, None
    try:
        from app.services.playback_entitlements import issue_playback_entitlement

        ttl = getattr(S, "video_playback_token_ttl_seconds", 300) or 300
        result = issue_playback_entitlement(
            tenant_id=video.owner_user_id,
            asset_id=video.id,
            session_id=f"web_{user_sub}",
            device_id="browser",
            profile="auto",
            audience="playback",
            ttl_seconds=ttl,
        )
        return result.get("token"), result.get("expires_at_epoch")
    except Exception:
        logger.debug("Failed to issue playback token for video %s", video.id, exc_info=True)
        return None, None


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.get("/public", response_model=VideoListOut)
def list_public_videos(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user=Depends(require_ui_session),
):
    """Browse publicly available (published + public) videos."""
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_public(limit=limit, cursor=decoded_cursor)
    items = [_video_to_list_item(v) for v in result["items"]]
    return VideoListOut(items=items, cursor=encode_cursor(_sanitize_cursor(result.get("cursor"))))


@router.get("/creator/{creator_id}", response_model=VideoListOut)
def list_creator_public_videos(
    creator_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user=Depends(require_ui_session),
):
    """List a specific creator's published + public videos."""
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_by_creator_public(creator_id, limit=limit, cursor=decoded_cursor)
    items = [_video_to_list_item(v) for v in result["items"]]
    return VideoListOut(items=items, cursor=encode_cursor(_sanitize_cursor(result.get("cursor"))))


@router.get("/admin/by-status/{status}", response_model=VideoListOut)
def admin_list_by_status(
    status: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Admin: list videos by status."""
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_by_status(status, limit=limit, cursor=decoded_cursor)
    items = [_video_to_list_item(v) for v in result["items"]]
    return VideoListOut(items=items, cursor=encode_cursor(_sanitize_cursor(result.get("cursor"))))


# ─── Video Gallery Hub (VOD-017) ────────────────────────────────────────────
#
# These endpoints MUST be registered before GET /{video_id} to avoid
# FastAPI treating "gallery" as a video_id path parameter.


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
    created_at: int = 0
    published_at: Optional[int] = None


class GalleryListOut(BaseModel):
    videos: List[GalleryVideoItem]
    categories: List[dict] = Field(default_factory=list)
    cursor: Optional[str] = None


class GallerySearchOut(BaseModel):
    videos: List[GalleryVideoItem]
    cursor: Optional[str] = None


class PublishToGalleryIn(BaseModel):
    category: str = Field(min_length=1, max_length=50)
    tags: List[str] = Field(default_factory=list)
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)


class PublishToGalleryOut(BaseModel):
    video_id: str
    gallery_published: bool
    category: str
    tags: List[str]
    published_at: int


class ViewRecordOut(BaseModel):
    view_count: int
    is_new_view: bool


class LikeToggleOut(BaseModel):
    liked: bool
    like_count: int


class LikeCheckOut(BaseModel):
    liked: bool


class VideoCommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


class VideoCommentOut(BaseModel):
    comment_id: str
    video_id: str
    user_id: str
    text: str
    created_at: int


class VideoCommentListOut(BaseModel):
    comments: List[VideoCommentOut]
    cursor: Optional[str] = None


class CategoriesOut(BaseModel):
    categories: List[dict]


def _video_to_gallery_item(video) -> GalleryVideoItem:
    return GalleryVideoItem(
        video_id=video.id,
        title=video.title,
        description=video.description,
        thumbnail_url=video.thumbnail_url,
        duration_seconds=video.duration_seconds,
        category=video.category,
        tags=video.tags or [],
        view_count=video.view_count,
        like_count=video.like_count,
        comment_count=video.comment_count,
        owner_user_id=video.owner_user_id,
        price_cents=video.price_cents,
        access_mode=video.access_mode,
        created_at=video.created_at,
        published_at=video.published_at,
    )


@router.get("/gallery", response_model=GalleryListOut)
def browse_gallery_endpoint(
    category: Optional[str] = Query(default=None),
    limit: int = Query(default=24, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    user=Depends(require_ui_session),
):
    """Browse the video gallery hub."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_gallery import browse_gallery, GALLERY_CATEGORIES

    decoded_cursor = decode_cursor(cursor)
    result = browse_gallery(category=category, cursor=decoded_cursor, limit=limit)
    videos = [_video_to_gallery_item(v) for v in result["items"]]
    return GalleryListOut(
        videos=videos,
        categories=GALLERY_CATEGORIES,
        cursor=encode_cursor(_sanitize_cursor(result.get("cursor"))),
    )


@router.get("/gallery/search", response_model=GallerySearchOut)
def search_gallery_endpoint(
    q: str = Query(min_length=1, max_length=200),
    limit: int = Query(default=24, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    user=Depends(require_ui_session),
):
    """Search gallery videos by title/description/tags."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_gallery import search_gallery

    decoded_cursor = decode_cursor(cursor)
    result = search_gallery(query=q, cursor=decoded_cursor, limit=limit)
    videos = [_video_to_gallery_item(v) for v in result["items"]]
    return GallerySearchOut(
        videos=videos,
        cursor=encode_cursor(_sanitize_cursor(result.get("cursor"))),
    )


@router.get("/gallery/categories", response_model=CategoriesOut)
def list_gallery_categories(
    user=Depends(require_ui_session),
):
    """List available gallery categories."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_gallery import GALLERY_CATEGORIES

    return CategoriesOut(categories=GALLERY_CATEGORIES)


@router.post("/{video_id}/gallery/publish", response_model=PublishToGalleryOut)
def publish_to_gallery_endpoint(
    video_id: str,
    body: PublishToGalleryIn,
    user=Depends(require_ui_session),
):
    """Publish a video to the gallery."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_gallery import publish_to_gallery

    user_sub = user["user_sub"]
    result = publish_to_gallery(
        video_id=video_id,
        user_id=user_sub,
        category=body.category,
        tags=body.tags,
        title=body.title,
        description=body.description,
    )
    return PublishToGalleryOut(**result)


@router.post("/{video_id}/gallery/unpublish")
def unpublish_from_gallery_endpoint(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Unpublish a video from the gallery."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_gallery import unpublish_from_gallery

    user_sub = user["user_sub"]
    result = unpublish_from_gallery(video_id=video_id, user_id=user_sub)
    return result


@router.post("/{video_id}/view", response_model=ViewRecordOut)
def record_view_endpoint(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Record a video view (deduplicated per user per day)."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_gallery import record_view

    user_sub = user["user_sub"]
    result = record_view(video_id=video_id, user_id=user_sub)
    return ViewRecordOut(**result)


@router.post("/{video_id}/like", response_model=LikeToggleOut)
def toggle_like_endpoint(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Toggle like on a video."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_gallery import toggle_like

    user_sub = user["user_sub"]
    result = toggle_like(video_id=video_id, user_id=user_sub)
    return LikeToggleOut(**result)


@router.get("/{video_id}/like", response_model=LikeCheckOut)
def check_like_endpoint(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Check if the current user has liked a video."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_gallery import check_liked

    user_sub = user["user_sub"]
    liked = check_liked(video_id=video_id, user_id=user_sub)
    return LikeCheckOut(liked=liked)


@router.post("/{video_id}/comments", status_code=201, response_model=VideoCommentOut)
def add_comment_endpoint(
    video_id: str,
    body: VideoCommentIn,
    user=Depends(require_ui_session),
):
    """Add a comment to a video."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_comments import add_comment

    user_sub = user["user_sub"]
    result = add_comment(video_id=video_id, user_id=user_sub, text=body.text)
    return VideoCommentOut(**result)


@router.get("/{video_id}/comments", response_model=VideoCommentListOut)
def list_comments_endpoint(
    video_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    user=Depends(require_ui_session),
):
    """List comments for a video, newest first."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_comments import list_comments

    result = list_comments(video_id=video_id, cursor=cursor, limit=limit)
    return VideoCommentListOut(
        comments=[VideoCommentOut(**c) for c in result["comments"]],
        cursor=result.get("cursor"),
    )


@router.delete("/{video_id}/comments/{comment_id}", status_code=204)
def delete_comment_endpoint(
    video_id: str,
    comment_id: str,
    user=Depends(require_ui_session),
):
    """Delete a comment (author only)."""
    if not S.video_gallery_enabled:
        raise HTTPException(status_code=404, detail="gallery not enabled")

    from app.services.video_comments import delete_comment

    user_sub = user["user_sub"]
    delete_comment(video_id=video_id, comment_id=comment_id, user_id=user_sub)
    return None


# ─── Video Detail ─────────────────────────────────────────────────────────


class VideoTipIn(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = "usd"
    payment_method_id: Optional[str] = None


class VideoTipOut(BaseModel):
    ok: bool
    video_id: str
    amount_cents: int
    currency: str
    tip_total_cents: int


@router.post("/{video_id}/tip", response_model=VideoTipOut)
def tip_video_endpoint(
    video_id: str,
    body: VideoTipIn,
    user=Depends(require_ui_session),
):
    """B-VIDSOCIAL2 (#2): tip a video's creator. Mirrors newsfeed POST /posts/{id}/tip
    so VOD posts reach full social parity (reactions + comments + tips)."""
    user_sub = user["user_sub"]
    video = get_video(video_id)
    if video.owner_user_id == user_sub:
        raise HTTPException(status_code=400, detail="Cannot tip your own video")
    # Non-owner may only tip a published, viewable video.
    if video.status != "published" or video.visibility not in ("public", "unlisted"):
        raise HTTPException(status_code=403, detail="video not available for tipping")

    # TIP-011: charge + credit via the centralized charge_tip seam (replaces the
    # mock PaymentProvider stub + direct write_tip_ledger). Charge BEFORE bumping
    # tip_total_cents so a failed charge does not leave an orphan total.
    from app.services.tips import charge_tip
    charge_tip(
        tipper_id=user_sub,
        recipient_id=video.owner_user_id,
        amount_cents=body.amount_cents,
        currency=body.currency,
        payment_method_id=body.payment_method_id,
        content_type="video",
        content_id=video_id,
        meta={"video_id": video_id},
        idempotency_key="videotip:" + uuid.uuid4().hex,
    )

    # Accumulate tip_total_cents on the video metadata row (best-effort additive).
    new_total = body.amount_cents
    try:
        upd = T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET tip_total_cents = if_not_exists(tip_total_cents, :z) + :amt",
            ExpressionAttributeValues={":z": 0, ":amt": body.amount_cents},
            ReturnValues="UPDATED_NEW",
        )
        new_total = int(upd.get("Attributes", {}).get("tip_total_cents", body.amount_cents))
    except Exception:
        logger.warning("failed to accumulate tip_total_cents on video %s", video_id)

    # Social activity + notification hooks (best-effort).
    try:
        from app.services.activity_feed import record_social_interaction
        record_social_interaction(
            recipient_id=video.owner_user_id, actor_id=user_sub, kind="tip",
            target_type="video", target_id=video_id,
            extra={"amount_cents": body.amount_cents, "currency": body.currency},
        )
    except Exception:
        logger.debug("social hook: tip_video", exc_info=True)

    return VideoTipOut(
        ok=True, video_id=video_id, amount_cents=body.amount_cents,
        currency=body.currency, tip_total_cents=new_total,
    )


@router.get("/{video_id}", response_model=VideoDetailOut)
def get_video_detail(
    video_id: str,
    request: Request,
    user=Depends(require_ui_session),
):
    """Get video detail. Owner sees any status; non-owner only published+public/unlisted."""
    user_sub = user["user_sub"]
    video = get_video(video_id)

    is_owner = video.owner_user_id == user_sub
    if not is_owner:
        if video.status != "published" or video.visibility not in ("public", "unlisted"):
            raise HTTPException(status_code=403, detail="access denied")
        # GEO-001: Check geo-access for non-owners
        _geo_mode = getattr(video, "geo_mode", None)
        _geo_countries = getattr(video, "geo_countries", None)
        # Also read from raw DDB item in case model doesn't have these attrs
        if _geo_mode is None:
            raw = T.video_metadata.get_item(Key={"video_id": video_id}).get("Item", {})
            _geo_mode = raw.get("geo_mode")
            _geo_countries = raw.get("geo_countries")
        if _geo_mode:
            from app.services.geo_check import check_geo_access
            check_geo_access(request, _geo_mode, _geo_countries)

    # MON-005: Comprehensive access check (owner/free/purchased/subscription cascade)
    from app.services.vod_purchase import check_vod_access
    access = check_vod_access(user_id=user_sub, video_id=video_id, video=video)

    playback_token, playback_expires_at = None, None
    if access.entitled:
        playback_token, playback_expires_at = _try_issue_playback_token(video, user_sub)

    return _video_to_detail(
        video,
        playback_token=playback_token,
        playback_expires_at=playback_expires_at,
        is_entitled=access.entitled,
        access_reason=access.reason,
        subscription_available=access.subscription_available,
        purchase_available=access.purchase_available,
        subscription_upsell=access.subscription_upsell,
        # VOD-018
        ads_enabled=access.ads_enabled,
        # VOD-019 fields
        purchase_type=access.purchase_type,
        views_remaining=access.views_remaining,
        expires_at=access.expires_at,
        download_allowed=access.download_allowed,
    )


@router.patch("/{video_id}", response_model=VideoDetailOut)
def update_video_endpoint(
    video_id: str,
    body: VideoUpdateIn,
    user=Depends(require_ui_session),
):
    """Update video metadata (owner only)."""
    user_sub = user["user_sub"]
    video = get_video(video_id)

    if video.owner_user_id != user_sub:
        raise HTTPException(status_code=403, detail="not your video")

    # Build UpdateVideoIn from our request body
    update_data = UpdateVideoIn(
        title=body.title,
        description=body.description,
        visibility=body.visibility,
        allow_download=body.allow_download,
    )

    updated = update_video(video_id, update_data)

    # Handle scheduled_publish_at update (content calendar integration)
    if body.scheduled_publish_at is not None:
        from app.core.tables import T as _T
        _T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET scheduled_publish_at = :spa, updated_at = :now",
            ExpressionAttributeValues={
                ":spa": body.scheduled_publish_at,
                ":now": now_ts(),
            },
        )
        updated_data = updated.model_dump()
        updated_data["scheduled_publish_at"] = body.scheduled_publish_at
        updated_data["updated_at"] = now_ts()
        from app.models_video import VideoMetadataModel as VMM2
        updated = VMM2(**updated_data)

    # VOD-012: Trigger MP4 generation when allow_download is toggled on
    if body.allow_download is True and updated.download_mp4_status != "ready":
        from app.services.vod_mp4_generator import generate_download_mp4

        gen_result = generate_download_mp4(updated)
        # Apply generation result to the video
        patch_data = UpdateVideoIn()
        updated_data = updated.model_dump()
        updated_data.update(gen_result)
        updated_data["updated_at"] = now_ts()
        from app.models_video import VideoMetadataModel as VMM
        updated = VMM(**updated_data)
        from app.core.tables import T
        from app.services.video_metadata_store import video_to_item
        T.video_metadata.put_item(Item=video_to_item(updated))

    return _video_to_detail(updated)


@router.get("/{video_id}/download")
def download_video_endpoint(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Generate and return a presigned download URL for the video's MP4 (VOD-012)."""
    if not S.video_download_enabled:
        raise HTTPException(status_code=503, detail="downloads temporarily disabled")

    video = get_video(video_id)
    user_sub = user["user_sub"]

    # Authorization: owner always allowed; non-owner needs published + public/unlisted
    is_owner = video.owner_user_id == user_sub
    if not is_owner:
        is_public = video.status == "published" and video.visibility in ("public", "unlisted")
        if not is_public:
            raise HTTPException(status_code=403, detail="forbidden")

        # VOD-019: Check download entitlement for non-owners — but only for
        # videos that actually require a purchase. A free public video (no
        # purchase types, no price, no SKU) is freely downloadable by anyone.
        requires_purchase = bool(
            getattr(video, "available_purchase_types", None)
            or getattr(video, "price_cents", None)
            or getattr(video, "download_price_cents", None)
            or getattr(video, "entitlement_sku", None)
        )
        if S.vod_purchase_tiers_enabled and requires_purchase:
            from app.services.vod_purchase import check_entitlement_purchase_only
            ent = check_entitlement_purchase_only(user_id=user_sub, video_id=video_id)
            if not ent.entitled or not ent.download_allowed:
                raise HTTPException(status_code=403, detail="Download access not included in your purchase")

    if not video.allow_download:
        raise HTTPException(status_code=403, detail="downloads not enabled for this video")

    if not video.download_mp4_key or video.download_mp4_status != "ready":
        raise HTTPException(status_code=404, detail="download mp4 not ready")

    # GAP-0375 / VOD-012 §1.4: throttle presigned-URL minting per user per video
    # to prevent download-URL farming. Uses the shared DDB-backed bucket counter
    # (same code path dev + prod, SECOPS-007 parity). Limit/window are config-driven.
    _dl_rate_window = 600  # 10 minutes
    _dl_rate_max = int(getattr(S, "video_download_rate_limit_per_10m", 5) or 0)
    if _dl_rate_max > 0 and not _bucket_limit(
        user_sub,
        f"viddl:{video_id}",
        _dl_rate_max,
        _dl_rate_window,
    ):
        raise HTTPException(
            status_code=429,
            detail={
                "code": "download_rate_limit_exceeded",
                "message": (
                    f"Download rate limit of {_dl_rate_max} per 10 minutes exceeded"
                ),
                "limit": _dl_rate_max,
                "window_seconds": _dl_rate_window,
            },
            headers={"Retry-After": str(_dl_rate_window)},
        )

    from app.services.vod_mp4_generator import mint_video_download_url
    from app.services.video_metadata_store import increment_download_count

    ttl = S.video_download_url_ttl_seconds
    result = mint_video_download_url(video, ttl)

    # Increment download counter (best-effort)
    try:
        increment_download_count(video_id)
    except Exception:
        logger.warning("Failed to increment download count for %s", video_id)

    return result


# ─── Video Clipping (VOD-015) ──────────────────────────────────────────────


class ClipVideoIn(BaseModel):
    start_seconds: float = Field(ge=0)
    end_seconds: float = Field(gt=0)
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)


class ClipVideoOut(BaseModel):
    video_id: str
    title: str
    status: str
    source_video_id: str
    clip_start_seconds: float
    clip_end_seconds: float
    created_via: str
    clip_job_id: str


@router.post("/{video_id}/clip", status_code=201, response_model=ClipVideoOut)
def clip_video_endpoint(
    video_id: str,
    body: ClipVideoIn,
    user=Depends(require_ui_session),
):
    """Create a clipped version of an existing video (VOD-015)."""
    if not S.video_clipping_enabled:
        raise HTTPException(status_code=403, detail="video clipping is not enabled")

    user_sub = user["user_sub"]
    video = get_video(video_id)

    if video.owner_user_id != user_sub:
        raise HTTPException(status_code=403, detail="forbidden")

    if video.status not in ("published", "approved"):
        raise HTTPException(status_code=400, detail="video must be published or approved")

    if not video.source_s3_key:
        raise HTTPException(status_code=409, detail="source file not available")

    if video.duration_seconds is None:
        raise HTTPException(status_code=409, detail="video duration unknown")

    if body.start_seconds >= body.end_seconds:
        raise HTTPException(status_code=400, detail="start_seconds must be less than end_seconds")

    if body.end_seconds > video.duration_seconds:
        raise HTTPException(status_code=400, detail="end_seconds exceeds video duration")

    clip_duration = body.end_seconds - body.start_seconds
    min_duration = S.video_clip_min_duration_seconds
    if clip_duration < min_duration:
        raise HTTPException(
            status_code=400,
            detail=f"minimum clip length is {min_duration} seconds",
        )

    # Create new video metadata for the clip
    from app.services.video_metadata_store import create_video as _create_video, update_clip_fields
    from app.services.transcode_job_store import create_job as _create_job

    title = body.title or f"{video.title} (clip)"
    new_video = _create_video(
        owner_user_id=user_sub,
        title=title,
        description=video.description,
        source_type="upload",
        visibility=video.visibility,
    )

    # Set clip provenance fields
    update_clip_fields(
        video_id=new_video.id,
        source_video_id=video_id,
        clip_start_seconds=body.start_seconds,
        clip_end_seconds=body.end_seconds,
        created_via="clip",
    )

    # Enqueue clip job
    from decimal import Decimal as _D
    job = _create_job(
        video_id=new_video.id,
        tenant_id=user_sub,
        rendition_profiles=[],
        source_uri=video.source_s3_key,
        job_type="clip",
        extra_fields={
            "clip_source_video_id": video_id,
            "clip_start_seconds": _D(str(body.start_seconds)),
            "clip_end_seconds": _D(str(body.end_seconds)),
        },
    )

    return ClipVideoOut(
        video_id=new_video.id,
        title=title,
        status="created",
        source_video_id=video_id,
        clip_start_seconds=body.start_seconds,
        clip_end_seconds=body.end_seconds,
        created_via="clip",
        clip_job_id=job["job_id"],
    )


# ─── Video Concatenation (VOD-016) ───────────────────────────────────────


class CombineVideosIn(BaseModel):
    source_video_ids: List[str] = Field(min_length=2, max_length=10)
    title: str = Field(min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)


class CombineVideosOut(BaseModel):
    video_id: str
    title: str
    status: str
    source_video_ids: List[str]
    created_via: str
    estimated_duration_seconds: float
    concat_method: str
    concat_job_id: str


@router.post("/combine", status_code=201, response_model=CombineVideosOut)
def combine_videos_endpoint(
    body: CombineVideosIn,
    user=Depends(require_ui_session),
):
    """Combine 2-10 videos into a single output (VOD-016)."""
    if not S.video_concat_enabled:
        raise HTTPException(status_code=403, detail="video concatenation is not enabled")

    user_sub = user["user_sub"]

    from app.services.video_concatenator import create_concat_job
    result = create_concat_job(
        owner_user_id=user_sub,
        source_video_ids=body.source_video_ids,
        title=body.title,
        description=body.description,
    )

    return CombineVideosOut(**result)


@router.delete("/{video_id}", status_code=204)
def delete_video_endpoint(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Soft-delete a video (owner only)."""
    user_sub = user["user_sub"]
    delete_video(video_id, user_sub)
    return None


@router.get("", response_model=VideoListOut)
def list_own_videos(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    visibility: Optional[str] = Query(default=None),
    user=Depends(require_ui_session),
):
    """List the caller's own videos (paginated, filterable)."""
    user_sub = user["user_sub"]
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_by_owner(
        user_sub,
        limit=limit,
        cursor=decoded_cursor,
        status_filter=status,
        visibility_filter=visibility,
    )
    items = [_video_to_list_item(v) for v in result["items"]]
    return VideoListOut(items=items, cursor=encode_cursor(_sanitize_cursor(result.get("cursor"))))


# ─── Pay-Per-View Endpoints (MON-001) ───────────────────────────────────────


class VodAccessOut(BaseModel):
    entitled: bool
    reason: str
    price_cents: Optional[int] = None
    access_mode: Optional[str] = None
    # MON-005 fields
    subscription_available: bool = False
    purchase_available: bool = False
    subscription_upsell: bool = False
    # VOD-018: ad-supported tier
    ads_enabled: bool = False
    # VOD-019 fields
    purchase_type: str = "permanent"
    views_remaining: int = -1
    expires_at: Optional[int] = None
    download_allowed: bool = False


class VodPurchaseIn(BaseModel):
    payment_method_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    # VOD-019: purchase type selection
    purchase_type: str = Field(
        default="permanent",
        pattern=r"^(view_once|rental|permanent|download)$",
    )


class VodPurchaseOut(BaseModel):
    video_id: str
    already_owned: bool
    granted_at: int
    grant_type: str
    amount_cents: int
    purchase_id: str = ""
    # VOD-019 fields
    purchase_type: str = "permanent"
    views_remaining: int = -1
    expires_at: Optional[int] = None
    download_allowed: bool = False


class VodPurchaseListItem(BaseModel):
    video_id: str
    granted_at: int
    grant_type: str
    amount_cents: int
    purchase_id: str = ""
    # VOD-019 fields
    purchase_type: str = "permanent"
    views_remaining: int = -1
    expires_at: Optional[int] = None
    download_allowed: bool = False


class VodPurchaseListOut(BaseModel):
    items: List[VodPurchaseListItem]


class VodPricingIn(BaseModel):
    price_cents: Optional[int] = Field(default=None, ge=0)
    access_mode: Optional[str] = Field(default=None, pattern=r"^(free|ppv|subscriber_only|subscriber_free|ad_supported)$")
    # VOD-019: per-type pricing fields
    available_purchase_types: Optional[List[str]] = None
    view_once_price_cents: Optional[int] = Field(default=None, ge=0)
    rental_price_cents: Optional[int] = Field(default=None, ge=0)
    rental_duration_hours: Optional[int] = Field(default=None, ge=1, le=720)
    download_price_cents: Optional[int] = Field(default=None, ge=0)


@router.get("/{video_id}/access", response_model=VodAccessOut)
def check_video_access(
    video_id: str,
    user=Depends(require_ui_session),
):
    user_sub = user["user_sub"]
    video = get_video(video_id)

    # MON-005: Use comprehensive access check
    from app.services.vod_purchase import check_vod_access
    access = check_vod_access(user_id=user_sub, video_id=video_id, video=video)
    return VodAccessOut(
        entitled=access.entitled,
        reason=access.reason,
        price_cents=access.price_cents if access.price_cents is not None else video.price_cents,
        access_mode=video.access_mode,
        subscription_available=access.subscription_available,
        purchase_available=access.purchase_available,
        subscription_upsell=access.subscription_upsell,
        # VOD-018
        ads_enabled=access.ads_enabled,
        # VOD-019 fields
        purchase_type=access.purchase_type,
        views_remaining=access.views_remaining,
        expires_at=access.expires_at if access.expires_at > 0 else None,
        download_allowed=access.download_allowed,
    )


def _resolve_price(video: VideoMetadataModel, purchase_type: str) -> Optional[int]:
    """Resolve the correct price for a purchase type (VOD-019)."""
    if purchase_type == "view_once":
        return video.view_once_price_cents
    elif purchase_type == "rental":
        return video.rental_price_cents
    elif purchase_type == "download":
        return video.download_price_cents
    else:  # permanent
        return video.price_cents


@router.post("/{video_id}/purchase", response_model=VodPurchaseOut)
def purchase_video_endpoint(
    video_id: str,
    body: VodPurchaseIn,
    user=Depends(require_ui_session),
):
    user_sub = user["user_sub"]
    video = get_video(video_id)

    if video.owner_user_id == user_sub:
        raise HTTPException(status_code=400, detail="cannot purchase your own video")

    if video.status != "published":
        raise HTTPException(status_code=400, detail="video not available for purchase")

    # MON-005: Block purchase for subscriber_only videos (no individual purchase option)
    if video.access_mode == "subscriber_only":
        raise HTTPException(
            status_code=403,
            detail="This video is only available to subscribers — individual purchase is not available",
        )

    # MON-005: Block purchase for subscribers viewing subscriber_free videos
    if video.access_mode == "subscriber_free":
        from app.services.subscription_access import has_active_subscription
        if has_active_subscription(subscriber_id=user_sub, creator_id=video.owner_user_id):
            raise HTTPException(
                status_code=400,
                detail="You already have access via your subscription",
            )

    # VOD-019: Validate purchase type is available for this video
    if S.vod_purchase_tiers_enabled and body.purchase_type != "permanent":
        available_types = video.available_purchase_types or ["permanent"]
        if body.purchase_type not in available_types:
            raise HTTPException(
                status_code=400,
                detail=f"Purchase type '{body.purchase_type}' not available for this video",
            )
    elif not S.vod_purchase_tiers_enabled and body.purchase_type != "permanent":
        raise HTTPException(
            status_code=400,
            detail="Purchase tiers are not enabled",
        )

    # VOD-019: Resolve price based on purchase type
    price = _resolve_price(video, body.purchase_type)
    if price is None or price <= 0:
        # Fallback: for permanent type, check video.price_cents
        if body.purchase_type == "permanent" and video.price_cents and video.price_cents > 0:
            price = video.price_cents
        else:
            raise HTTPException(status_code=400, detail="video is free")

    from app.services.vod_purchase import purchase_video
    result = purchase_video(
        buyer_id=user_sub,
        video_id=video_id,
        price_cents=price,
        seller_id=video.owner_user_id,
        payment_method_id=body.payment_method_id,
        idempotency_key=body.idempotency_key,
        purchase_type=body.purchase_type,
        rental_duration_hours=video.rental_duration_hours or S.vod_rental_default_duration_hours,
    )
    return VodPurchaseOut(**result)


@router.get("/purchases/list", response_model=VodPurchaseListOut)
def list_purchases_endpoint(
    limit: int = Query(default=50, ge=1, le=200),
    user=Depends(require_ui_session),
):
    user_sub = user["user_sub"]
    from app.services.vod_purchase import list_purchases
    items = list_purchases(user_sub, limit=limit)
    return VodPurchaseListOut(items=[VodPurchaseListItem(**i) for i in items])


# ─── VOD-019: Playback Complete ──────────────────────────────────────────────


@router.post("/{video_id}/playback-complete")
def playback_complete_endpoint(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Record playback completion (VOD-019).

    For view_once purchases: atomically consumes the view (sets views_remaining=0).
    For other types: no-op (returned for analytics).
    Idempotent: calling twice on an already-consumed view is safe.
    """
    user_sub = user["user_sub"]
    from app.services.vod_purchase import record_playback_complete
    result = record_playback_complete(user_id=user_sub, video_id=video_id)

    if not result.get("ok"):
        raise HTTPException(status_code=404, detail="No entitlement found")

    return result


@router.patch("/{video_id}/pricing", response_model=VideoDetailOut)
def set_video_pricing(
    video_id: str,
    body: VodPricingIn,
    user=Depends(require_ui_session),
):
    user_sub = user["user_sub"]
    video = get_video(video_id)

    if video.owner_user_id != user_sub:
        raise HTTPException(status_code=403, detail="not your video")

    # VOD-019: Validate available_purchase_types
    valid_types = {"view_once", "rental", "permanent", "download"}
    if body.available_purchase_types is not None:
        for pt in body.available_purchase_types:
            if pt not in valid_types:
                raise HTTPException(status_code=422, detail=f"Invalid purchase type: {pt}")

    # VOD-019: Validate download_price >= permanent price
    eff_price = body.price_cents if body.price_cents is not None else (video.price_cents or 0)
    eff_download = body.download_price_cents if body.download_price_cents is not None else video.download_price_cents
    if eff_download is not None and eff_price is not None and eff_download < eff_price:
        raise HTTPException(status_code=422, detail="download_price_cents must be >= price_cents")

    update_expr_parts = []
    expr_values: dict = {}
    expr_names: dict = {}

    if body.price_cents is not None:
        update_expr_parts.append("#pc = :pc")
        expr_names["#pc"] = "price_cents"
        expr_values[":pc"] = body.price_cents

    if body.access_mode is not None:
        update_expr_parts.append("#am = :am")
        expr_names["#am"] = "access_mode"
        expr_values[":am"] = body.access_mode

    # VOD-019: per-type pricing fields
    if body.available_purchase_types is not None:
        update_expr_parts.append("available_purchase_types = :apt")
        expr_values[":apt"] = body.available_purchase_types

    if body.view_once_price_cents is not None:
        update_expr_parts.append("view_once_price_cents = :vopc")
        expr_values[":vopc"] = body.view_once_price_cents

    if body.rental_price_cents is not None:
        update_expr_parts.append("rental_price_cents = :rpc")
        expr_values[":rpc"] = body.rental_price_cents

    if body.rental_duration_hours is not None:
        update_expr_parts.append("rental_duration_hours = :rdh")
        expr_values[":rdh"] = body.rental_duration_hours

    if body.download_price_cents is not None:
        update_expr_parts.append("download_price_cents = :dpc")
        expr_values[":dpc"] = body.download_price_cents

    if not update_expr_parts:
        raise HTTPException(status_code=400, detail="no fields to update")

    update_expr_parts.append("updated_at = :ua")
    expr_values[":ua"] = now_ts()

    kwargs: dict = {
        "Key": {"video_id": video_id},
        "UpdateExpression": "SET " + ", ".join(update_expr_parts),
        "ExpressionAttributeValues": expr_values,
    }
    if expr_names:
        kwargs["ExpressionAttributeNames"] = expr_names
    T.video_metadata.update_item(**kwargs)

    updated = get_video(video_id)
    return _video_to_detail(updated, is_entitled=True, access_reason="owner")


# ─── MON-005: Subscription-Aware Creator Video List ──────────────────────────


class CreatorVideoListItem(BaseModel):
    video_id: str
    title: str
    description: Optional[str] = None
    thumbnail_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    price_cents: Optional[int] = None
    access_mode: Optional[str] = None
    entitled: bool
    access_reason: str  # "owner" | "free" | "purchased" | "subscription" | "none"
    created_at: int


class CreatorVideoListOut(BaseModel):
    videos: List[CreatorVideoListItem]
    viewer_has_subscription: bool
    next_cursor: Optional[str] = None


@router.get("/by-creator/{creator_id}", response_model=CreatorVideoListOut)
def list_creator_videos_with_access(
    creator_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user=Depends(require_ui_session),
):
    """List a creator's published videos with subscription-aware access info (MON-005).

    Checks the viewer's subscription status once for the creator, then batch-checks
    purchase entitlements for all returned videos. Significantly more efficient
    than calling check_vod_access() per video.
    """
    user_sub = user["user_sub"]
    decoded_cursor = decode_cursor(cursor)
    result = list_videos_by_creator_public(creator_id, limit=limit, cursor=decoded_cursor)
    videos = result["items"]

    # Single subscription check for all videos by this creator
    from app.services.subscription_access import has_active_subscription
    has_sub = has_active_subscription(subscriber_id=user_sub, creator_id=creator_id)

    # Batch check purchase entitlements
    from app.services.vod_purchase import _batch_check_entitlements
    purchased_ids: set = set()
    if user_sub != creator_id and videos:
        purchased_ids = _batch_check_entitlements(
            user_id=user_sub,
            video_ids=[v.id for v in videos],
        )

    items: List[CreatorVideoListItem] = []
    for v in videos:
        access_mode = v.access_mode or "free"
        price = v.price_cents or 0
        is_free = price == 0 or access_mode == "free"
        is_purchased = v.id in purchased_ids
        sub_grants = has_sub and access_mode in ("subscriber_only", "subscriber_free")

        entitled = (user_sub == creator_id) or is_free or is_purchased or sub_grants
        reason = (
            "owner" if user_sub == creator_id else
            "free" if is_free else
            "purchased" if is_purchased else
            "subscription" if sub_grants else
            "none"
        )

        items.append(CreatorVideoListItem(
            video_id=v.id,
            title=v.title,
            description=v.description,
            thumbnail_url=v.thumbnail_url,
            duration_seconds=v.duration_seconds,
            price_cents=v.price_cents,
            access_mode=v.access_mode,
            entitled=entitled,
            access_reason=reason,
            created_at=v.created_at,
        ))

    next_cursor = encode_cursor(_sanitize_cursor(result.get("cursor")))
    return CreatorVideoListOut(
        videos=items,
        viewer_has_subscription=has_sub,
        next_cursor=next_cursor if next_cursor else None,
    )


# ─── VOD-018: Ad-Supported Video Tier ──────────────────────────────────────


class AdConfigIn(BaseModel):
    pre_roll: bool = True
    mid_roll_intervals_seconds: List[int] = Field(default_factory=list)
    overlay_enabled: bool = False
    skip_after_seconds: int = Field(default=5, ge=0, le=30)
    ads_free_for_subscribers: bool = False


class AdSlotOut(BaseModel):
    type: str
    timestamp_seconds: int
    duration_seconds: int
    creative_id: str
    creative_url: str
    creative_type: str
    skip_after_seconds: int
    slot_index: int


class AdPlacementOut(BaseModel):
    ads_enabled: bool
    slots: List[AdSlotOut] = Field(default_factory=list)
    ad_free: bool = True


class AdImpressionIn(BaseModel):
    slot_type: str = Field(pattern=r"^(pre_roll|mid_roll|overlay)$")
    slot_index: int = Field(ge=0)
    creative_id: str = ""
    event_type: str = Field(default="impression", pattern=r"^(impression|complete|skip)$")
    # Fraud-signal: actual view duration reported by the player (GAP-0006).
    view_time_ms: int = Field(default=0, ge=0)


class AdImpressionOut(BaseModel):
    ok: bool
    event_id: str
    blocked: bool = False


class AdRevenueOut(BaseModel):
    video_id: str
    ad_impression_count: int
    ad_revenue_cents: int
    estimated_cpm_cents: int


@router.get("/{video_id}/ad-config", response_model=AdPlacementOut)
def get_video_ad_config(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Get ad placement config for a video (viewer-facing).

    Returns ad slots with creative URLs if ads are enabled for this viewer.
    Subscribers with ads_free_for_subscribers get empty slots.
    """
    if not S.vod_ads_enabled:
        raise HTTPException(status_code=404, detail="ads not enabled")

    user_sub = user["user_sub"]

    from app.services.ad_placement import get_ad_config as _get_ad_config
    result = _get_ad_config(video_id, user_sub)

    slots = [AdSlotOut(**s) for s in result.get("slots", [])]
    return AdPlacementOut(
        ads_enabled=result.get("ads_enabled", False),
        slots=slots,
        ad_free=result.get("ad_free", True),
    )


@router.post("/{video_id}/ad-impression", response_model=AdImpressionOut)
def record_ad_impression_endpoint(
    video_id: str,
    body: AdImpressionIn,
    request: Request,
    user=Depends(require_ui_session),
):
    """Record an ad impression event (impression/complete/skip)."""
    if not S.vod_ads_enabled:
        raise HTTPException(status_code=404, detail="ads not enabled")

    user_sub = user["user_sub"]

    from app.services.ad_placement import record_ad_impression
    result = record_ad_impression(
        video_id=video_id,
        user_id=user_sub,
        slot_type=body.slot_type,
        slot_index=body.slot_index,
        creative_id=body.creative_id,
        event_type=body.event_type,
        # Fraud signals forwarded to the fraud gate (GAP-0006).
        ip_address=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
        view_time_ms=body.view_time_ms,
    )
    return AdImpressionOut(
        ok=result["ok"],
        event_id=result["event_id"],
        blocked=result.get("blocked", False),
    )


@router.get("/{video_id}/ad-stats", response_model=AdRevenueOut)
def get_ad_stats_endpoint(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Get ad impression and revenue stats for a video (owner only)."""
    if not S.vod_ads_enabled:
        raise HTTPException(status_code=404, detail="ads not enabled")

    user_sub = user["user_sub"]
    video = get_video(video_id)

    if video.owner_user_id != user_sub:
        raise HTTPException(status_code=403, detail="not your video")

    from app.services.ad_placement import get_ad_stats
    stats = get_ad_stats(video_id)
    return AdRevenueOut(**stats)


@router.patch("/{video_id}/ad-config")
def set_video_ad_config(
    video_id: str,
    body: AdConfigIn,
    user=Depends(require_ui_session),
):
    """Configure ad placement for a video (owner only)."""
    if not S.vod_ads_enabled:
        raise HTTPException(status_code=404, detail="ads not enabled")

    user_sub = user["user_sub"]
    video = get_video(video_id)

    if video.owner_user_id != user_sub:
        raise HTTPException(status_code=403, detail="not your video")

    from app.services.ad_placement import validate_ad_config
    duration = video.duration_seconds or 60
    validated = validate_ad_config(body.model_dump(), duration)

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET ad_config = :ac, ads_free_for_subscribers = :afs, updated_at = :ua",
        ExpressionAttributeValues={
            ":ac": validated,
            ":afs": body.ads_free_for_subscribers,
            ":ua": now_ts(),
        },
    )
    return {
        "ok": True,
        "ad_config": validated,
        "ads_free_for_subscribers": body.ads_free_for_subscribers,
    }
