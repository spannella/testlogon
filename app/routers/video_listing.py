"""Video listing and management endpoints (VOD-006).

Provides browse, filter, detail, update, and soft-delete for videos.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
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


class VideoUpdateIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    visibility: Optional[VideoVisibility] = None
    allow_download: Optional[bool] = None


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
) -> VideoDetailOut:
    # Resolve DRM key URI if DRM is enabled for this video
    drm_key_uri: str | None = None
    if video.drm_enabled:
        try:
            from app.services.vod_drm_keys import get_key_uri

            drm_key_uri = get_key_uri(video.id)
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
        price_cents=video.price_cents,
        access_mode=video.access_mode,
        purchase_count=video.purchase_count,
        is_entitled=is_entitled,
        access_reason=access_reason,
        subscription_available=subscription_available,
        purchase_available=purchase_available,
        subscription_upsell=subscription_upsell,
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


@router.get("/{video_id}", response_model=VideoDetailOut)
def get_video_detail(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Get video detail. Owner sees any status; non-owner only published+public/unlisted."""
    user_sub = user["user_sub"]
    video = get_video(video_id)

    is_owner = video.owner_user_id == user_sub
    if not is_owner:
        if video.status != "published" or video.visibility not in ("public", "unlisted"):
            raise HTTPException(status_code=403, detail="access denied")

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

    if not video.allow_download:
        raise HTTPException(status_code=403, detail="downloads not enabled for this video")

    if not video.download_mp4_key or video.download_mp4_status != "ready":
        raise HTTPException(status_code=404, detail="download mp4 not ready")

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


class VodPurchaseIn(BaseModel):
    payment_method_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class VodPurchaseOut(BaseModel):
    video_id: str
    already_owned: bool
    granted_at: int
    grant_type: str
    amount_cents: int
    purchase_id: str = ""


class VodPurchaseListItem(BaseModel):
    video_id: str
    granted_at: int
    grant_type: str
    amount_cents: int
    purchase_id: str = ""


class VodPurchaseListOut(BaseModel):
    items: List[VodPurchaseListItem]


class VodPricingIn(BaseModel):
    price_cents: Optional[int] = Field(default=None, ge=0)
    access_mode: Optional[str] = Field(default=None, pattern=r"^(free|ppv|subscriber_only|subscriber_free)$")


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
    )


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

    if not video.price_cents or video.price_cents <= 0:
        raise HTTPException(status_code=400, detail="video is free")

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

    from app.services.vod_purchase import purchase_video
    result = purchase_video(
        buyer_id=user_sub,
        video_id=video_id,
        price_cents=video.price_cents,
        seller_id=video.owner_user_id,
        payment_method_id=body.payment_method_id,
        idempotency_key=body.idempotency_key,
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
