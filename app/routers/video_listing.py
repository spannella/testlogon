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


class VideoUpdateIn(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = Field(default=None, max_length=2000)
    visibility: Optional[VideoVisibility] = None


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


def _video_to_detail(video: VideoMetadataModel, *, playback_token: str | None = None, playback_expires_at: int | None = None) -> VideoDetailOut:
    # Resolve DRM key URI if DRM is enabled for this video
    drm_key_uri: str | None = None
    if video.drm_enabled:
        try:
            from app.services.vod_drm_keys import get_key_uri

            drm_key_uri = get_key_uri(video.id)
        except Exception:
            pass

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

    playback_token, playback_expires_at = _try_issue_playback_token(video, user_sub)
    return _video_to_detail(video, playback_token=playback_token, playback_expires_at=playback_expires_at)


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
    )

    updated = update_video(video_id, update_data)
    return _video_to_detail(updated)


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
