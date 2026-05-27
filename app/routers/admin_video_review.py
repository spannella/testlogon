"""Admin video review queue endpoints.

Provides endpoints for content moderation admins to list, preview,
approve, reject, and batch-review videos in pending_review status.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_scope
from app.auth.roles import AdminScope
from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.models_video import VideoStatus
from app.services.video_review import (
    approve_video,
    count_pending_review,
    get_owner_review_history,
    list_pending_review_videos,
    reject_video,
)
from app.services.video_metadata_store import get_video

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/admin/videos", tags=["admin-video-review"])

require_review_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)


# ─── Request / Response models ──────────────────────────────────────────────


class VideoReviewQueueItemOut(BaseModel):
    video_id: str
    owner_user_id: str
    title: str
    description: Optional[str] = None
    status: VideoStatus
    created_at: int
    updated_at: int
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    thumbnail_url: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    file_size_bytes: Optional[int] = None
    source_type: str
    visibility: str
    owner_display_name: Optional[str] = None
    owner_profile_photo_url: Optional[str] = None


class VideoReviewQueueOut(BaseModel):
    items: list[VideoReviewQueueItemOut]
    total_pending: int
    next_cursor: Optional[str] = None


class VideoReviewDetailOut(BaseModel):
    video: VideoReviewQueueItemOut
    owner_profile: dict[str, Any] = Field(default_factory=dict)
    prior_review_history: list[dict[str, Any]] = Field(default_factory=list)
    prior_rejections_count: int = 0
    prior_approvals_count: int = 0


class VideoApproveIn(BaseModel):
    review_notes: str = Field(default="", max_length=2000)
    auto_publish: bool = Field(default=True)

    @field_validator("review_notes")
    @classmethod
    def _sanitize_notes(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)


class VideoRejectIn(BaseModel):
    rejection_reason: str = Field(min_length=5, max_length=2000)
    notify_creator: bool = Field(default=True)

    @field_validator("rejection_reason")
    @classmethod
    def _sanitize_reason(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)


class VideoReviewDecisionOut(BaseModel):
    ok: bool
    video_id: str
    decision: Literal["approved", "rejected"]
    new_status: str
    reviewed_by: str
    reviewed_at: int
    audit_id: str
    auto_publish_failed: bool = False


class VideoBatchReviewDecisionIn(BaseModel):
    video_id: str = Field(min_length=1)
    action: Literal["approve", "reject"]
    reason: str = Field(default="", max_length=2000)

    @field_validator("reason")
    @classmethod
    def _sanitize_reason(cls, v: str) -> str:
        return re.sub(r"<[^>]+>", "", v)


class VideoBatchReviewIn(BaseModel):
    decisions: list[VideoBatchReviewDecisionIn] = Field(
        min_length=1, max_length=25
    )


class VideoBatchReviewResultOut(BaseModel):
    video_id: str
    ok: bool
    decision: Optional[str] = None
    new_status: Optional[str] = None
    error: Optional[str] = None
    audit_id: Optional[str] = None


class VideoBatchReviewOut(BaseModel):
    results: list[VideoBatchReviewResultOut]
    total: int
    succeeded: int
    failed: int


# ─── Helpers ────────────────────────────────────────────────────────────────


def _video_to_queue_item(video: Any) -> VideoReviewQueueItemOut:
    """Convert a VideoMetadataModel to a queue item output."""
    return VideoReviewQueueItemOut(
        video_id=video.id,
        owner_user_id=video.owner_user_id,
        title=video.title,
        description=video.description,
        status=video.status,
        created_at=video.created_at,
        updated_at=video.updated_at,
        duration_seconds=video.duration_seconds,
        width=video.width,
        height=video.height,
        thumbnail_url=video.thumbnail_url,
        hls_manifest_url=video.hls_manifest_url,
        file_size_bytes=video.file_size_bytes,
        source_type=video.source_type,
        visibility=video.visibility,
    )


def _enrich_with_owner_profiles(
    items: list[VideoReviewQueueItemOut],
) -> list[VideoReviewQueueItemOut]:
    """Batch-fetch owner profiles and attach display name + photo URL."""
    owner_ids = list({item.owner_user_id for item in items})
    if not owner_ids:
        return items

    profiles: dict[str, dict] = {}
    for owner_id in owner_ids:
        try:
            resp = T.profile.get_item(Key={"user_sub": owner_id})
            profile = resp.get("Item")
            if profile:
                profiles[owner_id] = profile
        except Exception:
            pass

    for item in items:
        profile = profiles.get(item.owner_user_id)
        if profile:
            item.owner_display_name = profile.get("display_name")
            item.owner_profile_photo_url = profile.get("profile_photo_url")

    return items


# ─── Endpoints ──────────────────────────────────────────────────────────────


@router.get("/review-queue", response_model=VideoReviewQueueOut)
async def get_review_queue(
    user: AuthenticatedUser = Depends(require_review_admin),
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    owner_user_id: Optional[str] = Query(default=None),
):
    """List videos in pending_review status, ordered oldest first."""
    decoded_cursor = None
    if cursor:
        try:
            decoded_cursor = decode_cursor(cursor)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid cursor")

    result = list_pending_review_videos(
        limit=limit,
        cursor=decoded_cursor,
        owner_filter=owner_user_id,
    )

    items = [_video_to_queue_item(v) for v in result["items"]]
    items = _enrich_with_owner_profiles(items)

    next_cursor = None
    if result["cursor"]:
        next_cursor = encode_cursor(result["cursor"])

    return VideoReviewQueueOut(
        items=items,
        total_pending=result["total_pending"],
        next_cursor=next_cursor,
    )


@router.get("/{video_id}/review-detail", response_model=VideoReviewDetailOut)
async def get_review_detail(
    video_id: str,
    user: AuthenticatedUser = Depends(require_review_admin),
):
    """Get full review detail for a single video."""
    video = get_video(video_id)
    item = _video_to_queue_item(video)
    items = _enrich_with_owner_profiles([item])
    item = items[0]

    # Fetch owner profile
    owner_profile: dict[str, Any] = {}
    try:
        resp = T.profile.get_item(Key={"user_sub": video.owner_user_id})
        profile = resp.get("Item")
        if profile:
            owner_profile = {
                "display_name": profile.get("display_name"),
                "bio": profile.get("bio"),
                "profile_photo_url": profile.get("profile_photo_url"),
                "created_at": profile.get("created_at"),
            }
    except Exception:
        pass

    # Get review history for owner
    history = get_owner_review_history(video.owner_user_id)

    return VideoReviewDetailOut(
        video=item,
        owner_profile=owner_profile,
        prior_review_history=history["events"],
        prior_rejections_count=history["rejections_count"],
        prior_approvals_count=history["approvals_count"],
    )


@router.post("/{video_id}/approve", response_model=VideoReviewDecisionOut)
async def approve_video_endpoint(
    video_id: str,
    body: VideoApproveIn,
    user: AuthenticatedUser = Depends(require_review_admin),
):
    """Approve a pending video. Auto-publishes by default."""
    video, audit_id, auto_publish_failed = approve_video(
        video_id=video_id,
        admin_user_id=user.sub,
        review_notes=body.review_notes,
        auto_publish=body.auto_publish,
    )
    return VideoReviewDecisionOut(
        ok=True,
        video_id=video_id,
        decision="approved",
        new_status=video.status,
        reviewed_by=user.sub,
        reviewed_at=video.reviewed_at or 0,
        audit_id=audit_id,
        auto_publish_failed=auto_publish_failed,
    )


@router.post("/{video_id}/reject", response_model=VideoReviewDecisionOut)
async def reject_video_endpoint(
    video_id: str,
    body: VideoRejectIn,
    user: AuthenticatedUser = Depends(require_review_admin),
):
    """Reject a pending video with a required reason."""
    video, audit_id = reject_video(
        video_id=video_id,
        admin_user_id=user.sub,
        rejection_reason=body.rejection_reason,
        notify_creator=body.notify_creator,
    )
    return VideoReviewDecisionOut(
        ok=True,
        video_id=video_id,
        decision="rejected",
        new_status=video.status,
        reviewed_by=user.sub,
        reviewed_at=video.reviewed_at or 0,
        audit_id=audit_id,
    )


@router.post("/batch-review", response_model=VideoBatchReviewOut)
async def batch_review_endpoint(
    body: VideoBatchReviewIn,
    user: AuthenticatedUser = Depends(require_review_admin),
):
    """Batch approve/reject up to 25 videos. Each decision is independent."""
    results: list[VideoBatchReviewResultOut] = []
    succeeded = 0
    failed = 0

    for decision in body.decisions:
        try:
            if decision.action == "approve":
                video, audit_id, _ = approve_video(
                    video_id=decision.video_id,
                    admin_user_id=user.sub,
                    review_notes=decision.reason,
                    auto_publish=True,
                )
                results.append(
                    VideoBatchReviewResultOut(
                        video_id=decision.video_id,
                        ok=True,
                        decision="approved",
                        new_status=video.status,
                        audit_id=audit_id,
                    )
                )
                succeeded += 1
            else:
                # reject
                if len(decision.reason) < 5:
                    results.append(
                        VideoBatchReviewResultOut(
                            video_id=decision.video_id,
                            ok=False,
                            error="rejection reason must be at least 5 characters",
                        )
                    )
                    failed += 1
                    continue

                video, audit_id = reject_video(
                    video_id=decision.video_id,
                    admin_user_id=user.sub,
                    rejection_reason=decision.reason,
                    notify_creator=True,
                )
                results.append(
                    VideoBatchReviewResultOut(
                        video_id=decision.video_id,
                        ok=True,
                        decision="rejected",
                        new_status=video.status,
                        audit_id=audit_id,
                    )
                )
                succeeded += 1
        except HTTPException as exc:
            detail = exc.detail
            if isinstance(detail, dict):
                error_msg = detail.get("code", str(detail))
            else:
                error_msg = str(detail)
            results.append(
                VideoBatchReviewResultOut(
                    video_id=decision.video_id,
                    ok=False,
                    error=error_msg,
                )
            )
            failed += 1
        except Exception as exc:
            results.append(
                VideoBatchReviewResultOut(
                    video_id=decision.video_id,
                    ok=False,
                    error=str(exc),
                )
            )
            failed += 1

    return VideoBatchReviewOut(
        results=results,
        total=len(body.decisions),
        succeeded=succeeded,
        failed=failed,
    )
