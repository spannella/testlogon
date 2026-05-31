"""MOD-001: Video Review Queue router.

Moderator/admin endpoints for queuing videos for human review and acting on
them (claim / approve / reject / escalate). Prefix: ``/ui/moderation/video-queue``.

Auth: ``require_admin_or_root`` for all moderator actions. The feature is gated
by the ``moderation_video_queue_enabled`` setting -- when disabled, every route
returns 404 so it can be dark-launched.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.models import (
    VideoReviewApproveIn,
    VideoReviewClaimOut,
    VideoReviewDecisionOut,
    VideoReviewDetailOut,
    VideoReviewEscalateIn,
    VideoReviewQueueEnqueueIn,
    VideoReviewQueueItemOut,
    VideoReviewQueueListOut,
    VideoReviewQueueStatsOut,
    VideoReviewRejectIn,
)
from app.services import moderation_video_queue as svc

moderation_video_queue_router = APIRouter(
    prefix="/ui/moderation/video-queue", tags=["moderation-video-queue"]
)


def _ensure_enabled() -> None:
    if not S.moderation_video_queue_enabled:
        raise HTTPException(status_code=404, detail="not found")


def _to_item(raw: dict) -> VideoReviewQueueItemOut:
    duration = raw.get("duration_seconds")
    return VideoReviewQueueItemOut(
        entry_id=raw.get("entry_id", ""),
        video_id=raw.get("video_id", ""),
        owner_user_id=raw.get("owner_user_id", ""),
        title=raw.get("title", "") or "",
        description=raw.get("description", "") or "",
        status=raw.get("status", ""),
        priority=raw.get("priority", "normal"),
        priority_rank=int(raw.get("priority_rank", 2)),
        source=raw.get("source", "manual"),
        created_at=int(raw.get("created_at", 0)),
        updated_at=int(raw.get("updated_at", 0)),
        claimed_by=raw.get("claimed_by", "") or "",
        claimed_at=int(raw.get("claimed_at", 0) or 0),
        reviewed_by=raw.get("reviewed_by", "") or "",
        reviewed_at=int(raw.get("reviewed_at", 0) or 0),
        review_notes=raw.get("review_notes", "") or "",
        decision=raw.get("decision", "") or "",
        escalated=bool(raw.get("escalated", False)),
        thumbnail_url=raw.get("thumbnail_url"),
        hls_manifest_url=raw.get("hls_manifest_url"),
        duration_seconds=float(duration) if duration not in (None, "") else None,
        flag_reason=raw.get("flag_reason"),
    )


@moderation_video_queue_router.post("/enqueue", response_model=VideoReviewQueueItemOut)
def enqueue(
    body: VideoReviewQueueEnqueueIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> VideoReviewQueueItemOut:
    """Manually enqueue a video (or a flagged video) for review."""
    _ensure_enabled()
    entry = svc.enqueue_video(
        video_id=body.video_id,
        owner_user_id=body.owner_user_id,
        title=body.title,
        description=body.description,
        priority=body.priority,
        source=body.source,
        thumbnail_url=body.thumbnail_url,
        hls_manifest_url=body.hls_manifest_url,
        duration_seconds=body.duration_seconds,
        flag_reason=body.flag_reason,
        enqueued_by=user.sub,
    )
    return _to_item(entry)


@moderation_video_queue_router.get("", response_model=VideoReviewQueueListOut)
def list_queue(
    status: str = Query("pending"),
    order_by: str = Query("priority", pattern="^(priority|created_at)$"),
    limit: int = Query(25, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    owner_user_id: Optional[str] = Query(None),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> VideoReviewQueueListOut:
    """List queue entries by status, ordered by priority or oldest-first."""
    _ensure_enabled()
    result = svc.list_queue(
        status=status,
        order_by=order_by,
        limit=limit,
        cursor=decode_cursor(cursor),
        owner_filter=owner_user_id,
    )
    return VideoReviewQueueListOut(
        items=[_to_item(it) for it in result["items"]],
        total=result["total"],
        next_cursor=encode_cursor(result["cursor"]),
    )


@moderation_video_queue_router.get("/stats", response_model=VideoReviewQueueStatsOut)
def stats(
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> VideoReviewQueueStatsOut:
    """Queue-depth counts across all statuses (for sidebar badge / dashboard)."""
    _ensure_enabled()
    counts = svc.queue_stats()
    total_open = sum(
        counts.get(s, 0) for s in (svc.STATUS_PENDING, svc.STATUS_IN_REVIEW, svc.STATUS_ESCALATED)
    )
    return VideoReviewQueueStatsOut(counts=counts, total_open=total_open)


@moderation_video_queue_router.get("/{entry_id}", response_model=VideoReviewDetailOut)
def detail(
    entry_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> VideoReviewDetailOut:
    """Full detail for a single entry, including the owner's review history."""
    _ensure_enabled()
    entry = svc.get_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="queue entry not found")
    history = svc.get_owner_review_history(entry.get("owner_user_id", ""))
    return VideoReviewDetailOut(
        entry=_to_item(entry),
        prior_review_history=history["events"],
        prior_approvals_count=history["approvals_count"],
        prior_rejections_count=history["rejections_count"],
    )


@moderation_video_queue_router.post(
    "/{entry_id}/claim", response_model=VideoReviewClaimOut
)
def claim(
    entry_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> VideoReviewClaimOut:
    """Claim a pending entry for review (pending -> in_review)."""
    _ensure_enabled()
    entry = svc.claim_entry(entry_id=entry_id, moderator_user_id=user.sub)
    return VideoReviewClaimOut(ok=True, entry=_to_item(entry))


@moderation_video_queue_router.post(
    "/{entry_id}/release", response_model=VideoReviewClaimOut
)
def release(
    entry_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> VideoReviewClaimOut:
    """Release a claimed entry back to pending."""
    _ensure_enabled()
    entry = svc.release_entry(entry_id=entry_id, moderator_user_id=user.sub)
    return VideoReviewClaimOut(ok=True, entry=_to_item(entry))


@moderation_video_queue_router.post(
    "/{entry_id}/approve", response_model=VideoReviewDecisionOut
)
def approve(
    entry_id: str,
    body: VideoReviewApproveIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> VideoReviewDecisionOut:
    """Approve a queued video."""
    _ensure_enabled()
    result = svc.approve_entry(
        entry_id=entry_id,
        moderator_user_id=user.sub,
        review_notes=body.review_notes,
        notify_creator=body.notify_creator,
    )
    entry = result["entry"]
    return VideoReviewDecisionOut(
        ok=True,
        entry_id=entry_id,
        decision="approve",
        new_status=entry["status"],
        reviewed_by=entry["reviewed_by"],
        reviewed_at=entry["reviewed_at"],
        audit_id=result["audit_id"],
    )


@moderation_video_queue_router.post(
    "/{entry_id}/reject", response_model=VideoReviewDecisionOut
)
def reject(
    entry_id: str,
    body: VideoReviewRejectIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> VideoReviewDecisionOut:
    """Reject a queued video with a required reason."""
    _ensure_enabled()
    result = svc.reject_entry(
        entry_id=entry_id,
        moderator_user_id=user.sub,
        rejection_reason=body.rejection_reason,
        notify_creator=body.notify_creator,
    )
    entry = result["entry"]
    return VideoReviewDecisionOut(
        ok=True,
        entry_id=entry_id,
        decision="reject",
        new_status=entry["status"],
        reviewed_by=entry["reviewed_by"],
        reviewed_at=entry["reviewed_at"],
        audit_id=result["audit_id"],
    )


@moderation_video_queue_router.post(
    "/{entry_id}/escalate", response_model=VideoReviewDecisionOut
)
def escalate(
    entry_id: str,
    body: VideoReviewEscalateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> VideoReviewDecisionOut:
    """Escalate a queued video to a senior moderator."""
    _ensure_enabled()
    result = svc.escalate_entry(
        entry_id=entry_id,
        moderator_user_id=user.sub,
        escalation_reason=body.escalation_reason,
        notify_creator=body.notify_creator,
    )
    entry = result["entry"]
    return VideoReviewDecisionOut(
        ok=True,
        entry_id=entry_id,
        decision="escalate",
        new_status=entry["status"],
        reviewed_by=entry["reviewed_by"],
        reviewed_at=entry["reviewed_at"],
        audit_id=result["audit_id"],
    )
