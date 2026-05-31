"""Newsfeed delegation router (DELEGATE-003).

Endpoints for delegated feed management: post CRUD, draft approval,
comment moderation, analytics, audit, and feed delegation settings.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query

from app.models import (
    DelegatedPostCreateIn,
    DelegatedPostEditIn,
    DelegatedPostOut,
    DraftApprovalIn,
    CommentModerationIn,
    FeedDelegationSettingsIn,
    FeedDelegationSettingsOut,
    FeedAnalyticsOut,
    FeedDelegateAuditEntry,
)
from app.services import delegate_feed as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/newsfeed/delegate", tags=["newsfeed-delegation"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_post_out(d: dict) -> DelegatedPostOut:
    return DelegatedPostOut(**d)


def _to_audit_entry(d: dict) -> FeedDelegateAuditEntry:
    return FeedDelegateAuditEntry(**d)


# ---------------------------------------------------------------------------
# Post CRUD (delegate with feed_post)
# ---------------------------------------------------------------------------


@router.post("/{creator_id}/posts", response_model=DelegatedPostOut, status_code=201)
async def create_post(
    creator_id: str,
    body: DelegatedPostCreateIn,
    user=Depends(require_ui_session),
):
    """Create a post on the creator's feed as a delegate."""
    result = svc.create_post_as_creator(
        creator_id=creator_id,
        delegate_id=user["user_sub"],
        text=body.text,
        image_url=body.image_url,
        lock_price_cents=body.lock_price_cents,
        tags=body.tags,
        scheduled_at=body.scheduled_at,
    )
    return _to_post_out(result)


@router.put("/{creator_id}/posts/{post_id}", response_model=DelegatedPostOut)
async def edit_post(
    creator_id: str,
    post_id: str,
    body: DelegatedPostEditIn,
    user=Depends(require_ui_session),
):
    """Edit a creator's post as a delegate."""
    result = svc.edit_post_as_creator(
        creator_id=creator_id,
        delegate_id=user["user_sub"],
        post_id=post_id,
        text=body.text,
        image_url=body.image_url,
        lock_price_cents=body.lock_price_cents,
        tags=body.tags,
    )
    return _to_post_out(result)


@router.delete("/{creator_id}/posts/{post_id}")
async def delete_post(
    creator_id: str,
    post_id: str,
    user=Depends(require_ui_session),
):
    """Delete a creator's post as a delegate."""
    svc.delete_post_as_creator(
        creator_id=creator_id,
        delegate_id=user["user_sub"],
        post_id=post_id,
    )
    return {"ok": True}


@router.get("/{creator_id}/posts", response_model=List[DelegatedPostOut])
async def list_posts(
    creator_id: str,
    user=Depends(require_ui_session),
    limit: int = Query(default=50, ge=1, le=200),
):
    """List a creator's posts (delegate with feed_read)."""
    results = svc.list_creator_posts(
        creator_id=creator_id,
        delegate_id=user["user_sub"],
        limit=limit,
    )
    return [_to_post_out(r) for r in results]


# ---------------------------------------------------------------------------
# Draft approval (creator only)
# ---------------------------------------------------------------------------


@router.get("/{creator_id}/drafts", response_model=List[DelegatedPostOut])
async def list_drafts(
    creator_id: str,
    user=Depends(require_ui_session),
    limit: int = Query(default=50, ge=1, le=200),
):
    """List pending delegate drafts for approval (creator only)."""
    if user["user_sub"] != creator_id:
        from fastapi import HTTPException
        raise HTTPException(403, "Only the creator can view the draft queue")
    results = svc.list_pending_drafts(creator_id=creator_id, limit=limit)
    return [_to_post_out(r) for r in results]


@router.post("/{creator_id}/drafts/{post_id}/approve", response_model=DelegatedPostOut)
async def approve_draft(
    creator_id: str,
    post_id: str,
    body: DraftApprovalIn,
    user=Depends(require_ui_session),
):
    """Approve a delegate's draft post (creator only)."""
    if user["user_sub"] != creator_id:
        from fastapi import HTTPException
        raise HTTPException(403, "Only the creator can approve drafts")
    result = svc.approve_draft(
        creator_id=creator_id,
        post_id=post_id,
        note=body.note,
    )
    return _to_post_out(result)


@router.post("/{creator_id}/drafts/{post_id}/reject", response_model=DelegatedPostOut)
async def reject_draft(
    creator_id: str,
    post_id: str,
    body: DraftApprovalIn,
    user=Depends(require_ui_session),
):
    """Reject a delegate's draft post (creator only)."""
    if user["user_sub"] != creator_id:
        from fastapi import HTTPException
        raise HTTPException(403, "Only the creator can reject drafts")
    result = svc.reject_draft(
        creator_id=creator_id,
        post_id=post_id,
        note=body.note,
    )
    return _to_post_out(result)


# ---------------------------------------------------------------------------
# Comment moderation (delegate with feed_moderate)
# ---------------------------------------------------------------------------


@router.post("/{creator_id}/posts/{post_id}/comments/{comment_id}/moderate")
async def moderate_comment(
    creator_id: str,
    post_id: str,
    comment_id: str,
    body: CommentModerationIn,
    user=Depends(require_ui_session),
):
    """Moderate a comment on a creator's post."""
    result = svc.moderate_comment(
        creator_id=creator_id,
        delegate_id=user["user_sub"],
        post_id=post_id,
        comment_id=comment_id,
        action=body.action,
    )
    return result


# ---------------------------------------------------------------------------
# Analytics (delegate with feed_read)
# ---------------------------------------------------------------------------


@router.get("/{creator_id}/analytics", response_model=FeedAnalyticsOut)
async def get_analytics(
    creator_id: str,
    user=Depends(require_ui_session),
    period: str = Query(default="30d"),
):
    """Get feed analytics for a creator."""
    result = svc.get_creator_feed_analytics(
        creator_id=creator_id,
        delegate_id=user["user_sub"],
        period=period,
    )
    return FeedAnalyticsOut(**result)


# ---------------------------------------------------------------------------
# Audit log (creator only)
# ---------------------------------------------------------------------------


@router.get("/{creator_id}/audit", response_model=List[FeedDelegateAuditEntry])
async def get_audit(
    creator_id: str,
    user=Depends(require_ui_session),
    limit: int = Query(default=50, ge=1, le=200),
):
    """List delegate feed actions (creator only)."""
    if user["user_sub"] != creator_id:
        from fastapi import HTTPException
        raise HTTPException(403, "Only the creator can view the audit log")
    results = svc.list_delegate_feed_actions(creator_id=creator_id, limit=limit)
    return [_to_audit_entry(r) for r in results]


# ---------------------------------------------------------------------------
# Feed delegation settings (creator only)
# ---------------------------------------------------------------------------


@router.get("/{creator_id}/settings", response_model=FeedDelegationSettingsOut)
async def get_settings(
    creator_id: str,
    user=Depends(require_ui_session),
):
    """Get feed delegation settings (creator only)."""
    if user["user_sub"] != creator_id:
        from fastapi import HTTPException
        raise HTTPException(403, "Only the creator can view feed delegation settings")
    item = svc.get_feed_delegation_settings(creator_id)
    return FeedDelegationSettingsOut(
        require_post_approval=bool(item.get("require_post_approval", False)),
        allow_delegate_scheduling=bool(item.get("allow_delegate_scheduling", True)),
        allow_delegate_locking=bool(item.get("allow_delegate_locking", False)),
        delegate_tag_on_posts=bool(item.get("delegate_tag_on_posts", False)),
        delegate_tag_format=item.get("delegate_tag_format", "[posted by @{delegate_name}]"),
    )


@router.put("/{creator_id}/settings", response_model=FeedDelegationSettingsOut)
async def update_settings(
    creator_id: str,
    body: FeedDelegationSettingsIn,
    user=Depends(require_ui_session),
):
    """Update feed delegation settings (creator only)."""
    if user["user_sub"] != creator_id:
        from fastapi import HTTPException
        raise HTTPException(403, "Only the creator can update feed delegation settings")
    item = svc.update_feed_delegation_settings(
        creator_id=creator_id,
        settings=body.model_dump(),
    )
    return FeedDelegationSettingsOut(
        require_post_approval=bool(item.get("require_post_approval", False)),
        allow_delegate_scheduling=bool(item.get("allow_delegate_scheduling", True)),
        allow_delegate_locking=bool(item.get("allow_delegate_locking", False)),
        delegate_tag_on_posts=bool(item.get("delegate_tag_on_posts", False)),
        delegate_tag_format=item.get("delegate_tag_format", "[posted by @{delegate_name}]"),
    )
