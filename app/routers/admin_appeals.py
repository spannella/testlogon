"""Admin appeals endpoints (MOD-003).

Provides admin/root access to the appeals queue: listing, detail,
claiming, and recording decisions.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_scope
from app.auth.roles import AdminScope
from app.models import (
    AppealClaimOut,
    AppealDecisionIn,
    AppealDecisionOut,
    AppealDetailOut,
    AppealListOut,
    AppealOut,
    AppealQueueStatsOut,
)
from app.services.appeals import (
    claim_appeal,
    decide_appeal,
    get_appeal_detail,
    list_appeals_admin,
    get_appeal_queue_stats,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/admin/appeals", tags=["admin-appeals"])

require_content_moderation_admin = require_admin_scope(AdminScope.CONTENT_MODERATION)


@router.get("", response_model=AppealListOut)
async def list_appeals_queue(
    status: Optional[str] = Query(None, description="Filter by status"),
    assigned_admin: Optional[str] = Query(None, description="Filter by assigned admin"),
    limit: int = Query(25, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
):
    """List the appeals queue with optional filters."""
    result = list_appeals_admin(
        status=status,
        assigned_admin=assigned_admin,
        limit=limit,
        cursor=cursor,
    )
    return AppealListOut(
        items=[AppealOut(**i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
    )


@router.get("/stats", response_model=AppealQueueStatsOut)
async def queue_stats(
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
):
    """Get appeal queue statistics."""
    stats = get_appeal_queue_stats()
    return AppealQueueStatsOut(**stats)


@router.get("/{appeal_id}", response_model=AppealDetailOut)
async def get_appeal_detail_endpoint(
    appeal_id: str,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
):
    """Get full appeal detail for admin review."""
    detail = get_appeal_detail(appeal_id)
    if not detail:
        raise HTTPException(404, "Appeal not found")
    return AppealDetailOut(
        appeal=AppealOut(**detail["appeal"]),
        enforcement_record=detail.get("enforcement_record", {}),
        moderation_ticket=detail.get("moderation_ticket", {}),
        user_enforcement_history=detail.get("user_enforcement_history", []),
        user_appeal_history=[AppealOut(**a) for a in detail.get("user_appeal_history", [])],
    )


@router.post("/{appeal_id}/claim", response_model=AppealClaimOut)
async def claim_appeal_endpoint(
    appeal_id: str,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
):
    """Claim an appeal for review (atomic — fails if already claimed)."""
    try:
        result = claim_appeal(appeal_id, admin.sub)
    except ValueError as exc:
        msg = str(exc)
        if msg == "claim_failed":
            raise HTTPException(409, "Appeal is not in submitted status or was already claimed")
        raise HTTPException(400, msg)
    except Exception as exc:
        # Handle boto3 ConditionalCheckFailedException
        if "ConditionalCheckFailedException" in str(type(exc).__name__):
            raise HTTPException(409, "Appeal is not in submitted status or was already claimed")
        raise
    return result


@router.post("/{appeal_id}/decide", response_model=AppealDecisionOut)
async def decide_appeal_endpoint(
    appeal_id: str,
    body: AppealDecisionIn,
    admin: AuthenticatedUser = Depends(require_content_moderation_admin),
):
    """Record a decision on an appeal."""
    try:
        result = decide_appeal(
            appeal_id=appeal_id,
            decision=body.decision,
            decision_note=body.decision_note,
            admin_user_id=admin.sub,
            modified_enforcement_type=body.modified_enforcement_type,
            modified_duration_days=body.modified_duration_days,
        )
    except ValueError as exc:
        msg = str(exc)
        if msg == "appeal_not_found":
            raise HTTPException(404, "Appeal not found")
        elif msg == "invalid_status":
            raise HTTPException(409, "Appeal is not under review")
        raise HTTPException(400, msg)
    return result
