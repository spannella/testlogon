"""Admin Payout router (MON-004).

Admin/root endpoints for managing payout requests: listing, approving,
rejecting, completing, and viewing queue stats.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.models import (
    PayoutActionOut,
    PayoutListOut,
    PayoutOut,
    PayoutStatsOut,
)
from app.services.creator_payouts import (
    approve_payout,
    complete_payout,
    get_payout_stats,
    list_payouts_admin,
    reject_payout,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/admin/payouts", tags=["admin-payouts"])


@router.get("", response_model=PayoutListOut)
def list_payout_queue(
    status: Optional[str] = Query(None, description="Filter by payout status"),
    limit: int = Query(25, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List the payout queue with optional status filter."""
    result = list_payouts_admin(status=status, limit=limit, cursor=cursor)
    items = [PayoutOut(**item) for item in result["items"]]
    return PayoutListOut(items=items, next_cursor=result.get("next_cursor"))


@router.get("/stats", response_model=PayoutStatsOut)
def payout_queue_stats(
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Get payout queue statistics."""
    result = get_payout_stats()
    return PayoutStatsOut(**result)


@router.post("/{payout_id}/approve", response_model=PayoutActionOut)
def approve_payout_request(
    payout_id: str,
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Approve a payout request."""
    try:
        result = approve_payout(payout_id, admin.sub)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return PayoutActionOut(ok=True, payout_id=result["payout_id"], status=result["status"])


@router.post("/{payout_id}/reject", response_model=PayoutActionOut)
def reject_payout_request(
    payout_id: str,
    reason: str = "",
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Reject a payout request."""
    try:
        result = reject_payout(payout_id, admin.sub, reason=reason)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return PayoutActionOut(ok=True, payout_id=result["payout_id"], status=result["status"])


@router.post("/{payout_id}/complete", response_model=PayoutActionOut)
def complete_payout_request(
    payout_id: str,
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Mark a payout as completed."""
    try:
        result = complete_payout(payout_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return PayoutActionOut(ok=True, payout_id=result["payout_id"], status=result["status"])
