"""Creator Payout router (MON-004).

User-facing endpoints for payout balance, requests, cancellation, and listing.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.services.sessions import require_ui_session
from app.models import (
    PayoutBalanceOut,
    PayoutCreateOut,
    PayoutActionOut,
    PayoutListOut,
    PayoutOut,
    PayoutRequestIn,
)
from app.services.creator_payouts import (
    cancel_payout,
    get_available_balance,
    list_user_payouts,
    request_payout,
)
from app.core.settings import S

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/payouts", tags=["payouts"])


@router.get("/balance", response_model=PayoutBalanceOut)
def payout_balance(session=Depends(require_ui_session)):
    """Get available payout balance for the authenticated creator."""
    user_id = session["user_sub"]
    result = get_available_balance(user_id)
    return PayoutBalanceOut(
        available_cents=result["available_cents"],
        pending_cents=result["pending_cents"],
        total_earned_cents=result["total_earned_cents"],
        hold_cents=result["hold_cents"],
        currency="USD",
        minimum_payout_cents=S.payout_minimum_cents,
    )


@router.post("/request", response_model=PayoutCreateOut, status_code=201)
def create_payout_request(body: PayoutRequestIn, session=Depends(require_ui_session)):
    """Request a payout withdrawal."""
    user_id = session["user_sub"]
    try:
        result = request_payout(
            user_id,
            amount_cents=body.amount_cents,
            method=body.method,
            notes=body.notes,
        )
    except ValueError as exc:
        msg = str(exc)
        if "DUPLICATE_PAYOUT" in msg:
            raise HTTPException(status_code=409, detail="A payout request is already pending")
        if "Insufficient" in msg:
            raise HTTPException(status_code=400, detail=msg)
        if "at least" in msg:
            raise HTTPException(status_code=400, detail=msg)
        raise HTTPException(status_code=400, detail=msg)

    return PayoutCreateOut(
        ok=True,
        payout_id=result["payout_id"],
        amount_cents=result["amount_cents"],
        status=result["status"],
    )


@router.post("/{payout_id}/cancel", response_model=PayoutActionOut)
def cancel_payout_request(payout_id: str, session=Depends(require_ui_session)):
    """Cancel a payout request (creator only)."""
    user_id = session["user_sub"]
    try:
        result = cancel_payout(payout_id, user_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout not found")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Not your payout")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return PayoutActionOut(ok=True, payout_id=result["payout_id"], status=result["status"])


@router.get("", response_model=PayoutListOut)
def list_payouts(
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    """List the authenticated creator's payouts."""
    user_id = session["user_sub"]
    result = list_user_payouts(user_id, limit=limit, cursor=cursor)
    items = [PayoutOut(**item) for item in result["items"]]
    return PayoutListOut(items=items, next_cursor=result.get("next_cursor"))
