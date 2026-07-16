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
    PayoutMethodIn,
    PayoutMethodUpdateIn,
    PayoutMethodOut,
    PayoutMethodListOut,
    ConnectAccountOut,
    ConnectOnboardingOut,
)
from app.services.creator_payouts import (
    cancel_payout,
    get_available_balance,
    list_user_payouts,
    request_payout,
    list_payout_methods,
    add_payout_method,
    update_payout_method,
    delete_payout_method,
    set_default_payout_method,
    verify_payout_method,
    create_connect_account,
    create_connect_onboarding_link,
    get_connect_account,
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
            method_id=body.method_id,
        )
    except ValueError as exc:
        msg = str(exc)
        if "DUPLICATE_PAYOUT" in msg:
            raise HTTPException(status_code=409, detail="A payout request is already pending")
        if "invalid_method_id" in msg:
            raise HTTPException(status_code=400, detail=msg)
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


# ─── Payout Methods (GAP-0195 / FIN-009) ──────────────────────────────


def _method_error(exc: ValueError) -> HTTPException:
    code, _, msg = str(exc).partition(":")
    return HTTPException(status_code=400, detail={"code": code, "message": msg or code})


@router.get("/methods", response_model=PayoutMethodListOut)
def list_methods(session=Depends(require_ui_session)):
    """List the authenticated creator's payout methods."""
    items = list_payout_methods(session["user_sub"])
    return PayoutMethodListOut(methods=[PayoutMethodOut(**m) for m in items])


@router.post("/methods", response_model=PayoutMethodOut, status_code=201)
def add_method(body: PayoutMethodIn, session=Depends(require_ui_session)):
    """Add a payout destination (bank/PayPal/check). Only last-4 digits are stored."""
    try:
        result = add_payout_method(session["user_sub"], **body.model_dump())
    except ValueError as exc:
        raise _method_error(exc)
    return PayoutMethodOut(**result)


@router.put("/methods/{method_id}", response_model=PayoutMethodOut)
def update_method(method_id: str, body: PayoutMethodUpdateIn, session=Depends(require_ui_session)):
    """Update mutable fields of a payout method (nickname)."""
    try:
        result = update_payout_method(session["user_sub"], method_id, nickname=body.nickname)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout method not found")
    return PayoutMethodOut(**result)


@router.delete("/methods/{method_id}", status_code=204)
def delete_method(method_id: str, session=Depends(require_ui_session)):
    """Delete a payout method (refuses the default while other methods remain)."""
    try:
        delete_payout_method(session["user_sub"], method_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout method not found")
    except ValueError as exc:
        raise _method_error(exc)


@router.post("/methods/{method_id}/default", response_model=PayoutMethodOut)
def set_default_method(method_id: str, session=Depends(require_ui_session)):
    """Mark a payout method as the creator's default destination."""
    try:
        result = set_default_payout_method(session["user_sub"], method_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout method not found")
    return PayoutMethodOut(**result)



# ---------------------------------------------------------------------------
# PAY-B (PAY-11/12): routable-destination verification + Stripe Connect seam.
# ---------------------------------------------------------------------------


@router.post("/methods/{method_id}/verify", response_model=PayoutMethodOut)
def verify_method(method_id: str, session=Depends(require_ui_session)):
    """Verify a payout method (PAY-12). Mock -> verified; real when keyed.

    A payout can only target a verified method.
    """
    try:
        result = verify_payout_method(session["user_sub"], method_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Payout method not found")
    except ValueError as exc:
        raise _method_error(exc)
    return PayoutMethodOut(**result)


@router.get("/connect", response_model=ConnectAccountOut)
def get_connect(session=Depends(require_ui_session)):
    """Return the creator's Stripe Connect account status (creates none)."""
    acct = get_connect_account(session["user_sub"])
    if not acct:
        return ConnectAccountOut(
            connect_account_id="", onboarding_status="none", payouts_enabled=False
        )
    return ConnectAccountOut(
        connect_account_id=acct.get("connect_account_id", ""),
        onboarding_status=acct.get("onboarding_status", "pending"),
        payouts_enabled=bool(acct.get("payouts_enabled", False)),
    )


@router.post("/connect/account", response_model=ConnectAccountOut, status_code=201)
def create_connect(session=Depends(require_ui_session)):
    """Create (or return) the creator's Stripe Connect account id (PAY-11)."""
    acct = create_connect_account(session["user_sub"])
    return ConnectAccountOut(
        connect_account_id=acct.get("connect_account_id", ""),
        onboarding_status=acct.get("onboarding_status", "pending"),
        payouts_enabled=bool(acct.get("payouts_enabled", False)),
    )


@router.post("/connect/onboarding-link", response_model=ConnectOnboardingOut)
def connect_onboarding_link(session=Depends(require_ui_session)):
    """Return a Connect onboarding link (real AccountLink when keyed; mock
    onboarding-complete otherwise) (PAY-11)."""
    result = create_connect_onboarding_link(session["user_sub"])
    return ConnectOnboardingOut(**result)
