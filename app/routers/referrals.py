"""Referral & Affiliate System — API router (AFFILIATE-001)."""

from __future__ import annotations

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.services.sessions import require_ui_session
from app.core.settings import S
from app.services.referrals import (
    attribute_referral,
    create_referral_code,
    disable_referral_code,
    get_attribution,
    get_referral_dashboard,
    list_commissions,
    list_referral_codes,
    list_referrals,
    lookup_referral_code,
    record_affiliate_commission,
    withdraw,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/referrals", tags=["referrals"])


def _require_referral_enabled() -> None:
    if not S.referral_enabled:
        raise HTTPException(503, "Referral system is disabled")


# ── Code CRUD ────────────────────────────────────────────────────

@router.post("/code", status_code=201)
def create_code(ctx: dict = Depends(require_ui_session)):
    _require_referral_enabled()
    user_id = ctx["user_sub"]
    try:
        result = create_referral_code(user_id)
    except ValueError as exc:
        raise HTTPException(429, str(exc))
    return result


@router.get("/codes")
def get_codes(ctx: dict = Depends(require_ui_session)):
    _require_referral_enabled()
    return list_referral_codes(ctx["user_sub"])


@router.delete("/codes/{code}")
def deactivate_code(code: str, ctx: dict = Depends(require_ui_session)):
    _require_referral_enabled()
    ok = disable_referral_code(ctx["user_sub"], code)
    if not ok:
        raise HTTPException(404, "Code not found or not owned by you")
    return {"ok": True}


# ── Dashboard ────────────────────────────────────────────────────

@router.get("/dashboard")
def dashboard(ctx: dict = Depends(require_ui_session)):
    _require_referral_enabled()
    return get_referral_dashboard(ctx["user_sub"])


# ── Commission list ──────────────────────────────────────────────

@router.get("/commissions")
def commissions(
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    ctx: dict = Depends(require_ui_session),
):
    _require_referral_enabled()
    return list_commissions(ctx["user_sub"], limit=limit, cursor=cursor)


# ── Withdrawal (redeem available commission into wallet) ─────────

class WithdrawBody(BaseModel):
    amount_cents: int


@router.post("/withdraw", status_code=200)
def withdraw_commissions(body: WithdrawBody, ctx: dict = Depends(require_ui_session)):
    _require_referral_enabled()
    try:
        return withdraw(ctx["user_sub"], body.amount_cents)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))


# ── Attribution (who referred me?) ───────────────────────────────

@router.get("/attribution")
def attribution(ctx: dict = Depends(require_ui_session)):
    _require_referral_enabled()
    attr = get_attribution(ctx["user_sub"])
    if not attr:
        return {"referred_by": None}
    return {
        "referred_by": {
            "user_id": attr.get("referrer_user_id"),
            "attributed_at": attr.get("attributed_at"),
        }
    }


# ── My referrals list ────────────────────────────────────────────

@router.get("/referrals")
def my_referrals(ctx: dict = Depends(require_ui_session)):
    _require_referral_enabled()
    return list_referrals(ctx["user_sub"])


# ── Internal endpoints for billing / registration hooks ──────────

internal_router = APIRouter(prefix="/internal/referrals", tags=["referrals-internal"])


class AttributeBody(BaseModel):
    referred_user_id: str = ""
    referral_code: str = ""
    ip_address: str = ""


class CommissionBody(BaseModel):
    referred_user_id: str = ""
    transaction_id: str = ""
    source_type: str = ""
    gross_amount_cents: int = 0
    platform_fee_cents: int = 0


@internal_router.post("/attribute")
def internal_attribute(body: AttributeBody):
    """Called by registration flow to record referral attribution."""
    if not S.referral_enabled:
        return {"ok": False, "reason": "disabled"}
    if not body.referred_user_id or not body.referral_code:
        return {"ok": False, "reason": "missing_params"}
    result = attribute_referral(body.referred_user_id, body.referral_code, body.ip_address)
    if result is None:
        return {"ok": False, "reason": "blocked"}
    return {"ok": True, "attribution": result}


@internal_router.post("/commission")
def internal_commission(body: CommissionBody):
    """Called by billing services to record affiliate commission."""
    if not S.referral_enabled:
        return {"ok": False, "reason": "disabled"}
    result = record_affiliate_commission(
        referred_user_id=body.referred_user_id,
        transaction_id=body.transaction_id,
        source_type=body.source_type,
        gross_amount_cents=body.gross_amount_cents,
        platform_fee_cents=body.platform_fee_cents,
    )
    if result is None:
        return {"ok": False, "reason": "no_attribution"}
    return {"ok": True, "commission": result}
