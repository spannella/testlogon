"""PMD-001 — Rent-policy router.

Prefix: /ui/rent-policy

Routes (ordered — /audit before /{owner_sub} to prevent FastAPI capture
of the literal string "audit" as an owner_sub path param):

  GET  /ui/rent-policy            → caller's own policy (require_ui_session)
  PUT  /ui/rent-policy            → upsert caller's policy (require_admin_or_root_csrf)
  GET  /ui/rent-policy/audit      → caller's audit log (require_ui_session)
  GET  /ui/rent-policy/{sub}      → admin read any owner's policy
  PUT  /ui/rent-policy/{sub}      → admin upsert any owner's policy
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

import app.services.rent_policy as rp
from app.models import RentPolicyOut, RentPolicyUpdateIn, RentPolicyAuditOut
from app.services.sessions import require_ui_session
from app.auth.policy import require_admin_or_root_csrf

rent_policy_router = APIRouter(prefix="/ui/rent-policy", tags=["rent-policy"])


@rent_policy_router.get("", response_model=RentPolicyOut)
async def get_my_policy(session=Depends(require_ui_session)):
    """Return the effective rent policy for the authenticated user (landlord)."""
    try:
        return RentPolicyOut(**rp.get_policy(session["user_sub"]))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@rent_policy_router.put("", response_model=RentPolicyOut)
async def set_my_policy(
    body: RentPolicyUpdateIn,
    user=Depends(require_admin_or_root_csrf),
):
    """Upsert the rent policy for the authenticated admin/root user."""
    actor = user.sub if hasattr(user, "sub") else user["user_sub"]
    try:
        return RentPolicyOut(**rp.set_policy(
            actor,
            rent_due_day=body.rent_due_day,
            late_fee_cents=body.late_fee_cents,
            grace_period_days=body.grace_period_days,
            currency=body.currency,
            actor_sub=actor,
        ))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@rent_policy_router.get("/audit", response_model=RentPolicyAuditOut)
async def get_my_policy_audit(
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
    session=Depends(require_ui_session),
):
    """Return paginated audit log for the authenticated user's rent policy."""
    return rp.list_policy_audit(session["user_sub"], limit=limit, cursor=cursor)


@rent_policy_router.get("/{owner_sub}", response_model=RentPolicyOut)
async def admin_get_policy(
    owner_sub: str,
    user=Depends(require_admin_or_root_csrf),
):
    """Admin: read any owner's rent policy."""
    return RentPolicyOut(**rp.get_policy(owner_sub))


@rent_policy_router.put("/{owner_sub}", response_model=RentPolicyOut)
async def admin_set_policy(
    owner_sub: str,
    body: RentPolicyUpdateIn,
    user=Depends(require_admin_or_root_csrf),
):
    """Admin: upsert any owner's rent policy."""
    actor = user.sub if hasattr(user, "sub") else user["user_sub"]
    try:
        return RentPolicyOut(**rp.set_policy(
            owner_sub,
            rent_due_day=body.rent_due_day,
            late_fee_cents=body.late_fee_cents,
            grace_period_days=body.grace_period_days,
            currency=body.currency,
            actor_sub=actor,
        ))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
