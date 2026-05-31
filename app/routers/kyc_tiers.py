"""KYC Tiered Verification Levels — router endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.services.sessions import require_ui_session
from app.auth.deps import require_root_session
from app.services.kyc_tiers import (
    get_tier_details,
    check_tier_requirements,
    auto_evaluate_tier,
    upgrade_tier,
    list_users_by_tier,
    KYC_TIER_MAX,
)

router = APIRouter(prefix="/v1/kyc/tiers", tags=["kyc-tiers"])


# ── Request models ──────────────────────────────────────────────────

class TierOverrideRequest(BaseModel):
    tier: int = Field(ge=0, le=4)
    reason: str = Field(min_length=5, max_length=500)


# ── User endpoints ──────────────────────────────────────────────────

@router.get("/me")
async def get_my_tier(ctx: dict = Depends(require_ui_session)):
    return get_tier_details(ctx["user_sub"])


@router.get("/me/requirements/{target_tier}")
async def check_my_requirements(target_tier: int, ctx: dict = Depends(require_ui_session)):
    if target_tier < 0 or target_tier > KYC_TIER_MAX:
        raise HTTPException(400, "target_tier must be 0-4")
    return check_tier_requirements(ctx["user_sub"], target_tier)


@router.post("/me/evaluate")
async def evaluate_my_tier(request: Request, ctx: dict = Depends(require_ui_session)):
    return auto_evaluate_tier(ctx["user_sub"], request=request)


# ── Admin endpoints ─────────────────────────────────────────────────

@router.get("/admin/{user_sub}")
async def admin_get_user_tier(user_sub: str, user=Depends(require_root_session)):
    return get_tier_details(user_sub)


@router.post("/admin/{user_sub}/override")
async def admin_override_tier(
    user_sub: str,
    body: TierOverrideRequest,
    request: Request,
    user=Depends(require_root_session),
):
    return upgrade_tier(
        user_sub=user_sub,
        new_tier=body.tier,
        reason=body.reason,
        actor_sub=user.sub,
        request=request,
    )


@router.get("/admin/by-tier/{tier}")
async def admin_list_by_tier(tier: int, user=Depends(require_root_session)):
    if tier < 0 or tier > KYC_TIER_MAX:
        raise HTTPException(400, "tier must be 0-4")
    users = list_users_by_tier(tier)
    return {"tier": tier, "users": users}
