"""
Promo Codes & Coupons router (PROMO-001).

Creator management endpoints and customer validation endpoint.
Auth: require_ui_session (cookie-based) for all endpoints.
"""
from __future__ import annotations

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from app.core.settings import S
from app.models import (
    PromoCodeCreateIn,
    PromoCodeListOut,
    PromoCodeOut,
    PromoCodeStatsOut,
    PromoCodeUpdateIn,
    PromoDeactivateOut,
    PromoValidateIn,
    PromoValidateOut,
)
from app.services.promo_codes import (
    create_promo_code,
    deactivate_promo_code,
    get_promo_code,
    get_promo_stats,
    list_promo_codes,
    redeem_promo_code,
    update_promo_code,
    validate_promo_code,
    _item_to_out,
)
from app.services.sessions import require_ui_session

router = APIRouter(tags=["promo-codes"])


def _require_enabled() -> None:
    if not S.promo_codes_enabled:
        raise HTTPException(status_code=404, detail="Promo codes are not enabled")


# ─── Creator CRUD ─────────────────────────────────────────────────


@router.post("/ui/promo-codes", response_model=PromoCodeOut, status_code=201)
async def create_code(
    body: PromoCodeCreateIn,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    creator_id = ctx["user_sub"]
    item, err = create_promo_code(
        creator_id=creator_id,
        code=body.code,
        discount_type=body.discount_type,
        discount_value=body.discount_value,
        free_trial_days=body.free_trial_days,
        applies_to=body.applies_to,
        min_purchase_cents=body.min_purchase_cents,
        max_uses=body.max_uses,
        max_uses_per_user=body.max_uses_per_user,
        expires_at=body.expires_at,
    )
    if err:
        # Duplicate code → 409, everything else → 400
        status = 409 if "already exists" in err else 400
        raise HTTPException(status_code=status, detail=err)
    return PromoCodeOut(**_item_to_out(item))


@router.get("/ui/promo-codes", response_model=PromoCodeListOut)
async def list_codes(
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    creator_id = ctx["user_sub"]
    items = list_promo_codes(creator_id)
    return PromoCodeListOut(items=[PromoCodeOut(**_item_to_out(i)) for i in items])


@router.get("/ui/promo-codes/{code_id}", response_model=PromoCodeStatsOut)
async def get_code_stats(
    code_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    creator_id = ctx["user_sub"]
    item = get_promo_code(code_id)
    if not item:
        raise HTTPException(status_code=404, detail="Promo code not found")
    if item["creator_user_id"] != creator_id:
        raise HTTPException(status_code=403, detail="Not your promo code")
    stats = get_promo_stats(code_id)
    out = _item_to_out(item)
    out["stats"] = stats
    return PromoCodeStatsOut(**out)


@router.patch("/ui/promo-codes/{code_id}", response_model=PromoCodeOut)
async def patch_code(
    code_id: str,
    body: PromoCodeUpdateIn,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    creator_id = ctx["user_sub"]
    item, err = update_promo_code(
        code_id=code_id,
        creator_id=creator_id,
        active=body.active,
        expires_at=body.expires_at,
        max_uses=body.max_uses,
    )
    if err:
        status = 404 if "not found" in err.lower() else 400
        raise HTTPException(status_code=status, detail=err)
    return PromoCodeOut(**_item_to_out(item))


@router.delete("/ui/promo-codes/{code_id}", response_model=PromoDeactivateOut)
async def delete_code(
    code_id: str,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    creator_id = ctx["user_sub"]
    item, err = deactivate_promo_code(code_id, creator_id)
    if err:
        status = 404 if "not found" in err.lower() else 400
        raise HTTPException(status_code=status, detail=err)
    return PromoDeactivateOut(ok=True, code_id=code_id, active=False)


# ─── Customer validation ──────────────────────────────────────────


@router.post("/ui/promo-codes/validate", response_model=PromoValidateOut)
async def validate_code(
    body: PromoValidateIn,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    user_id = ctx["user_sub"]
    result = validate_promo_code(
        code=body.code,
        user_id=user_id,
        checkout_type=body.checkout_type,
        item_price_cents=body.item_price_cents,
        creator_user_id=body.creator_user_id,
    )
    return PromoValidateOut(**result)


# ─── Internal redemption (called from billing flows) ─────────────


@router.post("/ui/promo-codes/redeem")
async def redeem_code(
    body: dict,
    ctx: Dict = Depends(require_ui_session),
):
    """Record a redemption after payment. Typically called internally."""
    _require_enabled()
    code_id = body.get("code_id", "")
    if not code_id:
        raise HTTPException(status_code=400, detail="code_id is required")
    user_id = ctx["user_sub"]
    item, err = redeem_promo_code(
        code_id=code_id,
        user_id=user_id,
        original_price_cents=body.get("original_price_cents", 0),
        final_price_cents=body.get("final_price_cents", 0),
        checkout_type=body.get("checkout_type", ""),
        checkout_item_id=body.get("checkout_item_id", ""),
    )
    if err:
        raise HTTPException(status_code=400, detail=err)
    return {"ok": True, "redeemed_at": item.get("redeemed_at", 0)}
