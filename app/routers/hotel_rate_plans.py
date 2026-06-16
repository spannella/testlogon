"""Hotel nightly rate-plan router (Hotel-PMS vertical, HTL-016).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF). Every handler
calls ``_require_enabled()`` first; when the flag is off all endpoints
return 404 and the platform is byte-for-byte unchanged (router still
mounted, just like inventory_router is always mounted).

Auth split (mirrors app/routers/inventory.py:37,48,65,81):
  * Read endpoints + /quote → ``require_ui_session``     (any authenticated user)
  * Write endpoints         → ``require_admin_or_root_csrf`` (ADMIN | ROOT + CSRF)

Route-declaration order (FastAPI path-param capture gotcha, CLAUDE.md):
  Literal collection routes (/{hotel_id}/rate-plans) declared BEFORE the
  dynamic /{hotel_id}/room-types/{rt}/... routes, and /quote is the last
  segment under {rt} so it is never captured as a sub-resource id.

SECOPS-007: no ``if S.dev_mode`` branch anywhere in this file.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    NightLineOut,
    RatePlanIn,
    RatePlanOut,
    RatePlanRuleIn,
    RatePlanRuleOut,
    RatePlanUpdateIn,
    StayQuoteIn,
    StayQuoteOut,
)
from app.services import hotel_rate_plans as rp
from app.services.sessions import require_ui_session

hotel_rate_plans_router = APIRouter(prefix="/ui/hotels", tags=["hotel-rate-plans"])


def _require_enabled() -> None:
    rp._require_enabled()


# ────────────── literal collection routes (declared first) ──────────────────


@hotel_rate_plans_router.get("/{hotel_id}/rate-plans")
async def list_rate_plans(
    hotel_id: str,
    cursor: Optional[str] = None,
    limit: int = 50,
    session=Depends(require_ui_session),
) -> dict:
    _require_enabled()
    return rp.list_rate_plans(hotel_id, cursor=cursor, limit=limit)


@hotel_rate_plans_router.post("/{hotel_id}/rate-plans", response_model=RatePlanOut, status_code=201)
async def create_rate_plan(
    hotel_id: str,
    body: RatePlanIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RatePlanOut:
    _require_enabled()
    item = rp.create_rate_plan(
        hotel_id,
        body.room_type_id,
        name=body.name,
        base_nightly_rate_cents=body.base_nightly_rate_cents,
        base_occupancy=body.base_occupancy,
        currency=body.currency,
        user_sub=user.sub,
    )
    return RatePlanOut(**item)


# ──────────────── dynamic room-type routes (declared after collection) ───────


@hotel_rate_plans_router.get(
    "/{hotel_id}/room-types/{rt}/rate-plan",
    response_model=RatePlanOut,
)
async def get_rate_plan(
    hotel_id: str,
    rt: str,
    session=Depends(require_ui_session),
) -> RatePlanOut:
    _require_enabled()
    item = rp.get_rate_plan(hotel_id, rt)
    if item is None:
        raise HTTPException(status_code=404, detail="Rate plan not found")
    return RatePlanOut(**item)


@hotel_rate_plans_router.put(
    "/{hotel_id}/room-types/{rt}/rate-plan",
    response_model=RatePlanOut,
)
async def update_rate_plan(
    hotel_id: str,
    rt: str,
    body: RatePlanUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RatePlanOut:
    _require_enabled()
    kwargs = {k: v for k, v in body.model_dump().items() if v is not None}
    item = rp.update_rate_plan(hotel_id, rt, user_sub=user.sub, **kwargs)
    return RatePlanOut(**item)


@hotel_rate_plans_router.delete(
    "/{hotel_id}/room-types/{rt}/rate-plan",
    response_model=RatePlanOut,
)
async def deactivate_rate_plan(
    hotel_id: str,
    rt: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RatePlanOut:
    _require_enabled()
    item = rp.deactivate_rate_plan(hotel_id, rt, user_sub=user.sub)
    return RatePlanOut(**item)


@hotel_rate_plans_router.get(
    "/{hotel_id}/room-types/{rt}/rate-plan/rules",
    response_model=List[RatePlanRuleOut],
)
async def list_rules(
    hotel_id: str,
    rt: str,
    session=Depends(require_ui_session),
) -> List[RatePlanRuleOut]:
    _require_enabled()
    return [RatePlanRuleOut(**r) for r in rp.list_rules(hotel_id, rt)]


@hotel_rate_plans_router.post(
    "/{hotel_id}/room-types/{rt}/rate-plan/rules",
    response_model=RatePlanRuleOut,
    status_code=201,
)
async def add_rule(
    hotel_id: str,
    rt: str,
    body: RatePlanRuleIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RatePlanRuleOut:
    _require_enabled()
    rc = body.rule_config.model_dump() if hasattr(body.rule_config, "model_dump") else body.rule_config
    item = rp.add_rule(
        hotel_id,
        rt,
        kind=body.kind,
        rule_config=rc,
        priority=body.priority,
        user_sub=user.sub,
    )
    return RatePlanRuleOut(**item)


@hotel_rate_plans_router.put(
    "/{hotel_id}/room-types/{rt}/rate-plan/rules/{rule_id}",
    response_model=RatePlanRuleOut,
)
async def update_rule(
    hotel_id: str,
    rt: str,
    rule_id: str,
    body: RatePlanRuleIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> RatePlanRuleOut:
    _require_enabled()
    rc = body.rule_config.model_dump() if hasattr(body.rule_config, "model_dump") else body.rule_config
    item = rp.update_rule(
        hotel_id,
        rt,
        rule_id,
        body.kind,
        rule_config=rc,
        priority=body.priority,
        user_sub=user.sub,
    )
    return RatePlanRuleOut(**item)


@hotel_rate_plans_router.delete(
    "/{hotel_id}/room-types/{rt}/rate-plan/rules/{rule_id}",
)
async def delete_rule(
    hotel_id: str,
    rt: str,
    rule_id: str,
    kind: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> dict:
    _require_enabled()
    if kind not in ("season", "occupancy", "los", "advance", "weekend"):
        raise HTTPException(status_code=422, detail="invalid rule kind")
    ok = rp.delete_rule(hotel_id, rt, rule_id, kind, user_sub=user.sub)
    return {"ok": ok}


# ─── /quote — literal last segment under {rt}; declared after all /rules routes ──


@hotel_rate_plans_router.post(
    "/{hotel_id}/room-types/{rt}/quote",
    response_model=StayQuoteOut,
)
async def quote_stay(
    hotel_id: str,
    rt: str,
    body: StayQuoteIn,
    session=Depends(require_ui_session),
) -> StayQuoteOut:
    _require_enabled()
    result = rp.compute_stay_price(
        hotel_id,
        rt,
        checkin=body.checkin,
        checkout=body.checkout,
        adults=body.adults,
        children=body.children,
        rooms=body.rooms,
        advance_days=body.advance_days,
    )
    return StayQuoteOut(
        nights=result.nights,
        per_night=[NightLineOut(**l.model_dump()) for l in result.per_night],
        stay_subtotal_cents=result.stay_subtotal_cents,
        los_discount_cents=result.los_discount_cents,
        advance_modifier_cents=result.advance_modifier_cents,
        rooms=result.rooms,
        total_cents=result.total_cents,
        currency=result.currency,
        applied_rule_ids=result.applied_rule_ids,
    )
