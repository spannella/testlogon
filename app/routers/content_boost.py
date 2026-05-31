# app/routers/content_boost.py
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    ContentBoostCancelOut,
    ContentBoostCreate,
    ContentBoostListOut,
    ContentBoostOut,
    ContentBoostSpendOut,
)
from app.services import content_boost as svc
from app.services.sessions import require_ui_session

content_boost_router = APIRouter(prefix="/ui/ads/boost", tags=["content-boost"])


@content_boost_router.post("", response_model=ContentBoostOut)
async def create_boost(
    body: ContentBoostCreate,
    sess: dict = Depends(require_ui_session),
):
    user_sub = sess["user_sub"]
    try:
        return svc.create_boost(
            user_sub,
            content_type=body.content_type,
            content_id=body.content_id,
            budget_cents=body.budget_cents,
            duration_seconds=body.duration_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@content_boost_router.get("", response_model=ContentBoostListOut)
async def list_boosts(
    sess: dict = Depends(require_ui_session),
    active_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
):
    user_sub = sess["user_sub"]
    boosts = svc.list_boosts(user_sub, active_only=active_only, limit=limit)
    return {"boosts": boosts}


@content_boost_router.get("/{boost_id}", response_model=ContentBoostOut)
async def get_boost(
    boost_id: str,
    sess: dict = Depends(require_ui_session),
):
    user_sub = sess["user_sub"]
    boost = svc.get_boost(boost_id)
    if not boost:
        raise HTTPException(status_code=404, detail="boost not found")
    if boost["owner_sub"] != user_sub:
        raise HTTPException(status_code=403, detail="not the owner of this boost")
    return boost


@content_boost_router.get("/{boost_id}/spend", response_model=ContentBoostSpendOut)
async def get_boost_spend(
    boost_id: str,
    sess: dict = Depends(require_ui_session),
):
    user_sub = sess["user_sub"]
    raw = svc.get_boost(boost_id)
    if not raw:
        raise HTTPException(status_code=404, detail="boost not found")
    if raw["owner_sub"] != user_sub:
        raise HTTPException(status_code=403, detail="not the owner of this boost")
    return svc.get_spend(boost_id)


@content_boost_router.post("/{boost_id}/cancel", response_model=ContentBoostCancelOut)
async def cancel_boost(
    boost_id: str,
    sess: dict = Depends(require_ui_session),
):
    user_sub = sess["user_sub"]
    try:
        return svc.cancel_boost(user_sub, boost_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        # "boost not found" -> 404, anything else -> 400
        if "not found" in str(exc):
            raise HTTPException(status_code=404, detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc))
