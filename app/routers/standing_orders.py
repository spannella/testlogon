"""OBP PAY-002 — Standing orders CRUD + lifecycle router. Flag-gated default-OFF."""
from __future__ import annotations

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import (
    StandingOrderCreateIn,
    StandingOrderOut,
    StandingOrderUpdateIn,
)
from app.services import standing_orders as svc
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

standing_orders_router = APIRouter(prefix="/ui/standing-orders", tags=["obp-payments"])


def _gate() -> None:
    if not (getattr(S, "open_bank_project_enabled", False) and S.payments_counterparties_enabled):
        raise HTTPException(404, "not found")


@standing_orders_router.post("", response_model=StandingOrderOut, status_code=201)
async def create_standing_order(req: StandingOrderCreateIn, session: Dict = Depends(require_ui_session)):
    _gate()
    try:
        return svc.create_standing_order(session["user_sub"], req.model_dump())
    except svc.StandingOrderError as e:
        code = 404 if e.code == "counterparty_not_found" else 400
        raise HTTPException(code, e.message)


@standing_orders_router.get("", response_model=Dict)
async def list_standing_orders(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session: Dict = Depends(require_ui_session),
):
    _gate()
    items, next_cursor = svc.list_standing_orders(session["user_sub"], limit=limit, cursor=cursor)
    return {"standing_orders": items, "cursor": next_cursor}


@standing_orders_router.get("/{standing_order_id}", response_model=StandingOrderOut)
async def get_standing_order(standing_order_id: str, session: Dict = Depends(require_ui_session)):
    _gate()
    out = svc.get_standing_order_out(session["user_sub"], standing_order_id)
    if not out:
        raise HTTPException(404, "standing order not found")
    return out


@standing_orders_router.patch("/{standing_order_id}", response_model=StandingOrderOut)
async def update_standing_order(
    standing_order_id: str, req: StandingOrderUpdateIn, session: Dict = Depends(require_ui_session)
):
    _gate()
    out = svc.update_standing_order(session["user_sub"], standing_order_id, req.model_dump(exclude_unset=True))
    if not out:
        raise HTTPException(404, "standing order not found")
    return out


@standing_orders_router.post("/{standing_order_id}/pause", response_model=StandingOrderOut)
async def pause_standing_order(standing_order_id: str, session: Dict = Depends(require_ui_session)):
    _gate()
    out = svc.pause(session["user_sub"], standing_order_id)
    if not out:
        raise HTTPException(404, "standing order not found")
    return out


@standing_orders_router.post("/{standing_order_id}/resume", response_model=StandingOrderOut)
async def resume_standing_order(standing_order_id: str, session: Dict = Depends(require_ui_session)):
    _gate()
    out = svc.resume(session["user_sub"], standing_order_id)
    if not out:
        raise HTTPException(404, "standing order not found")
    return out


@standing_orders_router.delete("/{standing_order_id}", response_model=StandingOrderOut)
async def cancel_standing_order(standing_order_id: str, session: Dict = Depends(require_ui_session)):
    _gate()
    out = svc.cancel(session["user_sub"], standing_order_id)
    if not out:
        raise HTTPException(404, "standing order not found")
    return out
