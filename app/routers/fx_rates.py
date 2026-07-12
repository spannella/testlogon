"""OBP PAY-004 — FX rate read + admin-set router. Flag-gated default-OFF.

``GET /ui/fx/rates`` + ``GET /ui/fx/convert`` are read-only (any session). The admin-set
``POST /ui/admin/fx/rates`` requires ADMIN/ROOT (``require_admin_or_root``) + CSRF.
"""
from __future__ import annotations

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.models import FxConvertOut, FxRateOut, FxRateSetIn
from app.services import fx_rates as svc
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

fx_rates_router = APIRouter(tags=["obp-payments"])


def _gate() -> None:
    if not (getattr(S, "open_bank_project_enabled", False) and S.payments_counterparties_enabled):
        raise HTTPException(404, "not found")


@fx_rates_router.get("/ui/fx/rates/{source}/{target}", response_model=FxRateOut)
async def get_fx_rate(source: str, target: str, session: Dict = Depends(require_ui_session)):
    _gate()
    rate = svc.get_rate(source, target)
    if not rate:
        raise HTTPException(404, "fx_rate_missing")
    return rate


@fx_rates_router.get("/ui/fx/convert", response_model=FxConvertOut)
async def convert_fx(
    amount_cents: int = Query(..., ge=0),
    from_: str = Query(..., alias="from"),
    to: str = Query(...),
    session: Dict = Depends(require_ui_session),
):
    _gate()
    try:
        return svc.convert(amount_cents, from_, to)
    except LookupError:
        raise HTTPException(404, "fx_rate_missing")


@fx_rates_router.post("/ui/admin/fx/rates", response_model=FxRateOut, status_code=201)
async def set_fx_rate(req: FxRateSetIn, request: Request, admin=Depends(require_admin_or_root)):
    _gate()
    try:
        return svc.set_rate(
            req.source_currency,
            req.target_currency,
            req.rate,
            source=req.source,
            set_by=getattr(admin, "sub", "") or "",
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
