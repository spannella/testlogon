"""OBP PAY-003 — Direct-debit mandates CRUD + revoke router. Flag-gated default-OFF."""
from __future__ import annotations

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import MandateCreateIn, MandateOut
from app.services import direct_debit_mandates as svc
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

mandates_router = APIRouter(prefix="/ui/mandates", tags=["obp-payments"])


def _gate() -> None:
    if not (getattr(S, "open_bank_project_enabled", False) and S.payments_counterparties_enabled):
        raise HTTPException(404, "not found")


@mandates_router.post("", response_model=MandateOut, status_code=201)
async def create_mandate(req: MandateCreateIn, session: Dict = Depends(require_ui_session)):
    _gate()
    try:
        return svc.create_mandate(session["user_sub"], req.model_dump())
    except svc.MandateError as e:
        code = 404 if e.code == "counterparty_not_found" else 400
        raise HTTPException(code, e.message)


@mandates_router.get("", response_model=Dict)
async def list_mandates(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session: Dict = Depends(require_ui_session),
):
    _gate()
    items, next_cursor = svc.list_mandates(session["user_sub"], limit=limit, cursor=cursor)
    return {"mandates": items, "cursor": next_cursor}


@mandates_router.get("/{mandate_id}", response_model=MandateOut)
async def get_mandate(mandate_id: str, session: Dict = Depends(require_ui_session)):
    _gate()
    out = svc.get_mandate_out(session["user_sub"], mandate_id)
    if not out:
        raise HTTPException(404, "mandate not found")
    return out


@mandates_router.post("/{mandate_id}/revoke", response_model=MandateOut)
async def revoke_mandate(mandate_id: str, session: Dict = Depends(require_ui_session)):
    _gate()
    out = svc.revoke(session["user_sub"], mandate_id)
    if not out:
        raise HTTPException(404, "mandate not found")
    return out


@mandates_router.post("/{mandate_id}/pause", response_model=MandateOut)
async def pause_mandate(mandate_id: str, session: Dict = Depends(require_ui_session)):
    _gate()
    out = svc.pause(session["user_sub"], mandate_id)
    if not out:
        raise HTTPException(404, "mandate not found")
    return out
