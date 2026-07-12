"""OBP PAY-001 — Counterparty / beneficiary CRUD router.

Flag-gated default-OFF: every route 404s unless the umbrella OBP flag
(``open_bank_project_enabled``, owned by ACC) AND the PAY per-series flag
(``payments_counterparties_enabled``) are both on. Cookie-session auth + CSRF
(enforced by ``require_ui_session`` for non-GET per CLAUDE.md). Ownership is enforced
by the ``{user_sub, counterparty_id}`` access pattern → foreign id 404.
"""
from __future__ import annotations

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import (
    CounterpartyCreateIn,
    CounterpartyOut,
    CounterpartyUpdateIn,
)
from app.services import counterparties as svc
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

counterparties_router = APIRouter(prefix="/ui/counterparties", tags=["obp-payments"])


def _gate() -> None:
    if not (getattr(S, "open_bank_project_enabled", False) and S.payments_counterparties_enabled):
        raise HTTPException(404, "not found")


@counterparties_router.post("", response_model=CounterpartyOut, status_code=201)
async def create_counterparty(req: CounterpartyCreateIn, session: Dict = Depends(require_ui_session)):
    _gate()
    try:
        return svc.create_counterparty(session["user_sub"], req.model_dump())
    except svc.CounterpartyError as e:
        raise HTTPException(400, e.message)


@counterparties_router.get("", response_model=Dict)
async def list_counterparties(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session: Dict = Depends(require_ui_session),
):
    _gate()
    items, next_cursor = svc.list_counterparties(session["user_sub"], limit=limit, cursor=cursor)
    return {"counterparties": items, "cursor": next_cursor}


@counterparties_router.get("/{counterparty_id}", response_model=CounterpartyOut)
async def get_counterparty(counterparty_id: str, session: Dict = Depends(require_ui_session)):
    _gate()
    out = svc.get_counterparty_out(session["user_sub"], counterparty_id)
    if not out:
        raise HTTPException(404, "counterparty not found")
    return out


@counterparties_router.patch("/{counterparty_id}", response_model=CounterpartyOut)
async def update_counterparty(
    counterparty_id: str, req: CounterpartyUpdateIn, session: Dict = Depends(require_ui_session)
):
    _gate()
    out = svc.update_counterparty(session["user_sub"], counterparty_id, req.model_dump(exclude_unset=True))
    if not out:
        raise HTTPException(404, "counterparty not found")
    return out


@counterparties_router.delete("/{counterparty_id}")
async def delete_counterparty(counterparty_id: str, session: Dict = Depends(require_ui_session)):
    _gate()
    if not svc.delete_counterparty(session["user_sub"], counterparty_id):
        raise HTTPException(404, "counterparty not found")
    return {"ok": True}
