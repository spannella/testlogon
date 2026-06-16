"""OBP Transaction Requests router (TXR-001..TXR-005).

Prefix ``/ui/txn-requests``. Cookie-auth (``require_ui_session``) with CSRF
enforced automatically for non-GET requests. Every handler is gated by the
effective enablement (umbrella ACC-001 flag AND per-series flag) — when off,
the service raises HTTPException(404), so the feature is invisible.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request

from app.core.settings import S
from app.models import TxnRequestCreateIn, TxnRequestListOut, TxnRequestOut
from app.services.sessions import require_ui_session
from app.services.txn_requests import (
    _require_enabled,
    create_request,
    execute_request,
    get_request,
    list_requests,
    _item_to_out,
)

router = APIRouter(prefix="/ui/txn-requests", tags=["txn-requests"])


@router.post("", status_code=201, response_model=TxnRequestOut)
async def create_txn_request(
    body: TxnRequestCreateIn,
    req: Request,
    ctx=Depends(require_ui_session),
) -> TxnRequestOut:
    _require_enabled()
    user_sub = ctx["user_sub"]
    return await asyncio.to_thread(create_request, user_sub, body, req)


@router.get("", response_model=TxnRequestListOut)
async def list_txn_requests(
    req: Request,
    status: Optional[str] = Query(default=None),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    ctx=Depends(require_ui_session),
) -> TxnRequestListOut:
    _require_enabled()
    user_sub = ctx["user_sub"]
    result = list_requests(user_sub, status, cursor, limit)
    return TxnRequestListOut(items=result["items"], next_cursor=result["next_cursor"])


@router.get("/{request_id}", response_model=TxnRequestOut)
async def get_txn_request(
    request_id: str,
    req: Request,
    ctx=Depends(require_ui_session),
) -> TxnRequestOut:
    _require_enabled()
    user_sub = ctx["user_sub"]
    item = get_request(user_sub, request_id)
    return _item_to_out(item)


@router.post("/{request_id}/execute", response_model=TxnRequestOut)
async def execute_txn_request(
    request_id: str,
    req: Request,
    ctx=Depends(require_ui_session),
) -> TxnRequestOut:
    _require_enabled()
    user_sub = ctx["user_sub"]
    return await asyncio.to_thread(execute_request, user_sub, request_id, req)
