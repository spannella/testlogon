"""RPT-008 — Saved searches router.

Endpoints:
  POST   /ui/crm/saved-searches
  GET    /ui/crm/saved-searches
  GET    /ui/crm/saved-searches/{id}
  PATCH  /ui/crm/saved-searches/{id}
  DELETE /ui/crm/saved-searches/{id}
  POST   /ui/crm/saved-searches/{id}/run
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/crm/saved-searches", tags=["crm-saved-searches"])


def _require_flag() -> None:
    if not S.crm_reports_enabled:
        raise HTTPException(status_code=404, detail="Not found")


@router.post("", status_code=201)
async def create_saved_search(body: Any, ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.models import SavedSearchCreateIn
    from app.services.crm_saved_searches import create_saved_search as _create
    payload = SavedSearchCreateIn.model_validate(body) if not hasattr(body, "model_dump") else body
    return _create(ctx["user_sub"], payload)


@router.get("")
async def list_saved_searches(
    cursor: Optional[str] = Query(None),
    ctx: dict = Depends(require_ui_session),
) -> Any:
    _require_flag()
    from app.services.crm_saved_searches import list_saved_searches as _list
    items, next_cursor = _list(ctx["user_sub"], cursor=cursor)
    return {"items": items, "cursor": next_cursor}


@router.post("/{sid}/run", status_code=200)
async def run_saved_search(sid: str, ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.services.crm_saved_searches import run_saved_search as _run
    return await asyncio.to_thread(_run, sid, ctx["user_sub"])


@router.get("/{sid}")
async def get_saved_search(sid: str, ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.services.crm_saved_searches import get_saved_search as _get
    return _get(sid, ctx["user_sub"])


@router.patch("/{sid}")
async def update_saved_search(sid: str, body: Any, ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.models import SavedSearchUpdateIn
    from app.services.crm_saved_searches import update_saved_search as _update
    patch = SavedSearchUpdateIn.model_validate(body) if not hasattr(body, "model_dump") else body
    return _update(sid, ctx["user_sub"], patch)


@router.delete("/{sid}")
async def delete_saved_search(sid: str, ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.services.crm_saved_searches import delete_saved_search as _delete
    _delete(sid, ctx["user_sub"])
    return {"ok": True}
