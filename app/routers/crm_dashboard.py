"""RPT-006 — Per-user configurable home dashboard router.

Endpoints:
  GET    /ui/crm/dashboard
  PATCH  /ui/crm/dashboard
  POST   /ui/crm/dashboard/dashlets
  POST   /ui/crm/dashboard/dashlets/reorder
  DELETE /ui/crm/dashboard/dashlets/{dashlet_id}
  GET    /ui/crm/dashboard/dashlets/{dashlet_id}/data   (RPT-007)
"""
from __future__ import annotations

from typing import Any, List

from fastapi import APIRouter, Body, Depends, HTTPException

from app.core.settings import S
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/crm", tags=["crm-dashboard"])


def _require_flag() -> None:
    if not S.crm_reports_enabled:
        raise HTTPException(status_code=404, detail="Not found")


@router.get("/dashboard")
async def get_dashboard(ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.services.crm_dashboard import get_or_create_default_dashboard
    return get_or_create_default_dashboard(ctx["user_sub"])


@router.patch("/dashboard")
async def patch_dashboard(body: Any = Body(...), ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.models import DashboardUpdateIn
    from app.services.crm_dashboard import update_dashboard
    patch = DashboardUpdateIn.model_validate(body) if not hasattr(body, "model_dump") else body
    return update_dashboard(ctx["user_sub"], patch)


@router.post("/dashboard/dashlets")
async def add_dashlet(body: Any = Body(...), ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.models import DashletAddIn
    from app.services.crm_dashboard import add_dashlet as _add
    payload = DashletAddIn.model_validate(body) if not hasattr(body, "model_dump") else body
    return _add(ctx["user_sub"], payload)


@router.post("/dashboard/dashlets/reorder")
async def reorder_dashlets(body: Any = Body(...), ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.models import DashletReorderIn
    from app.services.crm_dashboard import reorder_dashlets as _reorder
    payload = DashletReorderIn.model_validate(body) if not hasattr(body, "model_dump") else body
    return _reorder(ctx["user_sub"], payload.dashlet_ids)


@router.get("/dashboard/dashlets/{dashlet_id}/data")
async def get_dashlet_data(dashlet_id: str, ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    import asyncio
    from app.services.crm_dashlet_data import get_dashlet_data as _get_data
    return await asyncio.to_thread(_get_data, ctx["user_sub"], dashlet_id)


@router.delete("/dashboard/dashlets/{dashlet_id}")
async def remove_dashlet(dashlet_id: str, ctx: dict = Depends(require_ui_session)) -> Any:
    _require_flag()
    from app.services.crm_dashboard import remove_dashlet as _remove
    return _remove(ctx["user_sub"], dashlet_id)
