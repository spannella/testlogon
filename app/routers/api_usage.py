from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query

from app.services.sessions import require_ui_session
from app.services.api_usage_metering import (
    _api_usage_table,
    get_api_usage_summary_for_period,
    list_api_usage_key_breakdown,
    list_api_usage_route_breakdown,
)

router = APIRouter(prefix="/ui/api-usage", tags=["api-usage"])

_PERIOD_RE = re.compile(r"^\d{4}-\d{2}$")


@router.get("/summary")
async def ui_api_usage_summary(period: str, ctx=Depends(require_ui_session)):
    if not _PERIOD_RE.match(period or ""):
        raise HTTPException(400, "period must be YYYY-MM")
    if int(period[5:7]) < 1 or int(period[5:7]) > 12:
        raise HTTPException(400, "period must be YYYY-MM")

    table = _api_usage_table()
    if table is None:
        return get_api_usage_summary_for_period(None, user_sub=ctx["user_sub"], period_id=period)
    return get_api_usage_summary_for_period(table, user_sub=ctx["user_sub"], period_id=period)


@router.get("/routes")
async def ui_api_usage_routes(
    period: str,
    sort_by: str = Query("cost_subtotal_micros"),
    order: str = Query("desc"),
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    ctx=Depends(require_ui_session),
):
    if not _PERIOD_RE.match(period or "") or int(period[5:7]) < 1 or int(period[5:7]) > 12:
        raise HTTPException(400, "period must be YYYY-MM")
    table = _api_usage_table()
    if table is None:
        return {"period": period, "items": [], "next_cursor": None, "count": 0, "total": 0}
    data = list_api_usage_route_breakdown(
        table,
        user_sub=ctx["user_sub"],
        period_id=period,
        search=search,
        sort_by=sort_by,
        order=order,
        limit=limit,
        cursor=cursor,
    )
    return {"period": period, **data}


@router.get("/keys")
async def ui_api_usage_keys(
    period: str,
    sort_by: str = Query("cost_subtotal_micros"),
    order: str = Query("desc"),
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    ctx=Depends(require_ui_session),
):
    if not _PERIOD_RE.match(period or "") or int(period[5:7]) < 1 or int(period[5:7]) > 12:
        raise HTTPException(400, "period must be YYYY-MM")
    table = _api_usage_table()
    if table is None:
        return {"period": period, "items": [], "next_cursor": None, "count": 0, "total": 0}
    data = list_api_usage_key_breakdown(
        table,
        user_sub=ctx["user_sub"],
        period_id=period,
        search=search,
        sort_by=sort_by,
        order=order,
        limit=limit,
        cursor=cursor,
    )
    return {"period": period, **data}
