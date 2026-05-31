"""Platform Financial Dashboard router (FIN-013).

Admin platform-wide financial aggregation over the existing billing
ledger. Read endpoints require ADMIN or ROOT; the manual rollup trigger
requires ROOT (so admins cannot force expensive scans / escalate).

Auth:
  - KPIs / trends / providers / types / top-creators / export: require_admin_or_root
  - Manual rollup trigger: require_root
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_root
from app.core.settings import S
from app.models import (
    PlatformFinancialKpis,
    PlatformFinancialProviderResponse,
    PlatformFinancialRollupIn,
    PlatformFinancialRollupOut,
    PlatformFinancialTopCreatorsResponse,
    PlatformFinancialTrendsResponse,
    PlatformFinancialTypeResponse,
)
from app.services import platform_financial_dashboard as svc

platform_financial_dashboard_router = APIRouter(
    prefix="/ui/admin/financial-dashboard",
    tags=["platform-financial-dashboard"],
)


def _check_enabled() -> None:
    if not S.platform_financial_dashboard_enabled:
        raise HTTPException(status_code=404, detail="Platform financial dashboard disabled")


def _validate_range(start_date: str, end_date: str) -> None:
    try:
        start = svc._parse_date(start_date)
        end = svc._parse_date(end_date)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "dates must be YYYY-MM-DD"},
        )
    if end < start:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "start_date must be before end_date"},
        )


# ---------------------------------------------------------------------------
# KPIs
# ---------------------------------------------------------------------------

@platform_financial_dashboard_router.get("/kpis", response_model=PlatformFinancialKpis)
async def get_kpis(
    start_date: str = Query(...),
    end_date: str = Query(...),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    _validate_range(start_date, end_date)
    return svc.get_kpis(start_date=start_date, end_date=end_date)


# ---------------------------------------------------------------------------
# Trends
# ---------------------------------------------------------------------------

@platform_financial_dashboard_router.get("/trends", response_model=PlatformFinancialTrendsResponse)
async def get_trends(
    start_date: str = Query(...),
    end_date: str = Query(...),
    granularity: str = Query(default="daily"),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    _validate_range(start_date, end_date)
    try:
        svc.validate_granularity(granularity)
    except ValueError as e:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": str(e)},
        )
    return svc.get_trends(start_date=start_date, end_date=end_date, granularity=granularity)


# ---------------------------------------------------------------------------
# Breakdowns
# ---------------------------------------------------------------------------

@platform_financial_dashboard_router.get("/providers", response_model=PlatformFinancialProviderResponse)
async def get_providers(
    start_date: str = Query(...),
    end_date: str = Query(...),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    _validate_range(start_date, end_date)
    return svc.get_provider_breakdown(start_date=start_date, end_date=end_date)


@platform_financial_dashboard_router.get("/types", response_model=PlatformFinancialTypeResponse)
async def get_types(
    start_date: str = Query(...),
    end_date: str = Query(...),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    _validate_range(start_date, end_date)
    return svc.get_type_breakdown(start_date=start_date, end_date=end_date)


@platform_financial_dashboard_router.get("/top-creators", response_model=PlatformFinancialTopCreatorsResponse)
async def get_top_creators(
    start_date: str = Query(...),
    end_date: str = Query(...),
    limit: int = Query(default=20, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    _validate_range(start_date, end_date)
    return svc.get_top_creators(start_date=start_date, end_date=end_date, limit=limit)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@platform_financial_dashboard_router.get("/export/csv")
async def export_csv(
    start_date: str = Query(...),
    end_date: str = Query(...),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    _check_enabled()
    _validate_range(start_date, end_date)
    body = svc.export_summary_csv(start_date=start_date, end_date=end_date)
    return PlainTextResponse(
        content=body,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="financials_{start_date}_{end_date}.csv"',
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# Manual rollup (ROOT only)
# ---------------------------------------------------------------------------

@platform_financial_dashboard_router.post("/rollup", response_model=PlatformFinancialRollupOut)
async def trigger_rollup(
    body: PlatformFinancialRollupIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_root),
):
    _check_enabled()
    date_str = body.date or svc.today_str()
    try:
        svc._parse_date(date_str)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "date must be YYYY-MM-DD"},
        )
    return svc.compute_daily_rollup(date_str)
