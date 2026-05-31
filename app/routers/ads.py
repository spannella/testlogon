"""Advertiser ad analytics dashboard endpoints (ADS-008)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from app.services.sessions import require_ui_session
from app.services.ad_accounts import get_ad_account
from app.services.ad_analytics import (
    export_csv,
    get_breakdown,
    get_summary,
    get_timeseries,
)

router = APIRouter(prefix="/ui/ads", tags=["ads"])

_VALID_GRANULARITIES = {"hourly", "daily", "weekly", "monthly"}
_VALID_DIMENSIONS = {"creative", "surface", "targeting"}


# ── Helpers ────────────────────────────────────────────────────────


def _require_account_owner(account_id: str, user_sub: str) -> dict:
    acct = get_ad_account(account_id)
    if not acct or acct["owner_sub"] != user_sub:
        raise HTTPException(status_code=404, detail="Account not found")
    return acct


def _validate_days(days: int) -> None:
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="days must be between 1 and 365")


# ── Ad Analytics (ADS-008) ────────────────────────────────────────────


@router.get("/analytics/summary")
async def analytics_summary(
    account_id: str,
    campaign_id: Optional[str] = None,
    days: int = Query(default=30),
    ctx=Depends(require_ui_session),
):
    _validate_days(days)
    _require_account_owner(account_id, ctx["user_sub"])
    return get_summary(account_id, campaign_id, days)


@router.get("/analytics/timeseries")
async def analytics_timeseries(
    account_id: str,
    campaign_id: Optional[str] = None,
    days: int = Query(default=30),
    granularity: str = Query(default="daily"),
    ctx=Depends(require_ui_session),
):
    _validate_days(days)
    if granularity not in _VALID_GRANULARITIES:
        raise HTTPException(
            status_code=400,
            detail="Granularity must be hourly, daily, weekly, or monthly",
        )
    _require_account_owner(account_id, ctx["user_sub"])
    return get_timeseries(account_id, campaign_id, days, granularity)


@router.get("/analytics/breakdown")
async def analytics_breakdown(
    account_id: str,
    campaign_id: Optional[str] = None,
    dimension: str = Query(default="creative"),
    days: int = Query(default=30),
    ctx=Depends(require_ui_session),
):
    _validate_days(days)
    if dimension not in _VALID_DIMENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Dimension must be creative, surface, or targeting",
        )
    _require_account_owner(account_id, ctx["user_sub"])
    return get_breakdown(account_id, campaign_id, dimension, days)


@router.get("/analytics/export")
async def analytics_export(
    account_id: str,
    campaign_id: Optional[str] = None,
    days: int = Query(default=30),
    ctx=Depends(require_ui_session),
):
    _validate_days(days)
    _require_account_owner(account_id, ctx["user_sub"])
    csv_data = export_csv(account_id, campaign_id, days)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ad_analytics.csv"},
    )
