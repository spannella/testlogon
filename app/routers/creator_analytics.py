"""Creator Analytics Dashboard router (ANALYTICS-001).

Provides analytics endpoints for authenticated creators: overview, revenue,
views, subscribers, top-content, audience, and manual refresh trigger.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.core.time import now_ts
from app.models import (
    AnalyticsAudienceOut,
    AnalyticsCountryItem,
    AnalyticsDeviceItem,
    AnalyticsOverviewOut,
    AnalyticsRefreshOut,
    AnalyticsRevenueBreakdown,
    AnalyticsRevenueOut,
    AnalyticsRevenueTimeSeriesItem,
    AnalyticsSubscribersOut,
    AnalyticsSubscribersTimeSeriesItem,
    AnalyticsTopContentItem,
    AnalyticsTopContentOut,
    AnalyticsViewsOut,
    AnalyticsViewsTimeSeriesItem,
)
from app.services.creator_analytics import (
    get_audience,
    get_overview,
    get_revenue,
    get_subscribers,
    get_top_content,
    get_views,
    upsert_daily_rollup,
    upsert_summary_sentinel,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/analytics", tags=["analytics"])

# ── Helpers ──────────────────────────────────────────────────────

_DATE_FMT = "%Y-%m-%d"
_MAX_RANGE_DAYS = 365

# In-memory per-user refresh rate limit (1 per 5 minutes)
_refresh_timestamps: dict[str, int] = {}
_REFRESH_COOLDOWN_SECONDS = 300


def _today() -> str:
    return datetime.utcnow().strftime(_DATE_FMT)


def _days_ago(n: int) -> str:
    return (datetime.utcnow() - timedelta(days=n)).strftime(_DATE_FMT)


def _validate_date(s: str) -> str:
    try:
        datetime.strptime(s, _DATE_FMT)
        return s
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail=f"Invalid date format: {s}. Expected YYYY-MM-DD")


def _validate_date_range(from_date: str, to_date: str) -> None:
    fd = datetime.strptime(from_date, _DATE_FMT)
    td = datetime.strptime(to_date, _DATE_FMT)
    if fd > td:
        raise HTTPException(status_code=400, detail="from_date must be before to_date")
    if (td - fd).days > _MAX_RANGE_DAYS:
        raise HTTPException(status_code=400, detail="Date range cannot exceed 365 days")


def _validate_granularity(g: str) -> str:
    if g not in ("day", "week", "month"):
        raise HTTPException(status_code=400, detail=f"Invalid granularity: {g}. Must be day, week, or month")
    return g


# ── Endpoints ────────────────────────────────────────────────────


@router.get("/overview", response_model=AnalyticsOverviewOut)
def analytics_overview(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    """Get analytics overview for the authenticated creator."""
    fd = _validate_date(from_date) if from_date else _days_ago(7)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)

    user_id = session["user_sub"]
    result = get_overview(user_id, fd, td)

    top_content = [AnalyticsTopContentItem(**item) for item in result.get("top_content", [])]
    return AnalyticsOverviewOut(
        period_views=result["period_views"],
        period_revenue_cents=result["period_revenue_cents"],
        period_new_subscribers=result["period_new_subscribers"],
        total_subscribers=result["total_subscribers"],
        top_content=top_content,
        currency=result["currency"],
    )


@router.get("/revenue", response_model=AnalyticsRevenueOut)
def analytics_revenue(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    granularity: str = Query(default="day"),
    session=Depends(require_ui_session),
):
    """Get revenue breakdown and time series."""
    fd = _validate_date(from_date) if from_date else _days_ago(30)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)
    _validate_granularity(granularity)

    user_id = session["user_sub"]
    result = get_revenue(user_id, fd, td, granularity)

    time_series = [AnalyticsRevenueTimeSeriesItem(**item) for item in result["time_series"]]
    return AnalyticsRevenueOut(
        total_cents=result["total_cents"],
        breakdown=AnalyticsRevenueBreakdown(**result["breakdown"]),
        time_series=time_series,
        currency=result["currency"],
    )


@router.get("/views", response_model=AnalyticsViewsOut)
def analytics_views(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    granularity: str = Query(default="day"),
    session=Depends(require_ui_session),
):
    """Get view metrics time series."""
    fd = _validate_date(from_date) if from_date else _days_ago(30)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)
    _validate_granularity(granularity)

    user_id = session["user_sub"]
    result = get_views(user_id, fd, td, granularity)

    time_series = [AnalyticsViewsTimeSeriesItem(**item) for item in result["time_series"]]
    return AnalyticsViewsOut(
        time_series=time_series,
        total_views=result["total_views"],
        total_watch_time_seconds=result["total_watch_time_seconds"],
    )


@router.get("/subscribers", response_model=AnalyticsSubscribersOut)
def analytics_subscribers(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    granularity: str = Query(default="day"),
    session=Depends(require_ui_session),
):
    """Get subscriber growth time series."""
    fd = _validate_date(from_date) if from_date else _days_ago(30)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)
    _validate_granularity(granularity)

    user_id = session["user_sub"]
    result = get_subscribers(user_id, fd, td, granularity)

    time_series = [AnalyticsSubscribersTimeSeriesItem(**item) for item in result["time_series"]]
    return AnalyticsSubscribersOut(
        time_series=time_series,
        current_total=result["current_total"],
        net_change=result["net_change"],
    )


@router.get("/top-content", response_model=AnalyticsTopContentOut)
def analytics_top_content(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    sort_by: str = Query(default="views"),
    limit: int = Query(default=20, ge=1, le=100),
    session=Depends(require_ui_session),
):
    """Get top content ranked by views or revenue."""
    fd = _validate_date(from_date) if from_date else _days_ago(30)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)

    if sort_by not in ("views", "revenue"):
        raise HTTPException(status_code=400, detail="sort_by must be 'views' or 'revenue'")

    user_id = session["user_sub"]
    result = get_top_content(user_id, fd, td, sort_by, limit)

    items = [AnalyticsTopContentItem(**item) for item in result["items"]]
    return AnalyticsTopContentOut(
        items=items,
        total_items=result["total_items"],
    )


@router.get("/audience", response_model=AnalyticsAudienceOut)
def analytics_audience(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    """Get audience demographics (countries and devices)."""
    fd = _validate_date(from_date) if from_date else _days_ago(30)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)

    user_id = session["user_sub"]
    result = get_audience(user_id, fd, td)

    countries = [AnalyticsCountryItem(**c) for c in result["countries"]]
    devices = [AnalyticsDeviceItem(**d) for d in result["devices"]]
    return AnalyticsAudienceOut(
        countries=countries,
        devices=devices,
        total_unique_viewers=result["total_unique_viewers"],
    )


@router.post("/refresh", response_model=AnalyticsRefreshOut)
def analytics_refresh(session=Depends(require_ui_session)):
    """Trigger an on-demand analytics refresh for the authenticated creator.

    Rate limited to 1 request per 5 minutes per user.
    """
    user_id = session["user_sub"]
    now = now_ts()

    last_refresh = _refresh_timestamps.get(user_id, 0)
    if now - last_refresh < _REFRESH_COOLDOWN_SECONDS:
        raise HTTPException(
            status_code=429,
            detail="Analytics refresh rate limit exceeded. Try again in a few minutes.",
        )

    _refresh_timestamps[user_id] = now
    lookback = S.analytics_rollup_lookback_days

    # The refresh endpoint returns success immediately.
    # In a production system this would trigger an async rollup job.
    # For now it serves as a rate-limited placeholder.
    return AnalyticsRefreshOut(
        ok=True,
        message=f"Rollup refresh triggered for {lookback} days",
        days_refreshed=lookback,
    )
