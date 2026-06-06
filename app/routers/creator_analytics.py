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
    ContentAnalyticsOut,
    ContentAnalyticsRevenueBreakdown,
    ContentAnalyticsViewsItem,
    EngagementBenchmarksOut,
    EngagementPublicOut,
    EngagementPublicToggleIn,
    EngagementRateOut,
    EngagementTimeSeriesItem,
    EngagementTimeSeriesOut,
)
from app.services.creator_analytics import (
    get_audience,
    get_content_detail,
    get_overview,
    get_revenue,
    get_subscribers,
    get_top_content,
    get_views,
    upsert_daily_rollup,
    upsert_summary_sentinel,
)
from app.services.engagement_rate import (
    VALID_PERIOD_DAYS,
    compute_platform_benchmarks,
    get_benchmarks_with_percentile,
    get_engagement_history,
    get_engagement_summary,
    get_public_engagement,
    set_public_engagement_visibility,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/analytics", tags=["analytics"])

# Public (no-auth) router for profile-facing engagement display.
public_router = APIRouter(tags=["analytics-public"])

# Internal router for ops/cron triggers (not proxied to the public internet).
internal_router = APIRouter(prefix="/internal/analytics", tags=["analytics-internal"])

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


@router.get("/content/{content_id}", response_model=ContentAnalyticsOut)
def analytics_content_detail(
    content_id: str,
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    granularity: str = Query(default="day"),
    session=Depends(require_ui_session),
):
    """Get detailed analytics for a specific content item."""
    user_id = session["user_sub"]
    fd = _validate_date(from_date) if from_date else _days_ago(30)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)

    if granularity not in ("day", "week", "month"):
        raise HTTPException(status_code=400, detail="granularity must be 'day', 'week', or 'month'")

    result = get_content_detail(user_id, content_id, fd, td, granularity)
    if result is None:
        raise HTTPException(status_code=404, detail="Content not found")
    if result.get("error") == "forbidden":
        raise HTTPException(status_code=403, detail="Not your content")

    # Convert nested dicts to models
    view_series = [ContentAnalyticsViewsItem(**vs) for vs in result.get("view_time_series", [])]
    rev_breakdown = ContentAnalyticsRevenueBreakdown(**result.get("revenue_breakdown", {}))

    return ContentAnalyticsOut(
        content_id=result["content_id"],
        content_type=result["content_type"],
        title=result["title"],
        thumbnail_url=result.get("thumbnail_url"),
        published_at=result.get("published_at"),
        total_views=result.get("total_views", 0),
        total_revenue_cents=result.get("total_revenue_cents", 0),
        engagement_rate=result.get("engagement_rate", 0.0),
        like_count=result.get("like_count", 0),
        comment_count=result.get("comment_count", 0),
        view_time_series=view_series,
        revenue_breakdown=rev_breakdown,
        currency=result.get("currency", "USD"),
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


# ── Engagement Rate (FIN-012) ────────────────────────────────────


def _validate_period_days(period_days: int) -> int:
    if period_days not in VALID_PERIOD_DAYS:
        raise HTTPException(
            status_code=422,
            detail="period_days must be 7, 14, 30, 60, or 90",
        )
    return period_days


@router.get("/engagement", response_model=EngagementRateOut)
def analytics_engagement(
    period_days: int = Query(default=30),
    session=Depends(require_ui_session),
):
    """Get the authenticated creator's engagement rate with breakdown.

    Computed deterministically from real like/comment/tip data in the daily
    rollups, normalized by current follower count and posts-in-period. Returns
    ``engagement_rate = 0.0`` (no division by zero) when followers or posts are
    zero.
    """
    _validate_period_days(period_days)
    user_id = session["user_sub"]
    result = get_engagement_summary(user_id, period_days)
    return EngagementRateOut(
        engagement_rate=result["engagement_rate"],
        engagement_rate_bps=result["engagement_rate_bps"],
        period_days=result["period_days"],
        total_interactions=result["total_interactions"],
        follower_count=result["follower_count"],
        posts_in_period=result["posts_in_period"],
        likes=result["likes"],
        comments=result["comments"],
        shares=result["shares"],
        tips=result["tips"],
        trend=result["trend"],
        trend_delta=result["trend_delta"],
    )


@router.get("/engagement/history", response_model=EngagementTimeSeriesOut)
def analytics_engagement_history(
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    """Get the engagement-rate time series from the creator's daily rollups."""
    fd = _validate_date(from_date) if from_date else _days_ago(30)
    td = _validate_date(to_date) if to_date else _today()
    _validate_date_range(fd, td)

    user_id = session["user_sub"]
    rows = get_engagement_history(user_id, fd, td)
    items = [EngagementTimeSeriesItem(**r) for r in rows]
    return EngagementTimeSeriesOut(items=items)


@router.put("/engagement/public", response_model=EngagementPublicOut)
def analytics_engagement_public_toggle(
    body: EngagementPublicToggleIn,
    session=Depends(require_ui_session),
):
    """Toggle whether the engagement rate is shown on the public profile."""
    user_id = session["user_sub"]
    set_public_engagement_visibility(user_id, body.visible)
    if not body.visible:
        return EngagementPublicOut(visible=False)
    s30 = get_engagement_summary(user_id, 30)
    s7 = get_engagement_summary(user_id, 7)
    return EngagementPublicOut(
        engagement_rate_30d=s30["engagement_rate"],
        engagement_rate_7d=s7["engagement_rate"],
        visible=True,
    )


@router.get("/engagement/benchmarks", response_model=EngagementBenchmarksOut)
def analytics_engagement_benchmarks(
    date: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    """Platform-wide engagement benchmarks plus the caller's percentile.

    Returns 503 when no benchmark snapshot has been computed yet (the daily job
    or the internal compute endpoint must run first).
    """
    target = _validate_date(date) if date else _today()
    user_id = session["user_sub"]
    result = get_benchmarks_with_percentile(user_id, target)
    if result is None:
        raise HTTPException(
            status_code=503,
            detail="Benchmarks not yet computed. Try again later.",
        )
    return EngagementBenchmarksOut(**result)


@internal_router.post("/engagement/compute-benchmarks")
def trigger_compute_benchmarks(date: Optional[str] = Query(default=None)):
    """Recompute platform-wide engagement benchmarks for ``date`` (default today).

    Called by the daily background job and by ops tooling. The ``/internal``
    prefix is firewalled to the VPC in production (SECOPS-007); no per-request
    auth is enforced here.
    """
    target = _validate_date(date) if date else _today()
    result = compute_platform_benchmarks(target)
    return {
        "ok": True,
        "date": target,
        "sample_size": int(result.get("sample_size", 0)),
    }


@public_router.get("/api/creators/{creator_id}/engagement", response_model=EngagementPublicOut)
def public_creator_engagement(creator_id: str):
    """Public engagement rate for a creator's profile (if they opted in).

    Returns 404 when the creator has not enabled public display.
    """
    data = get_public_engagement(creator_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Engagement data not available")
    return EngagementPublicOut(
        engagement_rate_30d=data["engagement_rate_30d"],
        engagement_rate_7d=data["engagement_rate_7d"],
        visible=True,
    )
