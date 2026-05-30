"""Creator Earnings Dashboard router (MON-003).

Provides earnings summary (with time-series + granularity), quick stats,
and paginated transaction list endpoints for authenticated creators.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    EarningsBreakdown,
    EarningsQuickStatsOut,
    EarningsSummaryOut,
    EarningsTransactionOut,
    EarningsTransactionsOut,
    TimeSeriesPoint,
)
from app.services.creator_earnings import (
    get_earnings_summary,
    get_earnings_transactions,
    get_quick_stats,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/earnings", tags=["earnings"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_date_to_ts(date_str: str, end_of_day: bool = False) -> int:
    """Parse ISO date string (YYYY-MM-DD) to Unix timestamp (UTC).

    If *end_of_day* is True the timestamp is set to 23:59:59.
    Raises HTTPException(400) on invalid format.
    """
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if end_of_day:
            dt = dt.replace(hour=23, minute=59, second=59)
        return int(dt.timestamp())
    except ValueError:
        raise HTTPException(400, f"Invalid date format: {date_str}. Expected YYYY-MM-DD.")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/summary", response_model=EarningsSummaryOut)
def earnings_summary(
    from_date: Optional[str] = Query(default=None, description="Start date (YYYY-MM-DD, UTC)"),
    to_date: Optional[str] = Query(default=None, description="End date (YYYY-MM-DD, UTC)"),
    granularity: str = Query(default="day", description="Time series grouping: day, week, month"),
    # Also accept raw timestamps for backward compat
    from_ts: Optional[int] = Query(default=None, description="Start of time range (Unix seconds)"),
    to_ts: Optional[int] = Query(default=None, description="End of time range (Unix seconds)"),
    session=Depends(require_ui_session),
):
    """Get earnings summary with breakdown and time series."""
    if granularity not in ("day", "week", "month"):
        raise HTTPException(400, "granularity must be one of: day, week, month")

    # Prefer ISO dates over raw timestamps
    start = from_ts or 0
    end = to_ts or 0
    if from_date:
        start = _parse_date_to_ts(from_date)
    if to_date:
        end = _parse_date_to_ts(to_date, end_of_day=True)

    if start and end and start > end:
        raise HTTPException(400, "from_date must be before to_date")

    user_id = session["user_sub"]
    result = get_earnings_summary(
        user_id,
        from_ts=start,
        to_ts=end,
        granularity=granularity,
    )

    time_series = [TimeSeriesPoint(**pt) for pt in result.get("time_series", [])]

    return EarningsSummaryOut(
        total_cents=result["total_cents"],
        breakdown=EarningsBreakdown(**result["breakdown"]),
        transaction_count=result["transaction_count"],
        currency=result["currency"],
        time_series=time_series,
    )


@router.get("/quick-stats", response_model=EarningsQuickStatsOut)
def earnings_quick_stats(
    session=Depends(require_ui_session),
):
    """Get quick stats for dashboard cards (today, week, month, all time)."""
    user_id = session["user_sub"]
    result = get_quick_stats(user_id=user_id)
    return EarningsQuickStatsOut(**result)


@router.get("/transactions", response_model=EarningsTransactionsOut)
def earnings_transactions(
    limit: int = Query(default=50, ge=1, le=200, description="Number of items per page"),
    cursor: Optional[str] = Query(default=None, description="Pagination cursor"),
    from_date: Optional[str] = Query(default=None, description="Start date (YYYY-MM-DD, UTC)"),
    to_date: Optional[str] = Query(default=None, description="End date (YYYY-MM-DD, UTC)"),
    from_ts: Optional[int] = Query(default=None, description="Start of time range (Unix seconds)"),
    to_ts: Optional[int] = Query(default=None, description="End of time range (Unix seconds)"),
    session=Depends(require_ui_session),
):
    """Get paginated credit transactions for the authenticated creator."""
    start = from_ts or 0
    end = to_ts or 0
    if from_date:
        start = _parse_date_to_ts(from_date)
    if to_date:
        end = _parse_date_to_ts(to_date, end_of_day=True)

    user_id = session["user_sub"]
    result = get_earnings_transactions(
        user_id,
        limit=limit,
        cursor=cursor,
        from_ts=start,
        to_ts=end,
    )
    items = [EarningsTransactionOut(**item) for item in result["items"]]
    return EarningsTransactionsOut(
        items=items,
        next_cursor=result["next_cursor"],
    )
