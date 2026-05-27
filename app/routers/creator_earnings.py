"""Creator Earnings Dashboard router (MON-003).

Provides earnings summary and transaction list endpoints for authenticated creators.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.services.sessions import require_ui_session
from app.models import EarningsSummaryOut, EarningsTransactionsOut, EarningsTransactionOut, EarningsBreakdown
from app.services.creator_earnings import get_earnings_summary, get_earnings_transactions

router = APIRouter(prefix="/ui/earnings", tags=["earnings"])


@router.get("/summary", response_model=EarningsSummaryOut)
def earnings_summary(
    from_ts: Optional[int] = Query(default=None, description="Start of time range (Unix seconds)"),
    to_ts: Optional[int] = Query(default=None, description="End of time range (Unix seconds)"),
    session=Depends(require_ui_session),
):
    """Get earnings summary for the authenticated creator."""
    user_id = session["user_sub"]
    result = get_earnings_summary(
        user_id,
        from_ts=from_ts or 0,
        to_ts=to_ts or 0,
    )
    return EarningsSummaryOut(
        total_cents=result["total_cents"],
        breakdown=EarningsBreakdown(**result["breakdown"]),
        transaction_count=result["transaction_count"],
        currency=result["currency"],
    )


@router.get("/transactions", response_model=EarningsTransactionsOut)
def earnings_transactions(
    limit: int = Query(default=50, ge=1, le=200, description="Number of items per page"),
    cursor: Optional[str] = Query(default=None, description="Pagination cursor"),
    from_ts: Optional[int] = Query(default=None, description="Start of time range (Unix seconds)"),
    to_ts: Optional[int] = Query(default=None, description="End of time range (Unix seconds)"),
    session=Depends(require_ui_session),
):
    """Get paginated credit transactions for the authenticated creator."""
    user_id = session["user_sub"]
    result = get_earnings_transactions(
        user_id,
        limit=limit,
        cursor=cursor,
        from_ts=from_ts or 0,
        to_ts=to_ts or 0,
    )
    items = [EarningsTransactionOut(**item) for item in result["items"]]
    return EarningsTransactionsOut(
        items=items,
        next_cursor=result["next_cursor"],
    )
