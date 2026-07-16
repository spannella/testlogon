"""Tips measurement router (TIPX-D).

The ledger-backed, reconcilable "tips received" (creator) and "tips sent"
(tipper) surfaces.  Every total here is the SAME number the earnings tips bucket
and the leaderboard report for the same creator/period (net, reversed-excluded).

Endpoints (all under /ui/tips):
  * GET /ui/tips/received          -- creator's ledger-backed tips-received summary (D1/D3)
  * GET /ui/tips/received/history  -- creator's paginated NET tip credit rows (D3)
  * GET /ui/tips/sent              -- tipper's paginated GROSS tip debit receipts (D4)
  * GET /ui/tips/sent/summary      -- tipper's aggregate spend header (D4)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.services.sessions import require_ui_session
from app.services.tips_measurement import (
    get_tips_received_summary,
    get_tips_received_transactions,
    get_tips_sent,
    get_tips_sent_summary,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/tips", tags=["tips-measurement"])


@router.get("/received")
def tips_received_summary(
    period: str = Query(default="30d", pattern=r"^(7d|30d|all)$"),
    session=Depends(require_ui_session),
):
    """Ledger-backed tips-received summary for the current creator (the ONE TRUE TOTAL)."""
    user_id = session["user_sub"]
    return get_tips_received_summary(user_id, period)


@router.get("/received/history")
def tips_received_history(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    period: str = Query(default="all", pattern=r"^(7d|30d|all)$"),
    session=Depends(require_ui_session),
):
    """Paginated NET tip credit rows the current creator has received."""
    user_id = session["user_sub"]
    return get_tips_received_transactions(user_id, limit=limit, cursor=cursor, period=period)


@router.get("/sent")
def tips_sent(
    limit: int = Query(default=50, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    period: str = Query(default="all", pattern=r"^(7d|30d|all)$"),
    session=Depends(require_ui_session),
):
    """Paginated GROSS tip debit receipts the current tipper has sent (D4)."""
    user_id = session["user_sub"]
    return get_tips_sent(user_id, limit=limit, cursor=cursor, period=period)


@router.get("/sent/summary")
def tips_sent_summary(
    period: str = Query(default="all", pattern=r"^(7d|30d|all)$"),
    session=Depends(require_ui_session),
):
    """Aggregate of the current tipper's total spend (D4 header)."""
    user_id = session["user_sub"]
    return get_tips_sent_summary(user_id, period)
