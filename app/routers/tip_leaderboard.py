"""Tip leaderboard router (SOCIAL-005).

Public endpoint: GET /ui/creators/{creator_id}/top-supporters
Internal endpoint: POST /internal/tip-leaderboards/refresh
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.services.sessions import require_ui_session
from app.models import TopSupportersOut, TopSupporterItem
from app.services.tip_leaderboard import (
    get_leaderboard,
    refresh_creator_leaderboard,
    refresh_all_leaderboards,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/creators", tags=["tip-leaderboard"])
internal_router = APIRouter(prefix="/internal/tip-leaderboards", tags=["internal"])


@router.get("/{creator_id}/top-supporters", response_model=TopSupportersOut)
def get_top_supporters(
    creator_id: str,
    period: str = Query(default="30d", pattern=r"^(7d|30d|all)$"),
    limit: int = Query(default=10, ge=1, le=50),
    session=Depends(require_ui_session),
):
    """Get top supporters leaderboard for a creator."""
    viewer_id = session.get("user_sub") if isinstance(session, dict) else None
    result = get_leaderboard(creator_id, period, limit, viewer_id=viewer_id)
    return TopSupportersOut(
        creator_id=result["creator_id"],
        period=result["period"],
        supporters=[TopSupporterItem(**s) for s in result["supporters"]],
        total_tip_cents=result["total_tip_cents"],
        total_supporters=result["total_supporters"],
        computed_at=result["computed_at"],
    )


class RefreshBody(BaseModel):
    creator_id: Optional[str] = None


@internal_router.post("/refresh")
def refresh_leaderboards(body: RefreshBody = RefreshBody()):
    """Internal: refresh leaderboard pre-computations."""
    if body.creator_id:
        result = refresh_creator_leaderboard(body.creator_id)
        return {"ok": True, **result}
    return refresh_all_leaderboards()
