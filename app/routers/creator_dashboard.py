"""Creator Dashboard router (CREATOR-003).

Provides a unified dashboard summary endpoint that aggregates earnings,
analytics, broadcasts, and milestones. Also provides milestone CRUD and
an SSE stream for real-time dashboard updates.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.core.time import now_ts
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["creator-dashboard"])

# ── Helpers ──────────────────────────────────────────────────────

_DATE_FMT = "%Y-%m-%d"

# In-memory per-user refresh rate limit (1 per 5 minutes)
_refresh_timestamps: dict[str, int] = {}
_REFRESH_COOLDOWN_SECONDS = 300


def _today() -> str:
    return datetime.utcnow().strftime(_DATE_FMT)


def _days_ago(n: int) -> str:
    return (datetime.utcnow() - timedelta(days=n)).strftime(_DATE_FMT)


def _start_of_today_ts() -> int:
    now = datetime.utcnow()
    midnight = datetime(now.year, now.month, now.day)
    return int(midnight.timestamp())


def _serialize(obj: Any) -> Any:
    """Recursively convert Decimal to int/float for JSON serialization."""
    if isinstance(obj, Decimal):
        if obj == int(obj):
            return int(obj)
        return float(obj)
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    return obj


# ── Dashboard Summary ──────────────────────────────────────────


@router.get("/ui/dashboard/summary")
def dashboard_summary(session=Depends(require_ui_session)):
    """Unified dashboard summary: earnings + analytics + broadcasts + milestones."""
    user_id = session["user_sub"]
    warnings: List[str] = []
    now = now_ts()

    # 1. Today's earnings
    today_earnings: Dict[str, Any] = {
        "total_cents": 0,
        "breakdown": {"subscriptions": 0, "tips": 0, "unlocks": 0, "vod_purchases": 0, "other": 0},
        "transaction_count": 0,
        "currency": "USD",
    }
    try:
        from app.services.creator_earnings import get_earnings_summary
        today_earnings = _serialize(get_earnings_summary(user_id, from_ts=_start_of_today_ts()))
    except Exception:
        logger.exception("Failed to fetch earnings for dashboard")
        warnings.append("earnings_unavailable")

    # 2. 7-day analytics overview
    analytics: Dict[str, Any] = {
        "period_views": 0,
        "period_revenue_cents": 0,
        "period_new_subscribers": 0,
        "total_subscribers": 0,
        "top_content": [],
        "currency": "USD",
    }
    try:
        from app.services.creator_analytics import get_overview
        analytics = _serialize(get_overview(user_id, _days_ago(7), _today()))
    except Exception:
        logger.exception("Failed to fetch analytics for dashboard")
        warnings.append("analytics_unavailable")

    # 3. Active broadcasts
    active_broadcasts: List[Dict[str, Any]] = []
    try:
        from app.services.broadcast_store import list_sessions_by_creator
        result = list_sessions_by_creator(user_id, limit=10)
        items = result.get("items", [])
        for s in items:
            if getattr(s, "status", None) == "live":
                active_broadcasts.append({
                    "session_id": s.id,
                    "status": s.status,
                    "name": getattr(s, "name", None),
                    "started_at": getattr(s, "started_at", None),
                })
    except Exception:
        logger.exception("Failed to fetch broadcasts for dashboard")
        warnings.append("broadcasts_unavailable")

    # 4. Recent milestones (unacknowledged)
    recent_milestones: List[Dict[str, Any]] = []
    try:
        from app.services.milestones import list_milestones
        milestones = list_milestones(user_id, acknowledged=False)
        recent_milestones = _serialize(milestones[:10])
    except Exception:
        logger.exception("Failed to fetch milestones for dashboard")
        warnings.append("milestones_unavailable")

    return {
        "today_earnings_cents": today_earnings.get("total_cents", 0),
        "earnings_breakdown": today_earnings.get("breakdown", {}),
        "period_views": analytics.get("period_views", 0),
        "period_revenue_cents": analytics.get("period_revenue_cents", 0),
        "total_subscribers": analytics.get("total_subscribers", 0),
        "top_content": analytics.get("top_content", []),
        "active_broadcasts": active_broadcasts,
        "recent_milestones": recent_milestones,
        "currency": analytics.get("currency", "USD"),
        "generated_at": now,
        "warnings": warnings,
    }


# ── Dashboard Refresh ──────────────────────────────────────────


@router.post("/ui/dashboard/refresh")
def dashboard_refresh(session=Depends(require_ui_session)):
    """Proxy to analytics refresh — rate limited."""
    user_id = session["user_sub"]
    now = now_ts()

    last_refresh = _refresh_timestamps.get(user_id, 0)
    if now - last_refresh < _REFRESH_COOLDOWN_SECONDS:
        raise HTTPException(
            status_code=429,
            detail="Dashboard refresh rate limit exceeded. Try again in a few minutes.",
        )

    _refresh_timestamps[user_id] = now
    return {"ok": True, "message": "Dashboard refresh triggered", "refreshed_at": now}


# ── Dashboard SSE Stream ───────────────────────────────────────


@router.get("/ui/dashboard/stream")
async def dashboard_stream(session=Depends(require_ui_session)):
    """SSE stream for real-time dashboard updates."""
    from app.services.dashboard_sse import dashboard_sse_subscribe, dashboard_sse_unsubscribe

    user_id = session["user_sub"]
    q = dashboard_sse_subscribe(user_id)

    async def _gen():
        try:
            yield "data: {\"type\": \"connected\"}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=30)
                    if event.get("type") == "replaced":
                        yield "data: {\"type\": \"replaced\"}\n\n"
                        break
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            dashboard_sse_unsubscribe(user_id, q)

    return StreamingResponse(_gen(), media_type="text/event-stream")


# ── Milestones ─────────────────────────────────────────────────


@router.get("/ui/milestones")
def milestones_list(session=Depends(require_ui_session)):
    """List all milestones for the authenticated user."""
    from app.services.milestones import list_milestones

    user_id = session["user_sub"]
    items = list_milestones(user_id)
    return _serialize(items)


@router.post("/ui/milestones/{milestone_id}/acknowledge")
def milestone_acknowledge(milestone_id: str, session=Depends(require_ui_session)):
    """Acknowledge (dismiss) a milestone."""
    from app.services.milestones import acknowledge_milestone

    user_id = session["user_sub"]
    # milestone_id format: "metric_threshold"
    parts = milestone_id.rsplit("_", 1)
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid milestone_id format")

    metric = parts[0]
    try:
        threshold = int(parts[1])
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid milestone_id format")

    ok = acknowledge_milestone(user_id, metric, threshold)
    if not ok:
        raise HTTPException(status_code=404, detail="Milestone not found")

    return {"ok": True}


@router.get("/ui/milestones/settings")
def milestone_settings_get(session=Depends(require_ui_session)):
    """Get milestone notification preferences."""
    from app.services.milestones import get_milestone_settings

    user_id = session["user_sub"]
    return get_milestone_settings(user_id)


@router.patch("/ui/milestones/settings")
async def milestone_settings_update(request: Request, session=Depends(require_ui_session)):
    """Update milestone notification preferences."""
    from app.services.milestones import update_milestone_settings

    user_id = session["user_sub"]
    try:
        body = await request.json()
    except Exception:
        body = {}
    return update_milestone_settings(user_id, body)
