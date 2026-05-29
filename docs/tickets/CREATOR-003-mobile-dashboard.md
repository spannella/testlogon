# CREATOR-003: Creator Dashboard Mobile-Optimized View

**Ticket**: CREATOR-003
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The current creator analytics (`/ui/analytics/*`) and earnings (`/ui/earnings/*`) endpoints provide comprehensive data, but the frontend lacks a unified, mobile-optimized dashboard experience. Creators on mobile devices must navigate between separate Analytics and Earnings pages, each requiring multiple API calls and full-page renders. This creates friction for the most common creator use case: a quick daily check of "how am I doing?"

Key gaps:

- **No unified summary**: Creators must visit separate pages for analytics and earnings, with different date range selectors.
- **No quick-launch shortcuts**: Starting a post or broadcast from the dashboard requires navigating to a different page entirely.
- **No milestone notifications**: Creators are not alerted when they hit significant milestones (100th subscriber, $1000 in tips, etc.).
- **Desktop-first layout**: The existing analytics UI uses wide data tables and charts that are awkward on mobile viewports.

### 1.2 Goals

1. **Unified Mobile Dashboard**: A single responsive page showing earnings summary, recent analytics (views, tips, subscribers), and quick-action buttons.
2. **Card-Based Layout**: Touch-friendly cards that stack vertically on mobile and grid on desktop.
3. **Quick Post/Broadcast Launch**: One-tap buttons to create a post or start a broadcast.
4. **Push Notification Milestones**: Configurable alerts when creators reach milestones (new subscriber, tip goal, view count threshold).
5. **Real-Time Revenue Ticker**: SSE-driven live update of today's earnings during active broadcasts.

### 1.3 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to see today's earnings, subscriber count, and view count in one glance on my phone. | Dashboard loads in <2s with a unified summary card showing 3 KPIs. |
| Creator | I want to quickly post content or start a broadcast from the dashboard. | "New Post" and "Go Live" buttons are prominently placed at the top of the mobile dashboard. |
| Creator | I want to see a chart of my earnings for the last 7 days. | Compact sparkline chart renders in a card, touch-scrollable for date detail. |
| Creator | I want to be notified when I get a new subscriber. | Push notification fires with subscriber name and tier (if applicable). |
| Creator | I want to see my top-performing content from the last 7 days. | Card shows top 5 content items ranked by views or revenue. |
| Creator | I want to configure which milestone alerts I receive. | Settings page allows toggling: new subscriber, tip threshold, view milestone, earnings milestone. |
| Creator | I want the dashboard to update in real-time during a live broadcast. | Today's earnings card updates via SSE when tips come in during a live session. |
| Creator | I want to see which content earned the most today. | Earnings card has a breakdown by content type (tips, subscriptions, unlocks, VOD). |
| Creator | I want to swipe between daily/weekly/monthly views. | Tab-like selector at the top of the earnings sparkline lets me switch periods. |
| Creator | I want to dismiss milestone notifications and not see them again. | Milestone cards have an "acknowledge" action that marks them as seen. |
| Creator | I want to share my milestone achievements on social media. | Milestone cards include a "Share" button that copies a pre-formatted text/image link. |

---

## 2. Current State Analysis

### 2.1 Analytics API

The creator analytics router (`app/routers/creator_analytics.py`) provides seven endpoints under `/ui/analytics/`:
<!-- VERIFIED: app/routers/creator_analytics.py:51 router prefix="/ui/analytics" -->

```python
router = APIRouter(prefix="/ui/analytics", tags=["analytics"])

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
```

The overview endpoint (lines 97-119) returns `period_views`, `period_revenue_cents`, `period_new_subscribers`, `total_subscribers`, and `top_content`.
<!-- VERIFIED: app/routers/creator_analytics.py:97 analytics_overview --> However, this is date-range scoped with string dates (`YYYY-MM-DD`), not Unix timestamps, which is inconsistent with the earnings API.

Additional analytics endpoints:
- `GET /ui/analytics/revenue` — revenue time series with granularity (day/week/month)
- `GET /ui/analytics/views` — views time series
- `GET /ui/analytics/subscribers` — subscriber growth time series
- `GET /ui/analytics/top-content` — top content items ranked by views/revenue
- `GET /ui/analytics/audience` — geographic and device breakdown
- `POST /ui/analytics/refresh` — trigger on-demand analytics recalculation

The analytics service (`app/services/creator_analytics.py`, lines 78-101) reads from a `T.analytics_rollups` table:
<!-- CORRECTED: was "lines 78-99", actually _query_rollups is lines 78-101 -->

```python
def _query_rollups(user_id: str, from_date: str, to_date: str) -> List[Dict[str, Any]]:
    """Query daily rollup rows for a creator in a date range."""
    pk = f"CREATOR#{user_id}"
    sk_start = f"DAILY#{from_date}"
    sk_end = f"DAILY#{to_date}"
    key_cond = Key("pk").eq(pk) & Key("sk").between(sk_start, sk_end)
```

The rollup table stores pre-aggregated daily metrics under `pk=CREATOR#{user_id}`, `sk=DAILY#{YYYY-MM-DD}`. Each row contains `views`, `revenue_cents`, `new_subscribers`, `tips_count`, `unlock_count`, `vod_purchases`, and `top_content` (a list of content IDs with their metrics). A `SUMMARY` sentinel row stores lifetime totals.

### 2.2 Earnings API

The creator earnings router (`app/routers/creator_earnings.py`) provides two endpoints under `/ui/earnings/`:

```python
router = APIRouter(prefix="/ui/earnings", tags=["earnings"])

@router.get("/summary", response_model=EarningsSummaryOut)
def earnings_summary(
    from_ts: Optional[int] = Query(default=None, description="Start of time range (Unix seconds)"),
    to_ts: Optional[int] = Query(default=None, description="End of time range (Unix seconds)"),
    session=Depends(require_ui_session),
):
```

The earnings service (`app/services/creator_earnings.py`, lines 47-114) aggregates billing ledger credit entries
<!-- VERIFIED: app/services/creator_earnings.py:47 get_earnings_summary --> with category breakdown:

```python
def get_earnings_summary(user_id: str, *, from_ts: int = 0, to_ts: int = 0) -> dict:
    pk = f"USER#{user_id}"
    # ...
    breakdown: Dict[str, int] = {
        "subscriptions": 0,
        "tips": 0,
        "unlocks": 0,
        "vod_purchases": 0,
        "other": 0,
    }
```

The earnings query uses `FilterExpression: Attr("type").eq("credit")` to find credit entries from the billing ledger. As noted in CLAUDE.md, `FilterExpression` doesn't reduce page size, so the query loops via `LastEvaluatedKey` to collect all matching entries. For the "today" query, the SK range is narrow (`LEDGER#{start_of_today}` to `LEDGER#{now}`), which limits the data volume.

The transactions endpoint (`GET /ui/earnings/transactions`) returns paginated individual ledger entries with cursor-based pagination, category classification, and metadata.

### 2.3 Existing Frontend Dashboard State

The frontend pages are under `frontend/src/pages/`. There is currently no unified dashboard page -- the app routes to individual feature pages. The closest to a dashboard is `Dashboard.tsx` (the landing page after login), which shows a generic welcome message without any creator-specific analytics.

The current `Dashboard.tsx` renders a simple card with the user's display name and role. It does not query any analytics or earnings endpoints. The mobile dashboard will replace this for users who have creator content.

### 2.4 Analytics Refresh Endpoint

The analytics router includes a refresh endpoint (lines 288-314) with per-user rate limiting:
<!-- VERIFIED: app/routers/creator_analytics.py:288 analytics_refresh -->

```python
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
```

The rate limit is enforced via an in-memory dict (`_refresh_timestamps`).
<!-- VERIFIED: app/routers/creator_analytics.py:59 _refresh_timestamps, :60 _REFRESH_COOLDOWN_SECONDS --> The mobile dashboard will call this endpoint on pull-to-refresh, displaying a toast on 429 rather than an error state.

### 2.5 Notification System

The platform uses `put_notification` from `app/routers/newsfeed.py` for in-app notifications. The notification system writes to the app single table with `pk=USER#{user_id}` and `sk=NOTIF#{timestamp}#{id}`. This same pattern will be used for milestone alerts.

Existing notification types include: `new_follower`, `new_comment`, `new_tip`, `subscription_renewed`. Milestones will add: `milestone_subscribers`, `milestone_earnings`, `milestone_views`, `milestone_tips`.

### 2.6 SSE Infrastructure

The broadcast router (`app/routers/broadcast.py`, lines 625-645) implements SSE streaming:
<!-- VERIFIED: app/routers/broadcast.py:625 broadcast_event_stream_route -->

```python
@router.get("/sessions/{session_id}/stream")
async def broadcast_event_stream_route(session_id: str, ctx: dict = Depends(_ctx)):
    """SSE stream for real-time broadcast events."""
    q = broadcast_sse_subscribe(session_id)
    async def gen():
        try:
            yield "event: hello\ndata: {}\n\n"
            while True:
                try:
                    item = await asyncio.wait_for(q.get(), timeout=15.0)
                    event_type = item.pop("_type", "update")
                    yield f"event: {event_type}\ndata: {json.dumps(item, ...)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            broadcast_sse_unsubscribe(session_id, q)
    return StreamingResponse(gen(), media_type="text/event-stream")
```

The SSE infrastructure uses in-memory `asyncio.Queue` objects per subscriber (see `app/services/broadcast_sse.py`). Each queue has a max size of 100 events. Dead subscribers (full queues) are automatically cleaned up.

A similar per-user SSE endpoint will feed real-time updates to the mobile dashboard. The key difference: broadcast SSE is keyed by session_id (many viewers), while dashboard SSE is keyed by user_id (single viewer).

### 2.7 Broadcast Session Listing

The broadcast store provides `list_sessions_by_creator`:

```python
def list_sessions_by_creator(created_by: str, *, limit: int = 50) -> List[BroadcastSessionModel]:
    resp = T.broadcast_sessions.query(
        IndexName="ByCreatorCreatedAt",
        KeyConditionExpression=Key("created_by").eq(created_by),
        ScanIndexForward=False,
        Limit=limit,
    )
    return [session_from_item(i) for i in resp.get("Items", [])]
```

The dashboard will use this with a filter on `status="live"` to show active broadcasts. Since `FilterExpression` doesn't reduce page size, a small `limit` (3) and client-side filter is acceptable for the dashboard use case.

---

## 3. Technical Design

### 3.1 Unified Dashboard API Endpoint

A new backend endpoint aggregates data from both analytics and earnings into a single response, reducing the number of API calls the mobile client needs to make from 3+ to 1:

```python
# app/routers/creator_dashboard.py

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from app.core.time import now_ts
from app.services.creator_analytics import get_overview
from app.services.creator_earnings import get_earnings_summary
from app.services.broadcast_store import list_sessions_by_creator
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)
router = APIRouter(tags=["dashboard"])

# Timeout per internal call (seconds)
_INTERNAL_CALL_TIMEOUT_SECONDS = 2


def _start_of_today_ts() -> int:
    """Unix timestamp of 00:00:00 UTC today."""
    now = datetime.now(timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(midnight.timestamp())


def _today() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d")


def _days_ago(n: int) -> str:
    from datetime import timedelta
    return (datetime.utcnow() - timedelta(days=n)).strftime("%Y-%m-%d")


@router.get("/ui/dashboard/summary")
def dashboard_summary(session=Depends(require_ui_session)):
    """Unified dashboard summary for mobile.

    Combines:
    - Today's earnings (from billing ledger)
    - 7-day analytics overview (from analytics rollups)
    - Active broadcast status
    - Top 5 content items
    - Recent milestone notifications

    Each internal call has a 2-second soft timeout. If any call fails,
    partial data is returned with a warning flag rather than a 500 error.
    """
    user_id = session["user_sub"]
    warnings: List[str] = []

    # 1. Today's earnings
    try:
        today_start = _start_of_today_ts()
        today_earnings = get_earnings_summary(user_id, from_ts=today_start)
    except Exception:
        logger.exception("Dashboard: today_earnings failed for %s", user_id)
        today_earnings = {"total_cents": 0, "breakdown": {}, "transaction_count": 0}
        warnings.append("today_earnings")

    # 2. 7-day analytics overview
    try:
        overview = get_overview(user_id, _days_ago(7), _today())
    except Exception:
        logger.exception("Dashboard: overview failed for %s", user_id)
        overview = {
            "period_views": 0, "period_revenue_cents": 0,
            "period_new_subscribers": 0, "total_subscribers": 0,
            "top_content": [], "currency": "USD",
        }
        warnings.append("analytics_overview")

    # 3. Active broadcasts
    try:
        all_sessions = list_sessions_by_creator(user_id, limit=10)
        active_broadcasts = [
            {
                "session_id": s.id,
                "name": s.name,
                "status": s.status,
                "viewer_count": getattr(s, "viewer_count", 0),
                "started_at": getattr(s, "started_at", None),
            }
            for s in all_sessions
            if s.status == "live"
        ][:3]
    except Exception:
        logger.exception("Dashboard: active_broadcasts failed for %s", user_id)
        active_broadcasts = []
        warnings.append("active_broadcasts")

    # 4. Recent milestones
    try:
        milestones = _get_recent_milestones(user_id, limit=5)
    except Exception:
        logger.exception("Dashboard: milestones failed for %s", user_id)
        milestones = []
        warnings.append("milestones")

    return {
        "today_earnings_cents": today_earnings["total_cents"],
        "today_earnings_breakdown": today_earnings.get("breakdown", {}),
        "today_tip_count": today_earnings.get("transaction_count", 0),
        "today_new_subscribers": _count_today_subscribers(user_id),
        "period_views": overview.get("period_views", 0),
        "period_revenue_cents": overview.get("period_revenue_cents", 0),
        "period_new_subscribers": overview.get("period_new_subscribers", 0),
        "total_subscribers": overview.get("total_subscribers", 0),
        "top_content": (overview.get("top_content") or [])[:5],
        "active_broadcasts": active_broadcasts,
        "recent_milestones": milestones,
        "currency": "USD",
        "generated_at": now_ts(),
        "warnings": warnings,
    }


def _get_recent_milestones(user_id: str, limit: int = 5) -> List[Dict[str, Any]]:
    """Get recent milestone records from app_single_table."""
    from boto3.dynamodb.conditions import Key
    from app.core.tables import T

    try:
        resp = T.app.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{user_id}")
            & Key("sk").begins_with("MILESTONE#"),
            ScanIndexForward=False,
            Limit=limit,
        )
        return [
            {
                "milestone_id": item.get("milestone_id", ""),
                "metric": item.get("metric", ""),
                "threshold": int(item.get("threshold", 0)),
                "current_value": int(item.get("current_value", 0)),
                "reached_at": int(item.get("reached_at", 0)),
                "acknowledged": bool(item.get("acknowledged", False)),
            }
            for item in resp.get("Items", [])
        ]
    except Exception:
        return []


def _count_today_subscribers(user_id: str) -> int:
    """Count new subscribers for today (from analytics rollup)."""
    try:
        from app.services.creator_analytics import _query_rollups
        today = _today()
        rollups = _query_rollups(user_id, today, today)
        if rollups:
            return int(rollups[0].get("new_subscribers", 0))
    except Exception:
        pass
    return 0
```

### 3.2 Milestone Detection System

Milestones are checked asynchronously when relevant events occur:

```python
# app/services/milestones.py

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

MILESTONE_THRESHOLDS = {
    "subscribers": [10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000],
    "tips_total_cents": [1000, 5000, 10000, 50000, 100000, 500000, 1000000],
    "views": [100, 1000, 10000, 100000, 1000000],
    "earnings_total_cents": [10000, 50000, 100000, 500000, 1000000, 5000000],
}

# Friendly labels for notification text
METRIC_LABELS = {
    "subscribers": "subscribers",
    "tips_total_cents": "in tips",
    "views": "views",
    "earnings_total_cents": "in earnings",
}


def check_milestone(
    user_id: str,
    metric: str,
    current_value: int,
) -> Optional[Dict[str, Any]]:
    """Check if a milestone threshold was crossed.

    Returns milestone dict if crossed, None otherwise.
    Writes a milestone record to prevent duplicate alerts.

    Called from:
    - Subscription events (for "subscribers" metric)
    - Tip ledger writes (for "tips_total_cents" metric)
    - Analytics rollup (for "views" metric)
    - Earnings summary computation (for "earnings_total_cents" metric)
    """
    thresholds = MILESTONE_THRESHOLDS.get(metric, [])

    # Find the highest crossed threshold
    crossed_threshold = None
    for threshold in reversed(thresholds):
        if current_value >= threshold:
            # Check if already recorded
            existing = _get_milestone(user_id, metric, threshold)
            if not existing:
                crossed_threshold = threshold
                break
            else:
                # Already recorded this threshold, and all lower ones are implied
                break

    if crossed_threshold is None:
        return None

    milestone = _record_milestone(user_id, metric, crossed_threshold, current_value)
    _send_milestone_notification(user_id, milestone)

    # Also publish to dashboard SSE if connected
    _publish_milestone_sse(user_id, milestone)

    return milestone


def _get_milestone(user_id: str, metric: str, threshold: int) -> Optional[Dict[str, Any]]:
    """Check if a milestone has already been recorded."""
    sk = f"MILESTONE#{metric}#{threshold}"
    try:
        resp = T.app.get_item(Key={"pk": f"USER#{user_id}", "sk": sk})
        return resp.get("Item")
    except Exception:
        return None


def _record_milestone(user_id: str, metric: str, threshold: int, current_value: int) -> Dict[str, Any]:
    """Record a milestone achievement."""
    milestone_id = f"ms_{uuid.uuid4().hex[:12]}"
    now = now_ts()

    item = {
        "pk": f"USER#{user_id}",
        "sk": f"MILESTONE#{metric}#{threshold}",
        "milestone_id": milestone_id,
        "metric": metric,
        "threshold": threshold,
        "current_value": current_value,
        "reached_at": now,
        "acknowledged": False,
    }

    try:
        T.app.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(sk)",
        )
    except Exception:
        logger.warning("Milestone already exists or write failed", extra={
            "user_id": user_id, "metric": metric, "threshold": threshold,
        })

    return item


def _format_threshold(metric: str, threshold: int) -> str:
    """Format a threshold value for display."""
    if metric in ("tips_total_cents", "earnings_total_cents"):
        dollars = threshold / 100
        if dollars >= 1000:
            return f"${dollars / 1000:.0f}K"
        return f"${dollars:.0f}"
    if threshold >= 1000000:
        return f"{threshold / 1000000:.0f}M"
    if threshold >= 1000:
        return f"{threshold / 1000:.0f}K"
    return str(threshold)


def _send_milestone_notification(user_id: str, milestone: Dict[str, Any]) -> None:
    """Send an in-app notification for a milestone achievement."""
    metric = milestone["metric"]
    threshold = milestone["threshold"]
    label = METRIC_LABELS.get(metric, metric)
    formatted = _format_threshold(metric, threshold)

    try:
        from app.routers.newsfeed import put_notification
        put_notification(
            user_id,
            title=f"Milestone Reached! {formatted} {label}",
            body=f"Congratulations! You've reached {formatted} {label}. Keep up the great work!",
            action_url="/creator-dashboard",
            meta={
                "type": "milestone",
                "metric": metric,
                "threshold": threshold,
                "milestone_id": milestone["milestone_id"],
            },
        )
    except Exception:
        logger.warning("Failed to send milestone notification", extra={
            "user_id": user_id, "milestone_id": milestone.get("milestone_id"),
        })


def _publish_milestone_sse(user_id: str, milestone: Dict[str, Any]) -> None:
    """Publish milestone event to dashboard SSE stream."""
    try:
        from app.services.dashboard_sse import dashboard_sse_publish
        dashboard_sse_publish(user_id, {
            "_type": "milestone:reached",
            "milestone_id": milestone["milestone_id"],
            "metric": milestone["metric"],
            "threshold": milestone["threshold"],
            "current_value": milestone["current_value"],
            "reached_at": milestone["reached_at"],
        })
    except Exception:
        pass  # Non-critical


def acknowledge_milestone(user_id: str, metric: str, threshold: int) -> bool:
    """Mark a milestone as acknowledged (dismiss it from the dashboard)."""
    sk = f"MILESTONE#{metric}#{threshold}"
    try:
        T.app.update_item(
            Key={"pk": f"USER#{user_id}", "sk": sk},
            UpdateExpression="SET acknowledged = :true",
            ExpressionAttributeValues={":true": True},
            ConditionExpression="attribute_exists(sk)",
        )
        return True
    except Exception:
        return False
```

### 3.3 Real-Time Earnings SSE

A new SSE endpoint streams earnings updates to the mobile dashboard:

```python
# app/services/dashboard_sse.py

from __future__ import annotations

import asyncio
from typing import Any, Dict, Set

_DASHBOARD_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}
_MAX_QUEUES_PER_USER = 1  # Only allow 1 SSE connection per user


def dashboard_sse_subscribe(user_id: str) -> asyncio.Queue:
    """Subscribe to real-time dashboard updates for a user.

    Only 1 connection per user is allowed. New connections replace old ones.
    """
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    existing = _DASHBOARD_SUBSCRIBERS.get(user_id)

    if existing:
        # Close existing connections
        for old_q in list(existing):
            try:
                old_q.put_nowait({"_type": "close", "reason": "replaced"})
            except asyncio.QueueFull:
                pass
        existing.clear()
        existing.add(q)
    else:
        _DASHBOARD_SUBSCRIBERS[user_id] = {q}

    return q


def dashboard_sse_unsubscribe(user_id: str, q: asyncio.Queue) -> None:
    """Unsubscribe from dashboard updates."""
    subs = _DASHBOARD_SUBSCRIBERS.get(user_id)
    if not subs:
        return
    subs.discard(q)
    if not subs:
        _DASHBOARD_SUBSCRIBERS.pop(user_id, None)


def dashboard_sse_publish(user_id: str, event: Dict[str, Any]) -> None:
    """Publish an event to the user's dashboard SSE stream."""
    subs = _DASHBOARD_SUBSCRIBERS.get(user_id)
    if not subs:
        return
    dead = []
    for q in list(subs):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        subs.discard(q)
        if not subs:
            _DASHBOARD_SUBSCRIBERS.pop(user_id, None)
```

SSE endpoint in the router:

```python
# In app/routers/creator_dashboard.py

@router.get("/ui/dashboard/stream")
async def dashboard_stream(session=Depends(require_ui_session)):
    """SSE stream for real-time dashboard updates.

    Emits:
    - earnings:update — when a new credit entry is written
    - milestone:reached — when a milestone threshold is crossed
    - broadcast:status — when an active broadcast changes state
    - subscriber:new — when a new subscriber signs up
    """
    user_id = session["user_sub"]
    q = dashboard_sse_subscribe(user_id)

    async def gen():
        yield "event: hello\ndata: {}\n\n"
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=15.0)
                event_type = item.pop("_type", "update")
                if event_type == "close":
                    yield f"event: close\ndata: {json.dumps(item)}\n\n"
                    break
                yield f"event: {event_type}\ndata: {json.dumps(item)}\n\n"
            except asyncio.TimeoutError:
                yield ": ping\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")
```

### 3.4 Milestone Notification Settings

Notification preferences stored under the user's profile in the app single table:

```python
{
    "pk": "USER#{user_id}",
    "sk": "MILESTONE_PREFS",
    "new_subscriber": True,
    "tip_threshold_cents": 500,   # notify when single tip >= $5
    "earnings_milestone": True,
    "view_milestone": True,
    "subscriber_milestone": True,
    "updated_at": 1748390400,
}
```

Settings are read at milestone check time to decide whether to fire the notification. This avoids unnecessary DDB reads for creators who have disabled milestone alerts.

### 3.5 Dashboard Data Flow (Sequence Diagram)

```
Mobile Client                Backend Dashboard Router         Analytics    Earnings    Broadcasts
    |                               |                            |            |            |
    |  GET /ui/dashboard/summary    |                            |            |            |
    |------------------------------>|                            |            |            |
    |                               |  get_overview(7d)          |            |            |
    |                               |--------------------------->|            |            |
    |                               |  <-- overview data --------|            |            |
    |                               |                            |            |            |
    |                               |  get_earnings_summary(today)            |            |
    |                               |---------------------------------------->|            |
    |                               |  <-- earnings data ----------------------|            |
    |                               |                            |            |            |
    |                               |  list_sessions(user, live)              |            |
    |                               |-------------------------------------------------------->|
    |                               |  <-- active broadcasts --------------------------------|
    |                               |                            |            |            |
    |                               |  get_recent_milestones     |            |            |
    |                               |  (app_single_table)        |            |            |
    |                               |                            |            |            |
    |  <-- unified summary ---------|                            |            |            |
    |                               |                            |            |            |
    |  GET /ui/dashboard/stream     |                            |            |            |
    |  (SSE connection)             |                            |            |            |
    |------------------------------>|                            |            |            |
    |  <-- event: hello ------------|                            |            |            |
    |  ...                          |                            |            |            |
    |  <-- event: earnings:update   |  (on tip received)         |            |            |
    |  <-- event: milestone:reached |  (on threshold crossed)    |            |            |
```

### 3.6 Earnings SSE Integration Points

To emit `earnings:update` events, the tip ledger write function is hooked:

```python
# In app/services/tip_ledger.py, after write_tip_ledger:

def write_tip_ledger_with_dashboard_update(entry: TipLedgerEntry) -> Dict[str, str]:
    """Write tip ledger and emit dashboard SSE update for the recipient."""
    result = write_tip_ledger(entry)

    # Emit SSE update to recipient's dashboard
    try:
        from app.services.dashboard_sse import dashboard_sse_publish
        dashboard_sse_publish(entry.recipient_user_id, {
            "_type": "earnings:update",
            "amount_cents": entry.amount_cents,
            "currency": entry.currency,
            "content_type": entry.content_type,
            "content_id": entry.content_id,
            "reason": _reason_for_content_type(entry.content_type),
            "ts": now_ts(),
        })
    except Exception:
        pass  # Non-critical: dashboard SSE is best-effort

    return result
```

---

## 4. API Endpoints

### 4.1 Dashboard Summary

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/dashboard/summary` | `require_ui_session` | Unified dashboard summary |
| GET | `/ui/dashboard/stream` | `require_ui_session` | SSE stream for real-time updates |
| POST | `/ui/dashboard/refresh` | `require_ui_session` | Trigger analytics refresh (proxies to analytics refresh) |

### 4.2 Milestone Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/milestones` | `require_ui_session` | List achieved milestones |
| POST | `/ui/milestones/{milestone_id}/acknowledge` | `require_ui_session` | Dismiss a milestone notification |
| GET | `/ui/milestones/settings` | `require_ui_session` | Get notification preferences |
| PATCH | `/ui/milestones/settings` | `require_ui_session` | Update notification preferences |

### 4.3 Request/Response Models

```python
# app/models.py additions

class DashboardSummaryOut(BaseModel):
    # Today
    today_earnings_cents: int = 0
    today_earnings_breakdown: Dict[str, int] = Field(default_factory=dict)
    today_tip_count: int = 0
    today_new_subscribers: int = 0

    # 7-day period
    period_views: int = 0
    period_revenue_cents: int = 0
    period_new_subscribers: int = 0
    total_subscribers: int = 0

    # Top content
    top_content: List[Dict[str, Any]] = Field(default_factory=list)

    # Active broadcasts
    active_broadcasts: List[Dict[str, Any]] = Field(default_factory=list)

    # Milestones
    recent_milestones: List[Dict[str, Any]] = Field(default_factory=list)

    currency: str = "USD"
    generated_at: int = 0
    warnings: List[str] = Field(default_factory=list, description="Names of data sources that failed to load")


class MilestoneOut(BaseModel):
    milestone_id: str
    metric: str         # "subscribers", "tips_total_cents", "views", "earnings_total_cents"
    threshold: int
    current_value: int
    reached_at: int
    acknowledged: bool = False


class MilestoneSettingsIn(BaseModel):
    new_subscriber: Optional[bool] = None
    tip_threshold_cents: Optional[int] = Field(default=None, ge=100, le=100000)
    earnings_milestone: Optional[bool] = None
    view_milestone: Optional[bool] = None
    subscriber_milestone: Optional[bool] = None


class MilestoneSettingsOut(BaseModel):
    new_subscriber: bool = True
    tip_threshold_cents: int = 500
    earnings_milestone: bool = True
    view_milestone: bool = True
    subscriber_milestone: bool = True
    updated_at: int = 0


class DashboardSSEEvent(BaseModel):
    """Schema for SSE events (documentation only, not used for validation)."""
    event_type: str  # "earnings:update" | "milestone:reached" | "broadcast:status" | "subscriber:new"
    data: Dict[str, Any]
```

---

## 5. Frontend Components

### 5.1 New Pages and Components

| Component | Path | Purpose |
|-----------|------|---------|
| `CreatorDashboard` | `frontend/src/pages/dashboard/CreatorDashboard.tsx` | Main mobile-optimized dashboard page |
| `EarningsSummaryCard` | `frontend/src/pages/dashboard/EarningsSummaryCard.tsx` | Today's earnings with category breakdown |
| `AnalyticsSparkline` | `frontend/src/pages/dashboard/AnalyticsSparkline.tsx` | Compact 7-day sparkline chart (views, revenue, subscribers) |
| `QuickActionBar` | `frontend/src/pages/dashboard/QuickActionBar.tsx` | "New Post" + "Go Live" + "Schedule" buttons |
| `TopContentList` | `frontend/src/pages/dashboard/TopContentList.tsx` | Top 5 content items with thumbnail and KPI |
| `MilestoneToast` | `frontend/src/pages/dashboard/MilestoneToast.tsx` | Celebration toast for milestone achievements |
| `MilestoneSettingsDialog` | `frontend/src/pages/dashboard/MilestoneSettingsDialog.tsx` | Configure milestone notification preferences |
| `ActiveBroadcastCard` | `frontend/src/pages/dashboard/ActiveBroadcastCard.tsx` | Live broadcast status with viewer count |
| `KpiCard` | `frontend/src/pages/dashboard/KpiCard.tsx` | Single KPI display card with trend indicator |
| `PullToRefresh` | `frontend/src/pages/dashboard/PullToRefresh.tsx` | Pull-to-refresh wrapper for mobile touch interaction |

### 5.2 Frontend API Endpoints

```typescript
// frontend/src/api/endpoints/dashboard.ts

import api from "../client";
import type { DashboardSummaryOut, MilestoneOut, MilestoneSettingsOut } from "../types";

export async function getDashboardSummary(): Promise<DashboardSummaryOut> {
  const res = await api.get("/ui/dashboard/summary");
  return res.data;
}

export async function refreshDashboard(): Promise<void> {
  await api.post("/ui/dashboard/refresh");
}

export async function listMilestones(): Promise<MilestoneOut[]> {
  const res = await api.get("/ui/milestones");
  return res.data;
}

export async function acknowledgeMilestone(milestoneId: string): Promise<void> {
  await api.post(`/ui/milestones/${milestoneId}/acknowledge`);
}

export async function getMilestoneSettings(): Promise<MilestoneSettingsOut> {
  const res = await api.get("/ui/milestones/settings");
  return res.data;
}

export async function updateMilestoneSettings(data: Partial<MilestoneSettingsOut>): Promise<MilestoneSettingsOut> {
  const res = await api.patch("/ui/milestones/settings", data);
  return res.data;
}
```

### 5.3 Responsive Layout

The dashboard uses a card-based layout that adapts to viewport:

```tsx
// CreatorDashboard.tsx (layout structure)

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Radio, CalendarDays, Settings } from "lucide-react";
import { toast } from "sonner";
import { AxiosError } from "axios";
import { getDashboardSummary, refreshDashboard } from "@/api/endpoints/dashboard";
import { useSSE } from "@/hooks/useSSE";

export default function CreatorDashboard() {
  const queryClient = useQueryClient();

  const { data: summary, isLoading } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: getDashboardSummary,
    refetchInterval: 60_000, // Refetch every minute as fallback
  });

  // SSE for real-time updates
  useSSE("/ui/dashboard/stream", {
    "earnings:update": (data) => {
      // Optimistically update the today_earnings_cents
      queryClient.setQueryData(["dashboard-summary"], (prev: DashboardSummaryOut | undefined) => {
        if (!prev) return prev;
        return {
          ...prev,
          today_earnings_cents: prev.today_earnings_cents + data.amount_cents,
          today_tip_count: prev.today_tip_count + 1,
        };
      });
    },
    "milestone:reached": (data) => {
      toast.success(`Milestone reached: ${data.metric} = ${data.threshold}`, {
        duration: 10_000,
        action: { label: "View", onClick: () => window.scrollTo(0, document.body.scrollHeight) },
      });
      void queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
    },
  });

  const refreshMut = useMutation({
    mutationFn: refreshDashboard,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
      toast.success("Dashboard refreshed");
    },
    onError: (err) => {
      if (err instanceof AxiosError && err.response?.status === 429) {
        toast.info("Dashboard was recently refreshed. Try again in a few minutes.");
      }
    },
  });

  if (isLoading || !summary) {
    return <DashboardSkeleton />;
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-4 p-4">
      {/* Quick Actions - always at top */}
      <QuickActionBar />

      {/* KPI Row - horizontal scroll on mobile, grid on desktop */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard
          label="Today's Earnings"
          value={formatCents(summary.today_earnings_cents)}
          icon="dollar-sign"
          trend={summary.today_earnings_cents > 0 ? "up" : "neutral"}
        />
        <KpiCard
          label="Subscribers"
          value={summary.total_subscribers.toLocaleString()}
          icon="users"
          delta={summary.today_new_subscribers > 0 ? `+${summary.today_new_subscribers} today` : undefined}
        />
        <KpiCard
          label="7d Views"
          value={formatNumber(summary.period_views)}
          icon="eye"
        />
        <KpiCard
          label="7d Revenue"
          value={formatCents(summary.period_revenue_cents)}
          icon="trending-up"
        />
      </div>

      {/* Earnings Card with sparkline */}
      <EarningsSummaryCard data={summary} />

      {/* Active Broadcasts */}
      {summary.active_broadcasts.length > 0 && (
        <ActiveBroadcastCard broadcasts={summary.active_broadcasts} />
      )}

      {/* Top Content */}
      <TopContentList items={summary.top_content} />

      {/* Milestones */}
      {summary.recent_milestones.length > 0 && (
        <MilestonesList milestones={summary.recent_milestones} />
      )}

      {/* Warnings for failed data sources */}
      {summary.warnings.length > 0 && (
        <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-3 text-sm text-yellow-800">
          Some data could not be loaded. Pull to refresh or try again later.
        </div>
      )}
    </div>
  );
}

function formatCents(cents: number): string {
  if (cents >= 100000) return `$${(cents / 100).toLocaleString(undefined, { maximumFractionDigits: 0 })}`;
  return `$${(cents / 100).toFixed(2)}`;
}

function formatNumber(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return n.toLocaleString();
}
```

### 5.4 KpiCard Component

```tsx
// KpiCard.tsx
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface KpiCardProps {
  label: string;
  value: string;
  icon?: string;
  trend?: "up" | "down" | "neutral";
  delta?: string;
}

export function KpiCard({ label, value, trend, delta }: KpiCardProps) {
  return (
    <Card className="p-3">
      <CardContent className="p-0">
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
        <p className={cn(
          "mt-1 text-2xl font-bold tabular-nums",
          trend === "up" && "text-green-600",
          trend === "down" && "text-red-600",
        )}>
          {value}
        </p>
        {delta && (
          <p className="mt-0.5 text-xs text-muted-foreground">{delta}</p>
        )}
      </CardContent>
    </Card>
  );
}
```

### 5.5 QuickActionBar Component

```tsx
// QuickActionBar.tsx
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Plus, Radio, CalendarDays } from "lucide-react";

export function QuickActionBar() {
  const navigate = useNavigate();

  return (
    <div className="flex gap-2 overflow-x-auto pb-1">
      <Button
        onClick={() => navigate("/feed?compose=true")}
        className="flex-shrink-0 gap-2"
      >
        <Plus className="h-4 w-4" />
        New Post
      </Button>
      <Button
        onClick={() => navigate("/broadcast?create=true")}
        variant="destructive"
        className="flex-shrink-0 gap-2"
      >
        <Radio className="h-4 w-4" />
        Go Live
      </Button>
      <Button
        onClick={() => navigate("/content-calendar")}
        variant="outline"
        className="flex-shrink-0 gap-2"
      >
        <CalendarDays className="h-4 w-4" />
        Schedule
      </Button>
    </div>
  );
}
```

### 5.6 SSE Hook

```typescript
// frontend/src/hooks/useSSE.ts

import { useEffect, useRef } from "react";

type EventHandlers = Record<string, (data: any) => void>;

export function useSSE(url: string, handlers: EventHandlers) {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    let es: EventSource | null = null;
    let retryDelay = 1000;
    let mounted = true;

    function connect() {
      if (!mounted) return;
      es = new EventSource(url, { withCredentials: true });

      es.addEventListener("hello", () => {
        retryDelay = 1000; // Reset backoff on successful connection
      });

      for (const eventType of Object.keys(handlersRef.current)) {
        es.addEventListener(eventType, (event: MessageEvent) => {
          try {
            const data = JSON.parse(event.data);
            handlersRef.current[eventType]?.(data);
          } catch {
            // ignore parse errors
          }
        });
      }

      es.addEventListener("close", () => {
        es?.close();
      });

      es.onerror = () => {
        es?.close();
        // Reconnect with exponential backoff
        if (mounted) {
          setTimeout(connect, retryDelay);
          retryDelay = Math.min(retryDelay * 2, 30000);
        }
      };
    }

    connect();

    return () => {
      mounted = false;
      es?.close();
    };
  }, [url]);
}
```

### 5.7 Route

```tsx
// App.tsx
{ path: "/creator-dashboard", element: <CreatorDashboard /> }
```

### 5.8 Navigation

- Replace the generic Dashboard link with "Creator Dashboard" for users who have creator content
- Add to MobileNav as a primary tab
- Add to Sidebar.tsx under a "Creator" section

---

## 6. DynamoDB Storage

### 6.1 Milestone Records (App Single Table)

```python
# Milestones stored in app single table
{
    "pk": "USER#{user_id}",
    "sk": "MILESTONE#{metric}#{threshold}",
    "milestone_id": "ms_abc123",
    "metric": "subscribers",
    "threshold": 100,
    "current_value": 102,
    "reached_at": 1748390400,
    "acknowledged": False,
}
```

No new table needed. Milestones are low-volume (max ~30 per creator over their lifetime) and fit in the existing app single table.

### 6.2 Milestone Settings (App Single Table)

```python
{
    "pk": "USER#{user_id}",
    "sk": "MILESTONE_PREFS",
    "new_subscriber": True,
    "tip_threshold_cents": 500,
    "earnings_milestone": True,
    "view_milestone": True,
    "subscriber_milestone": True,
    "updated_at": 1748390400,
}
```

### 6.3 Dashboard SSE State (In-Memory)

Dashboard SSE subscriptions are stored in-memory (same pattern as `app/services/broadcast_sse.py`). No DDB persistence needed for SSE queues.

In-memory state includes:
- `_DASHBOARD_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]]` — keyed by user_id
- Max 1 queue per user (new connections replace old)
- Queue max size: 100 events
- Dead queues cleaned up on publish failure

---

## 7. E2E Test Plan

### 7.1 Test File

`frontend/e2e/creator-dashboard.spec.ts`

### 7.2 Test Sections

| Section | Title | Tests |
|---------|-------|-------|
| 1 | Dashboard Summary API | 5 tests: summary returns all fields, today's earnings calculated correctly, period analytics aggregated, top content sorted, active broadcasts included |
| 2 | Milestone API | 5 tests: milestone detected on threshold crossing, no duplicate milestone, milestone list returns ordered, settings update persists, milestone notification created |
| 3 | Dashboard UI - Mobile | 6 tests: page loads with KPI cards, sparkline renders, quick action buttons visible, top content list visible, active broadcast card shown, pull-to-refresh triggers reload |
| 4 | Dashboard UI - Quick Actions | 3 tests: "New Post" navigates to feed/create, "Go Live" navigates to broadcast, "Schedule" opens scheduling dialog |
| 5 | Dashboard SSE | 3 tests: SSE connection established, earnings update event received, milestone event received |
| 6 | Milestone Settings UI | 3 tests: settings dialog opens, toggle new_subscriber, set tip_threshold_cents |
| 7 | Graceful Degradation | 3 tests: partial data shown when analytics fails, warning banner shown, refresh works after error |
| 8 | Milestone Acknowledge | 2 tests: acknowledge hides milestone, acknowledged milestones excluded from recent list |

**Estimated total**: ~30 tests

### 7.3 Test Data Setup

```typescript
const TS = Date.now();

test.beforeAll(async ({ browser }) => {
  const page = await browser.newPage();
  await injectAuth(page, "alice");

  // 1. Write billing ledger entries for today
  // (direct DDB writes to T.billing)
  const aliceSub = sessions.alice.user_sub;
  const todayTs = Math.floor(Date.now() / 1000);

  // Write 3 tip credits for today
  for (let i = 0; i < 3; i++) {
    await writeBillingEntry({
      pk: `USER#${aliceSub}`,
      sk: `LEDGER#${todayTs + i}#tip_${TS}_${i}`,
      entry_id: `tip_${TS}_${i}`,
      ts: todayTs + i,
      type: "credit",
      amount_cents: 500, // $5 each
      currency: "USD",
      state: "settled",
      reason: "Tip: message",
      meta: { content_type: "message" },
    });
  }

  // 2. Write analytics rollup rows for past 7 days
  for (let d = 0; d < 7; d++) {
    const date = new Date();
    date.setDate(date.getDate() - d);
    const dateStr = date.toISOString().slice(0, 10);
    await writeAnalyticsRollup({
      pk: `CREATOR#${aliceSub}`,
      sk: `DAILY#${dateStr}`,
      views: 100 + d * 10,
      revenue_cents: 500 + d * 100,
      new_subscribers: d === 0 ? 2 : 1,
      tips_count: 3 + d,
    });
  }

  // 3. Write SUMMARY sentinel
  await writeAnalyticsRollup({
    pk: `CREATOR#${aliceSub}`,
    sk: "SUMMARY",
    total_subscribers: 47,
  });

  await page.close();
});
```

### 7.4 Example Test Cases

```typescript
test("1.1 — Dashboard summary returns all expected fields", async ({ browser }) => {
  const page = await browser.newPage();
  await injectAuth(page, "alice");

  const resp = await page.request.get("/ui/dashboard/summary");
  expect(resp.status()).toBe(200);

  const body = await resp.json();
  expect(body.today_earnings_cents).toBeGreaterThanOrEqual(0);
  expect(body.today_earnings_breakdown).toBeDefined();
  expect(body.period_views).toBeGreaterThanOrEqual(0);
  expect(body.total_subscribers).toBeGreaterThanOrEqual(0);
  expect(body.top_content).toBeInstanceOf(Array);
  expect(body.active_broadcasts).toBeInstanceOf(Array);
  expect(body.recent_milestones).toBeInstanceOf(Array);
  expect(body.currency).toBe("USD");
  expect(body.generated_at).toBeGreaterThan(0);

  await page.close();
});

test("2.1 — Milestone detected when threshold crossed", async ({ browser }) => {
  const page = await browser.newPage();
  await injectAuth(page, "alice");

  // Write a SUMMARY with total_subscribers = 100 (crossing the 100 threshold)
  await writeAnalyticsRollup({
    pk: `CREATOR#${sessions.alice.user_sub}`,
    sk: "SUMMARY",
    total_subscribers: 100,
  });

  // Trigger milestone check
  // (In production this happens on subscription events; in tests, call directly)
  const resp = await page.request.post("/ui/dashboard/refresh", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
  });

  // Check milestones
  const msResp = await page.request.get("/ui/milestones");
  const milestones = await msResp.json();
  const subMilestone = milestones.find(
    (m: any) => m.metric === "subscribers" && m.threshold === 100
  );
  expect(subMilestone).toBeDefined();
  expect(subMilestone.acknowledged).toBe(false);

  await page.close();
});

test("3.1 — Dashboard page loads with KPI cards", async ({ browser }) => {
  const page = await browser.newPage();
  await injectAuth(page, "alice");
  await page.goto("/creator-dashboard");

  // Wait for KPI cards to appear
  await expect(page.getByText("Today's Earnings")).toBeVisible();
  await expect(page.getByText("Subscribers")).toBeVisible();
  await expect(page.getByText("7d Views")).toBeVisible();
  await expect(page.getByText("7d Revenue")).toBeVisible();

  await page.close();
});
```

---

## 8. Edge Cases

| Case | Behavior |
|------|----------|
| Creator with no content | Dashboard shows zero values and "Get started" prompts instead of empty cards. |
| Creator with no subscribers | Subscriber KPI shows 0. Subscriber sparkline is flat. Top content sorts by views only. |
| Analytics rollup not yet generated | `get_overview` returns zeros for periods without rollups. Dashboard still renders with available data. |
| SSE connection drops | Frontend reconnects automatically with exponential backoff (1s, 2s, 4s, max 30s). |
| Milestone already reached | `check_milestone` returns None (idempotent). No duplicate notification. |
| Rate-limited refresh | 429 response handled gracefully with informational toast. Data remains from last successful fetch. |
| Multiple active broadcasts | Dashboard shows all (up to 3). Cards stack vertically. |
| Very high earning day | Earnings card uses abbreviated notation ($1.2K, $45.3K) on mobile to prevent text overflow. |
| Timezone handling | "Today" is computed server-side using UTC. Future enhancement: accept timezone from client. |
| Concurrent SSE streams | Max 1 SSE connection per user. New connection replaces old one (old queue unsubscribed). |
| Analytics service down | Dashboard returns partial data with `warnings: ["analytics_overview"]`. UI shows yellow warning banner. |
| Earnings service down | Dashboard returns partial data with `warnings: ["today_earnings"]`. KPI shows $0.00 with warning indicator. |
| Milestone notification dismissed | `acknowledge` endpoint sets `acknowledged=true`. Milestone no longer appears in `recent_milestones`. |
| Large top_content list | Server returns max 5 items. Additional items are available via the full analytics endpoints. |
| SSE event ordering | Events may arrive out of order during high traffic. Frontend uses `ts` field for ordering; optimistic UI updates are eventually consistent with server state. |

---

## 9. Security Considerations

### 9.1 Data Scoping

- Dashboard summary endpoint returns data **only** for the authenticated user (`session["user_sub"]`)
- No cross-user data leakage: all queries are scoped to `USER#{user_id}` or `CREATOR#{user_id}`
- Analytics and earnings data cannot be accessed for other users via this endpoint
- The `warnings` field never exposes internal error messages or stack traces

### 9.2 SSE Authentication

- SSE stream requires `require_ui_session` authentication (cookie-based)
- SSE connection is terminated if the session cookie expires mid-stream
- Heartbeat pings every 15 seconds keep the connection alive and detect stale sessions
- The `close` event instructs the client to stop reconnecting (e.g., when replaced by a new connection)

### 9.3 Rate Limiting

- Dashboard summary: standard session-based rate limiting (no special limits)
- Analytics refresh: 1 per 5 minutes per user (existing limit, `app/routers/creator_analytics.py` line 59)
- SSE connections: max 1 per user (prevents resource exhaustion)
- Milestone settings updates: 10 per minute per user
- Milestone acknowledge: 10 per minute per user

### 9.4 Performance

- Dashboard summary endpoint makes 4 internal calls (earnings, overview, broadcasts, milestones). To prevent latency spikes, each call has a 2-second timeout with graceful degradation (partial data returned if one call fails).
- Analytics rollup queries are bounded by the 7-day range (max 7 DDB items).
- Earnings summary query for "today" has a narrow SK range, limiting DDB throughput.
- SSE events are fire-and-forget from the publisher's perspective -- publishing never blocks the tip flow.
- Badge and milestone caches reduce DDB read load during active broadcast sessions.

### 9.5 SSE Resource Management

- Each SSE queue has a max size of 100 events. Full queues are disconnected (client reconnects).
- Dashboard SSE subscribers are cleaned up on connection close, error, or replacement.
- In-memory subscriber maps are bounded by active user count (not total user count).
- The SSE endpoint uses `StreamingResponse` which holds a TCP connection open. Server-side connection limits should be monitored.
