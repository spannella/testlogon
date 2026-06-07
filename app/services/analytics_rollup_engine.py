"""Analytics rollup engine (ANALYTICS-001 / PLATFORM-019, GAP-0335).

Background loop that aggregates raw events from ``analytics_events`` into daily
rollup rows in ``analytics_rollups``. Runs every
``S.analytics_rollup_interval_seconds`` and reprocesses the last
``S.analytics_rollup_lookback_days`` days to absorb late-arriving events.

Reuses the existing rollup write primitive ``upsert_daily_rollup`` from
``app/services/creator_analytics.py`` — no new rollup table is introduced.

Canonical signature: ``compute_daily_rollups(lookback_days: int | None = None)``
(GAP-0335 design; GAP-0336's ``/refresh`` endpoint calls it accordingly).

Event read schema (written by ``analytics_events.py``):
  pk:     EVENT#{creator_id}#{YYYYMMDD}   ← per-creator-per-day partition
  GSI1PK: CREATOR#{creator_id}
  GSI1SK: DATE#{YYYY-MM-DD}

Per-creator-per-day reads use a single base-table ``query`` on
``pk = EVENT#{creator_id}#{yyyymmdd}``. Active-creator discovery for a day uses a
``scan`` with a ``FilterExpression`` on ``GSI1SK = DATE#{date}`` — a GSI
``query`` keyed on the sort key alone is invalid in DynamoDB (GAP-0335
second-pass correction), so a filtered scan is used instead.

Dev/prod parity (SECOPS-007): only ``T.analytics_events`` /
``T.analytics_rollups`` are touched; the loop is gated by
``S.analytics_rollup_enabled``. No ``dev_mode`` branch.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Set

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.services.creator_analytics import upsert_daily_rollup

logger = logging.getLogger(__name__)


# ── Date helpers ──────────────────────────────────────────────────────────────

def _yyyymmdd(date_str: str) -> str:
    """Convert 'YYYY-MM-DD' → 'YYYYMMDD' (the pk date segment)."""
    return date_str.replace("-", "")


def _lookback_dates(lookback_days: int) -> List[str]:
    """Return ['YYYY-MM-DD', ...] for today back through ``lookback_days`` days."""
    days = max(1, int(lookback_days or 1))
    today = datetime.now(tz=timezone.utc).date()
    return [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days)]


def _to_int(v: Any) -> int:
    if isinstance(v, Decimal):
        return int(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# ── Event fetching ────────────────────────────────────────────────────────────

def _fetch_events_for_creator_date(creator_id: str, date_str: str) -> List[Dict[str, Any]]:
    """Fetch all raw events for a creator on a given day via the base-table pk."""
    pk = f"EVENT#{creator_id}#{_yyyymmdd(date_str)}"
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {"KeyConditionExpression": Key("pk").eq(pk)}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = T.analytics_events.query(**kwargs)
        except Exception:
            logger.exception(
                "rollup.fetch_events failed creator=%s date=%s", creator_id, date_str
            )
            break
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def _get_active_creator_ids(date_str: str) -> List[str]:
    """Find all distinct creator ids with events on ``date_str``.

    Uses a filtered scan on ``GSI1SK = DATE#{date}`` (a GSI query keyed only on
    the sort key is invalid in DynamoDB — see module docstring).
    """
    creator_ids: Set[str] = set()
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "FilterExpression": Attr("GSI1SK").eq(f"DATE#{date_str}"),
            "ProjectionExpression": "creator_id, GSI1PK",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = T.analytics_events.scan(**kwargs)
        except Exception:
            logger.exception("rollup.get_active_creators failed date=%s", date_str)
            break
        for item in resp.get("Items", []):
            cid = item.get("creator_id")
            if not cid:
                gpk = item.get("GSI1PK", "")
                if gpk.startswith("CREATOR#"):
                    cid = gpk[len("CREATOR#"):]
            if cid:
                creator_ids.add(cid)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return list(creator_ids)


# ── Aggregation ───────────────────────────────────────────────────────────────

def _compute_creator_daily(creator_id: str, day: str) -> Dict[str, Any]:
    """Aggregate all raw events for ``creator_id`` on ``day`` into a rollup dict."""
    events = _fetch_events_for_creator_date(creator_id, day)

    data: Dict[str, Any] = {
        "total_views": 0,
        "unique_viewers": 0,
        "watch_time_seconds": 0,
        "revenue_cents": 0,
        "revenue_tips_cents": 0,
        "revenue_subscriptions_cents": 0,
        "revenue_unlocks_cents": 0,
        "revenue_vod_cents": 0,
        "revenue_ads_cents": 0,
        "revenue_calls_cents": 0,
        "new_subscribers": 0,
        "churned_subscribers": 0,
        "net_subscribers": 0,
        "post_reactions": 0,
        "post_comments": 0,
        "post_shares": 0,
    }

    viewers: Set[str] = set()
    countries: Dict[str, int] = defaultdict(int)
    devices: Dict[str, int] = defaultdict(int)

    for evt in events:
        etype = evt.get("event_type", "")

        if etype == "page_view":
            data["total_views"] += 1
            viewer = evt.get("viewer_id", "")
            if viewer and viewer != "anonymous":
                viewers.add(viewer)
            data["watch_time_seconds"] += _to_int(evt.get("watch_time_seconds", 0))
            country = evt.get("country_code")
            if country:
                countries[country] += 1
            device = evt.get("device_type")
            if device:
                devices[device] += 1

        elif etype == "revenue":
            cents = _to_int(evt.get("amount_cents", 0))
            data["revenue_cents"] += cents
            rtype = evt.get("revenue_type", "")
            if rtype == "tip":
                data["revenue_tips_cents"] += cents
            elif rtype == "subscription":
                data["revenue_subscriptions_cents"] += cents
            elif rtype == "unlock":
                data["revenue_unlocks_cents"] += cents
            elif rtype == "vod":
                data["revenue_vod_cents"] += cents
            elif rtype == "ad":
                data["revenue_ads_cents"] += cents
            elif rtype == "call":
                data["revenue_calls_cents"] += cents

        elif etype == "subscriber":
            kind = evt.get("event_kind", "")
            if kind == "new":
                data["new_subscribers"] += 1
            elif kind in ("cancelled", "churned"):
                data["churned_subscribers"] += 1

        elif etype == "engagement":
            action = evt.get("action", "")
            if action == "reaction":
                data["post_reactions"] += 1
            elif action == "comment":
                data["post_comments"] += 1
            elif action == "share":
                data["post_shares"] += 1

    data["unique_viewers"] = len(viewers)
    data["net_subscribers"] = data["new_subscribers"] - data["churned_subscribers"]
    if countries:
        data["audience_countries"] = dict(countries)
    if devices:
        data["audience_devices"] = dict(devices)

    return data


# ── Rollup computation ────────────────────────────────────────────────────────

def compute_daily_rollups(lookback_days: int | None = None) -> int:
    """Recompute daily rollups for all active creators over the lookback window.

    Reads raw events from ``T.analytics_events`` and writes aggregated daily rows
    via ``upsert_daily_rollup``. Returns the count of (creator, day) pairs
    processed.
    """
    if lookback_days is None:
        lookback_days = S.analytics_rollup_lookback_days
    dates = _lookback_dates(lookback_days)
    processed = 0

    for day in dates:
        for creator_id in _get_active_creator_ids(day):
            try:
                data = _compute_creator_daily(creator_id, day)
                upsert_daily_rollup(creator_id, day, data)
                processed += 1
            except Exception:
                logger.exception(
                    "rollup.compute_creator_daily failed creator=%s date=%s",
                    creator_id, day,
                )

    logger.info(
        "rollup.compute_daily_rollups complete days=%d processed=%d",
        len(dates), processed,
    )
    return processed


# ── Background loop ───────────────────────────────────────────────────────────

async def run_rollup_loop() -> None:
    """Background coroutine: compute daily rollups on a fixed interval."""
    interval = max(60, int(S.analytics_rollup_interval_seconds or 900))
    logger.info(
        "analytics_rollup_engine.start interval=%ds lookback=%dd",
        interval, S.analytics_rollup_lookback_days,
    )
    while True:
        try:
            n = compute_daily_rollups()
            logger.info("analytics_rollup_engine.ran processed=%d", n)
        except Exception:
            logger.exception("analytics_rollup_engine.loop_error")
        await asyncio.sleep(interval)


def start_analytics_rollup_task() -> None:
    """FastAPI startup handler: launch ``run_rollup_loop`` as a background task."""
    if not S.analytics_rollup_enabled:
        logger.info("analytics_rollup_engine.disabled (ANALYTICS_ROLLUP_ENABLED=0)")
        return
    asyncio.ensure_future(run_rollup_loop())
    logger.info("analytics_rollup_engine.task_created")
