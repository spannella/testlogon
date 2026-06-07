"""Analytics event recording service (ANALYTICS-001 / PLATFORM-019, GAP-0334).

Writes raw event records to the ``analytics_events`` DynamoDB table. Records are
TTL-tagged (via ``ttl_epoch``) for automatic expiry after ``_TTL_DAYS`` days. The
rollup engine (``analytics_rollup_engine.py``, GAP-0335) aggregates these into
daily rows in the ``analytics_rollups`` table for the creator dashboard.

Event key schema (matches scripts/local-ddb-init.py AnalyticsEvents TableDef):
  pk:     EVENT#{creator_id}#{YYYYMMDD}   ← one partition per creator per day
  sk:     {event_type}#{ts}#{short_uuid}
  GSI1PK: CREATOR#{creator_id}            ← cross-day creator query
  GSI1SK: DATE#{YYYY-MM-DD}

The rollup engine queries ``pk = EVENT#{creator_id}#{yyyymmdd}`` to read all of a
creator's events for a single day efficiently (a single ``query`` on the base
table, no GSI hop required).

There is intentionally NO ``S.analytics_events_ttl_days`` setting (GAP-0334
second-pass correction); the retention window is hard-coded here.

Dev/prod parity (SECOPS-007): the service uses only ``T.analytics_events`` — the
same DynamoDB code path runs in dev (DynamoDB Local) and prod (real DynamoDB),
with no ``dev_mode`` branch.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Raw-event retention. No S.analytics_events_ttl_days setting exists — hard-coded.
_TTL_DAYS = 90

_ANON = "anonymous"


def _yyyymmdd(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d")


def _date_str(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def _event_sk(event_type: str, ts: int) -> str:
    return f"{event_type}#{ts}#{uuid.uuid4().hex[:8]}"


def _ttl_epoch(ts: int) -> int:
    return ts + _TTL_DAYS * 86400


def _base_item(creator_id: str, event_type: str, ts: int) -> Dict[str, Any]:
    return {
        "pk": f"EVENT#{creator_id}#{_yyyymmdd(ts)}",
        "sk": _event_sk(event_type, ts),
        "GSI1PK": f"CREATOR#{creator_id}",
        "GSI1SK": f"DATE#{_date_str(ts)}",
        "event_type": event_type,
        "creator_id": creator_id,
        "created_at": ts,
        "ttl_epoch": _ttl_epoch(ts),
    }


def record_page_view(
    creator_id: str,
    content_id: str,
    viewer_id: Optional[str] = None,
    watch_time_seconds: int = 0,
    country_code: Optional[str] = None,
    device_type: Optional[str] = None,
) -> None:
    """Record a content page view / VOD play event."""
    try:
        ts = now_ts()
        item = _base_item(creator_id, "page_view", ts)
        item.update({
            "content_id": content_id,
            "viewer_id": viewer_id or _ANON,
            "watch_time_seconds": int(watch_time_seconds or 0),
        })
        if country_code:
            item["country_code"] = country_code
        if device_type:
            item["device_type"] = device_type
        T.analytics_events.put_item(Item=item)
    except Exception:
        logger.exception(
            "analytics.record_page_view failed creator=%s content=%s",
            creator_id, content_id,
        )


def record_revenue_event(
    creator_id: str,
    revenue_type: str,
    amount_cents: int,
    subscriber_id: Optional[str] = None,
    content_id: Optional[str] = None,
) -> None:
    """Record a revenue event (subscription, tip, unlock, vod, ad, call)."""
    _VALID = {"subscription", "tip", "unlock", "vod", "ad", "call"}
    if revenue_type not in _VALID:
        logger.warning("analytics.record_revenue_event unknown type=%s", revenue_type)
        revenue_type = "other"
    try:
        ts = now_ts()
        item = _base_item(creator_id, "revenue", ts)
        item.update({
            "revenue_type": revenue_type,
            "amount_cents": int(amount_cents or 0),
        })
        if subscriber_id:
            item["subscriber_id"] = subscriber_id
        if content_id:
            item["content_id"] = content_id
        T.analytics_events.put_item(Item=item)
    except Exception:
        logger.exception(
            "analytics.record_revenue_event failed creator=%s type=%s",
            creator_id, revenue_type,
        )


def record_subscriber_event(
    creator_id: str,
    subscriber_id: str,
    event_kind: str,
) -> None:
    """Record a subscription lifecycle event (new, renewed, cancelled, churned)."""
    _VALID = {"new", "renewed", "cancelled", "churned"}
    if event_kind not in _VALID:
        logger.warning("analytics.record_subscriber_event unknown kind=%s", event_kind)
        event_kind = "other"
    try:
        ts = now_ts()
        item = _base_item(creator_id, "subscriber", ts)
        item.update({
            "event_kind": event_kind,
            "subscriber_id": subscriber_id,
        })
        T.analytics_events.put_item(Item=item)
    except Exception:
        logger.exception(
            "analytics.record_subscriber_event failed creator=%s kind=%s",
            creator_id, event_kind,
        )


def record_engagement_event(
    creator_id: str,
    content_id: str,
    actor_id: str,
    action: str,
) -> None:
    """Record a content engagement event (reaction, comment, share)."""
    _VALID = {"reaction", "comment", "share"}
    if action not in _VALID:
        logger.warning("analytics.record_engagement_event unknown action=%s", action)
        action = "other"
    try:
        ts = now_ts()
        item = _base_item(creator_id, "engagement", ts)
        item.update({
            "action": action,
            "content_id": content_id,
            "actor_id": actor_id,
        })
        T.analytics_events.put_item(Item=item)
    except Exception:
        logger.exception(
            "analytics.record_engagement_event failed creator=%s content=%s action=%s",
            creator_id, content_id, action,
        )
