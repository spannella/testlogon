"""
Rate limit event logging and dashboard queries (PLATFORM-001).
"""
from __future__ import annotations

import logging
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Async event logging (fire-and-forget)
# ---------------------------------------------------------------------------

def log_rate_limit_event(
    *,
    endpoint_group: str,
    identity_type: str,
    identity_value: str,
    endpoint: str,
    method: str,
    status: str,
    count: int = 0,
    limit: int = 0,
) -> None:
    """
    Write a rate-limit event to the events table.

    Called fire-and-forget; failures are logged but not propagated.
    """
    try:
        now = now_ts()
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        date_str = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")
        ttl = now + S.rate_limit_events_ttl_days * 86400

        T.rate_limit_events.put_item(Item={
            "pk": f"DATE#{date_str}",
            "sk": f"{now}#{event_id}",
            "endpoint_group": endpoint_group,
            "identity_type": identity_type,
            "identity_value": identity_value,
            "endpoint": endpoint,
            "method": method,
            "status": status,
            "count": count,
            "limit": limit,
            "ttl_epoch": ttl,
        })
    except Exception:
        logger.warning("rate_limit_dashboard: failed to log event", exc_info=True)


# ---------------------------------------------------------------------------
# Dashboard queries
# ---------------------------------------------------------------------------

def query_events(
    *,
    hours: int = 1,
    limit: int = 100,
    status_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Query rate limit events for the last *hours*."""
    now = now_ts()
    results: list = []

    # Query each date partition that falls within the window
    start_ts = now - hours * 3600
    start_date = datetime.fromtimestamp(start_ts, tz=timezone.utc)
    end_date = datetime.fromtimestamp(now, tz=timezone.utc)

    dates_to_query = set()
    current = start_date.date()
    end = end_date.date()
    while current <= end:
        dates_to_query.add(current.strftime("%Y-%m-%d"))
        current += timedelta(days=1)
        if len(dates_to_query) > 7:
            break

    for date_str in sorted(dates_to_query):
        try:
            kwargs: dict = {
                "KeyConditionExpression": "pk = :pk AND sk >= :sk_start",
                "ExpressionAttributeValues": {
                    ":pk": f"DATE#{date_str}",
                    ":sk_start": str(start_ts),
                },
                "Limit": limit,
                "ScanIndexForward": False,
            }
            if status_filter:
                kwargs["FilterExpression"] = "#st = :sf"
                kwargs["ExpressionAttributeNames"] = {"#st": "status"}
                kwargs["ExpressionAttributeValues"][":sf"] = status_filter

            resp = T.rate_limit_events.query(**kwargs)
            results.extend(resp.get("Items", []))
        except Exception:
            logger.warning("rate_limit_dashboard: query_events failed for %s", date_str, exc_info=True)

    # Sort by sk descending and cap
    results.sort(key=lambda x: x.get("sk", ""), reverse=True)
    return results[:limit]


def get_top_offenders(
    *,
    hours: int = 1,
    limit: int = 20,
) -> Dict[str, Any]:
    """Aggregate rejected events to find top offending IPs and users."""
    events = query_events(hours=hours, limit=2000, status_filter="rejected")

    ip_counter: Counter = Counter()
    user_counter: Counter = Counter()
    ip_last_seen: Dict[str, int] = {}
    user_last_seen: Dict[str, int] = {}

    for evt in events:
        identity_type = evt.get("identity_type", "")
        identity_value = evt.get("identity_value", "")
        sk = evt.get("sk", "")
        ts = int(sk.split("#")[0]) if "#" in sk else 0

        if identity_type == "ip":
            ip_counter[identity_value] += 1
            ip_last_seen[identity_value] = max(ip_last_seen.get(identity_value, 0), ts)
        elif identity_type == "user":
            user_counter[identity_value] += 1
            user_last_seen[identity_value] = max(user_last_seen.get(identity_value, 0), ts)

    top_ips = [
        {"ip": ip, "rejected_count": count, "last_seen": ip_last_seen.get(ip, 0)}
        for ip, count in ip_counter.most_common(limit)
    ]
    top_users = [
        {"user_sub": user, "rejected_count": count, "last_seen": user_last_seen.get(user, 0)}
        for user, count in user_counter.most_common(limit)
    ]

    return {"top_ips": top_ips, "top_users": top_users}
