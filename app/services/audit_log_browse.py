"""Audit Log Browse service — EVT-015.

Provides a single-page, synchronous DynamoDB read for the audit-log
browse endpoint.  Drives existing adapters with a per-page limit rather
than iterating the full result set.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.services.audit_adapters import ADAPTERS, VALID_CATEGORIES
from app.services.audit_export import UnifiedAuditEvent

logger = logging.getLogger(__name__)

_BROWSE_MAX_LIMIT = 200
_BROWSE_DEFAULT_LIMIT = 50


def browse_audit_log(
    *,
    category: str,
    from_ts: int,
    to_ts: int,
    user_sub_filter: Optional[str] = None,
    event_type_filter: Optional[str] = None,
    limit: int = _BROWSE_DEFAULT_LIMIT,
    cursor: Optional[str] = None,
) -> dict[str, Any]:
    """Paginated synchronous browse of a single audit category.

    Returns:
        {
            "items": list[dict],          # UnifiedAuditEvent.to_ndjson_dict() each
            "cursor": str | None,         # next-page opaque cursor; None = last page
            "total_scanned": int,
            "category": str,
            "from_ts": int,
            "to_ts": int,
        }
    Raises:
        ValueError: invalid category, date range issues.
    """
    # Validate
    if category not in VALID_CATEGORIES:
        raise ValueError(
            f"Unknown category: {category}. Valid: {', '.join(sorted(VALID_CATEGORIES))}"
        )
    if from_ts == 0 and to_ts == 0:
        raise ValueError("Date range is empty")
    if from_ts > to_ts:
        raise ValueError("from_ts must be <= to_ts")
    max_range = S.audit_export_max_date_range_days * 86400
    if (to_ts - from_ts) > max_range:
        raise ValueError(
            f"Date range exceeds maximum of {S.audit_export_max_date_range_days} days"
        )

    limit = min(limit, _BROWSE_MAX_LIMIT)
    decoded_cursor = decode_cursor(cursor)  # None on invalid/expired cursor → start from beginning

    # Drive a single DynamoDB page via the adapter's underlying tables
    items: list[dict] = []
    total_scanned = 0
    next_lek: Optional[dict] = None

    try:
        if category == "auth":
            items, total_scanned, next_lek = _browse_alerts(
                from_ts=from_ts,
                to_ts=to_ts,
                user_sub_filter=user_sub_filter,
                event_type_filter=event_type_filter,
                limit=limit,
                start_key=decoded_cursor,
            )
        elif category == "broadcast":
            items, total_scanned, next_lek = _browse_broadcast(
                from_ts=from_ts,
                to_ts=to_ts,
                limit=limit,
                start_key=decoded_cursor,
            )
        else:
            # moderation, admin, billing — scan-based
            items, total_scanned, next_lek = _browse_via_adapter(
                category=category,
                from_ts=from_ts,
                to_ts=to_ts,
                user_sub_filter=user_sub_filter,
                limit=limit,
                start_key=decoded_cursor,
            )
    except Exception:
        logger.warning("audit_log_browse query failed category=%s", category, exc_info=True)
        items, total_scanned, next_lek = [], 0, None

    next_cursor = encode_cursor(next_lek) if next_lek else None

    # Self-audit best-effort
    try:
        from app.services.alerts import audit_event  # lazy import (RULE-1)
        audit_event("crm_audit_log_browse", user_sub_filter or "root", category=category, from_ts=from_ts, to_ts=to_ts)
    except Exception:
        pass

    return {
        "items": items,
        "cursor": next_cursor,
        "total_scanned": total_scanned,
        "category": category,
        "from_ts": from_ts,
        "to_ts": to_ts,
    }


# ---------------------------------------------------------------------------
# Per-adapter browse helpers
# ---------------------------------------------------------------------------

def _event_to_dict(event: Optional[UnifiedAuditEvent]) -> Optional[dict]:
    if event is None:
        return None
    return event.to_ndjson_dict()


def _browse_alerts(
    *,
    from_ts: int,
    to_ts: int,
    user_sub_filter: Optional[str],
    event_type_filter: Optional[str],
    limit: int,
    start_key: Optional[dict],
) -> tuple[list[dict], int, Optional[dict]]:
    """Single-page browse of T.alerts (auth category)."""
    adapter = ADAPTERS["auth"]

    filter_expr = Attr("ts").between(from_ts, to_ts)
    if event_type_filter:
        filter_expr = filter_expr & Attr("event").eq(event_type_filter)

    if user_sub_filter:
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub_filter),
            "FilterExpression": filter_expr,
            "Limit": limit * 3,
            "ScanIndexForward": False,
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = T.alerts.query(**kwargs)
    else:
        kwargs = {
            "FilterExpression": filter_expr,
            "Limit": limit * 5,
        }
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = T.alerts.scan(**kwargs)

    raw_items = resp.get("Items", [])
    scanned = resp.get("ScannedCount", len(raw_items))
    lek = resp.get("LastEvaluatedKey")

    items = []
    for raw in raw_items[:limit]:
        try:
            event = adapter._item_to_event(raw)  # type: ignore[attr-defined]
            d = _event_to_dict(event)
            if d is not None:
                items.append(d)
        except Exception:
            pass

    return items, scanned, lek


def _browse_broadcast(
    *,
    from_ts: int,
    to_ts: int,
    limit: int,
    start_key: Optional[dict],
) -> tuple[list[dict], int, Optional[dict]]:
    """Single-page browse via BroadcastAuditAdapter GSI."""
    adapter = ADAPTERS["broadcast"]
    kwargs: dict[str, Any] = {
        "IndexName": "ByCreatedAt",
        "KeyConditionExpression": (
            Key("scope").eq("platform") & Key("created_at").between(str(from_ts), str(to_ts))
        ),
        "Limit": limit * 3,
    }
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key
    try:
        resp = T.broadcast_action_audit.query(**kwargs)
    except Exception:
        return [], 0, None

    raw_items = resp.get("Items", [])
    scanned = resp.get("ScannedCount", len(raw_items))
    lek = resp.get("LastEvaluatedKey")

    items = []
    for raw in raw_items[:limit]:
        try:
            event = adapter._item_to_event(raw)  # type: ignore[attr-defined]
            d = _event_to_dict(event)
            if d is not None:
                items.append(d)
        except Exception:
            pass

    return items, scanned, lek


def _browse_via_adapter(
    *,
    category: str,
    from_ts: int,
    to_ts: int,
    user_sub_filter: Optional[str],
    limit: int,
    start_key: Optional[dict],
) -> tuple[list[dict], int, Optional[dict]]:
    """Generic scan-based browse for moderation, admin, billing categories."""
    adapter = ADAPTERS[category]

    # Collect up to limit items from the adapter (one page)
    collected: list[dict] = []
    scanned = 0
    last_lek: Optional[dict] = None

    try:
        for event in adapter.query(
            from_ts=from_ts,
            to_ts=to_ts,
            actor=user_sub_filter,
        ):
            d = _event_to_dict(event)
            if d is not None:
                collected.append(d)
                scanned += 1
            if len(collected) >= limit:
                break
    except Exception:
        logger.warning("browse_via_adapter failed category=%s", category, exc_info=True)

    return collected, scanned, None  # adapter iterates fully; no cursor for scan path
