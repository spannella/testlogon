"""CMP-003 — Marketing tracking codes and visit recording.

Owns T.marketing_tracking_codes. Provides:
- create_tracking_code: create a META row (idempotent via attribute_not_exists)
- record_visit: append VISIT row and increment counters on META row
- get_tracking_code: point lookup
- list_visits_for_code: paginated query of VISIT rows (optional event_type filter)
"""
from __future__ import annotations

import logging
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_BOT_UA_CACHE: Optional[List[str]] = None


def _bot_uas() -> List[str]:
    global _BOT_UA_CACHE
    if _BOT_UA_CACHE is None:
        raw = getattr(S, "marketing_open_tracking_bot_ignore_uas", "")
        _BOT_UA_CACHE = [f.strip() for f in raw.split(",") if f.strip() and f.strip().lower() != "none"]
    return _BOT_UA_CACHE


def _is_bot_ua(ua: str) -> bool:
    if not ua:
        return False
    ua_lower = ua.lower()
    return any(f.lower() in ua_lower for f in _bot_uas())


def create_tracking_code(owner_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a tracking code META row. Idempotent (attribute_not_exists)."""
    code_slug = data.get("code_slug") or ""
    if not code_slug:
        raise ValueError("code_slug is required")

    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"TRACK#{code_slug}",
        "sk": "META",
        "code_slug": code_slug,
        "owner_id": owner_id,
        "campaign_id": data.get("campaign_id", ""),
        "destination_url": data.get("destination_url", ""),
        "visit_count": 0,
        "open_count": 0,
        "created_at": ts,
        "updated_at": ts,
    }

    try:
        T.marketing_tracking_codes.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
        )
    except Exception as exc:
        if "ConditionalCheckFailedException" in type(exc).__name__:
            # Already exists — fetch and return
            return get_tracking_code(code_slug) or item
        raise

    return item


def get_tracking_code(code_slug: str) -> Optional[Dict[str, Any]]:
    resp = T.marketing_tracking_codes.get_item(
        Key={"pk": f"TRACK#{code_slug}", "sk": "META"}
    )
    return resp.get("Item")


def record_visit(
    code_slug: str,
    *,
    party_id: str = "anon",
    referrer: Optional[str] = None,
    event_type: str = "click",
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """Record a visit/open event. Silently returns if code does not exist."""
    meta = get_tracking_code(code_slug)
    if not meta:
        return  # unknown code — silent no-op per CMP-003 spec

    ts = now_ts()
    nonce = secrets.token_hex(4)

    visit_item: Dict[str, Any] = {
        "pk": f"TRACK#{code_slug}",
        "sk": f"VISIT#{ts:010d}#{nonce}",
        "code_slug": code_slug,
        "ts": ts,
        "party_id": party_id,
    }
    if referrer:
        visit_item["referrer"] = referrer[:500]
    if event_type != "click":
        visit_item["event_type"] = event_type
    if ip_address:
        visit_item["ip_address"] = ip_address[:45]
    if user_agent:
        visit_item["user_agent"] = user_agent[:256]

    try:
        T.marketing_tracking_codes.put_item(Item=visit_item)
    except Exception as exc:
        logger.warning("record_visit put_item failed for code=%s: %s", code_slug, exc)
        return

    # Update counters on META row
    try:
        if event_type == "open":
            expr = (
                "SET visit_count = if_not_exists(visit_count, :z) + :one, "
                "    open_count = if_not_exists(open_count, :z) + :one, "
                "    updated_at = :ts"
            )
        else:
            expr = (
                "SET visit_count = if_not_exists(visit_count, :z) + :one, "
                "    updated_at = :ts"
            )
        T.marketing_tracking_codes.update_item(
            Key={"pk": f"TRACK#{code_slug}", "sk": "META"},
            UpdateExpression=expr,
            ExpressionAttributeValues={":one": 1, ":z": 0, ":ts": ts},
        )
    except Exception as exc:
        logger.warning("record_visit counter update failed for code=%s: %s", code_slug, exc)


def list_visits_for_code(
    code_slug: str,
    *,
    event_type: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Query VISIT rows for a code. Returns (items, next_cursor)."""
    from boto3.dynamodb.conditions import Key, Attr

    kwargs: Dict[str, Any] = {
        "IndexName": "ByCodeTs",
        "KeyConditionExpression": Key("code_slug").eq(code_slug),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if event_type:
        if event_type == "click":
            # click rows omit event_type attribute — filter for absent or "click"
            kwargs["FilterExpression"] = Attr("event_type").not_exists() | Attr("event_type").eq("click")
        else:
            kwargs["FilterExpression"] = Attr("event_type").eq(event_type)

    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    results: List[Dict[str, Any]] = []
    last_key = None
    pages = 0
    while pages < 20:
        resp = T.marketing_tracking_codes.query(**kwargs)
        results.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(results) >= limit:
            break
        kwargs["ExclusiveStartKey"] = last_key
        pages += 1

    next_cursor = encode_cursor(last_key) if last_key and len(results) >= limit else None
    return results[:limit], next_cursor
