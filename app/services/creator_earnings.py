"""Creator Earnings Dashboard service (MON-003).

Aggregates billing ledger credit entries for a creator and returns
earnings summaries and paginated transaction lists.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _reason_to_category(reason: str) -> str:
    """Map a ledger credit reason to an earnings category."""
    reason_lower = reason.lower() if reason else ""
    if "subscription" in reason_lower:
        return "subscriptions"
    if reason_lower.startswith("tip"):
        return "tips"
    if "unlock" in reason_lower:
        return "unlocks"
    if "vod" in reason_lower:
        return "vod_purchases"
    return "other"


def _to_int(val: Any) -> int:
    """Coerce DynamoDB Decimal or string to int."""
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return 0


def get_earnings_summary(user_id: str, *, from_ts: int = 0, to_ts: int = 0) -> dict:
    """Aggregate all credit ledger entries for a creator in a time range.

    Returns dict with:
    - total_cents: int (sum of all credits)
    - breakdown: dict mapping category to cents
    - transaction_count: int
    - currency: "USD"
    """
    pk = f"USER#{user_id}"

    # Build key condition
    if from_ts and to_ts:
        key_cond = Key("pk").eq(pk) & Key("sk").between(
            f"LEDGER#{from_ts}", f"LEDGER#{to_ts}z"
        )
    elif from_ts:
        key_cond = Key("pk").eq(pk) & Key("sk").between(
            f"LEDGER#{from_ts}", "LEDGER#9999999999z"
        )
    elif to_ts:
        key_cond = Key("pk").eq(pk) & Key("sk").between(
            "LEDGER#0", f"LEDGER#{to_ts}z"
        )
    else:
        key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")

    filter_expr = Attr("type").eq("credit")

    total_cents = 0
    breakdown: Dict[str, int] = {
        "subscriptions": 0,
        "tips": 0,
        "unlocks": 0,
        "vod_purchases": 0,
        "other": 0,
    }
    transaction_count = 0

    # Loop through all pages
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": filter_expr,
    }

    while True:
        resp = T.billing.query(**query_kwargs)
        items = resp.get("Items", [])

        for item in items:
            amount = _to_int(item.get("amount_cents", 0))
            reason = item.get("reason", "")
            category = _reason_to_category(reason)
            total_cents += amount
            breakdown[category] = breakdown.get(category, 0) + amount
            transaction_count += 1

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    return {
        "total_cents": total_cents,
        "breakdown": breakdown,
        "transaction_count": transaction_count,
        "currency": "USD",
    }


def get_earnings_transactions(
    user_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
    from_ts: int = 0,
    to_ts: int = 0,
) -> dict:
    """Paginated list of individual credit ledger entries.

    Returns dict with:
    - items: list of transaction dicts
    - next_cursor: optional str
    """
    pk = f"USER#{user_id}"

    # Build key condition
    if from_ts and to_ts:
        key_cond = Key("pk").eq(pk) & Key("sk").between(
            f"LEDGER#{from_ts}", f"LEDGER#{to_ts}z"
        )
    elif from_ts:
        key_cond = Key("pk").eq(pk) & Key("sk").between(
            f"LEDGER#{from_ts}", "LEDGER#9999999999z"
        )
    elif to_ts:
        key_cond = Key("pk").eq(pk) & Key("sk").between(
            "LEDGER#0", f"LEDGER#{to_ts}z"
        )
    else:
        key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")

    filter_expr = Attr("type").eq("credit")

    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": filter_expr,
        "ScanIndexForward": False,  # newest first
        "Limit": limit,
    }

    start_key = decode_cursor(cursor)
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key

    # Because FilterExpression is applied AFTER fetching, we may need to loop
    # to collect enough items.
    items: List[Dict[str, Any]] = []
    last_key = None

    while len(items) < limit:
        resp = T.billing.query(**query_kwargs)
        for item in resp.get("Items", []):
            amount = _to_int(item.get("amount_cents", 0))
            reason = item.get("reason", "")
            category = _reason_to_category(reason)
            meta = item.get("meta", {})
            # Convert any Decimal values in meta to int/float
            if isinstance(meta, dict):
                meta = {k: (int(v) if isinstance(v, Decimal) else v) for k, v in meta.items()}
            items.append({
                "entry_id": item.get("entry_id", ""),
                "ts": _to_int(item.get("ts", 0)),
                "amount_cents": amount,
                "reason": reason,
                "category": category,
                "currency": item.get("currency", "USD"),
                "meta": meta,
            })

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    # Trim to limit
    next_cursor: Optional[str] = None
    if len(items) > limit:
        items = items[:limit]
        # We need to reconstruct the start key for the next page
        # Use the last item's pk/sk as the exclusive start key
        last_item_resp = items[-1]
        # Reconstruct DDB key from the last returned item
        next_cursor = encode_cursor({"pk": pk, "sk": f"LEDGER#{last_item_resp['ts']}#{last_item_resp['entry_id']}"})
    elif last_key:
        next_cursor = encode_cursor(last_key)

    return {
        "items": items,
        "next_cursor": next_cursor,
    }
