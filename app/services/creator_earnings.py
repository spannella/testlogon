"""Creator Earnings Dashboard service (MON-003).

Aggregates billing ledger credit entries for a creator and returns
earnings summaries, time-series breakdowns, quick stats, and
paginated transaction lists.

Revenue categories:
  - tips: Tip entries (reason contains "tip" or meta.content_type in message/post/comment)
  - subscriptions: Subscription payments (reason contains "subscription")
  - unlocks: Locked-content unlocks (reason contains "unlock")
  - vod_purchases: VOD sales (reason contains "vod")
  - other: Anything else
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_entry(entry: Dict[str, Any]) -> str:
    """Classify a ledger entry into a revenue category.

    Supports both old format (reason="Tip sent") and new format
    (reason="Tip: message", meta.content_type="message").

    Returns one of: "tips", "subscriptions", "unlocks", "vod_purchases", "shop_sales", "live_commerce", "other".
    """
    reason = (entry.get("reason") or "").lower()
    meta = entry.get("meta") or {}

    # New-format entries with content_type in meta
    content_type = meta.get("content_type", "")
    # ECOMX-50: commerce credits carry an explicit content_type on the ledger
    # meta ("shop" from shoppingcart seller-credit, "livecom" from
    # live_commerce_split). Classify them into their OWN buckets so shop +
    # live-commerce revenue no longer collapses into "other" (and is NOT
    # double-counted against tips/subs/ads which key off different content_types).
    if content_type == "shop":
        return "shop_sales"
    if content_type == "livecom":
        return "live_commerce"
    if content_type in ("message", "post", "comment", "message_react", "post_react", "video", "video_comment"):
        return "tips"

    # Reason-based classification
    if "tip" in reason:
        return "tips"
    if "subscription" in reason:
        return "subscriptions"
    # ECOMX-50: reason-based fallback for commerce credits written before the
    # content_type convention (defensive; live rows all carry content_type).
    if "shop sale" in reason:
        return "shop_sales"
    if "live-stream" in reason or "live commerce" in reason:
        return "live_commerce"
    if "unlock" in reason:
        return "unlocks"
    if "vod" in reason:
        return "vod_purchases"

    return "other"


# Backward compat alias
_reason_to_category = classify_entry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_int(val: Any) -> int:
    """Coerce DynamoDB Decimal or string to int."""
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return 0


def _ts_to_date_key(ts: int, granularity: str) -> str:
    """Convert Unix timestamp to a date key for time-series aggregation.

    Args:
        ts: Unix timestamp (seconds).
        granularity: "day", "week", or "month".

    Returns:
        "2026-05-25" (day), "2026-W21" (week), "2026-05" (month).
    """
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    if granularity == "week":
        return dt.strftime("%Y-W%W")
    if granularity == "month":
        return dt.strftime("%Y-%m")
    return dt.strftime("%Y-%m-%d")


def _start_of_day_utc(ts: int) -> int:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return int(dt.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())


def _start_of_month_utc(ts: int) -> int:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return int(dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())


# ---------------------------------------------------------------------------
# DynamoDB query
# ---------------------------------------------------------------------------

def _build_key_condition(pk: str, from_ts: int = 0, to_ts: int = 0):
    """Build a DDB KeyConditionExpression for ledger entries in a time range."""
    if from_ts and to_ts:
        return Key("pk").eq(pk) & Key("sk").between(
            f"LEDGER#{from_ts}", f"LEDGER#{to_ts}z"
        )
    if from_ts:
        return Key("pk").eq(pk) & Key("sk").between(
            f"LEDGER#{from_ts}", "LEDGER#9999999999z"
        )
    if to_ts:
        return Key("pk").eq(pk) & Key("sk").between(
            "LEDGER#0", f"LEDGER#{to_ts}z"
        )
    return Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")


def _query_credit_entries(
    *,
    user_id: str,
    from_ts: int = 0,
    to_ts: int = 0,
    limit: int = 5000,
) -> List[Dict[str, Any]]:
    """Query all credit LEDGER entries for a user within a time range.

    Paginates via LastEvaluatedKey.  Caps at ``limit`` entries.
    """
    pk = f"USER#{user_id}"
    key_cond = _build_key_condition(pk, from_ts, to_ts)
    # FIX (reversal true-up): exclude reversed credits from GROSS earnings too so a
    # reversed tip/ad credit drops out of the dashboard total (mirrors get_available_balance;
    # Attr("state").ne("reversed") is True on legacy rows with no state attr -> back-compat).
    filter_expr = Attr("type").eq("credit") & Attr("state").ne("reversed")

    collected: List[Dict[str, Any]] = []
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": filter_expr,
        "Limit": 500,
    }

    for _ in range(20):  # safety cap
        resp = T.billing.query(**query_kwargs)
        items = resp.get("Items", [])
        collected.extend(items)

        if len(collected) >= limit:
            collected = collected[:limit]
            break

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    return collected


# ---------------------------------------------------------------------------
# Earnings Summary (with time-series + granularity)
# ---------------------------------------------------------------------------

class EarningsSummary:
    """Accumulates credit entries into totals, breakdown, and time-series."""

    def __init__(self) -> None:
        self.total_cents: int = 0
        self.currency: str = "USD"
        self.breakdown: Dict[str, int] = defaultdict(int)
        self.time_series: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.transaction_count: int = 0

    def add_entry(self, entry: Dict[str, Any], granularity: str = "day") -> None:
        amount = _to_int(entry.get("amount_cents", 0))
        ts = _to_int(entry.get("ts", 0))
        category = classify_entry(entry)

        self.total_cents += amount
        self.breakdown[category] += amount
        self.transaction_count += 1

        date_key = _ts_to_date_key(ts, granularity)
        self.time_series[date_key]["total"] += amount
        self.time_series[date_key][category] += amount

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cents": self.total_cents,
            "currency": self.currency,
            "breakdown": dict(self.breakdown),
            "time_series": [
                {"date": k, **v}
                for k, v in sorted(self.time_series.items())
            ],
            "transaction_count": self.transaction_count,
        }


def get_earnings_summary(
    user_id: str,
    *,
    from_ts: int = 0,
    to_ts: int = 0,
    granularity: str = "day",
) -> Dict[str, Any]:
    """Compute aggregated earnings summary for a creator.

    Returns dict with total_cents, breakdown, time_series, transaction_count.
    """
    entries = _query_credit_entries(user_id=user_id, from_ts=from_ts, to_ts=to_ts)
    summary = EarningsSummary()
    for entry in entries:
        summary.add_entry(entry, granularity=granularity)

    result = summary.to_dict()

    # Ensure all canonical categories are present in breakdown
    for cat in ("subscriptions", "tips", "unlocks", "vod_purchases", "shop_sales", "live_commerce", "other"):
        result["breakdown"].setdefault(cat, 0)

    logger.info(
        "earnings_summary_computed",
        extra={
            "user_id": user_id,
            "total_cents": result["total_cents"],
            "entries": result["transaction_count"],
        },
    )
    return result


# ---------------------------------------------------------------------------
# Quick Stats
# ---------------------------------------------------------------------------

def get_quick_stats(*, user_id: str) -> Dict[str, Any]:
    """Pre-aggregated totals for today, this week, this month, all time.

    Computes all four windows in a single ledger scan.
    """
    now = now_ts()
    today_start = _start_of_day_utc(now)
    week_start = today_start - (datetime.fromtimestamp(now, tz=timezone.utc).weekday() * 86400)
    month_start = _start_of_month_utc(now)

    entries = _query_credit_entries(user_id=user_id)
    today_cents = 0
    week_cents = 0
    month_cents = 0
    all_time_cents = 0

    for entry in entries:
        amount = _to_int(entry.get("amount_cents", 0))
        ts = _to_int(entry.get("ts", 0))
        all_time_cents += amount
        if ts >= month_start:
            month_cents += amount
        if ts >= week_start:
            week_cents += amount
        if ts >= today_start:
            today_cents += amount

    # TIPX-D5: wire the real in-flight payout figure (MON-004 is live via
    # creator_payouts.get_available_balance -> pending_cents = requested/approved/
    # processing payouts not yet debited). Best-effort: any failure falls back to 0
    # so the earnings quick-stats never breaks on a payout-service hiccup.
    pending_payout_cents = 0
    try:
        from app.services.creator_payouts import get_available_balance

        pending_payout_cents = int(get_available_balance(user_id).get("pending_cents", 0))
    except Exception:  # pragma: no cover - defensive
        logger.warning("quick_stats_pending_payout_lookup_failed", exc_info=True)

    return {
        "today_cents": today_cents,
        "this_week_cents": week_cents,
        "this_month_cents": month_cents,
        "all_time_cents": all_time_cents,
        "currency": "USD",
        "pending_payout_cents": pending_payout_cents,  # TIPX-D5 (MON-004 wired)
    }


# ---------------------------------------------------------------------------
# Paginated Transactions
# ---------------------------------------------------------------------------

def get_earnings_transactions(
    user_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
    from_ts: int = 0,
    to_ts: int = 0,
) -> Dict[str, Any]:
    """Paginated list of individual credit ledger entries (newest first).

    Returns dict with items (list) and next_cursor (optional str).
    """
    pk = f"USER#{user_id}"
    key_cond = _build_key_condition(pk, from_ts, to_ts)
    # FIX (reversal true-up): exclude reversed credits from GROSS earnings too so a
    # reversed tip/ad credit drops out of the dashboard total (mirrors get_available_balance;
    # Attr("state").ne("reversed") is True on legacy rows with no state attr -> back-compat).
    filter_expr = Attr("type").eq("credit") & Attr("state").ne("reversed")

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
    items: List[Dict[str, Any]] = []
    last_key = None

    while len(items) < limit:
        resp = T.billing.query(**query_kwargs)
        for item in resp.get("Items", []):
            amount = _to_int(item.get("amount_cents", 0))
            reason = item.get("reason", "")
            category = classify_entry(item)
            meta = item.get("meta", {})
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

    next_cursor: Optional[str] = None
    if len(items) > limit:
        items = items[:limit]
        last_item = items[-1]
        next_cursor = encode_cursor({
            "pk": pk,
            "sk": f"LEDGER#{last_item['ts']}#{last_item['entry_id']}",
        })
    elif last_key:
        next_cursor = encode_cursor(last_key)

    return {
        "items": items,
        "next_cursor": next_cursor,
    }
