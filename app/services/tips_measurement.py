"""Tips measurement / reconciliation service (TIPX-D).

SINGLE ledger-backed source of truth for every "tips received" / "tips sent"
total in the product.  Before TIPX-D there were three disagreeing totals:

  * ``creator_earnings`` tips bucket   -> NET credit rows, reversed-excluded (correct)
  * ``tip_leaderboard``                -> NET credit rows, reversed-excluded (correct after A6)
  * ``alerts.get_tips_summary``        -> GROSS, post_tip+message_tip ONLY, capped 1000

This module makes ALL of them read the LEDGER with the same rules:

  * received total = sum of the recipient's ``type=="credit"`` rows whose
    ``reason`` begins with ``"Tip"`` and whose ``state != "reversed"``.  Credit
    rows are already NET (the 20% platform fee is taken at debit time), so the
    received total is a NET figure and reconciles to the earnings tips bucket
    and to the leaderboard for the same creator/period.
  * sent total = sum of the tipper's ``type=="debit"`` rows whose ``reason``
    begins with ``"Tip"`` (GROSS -- what the tipper actually paid), excluding
    reversed debits.

Per-surface breakdown is derived from ``meta.content_type`` (falling back to the
reason label) so every one of the 8 tip surfaces is counted, not just 2.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# period -> lookback seconds (0 == all time)
PERIOD_SECONDS: Dict[str, int] = {"7d": 7 * 86400, "30d": 30 * 86400, "all": 0}

# meta.content_type -> stable breakdown bucket key (mirrors TIP_CONTENT_TYPES)
_CONTENT_TYPE_LABELS: Dict[str, str] = {
    "message": "message",
    "post": "post",
    "comment": "comment",
    "broadcast": "broadcast",
    "video": "video",
    "message_react": "message_react",
    "post_react": "post_react",
    "video_comment": "video_comment",
    "profile": "profile",
}

# reason label -> content_type (fallback for legacy rows with no meta.content_type)
_REASON_TO_TYPE: Dict[str, str] = {
    "tip: message": "message",
    "tip: post": "post",
    "tip: comment": "comment",
    "tip: broadcast": "broadcast",
    "tip: video": "video",
    "tip: message reaction": "message_react",
    "tip: post reaction": "post_react",
    "tip: video comment": "video_comment",
    "tip: creator": "profile",
}


def _to_int(val: Any) -> int:
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.lstrip("-").isdigit():
        return int(val)
    return 0


def _cutoff_for_period(period: str) -> int:
    secs = PERIOD_SECONDS.get(period, 0)
    return (now_ts() - secs) if secs > 0 else 0


def _bucket_for(item: Dict[str, Any]) -> str:
    meta = item.get("meta") or {}
    ct = meta.get("content_type", "")
    if ct in _CONTENT_TYPE_LABELS:
        return _CONTENT_TYPE_LABELS[ct]
    reason = (item.get("reason") or "").strip().lower()
    return _REASON_TO_TYPE.get(reason, "other")


def _is_tip_reason(item: Dict[str, Any]) -> bool:
    return (item.get("reason") or "").startswith("Tip")


def _query_ledger(user_id: str, *, entry_type: str, cutoff_ts: int) -> List[Dict[str, Any]]:
    """Query a user's ledger for tip rows of ``entry_type`` ("credit"/"debit").

    Excludes reversed rows; filters ``reason begins_with "Tip"`` server-side to
    keep the payload small.  Pages fully (FilterExpression is post-fetch).
    """
    pk = f"USER#{user_id}"
    if cutoff_ts > 0:
        key_cond = Key("pk").eq(pk) & Key("sk").between(
            f"LEDGER#{cutoff_ts}", "LEDGER#9999999999z"
        )
    else:
        key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")

    filter_expr = (
        Attr("type").eq(entry_type)
        & Attr("reason").begins_with("Tip")
        & Attr("state").ne("reversed")
    )

    out: List[Dict[str, Any]] = []
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": filter_expr,
        "ScanIndexForward": False,  # newest first
    }
    while True:
        resp = T.billing.query(**query_kwargs)
        out.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
    return out


# ---------------------------------------------------------------------------
# Received (creator-facing)
# ---------------------------------------------------------------------------

def get_tips_received_summary(creator_id: str, period: str = "30d") -> Dict[str, Any]:
    """Ledger-backed tips-received summary -- the ONE TRUE TOTAL (TIPX-D1).

    ``total_net_cents`` is NET (credit rows) and reconciles to the earnings tips
    bucket and the leaderboard.  ``by_type`` covers all 8 surfaces.  ``top_tippers``
    is derived from the same credit rows (net), matching the leaderboard.
    """
    if period not in PERIOD_SECONDS:
        period = "30d"
    cutoff = _cutoff_for_period(period)
    rows = _query_ledger(creator_id, entry_type="credit", cutoff_ts=cutoff)

    total_net = 0
    tip_count = 0
    by_type: Dict[str, Dict[str, int]] = defaultdict(lambda: {"count": 0, "total_cents": 0})
    tippers: Dict[str, Dict[str, Any]] = {}

    for item in rows:
        if not _is_tip_reason(item):
            continue
        amount = _to_int(item.get("amount_cents", 0))
        total_net += amount
        tip_count += 1
        bucket = _bucket_for(item)
        by_type[bucket]["count"] += 1
        by_type[bucket]["total_cents"] += amount

        meta = item.get("meta") or {}
        tipper_id = str(meta.get("tipper_user_id", ""))
        if tipper_id:
            t = tippers.setdefault(
                tipper_id,
                {"user_id": tipper_id, "display_name": tipper_id, "total_cents": 0, "tip_count": 0},
            )
            t["total_cents"] += amount
            t["tip_count"] += 1

    # enrich top tippers with display names (best-effort)
    top = sorted(tippers.values(), key=lambda x: (-x["total_cents"], x["user_id"]))[:10]
    for t in top:
        try:
            from app.services.profile import get_profile

            prof = get_profile(t["user_id"]) or {}
            t["display_name"] = prof.get("display_name") or t["user_id"]
        except Exception:
            pass

    return {
        "period": period,
        "total_net_cents": total_net,
        "tip_count": tip_count,
        "unique_tippers": len(tippers),
        "by_type": {k: dict(v) for k, v in sorted(by_type.items())},
        "top_tippers": top,
        "source": "ledger",
    }


def get_tips_received_transactions(
    creator_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
    period: str = "all",
) -> Dict[str, Any]:
    """Cursor-paginated NET tip credit rows for a creator (newest first)."""
    from app.core.cursor import decode_cursor, encode_cursor

    if period not in PERIOD_SECONDS:
        period = "all"
    cutoff = _cutoff_for_period(period)
    pk = f"USER#{creator_id}"
    if cutoff > 0:
        key_cond = Key("pk").eq(pk) & Key("sk").between(f"LEDGER#{cutoff}", "LEDGER#9999999999z")
    else:
        key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")
    filter_expr = (
        Attr("type").eq("credit") & Attr("reason").begins_with("Tip") & Attr("state").ne("reversed")
    )
    return _paginate_tip_rows(
        pk, key_cond, filter_expr, limit, cursor, decode_cursor, encode_cursor, party="tipper"
    )


def get_tips_sent(
    tipper_id: str,
    *,
    limit: int = 50,
    cursor: Optional[str] = None,
    period: str = "all",
) -> Dict[str, Any]:
    """Cursor-paginated GROSS tip debit rows for a tipper (TIPX-D4).

    Each row is a receipt: amount charged (gross), recipient, surface, date, and
    the platform fee that was taken (from meta).
    """
    from app.core.cursor import decode_cursor, encode_cursor

    if period not in PERIOD_SECONDS:
        period = "all"
    cutoff = _cutoff_for_period(period)
    pk = f"USER#{tipper_id}"
    if cutoff > 0:
        key_cond = Key("pk").eq(pk) & Key("sk").between(f"LEDGER#{cutoff}", "LEDGER#9999999999z")
    else:
        key_cond = Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")
    filter_expr = (
        Attr("type").eq("debit") & Attr("reason").begins_with("Tip") & Attr("state").ne("reversed")
    )
    return _paginate_tip_rows(
        pk, key_cond, filter_expr, limit, cursor, decode_cursor, encode_cursor, party="recipient"
    )


def get_tips_sent_summary(tipper_id: str, period: str = "all") -> Dict[str, Any]:
    """Aggregate a tipper's GROSS spend (TIPX-D4 header figure)."""
    if period not in PERIOD_SECONDS:
        period = "all"
    cutoff = _cutoff_for_period(period)
    rows = _query_ledger(tipper_id, entry_type="debit", cutoff_ts=cutoff)
    total = 0
    count = 0
    recipients: set[str] = set()
    for item in rows:
        if not _is_tip_reason(item):
            continue
        total += _to_int(item.get("amount_cents", 0))
        count += 1
        meta = item.get("meta") or {}
        rid = str(meta.get("recipient_user_id", ""))
        if rid:
            recipients.add(rid)
    return {
        "period": period,
        "total_sent_cents": total,
        "tip_count": count,
        "unique_recipients": len(recipients),
        "source": "ledger",
    }


def _paginate_tip_rows(
    pk: str,
    key_cond: Any,
    filter_expr: Any,
    limit: int,
    cursor: Optional[str],
    decode_cursor: Any,
    encode_cursor: Any,
    *,
    party: str,
) -> Dict[str, Any]:
    """Shared cursor pagination for tip credit/debit rows.

    ``party`` names the counterparty field surfaced ("tipper" for received,
    "recipient" for sent).
    """
    limit = max(1, min(int(limit), 100))
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": filter_expr,
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        query_kwargs["ExclusiveStartKey"] = start_key

    items: List[Dict[str, Any]] = []
    last_key = None
    while len(items) < limit + 1:
        resp = T.billing.query(**query_kwargs)
        for item in resp.get("Items", []):
            meta = item.get("meta") or {}
            if party == "tipper":
                counterparty = str(meta.get("tipper_user_id", ""))
            else:
                counterparty = str(meta.get("recipient_user_id", ""))
            items.append({
                "entry_id": item.get("entry_id", ""),
                "ts": _to_int(item.get("ts", 0)),
                "amount_cents": _to_int(item.get("amount_cents", 0)),
                "reason": item.get("reason", ""),
                "content_type": _bucket_for(item),
                "content_id": str(meta.get("content_id", "")),
                "counterparty_user_id": counterparty,
                "platform_fee_cents": _to_int(meta.get("platform_fee_cents", 0)),
                "tip_payment_id": str(meta.get("tip_payment_id", "")),
                "currency": item.get("currency", "USD"),
            })
            if len(items) >= limit + 1:
                break
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(items) >= limit + 1:
            break
        query_kwargs["ExclusiveStartKey"] = last_key

    next_cursor: Optional[str] = None
    if len(items) > limit:
        items = items[:limit]
        last_item = items[-1]
        next_cursor = encode_cursor({"pk": pk, "sk": f"LEDGER#{last_item['ts']}#{last_item['entry_id']}"})
    elif last_key:
        next_cursor = encode_cursor(last_key)

    # enrich counterparty display names (best-effort, deduped)
    names: Dict[str, str] = {}
    for it in items:
        cid = it["counterparty_user_id"]
        if cid and cid not in names:
            try:
                from app.services.profile import get_profile

                prof = get_profile(cid) or {}
                names[cid] = prof.get("display_name") or cid
            except Exception:
                names[cid] = cid
        it["counterparty_display_name"] = names.get(cid, cid)

    return {"items": items, "next_cursor": next_cursor}
