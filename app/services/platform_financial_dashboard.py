"""Platform financial dashboard aggregation (FIN-013).

Computes platform-wide GMV, net revenue, take rate, provider/type
breakdowns, time-series trends, and top-creator rankings from the
existing billing ledger (see ``app/services/billing_shared.py``).

This module does NOT recreate the ledger. Ledger entries live in the
``billing`` DynamoDB table with ``pk = USER#{user_id}`` and
``sk = LEDGER#{ts}#{entry_id}``. Each entry's fields are ``type``,
``amount_cents``, ``state``, ``reason``, ``ts``, ``entry_id`` and the
denormalized ``ledger_date`` (YYYY-MM-DD, written by ``new_ledger_entry``).
Optional ``provider`` / ``creator_id`` / ``user_id`` fields, when present,
are passed via the ``extra`` param at write time.

Aggregation strategy mirrors the cross-user scan pattern used by
``app/services/admin_compute.py``: a full table scan keeps only ledger
rows, buckets in-memory by day/type/provider. A ``financial_rollups``
table stores pre-computed daily rollups + a live current-day total so
hot reads (KPIs / trends) can be served without rescanning every time.
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Entry types that count toward GMV (gross value flowing through the platform).
GMV_ENTRY_TYPES = {
    "tip_debit",
    "unlock_debit",
    "deposit",
    "subscription_charge",
    "catalog_purchase",
}

# Entry types that represent platform revenue (fees / commissions retained).
REVENUE_ENTRY_TYPES = {
    "platform_commission",
    "platform_ad_commission",
    "ad_revenue_credit",
}

# Entry types that reduce GMV (money returned to users).
REFUND_ENTRY_TYPES = {
    "refund",
    "tip_refund",
    "unlock_refund",
    "chargeback",
}

_VALID_GRANULARITIES = {"daily", "weekly", "monthly"}

_ROLLUP_DAILY_PK = "ROLLUP#DAILY"
_ROLLUP_LIVE_PK = "ROLLUP#LIVE"
_ROLLUP_LIVE_SK = "CURRENT"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_int(v: Any) -> int:
    if v is None:
        return 0
    if isinstance(v, Decimal):
        return int(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _parse_date(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)


def _date_range(start_date: str, end_date: str) -> List[str]:
    """Inclusive list of YYYY-MM-DD strings between start and end."""
    start = _parse_date(start_date)
    end = _parse_date(end_date)
    if end < start:
        return []
    out: List[str] = []
    cur = start
    while cur <= end:
        out.append(cur.strftime("%Y-%m-%d"))
        cur += timedelta(days=1)
    return out


def validate_granularity(granularity: str) -> str:
    if granularity not in _VALID_GRANULARITIES:
        raise ValueError("granularity must be daily, weekly, or monthly")
    return granularity


def _provider_for(item: Dict[str, Any]) -> str:
    """Best-effort provider label for a ledger entry. The ledger does not
    always store ``provider`` (it lives on payment-method items), so fall
    back to ``unknown`` when absent."""
    return str(item.get("provider") or "unknown")


def _creator_for(item: Dict[str, Any]) -> str:
    """User credited as the creator/earner for an entry, if any."""
    return str(item.get("creator_id") or item.get("payee_user_id") or "")


def _user_for(item: Dict[str, Any]) -> str:
    uid = item.get("user_id")
    if uid:
        return str(uid)
    pk = str(item.get("pk", ""))
    if pk.startswith("USER#"):
        return pk[len("USER#"):]
    return ""


# ---------------------------------------------------------------------------
# Ledger scan
# ---------------------------------------------------------------------------

def _scan_ledger_entries(date_set: Optional[set[str]] = None) -> List[Dict[str, Any]]:
    """Scan the billing table, keeping only LEDGER# rows. Optionally filter
    to a set of ledger_date strings (computed in-memory to avoid a GSI)."""
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {}
    while True:
        resp = T.billing.scan(**kwargs)
        for item in resp.get("Items", []):
            sk = str(item.get("sk", ""))
            if not sk.startswith("LEDGER#"):
                continue
            ld = item.get("ledger_date")
            if not ld:
                ld = _ledger_date_fallback(item)
            if date_set is not None and ld not in date_set:
                continue
            out.append(item)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return out


def _ledger_date_fallback(item: Dict[str, Any]) -> str:
    ts = _to_int(item.get("ts"))
    if ts <= 0:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def _ledger_date_of(item: Dict[str, Any]) -> str:
    ld = item.get("ledger_date")
    return str(ld) if ld else _ledger_date_fallback(item)


# ---------------------------------------------------------------------------
# In-memory aggregation core
# ---------------------------------------------------------------------------

def _aggregate(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate a list of ledger entries into the rollup shape."""
    gmv = 0
    net_revenue = 0
    refunds = 0
    tx_count = 0
    payers: set[str] = set()
    by_type: Dict[str, Dict[str, int]] = {}
    by_provider: Dict[str, Dict[str, int]] = {}
    by_creator: Dict[str, Dict[str, int]] = {}

    for e in entries:
        etype = str(e.get("type", "unknown"))
        amount = abs(_to_int(e.get("amount_cents")))
        state = str(e.get("state", ""))
        tx_count += 1

        t_bucket = by_type.setdefault(etype, {"count": 0, "total_cents": 0})
        t_bucket["count"] += 1
        t_bucket["total_cents"] += amount

        prov = _provider_for(e)
        p_bucket = by_provider.setdefault(prov, {"count": 0, "total_cents": 0, "success": 0, "failure": 0})
        p_bucket["count"] += 1
        p_bucket["total_cents"] += amount
        if state in ("reversed", "failed", "voided"):
            p_bucket["failure"] += 1
        else:
            p_bucket["success"] += 1

        if etype in GMV_ENTRY_TYPES:
            gmv += amount
            uid = _user_for(e)
            if uid:
                payers.add(uid)
        if etype in REVENUE_ENTRY_TYPES:
            net_revenue += amount
        if etype in REFUND_ENTRY_TYPES:
            refunds += amount

        creator = _creator_for(e)
        if creator and etype in (GMV_ENTRY_TYPES | REVENUE_ENTRY_TYPES):
            c_bucket = by_creator.setdefault(creator, {"revenue_cents": 0, "tx_count": 0})
            c_bucket["revenue_cents"] += amount
            c_bucket["tx_count"] += 1

    top_creators = sorted(
        (
            {"user_id": uid, "revenue_cents": v["revenue_cents"], "tx_count": v["tx_count"]}
            for uid, v in by_creator.items()
        ),
        key=lambda c: c["revenue_cents"],
        reverse=True,
    )[:50]

    return {
        "gmv_cents": gmv,
        "net_revenue_cents": net_revenue,
        "refunds_cents": refunds,
        "tx_count": tx_count,
        "unique_payers": len(payers),
        "by_type": by_type,
        "by_provider": by_provider,
        "top_creators": top_creators,
    }


def _take_rate_bps(gmv: int, net: int) -> int:
    if gmv <= 0:
        return 0
    return int(round((net / gmv) * 10000))


def _avg(total: int, count: int) -> int:
    if count <= 0:
        return 0
    return int(total // count)


# ---------------------------------------------------------------------------
# Daily rollup compute + storage
# ---------------------------------------------------------------------------

def _store_daily_rollup(date_str: str, agg: Dict[str, Any]) -> int:
    computed_at = now_ts()
    item = {
        "pk": _ROLLUP_DAILY_PK,
        "sk": date_str,
        "gmv_cents": agg["gmv_cents"],
        "net_revenue_cents": agg["net_revenue_cents"],
        "refunds_cents": agg["refunds_cents"],
        "tx_count": agg["tx_count"],
        "unique_payers": agg["unique_payers"],
        "by_type": agg["by_type"],
        "by_provider": agg["by_provider"],
        "top_creators": agg["top_creators"],
        "computed_at": computed_at,
    }
    T.financial_rollups.put_item(Item=item)
    return computed_at


def _store_live_rollup(agg: Dict[str, Any]) -> None:
    T.financial_rollups.put_item(
        Item={
            "pk": _ROLLUP_LIVE_PK,
            "sk": _ROLLUP_LIVE_SK,
            "gmv_cents": agg["gmv_cents"],
            "net_revenue_cents": agg["net_revenue_cents"],
            "tx_count": agg["tx_count"],
            "last_updated": now_ts(),
        }
    )


def compute_daily_rollup(date_str: str) -> Dict[str, Any]:
    """Scan all ledger entries for ``date_str`` and persist a daily rollup.

    Also refreshes the live current-day total when ``date_str`` is today.
    Returns the rollup payload including ``computed_at``.
    """
    entries = _scan_ledger_entries(date_set={date_str})
    agg = _aggregate(entries)
    computed_at = _store_daily_rollup(date_str, agg)
    if date_str == today_str():
        _store_live_rollup(agg)
    logger.info(
        "financial_rollup_computed date=%s tx_count=%d gmv_cents=%d",
        date_str, agg["tx_count"], agg["gmv_cents"],
    )
    return {
        "date": date_str,
        "gmv_cents": agg["gmv_cents"],
        "net_revenue_cents": agg["net_revenue_cents"],
        "tx_count": agg["tx_count"],
        "unique_payers": agg["unique_payers"],
        "computed_at": computed_at,
    }


def _read_daily_rollup(date_str: str) -> Optional[Dict[str, Any]]:
    resp = T.financial_rollups.get_item(Key={"pk": _ROLLUP_DAILY_PK, "sk": date_str})
    return resp.get("Item")


def _entries_for_range(start_date: str, end_date: str) -> List[Dict[str, Any]]:
    """All ledger entries in the inclusive date range (single scan, filtered)."""
    dates = set(_date_range(start_date, end_date))
    if not dates:
        return []
    return _scan_ledger_entries(date_set=dates)


# ---------------------------------------------------------------------------
# Public query API
# ---------------------------------------------------------------------------

def get_kpis(*, start_date: str, end_date: str) -> Dict[str, Any]:
    """GMV, net revenue, take rate, tx count, unique payers, avg tx."""
    entries = _entries_for_range(start_date, end_date)
    agg = _aggregate(entries)
    return {
        "gmv_cents": agg["gmv_cents"],
        "net_revenue_cents": agg["net_revenue_cents"],
        "refunds_cents": agg["refunds_cents"],
        "take_rate_bps": _take_rate_bps(agg["gmv_cents"], agg["net_revenue_cents"]),
        "tx_count": agg["tx_count"],
        "unique_payers": agg["unique_payers"],
        "avg_tx_cents": _avg(agg["gmv_cents"], agg["tx_count"]),
        "period": {"start_date": start_date, "end_date": end_date},
    }


def get_trends(
    *, start_date: str, end_date: str, granularity: str = "daily"
) -> Dict[str, Any]:
    """Time-series points (date, gmv, net revenue, tx count) at the given
    granularity (daily / weekly / monthly), sorted ascending by date."""
    validate_granularity(granularity)
    entries = _entries_for_range(start_date, end_date)

    # Bucket each entry by its period key.
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for e in entries:
        ld = _ledger_date_of(e)
        if not ld:
            continue
        key = _period_key(ld, granularity)
        buckets.setdefault(key, []).append(e)

    points: List[Dict[str, Any]] = []
    for key in sorted(buckets.keys()):
        agg = _aggregate(buckets[key])
        points.append(
            {
                "date": key,
                "gmv_cents": agg["gmv_cents"],
                "net_revenue_cents": agg["net_revenue_cents"],
                "tx_count": agg["tx_count"],
            }
        )
    return {"data": points, "granularity": granularity}


def _period_key(date_str: str, granularity: str) -> str:
    d = _parse_date(date_str)
    if granularity == "daily":
        return date_str
    if granularity == "weekly":
        # ISO week Monday as the bucket label.
        monday = d - timedelta(days=d.weekday())
        return monday.strftime("%Y-%m-%d")
    # monthly
    return d.strftime("%Y-%m")


def get_provider_breakdown(*, start_date: str, end_date: str) -> Dict[str, Any]:
    entries = _entries_for_range(start_date, end_date)
    agg = _aggregate(entries)
    grand_total = sum(v["total_cents"] for v in agg["by_provider"].values())
    rows: List[Dict[str, Any]] = []
    for provider, v in agg["by_provider"].items():
        pct = round((v["total_cents"] / grand_total) * 100, 1) if grand_total > 0 else 0.0
        success_rate = round((v["success"] / v["count"]) * 100, 1) if v["count"] > 0 else 0.0
        rows.append(
            {
                "provider": provider,
                "total_cents": v["total_cents"],
                "tx_count": v["count"],
                "avg_cents": _avg(v["total_cents"], v["count"]),
                "pct": pct,
                "success_rate": success_rate,
            }
        )
    rows.sort(key=lambda r: r["total_cents"], reverse=True)
    return {"data": rows}


def get_type_breakdown(*, start_date: str, end_date: str) -> Dict[str, Any]:
    entries = _entries_for_range(start_date, end_date)
    agg = _aggregate(entries)
    rows: List[Dict[str, Any]] = []
    for etype, v in agg["by_type"].items():
        rows.append(
            {
                "entry_type": etype,
                "total_cents": v["total_cents"],
                "tx_count": v["count"],
                "avg_cents": _avg(v["total_cents"], v["count"]),
            }
        )
    rows.sort(key=lambda r: r["total_cents"], reverse=True)
    return {"data": rows}


def get_top_creators(*, start_date: str, end_date: str, limit: int = 20) -> Dict[str, Any]:
    entries = _entries_for_range(start_date, end_date)
    agg = _aggregate(entries)
    rows = [
        {
            "user_id": c["user_id"],
            "revenue_cents": c["revenue_cents"],
            "tx_count": c["tx_count"],
            "avg_cents": _avg(c["revenue_cents"], c["tx_count"]),
        }
        for c in agg["top_creators"]
    ]
    rows.sort(key=lambda r: r["revenue_cents"], reverse=True)
    return {"data": rows[: max(0, limit)]}


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_summary_csv(*, start_date: str, end_date: str) -> str:
    """CSV of per-day financial summary across the range."""
    trends = get_trends(start_date=start_date, end_date=end_date, granularity="daily")["data"]
    by_date = {p["date"]: p for p in trends}

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["date", "gmv_cents", "net_revenue_cents", "take_rate_bps", "tx_count"])
    for date_str in _date_range(start_date, end_date):
        p = by_date.get(date_str, {"gmv_cents": 0, "net_revenue_cents": 0, "tx_count": 0})
        writer.writerow(
            [
                date_str,
                p["gmv_cents"],
                p["net_revenue_cents"],
                _take_rate_bps(p["gmv_cents"], p["net_revenue_cents"]),
                p["tx_count"],
            ]
        )
    # Totals footer
    kpis = get_kpis(start_date=start_date, end_date=end_date)
    writer.writerow([])
    writer.writerow(
        [
            "TOTAL",
            kpis["gmv_cents"],
            kpis["net_revenue_cents"],
            kpis["take_rate_bps"],
            kpis["tx_count"],
        ]
    )
    return buf.getvalue()
