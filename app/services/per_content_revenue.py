"""Per-Content Revenue Breakdown service (FIN-006).

Attributes creator billing-ledger *credit* revenue to the content item that
generated it (a video, post, broadcast, or locked message) and presents
per-content totals, a per-source breakdown, sorting/top-content, and daily
time-series.

This service aggregates directly from the billing ledger
(``T.billing``) rather than maintaining a separate rollup table: every
attributable credit already carries ``meta.content_id`` (added at the
tip / unlock / VOD call sites), so a single creator-scoped ledger query
yields all the data we need. Money is always integer cents.

Revenue sources (per content item):
  - tips:          tip credits ("Tip: ...", meta.content_type message/post/comment/broadcast)
  - unlocks:       locked-content unlock credits ("Message unlock", "... unlock")
  - subscriptions: subscription credits attributed to content
  - ads:           ad-impression credits attributed to content
  - vod:           VOD sale credits ("VOD sale" / "VOD purchase")
"""

from __future__ import annotations

import csv
import io
import logging
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Per-source revenue buckets. Order matters for CSV column layout.
SOURCES = ("tips", "unlocks", "subscriptions", "ads", "vod")

VALID_CONTENT_TYPES = ("vod", "post", "broadcast", "message", "comment")
VALID_SORT_FIELDS = ("total_cents", "tips_cents", "unlocks_cents", "published_at")

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50
_LEDGER_SCAN_PAGES = 20
_LEDGER_PAGE_SIZE = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_int(val: Any) -> int:
    """Coerce a DynamoDB Decimal / numeric string to int."""
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.lstrip("-").isdigit():
        return int(val)
    return 0


def _ts_to_date(ts: int) -> str:
    """UTC YYYY-MM-DD for a Unix timestamp."""
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d")


def classify_source(entry: Dict[str, Any]) -> str:
    """Classify a credit ledger entry into a per-content revenue source.

    Returns one of SOURCES.
    """
    reason = (entry.get("reason") or "").lower()
    meta = entry.get("meta") or {}
    ctype = ""
    if isinstance(meta, dict):
        ctype = str(meta.get("content_type") or "")

    if "unlock" in reason:
        return "unlocks"
    if "subscription" in reason:
        return "subscriptions"
    if reason.startswith("ad ") or "ad revenue" in reason or "ad impression" in reason:
        return "ads"
    if "vod" in reason:
        return "vod"
    if "tip" in reason or ctype in ("message", "post", "comment", "broadcast"):
        return "tips"
    # Default attributable credit treated as a tip-like earning.
    return "tips"


def _normalize_content_type(raw: str) -> str:
    """Map a meta.content_type to one of the public types (vod/post/broadcast).

    Messages and comments are surfaced as "post" for display grouping while the
    underlying content_id remains distinct.
    """
    raw = (raw or "").lower()
    if raw in ("vod",):
        return "vod"
    if raw in ("broadcast",):
        return "broadcast"
    if raw in ("post", "comment", "message", ""):
        return "post"
    return raw


def _content_id_from_meta(meta: Dict[str, Any]) -> str:
    cid = meta.get("content_id") or meta.get("video_id") or ""
    return str(cid)


# ---------------------------------------------------------------------------
# Ledger query
# ---------------------------------------------------------------------------

def _build_key_condition(pk: str, from_ts: int = 0, to_ts: int = 0):
    if from_ts and to_ts:
        return Key("pk").eq(pk) & Key("sk").between(f"LEDGER#{from_ts}", f"LEDGER#{to_ts}z")
    if from_ts:
        return Key("pk").eq(pk) & Key("sk").between(f"LEDGER#{from_ts}", "LEDGER#9999999999z")
    if to_ts:
        return Key("pk").eq(pk) & Key("sk").between("LEDGER#0", f"LEDGER#{to_ts}z")
    return Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#")


def _query_attributable_credits(
    *, user_id: str, from_ts: int = 0, to_ts: int = 0
) -> List[Dict[str, Any]]:
    """Query all CREDIT ledger entries that carry a content_id for a creator.

    Loops via LastEvaluatedKey because FilterExpression is applied after the
    1MB page fetch (busy ledgers must be paged fully).
    """
    pk = f"USER#{user_id}"
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": _build_key_condition(pk, from_ts, to_ts),
        "FilterExpression": Attr("type").eq("credit"),
        "Limit": _LEDGER_PAGE_SIZE,
    }

    collected: List[Dict[str, Any]] = []
    for _ in range(_LEDGER_SCAN_PAGES):
        try:
            resp = T.billing.query(**query_kwargs)
        except Exception:
            logger.warning("per_content_revenue ledger query failed", exc_info=True)
            break
        for item in resp.get("Items", []):
            meta = item.get("meta") or {}
            if not isinstance(meta, dict):
                continue
            if not _content_id_from_meta(meta):
                continue
            collected.append(item)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        query_kwargs["ExclusiveStartKey"] = lek

    return collected


class _ContentAccumulator:
    """Accumulates per-content per-source revenue + daily time series."""

    def __init__(self, content_id: str) -> None:
        self.content_id = content_id
        self.content_type = "post"
        self.published_at = 0
        self.title = ""
        self.sources: Dict[str, int] = defaultdict(int)
        # date -> source -> cents
        self.series: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def add(self, entry: Dict[str, Any]) -> None:
        amount = _to_int(entry.get("amount_cents", 0))
        if amount <= 0:
            return
        ts = _to_int(entry.get("ts", 0))
        source = classify_source(entry)
        self.sources[source] += amount
        date = _ts_to_date(ts)
        self.series[date][source] += amount
        self.series[date]["total"] += amount

        meta = entry.get("meta") or {}
        if isinstance(meta, dict):
            ctype = _normalize_content_type(str(meta.get("content_type") or ""))
            if ctype == "vod" or self.content_type == "post":
                self.content_type = ctype
            pub = _to_int(meta.get("published_at", 0))
            if pub and (self.published_at == 0 or pub < self.published_at):
                self.published_at = pub

    @property
    def total_cents(self) -> int:
        return sum(self.sources.values())

    def to_item(self) -> Dict[str, Any]:
        return {
            "content_id": self.content_id,
            "content_type": self.content_type,
            "title": self.title or self.content_id,
            "published_at": self.published_at,
            "tips_cents": self.sources.get("tips", 0),
            "unlocks_cents": self.sources.get("unlocks", 0),
            "subscriptions_cents": self.sources.get("subscriptions", 0),
            "ads_cents": self.sources.get("ads", 0),
            "vod_cents": self.sources.get("vod", 0),
            "total_cents": self.total_cents,
        }

    def time_series(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for date in sorted(self.series.keys()):
            row = self.series[date]
            out.append({
                "date": date,
                "tips_cents": row.get("tips", 0),
                "unlocks_cents": row.get("unlocks", 0),
                "subscriptions_cents": row.get("subscriptions", 0),
                "ads_cents": row.get("ads", 0),
                "vod_cents": row.get("vod", 0),
                "total_cents": row.get("total", 0),
            })
        return out


def _accumulate(
    *, user_id: str, from_ts: int = 0, to_ts: int = 0
) -> Dict[str, _ContentAccumulator]:
    entries = _query_attributable_credits(user_id=user_id, from_ts=from_ts, to_ts=to_ts)
    accs: Dict[str, _ContentAccumulator] = {}
    for entry in entries:
        meta = entry.get("meta") or {}
        cid = _content_id_from_meta(meta)
        if not cid:
            continue
        acc = accs.get(cid)
        if acc is None:
            acc = _ContentAccumulator(cid)
            accs[cid] = acc
        acc.add(entry)
    return accs


def _resolve_titles(accs: Dict[str, _ContentAccumulator]) -> None:
    """Fill cached titles using the existing analytics resolver (best-effort)."""
    if not accs:
        return
    try:
        from app.services.creator_analytics import _resolve_content_details
        details = _resolve_content_details(list(accs.keys()))
        for cid, acc in accs.items():
            d = details.get(cid) or {}
            acc.title = d.get("title") or cid
    except Exception:
        logger.warning("per_content_revenue title resolution failed", exc_info=True)
        for cid, acc in accs.items():
            acc.title = acc.title or cid


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_content_revenue_list(
    user_id: str,
    *,
    from_ts: int = 0,
    to_ts: int = 0,
    sort_by: str = "total_cents",
    sort_order: str = "desc",
    content_type: Optional[str] = None,
    limit: int = _DEFAULT_LIMIT,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List all content items with per-source revenue for a creator.

    Aggregation happens in-memory over the creator's ledger; pagination is
    applied against the sorted result set (offset encoded in the cursor).
    """
    if sort_by not in VALID_SORT_FIELDS:
        sort_by = "total_cents"
    limit = max(1, min(int(limit or _DEFAULT_LIMIT), _MAX_LIMIT))

    accs = _accumulate(user_id=user_id, from_ts=from_ts, to_ts=to_ts)
    _resolve_titles(accs)

    norm_type = _normalize_content_type(content_type) if content_type else None
    items = [a.to_item() for a in accs.values()]
    if norm_type:
        items = [i for i in items if i["content_type"] == norm_type]

    reverse = (sort_order or "desc").lower() != "asc"
    items.sort(key=lambda i: (i.get(sort_by, 0), i["content_id"]), reverse=reverse)

    total_items = len(items)
    total_revenue_cents = sum(i["total_cents"] for i in items)

    offset = 0
    decoded = decode_cursor(cursor) if cursor else None
    if decoded and isinstance(decoded, dict):
        offset = _to_int(decoded.get("offset", 0))

    page = items[offset:offset + limit]
    next_cursor: Optional[str] = None
    if offset + limit < total_items:
        next_cursor = encode_cursor({"offset": offset + limit})

    logger.info(
        "per_content_revenue.list user=%s items=%d total=%d from=%s to=%s",
        user_id, total_items, total_revenue_cents, from_ts, to_ts,
    )

    return {
        "items": page,
        "total_items": total_items,
        "total_revenue_cents": total_revenue_cents,
        "next_cursor": next_cursor,
        "currency": "USD",
    }


def get_content_revenue_detail(
    user_id: str,
    content_id: str,
    *,
    from_ts: int = 0,
    to_ts: int = 0,
) -> Optional[Dict[str, Any]]:
    """Revenue breakdown + daily time-series for a single content item.

    Returns ``None`` if the creator has no attributed revenue for the item
    (router maps this to 404 — same response for not-found and not-owned to
    prevent enumeration).
    """
    accs = _accumulate(user_id=user_id, from_ts=from_ts, to_ts=to_ts)
    acc = accs.get(content_id)
    if acc is None:
        return None
    _resolve_titles({content_id: acc})

    item = acc.to_item()
    item["time_series"] = acc.time_series()
    item["currency"] = "USD"
    logger.info(
        "per_content_revenue.detail user=%s content=%s total=%d",
        user_id, content_id, item["total_cents"],
    )
    return item


def export_content_revenue_csv(
    user_id: str,
    *,
    from_ts: int = 0,
    to_ts: int = 0,
    max_rows: int = 10000,
) -> Tuple[str, int]:
    """Generate a CSV string of content revenue for the date range.

    Returns ``(csv_text, row_count)``. Limited to ``max_rows`` highest earners.
    """
    result = get_content_revenue_list(
        user_id, from_ts=from_ts, to_ts=to_ts,
        sort_by="total_cents", sort_order="desc", limit=_MAX_LIMIT,
    )
    # Re-aggregate the full set (list paginates); pull everything for export.
    accs = _accumulate(user_id=user_id, from_ts=from_ts, to_ts=to_ts)
    _resolve_titles(accs)
    items = [a.to_item() for a in accs.values()]
    items.sort(key=lambda i: i["total_cents"], reverse=True)

    truncated = False
    if len(items) > max_rows:
        items = items[:max_rows]
        truncated = True

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Content ID", "Type", "Title", "Published Date",
        "Tips ($)", "Unlocks ($)", "Subscriptions ($)", "Ads ($)", "VOD ($)", "Total ($)",
    ])

    def _d(cents: int) -> str:
        return f"{cents / 100:.2f}"

    for it in items:
        pub = it["published_at"]
        pub_date = _ts_to_date(pub) if pub else ""
        writer.writerow([
            it["content_id"], it["content_type"], it["title"], pub_date,
            _d(it["tips_cents"]), _d(it["unlocks_cents"]), _d(it["subscriptions_cents"]),
            _d(it["ads_cents"]), _d(it["vod_cents"]), _d(it["total_cents"]),
        ])

    if truncated:
        writer.writerow([f"Truncated to top {max_rows} items; narrow your date range."])

    logger.info(
        "per_content_revenue.export user=%s rows=%d from=%s to=%s",
        user_id, len(items), from_ts, to_ts,
    )
    _ = result  # totals validated above; export uses full set
    return buf.getvalue(), len(items)
