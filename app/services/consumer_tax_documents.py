"""Consumer Tax Documents (FIN-004).

Generates annual consumer SPENDING summaries for buyers from their billing
ledger *debit* (spending) entries — money the user *spent* (subscriptions,
tips sent, purchases, unlocks, deposits), NOT money they earned as a creator.

This module does NOT recompute or duplicate the ledger logic:
  - It categorizes each debited ledger entry via the local
    ``classify_category`` (subscriptions, tips, purchases, unlocks, deposits,
    other).
  - It reuses ``app.services.receipts._render_pdf`` for text-based PDF
    rendering (no new PDF dependency).
  - It reads the billing ledger directly via a date-range KeyCondition on the
    ``LEDGER#{ts}#{entry_id}`` sort key.

The credit-based helpers ``_query_credit_entries`` and
``compute_earnings_summary`` are RETAINED here (queries credit/earnings
entries, uses creator-earnings classification) solely for the creator 1099
path in ``app.services.tax_form_1099`` — do not use them for consumer
documents.

Storage (``tax_documents`` table, single-table by user PK):
  - Document records: pk=USER#{user_sub} sk=DOC#{year}#{doc_id}
  - Cache rows:       pk=USER#{user_sub} sk=CACHE#{year}

MONEY values are integer cents throughout.
"""

from __future__ import annotations

import io
import logging
import zipfile
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.aws_clients import s3_client
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ulidish
from app.services.creator_earnings import classify_entry
from app.services.profile import get_profile
from app.services.receipts import _render_pdf

logger = logging.getLogger(__name__)

_s3 = s3_client()

# Platform launch year — no data exists before this.
_PLATFORM_LAUNCH_YEAR = 2024

# Cap the number of receipts bundled into a single ZIP to guard against runaway
# memory / latency. Larger ranges must be narrowed by the caller (router → 422).
MAX_ZIP_RECEIPTS = 500

# Consumer SPENDING categories surfaced in consumer tax documents (FIN-004).
CATEGORIES = ("subscriptions", "tips", "purchases", "unlocks", "deposits", "other")

# Creator EARNINGS categories — retained ONLY for the credit-based 1099 path
# (``compute_earnings_summary`` / ``tax_form_1099.py``).
_CREDIT_CATEGORIES = ("subscriptions", "tips", "unlocks", "vod_purchases", "other")


def classify_category(entry: Dict[str, Any]) -> str:
    """Map a *debit* ledger entry's reason to a consumer spending category.

    Credit (earnings) entries are explicitly excluded — they must never be
    counted as consumer spending.
    """
    if entry.get("type") != "debit":
        return "other"
    reason = str(entry.get("reason", "")).lower()
    if reason.startswith(("subscription", "plan")):
        return "subscriptions"
    if reason.startswith("tip"):
        return "tips"
    if reason.startswith(("purchase", "cart", "order")):
        return "purchases"
    if reason.startswith("unlock"):
        return "unlocks"
    if reason.startswith(("deposit", "wallet")):
        return "deposits"
    return "other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_int(val: Any) -> int:
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return 0


def user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def year_bounds(year: int) -> tuple[int, int]:
    """Return (start_ts_inclusive, end_ts_inclusive) for a calendar year in UTC."""
    start = int(datetime(year, 1, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
    end = int(datetime(year, 12, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp())
    return start, end


def _fmt_date(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%B %d, %Y")


def _bucket() -> str:
    return S.filemgr_bucket or "filemgr"


def _s3_key(user_sub: str, doc_id: str) -> str:
    return f"tax-docs/{user_sub}/{doc_id}.pdf"


def _store_pdf(user_sub: str, doc_id: str, pdf: bytes) -> str:
    key = _s3_key(user_sub, doc_id)
    try:
        _s3.put_object(Bucket=_bucket(), Key=key, Body=pdf, ContentType="application/pdf")
    except Exception:  # pragma: no cover - best effort in dev
        logger.warning("tax doc PDF upload failed for %s", doc_id, exc_info=True)
    return key


def _pdf_url(s3_key: str) -> Optional[str]:
    if S.dev_mode:
        return f"{S.public_base_url}/mock/s3/{_bucket()}/{s3_key}"
    return None


# ---------------------------------------------------------------------------
# Ledger query (credit/earnings entries within a date range)
# ---------------------------------------------------------------------------

def _query_debit_entries(*, user_sub: str, date_from: int, date_to: int) -> List[Dict[str, Any]]:
    """Query billing ledger *debit* (consumer spending) entries within [date_from, date_to].

    The ledger SK format is ``LEDGER#{ts}#{entry_id}``. Loops on
    ``LastEvaluatedKey`` because DDB applies the type filter only after
    fetching a 1MB page.
    """
    pk = user_pk(user_sub)
    key_cond = Key("pk").eq(pk) & Key("sk").between(
        f"LEDGER#{date_from}#", f"LEDGER#{date_to}#~"
    )
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": Attr("type").eq("debit"),
        "Limit": 500,
    }
    collected: List[Dict[str, Any]] = []
    for _ in range(40):  # safety cap (~20k entries)
        resp = T.billing.query(**query_kwargs)
        collected.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
    return collected


def _query_credit_entries(*, user_sub: str, date_from: int, date_to: int) -> List[Dict[str, Any]]:
    """Query billing ledger *credit* entries for a user within [date_from, date_to].

    RETAINED for the creator 1099 path (``tax_form_1099.py``). Do NOT use for
    consumer spending documents — use ``_query_debit_entries`` instead.

    The ledger SK format is ``LEDGER#{ts}#{entry_id}``. The ``~`` upper-bound
    suffix ensures every entry within the ``date_to`` second is included
    (ASCII ``~`` sorts after any entry-id character).

    Loops on ``LastEvaluatedKey`` because DDB applies the type filter only
    after fetching a 1MB page.
    """
    pk = user_pk(user_sub)
    key_cond = Key("pk").eq(pk) & Key("sk").between(
        f"LEDGER#{date_from}#", f"LEDGER#{date_to}#~"
    )
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "FilterExpression": Attr("type").eq("credit"),
        "Limit": 500,
    }
    collected: List[Dict[str, Any]] = []
    for _ in range(40):  # safety cap (~20k entries)
        resp = T.billing.query(**query_kwargs)
        collected.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
    return collected


# ---------------------------------------------------------------------------
# Summary computation
# ---------------------------------------------------------------------------

def compute_spending_summary(
    *,
    user_sub: str,
    date_from: int,
    date_to: int,
) -> Dict[str, Any]:
    """Aggregate *debited* consumer spending by category for a date range.

    Returns a dict matching ``SpendingSummaryOut`` (categories list of
    {category, total_cents, transaction_count}, grand_total_cents,
    transaction_count, currency, date_from, date_to).
    """
    entries = _query_debit_entries(user_sub=user_sub, date_from=date_from, date_to=date_to)

    totals: Dict[str, int] = {c: 0 for c in CATEGORIES}
    counts: Dict[str, int] = {c: 0 for c in CATEGORIES}
    grand_total = 0
    txn_count = 0
    currency = "usd"

    for entry in entries:
        amount = _to_int(entry.get("amount_cents", 0))
        category = classify_category(entry)
        if category not in totals:
            category = "other"
        totals[category] += amount
        counts[category] += 1
        grand_total += amount
        txn_count += 1
        cur = entry.get("currency")
        if cur:
            currency = str(cur).lower()

    categories = [
        {"category": c, "total_cents": totals[c], "transaction_count": counts[c]}
        for c in CATEGORIES
    ]

    logger.info(
        "tax_spending_summary_computed",
        extra={
            "user_sub": user_sub,
            "date_from": date_from,
            "date_to": date_to,
            "grand_total_cents": grand_total,
            "transaction_count": txn_count,
            "entry_type_queried": "debit",
        },
    )

    return {
        "date_from": date_from,
        "date_to": date_to,
        "categories": categories,
        "grand_total_cents": grand_total,
        "transaction_count": txn_count,
        "currency": currency,
    }


def compute_earnings_summary(
    *,
    user_sub: str,
    date_from: int,
    date_to: int,
) -> Dict[str, Any]:
    """Aggregate credited earnings by category for a date range.

    RETAINED for the creator 1099 path (``tax_form_1099.py``). Do NOT use for
    consumer spending documents — use ``compute_spending_summary`` instead.
    """
    entries = _query_credit_entries(user_sub=user_sub, date_from=date_from, date_to=date_to)

    totals: Dict[str, int] = {c: 0 for c in _CREDIT_CATEGORIES}
    counts: Dict[str, int] = {c: 0 for c in _CREDIT_CATEGORIES}
    grand_total = 0
    txn_count = 0
    currency = "usd"

    for entry in entries:
        amount = _to_int(entry.get("amount_cents", 0))
        category = classify_entry(entry)
        if category not in totals:
            category = "other"
        totals[category] += amount
        counts[category] += 1
        grand_total += amount
        txn_count += 1
        cur = entry.get("currency")
        if cur:
            currency = str(cur).lower()

    categories = [
        {"category": c, "total_cents": totals[c], "transaction_count": counts[c]}
        for c in _CREDIT_CATEGORIES
    ]

    logger.info(
        "tax_earnings_summary_computed",
        extra={
            "user_sub": user_sub,
            "date_from": date_from,
            "date_to": date_to,
            "grand_total_cents": grand_total,
            "transaction_count": txn_count,
        },
    )

    return {
        "date_from": date_from,
        "date_to": date_to,
        "categories": categories,
        "grand_total_cents": grand_total,
        "transaction_count": txn_count,
        "currency": currency,
    }


# Cache schema version. Bumped from 1 -> 2 when the consumer summary switched
# from credit (earnings) to debit (spending) aggregation; any cache row without
# this version was computed with the old wrong-direction data and must be
# recomputed.
_CACHE_VERSION = 2


def get_annual_summary(
    *,
    user_sub: str,
    year: int,
    use_cache: bool = True,
) -> Dict[str, Any]:
    """Get or compute the annual consumer SPENDING summary for a year.

    Past years are immutable and cached in ``CACHE#{year}``; the current year
    is always computed fresh.
    """
    current_year = datetime.now(timezone.utc).year
    date_from, date_to = year_bounds(year)
    is_past_year = year < current_year

    if use_cache and is_past_year:
        cached = T.tax_documents.get_item(
            Key={"pk": user_pk(user_sub), "sk": f"CACHE#{year}"}
        ).get("Item")
        if (
            cached
            and cached.get("categories")
            and _to_int(cached.get("cache_version", 1)) >= _CACHE_VERSION
        ):
            return _cache_to_summary(cached, date_from, date_to)

    summary = compute_spending_summary(
        user_sub=user_sub, date_from=date_from, date_to=date_to
    )

    if is_past_year:
        _write_cache(user_sub=user_sub, year=year, summary=summary)

    return summary


def _cache_to_summary(item: Dict[str, Any], date_from: int, date_to: int) -> Dict[str, Any]:
    raw = item.get("categories") or {}
    categories = []
    for c in CATEGORIES:
        cat = raw.get(c) or {}
        categories.append(
            {
                "category": c,
                "total_cents": _to_int(cat.get("total_cents", 0)),
                "transaction_count": _to_int(cat.get("count", cat.get("transaction_count", 0))),
            }
        )
    return {
        "date_from": date_from,
        "date_to": date_to,
        "categories": categories,
        "grand_total_cents": _to_int(item.get("grand_total_cents", 0)),
        "transaction_count": _to_int(item.get("transaction_count", 0)),
        "currency": str(item.get("currency", "usd")),
    }


def _write_cache(*, user_sub: str, year: int, summary: Dict[str, Any]) -> None:
    categories_map = {
        c["category"]: {
            "total_cents": int(c["total_cents"]),
            "count": int(c["transaction_count"]),
        }
        for c in summary["categories"]
    }
    T.tax_documents.put_item(
        Item={
            "pk": user_pk(user_sub),
            "sk": f"CACHE#{year}",
            "year": int(year),
            "categories": categories_map,
            "grand_total_cents": int(summary["grand_total_cents"]),
            "transaction_count": int(summary["transaction_count"]),
            "currency": summary.get("currency", "usd"),
            "cache_version": _CACHE_VERSION,
            "computed_at": now_ts(),
        }
    )


# ---------------------------------------------------------------------------
# Year-over-year comparison
# ---------------------------------------------------------------------------

def get_year_comparison(*, user_sub: str, year: int) -> Dict[str, Any]:
    previous_year = year - 1
    current_summary = get_annual_summary(user_sub=user_sub, year=year)
    previous_summary = get_annual_summary(user_sub=user_sub, year=previous_year)

    cur_total = current_summary["grand_total_cents"]
    prev_total = previous_summary["grand_total_cents"]
    if prev_total > 0:
        change_pct = round((cur_total - prev_total) / prev_total * 100.0, 2)
    elif cur_total > 0:
        change_pct = 100.0
    else:
        change_pct = 0.0

    return {
        "current_year": year,
        "previous_year": previous_year,
        "current_summary": current_summary,
        "previous_summary": previous_summary,
        "change_pct": change_pct,
    }


# ---------------------------------------------------------------------------
# PDF generation
# ---------------------------------------------------------------------------

def generate_tax_summary_pdf(
    *,
    user_sub: str,
    summary: Dict[str, Any],
    year: Optional[int] = None,
) -> bytes:
    """Render an earnings tax summary to PDF bytes (reuses receipts._render_pdf)."""
    profile = get_profile(user_sub)
    name = profile.get("display_name") or user_sub
    email = profile.get("displayed_email") or ""

    date_from = int(summary["date_from"])
    date_to = int(summary["date_to"])

    lines: List[str] = [
        "ANNUAL SPENDING SUMMARY",
        "-" * 52,
    ]
    if year is not None:
        lines.append(f"Tax Year       : {year}")
    lines.append(f"Period         : {_fmt_date(date_from)} - {_fmt_date(date_to)}")
    lines.append(f"Prepared For   : {name}")
    if email:
        lines.append(f"Email          : {email}")
    lines.append(f"Generated      : {_fmt_date(now_ts())}")
    lines.append("")
    lines.append(f"{'Category':<20}{'Count':>8}{'Total':>14}")
    lines.append("-" * 52)

    label_map = {
        "subscriptions": "Subscriptions",
        "tips": "Tips Sent",
        "purchases": "Purchases",
        "unlocks": "Content Unlocks",
        "deposits": "Deposits",
        "other": "Other",
    }
    for cat in summary["categories"]:
        label = label_map.get(cat["category"], cat["category"].title())
        count = int(cat["transaction_count"])
        total = f"${int(cat['total_cents']) / 100:.2f}"
        lines.append(f"{label:<20}{count:>8}{total:>14}")

    lines.append("-" * 52)
    grand = f"${int(summary['grand_total_cents']) / 100:.2f}"
    lines.append(f"{'GRAND TOTAL':<20}{int(summary['transaction_count']):>8}{grand:>14}")
    lines.append("")
    lines.append("This document summarizes your spending on the platform and")
    lines.append("is for informational purposes only. It does not constitute")
    lines.append("tax advice. Consult a tax professional for guidance on")
    lines.append("deductibility of these expenses.")

    return _render_pdf(lines)


# ---------------------------------------------------------------------------
# Document generation / persistence
# ---------------------------------------------------------------------------

def _doc_record_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "doc_id": item.get("doc_id", ""),
        "doc_type": item.get("doc_type", "annual_summary"),
        "year": _to_int(item["year"]) if item.get("year") is not None else None,
        "date_from": _to_int(item.get("date_from", 0)),
        "date_to": _to_int(item.get("date_to", 0)),
        "grand_total_cents": _to_int(item.get("grand_total_cents", 0)),
        "transaction_count": _to_int(item.get("transaction_count", 0)),
        "currency": str(item.get("currency", "usd")),
        "created_at": _to_int(item.get("created_at", 0)),
    }


def generate_tax_document(
    *,
    user_sub: str,
    year: int,
    regenerate: bool = False,
) -> Dict[str, Any]:
    """Generate (or regenerate) an annual tax document, render its PDF, and persist it.

    Enforces the configurable minimum earnings threshold. Returns the document
    record dict. Raises ``ValueError`` with a code when the threshold is not met.
    """
    summary = get_annual_summary(user_sub=user_sub, year=year, use_cache=not regenerate)

    min_cents = int(S.tax_documents_min_earnings_cents)
    if summary["grand_total_cents"] < min_cents:
        raise ValueError(
            f"below_threshold:Spending ${summary['grand_total_cents'] / 100:.2f} "
            f"is below the ${min_cents / 100:.2f} minimum required to issue a tax document."
        )

    date_from, date_to = year_bounds(year)

    existing = _find_doc_for_year(user_sub=user_sub, year=year)
    if existing and not regenerate:
        return _doc_record_out(existing)

    doc_id = existing.get("doc_id") if existing else f"td_{ulidish()}"
    pdf = generate_tax_summary_pdf(user_sub=user_sub, summary=summary, year=year)
    s3_key = _store_pdf(user_sub, doc_id, pdf)

    categories_map = {
        c["category"]: {
            "total_cents": int(c["total_cents"]),
            "count": int(c["transaction_count"]),
        }
        for c in summary["categories"]
    }
    item = {
        "pk": user_pk(user_sub),
        "sk": f"DOC#{year}#{doc_id}",
        "doc_id": doc_id,
        "user_sub": user_sub,
        "doc_type": "annual_summary",
        "year": int(year),
        "date_from": int(date_from),
        "date_to": int(date_to),
        "categories": categories_map,
        "grand_total_cents": int(summary["grand_total_cents"]),
        "transaction_count": int(summary["transaction_count"]),
        "currency": summary.get("currency", "usd"),
        "s3_key": s3_key,
        "created_at": now_ts(),
    }
    T.tax_documents.put_item(Item=item)

    logger.info(
        "tax_document_generated",
        extra={
            "user_sub": user_sub,
            "year": year,
            "doc_id": doc_id,
            "regenerate": regenerate,
            "grand_total_cents": summary["grand_total_cents"],
        },
    )
    return _doc_record_out(item)


def _find_doc_for_year(*, user_sub: str, year: int) -> Optional[Dict[str, Any]]:
    resp = T.tax_documents.query(
        KeyConditionExpression=Key("pk").eq(user_pk(user_sub))
        & Key("sk").begins_with(f"DOC#{year}#"),
    )
    items = resp.get("Items", [])
    if not items:
        return None
    # Newest first.
    items.sort(key=lambda i: _to_int(i.get("created_at", 0)), reverse=True)
    return items[0]


def list_tax_documents(*, user_sub: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List previously generated tax documents for a user (newest first)."""
    resp = T.tax_documents.query(
        KeyConditionExpression=Key("pk").eq(user_pk(user_sub))
        & Key("sk").begins_with("DOC#"),
        Limit=limit * 2,
    )
    items = [_doc_record_out(i) for i in resp.get("Items", [])]
    items.sort(key=lambda d: (d.get("year") or 0, d.get("created_at") or 0), reverse=True)
    return items[:limit]


def download_tax_document_pdf(*, user_sub: str, year: int) -> bytes:
    """Return PDF bytes for the given year's tax document, generating fresh if needed."""
    summary = get_annual_summary(user_sub=user_sub, year=year)
    return generate_tax_summary_pdf(user_sub=user_sub, summary=summary, year=year)


# ---------------------------------------------------------------------------
# Bulk receipt ZIP export (FIN-004)
# ---------------------------------------------------------------------------

def _query_transactions_range(
    *, user_sub: str, date_from: int, date_to: int
) -> List[Dict[str, Any]]:
    """Query the caller's own purchase transactions within [date_from, date_to].

    The ``purchase_transactions`` table is keyed by ``user_sub`` (PK) with sort
    key ``TXN#{created_at}#{txn_id}``, so a timestamp range maps to a ``between``
    KeyCondition. The ``~`` upper-bound suffix sweeps every txn_id within the
    ``date_to`` second (ASCII ``~`` sorts after any txn-id character). Loops on
    ``LastEvaluatedKey`` so a busy table is not silently truncated.
    """
    key_cond = "user_sub = :u AND sk BETWEEN :lo AND :hi"
    expr_vals: Dict[str, Any] = {
        ":u": user_sub,
        ":lo": f"TXN#{int(date_from)}#",
        ":hi": f"TXN#{int(date_to)}#~",
    }
    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": key_cond,
        "ExpressionAttributeValues": expr_vals,
        "Limit": 500,
    }
    collected: List[Dict[str, Any]] = []
    for _ in range(40):  # safety cap (~20k transactions)
        resp = T.purchase_transactions.query(**query_kwargs)
        collected.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        query_kwargs["ExclusiveStartKey"] = last_key
    return collected


def _fetch_receipt_pdf_bytes(*, user_sub: str, txn_id: str) -> bytes:
    """Return the receipt PDF bytes for one transaction, fetched from S3.

    Ensures a receipt exists (generating + uploading it on first request) and
    then reads the object back through the shared ``s3_client`` helper. This is
    the same boto3 path in dev (moto, intercepted in-process) and prod (real
    S3), satisfying the SECOPS-007 dev/prod parity rule — no URL re-derivation
    or HTTP round-trip.
    """
    from app.services import filemanager as fm
    from app.services.receipts import get_or_create_receipt

    receipt_path = fm.norm_path(f"/billing/receipts/{txn_id}.pdf", is_folder=False)
    try:
        node = fm.get_node(user_sub, receipt_path)
    except Exception:
        # Receipt not generated yet — create it (uploads PDF to S3), then read.
        get_or_create_receipt(user_sub, txn_id)
        node = fm.get_node(user_sub, receipt_path)

    bucket = node.get("s3_bucket") or _bucket()
    key = node["s3_key"]
    resp = _s3.get_object(Bucket=bucket, Key=key)
    return resp["Body"].read()


def export_receipts_zip(*, user_sub: str, date_from: int, date_to: int) -> bytes:
    """Bundle every receipt PDF in [date_from, date_to] for ``user_sub`` into a ZIP.

    Only the caller's own transactions are included (scoped by the
    ``purchase_transactions`` user PK). Returns the ZIP archive as bytes.

    Raises ``ValueError("<code>:<message>")`` when:
      - ``no_transactions`` — the range contains no transactions, or
      - ``too_many_transactions`` — the range exceeds ``MAX_ZIP_RECEIPTS``.
    """
    txns = _query_transactions_range(
        user_sub=user_sub, date_from=date_from, date_to=date_to
    )
    if not txns:
        raise ValueError(
            "no_transactions:No transactions found in the specified range"
        )
    if len(txns) > MAX_ZIP_RECEIPTS:
        raise ValueError(
            f"too_many_transactions:Date range contains {len(txns)} transactions "
            f"(max {MAX_ZIP_RECEIPTS}). Please narrow the range."
        )

    written = 0
    skipped = 0
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for txn in txns:
            txn_id = str(txn.get("txn_id") or "")
            if not txn_id:
                skipped += 1
                continue
            try:
                pdf_bytes = _fetch_receipt_pdf_bytes(user_sub=user_sub, txn_id=txn_id)
            except Exception:
                logger.warning(
                    "export_receipts_zip: skipped txn %s", txn_id, exc_info=True
                )
                skipped += 1
                continue
            zf.writestr(f"receipt_{txn_id}.pdf", pdf_bytes)
            written += 1

    logger.info(
        "export_receipts_zip",
        extra={
            "user_sub": user_sub,
            "date_from": date_from,
            "date_to": date_to,
            "count": written,
            "skipped": skipped,
        },
    )

    buf.seek(0)
    return buf.read()
