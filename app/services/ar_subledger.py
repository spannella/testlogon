"""OFBiz AR aging engine (OFB-015, Milestone 4).

Accounts-Receivable open-item aging derived from existing invoices/billing data.
This foundation pass delivers the pure, deterministic aging core:
  - ``derive_charge_status(invoice, ...)`` — open vs. closed determination.
  - ``bucket_for_age(age_seconds)`` / ``age_seconds(created_at, as_of_ts)``.
  - ``compute_ar_aging(open_items, ...)`` — buckets a list of open items.
  - ``aging_from_invoices(...)`` — convenience over a list of invoice dicts.

Additive, flag-gated behind ``S.ar_ap_subledgers_enabled`` (default OFF). The
aging functions are read-only views — they never write to billing/invoices.
SECOPS-007 parity: no ``dev_mode`` branch.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.core.time import now_ts

BUCKET_30_SECS = 30 * 86_400
BUCKET_60_SECS = 60 * 86_400
BUCKET_90_SECS = 90 * 86_400

# Invoice statuses that mean the receivable is closed (no longer outstanding).
_CLOSED_STATUSES = frozenset({"paid", "refunded", "void", "voided", "cancelled"})


def _flag_on() -> bool:
    return bool(getattr(S, "ar_ap_subledgers_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=503, detail="AR/AP subledgers not enabled")


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def derive_charge_status(invoice: Dict[str, Any]) -> str:
    """Derive the AR charge status for an invoice.

    Returns ``"closed"`` when the invoice status is terminal (paid/refunded/
    void/cancelled) OR its linked billing ledger entry carries
    ``ledger_state == "settled"``. Otherwise ``"open"`` (conservative: an
    invoice with no ledger link is treated as open)."""
    status = str(invoice.get("status", "")).lower()
    if status in _CLOSED_STATUSES:
        return "closed"
    if str(invoice.get("ledger_state", "")).lower() == "settled":
        return "closed"
    return "open"


def age_seconds(created_at: int, as_of_ts: int) -> int:
    return max(0, int(as_of_ts) - int(created_at))


def bucket_for_age(secs: int) -> str:
    if secs <= BUCKET_30_SECS:
        return "current"
    if secs <= BUCKET_60_SECS:
        return "30"
    if secs <= BUCKET_90_SECS:
        return "60"
    return "90_plus"


_BUCKET_FIELD = {
    "current": "current_cents",
    "30": "days_30_cents",
    "60": "days_60_cents",
    "90_plus": "days_90_plus_cents",
}


def compute_ar_aging(
    open_items: Iterable[Dict[str, Any]],
    *,
    as_of_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Bucket a list of open items by age.

    Each item must carry ``amount_cents`` and ``created_at``; optional ``ref_id``,
    ``user_sub``, ``kind``, ``charge_status``. Returns an AgingOut-shaped dict.
    Raises 503 if the feature flag is off; rejects a future ``as_of_ts`` (400).
    """
    _require_enabled()
    now = now_ts()
    asof = as_of_ts if as_of_ts is not None else now
    if asof > now:
        raise HTTPException(status_code=400, detail="as_of_ts cannot be in the future")

    buckets = {"current_cents": 0, "days_30_cents": 0, "days_60_cents": 0, "days_90_plus_cents": 0}
    items_out: List[Dict[str, Any]] = []
    total = 0
    count = 0
    for it in open_items:
        created = _to_int(it.get("created_at"))
        if created > asof:
            continue  # not yet open as of the as-of date
        amt = _to_int(it.get("amount_cents"))
        secs = age_seconds(created, asof)
        bucket = bucket_for_age(secs)
        buckets[_BUCKET_FIELD[bucket]] += amt
        total += amt
        count += 1
        items_out.append(
            {
                "ref_id": str(it.get("ref_id", "")),
                "user_sub": str(it.get("user_sub", "")),
                "amount_cents": amt,
                "created_at": created,
                "age_days": secs // 86_400,
                "bucket": bucket,
                "charge_status": str(it.get("charge_status", "open")),
                "kind": str(it.get("kind", "invoice")),
            }
        )
    return {
        **buckets,
        "total_open_cents": total,
        "open_item_count": count,
        "as_of_ts": asof,
        "items": items_out,
    }


def aging_from_invoices(
    invoices: Iterable[Dict[str, Any]],
    *,
    as_of_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Convenience: filter invoices to AR-open items (via derive_charge_status)
    then bucket them. Each invoice dict needs ``amount_cents``/``total_cents``
    and ``created_at``; ``invoice_number``/``user_sub`` are projected through."""
    _require_enabled()
    open_items: List[Dict[str, Any]] = []
    for inv in invoices:
        if derive_charge_status(inv) != "open":
            continue
        amt = _to_int(inv.get("amount_cents", inv.get("total_cents", 0)))
        open_items.append(
            {
                "ref_id": inv.get("invoice_number", inv.get("ref_id", "")),
                "user_sub": inv.get("user_sub", ""),
                "amount_cents": amt,
                "created_at": _to_int(inv.get("created_at")),
                "charge_status": "open",
                "kind": "invoice",
            }
        )
    return compute_ar_aging(open_items, as_of_ts=as_of_ts)
