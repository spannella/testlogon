"""Honest 1099-NEC tax reporting from the PAY-A payout ledger (PAY-40 / PAY-E).

This module is the COMPLIANCE-TRUE 1099-NEC reporter for the payouts program. It
is DISTINCT from ``app.services.tax_form_1099`` (FIN-008), which sums *credited*
earnings (what a creator EARNED). PAY-E reports what the platform ACTUALLY PAID
OUT to each payee, derived from the PAY-A billing ledger:

  ``type="debit"  reason="payout"  state!="reversed"``

so a RETURNED / reversed payout (whose debit was flipped to ``state="reversed"``
by ``creator_payouts.reverse_payout_debit``) does NOT count toward 1099 income.
This is the honest, ledger-true reportable amount - never phantom / uncollected
earnings.

Rules (LOCKED, US-only tax scope):
  - Threshold: $600.00 / year per payee (1099-NEC).           (Box 1)
  - Backup withholding: 24% when the payee has NO certified W-9 on file (PAY-C)
    or a TIN-mismatch flag.                                     (Box 4)
  - TIN is NEVER stored or exported raw - KMS-encrypted + last-4 only (PAY-C /
    SEC-004). Records + exports carry the masked ``***-**-1234`` form only.
  - Idempotent per {payee, tax_year}; a later return/reversal that reduces the
    ledger total SUPERSEDES the prior 1099 as a CORRECTION.

Storage (co-located in the existing ``tax_forms_1099`` table under a DISTINCT
namespace so it never collides with FIN-008 ``FORM#`` rows):
  - NEC record:  pk=USER#{sub}  sk=NEC1099#{year}
                 GSI ByTaxYear: GSI1PK=NECYEAR#{year}  GSI1SK=updated_at(N)
  - Correction history (audit):  pk=USER#{sub}  sk=NEC1099HIST#{year}#{ts}

MONEY values are integer cents throughout.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ulidish

logger = logging.getLogger(__name__)

# --- Constants --------------------------------------------------------------

# The one honest reason tag written by PAY-A for a money-OUT payout debit.
_PAYOUT_DEBIT_REASON = "payout"

# Backup withholding rate: 24% (2400 basis points), 1099-NEC Box 4.
BACKUP_WITHHOLDING_BPS = 2400

_PAYER_NAME = "Platform Payments, Inc."
_PAYER_TIN_FALLBACK_LAST4 = "0000"

_RECORD_KIND = "nec_1099"


class Tax1099Error(Exception):
    """Domain error carrying a code (mapped to HTTP status by the router)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# --- Helpers ----------------------------------------------------------------

def _to_int(val: Any) -> int:
    if isinstance(val, Decimal):
        return int(val)
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return 0


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _rec_sk(tax_year: int) -> str:
    return f"NEC1099#{int(tax_year)}"


def _hist_sk(tax_year: int, ts: int) -> str:
    return f"NEC1099HIST#{int(tax_year)}#{int(ts)}"


def _year_gsi_pk(tax_year: int) -> str:
    return f"NECYEAR#{int(tax_year)}"


def _min_reportable_cents() -> int:
    return int(S.tax_form_1099_min_reportable_cents)


def _payer_tin_last4() -> str:
    ein = (getattr(S, "platform_ein", "") or "").replace("-", "").replace(" ", "")
    return ein[-4:] if len(ein) >= 4 else _PAYER_TIN_FALLBACK_LAST4


def _year_of(ts: Any) -> int:
    return datetime.fromtimestamp(_to_int(ts), tz=timezone.utc).year


def _mask_tin(last4: str) -> str:
    last4 = (last4 or "").strip()
    return f"***-**-{last4}" if last4 else ""


def compute_backup_withholding_cents(reportable_cents: int) -> int:
    """24% backup withholding on the reportable amount (rounded to the cent)."""
    if reportable_cents <= 0:
        return 0
    return int((reportable_cents * BACKUP_WITHHOLDING_BPS + 5000) // 10000)


# --- W-9 gap resolution (PAY-C) ---------------------------------------------

def _w9_gap(user_sub: str) -> Dict[str, Any]:
    """Resolve the payee's certified-W-9 / TIN-mismatch status from the PAY-C store.

    Returns a dict with:
      - has_certified_w9: certified W-9 with a tin_last4 on file
      - tin_mismatch: an explicit TIN-mismatch flag on the W-9 record
      - tin_last4 / legal_name: masked display fields only (never the raw TIN)
      - backup_withholding_applies: True when there is NO certified W-9 or a
        TIN-mismatch flag (IRS backup-withholding trigger).
    """
    tin_last4 = ""
    legal_name = ""
    certified = False
    tin_mismatch = False
    try:
        item = T.tax_info.get_item(
            Key={"pk": _user_pk(user_sub), "sk": "TAX_INFO"}
        ).get("Item")
        if item:
            tin_last4 = str(item.get("tin_last4") or "")
            legal_name = str(item.get("legal_name") or "")
            certified = bool(item.get("certified"))
            tin_mismatch = bool(item.get("tin_mismatch"))
    except Exception:  # pragma: no cover - defensive
        logger.warning("nec1099_w9_lookup_failed user_sub=%s", user_sub, exc_info=True)

    has_certified_w9 = bool(certified and tin_last4)
    applies = (not has_certified_w9) or tin_mismatch
    reason = ""
    if applies:
        reason = "tin_mismatch" if (tin_mismatch and has_certified_w9) else "no_certified_w9"
    return {
        "has_certified_w9": has_certified_w9,
        "tin_mismatch": tin_mismatch,
        "tin_last4": tin_last4,
        "legal_name": legal_name,
        "backup_withholding_applies": applies,
        "backup_withholding_reason": reason,
    }


def _payee_name(user_sub: str, w9_legal_name: str) -> str:
    if w9_legal_name:
        return w9_legal_name
    try:
        from app.services.profile import get_profile

        profile = get_profile(user_sub) or {}
        return profile.get("display_name") or user_sub
    except Exception:  # pragma: no cover - defensive
        return user_sub


# --- Ledger aggregation (the honest reportable amount) ----------------------

def aggregate_paid_payouts(*, user_sub: str, tax_year: int) -> Dict[str, Any]:
    """Sum REAL paid payouts for a payee in a calendar year from the PAY-A ledger.

    Honest source of truth: ``type="debit" reason="payout" state!="reversed"``
    rows in ``T.billing`` under ``pk=USER#{sub}``, bucketed by the calendar year
    of each debit's ``ts`` (the paid/settled timestamp). A RETURNED / reversed
    payout is EXCLUDED (its debit was flipped to ``state="reversed"``), so the
    total is net-of-returns - never phantom income.

    Returns ``{reportable_cents, payout_count, payout_ids, reversed_excluded_cents}``.
    """
    pk = _user_pk(user_sub)
    reportable_cents = 0
    reversed_excluded_cents = 0
    payout_ids: List[str] = []

    # Non-reversed (counted) payout debits for the year.
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#"),
        "FilterExpression": (
            Attr("type").eq("debit")
            & Attr("reason").eq(_PAYOUT_DEBIT_REASON)
            & Attr("state").ne("reversed")
        ),
    }
    while True:
        resp = T.billing.query(**kwargs)
        for item in resp.get("Items", []):
            if _year_of(item.get("ts", 0)) != int(tax_year):
                continue
            reportable_cents += _to_int(item.get("amount_cents", 0))
            meta = item.get("meta") or {}
            pid = meta.get("payout_id") if isinstance(meta, dict) else None
            if pid:
                payout_ids.append(str(pid))
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last

    # Reversed (excluded) payout debits for the year - reconciliation evidence.
    kwargs = {
        "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with("LEDGER#"),
        "FilterExpression": (
            Attr("type").eq("debit")
            & Attr("reason").eq(_PAYOUT_DEBIT_REASON)
            & Attr("state").eq("reversed")
        ),
    }
    while True:
        resp = T.billing.query(**kwargs)
        for item in resp.get("Items", []):
            if _year_of(item.get("ts", 0)) != int(tax_year):
                continue
            reversed_excluded_cents += _to_int(item.get("amount_cents", 0))
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last

    return {
        "reportable_cents": reportable_cents,
        "payout_count": len(payout_ids),
        "payout_ids": sorted(payout_ids),
        "reversed_excluded_cents": reversed_excluded_cents,
    }


# --- Record shaping ---------------------------------------------------------

def _record_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "record_id": item.get("record_id", ""),
        "user_sub": item.get("user_sub", ""),
        "tax_year": _to_int(item.get("tax_year", 0)),
        "payer_name": str(item.get("payer_name", _PAYER_NAME)),
        "payer_tin_last4": str(item.get("payer_tin_last4") or _payer_tin_last4()),
        "payee_name": str(item.get("payee_name", "")),
        "payee_tin_last4": str(item.get("payee_tin_last4", "")),
        "payee_tin_masked": str(item.get("payee_tin_masked", "")),
        # 1099-NEC boxes
        "box1_nonemployee_comp_cents": _to_int(item.get("box1_nonemployee_comp_cents", 0)),
        "box4_backup_withholding_cents": _to_int(item.get("box4_backup_withholding_cents", 0)),
        # flags
        "reportable": bool(item.get("reportable", False)),
        "threshold_cents": _to_int(item.get("threshold_cents", _min_reportable_cents())),
        "backup_withholding_applies": bool(item.get("backup_withholding_applies", False)),
        "backup_withholding_reason": str(item.get("backup_withholding_reason", "")),
        "has_certified_w9": bool(item.get("has_certified_w9", False)),
        # lifecycle
        "status": str(item.get("status", "generated")),
        "correction_count": _to_int(item.get("correction_count", 0)),
        "prior_box1_cents": _to_int(item.get("prior_box1_cents", 0)),
        "payout_count": _to_int(item.get("payout_count", 0)),
        "reversed_excluded_cents": _to_int(item.get("reversed_excluded_cents", 0)),
        "generated_at": _to_int(item.get("generated_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
    }


def _get_record_item(user_sub: str, tax_year: int) -> Optional[Dict[str, Any]]:
    return T.tax_forms_1099.get_item(
        Key={"pk": _user_pk(user_sub), "sk": _rec_sk(tax_year)}
    ).get("Item")


# --- Generate / refresh / correct (idempotent per {payee, year}) ------------

def build_assessment(*, user_sub: str, tax_year: int) -> Dict[str, Any]:
    """Compute (WITHOUT persisting) the honest 1099-NEC assessment for a payee/year.

    Ledger-true Box 1, $600 threshold flag, and 24% backup withholding (Box 4)
    for W-9 gaps. Safe to call for any payee (under-threshold included) - this is
    the queryable computation the report/export use.
    """
    agg = aggregate_paid_payouts(user_sub=user_sub, tax_year=tax_year)
    box1 = int(agg["reportable_cents"])
    threshold = _min_reportable_cents()
    reportable = box1 >= threshold

    gap = _w9_gap(user_sub)
    wh_applies = bool(gap["backup_withholding_applies"])
    # Withholding is computed on the reportable income; recorded honestly (Box 4),
    # never silently dropped, even for the (gate-blocked, rare) W-9-gap payee.
    box4 = compute_backup_withholding_cents(box1) if wh_applies else 0

    return {
        "user_sub": user_sub,
        "tax_year": int(tax_year),
        "payer_name": _PAYER_NAME,
        "payer_tin_last4": _payer_tin_last4(),
        "payee_name": _payee_name(user_sub, gap["legal_name"]),
        "payee_tin_last4": gap["tin_last4"],
        "payee_tin_masked": _mask_tin(gap["tin_last4"]),
        "box1_nonemployee_comp_cents": box1,
        "box4_backup_withholding_cents": box4,
        "reportable": reportable,
        "threshold_cents": threshold,
        "backup_withholding_applies": wh_applies,
        "backup_withholding_reason": gap["backup_withholding_reason"],
        "has_certified_w9": bool(gap["has_certified_w9"]),
        "payout_count": _to_int(agg["payout_count"]),
        "reversed_excluded_cents": _to_int(agg["reversed_excluded_cents"]),
    }


def generate_or_refresh(*, user_sub: str, tax_year: int) -> Dict[str, Any]:
    """Idempotently generate - or CORRECT/supersede - a payee's 1099-NEC for a year.

    - No existing record: create ``status="generated"``.
    - Existing record, box amounts UNCHANGED: idempotent no-op (returns as-is).
    - Existing record, box amounts CHANGED (e.g. a late return/reversal reduced
      the ledger total): SUPERSEDE as a CORRECTION - snapshot the prior figures to
      a history row, bump ``correction_count``, set ``status="corrected"``.

    Under-threshold payees are still persisted (queryable) with ``reportable=False``
    so the record set for the year is complete and auditable.
    """
    a = build_assessment(user_sub=user_sub, tax_year=tax_year)
    existing = _get_record_item(user_sub, tax_year)
    ts = now_ts()

    box1 = a["box1_nonemployee_comp_cents"]
    box4 = a["box4_backup_withholding_cents"]

    if existing is not None:
        prev_box1 = _to_int(existing.get("box1_nonemployee_comp_cents", 0))
        prev_box4 = _to_int(existing.get("box4_backup_withholding_cents", 0))
        unchanged = (prev_box1 == box1) and (prev_box4 == box4)
        if unchanged:
            return _record_out(existing)  # idempotent no-op
        # Correction: snapshot prior state to a history row (supersede cleanly).
        try:
            snap = dict(existing)
            snap["sk"] = _hist_sk(tax_year, _to_int(existing.get("updated_at", ts)))
            snap["superseded_at"] = ts
            snap["superseded_by_ts"] = ts
            snap.pop("GSI1PK", None)
            snap.pop("GSI1SK", None)
            T.tax_forms_1099.put_item(Item=snap)
        except Exception:  # pragma: no cover - best effort audit
            logger.warning("nec1099_history_snapshot_failed user_sub=%s year=%s", user_sub, tax_year)

    record_id = (existing or {}).get("record_id") or f"nec1099_{ulidish()}"
    correction_count = _to_int((existing or {}).get("correction_count", 0)) + (
        1 if existing is not None else 0
    )
    item: Dict[str, Any] = {
        "pk": _user_pk(user_sub),
        "sk": _rec_sk(tax_year),
        "record_kind": _RECORD_KIND,
        "record_id": record_id,
        "user_sub": user_sub,
        "tax_year": int(tax_year),
        "payer_name": a["payer_name"],
        "payer_tin_last4": a["payer_tin_last4"],
        "payee_name": a["payee_name"],
        "payee_tin_last4": a["payee_tin_last4"],
        "payee_tin_masked": a["payee_tin_masked"],
        "box1_nonemployee_comp_cents": int(box1),
        "box4_backup_withholding_cents": int(box4),
        "reportable": bool(a["reportable"]),
        "threshold_cents": int(a["threshold_cents"]),
        "backup_withholding_applies": bool(a["backup_withholding_applies"]),
        "backup_withholding_reason": a["backup_withholding_reason"],
        "has_certified_w9": bool(a["has_certified_w9"]),
        "payout_count": int(a["payout_count"]),
        "reversed_excluded_cents": int(a["reversed_excluded_cents"]),
        "status": "corrected" if existing is not None else "generated",
        "correction_count": int(correction_count),
        "prior_box1_cents": _to_int((existing or {}).get("box1_nonemployee_comp_cents", 0)),
        "generated_at": _to_int((existing or {}).get("generated_at", ts)),
        "updated_at": ts,
        "GSI1PK": _year_gsi_pk(tax_year),
        "GSI1SK": int(ts),
    }
    T.tax_forms_1099.put_item(Item=item)
    logger.info(
        "nec1099_persisted user_sub=%s year=%s box1=%d box4=%d status=%s corrections=%d",
        user_sub, tax_year, box1, box4, item["status"], correction_count,
    )
    return _record_out(item)


# --- Read / list ------------------------------------------------------------

def get_1099(*, user_sub: str, tax_year: int) -> Optional[Dict[str, Any]]:
    item = _get_record_item(user_sub, tax_year)
    return _record_out(item) if item else None


def list_year(*, tax_year: int, include_under_threshold: bool = False,
              limit: int = 500) -> List[Dict[str, Any]]:
    """Admin: list all NEC 1099 records issued for a tax year (via ByTaxYear GSI)."""
    out: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "ByTaxYear",
        "KeyConditionExpression": Key("GSI1PK").eq(_year_gsi_pk(tax_year)),
        "ScanIndexForward": False,
    }
    while True:
        resp = T.tax_forms_1099.query(**kwargs)
        for it in resp.get("Items", []):
            rec = _record_out(it)
            if include_under_threshold or rec["reportable"]:
                out.append(rec)
        last = resp.get("LastEvaluatedKey")
        if not last or len(out) >= limit:
            break
        kwargs["ExclusiveStartKey"] = last
    out.sort(key=lambda r: r.get("box1_nonemployee_comp_cents", 0), reverse=True)
    return out[:limit]


# --- Payee discovery + batch generation -------------------------------------

def discover_payee_subs(*, tax_year: int) -> List[str]:
    """Distinct payee subs with a NON-reversed payout debit in the tax year.

    Scans ``T.billing`` for ``type="debit" reason="payout" state!="reversed"``
    rows whose ``ts`` falls in the year, collecting the ``USER#{sub}`` partition.
    """
    date_from, date_to = None, None
    try:
        from app.services.consumer_tax_documents import year_bounds

        date_from, date_to = year_bounds(tax_year)
    except Exception:  # pragma: no cover
        pass

    subs: set[str] = set()
    filt = (
        Attr("type").eq("debit")
        & Attr("reason").eq(_PAYOUT_DEBIT_REASON)
        & Attr("state").ne("reversed")
    )
    if date_from is not None:
        filt = filt & Attr("ts").between(int(date_from), int(date_to))
    kwargs: Dict[str, Any] = {
        "FilterExpression": filt,
        "ProjectionExpression": "pk, #t",
        "ExpressionAttributeNames": {"#t": "ts"},
    }
    for _ in range(500):  # safety cap
        resp = T.billing.scan(**kwargs)
        for it in resp.get("Items", []):
            pk = str(it.get("pk", ""))
            if pk.startswith("USER#"):
                subs.add(pk[len("USER#"):])
        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        kwargs["ExclusiveStartKey"] = last
    return sorted(subs)


def generate_year_set(*, tax_year: int) -> Dict[str, Any]:
    """Admin: generate/refresh the whole NEC 1099 set for a tax year.

    Idempotent + correction-aware: re-running after a late return supersedes the
    affected payees' records with the reduced amount. Under-threshold payees are
    persisted (queryable) but flagged ``reportable=False``.
    """
    subs = discover_payee_subs(tax_year=tax_year)
    reportable = 0
    under = 0
    corrected = 0
    withholding_flagged = 0
    total_box1 = 0
    total_box4 = 0
    errors = 0
    for sub in subs:
        try:
            rec = generate_or_refresh(user_sub=sub, tax_year=tax_year)
            if rec["reportable"]:
                reportable += 1
            else:
                under += 1
            if rec["status"] == "corrected":
                corrected += 1
            if rec["backup_withholding_applies"]:
                withholding_flagged += 1
            total_box1 += rec["box1_nonemployee_comp_cents"]
            total_box4 += rec["box4_backup_withholding_cents"]
        except Exception:  # pragma: no cover - per-payee isolation
            errors += 1
            logger.warning("nec1099_batch_failed sub=%s year=%s", sub, tax_year, exc_info=True)
    result = {
        "tax_year": int(tax_year),
        "total_payees": len(subs),
        "reportable": reportable,
        "under_threshold": under,
        "corrected": corrected,
        "backup_withholding_flagged": withholding_flagged,
        "total_box1_cents": total_box1,
        "total_box4_backup_withholding_cents": total_box4,
        "errors": errors,
    }
    logger.info("nec1099_year_set_generated %s", result)
    return result


# --- Withholding gap report -------------------------------------------------

def withholding_gap_report(*, tax_year: int) -> Dict[str, Any]:
    """Payees who are reportable but have NO certified W-9 (or a TIN mismatch).

    Surfaces the 24% would-be-withheld figure per payee so a compliance gap is
    never silently dropped even though the PAY-C gate normally blocks payout
    without a certified W-9.
    """
    rows: List[Dict[str, Any]] = []
    total_would_be_withheld = 0
    for rec in list_year(tax_year=tax_year, include_under_threshold=False):
        if not rec["backup_withholding_applies"]:
            continue
        total_would_be_withheld += rec["box4_backup_withholding_cents"]
        rows.append({
            "user_sub": rec["user_sub"],
            "payee_name": rec["payee_name"],
            "payee_tin_masked": rec["payee_tin_masked"],
            "box1_nonemployee_comp_cents": rec["box1_nonemployee_comp_cents"],
            "backup_withholding_cents": rec["box4_backup_withholding_cents"],
            "reason": rec["backup_withholding_reason"],
            "has_certified_w9": rec["has_certified_w9"],
        })
    return {
        "tax_year": int(tax_year),
        "count": len(rows),
        "total_would_be_withheld_cents": total_would_be_withheld,
        "payees": rows,
    }


# --- Export (CSV / JSON) - masked TIN only, never raw -----------------------

_EXPORT_COLUMNS = [
    "tax_year",
    "user_sub",
    "payee_name",
    "payee_tin_masked",
    "payer_name",
    "payer_tin_last4",
    "box1_nonemployee_comp_cents",
    "box4_backup_withholding_cents",
    "reportable",
    "backup_withholding_applies",
    "backup_withholding_reason",
    "status",
    "correction_count",
]


def export_year(*, tax_year: int, fmt: str = "json",
                include_under_threshold: bool = False) -> Tuple[str, str]:
    """Return ``(content, content_type)`` for a filing-ready year export.

    NEVER includes a raw TIN - only ``payee_tin_masked`` (``***-**-1234``). CSV
    and JSON both carry Box 1 / Box 4 totals per payee.
    """
    records = list_year(
        tax_year=tax_year, include_under_threshold=include_under_threshold
    )
    if (fmt or "json").lower() == "csv":
        import csv
        import io

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_EXPORT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow({k: r.get(k, "") for k in _EXPORT_COLUMNS})
        return buf.getvalue(), "text/csv"

    import json

    summary = {
        "tax_year": int(tax_year),
        "payer_name": _PAYER_NAME,
        "payer_tin_last4": _payer_tin_last4(),
        "record_count": len(records),
        "total_box1_cents": sum(r["box1_nonemployee_comp_cents"] for r in records),
        "total_box4_backup_withholding_cents": sum(
            r["box4_backup_withholding_cents"] for r in records
        ),
        "records": [{k: r.get(k) for k in _EXPORT_COLUMNS} for r in records],
    }
    return json.dumps(summary, indent=2), "application/json"
