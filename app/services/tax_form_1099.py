"""Creator 1099 / Tax-Form generation (FIN-008).

This module generates annual 1099-style earnings forms for CREATORS / payees
(the platform's independent contractors). It is DISTINCT from
``app.services.consumer_tax_documents`` (FIN-004), which produces consumer /
buyer-side annual spending summaries. FIN-008 is the platform-issuer side:
per-creator annual income totals, a generated 1099 PDF, admin BATCH generation
across all eligible creators for a tax year, a correction/re-generate flow, and
PDF download.

This module does NOT re-invent ledger querying or PDF rendering. It REUSES:
  - ``consumer_tax_documents.compute_earnings_summary`` / ``_query_credit_entries``
    / ``year_bounds`` for credited-earnings aggregation from the billing ledger.
  - ``consumer_tax_documents._store_pdf`` / ``_pdf_url`` for S3 storage + dev URLs.
  - ``receipts._render_pdf`` for text-based PDF rendering (no new dependency).

Storage (``tax_forms_1099`` table, single-table):
  - Form records:  pk=USER#{user_sub} sk=FORM#{tax_year}
                   GSI ByTaxYear: GSI1PK=YEAR#{tax_year} GSI1SK=created_at(N)
  - Batch locks:   pk=BATCH#{tax_year} sk=LOCK

MONEY values are integer cents throughout.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ulidish
from app.services.consumer_tax_documents import (
    _pdf_url,
    _query_credit_entries,
    _store_pdf,
    compute_earnings_summary,
    year_bounds,
)
from app.services.profile import get_profile
from app.services.receipts import _render_pdf

logger = logging.getLogger(__name__)

# Earliest year for which the platform has any payee data.
_PLATFORM_LAUNCH_YEAR = 2024

# Display-only payer identity printed on every generated 1099.
_PAYER_NAME = "Platform Payments, Inc."
_PAYER_TIN_LAST4 = "0000"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class TaxForm1099Error(Exception):
    """Domain error carrying a code (mapped to HTTP status by the router)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


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


def _form_sk(tax_year: int) -> str:
    return f"FORM#{int(tax_year)}"


def _batch_pk(tax_year: int) -> str:
    return f"BATCH#{int(tax_year)}"


def _year_gsi_pk(tax_year: int) -> str:
    return f"YEAR#{int(tax_year)}"


def _fmt_date(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%B %d, %Y")


def _min_reportable_cents() -> int:
    return int(S.tax_form_1099_min_reportable_cents)


def annual_earnings_cents(*, user_sub: str, tax_year: int) -> int:
    """Total credited (income) earnings for a creator in a calendar year.

    Reuses the consumer_tax_documents ledger aggregation so the income figure is
    identical to the creator-earnings view.
    """
    date_from, date_to = year_bounds(tax_year)
    summary = compute_earnings_summary(
        user_sub=user_sub, date_from=date_from, date_to=date_to
    )
    return int(summary["grand_total_cents"])


# ---------------------------------------------------------------------------
# Record shaping
# ---------------------------------------------------------------------------

def _form_out(item: Dict[str, Any]) -> Dict[str, Any]:
    s3_key = item.get("pdf_s3_key") or ""
    return {
        "form_id": item.get("form_id", ""),
        "user_sub": item.get("user_sub", ""),
        "tax_year": _to_int(item.get("tax_year", 0)),
        "total_earnings_cents": _to_int(item.get("total_earnings_cents", 0)),
        "qualifies": bool(item.get("qualifies", False)),
        "status": str(item.get("status", "generated")),
        "correction_count": _to_int(item.get("correction_count", 0)),
        "generated_at": _to_int(item.get("generated_at", 0)),
        "updated_at": _to_int(item.get("updated_at", 0)),
        "payer_name": str(item.get("payer_name", _PAYER_NAME)),
        "payer_tin_last4": str(item.get("payer_tin_last4", _PAYER_TIN_LAST4)),
        "download_url": _pdf_url(s3_key) if s3_key else None,
    }


def _get_form_item(user_sub: str, tax_year: int) -> Optional[Dict[str, Any]]:
    return T.tax_forms_1099.get_item(
        Key={"pk": user_pk(user_sub), "sk": _form_sk(tax_year)}
    ).get("Item")


# ---------------------------------------------------------------------------
# PDF generation
# ---------------------------------------------------------------------------

def _render_1099_pdf(
    *,
    user_sub: str,
    tax_year: int,
    total_earnings_cents: int,
    corrected: bool,
) -> bytes:
    profile = get_profile(user_sub)
    recipient = profile.get("display_name") or user_sub
    email = profile.get("displayed_email") or ""

    lines: List[str] = [
        "FORM 1099-NEC  -  NONEMPLOYEE COMPENSATION",
        ("** CORRECTED **" if corrected else "(Original)"),
        "-" * 52,
        f"Tax Year       : {tax_year}",
        "",
        "PAYER",
        f"  Name         : {_PAYER_NAME}",
        f"  TIN          : ***-**-{_PAYER_TIN_LAST4}",
        "",
        "RECIPIENT",
        f"  Name         : {recipient}",
    ]
    if email:
        lines.append(f"  Email        : {email}")
    lines.append(f"  Recipient ID : {user_sub}")
    lines.append("")
    lines.append("-" * 52)
    box1 = f"${total_earnings_cents / 100:.2f}"
    lines.append(f"{'Box 1  Nonemployee compensation':<38}{box1:>14}")
    lines.append("-" * 52)
    lines.append(f"Generated      : {_fmt_date(now_ts())}")
    lines.append("")
    lines.append("This form reports nonemployee compensation paid by the")
    lines.append("platform during the tax year. It is provided for")
    lines.append("informational purposes and does not constitute tax advice.")
    return _render_pdf(lines)


# ---------------------------------------------------------------------------
# Single-creator generation
# ---------------------------------------------------------------------------

def _persist_form(
    *,
    user_sub: str,
    tax_year: int,
    total_earnings_cents: int,
    qualifies: bool,
    existing: Optional[Dict[str, Any]],
    corrected: bool,
) -> Dict[str, Any]:
    ts = now_ts()
    form_id = (existing or {}).get("form_id") or f"f1099_{ulidish()}"
    pdf = _render_1099_pdf(
        user_sub=user_sub,
        tax_year=tax_year,
        total_earnings_cents=total_earnings_cents,
        corrected=corrected,
    )
    # Reuse consumer_tax_documents._store_pdf (tax-docs/{user}/{id}.pdf in S3).
    s3_key = _store_pdf(user_sub, form_id, pdf)

    correction_count = _to_int((existing or {}).get("correction_count", 0)) + (
        1 if corrected else 0
    )
    item: Dict[str, Any] = {
        "pk": user_pk(user_sub),
        "sk": _form_sk(tax_year),
        "form_id": form_id,
        "user_sub": user_sub,
        "tax_year": int(tax_year),
        "total_earnings_cents": int(total_earnings_cents),
        "qualifies": bool(qualifies),
        "status": "corrected" if corrected else "generated",
        "correction_count": int(correction_count),
        "pdf_s3_key": s3_key,
        "payer_name": _PAYER_NAME,
        "payer_tin_last4": _PAYER_TIN_LAST4,
        "generated_at": _to_int((existing or {}).get("generated_at", ts)),
        "updated_at": ts,
        # GSI ByTaxYear: list all forms issued for a tax year.
        "GSI1PK": _year_gsi_pk(tax_year),
        "GSI1SK": int(ts),
    }
    T.tax_forms_1099.put_item(Item=item)
    logger.info(
        "tax_form_1099_persisted",
        extra={
            "user_sub": user_sub,
            "tax_year": tax_year,
            "form_id": form_id,
            "total_earnings_cents": total_earnings_cents,
            "qualifies": qualifies,
            "corrected": corrected,
        },
    )
    return _form_out(item)


def generate_1099(*, user_sub: str, tax_year: int) -> Dict[str, Any]:
    """Generate a 1099 for a single creator/year.

    Raises ``TaxForm1099Error`` with code:
      - ``below_threshold`` when annual earnings are under the reportable minimum.
      - ``already_generated`` (-> 409) when a form already exists for the year
        (callers must use the correction endpoint to re-issue).
    """
    existing = _get_form_item(user_sub, tax_year)
    if existing is not None:
        raise TaxForm1099Error(
            "already_generated",
            "1099 already generated for this tax year",
        )

    total = annual_earnings_cents(user_sub=user_sub, tax_year=tax_year)
    if total < _min_reportable_cents():
        raise TaxForm1099Error(
            "below_threshold",
            f"Annual earnings ${total / 100:.2f} are below the "
            f"${_min_reportable_cents() / 100:.2f} reportable threshold.",
        )

    return _persist_form(
        user_sub=user_sub,
        tax_year=tax_year,
        total_earnings_cents=total,
        qualifies=True,
        existing=None,
        corrected=False,
    )


def correct_1099(*, user_sub: str, tax_year: int) -> Dict[str, Any]:
    """Re-generate (correct) an existing 1099 with fresh ledger totals.

    Raises ``TaxForm1099Error('not_found')`` (-> 404) when no form exists yet
    (callers must generate first).
    """
    existing = _get_form_item(user_sub, tax_year)
    if existing is None:
        raise TaxForm1099Error(
            "not_found", "No 1099 found for this tax year"
        )

    total = annual_earnings_cents(user_sub=user_sub, tax_year=tax_year)
    qualifies = total >= _min_reportable_cents()
    return _persist_form(
        user_sub=user_sub,
        tax_year=tax_year,
        total_earnings_cents=total,
        qualifies=qualifies,
        existing=existing,
        corrected=True,
    )


# ---------------------------------------------------------------------------
# Read / list / download
# ---------------------------------------------------------------------------

def get_1099(*, user_sub: str, tax_year: int) -> Optional[Dict[str, Any]]:
    item = _get_form_item(user_sub, tax_year)
    return _form_out(item) if item else None


def list_1099s(*, user_sub: str, limit: int = 50) -> List[Dict[str, Any]]:
    resp = T.tax_forms_1099.query(
        KeyConditionExpression=Key("pk").eq(user_pk(user_sub))
        & Key("sk").begins_with("FORM#"),
        Limit=limit * 2,
    )
    items = [_form_out(i) for i in resp.get("Items", [])]
    items.sort(key=lambda f: f.get("tax_year", 0), reverse=True)
    return items[:limit]


def download_1099_url(*, user_sub: str, tax_year: int) -> str:
    """Return a download URL for a creator's 1099 PDF.

    Raises ``TaxForm1099Error('not_found')`` (-> 404) when no form exists.
    """
    item = _get_form_item(user_sub, tax_year)
    if item is None:
        raise TaxForm1099Error("not_found", "No 1099 found for this tax year")
    s3_key = item.get("pdf_s3_key") or ""
    url = _pdf_url(s3_key) if s3_key else None
    if not url:
        # Fall back to a deterministic dev URL even if S3 store was best-effort.
        url = f"{S.public_base_url}/mock/s3/{S.filemgr_bucket or 'filemgr'}/{s3_key}"
    return url


def download_1099_pdf_bytes(*, user_sub: str, tax_year: int) -> bytes:
    """Render fresh PDF bytes for an existing 1099 (used by streaming download).

    Raises ``TaxForm1099Error('not_found')`` (-> 404) when no form exists.
    """
    item = _get_form_item(user_sub, tax_year)
    if item is None:
        raise TaxForm1099Error("not_found", "No 1099 found for this tax year")
    return _render_1099_pdf(
        user_sub=user_sub,
        tax_year=tax_year,
        total_earnings_cents=_to_int(item.get("total_earnings_cents", 0)),
        corrected=str(item.get("status")) == "corrected",
    )


def list_year_forms(*, tax_year: int, limit: int = 200) -> List[Dict[str, Any]]:
    """Admin: list all 1099 forms issued for a tax year (via ByTaxYear GSI)."""
    resp = T.tax_forms_1099.query(
        IndexName="ByTaxYear",
        KeyConditionExpression=Key("GSI1PK").eq(_year_gsi_pk(tax_year)),
        Limit=limit,
        ScanIndexForward=False,
    )
    return [_form_out(i) for i in resp.get("Items", [])]


# ---------------------------------------------------------------------------
# Batch generation (admin)
# ---------------------------------------------------------------------------

def _discover_creator_subs(*, tax_year: int) -> List[str]:
    """Find distinct creator subs with credited earnings in the tax year.

    Scans the billing table for ``USER#{sub}`` partitions that have at least one
    credit ledger entry within the year. Deterministic for tests (stable order).
    """
    date_from, date_to = year_bounds(tax_year)
    subs: set[str] = set()
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": Attr("type").eq("credit")
        & Attr("sk").begins_with("LEDGER#")
        & Attr("ts").between(int(date_from), int(date_to)),
        "ProjectionExpression": "pk",
        "Limit": 1000,
    }
    for _ in range(200):  # safety cap
        resp = T.billing.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            pk = str(item.get("pk", ""))
            if pk.startswith("USER#"):
                subs.add(pk[len("USER#"):])
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        scan_kwargs["ExclusiveStartKey"] = last_key
    return sorted(subs)


def _batch_lock_active(tax_year: int) -> bool:
    item = T.tax_forms_1099.get_item(
        Key={"pk": _batch_pk(tax_year), "sk": "LOCK"}
    ).get("Item")
    return bool(item) and str(item.get("state")) == "in_progress"


def _acquire_batch_lock(tax_year: int) -> bool:
    """Atomically acquire the per-year batch lock. Returns False if already held."""
    try:
        T.tax_forms_1099.put_item(
            Item={
                "pk": _batch_pk(tax_year),
                "sk": "LOCK",
                "state": "in_progress",
                "started_at": now_ts(),
            },
            ConditionExpression="attribute_not_exists(pk) OR #s <> :ip",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={":ip": "in_progress"},
        )
        return True
    except Exception:
        return False


def _release_batch_lock(tax_year: int) -> None:
    try:
        T.tax_forms_1099.update_item(
            Key={"pk": _batch_pk(tax_year), "sk": "LOCK"},
            UpdateExpression="SET #s = :done, finished_at = :ts",
            ExpressionAttributeNames={"#s": "state"},
            ExpressionAttributeValues={":done": "done", ":ts": now_ts()},
        )
    except Exception:  # pragma: no cover - best effort
        logger.warning("failed to release 1099 batch lock for %s", tax_year)


def batch_generate_1099s(*, tax_year: int) -> Dict[str, Any]:
    """Admin: generate 1099s for all eligible creators for a tax year.

    Threshold-gated; creators below the reportable minimum are excluded.
    Already-generated forms are skipped (idempotent within a year).

    Raises ``TaxForm1099Error('batch_in_progress')`` (-> 429) when another batch
    for the same year is already running.
    """
    if not _acquire_batch_lock(tax_year):
        raise TaxForm1099Error(
            "batch_in_progress", "Batch generation already in progress"
        )

    total_creators = 0
    qualifying = 0
    generated = 0
    skipped = 0
    errors = 0
    try:
        subs = _discover_creator_subs(tax_year=tax_year)
        total_creators = len(subs)
        threshold = _min_reportable_cents()
        for sub in subs:
            try:
                total = annual_earnings_cents(user_sub=sub, tax_year=tax_year)
                if total < threshold:
                    continue
                qualifying += 1
                if _get_form_item(sub, tax_year) is not None:
                    skipped += 1
                    continue
                _persist_form(
                    user_sub=sub,
                    tax_year=tax_year,
                    total_earnings_cents=total,
                    qualifies=True,
                    existing=None,
                    corrected=False,
                )
                generated += 1
            except Exception:  # pragma: no cover - per-creator isolation
                errors += 1
                logger.warning(
                    "1099 batch: failed for creator",
                    extra={"user_sub": sub, "tax_year": tax_year},
                    exc_info=True,
                )
    finally:
        _release_batch_lock(tax_year)

    result = {
        "tax_year": int(tax_year),
        "total_creators": total_creators,
        "qualifying": qualifying,
        "generated": generated,
        "skipped": skipped,
        "errors": errors,
    }
    logger.info("tax_form_1099_batch_complete", extra=result)
    return result
