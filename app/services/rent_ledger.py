"""Rent-ledger subsystem (open-property vertical, RNT-001..RNT-006).

Property-scoped monthly rent recognition built entirely on the existing
billing-ledger primitives in :mod:`app.services.billing_shared`. NEVER forks the
ledger or balance math: every monetary row is written through
``new_ledger_entry`` and every counter via ``apply_balance_delta``; voids go
through ``settle_or_reverse_ledger`` (reversal, never delete).

Cross-cluster collaborators (LSE leases, OFB-015 AR-aging) are imported lazily
inside functions with ``try/except ImportError`` so this module loads against a
stale base that does not yet contain those siblings — their IDs are treated as
opaque strings.

Flag-gated default-OFF: ``RENT_LEDGER_ENABLED`` (cluster) + ``RENT_RUN_ENABLED``
(automated timer sub-gate). With the cluster flag off every public function
short-circuits to ``None``/``[]`` and writes nothing.

RECONCILIATION D1: every rent-charge / rent-payment ledger row carries a
``signed_amount_cents`` field (positive for charges = obligation owed, negative
for payments = obligation reduced) so a downstream reconciler can net the ledger
without re-deriving sign from ``rent_kind``.
"""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.services.alerts import audit_event
from app.services.billing_shared import (
    apply_balance_delta,
    compute_due,
    ddb_del,
    ddb_get,
    ddb_put,
    ddb_query_pk,
    new_ledger_entry,
    settle_or_reverse_ledger,
    user_pk,
)

logger = logging.getLogger("rent_ledger")

_PERIOD_RE = re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])$")


# ---------------------------------------------------------------------------
# Period / key helpers
# ---------------------------------------------------------------------------
def _current_period() -> str:
    """Current calendar month as ``YYYY-MM`` (UTC). Clone of
    ``compute_billing._current_month_key``."""
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _marker_pk(user_sub: str) -> str:
    return f"RENT_PERIOD#{user_sub}"


def _marker_sk(lease_id: str, period: str) -> str:
    return f"LEASE#{lease_id}#PERIOD#{period}"


def _valid_period(period: str) -> bool:
    return bool(_PERIOD_RE.match(period or ""))


# ---------------------------------------------------------------------------
# Lazy cross-cluster collaborators (LSE leases)
# ---------------------------------------------------------------------------
def _get_lease(user_sub: str, lease_id: str) -> Optional[Dict[str, Any]]:
    """Resolve a lease via LSE-001 ``get_lease`` if available.

    Returns ``None`` when the lease is absent / foreign-owned, or when the
    leases module is not yet present in the tree (stale base).
    """
    try:
        from app.services.leases import get_lease  # type: ignore
    except ImportError:
        return None
    try:
        return get_lease(user_sub, lease_id)
    except Exception:
        return None


def _list_active_leases_for_owner(user_sub: str) -> List[Dict[str, Any]]:
    """Owner-scoped active-lease enumeration via LSE-002 ``list_leases``.

    Pages via ``next_cursor`` to exhaustion (the GSI2 status path returns a
    single ``query()`` page — RNT-005 §10 Q1 resolution option (a)). Returns
    ``[]`` if the leases module is absent.
    """
    try:
        from app.services.leases import list_leases  # type: ignore
    except ImportError:
        return []
    leases: List[Dict[str, Any]] = []
    cursor: Optional[str] = None
    try:
        while True:
            try:
                result = list_leases(user_sub, status="active", cursor=cursor)
            except TypeError:
                # Older signature without cursor kwarg.
                result = list_leases(user_sub, status="active")
            if isinstance(result, dict):
                leases.extend(result.get("leases", []))
                cursor = result.get("next_cursor")
            else:  # defensive: a plain list
                leases.extend(result or [])
                cursor = None
            if not cursor:
                break
    except Exception:
        logger.exception("rent_ledger: list_leases failed user_sub=%s", user_sub)
    return leases


# ---------------------------------------------------------------------------
# RNT-001: rent-charge posting + system-wide timer
# ---------------------------------------------------------------------------
def post_rent_charge(
    user_sub: str,
    lease: Dict[str, Any],
    *,
    period: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Post exactly one ``rent_charge`` ledger row per ``(user_sub, lease, period)``.

    Idempotent via a conditional marker put on ``T.rent_period_markers``. Returns
    the created ledger item, or the skip sentinel
    ``{"skipped": True, "reason": "already_charged", "period": period}`` when the
    period was already charged, or ``None`` when the cluster flag is off.
    """
    if not S.rent_ledger_enabled:
        return None

    period = period or _current_period()
    lease_id = str(lease["lease_id"])
    amount_cents = int(lease.get("monthly_rent_cents", 0))
    currency = lease.get("currency", "usd")
    mpk = _marker_pk(user_sub)
    msk = _marker_sk(lease_id, period)

    # 1. Claim the idempotency marker (CAS).
    try:
        T.rent_period_markers.put_item(
            Item={
                "pk": mpk,
                "sk": msk,
                "ledger_sk": "",
                "charged_at": now_ts(),
                "amount_cents": amount_cents,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return {"skipped": True, "reason": "already_charged", "period": period}
        raise

    # 2. Write the rent_charge ledger row (positive signed amount = owed).
    reason = f"Rent {period} — {lease.get('lease_number', lease_id)}"
    sk, item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(user_sub),
        entry_type="rent_charge",
        amount_cents=amount_cents,
        state="settled",
        reason=reason,
        extra={
            "lease_id": lease_id,
            "property_id": lease.get("property_id", ""),
            "unit_id": lease.get("unit_id", ""),
            "tenant_id": lease.get("tenant_id", ""),
            "period": period,
            "rent_kind": "charge",
            "currency": currency,
            # RECONCILIATION D1: charges add to the obligation → positive.
            "signed_amount_cents": amount_cents,
        },
    )
    ddb_put(T.billing, item)

    # 3. Back-fill the ledger_sk onto the marker for traceability.
    T.rent_period_markers.update_item(
        Key={"pk": mpk, "sk": msk},
        UpdateExpression="SET ledger_sk = :s",
        ExpressionAttributeValues={":s": sk},
    )

    # 4. Bump the owed_settled_cents balance counter. A zero-amount charge is a
    #    monetary no-op (RNT-001 §5.3); skip the balance update entirely because
    #    apply_balance_delta cannot build a SET expression from an all-zero delta.
    if amount_cents != 0:
        apply_balance_delta(
            T.billing,
            user_pk(user_sub),
            {"owed_settled_cents": amount_cents},
            currency=currency,
        )

    # 5. Audit.
    audit_event(
        "rent.charge_posted",
        user_sub,
        lease_id=lease_id,
        period=period,
        amount_cents=amount_cents,
        ledger_sk=sk,
    )
    return item


def _scan_active_leases() -> List[Dict[str, Any]]:
    """System-wide active-lease sweep via LSE GSI1 (``leases-all-index``).

    Clones the ``LastEvaluatedKey`` loop from ``compute_billing._scan_all_running_instances``.
    Returns ``[]`` if the leases table handle is absent (stale base).
    """
    leases_tbl = getattr(T, "leases", None)
    if leases_tbl is None:
        return []
    from boto3.dynamodb.conditions import Key, Attr

    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "leases-all-index",
        "KeyConditionExpression": Key("GSI1PK").eq("LEASES#ALL"),
        "FilterExpression": Attr("status").eq("active"),
    }
    try:
        while True:
            resp = leases_tbl.query(**kwargs)
            items.extend(resp.get("Items", []))
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
    except Exception:
        logger.exception("rent_ledger: _scan_active_leases failed")
    return items


def run_rent_charges(*, period: Optional[str] = None) -> Dict[str, int]:
    """System-wide sweep: charge every active lease for ``period``.

    Returns ``{"period", "charged", "skipped", "lease_count"}`` (extended from
    the int-only RNT-001 contract per RNT-005 §10 Q6; the timer loop ignores the
    return value so this is backward-compatible).
    """
    if not S.rent_ledger_enabled:
        return {"period": period or _current_period(), "charged": 0, "skipped": 0, "lease_count": 0}
    period = period or _current_period()
    leases = _scan_active_leases()
    charged = 0
    skipped = 0
    for lease in leases:
        owner = lease.get("user_sub", "")
        if not owner:
            logger.warning("rent_run: lease without user_sub lease_id=%s", lease.get("lease_id"))
            continue
        try:
            result = post_rent_charge(owner, lease, period=period)
            if result and not result.get("skipped"):
                charged += 1
            else:
                skipped += 1
        except Exception:
            logger.exception(
                "rent_run_charge_failed user_sub=%s lease_id=%s period=%s",
                owner, lease.get("lease_id"), period,
            )
    logger.info("rent_run period=%s charged=%d skipped=%d", period, charged, skipped)
    audit_event(
        "rent.system_run",
        "system",
        period=period,
        charged=charged,
        skipped=skipped,
        lease_count=len(leases),
    )
    return {"period": period, "charged": charged, "skipped": skipped, "lease_count": len(leases)}


async def run_rent_run_loop(*, poll_interval: Optional[int] = None) -> None:
    interval = poll_interval if poll_interval is not None else S.rent_run_poll_interval
    while True:
        try:
            run_rent_charges()
        except Exception:
            logger.exception("rent_run_loop error")
        await asyncio.sleep(interval)


def start_rent_run_task() -> None:
    """Register the rent-run background timer at app startup (gated on both flags)."""
    if S.rent_ledger_enabled and S.rent_run_enabled:
        asyncio.ensure_future(run_rent_run_loop())
        logger.info("Rent-run timer started (interval=%ds)", S.rent_run_poll_interval)


# ---------------------------------------------------------------------------
# RNT-002: record-payment + charge-status derivation + per-lease ledger
# ---------------------------------------------------------------------------
def list_rent_ledger_for_lease(user_sub: str, lease_id: str) -> List[Dict[str, Any]]:
    """All non-system rent rows (charges + payments) for a lease, newest-first."""
    if not S.rent_ledger_enabled:
        return []
    rows = ddb_query_pk(T.billing, user_pk(user_sub))
    rent_rows = [
        r for r in rows
        if str(r.get("sk", "")).startswith("LEDGER#")
        and r.get("lease_id") == lease_id
        and r.get("rent_kind") in {"charge", "payment"}
    ]
    rent_rows.sort(key=lambda r: int(r.get("ts", 0)), reverse=True)
    return rent_rows


def record_payment(
    user_sub: str,
    *,
    lease_id: str,
    amount_cents: int,
    method: str,
    paid_on: Optional[int] = None,
    reference: str = "",
    period: Optional[str] = None,
    notes: str = "",
) -> Optional[Dict[str, Any]]:
    """Record a manually-received rent payment. NEVER calls a payment provider."""
    if not S.rent_ledger_enabled:
        return None

    from fastapi import HTTPException

    lease = _get_lease(user_sub, lease_id)
    if not lease:
        raise HTTPException(status_code=404, detail={"code": "lease_not_found"})
    if int(amount_cents) < 1:
        raise HTTPException(status_code=422, detail={"code": "invalid_amount"})

    period = period or _current_period()
    paid_on = paid_on if paid_on is not None else now_ts()
    currency = lease.get("currency", "usd")
    amount_cents = int(amount_cents)

    sk, item = new_ledger_entry(
        key_name="pk",
        key_value=user_pk(user_sub),
        entry_type="rent_payment",
        amount_cents=amount_cents,
        state="settled",
        reason=f"Rent payment — lease {lease.get('lease_number', lease_id)}",
        extra={
            "lease_id": lease_id,
            "property_id": lease.get("property_id", ""),
            "unit_id": lease.get("unit_id", ""),
            "tenant_id": lease.get("tenant_id", ""),
            "period": period,
            "rent_kind": "payment",
            "method": method,
            "reference": reference,
            "paid_on": int(paid_on),
            "currency": currency,
            # RECONCILIATION D1: payments reduce the obligation → negative.
            "signed_amount_cents": -amount_cents,
        },
        meta={"notes": notes} if notes else None,
    )
    ddb_put(T.billing, item)

    apply_balance_delta(
        T.billing,
        user_pk(user_sub),
        {"payments_settled_cents": amount_cents},
        currency=currency,
    )

    audit_event(
        "rent.payment_recorded",
        user_sub,
        lease_id=lease_id,
        period=period,
        amount_cents=amount_cents,
        method=method,
        reference=reference,
        ledger_sk=sk,
    )
    return item


def derive_charge_status(
    charge_row: Dict[str, Any],
    *,
    payments: List[Dict[str, Any]],
    lease: Dict[str, Any],
    as_of_ts: Optional[int] = None,
) -> str:
    """Pure status derivation: open|partial|paid|overdue|voided. No I/O."""
    as_of = as_of_ts if as_of_ts is not None else now_ts()

    if charge_row.get("state") == "reversed":
        return "voided"

    period = charge_row.get("period")
    charge_amount = int(charge_row.get("amount_cents", 0))
    lease_id = charge_row.get("lease_id")

    paid_total = sum(
        int(p.get("amount_cents", 0))
        for p in payments
        if p.get("rent_kind") == "payment"
        and p.get("period") == period
        and p.get("lease_id") == lease_id
        and p.get("state") != "reversed"
    )

    if paid_total >= charge_amount and charge_amount > 0:
        return "paid"
    if charge_amount == 0:
        # Zero-rent charge: paid iff any payment, else settled (open) — treat as paid.
        return "paid" if paid_total >= 0 else "open"
    if paid_total > 0:
        return "partial"

    # No payment — determine open vs overdue.
    if not period or not _valid_period(period):
        return "open"
    rent_due_day = int(lease.get("rent_due_day", 1) or 1)
    grace_days = int(lease.get("late_fee_grace_days", 0) or 0)
    year, month = int(period[:4]), int(period[5:7])
    rent_due_day = max(1, min(rent_due_day, 28))
    due_dt = datetime(year, month, rent_due_day, tzinfo=timezone.utc)
    due_ts = int(due_dt.timestamp()) + grace_days * 86400

    return "overdue" if as_of > due_ts else "open"


# ---------------------------------------------------------------------------
# RNT-003: paginated history + void
# ---------------------------------------------------------------------------
def list_rent_history(
    user_sub: str,
    lease_id: str,
    *,
    kind: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Paginated per-lease rent history, newest-first, charge rows annotated."""
    if not S.rent_ledger_enabled:
        return None

    from fastapi import HTTPException

    lease = _get_lease(user_sub, lease_id)
    if not lease:
        raise HTTPException(status_code=404, detail={"code": "lease_not_found"})

    all_rows = list_rent_ledger_for_lease(user_sub, lease_id)
    if kind in {"charge", "payment"}:
        all_rows = [r for r in all_rows if r.get("rent_kind") == kind]

    # Status annotation uses the full payment set (not the paged slice).
    all_payments = [r for r in all_rows if r.get("rent_kind") == "payment"]
    annotated: List[Dict[str, Any]] = []
    for r in all_rows:
        row = dict(r)
        if r.get("rent_kind") == "charge":
            row["status"] = derive_charge_status(r, payments=all_payments, lease=lease)
        annotated.append(row)

    capped = max(1, min(int(limit), 200))
    decoded = decode_cursor(cursor) or {}
    offset = int(decoded.get("offset", 0)) if isinstance(decoded, dict) else 0
    if offset < 0:
        offset = 0

    page = annotated[offset:offset + capped]
    next_offset = offset + capped
    next_cursor = encode_cursor({"offset": next_offset}) if next_offset < len(annotated) else None

    return {"rows": page, "count": len(annotated), "next_cursor": next_cursor}


def void_rent_row(
    user_sub: str,
    lease_id: str,
    ledger_sk: str,
    *,
    reason: str = "",
) -> Optional[Dict[str, Any]]:
    """Void (reverse, never delete) a rent ledger row + invert its balance counter."""
    if not S.rent_ledger_enabled:
        return None

    from fastapi import HTTPException

    lease = _get_lease(user_sub, lease_id)
    if not lease:
        raise HTTPException(status_code=404, detail={"code": "lease_not_found"})

    pk = user_pk(user_sub)
    row = ddb_get(T.billing, pk, ledger_sk)
    if not row:
        raise HTTPException(status_code=404, detail={"code": "rent_row_not_found"})
    if row.get("lease_id") != lease_id:
        raise HTTPException(status_code=404, detail={"code": "rent_row_not_found"})
    rent_kind = row.get("rent_kind")
    if rent_kind not in {"charge", "payment"}:
        raise HTTPException(status_code=404, detail={"code": "not_a_rent_row"})
    if row.get("state") == "reversed":
        raise HTTPException(
            status_code=409,
            detail={"code": "already_voided", "ledger_sk": ledger_sk},
        )

    amount_cents = int(row.get("amount_cents", 0))
    currency = row.get("currency", "usd")

    # 1. Flip state (the only mutation on the ledger row itself).
    settle_or_reverse_ledger(T.billing, "pk", pk, ledger_sk, "reversed")

    # 2. Invert the matching balance counter.
    counter = "owed_settled_cents" if rent_kind == "charge" else "payments_settled_cents"
    apply_balance_delta(T.billing, pk, {counter: -amount_cents}, currency=currency)

    # 3. Release the idempotency marker (charge voids only) so a corrected
    #    charge can be re-posted for that period. The ONLY delete in the cluster.
    if rent_kind == "charge":
        period = row.get("period")
        if period:
            ddb_del(T.rent_period_markers, _marker_pk(user_sub), _marker_sk(lease_id, period))

    audit_event(
        "rent.row_voided",
        user_sub,
        lease_id=lease_id,
        ledger_sk=ledger_sk,
        rent_kind=rent_kind,
        amount_cents=amount_cents,
        period=row.get("period"),
        reason=reason,
    )
    return {"ok": True, "ledger_sk": ledger_sk, "state": "reversed"}


# ---------------------------------------------------------------------------
# RNT-004: period summary + period navigation
# ---------------------------------------------------------------------------
def list_periods(
    user_sub: str,
    *,
    lease_id: Optional[str] = None,
    count: int = 12,
) -> List[str]:
    """Trailing ``count`` ``YYYY-MM`` strings ending at current month, ascending."""
    if not S.rent_ledger_enabled:
        return []
    count = max(1, min(int(count), 60))
    now_utc = datetime.now(timezone.utc)
    periods: List[str] = []
    for i in range(count - 1, -1, -1):
        y = now_utc.year
        m = now_utc.month - i
        while m <= 0:
            m += 12
            y -= 1
        periods.append(f"{y:04d}-{m:02d}")
    return periods


def _fallback_overdue(
    user_sub: str,
    charges: List[Dict[str, Any]],
    period: str,
) -> Tuple[int, None]:
    """Local overdue total via derive_charge_status (OFB-015 absent/off)."""
    try:
        overdue_total = 0
        for charge_row in charges:
            lid = charge_row.get("lease_id")
            lease = _get_lease(user_sub, lid)
            if not lease:
                continue
            payments_for_lease = list_rent_ledger_for_lease(user_sub, lid)
            status = derive_charge_status(charge_row, payments=payments_for_lease, lease=lease)
            if status == "overdue":
                overdue_total += int(charge_row.get("amount_cents", 0))
        return overdue_total, None
    except Exception:
        logger.warning("period_summary: fallback overdue failed", exc_info=True)
        return 0, None


def period_summary(
    user_sub: str,
    *,
    period: Optional[str] = None,
    lease_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Aggregate charged/collected/outstanding/overdue for a period."""
    if not S.rent_ledger_enabled:
        return None

    from fastapi import HTTPException

    period = period or _current_period()
    if not _valid_period(period):
        raise HTTPException(status_code=422, detail={"code": "invalid_period"})

    if lease_id:
        lease = _get_lease(user_sub, lease_id)
        if not lease:
            raise HTTPException(status_code=404, detail={"code": "lease_not_found"})

    all_items = ddb_query_pk(T.billing, user_pk(user_sub))
    ledger_rows = [
        it for it in all_items
        if str(it.get("sk", "")).startswith("LEDGER#")
        and it.get("rent_kind") in ("charge", "payment")
        and it.get("period") == period
    ]
    if lease_id:
        ledger_rows = [r for r in ledger_rows if r.get("lease_id") == lease_id]

    charges = [r for r in ledger_rows if r.get("rent_kind") == "charge" and r.get("state") != "reversed"]
    payments = [r for r in ledger_rows if r.get("rent_kind") == "payment" and r.get("state") != "reversed"]

    charged_cents = sum(int(r.get("amount_cents", 0)) for r in charges)
    collected_cents = sum(int(r.get("amount_cents", 0)) for r in payments)
    outstanding_cents = charged_cents - collected_cents

    bal = ddb_get(T.billing, user_pk(user_sub), "BALANCE") or {}
    due_totals = compute_due(bal)

    # Overdue + aging (OFB-015 soft dep).
    aging: Optional[Dict[str, Any]] = None
    overdue_cents = 0
    if getattr(S, "ar_ap_subledgers_enabled", False):
        try:
            from app.services.ar_subledger import compute_ar_aging  # type: ignore
            aging_raw = compute_ar_aging(user_sub=user_sub, as_of_ts=now_ts())
            overdue_cents = int(aging_raw.get("total_open_cents", 0))
            aging = {
                "current_cents": int(aging_raw.get("current_cents", 0)),
                "days_30_cents": int(aging_raw.get("days_30_cents", 0)),
                "days_60_cents": int(aging_raw.get("days_60_cents", 0)),
                "days_90_plus_cents": int(aging_raw.get("days_90_plus_cents", 0)),
                "total_open_cents": int(aging_raw.get("total_open_cents", 0)),
                "open_item_count": int(aging_raw.get("open_item_count", 0)),
                "source": "ar_subledger",
            }
        except Exception:
            logger.warning("period_summary: ar_subledger unavailable, falling back", exc_info=True)
            overdue_cents, aging = _fallback_overdue(user_sub, charges, period)
    else:
        overdue_cents, aging = _fallback_overdue(user_sub, charges, period)

    # Lease count (best-effort).
    if lease_id:
        lease_count = 1
    else:
        try:
            lease_count = len(_list_active_leases_for_owner(user_sub))
            if lease_count == 0:
                lease_count = len({r.get("lease_id") for r in charges})
        except Exception:
            lease_count = len({r.get("lease_id") for r in charges})

    return {
        "period": period,
        "scope": lease_id or "all",
        "charged_cents": charged_cents,
        "collected_cents": collected_cents,
        "outstanding_cents": outstanding_cents,
        "overdue_cents": overdue_cents,
        "due_settled_cents_all_time": due_totals["due_settled_cents"],
        "charge_count": len(charges),
        "payment_count": len(payments),
        "lease_count": lease_count,
        "aging": aging,
    }


# ---------------------------------------------------------------------------
# RNT-005: manual charge-now + per-owner run
# ---------------------------------------------------------------------------
def charge_lease_now(
    user_sub: str,
    lease_id: str,
    *,
    period: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """On-demand single-lease charge. Delegates entirely to post_rent_charge."""
    if not S.rent_ledger_enabled:
        return None

    from fastapi import HTTPException

    lease = _get_lease(user_sub, lease_id)
    if not lease:
        raise HTTPException(status_code=404, detail={"code": "lease_not_found"})
    if lease.get("status") != "active":
        raise HTTPException(
            status_code=409,
            detail={"code": "lease_not_active", "message": "Lease must be active to charge rent"},
        )
    return post_rent_charge(user_sub, lease, period=period)


def run_rent_charges_for_owner(
    user_sub: str,
    *,
    period: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Owner-scoped sweep: charge all of the caller's active leases."""
    if not S.rent_ledger_enabled:
        return None
    period = period or _current_period()
    leases = _list_active_leases_for_owner(user_sub)
    charged = 0
    skipped = 0
    for lease in leases:
        try:
            r = post_rent_charge(user_sub, lease, period=period)
            if r and not r.get("skipped"):
                charged += 1
            else:
                skipped += 1
        except Exception:
            logger.exception(
                "rent_run_owner_charge_failed user_sub=%s lease_id=%s period=%s",
                user_sub, lease.get("lease_id"), period,
            )
    audit_event(
        "rent.owner_run",
        user_sub,
        period=period,
        charged=charged,
        skipped=skipped,
        lease_count=len(leases),
    )
    return {"period": period, "charged": charged, "skipped": skipped, "lease_count": len(leases)}
