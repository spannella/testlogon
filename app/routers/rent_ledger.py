"""Rent-ledger HTTP surface (open-property vertical, RNT-002..RNT-005).

All landlord endpoints are gated on ``RENT_LEDGER_ENABLED`` (→ 404 when off) and
authenticated via ``require_ui_session`` (cookie + CSRF for non-GET). The
system-wide admin sweep is ROOT-only via ``require_root_session``.

No payment provider is ever contacted — rent is recorded, not processed.
"""
from __future__ import annotations

from typing import Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser, require_root_session
from app.core.settings import S
from app.models import (
    RentChargeListOut,
    RentChargeOut,
    RentChargeSkipOut,
    RentHistoryOut,
    RentPaymentIn,
    RentPaymentOut,
    RentPeriodSummaryOut,
    RentPeriodsOut,
    RentRunResultOut,
    RentRunTriggerIn,
    RentVoidIn,
    RentVoidOut,
)
from app.services.rent_ledger import (
    _current_period,
    charge_lease_now,
    derive_charge_status,
    list_periods,
    list_rent_history,
    list_rent_ledger_for_lease,
    period_summary,
    record_payment,
    run_rent_charges,
    run_rent_charges_for_owner,
    void_rent_row,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/rent", tags=["rent-ledger"])
admin_rent_router = APIRouter(prefix="/ui/admin/rent", tags=["rent-ledger-admin"])


def _require_enabled() -> None:
    if not S.rent_ledger_enabled:
        raise HTTPException(status_code=404, detail="rent_ledger_not_enabled")


def _get_lease_or_404(user_sub: str, lease_id: str):
    from app.services.rent_ledger import _get_lease

    lease = _get_lease(user_sub, lease_id)
    if not lease:
        raise HTTPException(status_code=404, detail={"code": "lease_not_found"})
    return lease


# ---------------------------------------------------------------------------
# RNT-002: record payment + charges list
# ---------------------------------------------------------------------------
@router.post("/leases/{lease_id}/payments", status_code=201, response_model=RentPaymentOut)
async def post_rent_payment(
    lease_id: str,
    body: RentPaymentIn,
    ctx=Depends(require_ui_session),
) -> RentPaymentOut:
    _require_enabled()
    user_sub = ctx["user_sub"]
    item = record_payment(
        user_sub,
        lease_id=lease_id,
        amount_cents=body.amount_cents,
        method=body.method,
        paid_on=body.paid_on,
        reference=body.reference or "",
        period=body.period,
        notes=body.notes or "",
    )
    period = body.period or _current_period()
    rows = list_rent_ledger_for_lease(user_sub, lease_id)
    lease = _get_lease_or_404(user_sub, lease_id)
    charge_row = next(
        (r for r in rows if r.get("rent_kind") == "charge" and r.get("period") == period),
        None,
    )
    status = (
        derive_charge_status(charge_row, payments=rows, lease=lease)
        if charge_row else None
    )
    return RentPaymentOut(
        ledger_sk=item["sk"],
        period=period,
        amount_cents=int(item["amount_cents"]),
        method=item.get("method", ""),
        reference=item.get("reference", ""),
        paid_on=item.get("paid_on"),
        charge_status=status,
    )


@router.get("/leases/{lease_id}/charges", response_model=RentChargeListOut)
async def get_rent_charges(
    lease_id: str,
    as_of_ts: Optional[int] = Query(default=None),
    ctx=Depends(require_ui_session),
) -> RentChargeListOut:
    _require_enabled()
    user_sub = ctx["user_sub"]
    lease = _get_lease_or_404(user_sub, lease_id)
    rows = list_rent_ledger_for_lease(user_sub, lease_id)
    payments = [r for r in rows if r.get("rent_kind") == "payment"]
    from app.core.time import now_ts

    clock = as_of_ts if as_of_ts is not None else now_ts()
    charges = []
    for r in rows:
        if r.get("rent_kind") != "charge":
            continue
        row = dict(r)
        row["status"] = derive_charge_status(r, payments=payments, lease=lease, as_of_ts=clock)
        charges.append(row)
    charges.sort(key=lambda r: int(r.get("ts", 0)), reverse=True)
    return RentChargeListOut(lease_id=lease_id, charges=charges, as_of_ts=clock)


# ---------------------------------------------------------------------------
# RNT-003: history + void
# ---------------------------------------------------------------------------
@router.get("/leases/{lease_id}/ledger", response_model=RentHistoryOut)
async def get_rent_ledger(
    lease_id: str,
    kind: Optional[str] = Query(default=None, pattern="^(charge|payment)$"),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx=Depends(require_ui_session),
) -> RentHistoryOut:
    _require_enabled()
    result = list_rent_history(
        ctx["user_sub"], lease_id, kind=kind, limit=limit, cursor=cursor
    )
    if result is None:
        raise HTTPException(status_code=404, detail="rent_ledger_not_enabled")
    return RentHistoryOut(**result)


@router.post("/leases/{lease_id}/ledger/{ledger_sk:path}/void", response_model=RentVoidOut)
async def void_rent_row_endpoint(
    lease_id: str,
    ledger_sk: str,
    body: RentVoidIn,
    req: Request,
    ctx=Depends(require_ui_session),
) -> RentVoidOut:
    _require_enabled()
    result = void_rent_row(ctx["user_sub"], lease_id, ledger_sk, reason=body.reason)
    return RentVoidOut(**result)


# ---------------------------------------------------------------------------
# RNT-004: summary + periods
# ---------------------------------------------------------------------------
@router.get("/summary", response_model=RentPeriodSummaryOut)
async def get_rent_summary(
    period: Optional[str] = Query(None, pattern=r"^\d{4}-(0[1-9]|1[0-2])$"),
    lease_id: Optional[str] = Query(None),
    ctx=Depends(require_ui_session),
) -> RentPeriodSummaryOut:
    _require_enabled()
    result = period_summary(ctx["user_sub"], period=period, lease_id=lease_id)
    if result is None:
        raise HTTPException(status_code=404, detail="rent_ledger_not_enabled")
    return RentPeriodSummaryOut(**result)


@router.get("/periods", response_model=RentPeriodsOut)
async def get_rent_periods(
    lease_id: Optional[str] = Query(None),
    count: int = Query(default=12, ge=1, le=60),
    ctx=Depends(require_ui_session),
) -> RentPeriodsOut:
    _require_enabled()
    periods = list_periods(ctx["user_sub"], lease_id=lease_id, count=count)
    return RentPeriodsOut(periods=periods, count=len(periods))


# ---------------------------------------------------------------------------
# RNT-005: manual charge-now + owner run + admin run
# ---------------------------------------------------------------------------
@router.post(
    "/leases/{lease_id}/charge",
    response_model=Union[RentChargeOut, RentChargeSkipOut],
)
async def charge_lease_now_endpoint(
    lease_id: str,
    body: RentRunTriggerIn,
    ctx=Depends(require_ui_session),
):
    _require_enabled()
    if body.period and not _is_period(body.period):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_period_format", "message": "period must be YYYY-MM"},
        )
    return charge_lease_now(ctx["user_sub"], lease_id, period=body.period)


@router.post("/run", response_model=RentRunResultOut)
async def run_rent_for_owner_endpoint(
    body: RentRunTriggerIn,
    ctx=Depends(require_ui_session),
) -> RentRunResultOut:
    _require_enabled()
    if body.period and not _is_period(body.period):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_period_format", "message": "period must be YYYY-MM"},
        )
    result = run_rent_charges_for_owner(ctx["user_sub"], period=body.period)
    return RentRunResultOut(**result)


@admin_rent_router.post("/run", response_model=RentRunResultOut)
async def admin_run_rent_endpoint(
    body: RentRunTriggerIn,
    user: AuthenticatedUser = Depends(require_root_session),
) -> RentRunResultOut:
    _require_enabled()
    if body.period and not _is_period(body.period):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_period_format", "message": "period must be YYYY-MM"},
        )
    result = run_rent_charges(period=body.period)
    return RentRunResultOut(**result)


def _is_period(value: str) -> bool:
    import re

    return bool(re.match(r"^\d{4}-\d{2}$", value or ""))
