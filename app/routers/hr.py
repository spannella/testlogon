"""HR + Payroll REST router (HRM-009).

Prefix: /ui/hr
Auth:   require_admin_or_root (GET) / require_admin_or_root_csrf (non-GET)

Feature-flag guards:
  _require_hr()      — checks S.hr_enabled; returns 404 when off.
  _require_payroll() — calls _require_hr() then checks S.hr_payroll_enabled.

Route declaration order follows FastAPI's first-match rule: static paths
before dynamic captures (e.g. /payroll declared before /payroll/{id}).
"""
from __future__ import annotations

from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.core.settings import S
from app.models import (
    CreateEmploymentIn,
    CreatePayrollRunIn,
    CreatePositionIn,
    EmploymentOut,
    PayrollLineOut,
    PayrollRunOut,
    PositionOut,
    TerminateEmploymentIn,
    UpdatePositionStatusIn,
)
import app.services.hr as hr_svc
import app.services.hr_payroll as payroll_svc
from app.services.hr import PositionInvalidTransitionError

router = APIRouter(prefix="/ui/hr", tags=["hr"])


# ──────────────────────────── feature-flag guards ─────────────────────────


def _require_hr() -> None:
    if not S.hr_enabled:
        raise HTTPException(status_code=404, detail={"code": "hr_disabled"})


def _require_payroll() -> None:
    _require_hr()
    if not S.hr_payroll_enabled:
        raise HTTPException(status_code=404, detail={"code": "hr_payroll_disabled"})


# ──────────────────────────── position endpoints ──────────────────────────


@router.post("/positions", status_code=201)
async def create_position(
    body: CreatePositionIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PositionOut:
    _require_hr()
    item = hr_svc.create_position(
        body.title,
        body.department,
        actor_sub=user.sub,
        correlation_id=body.correlation_id,
    )
    return PositionOut(**item)


@router.get("/positions")
async def list_positions(
    status: Optional[str] = Query(default=None),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict:
    _require_hr()
    page = hr_svc.list_positions(status, cursor=cursor, limit=limit)
    return {
        "items": [PositionOut(**it) for it in page["items"]],
        "next_cursor": page.get("next_cursor"),
    }


@router.patch("/positions/{position_id}/status")
async def update_position_status(
    position_id: str,
    body: UpdatePositionStatusIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PositionOut:
    _require_hr()
    try:
        item = hr_svc.update_position_status(
            position_id,
            body.status,
            actor_sub=user.sub,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail={"code": "position_not_found"})
    except PositionInvalidTransitionError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "position_invalid_transition", "message": str(exc)},
        )
    return PositionOut(**item)


@router.get("/positions/{position_id}")
async def get_position(
    position_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> PositionOut:
    _require_hr()
    item = hr_svc.get_position(position_id)
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "position_not_found"})
    return PositionOut(**item)


# ──────────────────────────── employment endpoints ────────────────────────


@router.post("/employments", status_code=201)
async def create_employment(
    body: CreateEmploymentIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> EmploymentOut:
    _require_hr()
    try:
        item = hr_svc.create_employment(
            body.party_id,
            body.position_id,
            body.org_party_id,
            body.pay_rate_cents,
            body.pay_period,
            body.start_date,
            end_date=body.end_date,
            currency=body.currency,
            actor_sub=user.sub,
            correlation_id=body.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": str(exc)})
    return EmploymentOut(**item)


@router.get("/employments")
async def list_employments(
    party_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict:
    _require_hr()
    page = hr_svc.list_employments(
        party_id=party_id,
        status=status,
        cursor=cursor,
        limit=limit,
    )
    return {
        "items": [EmploymentOut(**it) for it in page["items"]],
        "next_cursor": page.get("next_cursor"),
    }


# Sub-path BEFORE bare /{employment_id} to avoid FastAPI route capture
@router.post("/employments/{employment_id}/terminate")
async def terminate_employment(
    employment_id: str,
    body: TerminateEmploymentIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> EmploymentOut:
    _require_hr()
    try:
        item = hr_svc.terminate_employment(
            employment_id,
            body.end_date,
            actor_sub=user.sub,
            reason=body.note,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail={"code": "employment_not_found"})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": str(exc)})
    return EmploymentOut(**item)


@router.get("/employments/{employment_id}")
async def get_employment(
    employment_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> EmploymentOut:
    _require_hr()
    item = hr_svc.get_employment(employment_id)
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "employment_not_found"})
    return EmploymentOut(**item)


# ──────────────────────────── payroll endpoints ───────────────────────────
# Static paths BEFORE dynamic captures per FastAPI first-match routing.


@router.post("/payroll", status_code=201)
async def create_payroll_run(
    body: CreatePayrollRunIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PayrollRunOut:
    _require_payroll()
    try:
        item = payroll_svc.create_payroll_run(
            body.period_start,
            body.period_end,
            actor_sub=user.sub,
            currency=body.currency,
            correlation_id=body.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": str(exc)})
    return PayrollRunOut(**_strip_payroll_meta(item))


@router.get("/payroll")
async def list_payroll_runs(
    status: Optional[str] = Query(default=None),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict:
    _require_payroll()
    page = payroll_svc.list_payroll_runs(status, cursor=cursor, limit=limit)
    return {
        "items": [PayrollRunOut(**_strip_payroll_meta(it)) for it in page["items"]],
        "next_cursor": page.get("next_cursor"),
    }


@router.get("/payroll/{payroll_run_id}/lines")
async def get_payroll_run_lines(
    payroll_run_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict:
    _require_payroll()
    raw_lines = payroll_svc.get_payroll_run_lines(payroll_run_id)
    lines = [
        PayrollLineOut(
            employment_id=ln["employment_id"],
            party_id=ln.get("party_id", ""),
            gross_cents=int(ln.get("gross_cents", 0)),
            currency=ln.get("currency", "USD"),
        )
        for ln in raw_lines
    ]
    return {"lines": lines}


@router.post("/payroll/{payroll_run_id}/approve")
async def approve_payroll_run(
    payroll_run_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PayrollRunOut:
    _require_payroll()
    try:
        item = payroll_svc.approve_payroll_run(payroll_run_id, actor_sub=user.sub)
    except LookupError:
        raise HTTPException(status_code=404, detail={"code": "payroll_run_not_found"})
    except payroll_svc.PayrollRunInvalidTransitionError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "payroll_run_invalid_transition", "message": str(exc)},
        )
    return PayrollRunOut(**_strip_payroll_meta(item))


@router.post("/payroll/{payroll_run_id}/post")
async def post_payroll_run(
    payroll_run_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PayrollRunOut:
    _require_payroll()
    try:
        item = payroll_svc.post_payroll_run(payroll_run_id, actor_sub=user.sub)
    except LookupError:
        raise HTTPException(status_code=404, detail={"code": "payroll_run_not_found"})
    except payroll_svc.PayrollRunInvalidTransitionError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "payroll_run_invalid_transition", "message": str(exc)},
        )
    return PayrollRunOut(**_strip_payroll_meta(item))


@router.get("/payroll/{payroll_run_id}")
async def get_payroll_run(
    payroll_run_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> PayrollRunOut:
    _require_payroll()
    item = payroll_svc.get_payroll_run(payroll_run_id)
    if item is None:
        raise HTTPException(status_code=404, detail={"code": "payroll_run_not_found"})
    return PayrollRunOut(**_strip_payroll_meta(item))


# ──────────────────────────── serialisation helpers ───────────────────────


def _strip_payroll_meta(item: Dict) -> Dict:
    """Extract PayrollRunOut fields from a raw DDB item.

    DDB items carry internal GSI keys (GSI1PK, GSI1SK, PK, SK, entity_type,
    actor_sub, approved_at, posted_by) that Pydantic doesn't expect on
    PayrollRunOut. We project only the fields the model knows about.
    """
    return {
        "payroll_run_id": item.get("payroll_run_id", ""),
        "period_start": int(item.get("period_start", 0)),
        "period_end": int(item.get("period_end", 0)),
        "status": item.get("status", "DRAFT"),
        "lines": [],  # lines fetched separately via /lines endpoint
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "approved_by": item.get("approved_by"),
        "posted_at": int(item["posted_at"]) if item.get("posted_at") is not None else None,
    }
