"""Lease router — LSE-002 / LSE-003.

Endpoints:
  POST   /ui/leases                       — create lease
  GET    /ui/leases/expiring              — leases expiring within N days (LSE-003)
  GET    /ui/leases                       — list (status filter, cursor pagination)
  GET    /ui/leases/{lease_id}            — get single lease
  PATCH  /ui/leases/{lease_id}            — inline-edit mutable fields
  POST   /ui/leases/{lease_id}/status     — status transition
  GET    /ui/admin/leases                 — cross-owner admin list

Tenant-history endpoint (LSE-003):
  GET    /ui/tenants/{tenant_id}/leases   — per-tenant lease history

IMPORTANT — declaration order:
  1. /expiring must precede /{lease_id} so "expiring" is not captured as lease_id.
  2. The admin endpoint is on a separate APIRouter to avoid being captured by /{lease_id}.
  3. /tenants/{tenant_id}/leases is registered in create_app() via a separate APIRouter.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.models import (
    LeaseCreateIn,
    LeaseListOut,
    LeaseOut,
    LeasePatchIn,
    LeaseStatusTransitionIn,
)
from app.services import leases as leases_svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/leases", tags=["leases"])
admin_router = APIRouter(prefix="/ui/admin", tags=["leases-admin"])
tenant_leases_router = APIRouter(prefix="/ui/tenants", tags=["leases"])


def _flag_guard() -> None:
    if not S.leases_enabled:
        raise HTTPException(404, detail="leases not enabled")


def _lease_to_out(item: Optional[Dict[str, Any]]) -> LeaseOut:
    if item is None:
        raise HTTPException(404, detail="lease not found")
    return LeaseOut(**item)


def _list_to_out(result: Optional[Dict[str, Any]]) -> LeaseListOut:
    if result is None:
        raise HTTPException(404, detail="leases not enabled")
    return LeaseListOut(
        leases=[LeaseOut(**i) for i in result["leases"]],
        count=result["count"],
        next_cursor=result.get("next_cursor"),
    )


# ---------------------------------------------------------------------------
# POST /ui/leases — create
# ---------------------------------------------------------------------------

@router.post("", response_model=LeaseOut, status_code=201)
def create_lease(
    body: LeaseCreateIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> LeaseOut:
    _flag_guard()
    item = leases_svc.create_lease(
        user_sub=ctx["user_sub"],
        tenant_id=body.tenant_id,
        property_id=body.property_id,
        unit_id=body.unit_id,
        start_date=body.start_date,
        end_date=body.end_date,
        monthly_rent_cents=body.monthly_rent_cents,
        security_deposit_cents=body.security_deposit_cents,
        rent_due_day=body.rent_due_day,
        late_fee_type=body.late_fee_type,
        late_fee_cents=body.late_fee_cents,
        late_fee_percent_bps=body.late_fee_percent_bps,
        late_fee_grace_days=body.late_fee_grace_days,
        currency=body.currency,
        notes=body.notes,
        renewal_notice_days=body.renewal_notice_days,
        force_draft=getattr(body, "force_draft", False),
    )
    return _lease_to_out(item)


# ---------------------------------------------------------------------------
# GET /ui/leases/expiring (LSE-003) — MUST precede /{lease_id}
# ---------------------------------------------------------------------------

@router.get("/expiring", response_model=LeaseListOut)
def list_expiring_leases(
    within_days: int = Query(default=60, ge=1, le=365),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> LeaseListOut:
    _flag_guard()
    items = leases_svc.list_upcoming_expirations(
        ctx["user_sub"], within_days=within_days, limit=limit
    )
    if items is None:
        items = []
    return LeaseListOut(leases=[LeaseOut(**i) for i in items], count=len(items), next_cursor=None)


# ---------------------------------------------------------------------------
# GET /ui/leases — list with optional status filter
# ---------------------------------------------------------------------------

@router.get("", response_model=LeaseListOut)
def list_leases(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> LeaseListOut:
    _flag_guard()
    result = leases_svc.list_leases(
        ctx["user_sub"], status=status, limit=limit, cursor=cursor
    )
    return _list_to_out(result)


# ---------------------------------------------------------------------------
# GET /ui/leases/{lease_id} — single
# ---------------------------------------------------------------------------

@router.get("/{lease_id}", response_model=LeaseOut)
def get_lease(
    lease_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> LeaseOut:
    _flag_guard()
    item = leases_svc.get_lease(ctx["user_sub"], lease_id)
    return _lease_to_out(item)


# ---------------------------------------------------------------------------
# PATCH /ui/leases/{lease_id} — inline edit
# ---------------------------------------------------------------------------

@router.patch("/{lease_id}", response_model=LeaseOut)
def patch_lease(
    lease_id: str,
    body: LeasePatchIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> LeaseOut:
    _flag_guard()
    # Use model_dump(exclude_unset=True) to distinguish "not provided" from explicit None
    patch_data = body.model_dump(exclude_unset=True)

    item = leases_svc.update_lease(
        ctx["user_sub"],
        lease_id,
        end_date=patch_data.get("end_date"),
        _end_date_set="end_date" in patch_data,
        monthly_rent_cents=patch_data.get("monthly_rent_cents"),
        security_deposit_cents=patch_data.get("security_deposit_cents"),
        rent_due_day=patch_data.get("rent_due_day"),
        late_fee_type=patch_data.get("late_fee_type"),
        late_fee_cents=patch_data.get("late_fee_cents"),
        late_fee_percent_bps=patch_data.get("late_fee_percent_bps"),
        late_fee_grace_days=patch_data.get("late_fee_grace_days"),
        currency=patch_data.get("currency"),
        notes=patch_data.get("notes"),
        renewal_notice_days=patch_data.get("renewal_notice_days"),
    )
    if item is None:
        raise HTTPException(404, detail="lease not found")
    return LeaseOut(**item)


# ---------------------------------------------------------------------------
# POST /ui/leases/{lease_id}/status — transition
# ---------------------------------------------------------------------------

@router.post("/{lease_id}/status", response_model=LeaseOut)
def transition_status(
    lease_id: str,
    body: LeaseStatusTransitionIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> LeaseOut:
    _flag_guard()
    item = leases_svc.transition_status(ctx["user_sub"], lease_id, body.status)
    return _lease_to_out(item)


# ---------------------------------------------------------------------------
# GET /ui/admin/leases — cross-owner admin list
# ---------------------------------------------------------------------------

@admin_router.get("/leases", response_model=LeaseListOut)
def admin_list_leases(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    _actor: Any = Depends(require_admin_or_root),
) -> LeaseListOut:
    _flag_guard()
    result = leases_svc.admin_list_leases(limit=limit, cursor=cursor)
    return _list_to_out(result)


# ---------------------------------------------------------------------------
# GET /ui/tenants/{tenant_id}/leases — per-tenant history (LSE-003)
# ---------------------------------------------------------------------------

@tenant_leases_router.get("/{tenant_id}/leases", response_model=LeaseListOut)
def list_tenant_leases(
    tenant_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> LeaseListOut:
    _flag_guard()
    result = leases_svc.list_leases_for_tenant(
        ctx["user_sub"], tenant_id, limit=limit, cursor=cursor
    )
    return _list_to_out(result)
