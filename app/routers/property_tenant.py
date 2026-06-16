"""
Property Tenant router — TEN-003.
Prefix: /ui/property/tenants
Tags: property-tenants

Route-order rule (FastAPI first-match-wins):
  All literal sub-resource paths (/profile, /income-docs, /active-unit,
  /income-verification, /leases) are declared BEFORE /{tenant_id} bare routes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile

from app.auth.roles import Role
from app.core.settings import S
from app.models import (
    ActiveUnitIn,
    CreateTenantIn,
    IncomeDocListOut,
    IncomeDocOut,
    PropertyTenantOut,
    SetIncomeVerificationIn,
    TenantLeaseListOut,
    TenantLeaseSummaryOut,
    TenantListOut,
    TenantProfileIn,
    UpdateTenantIn,
)
from app.services.sessions import require_ui_session
import app.services.property_tenant as tenant_svc

router = APIRouter(
    prefix="/ui/property/tenants",
    tags=["property-tenants"],
)

_VALID_DOC_KINDS = {"pay_stub", "tax_return", "bank_statement", "offer_letter", "other"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _flag_guard() -> None:
    if not S.property_tenants_enabled:
        raise HTTPException(404, "Property tenants are not enabled")


def _item_to_tenant_out(item: dict) -> PropertyTenantOut:
    from decimal import Decimal

    def _cv(v: Any) -> Any:
        if isinstance(v, Decimal):
            return int(v) if v == int(v) else float(v)
        return v

    return PropertyTenantOut(
        tenant_id=item["tenant_id"],
        owner_id=item["owner_id"],
        party_id=item.get("party_id", ""),
        display_name=item.get("display_name", ""),
        email=item.get("email"),
        phone=item.get("phone"),
        status=item.get("status", "prospect"),
        active_unit_id=item.get("active_unit_id"),
        created_at=_cv(item.get("created_at", 0)),
        updated_at=_cv(item.get("updated_at", 0)),
    )


def _item_to_lease_summary(item: dict) -> TenantLeaseSummaryOut:
    from decimal import Decimal

    def _cv(v: Any) -> Any:
        if isinstance(v, Decimal):
            return int(v)
        return v

    return TenantLeaseSummaryOut(
        lease_id=item["lease_id"],
        unit_id=item.get("unit_id", ""),
        status=item.get("status", "draft"),
        start_date=_cv(item.get("start_date", 0)),
        end_date=_cv(item.get("end_date")) if item.get("end_date") is not None else None,
        monthly_rent_cents=_cv(item.get("monthly_rent_cents", 0)),
        security_deposit_cents=_cv(item.get("security_deposit_cents", 0)),
        currency=item.get("currency", "usd"),
        lease_number=item.get("lease_number"),
    )


def _own_or_404(item: dict, user_sub: str) -> None:
    """Raise 404 (not 403) for wrong-owner to avoid leaking existence."""
    if item.get("owner_id") != user_sub:
        raise HTTPException(404, "Tenant not found")


# ---------------------------------------------------------------------------
# Collection endpoints (must come before /{tenant_id})
# ---------------------------------------------------------------------------


@router.post("", status_code=201, response_model=PropertyTenantOut)
def create_tenant(
    body: CreateTenantIn,
    ctx: dict = Depends(require_ui_session),
) -> PropertyTenantOut:
    _flag_guard()
    item = tenant_svc.create_tenant(
        owner_id=ctx["user_sub"],
        display_name=body.display_name,
        email=body.email,
        phone=body.phone,
        party_id=body.party_id,
        correlation_id=body.correlation_id,
    )
    return _item_to_tenant_out(item)


@router.get("", response_model=TenantListOut)
def list_tenants(
    status: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=50),
    ctx: dict = Depends(require_ui_session),
) -> TenantListOut:
    _flag_guard()
    result = tenant_svc.list_tenants(
        owner_id=ctx["user_sub"],
        status=status,
        q=q,
        cursor=cursor,
        limit=limit,
    )
    return TenantListOut(
        tenants=[_item_to_tenant_out(t) for t in result["tenants"]],
        count=result["count"],
        next_cursor=result["next_cursor"],
    )


# ---------------------------------------------------------------------------
# Sub-resource endpoints under /{tenant_id} — MUST be declared before bare /{tenant_id}
# ---------------------------------------------------------------------------


@router.get("/{tenant_id}/profile")
def get_profile(
    tenant_id: str,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _flag_guard()
    item = tenant_svc.get_tenant(tenant_id)
    if item is None:
        raise HTTPException(404, "Tenant not found")
    _own_or_404(item, ctx["user_sub"])
    return tenant_svc.get_profile(tenant_id)


@router.put("/{tenant_id}/profile")
def update_profile(
    tenant_id: str,
    body: TenantProfileIn,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _flag_guard()
    item = tenant_svc.get_tenant(tenant_id)
    if item is None:
        raise HTTPException(404, "Tenant not found")
    _own_or_404(item, ctx["user_sub"])

    employment = body.employment.model_dump(exclude_none=True) if body.employment else None
    income = body.income.model_dump(exclude_none=True) if body.income else None
    ec = (
        [c.model_dump(exclude_none=True) for c in body.emergency_contacts]
        if body.emergency_contacts is not None
        else None
    )
    return tenant_svc.update_profile(
        tenant_id,
        employment=employment,
        income=income,
        emergency_contacts=ec,
    )


@router.post("/{tenant_id}/income-docs", status_code=201)
def upload_income_doc(
    tenant_id: str,
    file: UploadFile = File(...),
    doc_kind: str = Form(...),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _flag_guard()
    if doc_kind not in _VALID_DOC_KINDS:
        raise HTTPException(422, f"Invalid doc_kind: {doc_kind!r}")
    item = tenant_svc.get_tenant(tenant_id)
    if item is None:
        raise HTTPException(404, "Tenant not found")
    _own_or_404(item, ctx["user_sub"])
    return tenant_svc.add_income_doc(
        tenant_id, ctx["user_sub"], file, doc_kind=doc_kind
    )


@router.get("/{tenant_id}/income-docs", response_model=IncomeDocListOut)
def list_income_docs(
    tenant_id: str,
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    ctx: dict = Depends(require_ui_session),
) -> IncomeDocListOut:
    _flag_guard()
    item = tenant_svc.get_tenant(tenant_id)
    if item is None:
        raise HTTPException(404, "Tenant not found")
    _own_or_404(item, ctx["user_sub"])
    result = tenant_svc.list_income_docs(tenant_id, cursor=cursor, limit=limit)
    return IncomeDocListOut(
        docs=[IncomeDocOut(**d) for d in result["docs"]],
        next_cursor=result["next_cursor"],
        count=result["count"],
    )


@router.delete("/{tenant_id}/income-docs/{doc_id}", status_code=204, response_model=None)
def delete_income_doc(
    tenant_id: str,
    doc_id: str,
    ctx: dict = Depends(require_ui_session),
) -> None:
    _flag_guard()
    item = tenant_svc.get_tenant(tenant_id)
    if item is None:
        raise HTTPException(404, "Tenant not found")
    _own_or_404(item, ctx["user_sub"])
    tenant_svc.remove_income_doc(tenant_id, ctx["user_sub"], doc_id)


@router.put("/{tenant_id}/income-verification")
def set_income_verification(
    tenant_id: str,
    body: SetIncomeVerificationIn,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _flag_guard()
    # Income verification is admin/root only (TEN-002 §5.7)
    if ctx.get("role", Role.USER) < Role.ADMIN:
        raise HTTPException(403, "Admin required")
    item = tenant_svc.get_tenant(tenant_id)
    if item is None:
        raise HTTPException(404, "Tenant not found")
    _own_or_404(item, ctx["user_sub"])
    return tenant_svc.set_income_verification(tenant_id, body.status, ctx["user_sub"])


@router.put("/{tenant_id}/active-unit", response_model=PropertyTenantOut)
def set_active_unit(
    tenant_id: str,
    body: ActiveUnitIn,
    ctx: dict = Depends(require_ui_session),
) -> PropertyTenantOut:
    _flag_guard()
    item = tenant_svc.get_tenant(tenant_id)
    if item is None:
        raise HTTPException(404, "Tenant not found")
    _own_or_404(item, ctx["user_sub"])
    updated = tenant_svc.set_active_unit(
        tenant_id,
        ctx["user_sub"],
        body.property_id,
        body.unit_id,
    )
    return _item_to_tenant_out(updated)


@router.get("/{tenant_id}/leases", response_model=TenantLeaseListOut)
def get_tenant_leases(
    tenant_id: str,
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    ctx: dict = Depends(require_ui_session),
) -> TenantLeaseListOut:
    _flag_guard()
    result = tenant_svc.list_tenant_leases(
        ctx["user_sub"],
        tenant_id,
        cursor=cursor,
        limit=limit,
    )
    return TenantLeaseListOut(
        leases=[_item_to_lease_summary(l) for l in result.get("leases", [])],
        count=result.get("count", 0),
        next_cursor=result.get("next_cursor"),
    )


# ---------------------------------------------------------------------------
# Bare /{tenant_id} routes — declared AFTER all sub-resource routes
# ---------------------------------------------------------------------------


@router.get("/{tenant_id}", response_model=PropertyTenantOut)
def get_tenant(
    tenant_id: str,
    ctx: dict = Depends(require_ui_session),
) -> PropertyTenantOut:
    _flag_guard()
    item = tenant_svc.get_tenant(tenant_id)
    if item is None:
        raise HTTPException(404, "Tenant not found")
    _own_or_404(item, ctx["user_sub"])
    return _item_to_tenant_out(item)


@router.patch("/{tenant_id}", response_model=PropertyTenantOut)
def update_tenant(
    tenant_id: str,
    body: UpdateTenantIn,
    ctx: dict = Depends(require_ui_session),
) -> PropertyTenantOut:
    _flag_guard()
    item = tenant_svc.get_tenant(tenant_id)
    if item is None:
        raise HTTPException(404, "Tenant not found")
    _own_or_404(item, ctx["user_sub"])

    patch: dict = {}
    if body.display_name is not None:
        patch["display_name"] = body.display_name
    if body.email is not None:
        patch["email"] = body.email
    if body.phone is not None:
        patch["phone"] = body.phone
    if body.status is not None:
        patch["status"] = body.status

    if not patch:
        raise HTTPException(400, "Nothing to update")

    updated = tenant_svc.update_tenant(tenant_id, ctx["user_sub"], **patch)
    return _item_to_tenant_out(updated)
