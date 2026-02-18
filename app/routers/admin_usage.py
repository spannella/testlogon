from __future__ import annotations

from typing import Optional, Literal

from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel, Field

from app.core.settings import S
from app.services.filemanager import (
    finalize_billing_period_admin,
    recompute_usage_aggregates_admin,
    get_admin_user_usage_detail,
    generate_invoice_line_items_for_snapshot_admin,
    create_billing_adjustment_admin,
)
from app.services.sessions import require_ui_session
from app.services.alerts import audit_event

router = APIRouter(prefix="/v1/admin", tags=["admin-usage"])


def _current_user(ctx=Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


def _require_admin_user(user_sub: str = Depends(_current_user)) -> str:
    raw = str(getattr(S, "filemgr_admin_users", "") or "")
    allow = {u.strip() for u in raw.split(",") if u.strip()}
    if allow and user_sub not in allow:
        raise HTTPException(status_code=403, detail="admin privileges required")
    if not allow:
        raise HTTPException(status_code=403, detail="admin privileges not configured")
    return user_sub


class FinalizePeriodIn(BaseModel):
    period_id: str = Field(..., description="Billing period in YYYY-MM")
    user_id: Optional[str] = Field(default=None, description="Optional single user finalization target")




class GenerateInvoiceLinesIn(BaseModel):
    user_id: str
    period_id: str
    snapshot_version: int = Field(..., ge=1)
    pricing_catalog_version: Optional[str] = None


class CreateBillingAdjustmentIn(BaseModel):
    user_id: str
    period_id: str
    snapshot_version: int = Field(..., ge=1)
    adjustment_type: Literal["credit", "debit"]
    amount_cents: int = Field(..., gt=0)
    reason: str
    reference_id: Optional[str] = None

class RecomputeUsageIn(BaseModel):
    scope: Literal["user", "all"] = Field(default="all")
    period_id: Optional[str] = Field(default=None, description="Optional period in YYYY-MM")
    user_id: Optional[str] = Field(default=None, description="Required when scope=user")
    apply: bool = Field(default=True, description="Write recomputed values when true")


@router.post("/billing/finalize-period")
def finalize_billing_period(inp: FinalizePeriodIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    out = finalize_billing_period_admin(period_id=inp.period_id, user_id=inp.user_id)
    audit_event(
        "usage_period_finalize",
        admin_user,
        req,
        outcome="success",
        period_id=inp.period_id,
        target_user=inp.user_id,
        finalized_count=out.get("finalized_count", 0),
        snapshot_versions=[s.get("version") for s in out.get("snapshots", [])],
    )
    return out


@router.post("/usage/recompute")
def recompute_usage(inp: RecomputeUsageIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    out = recompute_usage_aggregates_admin(
        scope=inp.scope,
        period_id=inp.period_id,
        user_id=inp.user_id,
        apply=inp.apply,
    )
    audit_event(
        "usage_recompute_run",
        admin_user,
        req,
        outcome="success",
        scope=inp.scope,
        period_id=inp.period_id,
        target_user=inp.user_id,
        applied=inp.apply,
        events_scanned=out.get("events_scanned", 0),
        mismatches=out.get("mismatches", 0),
    )
    return out


@router.get("/usage/user/{user_id}")
def admin_user_usage_detail(user_id: str, period_id: Optional[str] = None, top_n: int = 10, include_paths: bool = False, admin_user: str = Depends(_require_admin_user)):
    return get_admin_user_usage_detail(user_id, period_id=period_id, top_n=top_n, include_resource_paths=include_paths)


@router.post("/billing/generate-invoice-lines")
def generate_invoice_lines(inp: GenerateInvoiceLinesIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    out = generate_invoice_line_items_for_snapshot_admin(
        user_id=inp.user_id,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        pricing_catalog_version=inp.pricing_catalog_version,
    )
    audit_event(
        "usage_snapshot_invoice_lines_generated",
        admin_user,
        req,
        outcome="success",
        target_user=inp.user_id,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        pricing_catalog_version=out.get("pricing_catalog_version"),
        total_amount_cents=out.get("total_amount_cents", 0),
    )
    return out


@router.post("/billing/adjustments")
def create_billing_adjustment(inp: CreateBillingAdjustmentIn, req: Request, admin_user: str = Depends(_require_admin_user)):
    out = create_billing_adjustment_admin(
        user_id=inp.user_id,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        adjustment_type=inp.adjustment_type,
        amount_cents=inp.amount_cents,
        reason=inp.reason,
        reference_id=inp.reference_id,
    )
    audit_event(
        "usage_billing_adjustment_created",
        admin_user,
        req,
        outcome="success",
        target_user=inp.user_id,
        period_id=inp.period_id,
        snapshot_version=inp.snapshot_version,
        adjustment_type=inp.adjustment_type,
        amount_cents=out.get("amount_cents", 0),
        adjustment_id=out.get("adjustment_id"),
    )
    return out
