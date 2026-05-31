"""Compute cost tracking API endpoints (INFRA-005).

Endpoints:
  GET  /ui/remote/billing/spending    - Current month spending summary
  GET  /ui/remote/billing/resources   - Per-resource spending breakdown
  GET  /ui/remote/billing/resources/{resource_id} - Single resource spending
  GET  /ui/remote/billing/history     - Billing tick history (paginated)
  POST /ui/remote/billing/budget      - Set monthly spending budget
  GET  /ui/remote/billing/budget      - Get budget status
  POST /ui/remote/billing/tick        - Manual billing tick (for testing)
"""
from __future__ import annotations

import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models import (
    BillingLedgerOut,
    BudgetOut,
    ComputeBillingTickIn,
    ComputeBillingTickOut,
    ResourceBreakdownOut,
    SpendingSummaryOut,
    UpdateBudgetIn,
)
from app.services.sessions import require_ui_session
from app.core.settings import S

router = APIRouter(prefix="/ui/remote/billing", tags=["compute-billing"])

_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


# ---------------------------------------------------------------------------
# Spending summary
# ---------------------------------------------------------------------------

@router.get("/spending", response_model=SpendingSummaryOut)
async def get_spending(
    month: Optional[str] = Query(None, description="Month in YYYY-MM format"),
    session=Depends(require_ui_session),
):
    """Get current month spending summary."""
    if month and not _MONTH_RE.match(month):
        raise HTTPException(400, detail={"code": "invalid_month_format", "message": "Month must be in YYYY-MM format"})

    from app.services.compute_billing import get_monthly_summary
    summary = get_monthly_summary(session["user_sub"], month=month)
    return SpendingSummaryOut(**summary)


# ---------------------------------------------------------------------------
# Resource breakdown
# ---------------------------------------------------------------------------

@router.get("/resources", response_model=ResourceBreakdownOut)
async def get_resources(
    month: Optional[str] = Query(None, description="Month in YYYY-MM format"),
    session=Depends(require_ui_session),
):
    """Get per-resource spending breakdown."""
    if month and not _MONTH_RE.match(month):
        raise HTTPException(400, detail={"code": "invalid_month_format", "message": "Month must be in YYYY-MM format"})

    from app.services.compute_billing import get_resource_breakdown
    resources = get_resource_breakdown(session["user_sub"], month=month)
    return ResourceBreakdownOut(
        resources=resources,
        month=month or __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m"),
    )


@router.get("/resources/{resource_id}")
async def get_resource_spending(
    resource_id: str,
    month: Optional[str] = Query(None),
    session=Depends(require_ui_session),
):
    """Get spending for a single resource."""
    if month and not _MONTH_RE.match(month):
        raise HTTPException(400, detail={"code": "invalid_month_format", "message": "Month must be in YYYY-MM format"})

    from app.services.compute_billing import get_resource_breakdown
    resources = get_resource_breakdown(session["user_sub"], month=month)
    for r in resources:
        if r["resource_id"] == resource_id:
            return r
    return {
        "resource_id": resource_id,
        "resource_label": "",
        "resource_type": "",
        "instance_type_or_preset": "",
        "total_cents": 0,
        "total_minutes": 0.0,
        "status": "unknown",
    }


# ---------------------------------------------------------------------------
# Billing history (ledger)
# ---------------------------------------------------------------------------

@router.get("/history", response_model=BillingLedgerOut)
async def get_history(
    resource_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    cursor: Optional[str] = Query(None),
    session=Depends(require_ui_session),
):
    """Get billing tick history (paginated)."""
    from app.services.compute_billing import get_spending_ledger
    result = get_spending_ledger(
        session["user_sub"],
        resource_id=resource_id,
        limit=limit,
        cursor=cursor,
    )
    return BillingLedgerOut(**result)


# ---------------------------------------------------------------------------
# Budget management
# ---------------------------------------------------------------------------

@router.post("/budget", response_model=BudgetOut)
async def update_budget(
    body: UpdateBudgetIn,
    session=Depends(require_ui_session),
):
    """Set monthly spending budget."""
    from app.services.compute_billing import set_budget
    result = set_budget(
        session["user_sub"],
        budget_monthly_cents=body.budget_monthly_cents,
        alert_thresholds=body.alert_thresholds,
    )
    return BudgetOut(**result)


@router.get("/budget", response_model=BudgetOut)
async def get_budget(
    session=Depends(require_ui_session),
):
    """Get budget status."""
    from app.services.compute_billing import get_budget_status
    result = get_budget_status(session["user_sub"])
    return BudgetOut(**result)


# ---------------------------------------------------------------------------
# Manual billing tick (for testing / dev mode)
# ---------------------------------------------------------------------------

@router.post("/tick", response_model=ComputeBillingTickOut)
async def manual_tick(
    body: ComputeBillingTickIn,
    session=Depends(require_ui_session),
):
    """Manually record a billing tick. Useful for testing."""
    from app.services.compute_billing import record_billing_tick, InsufficientBalanceError

    try:
        result = record_billing_tick(
            session["user_sub"],
            resource_type=body.resource_type,
            resource_id=body.resource_id,
            resource_label=body.resource_label,
            instance_type_or_preset=body.instance_type_or_preset,
            event="periodic_tick",
            duration_minutes=body.duration_minutes,
        )
    except InsufficientBalanceError:
        raise HTTPException(402, detail={
            "code": "insufficient_balance",
            "message": "Wallet balance insufficient for billing deduction",
        })

    return ComputeBillingTickOut(
        ok=True,
        entry_id=result["entry_id"],
        amount_cents=result["amount_cents"],
        wallet_balance_after=result["wallet_balance_after"],
        rate_cents_per_min=result["rate_cents_per_min"],
        created_at=result["created_at"],
    )
