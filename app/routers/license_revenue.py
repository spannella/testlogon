"""License revenue dashboard router (LICENSE-003)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional

from app.services.sessions import require_ui_session
from app.auth.policy import require_admin_or_root
from app.auth.deps import AuthenticatedUser
from app.services import license_revenue as svc
from app.models import (
    RevenueListOut,
    RevenueSplitPreviewOut,
    AdminRevenueListOut,
)
from app.core.settings import S

router = APIRouter(prefix="/ui/licenses/revenue", tags=["license-revenue"])
admin_router = APIRouter(prefix="/ui/admin/licenses/revenue", tags=["license-revenue-admin"])


# ---------------------------------------------------------------------------
# User endpoints
# ---------------------------------------------------------------------------


@router.get("/earned")
async def get_earned_revenue(
    source_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    ctx: dict = Depends(require_ui_session),
) -> RevenueListOut:
    """Get licensor revenue summary + transaction list."""
    user_id = ctx["user_sub"]
    data = svc.list_revenue_transactions(
        user_id=user_id,
        role="licensor",
        source_type=source_type,
        limit=limit,
        cursor=cursor,
    )
    return RevenueListOut(**data)


@router.get("/paid")
async def get_paid_revenue(
    source_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    ctx: dict = Depends(require_ui_session),
) -> RevenueListOut:
    """Get licensee payments summary + transaction list."""
    user_id = ctx["user_sub"]
    data = svc.list_revenue_transactions(
        user_id=user_id,
        role="licensee",
        source_type=source_type,
        limit=limit,
        cursor=cursor,
    )
    return RevenueListOut(**data)


@router.get("/license/{issued_license_id}")
async def get_license_revenue(
    issued_license_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None),
    ctx: dict = Depends(require_ui_session),
) -> dict:
    """Get transactions for a specific license."""
    data = svc.list_license_transactions(
        issued_license_id=issued_license_id,
        limit=limit,
        cursor=cursor,
    )
    return data


@router.get("/calculate")
async def calculate_split_preview(
    amount: int = Query(..., ge=0),
    revenue_share_pct: int = Query(0, ge=0, le=100),
    profit_share_pct: int = Query(0, ge=0, le=100),
    fixed_cost_cents: int = Query(0, ge=0),
    ctx: dict = Depends(require_ui_session),
) -> RevenueSplitPreviewOut:
    """Preview split calculation for given terms and amount."""
    platform_fee_pct = S.license_revenue_platform_fee_pct
    result = svc.calculate_split_preview(
        source_amount_cents=amount,
        platform_fee_pct=platform_fee_pct,
        revenue_share_pct=revenue_share_pct,
        profit_share_pct=profit_share_pct,
        fixed_cost_cents=fixed_cost_cents,
    )
    return RevenueSplitPreviewOut(**result)


# ---------------------------------------------------------------------------
# Internal: register / revoke content licenses (used by E2E tests and hooks)
# ---------------------------------------------------------------------------


@router.post("/register-license")
async def register_license(
    body: dict,
    ctx: dict = Depends(require_ui_session),
):
    """Register a content license mapping (used for testing and integration)."""
    user_id = ctx["user_sub"]
    result = svc.register_content_license(
        issued_license_id=body.get("issued_license_id", ""),
        content_id=body.get("content_id", ""),
        licensor_id=body.get("licensor_id", user_id),
        licensee_id=body.get("licensee_id", ""),
        revenue_share_pct=int(body.get("revenue_share_pct", 0)),
        profit_share_pct=int(body.get("profit_share_pct", 0)),
        fixed_cost_cents=int(body.get("fixed_cost_cents", 0)),
        status=body.get("status", "active"),
    )
    return {"ok": True, "license": result}


@router.post("/revoke-license")
async def revoke_license(
    body: dict,
    ctx: dict = Depends(require_ui_session),
):
    """Revoke a content license mapping."""
    svc.revoke_content_license(
        content_id=body["content_id"],
        issued_license_id=body["issued_license_id"],
    )
    return {"ok": True}


@router.post("/process-split")
async def process_split(
    body: dict,
    ctx: dict = Depends(require_ui_session),
):
    """Trigger revenue split processing for a content item.

    This endpoint allows testing the split engine without going through
    the full tip/unlock flow.
    """
    splits = svc.process_revenue_split(
        content_id=body["content_id"],
        licensee_id=body.get("licensee_id", ctx["user_sub"]),
        source_type=body.get("source_type", "tip"),
        source_amount_cents=int(body["source_amount_cents"]),
        source_txn_id=body.get("source_txn_id", "test_txn"),
        currency=body.get("currency", "usd"),
    )
    return {"ok": True, "splits": splits}


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------


@admin_router.get("")
async def admin_get_platform_revenue(
    limit: int = Query(100, ge=1, le=500),
    cursor: Optional[str] = Query(None),
    admin: AuthenticatedUser = Depends(require_admin_or_root),
) -> AdminRevenueListOut:
    """Admin: list platform-wide license revenue transactions."""
    data = svc.admin_list_platform_revenue(limit=limit, cursor=cursor)
    return AdminRevenueListOut(**data)
