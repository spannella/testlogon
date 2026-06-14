"""
OFBiz Fixed Assets router — FXA-007 / FXA-013.

All endpoints are admin/root only (fixed-asset records are finance-sensitive).
Route declaration order: literal sub-paths before /{asset_id} captures.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.models import (
    DepreciationScheduleOut,
    FixedAssetDisposeIn,
    FixedAssetIn,
    FixedAssetOut,
    FixedAssetPatchIn,
    MaintenanceOrderIn,
    MaintenanceOrderOut,
    MaintenanceOrderTransitionIn,
)

router = APIRouter(prefix="/ui/fixed-assets", tags=["fixed-assets"])


# ---------------------------------------------------------------------------
# Asset register
# ---------------------------------------------------------------------------

@router.post("", response_model=FixedAssetOut)
async def create_asset_endpoint(
    body: FixedAssetIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FixedAssetOut:
    from app.services.fixed_assets import create_asset
    return create_asset(user.user_sub, body)


@router.get("", response_model=Dict[str, Any])
async def list_assets_endpoint(
    owner_sub: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.fixed_assets import list_assets
    items, next_cursor = list_assets(
        owner_sub=owner_sub,
        status=status,
        cursor=cursor,
        limit=limit,
    )
    return {"items": [i.model_dump() for i in items], "count": len(items), "cursor": next_cursor}


# IMPORTANT: /work-orders (literal) must be declared BEFORE /{asset_id} (dynamic)
@router.get("/work-orders", response_model=Dict[str, Any])
async def list_work_orders_queue(
    wo_status: Optional[str] = Query(default=None),
    assignee_sub: Optional[str] = Query(default=None),
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.fixed_assets import list_work_orders
    items, next_cursor = list_work_orders(
        wo_status=wo_status,
        assignee_sub=assignee_sub,
        cursor=cursor,
        limit=limit,
    )
    return {"items": [i.model_dump() for i in items], "count": len(items), "cursor": next_cursor}


# PATCH /work-orders/{work_order_id} must precede /{asset_id} to avoid capture
@router.patch("/work-orders/{work_order_id}", response_model=MaintenanceOrderOut)
async def transition_work_order_endpoint(
    work_order_id: str,
    asset_id: str = Query(...),
    body: MaintenanceOrderTransitionIn = ...,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> MaintenanceOrderOut:
    from app.services.fixed_assets import transition_work_order
    return transition_work_order(work_order_id, asset_id, body, user.user_sub)


@router.get("/{asset_id}", response_model=FixedAssetOut)
async def get_asset_endpoint(
    asset_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FixedAssetOut:
    from app.services.fixed_assets import get_asset
    return get_asset(asset_id)


@router.patch("/{asset_id}", response_model=FixedAssetOut)
async def update_asset_endpoint(
    asset_id: str,
    body: FixedAssetPatchIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FixedAssetOut:
    from app.services.fixed_assets import update_asset
    return update_asset(asset_id, body, user.user_sub)


@router.post("/{asset_id}/dispose", response_model=FixedAssetOut)
async def dispose_asset_endpoint(
    asset_id: str,
    body: FixedAssetDisposeIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FixedAssetOut:
    from app.services.fixed_assets import dispose_asset
    return dispose_asset(asset_id, body, user.user_sub)


@router.get("/{asset_id}/schedule", response_model=DepreciationScheduleOut)
async def get_schedule_endpoint(
    asset_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> DepreciationScheduleOut:
    from app.services.fixed_assets import get_schedule
    return get_schedule(asset_id)


@router.post("/{asset_id}/schedule/generate", response_model=DepreciationScheduleOut)
async def generate_schedule_endpoint(
    asset_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> DepreciationScheduleOut:
    from app.services.fixed_assets import generate_schedule
    return generate_schedule(asset_id)


@router.post("/{asset_id}/schedule/{period}/post", response_model=Dict[str, Any])
async def post_period_endpoint(
    asset_id: str,
    period: int,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.fixed_assets import post_depreciation_period
    result = post_depreciation_period(asset_id, period)
    return result.model_dump()


# ---------------------------------------------------------------------------
# Work orders
# ---------------------------------------------------------------------------

@router.post("/{asset_id}/work-orders", response_model=MaintenanceOrderOut)
async def create_work_order_endpoint(
    asset_id: str,
    body: MaintenanceOrderIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> MaintenanceOrderOut:
    from app.services.fixed_assets import create_work_order
    return create_work_order(asset_id, body, user.user_sub)


@router.get("/{asset_id}/work-orders", response_model=Dict[str, Any])
async def list_work_orders_for_asset(
    asset_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.fixed_assets import list_work_orders
    items, next_cursor = list_work_orders(
        asset_id=asset_id,
        cursor=cursor,
        limit=limit,
    )
    return {"items": [i.model_dump() for i in items], "count": len(items), "cursor": next_cursor}
