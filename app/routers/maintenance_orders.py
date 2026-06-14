"""
Maintenance Work Orders + Vendor Directory router — WOV-002, WOV-004.

Routes are mounted under /ui prefix. Static literals are declared BEFORE
dynamic path segments to prevent FastAPI declaration-order capture.

Auth:
  - Mutations: require_admin_or_root_csrf (admin/root role + CSRF enforcement)
  - Reads:     require_ui_session (any authenticated session)

All handlers call _require_enabled() via the service layer → HTTP 404 when
MAINTENANCE_ORDERS_ENABLED=false.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    MaintenanceOrderAssignIn,
    MaintenanceOrderIn,
    MaintenanceOrderOut,
    MaintenanceOrderScheduleIn,
    MaintenanceOrderTransitionIn,
    VendorCreateIn,
    VendorListOut,
    VendorOut,
    VendorPatchIn,
    VendorStatusIn,
    WoListOut,
)
from app.services.maintenance_orders import (
    assign_work_order,
    create_work_order,
    default_wo_columns,
    get_work_order,
    list_work_orders,
    schedule_work_order,
    transition_work_order,
)
from app.services.maintenance_vendors import (
    VENDOR_TRADE_CATEGORIES,
    create_vendor,
    get_vendor,
    list_vendors,
    set_vendor_status,
    update_vendor,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui", tags=["maintenance"])


# ---------------------------------------------------------------------------
# Work-order board columns (static — no dynamic params)
# ---------------------------------------------------------------------------

@router.get("/maintenance/work-orders/board-columns")
async def get_board_columns(user=Depends(require_ui_session)):
    return {"columns": default_wo_columns()}


# ---------------------------------------------------------------------------
# Work-order system-wide list (by status or assignee)
# ---------------------------------------------------------------------------

@router.get("/maintenance/work-orders", response_model=WoListOut)
async def list_work_orders_endpoint(
    wo_status: Optional[str] = Query(None),
    assignee_sub: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user=Depends(require_ui_session),
):
    return list_work_orders(
        wo_status=wo_status,
        assignee_sub=assignee_sub,
        cursor=cursor,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Work-order mutations (by work_order_id in path)
# ---------------------------------------------------------------------------

@router.patch("/maintenance/work-orders/{work_order_id}/assign", response_model=MaintenanceOrderOut)
async def assign_work_order_endpoint(
    work_order_id: str,
    body: MaintenanceOrderAssignIn,
    user=Depends(require_admin_or_root_csrf),
):
    return assign_work_order(body.property_id, work_order_id, body, user.user_sub)


@router.patch("/maintenance/work-orders/{work_order_id}/schedule", response_model=MaintenanceOrderOut)
async def schedule_work_order_endpoint(
    work_order_id: str,
    body: MaintenanceOrderScheduleIn,
    user=Depends(require_admin_or_root_csrf),
):
    return schedule_work_order(body.property_id, work_order_id, body, user.user_sub)


@router.patch("/maintenance/work-orders/{work_order_id}", response_model=MaintenanceOrderOut)
async def transition_work_order_endpoint(
    work_order_id: str,
    body: MaintenanceOrderTransitionIn,
    user=Depends(require_admin_or_root_csrf),
):
    # Router-layer validation: cost_cents only valid on completed transition
    if body.cost_cents is not None and body.target_status != "completed":
        raise HTTPException(status_code=422, detail="cost_cents_only_on_completion")
    return transition_work_order(body.property_id, work_order_id, body, user.user_sub)


# ---------------------------------------------------------------------------
# Property-scoped work-order endpoints
# ---------------------------------------------------------------------------

@router.post("/properties/{property_id}/work-orders", response_model=MaintenanceOrderOut)
async def create_work_order_endpoint(
    property_id: str,
    body: MaintenanceOrderIn,
    user=Depends(require_admin_or_root_csrf),
):
    return create_work_order(property_id, body, user.user_sub)


@router.get("/properties/{property_id}/work-orders", response_model=WoListOut)
async def list_property_work_orders(
    property_id: str,
    wo_status: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user=Depends(require_ui_session),
):
    return list_work_orders(
        property_id=property_id,
        wo_status=wo_status,
        cursor=cursor,
        limit=limit,
    )


@router.get("/properties/{property_id}/work-orders/{work_order_id}", response_model=MaintenanceOrderOut)
async def get_work_order_endpoint(
    property_id: str,
    work_order_id: str,
    user=Depends(require_ui_session),
):
    wo = get_work_order(property_id, work_order_id)
    if wo is None:
        raise HTTPException(status_code=404, detail="work_order_not_found")
    return wo


# ---------------------------------------------------------------------------
# Vendor directory — static routes BEFORE dynamic {vendor_id}
# ---------------------------------------------------------------------------

@router.get("/maintenance/vendors/categories")
async def list_vendor_categories(user=Depends(require_ui_session)):
    return {"categories": sorted(VENDOR_TRADE_CATEGORIES)}


@router.post("/maintenance/vendors", response_model=VendorOut)
async def create_vendor_endpoint(
    body: VendorCreateIn,
    user=Depends(require_admin_or_root_csrf),
):
    return create_vendor(user.user_sub, body)


@router.get("/maintenance/vendors", response_model=VendorListOut)
async def list_vendors_endpoint(
    status: str = Query("active"),
    trade_category: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user=Depends(require_ui_session),
):
    return list_vendors(status=status, trade_category=trade_category, cursor=cursor, limit=limit)


@router.get("/maintenance/vendors/{vendor_id}", response_model=VendorOut)
async def get_vendor_endpoint(
    vendor_id: str,
    user=Depends(require_ui_session),
):
    v = get_vendor(vendor_id)
    if v is None:
        raise HTTPException(status_code=404, detail="vendor_not_found")
    return v


@router.patch("/maintenance/vendors/{vendor_id}", response_model=VendorOut)
async def update_vendor_endpoint(
    vendor_id: str,
    body: VendorPatchIn,
    user=Depends(require_admin_or_root_csrf),
):
    return update_vendor(vendor_id, user.user_sub, body)


@router.post("/maintenance/vendors/{vendor_id}/status", response_model=VendorOut)
async def set_vendor_status_endpoint(
    vendor_id: str,
    body: VendorStatusIn,
    user=Depends(require_admin_or_root_csrf),
):
    return set_vendor_status(vendor_id, body.status, user.user_sub)
