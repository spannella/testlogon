"""MFG-011 — Manufacturing router.

All endpoints require require_admin_or_root_csrf. Every handler calls
_require_enabled() as its first statement (delegated to the service layer).

Sub-path ordering: /boms/{bom_id}/explode before /{bom_id} (FastAPI
declaration order), same for /work-orders/{id}/release, /start, /complete,
/cancel before the bare /{id} GET.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends

from app.auth.policy import require_admin_or_root_csrf
from app.auth.deps import AuthenticatedUser
from app.models import (
    BomCreateIn,
    BomUpdateIn,
    WorkCenterCreateIn,
    WorkCenterUpdateIn,
    WorkOrderCreateIn,
    WorkOrderCompleteIn,
    WorkOrderCancelIn,
    MrpRunIn,
)

manufacturing_router = APIRouter(prefix="/ui/manufacturing", tags=["manufacturing"])


# ---------------------------------------------------------------------------
# BOM endpoints
# ---------------------------------------------------------------------------

@manufacturing_router.post("/boms")
async def create_bom(
    body: BomCreateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_bom import create_bom as _create
    components = [
        {
            "component_sku": c.component_sku,
            "quantity_per": c.quantity_per,
            "scrap_pct": c.scrap_pct,
            "unit_of_measure": c.unit_of_measure,
        }
        for c in body.components
    ]
    return _create(
        body.product_sku,
        body.name,
        body.output_quantity,
        components,
        correlation_id=body.correlation_id,
        user_sub=user.sub,
    )


@manufacturing_router.get("/boms")
async def list_boms(
    product_sku: Optional[str] = None,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_bom import list_boms as _list
    return {"boms": _list(product_sku=product_sku)}


# IMPORTANT: /boms/{bom_id}/explode MUST come before /boms/{bom_id}
@manufacturing_router.get("/boms/{bom_id}/explode")
async def explode_bom(
    bom_id: str,
    build_qty: int = 1,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_bom import explode_bom as _explode
    components = _explode(bom_id, build_qty)
    return {"bom_id": bom_id, "build_qty": build_qty, "components": components}


@manufacturing_router.get("/boms/{bom_id}")
async def get_bom(
    bom_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_bom import get_bom as _get
    from fastapi import HTTPException
    bom = _get(bom_id)
    if bom is None:
        raise HTTPException(404, f"BOM not found: {bom_id}")
    return bom


@manufacturing_router.patch("/boms/{bom_id}")
async def update_bom(
    bom_id: str,
    body: BomUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_bom import update_bom as _update
    return _update(bom_id, status=body.status, name=body.name, user_sub=user.sub)


@manufacturing_router.delete("/boms/{bom_id}")
async def deactivate_bom(
    bom_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_bom import update_bom as _update
    return _update(bom_id, status="inactive", user_sub=user.sub)


# ---------------------------------------------------------------------------
# Work-center endpoints
# ---------------------------------------------------------------------------

@manufacturing_router.post("/work-centers")
async def create_work_center(
    body: WorkCenterCreateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_routing import create_work_center as _create
    return _create(
        body.name,
        body.capacity_per_hour,
        body.cost_per_hour_cents,
        correlation_id=body.correlation_id,
        user_sub=user.sub,
    )


@manufacturing_router.get("/work-centers")
async def list_work_centers(
    status: str = "active",
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_routing import list_work_centers as _list
    return {"work_centers": _list(status=status)}


@manufacturing_router.patch("/work-centers/{work_center_id}")
async def update_work_center(
    work_center_id: str,
    body: WorkCenterUpdateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_routing import update_work_center as _update
    return _update(
        work_center_id,
        name=body.name,
        capacity_per_hour=body.capacity_per_hour,
        cost_per_hour_cents=body.cost_per_hour_cents,
        status=body.status,
        user_sub=user.sub,
    )


# ---------------------------------------------------------------------------
# Work-order endpoints
# IMPORTANT: action sub-paths (/release, /start, /complete, /cancel, /issues)
# must be declared BEFORE the bare /{work_order_id} GET.
# ---------------------------------------------------------------------------

@manufacturing_router.post("/work-orders")
async def create_work_order(
    body: WorkOrderCreateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_work_orders import create_work_order as _create
    return _create(
        body.product_sku,
        body.quantity,
        bom_id=body.bom_id,
        work_center_id=body.work_center_id,
        correlation_id=body.correlation_id,
        user_sub=user.sub,
    )


@manufacturing_router.get("/work-orders")
async def list_work_orders(
    status: Optional[str] = None,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_work_orders import list_work_orders as _list
    return {"work_orders": _list(status=status)}


@manufacturing_router.post("/work-orders/{work_order_id}/release")
async def release_work_order(
    work_order_id: str,
    location_id: str = "warehouse",
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_work_orders import release_work_order as _release
    return _release(work_order_id, location_id=location_id, user_sub=user.sub)


@manufacturing_router.post("/work-orders/{work_order_id}/start")
async def start_work_order(
    work_order_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_work_orders import start_work_order as _start
    return _start(work_order_id, user_sub=user.sub)


@manufacturing_router.post("/work-orders/{work_order_id}/complete")
async def complete_work_order(
    work_order_id: str,
    body: WorkOrderCompleteIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_work_orders import complete_work_order as _complete
    return _complete(
        work_order_id,
        produced_qty=body.produced_qty,
        location_id=body.location_id,
        user_sub=user.sub,
    )


@manufacturing_router.post("/work-orders/{work_order_id}/cancel")
async def cancel_work_order(
    work_order_id: str,
    body: WorkOrderCancelIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_work_orders import cancel_work_order as _cancel
    return _cancel(work_order_id, reason=body.reason, user_sub=user.sub)


@manufacturing_router.get("/work-orders/{work_order_id}/issues")
async def get_work_order_issues(
    work_order_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_work_orders import _get_issue_rows, _require_enabled
    _require_enabled()
    return {"issues": _get_issue_rows(work_order_id)}


@manufacturing_router.get("/work-orders/{work_order_id}")
async def get_work_order(
    work_order_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_work_orders import get_work_order as _get
    from fastapi import HTTPException
    wo = _get(work_order_id)
    if wo is None:
        raise HTTPException(404, f"Work order not found: {work_order_id}")
    return wo


# ---------------------------------------------------------------------------
# MRP endpoints
# ---------------------------------------------------------------------------

@manufacturing_router.post("/mrp/run")
async def run_mrp(
    body: MrpRunIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_mrp import run_mrp as _run
    return _run(
        horizon_days=body.horizon_days,
        location_id=body.location_id,
        correlation_id=body.correlation_id,
        user_sub=user.sub,
    )


@manufacturing_router.get("/mrp/runs/{mrp_run_id}")
async def get_mrp_run(
    mrp_run_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    from app.services.manufacturing_mrp import get_mrp_run as _get
    from fastapi import HTTPException
    run = _get(mrp_run_id)
    if run is None:
        raise HTTPException(404, f"MRP run not found: {mrp_run_id}")
    return run
