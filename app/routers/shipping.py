"""Shipping/Logistics HTTP router (SHP-005/007/009).

Mounted at /ui/shop/shipping. All handlers return 503 when S.shipping_enabled
is False. Admin mutations require require_admin_or_root_csrf; reads use
require_ui_session.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.core.settings import S
from app.models import (
    CarrierIn,
    CarrierOut,
    ShipmentAdvanceIn,
    ShipmentCancelIn,
    ShipmentIn,
    ShipmentMethodIn,
    ShipmentMethodOut,
    ShipmentOut,
    ShipmentTrackingUpdateIn,
    ShippingRateQuote,
    ShippingRateRequest,
)
from app.services.sessions import require_ui_session

shipping_router = APIRouter(prefix="/ui/shop/shipping", tags=["shipping"])


def _ensure_enabled() -> None:
    if not getattr(S, "shipping_enabled", False):
        raise HTTPException(status_code=503, detail="Shipping is not enabled")


# ---------------------------------------------------------------------------
# Carrier catalog
# ---------------------------------------------------------------------------

@shipping_router.post("/carriers", response_model=CarrierOut)
async def create_carrier_endpoint(
    body: CarrierIn,
    ctx: Dict[str, Any] = Depends(require_admin_or_root_csrf),
):
    _ensure_enabled()
    from app.services.shipping_carriers import create_carrier
    item = create_carrier(
        body.carrier_code, body.display_name,
        actor=ctx.get("user_sub", "admin"),
    )
    return CarrierOut(**item)


@shipping_router.get("/carriers", response_model=List[CarrierOut])
async def list_carriers_endpoint(
    enabled_only: bool = Query(default=True),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _ensure_enabled()
    from app.services.shipping_carriers import list_carriers
    items = list_carriers(enabled_only=enabled_only)
    return [CarrierOut(**i) for i in items]


@shipping_router.get("/carriers/{carrier_id}", response_model=CarrierOut)
async def get_carrier_endpoint(
    carrier_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _ensure_enabled()
    from app.services.shipping_carriers import get_carrier
    item = get_carrier(carrier_id)
    if not item:
        raise HTTPException(status_code=404, detail="Carrier not found")
    return CarrierOut(**item)


@shipping_router.patch("/carriers/{carrier_id}", response_model=CarrierOut)
async def update_carrier_endpoint(
    carrier_id: str,
    body: Dict[str, Any],
    ctx: Dict[str, Any] = Depends(require_admin_or_root_csrf),
):
    _ensure_enabled()
    from app.services.shipping_carriers import update_carrier
    item = update_carrier(carrier_id, patch=body, actor=ctx.get("user_sub", "admin"))
    return CarrierOut(**item)


@shipping_router.post("/carriers/{carrier_id}/disable")
async def disable_carrier_endpoint(
    carrier_id: str,
    ctx: Dict[str, Any] = Depends(require_admin_or_root_csrf),
):
    _ensure_enabled()
    from app.services.shipping_carriers import disable_carrier
    disable_carrier(carrier_id, actor=ctx.get("user_sub", "admin"))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Carrier methods
# ---------------------------------------------------------------------------

@shipping_router.post("/carriers/{carrier_id}/methods", response_model=ShipmentMethodOut)
async def add_method_endpoint(
    carrier_id: str,
    body: ShipmentMethodIn,
    ctx: Dict[str, Any] = Depends(require_admin_or_root_csrf),
):
    _ensure_enabled()
    from app.services.shipping_carriers import add_method
    item = add_method(
        carrier_id,
        body.method_code,
        body.method_label,
        base_rate_cents=body.base_rate_cents,
        currency=body.currency,
        transit_days_min=body.transit_days_min,
        transit_days_max=body.transit_days_max,
        actor=ctx.get("user_sub", "admin"),
    )
    return ShipmentMethodOut(**item)


@shipping_router.get("/carriers/{carrier_id}/methods", response_model=List[ShipmentMethodOut])
async def list_methods_endpoint(
    carrier_id: str,
    enabled_only: bool = Query(default=True),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _ensure_enabled()
    from app.services.shipping_carriers import list_methods
    items = list_methods(carrier_id, enabled_only=enabled_only)
    return [ShipmentMethodOut(**i) for i in items]


@shipping_router.patch("/carriers/{carrier_id}/methods/{method_code}", response_model=ShipmentMethodOut)
async def update_method_endpoint(
    carrier_id: str,
    method_code: str,
    body: Dict[str, Any],
    ctx: Dict[str, Any] = Depends(require_admin_or_root_csrf),
):
    _ensure_enabled()
    from app.services.shipping_carriers import update_method
    item = update_method(
        carrier_id, method_code,
        patch=body, actor=ctx.get("user_sub", "admin"),
    )
    return ShipmentMethodOut(**item)


# ---------------------------------------------------------------------------
# Rate estimation
# ---------------------------------------------------------------------------

@shipping_router.post("/estimate", response_model=ShippingRateQuote)
async def estimate_rate_endpoint(
    body: ShippingRateRequest,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _ensure_enabled()
    from app.services.shipping_rates import estimate_rates
    result = estimate_rates(
        carrier_code=body.carrier_code,
        method_code=body.method_code,
        weight_oz=body.weight_oz,
        destination_zip=body.destination_zip,
        origin_zip=body.origin_zip,
        user_sub=ctx.get("user_sub", "anonymous"),
    )
    return ShippingRateQuote(**result)


@shipping_router.get("/estimate")
async def estimate_rate_get_endpoint(
    carrier_code: str = Query(...),
    method_code: str = Query(...),
    weight_oz: int = Query(default=0, ge=0),
    destination_zip: str = Query(default=""),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _ensure_enabled()
    from app.services.shipping_rates import estimate_rates
    result = estimate_rates(
        carrier_code=carrier_code,
        method_code=method_code,
        weight_oz=weight_oz,
        destination_zip=destination_zip,
        user_sub=ctx.get("user_sub", "anonymous"),
    )
    return result


# ---------------------------------------------------------------------------
# Shipment CRUD
# ---------------------------------------------------------------------------

@shipping_router.post("/shipments", response_model=ShipmentOut)
async def create_shipment_endpoint(
    body: ShipmentIn,
    ctx: Dict[str, Any] = Depends(require_admin_or_root_csrf),
):
    _ensure_enabled()
    from app.services.shipments import create_shipment
    result = create_shipment(
        order_id=body.order_id,
        user_id=ctx.get("user_sub", ""),
        carrier_code=body.carrier_code,
        method_code=body.method_code,
        ship_to_address=body.ship_to_address,
        line_items=body.line_items,
        packages=[p.model_dump() for p in body.packages] if body.packages else None,
        ship_group_seq=body.ship_group_seq,
        purchase_txn_id=body.purchase_txn_id,
        actor=ctx.get("user_sub", "admin"),
    )
    return ShipmentOut(
        **{k: v for k, v in result.items() if k in ShipmentOut.model_fields}
    )


@shipping_router.get("/shipments/{shipment_id}", response_model=ShipmentOut)
async def get_shipment_endpoint(
    shipment_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _ensure_enabled()
    from app.services.shipments import get_shipment
    from app.auth.roles import Role
    is_admin = ctx.get("role", Role.USER) in (Role.ADMIN, Role.ROOT)
    item = get_shipment(
        shipment_id,
        user_id=ctx.get("user_sub"),
        admin=is_admin,
    )
    if not item:
        raise HTTPException(status_code=404, detail="Shipment not found")
    return ShipmentOut(
        **{k: v for k, v in item.items() if k in ShipmentOut.model_fields}
    )


@shipping_router.get("/orders/{order_id}/shipments")
async def list_order_shipments_endpoint(
    order_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _ensure_enabled()
    from app.services.shipments import list_shipments_for_order
    items = list_shipments_for_order(order_id)
    return {"shipments": items, "count": len(items)}


@shipping_router.patch("/shipments/{shipment_id}/tracking", response_model=ShipmentOut)
async def update_tracking_endpoint(
    shipment_id: str,
    body: ShipmentTrackingUpdateIn,
    ctx: Dict[str, Any] = Depends(require_admin_or_root_csrf),
):
    _ensure_enabled()
    from app.services.shipments import update_shipment_tracking
    item = update_shipment_tracking(
        shipment_id,
        tracking_number=body.tracking_number,
        carrier_code=body.carrier_code,
        actor=ctx.get("user_sub", "admin"),
    )
    return ShipmentOut(
        **{k: v for k, v in item.items() if k in ShipmentOut.model_fields}
    )


@shipping_router.post("/shipments/{shipment_id}/advance", response_model=ShipmentOut)
async def advance_shipment_endpoint(
    shipment_id: str,
    body: ShipmentAdvanceIn,
    ctx: Dict[str, Any] = Depends(require_admin_or_root_csrf),
):
    _ensure_enabled()
    from app.services.shipments import advance_shipment_status
    item = advance_shipment_status(
        shipment_id,
        body.target_status,
        actor=ctx.get("user_sub", "admin"),
        reason=body.reason,
    )
    return ShipmentOut(
        **{k: v for k, v in item.items() if k in ShipmentOut.model_fields}
    )


@shipping_router.post("/shipments/{shipment_id}/cancel", response_model=ShipmentOut)
async def cancel_shipment_endpoint(
    shipment_id: str,
    body: ShipmentCancelIn,
    ctx: Dict[str, Any] = Depends(require_admin_or_root_csrf),
):
    _ensure_enabled()
    from app.services.shipments import cancel_shipment_with_refund
    item = cancel_shipment_with_refund(
        shipment_id,
        ctx.get("user_sub", ""),
        reason=body.reason,
        actor=ctx.get("user_sub", "admin"),
    )
    return ShipmentOut(
        **{k: v for k, v in item.items() if k in ShipmentOut.model_fields}
    )
