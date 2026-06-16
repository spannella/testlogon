"""Inventory & soft-reservation router (ADR-001 OFB-003/004, Phase 1).

Additive + flag-gated (``INVENTORY_RESERVATIONS_ENABLED``, default OFF). Every
handler short-circuits to 404 when the flag is off, so mounting the router is a
no-op until a milestone explicitly enables it.

Role model (SECOPS-007 / ADR §Security):
  * Inventory admin mutations (set on-hand, adjust, reorder point, low-stock
    listing) → ``require_admin_or_root_csrf``.
  * Read of a single inventory record → ``require_ui_session`` (storefront).
  * Reserve / release reservations → ``require_ui_session`` (customer checkout).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    InventoryAdjustIn,
    InventoryRecordOut,
    InventoryReserveIn,
    InventorySetOnHandIn,
    ReservationOut,
)
from app.services import inventory as inv
from app.services.sessions import require_ui_session

inventory_router = APIRouter(prefix="/ui/inventory", tags=["inventory"])


def _require_enabled() -> None:
    inv._require_enabled()


@inventory_router.get("/items/{sku}", response_model=InventoryRecordOut)
async def get_inventory_item(sku: str, session=Depends(require_ui_session)):
    _require_enabled()
    rec = inv.get_inventory(sku)
    if rec is None:
        raise HTTPException(status_code=404, detail="No inventory record for SKU")
    return InventoryRecordOut(**rec)


@inventory_router.put("/items", response_model=InventoryRecordOut)
async def set_on_hand(
    body: InventorySetOnHandIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    _require_enabled()
    rec = inv.set_on_hand(
        body.sku,
        body.on_hand,
        reason=body.reason,
        location_id=body.location_id,
        reorder_point=body.reorder_point,
        user_sub=user.sub,
    )
    return InventoryRecordOut(**rec)


@inventory_router.post("/items/adjust", response_model=InventoryRecordOut)
async def adjust_inventory(
    body: InventoryAdjustIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    _require_enabled()
    rec = inv.adjust(
        body.sku,
        body.delta,
        body.reason or "manual_adjust",
        location_id=body.location_id,
        user_sub=user.sub,
    )
    return InventoryRecordOut(**rec)


@inventory_router.get("/low-stock")
async def list_low_stock(
    status: str = "low_stock",
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
):
    _require_enabled()
    if status not in ("low_stock", "out_of_stock", "in_stock"):
        raise HTTPException(status_code=422, detail="invalid status filter")
    return {"items": inv.list_low_stock(status)}


@inventory_router.post("/reservations", response_model=ReservationOut)
async def create_reservation(
    body: InventoryReserveIn,
    session=Depends(require_ui_session),
):
    _require_enabled()
    res = inv.reserve(
        body.sku,
        body.quantity,
        location_id=body.location_id,
        user_sub=session["user_sub"],
        cart_id=body.cart_id,
        ttl_seconds=body.ttl_seconds,
    )
    return ReservationOut(**res)


@inventory_router.get("/reservations/{reservation_id}", response_model=ReservationOut)
async def get_reservation(reservation_id: str, session=Depends(require_ui_session)):
    _require_enabled()
    res = inv.get_reservation(reservation_id)
    if res is None:
        raise HTTPException(status_code=404, detail="Reservation not found")
    if res.get("user_sub") not in (session["user_sub"], "system"):
        raise HTTPException(status_code=404, detail="Reservation not found")
    return ReservationOut(**res)


@inventory_router.post("/reservations/{reservation_id}/release", response_model=ReservationOut)
async def release_reservation(reservation_id: str, session=Depends(require_ui_session)):
    _require_enabled()
    existing = inv.get_reservation(reservation_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Reservation not found")
    if existing.get("user_sub") not in (session["user_sub"], "system"):
        raise HTTPException(status_code=404, detail="Reservation not found")
    res = inv.release_reservation(reservation_id, reason="customer_release", user_sub=session["user_sub"])
    return ReservationOut(**res)
