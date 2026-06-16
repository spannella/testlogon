"""OFBiz Facility/Fulfillment router (FAC-005/011).

Exposes:
  /ui/facilities         — facility CRUD (FAC-005)
  /ui/fulfillment/transfers   — transfer lifecycle (FAC-006)
  /ui/fulfillment/receiving   — inbound receipts (FAC-007)
  /ui/fulfillment/picklists   — picklist generation + pick confirm (FAC-008)
  /ui/fulfillment/shipments   — pack + ship lifecycle (FAC-009/010)

All endpoints call _require_enabled() as first action (404 when flag off).
Role split: reads via require_ui_session; mutations via require_admin_or_root_csrf.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    FacilityIn,
    FacilityListOut,
    FacilityLocationIn,
    FacilityLocationListOut,
    FacilityLocationOut,
    FacilityOut,
    PicklistOut,
    ReceiveIn,
    ReceiptListOut,
    ReceiptOut,
    FulfillmentShipmentIn,
    ShipmentListOut,
    FulfillmentShipmentOut,
    TransferIn,
    TransferListOut,
    TransferOut,
)
from app.services.sessions import require_ui_session

# ─────────────────────────── local _require_enabled shim ───────────────────


def _require_enabled() -> None:
    from app.services.facilities import _require_enabled as _fac_require
    _fac_require()


# ─────────────────────────── facility router ───────────────────────────────

facilities_router = APIRouter(prefix="/ui/facilities", tags=["facilities"])


@facilities_router.get("", response_model=FacilityListOut)
async def list_facilities_endpoint(
    status: str = Query("active"),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Dict[str, Any] = Depends(require_ui_session),
) -> FacilityListOut:
    _require_enabled()
    from app.services.facilities import list_facilities
    owner_sub = session["user_sub"]
    result = list_facilities(owner_sub, status=status, cursor=cursor, limit=limit)
    return FacilityListOut(**result)


@facilities_router.get("/admin/queue", response_model=FacilityListOut)
async def admin_list_facilities(
    status: str = Query("active"),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FacilityListOut:
    _require_enabled()
    from app.services.facilities import list_facilities_by_status
    result = list_facilities_by_status(status=status, cursor=cursor, limit=limit)
    return FacilityListOut(**result)


@facilities_router.post("", response_model=FacilityOut, status_code=201)
async def create_facility_endpoint(
    body: FacilityIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FacilityOut:
    _require_enabled()
    from app.services.facilities import create_facility
    owner_sub = body.owner_sub or user.sub
    result = create_facility(
        owner_sub,
        body.name,
        body.facility_type,
        description=body.description,
        address=body.address,
    )
    return FacilityOut(**result)


@facilities_router.get("/{facility_id}", response_model=FacilityOut)
async def get_facility_endpoint(
    facility_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> FacilityOut:
    _require_enabled()
    from app.services.facilities import get_facility
    rec = get_facility(facility_id)
    if rec is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Facility not found")
    return FacilityOut(**rec)


@facilities_router.put("/{facility_id}", response_model=FacilityOut)
async def update_facility_endpoint(
    facility_id: str,
    body: FacilityIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FacilityOut:
    _require_enabled()
    from app.services.facilities import update_facility
    result = update_facility(
        facility_id,
        user_sub=user.sub,
        name=body.name,
        facility_type=body.facility_type,
        description=body.description,
        address=body.address,
    )
    return FacilityOut(**result)


@facilities_router.delete("/{facility_id}", response_model=FacilityOut)
async def archive_facility_endpoint(
    facility_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FacilityOut:
    _require_enabled()
    from app.services.facilities import archive_facility
    result = archive_facility(facility_id, user_sub=user.sub)
    return FacilityOut(**result)


@facilities_router.get("/{facility_id}/locations", response_model=FacilityLocationListOut)
async def list_locations_endpoint(
    facility_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> FacilityLocationListOut:
    _require_enabled()
    from app.services.facilities import list_locations
    locs = list_locations(facility_id)
    return FacilityLocationListOut(locations=[FacilityLocationOut(**l) for l in locs])


@facilities_router.post("/{facility_id}/locations", response_model=FacilityLocationOut, status_code=201)
async def create_location_endpoint(
    facility_id: str,
    body: FacilityLocationIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FacilityLocationOut:
    _require_enabled()
    from app.services.facilities import create_location
    result = create_location(
        facility_id,
        body.name,
        body.location_type,
        description=body.description,
        parent_location_id=body.parent_location_id,
        user_sub=user.sub,
    )
    return FacilityLocationOut(**result)


@facilities_router.get("/{facility_id}/locations/{location_id}", response_model=FacilityLocationOut)
async def get_location_endpoint(
    facility_id: str,
    location_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> FacilityLocationOut:
    _require_enabled()
    from app.services.facilities import get_location
    rec = get_location(facility_id, location_id)
    if rec is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Location not found")
    return FacilityLocationOut(**rec)


# ─────────────────────────── fulfillment sub-routers ───────────────────────

fulfillment_router = APIRouter(prefix="/ui/fulfillment", tags=["fulfillment"])


# --- Transfers ---

@fulfillment_router.post("/transfers", response_model=TransferOut, status_code=201)
async def create_transfer_endpoint(
    body: TransferIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> TransferOut:
    _require_enabled()
    from app.services.transfers import create_transfer
    result = create_transfer(
        body.from_facility_id,
        body.from_location_id,
        body.to_facility_id,
        body.to_location_id,
        [{"sku": l.sku, "quantity": l.quantity} for l in body.lines],
        owner_sub=user.sub,
        notes=body.notes,
    )
    return TransferOut(**result)


@fulfillment_router.get("/transfers", response_model=TransferListOut)
async def list_transfers_endpoint(
    status: str = Query("requested"),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Dict[str, Any] = Depends(require_ui_session),
) -> TransferListOut:
    _require_enabled()
    from app.services.transfers import list_transfers
    result = list_transfers(status=status, cursor=cursor, limit=limit)
    return TransferListOut(**result)


@fulfillment_router.get("/transfers/{transfer_id}", response_model=TransferOut)
async def get_transfer_endpoint(
    transfer_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> TransferOut:
    _require_enabled()
    from app.services.transfers import get_transfer
    result = get_transfer(transfer_id)
    return TransferOut(**result)


@fulfillment_router.post("/transfers/{transfer_id}/advance", response_model=TransferOut)
async def advance_transfer_endpoint(
    transfer_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> TransferOut:
    _require_enabled()
    from app.services.transfers import advance_to_in_transit
    result = advance_to_in_transit(transfer_id, user_sub=user.sub)
    return TransferOut(**result)


@fulfillment_router.post("/transfers/{transfer_id}/complete", response_model=TransferOut)
async def complete_transfer_endpoint(
    transfer_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> TransferOut:
    _require_enabled()
    from app.services.transfers import complete_transfer
    result = complete_transfer(transfer_id, user_sub=user.sub)
    return TransferOut(**result)


@fulfillment_router.post("/transfers/{transfer_id}/cancel", response_model=TransferOut)
async def cancel_transfer_endpoint(
    transfer_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> TransferOut:
    _require_enabled()
    from app.services.transfers import cancel_transfer
    result = cancel_transfer(transfer_id, user_sub=user.sub)
    return TransferOut(**result)


# --- Receiving ---

@fulfillment_router.post("/receiving", response_model=ReceiptOut, status_code=201)
async def receive_shipment_endpoint(
    body: ReceiveIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> ReceiptOut:
    _require_enabled()
    from app.services.receiving import receive_shipment
    result = receive_shipment(
        body.facility_id,
        body.location_id,
        [
            {
                "sku": l.sku,
                "quantity": l.quantity,
                "unit_cost_cents": l.unit_cost_cents or 0,
                "lot_label": l.lot_label,
                "ordered_qty": 0,
            }
            for l in body.lines
        ],
        po_id=body.po_id,
        correlation_id=body.correlation_id,
        user_sub=user.sub,
        notes=body.notes,
    )
    return ReceiptOut(**result)


@fulfillment_router.get("/receiving/{receipt_id}", response_model=ReceiptOut)
async def get_receipt_endpoint(
    receipt_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> ReceiptOut:
    _require_enabled()
    from app.services.receiving import get_receipt
    result = get_receipt(receipt_id)
    return ReceiptOut(**result)


@fulfillment_router.get("/receiving", response_model=ReceiptListOut)
async def list_receipts_endpoint(
    facility_id: Optional[str] = Query(None),
    po_id: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Dict[str, Any] = Depends(require_ui_session),
) -> ReceiptListOut:
    _require_enabled()
    if facility_id:
        from app.services.receiving import list_receipts_for_facility
        result = list_receipts_for_facility(facility_id, cursor=cursor, limit=limit)
    elif po_id:
        from app.services.receiving import list_receipts_for_po
        result = list_receipts_for_po(po_id, cursor=cursor, limit=limit)
    else:
        result = {"receipts": [], "next_cursor": None}
    return ReceiptListOut(**result)


# --- Picklists ---

@fulfillment_router.post("/picklists", response_model=PicklistOut, status_code=201)
async def generate_picklist_endpoint(
    order_id: str = Query(...),
    facility_id: str = Query(...),
    location_id: Optional[str] = Query(None),
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PicklistOut:
    _require_enabled()
    from app.services.picking import generate_picklist
    result = generate_picklist(order_id, facility_id, user_sub=user.sub, location_id=location_id)
    return PicklistOut(**result)


@fulfillment_router.get("/picklists/{picklist_id}", response_model=PicklistOut)
async def get_picklist_endpoint(
    picklist_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> PicklistOut:
    _require_enabled()
    from app.services.picking import get_picklist
    result = get_picklist(picklist_id)
    return PicklistOut(**result)


@fulfillment_router.post("/picklists/{picklist_id}/confirm-pick/{line_no}", response_model=PicklistOut)
async def confirm_pick_endpoint(
    picklist_id: str,
    line_no: int,
    picked_qty: int = Query(..., ge=0),
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> PicklistOut:
    _require_enabled()
    from app.services.picking import confirm_pick
    result = confirm_pick(picklist_id, line_no, picked_qty, user_sub=user.sub)
    return PicklistOut(**result)


# --- Shipments ---

@fulfillment_router.post("/picklists/{picklist_id}/pack", response_model=FulfillmentShipmentOut, status_code=201)
async def pack_picklist_endpoint(
    picklist_id: str,
    body: FulfillmentShipmentIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FulfillmentShipmentOut:
    _require_enabled()
    from app.services.picking import pack_picklist
    packages = [
        {
            "weight_grams": p.weight_grams,
            "length_mm": p.length_mm,
            "width_mm": p.width_mm,
            "height_mm": p.height_mm,
            "contents": [{"sku": c.sku, "order_line_id": c.order_line_id, "quantity": c.quantity} for c in p.contents],
            "notes": p.notes,
        }
        for p in body.packages
    ]
    result = pack_picklist(picklist_id, packages, packed_by=user.sub)
    return FulfillmentShipmentOut(**result)


@fulfillment_router.get("/shipments/{shipment_id}", response_model=FulfillmentShipmentOut)
async def get_shipment_endpoint(
    shipment_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> FulfillmentShipmentOut:
    _require_enabled()
    from app.services.shipping_fulfillment import get_shipment
    result = get_shipment(shipment_id)
    return FulfillmentShipmentOut(**result)


@fulfillment_router.post("/shipments/{shipment_id}/ship", response_model=FulfillmentShipmentOut)
async def ship_shipment_endpoint(
    shipment_id: str,
    body: FulfillmentShipmentIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FulfillmentShipmentOut:
    _require_enabled()
    from app.services.shipping_fulfillment import ship_shipment
    result = ship_shipment(
        shipment_id,
        carrier=body.carrier,
        tracking_number=body.tracking_number,
        shipped_by=user.sub,
        service_level=body.service_level,
        notes=body.notes,
    )
    return FulfillmentShipmentOut(**result)


@fulfillment_router.post("/shipments/{shipment_id}/cancel", response_model=FulfillmentShipmentOut)
async def cancel_shipment_endpoint(
    shipment_id: str,
    reason: str = Query(""),
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FulfillmentShipmentOut:
    _require_enabled()
    from app.services.shipping_fulfillment import cancel_shipment
    result = cancel_shipment(shipment_id, cancelled_by=user.sub, reason=reason)
    return FulfillmentShipmentOut(**result)


@fulfillment_router.get("/shipments", response_model=ShipmentListOut)
async def list_shipments_endpoint(
    order_id: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Dict[str, Any] = Depends(require_ui_session),
) -> ShipmentListOut:
    _require_enabled()
    if order_id:
        from app.services.shipping_fulfillment import list_shipments_for_order
        result = list_shipments_for_order(order_id, cursor=cursor, limit=limit)
    else:
        result = {"shipments": [], "next_cursor": None}
    return ShipmentListOut(**result)
