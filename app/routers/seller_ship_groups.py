"""ECOM-SELLER (G3) - seller-scoped sales / fulfilment router.

Mounted at ``/ui/seller/sales``. A NON-ADMIN authenticated seller lists + fetches
ONLY their own per-seller ship groups (with the buyer shipping address + real
line-item names) and advances the order-lifecycle state machine scoped to their
own group. A seller can never see another seller's items nor the buyer's payment
internals. All handlers 503 when ``S.order_lifecycle_enabled`` is off.

  GET  /ui/seller/sales                    -> SellerSaleListOut (caller's groups)
  GET  /ui/seller/sales/{ship_group_id}    -> SellerSaleOut     (404 if not caller's)
  POST /ui/seller/sales/{ship_group_id}/transition -> SellerSaleOut (scoped fulfil)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core.settings import S
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/seller/sales", tags=["seller-sales"])

# ECOMX-51: seller sales analytics (GMV / units / AOV / open-fulfilment / top item).
analytics_router = APIRouter(prefix="/ui/seller", tags=["seller-sales"])


def _require_enabled() -> None:
    if not S.order_lifecycle_enabled:
        raise HTTPException(
            status_code=503,
            detail={"code": "order_lifecycle_not_enabled", "message": "Order lifecycle is not enabled"},
        )


class SellerSaleLineItem(BaseModel):
    item_id: str = ""
    sku: str = ""
    name: str = ""
    quantity: int = 1
    unit_price_cents: int = 0
    line_total_cents: int = 0


class SellerSaleOut(BaseModel):
    ship_group_id: str
    order_id: str
    status: str
    allowed_transitions: List[str] = []
    buyer_name: str = ""
    buyer_email: str = ""
    ship_to: Dict[str, Any] = {}
    line_items: List[SellerSaleLineItem] = []
    item_count: int = 0
    subtotal_cents: int = 0
    currency: str = "USD"
    tracking_number: Optional[str] = None
    carrier: Optional[str] = None
    created_at: int = 0
    updated_at: int = 0


class SellerSaleListOut(BaseModel):
    sales: List[SellerSaleOut] = []
    next_cursor: Optional[str] = None


class SellerSaleTransitionIn(BaseModel):
    target_status: str
    reason: Optional[str] = None
    tracking_number: Optional[str] = None
    carrier: Optional[str] = None
    idempotency_key: Optional[str] = None


def _row_to_out(row: Dict[str, Any]) -> SellerSaleOut:
    from app.services import seller_ship_groups as ssg

    status = str(row.get("status") or "")
    return SellerSaleOut(
        ship_group_id=str(row.get("ship_group_id", "")),
        order_id=str(row.get("order_id", "")),
        status=status,
        allowed_transitions=ssg.allowed_transitions(status),
        buyer_name=str(row.get("buyer_name", "")),
        buyer_email=str(row.get("buyer_email", "")),
        ship_to=dict(row.get("ship_to") or {}),
        line_items=[SellerSaleLineItem(**{k: li.get(k) for k in SellerSaleLineItem.model_fields if li.get(k) is not None}) for li in (row.get("line_items") or [])],
        item_count=int(row.get("item_count", 0) or 0),
        subtotal_cents=int(row.get("subtotal_cents", 0) or 0),
        currency=str(row.get("currency", "USD")),
        tracking_number=(str(row["tracking_number"]) if row.get("tracking_number") else None),
        carrier=(str(row["carrier"]) if row.get("carrier") else None),
        created_at=int(row.get("created_at", 0) or 0),
        updated_at=int(row.get("updated_at", 0) or 0),
    )


@router.get("", response_model=SellerSaleListOut)
async def list_seller_sales(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> SellerSaleListOut:
    """List the authenticated seller's own ship groups (their received sales)."""
    _require_enabled()
    from app.services import seller_ship_groups as ssg

    rows, next_cursor = ssg.list_for_seller(ctx["user_sub"], limit=limit, cursor=cursor)
    return SellerSaleListOut(sales=[_row_to_out(r) for r in rows], next_cursor=next_cursor)


@router.get("/{ship_group_id}", response_model=SellerSaleOut)
async def get_seller_sale(
    ship_group_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> SellerSaleOut:
    """Fetch one of the seller's own ship groups (404 if not theirs)."""
    _require_enabled()
    from app.services import seller_ship_groups as ssg

    row = ssg.get_for_seller(ctx["user_sub"], ship_group_id)
    if not row:
        raise HTTPException(404, {"code": "ship_group_not_found"})
    return _row_to_out(row)


@router.post("/{ship_group_id}/transition", response_model=SellerSaleOut)
async def transition_seller_sale(
    ship_group_id: str,
    body: SellerSaleTransitionIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> SellerSaleOut:
    """Advance the seller's own ship group (e.g. approved->allocated->...->shipped)."""
    _require_enabled()
    from app.services import seller_ship_groups as ssg

    try:
        row = ssg.transition(
            ctx["user_sub"],
            ship_group_id,
            body.target_status,
            actor=ctx["user_sub"],
            tracking_number=body.tracking_number,
            carrier=body.carrier,
            idempotency_key=body.idempotency_key,
        )
    except ssg.ShipGroupNotFound:
        raise HTTPException(404, {"code": "ship_group_not_found"})
    except ssg.IllegalShipGroupTransition as exc:
        raise HTTPException(409, {"code": "illegal_transition", "detail": str(exc)})
    return _row_to_out(row)


class SellerTopItemOut(BaseModel):
    item_id: str = ""
    name: str = ""
    units: int = 0
    revenue_cents: int = 0


class SellerAnalyticsOut(BaseModel):
    gmv_cents: int = 0
    units: int = 0
    order_count: int = 0
    aov_cents: int = 0
    open_fulfilment_count: int = 0
    shipped_count: int = 0
    delivered_count: int = 0
    cancelled_or_returned_count: int = 0
    top_item: Optional[SellerTopItemOut] = None
    currency: str = "USD"


@analytics_router.get("/analytics", response_model=SellerAnalyticsOut)
async def get_seller_analytics(
    from_ts: int = Query(default=0, ge=0),
    to_ts: int = Query(default=0, ge=0),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> SellerAnalyticsOut:
    """ECOMX-51: month-to-date shop revenue + units + AOV + open-fulfilment count
    + top item for the authenticated seller (scoped to their OWN ship groups)."""
    _require_enabled()
    from app.services import seller_ship_groups as ssg

    data = ssg.seller_analytics(ctx["user_sub"], from_ts=from_ts, to_ts=to_ts)
    top = data.get("top_item")
    return SellerAnalyticsOut(
        gmv_cents=data["gmv_cents"],
        units=data["units"],
        order_count=data["order_count"],
        aov_cents=data["aov_cents"],
        open_fulfilment_count=data["open_fulfilment_count"],
        shipped_count=data["shipped_count"],
        delivered_count=data["delivered_count"],
        cancelled_or_returned_count=data["cancelled_or_returned_count"],
        top_item=(SellerTopItemOut(**top) if top else None),
        currency=data["currency"],
    )
