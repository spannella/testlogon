from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from app.models import (
    PurchaseCancelReq,
    PurchaseCancelRespondReq,
    PurchaseShippingReq,
    PurchaseTransactionCreated,
    PurchaseTransactionIn,
    PurchaseTransactionInfo,
    PurchaseTransactionStatusReq,
    PurchaseTransactionSummary,
    ReceiptLinkOut,
)
from app.services.purchase_history import (
    create_transaction,
    get_transaction_info,
    list_events,
    list_transactions,
    confirm_received,
    mark_completed,
    mark_reverted,
    search_transactions,
    request_cancel,
    respond_cancel,
    update_shipping,
)
from app.services.carrier_tracking import build_tracking_url
from app.services.receipts import get_or_create_receipt
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/purchase-history", tags=["purchase-history"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])


@router.post("/transactions", response_model=PurchaseTransactionCreated)
async def ui_create_transaction(
    body: PurchaseTransactionIn,
    x_idempotency_key: str = Header(default="", alias="X-Idempotency-Key"),
    ctx=Depends(require_ui_session),
):
    idem = (x_idempotency_key or "").strip()
    if not idem:
        raise HTTPException(status_code=400, detail={"code": "idempotency_key_required", "message": "X-Idempotency-Key header required"})
    return create_transaction(ctx["user_sub"], body.model_dump(), idempotency_key=idem)


@router.get("/transactions", response_model=list[PurchaseTransactionSummary])
async def ui_list_transactions(
    ctx=Depends(require_ui_session),
    limit: int = Query(25, ge=1, le=100),
    status: str | None = Query(None),
):
    return list_transactions(ctx["user_sub"], limit, status)


@router.get("/transactions/search", response_model=list[PurchaseTransactionSummary])
async def ui_search_transactions(
    q: str = Query(..., min_length=1),
    ctx=Depends(require_ui_session),
    limit: int = Query(100, ge=1, le=200),
):
    return search_transactions(ctx["user_sub"], q, limit)


@router.get("/transactions/{txn_id}", response_model=PurchaseTransactionInfo)
async def ui_get_transaction(txn_id: str, ctx=Depends(require_ui_session)):
    return get_transaction_info(ctx["user_sub"], txn_id)


@router.put("/transactions/{txn_id}/shipping", response_model=PurchaseTransactionInfo)
async def ui_update_shipping(
    req: Request,
    txn_id: str,
    body: PurchaseShippingReq,
    ctx=Depends(require_ui_session),
):
    _ = req
    return update_shipping(ctx["user_sub"], txn_id, body.shipping.model_dump())


@router.post("/transactions/{txn_id}/confirm-received", response_model=PurchaseTransactionInfo)
async def ui_confirm_received(txn_id: str, ctx=Depends(require_ui_session)):
    """ECOMX-42 (B6): the buyer confirms delivery of THEIR order. Drives the order
    to completed + the txn to COMPLETED. Owner-scoped (the txn PK is the caller)."""
    return confirm_received(ctx["user_sub"], txn_id)


@router.post("/transactions/{txn_id}/complete", response_model=PurchaseTransactionInfo)
async def ui_mark_completed(
    txn_id: str,
    body: PurchaseTransactionStatusReq,
    ctx=Depends(require_ui_session),
):
    return mark_completed(ctx["user_sub"], txn_id, body.processor_ref, body.note)


@router.post("/transactions/{txn_id}/revert", response_model=PurchaseTransactionInfo)
async def ui_mark_reverted(
    txn_id: str,
    body: PurchaseTransactionStatusReq,
    ctx=Depends(require_ui_session),
):
    return mark_reverted(ctx["user_sub"], txn_id, body.reason)


@router.post("/transactions/{txn_id}/cancel/request", response_model=PurchaseTransactionInfo)
async def ui_request_cancel(
    txn_id: str,
    body: PurchaseCancelReq,
    ctx=Depends(require_ui_session),
):
    return request_cancel(ctx["user_sub"], txn_id, body.reason)


@router.post("/transactions/{txn_id}/cancel/respond", response_model=PurchaseTransactionInfo)
async def ui_respond_cancel(
    txn_id: str,
    body: PurchaseCancelRespondReq,
    ctx=Depends(require_ui_session),
):
    return respond_cancel(ctx["user_sub"], txn_id, body.decision, body.note)


@router.get("/transactions/{txn_id}/tracking")
async def ui_get_tracking(txn_id: str, ctx=Depends(require_ui_session)):
    info = get_transaction_info(ctx["user_sub"], txn_id)
    shipping = info.get("shipping") or {}
    carrier = shipping.get("carrier")
    tracking_number = shipping.get("tracking_number")
    if carrier and tracking_number:
        tracking_url = build_tracking_url(carrier, tracking_number)
        return {
            "txn_id": txn_id,
            "tracking_url": tracking_url,
            "carrier": carrier,
            "tracking_number": tracking_number,
            "status": shipping.get("status"),
            "carrier_events": shipping.get("carrier_events"),
            "estimated_delivery": shipping.get("estimated_delivery"),
            "delivered_at": shipping.get("delivered_at"),
        }
    # ECOMX-23: the cart-purchase path never wrote a `shipping` key on the txn —
    # the REAL tracking lives on the order's seller ship-group shipment_tracking
    # records (keyed by ship_group_id, not txn_id). Resolve the order off the txn
    # (external_ref/metadata.order_id) and return its FIRST shipment's tracking so
    # the buyer's txn-tracking view populates instead of the permanent-empty stub.
    order_id = str(info.get("external_ref") or (info.get("metadata") or {}).get("order_id") or "")
    if order_id:
        try:
            from app.services import order_fulfillment_bridge as _bridge
            agg = _bridge.order_tracking(order_id, buyer_sub=ctx["user_sub"])
            shipments = agg.get("shipments") or []
            primary = next((sh for sh in shipments if sh.get("tracking_number")), (shipments[0] if shipments else None))
            if primary:
                return {
                    "txn_id": txn_id,
                    "order_id": order_id,
                    "fulfillment_status": agg.get("fulfillment_status"),
                    "tracking_url": primary.get("tracking_url") or None,
                    "carrier": primary.get("carrier") or None,
                    "tracking_number": primary.get("tracking_number") or None,
                    "status": primary.get("status") or None,
                    "carrier_events": primary.get("events") or None,
                    "shipment_count": agg.get("shipment_count", 0),
                    "shipments": shipments,
                }
        except Exception:
            pass
    return {
        "txn_id": txn_id,
        "tracking_url": None,
        "carrier": None,
        "tracking_number": None,
        "status": None,
        "carrier_events": None,
    }


@router.get("/transactions/{txn_id}/events")
async def ui_list_events(
    txn_id: str,
    ctx=Depends(require_ui_session),
    limit: int = Query(50, ge=1, le=200),
):
    return {"txn_id": txn_id, "events": list_events(ctx["user_sub"], txn_id, limit)}


@router.get("/transactions/{txn_id}/receipt", response_model=ReceiptLinkOut)
async def ui_get_receipt(txn_id: str, ctx=Depends(require_ui_session)):
    return get_or_create_receipt(ctx["user_sub"], txn_id)
