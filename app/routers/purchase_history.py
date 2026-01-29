from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from app.models import (
    PurchaseCancelReq,
    PurchaseCancelRespondReq,
    PurchaseShippingReq,
    PurchaseTransactionCreated,
    PurchaseTransactionIn,
    PurchaseTransactionInfo,
    PurchaseTransactionStatusReq,
    PurchaseTransactionSummary,
)
from app.services.purchase_history import (
    create_transaction,
    get_transaction_info,
    list_events,
    list_transactions,
    mark_completed,
    mark_reverted,
    search_transactions,
    request_cancel,
    respond_cancel,
    update_shipping,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/purchase-history", tags=["purchase-history"])


@router.post("/transactions", response_model=PurchaseTransactionCreated)
async def ui_create_transaction(body: PurchaseTransactionIn, ctx=Depends(require_ui_session)):
    return create_transaction(ctx["user_sub"], body.model_dump())


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


@router.get("/transactions/{txn_id}/events")
async def ui_list_events(
    txn_id: str,
    ctx=Depends(require_ui_session),
    limit: int = Query(50, ge=1, le=200),
):
    return {"txn_id": txn_id, "events": list_events(ctx["user_sub"], txn_id, limit)}
