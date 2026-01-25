from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.models import (
    ShoppingCartItemIn,
    ShoppingCartItemOut,
    ShoppingCartItemsOut,
    ShoppingCartPurchaseOut,
    ShoppingCartSummary,
    ShoppingCartTotalOut,
    ShoppingCartUpdateQtyIn,
)
from app.services.sessions import require_ui_session
from app.services.shoppingcart import (
    add_item,
    cart_total_cents,
    decrement_item,
    delete_cart,
    list_carts,
    list_items,
    purchase_cart,
    set_item_quantity,
    start_cart,
)

router = APIRouter(prefix="/ui/shoppingcart", tags=["shoppingcart"])


@router.get("/carts", response_model=list[ShoppingCartSummary])
async def ui_list_carts(ctx=Depends(require_ui_session)):
    return list_carts(ctx["user_sub"])


@router.post("/carts", response_model=ShoppingCartSummary)
async def ui_start_cart(ctx=Depends(require_ui_session)):
    return start_cart(ctx["user_sub"])


@router.delete("/carts/{cart_id}")
async def ui_delete_cart(cart_id: str, ctx=Depends(require_ui_session)):
    delete_cart(ctx["user_sub"], cart_id)
    return {"deleted": True}


@router.get("/carts/{cart_id}/items", response_model=ShoppingCartItemsOut)
async def ui_list_items(cart_id: str, ctx=Depends(require_ui_session)):
    items = list_items(ctx["user_sub"], cart_id)
    return {"cart_id": cart_id, "items": items}


@router.post("/carts/{cart_id}/items", response_model=ShoppingCartItemOut)
async def ui_add_item(cart_id: str, body: ShoppingCartItemIn, ctx=Depends(require_ui_session)):
    return add_item(ctx["user_sub"], cart_id, body.model_dump())


@router.patch("/carts/{cart_id}/items/{sku}", response_model=ShoppingCartItemOut | None)
async def ui_update_item_quantity(
    cart_id: str,
    sku: str,
    body: ShoppingCartUpdateQtyIn,
    ctx=Depends(require_ui_session),
):
    return set_item_quantity(ctx["user_sub"], cart_id, sku, body.quantity)


@router.delete("/carts/{cart_id}/items/{sku}")
async def ui_remove_item(
    cart_id: str,
    sku: str,
    decrement: int = Query(default=1, ge=1),
    ctx=Depends(require_ui_session),
):
    decrement_item(ctx["user_sub"], cart_id, sku, decrement)
    return {"deleted": True}


@router.get("/carts/{cart_id}/total", response_model=ShoppingCartTotalOut)
async def ui_cart_total(cart_id: str, ctx=Depends(require_ui_session)):
    total = cart_total_cents(ctx["user_sub"], cart_id)
    return {"cart_id": cart_id, "total_cents": total, "currency": "USD"}


@router.post("/carts/{cart_id}/purchase", response_model=ShoppingCartPurchaseOut)
async def ui_purchase_cart(cart_id: str, ctx=Depends(require_ui_session)):
    return purchase_cart(ctx["user_sub"], cart_id)
