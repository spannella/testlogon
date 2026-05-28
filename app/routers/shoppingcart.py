from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.models import (
    CartPurchaseIn,
    CatalogCartItemIn,
    ShoppingCartItemIn,
    ShoppingCartItemOut,
    ShoppingCartItemsOut,
    ShoppingCartPurchaseOut,
    ShoppingCartSummary,
    ShoppingCartTotalOut,
    ShoppingCartUpdateQtyIn,
)
from app.services.alerts import audit_event
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from app.services.sessions import require_ui_session
from app.services.shoppingcart import (
    add_item,
    add_catalog_item,
    cart_total_cents,
    decrement_item,
    delete_cart,
    get_abandonment_stats,
    list_carts,
    list_items,
    purchase_cart,
    scan_abandoned_carts,
    search_items,
    send_cart_reminder,
    set_item_quantity,
    start_cart,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/shoppingcart", tags=["shoppingcart"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])


@router.get("/carts", response_model=list[ShoppingCartSummary])
async def ui_list_carts(ctx=Depends(require_ui_session)):
    return list_carts(ctx["user_sub"])


@router.post("/carts", response_model=ShoppingCartSummary)
async def ui_start_cart(req: Request = None, ctx=Depends(require_ui_session)):
    cart = start_cart(ctx["user_sub"])
    audit_event("cart_started", ctx["user_sub"], req, outcome="success", cart_id=cart.get("cart_id"))
    return cart


@router.delete("/carts/{cart_id}")
async def ui_delete_cart(cart_id: str, req: Request = None, ctx=Depends(require_ui_session)):
    delete_cart(ctx["user_sub"], cart_id)
    audit_event("cart_deleted", ctx["user_sub"], req, outcome="success", cart_id=cart_id)
    return {"deleted": True}


@router.get("/carts/{cart_id}/items", response_model=ShoppingCartItemsOut)
async def ui_list_items(cart_id: str, ctx=Depends(require_ui_session)):
    items = list_items(ctx["user_sub"], cart_id)
    return {"cart_id": cart_id, "items": items}


@router.get("/carts/items/search")
async def ui_search_items(
    q: str = Query(..., min_length=1),
    ctx=Depends(require_ui_session),
    limit: int = Query(100, ge=1, le=200),
):
    items = search_items(ctx["user_sub"], q, limit)
    return {"items": items, "count": len(items)}


@router.post("/carts/{cart_id}/items", response_model=ShoppingCartItemOut)
async def ui_add_item(cart_id: str, body: ShoppingCartItemIn, req: Request = None, ctx=Depends(require_ui_session)):
    item = add_item(ctx["user_sub"], cart_id, body.model_dump())
    audit_event(
        "cart_item_added",
        ctx["user_sub"],
        req,
        outcome="success",
        cart_id=cart_id,
        sku=item.get("sku"),
        quantity=item.get("quantity"),
        unit_price_cents=item.get("unit_price_cents"),
    )
    return item


@router.post("/carts/{cart_id}/items/catalog", response_model=ShoppingCartItemOut)
async def ui_add_catalog_item(cart_id: str, body: CatalogCartItemIn, req: Request = None, ctx=Depends(require_ui_session)):
    item = add_catalog_item(
        ctx["user_sub"],
        cart_id,
        category_id=body.category_id,
        item_id=body.item_id,
        quantity=body.quantity,
    )
    audit_event(
        "cart_catalog_item_added",
        ctx["user_sub"],
        req,
        outcome="success",
        cart_id=cart_id,
        category_id=body.category_id,
        item_id=body.item_id,
        sku=item.get("sku"),
        quantity=item.get("quantity"),
    )
    return item


@router.patch("/carts/{cart_id}/items/{sku}", response_model=ShoppingCartItemOut | None)
async def ui_update_item_quantity(
    cart_id: str,
    sku: str,
    body: ShoppingCartUpdateQtyIn,
    req: Request = None,
    ctx=Depends(require_ui_session),
):
    item = set_item_quantity(ctx["user_sub"], cart_id, sku, body.quantity)
    audit_event(
        "cart_item_quantity_set",
        ctx["user_sub"],
        req,
        outcome="success",
        cart_id=cart_id,
        sku=sku,
        quantity=body.quantity,
    )
    return item


@router.delete("/carts/{cart_id}/items/{sku}")
async def ui_remove_item(
    cart_id: str,
    sku: str,
    decrement: int = Query(default=1, ge=1),
    req: Request = None,
    ctx=Depends(require_ui_session),
):
    decrement_item(ctx["user_sub"], cart_id, sku, decrement)
    audit_event(
        "cart_item_removed",
        ctx["user_sub"],
        req,
        outcome="success",
        cart_id=cart_id,
        sku=sku,
        decrement=decrement,
    )
    return {"deleted": True}


@router.get("/carts/{cart_id}/total", response_model=ShoppingCartTotalOut)
async def ui_cart_total(cart_id: str, ctx=Depends(require_ui_session)):
    total = cart_total_cents(ctx["user_sub"], cart_id)
    return {"cart_id": cart_id, "total_cents": total, "currency": "USD"}


@router.post("/carts/{cart_id}/purchase", response_model=ShoppingCartPurchaseOut)
async def ui_purchase_cart(
    cart_id: str,
    body: CartPurchaseIn = CartPurchaseIn(),
    req: Request = None,
    x_idempotency_key: str = Header(default="", alias="X-Idempotency-Key"),
    ctx=Depends(require_ui_session),
):
    idem = (x_idempotency_key or "").strip()
    if not idem:
        raise HTTPException(status_code=400, detail={"code": "idempotency_key_required", "message": "X-Idempotency-Key header required"})
    purchase = purchase_cart(
        ctx["user_sub"],
        cart_id,
        idempotency_key=idem,
        promo_code=body.promo_code,
        promo_code_id=body.promo_code_id,
    )
    audit_event(
        "cart_purchased",
        ctx["user_sub"],
        req,
        outcome="success",
        cart_id=cart_id,
        order_id=purchase.get("order_id"),
        purchased_total_cents=purchase.get("purchased_total_cents"),
        currency=purchase.get("currency"),
        purchase_txn_id=purchase.get("purchase_txn_id"),
    )
    return purchase


# ─── SHOP-003: Admin Cart Abandonment Stats ────────────────────────────────────


@router.get("/admin/cart-abandonment/stats")
async def ui_cart_abandonment_stats(user: AuthenticatedUser = Depends(require_admin_or_root)):
    return get_abandonment_stats()


@router.post("/admin/cart-abandonment/scan")
async def ui_cart_abandonment_scan(user: AuthenticatedUser = Depends(require_admin_or_root)):
    """Dev/admin endpoint to trigger cart abandonment scan manually."""
    threshold = S.cart_abandonment_threshold_hours
    carts = scan_abandoned_carts(threshold_hours=threshold)
    reminded = 0
    for cart in carts:
        try:
            send_cart_reminder(cart)
            reminded += 1
        except Exception:
            pass
    return {"scanned": len(carts), "reminded": reminded, "threshold_hours": threshold}


# ─── SHOP-003: Background Cart Abandonment Loop ───────────────────────────────


async def _cart_abandonment_loop() -> None:
    """Periodic background task to detect and remind about abandoned carts."""
    await asyncio.sleep(10)  # Initial delay to let other services start
    while True:
        if S.cart_abandonment_enabled:
            try:
                carts = scan_abandoned_carts(
                    threshold_hours=S.cart_abandonment_threshold_hours,
                )
                for cart in carts:
                    try:
                        send_cart_reminder(cart)
                    except Exception:
                        logger.warning(
                            "cart_reminder_failed",
                            extra={"cart_id": cart.get("cart_id")},
                        )
            except Exception:
                logger.exception("Cart abandonment check failed")
        await asyncio.sleep(S.cart_abandonment_scan_interval_sec)


def start_cart_abandonment_task() -> None:
    """Register the cart abandonment background loop as an async task."""
    if not S.cart_abandonment_enabled:
        logger.info("Cart abandonment detection disabled")
        return
    asyncio.create_task(_cart_abandonment_loop())
