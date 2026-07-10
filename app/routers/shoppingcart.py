from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.models import (
    CartAbandonmentSweepIn,
    CartAbandonmentSweepOut,
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
    expire_abandoned_carts,
    get_abandonment_stats,
    get_cart,
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
        broadcast_session_id=getattr(body, "broadcast_session_id", None),  # LIVECOM L3
        host_id=getattr(body, "host_id", None),
    )
    # ADV-403: attribute this purchase to the buyer's last ad click (explicit
    # ad_click_id or last-click 7d) and charge the CPA bid. Idempotent: a retried
    # purchase re-resolves the same (already-converted) click -> no double charge.
    try:
        from app.services.ad_attribution import attribute_conversion
        attribute_conversion(
            viewer_sub=ctx["user_sub"],
            conversion_type="purchase",
            conversion_value_cents=int(purchase.get("purchased_total_cents") or 0),
            ad_click_id=getattr(body, "ad_click_id", "") or "",
        )
    except Exception:
        pass
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


@router.post("/admin/cart-abandonment/scan", response_model=CartAbandonmentSweepOut)
async def ui_cart_abandonment_scan(
    body: CartAbandonmentSweepIn | None = None,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Admin/root endpoint to run an abandonment sweep manually.

    `now` is injectable so E2E can pin the clock and assert deterministically.
    When `expire` is set, also auto-expires long-abandoned carts.
    """
    body = body or CartAbandonmentSweepIn()
    threshold = body.threshold_hours if body.threshold_hours is not None else S.cart_abandonment_threshold_hours
    now = body.now

    carts = scan_abandoned_carts(threshold_hours=threshold, now=now)
    reminded = 0
    for cart in carts:
        try:
            send_cart_reminder(cart, now=now)
            reminded += 1
        except Exception:
            pass

    expired_count = 0
    if body.expire:
        expired = expire_abandoned_carts(expire_hours=body.expire_hours, now=now)
        expired_count = len(expired)

    return CartAbandonmentSweepOut(
        scanned=len(carts),
        reminded=reminded,
        expired=expired_count,
        threshold_hours=threshold,
    )


@router.get("/carts/{cart_id}/abandonment-status")
async def ui_cart_abandonment_status(cart_id: str, ctx=Depends(require_ui_session)):
    """Buyer-facing abandonment status for one of their own carts."""
    cart = get_cart(ctx["user_sub"], cart_id)
    return {
        "cart_id": cart_id,
        "status": cart.get("status"),
        "last_activity_at": int(cart.get("last_activity_at", 0) or 0),
        "abandoned_at": int(cart.get("abandoned_at", 0) or 0),
        "reminder_count": int(cart.get("reminder_count", 0) or 0),
        "is_abandoned": int(cart.get("abandoned_at", 0) or 0) > 0,
    }


# ─── GAP-0190: public one-time cart recovery link ────────────────────────────


@router.get("/recover/{token}")
async def ui_recover_cart(token: str):
    """Public endpoint: validate a one-time recovery token and redirect to the cart.

    No auth required — the signed token is the credential. Consumes the token
    (one-time-use) then redirects to the cart page with the cart pre-selected.
    """
    from app.services.cart_reminders import recover_cart

    result = recover_cart(token)
    cart_id = result.get("cart_id", "")
    return RedirectResponse(
        url=f"/cart?cartId={cart_id}&recovered=1",
        status_code=302,
    )


# ─── GAP-0191: cart-reminder opt-out preference ──────────────────────────────


class ReminderPreferenceIn(BaseModel):
    opted_out: bool


@router.get("/reminders/preferences")
async def ui_get_reminder_preference(ctx=Depends(require_ui_session)):
    """Return the authenticated user's cart-reminder opt-out preference."""
    from app.services.cart_reminders import get_reminder_preference

    return get_reminder_preference(ctx["user_sub"])


@router.put("/reminders/preferences")
async def ui_set_reminder_preference(
    body: ReminderPreferenceIn,
    req: Request = None,
    ctx=Depends(require_ui_session),
):
    """Set the authenticated user's cart-reminder opt-out preference."""
    from app.services.cart_reminders import set_reminder_preference

    result = set_reminder_preference(ctx["user_sub"], body.opted_out)
    audit_event(
        "cart_reminder_preference_updated",
        ctx["user_sub"],
        req,
        outcome="success",
        opted_out=body.opted_out,
    )
    return result


# ─── SHOP-003: Background Cart Abandonment Loop ───────────────────────────────


async def _cart_abandonment_loop() -> None:
    """Periodic background task to detect and remind about abandoned carts."""
    await asyncio.sleep(10)  # Initial delay to let other services start
    while True:
        if S.cart_abandonment_enabled:
            try:
                if S.cart_reminders_enabled:
                    # GAP-0189 / FIN-003: multi-stage reminder pipeline.
                    from app.services.cart_reminders import process_abandoned_carts

                    result = process_abandoned_carts()
                    logger.info("cart_abandonment_sweep", extra=result)
                else:
                    # Legacy single-blast fallback (CART_REMINDERS_ENABLED=0).
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
                # Auto-expire long-abandoned carts (best-effort)
                try:
                    expire_abandoned_carts()
                except Exception:
                    logger.exception("Cart auto-expire failed")
            except Exception:
                logger.exception("Cart abandonment check failed")
        await asyncio.sleep(S.cart_abandonment_scan_interval_sec)


def start_cart_abandonment_task() -> None:
    """Register the cart abandonment background loop as an async task."""
    if not S.cart_abandonment_enabled:
        logger.info("Cart abandonment detection disabled")
        return
    asyncio.create_task(_cart_abandonment_loop())
