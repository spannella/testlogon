from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.models import FileBundleCheckoutSessionIn, UnifiedCheckoutSessionIn
from app.services.commerce_order_service import commerce_order_service
from app.services.commercial_line_items import from_direct_checkout_request, from_subscription_plan
from app.services.file_bundle_checkout import _load_file_bundle_sku, _parse_utc
from app.services.shoppingcart import _commercial_line_items_from_cart_items, get_cart, list_items


logger = logging.getLogger(__name__)

SOURCE_TO_ORDER_SOURCE = {
    "cart": "shopping_cart",
    "direct": "commercial_direct",
    "subscription_action": "subscription_cycle",
}


def _attribute_affiliate_conversion(afl_ref: Optional[str], order: Dict[str, Any]) -> None:
    """Attribute an affiliate conversion for a completed order.

    Bridges the gap between the ``afl_ref`` tracking cookie (captured at checkout
    time) and ``record_conversion``. Wrapped in try/except so attribution failure
    never aborts checkout. No-op when there is no tracking code.
    """
    if not afl_ref:
        return
    try:
        from app.services.affiliate_links import get_link_by_code, record_conversion

        link = get_link_by_code(afl_ref)
        if link and link.get("status") == "active":
            record_conversion(
                link_id=link["link_id"],
                order_id=str(order.get("order_id") or ""),
                amount_cents=int(order.get("amount_cents") or 0),
            )
    except Exception:
        logger.warning(
            "affiliate conversion attribution failed for order %s afl_ref %s",
            order.get("order_id"),
            afl_ref,
            exc_info=True,
        )


def _build_direct_line_items(body: UnifiedCheckoutSessionIn) -> List[Dict[str, Any]]:
    if not body.sku or not body.product_type or not body.billing_model:
        raise HTTPException(status_code=400, detail="direct checkout requires sku, product_type, and billing_model")
    line_item = from_direct_checkout_request(
        {
            "sku": body.sku,
            "product_type": body.product_type,
            "billing_model": body.billing_model,
            "quantity": int(body.quantity),
            "scope": dict(body.scope or {}),
            "pricing_ref": dict(body.pricing_ref or {}),
        }
    )
    return [line_item.model_dump()]


def _build_subscription_line_items(body: UnifiedCheckoutSessionIn) -> List[Dict[str, Any]]:
    if not isinstance(body.subscription_plan, dict):
        raise HTTPException(status_code=400, detail="subscription_action requires subscription_plan")
    line_item = from_subscription_plan(body.subscription_plan)
    return [line_item.model_dump()]


def _build_cart_line_items(user_id: str, body: UnifiedCheckoutSessionIn) -> List[Dict[str, Any]]:
    cart_id = str(body.cart_id or "").strip()
    if not cart_id:
        raise HTTPException(status_code=400, detail="cart source requires cart_id")
    cart = get_cart(user_id, cart_id)
    if cart.get("status") != "OPEN":
        raise HTTPException(status_code=409, detail="Cart is not open")
    cart_items = list_items(user_id, cart_id)
    if not cart_items:
        raise HTTPException(status_code=400, detail="Cart has no items")
    return _commercial_line_items_from_cart_items(cart_items, cart_id)


def create_unified_checkout_session(
    user_id: str,
    body: UnifiedCheckoutSessionIn,
    afl_ref: Optional[str] = None,
) -> Dict[str, Any]:
    source = str(body.source or "").strip()
    if source not in SOURCE_TO_ORDER_SOURCE:
        raise HTTPException(status_code=400, detail="invalid checkout source")

    if source == "cart":
        line_items = _build_cart_line_items(user_id, body)
        correlation_id = f"checkout_session:{user_id}:{body.cart_id}"
        metadata = {"cart_id": body.cart_id}
    elif source == "direct":
        line_items = _build_direct_line_items(body)
        correlation_id = f"checkout_session:{user_id}:direct:{body.sku}"
        metadata = {"sku": body.sku}
    else:
        line_items = _build_subscription_line_items(body)
        plan_id = (body.subscription_plan or {}).get("plan_id")
        correlation_id = f"checkout_session:{user_id}:subscription:{plan_id}"
        metadata = {"plan_id": plan_id}

    checkout_session_id = f"chk_{uuid.uuid4().hex}"
    order_metadata = {**metadata, "checkout_session_id": checkout_session_id}
    if afl_ref:
        order_metadata["afl_ref"] = afl_ref
    order = commerce_order_service.create_order_from_line_items(
        user_id=user_id,
        source_system=SOURCE_TO_ORDER_SOURCE[source],
        line_items=line_items,
        correlation_id=correlation_id,
        metadata=order_metadata,
    )

    _attribute_affiliate_conversion(afl_ref, order)

    return {
        "order_id": str(order.get("order_id") or ""),
        "checkout_session_id": checkout_session_id,
        "line_items": list(order.get("line_items") or []),
        "source": source,
        "status": str(order.get("status") or "pending_payment"),
    }


def create_file_bundle_checkout_via_unified(
    user_id: str,
    body: FileBundleCheckoutSessionIn,
    afl_ref: Optional[str] = None,
) -> Dict[str, Any]:
    sku = _load_file_bundle_sku(body.sku)
    req_start = _parse_utc(body.date_start, "date_start")
    req_end = _parse_utc(body.date_end, "date_end")
    if req_end <= req_start:
        raise HTTPException(400, "date_end must be after date_start")

    sku_start = _parse_utc(str(sku.get("date_start") or ""), "sku.date_start")
    sku_end = _parse_utc(str(sku.get("date_end") or ""), "sku.date_end")
    if req_start < sku_start or req_end > sku_end:
        raise HTTPException(400, "Requested date range must be within SKU date window")

    access_mode = str(body.access_mode)
    if access_mode != str(sku.get("access_mode")):
        raise HTTPException(400, "Requested access_mode does not match SKU configuration")

    normalized = create_unified_checkout_session(
        user_id,
        UnifiedCheckoutSessionIn(
            source="direct",
            sku=str(sku.get("sku") or body.sku),
            product_type="file_bundle",
            billing_model="rental" if access_mode == "rental" else "one_time",
            quantity=1,
            scope={
                "selection_type": "date_range",
                "date_start": req_start.isoformat(),
                "date_end": req_end.isoformat(),
                "access_mode": access_mode,
            },
            pricing_ref={
                "currency": str(sku.get("currency") or "USD"),
                "amount_cents": int(sku.get("amount_cents") or 0),
            },
        ),
        afl_ref=afl_ref,
    )

    return {
        "checkout_session_id": normalized["checkout_session_id"],
        "order_id": normalized["order_id"],
        "status": normalized["status"],
        "sku": str(sku.get("sku") or body.sku),
        "amount_cents": int(sku.get("amount_cents") or 0),
        "currency": str(sku.get("currency") or "USD"),
        "access_mode": access_mode,
    }
