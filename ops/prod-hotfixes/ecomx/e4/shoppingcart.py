from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.services.catalog_commercialization import _validate_product_version
from app.services.commerce_entitlement_orchestrator import CommerceEntitlementOrchestrator
from app.services.commerce_order_service import commerce_order_service
from app.services.commercial_line_items import from_shopping_cart_item
from app.services.profile import get_profile
from app.services.purchase_history import record_cart_purchase


commerce_entitlement_orchestrator = CommerceEntitlementOrchestrator()

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_cart_payment_method(user_sub: str, explicit_pm: Optional[str]) -> Optional[str]:
    """ECOMX-10: resolve + validate the buyer PM for a cart checkout, ONCE.

    Fallback chain: explicit -> the buyer's billing `default_payment_method_id`
    -> blank. A resolved (non-blank) PM is validated to belong to the buyer.
    A blank result is tolerated only in dev_mode (the stripe-mock ledger-only
    stub stands in for a processor charge, exactly as billing.py tolerates);
    outside dev_mode a blank PM raises 402 no_payment_method so checkout never
    writes an order for a buyer with no way to pay.
    """
    from app.services.billing_shared import ddb_get, user_pk as _user_pk_billing, ddb_query_pk

    pm = explicit_pm
    if not pm:
        billing = ddb_get(T.billing, _user_pk_billing(user_sub), "BILLING") or {}
        pm = billing.get("default_payment_method_id")
    if not pm:
        if S.dev_mode:
            return None
        raise HTTPException(402, {"code": "no_payment_method",
                                  "message": "No payment method on file for checkout."})
    items = ddb_query_pk(T.billing, _user_pk_billing(user_sub))
    pm_ids = {
        it["payment_method_id"]
        for it in items
        if str(it.get("sk", "")).startswith("PM#") and "payment_method_id" in it
    }
    if pm not in pm_ids:
        raise HTTPException(402, {"code": "no_payment_method", "message": "Payment method not found."})
    return pm


def _charge_cart_payment_intent(
    *,
    buyer_sub: str,
    amount_cents: int,
    currency: str,
    payment_method_id: Optional[str],
    order_id: str,
    cart_id: str,
    idempotency_key: str,
) -> Optional[str]:
    """ECOMX-10: real stripe-mock charge for a cart checkout, mirroring
    tips._charge_tip_payment_intent / billing.charge_once.

    Returns the PaymentIntent id on a successful charge, or None for the dev
    stub path (Stripe not configured, or a blank PM tolerated in dev_mode) —
    exactly the cases billing.py already tolerates.

    On a declined card, any Stripe error, or a non-succeeded terminal status
    this raises HTTPException(402, payment_failed) so the CALLER never marks the
    cart PURCHASED / order paid — NO order is completed for a failed charge. The
    idempotency_key (the canonical per-cart key) is threaded into the
    PaymentIntent so a double-submit never double-charges at the processor.
    """
    if amount_cents <= 0:
        # Free order (100% promo / zero-priced) — no processor charge needed.
        return None
    if not getattr(S, "stripe_secret_key", "") or not payment_method_id:
        return None

    from app.routers.billing import ensure_stripe_configured, get_or_create_customer
    import stripe

    ensure_stripe_configured()
    customer_id = get_or_create_customer(buyer_sub)
    try:
        pi = stripe.PaymentIntent.create(
            amount=int(amount_cents),
            currency=(currency or "usd").lower(),
            customer=customer_id,
            payment_method=payment_method_id,
            off_session=True,
            confirm=True,
            description=f"Shop checkout (cart {cart_id})",
            metadata={
                "app_user_id": buyer_sub,
                "purpose": "shop_checkout",
                "order_id": order_id,
                "cart_id": cart_id,
            },
            idempotency_key=(idempotency_key or None),
        )
    except stripe.error.CardError as exc:
        logger.info("cart charge declined for buyer=%s cart=%s: %s", buyer_sub, cart_id, exc)
        raise HTTPException(402, {"code": "payment_failed", "message": str(exc)})
    except stripe.error.StripeError as exc:
        logger.warning("cart charge stripe error for buyer=%s cart=%s: %s", buyer_sub, cart_id, exc)
        raise HTTPException(402, {"code": "payment_failed",
                                  "message": "Checkout charge failed at the payment processor."})

    status = (pi.get("status") or "").lower()
    charged_ok = status == "succeeded" or (
        bool(getattr(S, "stripe_api_base", "")) and status not in ("canceled", "payment_failed")
    )
    if not charged_ok:
        raise HTTPException(402, {"code": "payment_failed",
                                  "message": f"Checkout charge did not succeed (status={status})."})
    return pi.get("id")


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _cart_sk(cart_id: str) -> str:
    return f"CART#{cart_id}"


def _item_sk(cart_id: str, sku: str) -> str:
    return f"CART#{cart_id}#ITEM#{sku}"


def _catalog_item_key(category_id: str, item_id: str) -> Dict[str, str]:
    return {"PK": f"CAT#{category_id}", "SK": f"ITEM#{item_id}"}


def _ddb_int(value: Any) -> int:
    if isinstance(value, Decimal):
        return int(value)
    return int(value)


def _cart_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "cart_id": item.get("cart_id"),
        "status": item.get("status"),
        "created_at": item.get("created_at"),
        "purchased_at": item.get("purchased_at"),
        "purchased_total_cents": _ddb_int(item["purchased_total_cents"]) if item.get("purchased_total_cents") is not None else None,
        "currency": item.get("currency", "USD"),
        # SHOP-003: Abandonment tracking fields
        "last_activity_at": _ddb_int(item.get("last_activity_at", 0)),
        "abandoned_at": _ddb_int(item.get("abandoned_at", 0)),
        "reminder_count": _ddb_int(item.get("reminder_count", 0)),
    }


def _touch_cart_activity(user_sub: str, cart_id: str) -> None:
    """Update last_activity_at and TTL on the parent cart record (SHOP-003)."""
    ts = int(datetime.now(timezone.utc).timestamp())
    ttl_epoch = ts + (S.cart_ttl_days * 86400)
    T.shopping_cart.update_item(
        Key={"PK": _user_pk(user_sub), "SK": _cart_sk(cart_id)},
        UpdateExpression="SET last_activity_at = :ts, #ttl = :ttl",
        ExpressionAttributeNames={"#ttl": "ttl"},
        ExpressionAttributeValues={":ts": ts, ":ttl": ttl_epoch},
    )


def _item_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    qty = _ddb_int(item.get("quantity", 0))
    unit = _ddb_int(item.get("unit_price_cents", 0))
    out: Dict[str, Any] = {
        "sku": item.get("sku"),
        "name": item.get("name"),
        "quantity": qty,
        "unit_price_cents": unit,
        "line_total_cents": qty * unit,
        "updated_at": item.get("updated_at"),
    }
    if item.get("image_url"):
        out["image_url"] = item["image_url"]
    if item.get("category_id"):
        out["category_id"] = item["category_id"]
    if item.get("item_id"):
        out["item_id"] = item["item_id"]
    if item.get("creator_user_id"):
        out["creator_user_id"] = item["creator_user_id"]
    if item.get("product_type"):
        out["product_type"] = item.get("product_type")
        out["scope"] = dict(item.get("scope") or {})
        out["access_mode"] = item.get("access_mode")
        out["rental_metadata"] = dict(item.get("rental_metadata") or {})
        out["entitlement_template_metadata"] = dict(item.get("entitlement_template_metadata") or {})
    return out


def _normalize_commercial_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(payload)
    out["scope"] = dict(payload.get("scope") or {})
    out["rental_metadata"] = dict(payload.get("rental_metadata") or {})
    out["entitlement_template_metadata"] = dict(payload.get("entitlement_template_metadata") or {})
    return out


def _validate_commercial_item_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    product_type = str(payload.get("product_type") or "").strip()
    if not product_type:
        return payload
    if product_type not in {"file_bundle", "api_package", "internal_api_package"}:
        raise HTTPException(status_code=422, detail="invalid product_type for cart item")

    normalized = _normalize_commercial_payload(payload)
    config: Dict[str, Any]
    if product_type == "file_bundle":
        scope = normalized["scope"]
        access_mode = str(normalized.get("access_mode") or scope.get("access_mode") or "").strip()
        rental_hours = int((normalized["rental_metadata"] or {}).get("rental_duration_hours") or 0)
        config = {
            "selection_type": scope.get("selection_type"),
            "date_start": scope.get("date_start"),
            "date_end": scope.get("date_end"),
            "access_mode": access_mode,
        }
        if rental_hours > 0:
            config["rental_duration_hours"] = rental_hours
        normalized["access_mode"] = access_mode or None
    else:
        config = normalized["entitlement_template_metadata"]

    billing_model = str(normalized.get("billing_model") or "one_time")
    if product_type == "file_bundle" and normalized.get("access_mode") == "rental":
        billing_model = "rental"
    if product_type in {"api_package", "internal_api_package"} and billing_model == "one_time":
        billing_model = "subscription"

    try:
        _validate_product_version(
            {
                "sku": normalized.get("sku"),
                "product_type": product_type,
                "display_name": normalized.get("name") or normalized.get("sku"),
                "billing_model": billing_model,
                "effective_at": int(datetime.now(timezone.utc).timestamp()),
                "currency": payload.get("currency") or "USD",
                "amount": int(payload.get("unit_price_cents") or 0),
                "config": config,
            }
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid commercialization cart item: {exc}") from exc

    return normalized


def _search_tokens(text: str) -> List[str]:
    return [t for t in re.findall(r"[a-z0-9@._-]+", (text or "").lower()) if t]


def _item_haystack(item: Dict[str, Any]) -> str:
    return " ".join(
        [
            str(item.get("sku", "")),
            str(item.get("name", "")),
            str(item.get("cart_id", "")),
        ]
    ).lower()


def _item_matches(query_tokens: List[str], item: Dict[str, Any]) -> bool:
    if not query_tokens:
        return False
    haystack = _item_haystack(item)
    return all(token in haystack for token in query_tokens)


def _item_search_out(item: Dict[str, Any]) -> Dict[str, Any]:
    out = _item_from_item(item)
    out["cart_id"] = item.get("cart_id")
    return out




def _cart_purchase_idempotency_key(user_sub: str, cart_id: str) -> str:
    return f"cart_purchase:{user_sub}:{cart_id}"


def _commercial_line_items_from_cart_items(items: List[Dict[str, Any]], cart_id: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in items:
        if item.get("product_type"):
            normalized = from_shopping_cart_item({
                **item,
                "cart_id": cart_id,
                "currency": "USD",
            })
            out.append(normalized.model_dump())
            continue

        fallback = from_shopping_cart_item(
            {
                "sku": item.get("sku"),
                "quantity": int(item.get("quantity") or 1),
                "unit_price_cents": int(item.get("unit_price_cents") or 0),
                "cart_id": cart_id,
                "currency": "USD",
                "product_type": "internal_api_package",
                "billing_model": "one_time",
                "scope": dict(item.get("scope") or {}),
            }
        )
        out.append(fallback.model_dump())
    return out

def _buyer_snapshot(profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    buyer = {
        "display_name": profile.get("display_name"),
        "displayed_email": profile.get("displayed_email"),
        "displayed_telephone_number": profile.get("displayed_telephone_number"),
        "mailing_address": profile.get("mailing_address"),
    }
    if not any(buyer.values()):
        return None
    return buyer


def get_cart(user_sub: str, cart_id: str) -> Dict[str, Any]:
    resp = T.shopping_cart.get_item(Key={"PK": _user_pk(user_sub), "SK": _cart_sk(cart_id)})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Cart not found")
    return item


def list_carts(user_sub: str) -> List[Dict[str, Any]]:
    pk = _user_pk(user_sub)
    resp = T.shopping_cart.query(
        KeyConditionExpression=Key("PK").eq(pk) & Key("SK").begins_with("CART#"),
    )
    items = [item for item in resp.get("Items", []) if item.get("type") == "cart"]
    carts = [_cart_from_item(item) for item in items]
    carts.sort(key=lambda c: c.get("created_at", ""), reverse=True)
    return carts


def start_cart(user_sub: str) -> Dict[str, Any]:
    cart_id = uuid.uuid4().hex
    now = _now_iso()
    ts = int(datetime.now(timezone.utc).timestamp())
    ttl_epoch = ts + (S.cart_ttl_days * 86400)
    item = {
        "PK": _user_pk(user_sub),
        "SK": _cart_sk(cart_id),
        "type": "cart",
        "cart_id": cart_id,
        "status": "OPEN",
        "created_at": now,
        "last_activity_at": ts,
        "reminder_count": 0,
        "currency": "USD",
        "ttl": ttl_epoch,
    }
    T.shopping_cart.put_item(Item=item)
    return _cart_from_item(item)


def list_items(user_sub: str, cart_id: str) -> List[Dict[str, Any]]:
    pk = _user_pk(user_sub)
    prefix = f"CART#{cart_id}#ITEM#"
    resp = T.shopping_cart.query(
        KeyConditionExpression=Key("PK").eq(pk) & Key("SK").begins_with(prefix),
    )
    items = [_item_from_item(item) for item in resp.get("Items", [])]
    items.sort(key=lambda item: item.get("sku") or "")
    return items


def search_items(user_sub: str, query: str, limit: int) -> List[Dict[str, Any]]:
    tokens = _search_tokens(query)
    if not tokens:
        return []
    pk = _user_pk(user_sub)
    resp = T.shopping_cart.query(
        KeyConditionExpression=Key("PK").eq(pk) & Key("SK").begins_with("CART#"),
    )
    items = [item for item in resp.get("Items", []) if item.get("type") == "item"]
    matches = [item for item in items if _item_matches(tokens, item)]
    return [_item_search_out(item) for item in matches[:limit]]


def cart_total_cents(user_sub: str, cart_id: str) -> int:
    items = list_items(user_sub, cart_id)
    return sum(item.get("line_total_cents", 0) for item in items)


def _require_open_cart(cart: Dict[str, Any]) -> None:
    if cart.get("status") != "OPEN":
        raise HTTPException(status_code=409, detail="Cart is not open")


# --- ECM-008: soft inventory reservations on cart mutations. All lazy + best-
# effort + fully flag-gated inside store_integration (no-op unless both the ECM
# sub-flag and inventory_reservations_enabled are on) — a reservation hiccup must
# NEVER block a cart add / delete / purchase. ---
def _ecm_reserve(user_sub: str, cart_id: str, sku: str, quantity: int) -> None:
    try:
        from app.services import store_integration
        store_integration.reserve_for_cart(user_sub=user_sub, cart_id=cart_id, sku=sku, quantity=int(quantity))
    except Exception:
        pass


def _ecm_release(user_sub: str, cart_id: str) -> None:
    try:
        from app.services import store_integration
        store_integration.release_cart_reservations(user_sub=user_sub, cart_id=cart_id)
    except Exception:
        pass


def _ecm_commit(user_sub: str, cart_id: str) -> None:
    try:
        from app.services import store_integration
        store_integration.commit_cart_reservations(user_sub=user_sub, cart_id=cart_id)
    except Exception:
        pass


def add_item(user_sub: str, cart_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    cart = get_cart(user_sub, cart_id)
    _require_open_cart(cart)

    sku = payload["sku"]
    key = {"PK": _user_pk(user_sub), "SK": _item_sk(cart_id, sku)}
    existing = T.shopping_cart.get_item(Key=key).get("Item")
    now = _now_iso()
    if existing:
        new_qty = _ddb_int(existing.get("quantity", 0)) + int(payload.get("quantity", 1))
        updated = _validate_commercial_item_payload(
            {
                **existing,
                **payload,
                "quantity": new_qty,
                "name": payload.get("name", existing.get("name")),
                "unit_price_cents": int(payload.get("unit_price_cents", existing.get("unit_price_cents", 0))),
                "updated_at": now,
            }
        )
        updated = {
            **existing,
            **updated,
        }
        T.shopping_cart.put_item(Item=updated)
        _touch_cart_activity(user_sub, cart_id)
        _ecm_reserve(user_sub, cart_id, sku, new_qty)
        return _item_from_item(updated)

    item = _validate_commercial_item_payload(
        {
        "PK": _user_pk(user_sub),
        "SK": _item_sk(cart_id, sku),
        "type": "item",
        "cart_id": cart_id,
        "sku": sku,
        "name": payload["name"],
        "quantity": int(payload.get("quantity", 1)),
        "unit_price_cents": int(payload.get("unit_price_cents", 0)),
        "updated_at": now,
        "product_type": payload.get("product_type"),
        "scope": payload.get("scope"),
        "access_mode": payload.get("access_mode"),
        "rental_metadata": payload.get("rental_metadata"),
        "entitlement_template_metadata": payload.get("entitlement_template_metadata"),
        }
    )
    if payload.get("image_url"):
        item["image_url"] = payload["image_url"]
    if payload.get("category_id"):
        item["category_id"] = payload["category_id"]
    if payload.get("item_id"):
        item["item_id"] = payload["item_id"]
    if payload.get("creator_user_id"):
        item["creator_user_id"] = payload["creator_user_id"]
    elif payload.get("item_id") and payload.get("category_id"):
        # ECOM fix: enrich creator_user_id from the catalog so seller-credit fires for
        # clients (the Android app) that add via POST /items without a creator field.
        try:
            _cat_it = T.catalog.get_item(
                Key=_catalog_item_key(payload["category_id"], payload["item_id"])
            ).get("Item")
            if _cat_it and _cat_it.get("creator_id"):
                item["creator_user_id"] = _cat_it["creator_id"]
        except Exception:
            pass
    T.shopping_cart.put_item(Item=item)
    _touch_cart_activity(user_sub, cart_id)
    _ecm_reserve(user_sub, cart_id, sku, int(payload.get("quantity", 1)))
    return _item_from_item(item)


def add_catalog_item(
    user_sub: str,
    cart_id: str,
    *,
    category_id: str,
    item_id: str,
    quantity: int = 1,
) -> Dict[str, Any]:
    cart = get_cart(user_sub, cart_id)
    _require_open_cart(cart)

    resp = T.catalog.get_item(Key=_catalog_item_key(category_id, item_id))
    item = resp.get("Item")
    if not item or item.get("entity") != "item":
        raise HTTPException(status_code=404, detail="Catalog item not found")

    currency = item.get("currency", "USD")
    if cart.get("currency") and cart.get("currency") != currency:
        raise HTTPException(status_code=409, detail="Cart currency mismatch")

    payload = {
        "sku": f"catalog:{item_id}",
        "name": item.get("name", "Catalog item"),
        "quantity": quantity,
        "unit_price_cents": int(item.get("price_cents", 0)),
        "creator_user_id": item.get("creator_id"),
        "category_id": category_id,
        "item_id": item_id,
    }
    return add_item(user_sub, cart_id, payload)


def set_item_quantity(user_sub: str, cart_id: str, sku: str, quantity: int) -> Optional[Dict[str, Any]]:
    cart = get_cart(user_sub, cart_id)
    _require_open_cart(cart)

    key = {"PK": _user_pk(user_sub), "SK": _item_sk(cart_id, sku)}
    existing = T.shopping_cart.get_item(Key=key).get("Item")
    if not existing:
        raise HTTPException(status_code=404, detail="Item not found")

    if quantity <= 0:
        T.shopping_cart.delete_item(Key=key)
        _touch_cart_activity(user_sub, cart_id)
        return None

    updated = {
        **existing,
        "quantity": quantity,
        "updated_at": _now_iso(),
    }
    T.shopping_cart.put_item(Item=updated)
    _touch_cart_activity(user_sub, cart_id)
    return _item_from_item(updated)


def decrement_item(user_sub: str, cart_id: str, sku: str, amount: int) -> None:
    cart = get_cart(user_sub, cart_id)
    _require_open_cart(cart)

    key = {"PK": _user_pk(user_sub), "SK": _item_sk(cart_id, sku)}
    existing = T.shopping_cart.get_item(Key=key).get("Item")
    if not existing:
        raise HTTPException(status_code=404, detail="Item not found")

    new_qty = _ddb_int(existing.get("quantity", 0)) - amount
    if new_qty <= 0:
        T.shopping_cart.delete_item(Key=key)
        _touch_cart_activity(user_sub, cart_id)
        return

    updated = {
        **existing,
        "quantity": new_qty,
        "updated_at": _now_iso(),
    }
    T.shopping_cart.put_item(Item=updated)
    _touch_cart_activity(user_sub, cart_id)


def delete_cart(user_sub: str, cart_id: str) -> None:
    cart = get_cart(user_sub, cart_id)
    pk = _user_pk(user_sub)
    prefix = f"CART#{cart_id}#ITEM#"
    resp = T.shopping_cart.query(
        KeyConditionExpression=Key("PK").eq(pk) & Key("SK").begins_with(prefix),
    )
    with T.shopping_cart.batch_writer() as batch:
        for item in resp.get("Items", []):
            batch.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})
        batch.delete_item(Key={"PK": cart["PK"], "SK": cart["SK"]})
    # ECM-008: release any soft inventory holds the cart was carrying.
    _ecm_release(user_sub, cart_id)


def _resolve_cart_creator(items: List[Dict[str, Any]]) -> Optional[str]:
    """Return the single creator_user_id if all items are from the same creator.
    Returns None if mixed or no creator info."""
    creators = set()
    for item in items:
        cid = item.get("creator_user_id") or item.get("seller_id")
        if cid:
            creators.add(cid)
    if len(creators) == 1:
        return creators.pop()
    return None


def purchase_cart(
    user_sub: str,
    cart_id: str,
    *,
    idempotency_key: str | None = None,
    promo_code: str | None = None,
    promo_code_id: str | None = None,
    broadcast_session_id: str | None = None,  # LIVECOM L3
    host_id: str | None = None,
    address_id: str | None = None,  # ECOMX-40 (B3): checkout shipping address
    shipping_method: str | None = None,  # ECOMX-40: chosen shipping method code
) -> Dict[str, Any]:
    cart = get_cart(user_sub, cart_id)
    if cart.get("status") == "PURCHASED":
        return {
            "cart_id": cart_id,
            "order_id": str(cart.get("last_order_id") or ""),
            "purchased_at": str(cart.get("purchased_at") or ""),
            "purchased_total_cents": int(cart.get("purchased_total_cents") or 0),
            "currency": cart.get("currency", "USD"),
            "buyer": cart.get("buyer_profile"),
            "purchase_txn_id": cart.get("purchase_txn_id"),
        }
    _require_open_cart(cart)

    items = list_items(user_sub, cart_id)
    total_cents = sum(item.get("line_total_cents", 0) for item in items)

    # ── SHOP-001: Stock validation + atomic decrement ──
    decremented_stock: List[Dict[str, Any]] = []
    for cart_item in items:
        cat_id = cart_item.get("category_id")
        ci_item_id = cart_item.get("item_id")
        if not cat_id or not ci_item_id:
            continue
        catalog_key = _catalog_item_key(cat_id, ci_item_id)
        catalog_resp = T.catalog.get_item(Key=catalog_key)
        catalog_item = catalog_resp.get("Item")
        if not catalog_item:
            continue
        sc = catalog_item.get("stock_count")
        if sc is None:
            continue  # unlimited stock — skip
        qty = int(cart_item.get("quantity", 1))
        try:
            T.catalog.update_item(
                Key=catalog_key,
                UpdateExpression="SET stock_count = stock_count - :qty, stock_updated_at = :now",
                ConditionExpression="stock_count >= :qty",
                ExpressionAttributeValues={":qty": qty, ":now": _now_iso()},
            )
            decremented_stock.append({"cat_id": cat_id, "item_id": ci_item_id, "qty": qty})
        except ClientError as exc:
            if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
                for prev in decremented_stock:
                    try:
                        T.catalog.update_item(
                            Key=_catalog_item_key(prev["cat_id"], prev["item_id"]),
                            UpdateExpression="SET stock_count = stock_count + :qty",
                            ExpressionAttributeValues={":qty": prev["qty"]},
                        )
                    except Exception:
                        pass
                item_name = cart_item.get("name", ci_item_id)
                raise HTTPException(
                    status_code=409,
                    detail=f"Item '{item_name}' is out of stock",
                ) from exc
            raise

    now = _now_iso()
    buyer = _buyer_snapshot(get_profile(user_sub))
    canonical_idempotency_key = _cart_purchase_idempotency_key(user_sub, cart_id)
    request_idempotency_key = str(idempotency_key or "").strip()

    # ── SHOP-002: Promo code validation and discount ──
    discount_cents = 0
    resolved_promo: Optional[Dict[str, Any]] = None
    original_total_cents = total_cents

    if promo_code or promo_code_id:
        from app.services.promo_codes import validate_promo_code, get_promo_code

        # Resolve creator from cart items
        creator_id = _resolve_cart_creator(items)
        if not creator_id:
            # If items have no creator info, use the buyer's own id as fallback
            # (for self-created catalog items)
            creator_id = user_sub

        code_str = promo_code
        if not code_str and promo_code_id:
            promo_item = get_promo_code(promo_code_id)
            code_str = promo_item.get("code") if promo_item else None

        if code_str:
            result = validate_promo_code(
                code=code_str,
                user_id=user_sub,
                checkout_type="shop",
                item_price_cents=total_cents,
                creator_user_id=creator_id,
            )
            if not result["valid"]:
                raise HTTPException(422, result["message"] or "Invalid promo code")
            discount_cents = result["discount_cents"]
            resolved_promo = result

    subtotal_after_discount = max(0, total_cents - discount_cents)

    # ── ECOMX-40 (A7/B3): shipping + sales tax on a PHYSICAL order. ──────────
    # A physical order = >=1 line item from a seller other than the buyer (self-
    # purchases / digital-only carts collect neither shipping nor tax). When a
    # shipping address was selected we resolve it (its zip drives the rate quote),
    # add a shipping fee (rate engine when enabled+seeded, else the flat default)
    # and a sales-tax line (tax_bps on the post-discount subtotal). The components
    # are threaded onto the order + txn + charge so the buyer's quoted total ==
    # the amount actually charged (ECOMX-10).
    shipping_cents = 0
    tax_cents = 0
    ship_to_snapshot: Optional[Dict[str, Any]] = None
    _is_physical = any(
        (ci.get("creator_user_id") or ci.get("seller_id"))
        and (ci.get("creator_user_id") or ci.get("seller_id")) != user_sub
        for ci in items
    )
    if getattr(S, "checkout_shipping_tax_enabled", False) and _is_physical and address_id:
        try:
            from app.services.addresses import get_address as _get_address
            ship_to_snapshot = _get_address(user_sub, address_id)
        except Exception:
            ship_to_snapshot = None
        if ship_to_snapshot:
            # shipping fee: prefer the rate engine, fall back to the flat default.
            shipping_cents = int(getattr(S, "checkout_flat_shipping_cents", 0) or 0)
            try:
                if getattr(S, "shipping_rate_estimation_enabled", False):
                    from app.services.shipping_rates import estimate_rates_for_line_items as _est
                    _dest = {
                        "postal_code": ship_to_snapshot.get("postal_code")
                        or ship_to_snapshot.get("zip") or "",
                    }
                    _li = [
                        {"quantity": int(ci.get("quantity", 1) or 1),
                         "weight_oz": ci.get("weight_oz")}
                        for ci in items
                    ]
                    _quote = _est(destination=_dest, line_items=_li, user_sub=user_sub)
                    _opts = _quote.get("options") or []
                    _chosen = None
                    if shipping_method:
                        _chosen = next(
                            (o for o in _opts if o.get("method_code") == shipping_method), None
                        )
                    _chosen = _chosen or (_opts[0] if _opts else None)
                    if _chosen and _chosen.get("rate_cents") is not None:
                        shipping_cents = int(_chosen.get("rate_cents") or 0)
            except Exception:
                logger.exception("shipping rate estimate failed cart=%s; using flat default", cart_id)
            # sales tax on the post-discount merchandise subtotal (not on shipping).
            _tax_bps = int(getattr(S, "checkout_tax_bps", 0) or 0)
            tax_cents = int(round(subtotal_after_discount * _tax_bps / 10000))

    final_total = subtotal_after_discount + shipping_cents + tax_cents

    line_items = _commercial_line_items_from_cart_items(items, cart_id)
    order = commerce_order_service.create_order_from_line_items(
        user_id=user_sub,
        source_system="shopping_cart",
        correlation_id=canonical_idempotency_key,
        line_items=line_items,
        metadata={
            "cart_id": cart_id,
            "broadcast_session_id": broadcast_session_id,  # LIVECOM L3
            "host_id": host_id,
            "is_stream_attributed": bool(broadcast_session_id),
            "idempotency_key": canonical_idempotency_key,
            "request_idempotency_key": request_idempotency_key,
            "promo_code_id": resolved_promo["code_id"] if resolved_promo else None,
            "discount_cents": discount_cents,
            "original_total_cents": original_total_cents,
        },
    )
    order_id = str(order.get("order_id") or "")

    trigger_event_id = f"cart_purchase:{user_sub}:{cart_id}:{order_id}"

    # ── ECOMX-10: REAL charge before any COMPLETED write. ──────────────────────
    # Charge the buyer's PM on the honest stripe-mock rail BEFORE the cart CAS,
    # order-paid mark, purchase-txn, or seller credit. A decline / no-PM raises
    # 402: we restore the stock we decremented and re-open nothing else (the cart
    # is still OPEN, no order is completed, no ledger debit / seller credit is
    # written). The canonical per-cart idempotency key is the Stripe
    # idempotency_key so a double-submit charges exactly once at the processor.
    # A prior PURCHASED cart short-circuits at the top of purchase_cart (before
    # any stock decrement or charge), so a completed order never re-charges.
    try:
        pm = _resolve_cart_payment_method(user_sub, None)
        payment_intent_id = _charge_cart_payment_intent(
            buyer_sub=user_sub,
            amount_cents=int(final_total),
            currency=str(cart.get("currency", "USD")),
            payment_method_id=pm,
            order_id=order_id,
            cart_id=cart_id,
            idempotency_key=canonical_idempotency_key,
        )
    except HTTPException:
        # Charge failed (402). Restore every stock unit we decremented so a
        # declined checkout leaves inventory exactly as it was found.
        for prev in decremented_stock:
            try:
                T.catalog.update_item(
                    Key=_catalog_item_key(prev["cat_id"], prev["item_id"]),
                    UpdateExpression="SET stock_count = stock_count + :qty",
                    ExpressionAttributeValues={":qty": prev["qty"]},
                )
            except Exception:
                logger.exception("stock restore failed after declined charge cart=%s", cart_id)
        raise

    try:
        update_expr = (
            "SET #status = :status, purchased_at = :purchased_at, "
            "purchased_total_cents = :total, last_order_id = :order_id, purchase_idempotency_key = :idempotency_key, request_idempotency_key = :request_idempotency_key"
        )
        expr_values = {
            ":status": "PURCHASED",
            ":purchased_at": now,
            ":total": final_total,
            ":order_id": order_id,
            ":idempotency_key": canonical_idempotency_key,
            ":request_idempotency_key": request_idempotency_key,
            ":open": "OPEN",
        }
        if buyer:
            update_expr = f"{update_expr}, buyer_profile = :buyer"
            expr_values[":buyer"] = buyer
        if resolved_promo:
            update_expr += ", promo_code_id = :promo_id, discount_cents = :discount, original_total_cents = :orig_total"
            expr_values[":promo_id"] = resolved_promo["code_id"]
            expr_values[":discount"] = discount_cents
            expr_values[":orig_total"] = original_total_cents
        T.shopping_cart.update_item(
            Key={"PK": cart["PK"], "SK": cart["SK"]},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues=expr_values,
            ConditionExpression="#status = :open",
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            latest = get_cart(user_sub, cart_id)
            if latest.get("status") == "PURCHASED":
                return {
                    "cart_id": cart_id,
                    "order_id": str(latest.get("last_order_id") or ""),
                    "purchased_at": str(latest.get("purchased_at") or ""),
                    "purchased_total_cents": int(latest.get("purchased_total_cents") or 0),
                    "currency": latest.get("currency", "USD"),
                    "buyer": latest.get("buyer_profile"),
                    "purchase_txn_id": latest.get("purchase_txn_id"),
                }
            raise HTTPException(status_code=409, detail="Cart is not open") from exc
        raise HTTPException(status_code=500, detail="Failed to purchase cart") from exc

    # ── ECOMX-10/12: the charge succeeded AND we won the cart CAS. Mark the
    # order header paid + stamp the reversible-refund refs (payment_intent_id
    # for the real charge; the buyer-debit txn/entry is stamped below once
    # record_cart_purchase returns its txn_id). A missing PI on the mock/dev
    # stub path still marks paid (a ledger-only charge stands in). Best-effort;
    # the money already moved.
    try:
        commerce_order_service.orders.update_item(
            Key={"order_id": order_id, "sk": "ORDER"},
            UpdateExpression=(
                "SET payment_status = :ps, payment_intent_id = :pi, paid_at = :t, "
                "shipping_cents = :sh, tax_cents = :tx, merchandise_cents = :mc, "
                "grand_total_cents = :gt, ship_to = :st"
            ),
            ExpressionAttributeValues={
                ":ps": "paid",
                ":pi": str(payment_intent_id or ""),
                ":t": now,
                ":sh": int(shipping_cents),  # ECOMX-40
                ":tx": int(tax_cents),
                ":mc": int(subtotal_after_discount),
                ":gt": int(final_total),
                ":st": ship_to_snapshot or {},
            },
        )
    except Exception:
        logger.exception("failed to mark order paid order=%s", order_id)

    # ── ECOMX-11: grant digital entitlements ONLY after payment_status="paid".
    # Surface a deferral loudly (log) instead of swallowing it silently.
    try:
        commerce_entitlement_orchestrator.process_order_entitlements(
            order_id,
            trigger_event_id=trigger_event_id,
            source_system="shopping_cart",
        )
    except Exception:
        logger.exception("entitlement grant failed for paid order=%s (buyer paid, access deferred)", order_id)

    # ── SHOP-002: Redeem promo code on successful purchase ──
    if resolved_promo and resolved_promo.get("code_id"):
        try:
            from app.services.promo_codes import redeem_promo_code
            redeem_promo_code(
                code_id=resolved_promo["code_id"],
                user_id=user_sub,
                original_price_cents=original_total_cents,
                final_price_cents=final_total,
                checkout_type="shop",
                checkout_item_id=cart_id,
            )
        except Exception:
            pass  # best-effort redemption

    # ── ECOMX-12/13: stamp the reversible-refund attribution into the
    # buyer-debit ledger meta so refund_requests.approve_request can claw back
    # EVERY seller (multi-seller aware) AND the livecom host. recipient_user_id
    # keeps the single-seller fast path; refund_seller_ids/refund_host_id drive
    # the multi-party clawback.
    _refund_seller_ids = sorted({
        (ci.get("creator_user_id") or ci.get("seller_id"))
        for ci in items
        if (ci.get("creator_user_id") or ci.get("seller_id"))
        and (ci.get("creator_user_id") or ci.get("seller_id")) != user_sub
    })
    _refund_meta = {
        "recipient_user_id": _refund_seller_ids[0] if len(_refund_seller_ids) == 1 else None,
        "refund_seller_ids": _refund_seller_ids,
        "refund_host_id": host_id if broadcast_session_id else None,
        "is_stream_attributed": bool(broadcast_session_id),
        "broadcast_session_id": broadcast_session_id,
        # ECOMX-40: the money breakdown surfaced on the order/receipt.
        "shipping_cents": int(shipping_cents),
        "tax_cents": int(tax_cents),
        "merchandise_cents": int(subtotal_after_discount),
        "grand_total_cents": int(final_total),
    }
    txn_id = record_cart_purchase(
        user_sub=user_sub,
        cart_id=cart_id,
        order_id=order_id,
        total_cents=final_total,
        currency=cart.get("currency", "USD"),
        items=items,
        buyer=buyer,
        refund_meta=_refund_meta,
    )
    # ECOMX-12: stamp the buyer-debit refs onto the order header so an
    # owner-cancel refund (which has only the order_id) can reverse the real
    # charge + resolve the buyer-debit ledger entry.
    try:
        commerce_order_service.orders.update_item(
            Key={"order_id": order_id, "sk": "ORDER"},
            UpdateExpression="SET buyer_debit_txn_id = :t, buyer_debit_entry_id = :e",
            ExpressionAttributeValues={":t": txn_id, ":e": txn_id},
        )
    except Exception:
        logger.exception("failed to stamp buyer-debit refs on order=%s", order_id)
    try:
        T.shopping_cart.update_item(
            Key={"PK": cart["PK"], "SK": cart["SK"]},
            UpdateExpression="SET purchase_txn_id = :txn_id",
            ExpressionAttributeValues={":txn_id": txn_id},
        )
    except Exception:
        pass

    # SHOP seller earnings credit (ECOM fix): write a billing credit ledger
    # entry per creator so shop sales surface in /ui/earnings and /ui/payouts
    # (mirrors vod_purchase seller-credit but uses type="credit", which is what
    # creator_earnings._query_credit_entries and creator_payouts.get_available_balance
    # actually filter on). Best-effort; never blocks the purchase.
    #
    # ── ECOMX-14 (A6): ONE commission model. A regular shop sale now nets the
    # seller the SAME platform fee (SHOP_PLATFORM_FEE_BPS == LIVECOM_PLATFORM_FEE_BPS,
    # 1500 bps / 15%) as an in-stream sale, and records the platform fee in the
    # same PLATFORM#revenue ledger. Previously shop credited GROSS (seller earned
    # 15% MORE off-stream + the fee was never collected). The credit meta carries
    # gross/net/fee so the refund clawback (ECOMX-13) reverses the exact net.
    try:
        from app.services.billing_shared import new_ledger_entry as _nle, user_pk as _seller_pk
        from app.services.live_commerce_split import (
            LIVECOM_PLATFORM_FEE_BPS as _SHOP_FEE_BPS,
            _platform_fee_record as _shop_fee_record,
        )
        _by_creator = {}
        _stream_attributed = bool(broadcast_session_id)  # LIVECOM L4
        for _ci in items:
            _cid = _ci.get("creator_user_id") or _ci.get("seller_id")
            if not _cid or _cid == user_sub:
                continue
            _by_creator[_cid] = _by_creator.get(_cid, 0) + int(_ci.get("line_total_cents", 0) or 0)
        _gross = sum(_by_creator.values())
        for _cid, _amt in ({}.items() if _stream_attributed else _by_creator.items()):  # LIVECOM L4
            # ECOMX-40: prorate over the MERCHANDISE subtotal (post-discount), NOT
            # final_total — sellers must not be credited a share of the buyer's
            # shipping + sales tax (the platform keeps those).
            _gross_credit = int(round(_amt * (subtotal_after_discount / _gross))) if _gross > 0 else int(_amt)
            if _gross_credit <= 0:
                continue
            _platform_fee = int(round(_gross_credit * _SHOP_FEE_BPS / 10000))
            _net = _gross_credit - _platform_fee
            _sk, _credit_item = _nle(
                key_name="pk",
                key_value=_seller_pk(_cid),
                entry_type="credit",
                amount_cents=_net,
                state="settled",
                reason="Shop sale",
                meta={
                    "content_type": "shop",
                    "order_id": order_id,
                    "cart_id": cart_id,
                    "buyer_id": user_sub,
                    "purchase_txn_id": txn_id,
                    "seller_id": _cid,
                    "gross_cents": _gross_credit,
                    "platform_fee_cents": _platform_fee,
                    "platform_fee_bps": _SHOP_FEE_BPS,
                    "seller_net_cents": _net,
                },
            )
            T.billing.put_item(Item=_credit_item)
            # ECOMX-14: collect the platform fee on the shop sale, same ledger
            # (PLATFORM#revenue) as the livecom path.
            _shop_fee_record(order_id, "", _platform_fee, {
                "content_type": "shop", "cart_id": cart_id, "buyer_id": user_sub,
                "seller_id": _cid, "product_id": "", "gross_cents": _gross_credit,
                "platform_fee_bps": _SHOP_FEE_BPS, "purchase_txn_id": txn_id,
            })
    except Exception:
        logger.exception("Failed to write seller credit ledger for cart %s", cart_id)

    # LIVECOM L4: stream-attributed commission split (host commission + seller
    # net + platform fee), idempotent per order. Replaces the legacy seller
    # credit for in-stream sales (skipped above when broadcast_session_id set).
    if broadcast_session_id:
        try:
            from app.services.live_commerce_split import settle_stream_order as _settle_livecom
            _settle_livecom(order_id=order_id, session_id=broadcast_session_id,
                            host_id=host_id, buyer_sub=user_sub, items=items,
                            final_total=final_total, currency=cart.get("currency", "USD"),
                            cart_id=cart_id, txn_id=txn_id)
        except Exception:
            import logging as _lg_lc
            _lg_lc.getLogger(__name__).exception("livecom split failed for order %s", order_id)

    # SHOP-003: Remove TTL from purchased carts (permanent records)
    try:
        T.shopping_cart.update_item(
            Key={"PK": cart["PK"], "SK": cart["SK"]},
            UpdateExpression="REMOVE #ttl",
            ExpressionAttributeNames={"#ttl": "ttl"},
        )
    except Exception:
        pass  # Non-critical: TTL removal is best-effort

    # FIN-001: generate an invoice for the shop purchase (best-effort)
    try:
        from app.services.invoices import create_invoice_safe
        _line_items = []
        for _it in items:
            _qty = int(_it.get("quantity", 1) or 1)
            _line_total = int(_it.get("line_total_cents", 0) or 0)
            _line_items.append({
                "description": str(_it.get("name") or _it.get("item_id") or "Item"),
                "quantity": _qty,
                "amount_cents": _line_total,
            })
        create_invoice_safe(
            user_sub=user_sub,
            invoice_type="shop",
            amount_cents=int(final_total),
            line_items=_line_items,
            ledger_entry_id=str(txn_id),
            seller_name="Shop",
            buyer_name=(buyer or {}).get("display_name") or user_sub,
            buyer_email=(buyer or {}).get("displayed_email") or "",
            currency=str(cart.get("currency", "USD")).lower(),
        )
    except Exception:
        pass

    # ECM-008: convert this cart's soft reservations into committed stock.
    _ecm_commit(user_sub, cart_id)

    # ECOM Bug #2: advance the /ui/orders lifecycle header out of pending_payment.
    # purchase_cart captures payment synchronously (buyer debit COMPLETED, stock
    # decremented, seller credited) so the order is paid -- move it from the seeded
    # `created` (legacy "pending_payment") state to `approved` (legacy "approved")
    # via the canonical order_lifecycle state machine. Best-effort + idempotent
    # (keyed off the canonical cart idempotency key); never blocks the purchase and
    # only fires on the first successful purchase (replays return earlier).
    try:
        if S.order_lifecycle_enabled and order_id:
            from app.services import order_lifecycle as _ol
            _hdr = _ol.get_order_header(order_id)
            if _hdr and str(_hdr.get("lifecycle_status") or "") == "created":
                _ol.transition_order(
                    order_id,
                    "approved",
                    actor=user_sub,
                    reason="Cart purchase paid",
                    idempotency_key=canonical_idempotency_key,
                )
    except Exception:
        import logging as _logging_ol
        _logging_ol.getLogger(__name__).exception(
            "Failed to advance order lifecycle for cart %s order %s", cart_id, order_id
        )

    # ECOM-SELLER (G1-G4): on order approval, split the paid cart into per-seller
    # ship-groups (each = that seller's line items w/ REAL names + the buyer ship
    # address), notify each seller (you-sold-it alert+push), backfill line names.
    try:
        if S.order_lifecycle_enabled and order_id:
            from app.services import seller_ship_groups as _ssg
            _ssg.populate_on_approval(
                order_id=order_id,
                buyer_sub=user_sub,
                cart_items=items,
                buyer=buyer,
                currency=str(cart.get("currency", "USD")),
                ship_to=ship_to_snapshot,  # ECOMX-40 (B3): the chosen checkout address
            )
    except Exception:
        import logging as _lg_ssg
        _lg_ssg.getLogger(__name__).exception("seller ship-group populate failed for order %s", order_id)

    # ── ECOMX-42 (B2): instant-fulfilment completion. A digital-only / self-
    # purchase order produces NO seller ship groups, so the delivery-driven
    # bridge (which flips PENDING->COMPLETED on delivery) would never fire and the
    # txn would be stuck PENDING forever. When there are no ship groups the order
    # is delivered the moment entitlement is granted -> mark the buyer txn
    # COMPLETED now. Physical orders (>=1 ship group) stay PENDING until delivery.
    try:
        if S.order_lifecycle_enabled and order_id and txn_id:
            from app.services import seller_ship_groups as _ssg_chk
            if not _ssg_chk.list_by_order(order_id):
                from app.services import purchase_history as _ph_c
                _txn = _ph_c.get_transaction_item(user_sub, txn_id)
                if _txn and str(_txn.get("status") or "") == "PENDING":
                    _ph_c.mark_completed(user_sub, txn_id, str(payment_intent_id or ""), "Instant delivery")
    except Exception:
        import logging as _lg_inst
        _lg_inst.getLogger(__name__).exception("instant-completion failed for order %s", order_id)

    return {
        "cart_id": cart_id,
        "order_id": order_id,
        "purchased_at": now,
        "purchased_total_cents": final_total,
        "original_total_cents": original_total_cents if resolved_promo else None,
        "discount_cents": discount_cents if resolved_promo else None,
        "promo_code_id": resolved_promo["code_id"] if resolved_promo else None,
        "promo_discount_type": resolved_promo["discount_type"] if resolved_promo else None,
        "currency": cart.get("currency", "USD"),
        "buyer": buyer,
        "purchase_txn_id": txn_id,
        # ECOMX-40 (B3): the shipping/tax breakdown so the app can show it post-buy.
        "merchandise_cents": int(subtotal_after_discount),
        "shipping_cents": int(shipping_cents),
        "tax_cents": int(tax_cents),
    }


# ─── SHOP-003: Cart Abandonment Detection & Reminders ──────────────────────────


def scan_abandoned_carts(
    *,
    threshold_hours: int = 24,
    now: Optional[int] = None,
    apply_reminder_gate: bool = True,
) -> List[Dict[str, Any]]:
    """Find OPEN carts with no activity in the last threshold_hours.

    Uses ByStatusActivity GSI: status="OPEN" AND last_activity_at < cutoff.
    Loops over LastEvaluatedKey so a busy table doesn't silently hide carts
    beyond the first page (CLAUDE.md FilterExpression/pagination gotcha).

    When ``apply_reminder_gate`` is True (the legacy single-blast path) carts at
    ``max_reminders`` or within the global ``cooldown`` window are filtered out.
    The multi-stage service (GAP-0189) passes ``apply_reminder_gate=False`` and
    applies its own per-stage delay / stage-cap gating instead.

    `now` is injectable for deterministic testing; defaults to the wall clock.
    """
    if now is None:
        now = int(datetime.now(timezone.utc).timestamp())
    cutoff = now - (threshold_hours * 3600)
    cooldown = S.cart_abandonment_reminder_cooldown_hours * 3600
    max_reminders = S.cart_abandonment_max_reminders

    items: List[Dict[str, Any]] = []
    last_key: Optional[Dict[str, Any]] = None
    while len(items) < 200:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusActivity",
            "KeyConditionExpression": Key("status").eq("OPEN") & Key("last_activity_at").lt(cutoff),
            "Limit": 200,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.shopping_cart.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    if not apply_reminder_gate:
        return items

    # Filter in-memory: skip recently reminded or maxed-out carts
    eligible: List[Dict[str, Any]] = []
    for item in items:
        last_reminder = int(item.get("last_reminder_at", 0) or 0)
        count = int(item.get("reminder_count", 0) or 0)
        if count >= max_reminders:
            continue
        if last_reminder and (last_reminder + cooldown) > now:
            continue
        eligible.append(item)

    return eligible


def send_cart_reminder(cart: Dict[str, Any], *, now: Optional[int] = None) -> None:
    """Send an abandonment reminder for a single cart.

    Writes in-app alert, sends email, updates cart reminder tracking.
    `now` is injectable for deterministic testing.
    """
    from app.services.alerts import write_alert, send_alert_email

    user_sub = cart["PK"].replace("USER#", "")
    cart_id = cart.get("cart_id", "")
    ts = now if now is not None else int(datetime.now(timezone.utc).timestamp())

    # Race guard: cart may have been purchased between scan and send (edge 8.3).
    latest = T.shopping_cart.get_item(
        Key={"PK": cart["PK"], "SK": cart["SK"]}
    ).get("Item")
    if not latest or latest.get("status") != "OPEN":
        return

    # GAP-0191: respect the user's cart-reminder opt-out preference.
    from app.services.cart_reminders import is_user_opted_out, generate_recovery_link

    if is_user_opted_out(user_sub):
        return

    # Count items in this cart
    prefix = f"CART#{cart_id}#ITEM#"
    items_resp = T.shopping_cart.query(
        KeyConditionExpression=Key("PK").eq(cart["PK"]) & Key("SK").begins_with(prefix),
        Select="COUNT",
    )
    items_count = items_resp.get("Count", 0)
    if items_count == 0:
        return  # Don't remind for empty carts

    # GAP-0190: signed one-time recovery URL embedded in the alert + email.
    recovery_url = generate_recovery_link(user_sub, cart_id)

    # Write in-app alert
    write_alert(
        user_sub,
        event="cart.abandoned",
        outcome="reminder",
        title="You left items in your cart",
        details={
            "cart_id": cart_id,
            "alert_type": "cart.abandoned",
            "link": recovery_url,
            "items_count": str(items_count),
        },
    )

    # Send email reminder
    profile = get_profile(user_sub) or {}
    email = profile.get("email") or profile.get("displayed_email")
    if email:
        send_alert_email(
            [email],
            subject="You left items in your cart",
            body_text=(
                f"You have {items_count} item(s) waiting in your cart. "
                f"Complete your purchase: {recovery_url}"
            ),
        )

    # Update cart reminder tracking
    T.shopping_cart.update_item(
        Key={"PK": cart["PK"], "SK": cart["SK"]},
        UpdateExpression=(
            "SET last_reminder_at = :ts, "
            "abandoned_at = if_not_exists(abandoned_at, :ts) "
            "ADD reminder_count :one"
        ),
        ExpressionAttributeValues={":ts": ts, ":one": 1},
    )


def get_abandonment_stats() -> Dict[str, Any]:
    """Return aggregate cart abandonment metrics for admin dashboard."""
    # Scan all cart records (type=cart) — limited to 1000 for performance
    resp = T.shopping_cart.scan(
        FilterExpression="attribute_exists(cart_id) AND #t = :cart_type",
        ExpressionAttributeNames={"#t": "type"},
        ExpressionAttributeValues={":cart_type": "cart"},
        Limit=1000,
    )
    items = resp.get("Items", [])

    total_open = 0
    total_abandoned = 0
    total_purchased = 0

    for item in items:
        status = item.get("status")
        if status == "OPEN":
            total_open += 1
            abandoned_at = int(item.get("abandoned_at", 0) or 0)
            if abandoned_at > 0:
                total_abandoned += 1
        elif status == "PURCHASED":
            total_purchased += 1

    total_carts = total_open + total_purchased
    abandonment_rate = (total_abandoned / total_open * 100) if total_open > 0 else 0.0

    return {
        "total_open": total_open,
        "total_abandoned": total_abandoned,
        "total_purchased": total_purchased,
        "total_carts": total_carts,
        "abandonment_rate": round(abandonment_rate, 2),
    }


def expire_abandoned_carts(*, expire_hours: Optional[int] = None, now: Optional[int] = None) -> List[str]:
    """Auto-expire OPEN carts whose last_activity_at is older than expire_hours.

    Transitions such carts to status="EXPIRED" (immediately, ahead of the DDB
    TTL sweep). DDB TTL still acts as the final cleanup. Returns the list of
    expired cart_ids. `now` is injectable for deterministic testing.
    """
    if expire_hours is None:
        expire_hours = S.cart_abandonment_expire_hours
    if expire_hours <= 0:
        return []
    if now is None:
        now = int(datetime.now(timezone.utc).timestamp())
    cutoff = now - (expire_hours * 3600)

    expired: List[str] = []
    last_key: Optional[Dict[str, Any]] = None
    scanned = 0
    while scanned < 500:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusActivity",
            "KeyConditionExpression": Key("status").eq("OPEN") & Key("last_activity_at").lt(cutoff),
            "Limit": 200,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.shopping_cart.query(**kwargs)
        page = resp.get("Items", [])
        scanned += len(page)
        for item in page:
            try:
                T.shopping_cart.update_item(
                    Key={"PK": item["PK"], "SK": item["SK"]},
                    UpdateExpression="SET #status = :expired, abandoned_at = if_not_exists(abandoned_at, :ts)",
                    ConditionExpression="#status = :open",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={":expired": "EXPIRED", ":open": "OPEN", ":ts": now},
                )
                expired.append(str(item.get("cart_id", "")))
            except ClientError:
                pass  # Status changed (purchased/already expired) — skip
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    return expired
