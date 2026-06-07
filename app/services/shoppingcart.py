from __future__ import annotations

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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    T.shopping_cart.put_item(Item=item)
    _touch_cart_activity(user_sub, cart_id)
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

    final_total = max(0, total_cents - discount_cents)

    line_items = _commercial_line_items_from_cart_items(items, cart_id)
    order = commerce_order_service.create_order_from_line_items(
        user_id=user_sub,
        source_system="shopping_cart",
        correlation_id=canonical_idempotency_key,
        line_items=line_items,
        metadata={
            "cart_id": cart_id,
            "idempotency_key": canonical_idempotency_key,
            "request_idempotency_key": request_idempotency_key,
            "promo_code_id": resolved_promo["code_id"] if resolved_promo else None,
            "discount_cents": discount_cents,
            "original_total_cents": original_total_cents,
        },
    )
    order_id = str(order.get("order_id") or "")

    trigger_event_id = f"cart_purchase:{user_sub}:{cart_id}:{order_id}"

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

    try:
        commerce_entitlement_orchestrator.process_order_entitlements(
            order_id,
            trigger_event_id=trigger_event_id,
            source_system="shopping_cart",
        )
    except Exception:
        pass

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

    txn_id = record_cart_purchase(
        user_sub=user_sub,
        cart_id=cart_id,
        order_id=order_id,
        total_cents=final_total,
        currency=cart.get("currency", "USD"),
        items=items,
        buyer=buyer,
    )
    try:
        T.shopping_cart.update_item(
            Key={"PK": cart["PK"], "SK": cart["SK"]},
            UpdateExpression="SET purchase_txn_id = :txn_id",
            ExpressionAttributeValues={":txn_id": txn_id},
        )
    except Exception:
        pass

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
