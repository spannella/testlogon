from __future__ import annotations

import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

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
    }


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
    item = {
        "PK": _user_pk(user_sub),
        "SK": _cart_sk(cart_id),
        "type": "cart",
        "cart_id": cart_id,
        "status": "OPEN",
        "created_at": now,
        "currency": "USD",
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
    T.shopping_cart.put_item(Item=item)
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
        return None

    updated = {
        **existing,
        "quantity": quantity,
        "updated_at": _now_iso(),
    }
    T.shopping_cart.put_item(Item=updated)
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
        return

    updated = {
        **existing,
        "quantity": new_qty,
        "updated_at": _now_iso(),
    }
    T.shopping_cart.put_item(Item=updated)


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


def purchase_cart(user_sub: str, cart_id: str) -> Dict[str, Any]:
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
    now = _now_iso()
    buyer = _buyer_snapshot(get_profile(user_sub))
    idempotency_key = _cart_purchase_idempotency_key(user_sub, cart_id)

    line_items = _commercial_line_items_from_cart_items(items, cart_id)
    order = commerce_order_service.create_order_from_line_items(
        user_id=user_sub,
        source_system="shopping_cart",
        correlation_id=idempotency_key,
        line_items=line_items,
        metadata={"cart_id": cart_id, "idempotency_key": idempotency_key},
    )
    order_id = str(order.get("order_id") or "")

    trigger_event_id = f"cart_purchase:{user_sub}:{cart_id}:{order_id}"

    try:
        update_expr = (
            "SET #status = :status, purchased_at = :purchased_at, "
            "purchased_total_cents = :total, last_order_id = :order_id, purchase_idempotency_key = :idempotency_key"
        )
        expr_values = {
            ":status": "PURCHASED",
            ":purchased_at": now,
            ":total": total_cents,
            ":order_id": order_id,
            ":idempotency_key": idempotency_key,
            ":open": "OPEN",
        }
        if buyer:
            update_expr = f"{update_expr}, buyer_profile = :buyer"
            expr_values[":buyer"] = buyer
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

    txn_id = record_cart_purchase(
        user_sub=user_sub,
        cart_id=cart_id,
        order_id=order_id,
        total_cents=total_cents,
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

    return {
        "cart_id": cart_id,
        "order_id": order_id,
        "purchased_at": now,
        "purchased_total_cents": total_cents,
        "currency": cart.get("currency", "USD"),
        "buyer": buyer,
        "purchase_txn_id": txn_id,
    }
