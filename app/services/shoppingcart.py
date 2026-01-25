from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.tables import T


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _cart_sk(cart_id: str) -> str:
    return f"CART#{cart_id}"


def _item_sk(cart_id: str, sku: str) -> str:
    return f"CART#{cart_id}#ITEM#{sku}"


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
    return {
        "sku": item.get("sku"),
        "name": item.get("name"),
        "quantity": qty,
        "unit_price_cents": unit,
        "line_total_cents": qty * unit,
        "updated_at": item.get("updated_at"),
    }


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
        updated = {
            **existing,
            "name": payload.get("name", existing.get("name")),
            "quantity": new_qty,
            "unit_price_cents": int(payload.get("unit_price_cents", existing.get("unit_price_cents", 0))),
            "updated_at": now,
        }
        T.shopping_cart.put_item(Item=updated)
        return _item_from_item(updated)

    item = {
        "PK": _user_pk(user_sub),
        "SK": _item_sk(cart_id, sku),
        "type": "item",
        "cart_id": cart_id,
        "sku": sku,
        "name": payload["name"],
        "quantity": int(payload.get("quantity", 1)),
        "unit_price_cents": int(payload.get("unit_price_cents", 0)),
        "updated_at": now,
    }
    T.shopping_cart.put_item(Item=item)
    return _item_from_item(item)


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
    _require_open_cart(cart)

    total_cents = cart_total_cents(user_sub, cart_id)
    now = _now_iso()
    order_id = uuid.uuid4().hex

    try:
        T.shopping_cart.update_item(
            Key={"PK": cart["PK"], "SK": cart["SK"]},
            UpdateExpression="SET #status = :status, purchased_at = :purchased_at, purchased_total_cents = :total, last_order_id = :order_id",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":status": "PURCHASED",
                ":purchased_at": now,
                ":total": total_cents,
                ":order_id": order_id,
                ":open": "OPEN",
            },
            ConditionExpression="#status = :open",
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Cart is not open") from exc
        raise HTTPException(status_code=500, detail="Failed to purchase cart") from exc

    return {
        "cart_id": cart_id,
        "order_id": order_id,
        "purchased_at": now,
        "purchased_total_cents": total_cents,
        "currency": cart.get("currency", "USD"),
    }
