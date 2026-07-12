"""ORD-003 — order single-table accessors.

Thin DynamoDB access layer for the `orders` table after it gains the `sk`
sort key. The header row is keyed ``{"order_id": order_id, "sk": "ORDER"}``;
history/ship-group/adjustment rows share the partition under ``HIST#``,
``SHIPGRP#``, ``ADJ#`` prefixes.

All functions are synchronous (service-layer convention) and contain no
``S.dev_mode`` branch (SECOPS-007 parity). They go through ``T.orders`` which
points at DynamoDB Local in dev and real DynamoDB in prod.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T

ORDER_SK = "ORDER"


def get_order_header(order_id: str) -> Optional[Dict[str, Any]]:
    """Fetch the ORDER-SK header row, or ``None`` if it does not exist."""
    resp = T.orders.get_item(Key={"order_id": order_id, "sk": ORDER_SK})
    return resp.get("Item")


def put_order_header(item: Dict[str, Any]) -> None:
    """Write a full ORDER-SK header row (used at creation, not for updates)."""
    row = dict(item)
    row.setdefault("sk", ORDER_SK)
    T.orders.put_item(Item=row)


def query_order_rows(order_id: str, sk_prefix: Optional[str] = None) -> List[Dict[str, Any]]:
    """Query all rows under ``order_id`` (optionally filtered by SK prefix)."""
    cond = Key("order_id").eq(order_id)
    if sk_prefix:
        cond = cond & Key("sk").begins_with(sk_prefix)
    resp = T.orders.query(KeyConditionExpression=cond)
    return list(resp.get("Items", []))


def list_orders(
    *,
    user_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """List order-header rows newest-first (by ``created_at``).

    ORD list endpoint backing. Uses a GSI query, never a table scan:

    * ``status`` set        → ``GSI_STATUS`` (partition=status / sort=created_at).
                               ``user_id`` (when also set) is applied as a
                               post-query filter so a normal user can only see
                               their own orders within a status bucket.
    * ``user_id`` only      → ``GSI_USER`` (partition=user_id / sort=created_at).
    * neither               → not allowed (caller must scope to a user or status).

    Returns ``(headers, next_cursor)``. Only ``sk == ORDER`` header rows are
    indexed onto these GSIs (HIST#/SHIPGRP#/ADJ# rows carry no ``user_id`` /
    legacy ``status`` GSI keys), so the result is header-only by construction.
    """
    eff_limit = max(1, min(int(limit), 200))
    start_key = decode_cursor(cursor)

    kwargs: Dict[str, Any] = {
        "ScanIndexForward": False,  # newest-first by created_at
        "Limit": eff_limit,
    }
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    if status:
        kwargs["IndexName"] = "GSI_STATUS"
        kwargs["KeyConditionExpression"] = Key("status").eq(status)
        if user_id:
            kwargs["FilterExpression"] = Key("user_id").eq(user_id)
    elif user_id:
        kwargs["IndexName"] = "GSI_USER"
        kwargs["KeyConditionExpression"] = Key("user_id").eq(user_id)
    else:
        raise ValueError("list_orders requires user_id or status")

    resp = T.orders.query(**kwargs)
    items = list(resp.get("Items", []))
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return items, next_cursor
