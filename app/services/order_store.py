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

from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

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
