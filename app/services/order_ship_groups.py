"""ORD-009 — order ship groups service.

Ship groups partition order items into separate fulfillment batches that can
have different ship-to addresses, carriers, and tracking numbers.  They live in
the same ``T.orders`` single-table as the order header, keyed by
``SK=SHIPGRP#{ship_group_id}``.

Schema (per row)
----------------
  order_id            : str   — partition key
  sk                  : str   — ``SHIPGRP#{ship_group_id}``
  ship_group_id       : str   — uuid4().hex
  ship_to             : dict  — address dict (street, city, state, zip, country, …)
  carrier             : str | None
  tracking_number     : str | None
  ship_method         : str   — "standard" | "express" | "overnight"
  estimated_ship_date : str | None  — ISO date string (YYYY-MM-DD)
  item_ids            : list[str]   — order item_ids assigned to this group
  status              : str   — "pending" | "shipped" | "delivered"
  created_at          : int   — Unix seconds
  updated_at          : int   — Unix seconds

No ``S.dev_mode`` branch (SECOPS-007 parity).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_VALID_SHIP_METHODS = {"standard", "express", "overnight"}
_VALID_STATUSES = {"pending", "shipped", "delivered"}

_SHIPGRP_SK_PREFIX = "SHIPGRP#"


# ── Guard ─────────────────────────────────────────────────────────────────────

def _require_lifecycle_enabled() -> None:
    if not S.order_lifecycle_enabled:
        raise HTTPException(
            status_code=501,
            detail={"code": "order_lifecycle_not_enabled", "message": "Order lifecycle is not enabled"},
        )


# ── Core CRUD ─────────────────────────────────────────────────────────────────

def create_ship_group(
    order_id: str,
    ship_to: Dict[str, Any],
    carrier: Optional[str] = None,
    ship_method: str = "standard",
    item_ids: Optional[List[str]] = None,
    estimated_ship_date: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new ship group for the given order.

    Parameters
    ----------
    order_id            : target order id
    ship_to             : address dict with at least one key
    carrier             : optional carrier name (e.g. "UPS", "FedEx")
    ship_method         : "standard" | "express" | "overnight"
    item_ids            : list of order item_ids assigned to this group
    estimated_ship_date : optional ISO date string

    Returns the ship group dict as stored.
    """
    _require_lifecycle_enabled()

    if ship_method not in _VALID_SHIP_METHODS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_ship_method",
                "message": f"ship_method must be one of {sorted(_VALID_SHIP_METHODS)}",
            },
        )

    ship_group_id = uuid4().hex
    ts = now_ts()

    item: Dict[str, Any] = {
        "order_id": order_id,
        "sk": f"{_SHIPGRP_SK_PREFIX}{ship_group_id}",
        "ship_group_id": ship_group_id,
        "ship_to": ship_to,
        "ship_method": ship_method,
        "item_ids": item_ids or [],
        "status": "pending",
        "created_at": ts,
        "updated_at": ts,
    }
    if carrier is not None:
        item["carrier"] = carrier
    if estimated_ship_date is not None:
        item["estimated_ship_date"] = estimated_ship_date

    T.orders.put_item(Item=item)
    return item


def list_ship_groups(order_id: str) -> List[Dict[str, Any]]:
    """Return all SHIPGRP# rows for the given order, sorted by created_at asc."""
    _require_lifecycle_enabled()

    resp = T.orders.query(
        KeyConditionExpression=Key("order_id").eq(order_id)
        & Key("sk").begins_with(_SHIPGRP_SK_PREFIX),
    )
    rows = resp.get("Items", [])
    return sorted(rows, key=lambda r: int(r.get("created_at", 0)))


def update_ship_group(
    order_id: str,
    ship_group_id: str,
    *,
    tracking_number: Optional[str] = None,
    status: Optional[str] = None,
    carrier: Optional[str] = None,
    estimated_ship_date: Optional[str] = None,
) -> Dict[str, Any]:
    """Partially update a ship group row.

    Only the fields that are explicitly passed (non-None) are written.
    ``updated_at`` is always refreshed.

    Returns the updated ship group dict.
    Raises HTTPException(404) if the row does not exist.
    """
    _require_lifecycle_enabled()

    if status is not None and status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_status",
                "message": f"status must be one of {sorted(_VALID_STATUSES)}",
            },
        )

    sk = f"{_SHIPGRP_SK_PREFIX}{ship_group_id}"

    # Build UpdateExpression dynamically for the provided fields.
    set_parts: List[str] = ["updated_at = :updated_at"]
    expr_values: Dict[str, Any] = {":updated_at": now_ts()}

    if tracking_number is not None:
        set_parts.append("tracking_number = :tracking_number")
        expr_values[":tracking_number"] = tracking_number
    if status is not None:
        set_parts.append("#sg_status = :status")
        expr_values[":status"] = status
    if carrier is not None:
        set_parts.append("carrier = :carrier")
        expr_values[":carrier"] = carrier
    if estimated_ship_date is not None:
        set_parts.append("estimated_ship_date = :estimated_ship_date")
        expr_values[":estimated_ship_date"] = estimated_ship_date

    update_expr = "SET " + ", ".join(set_parts)

    kwargs: Dict[str, Any] = {
        "Key": {"order_id": order_id, "sk": sk},
        "UpdateExpression": update_expr,
        "ExpressionAttributeValues": expr_values,
        "ConditionExpression": "attribute_exists(ship_group_id)",
        "ReturnValues": "ALL_NEW",
    }
    # "status" is a reserved word in DynamoDB — use an alias.
    if status is not None:
        kwargs["ExpressionAttributeNames"] = {"#sg_status": "status"}

    try:
        resp = T.orders.update_item(**kwargs)
    except Exception as exc:
        code = getattr(getattr(exc, "response", None), "get", lambda *a: None)("Error", {}).get("Code", "")
        if not isinstance(code, str):
            try:
                code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
            except Exception:
                code = ""
        if code == "ConditionalCheckFailedException":
            raise HTTPException(404, {"code": "ship_group_not_found"}) from exc
        raise

    return resp.get("Attributes", {})


def delete_ship_group(order_id: str, ship_group_id: str) -> None:
    """Delete a SHIPGRP# row.  No-op if the row is missing."""
    _require_lifecycle_enabled()

    T.orders.delete_item(
        Key={"order_id": order_id, "sk": f"{_SHIPGRP_SK_PREFIX}{ship_group_id}"},
    )
