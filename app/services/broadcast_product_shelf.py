"""Broadcast product shelf -- DynamoDB CRUD for linking catalog items to broadcast sessions (LCOM-001).

Extended with broadcast-exclusive pricing support (LCOM-004).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish

logger = logging.getLogger("broadcast.pricing")

MAX_SHELF_ITEMS = 50


def _shelf_item_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB item to output dict.

    Handles Decimal-to-int coercion for numeric fields that DynamoDB
    returns as boto3 Decimal types. Provides safe defaults for all
    optional fields to prevent KeyError on malformed items.
    """
    return {
        "session_id": item["session_id"],
        "item_id": item["item_id"],
        "category_id": item.get("category_id", ""),
        "name": item.get("name", ""),
        "description": item.get("description"),
        "price_cents": int(item.get("price_cents", 0)),
        "currency": item.get("currency", "USD"),
        "image_url": item.get("image_url"),
        "display_order": int(item.get("display_order", 0)),
        "added_by": item.get("added_by", ""),
        "added_at": int(item.get("added_at", 0)),
    }


def add_product_to_shelf(
    session_id: str,
    item_id: str,
    category_id: str,
    catalog_item: Dict[str, Any],
    added_by: str,
    display_order: int = 0,
    *,
    is_live: bool = False,
) -> Dict[str, Any]:
    """Add a catalog item to the broadcast product shelf.

    Args:
        session_id: The broadcast session ID.
        item_id: The catalog item ID to add.
        category_id: The catalog category containing the item.
        catalog_item: Raw catalog item dict with name, price_cents, image_urls, etc.
        added_by: User sub of the broadcaster adding the product.
        display_order: Position in the shelf (0-based).
        is_live: Whether the session is currently live (triggers SSE).

    Returns:
        Dict with all shelf item fields suitable for API response.

    Raises:
        HTTPException 409: If product is already on the shelf.
        HTTPException 400: If shelf is at capacity (50 items).
    """
    # Check for duplicate
    existing = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item")
    if existing:
        raise HTTPException(status_code=409, detail="Product already on shelf.")

    # Check shelf size
    count_resp = T.broadcast_product_shelf.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Select="COUNT",
    )
    if count_resp.get("Count", 0) >= MAX_SHELF_ITEMS:
        raise HTTPException(status_code=400, detail=f"Shelf is full ({MAX_SHELF_ITEMS} items max).")

    ts = now_ts()
    image_urls = catalog_item.get("image_urls") or []
    item = {
        "session_id": session_id,
        "SK": f"ITEM#{item_id}",
        "item_id": item_id,
        "category_id": category_id,
        "name": catalog_item.get("name", ""),
        "description": (catalog_item.get("description") or "")[:500],
        "price_cents": int(catalog_item.get("price_cents", 0)),
        "currency": catalog_item.get("currency", "USD"),
        "image_url": image_urls[0] if image_urls else None,
        "display_order": display_order,
        "added_by": added_by,
        "added_at": ts,
        "ttl": ts + 30 * 24 * 3600,  # 30 day TTL
    }
    T.broadcast_product_shelf.put_item(Item=item)

    out = _shelf_item_out(item)

    if is_live:
        broadcast_sse_publish(session_id, {"_type": "shelf:add", **out})

    return out


def remove_product_from_shelf(
    session_id: str,
    item_id: str,
    *,
    is_live: bool = False,
) -> bool:
    """Remove a product from the shelf. Returns True if found and removed.

    Args:
        session_id: The broadcast session ID.
        item_id: The catalog item ID to remove.
        is_live: Whether the session is currently live (triggers SSE).

    Returns:
        True if the item was found and deleted, False if not found.
    """
    existing = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item")
    if not existing:
        return False

    T.broadcast_product_shelf.delete_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    )

    if is_live:
        broadcast_sse_publish(session_id, {"_type": "shelf:remove", "item_id": item_id})

    return True


def get_shelf_product(session_id: str, item_id: str) -> Dict[str, Any] | None:
    """Get a single shelf product by item_id. Returns None if not found."""
    resp = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _shelf_item_out(item)


def get_shelf_product_raw(session_id: str, item_id: str) -> Dict[str, Any] | None:
    """Get the raw DDB item for a shelf product. Returns None if not found.

    Unlike get_shelf_product(), this returns the unprocessed DynamoDB item
    including broadcast pricing fields, suitable for passing to
    resolve_effective_price().
    """
    return T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item")


def list_shelf_products(session_id: str) -> List[Dict[str, Any]]:
    """List all products on the shelf, ordered by display_order.

    Args:
        session_id: The broadcast session ID.

    Returns:
        List of shelf item dicts sorted by display_order ascending.
    """
    resp = T.broadcast_product_shelf.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Limit=MAX_SHELF_ITEMS,
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("display_order", 0)))
    return [_shelf_item_out(i) for i in items]


def reorder_shelf(session_id: str, item_order: List[str], *, is_live: bool = False) -> None:
    """Update display_order for all items based on the provided ordering.

    Args:
        session_id: The broadcast session ID.
        item_order: Ordered list of item_ids. Index becomes display_order.
        is_live: Whether the session is currently live (triggers SSE).
    """
    for idx, item_id in enumerate(item_order):
        T.broadcast_product_shelf.update_item(
            Key={"session_id": session_id, "SK": f"ITEM#{item_id}"},
            UpdateExpression="SET display_order = :order",
            ExpressionAttributeValues={":order": idx},
        )

    if is_live:
        updated = list_shelf_products(session_id)
        broadcast_sse_publish(session_id, {"_type": "shelf:reorder", "items": updated})


# ─── Broadcast-Exclusive Pricing (LCOM-004) ────────────────────────


def resolve_effective_price(shelf_item: Dict[str, Any], session_status: str) -> Dict[str, Any]:
    """Determine the effective price for a shelf item.

    This is the SINGLE SOURCE OF TRUTH for price resolution in the entire
    broadcast commerce pipeline. Both the shelf listing endpoint and the
    quick-buy endpoint MUST call this function. Client-submitted prices
    are NEVER trusted.

    Args:
        shelf_item: The raw DynamoDB item from BroadcastProductShelf table.
        session_status: The current broadcast session status string
            (one of: draft, provisioning, ready, live, stopping, stopped, error).

    Returns:
        Dict with effective_price_cents, original_price_cents, is_broadcast_price,
        broadcast_price_expires_at, and discount_pct.

    Broadcast price is active when ALL conditions are met:
        1. broadcast_price_cents is set and > 0
        2. session_status == "live"
        3. Not expired (broadcast_price_expires_at is None OR > now_ts())
    """
    original = int(shelf_item.get("price_cents", 0))
    broadcast = shelf_item.get("broadcast_price_cents")
    expires_at = shelf_item.get("broadcast_price_expires_at")

    broadcast_active = (
        broadcast is not None
        and int(broadcast) > 0
        and session_status == "live"
        and (expires_at is None or int(expires_at) > now_ts())
    )

    if broadcast_active:
        effective = int(broadcast)
        discount_pct = round((1 - effective / original) * 100) if original > 0 else 0
        return {
            "effective_price_cents": effective,
            "original_price_cents": original,
            "is_broadcast_price": True,
            "broadcast_price_expires_at": int(expires_at) if expires_at else None,
            "discount_pct": max(0, min(100, discount_pct)),
        }

    return {
        "effective_price_cents": original,
        "original_price_cents": original,
        "is_broadcast_price": False,
        "broadcast_price_expires_at": None,
        "discount_pct": 0,
    }


def _shelf_item_out_with_pricing(item: Dict[str, Any], session_status: str) -> Dict[str, Any]:
    """Extended shelf item output with resolved pricing.

    Merges the base shelf item output (from LCOM-001's _shelf_item_out) with
    the resolved pricing fields from resolve_effective_price().
    """
    base = _shelf_item_out(item)
    pricing = resolve_effective_price(item, session_status)
    base.update({
        "broadcast_price_cents": (
            int(item["broadcast_price_cents"])
            if item.get("broadcast_price_cents") is not None
            else None
        ),
        "broadcast_price_expires_at": (
            int(item["broadcast_price_expires_at"])
            if item.get("broadcast_price_expires_at")
            else None
        ),
        "broadcast_price_set_at": (
            int(item["broadcast_price_set_at"])
            if item.get("broadcast_price_set_at")
            else None
        ),
        "effective_price_cents": pricing["effective_price_cents"],
        "is_broadcast_price": pricing["is_broadcast_price"],
        "discount_pct": pricing["discount_pct"],
        "original_price_cents": pricing["original_price_cents"],
    })
    return base


def list_shelf_products_with_pricing(session_id: str, session_status: str) -> List[Dict[str, Any]]:
    """List all products on the shelf with resolved pricing, ordered by display_order.

    Args:
        session_id: The broadcast session ID.
        session_status: The current broadcast session status for price resolution.

    Returns:
        List of shelf item dicts with pricing fields, sorted by display_order ascending.
    """
    resp = T.broadcast_product_shelf.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Limit=MAX_SHELF_ITEMS,
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("display_order", 0)))
    return [_shelf_item_out_with_pricing(i, session_status) for i in items]


def set_broadcast_price(
    session_id: str,
    item_id: str,
    broadcast_price_cents: int,
    set_by: str,
    *,
    expires_in_seconds: Optional[int] = None,
    is_live: bool = False,
) -> Dict[str, Any]:
    """Set a broadcast-exclusive price on a shelf item.

    Args:
        session_id: The broadcast session ID.
        item_id: The catalog item ID (must already be on the shelf).
        broadcast_price_cents: The discounted price in cents.
        set_by: User sub of the broadcaster setting the price.
        expires_in_seconds: Optional duration until price reverts.
        is_live: Whether the session is currently live (triggers SSE).

    Returns:
        Dict with the updated shelf item including resolved pricing.

    Raises:
        HTTPException(404) if product not on shelf.
        HTTPException(400) if broadcast_price_cents >= catalog price.
    """
    item = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Product not on shelf.")

    catalog_price = int(item.get("price_cents", 0))
    if broadcast_price_cents >= catalog_price:
        raise HTTPException(
            status_code=400,
            detail=f"Broadcast price ({broadcast_price_cents}) must be less than catalog price ({catalog_price}).",
        )

    ts = now_ts()
    expires_at = (ts + expires_in_seconds) if expires_in_seconds else None

    # Build atomic update expression — SET for active fields, REMOVE for optional expiry
    update_expr = (
        "SET broadcast_price_cents = :bp, "
        "broadcast_price_set_by = :sb, "
        "broadcast_price_set_at = :sa"
    )
    expr_values: Dict[str, Any] = {
        ":bp": broadcast_price_cents,
        ":sb": set_by,
        ":sa": ts,
    }

    if expires_at:
        update_expr += ", broadcast_price_expires_at = :exp"
        expr_values[":exp"] = expires_at
    else:
        update_expr += " REMOVE broadcast_price_expires_at"

    T.broadcast_product_shelf.update_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
    )

    logger.info(
        "broadcast.pricing.set session_id=%s item_id=%s price=%d set_by=%s expires_in=%s",
        session_id, item_id, broadcast_price_cents, set_by, expires_in_seconds,
    )

    # Re-read the updated item for the response
    updated = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item", {})

    out = _shelf_item_out_with_pricing(updated, "live" if is_live else "draft")

    if is_live:
        broadcast_sse_publish(session_id, {"_type": "shelf:price_update", **out})

    return out


def clear_broadcast_price(
    session_id: str,
    item_id: str,
    *,
    is_live: bool = False,
) -> bool:
    """Remove broadcast-exclusive pricing from a shelf item.

    Args:
        session_id: The broadcast session ID.
        item_id: The catalog item ID.
        is_live: Whether the session is currently live (triggers SSE).

    Returns:
        True if the item was found and pricing was cleared, False if not found.
    """
    item = T.broadcast_product_shelf.get_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
    ).get("Item")
    if not item:
        return False

    T.broadcast_product_shelf.update_item(
        Key={"session_id": session_id, "SK": f"ITEM#{item_id}"},
        UpdateExpression=(
            "REMOVE broadcast_price_cents, broadcast_price_expires_at, "
            "broadcast_price_set_by, broadcast_price_set_at"
        ),
    )

    logger.info(
        "broadcast.pricing.clear session_id=%s item_id=%s",
        session_id, item_id,
    )

    if is_live:
        updated = T.broadcast_product_shelf.get_item(
            Key={"session_id": session_id, "SK": f"ITEM#{item_id}"}
        ).get("Item", {})
        out = _shelf_item_out_with_pricing(updated, "live")
        broadcast_sse_publish(session_id, {"_type": "shelf:price_update", **out})

    return True
