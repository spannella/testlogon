"""Live-stream commerce: pinned products for a live broadcast session (LIVECOM L1/L2).

A host pins products to their LIVE broadcast session -- either their OWN catalog
item or ANY other seller's product as an AFFILIATE. Viewers read the pinned set
("shop this stream") and buy in-stream. is_affiliate is DERIVED from ownership
(catalog creator_id != session host) so a host can never mislabel a foreign
product as their own. L2 stores the seller-set per-listing affiliate_commission_bps
directly on the catalog item (owner-scoped set).

Backed by the LiveStreamProducts table (PK session_id / SK). Pinned products use
SK = "PRODUCT#<product_id>"; the L4 settlement idempotency marker reuses the same
table under session_id = "ORDER#<order_id>", SK = "SETTLEMENT".
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.routers.catalog import cat_pk, item_sk

logger = logging.getLogger("livecom.products")

MAX_PINNED = 100
DEFAULT_AFFILIATE_COMMISSION_BPS = 1000  # 10% -- sensible default a seller can override


def _product_sk(product_id: str) -> str:
    return f"PRODUCT#{product_id}"


# ─── L2: per-listing affiliate commission (owner-scoped) ───────────────────────

def get_affiliate_commission_bps(category_id: str, item_id: str) -> int:
    """Read a listing's seller-set affiliate commission (bps). Default 1000 (10%)."""
    item = T.catalog.get_item(Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)}).get("Item")
    if not item:
        return DEFAULT_AFFILIATE_COMMISSION_BPS
    v = item.get("affiliate_commission_bps")
    try:
        return max(0, min(10000, int(v)))
    except (TypeError, ValueError):
        return DEFAULT_AFFILIATE_COMMISSION_BPS


def set_affiliate_commission_bps(category_id: str, item_id: str, owner_sub: str, bps: int) -> Dict[str, Any]:
    """Owner-scoped: the SELLER sets the affiliate commission % a host earns for
    selling this listing via a stream. Only the catalog item's creator_id may set it."""
    if bps < 0 or bps > 10000:
        raise HTTPException(status_code=400, detail="affiliate_commission_bps must be 0..10000")
    item = T.catalog.get_item(Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)}).get("Item")
    if not item or item.get("entity") != "item":
        raise HTTPException(status_code=404, detail="Catalog item not found.")
    owner = item.get("creator_id")
    if owner and owner != owner_sub:
        raise HTTPException(status_code=403, detail="Only the listing owner can set the affiliate commission.")
    T.catalog.update_item(
        Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)},
        UpdateExpression="SET affiliate_commission_bps = :b",
        ExpressionAttributeValues={":b": int(bps)},
    )
    return {
        "category_id": category_id,
        "item_id": item_id,
        "affiliate_commission_bps": int(bps),
        "seller_id": owner or owner_sub,
    }


# ─── L1: pin / unpin / list ────────────────────────────────────────────────────

def _pinned_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "session_id": item.get("session_id", ""),
        "product_id": item.get("product_id", ""),
        "category_id": item.get("category_id", ""),
        "seller_id": item.get("seller_id", ""),
        "is_affiliate": bool(item.get("is_affiliate", False)),
        "affiliate_commission_bps": int(item.get("affiliate_commission_bps", 0)),
        "name": item.get("name", ""),
        "price_cents": int(item.get("price_cents", 0)),
        "currency": item.get("currency", "USD"),
        "image_url": item.get("image_url"),
        "pinned_by": item.get("pinned_by", ""),
        "pinned_at": int(item.get("pinned_at", 0)),
    }


def pin_product(session_id: str, host_sub: str, product_id: str, category_id: str) -> Dict[str, Any]:
    """Host pins a product (own OR affiliate-any) to a live session. is_affiliate is
    derived from ownership: seller (catalog creator_id) != host => affiliate.

    Caller MUST already have enforced host-only (session.created_by == host_sub).
    """
    cat_item = T.catalog.get_item(
        Key={"PK": cat_pk(category_id), "SK": item_sk(product_id)}
    ).get("Item")
    if not cat_item or cat_item.get("entity") != "item":
        raise HTTPException(status_code=404, detail="Catalog item not found.")

    seller_id = cat_item.get("creator_id") or host_sub
    is_affiliate = seller_id != host_sub
    aff_bps = get_affiliate_commission_bps(category_id, product_id) if is_affiliate else 0

    cnt = T.live_stream_products.query(
        KeyConditionExpression=Key("session_id").eq(session_id), Select="COUNT"
    ).get("Count", 0)
    existing = T.live_stream_products.get_item(
        Key={"session_id": session_id, "SK": _product_sk(product_id)}
    ).get("Item")
    if not existing and cnt >= MAX_PINNED:
        raise HTTPException(status_code=400, detail=f"Too many pinned products ({MAX_PINNED} max).")

    image_urls = cat_item.get("image_urls") or []
    ts = now_ts()
    item = {
        "session_id": session_id,
        "SK": _product_sk(product_id),
        "product_id": product_id,
        "category_id": category_id,
        "seller_id": seller_id,
        "is_affiliate": is_affiliate,
        "affiliate_commission_bps": int(aff_bps),
        "name": cat_item.get("name", ""),
        "price_cents": int(cat_item.get("price_cents", 0)),
        "currency": cat_item.get("currency", "USD"),
        "image_url": image_urls[0] if image_urls else None,
        "pinned_by": host_sub,
        "pinned_at": ts,
    }
    T.live_stream_products.put_item(Item=item)
    logger.info("livecom.pin session=%s product=%s seller=%s affiliate=%s host=%s",
                session_id, product_id, seller_id, is_affiliate, host_sub)
    return _pinned_out(item)


def unpin_product(session_id: str, product_id: str) -> bool:
    """Remove a pinned product. Returns True if it existed. Caller enforces host-only."""
    existing = T.live_stream_products.get_item(
        Key={"session_id": session_id, "SK": _product_sk(product_id)}
    ).get("Item")
    if not existing:
        return False
    T.live_stream_products.delete_item(
        Key={"session_id": session_id, "SK": _product_sk(product_id)}
    )
    return True


def get_pinned(session_id: str, product_id: str) -> Optional[Dict[str, Any]]:
    """Raw pinned record for a product in a session (used by the L4 split)."""
    return T.live_stream_products.get_item(
        Key={"session_id": session_id, "SK": _product_sk(product_id)}
    ).get("Item")


def list_stream_products(session_id: str) -> List[Dict[str, Any]]:
    """Shop-this-stream: all products pinned to a session, refreshing the live
    affiliate commission for affiliate items."""
    resp = T.live_stream_products.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
        Limit=MAX_PINNED,
    )
    out: List[Dict[str, Any]] = []
    for it in resp.get("Items", []):
        if not str(it.get("SK", "")).startswith("PRODUCT#"):
            continue
        row = _pinned_out(it)
        if row["is_affiliate"]:
            row["affiliate_commission_bps"] = get_affiliate_commission_bps(
                row["category_id"], row["product_id"]
            )
        out.append(row)
    out.sort(key=lambda r: r.get("pinned_at", 0))
    return out
