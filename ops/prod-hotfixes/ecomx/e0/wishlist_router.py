from __future__ import annotations

import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.tables import T
from app.routers.catalog import cat_pk, item_sk, _catalog_item_out
from app.services.alerts import audit_event
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

# WISHLIST: per-user saved catalog items. Reuses the existing per-user
# ``shopping_cart`` DynamoDB table (PK=USER#<sub>) with a dedicated
# ``WISH#<category_id>#<item_id>`` sort-key namespace so no new infra is
# provisioned. Render fields are snapshotted at save time and best-effort
# refreshed from the live catalog on read.
router = APIRouter(
    prefix="/ui/wishlist",
    tags=["wishlist"],
    dependencies=[Depends(maybe_enforce_api_key_route_policy)],
)


def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _wish_sk(category_id: str, item_id: str) -> str:
    return f"WISH#{category_id}#{item_id}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class WishlistAddIn(BaseModel):
    category_id: str = Field(..., min_length=1)
    item_id: str = Field(..., min_length=1)


class WishlistItemOut(BaseModel):
    category_id: str
    item_id: str
    name: Optional[str] = None
    description: Optional[str] = None
    price_cents: Optional[int] = None
    currency: str = "USD"
    image_urls: List[str] = []
    creator_id: Optional[str] = None
    stock_status: Optional[str] = None
    # ``available`` is False when the underlying catalog item was removed after
    # it was saved (the row is still returned so the client can render a
    # "no longer available" state and offer removal).
    available: bool = True
    added_at: Optional[str] = None


class WishlistListOut(BaseModel):
    items: List[WishlistItemOut]
    count: int


def _fetch_catalog_item(category_id: str, item_id: str) -> Optional[Dict[str, Any]]:
    """Return the live catalog item record, or None if it does not exist."""
    try:
        resp = T.catalog.get_item(Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)})
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("wishlist: catalog lookup failed for %s/%s: %s", category_id, item_id, exc)
        return None
    return resp.get("Item")


def _snapshot_from_catalog(item: Dict[str, Any]) -> Dict[str, Any]:
    """Denormalize the render fields we persist on the wishlist row."""
    out = _catalog_item_out(item)
    return {
        "name": out.name,
        "description": out.description,
        "price_cents": _to_int(out.price_cents),
        "currency": out.currency or "USD",
        "image_urls": list(out.image_urls or []),
        "creator_id": out.creator_id,
        "stock_status": out.stock_status,
    }


def _row_to_out(row: Dict[str, Any]) -> WishlistItemOut:
    """Build a response item, best-effort refreshing from the live catalog."""
    category_id = row.get("category_id")
    item_id = row.get("item_id")
    live = _fetch_catalog_item(category_id, item_id) if category_id and item_id else None
    if live:
        snap = _snapshot_from_catalog(live)
        available = True
    else:
        snap = {
            "name": row.get("name"),
            "description": row.get("description"),
            "price_cents": _to_int(row.get("price_cents")),
            "currency": row.get("currency", "USD") or "USD",
            "image_urls": list(row.get("image_urls") or []),
            "creator_id": row.get("creator_id"),
            "stock_status": row.get("stock_status"),
        }
        available = False
    return WishlistItemOut(
        category_id=category_id,
        item_id=item_id,
        added_at=row.get("added_at"),
        available=available,
        **snap,
    )


@router.get("", response_model=WishlistListOut)
async def list_wishlist(ctx=Depends(require_ui_session)):
    """List the caller's saved catalog items (newest first)."""
    resp = T.shopping_cart.query(
        KeyConditionExpression=Key("PK").eq(_user_pk(ctx["user_sub"]))
        & Key("SK").begins_with("WISH#"),
    )
    rows = resp.get("Items", [])
    rows.sort(key=lambda r: str(r.get("added_at") or ""), reverse=True)
    items = [_row_to_out(r) for r in rows]
    return {"items": items, "count": len(items)}


@router.post("", response_model=WishlistItemOut)
async def add_wishlist(body: WishlistAddIn, req: Request = None, ctx=Depends(require_ui_session)):
    """Save a catalog item to the caller's wishlist (idempotent upsert)."""
    user_sub = ctx["user_sub"]
    live = _fetch_catalog_item(body.category_id, body.item_id)
    if not live:
        raise HTTPException(status_code=404, detail="Catalog item not found.")
    snap = _snapshot_from_catalog(live)
    added_at = _now_iso()
    record: Dict[str, Any] = {
        "PK": _user_pk(user_sub),
        "SK": _wish_sk(body.category_id, body.item_id),
        "entity": "wishlist_item",
        "category_id": body.category_id,
        "item_id": body.item_id,
        "added_at": added_at,
        "currency": snap.get("currency", "USD"),
    }
    for key in ("name", "description", "price_cents", "image_urls", "creator_id", "stock_status"):
        val = snap.get(key)
        if val is not None:
            record[key] = val
    T.shopping_cart.put_item(Item=record)
    audit_event(
        "wishlist_item_added",
        user_sub,
        req,
        outcome="success",
        category_id=body.category_id,
        item_id=body.item_id,
    )
    return WishlistItemOut(
        category_id=body.category_id,
        item_id=body.item_id,
        added_at=added_at,
        available=True,
        **snap,
    )


@router.delete("/{category_id}/{item_id}")
async def remove_wishlist(category_id: str, item_id: str, req: Request = None, ctx=Depends(require_ui_session)):
    """Remove a saved catalog item (idempotent)."""
    user_sub = ctx["user_sub"]
    T.shopping_cart.delete_item(
        Key={"PK": _user_pk(user_sub), "SK": _wish_sk(category_id, item_id)},
    )
    audit_event(
        "wishlist_item_removed",
        user_sub,
        req,
        outcome="success",
        category_id=category_id,
        item_id=item_id,
    )
    return {"deleted": True}
