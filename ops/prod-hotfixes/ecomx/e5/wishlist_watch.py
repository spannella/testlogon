"""ECOMX-54 (E5) - wishlist restock / price-drop watcher.

When a catalog item's stock or price changes we diff the NEW value against the
snapshot each wishlist row saved (``stock_status`` / ``price_cents``) and, for
every user who wishlisted the item, fire a tappable alert + push:

  - ``wishlist_restock``     : saved snapshot was out_of_stock -> now in stock
  - ``wishlist_price_drop``  : new price strictly lower than the saved snapshot

The wishlist row's snapshot is then refreshed so the same change only notifies
once. Wishlist rows live on the per-user ``shopping_cart`` table under
``SK begins_with WISH#`` (no item-keyed GSI), so we do a bounded scan filtered to
``entity = wishlist_item`` + the target item_id (same pattern as the E2 orphan
self-heal sweep). Best-effort: any failure is logged, never raised into the
catalog write path.
"""
from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr

from app.core.tables import T

logger = logging.getLogger(__name__)

_OUT_OF_STOCK = {"out_of_stock", "sold_out", "unavailable"}


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _scan_wishlist_rows_for_item(category_id: str, item_id: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    start_key = None
    filt = (
        Attr("entity").eq("wishlist_item")
        & Attr("item_id").eq(str(item_id))
        & Attr("category_id").eq(str(category_id))
    )
    while True:
        kwargs: Dict[str, Any] = {"FilterExpression": filt, "Limit": 500}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = T.shopping_cart.scan(**kwargs)
        rows.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return rows


def _emit(user_sub: str, event: str, title: str, body: str, item_id: str,
          category_id: str, details: Dict[str, Any]) -> None:
    action_url = f"/catalog/items/{item_id}"
    alert_id = item_id
    try:
        from app.services.alerts import write_alert
        res = write_alert(
            user_sub, event=event, outcome="info", title=title,
            details={"alert_type": event, "item_id": item_id,
                     "category_id": category_id, **details},
            action_url=action_url,
        )
        if isinstance(res, dict):
            alert_id = res.get("alert_id", item_id)
    except Exception:
        logger.exception("wishlist %s alert failed user=%s item=%s", event, user_sub, item_id)
    try:
        from app.services.push import send_push_for_alert
        send_push_for_alert(user_sub, event, title, body, alert_id, action_url=action_url)
    except Exception:
        logger.exception("wishlist %s push failed user=%s item=%s", event, user_sub, item_id)


def notify_item_changed(
    category_id: str,
    item_id: str,
    *,
    new_stock_status: Optional[str] = None,
    new_price_cents: Optional[int] = None,
) -> Dict[str, int]:
    """Diff the new stock/price vs each wishlister's saved snapshot and notify.

    Returns a small counter dict for verification. Refreshes the snapshot on the
    wishlist row so a change notifies at most once.
    """
    restock_sent = 0
    price_drop_sent = 0
    new_price = _to_int(new_price_cents)
    try:
        rows = _scan_wishlist_rows_for_item(category_id, item_id)
    except Exception:
        logger.exception("wishlist scan failed for %s/%s", category_id, item_id)
        return {"restock": 0, "price_drop": 0, "matched": 0}

    for row in rows:
        user_sub = str(row.get("PK", "")).split("USER#")[-1]
        if not user_sub:
            continue
        saved_status = str(row.get("stock_status") or "").lower()
        saved_price = _to_int(row.get("price_cents"))
        updates: Dict[str, Any] = {}

        # Restock: saved was out-of-stock, now back in stock.
        if new_stock_status is not None:
            ns = str(new_stock_status).lower()
            if saved_status in _OUT_OF_STOCK and ns not in _OUT_OF_STOCK:
                _emit(user_sub, "wishlist_restock",
                      "Back in stock", f"{row.get('name') or 'An item'} on your wishlist is back in stock. Tap to buy.",
                      item_id, category_id, {"stock_status": ns})
                restock_sent += 1
            updates["stock_status"] = new_stock_status

        # Price drop: new price strictly lower than the saved snapshot.
        if new_price is not None:
            if saved_price is not None and new_price < saved_price:
                _emit(user_sub, "wishlist_price_drop",
                      "Price drop", f"{row.get('name') or 'An item'} on your wishlist dropped in price. Tap to view.",
                      item_id, category_id,
                      {"old_price_cents": saved_price, "new_price_cents": new_price})
                price_drop_sent += 1
            updates["price_cents"] = new_price

        # Refresh the snapshot so the same change won't re-notify.
        if updates:
            try:
                set_expr = ", ".join(f"#{k} = :{k}" for k in updates)
                T.shopping_cart.update_item(
                    Key={"PK": row["PK"], "SK": row["SK"]},
                    UpdateExpression="SET " + set_expr,
                    ExpressionAttributeNames={f"#{k}": k for k in updates},
                    ExpressionAttributeValues={f":{k}": v for k, v in updates.items()},
                )
            except Exception:
                logger.exception("wishlist snapshot refresh failed user=%s item=%s", user_sub, item_id)

    return {"restock": restock_sent, "price_drop": price_drop_sent, "matched": len(rows)}
