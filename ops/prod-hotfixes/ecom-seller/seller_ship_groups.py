"""ECOM-SELLER (G1-G4) - per-seller ship groups + seller-scoped fulfilment.

On order APPROVAL (payment captured) we split the buyer's cart into one
*seller ship group* per distinct seller (catalog-item owner). Each group carries
ONLY that seller's line items (with the REAL product name + qty + unit price),
the buyer's shipping address, and the buyer's display name/email - never any
other seller's items and never the buyer's payment internals.

A non-admin seller then lists + fulfils their own groups (``/ui/seller/sales``),
advancing the same order-lifecycle state machine scoped to their group. Each
seller is notified ("you sold it") via in-app alert + FCM push on group creation.

Storage: table ``seller_ship_groups`` - PK ``seller_id`` / SK ``ship_group_id``
(deterministic ``sha1(order_id#seller_id)`` -> idempotent re-approval), GSI
``GSI_ORDER`` (partition ``order_id``) for per-order (multi-seller) listing.
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T

logger = logging.getLogger(__name__)

# The seller ship-group status follows the canonical order-lifecycle state
# machine; a group is born "approved" (the order is paid) and the seller drives
# it approved -> allocated -> picking -> packed -> shipped.
_START_STATUS = "approved"


def _now() -> int:
    return int(time.time())


def _sg_id(order_id: str, seller_id: str) -> str:
    return hashlib.sha1(f"{order_id}#{seller_id}".encode("utf-8")).hexdigest()[:32]


def _seller_of(item: Dict[str, Any]) -> str:
    return str(item.get("creator_user_id") or item.get("seller_id") or "").strip()


def _transitions() -> Dict[str, Any]:
    from app.services.order_lifecycle import TRANSITIONS
    return TRANSITIONS


def allowed_transitions(status: str) -> List[str]:
    return sorted(_transitions().get(str(status or ""), set()))


# -- buyer shipping address ---------------------------------------------------

def _resolve_ship_to(buyer: Optional[Dict[str, Any]], buyer_sub: str) -> Dict[str, Any]:
    """Buyer shipping address: prefer the profile mailing_address echoed on the
    purchase; fall back to the buyer's primary saved address (/ui/addresses)."""
    buyer = buyer or {}
    addr = buyer.get("mailing_address")
    if isinstance(addr, dict) and any(v for v in addr.values()):
        return dict(addr)
    try:
        from app.services.addresses import list_addresses
        rows = list_addresses(buyer_sub) or []
        primary = next((r for r in rows if r.get("is_primary") or r.get("primary")), None)
        chosen = primary or (rows[0] if rows else None)
        if chosen:
            return {k: v for k, v in chosen.items() if k not in ("user_sub",) and v is not None}
    except Exception:
        logger.exception("ship_to address fallback failed for buyer %s", buyer_sub)
    return {}


# -- G4: backfill the real product name onto the order line-item rows ---------

def _backfill_order_item_names(order_id: str, cart_items: List[Dict[str, Any]]) -> None:
    """The cart->order line rows are seeded with the internal product_type
    (``internal_api_package``) and no ``name``. Backfill each row's real catalog
    name + seller_id from the matching cart item so the order line (buyer detail
    AND seller sale) shows the real product name. Match by sku, index fallback."""
    try:
        resp = T.order_items.query(KeyConditionExpression=Key("order_id").eq(order_id))
        rows = sorted(resp.get("Items", []), key=lambda r: int(str(r.get("item_id") or "0") or 0))
    except Exception:
        logger.exception("backfill: could not load order_items for %s", order_id)
        return
    by_sku = {str(ci.get("sku")): ci for ci in cart_items if ci.get("sku")}
    for idx, row in enumerate(rows):
        ci = by_sku.get(str(row.get("sku"))) or (cart_items[idx] if idx < len(cart_items) else None)
        if not ci:
            continue
        name = ci.get("name")
        seller = _seller_of(ci)
        if not name and not seller:
            continue
        set_parts, vals, names = [], {}, {}
        if name:
            set_parts.append("#nm = :nm"); vals[":nm"] = str(name); names["#nm"] = "name"
        if seller:
            set_parts.append("seller_id = :sid"); vals[":sid"] = seller
        try:
            kwargs = {
                "Key": {"order_id": order_id, "item_id": str(row.get("item_id"))},
                "UpdateExpression": "SET " + ", ".join(set_parts),
                "ExpressionAttributeValues": vals,
            }
            if names:
                kwargs["ExpressionAttributeNames"] = names
            T.order_items.update_item(**kwargs)
        except Exception:
            logger.exception("backfill name failed for order %s item %s", order_id, row.get("item_id"))


# -- populate on approval -----------------------------------------------------

def populate_on_approval(
    *,
    order_id: str,
    buyer_sub: str,
    cart_items: List[Dict[str, Any]],
    buyer: Optional[Dict[str, Any]] = None,
    currency: str = "USD",
) -> List[Dict[str, Any]]:
    """Split the paid order into per-seller ship groups (idempotent) + notify
    each NEW seller. Returns the list of created group rows."""
    if not S.order_lifecycle_enabled or not order_id:
        return []

    # G4: real line names onto the order rows first (buyer + seller both benefit).
    _backfill_order_item_names(order_id, cart_items)

    ship_to = _resolve_ship_to(buyer, buyer_sub)
    buyer_name = str((buyer or {}).get("display_name") or buyer_sub)
    buyer_email = str((buyer or {}).get("displayed_email") or "")

    # group cart line items by seller (skip self-purchases + items with no seller)
    by_seller: Dict[str, List[Dict[str, Any]]] = {}
    for ci in cart_items:
        seller = _seller_of(ci)
        if not seller or seller == buyer_sub:
            continue
        qty = int(ci.get("quantity") or 1)
        unit = int(ci.get("unit_price_cents") or 0)
        line_total = int(ci.get("line_total_cents") or (qty * unit))
        by_seller.setdefault(seller, []).append({
            "item_id": str(ci.get("item_id") or ci.get("sku") or ""),
            "sku": str(ci.get("sku") or ""),
            "name": str(ci.get("name") or ""),
            "quantity": qty,
            "unit_price_cents": unit,
            "line_total_cents": line_total,
        })

    created: List[Dict[str, Any]] = []
    now = _now()
    for seller, lines in by_seller.items():
        sg_id = _sg_id(order_id, seller)
        subtotal = sum(int(l["line_total_cents"]) for l in lines)
        row = {
            "seller_id": seller,
            "ship_group_id": sg_id,
            "order_id": order_id,
            "buyer_id": buyer_sub,
            "buyer_name": buyer_name,
            "buyer_email": buyer_email,
            "ship_to": ship_to,
            "line_items": lines,
            "item_count": len(lines),
            "subtotal_cents": int(subtotal),
            "currency": str(currency or "USD").upper(),
            "status": _START_STATUS,
            "created_at": now,
            "updated_at": now,
        }
        try:
            T.seller_ship_groups.put_item(
                Item=row,
                ConditionExpression="attribute_not_exists(ship_group_id)",
            )
        except Exception as exc:
            code = ""
            try:
                code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
            except Exception:
                pass
            if code == "ConditionalCheckFailedException":
                continue  # already exists (idempotent replay) - do not re-notify
            logger.exception("failed to write seller ship group %s/%s", order_id, seller)
            continue
        created.append(row)
        _notify_seller(row)
    return created


def _notify_seller(row: Dict[str, Any]) -> None:
    """G1: "you sold it" in-app alert (write_alert) + FCM push to the seller,
    deep-linking to their sales queue."""
    seller = row["seller_id"]
    sg_id = row["ship_group_id"]
    lines = row.get("line_items", [])
    n = len(lines)
    first = (lines[0].get("name") if lines else "") or "your item"
    summary = first if n <= 1 else f"{first} +{n - 1} more"
    city = (row.get("ship_to") or {}).get("city") or ""
    ship_hint = f" - ship to {row.get('buyer_name','buyer')}" + (f", {city}" if city else "")
    title = f"You sold {summary}"
    body = f"{row.get('buyer_name','A buyer')} bought {n} item(s){ship_hint}. Tap to fulfil."
    action_url = f"/seller/orders?sale={sg_id}"
    alert_id = ""
    try:
        from app.services.alerts import write_alert
        res = write_alert(
            seller,
            event="shop_item_sold",
            outcome="success",
            title=title,
            details={
                "alert_type": "shop_item_sold",
                "ship_group_id": sg_id,
                "order_id": row.get("order_id"),
                "item_count": n,
                "subtotal_cents": row.get("subtotal_cents"),
                "buyer_name": row.get("buyer_name"),
                "summary": summary,
            },
            action_url=action_url,
            source_type="seller_ship_group",
            source_id=sg_id,
        )
        alert_id = (res or {}).get("alert_id", "") if isinstance(res, dict) else ""
    except Exception:
        logger.exception("write_alert failed for seller %s sg %s", seller, sg_id)
    try:
        from app.services.push import send_push_for_alert
        # P1: pass the sale deep-link so the FCM data payload carries action_url.
        send_push_for_alert(seller, "shop_item_sold", title, body, alert_id or sg_id, action_url=action_url)
    except Exception:
        logger.exception("push failed for seller %s sg %s", seller, sg_id)


# -- seller-scoped reads ------------------------------------------------------

def list_for_seller(seller_id: str, *, limit: int = 50, cursor: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("seller_id").eq(seller_id),
        "ScanIndexForward": False,
        "Limit": max(1, min(int(limit), 200)),
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = {"seller_id": seller_id, "ship_group_id": cursor}
    resp = T.seller_ship_groups.query(**kwargs)
    rows = list(resp.get("Items", []))
    rows.sort(key=lambda r: int(r.get("created_at", 0)), reverse=True)
    lek = resp.get("LastEvaluatedKey") or {}
    return rows, (lek.get("ship_group_id") if lek else None)


def get_for_seller(seller_id: str, ship_group_id: str) -> Optional[Dict[str, Any]]:
    resp = T.seller_ship_groups.get_item(Key={"seller_id": seller_id, "ship_group_id": ship_group_id})
    row = resp.get("Item")
    if not row or str(row.get("seller_id")) != str(seller_id):
        return None
    return row


def list_by_order(order_id: str) -> List[Dict[str, Any]]:
    """All seller groups for one order (per-order multi-seller view / admin / verify)."""
    resp = T.seller_ship_groups.query(
        IndexName="GSI_ORDER",
        KeyConditionExpression=Key("order_id").eq(order_id),
    )
    return list(resp.get("Items", []))


# -- seller-scoped fulfilment (transition, scoped to the seller's own group) --

class ShipGroupNotFound(Exception):
    pass


class IllegalShipGroupTransition(Exception):
    def __init__(self, frm: str, to: str) -> None:
        self.frm, self.to = frm, to
        super().__init__(f"illegal transition {frm} -> {to}")


def transition(
    seller_id: str,
    ship_group_id: str,
    target_status: str,
    *,
    actor: str,
    tracking_number: Optional[str] = None,
    carrier: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Advance a seller ship group through the order-lifecycle state machine,
    scoped to the seller's OWN group. Non-admin."""
    row = get_for_seller(seller_id, ship_group_id)
    if not row:
        raise ShipGroupNotFound(ship_group_id)
    current = str(row.get("status") or "")
    target = str(target_status or "")

    if current == target and idempotency_key:
        return row  # idempotent replay

    if target not in _transitions().get(current, set()):
        raise IllegalShipGroupTransition(current, target)

    now = _now()
    set_parts = ["#st = :st", "updated_at = :ua"]
    vals: Dict[str, Any] = {":st": target, ":ua": now, ":cur": current}
    if tracking_number is not None:
        set_parts.append("tracking_number = :tn"); vals[":tn"] = str(tracking_number)
    if carrier is not None:
        set_parts.append("carrier = :ca"); vals[":ca"] = str(carrier)
    set_parts.append("history = list_append(if_not_exists(history, :empty), :h)")
    vals[":empty"] = []
    vals[":h"] = [{"from": current, "to": target, "actor": actor, "ts": now}]

    resp = T.seller_ship_groups.update_item(
        Key={"seller_id": seller_id, "ship_group_id": ship_group_id},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues=vals,
        ConditionExpression="#st = :cur",
        ReturnValues="ALL_NEW",
    )
    return resp.get("Attributes", row)
