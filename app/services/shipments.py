"""First-class Shipment entity for OFBiz Shipping/Logistics (SHP-008).

Provides create_shipment (idempotent on order_id+ship_group_seq),
get_shipment, list_shipments_for_order, update_shipment_tracking,
advance_shipment_status, cancel_shipment_with_refund.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# Valid shipment statuses in order of lifecycle progression.
VALID_STATUSES = {
    "pending_fulfillment",
    "label_created",
    "picked_up",
    "in_transit",
    "out_for_delivery",
    "delivered",
    "exception",
    "returned",
    "cancelled",
}

# Allowed forward transitions: source_status → set of target statuses
_TRANSITIONS: Dict[str, set] = {
    "pending_fulfillment": {"label_created", "cancelled"},
    "label_created":       {"picked_up", "cancelled"},
    "picked_up":           {"in_transit"},
    "in_transit":          {"out_for_delivery", "exception", "returned"},
    "out_for_delivery":    {"delivered", "exception"},
    "delivered":           {"returned"},
    "exception":           {"returned", "in_transit"},
    "returned":            set(),
    "cancelled":           set(),
}


def _require_enabled() -> None:
    if not getattr(S, "shipping_enabled", False):
        raise HTTPException(status_code=404, detail="Shipping is not enabled")


def _audit(event: str, actor: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, actor, None, **fields)
    except Exception:
        pass


def _derive_shipment_id(order_id: str, ship_group_seq: int) -> Tuple[str, str]:
    correlation_id = f"shipment:{order_id}:{ship_group_seq}"
    shipment_id = hashlib.sha256(correlation_id.encode("utf-8")).hexdigest()[:32]
    return shipment_id, correlation_id


def _build_tracking_url(carrier_code: str, tracking_number: str) -> Optional[str]:
    try:
        from app.services.carrier_tracking import build_tracking_url
        return build_tracking_url(carrier_code, tracking_number)
    except ImportError:
        return None


def _detect_carrier(tracking_number: str) -> Optional[str]:
    try:
        from app.services.carrier_tracking import detect_carrier
        return detect_carrier(tracking_number)
    except ImportError:
        return None


def _project_item(item: Dict[str, Any], include_sub: bool = True) -> Dict[str, Any]:
    """Project a DDB shipments row to a clean dict for ShipmentOut."""
    return {k: v for k, v in item.items()}


def _project_item_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "item_id": row["item_id"],
        "sku": row.get("sku"),
        "quantity": int(row.get("quantity", 1)),
        "order_id": row.get("order_id"),
    }


def _project_pkg_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "package_seq": row["package_seq"],
        "weight_oz": int(row.get("weight_oz", 0)),
        "length_in": row.get("length_in"),
        "width_in": row.get("width_in"),
        "height_in": row.get("height_in"),
        "contents": row.get("contents", []),
        "billed_weight_oz": row.get("billed_weight_oz"),
    }


# ---------------------------------------------------------------------------
# Create shipment
# ---------------------------------------------------------------------------

def create_shipment(
    *,
    order_id: str,
    user_id: str,
    carrier_code: str,
    method_code: str,
    ship_to_address: Dict[str, Any],
    line_items: List[Dict[str, Any]],
    packages: Optional[List[Dict[str, Any]]] = None,
    ship_group_seq: int = 1,
    purchase_txn_id: Optional[str] = None,
    ship_method_id: Optional[str] = None,
    actor: str = "system",
) -> Dict[str, Any]:
    _require_enabled()
    shipment_id, correlation_id = _derive_shipment_id(order_id, ship_group_seq)
    ts = now_ts()
    item: Dict[str, Any] = {
        "shipment_id": shipment_id,
        "order_id": order_id,
        "user_id": user_id,
        "status": "pending_fulfillment",
        "carrier_code": carrier_code,
        "method_code": method_code,
        "ship_to_address": ship_to_address,
        "ship_group_seq": ship_group_seq,
        "correlation_id": correlation_id,
        "created_at": ts,
        "updated_at": ts,
        "version": 1,
    }
    if ship_method_id:
        item["ship_method_id"] = ship_method_id
    if purchase_txn_id:
        item["purchase_txn_id"] = purchase_txn_id

    try:
        T.shipments.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(shipment_id)",
        )
    except T.shipments.meta.client.exceptions.ConditionalCheckFailedException:
        # Idempotent: return existing
        existing = get_shipment(shipment_id, user_id=user_id, admin=True)
        if existing is None:
            raise HTTPException(status_code=409, detail="Shipment already exists")
        return existing

    # Write shipment_items rows
    for li in line_items:
        iid = str(li.get("item_id", ""))
        T.shipment_items.put_item(Item={
            "shipment_id": shipment_id,
            "item_id": iid,
            "order_id": order_id,
            "sku": li.get("sku", ""),
            "quantity": int(li.get("quantity", 1)),
            "created_at": ts,
        })

    # Write default single package row
    T.shipment_packages.put_item(Item={
        "shipment_id": shipment_id,
        "package_seq": "00001",
        "weight_oz": 0,
        "contents": [],
        "created_at": ts,
    })

    _audit(
        "shipment.created", actor,
        outcome="success",
        shipment_id=shipment_id,
        order_id=order_id,
        ship_group_seq=ship_group_seq,
    )

    result = dict(item)
    result["items"] = [_project_item_row({"item_id": str(li.get("item_id", "")),
                                          "sku": li.get("sku"), "quantity": int(li.get("quantity", 1)),
                                          "order_id": order_id}) for li in line_items]
    result["packages"] = [_project_pkg_row({"package_seq": "00001", "weight_oz": 0, "contents": []})]
    return result


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def get_shipment(
    shipment_id: str,
    *,
    user_id: Optional[str] = None,
    admin: bool = False,
) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.shipments.get_item(Key={"shipment_id": shipment_id})
    item = resp.get("Item")
    if not item:
        return None
    # Ownership enforcement: non-admin callers can only see their own shipments
    if not admin and user_id and item.get("user_id") != user_id:
        return None  # Return None (→ 404) to avoid leaking existence

    # Hydrate items + packages
    items_resp = T.shipment_items.query(
        KeyConditionExpression=Key("shipment_id").eq(shipment_id)
    )
    pkg_resp = T.shipment_packages.query(
        KeyConditionExpression=Key("shipment_id").eq(shipment_id)
    )

    result = dict(item)
    result["items"] = [_project_item_row(r) for r in items_resp.get("Items", [])]
    result["packages"] = [_project_pkg_row(r) for r in sorted(
        pkg_resp.get("Items", []), key=lambda x: x.get("package_seq", "")
    )]
    return result


def list_shipments_for_order(order_id: str) -> List[Dict[str, Any]]:
    _require_enabled()
    resp = T.shipments.query(
        IndexName="GSI_ORDER",
        KeyConditionExpression=Key("order_id").eq(order_id),
        ScanIndexForward=True,
    )
    return resp.get("Items", [])


def list_shipments_by_status(status: str) -> List[Dict[str, Any]]:
    _require_enabled()
    resp = T.shipments.query(
        IndexName="GSI_STATUS",
        KeyConditionExpression=Key("status").eq(status),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


# ---------------------------------------------------------------------------
# Tracking update
# ---------------------------------------------------------------------------

def update_shipment_tracking(
    shipment_id: str,
    *,
    tracking_number: str,
    carrier_code: Optional[str] = None,
    actor: str = "system",
) -> Dict[str, Any]:
    _require_enabled()
    resp = T.shipments.get_item(Key={"shipment_id": shipment_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Shipment not found")

    # Auto-detect carrier if not supplied
    if not carrier_code:
        detected = _detect_carrier(tracking_number)
        if detected:
            carrier_code = detected
        else:
            carrier_code = item.get("carrier_code", "manual")

    tracking_url = _build_tracking_url(carrier_code, tracking_number)

    ts = now_ts()
    update_expr = "SET tracking_number = :tn, carrier_code = :cc, updated_at = :ts"
    values: Dict[str, Any] = {":tn": tracking_number, ":cc": carrier_code, ":ts": ts}
    if tracking_url:
        update_expr += ", tracking_url = :tu"
        values[":tu"] = tracking_url

    # Advance status to label_created if currently pending_fulfillment
    current_status = item.get("status", "pending_fulfillment")
    if current_status == "pending_fulfillment":
        update_expr += ", #st = :st, version = version + :one"
        values[":st"] = "label_created"
        values[":one"] = 1
        T.shipments.update_item(
            Key={"shipment_id": shipment_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues=values,
        )
    else:
        T.shipments.update_item(
            Key={"shipment_id": shipment_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=values,
        )

    # Best-effort sync to purchase_transactions legacy record
    purchase_txn_id = item.get("purchase_txn_id")
    if purchase_txn_id:
        try:
            from app.services.purchase_history import update_shipping
            update_shipping(item.get("user_id", ""), purchase_txn_id, {
                "carrier": carrier_code,
                "tracking_number": tracking_number,
                "tracking_url": tracking_url,
                "status": "label_created",
            })
        except Exception:
            pass

    _audit("shipment.tracking.updated", actor,
           shipment_id=shipment_id, carrier_code=carrier_code,
           tracking_number=tracking_number)

    updated = T.shipments.get_item(Key={"shipment_id": shipment_id}).get("Item", {})
    return updated


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------

def advance_shipment_status(
    shipment_id: str,
    target_status: str,
    *,
    actor: str = "system",
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    _require_enabled()
    if target_status not in VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"Unknown status: {target_status}")

    resp = T.shipments.get_item(Key={"shipment_id": shipment_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Shipment not found")

    current_status = item.get("status", "pending_fulfillment")
    allowed = _TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot transition from '{current_status}' to '{target_status}'",
        )

    ts = now_ts()
    version = int(item.get("version", 1))
    update_expr = "SET #st = :st, updated_at = :ts, version = :nv"
    values: Dict[str, Any] = {
        ":st": target_status,
        ":ts": ts,
        ":nv": version + 1,
        ":cv": version,
    }

    # Set timestamps for terminal states
    if target_status == "label_created" and not item.get("shipped_at"):
        update_expr += ", shipped_at = :ts"
    elif target_status == "delivered":
        update_expr += ", delivered_at = :ts"

    try:
        T.shipments.update_item(
            Key={"shipment_id": shipment_id},
            UpdateExpression=update_expr,
            ConditionExpression="version = :cv",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues=values,
        )
    except T.shipments.meta.client.exceptions.ConditionalCheckFailedException:
        raise HTTPException(
            status_code=409,
            detail="Concurrent modification detected; please retry",
        )

    _audit("shipment.status.advanced", actor,
           shipment_id=shipment_id,
           from_status=current_status,
           to_status=target_status)

    updated = T.shipments.get_item(Key={"shipment_id": shipment_id}).get("Item", {})
    return updated


def cancel_shipment_with_refund(
    shipment_id: str,
    user_sub: str,
    *,
    reason: str = "cancelled",
    actor: str = "system",
) -> Dict[str, Any]:
    """Cancel a shipment and optionally refund its shipping charge.

    D1 reconciliation: uses new_ledger_entry with a POSITIVE signed_amount_cents
    stored in extra (credit to the user, never negative amount).
    """
    _require_enabled()
    resp = T.shipments.get_item(Key={"shipment_id": shipment_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Shipment not found")

    current_status = item.get("status", "pending_fulfillment")
    if current_status == "cancelled":
        return item

    # Check we can cancel
    if current_status in ("delivered", "returned"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot cancel a shipment in '{current_status}' status",
        )

    shipping_amount_cents = int(item.get("shipping_amount_cents", 0))

    # Idempotency key for the refund ledger entry
    billing_idempotency_key = hashlib.sha256(
        f"shipping_refund:{shipment_id}".encode("utf-8")
    ).hexdigest()[:32]

    # Write refund ledger entry if there is an amount to refund
    if shipping_amount_cents > 0:
        sentinel_pk = f"USER#{user_sub}"
        sentinel_sk = f"SHIPPING_REFUND#{billing_idempotency_key}"

        # Check sentinel to ensure idempotency
        sentinel_already_written = False
        try:
            from app.core.tables import T as _T
            billing_tbl = _T.billing
            sentinel_resp = billing_tbl.get_item(Key={"pk": sentinel_pk, "sk": sentinel_sk})
            sentinel_already_written = bool(sentinel_resp.get("Item"))
        except Exception:
            pass

        if not sentinel_already_written:
            try:
                from app.services.billing_shared import new_ledger_entry
                from app.core.tables import T as _T
                billing_tbl = _T.billing

                # Sentinel put (idempotency guard)
                try:
                    billing_tbl.put_item(
                        Item={"pk": sentinel_pk, "sk": sentinel_sk, "shipment_id": shipment_id},
                        ConditionExpression="attribute_not_exists(pk)",
                    )
                except Exception:
                    pass  # race: already written, skip

                # Write ledger credit entry.
                # D1: signed_amount_cents=+shipping_amount_cents (credit to user).
                _, ledger_item = new_ledger_entry(
                    key_name="pk",
                    key_value=sentinel_pk,
                    entry_type="shipping_refund",
                    amount_cents=shipping_amount_cents,
                    state="settled",
                    reason="shipping_refund",
                    extra={
                        "provider": item.get("carrier_code", "manual"),
                        "shipment_id": shipment_id,
                        "idempotency_key": billing_idempotency_key,
                        "signed_amount_cents": shipping_amount_cents,  # D1: positive = credit
                    },
                )
                billing_tbl.put_item(Item={**ledger_item, "pk": sentinel_pk})

            except Exception:
                pass  # best-effort: refund failure must not block cancel

    # Cancel the shipment
    ts = now_ts()
    T.shipments.update_item(
        Key={"shipment_id": shipment_id},
        UpdateExpression="SET #st = :st, updated_at = :ts, cancel_reason = :r, version = version + :one",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "cancelled",
            ":ts": ts,
            ":r": reason,
            ":one": 1,
        },
    )
    _audit("shipment.cancelled", actor, shipment_id=shipment_id, reason=reason)
    updated = T.shipments.get_item(Key={"shipment_id": shipment_id}).get("Item", {})
    return updated


# ---------------------------------------------------------------------------
# Attach ship group to order
# ---------------------------------------------------------------------------

def attach_ship_group(order_id: str, ship_group_data: Dict[str, Any]) -> None:
    """Write ship_group attribute to orders table (additive, flag-gated).

    Called after order creation when shipping_enabled is True.
    Safe to call when the orders item already has a ship_group (overwrites).
    """
    if not getattr(S, "shipping_enabled", False):
        return
    try:
        from app.core.tables import T as _T
        _T.orders.update_item(
            Key={"order_id": order_id},
            UpdateExpression="SET ship_group = :sg",
            ExpressionAttributeValues={":sg": ship_group_data},
        )
    except Exception:
        pass  # best-effort; do not block order creation
