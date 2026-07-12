"""OFBiz Shipping fulfillment service — finalize shipment, emit ORD event (FAC-010).

`ship_shipment`: draft → shipped. Stamps carrier/tracking, emits fulfillment event.
`cancel_shipment`: draft → cancelled. Releases inventory reservations.

Cross-cluster deps (inventory, order_lifecycle, carrier_tracking, purchase_history)
all via lazy import (try/except ImportError → graceful skip).
Flag-gated behind FACILITY_FULFILLMENT_ENABLED (default OFF).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


# ─────────────────────────── helpers ───────────────────────────────────────


def _flag_on() -> bool:
    return bool(getattr(S, "facility_fulfillment_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Facility fulfillment is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return default if value is None else int(value)
    except (TypeError, ValueError):
        return default


def _load_shipment(shipment_id: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    resp = T.shipments.query(
        KeyConditionExpression=Key("shipment_id").eq(shipment_id),
    )
    items = resp.get("Items", [])
    meta = next((i for i in items if i.get("sk") == "META"), None)
    if meta is None:
        raise HTTPException(status_code=404, detail="Shipment not found")
    packages = [i for i in items if i.get("sk", "").startswith("PKG#")]
    return meta, packages


def _shipment_out(meta: Dict[str, Any], packages: List[Dict[str, Any]]) -> Dict[str, Any]:
    shipped = meta.get("shipped_at", 0)
    return {
        "shipment_id": meta["shipment_id"],
        "order_id": meta.get("order_id", ""),
        "picklist_id": meta.get("picklist_id", ""),
        "status": meta.get("status", "draft"),
        "carrier": meta.get("carrier") or None,
        "tracking_number": meta.get("tracking_number") or None,
        "service_level": meta.get("service_level"),
        "packages": [
            {
                "package_id": p.get("sk", "").replace("PKG#", ""),
                "weight_grams": _to_int(p.get("weight_grams")),
                "length_mm": _to_int(p.get("length_mm")),
                "width_mm": _to_int(p.get("width_mm")),
                "height_mm": _to_int(p.get("height_mm")),
                "contents": p.get("contents", []),
                "notes": p.get("notes"),
            }
            for p in sorted(packages, key=lambda x: x.get("sk", ""))
        ],
        "notes": meta.get("notes"),
        "created_by": meta.get("created_by"),
        "created_at": _to_int(meta.get("created_at")),
        "shipped_at": None if not shipped else _to_int(shipped) or None,
        "delivered_at": None if not meta.get("delivered_at") else _to_int(meta.get("delivered_at")) or None,
    }


def _transition_shipment(
    shipment_id: str,
    from_status: str,
    to_status: str,
    *,
    extra_set: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    set_expr = "SET #s = :new, updated_at = :now"
    expr_vals: Dict[str, Any] = {
        ":new": to_status,
        ":from": from_status,
        ":now": now_ts(),
    }
    if extra_set:
        for k, v in extra_set.items():
            set_expr += f", {k} = :{k}"
            expr_vals[f":{k}"] = v

    try:
        resp = T.shipments.update_item(
            Key={"shipment_id": shipment_id, "sk": "META"},
            UpdateExpression=set_expr,
            ConditionExpression="#s = :from",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues=expr_vals,
            ReturnValues="ALL_OLD",
        )
        return resp.get("Attributes")
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ConditionalCheckFailedException":
            return None
        raise


# ─────────────────────────── public API ────────────────────────────────────


def ship_shipment(
    shipment_id: str,
    *,
    carrier: str,
    tracking_number: str,
    shipped_by: str,
    service_level: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Finalize a draft shipment: stamp carrier+tracking, advance to shipped.

    Idempotent: second call on an already-shipped shipment returns existing record.
    Optionally links tracking to purchase_history and calls order_lifecycle.
    """
    _require_enabled()
    meta, packages = _load_shipment(shipment_id)

    if meta["status"] == "shipped":
        return _shipment_out(meta, packages)

    if meta["status"] != "draft":
        raise HTTPException(
            status_code=409,
            detail=f"Shipment must be in 'draft' status to ship; current={meta['status']!r}",
        )

    # Validate carrier against known carriers (lazy import)
    resolved_carrier = carrier.lower()
    try:
        from app.services.carrier_tracking import CARRIER_TRACKING_URLS, detect_carrier  # type: ignore[import]
        if resolved_carrier not in CARRIER_TRACKING_URLS:
            auto = detect_carrier(tracking_number)
            if auto:
                resolved_carrier = auto
            # else: allow unknown carrier (graceful)
    except ImportError:
        pass

    ts = now_ts()
    extra: Dict[str, Any] = {
        "carrier": resolved_carrier,
        "tracking_number": tracking_number,
        "shipped_at": ts,
    }
    if service_level:
        extra["service_level"] = service_level
    if notes:
        extra["notes"] = notes

    old = _transition_shipment(shipment_id, "draft", "shipped", extra_set=extra)
    if old is None:
        # Race: already shipped
        meta, packages = _load_shipment(shipment_id)
        return _shipment_out(meta, packages)

    order_id = meta.get("order_id", "")

    # Optional: link tracking to purchase_history (best-effort)
    try:
        from app.services.purchase_history import update_shipping  # type: ignore[import]
        shipping_info = {
            "carrier": resolved_carrier,
            "tracking_number": tracking_number,
            "status": "shipped",
        }
        update_shipping(shipped_by, order_id, shipping_info)
    except Exception:
        pass

    # Optional: advance order to 'shipped' via ORD module (best-effort)
    order_lifecycle_enabled = bool(getattr(S, "order_lifecycle_enabled", False))
    if order_lifecycle_enabled and order_id:
        try:
            from app.services.order_lifecycle import transition_order  # type: ignore[import]
            transition_order(
                order_id,
                "shipped",
                actor=shipped_by,
                reason=f"order.fulfillment.shipped:{shipment_id}",
                idempotency_key=f"ship:{shipment_id}",
            )
        except Exception:
            pass

    _audit("shipping.shipped", shipped_by, shipment_id=shipment_id,
           order_id=order_id, carrier=resolved_carrier, tracking_number=tracking_number)
    meta, packages = _load_shipment(shipment_id)
    return _shipment_out(meta, packages)


def cancel_shipment(
    shipment_id: str,
    *,
    cancelled_by: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Cancel a draft shipment. Releases inventory reservations for picklist lines."""
    _require_enabled()
    meta, packages = _load_shipment(shipment_id)

    if meta["status"] == "cancelled":
        return _shipment_out(meta, packages)

    if meta["status"] not in ("draft",):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot cancel shipment in status={meta['status']!r}",
        )

    old = _transition_shipment(shipment_id, "draft", "cancelled")
    if old is None:
        meta, packages = _load_shipment(shipment_id)
        return _shipment_out(meta, packages)

    # Release inventory reservations for picklist lines
    picklist_id = meta.get("picklist_id", "")
    if picklist_id:
        _release_picklist_reservations(picklist_id, cancelled_by=cancelled_by)

    _audit("shipping.cancelled", cancelled_by, shipment_id=shipment_id,
           picklist_id=picklist_id, reason=reason)
    meta, packages = _load_shipment(shipment_id)
    return _shipment_out(meta, packages)


def _release_picklist_reservations(picklist_id: str, *, cancelled_by: str) -> None:
    """Release active reservations on picklist lines (best-effort)."""
    inv_enabled = bool(getattr(S, "inventory_reservations_enabled", False))
    if not inv_enabled:
        return
    try:
        from app.services import inventory as inv  # type: ignore[import]
    except ImportError:
        return

    try:
        resp = T.picklists.query(
            KeyConditionExpression=Key("picklist_id").eq(picklist_id),
        )
        for item in resp.get("Items", []):
            if not item.get("sk", "").startswith("LINE#"):
                continue
            line_status = item.get("line_status", "open")
            if line_status not in ("open", "picked"):
                continue
            reservation_id = item.get("reservation_id")
            if reservation_id:
                try:
                    inv.release_reservation(
                        reservation_id,
                        reason="shipment_cancelled",
                        user_sub=cancelled_by,
                    )
                except Exception:
                    pass
    except Exception:
        pass


def get_shipment(shipment_id: str) -> Dict[str, Any]:
    """Return shipment with packages."""
    _require_enabled()
    meta, packages = _load_shipment(shipment_id)
    return _shipment_out(meta, packages)


def list_shipments_for_order(
    order_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List shipments for an order via GSI_ORDER."""
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor
    from boto3.dynamodb.conditions import Attr

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_ORDER",
        "KeyConditionExpression": Key("order_id").eq(order_id),
        "FilterExpression": Attr("sk").eq("META"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.shipments.query(**kwargs)
    items = [_shipment_out(i, []) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"shipments": items, "next_cursor": next_cursor}
