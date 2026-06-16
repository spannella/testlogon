"""OFBiz Picking service — picklist generation, pick confirmation, and pack (FAC-008/009).

Lifecycle: pending → picking → picked → packed | cancelled.
Per-line confirmation uses a conditional status guard for idempotency.
On full-pick, commits reservations (or adjusts if no reservation).

Cross-cluster deps (inventory, order_items) via lazy import.
Flag-gated behind FACILITY_FULFILLMENT_ENABLED (default OFF).
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
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


def _load_picklist(picklist_id: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    resp = T.picklists.query(
        KeyConditionExpression=Key("picklist_id").eq(picklist_id),
    )
    items = resp.get("Items", [])
    meta = next((i for i in items if i.get("sk") == "META"), None)
    if meta is None:
        raise HTTPException(status_code=404, detail="Picklist not found")
    lines = sorted(
        [i for i in items if i.get("sk", "").startswith("LINE#")],
        key=lambda x: x.get("sk", ""),
    )
    return meta, lines


def _picklist_out(meta: Dict[str, Any], lines: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "picklist_id": meta["picklist_id"],
        "order_id": meta.get("order_id", ""),
        "status": meta.get("status", "pending"),
        "created_by": meta.get("created_by"),
        "created_at": _to_int(meta.get("created_at")),
        "updated_at": _to_int(meta.get("updated_at")),
        "packed_at": None if meta.get("packed_at") is None else _to_int(meta.get("packed_at")),
        "lines": [],
    }
    if lines:
        result["lines"] = [
            {
                "line_id": l.get("sk", ""),
                "order_line_id": l.get("order_line_id", ""),
                "sku": l.get("sku", ""),
                "requested_quantity": _to_int(l.get("quantity")),
                "picked_quantity": _to_int(l.get("picked_qty")),
                "from_facility_id": l.get("from_facility_id", ""),
                "from_location_id": l.get("location_id", ""),
                "reservation_id": l.get("reservation_id"),
                "status": l.get("line_status", "open"),
            }
            for l in lines
        ]
    return result


def _transition_picklist(
    picklist_id: str,
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
        resp = T.picklists.update_item(
            Key={"picklist_id": picklist_id, "sk": "META"},
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


def generate_picklist(
    order_id: str,
    facility_id: str,
    *,
    user_sub: str,
    location_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a picklist from an order's line items.

    Reads T.order_items (lazy import). If order_items unavailable, creates a
    draft picklist with no lines so the caller can add lines manually.
    """
    _require_enabled()
    picklist_id = uuid.uuid4().hex
    ts = now_ts()

    meta: Dict[str, Any] = {
        "picklist_id": picklist_id,
        "sk": "META",
        "order_id": order_id,
        "facility_id": facility_id,
        "status": "pending",
        "created_by": user_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    T.picklists.put_item(Item=meta)

    line_items: List[Dict[str, Any]] = []

    # Lazy read order items — cross-cluster dep
    try:
        resp = T.order_items.query(
            KeyConditionExpression=Key("order_id").eq(order_id),
        )
        order_lines = resp.get("Items", [])
    except Exception:
        order_lines = []

    pick_location = location_id or "warehouse"
    inv_enabled = bool(getattr(S, "inventory_reservations_enabled", False))

    for idx, ol in enumerate(order_lines, start=1):
        sku = ol.get("sku", "")
        qty = _to_int(ol.get("quantity"))
        item_id = ol.get("item_id", str(idx))
        if not sku or qty <= 0:
            continue

        reservation_id: Optional[str] = None

        # Attempt to reserve stock
        if inv_enabled:
            try:
                from app.services import inventory as inv  # type: ignore[import]
                res = inv.reserve(
                    sku,
                    qty,
                    location_id=pick_location,
                    user_sub=user_sub,
                    cart_id=f"pick:{picklist_id}",
                    ttl_seconds=_to_int(getattr(S, "inventory_reservation_ttl_seconds", 1800), 1800),
                )
                reservation_id = res.get("reservation_id") if res else None
            except Exception:
                pass  # no reservation — adjust at commit time

        li: Dict[str, Any] = {
            "picklist_id": picklist_id,
            "sk": f"LINE#{idx}",
            "order_line_id": item_id,
            "sku": sku,
            "location_id": pick_location,
            "from_facility_id": facility_id,
            "quantity": qty,
            "picked_qty": 0,
            "line_status": "open",
        }
        if reservation_id:
            li["reservation_id"] = reservation_id
        T.picklists.put_item(Item=li)
        line_items.append(li)

    _audit("picking.generated", user_sub, picklist_id=picklist_id, order_id=order_id, line_count=len(line_items))
    return _picklist_out(meta, line_items)


def get_picklist(picklist_id: str) -> Dict[str, Any]:
    """Return full picklist with lines."""
    _require_enabled()
    meta, lines = _load_picklist(picklist_id)
    return _picklist_out(meta, lines)


def list_picklists(
    *,
    status: str = "open",
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List picklists by status via GSI_STATUS."""
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_STATUS",
        "KeyConditionExpression": Key("status").eq(status),
        "FilterExpression": Attr("sk").eq("META"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.picklists.query(**kwargs)
    items = [_picklist_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"picklists": items, "next_cursor": next_cursor}


def confirm_pick(
    picklist_id: str,
    line_no: int,
    picked_qty: int,
    *,
    user_sub: str,
) -> Dict[str, Any]:
    """Confirm a single LINE#{n} row as picked (or short on under-pick).

    Idempotent: if line already in terminal pick state returns current picklist.
    """
    _require_enabled()
    meta, lines = _load_picklist(picklist_id)
    if meta["status"] in ("picked", "packed", "cancelled"):
        return _picklist_out(meta, lines)

    # Advance to picking if still pending
    if meta["status"] == "pending":
        _transition_picklist(picklist_id, "pending", "picking")
        meta, lines = _load_picklist(picklist_id)

    line_sk = f"LINE#{line_no}"
    line = next((l for l in lines if l.get("sk") == line_sk), None)
    if line is None:
        raise HTTPException(status_code=404, detail=f"Picklist line {line_sk} not found")

    if line.get("line_status") in ("picked", "short"):
        return _picklist_out(meta, lines)

    requested = _to_int(line.get("quantity"))
    new_line_status = "picked" if picked_qty >= requested else "short"

    # Update line row
    try:
        T.picklists.update_item(
            Key={"picklist_id": picklist_id, "sk": line_sk},
            UpdateExpression="SET line_status = :ls, picked_qty = :pq",
            ConditionExpression="line_status = :open",
            ExpressionAttributeValues={
                ":ls": new_line_status,
                ":pq": picked_qty,
                ":open": "open",
            },
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "ConditionalCheckFailedException":
            raise
        # Already confirmed — idempotent

    # Check if all lines are terminal
    meta, lines = _load_picklist(picklist_id)
    all_done = all(l.get("line_status") in ("picked", "short", "cancelled") for l in lines)
    if all_done and lines:
        old = _transition_picklist(picklist_id, "picking", "picked")
        if old is not None:
            _commit_picklist_reservations(picklist_id, lines, user_sub=user_sub)
            _audit("picking.picked", user_sub, picklist_id=picklist_id)

    meta, lines = _load_picklist(picklist_id)
    return _picklist_out(meta, lines)


def _commit_picklist_reservations(
    picklist_id: str,
    lines: List[Dict[str, Any]],
    *,
    user_sub: str,
) -> None:
    """Commit or adjust inventory for each line after full-pick."""
    inv_enabled = bool(getattr(S, "inventory_reservations_enabled", False))
    if not inv_enabled:
        return
    try:
        from app.services import inventory as inv  # type: ignore[import]
    except ImportError:
        return

    for line in lines:
        sku = line.get("sku", "")
        picked_qty = _to_int(line.get("picked_qty"))
        requested_qty = _to_int(line.get("quantity"))
        reservation_id = line.get("reservation_id")
        location_id = line.get("location_id", "warehouse")

        if reservation_id:
            try:
                inv.commit_reservation(reservation_id, user_sub=user_sub)
            except Exception:
                pass
            # Release remainder if short
            if picked_qty < requested_qty:
                try:
                    inv.release_reservation(reservation_id, reason="short_pick", user_sub=user_sub)
                except Exception:
                    pass
        else:
            # No reservation — direct adjust
            if picked_qty > 0 and sku:
                try:
                    inv.adjust(sku, -picked_qty, "pick", location_id=location_id, user_sub=user_sub)
                except Exception:
                    pass


def pack_picklist(
    picklist_id: str,
    packages: List[Dict[str, Any]],
    *,
    packed_by: str,
) -> Dict[str, Any]:
    """Pack a fully-picked picklist into packages and create a draft shipment.

    Validates package contents sum against picked quantities (no over-pack).
    Writes a T.shipments draft row and back-writes shipment_id to picklist META.
    """
    _require_enabled()
    meta, lines = _load_picklist(picklist_id)

    if meta["status"] != "picked":
        raise HTTPException(
            status_code=409,
            detail=f"Picklist must be in 'picked' status to pack; current={meta['status']!r}",
        )

    order_id = meta.get("order_id", "")
    ts = now_ts()
    shipment_id = uuid.uuid4().hex

    # Build and validate package contents
    packed_skus: Dict[str, int] = {}
    for pkg in packages:
        for content in pkg.get("contents", []):
            sku = content.get("sku", "")
            qty = int(content.get("quantity", 0))
            packed_skus[sku] = packed_skus.get(sku, 0) + qty

    # Verify against picked quantities
    for line in lines:
        sku = line.get("sku", "")
        picked_qty = _to_int(line.get("picked_qty"))
        if packed_skus.get(sku, 0) > picked_qty:
            raise HTTPException(
                status_code=409,
                detail=f"Over-pack: sku={sku!r} packed {packed_skus[sku]} > picked {picked_qty}",
            )

    # Write shipment META
    shipment_meta: Dict[str, Any] = {
        "shipment_id": shipment_id,
        "sk": "META",
        "order_id": order_id,
        "picklist_id": picklist_id,
        "status": "draft",
        "carrier": "",
        "tracking_number": "",
        "package_count": len(packages),
        "created_by": packed_by,
        "created_at": ts,
        "updated_at": ts,
        "shipped_at": 0,
    }
    T.shipments.put_item(Item=shipment_meta)

    # Write package rows
    for idx, pkg in enumerate(packages, start=1):
        pkg_item: Dict[str, Any] = {
            "shipment_id": shipment_id,
            "sk": f"PKG#{idx}",
            "weight_grams": int(pkg.get("weight_grams", 0) or 0),
            "length_mm": int(pkg.get("length_mm", 0) or 0),
            "width_mm": int(pkg.get("width_mm", 0) or 0),
            "height_mm": int(pkg.get("height_mm", 0) or 0),
            "contents": pkg.get("contents", []),
        }
        if pkg.get("notes"):
            pkg_item["notes"] = pkg["notes"]
        T.shipments.put_item(Item=pkg_item)

    # Flip picklist to packed, back-write shipment_id
    old = _transition_picklist(
        picklist_id, "picked", "packed",
        extra_set={"shipment_id": shipment_id, "packed_at": ts},
    )
    if old is None:
        # Already packed (replay) — return existing shipment
        pass

    _audit("packing.packed", packed_by, picklist_id=picklist_id, shipment_id=shipment_id, order_id=order_id)
    return _shipment_out(shipment_meta, [])


def _shipment_out(meta: Dict[str, Any], packages: List[Dict[str, Any]]) -> Dict[str, Any]:
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
        "shipped_at": None if not meta.get("shipped_at") else _to_int(meta.get("shipped_at")) or None,
        "delivered_at": None if not meta.get("delivered_at") else _to_int(meta.get("delivered_at")) or None,
    }


def get_shipment(shipment_id: str) -> Dict[str, Any]:
    """Return a shipment with packages."""
    _require_enabled()
    resp = T.shipments.query(
        KeyConditionExpression=Key("shipment_id").eq(shipment_id),
    )
    items = resp.get("Items", [])
    meta = next((i for i in items if i.get("sk") == "META"), None)
    if meta is None:
        raise HTTPException(status_code=404, detail="Shipment not found")
    packages = [i for i in items if i.get("sk", "").startswith("PKG#")]
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
