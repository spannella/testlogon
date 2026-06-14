"""OFBiz Receiving service — inbound goods → on-hand inventory (FAC-007).

`receive_shipment` is idempotent via deterministic receipt_id =
sha256(correlation_id)[:32] + attribute_not_exists conditional put.
inventory.adjust is called only on the first write (+ qty per line).

All cross-cluster deps (inventory) via lazy import (try/except ImportError).
Flag-gated behind FACILITY_FULFILLMENT_ENABLED (default OFF).
"""
from __future__ import annotations

import hashlib
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


def _derive_line_status(received_qty: int, ordered_qty: int) -> str:
    if ordered_qty == 0:
        return "received"
    if received_qty < ordered_qty:
        return "short"
    if received_qty > ordered_qty:
        return "over"
    return "received"


def _derive_header_status(line_statuses: List[str]) -> str:
    if any(s == "short" for s in line_statuses):
        return "partial"
    if any(s == "over" for s in line_statuses):
        return "over"
    return "received"


def _receipt_out(meta: Dict[str, Any], lines: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    # Strip "NONE" sentinel from po_id for API consumers
    po_id = meta.get("po_id")
    if po_id == "NONE":
        po_id = None
    result: Dict[str, Any] = {
        "receipt_id": meta["receipt_id"],
        "facility_id": meta.get("facility_id", ""),
        "location_id": meta.get("location_id", ""),
        "po_id": po_id,
        "correlation_id": meta.get("correlation_id", ""),
        "status": meta.get("status", "received"),
        "notes": meta.get("notes"),
        "received_by": meta.get("received_by"),
        "created_at": _to_int(meta.get("created_at")),
        "lines": [],
    }
    if lines is not None:
        result["lines"] = [
            {
                "sku": l.get("sku", ""),
                "ordered_quantity": _to_int(l.get("ordered_quantity")),
                "received_quantity": _to_int(l.get("received_quantity")),
                "unit_cost_cents": _to_int(l.get("unit_cost_cents")),
                "receipt_status": l.get("receipt_status", "received"),
                "lot_id": l.get("lot_id"),
            }
            for l in sorted(lines, key=lambda x: x.get("sk", ""))
        ]
    return result


def _load_receipt(receipt_id: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    resp = T.receipts.query(
        KeyConditionExpression=Key("receipt_id").eq(receipt_id),
    )
    items = resp.get("Items", [])
    meta = next((i for i in items if i.get("sk") == "META"), None)
    if meta is None:
        raise HTTPException(status_code=404, detail="Receipt not found")
    lines = [i for i in items if i.get("sk", "").startswith("ITEM#")]
    return meta, lines


# ─────────────────────────── public API ────────────────────────────────────


def receive_shipment(
    facility_id: str,
    location_id: str,
    lines: List[Dict[str, Any]],  # [{sku, quantity, unit_cost_cents?, lot_label?, ordered_qty?}]
    *,
    po_id: Optional[str] = None,
    correlation_id: str,
    user_sub: str,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Idempotent inbound receipt. Increments on-hand via inventory.adjust per line.

    receipt_id = sha256(correlation_id)[:32].
    Second call with same correlation_id returns existing receipt without re-adjusting.
    """
    _require_enabled()
    receipt_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
    ts = now_ts()

    # Compute per-line data
    line_statuses: List[str] = []
    line_items: List[Dict[str, Any]] = []
    for idx, line in enumerate(lines, start=1):
        sku = line["sku"]
        received_qty = int(line.get("quantity", line.get("received_quantity", 0)))
        ordered_qty = int(line.get("ordered_qty", line.get("ordered_quantity", 0)))
        unit_cost = int(line.get("unit_cost_cents", 0) or 0)
        lst = _derive_line_status(received_qty, ordered_qty)
        line_statuses.append(lst)

        li: Dict[str, Any] = {
            "receipt_id": receipt_id,
            "sk": f"ITEM#{idx}",
            "sku": sku,
            "received_quantity": received_qty,
            "ordered_quantity": ordered_qty,
            "unit_cost_cents": unit_cost,
            "receipt_status": lst,
        }
        if line.get("lot_label"):
            # Derive lot_id from receipt + sku + label
            lot_id = hashlib.sha256(f"{receipt_id}:{sku}:{line['lot_label']}".encode()).hexdigest()[:24]
            li["lot_id"] = lot_id
        line_items.append(li)

    header_status = _derive_header_status(line_statuses)

    meta: Dict[str, Any] = {
        "receipt_id": receipt_id,
        "sk": "META",
        "facility_id": facility_id,
        "location_id": location_id,
        "po_id": po_id if po_id else "NONE",  # sentinel so GSI_PO indexes row
        "correlation_id": correlation_id,
        "status": header_status,
        "received_by": user_sub,
        "owner_sub": user_sub,
        "created_at": ts,
    }
    if notes:
        meta["notes"] = notes

    try:
        T.receipts.put_item(
            Item=meta,
            ConditionExpression="attribute_not_exists(receipt_id)",
        )
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "ConditionalCheckFailedException":
            raise
        # Replay: return existing receipt
        existing_meta, existing_lines = _load_receipt(receipt_id)
        return _receipt_out(existing_meta, existing_lines)

    # Write line rows
    for li in line_items:
        T.receipts.put_item(Item=li)

    # Increment on-hand via inventory.adjust — best-effort, skip if unavailable
    inv_enabled = bool(getattr(S, "inventory_reservations_enabled", False))
    if inv_enabled:
        try:
            from app.services import inventory as inv  # type: ignore[import]
            for li in line_items:
                try:
                    inv.adjust(
                        li["sku"],
                        int(li["received_quantity"]),
                        "receipt",
                        location_id=location_id,
                        user_sub=user_sub,
                    )
                except Exception:
                    pass  # single-line failure must not roll back the receipt header
        except ImportError:
            pass  # inventory not available in this cluster

    _audit("receiving.received", user_sub, receipt_id=receipt_id,
           facility_id=facility_id, location_id=location_id, line_count=len(lines))
    return _receipt_out(meta, line_items)


def get_receipt(receipt_id: str) -> Dict[str, Any]:
    """Return full receipt with lines."""
    _require_enabled()
    meta, lines = _load_receipt(receipt_id)
    return _receipt_out(meta, lines)


def list_receipts_for_po(po_id: str, *, cursor: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
    """List receipts for a PO via GSI_PO (consumed by PUR module)."""
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_PO",
        "KeyConditionExpression": Key("po_id").eq(po_id),
        "FilterExpression": Attr("sk").eq("META"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.receipts.query(**kwargs)
    items = [_receipt_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"receipts": items, "next_cursor": next_cursor}


def list_receipts_for_facility(
    facility_id: str, *, cursor: Optional[str] = None, limit: int = 50
) -> Dict[str, Any]:
    """List receipts at a facility via GSI_FACILITY."""
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_FACILITY",
        "KeyConditionExpression": Key("facility_id").eq(facility_id),
        "FilterExpression": Attr("sk").eq("META"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.receipts.query(**kwargs)
    items = [_receipt_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"receipts": items, "next_cursor": next_cursor}
