"""OFBiz Transfer service — stock transfers between facility locations (FAC-006).

Lifecycle: requested → in_transit → completed | cancelled.
`complete_transfer` issues paired inventory.adjust calls (debit source,
credit destination) under a conditional status guard for exactly-once semantics.

All cross-cluster deps (inventory, facilities) accessed via lazy import.
Flag-gated behind FACILITY_FULFILLMENT_ENABLED (default OFF).
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ─────────────────────────── status transitions ────────────────────────────

_VALID_TRANSITIONS: Dict[str, List[str]] = {
    "requested": ["in_transit", "cancelled"],
    "in_transit": ["completed", "cancelled"],
}


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


def _transfer_out(meta: Dict[str, Any], lines: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "transfer_id": meta["transfer_id"],
        "from_facility_id": meta.get("from_facility_id", ""),
        "from_location_id": meta.get("from_location_id", ""),
        "to_facility_id": meta.get("to_facility_id", ""),
        "to_location_id": meta.get("to_location_id", ""),
        "status": meta.get("status", "requested"),
        "notes": meta.get("notes"),
        "created_by": meta.get("created_by"),
        "created_at": _to_int(meta.get("created_at")),
        "updated_at": _to_int(meta.get("updated_at")),
        "completed_at": None if meta.get("completed_at") is None else _to_int(meta.get("completed_at")),
        "lines": [],
    }
    if lines is not None:
        result["lines"] = [
            {
                "sku": l.get("sku", ""),
                "quantity": _to_int(l.get("quantity")),
                "picked_quantity": _to_int(l.get("picked_quantity")),
                "status": l.get("status", "pending"),
            }
            for l in lines
        ]
    return result


def _load_transfer(transfer_id: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Load META + all ITEM rows for a transfer; raises 404 if absent."""
    resp = T.transfers.query(
        KeyConditionExpression=Key("transfer_id").eq(transfer_id),
    )
    items = resp.get("Items", [])
    meta = next((i for i in items if i.get("sk") == "META"), None)
    if meta is None:
        raise HTTPException(status_code=404, detail="Transfer not found")
    lines = sorted([i for i in items if i.get("sk", "").startswith("ITEM#")],
                   key=lambda x: x.get("sk", ""))
    return meta, lines


def _transition_transfer(
    transfer_id: str,
    from_status: str,
    to_status: str,
    *,
    extra_set: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Conditional status flip; returns old META item on success, None if already transitioned."""
    set_expr = "SET #s = :new, updated_at = :now"
    expr_vals: Dict[str, Any] = {
        ":new": to_status,
        ":from": from_status,
        ":now": now_ts(),
    }
    if extra_set:
        for k, v in extra_set.items():
            safe = k.replace("#", "__")
            set_expr += f", {k} = :{safe}"
            expr_vals[f":{safe}"] = v

    try:
        resp = T.transfers.update_item(
            Key={"transfer_id": transfer_id, "sk": "META"},
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


def create_transfer(
    from_facility_id: str,
    from_location_id: str,
    to_facility_id: str,
    to_location_id: str,
    lines: List[Dict[str, Any]],  # [{sku, quantity}]
    *,
    owner_sub: str,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a transfer request; status starts at 'requested'."""
    _require_enabled()
    if not lines:
        raise HTTPException(status_code=422, detail="Transfer must have at least one line")

    transfer_id = uuid.uuid4().hex
    ts = now_ts()
    meta: Dict[str, Any] = {
        "transfer_id": transfer_id,
        "sk": "META",
        "from_facility_id": from_facility_id,
        "from_location_id": from_location_id,
        "to_facility_id": to_facility_id,
        "to_location_id": to_location_id,
        "status": "requested",
        "owner_sub": owner_sub,
        "created_by": owner_sub,
        "created_at": ts,
        "updated_at": ts,
    }
    if notes:
        meta["notes"] = notes

    T.transfers.put_item(Item=meta)

    line_items: List[Dict[str, Any]] = []
    for idx, line in enumerate(lines, start=1):
        li: Dict[str, Any] = {
            "transfer_id": transfer_id,
            "sk": f"ITEM#{idx}",
            "sku": line["sku"],
            "quantity": int(line["quantity"]),
            "picked_quantity": 0,
            "status": "pending",
        }
        T.transfers.put_item(Item=li)
        line_items.append(li)

    _audit("transfer.created", owner_sub, transfer_id=transfer_id,
           from_location=from_location_id, to_location=to_location_id)
    return _transfer_out(meta, line_items)


def get_transfer(transfer_id: str) -> Dict[str, Any]:
    """Return full transfer with lines."""
    _require_enabled()
    meta, lines = _load_transfer(transfer_id)
    return _transfer_out(meta, lines)


def list_transfers(
    *,
    status: str = "requested",
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """List transfers by status using GSI_STATUS (admin queue)."""
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

    resp = T.transfers.query(**kwargs)
    items = [_transfer_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"transfers": items, "next_cursor": next_cursor}


def list_transfers_for_location(
    from_location_id: str,
    *,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Transfers out of a specific source location via GSI_FROM_LOC."""
    _require_enabled()
    from app.core.cursor import decode_cursor, encode_cursor

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_FROM_LOC",
        "KeyConditionExpression": Key("from_location_id").eq(from_location_id),
        "FilterExpression": Attr("sk").eq("META"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.transfers.query(**kwargs)
    items = [_transfer_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"transfers": items, "next_cursor": next_cursor}


def advance_to_in_transit(transfer_id: str, *, user_sub: str) -> Dict[str, Any]:
    """requested → in_transit."""
    _require_enabled()
    old = _transition_transfer(transfer_id, "requested", "in_transit")
    if old is None:
        # Already transitioned or not in right state
        meta, lines = _load_transfer(transfer_id)
        return _transfer_out(meta, lines)
    _audit("transfer.in_transit", user_sub, transfer_id=transfer_id)
    meta, lines = _load_transfer(transfer_id)
    return _transfer_out(meta, lines)


def complete_transfer(transfer_id: str, *, user_sub: str) -> Dict[str, Any]:
    """in_transit → completed. Issues paired inventory.adjust calls exactly once."""
    _require_enabled()
    meta, lines = _load_transfer(transfer_id)
    if meta["status"] not in ("in_transit",):
        raise HTTPException(
            status_code=409,
            detail=f"Transfer must be in_transit to complete; current status={meta['status']}",
        )

    # Flip status to completed under conditional — exactly-once guard
    old = _transition_transfer(
        transfer_id, "in_transit", "completed",
        extra_set={"completed_at": now_ts()},
    )
    if old is None:
        # Already completed (replay)
        return _transfer_out(meta, lines)

    # Apply inventory adjustments — best-effort per line; lazy import
    from_loc = meta["from_location_id"]
    to_loc = meta["to_location_id"]

    try:
        from app.services import inventory as inv  # type: ignore[import]
        inv_available = True
    except ImportError:
        inv_available = False

    for line in lines:
        sku = line.get("sku", "")
        qty = _to_int(line.get("quantity"))
        if qty <= 0 or not sku:
            continue
        if inv_available:
            try:
                inv.adjust(sku, -qty, "transfer_out", location_id=from_loc, user_sub=user_sub)
            except Exception:
                pass  # best effort; do not roll back transfer state
            try:
                inv.adjust(sku, +qty, "transfer_in", location_id=to_loc, user_sub=user_sub)
            except Exception:
                pass

        # Mark line as moved
        T.transfers.update_item(
            Key={"transfer_id": transfer_id, "sk": line["sk"]},
            UpdateExpression="SET #s = :s, picked_quantity = :q",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "moved", ":q": qty},
        )

    _audit("transfer.completed", user_sub, transfer_id=transfer_id)
    meta, lines = _load_transfer(transfer_id)
    return _transfer_out(meta, lines)


def cancel_transfer(transfer_id: str, *, user_sub: str) -> Dict[str, Any]:
    """Cancel a requested or in_transit transfer."""
    _require_enabled()
    meta, lines = _load_transfer(transfer_id)
    current = meta.get("status", "")
    if current not in _VALID_TRANSITIONS or "cancelled" not in _VALID_TRANSITIONS.get(current, []):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot cancel transfer in status={current!r}",
        )

    old = _transition_transfer(transfer_id, current, "cancelled")
    if old is None:
        return _transfer_out(meta, lines)

    _audit("transfer.cancelled", user_sub, transfer_id=transfer_id)
    meta, lines = _load_transfer(transfer_id)
    return _transfer_out(meta, lines)
