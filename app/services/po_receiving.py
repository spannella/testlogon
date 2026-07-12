"""PUR-008 — Goods receipt against a purchase order → inventory increment.

Sequence:
1. Idempotency check via GSI_RECEIPT
2. Validate PO is receivable (approved|ordered|partially_received)
3. Per-line: validate no over-receive; increment quantity_received
4. If inventory_reservations_enabled: call inventory.adjust(+qty)
5. Write receipt row to T.po_receipts
6. Recompute PO status; transition to partially_received|received via transition_po
7. Emit audit event
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _flag_on() -> bool:
    return getattr(S, "purchasing_scm_enabled", False)


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Purchasing/SCM is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub, None, **fields)
    except Exception:
        pass


_RECEIVABLE_STATUSES = {"approved", "ordered", "partially_received"}


def _receipt_id(receipt_correlation_id: str) -> str:
    return hashlib.sha256(receipt_correlation_id.encode()).hexdigest()[:32]


def receive_po(
    po_id: str,
    lines: List[Dict[str, Any]],
    actor_sub: str,
    *,
    receipt_correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Record a goods receipt, increment inventory, and advance PO status.

    lines: list of {line_no: int, quantity: int}
    Returns {'receipt': {...}, 'po': {...updated header...}}
    """
    _require_enabled()

    if not receipt_correlation_id:
        receipt_correlation_id = f"receipt:{po_id}:{uuid.uuid4().hex}"
    rid = _receipt_id(receipt_correlation_id)

    # --- 1. Idempotency check via GSI_RECEIPT ---
    existing_check = T.po_receipts.query(
        IndexName="GSI_RECEIPT",
        KeyConditionExpression="receipt_id = :rid",
        ExpressionAttributeValues={":rid": rid},
        Limit=1,
    )
    if existing_check.get("Items"):
        existing_receipt = existing_check["Items"][0]
        from app.services.purchase_orders import get_purchase_order
        po = get_purchase_order(po_id) or {}
        return {"receipt": _item_to_receipt(existing_receipt), "po": po}

    # --- 2. Validate PO status ---
    from app.services.purchase_orders import get_purchase_order, transition_po  # lazy

    header_resp = T.purchase_orders.get_item(Key={"po_id": po_id, "sk": "META"})
    header = header_resp.get("Item")
    if not header:
        raise HTTPException(status_code=404, detail="purchase_order_not_found")

    current_status = header.get("status", "")
    if current_status not in _RECEIVABLE_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=f"PO is not in a receivable status (current: {current_status})",
        )

    # --- 3. Per-line processing ---
    ts = now_ts()
    receipt_lines: List[Dict[str, Any]] = []
    inv_enabled = getattr(S, "inventory_reservations_enabled", False)

    for line_spec in lines:
        line_no = int(line_spec["line_no"])
        qty = int(line_spec["quantity"])
        line_sk = f"LINE#{line_no:06d}"

        # Read PO line
        line_resp = T.purchase_orders.get_item(Key={"po_id": po_id, "sk": line_sk})
        po_line = line_resp.get("Item")
        if not po_line:
            raise HTTPException(status_code=422, detail=f"PO line {line_no} not found")

        qty_ordered = _to_int(po_line.get("quantity_ordered"))
        qty_received_so_far = _to_int(po_line.get("quantity_received"))
        new_qty_received = qty_received_so_far + qty
        sku = po_line.get("sku", "")

        if new_qty_received > qty_ordered:
            raise HTTPException(
                status_code=422,
                detail=f"over_receive: line {line_no} ordered={qty_ordered} already_received={qty_received_so_far} new_qty={qty}",
            )

        # Increment quantity_received on PO line
        T.purchase_orders.update_item(
            Key={"po_id": po_id, "sk": line_sk},
            UpdateExpression="ADD quantity_received :qty SET updated_at = :ua",
            ExpressionAttributeValues={":qty": qty, ":ua": ts},
        )

        # Increment inventory (guarded by flag per RULE-2)
        if inv_enabled:
            try:
                from app.services.inventory import adjust  # lazy
                adjust(sku, qty, "po_receipt", location_id="warehouse", user_sub=actor_sub)
            except Exception:
                # Guard: inventory flag may be on but inventory service unavailable
                pass

        receipt_lines.append({"line_no": line_no, "quantity_received": qty})

    # --- 4. Write receipt row ---
    receipt_item: Dict[str, Any] = {
        "po_id": po_id,
        "sk": f"RECEIPT#{rid}",
        "receipt_id": rid,
        "received_by": actor_sub,
        "lines": receipt_lines,
        "created_at": ts,
    }
    T.po_receipts.put_item(Item=receipt_item)

    # --- 5. Recompute PO header status ---
    # Re-fetch all lines to determine new status
    all_lines_resp = T.purchase_orders.query(
        KeyConditionExpression="po_id = :pid AND begins_with(sk, :pfx)",
        ExpressionAttributeValues={":pid": po_id, ":pfx": "LINE#"},
    )
    all_lines = all_lines_resp.get("Items", [])
    total_lines = len(all_lines)
    fully_received_count = 0
    for l in all_lines:
        if _to_int(l.get("quantity_received")) >= _to_int(l.get("quantity_ordered")):
            fully_received_count += 1

    if total_lines > 0 and fully_received_count == total_lines:
        new_status = "received"
    elif fully_received_count > 0 or any(_to_int(l.get("quantity_received")) > 0 for l in all_lines):
        new_status = "partially_received"
    else:
        new_status = current_status  # no change (edge case)

    # Advance PO status
    if new_status != current_status:
        try:
            transition_po(po_id, new_status, actor_sub)
        except Exception:
            # Best-effort: transition may fail due to races; re-read below
            pass

    # If PO is now received, post AP payable and advance to closed
    if new_status == "received":
        try:
            from app.services.purchase_orders import record_ap_payable
            record_ap_payable(po_id)
        except Exception:
            pass
        try:
            transition_po(po_id, "closed", actor_sub)
        except Exception:
            pass

    # --- 6. Emit audit event ---
    _audit(
        "purchase_order_received",
        actor_sub,
        po_id=po_id,
        receipt_id=rid,
        lines_count=len(receipt_lines),
    )

    po = get_purchase_order(po_id) or {}
    return {"receipt": _item_to_receipt(receipt_item), "po": po}


def _item_to_receipt(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "receipt_id": item.get("receipt_id", ""),
        "po_id": item.get("po_id", ""),
        "received_by": item.get("received_by", ""),
        "lines": item.get("lines", []),
        "created_at": _to_int(item.get("created_at")),
    }
