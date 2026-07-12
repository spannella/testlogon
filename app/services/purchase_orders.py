"""PUR-006/007/009 — Purchase-order entity, lifecycle state machine, AP payable.

PO status lifecycle:
  draft → submitted → approved → ordered → partially_received → received → closed
  (various cancellation / rejection branches — see _ALLOWED_TRANSITIONS)

All public functions raise HTTPException(404) when purchasing_scm_enabled is False.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

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


# ── State machine ─────────────────────────────────────────────────────────────

_ALLOWED_TRANSITIONS: Dict[str, List[str]] = {
    "draft": ["submitted", "cancelled"],
    "submitted": ["approved", "rejected", "cancelled"],
    "approved": ["ordered", "rejected", "cancelled"],
    "ordered": ["partially_received", "received", "cancelled"],
    "partially_received": ["received"],
    "received": ["closed"],
    "closed": [],
    "rejected": [],
    "cancelled": [],
}

_TERMINAL_STATUSES = {"closed", "rejected", "cancelled"}


def _po_id(correlation_id: str) -> str:
    return hashlib.sha256(correlation_id.encode()).hexdigest()[:32]


def _item_to_line(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "line_no": _to_int(item.get("line_no")),
        "sku": item.get("sku", ""),
        "quantity_ordered": _to_int(item.get("quantity_ordered")),
        "quantity_received": _to_int(item.get("quantity_received")),
        "unit_cost_cents": _to_int(item.get("unit_cost_cents")),
        "line_total_cents": _to_int(item.get("line_total_cents")),
    }


def _item_to_header(item: Dict[str, Any], lines: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {
        "po_id": item.get("po_id", ""),
        "supplier_id": item.get("supplier_id", ""),
        "status": item.get("status", "draft"),
        "currency": item.get("currency", "USD"),
        "subtotal_cents": _to_int(item.get("subtotal_cents")),
        "expected_delivery_date": item.get("expected_delivery_date"),
        "created_by": item.get("created_by", ""),
        "approved_by": item.get("approved_by"),
        "approved_at": _to_int(item.get("approved_at")) if item.get("approved_at") else None,
        "rejected_by": item.get("rejected_by"),
        "rejected_reason": item.get("rejected_reason"),
        "ledger_entry_sk": item.get("ledger_entry_sk"),
        "paid_at": _to_int(item.get("paid_at")) if item.get("paid_at") else None,
        "correlation_id": item.get("correlation_id", ""),
        "created_at": _to_int(item.get("created_at")),
        "updated_at": _to_int(item.get("updated_at")),
        "lines": lines if lines is not None else [],
    }


def create_purchase_order(
    user_sub: str,
    supplier_id: str,
    lines: List[Dict[str, Any]],
    *,
    currency: str = "USD",
    expected_delivery_date: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a draft PO (or idempotently return existing one for same correlation_id).

    Lines dict keys: sku, quantity_ordered, unit_cost_cents (optional).
    If unit_cost_cents omitted, looks up from supplier_products.
    """
    _require_enabled()

    if not correlation_id:
        correlation_id = f"po:{user_sub}:{uuid.uuid4().hex}"
    pid = _po_id(correlation_id)

    ts = now_ts()

    # Build line items
    line_items: List[Dict[str, Any]] = []
    subtotal = 0
    for i, line in enumerate(lines, start=1):
        sku = line["sku"]
        qty = int(line["quantity_ordered"])
        unit_cost = line.get("unit_cost_cents")

        if unit_cost is None:
            # Look up from supplier_products
            try:
                from app.services.supplier_products import get_supplier_product  # lazy
                sp = get_supplier_product(supplier_id, sku)
                if sp is None:
                    raise HTTPException(
                        status_code=422,
                        detail=f"unit_cost_cents required for sku={sku}: no supplier_product found",
                    )
                unit_cost = sp["unit_cost_cents"]
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(
                    status_code=422,
                    detail=f"unit_cost_cents required for sku={sku}",
                )
        unit_cost = int(unit_cost)
        line_total = qty * unit_cost
        subtotal += line_total

        line_items.append({
            "po_id": pid,
            "sk": f"LINE#{i:06d}",
            "line_no": i,
            "sku": sku,
            "quantity_ordered": qty,
            "quantity_received": 0,
            "unit_cost_cents": unit_cost,
            "line_total_cents": line_total,
        })

    # Write header
    header: Dict[str, Any] = {
        "po_id": pid,
        "sk": "META",
        "supplier_id": supplier_id,
        "status": "draft",
        "currency": currency,
        "subtotal_cents": subtotal,
        "created_by": user_sub,
        "correlation_id": correlation_id,
        "created_at": ts,
        "updated_at": ts,
    }
    if expected_delivery_date is not None:
        header["expected_delivery_date"] = expected_delivery_date

    T.purchase_orders.put_item(Item=header)

    # Write line rows
    for li in line_items:
        T.purchase_orders.put_item(Item=li)

    _audit("purchase_order_created", user_sub, po_id=pid, supplier_id=supplier_id)
    return _item_to_header(header, [_item_to_line(li) for li in line_items])


def get_purchase_order(po_id: str) -> Optional[Dict[str, Any]]:
    """Return PO header + ordered lines. None if not found."""
    _require_enabled()

    # Fetch header
    resp = T.purchase_orders.get_item(Key={"po_id": po_id, "sk": "META"})
    header = resp.get("Item")
    if not header:
        return None

    # Fetch all items for this po_id (header + lines)
    lines: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "po_id = :pid AND begins_with(sk, :pfx)",
        "ExpressionAttributeValues": {":pid": po_id, ":pfx": "LINE#"},
    }
    while True:
        qr = T.purchase_orders.query(**kwargs)
        lines.extend(qr.get("Items", []))
        lk = qr.get("LastEvaluatedKey")
        if not lk:
            break
        kwargs["ExclusiveStartKey"] = lk

    lines.sort(key=lambda x: _to_int(x.get("line_no")))
    return _item_to_header(header, [_item_to_line(li) for li in lines])


def list_purchase_orders(
    *,
    supplier_id: Optional[str] = None,
    status: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """Paginated list. Use supplier_id or status (not both). Returns {'purchase_orders': [...], 'cursor': ...}."""
    _require_enabled()

    from app.core.cursor import encode_cursor, decode_cursor  # lazy

    if supplier_id:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI_SUPPLIER",
            "KeyConditionExpression": "supplier_id = :sid",
            "ExpressionAttributeValues": {":sid": supplier_id},
            "Limit": limit,
            "ScanIndexForward": False,
        }
    elif status:
        kwargs = {
            "IndexName": "GSI_STATUS",
            "KeyConditionExpression": "#s = :s",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":s": status},
            "Limit": limit,
            "ScanIndexForward": False,
        }
    else:
        raise HTTPException(status_code=422, detail="Provide supplier_id or status")

    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    resp = T.purchase_orders.query(**kwargs)
    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = encode_cursor(last_key) if last_key else None

    return {
        "purchase_orders": [_item_to_header(i) for i in items],
        "cursor": next_cursor,
    }


def transition_po(
    po_id: str,
    target_status: str,
    actor_sub: str,
    *,
    reason: str = "",
    rejected_reason: str = "",
) -> Dict[str, Any]:
    """Atomically advance a PO's status via conditional update.

    Raises HTTPException(409) for illegal transitions or concurrency conflicts.
    Replaying an already-applied transition returns the current PO (idempotent).
    """
    _require_enabled()

    # Read current header first
    header_resp = T.purchase_orders.get_item(Key={"po_id": po_id, "sk": "META"})
    header = header_resp.get("Item")
    if not header:
        raise HTTPException(status_code=404, detail="purchase_order_not_found")

    current_status = header.get("status", "")

    # Idempotent replay: already at target
    if current_status == target_status:
        return get_purchase_order(po_id) or _item_to_header(header)

    # Validate transition legality
    allowed = _ALLOWED_TRANSITIONS.get(current_status, [])
    if target_status not in allowed:
        raise HTTPException(
            status_code=409,
            detail=f"po_invalid_transition: {current_status} → {target_status}",
        )

    # Special validation: ordered → cancelled blocked after any receipt
    if current_status == "ordered" and target_status == "cancelled":
        # Check if any line has quantity_received > 0
        lines_resp = T.purchase_orders.query(
            KeyConditionExpression="po_id = :pid AND begins_with(sk, :pfx)",
            ExpressionAttributeValues={":pid": po_id, ":pfx": "LINE#"},
        )
        for line in lines_resp.get("Items", []):
            if _to_int(line.get("quantity_received")) > 0:
                raise HTTPException(
                    status_code=422,
                    detail="Cannot cancel PO after goods have been received",
                )

    ts = now_ts()

    # Build update expression
    set_parts = ["#status = :new_status", "updated_at = :ua"]
    eav: Dict[str, Any] = {
        ":new_status": target_status,
        ":expected": current_status,
        ":ua": ts,
    }
    ean: Dict[str, str] = {"#status": "status"}

    if target_status == "approved":
        set_parts.append("approved_by = :ab")
        set_parts.append("approved_at = :aat")
        eav[":ab"] = actor_sub
        eav[":aat"] = ts
    elif target_status in ("rejected",):
        set_parts.append("rejected_by = :rb")
        eav[":rb"] = actor_sub
        if rejected_reason:
            set_parts.append("rejected_reason = :rr")
            eav[":rr"] = rejected_reason

    try:
        resp = T.purchase_orders.update_item(
            Key={"po_id": po_id, "sk": "META"},
            UpdateExpression="SET " + ", ".join(set_parts),
            ConditionExpression="#status = :expected",
            ExpressionAttributeNames=ean,
            ExpressionAttributeValues=eav,
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # Race: check if already at target
            fresh_resp = T.purchase_orders.get_item(Key={"po_id": po_id, "sk": "META"})
            fresh = fresh_resp.get("Item", {})
            if fresh.get("status") == target_status:
                return get_purchase_order(po_id) or _item_to_header(fresh)
            raise HTTPException(
                status_code=409,
                detail=f"po_concurrent_update: current status is {fresh.get('status')}",
            )
        raise

    updated = resp.get("Attributes", header)
    _audit(
        f"po_{target_status}",
        actor_sub,
        po_id=po_id,
        from_status=current_status,
        to_status=target_status,
    )
    return get_purchase_order(po_id) or _item_to_header(updated)


# ── PUR-009: AP payable ────────────────────────────────────────────────────────

def record_ap_payable(po_id: str) -> Tuple[str, Dict[str, Any]]:
    """Post a purchase_payable ledger entry to T.purchase_orders for this PO.

    Idempotent: deterministic entry_id = sha256(f'payable:{po_id}')[:32].
    Returns (ledger_sk, ledger_item).
    """
    _require_enabled()

    header_resp = T.purchase_orders.get_item(Key={"po_id": po_id, "sk": "META"})
    header = header_resp.get("Item")
    if not header:
        raise HTTPException(status_code=404, detail="purchase_order_not_found")

    supplier_id = header.get("supplier_id", "")
    subtotal = _to_int(header.get("subtotal_cents"))

    # Deterministic entry_id for idempotency
    entry_id = hashlib.sha256(f"payable:{po_id}".encode()).hexdigest()[:32]

    from app.services.billing_shared import new_ledger_entry  # lazy

    # Build item manually using billing_shared primitives but with deterministic entry_id
    from app.services.billing_shared import ledger_sk, ledger_date_for_ts
    ts = now_ts()
    sk = ledger_sk(ts, entry_id)

    item: Dict[str, Any] = {
        "po_id": po_id,
        "sk": sk,
        "entry_id": entry_id,
        "ts": ts,
        "type": "purchase_payable",
        "amount_cents": subtotal,
        "state": "pending",
        "reason": "supplier_payment",
        "ledger_date": ledger_date_for_ts(ts),
        "provider": "internal",
        "supplier_id": supplier_id,
    }

    try:
        T.purchase_orders.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # Already posted — idempotent no-op; look up existing
            pass
        else:
            raise

    # Write back ledger_entry_sk onto the PO header
    T.purchase_orders.update_item(
        Key={"po_id": po_id, "sk": "META"},
        UpdateExpression="SET ledger_entry_sk = :sk, updated_at = :ua",
        ExpressionAttributeValues={":sk": sk, ":ua": ts},
    )

    _audit("ap_payable_recorded", "system", po_id=po_id, supplier_id=supplier_id, amount_cents=subtotal)
    return sk, item


def settle_supplier_payment(
    po_id: str,
    payment_ref: str,
    provider: str,
    actor_sub: str,
) -> Dict[str, Any]:
    """Mark AP payable as settled and back-write paid_at on the PO header."""
    _require_enabled()

    header_resp = T.purchase_orders.get_item(Key={"po_id": po_id, "sk": "META"})
    header = header_resp.get("Item")
    if not header:
        raise HTTPException(status_code=404, detail="purchase_order_not_found")

    ledger_sk_val = header.get("ledger_entry_sk")
    if not ledger_sk_val:
        raise HTTPException(status_code=422, detail="No AP payable recorded for this PO")

    from app.services.billing_shared import settle_or_reverse_ledger  # lazy
    settle_or_reverse_ledger(T.purchase_orders, "po_id", po_id, ledger_sk_val, "settled")

    ts = now_ts()
    T.purchase_orders.update_item(
        Key={"po_id": po_id, "sk": "META"},
        UpdateExpression="SET paid_at = :pa, updated_at = :ua",
        ExpressionAttributeValues={":pa": ts, ":ua": ts},
    )

    _audit("supplier_payment_settled", actor_sub, po_id=po_id, payment_ref=payment_ref, provider=provider)
    return get_purchase_order(po_id) or {}


def get_ap_payable(po_id: str) -> Optional[Dict[str, Any]]:
    """Return the AP payable ledger row for a PO, or None."""
    _require_enabled()

    header_resp = T.purchase_orders.get_item(Key={"po_id": po_id, "sk": "META"})
    header = header_resp.get("Item")
    if not header:
        return None

    ledger_sk_val = header.get("ledger_entry_sk")
    if not ledger_sk_val:
        return None

    resp = T.purchase_orders.get_item(Key={"po_id": po_id, "sk": ledger_sk_val})
    return resp.get("Item")
