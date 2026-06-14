"""MFG-007 — Work-order lifecycle service (issue → produce).

Includes MFG-008 optional costed-production GL hook inside complete_work_order.

RULE-2 sibling guards:
  - inventory.adjust / inventory.get_or_zero: guarded by inventory_reservations_enabled
  - billing_shared.new_ledger_entry: guarded by manufacturing_cost_posting_enabled
  - gl_posting.post_journal_entry: guarded by gl_double_entry_enabled
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts


# ---------------------------------------------------------------------------
# Flag helpers
# ---------------------------------------------------------------------------

def _flag_on() -> bool:
    return bool(getattr(S, "manufacturing_mrp_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Manufacturing/MRP not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event  # type: ignore
        audit_event(event, user_sub, None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Inventory helpers (lazy import + sibling flag guard)
# ---------------------------------------------------------------------------

def _inventory_adjust(sku: str, delta: int, reason: str, *, location_id: str, user_sub: str) -> None:
    """Call inventory.adjust — no-op when inventory_reservations_enabled is off."""
    if not getattr(S, "inventory_reservations_enabled", False):
        return
    try:
        from app.services.inventory import adjust  # type: ignore
        adjust(sku, delta, reason, location_id=location_id, user_sub=user_sub)
    except ImportError:
        pass  # inventory service not yet available in this deployment


def _inventory_get_or_zero(sku: str, location_id: str) -> Dict[str, Any]:
    """Call inventory.get_or_zero — returns zeroed record when flag is off."""
    if not getattr(S, "inventory_reservations_enabled", False):
        return {"sku": sku, "location_id": location_id, "on_hand": 0, "reserved": 0, "available": 0}
    try:
        from app.services.inventory import get_or_zero  # type: ignore
        return get_or_zero(sku, location_id)
    except ImportError:
        return {"sku": sku, "location_id": location_id, "on_hand": 0, "reserved": 0, "available": 0}


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _item_to_work_order(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "work_order_id": item["work_order_id"],
        "product_sku": item.get("product_sku", ""),
        "quantity": int(item.get("quantity", 0)),
        "produced_qty": int(item.get("produced_qty", 0)),
        "bom_id": item.get("bom_id", ""),
        "work_center_id": item.get("work_center_id", ""),
        "status": item.get("status", "created"),
        "correlation_id": item.get("correlation_id", ""),
        "issues_guard": item.get("issues_guard", ""),
        "produce_guard": item.get("produce_guard", ""),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "user_sub": item.get("user_sub", ""),
    }


def _item_to_issue(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "component_sku": item.get("component_sku", ""),
        "required_quantity": float(item.get("required_quantity", 0)),
        "issued_quantity": float(item.get("issued_quantity", 0)),
        "location_id": item.get("location_id", ""),
        "issued_at": int(item.get("issued_at", 0)),
    }


def _get_issue_rows(work_order_id: str) -> List[Dict[str, Any]]:
    from boto3.dynamodb.conditions import Key  # type: ignore
    resp = T.mfg_work_orders.query(
        KeyConditionExpression=Key("work_order_id").eq(work_order_id) & Key("sk").begins_with("ISSUE#"),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: x.get("sk", ""))
    return [_item_to_issue(it) for it in items]


def _write_event(work_order_id: str, from_status: str, to_status: str, actor_sub: str) -> None:
    ts = now_ts()
    evt_id = uuid.uuid4().hex[:8]
    T.mfg_work_orders.put_item(Item={
        "work_order_id": work_order_id,
        "sk": f"EVENT#{ts:010d}#{evt_id}",
        "from_status": from_status,
        "to_status": to_status,
        "actor_sub": actor_sub,
        "ts": ts,
    })


# ---------------------------------------------------------------------------
# Public CRUD
# ---------------------------------------------------------------------------

def create_work_order(
    product_sku: str,
    quantity: int,
    *,
    bom_id: Optional[str] = None,
    work_center_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    user_sub: str = "system",
) -> Dict[str, Any]:
    _require_enabled()

    # Resolve BOM
    if bom_id is None:
        from app.services.manufacturing_bom import get_active_bom  # type: ignore
        bom = get_active_bom(product_sku)
        if bom is None:
            raise HTTPException(422, f"No active BOM found for SKU {product_sku}; supply bom_id explicitly")
        bom_id = bom["bom_id"]

    # Derive work_order_id
    if correlation_id:
        wo_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
    else:
        wo_id = uuid.uuid4().hex

    ts = now_ts()
    item = {
        "work_order_id": wo_id,
        "sk": "META",
        "product_sku": product_sku,
        "quantity": quantity,
        "produced_qty": 0,
        "bom_id": bom_id,
        "work_center_id": work_center_id or "",
        "status": "created",
        "correlation_id": correlation_id or "",
        "issues_guard": "",
        "produce_guard": "",
        "created_at": ts,
        "updated_at": ts,
        "user_sub": user_sub,
    }

    from boto3.dynamodb.conditions import Attr  # type: ignore
    try:
        T.mfg_work_orders.put_item(
            Item=item,
            ConditionExpression=Attr("work_order_id").not_exists(),
        )
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(409, f"Work order already exists: {wo_id}")
        raise

    _write_event(wo_id, "", "created", user_sub)
    _audit("mfg_work_order.created", user_sub, work_order_id=wo_id, product_sku=product_sku)
    result = _item_to_work_order(item)
    result["issues"] = []
    return result


def get_work_order(work_order_id: str, *, include_issues: bool = True) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.mfg_work_orders.get_item(Key={"work_order_id": work_order_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None
    result = _item_to_work_order(item)
    if include_issues:
        result["issues"] = _get_issue_rows(work_order_id)
    return result


def list_work_orders(status: Optional[str] = None) -> List[Dict[str, Any]]:
    _require_enabled()
    if status:
        from boto3.dynamodb.conditions import Key  # type: ignore
        resp = T.mfg_work_orders.query(
            IndexName="GSI_STATUS",
            KeyConditionExpression=Key("status").eq(status),
            ScanIndexForward=False,
        )
        items = [it for it in resp.get("Items", []) if it.get("sk") == "META"]
    else:
        from boto3.dynamodb.conditions import Attr  # type: ignore
        resp = T.mfg_work_orders.scan(FilterExpression=Attr("sk").eq("META"))
        items = resp.get("Items", [])

    result = []
    for item in items:
        wo = _item_to_work_order(item)
        wo["issues"] = []
        result.append(wo)
    return result


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------

_VALID_TRANSITIONS = {
    "created": {"released", "cancelled"},
    "released": {"in_progress", "cancelled"},
    "in_progress": {"completed", "cancelled"},
    "completed": set(),
    "cancelled": set(),
}


def _assert_valid_transition(current: str, target: str, work_order_id: str) -> None:
    allowed = _VALID_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise HTTPException(
            409,
            f"Cannot transition work order {work_order_id} from '{current}' to '{target}'"
        )


def _update_status(work_order_id: str, new_status: str, ts: int, extra_sets: Optional[Dict] = None) -> None:
    parts = ["#st = :st", "#ua = :ua"]
    names: Dict[str, str] = {"#st": "status", "#ua": "updated_at"}
    vals: Dict[str, Any] = {":st": new_status, ":ua": ts}
    if extra_sets:
        for k, v in extra_sets.items():
            parts.append(f"#{k} = :{k}")
            names[f"#{k}"] = k
            vals[f":{k}"] = v
    T.mfg_work_orders.update_item(
        Key={"work_order_id": work_order_id, "sk": "META"},
        UpdateExpression="SET " + ", ".join(parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=vals,
    )


def release_work_order(
    work_order_id: str,
    *,
    location_id: str = "warehouse",
    user_sub: str = "system",
) -> Dict[str, Any]:
    """Release: explode BOM, issue components from inventory, write ISSUE rows.

    Idempotent via issues_guard flag. If any inventory.adjust fails (409 on
    insufficient stock), already-issued components are reversed.
    """
    _require_enabled()

    wo = get_work_order(work_order_id, include_issues=False)
    if not wo:
        raise HTTPException(404, f"Work order not found: {work_order_id}")

    # Idempotency guard: if components already issued, return current state
    if wo.get("issues_guard") == "done":
        return get_work_order(work_order_id)  # type: ignore[return-value]

    _assert_valid_transition(wo["status"], "released", work_order_id)

    # Explode BOM
    from app.services.manufacturing_bom import explode_bom, _require_enabled as bom_enabled  # type: ignore
    try:
        bom_enabled()
    except HTTPException:
        raise HTTPException(404, "Manufacturing/MRP not enabled")

    components = explode_bom(wo["bom_id"], wo["quantity"])

    # Issue components (with reversal on partial failure)
    issued: List[Dict[str, Any]] = []
    failed_sku: Optional[str] = None
    for comp in components:
        comp_sku = comp["component_sku"]
        qty = int(comp["required_qty"])
        try:
            _inventory_adjust(comp_sku, -qty, "mfg_issue", location_id=location_id, user_sub=user_sub)
            issued.append({"sku": comp_sku, "qty": qty})
        except HTTPException as exc:
            if exc.status_code == 409:
                failed_sku = comp_sku
                break
            raise

    if failed_sku:
        # Reverse already-issued
        for rev in issued:
            try:
                _inventory_adjust(rev["sku"], rev["qty"], "mfg_issue_reversal", location_id=location_id, user_sub=user_sub)
            except Exception:
                pass
        raise HTTPException(409, f"Insufficient stock to issue component {failed_sku}; release aborted and reversed")

    ts = now_ts()
    # Write ISSUE rows
    from decimal import Decimal
    for i, comp in enumerate(components, start=1):
        qty_dec = Decimal(str(int(comp["required_qty"])))
        T.mfg_work_orders.put_item(Item={
            "work_order_id": work_order_id,
            "sk": f"ISSUE#{i:04d}",
            "component_sku": comp["component_sku"],
            "required_quantity": qty_dec,
            "issued_quantity": qty_dec,
            "location_id": location_id,
            "issued_at": ts,
        })

    # Mark guard + update status
    _update_status(work_order_id, "released", ts, {"issues_guard": "done"})
    _write_event(work_order_id, wo["status"], "released", user_sub)
    _audit("mfg_work_order.released", user_sub, work_order_id=work_order_id)
    return get_work_order(work_order_id)  # type: ignore[return-value]


def start_work_order(work_order_id: str, *, user_sub: str = "system") -> Dict[str, Any]:
    """Mark work order in_progress."""
    _require_enabled()
    wo = get_work_order(work_order_id, include_issues=False)
    if not wo:
        raise HTTPException(404, f"Work order not found: {work_order_id}")
    _assert_valid_transition(wo["status"], "in_progress", work_order_id)
    ts = now_ts()
    _update_status(work_order_id, "in_progress", ts)
    _write_event(work_order_id, wo["status"], "in_progress", user_sub)
    _audit("mfg_work_order.started", user_sub, work_order_id=work_order_id)
    return get_work_order(work_order_id)  # type: ignore[return-value]


def complete_work_order(
    work_order_id: str,
    *,
    produced_qty: Optional[int] = None,
    location_id: str = "warehouse",
    user_sub: str = "system",
) -> Dict[str, Any]:
    """Complete: receive finished goods into inventory. Optionally post GL entry.

    MFG-008: If manufacturing_cost_posting_enabled is True, posts a single
    ledger entry capturing total production cost. The GL double-entry journal
    (WIP debit / FG credit) is posted if gl_double_entry_enabled is also True.
    """
    _require_enabled()
    wo = get_work_order(work_order_id, include_issues=False)
    if not wo:
        raise HTTPException(404, f"Work order not found: {work_order_id}")

    # Idempotency guard: if finished goods already produced, return current state
    if wo.get("produce_guard") == "done":
        return get_work_order(work_order_id)  # type: ignore[return-value]

    _assert_valid_transition(wo["status"], "completed", work_order_id)

    qty = produced_qty or wo["quantity"]

    # Produce finished goods
    _inventory_adjust(wo["product_sku"], qty, "mfg_produce", location_id=location_id, user_sub=user_sub)

    ts = now_ts()
    _update_status(work_order_id, "completed", ts, {
        "produce_guard": "done",
        "produced_qty": qty,
        "completed_at": ts,
    })
    _write_event(work_order_id, wo["status"], "completed", user_sub)
    _audit("mfg_work_order.completed", user_sub, work_order_id=work_order_id, produced_qty=qty)

    # --- MFG-008 GL hook ---
    if getattr(S, "manufacturing_cost_posting_enabled", False):
        _post_cost_entry(work_order_id, wo, qty, user_sub)

    return get_work_order(work_order_id)  # type: ignore[return-value]


def _post_cost_entry(
    work_order_id: str,
    wo: Dict[str, Any],
    produced_qty: int,
    user_sub: str,
) -> None:
    """MFG-008: Post a single ledger entry for production cost.

    Component material cost is estimated from inventory unit_cost (if available)
    or defaults to 0 (per spec §10 assumption 9). Routing labor cost comes from
    the work center's cost_per_hour_cents.

    RULE-2: billing_shared is always available (no flag gate). GL double-entry
    journal is gated on gl_double_entry_enabled.
    """
    try:
        # Estimate labor cost from work center
        labor_cost_cents = 0
        if wo.get("work_center_id"):
            try:
                from app.services.manufacturing_routing import estimate_routing_cost  # type: ignore
                cost_est = estimate_routing_cost(wo["work_center_id"], produced_qty)
                labor_cost_cents = cost_est.get("total_cost_cents", 0)
            except Exception:
                pass

        # Material cost: iterate ISSUE rows; use unit_cost=0 per assumption
        # (unit_cost not stored on inventory in current codebase)
        material_cost_cents = 0

        total_cost_cents = material_cost_cents + labor_cost_cents

        # Write ledger entry via billing_shared
        from app.services.billing_shared import new_ledger_entry  # type: ignore
        from app.core.tables import T as _T  # type: ignore

        _, led_item = new_ledger_entry(
            key_name="work_order_id",
            key_value=work_order_id,
            entry_type="production_cost",
            amount_cents=total_cost_cents,
            state="settled",
            reason="mfg_production_completed",
            extra={
                "product_sku": wo.get("product_sku", ""),
                "produced_qty": produced_qty,
                "bom_id": wo.get("bom_id", ""),
                "work_center_id": wo.get("work_center_id", ""),
                "actor_sub": user_sub,
            },
        )
        _T.billing.put_item(Item=led_item)

        # --- GL double-entry hook (RULE-2: guard on gl_double_entry_enabled) ---
        if getattr(S, "gl_double_entry_enabled", False) and total_cost_cents > 0:
            try:
                from app.services.gl_posting import post_journal_entry  # type: ignore
                # WIP debit / Inventory-FG credit (balanced: debit=credit)
                post_journal_entry(
                    reference_type="work_order",
                    reference_id=work_order_id,
                    lines=[
                        {"account_code": "WIP", "amount_cents": total_cost_cents, "side": "debit"},
                        {"account_code": "INVENTORY_FG", "amount_cents": total_cost_cents, "side": "credit"},
                    ],
                    memo=f"Production completed: {wo.get('product_sku', '')} x{produced_qty}",
                    actor_sub=user_sub,
                )
            except ImportError:
                pass
    except Exception:
        # GL hook failures must not block work order completion
        pass


def cancel_work_order(
    work_order_id: str,
    *,
    reason: Optional[str] = None,
    location_id: str = "warehouse",
    user_sub: str = "system",
) -> Dict[str, Any]:
    """Cancel work order. If components were issued, return them to inventory."""
    _require_enabled()
    wo = get_work_order(work_order_id, include_issues=False)
    if not wo:
        raise HTTPException(404, f"Work order not found: {work_order_id}")
    _assert_valid_transition(wo["status"], "cancelled", work_order_id)

    # Return issued components if any
    if wo.get("issues_guard") == "done":
        issue_rows = _get_issue_rows(work_order_id)
        for issue in issue_rows:
            try:
                qty = int(issue.get("issued_quantity", 0))
                if qty > 0:
                    _inventory_adjust(
                        issue["component_sku"],
                        qty,
                        "mfg_cancel_return",
                        location_id=location_id,
                        user_sub=user_sub,
                    )
            except Exception:
                # Return failure must not block cancellation
                pass

    ts = now_ts()
    _update_status(work_order_id, "cancelled", ts, {"cancel_reason": reason or ""})
    _write_event(work_order_id, wo["status"], "cancelled", user_sub)
    _audit("mfg_work_order.cancelled", user_sub, work_order_id=work_order_id, reason=reason)
    return get_work_order(work_order_id)  # type: ignore[return-value]
