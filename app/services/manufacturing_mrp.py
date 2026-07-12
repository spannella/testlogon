"""MFG-010 — Lite MRP engine.

Net-requirement formula:
  net_requirement(sku) = gross_demand(sku) - on_hand_available(sku) - scheduled_receipts(sku)

Demand sources:
  - Open sales orders (status="pending_payment") from T.orders / T.order_items
  - Horizon filter applied client-side (orders.created_at stored as ISO string)

Scheduled receipts:
  - Open work orders (status in released/in_progress) from T.mfg_work_orders GSI_STATUS
  - Optional PUR (purchasing) table guarded on purchasing_scm_enabled

RULE-2: all sibling calls are lazy-imported and guarded on their feature flags.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts


DEFAULT_LOCATION = "warehouse"


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
# Demand collection
# ---------------------------------------------------------------------------

def _collect_gross_demand(horizon_days: int) -> Dict[str, int]:
    """Sum quantity per SKU from open orders created within the horizon window.

    Orders.created_at is stored as an ISO string; we do client-side filtering.
    Only status="pending_payment" exists (per MFG-001 §2.6 / §13 verification).
    """
    import datetime  # stdlib
    from boto3.dynamodb.conditions import Key  # type: ignore

    cutoff_iso = (
        datetime.datetime.utcnow() - datetime.timedelta(days=horizon_days)
    ).strftime("%Y-%m-%dT%H:%M:%S")

    # Query orders with status=pending_payment
    demand: Dict[str, int] = {}
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI_STATUS",
            "KeyConditionExpression": Key("status").eq("pending_payment"),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = T.orders.query(**kwargs)
        except Exception:
            break
        for order in resp.get("Items", []):
            # Client-side horizon filter on ISO-string created_at
            created = order.get("created_at", "")
            if created and str(created) < cutoff_iso:
                continue
            order_id = order.get("order_id") or order.get("pk", "")
            if not order_id:
                continue
            # Fetch line items
            _collect_order_items(order_id, demand)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return demand


def _collect_order_items(order_id: str, demand: Dict[str, int]) -> None:
    from boto3.dynamodb.conditions import Key  # type: ignore
    try:
        resp = T.order_items.query(
            KeyConditionExpression=Key("order_id").eq(order_id),
        )
        for item in resp.get("Items", []):
            sku = item.get("sku", "")
            qty = int(item.get("quantity", 0))
            if sku and qty > 0:
                demand[sku] = demand.get(sku, 0) + qty
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Scheduled receipts
# ---------------------------------------------------------------------------

def _collect_scheduled_receipts() -> Dict[str, int]:
    """Sum planned production quantities from open (released / in_progress) work orders."""
    from boto3.dynamodb.conditions import Key  # type: ignore
    receipts: Dict[str, int] = {}
    for status in ("released", "in_progress"):
        last_key = None
        while True:
            kwargs: Dict[str, Any] = {
                "IndexName": "GSI_STATUS",
                "KeyConditionExpression": Key("status").eq(status),
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            try:
                resp = T.mfg_work_orders.query(**kwargs)
            except Exception:
                break
            for item in resp.get("Items", []):
                if item.get("sk") != "META":
                    continue
                sku = item.get("product_sku", "")
                qty = int(item.get("quantity", 0))
                if sku and qty > 0:
                    receipts[sku] = receipts.get(sku, 0) + qty
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

    # Optional: pull from purchasing module if flag on
    if getattr(S, "purchasing_scm_enabled", False):
        po_tbl = getattr(T, "purchase_orders", None)
        if po_tbl is not None:
            try:
                _collect_po_receipts(receipts)
            except Exception:
                pass
    return receipts


def _collect_po_receipts(receipts: Dict[str, int]) -> None:
    """Add open purchase-order planned receipt quantities (optional SCM integration)."""
    from boto3.dynamodb.conditions import Attr  # type: ignore
    try:
        po_tbl = getattr(T, "purchase_orders", None)
        if po_tbl is None:
            return
        resp = po_tbl.scan(FilterExpression=Attr("status").is_in(["open", "approved"]))
        for item in resp.get("Items", []):
            sku = item.get("sku", "")
            qty = int(item.get("quantity", 0))
            if sku and qty > 0:
                receipts[sku] = receipts.get(sku, 0) + qty
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Inventory on-hand helper
# ---------------------------------------------------------------------------

def _get_on_hand_available(sku: str, location_id: str) -> int:
    """Get available quantity from inventory service or return 0."""
    if not getattr(S, "inventory_reservations_enabled", False):
        return 0
    try:
        from app.services.inventory import get_or_zero  # type: ignore
        rec = get_or_zero(sku, location_id)
        return int(rec.get("available", 0))
    except ImportError:
        return 0
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Main MRP run
# ---------------------------------------------------------------------------

def run_mrp(
    horizon_days: Optional[int] = None,
    location_id: str = DEFAULT_LOCATION,
    *,
    correlation_id: Optional[str] = None,
    user_sub: str = "system",
) -> Dict[str, Any]:
    """Execute a lite-MRP run and persist the results.

    Returns the run header with requirements embedded.
    Idempotent: same correlation_id → same mrp_run_id (last-write-wins).
    """
    _require_enabled()

    if horizon_days is None:
        horizon_days = getattr(S, "mfg_mrp_default_horizon_days", 30)

    if correlation_id:
        mrp_run_id = hashlib.sha256(correlation_id.encode()).hexdigest()[:32]
    else:
        mrp_run_id = uuid.uuid4().hex

    ts = now_ts()
    header: Dict[str, Any] = {
        "mrp_run_id": mrp_run_id,
        "sk": "META",
        "status": "running",
        "horizon_days": horizon_days,
        "location_id": location_id,
        "correlation_id": correlation_id or "",
        "created_at": ts,
        "completed_at": 0,
        "requirement_count": 0,
        "user_sub": user_sub,
    }
    T.mfg_mrp.put_item(Item=header)

    try:
        requirements = _compute_requirements(mrp_run_id, horizon_days, location_id)
    except Exception as exc:
        T.mfg_mrp.update_item(
            Key={"mrp_run_id": mrp_run_id, "sk": "META"},
            UpdateExpression="SET #st = :st",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":st": "failed"},
        )
        raise HTTPException(500, f"MRP run failed: {exc}") from exc

    done_ts = now_ts()
    T.mfg_mrp.update_item(
        Key={"mrp_run_id": mrp_run_id, "sk": "META"},
        UpdateExpression="SET #st = :st, completed_at = :ct, requirement_count = :rc",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "completed",
            ":ct": done_ts,
            ":rc": len(requirements),
        },
    )

    _audit("mfg_mrp.run_completed", user_sub, mrp_run_id=mrp_run_id, requirement_count=len(requirements))
    result = {
        "mrp_run_id": mrp_run_id,
        "status": "completed",
        "horizon_days": horizon_days,
        "location_id": location_id,
        "created_at": ts,
        "completed_at": done_ts,
        "requirement_count": len(requirements),
        "user_sub": user_sub,
        "requirements": requirements,
    }
    return result


def _compute_requirements(
    mrp_run_id: str,
    horizon_days: int,
    location_id: str,
) -> List[Dict[str, Any]]:
    """Core MRP computation: collect demand, compute net requirements, explode BOMs."""
    from app.services.manufacturing_bom import get_active_bom, explode_bom  # type: ignore

    gross_demand = _collect_gross_demand(horizon_days)
    scheduled_receipts = _collect_scheduled_receipts()

    requirements: List[Dict[str, Any]] = []
    seq = 0

    # --- Finished-goods net requirements ---
    for sku, gross_qty in gross_demand.items():
        on_hand = _get_on_hand_available(sku, location_id)
        receipts = scheduled_receipts.get(sku, 0)
        net_req = gross_qty - on_hand - receipts
        suggested_qty = max(0, net_req)

        # Determine suggested action
        active_bom = None
        if net_req > 0:
            try:
                active_bom = get_active_bom(sku)
            except Exception:
                pass
        if net_req > 0 and active_bom:
            action = "produce"
        elif net_req > 0:
            action = "purchase"
        else:
            action = "none"

        req_row = {
            "mrp_run_id": mrp_run_id,
            "sk": f"REQ#{sku}#{seq:06d}",
            "sku": sku,
            "gross_requirement": gross_qty,
            "on_hand_available": on_hand,
            "scheduled_receipts": receipts,
            "net_requirement": net_req,
            "suggested_action": action,
            "suggested_quantity": suggested_qty,
            "depth": 0,
            "bom_id": active_bom["bom_id"] if active_bom else "",
        }
        T.mfg_mrp.put_item(Item=req_row)
        requirements.append(_item_to_requirement(req_row))
        seq += 1

        # --- Component explosion for "produce" SKUs ---
        if action == "produce" and active_bom and suggested_qty > 0:
            try:
                exploded = explode_bom(active_bom["bom_id"], suggested_qty)
            except Exception:
                exploded = []

            # Merge exploded components by SKU
            comp_demand: Dict[str, int] = {}
            for comp in exploded:
                c_sku = comp["component_sku"]
                comp_demand[c_sku] = comp_demand.get(c_sku, 0) + int(comp["required_qty"])

            for comp_sku, comp_gross in comp_demand.items():
                comp_on_hand = _get_on_hand_available(comp_sku, location_id)
                comp_receipts = scheduled_receipts.get(comp_sku, 0)
                comp_net = comp_gross - comp_on_hand - comp_receipts
                comp_suggested = max(0, comp_net)

                # Components are purchased unless they too have a BOM
                comp_action = "none"
                comp_bom_id = ""
                if comp_net > 0:
                    try:
                        comp_bom = get_active_bom(comp_sku)
                    except Exception:
                        comp_bom = None
                    if comp_bom:
                        comp_action = "produce"
                        comp_bom_id = comp_bom["bom_id"]
                    else:
                        comp_action = "purchase"

                comp_req = {
                    "mrp_run_id": mrp_run_id,
                    "sk": f"REQ#{comp_sku}#{seq:06d}",
                    "sku": comp_sku,
                    "gross_requirement": comp_gross,
                    "on_hand_available": comp_on_hand,
                    "scheduled_receipts": comp_receipts,
                    "net_requirement": comp_net,
                    "suggested_action": comp_action,
                    "suggested_quantity": comp_suggested,
                    "depth": 1,
                    "bom_id": comp_bom_id,
                }
                T.mfg_mrp.put_item(Item=comp_req)
                requirements.append(_item_to_requirement(comp_req))
                seq += 1

    return requirements


def _item_to_requirement(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "sku": item.get("sku", ""),
        "gross_requirement": int(item.get("gross_requirement", 0)),
        "on_hand_available": int(item.get("on_hand_available", 0)),
        "scheduled_receipts": int(item.get("scheduled_receipts", 0)),
        "net_requirement": int(item.get("net_requirement", 0)),
        "suggested_action": item.get("suggested_action", "none"),
        "suggested_quantity": int(item.get("suggested_quantity", 0)),
        "depth": int(item.get("depth", 0)),
        "bom_id": item.get("bom_id", ""),
    }


def get_mrp_run(mrp_run_id: str) -> Optional[Dict[str, Any]]:
    """Return an MRP run header with embedded requirements."""
    _require_enabled()
    resp = T.mfg_mrp.get_item(Key={"mrp_run_id": mrp_run_id, "sk": "META"})
    header = resp.get("Item")
    if not header:
        return None

    from boto3.dynamodb.conditions import Key  # type: ignore
    req_resp = T.mfg_mrp.query(
        KeyConditionExpression=Key("mrp_run_id").eq(mrp_run_id) & Key("sk").begins_with("REQ#"),
    )
    req_items = req_resp.get("Items", [])
    req_items.sort(key=lambda x: x.get("sk", ""))
    requirements = [_item_to_requirement(it) for it in req_items]

    return {
        "mrp_run_id": header["mrp_run_id"],
        "status": header.get("status", ""),
        "horizon_days": int(header.get("horizon_days", 0)),
        "location_id": header.get("location_id", ""),
        "created_at": int(header.get("created_at", 0)),
        "completed_at": int(header.get("completed_at", 0)),
        "requirement_count": int(header.get("requirement_count", 0)),
        "user_sub": header.get("user_sub", ""),
        "requirements": requirements,
    }
