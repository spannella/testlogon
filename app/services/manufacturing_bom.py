"""MFG-004 — Bill-of-Materials service.

Owns CRUD for BOM headers + component rows and the recursive BOM explosion
algorithm. All public functions call _require_enabled() first; when the master
flag is off every call raises HTTP 404 with no table access.

Sibling guard: inventory.adjust / inventory.get_or_zero are lazy-imported and
guarded on S.inventory_reservations_enabled per RULE-2. Tests may run with the
sibling flag OFF so every call to inventory is inside:
    if getattr(S, "inventory_reservations_enabled", False):
        <call>
"""
from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set

from fastapi import HTTPException

from app.core.tables import T
from app.core.settings import S
from app.core.time import now_ts


def _to_dec(v: float) -> Decimal:
    """Convert float to Decimal for DynamoDB compatibility."""
    return Decimal(str(v))


# ---------------------------------------------------------------------------
# Flag helpers
# ---------------------------------------------------------------------------

def _flag_on() -> bool:
    return bool(getattr(S, "manufacturing_mrp_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Manufacturing/MRP not enabled")


# ---------------------------------------------------------------------------
# Audit helper (best-effort, lazy import)
# ---------------------------------------------------------------------------

def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event  # type: ignore
        audit_event(event, user_sub, None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _bom_id_from_correlation(correlation_id: str) -> str:
    return hashlib.sha256(correlation_id.encode()).hexdigest()[:32]


def _item_to_bom(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "bom_id": item["bom_id"],
        "product_sku": item.get("product_sku", ""),
        "name": item.get("name", ""),
        "output_quantity": int(item.get("output_quantity", 1)),
        "status": item.get("status", "draft"),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "created_by": item.get("created_by", ""),
    }


def _item_to_component(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "component_sku": item.get("component_sku", ""),
        "quantity_per": float(item.get("quantity_per", 1)),
        "scrap_pct": float(item.get("scrap_pct", 0.0)),
        "unit_of_measure": item.get("unit_of_measure", "each"),
        "seq": int(item.get("seq", 0)),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_bom(
    product_sku: str,
    name: str,
    output_quantity: int,
    components: List[Dict[str, Any]],
    *,
    correlation_id: Optional[str] = None,
    user_sub: str = "system",
) -> Dict[str, Any]:
    """Create a new BOM header + component rows.

    If correlation_id is supplied the bom_id is deterministic (sha256[:32]);
    a second call with the same correlation_id raises 409 (DynamoDB conditional
    put). Without a correlation_id a random uuid4 hex is used.
    """
    _require_enabled()

    import uuid
    if correlation_id:
        bom_id = _bom_id_from_correlation(correlation_id)
    else:
        bom_id = uuid.uuid4().hex

    ts = now_ts()
    header = {
        "bom_id": bom_id,
        "sk": "META",
        "product_sku": product_sku,
        "name": name,
        "output_quantity": output_quantity,
        "status": "active",
        "created_at": ts,
        "updated_at": ts,
        "created_by": user_sub,
    }
    if correlation_id:
        header["correlation_id"] = correlation_id

    from boto3.dynamodb.conditions import Attr  # type: ignore
    try:
        T.mfg_boms.put_item(
            Item=header,
            ConditionExpression=Attr("bom_id").not_exists(),
        )
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(409, f"BOM with correlation_id already exists: {bom_id}")
        raise

    # Write component rows
    for i, comp in enumerate(components, start=1):
        seq = i
        comp_row = {
            "bom_id": bom_id,
            "sk": f"COMP#{seq:04d}",
            "component_sku": comp["component_sku"],
            "quantity_per": _to_dec(float(comp.get("quantity_per", 1))),
            "scrap_pct": _to_dec(float(comp.get("scrap_pct", 0.0))),
            "unit_of_measure": comp.get("unit_of_measure", "each"),
            "seq": seq,
        }
        T.mfg_boms.put_item(Item=comp_row)

    _audit("mfg_bom.created", user_sub, bom_id=bom_id, product_sku=product_sku)
    result = _item_to_bom(header)
    result["components"] = [_item_to_component({**c, "seq": i}) for i, c in enumerate(components, 1)]
    return result


def get_bom(bom_id: str, *, include_components: bool = True) -> Optional[Dict[str, Any]]:
    """Return BOM header (and optionally components) or None."""
    _require_enabled()

    resp = T.mfg_boms.get_item(Key={"bom_id": bom_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None

    result = _item_to_bom(item)
    if include_components:
        result["components"] = _get_components(bom_id)
    return result


def _get_components(bom_id: str) -> List[Dict[str, Any]]:
    from boto3.dynamodb.conditions import Key  # type: ignore
    resp = T.mfg_boms.query(
        KeyConditionExpression=Key("bom_id").eq(bom_id) & Key("sk").begins_with("COMP#"),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda x: int(x.get("seq", 0)))
    return [_item_to_component(it) for it in items]


def get_active_bom(product_sku: str) -> Optional[Dict[str, Any]]:
    """Return the most-recently-created active BOM for the given product SKU."""
    _require_enabled()

    from boto3.dynamodb.conditions import Key, Attr  # type: ignore
    resp = T.mfg_boms.query(
        IndexName="GSI_PRODUCT",
        KeyConditionExpression=Key("product_sku").eq(product_sku),
        FilterExpression=Attr("status").eq("active"),
        ScanIndexForward=False,
        Limit=10,  # fetch a few; first active one after filter is the answer
    )
    items = resp.get("Items", [])
    # Items come back sorted by created_at DESC (ScanIndexForward=False)
    for item in items:
        if item.get("status") == "active" and item.get("sk") == "META":
            result = _item_to_bom(item)
            result["components"] = _get_components(item["bom_id"])
            return result
    return None


def update_bom(
    bom_id: str,
    *,
    status: Optional[str] = None,
    name: Optional[str] = None,
    user_sub: str = "system",
) -> Dict[str, Any]:
    """Update BOM status and/or name."""
    _require_enabled()

    existing = get_bom(bom_id)
    if not existing:
        raise HTTPException(404, f"BOM not found: {bom_id}")

    ts = now_ts()
    update_expr_parts = ["#ua = :ua"]
    expr_names = {"#ua": "updated_at"}
    expr_vals: Dict[str, Any] = {":ua": ts}

    if status is not None:
        valid = {"draft", "active", "inactive"}
        if status not in valid:
            raise HTTPException(422, f"Invalid status: {status}")
        update_expr_parts.append("#st = :st")
        expr_names["#st"] = "status"
        expr_vals[":st"] = status

    if name is not None:
        update_expr_parts.append("#nm = :nm")
        expr_names["#nm"] = "name"
        expr_vals[":nm"] = name

    T.mfg_boms.update_item(
        Key={"bom_id": bom_id, "sk": "META"},
        UpdateExpression="SET " + ", ".join(update_expr_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )
    _audit("mfg_bom.updated", user_sub, bom_id=bom_id)
    updated = get_bom(bom_id)
    return updated  # type: ignore[return-value]


def list_boms(product_sku: Optional[str] = None) -> List[Dict[str, Any]]:
    """List BOMs, optionally filtered by product SKU."""
    _require_enabled()

    if product_sku:
        from boto3.dynamodb.conditions import Key  # type: ignore
        resp = T.mfg_boms.query(
            IndexName="GSI_PRODUCT",
            KeyConditionExpression=Key("product_sku").eq(product_sku),
            ScanIndexForward=False,
        )
        items = [it for it in resp.get("Items", []) if it.get("sk") == "META"]
    else:
        # Scan all META rows (admin-only, small table)
        from boto3.dynamodb.conditions import Attr  # type: ignore
        resp = T.mfg_boms.scan(FilterExpression=Attr("sk").eq("META"))
        items = resp.get("Items", [])

    result = []
    for item in items:
        bom = _item_to_bom(item)
        bom["components"] = _get_components(item["bom_id"])
        result.append(bom)
    return result


def explode_bom(
    bom_id: str,
    build_qty: int,
    *,
    _depth: int = 0,
    _seen: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Recursively explode a BOM into leaf-component quantities.

    Returns a flat list of {component_sku, required_qty, depth}.
    Sub-assemblies (components whose SKU has an active BOM) are recursed.
    Cycle detection and depth limit are enforced.
    """
    _require_enabled()

    max_depth = getattr(S, "mfg_bom_max_explosion_depth", 5)
    if _depth > max_depth:
        raise HTTPException(409, "BOM explosion depth exceeded")

    if _seen is None:
        _seen = set()
    if bom_id in _seen:
        raise HTTPException(409, f"Cyclic BOM detected at bom_id={bom_id}")
    _seen = set(_seen)  # copy so siblings don't interfere
    _seen.add(bom_id)

    # Load the header to get output_quantity
    resp = T.mfg_boms.get_item(Key={"bom_id": bom_id, "sk": "META"})
    header = resp.get("Item")
    if not header:
        raise HTTPException(404, f"BOM not found: {bom_id}")
    output_qty = int(header.get("output_quantity", 1))

    components = _get_components(bom_id)
    result: List[Dict[str, Any]] = []

    for comp in components:
        comp_sku = comp["component_sku"]
        qty_per = float(comp["quantity_per"])
        scrap = float(comp.get("scrap_pct", 0.0))
        required_qty = math.ceil(qty_per * build_qty / output_qty * (1 + scrap))

        # Check if the component is itself a sub-assembly
        sub_bom = _get_active_bom_for_explosion(comp_sku)
        if sub_bom:
            sub_components = explode_bom(
                sub_bom["bom_id"],
                required_qty,
                _depth=_depth + 1,
                _seen=_seen,
            )
            result.extend(sub_components)
        else:
            result.append({
                "component_sku": comp_sku,
                "required_qty": required_qty,
                "depth": _depth + 1,
            })

    return result


def _get_active_bom_for_explosion(product_sku: str) -> Optional[Dict[str, Any]]:
    """Like get_active_bom but bypasses _require_enabled (called internally)."""
    from boto3.dynamodb.conditions import Key, Attr  # type: ignore
    try:
        resp = T.mfg_boms.query(
            IndexName="GSI_PRODUCT",
            KeyConditionExpression=Key("product_sku").eq(product_sku),
            FilterExpression=Attr("status").eq("active"),
            ScanIndexForward=False,
            Limit=10,
        )
        items = resp.get("Items", [])
        for item in items:
            if item.get("status") == "active" and item.get("sk") == "META":
                return item
    except Exception:
        pass
    return None
