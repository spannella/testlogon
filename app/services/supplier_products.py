"""PUR-004 — Supplier-product pricing (supplier ↔ SKU price / lead-time / MOQ).

All public functions raise HTTPException(404) when purchasing_scm_enabled is False.
Upsert is idempotent on (supplier_id, sku) — uses unconditional put_item (same key = overwrite).
SKU validation: must exist in inventory OR catalog.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

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


def _validate_sku(sku: str) -> None:
    """Raise HTTP 422 if sku doesn't exist in inventory or catalog."""
    # Try inventory first (lazy import to avoid circular deps)
    try:
        if getattr(S, "inventory_reservations_enabled", False):
            from app.services.inventory import get_inventory  # lazy
            if get_inventory(sku) is not None:
                return
    except Exception:
        pass

    # Try catalog (sku may be "catalog:{item_id}")
    try:
        if sku.startswith("catalog:"):
            item_id = sku[len("catalog:"):]
            resp = T.catalog.get_item(Key={"item_id": item_id})
            if resp.get("Item") and resp["Item"].get("entity") == "item":
                return
    except Exception:
        pass

    # Last attempt: check raw inventory table directly (flag-off case)
    try:
        resp = T.inventory.get_item(Key={"sku": sku, "location_sk": "LOC#warehouse"})
        if resp.get("Item"):
            return
    except Exception:
        pass

    # Nothing found
    raise HTTPException(status_code=422, detail="sku_not_found")


def _item_to_product(item: Dict[str, Any]) -> Dict[str, Any]:
    sk = item.get("sk", "")
    sku = item.get("sku", sk.replace("SKU#", "", 1) if sk.startswith("SKU#") else sk)
    return {
        "supplier_id": item.get("supplier_id", ""),
        "sku": sku,
        "supplier_sku": item.get("supplier_sku"),
        "unit_cost_cents": _to_int(item.get("unit_cost_cents")),
        "currency": item.get("currency", "USD"),
        "lead_time_days": _to_int(item.get("lead_time_days")),
        "min_order_qty": _to_int(item.get("min_order_qty"), 1),
        "preferred": bool(item.get("preferred", False)),
        "created_at": _to_int(item.get("created_at")),
        "updated_at": _to_int(item.get("updated_at")),
    }


def upsert_supplier_product(
    supplier_id: str,
    sku: str,
    *,
    unit_cost_cents: int,
    currency: str = "USD",
    lead_time_days: int = 0,
    min_order_qty: int = 1,
    supplier_sku: Optional[str] = None,
    preferred: bool = False,
    actor: str = "",
) -> Dict[str, Any]:
    """Upsert supplier-product pricing. Idempotent on (supplier_id, sku)."""
    _require_enabled()
    _validate_sku(sku)

    ts = now_ts()

    # Read before write to preserve created_at
    existing_resp = T.supplier_products.get_item(
        Key={"supplier_id": supplier_id, "sk": f"SKU#{sku}"}
    )
    existing = existing_resp.get("Item")
    created_at = _to_int(existing.get("created_at"), ts) if existing else ts

    item: Dict[str, Any] = {
        "supplier_id": supplier_id,
        "sk": f"SKU#{sku}",
        "sku": sku,
        "unit_cost_cents": unit_cost_cents,
        "currency": currency,
        "lead_time_days": lead_time_days,
        "min_order_qty": min_order_qty,
        "preferred": preferred,
        "created_at": created_at,
        "updated_at": ts,
    }
    if supplier_sku is not None:
        item["supplier_sku"] = supplier_sku

    T.supplier_products.put_item(Item=item)
    _audit("supplier_product_upserted", actor or supplier_id, supplier_id=supplier_id, sku=sku)
    return _item_to_product(item)


def get_supplier_product(supplier_id: str, sku: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.supplier_products.get_item(
        Key={"supplier_id": supplier_id, "sk": f"SKU#{sku}"}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _item_to_product(item)


def list_products_for_supplier(
    supplier_id: str,
    *,
    limit: int = 200,
    start_key: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Return (products_list, last_evaluated_key) for pagination."""
    _require_enabled()
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "supplier_id = :sid",
        "ExpressionAttributeValues": {":sid": supplier_id},
        "Limit": limit,
    }
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    items: List[Dict[str, Any]] = []
    while True:
        resp = T.supplier_products.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key
        kwargs.pop("Limit", None)  # Fetch remaining after first page

    return [_item_to_product(i) for i in items], None


def list_suppliers_for_sku(sku: str) -> List[Dict[str, Any]]:
    """Query GSI_SKU, returning suppliers for a SKU ordered by ascending unit_cost_cents."""
    _require_enabled()
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_SKU",
        "KeyConditionExpression": "sku = :sku",
        "ExpressionAttributeValues": {":sku": sku},
        "ScanIndexForward": True,  # ascending unit_cost_cents
    }
    while True:
        resp = T.supplier_products.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        kwargs["ExclusiveStartKey"] = last_key

    return [_item_to_product(i) for i in items]
