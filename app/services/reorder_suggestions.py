"""PUR-011/012 — Reorder-suggestion engine.

Queries OFB-005 low-stock signals (inventory.list_low_stock) and crosses them
against supplier_products to produce per-supplier suggested PO quantities.

Gated by: purchasing_scm_enabled AND purchase_order_reorder_suggestions_enabled.
Inventory calls are further guarded by inventory_reservations_enabled.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.settings import S


def _flag_on() -> bool:
    return (
        getattr(S, "purchasing_scm_enabled", False)
        and getattr(S, "purchase_order_reorder_suggestions_enabled", False)
    )


def _require_enabled() -> None:
    if not getattr(S, "purchasing_scm_enabled", False):
        raise HTTPException(status_code=404, detail="Purchasing/SCM is not enabled")
    if not getattr(S, "purchase_order_reorder_suggestions_enabled", False):
        raise HTTPException(status_code=404, detail="Reorder suggestions not enabled")


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _suggested_qty(available: int, reorder_point: int, moq: int) -> int:
    """Compute suggested order quantity.

    gap = max(reorder_point - available, 0)
    If gap == 0: suggest one MOQ
    Else: round gap up to nearest MOQ multiple: ceil(gap / moq) * moq
    """
    gap = max(reorder_point - available, 0)
    if gap == 0:
        return moq
    return math.ceil(gap / moq) * moq


def generate_reorder_suggestions() -> Dict[str, Any]:
    """Generate reorder suggestions from low-stock inventory items.

    Returns: {'suggestions': [...], 'no_supplier_skus': [...]}
    """
    _require_enabled()

    low_stock_records: List[Dict[str, Any]] = []

    # RULE-2: guard inventory call on its own flag
    if getattr(S, "inventory_reservations_enabled", False):
        try:
            from app.services.inventory import list_low_stock  # lazy
            for loc_status in ("low_stock", "out_of_stock"):
                records = list_low_stock(loc_status)
                low_stock_records.extend(records)
        except Exception:
            pass

    if not low_stock_records:
        return {"suggestions": [], "no_supplier_skus": []}

    from app.services.supplier_products import list_suppliers_for_sku  # lazy
    from app.services.suppliers import get_supplier  # lazy

    suggestions: List[Dict[str, Any]] = []
    no_supplier_skus: List[str] = []

    for record in low_stock_records:
        sku = record.get("sku", "")
        available = _to_int(record.get("available"))
        reorder_point = _to_int(record.get("reorder_point"), 1)

        try:
            supplier_list = list_suppliers_for_sku(sku)
        except Exception:
            supplier_list = []

        if not supplier_list:
            if sku not in no_supplier_skus:
                no_supplier_skus.append(sku)
            continue

        # Pick cheapest/preferred supplier
        chosen = supplier_list[0]
        supplier_id = chosen.get("supplier_id")
        moq = max(_to_int(chosen.get("min_order_qty"), 1), 1)
        unit_cost = _to_int(chosen.get("unit_cost_cents"))
        lead_time = _to_int(chosen.get("lead_time_days"))

        # Get supplier name
        supplier_name: Optional[str] = None
        try:
            sup = get_supplier(supplier_id)
            if sup:
                supplier_name = sup.get("name")
        except Exception:
            pass

        suggested = _suggested_qty(available, reorder_point, moq)

        suggestions.append({
            "sku": sku,
            "available": available,
            "reorder_point": reorder_point,
            "suggested_qty": suggested,
            "supplier_id": supplier_id,
            "supplier_name": supplier_name,
            "unit_cost_cents": unit_cost,
            "lead_time_days": lead_time,
            "warning": None,
        })

    return {"suggestions": suggestions, "no_supplier_skus": no_supplier_skus}


def create_purchase_order_from_suggestion(
    supplier_id: str,
    skus: List[str],
    user_sub: str,
) -> Dict[str, Any]:
    """Materialise a draft PO from reorder suggestions (idempotent on same supplier+skus).

    correlation_id = sha256(f"reorder:{supplier_id}:{sorted_skus}")[:32]
    """
    _require_enabled()

    import hashlib
    sorted_skus_str = ",".join(sorted(skus))
    correlation_id = hashlib.sha256(
        f"reorder:{supplier_id}:{sorted_skus_str}".encode()
    ).hexdigest()[:32]

    from app.services.supplier_products import get_supplier_product  # lazy
    from app.services.purchase_orders import create_purchase_order  # lazy

    lines: List[Dict[str, Any]] = []
    for sku in skus:
        sp = get_supplier_product(supplier_id, sku)
        if not sp:
            continue
        # Get suggested qty from current low-stock info
        moq = max(sp.get("min_order_qty", 1), 1)
        lines.append({
            "sku": sku,
            "quantity_ordered": moq,
            "unit_cost_cents": sp.get("unit_cost_cents", 0),
        })

    if not lines:
        raise HTTPException(status_code=422, detail="No supplier-product pricing found for requested SKUs")

    return create_purchase_order(
        user_sub,
        supplier_id,
        lines,
        correlation_id=correlation_id,
    )
