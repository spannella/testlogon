"""PUR-005/010/012 — Purchasing / SCM HTTP router.

All endpoints are admin-only (require_admin_or_root_csrf for mutations,
require_admin_or_root for read-only GETs). All endpoints call _require_enabled()
(delegated to the service layer) which raises HTTP 404 when the flag is off.

Route declaration order follows FastAPI literal-before-dynamic rule:
  /suppliers, /purchase-orders, /reorder-suggestions  BEFORE  /{id} segments.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query

from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.models import (
    ApPayableOut,
    PoReceiveIn,
    PoReceiveOut,
    PoSettlePaymentIn,
    PoTransitionIn,
    PurchaseOrderCreateIn,
    PurchaseOrderListOut,
    PurchaseOrderOut,
    ReorderCreatePoIn,
    ReorderSuggestionListOut,
    SupplierCreateIn,
    SupplierListOut,
    SupplierOut,
    SupplierPatchIn,
    SupplierProductListOut,
    SupplierProductOut,
    SupplierProductUpsertIn,
    SupplierStatusIn,
)

purchasing_router = APIRouter(prefix="/ui/purchasing", tags=["purchasing"])


# ── Suppliers ─────────────────────────────────────────────────────────────────

@purchasing_router.post("/suppliers", response_model=SupplierOut)
async def create_supplier_endpoint(
    body: SupplierCreateIn,
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.suppliers import create_supplier  # lazy
    return create_supplier(
        user.sub,
        body.name,
        email=body.email,
        phone=body.phone,
        address=body.address,
        default_currency=body.default_currency,
        payment_terms_days=body.payment_terms_days,
    )


@purchasing_router.get("/suppliers", response_model=SupplierListOut)
async def list_suppliers_endpoint(
    status: str = Query("active"),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: Any = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.suppliers import list_suppliers  # lazy
    return list_suppliers(status, cursor=cursor, limit=limit)


@purchasing_router.get("/suppliers/{supplier_id}", response_model=SupplierOut)
async def get_supplier_endpoint(
    supplier_id: str,
    user: Any = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.suppliers import get_supplier  # lazy
    from fastapi import HTTPException
    result = get_supplier(supplier_id)
    if not result:
        raise HTTPException(status_code=404, detail="supplier_not_found")
    return result


@purchasing_router.patch("/suppliers/{supplier_id}", response_model=SupplierOut)
async def update_supplier_endpoint(
    supplier_id: str,
    body: SupplierPatchIn,
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.suppliers import update_supplier  # lazy
    return update_supplier(
        supplier_id,
        user.sub,
        name=body.name,
        email=body.email,
        phone=body.phone,
        address=body.address,
        default_currency=body.default_currency,
        payment_terms_days=body.payment_terms_days,
    )


@purchasing_router.post("/suppliers/{supplier_id}/status", response_model=SupplierOut)
async def set_supplier_status_endpoint(
    supplier_id: str,
    body: SupplierStatusIn,
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.suppliers import set_supplier_status  # lazy
    return set_supplier_status(supplier_id, body.status, user.sub)


# ── Supplier products ──────────────────────────────────────────────────────────

@purchasing_router.get("/suppliers/{supplier_id}/products", response_model=SupplierProductListOut)
async def list_supplier_products_endpoint(
    supplier_id: str,
    user: Any = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.supplier_products import list_products_for_supplier  # lazy
    products, _ = list_products_for_supplier(supplier_id)
    return {"products": products}


@purchasing_router.put(
    "/suppliers/{supplier_id}/products/{sku:path}",
    response_model=SupplierProductOut,
)
async def upsert_supplier_product_endpoint(
    supplier_id: str,
    sku: str,
    body: SupplierProductUpsertIn,
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.supplier_products import upsert_supplier_product  # lazy
    return upsert_supplier_product(
        supplier_id,
        sku,
        unit_cost_cents=body.unit_cost_cents,
        currency=body.currency,
        lead_time_days=body.lead_time_days,
        min_order_qty=body.min_order_qty,
        supplier_sku=body.supplier_sku,
        preferred=body.preferred,
        actor=user.sub,
    )


@purchasing_router.get(
    "/suppliers/{supplier_id}/products/{sku:path}",
    response_model=SupplierProductOut,
)
async def get_supplier_product_endpoint(
    supplier_id: str,
    sku: str,
    user: Any = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.supplier_products import get_supplier_product  # lazy
    from fastapi import HTTPException
    result = get_supplier_product(supplier_id, sku)
    if not result:
        raise HTTPException(status_code=404, detail="supplier_product_not_found")
    return result


# ── Purchase orders ────────────────────────────────────────────────────────────

@purchasing_router.post("/purchase-orders", response_model=PurchaseOrderOut)
async def create_purchase_order_endpoint(
    body: PurchaseOrderCreateIn,
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.purchase_orders import create_purchase_order  # lazy
    lines = [l.model_dump() for l in body.lines]
    return create_purchase_order(
        user.sub,
        body.supplier_id,
        lines,
        currency=body.currency,
        expected_delivery_date=body.expected_delivery_date,
        correlation_id=body.correlation_id,
    )


@purchasing_router.get("/purchase-orders", response_model=PurchaseOrderListOut)
async def list_purchase_orders_endpoint(
    supplier_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: Any = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.purchase_orders import list_purchase_orders  # lazy
    return list_purchase_orders(
        supplier_id=supplier_id,
        status=status,
        cursor=cursor,
        limit=limit,
    )


@purchasing_router.get("/purchase-orders/{po_id}", response_model=PurchaseOrderOut)
async def get_purchase_order_endpoint(
    po_id: str,
    user: Any = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.purchase_orders import get_purchase_order  # lazy
    from fastapi import HTTPException
    result = get_purchase_order(po_id)
    if not result:
        raise HTTPException(status_code=404, detail="purchase_order_not_found")
    return result


@purchasing_router.post("/purchase-orders/{po_id}/submit", response_model=PurchaseOrderOut)
async def submit_po_endpoint(
    po_id: str,
    body: PoTransitionIn = PoTransitionIn(),
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.purchase_orders import transition_po  # lazy
    return transition_po(
        po_id, "submitted", user.sub,
        reason=body.reason or "",
    )


@purchasing_router.post("/purchase-orders/{po_id}/approve", response_model=PurchaseOrderOut)
async def approve_po_endpoint(
    po_id: str,
    body: PoTransitionIn = PoTransitionIn(),
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.purchase_orders import transition_po  # lazy
    return transition_po(
        po_id, "approved", user.sub,
        reason=body.reason or "",
    )


@purchasing_router.post("/purchase-orders/{po_id}/reject", response_model=PurchaseOrderOut)
async def reject_po_endpoint(
    po_id: str,
    body: PoTransitionIn = PoTransitionIn(),
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.purchase_orders import transition_po  # lazy
    return transition_po(
        po_id, "rejected", user.sub,
        rejected_reason=body.rejected_reason or "",
    )


@purchasing_router.post("/purchase-orders/{po_id}/order", response_model=PurchaseOrderOut)
async def order_po_endpoint(
    po_id: str,
    body: PoTransitionIn = PoTransitionIn(),
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.purchase_orders import transition_po  # lazy
    return transition_po(
        po_id, "ordered", user.sub,
        reason=body.reason or "",
    )


@purchasing_router.post("/purchase-orders/{po_id}/cancel", response_model=PurchaseOrderOut)
async def cancel_po_endpoint(
    po_id: str,
    body: PoTransitionIn = PoTransitionIn(),
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.purchase_orders import transition_po  # lazy
    return transition_po(
        po_id, "cancelled", user.sub,
        reason=body.reason or "",
    )


@purchasing_router.post("/purchase-orders/{po_id}/receive", response_model=PoReceiveOut)
async def receive_po_endpoint(
    po_id: str,
    body: PoReceiveIn,
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.po_receiving import receive_po  # lazy
    lines = [{"line_no": l.line_no, "quantity": l.quantity} for l in body.lines]
    return receive_po(
        po_id,
        lines,
        user.sub,
        receipt_correlation_id=body.receipt_correlation_id,
    )


@purchasing_router.get("/purchase-orders/{po_id}/ap-payable", response_model=ApPayableOut)
async def get_ap_payable_endpoint(
    po_id: str,
    user: Any = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.purchase_orders import get_ap_payable  # lazy
    from fastapi import HTTPException
    result = get_ap_payable(po_id)
    if not result:
        raise HTTPException(status_code=404, detail="no_ap_payable")
    return result


@purchasing_router.post("/purchase-orders/{po_id}/settle-payment", response_model=PurchaseOrderOut)
async def settle_payment_endpoint(
    po_id: str,
    body: PoSettlePaymentIn,
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.purchase_orders import settle_supplier_payment  # lazy
    return settle_supplier_payment(
        po_id,
        body.payment_ref,
        body.provider,
        user.sub,
    )


# ── Reorder suggestions ────────────────────────────────────────────────────────

@purchasing_router.get("/reorder-suggestions", response_model=ReorderSuggestionListOut)
async def get_reorder_suggestions_endpoint(
    user: Any = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    from app.services.reorder_suggestions import generate_reorder_suggestions  # lazy
    return generate_reorder_suggestions()


@purchasing_router.post(
    "/reorder-suggestions/{supplier_id}/create-po",
    response_model=PurchaseOrderOut,
)
async def create_po_from_suggestion_endpoint(
    supplier_id: str,
    body: ReorderCreatePoIn,
    user: Any = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    from app.services.reorder_suggestions import create_purchase_order_from_suggestion  # lazy
    return create_purchase_order_from_suggestion(supplier_id, body.skus, user.sub)
