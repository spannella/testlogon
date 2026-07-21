"""ERP Accounts-Receivable subledger admin router (P1).

Exposes the previously-unmounted ar_subledger aging engine over an
operator/admin surface. The aging service is a pure, read-only view — it never
writes to billing/invoices. This router feeds it real invoices sourced from the
existing admin invoice listing (invoices.admin_list_invoices), so operators get
a live AR aging report (current / 30 / 60 / 90+ buckets).

Admin/root only. Flag-gated behind S.ar_ap_subledgers_enabled (the service
raises 503 when off).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.services import ar_subledger as ar_svc
from app.services import invoices as invoices_svc

router = APIRouter(prefix="/v1/admin/ar", tags=["admin-ar"])


class ComputeAgingIn(BaseModel):
    open_items: List[Dict[str, Any]] = Field(default_factory=list)
    as_of_ts: Optional[int] = Field(default=None)


@router.get("/aging")
def ar_aging(
    target_user_sub: Optional[str] = Query(default=None),
    invoice_type: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=200),
    as_of_ts: Optional[int] = Query(default=None),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    """Live AR aging over real invoices (admin-scoped). Sources invoices via
    invoices.admin_list_invoices, then buckets the AR-open ones by age."""
    listing = invoices_svc.admin_list_invoices(
        target_user_sub=target_user_sub,
        invoice_type=invoice_type,
        limit=limit,
    )
    invoices = listing.get("invoices", []) if isinstance(listing, dict) else []
    aging = ar_svc.aging_from_invoices(invoices, as_of_ts=as_of_ts)
    aging["source_invoice_count"] = len(invoices)
    return aging


@router.post("/aging/compute")
def ar_aging_compute(
    inp: ComputeAgingIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    """Compute AR aging over an explicitly-supplied list of open items
    (ad-hoc what-if for operators)."""
    return ar_svc.compute_ar_aging(inp.open_items, as_of_ts=inp.as_of_ts)
