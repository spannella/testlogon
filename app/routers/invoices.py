"""Invoice management router (FIN-001).

Endpoints for listing, retrieving, downloading (PDF), and emailing invoices,
plus an admin endpoint for cross-user lookup.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from fastapi import Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.models import (
    InvoiceEmailOut,
    InvoiceListOut,
    InvoiceOut,
    ManualInvoiceCreateIn,
    ManualPayInvoiceIn,
    RecordExternalPaymentIn,
)
from app.services import invoices as invoice_service
from app.services.sessions import require_ui_session

invoices_router = APIRouter(prefix="/ui/invoices", tags=["invoices"])
invoices_admin_router = APIRouter(prefix="/ui/admin/invoices", tags=["invoices-admin"])


def _require_enabled() -> None:
    from app.core.settings import S
    if not S.invoices_enabled:
        raise HTTPException(404, "Invoices are not enabled")


@invoices_router.get("", response_model=InvoiceListOut)
@invoices_router.get("/", response_model=InvoiceListOut)
def list_invoices(
    type: Optional[str] = Query(default=None),
    date_from: Optional[int] = Query(default=None),
    date_to: Optional[int] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> InvoiceListOut:
    _require_enabled()
    result = invoice_service.list_invoices(
        user_sub=ctx["user_sub"],
        invoice_type=type,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
        cursor=cursor,
    )
    return InvoiceListOut(
        invoices=[InvoiceOut(**inv) for inv in result["invoices"]],
        next_cursor=result.get("next_cursor"),
    )


# --------------------------------------------------------------------------
# QUO-005: standalone invoice lifecycle endpoints.
# NOTE: declared BEFORE the dynamic /{invoice_number} GET so the literal
# action segments are not captured as a path param.
# --------------------------------------------------------------------------

@invoices_router.post("/{invoice_number}/void", response_model=InvoiceOut)
def void_invoice(
    invoice_number: str,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> InvoiceOut:
    invoice_service._require_standalone_enabled()
    result = invoice_service.update_invoice_status(
        ctx["user_sub"], invoice_number, "void", admin=False, request=request,
    )
    return InvoiceOut(**result)


@invoices_router.post("/{invoice_number}/send", response_model=InvoiceOut)
def send_invoice(
    invoice_number: str,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> InvoiceOut:
    invoice_service._require_standalone_enabled()
    result = invoice_service.update_invoice_status(
        ctx["user_sub"], invoice_number, "sent", request=request,
    )
    try:
        invoice_service.email_invoice(ctx["user_sub"], invoice_number)
    except Exception:  # best-effort; do not block the transition
        pass
    return InvoiceOut(**result)


@invoices_router.post("/{invoice_number}/pay", response_model=InvoiceOut)
def pay_invoice(
    invoice_number: str,
    request: Request,
    body: ManualPayInvoiceIn = ManualPayInvoiceIn(),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> InvoiceOut:
    invoice_service._require_standalone_enabled()
    result = invoice_service.update_invoice_status(
        ctx["user_sub"], invoice_number, "paid",
        payment_ref=body.payment_ref, request=request,
    )
    return InvoiceOut(**result)


@invoices_router.get("/{invoice_number}", response_model=InvoiceOut)
def get_invoice(
    invoice_number: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> InvoiceOut:
    _require_enabled()
    inv = invoice_service.get_invoice(ctx["user_sub"], invoice_number)
    if not inv:
        raise HTTPException(404, "Invoice not found")
    return InvoiceOut(**inv)


@invoices_router.get("/{invoice_number}/pdf")
def download_invoice_pdf(
    invoice_number: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Response:
    _require_enabled()
    pdf = invoice_service.download_invoice_pdf(ctx["user_sub"], invoice_number)
    if pdf is None:
        raise HTTPException(404, "Invoice not found")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{invoice_number}.pdf"'},
    )


@invoices_router.post("/{invoice_number}/email", response_model=InvoiceEmailOut)
def email_invoice(
    invoice_number: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> InvoiceEmailOut:
    _require_enabled()
    result = invoice_service.email_invoice(ctx["user_sub"], invoice_number)
    if not result.get("ok"):
        raise HTTPException(404, "Invoice not found")
    return InvoiceEmailOut(
        ok=True,
        emailed_to=result.get("emailed_to", ""),
        message=result.get("message", ""),
    )


@invoices_admin_router.get("", response_model=InvoiceListOut)
@invoices_admin_router.get("/", response_model=InvoiceListOut)
def admin_list_invoices(
    user_sub: Optional[str] = Query(default=None),
    type: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> InvoiceListOut:
    _require_enabled()
    result = invoice_service.admin_list_invoices(
        target_user_sub=user_sub,
        invoice_type=type,
        limit=limit,
        cursor=cursor,
    )
    return InvoiceListOut(
        invoices=[InvoiceOut(**inv) for inv in result["invoices"]],
        next_cursor=result.get("next_cursor"),
    )


# --------------------------------------------------------------------------
# QUO-005 admin endpoints: manual B2B create, admin void, record-payment (D5).
# --------------------------------------------------------------------------

@invoices_admin_router.post("/manual", response_model=InvoiceOut, status_code=201)
def create_manual_invoice(
    body: ManualInvoiceCreateIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> InvoiceOut:
    invoice_service._require_standalone_enabled()
    result = invoice_service.create_manual_invoice(
        admin_user_sub=actor.sub,
        buyer_user_sub=body.buyer_user_sub,
        buyer_name=body.buyer_name,
        buyer_email=body.buyer_email,
        billing_address=body.billing_address.model_dump(),
        line_items=[li.model_dump() for li in body.line_items],
        currency=body.currency,
        payment_terms_days=body.payment_terms_days,
        notes=body.notes,
    )
    return InvoiceOut(**result)


@invoices_admin_router.post("/{invoice_number}/void", response_model=InvoiceOut)
def admin_void_invoice(
    invoice_number: str,
    request: Request,
    user_sub: str = Query(...),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> InvoiceOut:
    invoice_service._require_standalone_enabled()
    result = invoice_service.update_invoice_status(
        user_sub, invoice_number, "void", admin=True, request=request,
    )
    return InvoiceOut(**result)


@invoices_admin_router.post("/{invoice_number}/record-payment", response_model=InvoiceOut)
def admin_record_payment(
    invoice_number: str,
    body: RecordExternalPaymentIn,
    request: Request,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> InvoiceOut:
    """D5: record an offline/external payment (no Stripe / provider charge)."""
    invoice_service._require_standalone_enabled()
    result = invoice_service.record_external_payment(
        admin_user_sub=actor.sub,
        owner_user_sub=body.user_sub,
        invoice_number=invoice_number,
        amount_cents=body.amount_cents,
        reference=body.reference,
        reason=body.reason,
        request=request,
    )
    return InvoiceOut(**result)
