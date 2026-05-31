"""Invoice management router (FIN-001).

Endpoints for listing, retrieving, downloading (PDF), and emailing invoices,
plus an admin endpoint for cross-user lookup.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.models import InvoiceEmailOut, InvoiceListOut, InvoiceOut
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
