"""AOS Sales Quote router (QUO-001) + quote conversion (QUO-003)."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    ContractOut,
    InvoiceOut,
    QuoteCreateIn,
    QuoteListOut,
    QuoteOut,
    QuotePatchIn,
    QuoteStageIn,
)
from app.services import aos_quotes as quote_service
from app.services import aos_quote_conversion as conversion_service
from app.services.sessions import require_ui_session

aos_quotes_router = APIRouter(prefix="/ui/quotes", tags=["aos-quotes"])
aos_quotes_admin_router = APIRouter(prefix="/ui/admin/quotes", tags=["aos-quotes-admin"])


def _require_enabled() -> None:
    from app.core.settings import S
    if not S.aos_quotes_enabled:
        raise HTTPException(404, "AOS quotes are not enabled")


@aos_quotes_router.post("", response_model=QuoteOut, status_code=201)
@aos_quotes_router.post("/", response_model=QuoteOut, status_code=201)
def create_quote(
    body: QuoteCreateIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> QuoteOut:
    _require_enabled()
    try:
        result = quote_service.create_quote(
            ctx["user_sub"],
            body.title,
            valid_until=body.valid_until,
            assigned_user_sub=body.assigned_user_sub,
            account_id=body.account_id,
            contact_id=body.contact_id,
            currency=body.currency,
            billing_address=body.billing_address.model_dump(),
            shipping_address=body.shipping_address.model_dump(),
            notes=body.notes,
            line_items=[li.model_dump() for li in body.line_items],
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    if result is None:
        raise HTTPException(404, "AOS quotes are not enabled")
    return QuoteOut(**result)


@aos_quotes_router.get("", response_model=QuoteListOut)
@aos_quotes_router.get("/", response_model=QuoteListOut)
def list_quotes(
    stage: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> QuoteListOut:
    _require_enabled()
    result = quote_service.list_quotes(ctx["user_sub"], stage=stage, limit=limit, cursor=cursor)
    if result is None:
        raise HTTPException(404, "AOS quotes are not enabled")
    return QuoteListOut(
        quotes=[QuoteOut(**q) for q in result["quotes"]],
        next_cursor=result.get("next_cursor"),
    )


@aos_quotes_router.get("/{quote_id}", response_model=QuoteOut)
def get_quote(
    quote_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> QuoteOut:
    _require_enabled()
    result = quote_service.get_quote(ctx["user_sub"], quote_id)
    if not result:
        raise HTTPException(404, "Quote not found")
    return QuoteOut(**result)


@aos_quotes_router.patch("/{quote_id}", response_model=QuoteOut)
def patch_quote(
    quote_id: str,
    body: QuotePatchIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> QuoteOut:
    _require_enabled()
    patch: Dict[str, Any] = {}
    for key, value in body.model_dump(exclude_unset=True).items():
        patch[key] = value
    try:
        result = quote_service.update_quote(ctx["user_sub"], quote_id, **patch)
    except ValueError as e:
        msg = str(e)
        if "converted" in msg:
            raise HTTPException(409, "Quote already converted")
        raise HTTPException(400, msg)
    if result is None:
        raise HTTPException(404, "Quote not found")
    return QuoteOut(**result)


@aos_quotes_router.post("/{quote_id}/stage", response_model=QuoteOut)
def transition_quote_stage(
    quote_id: str,
    body: QuoteStageIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> QuoteOut:
    _require_enabled()
    try:
        result = quote_service.transition_stage(ctx["user_sub"], quote_id, body.stage)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if result is None:
        raise HTTPException(404, "Quote not found")
    return QuoteOut(**result)


@aos_quotes_router.post("/{quote_id}/convert-to-invoice", response_model=InvoiceOut, status_code=201)
def convert_quote_to_invoice(
    quote_id: str,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> InvoiceOut:
    _require_enabled()
    result = conversion_service.convert_to_invoice(
        user_sub=ctx["user_sub"], quote_id=quote_id, request=request,
    )
    return InvoiceOut(**result)


@aos_quotes_router.post("/{quote_id}/convert-to-contract", response_model=ContractOut, status_code=201)
def convert_quote_to_contract(
    quote_id: str,
    request: Request,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ContractOut:
    _require_enabled()
    result = conversion_service.convert_to_contract(
        user_sub=ctx["user_sub"], quote_id=quote_id, request=request,
    )
    return ContractOut(**result)


@aos_quotes_admin_router.get("", response_model=QuoteListOut)
@aos_quotes_admin_router.get("/", response_model=QuoteListOut)
def admin_list_quotes(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> QuoteListOut:
    _require_enabled()
    result = quote_service.admin_list_quotes(limit=limit, cursor=cursor)
    if result is None:
        raise HTTPException(404, "AOS quotes are not enabled")
    return QuoteListOut(
        quotes=[QuoteOut(**q) for q in result["quotes"]],
        next_cursor=result.get("next_cursor"),
    )
