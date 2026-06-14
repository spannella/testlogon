"""INV-002 — Admin currency registry endpoints (/ui/admin/currencies)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.core.settings import S
from app.models import (
    CurrencyCreateIn,
    CurrencyListOut,
    CurrencyOut,
    CurrencyPatchIn,
)
from app.services import crm_currencies

crm_currencies_router = APIRouter(prefix="/ui/admin/currencies", tags=["currencies"])


def _require_enabled() -> None:
    if not S.crm_currencies_enabled:
        raise HTTPException(404, "Currency management is not enabled")


@crm_currencies_router.post("", response_model=CurrencyOut, status_code=201)
@crm_currencies_router.post("/", response_model=CurrencyOut, status_code=201)
async def create_currency_endpoint(
    body: CurrencyCreateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> CurrencyOut:
    _require_enabled()
    try:
        result = crm_currencies.create_currency(
            iso_code=body.iso_code,
            name=body.name,
            symbol=body.symbol,
            rate_to_usd=body.rate_to_usd,
            decimal_places=body.decimal_places,
            is_active=body.is_active,
            created_by=user.sub,
        )
    except ValueError as exc:
        msg = str(exc)
        if "already exists" in msg:
            raise HTTPException(409, {"code": "currency_exists", "message": msg})
        raise HTTPException(422, {"code": "invalid_currency", "message": msg})
    return CurrencyOut(**result)


@crm_currencies_router.get("", response_model=CurrencyListOut)
@crm_currencies_router.get("/", response_model=CurrencyListOut)
async def list_currencies_endpoint(
    active_only: bool = Query(default=True),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CurrencyListOut:
    _require_enabled()
    items = crm_currencies.list_currencies(active_only=active_only)
    return CurrencyListOut(currencies=[CurrencyOut(**c) for c in items])


@crm_currencies_router.get("/{iso_code}", response_model=CurrencyOut)
async def get_currency_endpoint(
    iso_code: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CurrencyOut:
    _require_enabled()
    item = crm_currencies.get_currency(iso_code)
    if not item:
        raise HTTPException(404, {"code": "currency_not_found"})
    return CurrencyOut(**item)


@crm_currencies_router.patch("/{iso_code}", response_model=CurrencyOut)
async def update_currency_endpoint(
    iso_code: str,
    body: CurrencyPatchIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> CurrencyOut:
    _require_enabled()
    try:
        result = crm_currencies.update_currency(
            iso_code,
            name=body.name,
            symbol=body.symbol,
            rate_to_usd=body.rate_to_usd,
            is_active=body.is_active,
            decimal_places=body.decimal_places,
            updated_by=user.sub,
        )
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg:
            raise HTTPException(404, {"code": "currency_not_found", "message": msg})
        raise HTTPException(422, {"code": "invalid_currency", "message": msg})
    return CurrencyOut(**result)
