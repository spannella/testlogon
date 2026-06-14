"""INV-005 — Admin tax-rate registry endpoints (/ui/admin/tax-rates)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.core.settings import S
from app.models import (
    TaxRateCreateIn,
    TaxRateListOut,
    TaxRateOut,
    TaxRatePatchIn,
)
from app.services import crm_tax_rates

crm_tax_rates_router = APIRouter(prefix="/ui/admin/tax-rates", tags=["crm-tax-rates"])


def _require_enabled() -> None:
    if not S.crm_tax_rates_enabled:
        raise HTTPException(404, "Tax rate management is not enabled")


@crm_tax_rates_router.post("", response_model=TaxRateOut, status_code=201)
@crm_tax_rates_router.post("/", response_model=TaxRateOut, status_code=201)
async def create_tax_rate_endpoint(
    body: TaxRateCreateIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> TaxRateOut:
    _require_enabled()
    try:
        result = crm_tax_rates.create_tax_rate(
            name=body.name,
            rate_bps=body.rate_bps,
            jurisdiction=body.jurisdiction,
            description=body.description,
            created_by=user.sub,
        )
    except ValueError as exc:
        raise HTTPException(422, {"code": "invalid_tax_rate", "message": str(exc)})
    return TaxRateOut(**result)


@crm_tax_rates_router.get("", response_model=TaxRateListOut)
@crm_tax_rates_router.get("/", response_model=TaxRateListOut)
async def list_tax_rates_endpoint(
    jurisdiction: Optional[str] = Query(default=None),
    active_only: bool = Query(default=True),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> TaxRateListOut:
    _require_enabled()
    result = crm_tax_rates.list_tax_rates(
        jurisdiction=jurisdiction,
        active_only=active_only,
        limit=limit,
        cursor=cursor,
    )
    return TaxRateListOut(
        tax_rates=[TaxRateOut(**r) for r in result["tax_rates"]],
        next_cursor=result.get("next_cursor"),
    )


@crm_tax_rates_router.get("/{tax_rate_id}", response_model=TaxRateOut)
async def get_tax_rate_endpoint(
    tax_rate_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> TaxRateOut:
    _require_enabled()
    item = crm_tax_rates.get_tax_rate(tax_rate_id)
    if not item:
        raise HTTPException(404, {"code": "tax_rate_not_found"})
    return TaxRateOut(**item)


@crm_tax_rates_router.patch("/{tax_rate_id}", response_model=TaxRateOut)
async def update_tax_rate_endpoint(
    tax_rate_id: str,
    body: TaxRatePatchIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> TaxRateOut:
    _require_enabled()
    try:
        result = crm_tax_rates.update_tax_rate(
            tax_rate_id,
            updated_by=user.sub,
            **body.model_dump(exclude_none=True),
        )
    except KeyError:
        raise HTTPException(404, {"code": "tax_rate_not_found"})
    except ValueError as exc:
        raise HTTPException(422, {"code": "invalid_tax_rate", "message": str(exc)})
    return TaxRateOut(**result)
