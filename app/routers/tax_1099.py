"""Honest 1099-NEC tax-reporting admin endpoints (PAY-40 / PAY-E).

The platform is the payer/filer, so these are ADMIN-ONLY (``require_admin_or_root``
-> 403 for non-admin). They report what was ACTUALLY PAID OUT per payee from the
PAY-A ledger (returns/reversals excluded), NOT phantom credited earnings - which
is what the separate FIN-008 ``/ui/tax-forms`` router does.

Endpoints (prefix ``/ui/tax-1099``):
  - POST /admin/year/{tax_year}/generate                  generate/refresh the year set
  - POST /admin/year/{tax_year}/payee/{user_sub}/generate generate/refresh one payee
  - GET  /admin/year/{tax_year}                           list year records (?include_under_threshold)
  - GET  /admin/year/{tax_year}/payee/{user_sub}          get one payee record (queryable under-threshold)
  - GET  /admin/year/{tax_year}/withholding-report        W-9-gap / would-be-withheld report
  - GET  /admin/year/{tax_year}/export                    filing export (?format=csv|json, masked TIN)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.services import tax_1099 as svc
from app.services.alerts import audit_event

tax_1099_router = APIRouter(prefix="/ui/tax-1099", tags=["tax-1099-nec"])


def _ensure_enabled() -> None:
    if not S.tax_form_1099_enabled:
        raise HTTPException(
            status_code=503, detail="1099 tax reporting is temporarily unavailable"
        )


@tax_1099_router.post("/admin/year/{tax_year}/generate")
def admin_generate_year(
    tax_year: int,
    request: Request,
    admin: Any = Depends(require_admin_or_root),
) -> dict:
    """Generate/refresh the whole NEC 1099 set for the tax year (idempotent + correction-aware)."""
    _ensure_enabled()
    result = svc.generate_year_set(tax_year=tax_year)
    audit_event(
        "nec1099_year_generated",
        admin.sub,
        request=request,
        tax_year=tax_year,
        reportable=result.get("reportable", 0),
        corrected=result.get("corrected", 0),
    )
    return result


@tax_1099_router.post("/admin/year/{tax_year}/payee/{user_sub}/generate")
def admin_generate_payee(
    tax_year: int,
    user_sub: str,
    request: Request,
    admin: Any = Depends(require_admin_or_root),
) -> dict:
    """Generate/refresh a single payee's NEC 1099 for the year (idempotent + correction-aware)."""
    _ensure_enabled()
    if not user_sub:
        raise HTTPException(status_code=422, detail="user_sub is required")
    rec = svc.generate_or_refresh(user_sub=user_sub, tax_year=tax_year)
    audit_event(
        "nec1099_payee_generated",
        admin.sub,
        request=request,
        target_user_sub=user_sub,
        tax_year=tax_year,
        status=rec.get("status"),
    )
    return rec


@tax_1099_router.get("/admin/year/{tax_year}")
def admin_list_year(
    tax_year: int,
    include_under_threshold: bool = Query(default=False),
    admin: Any = Depends(require_admin_or_root),
) -> dict:
    """List all NEC 1099 records for the year (reportable only unless include_under_threshold)."""
    _ensure_enabled()
    items = svc.list_year(
        tax_year=tax_year, include_under_threshold=include_under_threshold
    )
    return {"tax_year": tax_year, "count": len(items), "items": items}


@tax_1099_router.get("/admin/year/{tax_year}/payee/{user_sub}")
def admin_get_payee(
    tax_year: int,
    user_sub: str,
    refresh: bool = Query(default=False),
    admin: Any = Depends(require_admin_or_root),
) -> dict:
    """Get one payee's NEC 1099 (queryable even under the $600 threshold).

    ``?refresh=1`` recomputes from the ledger first (so under-threshold /
    not-yet-generated payees still return their honest computed figure).
    """
    _ensure_enabled()
    if refresh:
        return svc.generate_or_refresh(user_sub=user_sub, tax_year=tax_year)
    rec = svc.get_1099(user_sub=user_sub, tax_year=tax_year)
    if rec is None:
        # Not generated yet - return the honest computed assessment (queryable).
        return svc.build_assessment(user_sub=user_sub, tax_year=tax_year)
    return rec


@tax_1099_router.get("/admin/year/{tax_year}/withholding-report")
def admin_withholding_report(
    tax_year: int,
    admin: Any = Depends(require_admin_or_root),
) -> dict:
    """Payees who are reportable but lack a certified W-9 - the 24% would-be-withheld gap."""
    _ensure_enabled()
    return svc.withholding_gap_report(tax_year=tax_year)


@tax_1099_router.get("/admin/year/{tax_year}/export")
def admin_export_year(
    tax_year: int,
    request: Request,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    include_under_threshold: bool = Query(default=False),
    admin: Any = Depends(require_admin_or_root),
) -> Response:
    """Filing-ready export (CSV or JSON), masked TIN only (``***-**-1234``), never raw."""
    _ensure_enabled()
    content, content_type = svc.export_year(
        tax_year=tax_year, fmt=format, include_under_threshold=include_under_threshold
    )
    audit_event(
        "nec1099_year_exported",
        admin.sub,
        request=request,
        tax_year=tax_year,
        format=format,
    )
    filename = f"1099nec_{tax_year}.{'csv' if format == 'csv' else 'json'}"
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
