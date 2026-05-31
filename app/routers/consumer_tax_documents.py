"""Consumer Tax Documents endpoints (FIN-004).

Annual creator-earnings (1099-style) tax documents derived from billing
ledger credit entries. Creator-scoped: each user sees only their own
documents. Admin/root endpoints can issue/regenerate/view any user's docs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.models import (
    GenerateTaxDocumentIn,
    SpendingSummaryOut,
    TaxDocumentListOut,
    TaxDocumentOut,
    YearComparisonOut,
)
from app.services import consumer_tax_documents as svc
from app.services.sessions import require_ui_session

consumer_tax_documents_router = APIRouter(prefix="/ui/tax-documents", tags=["tax-documents"])
consumer_tax_documents_admin_router = APIRouter(
    prefix="/ui/admin/tax-documents", tags=["tax-documents-admin"]
)

_PLATFORM_LAUNCH_YEAR = 2024


def _ensure_enabled() -> None:
    if not S.tax_documents_enabled:
        raise HTTPException(status_code=503, detail="Tax documents are temporarily unavailable")


def _resolve_range(
    year: Optional[int],
    date_from: Optional[int],
    date_to: Optional[int],
) -> tuple[Optional[int], int, int]:
    """Resolve (year, date_from, date_to) from query params with validation."""
    current_year = datetime.now(timezone.utc).year
    if year is not None:
        if year > current_year:
            raise HTTPException(status_code=422, detail="Year cannot be in the future")
        if year < _PLATFORM_LAUNCH_YEAR:
            raise HTTPException(
                status_code=422, detail=f"No data available before {_PLATFORM_LAUNCH_YEAR}"
            )
        df, dt = svc.year_bounds(year)
        return year, df, dt
    if date_from is not None and date_to is not None:
        if date_from > date_to:
            raise HTTPException(status_code=422, detail="date_from must be before date_to")
        return None, int(date_from), int(date_to)
    raise HTTPException(
        status_code=422,
        detail="Either 'year' or both 'date_from' and 'date_to' are required",
    )


def _validate_year(year: int) -> None:
    """Validate a year-only param (raises 422 on out-of-range)."""
    _resolve_range(year, None, None)


# ---------------------------------------------------------------------------
# Creator-scoped endpoints
# ---------------------------------------------------------------------------

@consumer_tax_documents_router.get("/summary", response_model=SpendingSummaryOut)
def get_summary(
    year: Optional[int] = Query(default=None),
    date_from: Optional[int] = Query(default=None),
    date_to: Optional[int] = Query(default=None),
    session: Dict[str, str] = Depends(require_ui_session),
) -> SpendingSummaryOut:
    _ensure_enabled()
    resolved_year, df, dt = _resolve_range(year, date_from, date_to)
    user_sub = session["user_sub"]
    if resolved_year is not None:
        summary = svc.get_annual_summary(user_sub=user_sub, year=resolved_year)
    else:
        summary = svc.compute_earnings_summary(user_sub=user_sub, date_from=df, date_to=dt)
    return SpendingSummaryOut(**summary)


@consumer_tax_documents_router.get("/summary/pdf")
def get_summary_pdf(
    year: Optional[int] = Query(default=None),
    date_from: Optional[int] = Query(default=None),
    date_to: Optional[int] = Query(default=None),
    session: Dict[str, str] = Depends(require_ui_session),
) -> Response:
    _ensure_enabled()
    resolved_year, df, dt = _resolve_range(year, date_from, date_to)
    user_sub = session["user_sub"]
    if resolved_year is not None:
        summary = svc.get_annual_summary(user_sub=user_sub, year=resolved_year)
        filename = f"earnings-summary-{resolved_year}.pdf"
    else:
        summary = svc.compute_earnings_summary(user_sub=user_sub, date_from=df, date_to=dt)
        filename = f"earnings-summary-{df}-{dt}.pdf"
    pdf = svc.generate_tax_summary_pdf(user_sub=user_sub, summary=summary, year=resolved_year)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@consumer_tax_documents_router.get("/comparison", response_model=YearComparisonOut)
def get_comparison(
    year: int = Query(...),
    session: Dict[str, str] = Depends(require_ui_session),
) -> YearComparisonOut:
    _ensure_enabled()
    _validate_year(year)
    result = svc.get_year_comparison(user_sub=session["user_sub"], year=year)
    return YearComparisonOut(**result)


@consumer_tax_documents_router.get("/history", response_model=TaxDocumentListOut)
def get_history(
    session: Dict[str, str] = Depends(require_ui_session),
) -> TaxDocumentListOut:
    _ensure_enabled()
    docs = svc.list_tax_documents(user_sub=session["user_sub"])
    return TaxDocumentListOut(documents=[TaxDocumentOut(**d) for d in docs])


@consumer_tax_documents_router.post("/generate", response_model=TaxDocumentOut)
def generate_document(
    body: GenerateTaxDocumentIn,
    session: Dict[str, str] = Depends(require_ui_session),
) -> TaxDocumentOut:
    _ensure_enabled()
    _validate_year(body.year)
    try:
        doc = svc.generate_tax_document(
            user_sub=session["user_sub"], year=body.year, regenerate=body.regenerate
        )
    except ValueError as exc:
        code, _, message = str(exc).partition(":")
        raise HTTPException(status_code=422, detail={"code": code, "message": message or code})
    return TaxDocumentOut(**doc)


@consumer_tax_documents_router.get("/document/{year}/pdf")
def download_document_pdf(
    year: int,
    session: Dict[str, str] = Depends(require_ui_session),
) -> Response:
    _ensure_enabled()
    _validate_year(year)
    pdf = svc.download_tax_document_pdf(user_sub=session["user_sub"], year=year)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="earnings-summary-{year}.pdf"',
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

def _ensure_target_exists(target_user_sub: str) -> None:
    from app.core.tables import T

    item = T.profile.get_item(Key={"user_sub": target_user_sub}).get("Item")
    if not item:
        raise HTTPException(
            status_code=404, detail={"code": "user_not_found", "message": "User not found"}
        )


@consumer_tax_documents_admin_router.get("/summary", response_model=SpendingSummaryOut)
def admin_get_summary(
    user_sub: str = Query(...),
    year: Optional[int] = Query(default=None),
    date_from: Optional[int] = Query(default=None),
    date_to: Optional[int] = Query(default=None),
    _admin: Any = Depends(require_admin_or_root),
) -> SpendingSummaryOut:
    _ensure_enabled()
    if not user_sub:
        raise HTTPException(status_code=422, detail="user_sub is required")
    _ensure_target_exists(user_sub)
    resolved_year, df, dt = _resolve_range(year, date_from, date_to)
    if resolved_year is not None:
        summary = svc.get_annual_summary(user_sub=user_sub, year=resolved_year)
    else:
        summary = svc.compute_earnings_summary(user_sub=user_sub, date_from=df, date_to=dt)
    return SpendingSummaryOut(**summary)


@consumer_tax_documents_admin_router.post("/generate", response_model=TaxDocumentOut)
def admin_generate_document(
    body: GenerateTaxDocumentIn,
    user_sub: str = Query(...),
    _admin: Any = Depends(require_admin_or_root),
) -> TaxDocumentOut:
    _ensure_enabled()
    if not user_sub:
        raise HTTPException(status_code=422, detail="user_sub is required")
    _ensure_target_exists(user_sub)
    _validate_year(body.year)
    try:
        doc = svc.generate_tax_document(
            user_sub=user_sub, year=body.year, regenerate=body.regenerate
        )
    except ValueError as exc:
        code, _, message = str(exc).partition(":")
        raise HTTPException(status_code=422, detail={"code": code, "message": message or code})
    return TaxDocumentOut(**doc)
