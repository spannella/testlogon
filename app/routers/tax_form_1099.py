"""Creator 1099 / Tax-Form generation endpoints (FIN-008).

DISTINCT from ``consumer_tax_documents`` (FIN-004, consumer/buyer side). FIN-008
is the platform-issuer side: per-creator annual 1099-NEC earnings forms.

Creator-scoped endpoints (``require_ui_session``):
  - GET  /ui/tax-forms/1099s                       list own forms
  - GET  /ui/tax-forms/1099s/{tax_year}            get one form
  - POST /ui/tax-forms/1099s/{tax_year}/generate   generate own form (409 dup)
  - GET  /ui/tax-forms/1099s/{tax_year}/download    download URL (404 missing)

Admin endpoints (``require_admin_or_root``):
  - POST /ui/tax-forms/admin/1099s/{tax_year}/generate          single (any creator)
  - POST /ui/tax-forms/admin/1099s/{tax_year}/correct           correction/re-gen
  - POST /ui/tax-forms/admin/batch                              batch (429 in-progress)
  - GET  /ui/tax-forms/admin/year/{tax_year}                    list all year forms
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.models import (
    BatchGenerateTaxForm1099In,
    BatchGenerateTaxForm1099Out,
    TaxForm1099DownloadOut,
    TaxForm1099ListOut,
    TaxForm1099Out,
    W9StatusOut,
    W9SubmitIn,
)
from app.services import tax_form_1099 as svc
from app.services import tax_info_w9
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session

tax_form_1099_router = APIRouter(prefix="/ui/tax-forms", tags=["tax-forms-1099"])

_CODE_TO_STATUS = {
    "already_generated": 409,
    "batch_in_progress": 429,
    "not_found": 404,
    "below_threshold": 422,
}


def _ensure_enabled() -> None:
    if not S.tax_form_1099_enabled:
        raise HTTPException(
            status_code=503, detail="1099 tax forms are temporarily unavailable"
        )


def _raise_for(err: svc.TaxForm1099Error) -> "HTTPException":
    status = _CODE_TO_STATUS.get(err.code, 400)
    return HTTPException(status_code=status, detail={"code": err.code, "message": err.message})


def _ensure_target_exists(target_user_sub: str) -> None:
    from app.core.tables import T

    item = T.profile.get_item(Key={"user_sub": target_user_sub}).get("Item")
    if not item:
        raise HTTPException(
            status_code=404, detail={"code": "user_not_found", "message": "User not found"}
        )


# ---------------------------------------------------------------------------
# W-9 / TIN collection (GAP-0020)
# ---------------------------------------------------------------------------

@tax_form_1099_router.post("/w9", response_model=W9StatusOut, summary="Submit W-9 tax information")
def submit_w9(
    body: W9SubmitIn,
    session: Dict[str, str] = Depends(require_ui_session),
) -> W9StatusOut:
    """Collect and KMS-encrypt the creator's TIN. Required before 1099 generation.

    The raw TIN is never stored in plaintext, logged, or returned — the response
    exposes the masked last-4 only.
    """
    _ensure_enabled()
    try:
        result = tax_info_w9.submit_tax_info(
            user_sub=session["user_sub"],
            **body.model_dump(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail={"code": "invalid_tin", "message": str(exc)}
        )
    return W9StatusOut(**result)


@tax_form_1099_router.get("/w9", response_model=W9StatusOut, summary="Get W-9 status")
def get_w9_status(
    session: Dict[str, str] = Depends(require_ui_session),
) -> W9StatusOut:
    """Return the masked W-9 status for the current user (never the raw TIN)."""
    _ensure_enabled()
    result = tax_info_w9.get_tax_info(session["user_sub"])
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "No W-9 on file"},
        )
    return W9StatusOut(**result)


# ---------------------------------------------------------------------------
# Creator-scoped endpoints
# ---------------------------------------------------------------------------

@tax_form_1099_router.get("/1099s", response_model=TaxForm1099ListOut)
def list_my_1099s(
    session: Dict[str, str] = Depends(require_ui_session),
) -> TaxForm1099ListOut:
    _ensure_enabled()
    items = svc.list_1099s(user_sub=session["user_sub"])
    return TaxForm1099ListOut(items=[TaxForm1099Out(**i) for i in items])


@tax_form_1099_router.get("/1099s/{tax_year}", response_model=TaxForm1099Out)
def get_my_1099(
    tax_year: int,
    session: Dict[str, str] = Depends(require_ui_session),
) -> TaxForm1099Out:
    _ensure_enabled()
    form = svc.get_1099(user_sub=session["user_sub"], tax_year=tax_year)
    if form is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "No 1099 found for this tax year"},
        )
    return TaxForm1099Out(**form)


@tax_form_1099_router.post("/1099s/{tax_year}/generate", response_model=TaxForm1099Out)
def generate_my_1099(
    tax_year: int,
    request: Request,
    session: Dict[str, str] = Depends(require_ui_session),
) -> TaxForm1099Out:
    _ensure_enabled()
    user_sub = session["user_sub"]
    try:
        form = svc.generate_1099(user_sub=user_sub, tax_year=tax_year)
    except svc.TaxForm1099Error as err:
        raise _raise_for(err)
    return TaxForm1099Out(**form)


@tax_form_1099_router.get(
    "/1099s/{tax_year}/download", response_model=TaxForm1099DownloadOut
)
def download_my_1099(
    tax_year: int,
    session: Dict[str, str] = Depends(require_ui_session),
) -> TaxForm1099DownloadOut:
    _ensure_enabled()
    try:
        url = svc.download_1099_url(user_sub=session["user_sub"], tax_year=tax_year)
    except svc.TaxForm1099Error as err:
        raise _raise_for(err)
    return TaxForm1099DownloadOut(download_url=url)


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@tax_form_1099_router.post(
    "/admin/1099s/{tax_year}/generate", response_model=TaxForm1099Out
)
def admin_generate_1099(
    tax_year: int,
    request: Request,
    user_sub: str = Query(...),
    admin: Any = Depends(require_admin_or_root),
) -> TaxForm1099Out:
    _ensure_enabled()
    if not user_sub:
        raise HTTPException(status_code=422, detail="user_sub is required")
    _ensure_target_exists(user_sub)
    try:
        form = svc.generate_1099(user_sub=user_sub, tax_year=tax_year)
    except svc.TaxForm1099Error as err:
        raise _raise_for(err)
    audit_event(
        "tax_form_1099_generated",
        admin.sub,
        request=request,
        target_user_sub=user_sub,
        tax_year=tax_year,
    )
    return TaxForm1099Out(**form)


@tax_form_1099_router.post(
    "/admin/1099s/{tax_year}/correct", response_model=TaxForm1099Out
)
def admin_correct_1099(
    tax_year: int,
    request: Request,
    user_sub: str = Query(...),
    admin: Any = Depends(require_admin_or_root),
) -> TaxForm1099Out:
    _ensure_enabled()
    if not user_sub:
        raise HTTPException(status_code=422, detail="user_sub is required")
    _ensure_target_exists(user_sub)
    try:
        form = svc.correct_1099(user_sub=user_sub, tax_year=tax_year)
    except svc.TaxForm1099Error as err:
        raise _raise_for(err)
    audit_event(
        "tax_form_1099_corrected",
        admin.sub,
        request=request,
        target_user_sub=user_sub,
        tax_year=tax_year,
    )
    return TaxForm1099Out(**form)


@tax_form_1099_router.post("/admin/batch", response_model=BatchGenerateTaxForm1099Out)
def admin_batch_generate(
    body: BatchGenerateTaxForm1099In,
    request: Request,
    admin: Any = Depends(require_admin_or_root),
) -> BatchGenerateTaxForm1099Out:
    _ensure_enabled()
    try:
        result = svc.batch_generate_1099s(tax_year=body.tax_year)
    except svc.TaxForm1099Error as err:
        raise _raise_for(err)
    audit_event(
        "tax_form_1099_batch_generated",
        admin.sub,
        request=request,
        tax_year=body.tax_year,
        generated=result.get("generated", 0),
        qualifying=result.get("qualifying", 0),
    )
    return BatchGenerateTaxForm1099Out(**result)


@tax_form_1099_router.get(
    "/admin/year/{tax_year}", response_model=TaxForm1099ListOut
)
def admin_list_year(
    tax_year: int,
    admin: Any = Depends(require_admin_or_root),
) -> TaxForm1099ListOut:
    _ensure_enabled()
    items = svc.list_year_forms(tax_year=tax_year)
    return TaxForm1099ListOut(items=[TaxForm1099Out(**i) for i in items])
