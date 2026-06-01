"""KYC-010: Passport / National-ID Scanner router.

Prefix: ``/ui/kyc/id-scanner``

NET-NEW scanner invoked explicitly; independent of the KYC case file-attachment
flow. Mirrors ``app/routers/kyc_documents.py``.

User endpoints (owner, cookie + CSRF auth via ``require_ui_session``):
    POST  /ui/kyc/id-scanner/cases/{case_id}/scan-document   -> scan a document
    GET   /ui/kyc/id-scanner/cases/{case_id}/scans            -> list own scans
    GET   /ui/kyc/id-scanner/cases/{case_id}/scans/{scan_id}  -> get one (owner)
    POST  /ui/kyc/id-scanner/cases/{case_id}/validate-document -> side/MRZ reqs

Reviewer/admin endpoints (``require_admin_or_root``):
    GET   /ui/kyc/id-scanner/admin/by-status                  -> list by status (ByStatus GSI)
    GET   /ui/kyc/id-scanner/admin/scans/{scan_id}            -> get one (with cross-ref)
    POST  /ui/kyc/id-scanner/admin/scans/{scan_id}/adjudicate -> approve/decline
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    KycIdScannerAdjudicateRequest,
    KycIdScannerScanListResponse,
    KycIdScannerScanOut,
    KycIdScannerScanRequest,
    KycIdScannerValidateRequest,
    KycIdScannerValidationOut,
)
from app.services.kyc_id_scanner import (
    LISTABLE_STATUSES,
    STORE,
    KycIdScannerNotFoundError,
    KycIdScannerStateError,
    KycIdScannerValidationError,
    public_scan_view,
    scan_summary_view,
)
from app.services.sessions import require_ui_session

kyc_id_scanner_router = APIRouter(prefix="/ui/kyc/id-scanner", tags=["kyc-id-scanner"])


def _out(item: dict, *, include_cross_reference: bool) -> KycIdScannerScanOut:
    return KycIdScannerScanOut.model_validate(
        public_scan_view(item, include_cross_reference=include_cross_reference)
    )


def _require_owner(item: dict, user_sub: str) -> None:
    if str(item.get("user_sub") or "") != str(user_sub):
        raise HTTPException(
            status_code=403,
            detail={"code": "kyc_access_forbidden", "message": "You do not own this scan."},
        )


# --- owner endpoints -------------------------------------------------------


@kyc_id_scanner_router.post(
    "/cases/{case_id}/scan-document", response_model=KycIdScannerScanOut, status_code=201
)
async def scan_document(
    case_id: str,
    body: KycIdScannerScanRequest,
    session: dict = Depends(require_ui_session),
) -> KycIdScannerScanOut:
    try:
        item = STORE.scan_document(
            user_sub=session["user_sub"],
            case_id=case_id,
            document_type=body.document_type,
            file_type=body.file_type,
            mrz_lines=body.mrz_lines,
            image_ref=body.image_ref,
        )
    except KycIdScannerNotFoundError as exc:
        raise HTTPException(
            status_code=404, detail={"code": "kyc_case_not_found", "message": "Case not found."}
        ) from exc
    except KycIdScannerStateError as exc:
        code = str(exc)
        status_code = 403 if code == "kyc_access_forbidden" else 400
        message = (
            "You do not own this case."
            if code == "kyc_access_forbidden"
            else "Cannot scan documents on a finalized case."
        )
        raise HTTPException(status_code=status_code, detail={"code": code, "message": message}) from exc
    except KycIdScannerValidationError as exc:
        code = str(exc)
        status_code = 400 if code == "kyc_mrz_invalid_lines" else 422
        raise HTTPException(
            status_code=status_code, detail={"code": code, "message": "Invalid scan request."}
        ) from exc
    return _out(item, include_cross_reference=True)


@kyc_id_scanner_router.get(
    "/cases/{case_id}/scans", response_model=KycIdScannerScanListResponse
)
async def list_my_scans(
    case_id: str,
    session: dict = Depends(require_ui_session),
) -> KycIdScannerScanListResponse:
    items = STORE.list_scans_for_case(case_id)
    items = [i for i in items if str(i.get("user_sub") or "") == str(session["user_sub"])]
    return KycIdScannerScanListResponse(scans=[scan_summary_view(i) for i in items])


@kyc_id_scanner_router.post(
    "/cases/{case_id}/validate-document", response_model=KycIdScannerValidationOut
)
async def validate_document(
    case_id: str,
    body: KycIdScannerValidateRequest,
    session: dict = Depends(require_ui_session),
) -> KycIdScannerValidationOut:
    try:
        result = STORE.validate_requirements(document_type=body.document_type, case_id=case_id)
    except KycIdScannerValidationError as exc:
        raise HTTPException(
            status_code=422, detail={"code": str(exc), "message": "Invalid document type."}
        ) from exc
    return KycIdScannerValidationOut.model_validate(result)


# --- reviewer / admin endpoints -------------------------------------------


@kyc_id_scanner_router.get("/admin/by-status", response_model=KycIdScannerScanListResponse)
async def admin_list_by_status(
    status: str = Query(..., description="matched | flagged | rejected | approved | declined"),
    limit: int = Query(100, ge=1, le=500),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycIdScannerScanListResponse:
    if status not in LISTABLE_STATUSES:
        raise HTTPException(
            status_code=422, detail={"code": "invalid_status", "message": "Unknown status."}
        )
    items = STORE.list_by_status(status, limit=limit)
    return KycIdScannerScanListResponse(scans=[scan_summary_view(i) for i in items])


@kyc_id_scanner_router.get("/admin/scans/{scan_id}", response_model=KycIdScannerScanOut)
async def admin_get_scan(
    scan_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycIdScannerScanOut:
    item = STORE.get_scan(scan_id)
    if not item:
        raise HTTPException(
            status_code=404, detail={"code": "kyc_scan_not_found", "message": "Scan not found."}
        )
    return _out(item, include_cross_reference=True)


@kyc_id_scanner_router.post(
    "/admin/scans/{scan_id}/adjudicate", response_model=KycIdScannerScanOut
)
async def admin_adjudicate_scan(
    scan_id: str,
    body: KycIdScannerAdjudicateRequest,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycIdScannerScanOut:
    try:
        item = STORE.adjudicate(
            scan_id=scan_id,
            decision=body.decision,
            reviewer_sub=user.sub,
            note=body.note,
        )
    except KycIdScannerNotFoundError as exc:
        raise HTTPException(
            status_code=404, detail={"code": "kyc_scan_not_found", "message": "Scan not found."}
        ) from exc
    except KycIdScannerValidationError as exc:
        raise HTTPException(
            status_code=422, detail={"code": str(exc), "message": "Invalid adjudication decision."}
        ) from exc
    return _out(item, include_cross_reference=True)


# --- owner get-one (registered last so /admin/* and /validate-document win) ---


@kyc_id_scanner_router.get(
    "/cases/{case_id}/scans/{scan_id}", response_model=KycIdScannerScanOut
)
async def get_my_scan(
    case_id: str,
    scan_id: str,
    session: dict = Depends(require_ui_session),
) -> KycIdScannerScanOut:
    item = STORE.get_scan(scan_id)
    if not item:
        raise HTTPException(
            status_code=404, detail={"code": "kyc_scan_not_found", "message": "Scan not found."}
        )
    _require_owner(item, session["user_sub"])
    return _out(item, include_cross_reference=True)
