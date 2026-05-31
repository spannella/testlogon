"""KYC-004: Proof of Residency Verification router.

Prefix: ``/ui/kyc/residency``

User endpoints (owner, cookie + CSRF auth via ``require_ui_session``):
    POST   /ui/kyc/residency                       -> upload a residency document
    GET    /ui/kyc/residency                        -> list own documents
    GET    /ui/kyc/residency/{document_id}          -> get one (owner)
    POST   /ui/kyc/residency/{document_id}/extract  -> (re)run extraction

Reviewer/admin endpoints (``require_admin_or_root``):
    GET    /ui/kyc/residency/admin/by-status         -> list by status via ByStatus GSI
    GET    /ui/kyc/residency/admin/{document_id}      -> get one (with match details)
    POST   /ui/kyc/residency/admin/{document_id}/review -> approve/reject
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    KycResidencyDocumentOut,
    KycResidencyListResponse,
    KycResidencyReviewRequest,
    KycResidencyUploadRequest,
)
from app.services.kyc_residency import (
    LISTABLE_STATUSES,
    STORE,
    KycResidencyNotFoundError,
    KycResidencyStateError,
    KycResidencyValidationError,
    public_document_view,
)
from app.services.sessions import require_ui_session

kyc_residency_router = APIRouter(prefix="/ui/kyc/residency", tags=["kyc-residency"])


def _out(item: dict, *, include_match: bool) -> KycResidencyDocumentOut:
    return KycResidencyDocumentOut.model_validate(
        public_document_view(item, include_match=include_match)
    )


def _require_owner(item: dict, user_sub: str) -> None:
    if str(item.get("user_sub") or "") != str(user_sub):
        raise HTTPException(
            status_code=403,
            detail={"code": "kyc_access_forbidden", "message": "You do not own this document."},
        )


# --- owner endpoints -------------------------------------------------------


@kyc_residency_router.post("", response_model=KycResidencyDocumentOut, status_code=201)
@kyc_residency_router.post(
    "/", response_model=KycResidencyDocumentOut, status_code=201, include_in_schema=False
)
async def upload_residency_document(
    body: KycResidencyUploadRequest,
    session: dict = Depends(require_ui_session),
) -> KycResidencyDocumentOut:
    try:
        item = STORE.upload_document(
            user_sub=session["user_sub"],
            document_type=body.document_type,
            issuing_entity=body.issuing_entity,
            document_date=body.document_date,
            file_name=body.file_name,
            case_id=body.case_id,
            content_b64=body.content_b64,
        )
    except KycResidencyValidationError as exc:
        raise HTTPException(
            status_code=422, detail={"code": str(exc), "message": "Invalid residency upload."}
        ) from exc
    # Run the extraction/verification pipeline synchronously (mock provider in dev/E2E).
    try:
        item = STORE.run_extraction(item["document_id"])
    except Exception:
        refreshed = STORE.get_document(item["document_id"])
        if refreshed:
            item = refreshed
    return _out(item, include_match=True)


@kyc_residency_router.get("", response_model=KycResidencyListResponse)
@kyc_residency_router.get("/", response_model=KycResidencyListResponse, include_in_schema=False)
async def list_my_residency_documents(
    session: dict = Depends(require_ui_session),
) -> KycResidencyListResponse:
    items = STORE.list_documents_for_owner(session["user_sub"])
    return KycResidencyListResponse(documents=[_out(i, include_match=True) for i in items])


@kyc_residency_router.get("/admin/by-status", response_model=KycResidencyListResponse)
async def admin_list_by_status(
    status: str = Query(..., description="pending | verified | rejected | expired"),
    limit: int = Query(100, ge=1, le=500),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycResidencyListResponse:
    if status not in LISTABLE_STATUSES:
        raise HTTPException(
            status_code=422, detail={"code": "invalid_status", "message": "Unknown status."}
        )
    items = STORE.list_by_status(status, limit=limit)
    return KycResidencyListResponse(documents=[_out(i, include_match=True) for i in items])


@kyc_residency_router.get("/admin/{document_id}", response_model=KycResidencyDocumentOut)
async def admin_get_residency_document(
    document_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycResidencyDocumentOut:
    item = STORE.get_document(document_id)
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_residency_not_found", "message": "Document not found."},
        )
    return _out(item, include_match=True)


@kyc_residency_router.post("/admin/{document_id}/review", response_model=KycResidencyDocumentOut)
async def admin_review_residency_document(
    document_id: str,
    body: KycResidencyReviewRequest,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycResidencyDocumentOut:
    try:
        item = STORE.review_document(
            document_id=document_id,
            decision=body.decision,
            reviewer_sub=user.sub,
            note=body.note,
        )
    except KycResidencyNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_residency_not_found", "message": "Document not found."},
        ) from exc
    except KycResidencyStateError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": str(exc), "message": "Document is not in a reviewable state."},
        ) from exc
    except KycResidencyValidationError as exc:
        raise HTTPException(
            status_code=422, detail={"code": str(exc), "message": "Invalid review decision."}
        ) from exc
    return _out(item, include_match=True)


@kyc_residency_router.get("/{document_id}", response_model=KycResidencyDocumentOut)
async def get_residency_document(
    document_id: str,
    session: dict = Depends(require_ui_session),
) -> KycResidencyDocumentOut:
    item = STORE.get_document(document_id)
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_residency_not_found", "message": "Document not found."},
        )
    _require_owner(item, session["user_sub"])
    return _out(item, include_match=True)


@kyc_residency_router.post("/{document_id}/extract", response_model=KycResidencyDocumentOut)
async def extract_residency_document(
    document_id: str,
    session: dict = Depends(require_ui_session),
) -> KycResidencyDocumentOut:
    item = STORE.get_document(document_id)
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_residency_not_found", "message": "Document not found."},
        )
    _require_owner(item, session["user_sub"])
    try:
        item = STORE.run_extraction(document_id)
    except KycResidencyNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_residency_not_found", "message": "Document not found."},
        ) from exc
    return _out(item, include_match=True)
