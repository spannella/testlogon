"""KYC-002: Identity Document Verification router.

Prefix: ``/ui/kyc/documents``

User endpoints (owner, cookie + CSRF auth via ``require_ui_session``):
    POST   /ui/kyc/documents                      -> upload a document
    GET    /ui/kyc/documents                       -> list own documents
    GET    /ui/kyc/documents/{document_id}         -> get one (owner)
    POST   /ui/kyc/documents/{document_id}/extract -> (re)run extraction

Reviewer/admin endpoints (``require_admin_or_root``):
    GET    /ui/kyc/documents/admin/by-status        -> list by status via ByStatus GSI
    GET    /ui/kyc/documents/admin/{document_id}     -> get one (with match details)
    POST   /ui/kyc/documents/admin/{document_id}/review -> approve/reject
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    KycDocumentListResponse,
    KycDocumentOut,
    KycDocumentReviewRequest,
    KycDocumentUploadRequest,
)
from app.services.kyc_document_verification import (
    LISTABLE_STATUSES,
    STORE,
    KycDocumentNotFoundError,
    KycDocumentStateError,
    KycDocumentValidationError,
    public_document_view,
)
from app.services.sessions import require_ui_session

kyc_documents_router = APIRouter(prefix="/ui/kyc/documents", tags=["kyc-documents"])


def _out(item: dict, *, include_match: bool) -> KycDocumentOut:
    return KycDocumentOut.model_validate(public_document_view(item, include_match=include_match))


def _require_owner(item: dict, user_sub: str) -> None:
    if str(item.get("user_sub") or "") != str(user_sub):
        raise HTTPException(status_code=403, detail={"code": "kyc_access_forbidden", "message": "You do not own this document."})


# --- owner endpoints -------------------------------------------------------


@kyc_documents_router.post("", response_model=KycDocumentOut, status_code=201)
@kyc_documents_router.post("/", response_model=KycDocumentOut, status_code=201, include_in_schema=False)
async def upload_document(
    body: KycDocumentUploadRequest,
    session: dict = Depends(require_ui_session),
) -> KycDocumentOut:
    try:
        item = STORE.upload_document(
            user_sub=session["user_sub"],
            document_type=body.document_type,
            file_name=body.file_name,
            case_id=body.case_id,
            content_b64=body.content_b64,
        )
    except KycDocumentValidationError as exc:
        raise HTTPException(status_code=422, detail={"code": str(exc), "message": "Invalid document upload."}) from exc
    # Run the extraction pipeline synchronously (mock provider in dev/E2E).
    try:
        item = STORE.run_extraction(item["document_id"])
    except Exception:
        # Extraction failures are recorded on the item; never block the upload.
        refreshed = STORE.get_document(item["document_id"])
        if refreshed:
            item = refreshed
    return _out(item, include_match=False)


@kyc_documents_router.get("", response_model=KycDocumentListResponse)
@kyc_documents_router.get("/", response_model=KycDocumentListResponse, include_in_schema=False)
async def list_my_documents(
    session: dict = Depends(require_ui_session),
) -> KycDocumentListResponse:
    items = STORE.list_documents_for_owner(session["user_sub"])
    return KycDocumentListResponse(documents=[_out(i, include_match=False) for i in items])


@kyc_documents_router.get("/admin/by-status", response_model=KycDocumentListResponse)
async def admin_list_by_status(
    status: str = Query(..., description="pending | extracted | failed | approved | rejected"),
    limit: int = Query(100, ge=1, le=500),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycDocumentListResponse:
    if status not in LISTABLE_STATUSES:
        raise HTTPException(status_code=422, detail={"code": "invalid_status", "message": "Unknown status."})
    items = STORE.list_by_status(status, limit=limit)
    return KycDocumentListResponse(documents=[_out(i, include_match=True) for i in items])


@kyc_documents_router.get("/admin/{document_id}", response_model=KycDocumentOut)
async def admin_get_document(
    document_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycDocumentOut:
    item = STORE.get_document(document_id)
    if not item:
        raise HTTPException(status_code=404, detail={"code": "kyc_document_not_found", "message": "Document not found."})
    return _out(item, include_match=True)


@kyc_documents_router.post("/admin/{document_id}/review", response_model=KycDocumentOut)
async def admin_review_document(
    document_id: str,
    body: KycDocumentReviewRequest,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycDocumentOut:
    try:
        item = STORE.review_document(
            document_id=document_id,
            decision=body.decision,
            reviewer_sub=user.sub,
            note=body.note,
        )
    except KycDocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail={"code": "kyc_document_not_found", "message": "Document not found."}) from exc
    except KycDocumentStateError as exc:
        raise HTTPException(status_code=409, detail={"code": str(exc), "message": "Document is not in a reviewable state."}) from exc
    except KycDocumentValidationError as exc:
        raise HTTPException(status_code=422, detail={"code": str(exc), "message": "Invalid review decision."}) from exc
    return _out(item, include_match=True)


@kyc_documents_router.get("/{document_id}", response_model=KycDocumentOut)
async def get_document(
    document_id: str,
    session: dict = Depends(require_ui_session),
) -> KycDocumentOut:
    item = STORE.get_document(document_id)
    if not item:
        raise HTTPException(status_code=404, detail={"code": "kyc_document_not_found", "message": "Document not found."})
    _require_owner(item, session["user_sub"])
    return _out(item, include_match=True)


@kyc_documents_router.post("/{document_id}/extract", response_model=KycDocumentOut)
async def extract_document(
    document_id: str,
    session: dict = Depends(require_ui_session),
) -> KycDocumentOut:
    item = STORE.get_document(document_id)
    if not item:
        raise HTTPException(status_code=404, detail={"code": "kyc_document_not_found", "message": "Document not found."})
    _require_owner(item, session["user_sub"])
    try:
        item = STORE.run_extraction(document_id)
    except KycDocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail={"code": "kyc_document_not_found", "message": "Document not found."}) from exc
    return _out(item, include_match=True)
