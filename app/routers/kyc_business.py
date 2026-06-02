"""KYC-015: KYC for Business / Corporate Accounts (KYB) router.

User endpoints (``require_ui_session``) manage the business-case lifecycle:
create / get / list / patch / submit plus UBO, director, document and address
sub-resources. Admin endpoints (``require_admin_or_root``) review, screen,
approve and reject business cases; approval grants Tier 4 (KYC-009).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.models import (
    KybAddressEnvelope,
    KybAddressRequest,
    KybAdminDecisionRequest,
    KybAdminQueueEnvelope,
    KybCaseEnvelope,
    KybCaseListEnvelope,
    KybCompanyPatchRequest,
    KybCreateRequest,
    KybDirectorAddRequest,
    KybDirectorEnvelope,
    KybDirectorListEnvelope,
    KybDocumentEnvelope,
    KybDocumentRequest,
    KybScreeningEnvelope,
    KybSubmitRequest,
    KybUboAddRequest,
    KybUboEnvelope,
    KybUboLinkRequest,
    KybUboListEnvelope,
)
from app.services.kyc_business import (
    STORE,
    KybConflictError,
    KybNotFoundError,
    KybValidationError,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/v1/kyc/business-cases", tags=["kyc-business"])


# --- error mapping ---------------------------------------------------------


def _raise(exc: Exception) -> None:
    if isinstance(exc, KybNotFoundError):
        raise HTTPException(status_code=404, detail={"code": str(exc) or "kyb_not_found"})
    if isinstance(exc, KybConflictError):
        raise HTTPException(status_code=409, detail={"code": str(exc) or "kyb_conflict"})
    if isinstance(exc, KybValidationError):
        code = str(exc) or "kyb_invalid_request"
        status = 403 if code == "kyb_access_forbidden" else 422
        raise HTTPException(status_code=status, detail={"code": code})
    raise exc


def _load_owned(case_id: str, user: AuthenticatedUser) -> dict:
    case = STORE.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail={"code": "kyb_case_not_found"})
    if str(case.get("user_sub") or "") != user.sub:
        raise HTTPException(status_code=403, detail={"code": "kyb_access_forbidden"})
    return case


# --- case lifecycle (user) -------------------------------------------------


@router.post("", response_model=KybCaseEnvelope)
def create_business_case(
    body: KybCreateRequest,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    try:
        created = STORE.create_case(
            user_sub=user.sub,
            company=body.model_dump(exclude={"org_id"}),
            org_id=body.org_id,
        )
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybCaseEnvelope(case=created)


@router.get("", response_model=KybCaseListEnvelope)
def list_my_business_cases(
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    return KybCaseListEnvelope(cases=STORE.list_cases_by_owner(user_sub=user.sub, limit=100))


@router.get("/{case_id}", response_model=KybCaseEnvelope)
def get_business_case(
    case_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    case = _load_owned(case_id, user)
    return KybCaseEnvelope(case=case)


@router.patch("/{case_id}", response_model=KybCaseEnvelope)
def patch_business_case(
    case_id: str,
    body: KybCompanyPatchRequest,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    patch = body.model_dump(exclude={"expected_version"}, exclude_none=True)
    try:
        updated = STORE.update_company(
            case_id=case_id,
            owner_sub=user.sub,
            expected_version=body.expected_version,
            company_patch=patch,
        )
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybCaseEnvelope(case=updated)


@router.post("/{case_id}/submit", response_model=KybCaseEnvelope)
def submit_business_case(
    case_id: str,
    body: KybSubmitRequest,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    try:
        updated = STORE.submit_case(
            case_id=case_id,
            owner_sub=user.sub,
            expected_version=body.expected_version,
        )
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybCaseEnvelope(case=updated)


# --- UBOs (user) -----------------------------------------------------------


@router.post("/{case_id}/ubos", response_model=KybUboEnvelope)
def add_ubo(
    case_id: str,
    body: KybUboAddRequest,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    try:
        ubo = STORE.add_ubo(case_id=case_id, owner_sub=user.sub, ubo_data=body.model_dump())
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybUboEnvelope(ubo=ubo)


@router.get("/{case_id}/ubos", response_model=KybUboListEnvelope)
def list_ubos(
    case_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    return KybUboListEnvelope(ubos=STORE.list_ubos(case_id))


@router.post("/{case_id}/ubos/{ubo_id}/link", response_model=KybUboEnvelope)
def link_ubo_personal_kyc(
    case_id: str,
    ubo_id: str,
    body: KybUboLinkRequest,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    try:
        ubo = STORE.link_ubo_personal_kyc(
            case_id=case_id,
            owner_sub=user.sub,
            ubo_id=ubo_id,
            personal_kyc_case_id=body.personal_kyc_case_id,
        )
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybUboEnvelope(ubo=ubo)


@router.delete("/{case_id}/ubos/{ubo_id}")
def remove_ubo(
    case_id: str,
    ubo_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    try:
        STORE.remove_ubo(case_id=case_id, owner_sub=user.sub, ubo_id=ubo_id)
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return {"ok": True, "ubo_id": ubo_id}


# --- directors (user) ------------------------------------------------------


@router.post("/{case_id}/directors", response_model=KybDirectorEnvelope)
def add_director(
    case_id: str,
    body: KybDirectorAddRequest,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    try:
        director = STORE.add_director(case_id=case_id, owner_sub=user.sub, director_data=body.model_dump())
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybDirectorEnvelope(director=director)


@router.get("/{case_id}/directors", response_model=KybDirectorListEnvelope)
def list_directors(
    case_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    return KybDirectorListEnvelope(directors=STORE.list_directors(case_id))


@router.delete("/{case_id}/directors/{director_id}")
def remove_director(
    case_id: str,
    director_id: str,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    try:
        STORE.remove_director(case_id=case_id, owner_sub=user.sub, director_id=director_id)
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return {"ok": True, "director_id": director_id}


# --- documents + addresses (user) -----------------------------------------


@router.post("/{case_id}/documents", response_model=KybDocumentEnvelope)
def add_document(
    case_id: str,
    body: KybDocumentRequest,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    try:
        doc = STORE.add_document(case_id=case_id, owner_sub=user.sub, doc_data=body.model_dump())
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybDocumentEnvelope(document=doc)


@router.post("/{case_id}/addresses", response_model=KybAddressEnvelope)
def set_address(
    case_id: str,
    body: KybAddressRequest,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _load_owned(case_id, user)
    try:
        addr = STORE.set_address(
            case_id=case_id,
            owner_sub=user.sub,
            address_type=body.address_type,
            address=body.model_dump(exclude={"address_type"}),
        )
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybAddressEnvelope(address=addr)


# --- admin -----------------------------------------------------------------


@router.get("/admin/queue", response_model=KybAdminQueueEnvelope)
def admin_queue(
    status: str | None = Query(default=None),
    _admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    statuses = [status] if status else None
    return KybAdminQueueEnvelope(cases=STORE.list_admin_queue(statuses=statuses, limit=100))


@router.get("/admin/{case_id}", response_model=KybCaseEnvelope)
def admin_get_case(
    case_id: str,
    _admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    case = STORE.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail={"code": "kyb_case_not_found"})
    return KybCaseEnvelope(case=case)


@router.post("/admin/{case_id}/screen", response_model=KybScreeningEnvelope)
def admin_screen_case(
    case_id: str,
    _admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        result = STORE.screen_business(case_id=case_id)
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybScreeningEnvelope(**result)


@router.post("/admin/{case_id}/approve", response_model=KybCaseEnvelope)
def admin_approve_case(
    case_id: str,
    body: KybAdminDecisionRequest,
    request: Request,
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        updated = STORE.apply_admin_decision(
            case_id=case_id,
            expected_version=body.expected_version,
            admin_sub=admin.sub,
            decision="approve",
            reason_codes=body.reason_codes,
            note=body.note,
            request=request,
        )
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybCaseEnvelope(case=updated)


@router.post("/admin/{case_id}/reject", response_model=KybCaseEnvelope)
def admin_reject_case(
    case_id: str,
    body: KybAdminDecisionRequest,
    request: Request,
    admin: AuthenticatedUser = Depends(require_admin_or_root),
):
    try:
        updated = STORE.apply_admin_decision(
            case_id=case_id,
            expected_version=body.expected_version,
            admin_sub=admin.sub,
            decision="reject",
            reason_codes=body.reason_codes,
            note=body.note,
            request=request,
        )
    except (KybValidationError, KybConflictError, KybNotFoundError) as exc:
        _raise(exc)
    return KybCaseEnvelope(case=updated)
