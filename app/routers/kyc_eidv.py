"""KYC-022: Electronic Identity Verification (eIDV) endpoints.

User-facing eID flow (provider selection -> initiate -> mock callback -> result)
plus a dev-mode mock provider endpoint. Mounted with NO router prefix so it can
expose both the ``/v1/kyc/...`` user routes and the ``/mock/eid/verify`` mock
provider route from a single router (registered exactly once in app/main.py).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.models import (
    EidSchemeOut,
    EidSchemesListOut,
    EidStatusOut,
    MockEidRequest,
    MockEidResponse,
    StartEidVerificationIn,
    StartEidVerificationOut,
)
from app.services.kyc_eidv import (
    KycEidvError,
    build_mock_assertion,
    create_verification_session,
    get_eid_status,
    get_supported_schemes,
    process_callback,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

kyc_eidv_router = APIRouter(tags=["kyc-eidv"])

# Map service error codes -> HTTP status (mirrors spec §4 error matrix).
_EIDV_ERROR_STATUS: dict[str, int] = {
    "eid_unsupported_scheme": 400,
    "case_not_found": 404,
    "eid_not_owner": 403,
    "eid_already_verified": 409,
    "eid_session_expired": 400,
    "eid_invalid_signature": 400,
    "eid_assertion_expired": 400,
    "eid_case_not_draft": 400,
    "eid_session_not_found": 404,
}


def _raise(exc: KycEidvError) -> None:
    code = str(exc)
    raise HTTPException(status_code=_EIDV_ERROR_STATUS.get(code, 400), detail=code)


def _ensure_enabled() -> None:
    if not S.kyc_eid_enabled:
        raise HTTPException(status_code=503, detail="kyc_eid_disabled")


@kyc_eidv_router.get("/v1/kyc/eid/schemes", response_model=EidSchemesListOut)
def list_eid_schemes(
    country: str | None = Query(default=None),
    _ctx: dict[str, str] = Depends(require_ui_session),
):
    _ensure_enabled()
    schemes = [EidSchemeOut.model_validate(s) for s in get_supported_schemes(country=country)]
    return EidSchemesListOut(schemes=schemes)


@kyc_eidv_router.post(
    "/v1/kyc/cases/{case_id}/eid/start", response_model=StartEidVerificationOut
)
def start_eid_verification(
    case_id: str,
    body: StartEidVerificationIn,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_enabled()
    callback_base = str(request.base_url).rstrip("/")
    try:
        result = create_verification_session(
            case_id=case_id,
            scheme=body.scheme,
            user_sub=user.sub,
            callback_base=callback_base,
        )
    except KycEidvError as exc:
        _raise(exc)
    return StartEidVerificationOut.model_validate(result)


@kyc_eidv_router.get("/v1/kyc/eid/callback")
def eid_callback(
    request: Request,
    session_id: str = Query(...),
    assertion: str = Query(...),
    signature: str = Query(...),
):
    """eID provider callback (no auth -- comes from the external provider).

    Validates the assertion, updates the case, and redirects back to the case
    detail page with ``?eid=success|failed``.
    """
    _ensure_enabled()
    try:
        session = None
        from app.services.kyc_eidv import get_verification_session

        session = get_verification_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="eid_session_not_found")
        case_id = str(session.get("case_id") or "")
        process_callback(
            session_id=session_id,
            raw_assertion=assertion,
            signature=signature,
            request=request,
        )
    except KycEidvError as exc:
        code = str(exc)
        if code == "eid_session_not_found":
            raise HTTPException(status_code=404, detail=code)
        target = f"/kyc/cases/{session.get('case_id') if session else ''}?eid=failed&reason={code}"
        return RedirectResponse(url=target, status_code=303)
    return RedirectResponse(url=f"/kyc/cases/{case_id}?eid=success", status_code=303)


@kyc_eidv_router.get(
    "/v1/kyc/cases/{case_id}/eid/status", response_model=EidStatusOut
)
def eid_status(
    case_id: str,
    request: Request,
    _ctx: dict[str, str] = Depends(require_ui_session),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    _ensure_enabled()
    # Owner or admin/root may read the status.
    from app.services.kyc_cases import STORE as KYC_STORE

    case = KYC_STORE.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")
    is_admin = normalize_role(user.role) in {Role.ADMIN, Role.ROOT}
    if str(case.get("user_sub") or "") != user.sub and not is_admin:
        raise HTTPException(status_code=403, detail="eid_not_owner")
    try:
        status = get_eid_status(case_id)
    except KycEidvError as exc:
        _raise(exc)
    return EidStatusOut(eid_verification=status)


@kyc_eidv_router.post("/mock/eid/verify", response_model=MockEidResponse)
def mock_eid_verify(body: MockEidRequest):
    """Mock eID provider (dev mode only). Returns a signed assertion."""
    _ensure_enabled()
    if not S.kyc_eid_mock_enabled or not S.dev_mode:
        raise HTTPException(status_code=404, detail="eid_mock_disabled")
    try:
        result = build_mock_assertion(body.session_id)
    except KycEidvError as exc:
        _raise(exc)
    return MockEidResponse.model_validate(result)
