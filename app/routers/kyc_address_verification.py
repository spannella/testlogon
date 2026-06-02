"""KYC-018: Address Verification Service router.

Prefix: ``/v1/kyc/address-verification``

Independently verifies a KYC case address against a country's postal format,
checks existence against a mock postal database, compares the profile address
with the proof-of-residency document address, and produces a verification
result + confidence + decision bucket. Builds alongside KYC-004
(proof-of-residency) WITHOUT modifying it.

User endpoints (case owner or admin, cookie + CSRF via ``require_ui_session``):
    POST /v1/kyc/address-verification/cases/{case_id}/verify  -> run verification
    GET  /v1/kyc/address-verification/cases/{case_id}         -> latest result
    GET  /v1/kyc/address-verification/cases/{case_id}/attempts -> attempt history
    POST /v1/kyc/address-verification/validate-postal-code     -> postal validation

Admin endpoints (``require_admin_or_root``):
    POST /v1/kyc/address-verification/cases/{case_id}/cross-reference -> compare
    POST /v1/kyc/address-verification/cases/{case_id}/override        -> override
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.auth.roles import Role, normalize_role
from app.models import (
    AddressOverrideRequest,
    AddressVerificationListResponse,
    AddressVerificationOut,
    AddressVerificationResponse,
    CrossReferenceOut,
    CrossReferenceRequest,
    CrossReferenceResponse,
    PostalCodeValidationOut,
    PostalCodeValidationRequest,
    VerifyAddressRequest,
)
from app.services.kyc_address_verification import (
    STORE,
    KycAddressFeatureDisabledError,
    KycAddressNotFoundError,
    KycAddressValidationError,
    public_verification_view,
)
from app.services.sessions import require_ui_session

kyc_address_verification_router = APIRouter(
    prefix="/v1/kyc/address-verification", tags=["kyc-address-verification"]
)


def _out(record: dict | None) -> AddressVerificationOut:
    return AddressVerificationOut.model_validate(public_verification_view(record))


def _is_admin(session: dict) -> bool:
    role = normalize_role(session.get("role"))
    return role in (Role.ADMIN, Role.ROOT)


def _require_owner_or_admin(case: dict, session: dict) -> None:
    if _is_admin(session):
        return
    if str(case.get("user_sub") or "") != str(session.get("user_sub") or ""):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "forbidden",
                "message": "You do not have access to this case.",
            },
        )


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": "case_not_found", "message": "KYC case not found."},
    )


def _disabled() -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "code": "feature_disabled",
            "message": "Address verification is currently disabled.",
        },
    )


# --- owner / user endpoints ------------------------------------------------


@kyc_address_verification_router.post(
    "/cases/{case_id}/verify", response_model=AddressVerificationResponse
)
async def verify_case_address(
    case_id: str,
    body: VerifyAddressRequest,
    session: dict = Depends(require_ui_session),
) -> AddressVerificationResponse:
    try:
        case = STORE.require_case(case_id)
    except KycAddressNotFoundError as exc:
        raise _not_found() from exc
    _require_owner_or_admin(case, session)
    try:
        record = STORE.verify_address(
            case_id=case_id,
            address=body.address.model_dump(),
            triggered_by=str(session.get("user_sub") or ""),
        )
    except KycAddressFeatureDisabledError as exc:
        raise _disabled() from exc
    except KycAddressValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": str(exc), "message": "Invalid address input."},
        ) from exc
    return AddressVerificationResponse(verification=_out(record))


@kyc_address_verification_router.get(
    "/cases/{case_id}", response_model=AddressVerificationResponse
)
async def get_case_address_verification(
    case_id: str,
    session: dict = Depends(require_ui_session),
) -> AddressVerificationResponse:
    try:
        case = STORE.require_case(case_id)
    except KycAddressNotFoundError as exc:
        raise _not_found() from exc
    _require_owner_or_admin(case, session)
    latest = STORE.get_latest(case_id)
    return AddressVerificationResponse(verification=_out(latest))


@kyc_address_verification_router.get(
    "/cases/{case_id}/attempts", response_model=AddressVerificationListResponse
)
async def list_case_address_attempts(
    case_id: str,
    session: dict = Depends(require_ui_session),
) -> AddressVerificationListResponse:
    try:
        case = STORE.require_case(case_id)
    except KycAddressNotFoundError as exc:
        raise _not_found() from exc
    _require_owner_or_admin(case, session)
    attempts = STORE.list_attempts(case_id)
    return AddressVerificationListResponse(attempts=[_out(a) for a in attempts])


@kyc_address_verification_router.post(
    "/validate-postal-code", response_model=PostalCodeValidationOut
)
async def validate_postal_code_endpoint(
    body: PostalCodeValidationRequest,
    session: dict = Depends(require_ui_session),
) -> PostalCodeValidationOut:
    result = STORE.validate_postal_code(
        postal_code=body.postal_code, country=body.country
    )
    return PostalCodeValidationOut.model_validate(result)


# --- admin endpoints -------------------------------------------------------


@kyc_address_verification_router.post(
    "/cases/{case_id}/cross-reference", response_model=CrossReferenceResponse
)
async def cross_reference_case_address(
    case_id: str,
    body: CrossReferenceRequest,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CrossReferenceResponse:
    try:
        record = STORE.cross_reference_document(
            case_id=case_id,
            document_address=body.document_address.model_dump(),
            actor_sub=user.sub,
        )
    except KycAddressFeatureDisabledError as exc:
        raise _disabled() from exc
    except KycAddressNotFoundError as exc:
        raise _not_found() from exc
    except KycAddressValidationError as exc:
        code = str(exc)
        status = 400 if code == "no_verification_to_cross_reference" else 422
        raise HTTPException(
            status_code=status,
            detail={"code": code, "message": "Cross-reference failed."},
        ) from exc
    cr = (record.get("cross_reference") or {}) if record else {}
    return CrossReferenceResponse(
        cross_reference=CrossReferenceOut.model_validate(
            {
                "match_score": cr.get("match_score", 0.0),
                "discrepancies": cr.get("discrepancies", []),
                "field_comparisons": cr.get("field_comparisons", []),
            }
        )
    )


@kyc_address_verification_router.post(
    "/cases/{case_id}/override", response_model=AddressVerificationResponse
)
async def override_case_address_decision(
    case_id: str,
    body: AddressOverrideRequest,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> AddressVerificationResponse:
    try:
        record = STORE.override_decision(
            case_id=case_id,
            decision=body.decision,
            reviewer_sub=user.sub,
            note=body.note,
        )
    except KycAddressFeatureDisabledError as exc:
        raise _disabled() from exc
    except KycAddressNotFoundError as exc:
        raise _not_found() from exc
    except KycAddressValidationError as exc:
        code = str(exc)
        status = 400 if code == "no_verification_to_override" else 422
        raise HTTPException(
            status_code=status,
            detail={"code": code, "message": "Override failed."},
        ) from exc
    return AddressVerificationResponse(verification=_out(record))
