"""KYC-003: Liveness Video Verification Call router.

Prefix: ``/ui/kyc/liveness-call``

Owner endpoints (case owner, cookie + CSRF auth via ``require_ui_session``):
    POST   /ui/kyc/liveness-call                       -> schedule a call for a case
    GET    /ui/kyc/liveness-call                        -> list own calls
    GET    /ui/kyc/liveness-call/case/{case_id}         -> owner status for a case
    GET    /ui/kyc/liveness-call/{call_id}              -> get one (owner)
    POST   /ui/kyc/liveness-call/{call_id}/cancel        -> cancel own call

Verifier/reviewer endpoints (``require_admin_or_root`` -- KYC_VERIFIER scope
does NOT exist; admins/root act as verifiers):
    GET    /ui/kyc/liveness-call/admin/by-status         -> list by status (ByStatus GSI)
    GET    /ui/kyc/liveness-call/admin/case/{case_id}     -> most relevant call for a case
    GET    /ui/kyc/liveness-call/admin/{call_id}          -> get one (verifier)
    POST   /ui/kyc/liveness-call/admin/{call_id}/conduct  -> mark in_progress
    POST   /ui/kyc/liveness-call/admin/{call_id}/result   -> record pass/fail outcome
    POST   /ui/kyc/liveness-call/admin/{call_id}/cancel   -> cancel a call
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    KycLivenessCallListResponse,
    KycLivenessCallOut,
    KycLivenessCallResultRequest,
    KycLivenessCallScheduleRequest,
    KycLivenessCallStatusResponse,
)
from app.services.kyc_liveness_call import (
    LISTABLE_STATUSES,
    STORE,
    KycLivenessCallConflictError,
    KycLivenessCallNotFoundError,
    KycLivenessCallStateError,
    KycLivenessCallValidationError,
    owner_call_view,
    public_call_view,
)
from app.services.sessions import require_ui_session

kyc_liveness_call_router = APIRouter(
    prefix="/ui/kyc/liveness-call", tags=["kyc-liveness-call"]
)


def _out(item: dict) -> KycLivenessCallOut:
    return KycLivenessCallOut.model_validate(public_call_view(item, include_verifier=True))


def _require_owner(item: dict, user_sub: str) -> None:
    if str(item.get("user_sub") or "") != str(user_sub):
        raise HTTPException(
            status_code=403,
            detail={"code": "kyc_access_forbidden", "message": "You do not own this case."},
        )


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": "kyc_call_not_found", "message": "Verification call not found."},
    )


# --- owner endpoints -------------------------------------------------------


@kyc_liveness_call_router.post("", response_model=KycLivenessCallOut, status_code=201)
@kyc_liveness_call_router.post(
    "/", response_model=KycLivenessCallOut, status_code=201, include_in_schema=False
)
async def schedule_liveness_call(
    body: KycLivenessCallScheduleRequest,
    session: dict = Depends(require_ui_session),
) -> KycLivenessCallOut:
    try:
        item = STORE.schedule_call(
            case_id=body.case_id,
            user_sub=session["user_sub"],
            scheduled_at=body.scheduled_at,
            duration_minutes=body.duration_minutes,
            verifier_sub=body.verifier_sub,
            note=body.note,
        )
    except KycLivenessCallConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": str(exc),
                "message": "A verification call is already scheduled for this case.",
            },
        ) from exc
    except KycLivenessCallValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "code": str(exc),
                "message": "Scheduled time must be in the future.",
            },
        ) from exc
    return _out(item)


@kyc_liveness_call_router.get("", response_model=KycLivenessCallListResponse)
@kyc_liveness_call_router.get(
    "/", response_model=KycLivenessCallListResponse, include_in_schema=False
)
async def list_my_liveness_calls(
    session: dict = Depends(require_ui_session),
) -> KycLivenessCallListResponse:
    items = STORE.list_calls_for_owner(session["user_sub"])
    return KycLivenessCallListResponse(calls=[_out(i) for i in items])


@kyc_liveness_call_router.get(
    "/case/{case_id}", response_model=KycLivenessCallStatusResponse
)
async def get_liveness_call_status_for_case(
    case_id: str,
    session: dict = Depends(require_ui_session),
) -> KycLivenessCallStatusResponse:
    item = STORE.get_latest_call_for_case(case_id)
    if not item:
        return KycLivenessCallStatusResponse(verification_call=None)
    _require_owner(item, session["user_sub"])
    return KycLivenessCallStatusResponse.model_validate(
        {"verification_call": owner_call_view(item)}
    )


# --- verifier / admin endpoints --------------------------------------------


@kyc_liveness_call_router.get(
    "/admin/by-status", response_model=KycLivenessCallListResponse
)
async def admin_list_by_status(
    status: str = Query(
        ..., description="scheduled | in_progress | passed | failed | cancelled | expired"
    ),
    limit: int = Query(100, ge=1, le=500),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycLivenessCallListResponse:
    if status not in LISTABLE_STATUSES:
        raise HTTPException(
            status_code=422, detail={"code": "invalid_status", "message": "Unknown status."}
        )
    items = STORE.list_by_status(status, limit=limit)
    return KycLivenessCallListResponse(calls=[_out(i) for i in items])


@kyc_liveness_call_router.get(
    "/admin/case/{case_id}", response_model=KycLivenessCallOut
)
async def admin_get_liveness_call_for_case(
    case_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycLivenessCallOut:
    """GAP-0251: return the most relevant liveness call for a KYC case (admin/root).

    Direct case-level lookup so reviewers don't have to fan out the ByStatus GSI
    across every status bucket and filter by ``case_id`` themselves. Declared
    before ``/admin/{call_id}`` so ``case`` is never matched as a ``call_id``.
    """
    item = STORE.get_call_for_case(case_id)
    if not item:
        raise _not_found()
    return _out(item)


@kyc_liveness_call_router.get("/admin/{call_id}", response_model=KycLivenessCallOut)
async def admin_get_liveness_call(
    call_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycLivenessCallOut:
    item = STORE.get_call(call_id)
    if not item:
        raise _not_found()
    return _out(item)


@kyc_liveness_call_router.post(
    "/admin/{call_id}/conduct", response_model=KycLivenessCallOut
)
async def admin_conduct_liveness_call(
    call_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycLivenessCallOut:
    try:
        item = STORE.conduct_call(call_id=call_id, verifier_sub=user.sub)
    except KycLivenessCallNotFoundError as exc:
        raise _not_found() from exc
    except KycLivenessCallStateError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": str(exc), "message": "Call is not in a conductable state."},
        ) from exc
    return _out(item)


@kyc_liveness_call_router.post(
    "/admin/{call_id}/result", response_model=KycLivenessCallOut
)
async def admin_record_liveness_call_result(
    call_id: str,
    body: KycLivenessCallResultRequest,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycLivenessCallOut:
    try:
        item = STORE.record_outcome(
            call_id=call_id,
            verifier_sub=user.sub,
            result=body.result,
            notes=body.notes,
            recording_linked=body.recording_linked,
        )
    except KycLivenessCallNotFoundError as exc:
        raise _not_found() from exc
    except KycLivenessCallStateError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": str(exc), "message": "Call is not in a recordable state."},
        ) from exc
    except KycLivenessCallValidationError as exc:
        raise HTTPException(
            status_code=422, detail={"code": str(exc), "message": "Invalid call result."}
        ) from exc
    return _out(item)


@kyc_liveness_call_router.post(
    "/admin/{call_id}/cancel", response_model=KycLivenessCallOut
)
async def admin_cancel_liveness_call(
    call_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycLivenessCallOut:
    try:
        item = STORE.cancel_call(call_id=call_id, actor_sub=user.sub)
    except KycLivenessCallNotFoundError as exc:
        raise _not_found() from exc
    except KycLivenessCallStateError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": str(exc), "message": "Call is not in a cancellable state."},
        ) from exc
    return _out(item)


# --- owner endpoints (parameterized; declared last to avoid shadowing) ------


@kyc_liveness_call_router.get("/{call_id}", response_model=KycLivenessCallOut)
async def get_liveness_call(
    call_id: str,
    session: dict = Depends(require_ui_session),
) -> KycLivenessCallOut:
    item = STORE.get_call(call_id)
    if not item:
        raise _not_found()
    _require_owner(item, session["user_sub"])
    return _out(item)


@kyc_liveness_call_router.post("/{call_id}/cancel", response_model=KycLivenessCallOut)
async def cancel_my_liveness_call(
    call_id: str,
    session: dict = Depends(require_ui_session),
) -> KycLivenessCallOut:
    item = STORE.get_call(call_id)
    if not item:
        raise _not_found()
    _require_owner(item, session["user_sub"])
    try:
        item = STORE.cancel_call(call_id=call_id, actor_sub=session["user_sub"])
    except KycLivenessCallNotFoundError as exc:
        raise _not_found() from exc
    except KycLivenessCallStateError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": str(exc), "message": "Call is not in a cancellable state."},
        ) from exc
    return _out(item)
