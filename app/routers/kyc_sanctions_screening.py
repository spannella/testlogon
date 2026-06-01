"""KYC-006: Sanctions / PEP Screening router.

Prefix: ``/ui/kyc/screening``

Owner endpoints (cookie + CSRF auth via ``require_ui_session``):
    GET    /ui/kyc/screening/cases/{case_id}            -> own case screening (summary; match details redacted)

Reviewer / admin endpoints (``require_admin_or_root``):
    POST   /ui/kyc/screening/run                          -> run screening for a user / case
    GET    /ui/kyc/screening/admin/cases/{case_id}        -> full case screening results
    POST   /ui/kyc/screening/admin/cases/{case_id}/rescreen -> re-screen a case
    GET    /ui/kyc/screening/admin/pending                -> list results needing review
    POST   /ui/kyc/screening/admin/cases/{case_id}/{screen_key}/review -> adjudicate a match
    GET    /ui/kyc/screening/admin/users/{user_sub}/history -> user screening history
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.models import (
    KycScreeningPendingReviewsResponse,
    KycScreeningRescreenResponse,
    KycScreeningResultOut,
    KycScreeningResultsListResponse,
    KycScreeningReviewRequest,
    KycScreeningRunRequest,
    KycScreeningUserHistoryResponse,
)
from app.services.kyc_sanctions_screening import (
    LISTABLE_RESULTS,
    RESULT_CLEAR,
    STORE,
    TRIGGER_MANUAL,
    KycScreeningAlreadyReviewedError,
    KycScreeningNotFoundError,
    KycScreeningValidationError,
    public_screening_view,
)
from app.services.sessions import require_ui_session

kyc_sanctions_screening_router = APIRouter(
    prefix="/ui/kyc/screening", tags=["kyc-sanctions-screening"]
)


def _out(item: dict, *, include_match: bool) -> KycScreeningResultOut:
    return KycScreeningResultOut.model_validate(
        public_screening_view(item, include_match=include_match)
    )


def _require_case_owner(case_id: str, user_sub: str) -> list[dict]:
    """Return the case's screening results, enforcing the caller owns the case."""
    items = STORE.get_results_for_case(case_id=case_id)
    if not items:
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_case_not_found", "message": "Case not found."},
        )
    if any(str(i.get("user_sub") or "") != str(user_sub) for i in items):
        raise HTTPException(
            status_code=403,
            detail={"code": "kyc_access_forbidden", "message": "Access denied."},
        )
    return items


# --- owner endpoint --------------------------------------------------------


@kyc_sanctions_screening_router.get(
    "/cases/{case_id}", response_model=KycScreeningResultsListResponse
)
async def get_my_case_screening(
    case_id: str,
    session: dict = Depends(require_ui_session),
) -> KycScreeningResultsListResponse:
    items = _require_case_owner(case_id, session["user_sub"])
    # owner sees status only; match details are redacted
    return KycScreeningResultsListResponse(
        results=[_out(i, include_match=False) for i in items]
    )


# --- reviewer / admin endpoints --------------------------------------------


@kyc_sanctions_screening_router.post(
    "/run", response_model=KycScreeningRescreenResponse
)
async def run_screening(
    body: KycScreeningRunRequest,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycScreeningRescreenResponse:
    case_id = (body.case_id or "").strip() or f"kyc_{uuid.uuid4().hex[:12]}"
    results = STORE.screen_case(
        case_id=case_id,
        user_sub=body.user_sub,
        trigger="manual",
        name=body.name,
        dob=body.dob,
        country=body.country,
    )
    matches = sum(1 for r in results if r["result"] != RESULT_CLEAR)
    return KycScreeningRescreenResponse(
        case_id=case_id,
        user_sub=body.user_sub,
        results_count=len(results),
        trigger="manual",
        matches_found=matches,
        results=[_out(r, include_match=True) for r in results],
    )


@kyc_sanctions_screening_router.get(
    "/admin/cases/{case_id}", response_model=KycScreeningResultsListResponse
)
async def admin_get_case_screening(
    case_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycScreeningResultsListResponse:
    items = STORE.get_results_for_case(case_id=case_id)
    if not items:
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_case_not_found", "message": "Case not found."},
        )
    return KycScreeningResultsListResponse(
        results=[_out(i, include_match=True) for i in items]
    )


@kyc_sanctions_screening_router.post(
    "/admin/cases/{case_id}/rescreen", response_model=KycScreeningRescreenResponse
)
async def admin_rescreen_case(
    case_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycScreeningRescreenResponse:
    existing = STORE.get_results_for_case(case_id=case_id)
    if not existing:
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_case_not_found", "message": "Case not found."},
        )
    user_sub = str(existing[0].get("user_sub") or "")
    results = STORE.rescreen_user(
        case_id=case_id, user_sub=user_sub, trigger=TRIGGER_MANUAL
    )
    matches = sum(1 for r in results if r["result"] != RESULT_CLEAR)
    return KycScreeningRescreenResponse(
        case_id=case_id,
        user_sub=user_sub,
        results_count=len(results),
        trigger="manual",
        matches_found=matches,
        results=[_out(r, include_match=True) for r in results],
    )


@kyc_sanctions_screening_router.get(
    "/admin/pending", response_model=KycScreeningPendingReviewsResponse
)
async def admin_list_pending_reviews(
    result: str = Query(
        "potential_match", description="potential_match | confirmed_match"
    ),
    limit: int = Query(50, ge=1, le=500),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycScreeningPendingReviewsResponse:
    if result not in LISTABLE_RESULTS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "kyc_invalid_screening_result",
                "message": "Unknown screening result.",
            },
        )
    items = STORE.get_pending_reviews(result=result, limit=limit)
    return KycScreeningPendingReviewsResponse(
        items=[_out(i, include_match=True) for i in items], cursor=None
    )


@kyc_sanctions_screening_router.post(
    "/admin/cases/{case_id}/{screen_key:path}/review",
    response_model=KycScreeningResultOut,
)
async def admin_review_match(
    body: KycScreeningReviewRequest,
    case_id: str = Path(...),
    screen_key: str = Path(..., description="{screen_type}#{iso_ts}"),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycScreeningResultOut:
    try:
        item = STORE.review_match(
            case_id=case_id,
            screen_key=screen_key,
            reviewer_sub=user.sub,
            decision=body.decision,
            note=body.note,
        )
    except KycScreeningNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "kyc_screening_not_found",
                "message": "Screening result not found.",
            },
        ) from exc
    except KycScreeningAlreadyReviewedError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "kyc_screening_already_reviewed",
                "message": "This match has already been reviewed.",
            },
        ) from exc
    except KycScreeningValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": str(exc), "message": "Invalid review."},
        ) from exc
    return _out(item, include_match=True)


@kyc_sanctions_screening_router.get(
    "/admin/users/{user_sub:path}/history",
    response_model=KycScreeningUserHistoryResponse,
)
async def admin_get_user_history(
    user_sub: str = Path(...),
    limit: int = Query(50, ge=1, le=500),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> KycScreeningUserHistoryResponse:
    items = STORE.get_results_for_user(user_sub=user_sub, limit=limit)
    return KycScreeningUserHistoryResponse(
        user_sub=user_sub,
        results=[_out(i, include_match=True) for i in items],
        total=len(items),
    )
