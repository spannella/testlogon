"""Fraud Detection admin API (FIN-015).

Admin/root review queue, case lifecycle, user freeze, risk-score lookup,
chargeback recording, config, and stats. Prefix ``/v1/admin/fraud``.

DISTINCT module name ``fraud_detection`` (consolidates the ticket's
``admin_fraud`` router). Unrelated to ADS-014 ad-fraud prevention.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_root
from app.models import (
    FraudCaseCreate,
    FraudCaseOut,
    FraudCaseResolve,
    FraudChargebackRecord,
    FraudConfigOut,
    FraudConfigUpdate,
    FraudFlagOut,
    FraudFlagQueueOut,
    FraudFlagReview,
    FraudStatsOut,
    FreezeUserRequest,
    UserRiskProfile,
)
from app.services import fraud_detection as fd

router = APIRouter(prefix="/v1/admin/fraud", tags=["fraud-detection"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Review queue
# ---------------------------------------------------------------------------

@router.get("/queue", response_model=FraudFlagQueueOut)
async def get_fraud_queue(
    status: str = Query("pending"),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FraudFlagQueueOut:
    result = fd.list_review_queue(status=status, limit=limit, cursor=cursor)
    return FraudFlagQueueOut(**result)


@router.post("/flags/{flag_id}/review", response_model=FraudFlagOut)
async def review_flag(
    flag_id: str,
    body: FraudFlagReview,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FraudFlagOut:
    result = fd.review_decision(
        flag_id=flag_id, action=body.action, admin_sub=user.sub, notes=body.notes,
    )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Flag {flag_id} not found")
    flag = fd.get_flag(flag_id)
    if flag is None:
        raise HTTPException(status_code=404, detail=f"Flag {flag_id} not found")
    return FraudFlagOut(**flag)


# ---------------------------------------------------------------------------
# User risk + freeze
# ---------------------------------------------------------------------------

@router.get("/users/{user_id}/risk", response_model=UserRiskProfile)
async def get_user_risk(
    user_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> UserRiskProfile:
    profile = fd.get_user_risk_profile(user_id)
    return UserRiskProfile(**profile)


@router.post("/users/{user_id}/freeze")
async def freeze_user(
    user_id: str,
    body: FreezeUserRequest,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return fd.freeze_user(user_id=user_id, admin_sub=user.sub, reason=body.reason)


@router.post("/users/{user_id}/unfreeze")
async def unfreeze_user(
    user_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return fd.unfreeze_user(user_id=user_id, admin_sub=user.sub)


# ---------------------------------------------------------------------------
# Chargebacks
# ---------------------------------------------------------------------------

@router.post("/chargebacks")
async def record_chargeback(
    body: FraudChargebackRecord,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    return fd.record_chargeback(
        user_id=body.user_id, amount_cents=body.amount_cents, tx_id=body.tx_id,
    )


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@router.post("/cases", response_model=FraudCaseOut, status_code=201)
async def create_case(
    body: FraudCaseCreate,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FraudCaseOut:
    case = fd.flag_case(
        user_id=body.user_id, flag_ids=body.flag_ids, admin_sub=user.sub, notes=body.notes,
    )
    return FraudCaseOut(**case)


@router.get("/cases", response_model=list[FraudCaseOut])
async def list_cases(
    status: str = Query("open"),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> list[FraudCaseOut]:
    return [FraudCaseOut(**c) for c in fd.list_cases(status=status)]


@router.get("/cases/{case_id}", response_model=FraudCaseOut)
async def get_case(
    case_id: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FraudCaseOut:
    case = fd.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return FraudCaseOut(**case)


@router.post("/cases/{case_id}/resolve")
async def resolve_case(
    case_id: str,
    body: FraudCaseResolve,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    result = fd.resolve_case(
        case_id=case_id, resolution=body.resolution, admin_sub=user.sub, notes=body.notes,
    )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    if result.get("conflict"):
        raise HTTPException(status_code=409, detail="Case already resolved")
    return result


# ---------------------------------------------------------------------------
# Config + stats
# ---------------------------------------------------------------------------

@router.get("/config", response_model=FraudConfigOut)
async def get_config(
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FraudConfigOut:
    return FraudConfigOut(**fd.get_fraud_config())


@router.patch("/config", response_model=FraudConfigOut)
async def update_config(
    body: FraudConfigUpdate,
    user: AuthenticatedUser = Depends(require_root),
) -> FraudConfigOut:
    updated = fd.update_fraud_config(admin_sub=user.sub, **body.model_dump(exclude_none=True))
    return FraudConfigOut(**updated)


@router.get("/stats", response_model=FraudStatsOut)
async def get_stats(
    _user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FraudStatsOut:
    return FraudStatsOut(**fd.get_fraud_stats())
