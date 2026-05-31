"""Group treasury REST endpoints (GROUP-004)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.settings import S
from app.models import (
    ContributeIn,
    ContributeResponse,
    ContributorListResponse,
    SetGoalIn,
    SpendIn,
    SpendResponse,
    TreasuryBalanceOut,
    TreasuryLedgerResponse,
)
from app.services.sessions import require_ui_session
from app.services import group_treasury as treasury_svc
from app.services import user_groups

router = APIRouter(tags=["group-treasury"])


def _check_enabled() -> None:
    if not S.group_treasury_enabled:
        raise HTTPException(status_code=404, detail="Group treasury is not enabled")


@router.get("/ui/groups/{group_id}/treasury")
def get_treasury(
    group_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> TreasuryBalanceOut:
    _check_enabled()
    user_sub = ctx["user_sub"]

    # Check group exists and not dissolved
    meta = user_groups.get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    # Verify membership
    user_groups.require_membership(group_id, user_sub)

    balance = treasury_svc.get_treasury_balance(group_id)
    return TreasuryBalanceOut(**balance)


@router.post("/ui/groups/{group_id}/treasury/contribute")
def contribute(
    group_id: str,
    body: ContributeIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ContributeResponse:
    _check_enabled()
    user_sub = ctx["user_sub"]

    meta = user_groups.get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    result = treasury_svc.contribute(
        group_id=group_id,
        user_id=user_sub,
        amount_cents=body.amount_cents,
        display_name=user_sub,
    )
    return ContributeResponse(**result)


@router.get("/ui/groups/{group_id}/treasury/ledger")
def get_ledger(
    group_id: str,
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> TreasuryLedgerResponse:
    _check_enabled()
    user_sub = ctx["user_sub"]

    meta = user_groups.get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    user_groups.require_membership(group_id, user_sub)

    result = treasury_svc.list_treasury_ledger(group_id, cursor=cursor, limit=limit)
    return TreasuryLedgerResponse(**result)


@router.get("/ui/groups/{group_id}/treasury/contributors")
def get_contributors(
    group_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> ContributorListResponse:
    _check_enabled()
    user_sub = ctx["user_sub"]

    meta = user_groups.get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    user_groups.require_membership(group_id, user_sub)

    result = treasury_svc.list_contributors(group_id)
    return ContributorListResponse(**result)


@router.patch("/ui/groups/{group_id}/treasury/goal")
def set_goal(
    group_id: str,
    body: SetGoalIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _check_enabled()
    user_sub = ctx["user_sub"]

    meta = user_groups.get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    return treasury_svc.set_fundraising_goal(
        group_id=group_id,
        admin_id=user_sub,
        goal_cents=body.goal_cents,
    )


@router.post("/ui/groups/{group_id}/treasury/spend")
def spend(
    group_id: str,
    body: SpendIn,
    ctx: Dict[str, Any] = Depends(require_ui_session),
) -> SpendResponse:
    _check_enabled()
    user_sub = ctx["user_sub"]

    meta = user_groups.get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")

    result = treasury_svc.spend_treasury(
        group_id=group_id,
        admin_id=user_sub,
        amount_cents=body.amount_cents,
        reason=body.reason,
        category=body.category,
        reference_id=body.reference_id,
    )
    return SpendResponse(**result)
