"""User-facing appeals endpoints (MOD-003).

Allows users to file appeals against enforcement actions, view their
appeal history, and withdraw pending appeals.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.models import (
    AppealCreateIn,
    AppealCreateOut,
    AppealListOut,
    AppealOut,
    AppealWithdrawOut,
)
from app.services.appeals import (
    file_appeal,
    get_appeal,
    list_user_appeals,
    withdraw_appeal,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/appeals", tags=["appeals"])


@router.post("", response_model=AppealCreateOut, status_code=201)
async def submit_appeal(
    body: AppealCreateIn,
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Submit a new appeal against an enforcement action."""
    try:
        result = file_appeal(
            user_id=user.sub,
            enforcement_id=body.enforcement_id,
            appeal_text=body.appeal_text,
        )
    except ValueError as exc:
        msg = str(exc)
        if msg == "enforcement_not_found":
            raise HTTPException(404, "Enforcement record not found")
        elif msg == "appeal_already_exists":
            raise HTTPException(409, "An appeal already exists for this enforcement action")
        elif msg == "pending_appeal_exists":
            raise HTTPException(429, "You already have a pending appeal")
        raise HTTPException(400, msg)
    return result


@router.get("", response_model=AppealListOut)
async def list_my_appeals(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(25, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """List the authenticated user's appeals."""
    result = list_user_appeals(user.sub, status=status, limit=limit, cursor=cursor)
    return AppealListOut(
        items=[AppealOut(**i) for i in result["items"]],
        next_cursor=result.get("next_cursor"),
    )


@router.get("/{appeal_id}", response_model=AppealOut)
async def get_my_appeal(
    appeal_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Get a specific appeal. Only the appeal owner may view."""
    item = get_appeal(appeal_id)
    if not item:
        raise HTTPException(404, "Appeal not found")
    if item.get("user_id") != user.sub:
        raise HTTPException(403, "Not authorized to view this appeal")
    return AppealOut(**item)


@router.post("/{appeal_id}/withdraw", response_model=AppealWithdrawOut)
async def withdraw_my_appeal(
    appeal_id: str,
    user: AuthenticatedUser = Depends(get_authenticated_user),
):
    """Withdraw a pending appeal."""
    try:
        result = withdraw_appeal(appeal_id, user.sub)
    except ValueError as exc:
        msg = str(exc)
        if msg == "appeal_not_found":
            raise HTTPException(404, "Appeal not found")
        elif msg == "not_owner":
            raise HTTPException(403, "Not authorized to withdraw this appeal")
        elif msg == "invalid_status":
            raise HTTPException(409, "Appeal cannot be withdrawn in its current status")
        raise HTTPException(400, msg)
    return result
