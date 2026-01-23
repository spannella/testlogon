from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.models import AccountStatusReq
from app.services.account_state import get_account_state, set_account_state
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui", tags=["account"])


@router.get("/account/status")
async def account_status(ctx=Depends(require_ui_session)):
    return get_account_state(ctx["user_sub"])


@router.post("/account/suspend")
async def account_suspend(body: AccountStatusReq, req: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    state = get_account_state(user_sub)
    if state["status"] != "active":
        raise HTTPException(400, "Account is already in a suspension or reactivation flow.")
    updated = set_account_state(user_sub, "suspension_requested", reason=body.reason or "", requested_by=user_sub)
    audit_event("account_suspension_requested", user_sub, req, outcome="success", reason=body.reason or "")
    return updated


@router.post("/account/reactivate")
async def account_reactivate(body: AccountStatusReq, req: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    state = get_account_state(user_sub)
    if state["status"] == "active":
        raise HTTPException(400, "Account is already active.")
    if state["status"] == "reactivation_requested":
        raise HTTPException(400, "Reactivation already requested.")
    updated = set_account_state(user_sub, "reactivation_requested", reason=body.reason or "", requested_by=user_sub)
    audit_event("account_reactivation_requested", user_sub, req, outcome="success", reason=body.reason or "")
    return updated
