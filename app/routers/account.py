from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.models import AccountClosureFinalizeReq
from app.services.account import delete_user_data
from app.services.alerts import audit_event
from app.services.sessions import (
    challenge_done,
    compute_required_factors,
    create_stepup_challenge,
    load_challenge_or_401,
    require_ui_session,
)

router = APIRouter(prefix="/ui/account", tags=["account"])


@router.post("/closure/start")
async def account_closure_start(req: Request, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    required = compute_required_factors(user_sub)
    challenge_id = create_stepup_challenge(req, user_sub, required_factors=required, purpose="account_closure")
    audit_event(
        "account_closure_start",
        user_sub,
        req,
        outcome="info",
        challenge_id=challenge_id,
        required_factors=required,
    )
    return {"auth_required": bool(required), "challenge_id": challenge_id, "required_factors": required}


@router.post("/closure/finalize")
async def account_closure_finalize(req: Request, body: AccountClosureFinalizeReq, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if chal.get("purpose") != "account_closure":
        raise HTTPException(400, "Wrong challenge purpose")
    if not challenge_done(chal):
        return {
            "status": "pending",
            "required_factors": chal.get("required_factors", []),
            "passed": chal.get("passed", {}),
        }
    audit_event("account_closure_finalize", user_sub, req, outcome="success", challenge_id=body.challenge_id)
    delete_user_data(user_sub)
    return {"status": "closed"}
