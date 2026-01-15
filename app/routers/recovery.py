from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import get_authenticated_user_sub
from app.models import RecoveryReq
from app.services.alerts import audit_event
from app.services.mfa import consume_recovery_code
from app.services.sessions import load_challenge_or_401, mark_factor_passed, maybe_finalize

router = APIRouter(prefix="/ui", tags=["recovery"])


def _recover(req: Request, user_sub: str, factor: str, body: RecoveryReq):
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if factor not in ("totp", "sms", "email"):
        raise HTTPException(400, "Invalid factor")
    if factor not in (chal.get("required_factors") or []):
        raise HTTPException(400, "Factor not required")
    consume_recovery_code(user_sub, factor, body.recovery_code)
    mark_factor_passed(user_sub, body.challenge_id, factor)
    sid = maybe_finalize(req, user_sub, body.challenge_id)
    audit_event("mfa_recovery", user_sub, req, outcome="success", challenge_id=body.challenge_id, factor=factor)
    return {"ok": True, "session_id": sid}


@router.post("/recovery/{factor}")
async def recovery_factor(req: Request, factor: str, body: RecoveryReq, user_sub: str = Depends(get_authenticated_user_sub)):
    return _recover(req, user_sub, factor, body)


@router.post("/recovery/totp")
async def recovery_totp(req: Request, body: RecoveryReq, user_sub: str = Depends(get_authenticated_user_sub)):
    return _recover(req, user_sub, "totp", body)


@router.post("/recovery/sms")
async def recovery_sms(req: Request, body: RecoveryReq, user_sub: str = Depends(get_authenticated_user_sub)):
    return _recover(req, user_sub, "sms", body)


@router.post("/recovery/email")
async def recovery_email(req: Request, body: RecoveryReq, user_sub: str = Depends(get_authenticated_user_sub)):
    return _recover(req, user_sub, "email", body)
