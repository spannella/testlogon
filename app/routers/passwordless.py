from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, HTTPException, Request

from app.core.normalize import client_ip_from_request
from app.models import PasswordlessStartReq, PasswordlessStartResp, PasswordlessVerifyReq, PasswordlessVerifyResp
from app.services.alerts import audit_event
from app.services.magic_links import create_magic_link, load_magic_link, mark_magic_link_used
from app.services.rate_limit import (
    rate_limit_password_recovery,
    enforce_lockout,
    record_lockout_failure,
    clear_lockout,
)
from app.services.sessions import compute_required_factors, create_real_session, create_stepup_challenge

router = APIRouter(prefix="/ui/passwordless", tags=["passwordless"])

def _normalized_username(username: str) -> str:
    cleaned = username.strip()
    if not cleaned:
        raise HTTPException(400, "Username required")
    return cleaned

@router.post("/start", response_model=PasswordlessStartResp)
async def passwordless_start(req: Request, body: PasswordlessStartReq) -> Dict[str, object]:
    username = _normalized_username(body.username)
    enforce_lockout(username, client_ip_from_request(req), "passwordless_start")
    rate_limit_password_recovery(username, client_ip_from_request(req), "passwordless_start")
    try:
        resp = create_magic_link(req, username)
    except Exception:
        record_lockout_failure(username, client_ip_from_request(req), "passwordless_start")
        raise
    audit_event("passwordless_start", username, req, outcome="success")
    return {"status": "sent", "sent_to": resp["sent_to"]}

@router.post("/verify", response_model=PasswordlessVerifyResp)
async def passwordless_verify(req: Request, body: PasswordlessVerifyReq) -> Dict[str, object]:
    record = load_magic_link(body.token)
    user_sub = record.get("target_user_sub", "")
    if not user_sub:
        raise HTTPException(401, "Invalid token")
    enforce_lockout(user_sub, client_ip_from_request(req), "passwordless_verify")
    required = compute_required_factors(user_sub)
    if required:
        mark_magic_link_used(body.token)
        challenge_id = create_stepup_challenge(req, user_sub, required_factors=required)
        audit_event("passwordless_verify", user_sub, req, outcome="info", required_factors=required, challenge_id=challenge_id)
        return {
            "status": "pending",
            "auth_required": True,
            "challenge_id": challenge_id,
            "required_factors": required,
        }
    mark_magic_link_used(body.token)
    session_id = create_real_session(req, user_sub)
    clear_lockout(user_sub, client_ip_from_request(req), "passwordless_verify")
    audit_event("passwordless_verify", user_sub, req, outcome="success", session_id=session_id)
    return {"status": "ok", "session_id": session_id, "auth_required": False}
