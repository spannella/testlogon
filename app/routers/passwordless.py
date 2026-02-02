from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, HTTPException, Request, Response

from app.core.normalize import client_ip_from_request
from app.models import PasswordlessStartReq, PasswordlessStartResp, PasswordlessVerifyReq, PasswordlessVerifyResp
from app.services.alerts import audit_event
from app.services.magic_links import create_magic_link, load_magic_link, magic_link_mismatch, mark_magic_link_used
from app.services.rate_limit import (
    rate_limit_password_recovery,
    enforce_lockout,
    record_lockout_failure,
    clear_lockout,
    record_login_anomaly,
)
from app.services.sessions import compute_required_factors, create_real_session, create_stepup_challenge, rotate_session_cookies

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
    anomaly = record_login_anomaly(username, client_ip_from_request(req))
    if anomaly.get("user_threshold_exceeded") or anomaly.get("ip_threshold_exceeded"):
        audit_event(
            "login_anomaly",
            username,
            req,
            outcome="warning",
            ip_prefix=anomaly.get("ip_prefix"),
            user_ip_count=anomaly.get("user_ip_count"),
            ip_user_count=anomaly.get("ip_user_count"),
        )
    try:
        resp = create_magic_link(req, username)
    except Exception:
        record_lockout_failure(username, client_ip_from_request(req), "passwordless_start")
        resp = {"sent_to": []}
    else:
        audit_event("passwordless_start", username, req, outcome="success")
    return {"status": "sent", "sent_to": []}

@router.post("/verify", response_model=PasswordlessVerifyResp)
async def passwordless_verify(req: Request, body: PasswordlessVerifyReq, response: Response) -> Dict[str, object]:
    record = load_magic_link(body.token)
    user_sub = record.get("target_user_sub", "")
    if not user_sub:
        raise HTTPException(401, "Invalid token")
    enforce_lockout(user_sub, client_ip_from_request(req), "passwordless_verify")
    required = compute_required_factors(user_sub)
    mismatch = magic_link_mismatch(record, req)
    if mismatch["ip_mismatch"] or mismatch["ua_mismatch"]:
        if "email" not in required:
            required = required + ["email"]
        mark_magic_link_used(body.token)
        challenge_id = create_stepup_challenge(req, user_sub, required_factors=required)
        audit_event(
            "passwordless_verify",
            user_sub,
            req,
            outcome="warning",
            required_factors=required,
            challenge_id=challenge_id,
            ip_mismatch=mismatch["ip_mismatch"],
            ua_mismatch=mismatch["ua_mismatch"],
        )
        return {
            "status": "pending",
            "auth_required": True,
            "challenge_id": challenge_id,
            "required_factors": required,
            "device_confirmation": True,
        }
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
    session = create_real_session(req, user_sub)
    rotate_session_cookies(req, response, user_sub, session)
    clear_lockout(user_sub, client_ip_from_request(req), "passwordless_verify")
    audit_event("passwordless_verify", user_sub, req, outcome="success", session_id=session.session_id)
    return {"status": "ok", "session_id": session.session_id, "auth_required": False}
