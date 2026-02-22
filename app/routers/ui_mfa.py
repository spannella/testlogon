from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import get_authenticated_user_sub
from app.core.settings import S
from app.core.normalize import client_ip_from_request
from app.models import EmailBeginReq, EmailVerifyReq, SmsBeginReq, SmsVerifyReq, TotpVerifyReq, RecoveryReq
from app.services.alerts import audit_event
from app.services.mfa import (
    gen_numeric_code,
    list_enabled_emails,
    list_enabled_sms_numbers,
    send_email_code,
    totp_verify_any_enabled,
    twilio_check_sms,
    twilio_start_sms,
    consume_recovery_code,
)
from app.services.rate_limit import (
    rate_limit_or_429,
    can_send_verification,
    rate_limit_mfa_verify,
    enforce_lockout,
    record_lockout_failure,
    clear_lockout,
)
from app.services.sessions import (
    load_challenge_or_401,
    mark_factor_passed,
)
from app.core.tables import T
from app.core.time import now_ts

router = APIRouter(prefix="/ui/mfa", tags=["ui-mfa"])

def _sessions_table_enabled() -> bool:
    return bool(getattr(S, "ddb_sessions_table", ""))

def _challenge_progress(chal: dict, passed_factor: str) -> dict:
    required = list(chal.get("required_factors") or [])
    passed = dict(chal.get("passed") or {})
    passed[passed_factor] = True
    remaining = [f for f in required if not passed.get(f)]
    return {
        "required_factors": required,
        "passed": passed,
        "remaining_factors": remaining,
    }

@router.post("/totp/verify")
async def ui_totp_verify(
    req: Request,
    body: TotpVerifyReq,
    user_sub: str = Depends(get_authenticated_user_sub),
):
    enforce_lockout(user_sub, client_ip_from_request(req), "mfa_totp")
    rate_limit_mfa_verify(user_sub, client_ip_from_request(req), "totp")
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "totp" not in (chal.get("required_factors") or []):
        raise HTTPException(400, "TOTP not required")
    dev = totp_verify_any_enabled(user_sub, body.totp_code)
    if not dev:
        audit_event("mfa_totp_verify", user_sub, req, outcome="failure", challenge_id=body.challenge_id)
        record_lockout_failure(user_sub, client_ip_from_request(req), "mfa_totp")
        raise HTTPException(401, "Bad TOTP")
    mark_factor_passed(user_sub, body.challenge_id, "totp")
    audit_event("mfa_totp_verify", user_sub, req, outcome="success", challenge_id=body.challenge_id, device_id=dev)
    clear_lockout(user_sub, client_ip_from_request(req), "mfa_totp")
    return {"status": "ok", **_challenge_progress(chal, "totp")}

@router.post("/sms/begin")
async def ui_sms_begin(req: Request, body: SmsBeginReq, user_sub: str = Depends(get_authenticated_user_sub)):
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "sms" not in (chal.get("required_factors") or []):
        raise HTTPException(400, "SMS not required")
    nums = list_enabled_sms_numbers(user_sub)
    if not nums:
        raise HTTPException(400, "No SMS devices")
    if not can_send_verification(user_sub, "sms"):
        raise HTTPException(429, "Rate limited")
    rate_limit_or_429(user_sub, "sms_login")
    if _sessions_table_enabled():
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": body.challenge_id},
            UpdateExpression="SET sms_code_sent_at=:t, sms_code_attempts=:z",
            ExpressionAttributeValues={":t": now_ts(), ":z": 0},
        )
    # Send to all enabled numbers
    send_to = nums[:S.sms_device_limit]
    for n in send_to:
        twilio_start_sms(n)
    audit_event("mfa_sms_begin", user_sub, req, outcome="success", challenge_id=body.challenge_id)
    return {"status":"sent","sent_to": send_to}

@router.post("/sms/verify")
async def ui_sms_verify(
    req: Request,
    body: SmsVerifyReq,
    user_sub: str = Depends(get_authenticated_user_sub),
):
    enforce_lockout(user_sub, client_ip_from_request(req), "mfa_sms")
    rate_limit_mfa_verify(user_sub, client_ip_from_request(req), "sms")
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "sms" not in (chal.get("required_factors") or []):
        raise HTTPException(400, "SMS not required")
    attempts = int(chal.get("sms_code_attempts", 0))
    sent_at = int(chal.get("sms_code_sent_at", 0))
    if attempts >= S.sms_code_max_attempts and (now_ts() - sent_at) < S.sms_code_attempt_window_seconds:
        audit_event("mfa_sms_verify", user_sub, req, outcome="failure", challenge_id=body.challenge_id, reason="too_many_attempts")
        record_lockout_failure(user_sub, client_ip_from_request(req), "mfa_sms")
        raise HTTPException(429, "Too many attempts; wait and retry")
    nums = list_enabled_sms_numbers(user_sub)
    if not nums:
        raise HTTPException(400, "No SMS devices")
    ok = False
    for n in nums[:S.sms_device_limit]:
        try:
            if twilio_check_sms(n, body.code.strip()):
                ok = True
                break
        except Exception:
            continue
    if not ok:
        if _sessions_table_enabled():
            T.sessions.update_item(
                Key={"user_sub": user_sub, "session_id": body.challenge_id},
                UpdateExpression="SET sms_code_attempts = :n",
                ExpressionAttributeValues={":n": attempts + 1},
            )
        audit_event("mfa_sms_verify", user_sub, req, outcome="failure", challenge_id=body.challenge_id)
        record_lockout_failure(user_sub, client_ip_from_request(req), "mfa_sms")
        raise HTTPException(401, "Bad SMS code")
    if _sessions_table_enabled():
        try:
            T.sessions.update_item(
                Key={"user_sub": user_sub, "session_id": body.challenge_id},
                UpdateExpression="REMOVE sms_code_sent_at SET sms_code_attempts = :z",
                ExpressionAttributeValues={":z": 0},
            )
        except Exception:
            pass
    mark_factor_passed(user_sub, body.challenge_id, "sms")
    audit_event("mfa_sms_verify", user_sub, req, outcome="success", challenge_id=body.challenge_id)
    clear_lockout(user_sub, client_ip_from_request(req), "mfa_sms")
    return {"status": "ok", **_challenge_progress(chal, "sms")}

@router.post("/email/begin")
async def ui_email_begin(req: Request, body: EmailBeginReq, user_sub: str = Depends(get_authenticated_user_sub)):
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "email" not in (chal.get("required_factors") or []):
        raise HTTPException(400, "Email not required")
    emails = list_enabled_emails(user_sub)
    if not emails:
        raise HTTPException(400, "No email devices")
    if not can_send_verification(user_sub, "email"):
        raise HTTPException(429, "Rate limited")
    rate_limit_or_429(user_sub, "email_login")
    code = gen_numeric_code(6)
    # store hashed code on the challenge item (best effort)
    from app.core.crypto import sha256_str
    if _sessions_table_enabled():
        T.sessions.update_item(Key={"user_sub": user_sub, "session_id": body.challenge_id}, UpdateExpression="SET email_code_hash=:h, email_code_sent_at=:t, email_code_attempts=:z", ExpressionAttributeValues={":h": sha256_str(code), ":t": now_ts(), ":z": 0})
    send_to = emails[:S.email_device_limit]
    for e in send_to:
        send_email_code(e, "login", code)
    audit_event("mfa_email_begin", user_sub, req, outcome="success", challenge_id=body.challenge_id)
    return {"status":"sent","sent_to": send_to}

@router.post("/email/verify")
async def ui_email_verify(
    req: Request,
    body: EmailVerifyReq,
    user_sub: str = Depends(get_authenticated_user_sub),
):
    enforce_lockout(user_sub, client_ip_from_request(req), "mfa_email")
    rate_limit_mfa_verify(user_sub, client_ip_from_request(req), "email")
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "email" not in (chal.get("required_factors") or []):
        raise HTTPException(400, "Email not required")
    from app.core.crypto import sha256_str
    expected = chal.get("email_code_hash","")
    if not expected:
        raise HTTPException(400, "No email code pending")
    attempts = int(chal.get("email_code_attempts", 0))
    sent_at = int(chal.get("email_code_sent_at", 0))
    if attempts >= S.email_code_max_attempts and (now_ts() - sent_at) < S.email_code_attempt_window_seconds:
        audit_event("mfa_email_verify", user_sub, req, outcome="failure", challenge_id=body.challenge_id, reason="too_many_attempts")
        record_lockout_failure(user_sub, client_ip_from_request(req), "mfa_email")
        raise HTTPException(429, "Too many attempts; wait and retry")
    if sha256_str(body.code.strip()) != expected:
        T.sessions.update_item(Key={"user_sub": user_sub, "session_id": body.challenge_id}, UpdateExpression="SET email_code_attempts = :n", ExpressionAttributeValues={":n": attempts + 1})
        audit_event("mfa_email_verify", user_sub, req, outcome="failure", challenge_id=body.challenge_id)
        record_lockout_failure(user_sub, client_ip_from_request(req), "mfa_email")
        raise HTTPException(401, "Bad email code")
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": body.challenge_id},
            UpdateExpression="REMOVE email_code_hash, email_code_sent_at SET email_code_attempts = :z",
            ExpressionAttributeValues={":z": 0},
        )
    except Exception:
        pass
    mark_factor_passed(user_sub, body.challenge_id, "email")
    audit_event("mfa_email_verify", user_sub, req, outcome="success", challenge_id=body.challenge_id)
    clear_lockout(user_sub, client_ip_from_request(req), "mfa_email")
    return {"status": "ok", **_challenge_progress(chal, "email")}

@router.post("/recovery/{factor}")
async def ui_recovery_factor(
    req: Request,
    factor: str,
    body: RecoveryReq,
    user_sub: str = Depends(get_authenticated_user_sub),
):
    enforce_lockout(user_sub, client_ip_from_request(req), f"mfa_recovery_{factor}")
    rate_limit_mfa_verify(user_sub, client_ip_from_request(req), f"recovery_{factor}")
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if factor not in ("totp","sms","email"):
        raise HTTPException(400, "Invalid factor")
    if factor not in (chal.get("required_factors") or []):
        raise HTTPException(400, "Factor not required")
    try:
        consume_recovery_code(user_sub, factor, body.recovery_code)
    except HTTPException:
        record_lockout_failure(user_sub, client_ip_from_request(req), f"mfa_recovery_{factor}")
        raise
    mark_factor_passed(user_sub, body.challenge_id, factor)
    audit_event("mfa_recovery", user_sub, req, outcome="success", challenge_id=body.challenge_id, factor=factor)
    clear_lockout(user_sub, client_ip_from_request(req), f"mfa_recovery_{factor}")
    return {"status": "ok", **_challenge_progress(chal, factor)}
