from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.deps import get_authenticated_user_sub
from app.core.settings import S
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
from app.services.rate_limit import rate_limit_or_429, can_send_verification
from app.services.sessions import load_challenge_or_401, mark_factor_passed, maybe_finalize, revoke_challenge
from app.core.tables import T
from app.core.time import now_ts

router = APIRouter(prefix="/ui/mfa", tags=["ui-mfa"])

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
async def ui_totp_verify(req: Request, body: TotpVerifyReq, user_sub: str = Depends(get_authenticated_user_sub)):
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "totp" not in (chal.get("required_factors") or []):
        raise HTTPException(400, "TOTP not required")
    dev = totp_verify_any_enabled(user_sub, body.totp_code)
    if not dev:
        audit_event("mfa_totp_verify", user_sub, req, outcome="failure", challenge_id=body.challenge_id)
        raise HTTPException(401, "Bad TOTP")
    mark_factor_passed(user_sub, body.challenge_id, "totp")
    sid = maybe_finalize(req, user_sub, body.challenge_id)
    audit_event("mfa_totp_verify", user_sub, req, outcome="success", challenge_id=body.challenge_id, device_id=dev)
    return {"status":"ok","session_id": sid, **_challenge_progress(chal, "totp")}

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
    # Send to all enabled numbers
    send_to = nums[:S.sms_device_limit]
    for n in send_to:
        twilio_start_sms(n)
    audit_event("mfa_sms_begin", user_sub, req, outcome="success", challenge_id=body.challenge_id)
    return {"status":"sent","sent_to": send_to}

@router.post("/sms/verify")
async def ui_sms_verify(req: Request, body: SmsVerifyReq, user_sub: str = Depends(get_authenticated_user_sub)):
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if "sms" not in (chal.get("required_factors") or []):
        raise HTTPException(400, "SMS not required")
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
        audit_event("mfa_sms_verify", user_sub, req, outcome="failure", challenge_id=body.challenge_id)
        raise HTTPException(401, "Bad SMS code")
    mark_factor_passed(user_sub, body.challenge_id, "sms")
    sid = maybe_finalize(req, user_sub, body.challenge_id)
    audit_event("mfa_sms_verify", user_sub, req, outcome="success", challenge_id=body.challenge_id)
    return {"status":"ok","session_id": sid, **_challenge_progress(chal, "sms")}

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
    T.sessions.update_item(Key={"user_sub": user_sub, "session_id": body.challenge_id}, UpdateExpression="SET email_code_hash=:h, email_code_sent_at=:t, email_code_attempts=:z", ExpressionAttributeValues={":h": sha256_str(code), ":t": now_ts(), ":z": 0})
    send_to = emails[:S.email_device_limit]
    for e in send_to:
        send_email_code(e, "login", code)
    audit_event("mfa_email_begin", user_sub, req, outcome="success", challenge_id=body.challenge_id)
    return {"status":"sent","sent_to": send_to}

@router.post("/email/verify")
async def ui_email_verify(req: Request, body: EmailVerifyReq, user_sub: str = Depends(get_authenticated_user_sub)):
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
        raise HTTPException(429, "Too many attempts; wait and retry")
    if sha256_str(body.code.strip()) != expected:
        T.sessions.update_item(Key={"user_sub": user_sub, "session_id": body.challenge_id}, UpdateExpression="SET email_code_attempts = :n", ExpressionAttributeValues={":n": attempts + 1})
        audit_event("mfa_email_verify", user_sub, req, outcome="failure", challenge_id=body.challenge_id)
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
    sid = maybe_finalize(req, user_sub, body.challenge_id)
    audit_event("mfa_email_verify", user_sub, req, outcome="success", challenge_id=body.challenge_id)
    return {"status":"ok","session_id": sid, **_challenge_progress(chal, "email")}

@router.post("/recovery/{factor}")
async def ui_recovery_factor(req: Request, factor: str, body: RecoveryReq, user_sub: str = Depends(get_authenticated_user_sub)):
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    if factor not in ("totp","sms","email"):
        raise HTTPException(400, "Invalid factor")
    if factor not in (chal.get("required_factors") or []):
        raise HTTPException(400, "Factor not required")
    consume_recovery_code(user_sub, factor, body.recovery_code)
    mark_factor_passed(user_sub, body.challenge_id, factor)
    sid = maybe_finalize(req, user_sub, body.challenge_id)
    audit_event("mfa_recovery", user_sub, req, outcome="success", challenge_id=body.challenge_id, factor=factor)
    return {"status":"ok","session_id": sid, **_challenge_progress(chal, factor)}
