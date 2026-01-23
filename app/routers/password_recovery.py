from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request

from app.core.crypto import sha256_str
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    PasswordRecoveryConfirmReq,
    PasswordRecoveryChallengeReq,
    PasswordRecoveryEmailVerifyReq,
    PasswordRecoveryRecoveryCodeReq,
    PasswordRecoverySmsVerifyReq,
    PasswordRecoveryStartReq,
    PasswordRecoveryTotpVerifyReq,
)
from app.services.alerts import audit_event
from app.services.cognito import cognito_confirm_forgot_password, cognito_forgot_password
from app.services.mfa import (
    consume_recovery_code,
    gen_numeric_code,
    list_enabled_emails,
    list_enabled_sms_numbers,
    send_email_code,
    totp_verify_any_enabled,
    twilio_check_sms,
    twilio_start_sms,
)
from app.services.rate_limit import can_send_verification, rate_limit_or_429
from app.services.sessions import (
    compute_required_factors,
    create_stepup_challenge,
    load_challenge_or_401,
    mark_factor_passed,
    revoke_challenge,
)

router = APIRouter(prefix="/ui", tags=["password-recovery"])


def _require_cognito() -> None:
    if not S.cognito_app_client_id:
        raise HTTPException(500, "Cognito app client id not configured")


def _normalized_username(username: str) -> str:
    cleaned = username.strip()
    if not cleaned:
        raise HTTPException(400, "Username required")
    return cleaned


def _load_password_recovery_challenge(username: str, challenge_id: str) -> Dict[str, Any]:
    chal = load_challenge_or_401(username, challenge_id)
    if chal.get("purpose") not in (None, "password_recovery"):
        raise HTTPException(400, "Wrong challenge purpose")
    return chal


def _ensure_factor_required(chal: Dict[str, Any], factor: str) -> None:
    if factor not in (chal.get("required_factors") or []):
        raise HTTPException(400, f"{factor.upper()} not required")


def _challenge_required_factors(username: str) -> List[str]:
    return compute_required_factors(username)


@router.post("/password-recovery/start")
async def password_recovery_start(req: Request, body: PasswordRecoveryStartReq) -> Dict[str, Any]:
    _require_cognito()
    username = _normalized_username(body.username)
    resp = cognito_forgot_password(username)
    delivery = resp.get("CodeDeliveryDetails") or {}
    required = _challenge_required_factors(username)
    challenge_id = None
    if required:
        challenge_id = create_stepup_challenge(req, username, required_factors=required)
        T.sessions.update_item(
            Key={"user_sub": username, "session_id": challenge_id},
            UpdateExpression="SET purpose=:p",
            ExpressionAttributeValues={":p": "password_recovery"},
        )
    audit_event(
        "password_recovery_start",
        username,
        req,
        outcome="success",
        delivery_medium=delivery.get("DeliveryMedium"),
        delivery_destination=delivery.get("Destination"),
    )
    return {
        "status": "ok",
        "delivery_medium": delivery.get("DeliveryMedium"),
        "delivery_destination": delivery.get("Destination"),
        "challenge_id": challenge_id,
        "required_factors": required,
    }


@router.post("/password-recovery/confirm")
async def password_recovery_confirm(req: Request, body: PasswordRecoveryConfirmReq) -> Dict[str, Any]:
    _require_cognito()
    username = _normalized_username(body.username)
    required = _challenge_required_factors(username)
    if required:
        if not body.challenge_id:
            raise HTTPException(400, "Challenge required")
        chal = _load_password_recovery_challenge(username, body.challenge_id)
        if set(chal.get("required_factors") or []) != set(required):
            raise HTTPException(400, "Challenge factors out of date; restart recovery")
        passed = chal.get("passed", {}) or {}
        if not all(passed.get(f, False) for f in required):
            raise HTTPException(401, "Complete all challenges before confirming")
        revoke_challenge(username, body.challenge_id)
    cognito_confirm_forgot_password(username, body.confirmation_code, body.new_password)
    audit_event("password_recovery_confirm", username, req, outcome="success")
    return {"status": "ok"}


@router.post("/password-recovery/challenge/totp/verify")
async def password_recovery_totp_verify(req: Request, body: PasswordRecoveryTotpVerifyReq) -> Dict[str, Any]:
    chal = _load_password_recovery_challenge(body.username, body.challenge_id)
    _ensure_factor_required(chal, "totp")
    dev = totp_verify_any_enabled(body.username, body.totp_code)
    if not dev:
        audit_event("password_recovery_totp_verify", body.username, req, outcome="failure", challenge_id=body.challenge_id)
        raise HTTPException(401, "Bad TOTP")
    mark_factor_passed(body.username, body.challenge_id, "totp")
    audit_event("password_recovery_totp_verify", body.username, req, outcome="success", challenge_id=body.challenge_id)
    return {"status": "ok"}


@router.post("/password-recovery/challenge/sms/begin")
async def password_recovery_sms_begin(req: Request, body: PasswordRecoveryChallengeReq) -> Dict[str, Any]:
    chal = _load_password_recovery_challenge(body.username, body.challenge_id)
    _ensure_factor_required(chal, "sms")
    nums = list_enabled_sms_numbers(body.username)
    if not nums:
        raise HTTPException(400, "No SMS devices")
    if not can_send_verification(body.username, "sms"):
        raise HTTPException(429, "Rate limited")
    rate_limit_or_429(body.username, "sms_recovery")
    send_to = nums[:S.sms_device_limit]
    for n in send_to:
        twilio_start_sms(n)
    audit_event("password_recovery_sms_begin", body.username, req, outcome="success", challenge_id=body.challenge_id)
    return {"status": "sent", "sent_to": send_to}


@router.post("/password-recovery/challenge/sms/verify")
async def password_recovery_sms_verify(req: Request, body: PasswordRecoverySmsVerifyReq) -> Dict[str, Any]:
    chal = _load_password_recovery_challenge(body.username, body.challenge_id)
    _ensure_factor_required(chal, "sms")
    nums = list_enabled_sms_numbers(body.username)
    if not nums:
        raise HTTPException(400, "No SMS devices")
    ok = False
    for number in nums[:S.sms_device_limit]:
        try:
            if twilio_check_sms(number, body.code.strip()):
                ok = True
                break
        except Exception:
            continue
    if not ok:
        audit_event("password_recovery_sms_verify", body.username, req, outcome="failure", challenge_id=body.challenge_id)
        raise HTTPException(401, "Bad SMS code")
    mark_factor_passed(body.username, body.challenge_id, "sms")
    audit_event("password_recovery_sms_verify", body.username, req, outcome="success", challenge_id=body.challenge_id)
    return {"status": "ok"}


@router.post("/password-recovery/challenge/email/begin")
async def password_recovery_email_begin(req: Request, body: PasswordRecoveryChallengeReq) -> Dict[str, Any]:
    chal = _load_password_recovery_challenge(body.username, body.challenge_id)
    _ensure_factor_required(chal, "email")
    emails = list_enabled_emails(body.username)
    if not emails:
        raise HTTPException(400, "No email devices")
    if not can_send_verification(body.username, "email"):
        raise HTTPException(429, "Rate limited")
    rate_limit_or_429(body.username, "email_recovery")
    code = gen_numeric_code(6)
    T.sessions.update_item(
        Key={"user_sub": body.username, "session_id": body.challenge_id},
        UpdateExpression="SET email_code_hash=:h, email_code_sent_at=:t, email_code_attempts=:z",
        ExpressionAttributeValues={":h": sha256_str(code), ":t": now_ts(), ":z": 0},
    )
    send_to = emails[:S.email_device_limit]
    for e in send_to:
        send_email_code(e, "password recovery", code)
    audit_event("password_recovery_email_begin", body.username, req, outcome="success", challenge_id=body.challenge_id)
    return {"status": "sent", "sent_to": send_to}


@router.post("/password-recovery/challenge/email/verify")
async def password_recovery_email_verify(req: Request, body: PasswordRecoveryEmailVerifyReq) -> Dict[str, Any]:
    chal = _load_password_recovery_challenge(body.username, body.challenge_id)
    _ensure_factor_required(chal, "email")
    expected = chal.get("email_code_hash", "")
    if not expected:
        raise HTTPException(400, "No email code pending")
    attempts = int(chal.get("email_code_attempts", 0))
    sent_at = int(chal.get("email_code_sent_at", 0))
    if attempts >= S.email_code_max_attempts and (now_ts() - sent_at) < S.email_code_attempt_window_seconds:
        audit_event(
            "password_recovery_email_verify",
            body.username,
            req,
            outcome="failure",
            challenge_id=body.challenge_id,
            reason="too_many_attempts",
        )
        raise HTTPException(429, "Too many attempts; wait and retry")
    if sha256_str(body.code.strip()) != expected:
        T.sessions.update_item(
            Key={"user_sub": body.username, "session_id": body.challenge_id},
            UpdateExpression="SET email_code_attempts = :n",
            ExpressionAttributeValues={":n": attempts + 1},
        )
        audit_event("password_recovery_email_verify", body.username, req, outcome="failure", challenge_id=body.challenge_id)
        raise HTTPException(401, "Bad email code")
    mark_factor_passed(body.username, body.challenge_id, "email")
    audit_event("password_recovery_email_verify", body.username, req, outcome="success", challenge_id=body.challenge_id)
    return {"status": "ok"}


@router.post("/password-recovery/challenge/recovery")
async def password_recovery_code(req: Request, body: PasswordRecoveryRecoveryCodeReq) -> Dict[str, Any]:
    chal = _load_password_recovery_challenge(body.username, body.challenge_id)
    factor = body.factor
    if factor not in ("totp", "sms", "email"):
        raise HTTPException(400, "Invalid factor")
    _ensure_factor_required(chal, factor)
    consume_recovery_code(body.username, factor, body.recovery_code)
    mark_factor_passed(body.username, body.challenge_id, factor)
    audit_event("password_recovery_code", body.username, req, outcome="success", challenge_id=body.challenge_id, factor=factor)
    return {"status": "ok"}
