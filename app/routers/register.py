from __future__ import annotations

import asyncio
from typing import Dict

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.core.time import now_ts
from app.models import (
    RegisterConfirmReq,
    RegisterConfirmResp,
    RegisterEmailCheckReq,
    RegisterEmailCheckResp,
    RegisterResendReq,
    RegisterResendResp,
    RegisterStartReq,
    RegisterStartResp,
)
from app.services.alerts import audit_event
from app.services.breach_check import check_password_breach
from app.services.cognito import cognito_admin_confirm_sign_up, cognito_sign_up
from app.services.mfa import send_email_code, twilio_start_sms
from app.services.rate_limit import (
    can_send_verification,
    enforce_lockout,
    record_lockout_failure,
    clear_lockout,
    rate_limit_password_recovery,
)
from app.services.registration import (
    create_registration_challenge,
    create_user_record,
    is_email_available,
    mark_user_verified,
    verify_registration_code,
)
from app.services.sessions import create_real_session, rotate_session_cookies, session_id_value

router = APIRouter(prefix="/ui/register", tags=["register"])

DEFAULT_DEV_REGISTRATION_EMAIL = "demo@example.com"
DEFAULT_DEV_REGISTRATION_PASSWORD = "CloudRiver789!"
DEFAULT_DEV_REGISTRATION_CODE = "000000"
DEFAULT_DEV_REGISTRATION_PHONE = "+15555550123"
REGISTER_CHECK_TIMEOUT_SECONDS = 5


def _require_cognito() -> None:
    if not S.cognito_app_client_id:
        raise HTTPException(500, "Cognito app client id not configured")


def _cognito_available() -> bool:
    return bool(S.cognito_app_client_id)

def _dev_registration_config() -> dict[str, str] | None:
    if not S.dev_mode:
        return None
    return {
        "email": S.dev_registration_email or DEFAULT_DEV_REGISTRATION_EMAIL,
        "password": S.dev_registration_password or DEFAULT_DEV_REGISTRATION_PASSWORD,
        "code": S.dev_registration_code or DEFAULT_DEV_REGISTRATION_CODE,
        "phone": S.dev_registration_phone or DEFAULT_DEV_REGISTRATION_PHONE,
    }

def _is_dev_registration(email: str, password: str | None = None) -> bool:
    config = _dev_registration_config()
    if not config:
        return False
    if email != config["email"]:
        return False
    if password is None:
        return True
    return password == config["password"]


@router.post("/start", response_model=RegisterStartResp)
async def register_start(
    req: Request,
    body: RegisterStartReq,
    response: Response = None,
) -> Dict[str, object]:
    if response is None:
        response = Response()
    generic_response = {
        "status": "ok",
        "verification_required": True,
        "delivery_medium": None,
        "delivery_destination": None,
    }
    if _is_dev_registration(body.email, body.password):
        audit_event("register_start", body.email, req, outcome="success", mode="dev")
        return generic_response
    use_cognito = _cognito_available()
    if not use_cognito and not S.dev_mode:
        _require_cognito()
    username = body.email
    ip = client_ip_from_request(req)
    enforce_lockout(username, ip, "register_start")
    rate_limit_password_recovery(username, ip, "register_start")

    breach_count = check_password_breach(body.password)
    if breach_count:
        audit_event("register_start", username, req, outcome="failure", reason="breach_password")
        record_lockout_failure(username, ip, "register_start")
        raise HTTPException(400, "Password found in breach corpus")

    if use_cognito:
        try:
            cognito_sign_up(username, body.password, body.full_name)
        except HTTPException:
            audit_event("register_start", username, req, outcome="failure", reason="cognito_sign_up")
            record_lockout_failure(username, ip, "register_start")
            return generic_response
        except Exception:
            audit_event("register_start", username, req, outcome="failure", reason="unexpected_error")
            record_lockout_failure(username, ip, "register_start")
            return generic_response

    verification_required = True
    try:
        create_user_record(
            email=username,
            full_name=body.full_name,
            password=body.password,
            verification_required=verification_required,
        )
    except HTTPException:
        audit_event("register_start", username, req, outcome="failure", reason="duplicate_or_invalid")
        clear_lockout(username, ip, "register_start")
        return generic_response
    mfa_setup: list[str] = []
    if body.enable_sms_mfa:
        mfa_setup.append("sms")
    if body.enable_totp_mfa:
        mfa_setup.append("totp")
    if can_send_verification(username, "email"):
        code = create_registration_challenge(
            user_sub=username,
            channel="email",
            send_to=username,
            mfa_setup=mfa_setup,
            sms_phone=body.phone,
        )
        send_email_code(username, "Registration", code)
    else:
        audit_event("register_start", username, req, outcome="warning", reason="verification_send_rate_limited")
    audit_event(
        "register_start",
        username,
        req,
        outcome="success",
        verification_required=verification_required,
        delivery_medium="suppressed",
    )
    clear_lockout(username, ip, "register_start")
    return generic_response


@router.post("/check", response_model=RegisterEmailCheckResp)
async def register_check(req: Request, body: RegisterEmailCheckReq) -> Dict[str, object]:
    ip = client_ip_from_request(req)
    enforce_lockout(body.email, ip, "register_check")
    rate_limit_password_recovery(body.email, ip, "register_check")
    generic_response = {"status": "ok", "available": True}
    if _is_dev_registration(body.email):
        audit_event("register_check", body.email, req, outcome="success", mode="dev")
        return generic_response
    try:
        available = await asyncio.wait_for(
            run_in_threadpool(is_email_available, body.email),
            timeout=REGISTER_CHECK_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        audit_event("register_check", body.email, req, outcome="failure", reason="check_timeout")
        record_lockout_failure(body.email, ip, "register_check")
        return generic_response
    except HTTPException:
        audit_event("register_check", body.email, req, outcome="failure", reason="check_error")
        record_lockout_failure(body.email, ip, "register_check")
        return generic_response
    except Exception:
        audit_event("register_check", body.email, req, outcome="failure", reason="unexpected_error")
        record_lockout_failure(body.email, ip, "register_check")
        return generic_response
    clear_lockout(body.email, ip, "register_check")
    audit_event("register_check", body.email, req, outcome="success", available=available)
    return generic_response


@router.post("/confirm", response_model=RegisterConfirmResp)
async def register_confirm(
    req: Request,
    body: RegisterConfirmReq,
    response: Response = None,
) -> Dict[str, object]:
    if response is None:
        response = Response()
    config = _dev_registration_config()
    if config and body.email == config["email"]:
        if body.confirmation_code != config["code"]:
            raise HTTPException(400, "Invalid verification code")
        return {
            "status": "ok",
            "session_id": "dev-session",
            "mfa_setup": [],
            "sms_phone": config["phone"] or None,
        }
    use_cognito = _cognito_available()
    if not use_cognito and not S.dev_mode:
        _require_cognito()
    username = body.email
    ip = client_ip_from_request(req)
    enforce_lockout(username, ip, "register_confirm")
    rate_limit_password_recovery(username, ip, "register_confirm")

    try:
        verification = verify_registration_code(user_sub=username, code=body.confirmation_code)
        if use_cognito:
            cognito_admin_confirm_sign_up(username)
    except HTTPException:
        audit_event("register_confirm", username, req, outcome="failure", reason="verification_failed")
        record_lockout_failure(username, ip, "register_confirm")
        raise
    except Exception as exc:
        audit_event("register_confirm", username, req, outcome="failure", reason="unexpected_error")
        record_lockout_failure(username, ip, "register_confirm")
        raise HTTPException(400, "Registration confirmation failed") from exc

    clear_lockout(username, ip, "register_confirm")
    mark_user_verified(username)
    audit_event("register_confirm", username, req, outcome="success")

    session = create_real_session(req, username, mfa_verified_at=now_ts())
    rotate_session_cookies(req, response, username, session)
    session_id = session_id_value(session)
    audit_event("register_session_start", username, req, outcome="success", session_id=session_id)
    return {
        "status": "ok",
        "session_id": session_id,
        "mfa_setup": verification.get("mfa_setup") or [],
        "sms_phone": verification.get("sms_phone") or None,
    }


@router.post("/resend", response_model=RegisterResendResp)
async def register_resend(req: Request, body: RegisterResendReq) -> Dict[str, object]:
    generic_response = {
        "status": "ok",
        "delivery_medium": None,
        "delivery_destination": None,
    }
    if _is_dev_registration(body.email):
        audit_event("register_resend", body.email, req, outcome="success", mode="dev")
        return generic_response
    if not _cognito_available() and not S.dev_mode:
        _require_cognito()
    username = body.email
    ip = client_ip_from_request(req)
    enforce_lockout(username, ip, "register_resend")
    rate_limit_password_recovery(username, ip, "register_resend")

    try:
        mfa_setup: list[str] = []
        if body.enable_sms_mfa:
            mfa_setup.append("sms")
        if body.enable_totp_mfa:
            mfa_setup.append("totp")
        if body.delivery_method == "sms":
            if not body.phone:
                raise HTTPException(400, "Phone required for SMS verification")
            if not can_send_verification(username, "sms"):
                raise HTTPException(429, "Too many verification SMS; try again later")
            create_registration_challenge(
                user_sub=username,
                channel="sms",
                send_to=body.phone,
                mfa_setup=mfa_setup,
                sms_phone=body.phone,
            )
            twilio_start_sms(body.phone)
            delivery_medium = "sms"
            delivery_destination = body.phone
        else:
            if not can_send_verification(username, "email"):
                raise HTTPException(429, "Too many verification emails; try again later")
            code = create_registration_challenge(
                user_sub=username,
                channel="email",
                send_to=username,
                mfa_setup=mfa_setup,
                sms_phone=body.phone,
            )
            send_email_code(username, "Registration", code)
            delivery_medium = "email"
            delivery_destination = username
    except HTTPException:
        audit_event("register_resend", username, req, outcome="failure", reason="resend_failed")
        record_lockout_failure(username, ip, "register_resend")
        return generic_response
    except Exception:
        audit_event("register_resend", username, req, outcome="failure", reason="unexpected_error")
        record_lockout_failure(username, ip, "register_resend")
        return generic_response

    audit_event(
        "register_resend",
        username,
        req,
        outcome="success",
        delivery_medium=delivery_medium,
        delivery_destination=delivery_destination,
    )
    clear_lockout(username, ip, "register_resend")
    return generic_response
