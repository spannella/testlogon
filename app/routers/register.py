from __future__ import annotations

import asyncio
import logging
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
    check_email_status,
    create_registration_challenge,
    create_user_record,
    get_pending_user,
    mark_user_verified,
    verify_registration_code,
)
from app.services.sessions import create_real_session, rotate_session_cookies, session_id_value

router = APIRouter(prefix="/ui/register", tags=["register"])

REGISTER_CHECK_TIMEOUT_SECONDS = 5
logger = logging.getLogger(__name__)


def _require_cognito() -> None:
    if not S.cognito_app_client_id:
        raise HTTPException(500, "Cognito app client id not configured")


def _cognito_available() -> bool:
    if S.dev_mode:
        return False  # Use direct DDB registration path in dev mode (fixes #144)
    return bool(S.cognito_app_client_id)


def _resume_pending_registration(req: Request, body: RegisterStartReq, username: str, ip: str) -> None:
    """Re-issue a verification challenge for an existing pending_verification account.

    GAP-0108 resume path: the account record already exists, so we do NOT create
    a new user record and do NOT touch the stored password hash — we only mint a
    fresh challenge (gated by the same rate limiter /resend uses) so the returning
    user actually receives a code instead of a silent fake success.
    """
    if can_send_verification(username, "email"):
        mfa_setup: list[str] = []
        if body.enable_sms_mfa:
            mfa_setup.append("sms")
        if body.enable_totp_mfa:
            mfa_setup.append("totp")
        code = create_registration_challenge(
            user_sub=username,
            channel="email",
            send_to=username,
            mfa_setup=mfa_setup,
            sms_phone=body.phone,
        )
        send_email_code(username, "Registration", code)
        audit_event(
            "register_start",
            username,
            req,
            outcome="success",
            verification_required=True,
            delivery_medium="suppressed",
            reason="resume_pending",
        )
    else:
        audit_event("register_start", username, req, outcome="warning", reason="resume_rate_limited")
    clear_lockout(username, ip, "register_start")


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
        except HTTPException as exc:
            if exc.status_code == 400:
                # Password did not meet Cognito's policy.  The frontend should have
                # caught this before submission; if it still gets through, surface the
                # error clearly rather than returning a misleading "ok".
                audit_event("register_start", username, req, outcome="failure", reason="password_policy")
                raise
            # 409 user-already-exists: if the local account is still
            # pending_verification, resume by re-issuing a challenge (GAP-0108
            # dev/prod parity) rather than returning a silent fake success.
            if (
                exc.status_code == 409
                and S.registration_allow_resume_unverified
                and get_pending_user(username)
            ):
                _resume_pending_registration(req, body, username, ip)
                return generic_response
            # Other non-400 errors (and active-account 409s): return the generic
            # response to avoid leaking whether this email address is registered.
            logger.warning(
                "register_start cognito_sign_up rejected",
                extra={"email": username, "status_code": exc.status_code, "detail": exc.detail},
            )
            audit_event("register_start", username, req, outcome="failure", reason="cognito_sign_up")
            record_lockout_failure(username, ip, "register_start")
            return generic_response
        except Exception:
            logger.exception("register_start unexpected error during cognito_sign_up", extra={"email": username})
            audit_event("register_start", username, req, outcome="failure", reason="unexpected_error")
            record_lockout_failure(username, ip, "register_start")
            return generic_response

    # Resume path (GAP-0108): if this email already exists as a pending_verification
    # account, re-issue a fresh challenge instead of silently no-op'ing. Active
    # accounts fall through to create_user_record below, which raises 409 (no code
    # is sent to an already-verified account).
    if S.registration_allow_resume_unverified and get_pending_user(username):
        _resume_pending_registration(req, body, username, ip)
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
    # On timeout/error we conservatively report the email as available and not
    # unverified, to avoid false negatives (blocking users) from transient
    # DynamoDB issues and to avoid surfacing a resend path we cannot confirm.
    generic_response = {"status": "ok", "available": True, "unverified": False}
    try:
        result = await asyncio.wait_for(
            run_in_threadpool(check_email_status, body.email),
            timeout=REGISTER_CHECK_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("register_check timed out", extra={"email": body.email, "timeout_seconds": REGISTER_CHECK_TIMEOUT_SECONDS})
        audit_event("register_check", body.email, req, outcome="failure", reason="check_timeout")
        record_lockout_failure(body.email, ip, "register_check")
        return generic_response
    except HTTPException as exc:
        logger.warning(
            "register_check failed with HTTP exception",
            extra={"email": body.email, "status_code": exc.status_code, "detail": exc.detail},
        )
        audit_event("register_check", body.email, req, outcome="failure", reason="check_error")
        record_lockout_failure(body.email, ip, "register_check")
        return generic_response
    except Exception:
        logger.exception("register_check unexpected error", extra={"email": body.email})
        audit_event("register_check", body.email, req, outcome="failure", reason="unexpected_error")
        record_lockout_failure(body.email, ip, "register_check")
        return generic_response
    clear_lockout(body.email, ip, "register_check")
    audit_event(
        "register_check",
        body.email,
        req,
        outcome="success",
        available=result["available"],
        unverified=result["unverified"],
    )
    return {"status": "ok", **result}


@router.post("/confirm", response_model=RegisterConfirmResp)
async def register_confirm(
    req: Request,
    body: RegisterConfirmReq,
    response: Response = None,
) -> Dict[str, object]:
    if response is None:
        response = Response()
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

    # KYC-009 / GAP-0269: auto-evaluate KYC tier after email verification.
    # Best-effort; no-op when gating is disabled (get_user_kyc_tier returns max).
    try:
        from app.services.kyc_tiers import auto_evaluate_tier
        auto_evaluate_tier(username, request=req)
    except Exception:
        logger.warning("kyc.tier.auto_evaluate_failed user_sub=%s", username, exc_info=True)

    # ── Referral attribution hook (AFFILIATE-001) ───────────────
    try:
        ref_code = req.cookies.get("ref_attribution", "")
        if ref_code and S.referral_enabled:
            from app.services.referrals import attribute_referral as _attr_ref
            _attr_ref(username, ref_code, ip)
    except Exception:
        logger.warning("referral attribution failed for %s", username, exc_info=True)

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
