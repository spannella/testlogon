from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, HTTPException, Request, Response

from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.models import RegisterConfirmReq, RegisterConfirmResp, RegisterStartReq, RegisterStartResp
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
    mark_user_verified,
    verify_registration_code,
)
from app.services.sessions import create_real_session, rotate_session_cookies, session_id_value

router = APIRouter(prefix="/ui/register", tags=["register"])


def _require_cognito() -> None:
    if not S.cognito_app_client_id:
        raise HTTPException(500, "Cognito app client id not configured")


@router.post("/start", response_model=RegisterStartResp)
async def register_start(
    req: Request,
    body: RegisterStartReq,
    response: Response = None,
) -> Dict[str, object]:
    if response is None:
        response = Response()
    _require_cognito()
    username = body.email
    ip = client_ip_from_request(req)
    enforce_lockout(username, ip, "register_start")
    rate_limit_password_recovery(username, ip, "register_start")

    breach_count = check_password_breach(body.password)
    if breach_count:
        record_lockout_failure(username, ip, "register_start")
        raise HTTPException(400, "Password found in breach corpus")

    try:
        resp = cognito_sign_up(username, body.password, body.full_name)
    except HTTPException:
        record_lockout_failure(username, ip, "register_start")
        raise
    except Exception as exc:
        record_lockout_failure(username, ip, "register_start")
        raise HTTPException(400, "Registration failed") from exc

    delivery = resp.get("CodeDeliveryDetails") or {}
    verification_required = not bool(resp.get("UserConfirmed"))
    create_user_record(
        email=username,
        full_name=body.full_name,
        password=body.password,
        verification_required=verification_required,
    )
    delivery_medium = None
    delivery_destination = None
    if verification_required:
        channel = body.delivery_method
        if channel == "sms":
            if not body.phone:
                raise HTTPException(400, "Phone required for SMS verification")
            if not can_send_verification(username, "sms"):
                raise HTTPException(429, "Too many verification SMS; try again later")
            create_registration_challenge(user_sub=username, channel="sms", send_to=body.phone)
            twilio_start_sms(body.phone)
            delivery_medium = "sms"
            delivery_destination = body.phone
        else:
            if not can_send_verification(username, "email"):
                raise HTTPException(429, "Too many verification emails; try again later")
            code = create_registration_challenge(user_sub=username, channel="email", send_to=username)
            send_email_code(username, "Registration", code)
            delivery_medium = "email"
            delivery_destination = username
    audit_event(
        "register_start",
        username,
        req,
        outcome="success",
        verification_required=verification_required,
        delivery_medium=delivery_medium or delivery.get("DeliveryMedium"),
    )
    clear_lockout(username, ip, "register_start")
    if not verification_required:
        session = create_real_session(req, username)
        rotate_session_cookies(req, response, username, session)
        session_id = session_id_value(session)
        audit_event("register_session_start", username, req, outcome="success", session_id=session_id)
        return {
            "status": "ok",
            "verification_required": False,
            "delivery_medium": None,
            "delivery_destination": None,
            "session_id": session_id,
        }
    return {
        "status": "ok",
        "verification_required": verification_required,
        "delivery_medium": delivery_medium or delivery.get("DeliveryMedium"),
        "delivery_destination": delivery_destination or delivery.get("Destination"),
    }


@router.post("/confirm", response_model=RegisterConfirmResp)
async def register_confirm(req: Request, body: RegisterConfirmReq) -> Dict[str, object]:
    _require_cognito()
    username = body.email
    ip = client_ip_from_request(req)
    enforce_lockout(username, ip, "register_confirm")
    rate_limit_password_recovery(username, ip, "register_confirm")

    try:
        verify_registration_code(user_sub=username, code=body.confirmation_code)
        cognito_admin_confirm_sign_up(username)
    except HTTPException:
        record_lockout_failure(username, ip, "register_confirm")
        raise
    except Exception as exc:
        record_lockout_failure(username, ip, "register_confirm")
        raise HTTPException(400, "Registration confirmation failed") from exc

    clear_lockout(username, ip, "register_confirm")
    mark_user_verified(username)
    audit_event("register_confirm", username, req, outcome="success")
    return {"status": "ok"}
