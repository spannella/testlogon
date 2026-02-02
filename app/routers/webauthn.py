from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from app.auth.deps import get_authenticated_user_sub
from app.core.normalize import client_ip_from_request
from app.models import (
    WebAuthnRegisterBeginReq,
    WebAuthnRegisterBeginResp,
    WebAuthnRegisterFinishReq,
    WebAuthnRegisterFinishResp,
    WebAuthnAuthBeginReq,
    WebAuthnAuthBeginResp,
    WebAuthnAuthFinishReq,
    WebAuthnAuthFinishResp,
)
from app.services.alerts import audit_event
from app.services.sessions import require_ui_session, create_real_session, rotate_session_cookies
from app.services.webauthn import (
    registration_options,
    register_credential,
    authentication_options,
    verify_authentication,
)

router = APIRouter(prefix="/ui/webauthn", tags=["webauthn"])

@router.post("/register/begin", response_model=WebAuthnRegisterBeginResp)
async def webauthn_register_begin(
    req: Request,
    body: WebAuthnRegisterBeginReq,
    ctx=Depends(require_ui_session),
):
    options = registration_options(ctx["user_sub"], ctx["user_sub"])
    audit_event("webauthn_register_begin", ctx["user_sub"], req, outcome="info")
    return {"options": options}

@router.post("/register/finish", response_model=WebAuthnRegisterFinishResp)
async def webauthn_register_finish(
    req: Request,
    body: WebAuthnRegisterFinishReq,
    ctx=Depends(require_ui_session),
):
    out = register_credential(ctx["user_sub"], ctx["user_sub"], body.credential, body.label)
    audit_event("webauthn_register_finish", ctx["user_sub"], req, outcome="success", credential_id=out["credential_id"])
    return out

@router.post("/authenticate/begin", response_model=WebAuthnAuthBeginResp)
async def webauthn_auth_begin(req: Request, body: WebAuthnAuthBeginReq):
    username = body.username.strip()
    if not username:
        raise HTTPException(400, "Username required")
    options = authentication_options(username)
    audit_event("webauthn_auth_begin", username, req, outcome="info")
    return {"options": options}

@router.post("/authenticate/finish", response_model=WebAuthnAuthFinishResp)
async def webauthn_auth_finish(req: Request, body: WebAuthnAuthFinishReq, response: Response):
    username = body.username.strip()
    if not username:
        raise HTTPException(400, "Username required")
    verification = verify_authentication(username, body.credential)
    session = create_real_session(req, username)
    rotate_session_cookies(req, response, username, session)
    audit_event(
        "webauthn_auth_finish",
        username,
        req,
        outcome="success",
        credential_id=verification.get("credential_id"),
        ip=client_ip_from_request(req),
    )
    return {"status": "ok", "session_id": session.session_id}
