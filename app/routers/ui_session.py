from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from boto3.dynamodb.conditions import Key

from app.auth.deps import get_authenticated_user_sub, resolve_dev_or_authenticated_user_sub
from app.models import UiSessionFinalizeReq, UiSessionStartReq, UiSessionStartResp
from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.services.alerts import audit_event
from app.services.mfa import list_enabled_emails
from app.services.device_trust import record_device_login
from app.services.rate_limit import rate_limit_login_attempt, record_login_anomaly
from app.services.device_trust import trust_current_device
from app.services.sessions import (
    compute_required_factors,
    clear_session_cookies,
    create_real_session,
    create_stepup_challenge,
    is_real_ui_session_id,
    load_challenge_or_401,
    maybe_finalize,
    mint_access_token,
    require_ui_session,
    rotate_session_cookies,
    rotate_refresh_token,
    session_id_value,
)
from app.metrics import record_session_revoked
from app.core.tables import T
from app.core.time import now_ts

router = APIRouter(prefix="/ui", tags=["ui-session"])


def _adaptive_login_policy(user_sub: str, base_required: list[str], anomaly: dict[str, object]) -> tuple[list[str], int, int | None]:
    required = list(base_required)
    risk_score = int(bool(anomaly.get("user_threshold_exceeded"))) + int(bool(anomaly.get("ip_threshold_exceeded")))
    if risk_score <= 0:
        return required, 0, None

    available = set(compute_required_factors(user_sub))
    stronger_order = ["totp", "email", "sms"]
    for factor in stronger_order:
        if factor in available and factor not in required:
            required.append(factor)

    # If anomaly risk is high and we have multiple factors, require at least 2 factors.
    if risk_score >= getattr(S, "login_anomaly_risk_score_threshold", 1):
        stronger = [f for f in stronger_order if f in required]
        if len(stronger) >= 2:
            required = stronger[:2]
        refresh_ttl = max(300, int(getattr(S, "login_high_risk_refresh_ttl_seconds", 3600)))
    else:
        refresh_ttl = None

    # Preserve deterministic order.
    ordered = [f for f in stronger_order if f in required]
    return ordered, risk_score, refresh_ttl

@router.post("/session/start", response_model=UiSessionStartResp)
async def ui_session_start(
    req: Request,
    body: UiSessionStartReq,
    response: Response = None,
    user_sub: str = Depends(resolve_dev_or_authenticated_user_sub),
):
    if response is None:
        response = Response()
    if user_sub == (S.root_user_sub or "").strip():
        raise HTTPException(status_code=403, detail="Root login must use /auth/root/login")
    rate_limit_login_attempt(user_sub, client_ip_from_request(req))
    anomaly = record_login_anomaly(user_sub, client_ip_from_request(req))
    if anomaly.get("user_threshold_exceeded") or anomaly.get("ip_threshold_exceeded"):
        audit_event(
            "login_anomaly",
            user_sub,
            req,
            outcome="warning",
            ip_prefix=anomaly.get("ip_prefix"),
            user_ip_count=anomaly.get("user_ip_count"),
            ip_user_count=anomaly.get("ip_user_count"),
        )
    required = compute_required_factors(user_sub)
    required, anomaly_risk_score, high_risk_refresh_ttl = _adaptive_login_policy(user_sub, required, anomaly)
    device_info = record_device_login(req, user_sub)
    suspicious = device_info.get("new_device") or device_info.get("location_mismatch")
    if suspicious and "email" not in required:
        if list_enabled_emails(user_sub):
            required = required + ["email"]
            audit_event(
                "login_suspicious",
                user_sub,
                req,
                outcome="warning",
                reason="device_mismatch_requires_email",
                device_id=device_info.get("device_id"),
            )
        else:
            audit_event(
                "login_suspicious",
                user_sub,
                req,
                outcome="warning",
                reason="device_mismatch_no_email",
                device_id=device_info.get("device_id"),
            )
    if anomaly_risk_score > 0:
        audit_event(
            "login_unusual_signin",
            user_sub,
            req,
            outcome="warning",
            risk_score=anomaly_risk_score,
            required_factors=required,
            short_refresh_ttl=high_risk_refresh_ttl or 0,
        )

    if not required:
        session = create_real_session(
            req,
            user_sub,
            risk_score=anomaly_risk_score,
            refresh_ttl_seconds=high_risk_refresh_ttl,
        )
        rotate_session_cookies(req, response, user_sub, session, refresh_ttl_seconds=high_risk_refresh_ttl)
        session_id = session_id_value(session)
        audit_event(
            "ui_session_start",
            user_sub,
            req,
            outcome="success",
            session_id=session_id,
            risk_score=anomaly_risk_score,
        )
        return UiSessionStartResp(auth_required=False, session_id=session_id, required_factors=[])
    challenge_id = create_stepup_challenge(
        req,
        user_sub,
        required_factors=required,
        risk_score=anomaly_risk_score,
        refresh_ttl_seconds=high_risk_refresh_ttl,
    )
    # Mint a short-lived access token cookie so MFA endpoints can identify the user
    # during the challenge phase. get_authenticated_user_sub reads this cookie; without
    # it the call would hit the Cognito check and raise 401 "Missing bearer token".
    _chal_access = mint_access_token(user_sub, challenge_id)
    if _chal_access:
        response.set_cookie(
            S.ui_access_token_cookie_name,
            _chal_access,
            max_age=S.session_challenge_ttl_seconds,
            httponly=True,
            secure=S.ui_cookie_secure,
            samesite=S.ui_cookie_samesite,
        )
    audit_event(
        "ui_session_start",
        user_sub,
        req,
        outcome="info",
        required_factors=required,
        challenge_id=challenge_id,
        risk_score=anomaly_risk_score,
    )
    return UiSessionStartResp(auth_required=True, challenge_id=challenge_id, required_factors=required)

@router.post("/session/finalize")
async def ui_session_finalize(
    req: Request,
    body: UiSessionFinalizeReq,
    response: Response = None,
    user_sub: str = Depends(get_authenticated_user_sub),
):
    if response is None:
        response = Response()
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    sid = maybe_finalize(req, user_sub, body.challenge_id)
    if sid:
        rotate_session_cookies(req, response, user_sub, sid, refresh_ttl_seconds=int(chal.get("refresh_ttl_seconds") or 0) or None)
        if body.remember_device:
            device_id = trust_current_device(req, user_sub)
            audit_event("device_trust", user_sub, req, outcome="success", device_id=device_id)
        session_id = session_id_value(sid)
        audit_event("ui_session_finalize", user_sub, req, outcome="success", challenge_id=body.challenge_id, session_id=session_id)
        return {"status": "ok", "session_id": session_id}
    audit_event("ui_session_finalize", user_sub, req, outcome="pending", challenge_id=body.challenge_id, passed=chal.get("passed", {}))
    return {"status": "pending", "required_factors": chal.get("required_factors", []), "passed": chal.get("passed", {})}

@router.get("/me")
async def ui_me(req: Request, ctx: Dict[str, str] = Depends(require_ui_session)):
    return {"user_sub": ctx["user_sub"], "session_id": ctx["session_id"], "ip": client_ip_from_request(req)}

@router.get("/sessions")
async def ui_sessions(ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    cur = ctx["session_id"]
    r = T.sessions.query(KeyConditionExpression=Key("user_sub").eq(user_sub), Limit=200)
    out = []
    for it in r.get("Items", []):
        sid = it.get("session_id","")
        if not is_real_ui_session_id(sid):
            continue
        if it.get("revoked") and sid != cur:
            continue
        out.append({
            "session_id": sid,
            "is_current": sid == cur,
            "created_at": it.get("created_at",0),
            "last_seen_at": it.get("last_seen_at",0),
            "ip": it.get("ip",""),
            "user_agent": it.get("user_agent",""),
            "revoked": it.get("revoked",False),
            "revoked_at": it.get("revoked_at",0),
        })
    out.sort(key=lambda x: x.get("created_at",0), reverse=True)
    return {"sessions": out}

@router.post("/sessions/revoke")
async def ui_sessions_revoke(
    req: Request,
    body: Dict[str, Any],
    response: Response = None,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    if response is None:
        response = Response()
    target = body.get("session_id","")
    if not target:
        return {"status":"error","reason":"missing session_id"}
    T.sessions.update_item(Key={"user_sub": ctx["user_sub"], "session_id": target}, UpdateExpression="SET revoked=:t, revoked_at=:now", ExpressionAttributeValues={":t": True, ":now": now_ts()})
    if is_real_ui_session_id(target):
        record_session_revoked(ctx["user_sub"])
    audit_event("ui_session_revoke", ctx["user_sub"], req, outcome="success", session_id=target)
    if target == ctx["session_id"]:
        clear_session_cookies(response)
    return {"status":"ok"}

@router.post("/session/logout")
async def ui_session_logout(
    req: Request,
    response: Response = None,
    ctx: Dict[str, str] = Depends(require_ui_session),
):
    if response is None:
        response = Response()
    T.sessions.update_item(
        Key={"user_sub": ctx["user_sub"], "session_id": ctx["session_id"]},
        UpdateExpression="SET revoked=:t, revoked_at=:now",
        ExpressionAttributeValues={":t": True, ":now": now_ts()},
    )
    record_session_revoked(ctx["user_sub"])
    audit_event("ui_session_revoke", ctx["user_sub"], req, outcome="success", session_id=ctx["session_id"])
    clear_session_cookies(response)
    return {"status": "ok"}

@router.post("/session/refresh")
async def ui_session_refresh(
    req: Request,
    response: Response,
    user_sub: str = Depends(get_authenticated_user_sub),
):
    session_id = req.cookies.get(S.ui_session_cookie_name) or req.headers.get("X-SESSION-ID", "")
    if not session_id:
        raise HTTPException(401, "Missing session")
    refresh_token = req.cookies.get(S.ui_refresh_token_cookie_name, "")
    rotate_refresh_token(response, user_sub, session_id, refresh_token)
    audit_event("ui_session_refresh", user_sub, req, outcome="success", session_id=session_id)
    return {"status": "ok"}

@router.post("/sessions/revoke_others")
async def ui_sessions_revoke_others(req: Request, ctx: Dict[str, str] = Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    keep = ctx["session_id"]
    r = T.sessions.query(KeyConditionExpression=Key("user_sub").eq(user_sub), Limit=200)
    for it in r.get("Items", []):
        sid = it.get("session_id","")
        if not sid or sid == keep or sid.startswith("chal_") or sid.startswith("rl#"):
            continue
        try:
            T.sessions.update_item(Key={"user_sub": user_sub, "session_id": sid}, UpdateExpression="SET revoked=:t, revoked_at=:now", ExpressionAttributeValues={":t": True, ":now": now_ts()})
        except Exception:
            pass
        if is_real_ui_session_id(sid):
            record_session_revoked(user_sub)
    audit_event("ui_session_revoke_others", user_sub, req, outcome="success")
    return {"status":"ok"}
