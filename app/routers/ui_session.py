from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from boto3.dynamodb.conditions import Key

from app.auth.deps import get_authenticated_user_sub
from app.models import UiSessionFinalizeReq, UiSessionStartReq, UiSessionStartResp
from app.core.normalize import client_ip_from_request
from app.services.alerts import audit_event
from app.services.sessions import (
    compute_required_factors,
    create_real_session,
    create_stepup_challenge,
    load_challenge_or_401,
    maybe_finalize,
    require_ui_session,
)
from app.core.tables import T
from app.core.time import now_ts

router = APIRouter(prefix="/ui", tags=["ui-session"])

@router.post("/session/start", response_model=UiSessionStartResp)
async def ui_session_start(req: Request, body: UiSessionStartReq, user_sub: str = Depends(get_authenticated_user_sub)):
    required = compute_required_factors(user_sub)
    if not required:
        sid = create_real_session(req, user_sub)
        audit_event("ui_session_start", user_sub, req, outcome="success", session_id=sid)
        return UiSessionStartResp(auth_required=False, session_id=sid, required_factors=[])
    challenge_id = create_stepup_challenge(req, user_sub, required_factors=required)
    audit_event("ui_session_start", user_sub, req, outcome="info", required_factors=required, challenge_id=challenge_id)
    return UiSessionStartResp(auth_required=True, challenge_id=challenge_id, required_factors=required)

@router.post("/session/finalize")
async def ui_session_finalize(req: Request, body: UiSessionFinalizeReq, user_sub: str = Depends(get_authenticated_user_sub)):
    chal = load_challenge_or_401(user_sub, body.challenge_id)
    sid = maybe_finalize(req, user_sub, body.challenge_id)
    if sid:
        audit_event("ui_session_finalize", user_sub, req, outcome="success", challenge_id=body.challenge_id, session_id=sid)
        return {"status": "ok", "session_id": sid}
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
        if not sid or sid.startswith("chal_") or sid.startswith("rl#"):
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
async def ui_sessions_revoke(req: Request, body: Dict[str, Any], ctx: Dict[str, str] = Depends(require_ui_session)):
    target = body.get("session_id","")
    if not target:
        return {"status":"error","reason":"missing session_id"}
    T.sessions.update_item(Key={"user_sub": ctx["user_sub"], "session_id": target}, UpdateExpression="SET revoked=:t, revoked_at=:now", ExpressionAttributeValues={":t": True, ":now": now_ts()})
    audit_event("ui_session_revoke", ctx["user_sub"], req, outcome="success", session_id=target)
    return {"status":"ok"}

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
    audit_event("ui_session_revoke_others", user_sub, req, outcome="success")
    return {"status":"ok"}
