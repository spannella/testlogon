from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import Depends, Header, HTTPException, Request

from app.auth.deps import get_authenticated_user_sub
from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.ttl import with_ttl

def is_real_ui_session_id(session_id: str) -> bool:
    if session_id.startswith("chal_") or session_id.startswith("rl#"):
        return False
    if "_" in session_id:
        return False
    return len(session_id) == 36 and session_id.count("-") == 4

async def require_ui_session(
    request: Request,
    user_sub: str = Depends(get_authenticated_user_sub),
    x_session_id: Optional[str] = Header(default=None, alias="X-SESSION-ID"),
) -> Dict[str, str]:
    if not x_session_id:
        raise HTTPException(401, "Missing X-SESSION-ID")
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": x_session_id}).get("Item")
    if not it:
        raise HTTPException(401, "Unknown session")
    if it.get("revoked", False):
        raise HTTPException(401, "Session revoked")
    if it.get("pending_auth", False):
        raise HTTPException(401, "Session not finalized")

    ts = now_ts()
    last = int(it.get("last_seen_at", 0) or 0)
    if last and (ts - last) > S.ui_inactivity_seconds:
        T.sessions.update_item(Key={"user_sub": user_sub, "session_id": x_session_id}, UpdateExpression="SET revoked=:t", ExpressionAttributeValues={":t": True})
        raise HTTPException(401, "Session expired (inactive)")

    # Touch last_seen (best effort)
    try:
        T.sessions.update_item(Key={"user_sub": user_sub, "session_id": x_session_id}, UpdateExpression="SET last_seen_at=:t", ExpressionAttributeValues={":t": ts})
    except Exception:
        pass

    request.state.user_sub = user_sub
    return {"user_sub": user_sub, "session_id": x_session_id}

def create_real_session(req: Request, user_sub: str) -> str:
    session_id = str(uuid.uuid4())
    ts = now_ts()
    ttl = ts + S.ui_session_ttl_seconds
    T.sessions.put_item(Item=with_ttl({
        "user_sub": user_sub,
        "session_id": session_id,
        "created_at": ts,
        "last_seen_at": ts,
        "ip": client_ip_from_request(req),
        "user_agent": (req.headers.get("user-agent", "")[:512]),
        "revoked": False,
        "pending_auth": False,
    }, ttl_epoch=ttl))
    return session_id

def load_challenge_or_401(user_sub: str, challenge_id: str) -> Dict[str, Any]:
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": challenge_id}).get("Item")
    if not it or it.get("revoked") or not it.get("pending_auth"):
        raise HTTPException(401, "Invalid challenge")
    ts = now_ts()
    if int(it.get("expires_at", ts + 1)) < ts:
        try:
            T.sessions.update_item(Key={"user_sub": user_sub, "session_id": challenge_id}, UpdateExpression="SET revoked=:t", ExpressionAttributeValues={":t": True})
        except Exception:
            pass
        raise HTTPException(401, "Challenge expired")
    return it

def revoke_challenge(user_sub: str, challenge_id: str) -> None:
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": challenge_id},
            UpdateExpression="SET revoked = :t, #ttl = :ttl, revoked_at = :now",
            ExpressionAttributeNames={"#ttl": S.ddb_ttl_attr},
            ExpressionAttributeValues={":t": True, ":ttl": now_ts() + 3600, ":now": now_ts()},
        )
    except Exception:
        pass

def mark_factor_passed(user_sub: str, challenge_id: str, factor: str) -> None:
    T.sessions.update_item(
        Key={"user_sub": user_sub, "session_id": challenge_id},
        UpdateExpression="SET passed.#f = :t",
        ExpressionAttributeNames={"#f": factor},
        ExpressionAttributeValues={":t": True},
    )

def challenge_done(chal: Dict[str, Any]) -> bool:
    required = chal.get("required_factors", []) or []
    passed = chal.get("passed", {}) or {}
    return all(bool(passed.get(f, False)) for f in required)

def compute_required_factors(user_sub: str) -> List[str]:
    required: List[str] = []
    r1 = T.totp.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    if any(d.get("enabled", False) for d in r1.get("Items", [])):
        required.append("totp")
    r2 = T.sms.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    if any(d.get("enabled", False) for d in r2.get("Items", [])):
        required.append("sms")
    r3 = T.email.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    if any(d.get("enabled", False) for d in r3.get("Items", [])):
        required.append("email")
    return required

def create_stepup_challenge(req: Request, user_sub: str, required_factors: List[str]) -> str:
    challenge_id = "chal_" + uuid.uuid4().hex
    ts = now_ts()
    expires = ts + S.session_challenge_ttl_seconds
    T.sessions.put_item(Item=with_ttl({
        "user_sub": user_sub,
        "session_id": challenge_id,
        "created_at": ts,
        "last_seen_at": ts,
        "ip": client_ip_from_request(req),
        "user_agent": (req.headers.get("user-agent", "")[:512]),
        "revoked": False,
        "pending_auth": True,
        "required_factors": required_factors,
        "passed": {f: False for f in required_factors},
        "expires_at": expires,
    }, ttl_epoch=expires))
    return challenge_id

def maybe_finalize(req: Request, user_sub: str, challenge_id: str) -> Optional[str]:
    chal = load_challenge_or_401(user_sub, challenge_id)
    if not challenge_done(chal):
        return None
    sid = create_real_session(req, user_sub)
    revoke_challenge(user_sub, challenge_id)
    return sid
