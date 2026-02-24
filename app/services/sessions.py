from __future__ import annotations

import hmac
import secrets
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jwt
from boto3.dynamodb.conditions import Key
from fastapi import Depends, Header, HTTPException, Request, Response

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role, normalize_role
from app.core.crypto import sha256_str
from app.core.normalize import client_ip_from_request
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.metrics import record_session_created, record_session_revoked
from app.services.device_trust import ensure_device_cookie, record_device_login
from app.services.ttl import with_ttl

@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    csrf_token: str
    user_sub: str


def _is_root_user(user_sub: str) -> bool:
    return user_sub == (S.root_user_sub or "").strip()


def _session_ttl_seconds_for_user(user_sub: str) -> int:
    if _is_root_user(user_sub):
        return max(60, int(getattr(S, "root_session_ttl_seconds", 3600)))
    return int(S.ui_session_ttl_seconds)


def _access_ttl_seconds_for_user(user_sub: str) -> int:
    if _is_root_user(user_sub):
        return max(60, int(getattr(S, "root_access_token_ttl_seconds", 300)))
    return int(S.ui_access_token_ttl_seconds)


def _refresh_ttl_seconds_for_user(user_sub: str, explicit_ttl: Optional[int] = None) -> int:
    if explicit_ttl and explicit_ttl > 0:
        return int(explicit_ttl)
    if _is_root_user(user_sub):
        return max(60, int(getattr(S, "root_refresh_token_ttl_seconds", 1800)))
    return int(S.ui_refresh_token_ttl_seconds)

def _coerce_session_info(session: SessionInfo | str, user_sub: str) -> SessionInfo:
    if isinstance(session, SessionInfo):
        return session
    session_id = session.session_id if hasattr(session, "session_id") else str(session)
    csrf_token = ""
    if hasattr(session, "csrf_token"):
        csrf_token = session.csrf_token
    if not csrf_token:
        if getattr(S, "ddb_sessions_table", ""):
            try:
                it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": session_id}).get("Item") or {}
                csrf_token = it.get("csrf_token", "")
            except Exception:
                csrf_token = ""
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
    return SessionInfo(session_id=session_id, csrf_token=csrf_token, user_sub=user_sub)

def session_id_value(session: SessionInfo | str) -> str:
    if isinstance(session, SessionInfo):
        return session.session_id
    return session.session_id if hasattr(session, "session_id") else str(session)

def set_session_cookies(response: Response, session: SessionInfo, *, refresh_ttl_seconds: Optional[int] = None) -> None:
    session_ttl = _session_ttl_seconds_for_user(session.user_sub)
    access_ttl = _access_ttl_seconds_for_user(session.user_sub)
    refresh_ttl = _refresh_ttl_seconds_for_user(session.user_sub, refresh_ttl_seconds)
    response.set_cookie(
        S.ui_session_cookie_name,
        session.session_id,
        max_age=session_ttl,
        httponly=True,
        secure=S.ui_cookie_secure,
        samesite=S.ui_cookie_samesite,
    )
    _issue_refresh_token(response, session.session_id, session.user_sub, refresh_ttl_seconds=refresh_ttl)
    access = mint_access_token(session.user_sub, session.session_id)
    if access:
        response.set_cookie(
            S.ui_access_token_cookie_name,
            access,
            max_age=_access_ttl_seconds_for_user(user_sub),
            httponly=True,
            secure=S.ui_cookie_secure,
            samesite=S.ui_cookie_samesite,
        )
    response.set_cookie(
        S.ui_csrf_cookie_name,
        session.csrf_token,
        max_age=session_ttl,
        httponly=False,
        secure=S.ui_cookie_secure,
        samesite=S.ui_cookie_samesite,
    )

def revoke_session(user_sub: str, session_id: str) -> None:
    if not session_id:
        return
    ts = now_ts()
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": session_id},
            UpdateExpression="SET revoked=:t, revoked_at=:now",
            ExpressionAttributeValues={":t": True, ":now": ts},
        )
    except Exception:
        pass
    if is_real_ui_session_id(session_id):
        record_session_revoked(user_sub)

def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(S.ui_session_cookie_name)
    response.delete_cookie(S.ui_csrf_cookie_name)
    response.delete_cookie(S.ui_access_token_cookie_name)
    response.delete_cookie(S.ui_refresh_token_cookie_name)

def rotate_session_cookies(
    request: Request,
    response: Response,
    user_sub: str,
    session: SessionInfo | str,
    *,
    refresh_ttl_seconds: Optional[int] = None,
) -> None:
    session = _coerce_session_info(session, user_sub)
    prior = (getattr(request, "cookies", {}) or {}).get(S.ui_session_cookie_name)
    if prior and prior != session.session_id:
        revoke_session(user_sub, prior)
    set_session_cookies(response, session, refresh_ttl_seconds=refresh_ttl_seconds)
    ensure_device_cookie(request, response, user_sub)

def rotate_existing_session(
    request: Request,
    response: Response,
    ctx: Dict[str, str],
    *,
    mfa_verified_at: Optional[int] = None,
    refresh_ttl_seconds: Optional[int] = None,
) -> SessionInfo:
    session = create_real_session(request, ctx["user_sub"], mfa_verified_at=mfa_verified_at, refresh_ttl_seconds=refresh_ttl_seconds)
    revoke_session(ctx["user_sub"], ctx["session_id"])
    set_session_cookies(response, session, refresh_ttl_seconds=refresh_ttl_seconds)
    ensure_device_cookie(request, response, ctx["user_sub"])
    return session

def is_real_ui_session_id(session_id: str) -> bool:
    if isinstance(session_id, SessionInfo):
        session_id = session_id.session_id
    elif hasattr(session_id, "session_id"):
        session_id = session_id.session_id
    if session_id.startswith("chal_") or session_id.startswith("rl#"):
        return False
    if "_" in session_id:
        return False
    return len(session_id) == 36 and session_id.count("-") == 4

def mint_access_token(user_sub: str, session_id: str) -> str:
    if not S.ui_access_token_secret:
        return ""
    access_ttl = _access_ttl_seconds_for_user(user_sub)
    role = "root" if _is_root_user(user_sub) else "user"
    auth_level = "high" if role == "root" else "standard"
    payload = {
        "sub": user_sub,
        "sid": session_id,
        "role": role,
        "auth_level": auth_level,
        "exp": now_ts() + access_ttl,
        "iat": now_ts(),
    }
    return jwt.encode(payload, S.ui_access_token_secret, algorithm="HS256")

def _issue_refresh_token(response: Response, session_id: str, user_sub: str, *, refresh_ttl_seconds: Optional[int] = None) -> None:
    token = secrets.token_urlsafe(48)
    token_hash = sha256_str(token)
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": session_id},
            UpdateExpression="SET refresh_token_hash=:h, refresh_token_issued_at=:t",
            ExpressionAttributeValues={":h": token_hash, ":t": now_ts()},
        )
    except Exception:
        pass
    response.set_cookie(
        S.ui_refresh_token_cookie_name,
        token,
        max_age=_refresh_ttl_seconds_for_user(user_sub, refresh_ttl_seconds),
        httponly=True,
        secure=S.ui_cookie_secure,
        samesite=S.ui_cookie_samesite,
    )



def _resolve_impersonation_context(request: Request, actor_sub: str, token: str) -> Dict[str, str]:
    if not token:
        return {}
    if not S.ui_access_token_secret:
        raise HTTPException(401, "Impersonation token validation unavailable")
    try:
        payload = jwt.decode(token, S.ui_access_token_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(401, "impersonation_expired") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "Invalid impersonation token") from exc

    if not payload.get("impersonation"):
        raise HTTPException(401, "Invalid impersonation token")

    token_actor = str(payload.get("actor_sub") or payload.get("sub") or "").strip()
    effective_sub = str(payload.get("effective_sub") or "").strip()
    imp_sid = str(payload.get("sid") or "").strip()
    if not token_actor or not effective_sub or not imp_sid or token_actor != actor_sub:
        raise HTTPException(401, "Invalid impersonation token")

    it = T.sessions.get_item(Key={"user_sub": actor_sub, "session_id": imp_sid}).get("Item") or {}
    if not it or it.get("purpose") != "impersonation":
        raise HTTPException(401, "Invalid impersonation token")
    if it.get("revoked"):
        raise HTTPException(401, "Impersonation revoked")
    ts = now_ts()
    if int(it.get("expires_at") or 0) <= ts:
        try:
            T.sessions.update_item(
                Key={"user_sub": actor_sub, "session_id": imp_sid},
                UpdateExpression="SET revoked=:t, revoked_at=:now",
                ExpressionAttributeValues={":t": True, ":now": ts},
            )
        except Exception:
            pass
        raise HTTPException(401, "impersonation_expired")

    return {
        "actor_sub": actor_sub,
        "effective_sub": effective_sub,
        "impersonation_id": imp_sid,
        "impersonation": "true",
    }

def rotate_refresh_token(response: Response, user_sub: str, session_id: str, refresh_token: str) -> None:
    if not refresh_token:
        raise HTTPException(400, "Missing refresh token")
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": session_id}).get("Item") or {}
    stored = it.get("refresh_token_hash", "")
    if not stored or not hmac.compare_digest(stored, sha256_str(refresh_token)):
        raise HTTPException(401, "Invalid refresh token")
    refresh_ttl = int(it.get("refresh_ttl_seconds") or 0)
    _issue_refresh_token(response, session_id, user_sub, refresh_ttl_seconds=refresh_ttl or None)
    access = mint_access_token(user_sub, session_id)
    if access:
        response.set_cookie(
            S.ui_access_token_cookie_name,
            access,
            max_age=_access_ttl_seconds_for_user(user_sub),
            httponly=True,
            secure=S.ui_cookie_secure,
            samesite=S.ui_cookie_samesite,
        )

async def require_ui_session(
    request: Request,
    auth_user: Optional[AuthenticatedUser] = Depends(get_authenticated_user),
    user_sub: Optional[str] = None,
    x_session_id: Optional[str] = Header(default=None, alias="X-SESSION-ID"),
    x_impersonation_token: Optional[str] = Header(default=None, alias="X-IMPERSONATION-TOKEN"),
) -> Dict[str, str]:
    resolved_user_sub = user_sub or (auth_user.sub if auth_user else "")
    if not resolved_user_sub:
        raise HTTPException(401, "Missing user")
    role: Role = normalize_role(getattr(auth_user, "role", None))
    session_id = None
    cookies = getattr(request, "cookies", {}) or {}
    headers = getattr(request, "headers", {}) or {}
    method = getattr(request, "method", "GET")
    access_cookie_name = getattr(S, "ui_access_token_cookie_name", "")
    access_secret = getattr(S, "ui_access_token_secret", "")
    access_cookie = cookies.get(access_cookie_name) if access_cookie_name else None
    if access_cookie and access_secret:
        try:
            payload = jwt.decode(access_cookie, access_secret, algorithms=["HS256"])
            session_id = payload.get("sid")
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(401, "Access token expired") from exc
        except jwt.PyJWTError:
            session_id = None
    session_cookie_name = getattr(S, "ui_session_cookie_name", "")
    session_cookie = cookies.get(session_cookie_name) if session_cookie_name else None
    session_id = session_id or session_cookie or x_session_id
    if not session_id:
        raise HTTPException(401, "Missing session")
    it = T.sessions.get_item(Key={"user_sub": resolved_user_sub, "session_id": session_id}).get("Item")
    if not it:
        raise HTTPException(401, "Unknown session")
    if it.get("revoked", False):
        raise HTTPException(401, "Session revoked")
    if it.get("pending_auth", False):
        raise HTTPException(401, "Session not finalized")

    ts = now_ts()
    ttl_attr = getattr(S, "ddb_ttl_attr", "")
    ttl_epoch = int(it.get(ttl_attr, 0) or 0) if ttl_attr else 0
    if ttl_epoch and ttl_epoch <= ts:
        try:
            T.sessions.update_item(
                Key={"user_sub": resolved_user_sub, "session_id": session_id},
                UpdateExpression="SET revoked=:t, revoked_at=:now",
                ExpressionAttributeValues={":t": True, ":now": ts},
            )
        except Exception:
            pass
        raise HTTPException(401, "Session expired")
    last = int(it.get("last_seen_at", 0) or 0)
    inactivity_seconds = getattr(S, "ui_inactivity_seconds", 0)
    if last and inactivity_seconds and (ts - last) > inactivity_seconds:
        T.sessions.update_item(Key={"user_sub": resolved_user_sub, "session_id": session_id}, UpdateExpression="SET revoked=:t", ExpressionAttributeValues={":t": True})
        raise HTTPException(401, "Session expired (inactive)")

    if getattr(S, "ddb_sessions_table", ""):
        device_info = record_device_login(request, resolved_user_sub)
        if not device_info.get("trusted", False) and (
            device_info.get("new_device")
            or device_info.get("location_mismatch")
            or device_info.get("token_mismatch")
        ):
            if compute_required_factors(user_sub):
                require_fresh_mfa({"user_sub": resolved_user_sub, "session_id": session_id})
            else:
                raise HTTPException(401, "Re-auth required")

    csrf_header_name = getattr(S, "ui_csrf_header_name", "")
    csrf_cookie_name = getattr(S, "ui_csrf_cookie_name", "")
    if session_cookie and method.upper() not in ("GET", "HEAD", "OPTIONS"):
        csrf_header = headers.get(csrf_header_name, "") if csrf_header_name else ""
        csrf_cookie = cookies.get(csrf_cookie_name, "") if csrf_cookie_name else ""
        expected = it.get("csrf_token", "")
        if not expected or not csrf_cookie or not csrf_header:
            raise HTTPException(403, "Missing CSRF token")
        if csrf_header != csrf_cookie or csrf_cookie != expected:
            raise HTTPException(403, "CSRF validation failed")

    # Touch last_seen (best effort)
    try:
        T.sessions.update_item(Key={"user_sub": resolved_user_sub, "session_id": session_id}, UpdateExpression="SET last_seen_at=:t", ExpressionAttributeValues={":t": ts})
    except Exception:
        pass

    imp_token = x_impersonation_token if isinstance(x_impersonation_token, str) else ""
    impersonation_ctx = _resolve_impersonation_context(request, resolved_user_sub, imp_token)

    request.state.user_sub = resolved_user_sub
    request.state.user_role = role.value
    if impersonation_ctx:
        request.state.actor_sub = impersonation_ctx["actor_sub"]
        request.state.effective_sub = impersonation_ctx["effective_sub"]
        request.state.impersonation_id = impersonation_ctx["impersonation_id"]

    out = {
        "user_sub": resolved_user_sub,
        "session_id": session_id,
        "role": role.value,
        "ip": str(it.get("ip") or ""),
    }
    out.update(impersonation_ctx)
    return out

def create_real_session(req: Request, user_sub: str, *, mfa_verified_at: Optional[int] = None, risk_score: int = 0, refresh_ttl_seconds: Optional[int] = None) -> SessionInfo:
    session_id = str(uuid.uuid4())
    csrf_token = secrets.token_urlsafe(32)
    ts = now_ts()
    ttl = ts + _session_ttl_seconds_for_user(user_sub)
    is_new_user = _is_new_user(user_sub)
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "session_id": session_id,
        "csrf_token": csrf_token,
        "created_at": ts,
        "last_seen_at": ts,
        "ip": client_ip_from_request(req),
        "user_agent": (req.headers.get("user-agent", "")[:512]),
        "revoked": False,
        "pending_auth": False,
    }
    if mfa_verified_at:
        item["mfa_verified_at"] = mfa_verified_at
    if risk_score > 0:
        item["risk_score"] = risk_score
        item["risk_level"] = "high" if risk_score >= getattr(S, "login_anomaly_risk_score_threshold", 1) else "elevated"
    item["refresh_ttl_seconds"] = _refresh_ttl_seconds_for_user(user_sub, refresh_ttl_seconds)
    T.sessions.put_item(Item=with_ttl(item, ttl_epoch=ttl))
    try:
        record_device_login(req, user_sub)
    except Exception:
        pass
    record_session_created(user_sub, is_new_user)
    return SessionInfo(session_id=session_id, csrf_token=csrf_token, user_sub=user_sub)


def _is_new_user(user_sub: str) -> bool:
    try:
        r = T.sessions.query(KeyConditionExpression=Key("user_sub").eq(user_sub), Limit=200)
        for it in r.get("Items", []):
            sid = it.get("session_id", "")
            if is_real_ui_session_id(sid) and not it.get("pending_auth", False):
                return False
        return True
    except Exception:
        return False

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
    try:
        r1 = T.totp.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    except Exception:
        r1 = {"Items": []}
    if any(d.get("enabled", False) for d in r1.get("Items", [])):
        required.append("totp")
    try:
        r2 = T.sms.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    except Exception:
        r2 = {"Items": []}
    if any(d.get("enabled", False) for d in r2.get("Items", [])):
        required.append("sms")
    try:
        r3 = T.email.query(KeyConditionExpression=Key("user_sub").eq(user_sub))
    except Exception:
        r3 = {"Items": []}
    if any(d.get("enabled", False) for d in r3.get("Items", [])):
        required.append("email")
    return required

def create_stepup_challenge(
    req: Request,
    user_sub: str,
    required_factors: List[str],
    *,
    purpose: Optional[str] = None,
    risk_score: int = 0,
    refresh_ttl_seconds: Optional[int] = None,
) -> str:
    challenge_id = "chal_" + uuid.uuid4().hex
    ts = now_ts()
    expires = ts + S.session_challenge_ttl_seconds
    item: Dict[str, Any] = {
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
    }
    if purpose:
        item["purpose"] = purpose
    if risk_score > 0:
        item["risk_score"] = risk_score
    item["refresh_ttl_seconds"] = _refresh_ttl_seconds_for_user(user_sub, refresh_ttl_seconds)
    T.sessions.put_item(Item=with_ttl(item, ttl_epoch=expires))
    return challenge_id

def create_action_challenge(
    req: Request,
    user_sub: str,
    purpose: str,
    send_to: List[str],
    payload: Dict[str, Any],
    ttl_seconds: int = 300,
) -> str:
    challenge_id = f"{purpose}_" + uuid.uuid4().hex
    ts = now_ts()
    expires = ts + ttl_seconds
    item: Dict[str, Any] = {
        "user_sub": user_sub,
        "session_id": challenge_id,
        "created_at": ts,
        "expires_at": expires,
        "revoked": False,
        "pending_auth": True,
        "purpose": purpose,
        "send_to": send_to,
        "ip": client_ip_from_request(req),
        "user_agent": (req.headers.get("user-agent", "")[:512]),
    }
    item.update(payload or {})
    T.sessions.put_item(Item=with_ttl(item, ttl_epoch=expires))
    return challenge_id

def maybe_finalize(req: Request, user_sub: str, challenge_id: str) -> Optional[SessionInfo]:
    chal = load_challenge_or_401(user_sub, challenge_id)
    if not challenge_done(chal):
        return None
    if chal.get("purpose"):
        return None
    sid = create_real_session(
        req,
        user_sub,
        mfa_verified_at=now_ts(),
        risk_score=int(chal.get("risk_score") or 0),
        refresh_ttl_seconds=int(chal.get("refresh_ttl_seconds") or 0) or None,
    )
    revoke_challenge(user_sub, challenge_id)
    return sid

def revoke_all_sessions(user_sub: str) -> None:
    last_key = None
    ts = now_ts()
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub),
            "Limit": 200,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.sessions.query(**kwargs)
        items = resp.get("Items", [])
        for it in items:
            sid = it.get("session_id", "")
            if not sid:
                continue
            try:
                T.sessions.update_item(
                    Key={"user_sub": user_sub, "session_id": sid},
                    UpdateExpression="SET revoked=:t, revoked_at=:now",
                    ExpressionAttributeValues={":t": True, ":now": ts},
                )
            except Exception:
                pass
            if is_real_ui_session_id(sid):
                record_session_revoked(user_sub)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

def require_fresh_mfa(ctx: Dict[str, str], *, max_age_seconds: Optional[int] = None) -> None:
    required = compute_required_factors(ctx["user_sub"])
    if not required:
        return
    max_age = max_age_seconds or S.ui_stepup_max_age_seconds
    it = T.sessions.get_item(Key={"user_sub": ctx["user_sub"], "session_id": ctx["session_id"]}).get("Item") or {}
    verified_at = int(it.get("mfa_verified_at", 0) or 0)
    if not verified_at or (now_ts() - verified_at) > max_age:
        raise HTTPException(401, "Fresh MFA required")
