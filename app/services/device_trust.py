from __future__ import annotations

import hashlib
import secrets
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException, Request, Response

from app.core.normalize import client_ip_from_request
from app.core.time import now_ts
from app.core.tables import T
from app.core.settings import S
from app.services.alerts import audit_event


def _ip_prefix(ip: str) -> str:
    if not ip:
        return ""
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:4])
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else ip


def _device_id(user_agent: str) -> str:
    ua = (user_agent or "").strip()
    return hashlib.sha256(ua.encode("utf-8")).hexdigest()[:32]

def _device_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _device_token_from_request(req: Request) -> str:
    cookies = getattr(req, "cookies", {}) or {}
    cookie_name = getattr(S, "ui_device_cookie_name", "")
    return cookies.get(cookie_name, "") if cookie_name else ""

def record_device_login(req: Request, user_sub: str) -> Dict[str, Any]:
    if not getattr(S, "ddb_sessions_table", ""):
        return {
            "device_id": "",
            "new_device": False,
            "location_mismatch": False,
            "trusted": True,
            "token_mismatch": False,
            "issue_token": False,
        }
    ip = client_ip_from_request(req)
    user_agent = (req.headers.get("user-agent", "")[:512])
    device_id = _device_id(user_agent)
    token = _device_token_from_request(req)
    token_hash = _device_token_hash(token) if token else ""
    sid = f"dev#{device_id}"
    ts = now_ts()
    ip_prefix = _ip_prefix(ip)
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": sid}).get("Item")
    if not it:
        T.sessions.put_item(Item={
            "user_sub": user_sub,
            "session_id": sid,
            "device_id": device_id,
            "user_agent": user_agent,
            "first_seen_at": ts,
            "last_seen_at": ts,
            "last_ip": ip,
            "last_ip_prefix": ip_prefix,
            "trusted": False,
            "token_hash": token_hash,
        })
        audit_event("device_new", user_sub, req, outcome="info", device_id=device_id, ip=ip, ip_prefix=ip_prefix)
        return {
            "device_id": device_id,
            "new_device": True,
            "location_mismatch": False,
            "trusted": False,
            "token_mismatch": False,
            "issue_token": not token,
        }

    last_prefix = it.get("last_ip_prefix", "")
    trusted = bool(it.get("trusted", False))
    location_mismatch = bool(last_prefix and ip_prefix and last_prefix != ip_prefix)
    stored_hash = it.get("token_hash", "") or ""
    token_mismatch = bool(stored_hash and token_hash and stored_hash != token_hash)
    issue_token = bool(not token or token_mismatch or not stored_hash)
    if location_mismatch:
        audit_event("device_location_mismatch", user_sub, req, outcome="warning", device_id=device_id, ip=ip, ip_prefix=ip_prefix, previous_ip_prefix=last_prefix)

    try:
        update_expr = "SET last_seen_at=:t, last_ip=:ip, last_ip_prefix=:p, user_agent=:ua"
        values = {":t": ts, ":ip": ip, ":p": ip_prefix, ":ua": user_agent}
        if token_hash and not stored_hash:
            update_expr += ", token_hash=:th"
            values[":th"] = token_hash
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": sid},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=values,
        )
    except Exception:
        pass

    return {
        "device_id": device_id,
        "new_device": False,
        "location_mismatch": location_mismatch,
        "trusted": trusted,
        "token_mismatch": token_mismatch,
        "issue_token": issue_token,
    }

def ensure_device_cookie(req: Request, response: Response, user_sub: str) -> Optional[str]:
    if not getattr(S, "ddb_sessions_table", ""):
        return None
    user_agent = (req.headers.get("user-agent", "")[:512])
    device_id = _device_id(user_agent)
    sid = f"dev#{device_id}"
    token = _device_token_from_request(req)
    token_hash = _device_token_hash(token) if token else ""
    it = T.sessions.get_item(Key={"user_sub": user_sub, "session_id": sid}).get("Item") or {}
    stored_hash = it.get("token_hash", "") or ""
    if stored_hash and token_hash and stored_hash == token_hash:
        return None
    new_token = secrets.token_urlsafe(32)
    new_hash = _device_token_hash(new_token)
    try:
        if it:
            T.sessions.update_item(
                Key={"user_sub": user_sub, "session_id": sid},
                UpdateExpression="SET token_hash=:h, token_issued_at=:t",
                ExpressionAttributeValues={":h": new_hash, ":t": now_ts()},
            )
        else:
            T.sessions.put_item(Item={
                "user_sub": user_sub,
                "session_id": sid,
                "device_id": device_id,
                "user_agent": user_agent,
                "first_seen_at": now_ts(),
                "last_seen_at": now_ts(),
                "last_ip": client_ip_from_request(req),
                "last_ip_prefix": _ip_prefix(client_ip_from_request(req)),
                "trusted": False,
                "token_hash": new_hash,
                "token_issued_at": now_ts(),
            })
    except Exception:
        pass
    response.set_cookie(
        S.ui_device_cookie_name,
        new_token,
        max_age=S.ui_device_cookie_ttl_seconds,
        httponly=True,
        secure=S.ui_cookie_secure,
        samesite=S.ui_cookie_samesite,
    )
    return device_id


def trust_current_device(req: Request, user_sub: str) -> str:
    info = record_device_login(req, user_sub)
    device_id = info["device_id"]
    _update_trust(user_sub, device_id, True)
    return device_id


def list_devices(user_sub: str) -> List[Dict[str, Any]]:
    r = T.sessions.query(KeyConditionExpression=Key("user_sub").eq(user_sub), Limit=200)
    out = []
    for it in r.get("Items", []):
        sid = it.get("session_id", "")
        if not sid.startswith("dev#"):
            continue
        out.append({
            "device_id": it.get("device_id", sid.replace("dev#", "")),
            "user_agent": it.get("user_agent", ""),
            "first_seen_at": it.get("first_seen_at", 0),
            "last_seen_at": it.get("last_seen_at", 0),
            "last_ip": it.get("last_ip", ""),
            "trusted": bool(it.get("trusted", False)),
        })
    out.sort(key=lambda x: int(x.get("last_seen_at") or 0), reverse=True)
    return out


def _update_trust(user_sub: str, device_id: str, trusted: bool) -> None:
    sid = f"dev#{device_id}"
    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": sid},
            UpdateExpression="SET trusted=:t, trust_updated_at=:now",
            ExpressionAttributeValues={":t": trusted, ":now": now_ts()},
        )
    except Exception:
        raise HTTPException(404, "Device not found")


def trust_device(user_sub: str, device_id: str) -> None:
    _update_trust(user_sub, device_id, True)


def revoke_device(user_sub: str, device_id: str) -> None:
    _update_trust(user_sub, device_id, False)
