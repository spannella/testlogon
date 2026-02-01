from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException, Request

from app.core.normalize import client_ip_from_request
from app.core.time import now_ts
from app.core.tables import T
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


def record_device_login(req: Request, user_sub: str) -> Dict[str, Any]:
    ip = client_ip_from_request(req)
    user_agent = (req.headers.get("user-agent", "")[:512])
    device_id = _device_id(user_agent)
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
        })
        audit_event("device_new", user_sub, req, outcome="info", device_id=device_id, ip=ip, ip_prefix=ip_prefix)
        return {"device_id": device_id, "new_device": True, "location_mismatch": False}

    last_prefix = it.get("last_ip_prefix", "")
    location_mismatch = bool(last_prefix and ip_prefix and last_prefix != ip_prefix)
    if location_mismatch:
        audit_event("device_location_mismatch", user_sub, req, outcome="warning", device_id=device_id, ip=ip, ip_prefix=ip_prefix, previous_ip_prefix=last_prefix)

    try:
        T.sessions.update_item(
            Key={"user_sub": user_sub, "session_id": sid},
            UpdateExpression="SET last_seen_at=:t, last_ip=:ip, last_ip_prefix=:p, user_agent=:ua",
            ExpressionAttributeValues={":t": ts, ":ip": ip, ":p": ip_prefix, ":ua": user_agent},
        )
    except Exception:
        pass

    return {"device_id": device_id, "new_device": False, "location_mismatch": location_mismatch}


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
