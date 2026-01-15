from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.crypto import sha256_str
from app.core.normalize import normalize_cidr, ip_in_any_cidr
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.ttl import with_ttl

def new_api_key_secret() -> str:
    return secrets.token_urlsafe(32)

def parse_api_key(api_key: str) -> Dict[str, str]:
    if not api_key or not api_key.startswith("ak_") or "." not in api_key:
        raise HTTPException(401, "Invalid API key format")
    kid, secret = api_key.split(".", 1)
    key_id = kid[len("ak_"):]
    if not key_id or not secret:
        raise HTTPException(401, "Invalid API key format")
    return {"key_id": key_id, "secret": secret}

def api_key_hash(secret: str) -> str:
    if not S.api_key_pepper:
        raise RuntimeError("API_KEY_PEPPER not set")
    return sha256_str(secret + "|" + S.api_key_pepper)

def create_api_key(user_sub: str, label: str) -> Dict[str, Any]:
    ts = now_ts()
    key_id = secrets.token_hex(16)
    secret = new_api_key_secret()
    secret_hash = api_key_hash(secret)
    ttl = ts + 365 * 86400  # 1y; rotate as you like

    item = with_ttl({
        "key_id": key_id,
        "user_sub": user_sub,
        "secret_hash": secret_hash,
        "label": (label or "")[:64],
        "created_at": ts,
        "last_used_at": 0,
        "revoked": False,
        "revoked_at": 0,
        "prefix": f"ak_{key_id[:8]}",
        "allow_cidrs": [],
        "deny_cidrs": [],
    }, ttl_epoch=ttl)

    T.api_keys.put_item(Item=item)
    return {"key_id": key_id, "api_key": f"ak_{key_id}.{secret}", "label": item["label"], "created_at": ts}

def revoke_api_key(user_sub: str, key_id: str) -> None:
    try:
        T.api_keys.update_item(
            Key={"key_id": key_id},
            UpdateExpression="SET revoked = :t, revoked_at = :now",
            ConditionExpression="user_sub = :u",
            ExpressionAttributeValues={":t": True, ":now": now_ts(), ":u": user_sub},
        )
    except Exception:
        raise HTTPException(404, "API key not found")

def set_api_key_ip_rules(user_sub: str, key_id: str, allow_cidrs: List[str], deny_cidrs: List[str]) -> Dict[str, List[str]]:
    allow = [normalize_cidr(r) for r in (allow_cidrs or []) if (r or "").strip()]
    deny = [normalize_cidr(r) for r in (deny_cidrs or []) if (r or "").strip()]
    try:
        T.api_keys.update_item(
            Key={"key_id": key_id},
            UpdateExpression="SET allow_cidrs = :a, deny_cidrs = :d, updated_at=:now",
            ConditionExpression="user_sub = :u",
            ExpressionAttributeValues={":a": allow, ":d": deny, ":u": user_sub, ":now": now_ts()},
        )
    except Exception:
        raise HTTPException(404, "API key not found")
    return {"allow_cidrs": allow, "deny_cidrs": deny}

def list_api_keys(user_sub: str) -> List[Dict[str, Any]]:
    r = T.api_keys.query(IndexName=S.api_keys_user_index, KeyConditionExpression=Key("user_sub").eq(user_sub), ScanIndexForward=False, Limit=100)
    out = []
    for it in r.get("Items", []):
        out.append({
            "key_id": it.get("key_id") or it.get("api_key_id"),
            "label": it.get("label",""),
            "created_at": it.get("created_at",0),
            "last_used_at": it.get("last_used_at", 0),
            "revoked": it.get("revoked",False),
            "revoked_at": it.get("revoked_at",0),
            "prefix": it.get("prefix",""),
            "allow_cidrs": it.get("allow_cidrs", []),
            "deny_cidrs": it.get("deny_cidrs", []),
        })
    out.sort(key=lambda x: int(x.get("created_at") or 0), reverse=True)
    return out

def enforce_api_key_ip_rules(client_ip: str, key_item: Dict[str, Any]) -> None:
    allow = key_item.get("allow_cidrs") or []
    deny = key_item.get("deny_cidrs") or []
    if not allow and not deny:
        return
    if allow and not ip_in_any_cidr(client_ip, allow):
        raise HTTPException(403, "API key not allowed from this IP")
    if deny and ip_in_any_cidr(client_ip, deny):
        raise HTTPException(403, "API key denied from this IP")

def check_api_key_allowed(api_key_id: str, api_key_secret: str, client_ip: str) -> Dict[str, Any]:
    it = T.api_keys.get_item(Key={"key_id": api_key_id}).get("Item")
    if not it or it.get("revoked", False):
        raise HTTPException(401, "Invalid API key")
    enforce_api_key_ip_rules(client_ip, it)
    if api_key_hash(api_key_secret) != it.get("secret_hash"):
        raise HTTPException(401, "Invalid API key")
    return it
