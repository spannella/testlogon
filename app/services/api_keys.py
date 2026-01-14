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

def api_key_hash(secret: str) -> str:
    if not S.api_key_pepper:
        raise RuntimeError("API_KEY_PEPPER not set")
    return sha256_str(secret + "|" + S.api_key_pepper)

def create_api_key(user_sub: str, label: str, *, ip_rules: Optional[List[str]] = None) -> Dict[str, Any]:
    ts = now_ts()
    api_key_id = secrets.token_hex(8)
    secret = new_api_key_secret()
    secret_hash = api_key_hash(secret)
    ttl = ts + 365 * 86400  # 1y; rotate as you like

    ip_rules_n = []
    for r in ip_rules or []:
        ip_rules_n.append(normalize_cidr(r))

    item = with_ttl({
        "api_key_id": api_key_id,
        "user_sub": user_sub,
        "secret_hash": secret_hash,
        "label": (label or "")[:64],
        "created_at": ts,
        "revoked": False,
        "revoked_at": 0,
        "ip_rules": ip_rules_n,
    }, ttl_epoch=ttl)

    T.api_keys.put_item(Item=item)
    return {"api_key_id": api_key_id, "api_key_secret": secret, "label": item["label"], "created_at": ts, "ip_rules": ip_rules_n}

def revoke_api_key(user_sub: str, api_key_id: str) -> None:
    try:
        T.api_keys.update_item(
            Key={"api_key_id": api_key_id},
            UpdateExpression="SET revoked = :t, revoked_at = :now",
            ConditionExpression="user_sub = :u",
            ExpressionAttributeValues={":t": True, ":now": now_ts(), ":u": user_sub},
        )
    except Exception:
        raise HTTPException(404, "API key not found")

def set_api_key_ip_rules(user_sub: str, api_key_id: str, ip_rules: List[str]) -> List[str]:
    rules = [normalize_cidr(r) for r in (ip_rules or [])]
    try:
        T.api_keys.update_item(
            Key={"api_key_id": api_key_id},
            UpdateExpression="SET ip_rules = :r, updated_at=:now",
            ConditionExpression="user_sub = :u AND revoked = :f",
            ExpressionAttributeValues={":r": rules, ":u": user_sub, ":f": False, ":now": now_ts()},
        )
    except Exception:
        raise HTTPException(404, "API key not found or revoked")
    return rules

def list_api_keys(user_sub: str) -> List[Dict[str, Any]]:
    r = T.api_keys.query(IndexName=S.api_keys_user_index, KeyConditionExpression=Key("user_sub").eq(user_sub), ScanIndexForward=False, Limit=100)
    out = []
    for it in r.get("Items", []):
        out.append({
            "api_key_id": it["api_key_id"],
            "label": it.get("label",""),
            "created_at": it.get("created_at",0),
            "revoked": it.get("revoked",False),
            "revoked_at": it.get("revoked_at",0),
            "ip_rules": it.get("ip_rules", []),
        })
    return out

def check_api_key_allowed(api_key_id: str, api_key_secret: str, client_ip: str) -> Dict[str, Any]:
    it = T.api_keys.get_item(Key={"api_key_id": api_key_id}).get("Item")
    if not it or it.get("revoked", False):
        raise HTTPException(401, "Invalid API key")
    if api_key_hash(api_key_secret) != it.get("secret_hash"):
        raise HTTPException(401, "Invalid API key")
    rules = it.get("ip_rules") or []
    if rules and (not ip_in_any_cidr(client_ip, rules)):
        raise HTTPException(403, "API key not allowed from this IP")
    return it
