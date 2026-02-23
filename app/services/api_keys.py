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
    api_key = (api_key or "").strip()
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

def create_api_key(user_sub: str, label: str, expires_in_days: Optional[int] = None) -> Dict[str, Any]:
    ts = now_ts()
    key_id = secrets.token_hex(16)
    secret = new_api_key_secret()
    secret_hash = api_key_hash(secret)
    if expires_in_days is not None:
        ttl = ts + max(expires_in_days, 1) * 86400
    else:
        ttl = 0  # user explicitly chose no expiry

    item = {
        "key_id": key_id,
        "user_sub": user_sub,
        "secret_hash": secret_hash,
        "label": (label or "")[:64],
        "created_at": ts,
        "updated_at": ts,
        "last_used_at": 0,
        "last_used_ip": "",
        "revoked": False,
        "revoked_at": 0,
        "expires_at": ttl,
        "prefix": f"ak_{key_id[:8]}",
        "allow_cidrs": [],
        "deny_cidrs": [],
        "monthly_calls_cap": 0,
        "monthly_spend_cap_micros": 0,
        "route_caps": {},
    }
    if ttl:
        item = with_ttl(item, ttl_epoch=ttl)

    T.api_keys.put_item(Item=item)
    return {
        "key_id": key_id,
        "key_secret": f"ak_{key_id}.{secret}",
        "label": item["label"],
        "created_at": ts,
        "expires_at": item["expires_at"],
    }

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

def revoke_all_api_keys(user_sub: str) -> int:
    revoked = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": S.api_keys_user_index,
            "KeyConditionExpression": Key("user_sub").eq(user_sub),
            "Limit": 200,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.api_keys.query(**kwargs)
        items = resp.get("Items", [])
        for it in items:
            key_id = it.get("key_id") or it.get("api_key_id")
            if not key_id:
                continue
            try:
                T.api_keys.update_item(
                    Key={"key_id": key_id},
                    UpdateExpression="SET revoked = :t, revoked_at = :now",
                    ExpressionAttributeValues={":t": True, ":now": now_ts()},
                )
                revoked += 1
            except Exception:
                pass
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return revoked

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



def _coerce_non_negative_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except Exception:
        return 0


def _normalize_route_caps(route_caps: Dict[str, Dict[str, Any]] | None) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for route_id, caps in (route_caps or {}).items():
        rid = (route_id or "").strip()
        if not rid or ":" not in rid:
            continue
        method, path = rid.split(":", 1)
        normalized = f"{method.upper()}:{path}"
        out[normalized] = {
            "monthly_calls_cap": _coerce_non_negative_int((caps or {}).get("monthly_calls_cap")),
            "monthly_spend_cap_micros": _coerce_non_negative_int((caps or {}).get("monthly_spend_cap_micros")),
        }
    return out


def _enforce_self_limit_guardrails(*, monthly_calls_cap: int, monthly_spend_cap_micros: int, route_caps: Dict[str, Dict[str, int]]) -> None:
    account_monthly_calls = _coerce_non_negative_int(getattr(S, "api_usage_account_monthly_calls_limit", 0))
    account_monthly_spend = _coerce_non_negative_int(getattr(S, "api_usage_account_monthly_spend_micros_limit", 0))

    if account_monthly_calls > 0 and monthly_calls_cap > account_monthly_calls:
        raise HTTPException(400, "monthly_calls_cap exceeds account monthly limit")
    if account_monthly_spend > 0 and monthly_spend_cap_micros > account_monthly_spend:
        raise HTTPException(400, "monthly_spend_cap_micros exceeds account monthly spend limit")

    for route_id, caps in route_caps.items():
        route_calls = _coerce_non_negative_int(caps.get("monthly_calls_cap"))
        route_spend = _coerce_non_negative_int(caps.get("monthly_spend_cap_micros"))
        if account_monthly_calls > 0 and route_calls > account_monthly_calls:
            raise HTTPException(400, f"route cap monthly_calls_cap exceeds account monthly limit: {route_id}")
        if account_monthly_spend > 0 and route_spend > account_monthly_spend:
            raise HTTPException(400, f"route cap monthly_spend_cap_micros exceeds account monthly spend limit: {route_id}")


def set_api_key_self_limits(
    user_sub: str,
    key_id: str,
    *,
    monthly_calls_cap: int,
    monthly_spend_cap_micros: int,
    route_caps: Dict[str, Dict[str, Any]] | None,
) -> Dict[str, Any]:
    calls_cap = _coerce_non_negative_int(monthly_calls_cap)
    spend_cap = _coerce_non_negative_int(monthly_spend_cap_micros)
    normalized_route_caps = _normalize_route_caps(route_caps)
    _enforce_self_limit_guardrails(
        monthly_calls_cap=calls_cap,
        monthly_spend_cap_micros=spend_cap,
        route_caps=normalized_route_caps,
    )

    try:
        T.api_keys.update_item(
            Key={"key_id": key_id},
            UpdateExpression=(
                "SET monthly_calls_cap = :mc, monthly_spend_cap_micros = :ms, "
                "route_caps = :rc, updated_at = :now"
            ),
            ConditionExpression="user_sub = :u",
            ExpressionAttributeValues={
                ":mc": calls_cap,
                ":ms": spend_cap,
                ":rc": normalized_route_caps,
                ":u": user_sub,
                ":now": now_ts(),
            },
        )
    except Exception:
        raise HTTPException(404, "API key not found")

    return {
        "key_id": key_id,
        "monthly_calls_cap": calls_cap,
        "monthly_spend_cap_micros": spend_cap,
        "route_caps": normalized_route_caps,
    }


def get_api_key_item(key_id: str) -> Dict[str, Any]:
    return T.api_keys.get_item(Key={"key_id": key_id}).get("Item") or {}
def list_api_keys(user_sub: str) -> List[Dict[str, Any]]:
    r = T.api_keys.query(IndexName=S.api_keys_user_index, KeyConditionExpression=Key("user_sub").eq(user_sub), ScanIndexForward=False, Limit=100)
    out = []
    for it in r.get("Items", []):
        if it.get("revoked"):
            continue
        out.append({
            "key_id": it.get("key_id") or it.get("api_key_id"),
            "label": it.get("label",""),
            "created_at": it.get("created_at",0),
            "last_used_at": it.get("last_used_at", 0),
            "last_used_ip": it.get("last_used_ip", ""),
            "revoked": it.get("revoked",False),
            "revoked_at": it.get("revoked_at",0),
            "expires_at": it.get("expires_at", 0),
            "prefix": it.get("prefix",""),
            "allow_cidrs": it.get("allow_cidrs", []),
            "deny_cidrs": it.get("deny_cidrs", []),
            "monthly_calls_cap": int(it.get("monthly_calls_cap", 0) or 0),
            "monthly_spend_cap_micros": int(it.get("monthly_spend_cap_micros", 0) or 0),
            "route_caps": it.get("route_caps", {}),
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
    expires_at = int(it.get("expires_at") or 0)
    if expires_at and now_ts() > expires_at:
        try:
            T.api_keys.update_item(
                Key={"key_id": api_key_id},
                UpdateExpression="SET revoked = :t, revoked_at = :now",
                ExpressionAttributeValues={":t": True, ":now": now_ts()},
            )
        except Exception:
            pass
        raise HTTPException(401, "API key expired")
    enforce_api_key_ip_rules(client_ip, it)
    if api_key_hash(api_key_secret) != it.get("secret_hash"):
        raise HTTPException(401, "Invalid API key")
    try:
        T.api_keys.update_item(
            Key={"key_id": api_key_id},
            UpdateExpression="SET last_used_at = :now, last_used_ip = :ip",
            ExpressionAttributeValues={":now": now_ts(), ":ip": client_ip},
        )
    except Exception:
        pass
    return it
