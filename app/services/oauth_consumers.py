"""OAU-001: Consumer-app registry — CRUD + secret verification.

Modeled on app/services/api_keys.py. Reuses api_key_hash, now_ts, audit_event.
No dev_mode branch (SECOPS-007 parity).
"""
from __future__ import annotations

import hmac
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.api_keys import api_key_hash


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _valid_scope_vocabulary() -> set:
    """Return the union of all required_scopes in the API-key route registry."""
    from app.services.api_key_route_scope_registry import API_KEY_ROUTE_SCOPE_REGISTRY
    vocab: set = set()
    for policy in API_KEY_ROUTE_SCOPE_REGISTRY.values():
        vocab.update(policy.get("required_scopes", []))
    return vocab


def _validate_redirect_uris(uris: List[str]) -> List[str]:
    """Validate each URI: http/https scheme + non-empty netloc + no fragment."""
    if not uris:
        raise HTTPException(400, {"code": "invalid_redirect_uri", "message": "redirect_uris must not be empty"})
    seen: set = set()
    result: List[str] = []
    for raw in uris:
        uri = raw.strip()
        if not uri:
            continue
        if "#" in uri:
            raise HTTPException(400, {"code": "invalid_redirect_uri", "message": f"URI must not contain fragment: {uri}"})
        parsed = urlparse(uri)
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(400, {"code": "invalid_redirect_uri", "message": f"URI must use http or https scheme: {uri}"})
        if not parsed.netloc:
            raise HTTPException(400, {"code": "invalid_redirect_uri", "message": f"URI must have a non-empty host: {uri}"})
        if uri not in seen:
            seen.add(uri)
            result.append(uri)
    if not result:
        raise HTTPException(400, {"code": "invalid_redirect_uri", "message": "redirect_uris must not be empty"})
    return result


def _validate_allowed_scopes(scopes: List[str]) -> List[str]:
    """Validate scopes against the route registry vocabulary + OIDC identity scopes."""
    # Always-permitted OIDC identity scopes
    always_valid = {"openid", "profile", "email", "offline_access"}
    vocab = _valid_scope_vocabulary() | always_valid
    invalid: List[str] = []
    seen: set = set()
    result: List[str] = []
    for s in scopes:
        s = s.strip()
        if not s:
            continue
        if s not in vocab:
            invalid.append(s)
        if s not in seen:
            seen.add(s)
            result.append(s)
    if invalid:
        raise HTTPException(400, {"code": "invalid_scope", "invalid": invalid, "message": "Unknown scopes requested"})
    return result


def _safe_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Return item with client_secret_hash stripped (safe to expose to API callers)."""
    out = {k: v for k, v in item.items() if k != "client_secret_hash"}
    return out


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def create_consumer(
    owner_sub: str,
    *,
    name: str,
    description: str = "",
    redirect_uris: List[str],
    allowed_scopes: List[str],
    is_confidential: bool = True,
) -> Dict[str, Any]:
    """Create a new OAuth consumer app. Returns dict including one-time client_secret."""
    ts = now_ts()
    client_id = secrets.token_hex(16)
    secret = secrets.token_urlsafe(32)
    secret_hash = api_key_hash(secret) if is_confidential else ""
    uris = _validate_redirect_uris(redirect_uris)
    scope_list = _validate_allowed_scopes(allowed_scopes)
    item: Dict[str, Any] = {
        "client_id": client_id,
        "sk": "META",
        "client_secret_hash": secret_hash,
        "client_secret_prefix": f"oc_{client_id[:8]}",
        "owner_sub": owner_sub,
        "name": (name or "")[:128],
        "description": (description or "")[:512],
        "redirect_uris": uris,
        "allowed_scopes": scope_list,
        "is_confidential": is_confidential,
        "enabled": True,
        "created_at": ts,
        "updated_at": ts,
        "secret_rotated_at": 0,
    }
    T.oauth_consumers.put_item(Item=item)
    return {
        "client_id": client_id,
        "client_secret": f"oc_{client_id}.{secret}" if is_confidential else "",
        "client_secret_prefix": item["client_secret_prefix"],
        "name": item["name"],
        "created_at": ts,
    }


def get_consumer(client_id: str) -> Dict[str, Any]:
    """Return the consumer META item (including hash) or {} if not found."""
    resp = T.oauth_consumers.get_item(Key={"client_id": client_id, "sk": "META"})
    return resp.get("Item") or {}


def list_consumers(owner_sub: str) -> List[Dict[str, Any]]:
    """List consumers for an owner, newest first (up to 100). Hashes stripped."""
    resp = T.oauth_consumers.query(
        IndexName=S.oauth_consumers_owner_index,
        KeyConditionExpression=Key("owner_sub").eq(owner_sub),
        ScanIndexForward=False,
        Limit=100,
    )
    return [_safe_item(i) for i in resp.get("Items", [])]


def update_consumer(
    owner_sub: str,
    client_id: str,
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    redirect_uris: Optional[List[str]] = None,
    allowed_scopes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Update mutable fields on a consumer META row. Raises 404 if not owned."""
    set_parts: List[str] = ["updated_at = :now"]
    vals: Dict[str, Any] = {":now": now_ts(), ":u": owner_sub, ":meta": "META"}
    names: Dict[str, str] = {}
    if name is not None:
        set_parts.append("#nm = :nm")
        vals[":nm"] = name[:128]
        names["#nm"] = "name"
    if description is not None:
        set_parts.append("description = :desc")
        vals[":desc"] = description[:512]
    if redirect_uris is not None:
        set_parts.append("redirect_uris = :uris")
        vals[":uris"] = _validate_redirect_uris(redirect_uris)
    if allowed_scopes is not None:
        set_parts.append("allowed_scopes = :scopes")
        vals[":scopes"] = _validate_allowed_scopes(allowed_scopes)
    update_expr = "SET " + ", ".join(set_parts)
    kwargs: Dict[str, Any] = {
        "Key": {"client_id": client_id, "sk": "META"},
        "UpdateExpression": update_expr,
        "ConditionExpression": "owner_sub = :u AND sk = :meta",
        "ExpressionAttributeValues": vals,
        "ReturnValues": "ALL_NEW",
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    try:
        resp = T.oauth_consumers.update_item(**kwargs)
        return _safe_item(resp.get("Attributes") or {})
    except Exception as exc:
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailedException" in str(exc):
            raise HTTPException(404, "Consumer not found or not owned by caller")
        raise


def delete_consumer(owner_sub: str, client_id: str) -> None:
    """Delete a consumer META row. Raises 404 if not found or not owned."""
    try:
        T.oauth_consumers.delete_item(
            Key={"client_id": client_id, "sk": "META"},
            ConditionExpression="owner_sub = :u",
            ExpressionAttributeValues={":u": owner_sub},
        )
    except Exception as exc:
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailedException" in str(exc):
            raise HTTPException(404, "Consumer not found or not owned by caller")
        raise


def verify_client_secret(client_id: str, secret: str) -> bool:
    """Constant-time secret verification. Returns False if consumer is disabled or not found."""
    item = get_consumer(client_id)
    if not item or not item.get("enabled"):
        return False
    if not item.get("is_confidential", True):
        return False
    stored_hash = item.get("client_secret_hash", "")
    if not stored_hash:
        return False
    candidate_hash = api_key_hash(secret)
    return hmac.compare_digest(stored_hash, candidate_hash)


# ---------------------------------------------------------------------------
# OAU-005: Enable/disable + secret rotation
# ---------------------------------------------------------------------------

def set_consumer_enabled(owner_sub: str, client_id: str, *, enabled: bool) -> Dict[str, Any]:
    """Enable or disable a consumer. Owner or admin must pass owner_sub."""
    try:
        resp = T.oauth_consumers.update_item(
            Key={"client_id": client_id, "sk": "META"},
            UpdateExpression="SET enabled = :e, updated_at = :now",
            ConditionExpression="owner_sub = :u AND sk = :meta",
            ExpressionAttributeValues={
                ":e": enabled,
                ":now": now_ts(),
                ":u": owner_sub,
                ":meta": "META",
            },
            ReturnValues="ALL_NEW",
        )
        return _safe_item(resp.get("Attributes") or {})
    except Exception as exc:
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailedException" in str(exc):
            raise HTTPException(404, "Consumer not found or not owned by caller")
        raise


def rotate_client_secret(owner_sub: str, client_id: str) -> Dict[str, Any]:
    """Rotate the client secret. Returns new plaintext (one-time). Raises 404 if not owned."""
    # Verify ownership first
    item = get_consumer(client_id)
    if not item or item.get("owner_sub") != owner_sub:
        raise HTTPException(404, "Consumer not found or not owned by caller")
    if not item.get("is_confidential", True):
        raise HTTPException(400, "Public clients do not have a rotatable client_secret")

    ts = now_ts()
    new_secret = secrets.token_urlsafe(32)
    new_hash = api_key_hash(new_secret)
    try:
        T.oauth_consumers.update_item(
            Key={"client_id": client_id, "sk": "META"},
            UpdateExpression="SET client_secret_hash = :h, secret_rotated_at = :now, updated_at = :now",
            ConditionExpression="owner_sub = :u AND sk = :meta",
            ExpressionAttributeValues={
                ":h": new_hash,
                ":now": ts,
                ":u": owner_sub,
                ":meta": "META",
            },
        )
    except Exception as exc:
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailedException" in str(exc):
            raise HTTPException(404, "Consumer not found or not owned by caller")
        raise
    return {
        "client_id": client_id,
        "client_secret": f"oc_{client_id}.{new_secret}",
        "client_secret_prefix": item.get("client_secret_prefix", f"oc_{client_id[:8]}"),
        "secret_rotated_at": ts,
    }
