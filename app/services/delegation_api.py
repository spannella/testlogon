"""Delegation API service (DELEGATE-005).

Builds a delegation-scoped programmatic API-key layer on top of the
existing API-key hashing infrastructure (``app/services/api_keys.py``).

A delegation API key is bound to a single delegation relationship
(creator + delegate) and to a subset of that delegate's permissions.
Keys are stored in the dedicated ``delegation_api_keys`` DynamoDB table.
Raw key secrets are NEVER stored -- only an HMAC hash (reusing
``api_key_hash`` with ``API_KEY_PEPPER``). The plaintext key is returned
exactly once at creation time.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.api_keys import api_key_hash, new_api_key_secret, parse_api_key
from app.services.delegates import get_delegate, require_delegate_permission
from app.services.moderation_policy_engine import is_user_currently_banned

logger = logging.getLogger(__name__)

# Plaintext key format: dak_<key_id>.<secret>
KEY_PREFIX = "dak_"

# Per-key rate-limit sliding-window buckets (in-memory; source of truth).
_key_rate_buckets: Dict[str, Deque[float]] = defaultdict(deque)


def _default_rate_limit_rpm() -> int:
    return int(getattr(S, "delegation_api_default_rate_limit_rpm", 60) or 60)


def _max_rate_limit_rpm() -> int:
    return int(getattr(S, "delegation_api_max_rate_limit_rpm", 300) or 300)


# Maps each delegation permission to the API actions it unlocks.
_ACTION_MAP: Dict[str, List[Dict[str, str]]] = {
    "chat_read": [
        {"method": "GET", "path": "/ui/delegation-api/v1/conversations", "description": "List creator's conversations"},
        {"method": "GET", "path": "/ui/delegation-api/v1/conversations/{cid}/messages", "description": "List messages"},
    ],
    "chat_respond": [
        {"method": "POST", "path": "/ui/delegation-api/v1/conversations/{cid}/messages", "description": "Send message as creator"},
    ],
    "feed_read": [
        {"method": "GET", "path": "/ui/delegation-api/v1/posts", "description": "List creator's posts"},
    ],
    "feed_post": [
        {"method": "POST", "path": "/ui/delegation-api/v1/posts", "description": "Create post as creator"},
    ],
    "feed_moderate": [
        {"method": "POST", "path": "/ui/delegation-api/v1/posts/{pid}/comments/{cid}/moderate", "description": "Moderate comment"},
    ],
    "broadcast_moderate": [
        {"method": "POST", "path": "/ui/delegation-api/v1/broadcast/{sid}/mute", "description": "Mute viewer"},
    ],
    "broadcast_control": [
        {"method": "POST", "path": "/ui/delegation-api/v1/broadcast/{sid}/start", "description": "Start broadcast"},
    ],
}


# ---------------------------------------------------------------------------
# Key lifecycle
# ---------------------------------------------------------------------------


def create_delegation_api_key(
    *,
    owner_sub: str,
    label: str,
    creator_id: str,
    permissions: List[str],
    expires_in_days: Optional[int] = None,
) -> Dict[str, Any]:
    """Issue a delegation-scoped API key.

    The ``owner_sub`` must be an active delegate of ``creator_id`` and must
    actually hold every permission requested for the key (least privilege --
    a key can never exceed the delegate's own granted permissions).

    Returns the stored item plus the one-time plaintext key under
    ``key_secret``.
    """
    permissions = [str(p).strip() for p in (permissions or []) if str(p).strip()]
    if not permissions:
        raise HTTPException(400, "At least one permission is required")

    delegate_item = require_delegate_permission(
        creator_id=creator_id,
        delegate_id=owner_sub,
        required_permission=permissions[0],
    )
    granted = set(delegate_item.get("permissions", []))
    missing = sorted(set(permissions) - granted)
    if missing:
        raise HTTPException(
            403, f"Delegate lacks requested permissions: {missing}"
        )

    ts = now_ts()
    key_id = secrets.token_hex(16)
    secret = new_api_key_secret()
    secret_hash = api_key_hash(secret)
    expires_at = ts + max(int(expires_in_days), 1) * 86400 if expires_in_days else 0

    item: Dict[str, Any] = {
        "key_id": key_id,
        "owner_sub": owner_sub,
        "creator_id": creator_id,
        "secret_hash": secret_hash,
        "label": (label or "")[:200],
        "permissions": permissions,
        "preset": delegate_item.get("preset"),
        "status": "active",
        "revoked": False,
        "created_at": ts,
        "updated_at": ts,
        "last_used_at": 0,
        "last_used_ip": "",
        "total_calls": 0,
        "expires_at": expires_at,
        "prefix": f"{KEY_PREFIX}{key_id[:8]}",
        "GSI_OWNER_PK": f"OWNER#{owner_sub}",
        "GSI_OWNER_SK": ts,
        "GSI_CREATOR_PK": f"DELEGATION_CREATOR#{creator_id}",
        "GSI_CREATOR_SK": ts,
    }
    T.delegation_api_keys.put_item(Item=item)

    out = _public_view(item)
    out["key_secret"] = f"{KEY_PREFIX}{key_id}.{secret}"
    return out


def get_key_item(key_id: str) -> Dict[str, Any]:
    return T.delegation_api_keys.get_item(Key={"key_id": key_id}).get("Item") or {}


def list_keys_for_owner(owner_sub: str, *, limit: int = 100) -> List[Dict[str, Any]]:
    """List a delegate/developer's own delegation API keys (non-revoked)."""
    resp = T.delegation_api_keys.query(
        IndexName="ByOwner",
        KeyConditionExpression=Key("GSI_OWNER_PK").eq(f"OWNER#{owner_sub}"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return [_public_view(it) for it in resp.get("Items", []) if not it.get("revoked")]


def list_keys_for_creator(creator_id: str, *, limit: int = 100) -> List[Dict[str, Any]]:
    """List all delegation API keys scoped to a creator (non-revoked)."""
    resp = T.delegation_api_keys.query(
        IndexName="ByDelegationCreator",
        KeyConditionExpression=Key("GSI_CREATOR_PK").eq(f"DELEGATION_CREATOR#{creator_id}"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return [_public_view(it) for it in resp.get("Items", []) if not it.get("revoked")]


def revoke_key_by_owner(*, owner_sub: str, key_id: str) -> None:
    """The key owner (delegate) revokes one of their own keys."""
    item = get_key_item(key_id)
    if not item or item.get("owner_sub") != owner_sub:
        raise HTTPException(404, "Delegation API key not found")
    _do_revoke(key_id)


def revoke_key_by_creator(*, creator_id: str, key_id: str) -> None:
    """The creator revokes a delegation API key scoped to them."""
    item = get_key_item(key_id)
    if not item or item.get("creator_id") != creator_id:
        raise HTTPException(404, "Delegation API key not found")
    _do_revoke(key_id)


def get_key_scope(key_id: str, *, requester_sub: str) -> Dict[str, Any]:
    """Return scope + available actions for a key.

    Only the key owner or the bound creator may inspect the scope.
    """
    item = get_key_item(key_id)
    if not item or item.get("revoked"):
        raise HTTPException(404, "Delegation API key not found")
    if requester_sub not in (item.get("owner_sub"), item.get("creator_id")):
        raise HTTPException(403, "Not authorized to view this key")
    return _scope_view(item)


# ---------------------------------------------------------------------------
# Authentication for programmatic (key-authenticated) requests
# ---------------------------------------------------------------------------


def authenticate_key(
    *,
    api_key: str,
    client_ip: str,
    required_permission: str,
) -> Dict[str, Any]:
    """Validate a delegation API key for a programmatic request.

    Checks key format, existence, revocation/expiry, that the bound
    delegation relationship is still active, that the key carries the
    required permission, enforces per-key rate limits, and records usage.

    Returns the key item (with delegation context). Raises HTTPException on
    any failure.
    """
    parsed = _parse_delegation_key(api_key)
    key_id, secret = parsed["key_id"], parsed["secret"]

    item = get_key_item(key_id)
    if not item or item.get("revoked"):
        raise HTTPException(401, "Invalid delegation API key")

    expires_at = int(item.get("expires_at") or 0)
    if expires_at and now_ts() > expires_at:
        _do_revoke(key_id)
        raise HTTPException(401, "Delegation API key expired")

    if api_key_hash(secret) != item.get("secret_hash"):
        raise HTTPException(401, "Invalid delegation API key")

    # The underlying delegation relationship must still be active.
    delegate = get_delegate(item.get("creator_id", ""), item.get("owner_sub", ""))
    if not delegate or delegate.get("status") != "active":
        raise HTTPException(403, "Delegation relationship is no longer active")

    # GAP-0158: reject if the key holder (delegate) is platform-banned. The
    # delegation API key path runs outside require_ui_session, which is where
    # the normal session path enforces account bans, so the same ban lookup
    # must be applied here.
    owner_sub = item.get("owner_sub", "")
    if is_user_currently_banned(owner_sub):
        raise HTTPException(
            403, "Delegation API key owner account is suspended"
        )

    if required_permission not in item.get("permissions", []):
        raise HTTPException(
            403, f"Key does not have permission: {required_permission}"
        )

    rpm = int(item.get("rate_limit_rpm") or _default_rate_limit_rpm())
    _enforce_key_rate_limit(key_id, rpm)
    _record_usage(key_id, client_ip)

    return item


def rate_limit_headers(key_id: str, rpm: int) -> Dict[str, str]:
    """Build standard rate-limit response headers for a key."""
    now = time.time()
    bucket = _key_rate_buckets.get(key_id, deque())
    used = sum(1 for t in bucket if t > now - 60.0)
    remaining = max(0, rpm - used)
    reset = int(bucket[0] + 60) if bucket else int(now + 60)
    return {
        "X-RateLimit-Limit": str(rpm),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_delegation_key(api_key: str) -> Dict[str, str]:
    api_key = (api_key or "").strip()
    if api_key.startswith(KEY_PREFIX):
        # Reuse the api_keys parser by swapping our prefix for theirs.
        try:
            return parse_api_key("ak_" + api_key[len(KEY_PREFIX):])
        except HTTPException:
            raise HTTPException(401, "Invalid delegation API key format")
    raise HTTPException(401, "Invalid delegation API key format")


def _do_revoke(key_id: str) -> None:
    T.delegation_api_keys.update_item(
        Key={"key_id": key_id},
        UpdateExpression="SET revoked = :t, #st = :s, revoked_at = :now, updated_at = :now",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":t": True, ":s": "revoked", ":now": now_ts()},
    )
    _key_rate_buckets.pop(key_id, None)


def _enforce_key_rate_limit(key_id: str, rpm: int) -> None:
    now = time.time()
    bucket = _key_rate_buckets[key_id]
    while bucket and bucket[0] < now - 60.0:
        bucket.popleft()
    if len(bucket) >= rpm:
        retry_after = int(bucket[0] + 60.0 - now) + 1
        raise HTTPException(
            429,
            detail=f"Rate limit exceeded ({rpm} requests/minute)",
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(rpm),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(bucket[0] + 60.0)),
            },
        )
    bucket.append(now)


def _record_usage(key_id: str, client_ip: str) -> None:
    try:
        T.delegation_api_keys.update_item(
            Key={"key_id": key_id},
            UpdateExpression="SET last_used_at = :now, last_used_ip = :ip ADD total_calls :one",
            ExpressionAttributeValues={":now": now_ts(), ":ip": client_ip or "", ":one": 1},
        )
    except Exception:  # usage tracking must never break the request
        logger.warning("failed to record delegation key usage for %s", key_id)


def _public_view(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "key_id": item.get("key_id", ""),
        "label": item.get("label", ""),
        "owner_sub": item.get("owner_sub", ""),
        "creator_id": item.get("creator_id", ""),
        "permissions": item.get("permissions", []),
        "preset": item.get("preset"),
        "status": item.get("status", "active"),
        "prefix": item.get("prefix", ""),
        "rate_limit_rpm": int(item.get("rate_limit_rpm") or _default_rate_limit_rpm()),
        "total_calls": int(item.get("total_calls", 0) or 0),
        "last_used_at": int(item.get("last_used_at", 0) or 0),
        "created_at": int(item.get("created_at", 0) or 0),
        "expires_at": int(item.get("expires_at", 0) or 0),
    }


def _scope_view(item: Dict[str, Any]) -> Dict[str, Any]:
    permissions = item.get("permissions", [])
    actions: List[Dict[str, str]] = []
    for perm in permissions:
        actions.extend(_ACTION_MAP.get(perm, []))
    return {
        "key_id": item.get("key_id", ""),
        "creator_id": item.get("creator_id", ""),
        "permissions": permissions,
        "preset": item.get("preset"),
        "available_actions": actions,
        "rate_limit_rpm": int(item.get("rate_limit_rpm") or _default_rate_limit_rpm()),
        "total_calls": int(item.get("total_calls", 0) or 0),
    }
