"""OAU-002: OAuth2 authorization-code + PKCE flow service layer.

Handles auth-code issuance, single-use consumption, PKCE verification,
access-token minting, refresh-token issuance + rotation, and DirectLogin.

No dev_mode branch (SECOPS-007 parity).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Optional

import jwt
from fastapi import HTTPException

from app.core.crypto import b64url, b64url_decode, verify_ws_token
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.api_keys import api_key_hash
from app.services.oauth_consumers import get_consumer, verify_client_secret
from app.services.ttl import with_ttl


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------

def _pkce_challenge(code_verifier: str) -> str:
    """Compute BASE64URL(SHA256(code_verifier)) — the S256 code_challenge."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return b64url(digest)


def _pkce_verify(code_verifier: str, stored_challenge: str) -> bool:
    """Constant-time comparison of computed vs stored challenge."""
    computed = _pkce_challenge(code_verifier)
    return hmac.compare_digest(computed, stored_challenge)


# ---------------------------------------------------------------------------
# Auth-code helpers
# ---------------------------------------------------------------------------

def _mint_auth_code_token(code_id: str, ttl_seconds: int) -> str:
    """Mint a tamper-evident HMAC-signed auth-code token using mint_ws_token scheme.

    Reuses the mint_ws_token shape (base64url(payload) + "." + base64url(sig))
    but carries code_id instead of user_sub in the payload.
    """
    if not S.ws_token_secret:
        raise RuntimeError("WS_TOKEN_SECRET not set")
    now = int(time.time())
    payload = {"code_id": code_id, "exp": now + ttl_seconds, "iat": now}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(S.ws_token_secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{b64url(raw)}.{b64url(sig)}"


def _verify_auth_code_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify a code token; returns payload dict or None."""
    if not S.ws_token_secret:
        return None
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = b64url_decode(raw_b64)
        sig = b64url_decode(sig_b64)
        expected = hmac.new(S.ws_token_secret.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            return None
        if int(obj.get("exp", 0)) < int(time.time()):
            return None
        return obj
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Access-token minting
# ---------------------------------------------------------------------------

def _mint_oauth_access_token(
    owner_user_sub: str,
    client_id: str,
    scope: str,
    *,
    ttl_seconds: int,
) -> str:
    """Mint an HS256 JWT access token for OAuth2."""
    if not S.ui_access_token_secret:
        raise RuntimeError("UI_ACCESS_TOKEN_SECRET not set")
    now = now_ts()
    payload = {
        "sub": owner_user_sub,
        "client_id": client_id,
        "scope": scope,
        "token_type": "access",
        "iss": getattr(S, "public_base_url", "http://localhost:8000"),
        "exp": now + ttl_seconds,
        "iat": now,
    }
    return jwt.encode(payload, S.ui_access_token_secret, algorithm="HS256")


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------

def _validate_requested_scopes(requested: str, consumer_item: Dict[str, Any]) -> str:
    """Validate requested scope ⊆ consumer.allowed_scopes. Returns granted scopes string."""
    always_ok = {"openid", "profile", "email", "offline_access"}
    allowed = set(consumer_item.get("allowed_scopes", [])) | always_ok
    requested_set = set(requested.split()) if requested else set()
    invalid = requested_set - allowed
    if invalid:
        raise HTTPException(
            400,
            {"error": "invalid_scope", "error_description": f"Requested scopes not allowed: {sorted(invalid)}"},
        )
    return " ".join(sorted(requested_set))


# ---------------------------------------------------------------------------
# Public flow functions
# ---------------------------------------------------------------------------

def issue_auth_code(
    *,
    client_id: str,
    owner_user_sub: str,
    redirect_uri: str,
    granted_scopes: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    nonce: Optional[str] = None,
) -> str:
    """Write a CODE# row and return the signed opaque code envelope."""
    ttl = getattr(S, "oauth_code_ttl_seconds", 60)
    code_id = secrets.token_hex(16)
    ts = now_ts()
    item: Dict[str, Any] = {
        "client_id": client_id,
        "sk": f"CODE#{code_id}",
        "code_id": code_id,
        "owner_user_sub": owner_user_sub,
        "client_id_denorm": client_id,
        "redirect_uri": redirect_uri,
        "granted_scopes": granted_scopes,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "issued_at": ts,
    }
    if nonce:
        item["nonce"] = nonce
    item = with_ttl(item, ttl_epoch=ts + ttl)
    T.oauth_consumers.put_item(Item=item)
    return _mint_auth_code_token(code_id, ttl)


def exchange_code_for_tokens(
    *,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    client_secret: Optional[str] = None,
) -> Dict[str, Any]:
    """Exchange an authorization code for access (+ optional refresh) tokens."""
    # 1. Load consumer
    consumer = get_consumer(client_id)
    if not consumer or not consumer.get("enabled"):
        raise HTTPException(400, {"error": "invalid_client", "error_description": "Unknown or disabled client"})

    # 2. Verify client_secret for confidential clients
    if consumer.get("is_confidential", True):
        if not client_secret:
            raise HTTPException(400, {"error": "invalid_client", "error_description": "client_secret required"})
        if not verify_client_secret(client_id, client_secret):
            raise HTTPException(400, {"error": "invalid_client", "error_description": "Invalid client_secret"})

    # 3. Verify code signature + expiry
    payload = _verify_auth_code_token(code)
    if not payload:
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"})
    code_id = payload.get("code_id")
    if not code_id:
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "Malformed code"})

    # 4. Single-use consume: attribute_not_exists(consumed_at)
    try:
        T.oauth_consumers.update_item(
            Key={"client_id": client_id, "sk": f"CODE#{code_id}"},
            UpdateExpression="SET consumed_at = :now",
            ConditionExpression=(
                "attribute_exists(client_id) AND attribute_exists(sk) AND attribute_not_exists(consumed_at)"
            ),
            ExpressionAttributeValues={":now": now_ts()},
        )
    except Exception as exc:
        if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailedException" in str(exc):
            raise HTTPException(400, {"error": "invalid_grant", "error_description": "authorization code already used"})
        raise

    # 5. Read code row to get details
    code_resp = T.oauth_consumers.get_item(Key={"client_id": client_id, "sk": f"CODE#{code_id}"})
    code_row = code_resp.get("Item") or {}
    if not code_row:
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "Authorization code not found"})

    # 6. Cross-check redirect_uri and client_id
    if code_row.get("redirect_uri") != redirect_uri:
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
    if code_row.get("client_id", code_row.get("client_id_denorm")) != client_id:
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "client_id mismatch"})

    # 7. PKCE verify
    if not _pkce_verify(code_verifier, code_row.get("code_challenge", "")):
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})

    # 8. Mint access token
    granted_scopes = code_row.get("granted_scopes", "")
    owner_user_sub = code_row.get("owner_user_sub", "")
    ttl_seconds = getattr(S, "oauth_access_token_ttl_seconds", 900)
    access_token = _mint_oauth_access_token(owner_user_sub, client_id, granted_scopes, ttl_seconds=ttl_seconds)

    result: Dict[str, Any] = {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ttl_seconds,
        "scope": granted_scopes,
    }

    # 9. Issue refresh token if requested
    scope_set = set(granted_scopes.split())
    always_refresh = getattr(S, "oauth_always_issue_refresh_token", False)
    if "offline_access" in scope_set or always_refresh:
        refresh_plaintext = secrets.token_urlsafe(32)
        grant_id = secrets.token_hex(16)
        refresh_hash = api_key_hash(refresh_plaintext)
        ts = now_ts()
        refresh_ttl = getattr(S, "oauth_refresh_token_ttl_seconds", 2592000)
        grant_item: Dict[str, Any] = {
            "client_id": client_id,
            "sk": f"GRANT#{grant_id}",
            "grant_id": grant_id,
            "owner_user_sub": owner_user_sub,
            "client_id_denorm": client_id,
            "granted_scopes": granted_scopes,
            "refresh_token_hash": refresh_hash,
            "issued_at": ts,
            "revoked": False,
        }
        if code_row.get("nonce"):
            grant_item["nonce"] = code_row["nonce"]
        grant_item = with_ttl(grant_item, ttl_epoch=ts + refresh_ttl)
        T.oauth_consumers.put_item(Item=grant_item)
        result["refresh_token"] = f"oar_{grant_id}.{refresh_plaintext}"

    # 10. OIDC id_token (OAU-003 extension)
    if "openid" in scope_set:
        nonce = code_row.get("nonce")
        try:
            oidc_enabled = getattr(S, "oauth_provider_oidc_enabled", False)
            if oidc_enabled:
                from app.services.oauth_oidc_keys import build_id_token
                id_token = build_id_token(
                    owner_user_sub=owner_user_sub,
                    client_id=client_id,
                    granted_scopes=list(scope_set),
                    nonce=nonce,
                )
                result["id_token"] = id_token
        except Exception:
            pass  # best-effort; OIDC issuance failure must not block the access token

    return result


def refresh_access_token(
    *,
    client_id: str,
    refresh_token: str,
    client_secret: Optional[str] = None,
) -> Dict[str, Any]:
    """Rotate a refresh token and issue a new access token."""
    # Parse oar_{grant_id}.{plaintext}
    if not refresh_token.startswith("oar_"):
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "Malformed refresh_token"})
    rest = refresh_token[4:]
    dot_idx = rest.find(".")
    if dot_idx < 1:
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "Malformed refresh_token"})
    grant_id = rest[:dot_idx]
    plaintext = rest[dot_idx + 1:]

    # Load consumer
    consumer = get_consumer(client_id)
    if not consumer or not consumer.get("enabled"):
        raise HTTPException(400, {"error": "invalid_client", "error_description": "Unknown or disabled client"})

    if consumer.get("is_confidential", True):
        if not client_secret:
            raise HTTPException(400, {"error": "invalid_client", "error_description": "client_secret required"})
        if not verify_client_secret(client_id, client_secret):
            raise HTTPException(400, {"error": "invalid_client", "error_description": "Invalid client_secret"})

    # Load grant row
    grant_resp = T.oauth_consumers.get_item(Key={"client_id": client_id, "sk": f"GRANT#{grant_id}"})
    grant_row = grant_resp.get("Item") or {}
    if not grant_row:
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "Refresh token not found"})

    if grant_row.get("revoked", False):
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "Refresh token has been revoked"})

    # Check TTL
    ttl_epoch = grant_row.get(getattr(S, "ddb_ttl_attr", "ttl_epoch"), 0)
    if ttl_epoch and int(ttl_epoch) <= now_ts():
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "Refresh token has expired"})

    # Verify hash
    candidate_hash = api_key_hash(plaintext)
    stored_hash = grant_row.get("refresh_token_hash", "")
    if not hmac.compare_digest(candidate_hash, stored_hash):
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "Invalid refresh_token"})

    # Rotate: generate new secret
    new_plaintext = secrets.token_urlsafe(32)
    new_hash = api_key_hash(new_plaintext)
    ts = now_ts()
    T.oauth_consumers.update_item(
        Key={"client_id": client_id, "sk": f"GRANT#{grant_id}"},
        UpdateExpression="SET refresh_token_hash = :h, rotated_at = :now",
        ExpressionAttributeValues={":h": new_hash, ":now": ts},
    )

    # Mint new access token
    granted_scopes = grant_row.get("granted_scopes", "")
    owner_user_sub = grant_row.get("owner_user_sub", "")
    ttl_seconds = getattr(S, "oauth_access_token_ttl_seconds", 900)
    access_token = _mint_oauth_access_token(owner_user_sub, client_id, granted_scopes, ttl_seconds=ttl_seconds)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ttl_seconds,
        "scope": granted_scopes,
        "refresh_token": f"oar_{grant_id}.{new_plaintext}",
    }


def directlogin_grant(
    *,
    client_id: str,
    username: str,
    password: str,
    client_secret: str,
    scope: str,
) -> Dict[str, Any]:
    """DirectLogin (grant_type=password). Gated by S.oauth_provider_directlogin_enabled."""
    if not getattr(S, "oauth_provider_directlogin_enabled", False):
        raise HTTPException(400, {"error": "unsupported_grant_type", "error_description": "DirectLogin is not enabled"})

    consumer = get_consumer(client_id)
    if not consumer or not consumer.get("enabled"):
        raise HTTPException(400, {"error": "invalid_client", "error_description": "Unknown or disabled client"})

    if not verify_client_secret(client_id, client_secret):
        raise HTTPException(400, {"error": "invalid_client", "error_description": "Invalid client_secret"})

    # Verify credentials
    from app.auth.deps import _verify_local_password  # type: ignore[attr-defined]
    user_sub = _verify_local_password(username, password)
    if not user_sub:
        raise HTTPException(400, {"error": "invalid_grant", "error_description": "invalid credentials"})

    # Validate scope
    granted_scopes = _validate_requested_scopes(scope, consumer)
    ttl_seconds = getattr(S, "oauth_access_token_ttl_seconds", 900)
    access_token = _mint_oauth_access_token(user_sub, client_id, granted_scopes, ttl_seconds=ttl_seconds)

    result: Dict[str, Any] = {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ttl_seconds,
        "scope": granted_scopes,
    }

    scope_set = set(granted_scopes.split())
    always_refresh = getattr(S, "oauth_always_issue_refresh_token", False)
    if "offline_access" in scope_set or always_refresh:
        refresh_plaintext = secrets.token_urlsafe(32)
        grant_id = secrets.token_hex(16)
        refresh_hash = api_key_hash(refresh_plaintext)
        ts = now_ts()
        refresh_ttl = getattr(S, "oauth_refresh_token_ttl_seconds", 2592000)
        grant_item: Dict[str, Any] = {
            "client_id": client_id,
            "sk": f"GRANT#{grant_id}",
            "grant_id": grant_id,
            "owner_user_sub": user_sub,
            "client_id_denorm": client_id,
            "granted_scopes": granted_scopes,
            "refresh_token_hash": refresh_hash,
            "issued_at": ts,
            "revoked": False,
        }
        grant_item = with_ttl(grant_item, ttl_epoch=ts + refresh_ttl)
        T.oauth_consumers.put_item(Item=grant_item)
        result["refresh_token"] = f"oar_{grant_id}.{refresh_plaintext}"

    return result
