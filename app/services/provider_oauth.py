from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse
from urllib.parse import urlencode

from botocore.exceptions import ClientError
import requests
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.metrics import record_filemgr_mount_refresh_attempt
from app.services.alerts import audit_event
from app.services.ttl import with_ttl
from app.services.provider_credentials import (
    get_provider_credential,
    merge_provider_credential_metadata,
    rotate_provider_access_token,
    upsert_provider_credential,
)


def _state_signing_secret() -> str:
    secret = (getattr(S, "google_oauth_state_signing_secret", "") or "").strip()
    if secret:
        return secret
    fallback = (getattr(S, "ui_access_token_secret", "") or "").strip()
    if fallback:
        return fallback
    raise HTTPException(status_code=500, detail="google oauth state signing secret is not configured")


def _state_ttl_seconds() -> int:
    ttl = int(getattr(S, "google_oauth_state_ttl_seconds", 600) or 600)
    return max(60, ttl)


def _pk(owner: str) -> str:
    return f"OWNER#{owner}"


def _sk(provider: str, nonce: str) -> str:
    return f"PROVIDER_OAUTH_STATE#{provider}#{nonce}"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    pad = "=" * ((4 - (len(value) % 4)) % 4)
    return base64.urlsafe_b64decode((value + pad).encode("utf-8"))


def _now_epoch() -> int:
    return int(time.time())


def _parse_redirect_uri_allowlist() -> list[str]:
    raw = str(getattr(S, "google_oauth_redirect_uri_allowlist", "") or "").strip()
    if not raw:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for value in raw.split(","):
        item = value.strip()
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _validate_google_redirect_uri(redirect_uri: str) -> str:
    normalized = (redirect_uri or "").strip()
    if not normalized:
        raise HTTPException(status_code=500, detail="google oauth redirect_uri is not configured")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=500, detail="google oauth redirect_uri is invalid")

    allowlist = _parse_redirect_uri_allowlist()
    allowed = set(allowlist or [normalized])
    if normalized not in allowed:
        raise HTTPException(status_code=500, detail="google oauth redirect_uri is not in allowlist")
    return normalized


def build_google_oauth_start(owner: str) -> Dict[str, Any]:
    owner_norm = (owner or "").strip()
    if not owner_norm:
        raise HTTPException(status_code=400, detail="owner is required")

    client_id = (getattr(S, "google_oauth_client_id", "") or "").strip()
    redirect_uri = _validate_google_redirect_uri((getattr(S, "google_oauth_redirect_uri", "") or "").strip())
    if not client_id:
        raise HTTPException(status_code=500, detail="google oauth client_id is not configured")
    if not redirect_uri:
        raise HTTPException(status_code=500, detail="google oauth redirect_uri is not configured")

    ttl_seconds = _state_ttl_seconds()
    now = _now_epoch()
    exp = now + ttl_seconds
    nonce = secrets.token_urlsafe(24)

    payload = {
        "v": 1,
        "provider": "google_drive",
        "owner": owner_norm,
        "nonce": nonce,
        "exp": exp,
        "redirect_uri": redirect_uri,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = _b64url_encode(payload_json)
    sig = hmac.new(_state_signing_secret().encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
    state = f"{payload_b64}.{_b64url_encode(sig)}"

    item = {
        "PK": _pk(owner_norm),
        "SK": _sk("google_drive", nonce),
        "entity_type": "provider_oauth_state",
        "owner": owner_norm,
        "provider": "google_drive",
        "nonce": nonce,
        "state_sig": _b64url_encode(sig),
        "issued_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        "expires_at": datetime.fromtimestamp(exp, tz=timezone.utc).isoformat(),
        "consumed_at": None,
    }
    T.projects.put_item(
        Item=with_ttl(item, ttl_epoch=exp),
        ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
    )

    scopes_csv = (getattr(S, "google_oauth_scopes", "") or "").strip()
    scopes = [s.strip() for s in scopes_csv.split(",") if s.strip()] if scopes_csv else ["https://www.googleapis.com/auth/drive.file"]
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
    }
    authorization_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

    return {
        "provider": "google_drive",
        "authorization_url": authorization_url,
        "state": state,
        "expires_at": item["expires_at"],
    }


def consume_google_oauth_state(owner: str, state: str) -> Dict[str, Any]:
    owner_norm = (owner or "").strip()
    state_norm = (state or "").strip()
    if not owner_norm or not state_norm:
        raise HTTPException(status_code=400, detail="owner and state are required")

    try:
        payload_b64, sig_b64 = state_norm.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid oauth state") from exc

    expected_sig = hmac.new(_state_signing_secret().encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_encode(expected_sig), sig_b64):
        raise HTTPException(status_code=400, detail="invalid oauth state")

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid oauth state") from exc

    nonce = str(payload.get("nonce") or "").strip()
    provider = str(payload.get("provider") or "")
    exp = int(payload.get("exp") or 0)
    payload_owner = str(payload.get("owner") or "").strip()
    payload_redirect_uri = str(payload.get("redirect_uri") or "").strip()
    expected_redirect_uri = _validate_google_redirect_uri((getattr(S, "google_oauth_redirect_uri", "") or "").strip())
    if provider != "google_drive" or not nonce or payload_owner != owner_norm or payload_redirect_uri != expected_redirect_uri:
        raise HTTPException(status_code=400, detail="invalid oauth state")

    if _now_epoch() >= exp:
        raise HTTPException(status_code=400, detail="oauth state expired")

    key = {"PK": _pk(owner_norm), "SK": _sk("google_drive", nonce)}
    try:
        resp = T.projects.update_item(
            Key=key,
            ConditionExpression="attribute_exists(PK) AND attribute_exists(SK) AND attribute_not_exists(consumed_at)",
            UpdateExpression="SET consumed_at = :ts",
            ExpressionAttributeValues={":ts": datetime.now(timezone.utc).isoformat()},
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            existing = T.projects.get_item(Key=key, ConsistentRead=True).get("Item") or {}
            if existing.get("consumed_at"):
                raise HTTPException(status_code=400, detail="oauth state already used") from exc
            raise HTTPException(status_code=400, detail="oauth state not found") from exc
        raise

    item = resp.get("Attributes") or {}
    if not hmac.compare_digest(str(item.get("state_sig") or ""), sig_b64):
        raise HTTPException(status_code=400, detail="invalid oauth state")
    if str(item.get("provider") or "") != "google_drive":
        raise HTTPException(status_code=400, detail="invalid oauth state")

    return payload


def _google_token_endpoint() -> str:
    return (getattr(S, "google_oauth_token_url", "https://oauth2.googleapis.com/token") or "https://oauth2.googleapis.com/token").strip()


def complete_google_oauth_callback(owner: str, *, code: str, state: str) -> Dict[str, Any]:
    owner_norm = (owner or "").strip()
    code_norm = (code or "").strip()
    state_norm = (state or "").strip()
    if not owner_norm:
        raise HTTPException(status_code=400, detail="owner is required")
    if not code_norm:
        raise HTTPException(status_code=400, detail="code is required")
    if not state_norm:
        raise HTTPException(status_code=400, detail="state is required")

    consume_google_oauth_state(owner_norm, state_norm)

    client_id = (getattr(S, "google_oauth_client_id", "") or "").strip()
    client_secret = (getattr(S, "google_oauth_client_secret", "") or "").strip()
    redirect_uri = _validate_google_redirect_uri((getattr(S, "google_oauth_redirect_uri", "") or "").strip())
    if not client_id or not client_secret or not redirect_uri:
        raise HTTPException(status_code=500, detail="google oauth callback configuration is incomplete")

    try:
        response = requests.post(
            _google_token_endpoint(),
            data={
                "code": code_norm,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        audit_event("provider_oauth_connect", owner_norm, None, outcome="failure", provider="google_drive", reason="token_exchange_request_failed")
        raise HTTPException(status_code=502, detail="google oauth token exchange request failed") from exc

    body = response.json() if response.content else {}
    if response.status_code in (400, 401):
        err = str((body or {}).get("error") or "invalid_grant")
        desc = str((body or {}).get("error_description") or "authorization code is invalid or expired")
        audit_event("provider_oauth_connect", owner_norm, None, outcome="failure", provider="google_drive", reason=err)
        raise HTTPException(status_code=400, detail=f"google oauth token exchange failed: {err}: {desc}")
    if response.status_code == 403:
        audit_event("provider_oauth_connect", owner_norm, None, outcome="failure", provider="google_drive", reason="access_denied")
        raise HTTPException(status_code=403, detail="google oauth token exchange denied")
    if response.status_code >= 500:
        audit_event("provider_oauth_connect", owner_norm, None, outcome="failure", provider="google_drive", reason="upstream_unavailable")
        raise HTTPException(status_code=502, detail=f"google oauth token exchange failed ({response.status_code})")
    if response.status_code >= 400:
        audit_event("provider_oauth_connect", owner_norm, None, outcome="failure", provider="google_drive", reason="oauth_exchange_failed")
        raise HTTPException(status_code=400, detail=f"google oauth token exchange failed ({response.status_code})")

    if not isinstance(body, dict):
        audit_event("provider_oauth_connect", owner_norm, None, outcome="failure", provider="google_drive", reason="invalid_token_payload")
        raise HTTPException(status_code=400, detail="google oauth token exchange returned invalid response")

    access_token = str(body.get("access_token") or "").strip()
    if not access_token:
        audit_event("provider_oauth_connect", owner_norm, None, outcome="failure", provider="google_drive", reason="missing_access_token")
        raise HTTPException(status_code=400, detail="google oauth token exchange returned no access_token")

    refresh_token = str(body.get("refresh_token") or "").strip()
    expires_in_raw = body.get("expires_in")
    try:
        expires_in = int(expires_in_raw) if expires_in_raw is not None else None
    except (TypeError, ValueError):
        expires_in = None

    token_scope = str(body.get("scope") or "").strip()
    scopes = [s.strip().lower() for s in token_scope.split() if s.strip()]

    expires_at = None
    if expires_in is not None and expires_in > 0:
        expires_at = datetime.fromtimestamp(_now_epoch() + expires_in, tz=timezone.utc).isoformat()

    metadata: Dict[str, Any] = {
        "token_type": str(body.get("token_type") or "Bearer"),
        "expires_in": expires_in,
        "expires_at": expires_at,
    }
    if refresh_token:
        # Store refresh token encrypted-at-rest, same as access token handling.
        from app.core.crypto import kms_encrypt

        metadata["refresh_token_ct_b64"] = kms_encrypt(refresh_token)

    stored = upsert_provider_credential(
        owner_norm,
        "google_drive",
        access_token,
        required_scopes=None,
        metadata_override=metadata,
        scopes_override=scopes,
    )

    audit_event("provider_oauth_connect", owner_norm, None, outcome="success", provider="google_drive")

    return {
        "provider": stored.provider,
        "scopes": stored.scopes,
        "metadata": stored.metadata,
        "created_at": stored.created_at,
        "updated_at": stored.updated_at,
    }


def _normalize_google_auth_failure_reason(error_code: str, error_description: str = "") -> str:
    code = (error_code or "").strip().lower()
    desc = (error_description or "").strip().lower()
    if code in {"invalid_grant", "invalid_token"} or "revoked" in desc:
        return "revoked"
    if code in {"insufficient_scope", "invalid_scope"} or "insufficient" in desc or "scope" in desc:
        return "insufficient_scope"
    if code in {"access_denied", "forbidden"} or "access" in desc:
        return "access_removed"
    return "access_removed"


def _raise_google_reconnect_required(reason: str) -> None:
    raise HTTPException(
        status_code=401,
        detail={
            "code": "provider_reconnect_required",
            "provider": "google_drive",
            "reason": reason,
            "reconnect_required": True,
            "action": "reconnect_google_drive",
        },
    )


def refresh_google_oauth_access_token(
    owner: str,
    *,
    org: Optional[str] = None,
    required_scopes: Optional[list[str]] = None,
) -> Dict[str, Any]:
    record_filemgr_mount_refresh_attempt("google_drive", "attempt", "start")
    cred = get_provider_credential(owner, "google_drive", org=org)
    metadata = dict(cred.metadata or {})

    refresh_token_ct_b64 = str(metadata.get("refresh_token_ct_b64") or "").strip()
    if not refresh_token_ct_b64:
        merge_provider_credential_metadata(
            owner,
            "google_drive",
            org=org,
            metadata_updates={
                "oauth_status": "reconnect_required",
                "auth_failure_reason": "revoked",
                "reconnect_required": True,
            },
        )
        audit_event("provider_oauth_refresh", owner, None, outcome="failure", provider="google_drive", reason="revoked")
        record_filemgr_mount_refresh_attempt("google_drive", "failure", "revoked")
        _raise_google_reconnect_required("revoked")

    from app.core.crypto import kms_decrypt

    try:
        refresh_token = kms_decrypt(refresh_token_ct_b64).decode("utf-8")
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail="credential decryption is not configured") from exc

    client_id = (getattr(S, "google_oauth_client_id", "") or "").strip()
    client_secret = (getattr(S, "google_oauth_client_secret", "") or "").strip()
    if not client_id or not client_secret:
        raise HTTPException(status_code=500, detail="google oauth refresh configuration is incomplete")

    try:
        response = requests.post(
            _google_token_endpoint(),
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        audit_event("provider_oauth_refresh", owner, None, outcome="failure", provider="google_drive", reason="token_refresh_request_failed")
        record_filemgr_mount_refresh_attempt("google_drive", "failure", "request_error")
        raise HTTPException(status_code=502, detail="google oauth token refresh request failed") from exc

    body = response.json() if response.content else {}
    if response.status_code >= 400:
        err = str((body or {}).get("error") or "access_denied")
        desc = str((body or {}).get("error_description") or "")
        reason = _normalize_google_auth_failure_reason(err, desc)
        merge_provider_credential_metadata(
            owner,
            "google_drive",
            org=org,
            metadata_updates={
                "oauth_status": "reconnect_required",
                "auth_failure_reason": reason,
                "reconnect_required": True,
                "last_refresh_error": {"error": err, "error_description": desc},
            },
        )
        audit_event("provider_oauth_refresh", owner, None, outcome="failure", provider="google_drive", reason=reason)
        record_filemgr_mount_refresh_attempt("google_drive", "failure", reason)
        _raise_google_reconnect_required(reason)

    if not isinstance(body, dict):
        audit_event("provider_oauth_refresh", owner, None, outcome="failure", provider="google_drive", reason="invalid_token_payload")
        record_filemgr_mount_refresh_attempt("google_drive", "failure", "invalid_payload")
        raise HTTPException(status_code=400, detail="google oauth token refresh returned invalid response")

    access_token = str(body.get("access_token") or "").strip()
    if not access_token:
        audit_event("provider_oauth_refresh", owner, None, outcome="failure", provider="google_drive", reason="missing_access_token")
        record_filemgr_mount_refresh_attempt("google_drive", "failure", "missing_access_token")
        raise HTTPException(status_code=400, detail="google oauth token refresh returned no access_token")

    scope_raw = str(body.get("scope") or "").strip()
    scopes = [s.strip().lower() for s in scope_raw.split() if s.strip()] if scope_raw else list(cred.scopes or [])
    req = [s.strip().lower() for s in (required_scopes or []) if s and s.strip()]
    missing = [s for s in req if s not in scopes]
    if missing:
        merge_provider_credential_metadata(
            owner,
            "google_drive",
            org=org,
            metadata_updates={
                "oauth_status": "reconnect_required",
                "auth_failure_reason": "insufficient_scope",
                "reconnect_required": True,
                "missing_scopes": missing,
            },
        )
        audit_event("provider_oauth_refresh", owner, None, outcome="failure", provider="google_drive", reason="insufficient_scope")
        record_filemgr_mount_refresh_attempt("google_drive", "failure", "insufficient_scope")
        _raise_google_reconnect_required("insufficient_scope")

    expires_in = None
    try:
        if body.get("expires_in") is not None:
            expires_in = int(body.get("expires_in"))
    except (TypeError, ValueError):
        expires_in = None

    expires_at = None
    if expires_in and expires_in > 0:
        expires_at = datetime.fromtimestamp(_now_epoch() + expires_in, tz=timezone.utc).isoformat()

    updated = rotate_provider_access_token(
        owner,
        "google_drive",
        access_token,
        org=org,
        scopes_override=scopes,
        metadata_override={
            "token_type": str(body.get("token_type") or metadata.get("token_type") or "Bearer"),
            "expires_in": expires_in,
            "expires_at": expires_at,
            "oauth_status": "active",
            "reconnect_required": False,
            "auth_failure_reason": None,
            "last_refresh_error": None,
            "last_refreshed_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    from app.core.crypto import kms_decrypt

    token = kms_decrypt(updated.token_ct_b64).decode("utf-8")
    audit_event("provider_oauth_refresh", owner, None, outcome="success", provider="google_drive")
    record_filemgr_mount_refresh_attempt("google_drive", "success", "none")
    return {
        "token": token,
        "provider": updated.provider,
        "org": updated.org,
        "scopes": list(updated.scopes or []),
        "metadata": dict(updated.metadata or {}),
    }


def validate_google_drive_mount_oauth_configuration() -> None:
    if not bool(getattr(S, "filemgr_google_drive_mounts_enabled", False)):
        return

    missing = []
    if not (getattr(S, "google_oauth_client_id", "") or "").strip():
        missing.append("GOOGLE_OAUTH_CLIENT_ID")
    if not (getattr(S, "google_oauth_client_secret", "") or "").strip():
        missing.append("GOOGLE_OAUTH_CLIENT_SECRET")
    if not (getattr(S, "google_oauth_redirect_uri", "") or "").strip():
        missing.append("GOOGLE_OAUTH_REDIRECT_URI")
    if not (getattr(S, "google_oauth_redirect_uri_allowlist", "") or "").strip():
        missing.append("GOOGLE_OAUTH_REDIRECT_URI_ALLOWLIST")
    state_secret = (getattr(S, "google_oauth_state_signing_secret", "") or "").strip()
    fallback_secret = (getattr(S, "ui_access_token_secret", "") or "").strip()
    if not state_secret and not fallback_secret:
        missing.append("GOOGLE_OAUTH_STATE_SIGNING_SECRET or UI_ACCESS_TOKEN_SECRET")

    if missing:
        joined = ", ".join(missing)
        raise RuntimeError(
            "Google Drive mounts are enabled but OAuth configuration is incomplete: " + joined
        )

    _validate_google_redirect_uri((getattr(S, "google_oauth_redirect_uri", "") or "").strip())
