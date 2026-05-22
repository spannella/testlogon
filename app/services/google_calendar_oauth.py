from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from urllib.parse import urlencode

import requests
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.metrics import record_google_calendar_oauth_callback_outcome, record_google_calendar_oauth_callback_rejection
from app.services.google_calendar_connections import (
    disconnect_calendar_provider_connection,
    get_calendar_provider_connection,
    upsert_calendar_provider_connection,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _state_pk(state: str) -> str:
    return f"gcal_oauth_state#{state}"


def _state_sk() -> str:
    return "meta"


def _oauth_scopes() -> list[str]:
    raw = str(getattr(S, "google_calendar_oauth_scopes", "") or "").strip()
    if not raw:
        return ["openid", "email", "profile", "https://www.googleapis.com/auth/calendar.events"]
    return [s.strip() for s in raw.split(",") if s.strip()]


def _scope_set(value: str) -> set[str]:
    return {part.strip() for part in str(value or "").split() if part.strip()}


def _validate_granted_scopes(granted_scope_raw: str) -> None:
    granted = _scope_set(granted_scope_raw)
    expected = set(_oauth_scopes())
    required_google_scopes = {scope for scope in expected if scope.startswith("https://www.googleapis.com/auth/")}

    if required_google_scopes and not granted:
        record_google_calendar_oauth_callback_rejection(reason="scope_validation_failed_empty_grant")
        record_google_calendar_oauth_callback_outcome(outcome="error", reason="scope_validation_failed_empty_grant")
        raise HTTPException(status_code=400, detail="google oauth scope validation failed")

    missing = required_google_scopes - granted
    if missing:
        record_google_calendar_oauth_callback_rejection(reason="scope_validation_failed_missing_required")
        record_google_calendar_oauth_callback_outcome(outcome="error", reason="scope_validation_failed_missing_required")
        raise HTTPException(status_code=400, detail="google oauth required scope missing")

    strict = bool(getattr(S, "google_calendar_oauth_strict_scope_validation", False))
    if strict:
        unexpected = granted - expected
        if unexpected:
            record_google_calendar_oauth_callback_rejection(reason="scope_validation_failed_unexpected_scope")
            record_google_calendar_oauth_callback_outcome(outcome="error", reason="scope_validation_failed_unexpected_scope")
            raise HTTPException(status_code=400, detail="google oauth unexpected scope granted")


def _oauth_client_id() -> str:
    client_id = str(getattr(S, "google_calendar_oauth_client_id", "") or "").strip()
    if not client_id:
        raise HTTPException(status_code=500, detail="google oauth client id not configured")
    return client_id


def _oauth_client_secret() -> str:
    secret = str(getattr(S, "google_calendar_oauth_client_secret", "") or "").strip()
    if not secret:
        raise HTTPException(status_code=500, detail="google oauth client secret not configured")
    return secret


def _oauth_redirect_uri() -> str:
    redirect_uri = str(getattr(S, "google_calendar_oauth_redirect_uri", "") or "").strip()
    if not redirect_uri:
        raise HTTPException(status_code=500, detail="google oauth redirect uri not configured")
    return redirect_uri


def _state_ttl_seconds() -> int:
    ttl = int(getattr(S, "google_calendar_oauth_state_ttl_seconds", 600) or 600)
    return max(60, min(3600, ttl))


def _authorization_url(*, state: str, nonce: str) -> str:
    params = {
        "client_id": _oauth_client_id(),
        "redirect_uri": _oauth_redirect_uri(),
        "response_type": "code",
        "scope": " ".join(_oauth_scopes()),
        "access_type": "offline",
        "include_granted_scopes": "true",
        "prompt": "consent",
        "state": state,
        "nonce": nonce,
    }
    base = str(getattr(S, "google_calendar_oauth_auth_base_url", "") or "").strip()
    if not base:
        raise HTTPException(status_code=500, detail="google oauth auth base url not configured")
    return f"{base}?{urlencode(params)}"


def create_connect_start_state(*, user_sub: str) -> Dict[str, Any]:
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    now = _utc_now()
    expires_at = now + timedelta(seconds=_state_ttl_seconds())

    item = {
        "calendar_id": _state_pk(state),
        "sk": _state_sk(),
        "type": "google_oauth_state",
        "provider": "google",
        "user_sub": user_sub,
        "state": state,
        "nonce": nonce,
        "created_at_utc": _iso(now),
        "expires_at_utc": _iso(expires_at),
        "consumed": False,
    }
    T.calendar.put_item(Item=item)

    return {
        "provider": "google",
        "authorization_url": _authorization_url(state=state, nonce=nonce),
        "state": state,
        "nonce": nonce,
        "expires_at_utc": item["expires_at_utc"],
    }


def consume_connect_state(*, user_sub: str, state: str) -> Dict[str, Any]:
    state_norm = (state or "").strip()
    if len(state_norm) < 16:
        raise HTTPException(status_code=400, detail="invalid oauth state")

    item = T.calendar.get_item(Key={"calendar_id": _state_pk(state_norm), "sk": _state_sk()}).get("Item")
    if not item or item.get("type") != "google_oauth_state":
        raise HTTPException(status_code=400, detail="invalid oauth state")
    if str(item.get("user_sub") or "") != user_sub:
        raise HTTPException(status_code=403, detail="oauth state does not belong to user")
    if bool(item.get("consumed")):
        raise HTTPException(status_code=400, detail="oauth state already consumed")

    expires_raw = str(item.get("expires_at_utc") or "")
    try:
        expires_at = _parse_iso(expires_raw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid oauth state") from exc
    if expires_at <= _utc_now():
        raise HTTPException(status_code=400, detail="oauth state expired")

    consumed_at_utc = _iso(_utc_now())
    table = T.calendar
    if hasattr(table, "update_item"):
        try:
            out = table.update_item(
                Key={"calendar_id": _state_pk(state_norm), "sk": _state_sk()},
                UpdateExpression="SET #consumed = :consumed, consumed_at_utc = :consumed_at",
                ConditionExpression="attribute_not_exists(#consumed) OR #consumed = :not_consumed",
                ExpressionAttributeNames={"#consumed": "consumed"},
                ExpressionAttributeValues={
                    ":consumed": True,
                    ":consumed_at": consumed_at_utc,
                    ":not_consumed": False,
                },
                ReturnValues="ALL_NEW",
            )
        except Exception as exc:  # pragma: no cover - provider-specific conditional exceptions
            if "ConditionalCheckFailed" in str(exc):
                raise HTTPException(status_code=400, detail="oauth state already consumed") from exc
            raise
        attrs = out.get("Attributes") if isinstance(out, dict) else None
        if isinstance(attrs, dict) and attrs:
            return attrs

    item["consumed"] = True
    item["consumed_at_utc"] = consumed_at_utc
    table.put_item(Item=item)
    return item


def exchange_code_for_tokens(*, code: str) -> Dict[str, Any]:
    token_url = str(getattr(S, "google_calendar_oauth_token_url", "") or "").strip()
    if not token_url:
        raise HTTPException(status_code=500, detail="google oauth token url not configured")

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": _oauth_client_id(),
        "client_secret": _oauth_client_secret(),
        "redirect_uri": _oauth_redirect_uri(),
    }
    try:
        resp = requests.post(token_url, data=payload, timeout=15)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="google oauth token exchange temporarily unavailable") from exc
    if resp.status_code >= 400:
        raise HTTPException(status_code=400, detail="google oauth code exchange failed")

    data = resp.json() if resp.content else {}
    refresh_token = str(data.get("refresh_token") or "")
    access_token = str(data.get("access_token") or "")
    scope = str(data.get("scope") or "")
    if not access_token:
        raise HTTPException(status_code=400, detail="google oauth code exchange failed")
    require_refresh_token = bool(getattr(S, "google_calendar_oauth_require_refresh_token", True))
    if require_refresh_token and not refresh_token:
        raise HTTPException(status_code=400, detail="google oauth refresh token missing")
    _validate_granted_scopes(scope)

    expires_in = int(data.get("expires_in") or 3600)
    expires_at = _utc_now() + timedelta(seconds=max(1, expires_in))
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": str(data.get("token_type") or "Bearer"),
        "scope": scope,
        "id_token": str(data.get("id_token") or ""),
        "expires_at_utc": _iso(expires_at),
    }


def fetch_google_account_profile(*, access_token: str) -> Dict[str, str]:
    userinfo_url = str(getattr(S, "google_calendar_oauth_userinfo_url", "") or "").strip()
    if not userinfo_url:
        raise HTTPException(status_code=500, detail="google oauth userinfo url not configured")
    try:
        resp = requests.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="google account lookup temporarily unavailable") from exc
    if resp.status_code >= 400:
        raise HTTPException(status_code=400, detail="google account lookup failed")
    data = resp.json() if resp.content else {}
    return {
        "sub": str(data.get("sub") or ""),
        "email": str(data.get("email") or ""),
        "email_verified": str(data.get("email_verified") or ""),
    }


def _is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    raw = str(value or "").strip().lower()
    return raw in {"1", "true", "yes", "y"}


def handle_connect_callback(*, user_sub: str, state: str, code: str) -> Dict[str, Any]:
    consume_connect_state(user_sub=user_sub, state=state)
    token_payload = exchange_code_for_tokens(code=code)
    profile = fetch_google_account_profile(access_token=token_payload["access_token"])

    google_sub = str(profile.get("sub") or "").strip()
    if not google_sub:
        record_google_calendar_oauth_callback_rejection(reason="missing_google_subject")
        record_google_calendar_oauth_callback_outcome(outcome="error", reason="missing_google_subject")
        raise HTTPException(status_code=400, detail="google account profile missing subject")
    account_email = str(profile.get("email") or "").strip()
    if account_email and not _is_truthy(profile.get("email_verified")):
        record_google_calendar_oauth_callback_rejection(reason="unverified_google_email")
        record_google_calendar_oauth_callback_outcome(outcome="error", reason="unverified_google_email")
        raise HTTPException(status_code=400, detail="google account email is not verified")

    default_cid = str(getattr(S, "google_calendar_connection_default_id", "") or "").strip()
    connection_id = default_cid if default_cid else f"google-{google_sub}"

    out = upsert_calendar_provider_connection(
        user_sub=user_sub,
        connection_id=connection_id,
        account_email=account_email,
        token_payload=token_payload,
    )
    record_google_calendar_oauth_callback_outcome(outcome="success", reason="linked")
    return {
        "provider": "google",
        "connection_id": out["connection_id"],
        "account_email": out.get("account_email") or "",
        "linked": True,
        "updated_at_utc": out["updated_at_utc"],
    }


def revoke_google_token(*, token: str) -> None:
    revoke_url = str(getattr(S, "google_calendar_oauth_revoke_url", "") or "").strip()
    if not revoke_url:
        raise HTTPException(status_code=500, detail="google oauth revoke url not configured")
    try:
        resp = requests.post(
            revoke_url,
            data={"token": token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="google token revocation temporarily unavailable") from exc
    if resp.status_code >= 500:
        raise HTTPException(status_code=502, detail="google token revocation temporarily unavailable")
    if resp.status_code >= 400:
        body: Dict[str, Any] = {}
        try:
            body = resp.json() if resp.content else {}
        except ValueError:
            body = {}
        error_code = str(body.get("error") or "").strip().lower()
        if error_code == "invalid_token":
            # token already revoked/expired upstream; treat as terminally successful revocation
            return None
        raise HTTPException(status_code=400, detail="google token revocation failed")


def handle_disconnect(*, user_sub: str, connection_id: str) -> Dict[str, Any]:
    conn = get_calendar_provider_connection(
        user_sub=user_sub,
        connection_id=connection_id,
        include_tokens=True,
        include_inactive=False,
    )
    payload = conn.get("token_payload") if isinstance(conn.get("token_payload"), dict) else {}
    token = str(payload.get("refresh_token") or payload.get("access_token") or "")
    if not token:
        raise HTTPException(status_code=400, detail="google connection missing revocable token")

    try:
        revoke_google_token(token=token)
    except HTTPException as exc:
        if exc.status_code >= 500:
            raise HTTPException(status_code=502, detail="token revocation failed, retry later") from exc
        raise

    return disconnect_calendar_provider_connection(
        user_sub=user_sub,
        connection_id=connection_id,
        revoked=True,
        revoke_status="revoked",
    )
