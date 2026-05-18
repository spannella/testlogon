from __future__ import annotations

import logging
import random
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict

import requests
from fastapi import HTTPException

from app.core.settings import S
from app.metrics import record_google_calendar_api_retry, record_google_calendar_token_refresh_failure
from app.services.google_calendar_connections import (
    get_calendar_provider_connection,
    update_calendar_provider_connection_sync_status,
    upsert_calendar_provider_connection,
)

logger = logging.getLogger(__name__)


RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
AUTH_STATUS_CODES = {401, 403}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _api_base_url() -> str:
    return str(getattr(S, "google_calendar_api_base_url", "https://www.googleapis.com/calendar/v3") or "").rstrip("/")


def _timeout_seconds() -> int:
    value = int(getattr(S, "google_calendar_api_timeout_seconds", 20) or 20)
    return max(5, min(120, value))


def _retry_max_attempts() -> int:
    value = int(getattr(S, "google_calendar_api_retry_max_attempts", 3) or 3)
    return max(1, min(6, value))


def _retry_base_backoff_seconds() -> float:
    value = float(getattr(S, "google_calendar_api_retry_base_backoff_seconds", 0.25) or 0.25)
    return max(0.05, min(5.0, value))


def _retry_after_cap_seconds() -> float:
    value = float(getattr(S, "google_calendar_api_retry_after_max_seconds", 60.0) or 60.0)
    return max(1.0, min(600.0, value))


def _retry_sleep_seconds(attempt: int) -> float:
    exp_window = _retry_base_backoff_seconds() * (2 ** max(0, attempt - 1))
    jitter = random.uniform(0.0, exp_window * 0.5)
    return min(10.0, exp_window + jitter)


def _retry_after_seconds(resp: requests.Response | None) -> float | None:
    if resp is None:
        return None
    raw = str((resp.headers or {}).get("Retry-After") or "").strip()
    if not raw:
        return None
    try:
        seconds = float(raw)
    except ValueError:
        try:
            dt = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta_seconds = (dt.astimezone(timezone.utc) - _utc_now()).total_seconds()
        seconds = delta_seconds
    if seconds < 0:
        return None
    return min(_retry_after_cap_seconds(), seconds)


def _oauth_token_url() -> str:
    token_url = str(getattr(S, "google_calendar_oauth_token_url", "") or "").strip()
    if not token_url:
        raise HTTPException(status_code=500, detail="google oauth token url not configured")
    return token_url


def _oauth_client_id() -> str:
    value = str(getattr(S, "google_calendar_oauth_client_id", "") or "").strip()
    if not value:
        raise HTTPException(status_code=500, detail="google oauth client id not configured")
    return value


def _oauth_client_secret() -> str:
    value = str(getattr(S, "google_calendar_oauth_client_secret", "") or "").strip()
    if not value:
        raise HTTPException(status_code=500, detail="google oauth client secret not configured")
    return value


def _google_error_payload(resp: requests.Response) -> Dict[str, Any]:
    try:
        body = resp.json() if resp.content else {}
    except ValueError:
        body = {}
    if isinstance(body, dict):
        return body
    return {}


def _is_auth_error_response(resp: requests.Response) -> bool:
    if resp.status_code not in AUTH_STATUS_CODES:
        return False
    body = _google_error_payload(resp)
    err = body.get("error")
    if isinstance(err, dict):
        status = str(err.get("status") or "").upper()
        message = str(err.get("message") or "").lower()
        if status in {"UNAUTHENTICATED", "PERMISSION_DENIED"}:
            return True
        if "invalid credentials" in message or "login required" in message:
            return True
        for detail in err.get("errors") or []:
            if str((detail or {}).get("reason") or "").strip() in {"authError", "invalidCredentials"}:
                return True
    return True


def _classify_error(resp: requests.Response) -> tuple[bool, bool, str]:
    retryable = resp.status_code in RETRYABLE_STATUS_CODES
    reauth_required = _is_auth_error_response(resp)
    body = _google_error_payload(resp)
    err = body.get("error")
    if isinstance(err, dict):
        message = str(err.get("message") or "").strip() or f"google api request failed ({resp.status_code})"
    elif isinstance(err, str):
        message = err
    else:
        message = f"google api request failed ({resp.status_code})"
    return retryable, reauth_required, message


def _token_expired(connection: Dict[str, Any]) -> bool:
    payload = connection.get("token_payload") if isinstance(connection.get("token_payload"), dict) else {}
    expires_at = _parse_iso(str(payload.get("expires_at_utc") or ""))
    if not expires_at:
        return False
    return expires_at <= (_utc_now() + timedelta(seconds=30))


def refresh_google_calendar_access_token(*, user_sub: str, connection_id: str) -> Dict[str, Any]:
    conn = get_calendar_provider_connection(
        user_sub=user_sub,
        connection_id=connection_id,
        include_tokens=True,
        include_inactive=False,
    )
    payload = conn.get("token_payload") if isinstance(conn.get("token_payload"), dict) else {}
    refresh_token = str(payload.get("refresh_token") or "").strip()
    if not refresh_token:
        record_google_calendar_token_refresh_failure(reason="missing_refresh_token")
        update_calendar_provider_connection_sync_status(
            user_sub=user_sub,
            connection_id=connection_id,
            sync_health="error",
            last_sync_status="error",
            last_sync_error="google connection missing refresh token",
            reauth_required=True,
        )
        raise HTTPException(status_code=401, detail="google reauthorization required")

    resp = requests.post(
        _oauth_token_url(),
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": _oauth_client_id(),
            "client_secret": _oauth_client_secret(),
        },
        timeout=_timeout_seconds(),
    )
    if resp.status_code >= 400:
        body = _google_error_payload(resp)
        error_code = str(body.get("error") or "").strip()
        is_reauth = error_code in {"invalid_grant", "unauthorized_client"} or resp.status_code in AUTH_STATUS_CODES
        record_google_calendar_token_refresh_failure(reason="oauth_refresh_http_error")
        update_calendar_provider_connection_sync_status(
            user_sub=user_sub,
            connection_id=connection_id,
            sync_health="error",
            last_sync_status="error",
            last_sync_error=f"token refresh failed ({resp.status_code})",
            reauth_required=is_reauth,
        )
        if is_reauth:
            raise HTTPException(status_code=401, detail="google reauthorization required")
        raise HTTPException(status_code=502, detail="google token refresh temporarily unavailable")

    data = resp.json() if resp.content else {}
    access_token = str(data.get("access_token") or "").strip()
    if not access_token:
        record_google_calendar_token_refresh_failure(reason="invalid_refresh_payload")
        raise HTTPException(status_code=502, detail="google token refresh returned invalid payload")
    expires_in = int(data.get("expires_in") or 3600)
    expires_at_utc = _iso(_utc_now() + timedelta(seconds=max(60, expires_in)))
    next_payload = {
        "access_token": access_token,
        "refresh_token": str(data.get("refresh_token") or refresh_token),
        "token_type": str(data.get("token_type") or payload.get("token_type") or "Bearer"),
        "scope": str(data.get("scope") or payload.get("scope") or ""),
        "id_token": str(data.get("id_token") or payload.get("id_token") or ""),
        "expires_at_utc": expires_at_utc,
    }
    upsert_calendar_provider_connection(
        user_sub=user_sub,
        connection_id=connection_id,
        account_email=str(conn.get("account_email") or ""),
        token_payload=next_payload,
    )
    update_calendar_provider_connection_sync_status(
        user_sub=user_sub,
        connection_id=connection_id,
        sync_health="healthy",
        last_sync_status="success",
        last_sync_error="",
        reauth_required=False,
    )
    logger.info(
        "google_calendar_token_refreshed",
        extra={
            "correlation_id": f"gcal:token_refresh:{user_sub}:{connection_id}",
            "user_sub": user_sub,
            "connection_id": connection_id,
            "expires_at_utc": expires_at_utc,
        },
    )
    return next_payload


def _request_with_connection_token(
    *,
    user_sub: str,
    connection_id: str,
    method: str,
    path: str,
    params: Dict[str, Any] | None = None,
    json: Dict[str, Any] | None = None,
    extra_headers: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    correlation_id = f"gcal:req:{user_sub}:{connection_id}:{method.lower()}:{path.lstrip('/')}"
    connection = get_calendar_provider_connection(
        user_sub=user_sub,
        connection_id=connection_id,
        include_tokens=True,
        include_inactive=False,
    )
    token_payload = connection.get("token_payload") if isinstance(connection.get("token_payload"), dict) else {}
    access_token = str(token_payload.get("access_token") or "").strip()
    if not access_token or _token_expired(connection):
        token_payload = refresh_google_calendar_access_token(user_sub=user_sub, connection_id=connection_id)
        access_token = str(token_payload.get("access_token") or "").strip()

    url = f"{_api_base_url()}/{path.lstrip('/')}"
    headers = {"Authorization": f"Bearer {access_token}"}
    if extra_headers:
        headers.update({k: v for k, v in extra_headers.items() if v is not None})
    resp: requests.Response | None = None
    max_attempts = _retry_max_attempts()
    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.request(
                method=method.upper(),
                url=url,
                params=params or None,
                json=json or None,
                headers=headers,
                timeout=_timeout_seconds(),
            )
        except requests.RequestException as exc:
            if attempt < max_attempts:
                record_google_calendar_api_retry(reason="network_exception")
                time.sleep(_retry_sleep_seconds(attempt))
                continue
            update_calendar_provider_connection_sync_status(
                user_sub=user_sub,
                connection_id=connection_id,
                sync_health="degraded",
                last_sync_status="error",
                last_sync_error="google api network failure",
            )
            raise HTTPException(status_code=502, detail="google api temporarily unavailable") from exc

        if resp.status_code in AUTH_STATUS_CODES:
            token_payload = refresh_google_calendar_access_token(user_sub=user_sub, connection_id=connection_id)
            retry_headers = {"Authorization": f"Bearer {token_payload['access_token']}"}
            if extra_headers:
                retry_headers.update({k: v for k, v in extra_headers.items() if v is not None})
            try:
                resp = requests.request(
                    method=method.upper(),
                    url=url,
                    params=params or None,
                    json=json or None,
                    headers=retry_headers,
                    timeout=_timeout_seconds(),
                )
            except requests.RequestException as exc:
                if attempt < max_attempts:
                    record_google_calendar_api_retry(reason="network_exception_after_refresh")
                    time.sleep(_retry_sleep_seconds(attempt))
                    continue
                update_calendar_provider_connection_sync_status(
                    user_sub=user_sub,
                    connection_id=connection_id,
                    sync_health="degraded",
                    last_sync_status="error",
                    last_sync_error="google api network failure",
                )
                raise HTTPException(status_code=502, detail="google api temporarily unavailable") from exc

        if resp.status_code >= 400:
            retryable, reauth_required, message = _classify_error(resp)
            if retryable and not reauth_required and attempt < max_attempts:
                record_google_calendar_api_retry(reason="retryable_status_code", provider_status_code=resp.status_code)
                retry_after = _retry_after_seconds(resp)
                retry_sleep = max(_retry_sleep_seconds(attempt), retry_after) if retry_after is not None else _retry_sleep_seconds(attempt)
                logger.warning(
                    "google_calendar_api_request_retrying",
                    extra={
                        "correlation_id": correlation_id,
                        "attempt": attempt,
                        "status_code": resp.status_code,
                        "retry_after_seconds": retry_after,
                    },
                )
                time.sleep(retry_sleep)
                continue
            update_calendar_provider_connection_sync_status(
                user_sub=user_sub,
                connection_id=connection_id,
                sync_health="degraded" if retryable else "error",
                last_sync_status="error",
                last_sync_error=message,
                reauth_required=reauth_required,
            )
            status = 502 if retryable else 401 if reauth_required else 400
            raise HTTPException(
                status_code=status,
                detail={
                    "code": "google_api_error",
                    "message": message,
                    "retryable": retryable,
                    "reauth_required": reauth_required,
                    "provider_status_code": resp.status_code,
                },
            )
        break

    if resp is None:
        update_calendar_provider_connection_sync_status(
            user_sub=user_sub,
            connection_id=connection_id,
            sync_health="degraded",
            last_sync_status="error",
            last_sync_error="google api temporarily unavailable",
        )
        raise HTTPException(status_code=502, detail="google api temporarily unavailable")

    body = resp.json() if resp.content else {}
    update_calendar_provider_connection_sync_status(
        user_sub=user_sub,
        connection_id=connection_id,
        sync_health="healthy",
        last_sync_status="success",
        last_sync_error="",
        reauth_required=False,
        last_sync_at_utc=_iso(_utc_now()),
    )
    logger.info(
        "google_calendar_api_request_completed",
        extra={
            "correlation_id": correlation_id,
            "user_sub": user_sub,
            "connection_id": connection_id,
            "method": method.lower(),
            "path": path.lstrip("/"),
            "status_code": resp.status_code,
        },
    )
    return body if isinstance(body, dict) else {}


def list_google_calendars(*, user_sub: str, connection_id: str, page_token: str | None = None) -> Dict[str, Any]:
    params = {"maxResults": 250}
    if page_token:
        params["pageToken"] = page_token
    return _request_with_connection_token(
        user_sub=user_sub,
        connection_id=connection_id,
        method="GET",
        path="/users/me/calendarList",
        params=params,
    )


def list_google_calendar_events(
    *,
    user_sub: str,
    connection_id: str,
    google_calendar_id: str,
    sync_token: str | None = None,
    page_token: str | None = None,
    time_min: str | None = None,
    time_max: str | None = None,
) -> Dict[str, Any]:
    calendar_id = (google_calendar_id or "").strip()
    if not calendar_id:
        raise HTTPException(status_code=400, detail="google_calendar_id is required")
    params: Dict[str, Any] = {"maxResults": 250}
    if sync_token:
        params["syncToken"] = sync_token
    if page_token:
        params["pageToken"] = page_token
    if time_min and not sync_token:
        params["timeMin"] = time_min
    if time_max and not sync_token:
        params["timeMax"] = time_max
    return _request_with_connection_token(
        user_sub=user_sub,
        connection_id=connection_id,
        method="GET",
        path=f"/calendars/{calendar_id}/events",
        params=params,
    )


def watch_google_calendar_events(
    *,
    user_sub: str,
    connection_id: str,
    google_calendar_id: str,
    channel_id: str,
    webhook_url: str,
    channel_token: str | None = None,
    ttl_seconds: int | None = None,
) -> Dict[str, Any]:
    calendar_id = (google_calendar_id or "").strip()
    if not calendar_id:
        raise HTTPException(status_code=400, detail="google_calendar_id is required")
    if not channel_id or not webhook_url:
        raise HTTPException(status_code=400, detail="channel_id and webhook_url are required")

    payload: Dict[str, Any] = {"id": channel_id, "type": "web_hook", "address": webhook_url}
    if channel_token:
        payload["token"] = channel_token
    if ttl_seconds:
        payload["params"] = {"ttl": str(max(60, ttl_seconds))}

    return _request_with_connection_token(
        user_sub=user_sub,
        connection_id=connection_id,
        method="POST",
        path=f"/calendars/{calendar_id}/events/watch",
        json=payload,
    )


def create_google_calendar_event(
    *,
    user_sub: str,
    connection_id: str,
    google_calendar_id: str,
    event_body: Dict[str, Any],
) -> Dict[str, Any]:
    calendar_id = (google_calendar_id or "").strip()
    if not calendar_id:
        raise HTTPException(status_code=400, detail="google_calendar_id is required")
    return _request_with_connection_token(
        user_sub=user_sub,
        connection_id=connection_id,
        method="POST",
        path=f"/calendars/{calendar_id}/events",
        json=event_body,
    )


def patch_google_calendar_event(
    *,
    user_sub: str,
    connection_id: str,
    google_calendar_id: str,
    google_event_id: str,
    event_body: Dict[str, Any],
    if_match_etag: str | None = None,
) -> Dict[str, Any]:
    calendar_id = (google_calendar_id or "").strip()
    event_id = (google_event_id or "").strip()
    if not calendar_id or not event_id:
        raise HTTPException(status_code=400, detail="google calendar/event id is required")
    headers = {"If-Match": if_match_etag} if if_match_etag else None
    return _request_with_connection_token(
        user_sub=user_sub,
        connection_id=connection_id,
        method="PATCH",
        path=f"/calendars/{calendar_id}/events/{event_id}",
        json=event_body,
        extra_headers=headers,
    )


def delete_google_calendar_event(
    *,
    user_sub: str,
    connection_id: str,
    google_calendar_id: str,
    google_event_id: str,
    if_match_etag: str | None = None,
) -> Dict[str, Any]:
    calendar_id = (google_calendar_id or "").strip()
    event_id = (google_event_id or "").strip()
    if not calendar_id or not event_id:
        raise HTTPException(status_code=400, detail="google calendar/event id is required")
    headers = {"If-Match": if_match_etag} if if_match_etag else None
    return _request_with_connection_token(
        user_sub=user_sub,
        connection_id=connection_id,
        method="DELETE",
        path=f"/calendars/{calendar_id}/events/{event_id}",
        extra_headers=headers,
    )
