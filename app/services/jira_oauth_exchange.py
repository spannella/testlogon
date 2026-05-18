from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from app.core.settings import S


class JiraOAuthExchangeError(RuntimeError):
    def __init__(self, *, code: str, message: str, status_code: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = int(status_code)


@dataclass(frozen=True)
class JiraOAuthTokens:
    access_token: str
    refresh_token: str
    expires_in: int
    scopes: list[str]


def _resolve_client_secret(*, settings: object | None = None) -> str:
    cfg = settings or S
    secret_ref = str(getattr(cfg, "jira_sync_oauth_client_secret_ref", "")).strip()
    secret_value = str(getattr(cfg, "jira_sync_oauth_client_secret_value", "")).strip()

    if secret_value:
        return secret_value

    if secret_ref.startswith("env://"):
        env_name = secret_ref.removeprefix("env://").strip()
        value = os.environ.get(env_name, "").strip()
        if value:
            return value

    raise JiraOAuthExchangeError(
        code="jira_oauth_client_secret_unavailable",
        message="OAuth client secret unavailable; set JIRA_SYNC_OAUTH_CLIENT_SECRET_VALUE or use env:// in JIRA_SYNC_OAUTH_CLIENT_SECRET_REF",
        status_code=500,
    )


def _json_post(url: str, payload: dict[str, Any], timeout_seconds: int = 15) -> tuple[int, dict[str, Any]]:
    req = urllib_request.Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout_seconds) as resp:  # nosec B310 - controlled URL from config
            status = int(getattr(resp, "status", 200))
            raw = resp.read().decode("utf-8") if resp else ""
            body = json.loads(raw) if raw else {}
            return status, body if isinstance(body, dict) else {}
    except HTTPError as exc:
        raw = exc.read().decode("utf-8") if hasattr(exc, "read") else ""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        return int(exc.code or 500), body if isinstance(body, dict) else {}
    except URLError as exc:
        raise JiraOAuthExchangeError(
            code="jira_oauth_exchange_network_error",
            message="Failed to reach Jira OAuth token endpoint",
            status_code=502,
        ) from exc


def _json_get(url: str, *, access_token: str, timeout_seconds: int = 15) -> tuple[int, Any]:
    req = urllib_request.Request(
        url=url,
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout_seconds) as resp:  # nosec B310 - controlled URL from config
            status = int(getattr(resp, "status", 200))
            raw = resp.read().decode("utf-8") if resp else ""
            return status, (json.loads(raw) if raw else [])
    except HTTPError as exc:
        return int(exc.code or 500), []
    except URLError:
        return 502, []


def exchange_authorization_code(*, code: str, redirect_uri: str, settings: object | None = None) -> JiraOAuthTokens:
    cfg = settings or S
    token_url = str(getattr(cfg, "jira_sync_oauth_token_url", "https://auth.atlassian.com/oauth/token")).strip()
    client_id = str(getattr(cfg, "jira_sync_oauth_client_id", "")).strip()
    client_secret = _resolve_client_secret(settings=cfg)

    if not client_id:
        raise JiraOAuthExchangeError(
            code="jira_oauth_client_id_missing",
            message="OAuth client id missing",
            status_code=500,
        )

    payload = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }

    status, body = _json_post(token_url, payload)
    if status >= 400:
        err = str(body.get("error") or "").strip()
        if err == "invalid_grant":
            raise JiraOAuthExchangeError(
                code="jira_oauth_code_invalid_or_expired",
                message="Authorization code is invalid or expired",
                status_code=401,
            )
        raise JiraOAuthExchangeError(
            code="jira_oauth_exchange_failed",
            message=f"Jira OAuth token exchange failed ({status})",
            status_code=502,
        )

    access_token = str(body.get("access_token") or "").strip()
    refresh_token = str(body.get("refresh_token") or "").strip()
    expires_in = int(body.get("expires_in") or 3600)
    scope_raw = str(body.get("scope") or "")
    scopes = [s for s in scope_raw.split(" ") if s]

    if not access_token:
        raise JiraOAuthExchangeError(
            code="jira_oauth_access_token_missing",
            message="Jira OAuth response missing access token",
            status_code=502,
        )

    return JiraOAuthTokens(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        scopes=scopes,
    )




def refresh_access_token(*, refresh_token: str, settings: object | None = None) -> JiraOAuthTokens:
    cfg = settings or S
    token_url = str(getattr(cfg, "jira_sync_oauth_token_url", "https://auth.atlassian.com/oauth/token")).strip()
    client_id = str(getattr(cfg, "jira_sync_oauth_client_id", "")).strip()
    client_secret = _resolve_client_secret(settings=cfg)

    if not client_id:
        raise JiraOAuthExchangeError(
            code="jira_oauth_client_id_missing",
            message="OAuth client id missing",
            status_code=500,
        )

    payload = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    }

    status, body = _json_post(token_url, payload)
    if status >= 400:
        err = str(body.get("error") or "").strip()
        if err in {"invalid_grant", "invalid_refresh_token"}:
            raise JiraOAuthExchangeError(
                code="jira_oauth_refresh_invalid",
                message="Refresh token is invalid or expired",
                status_code=401,
            )
        raise JiraOAuthExchangeError(
            code="jira_oauth_refresh_failed",
            message=f"Jira OAuth refresh failed ({status})",
            status_code=502,
        )

    access_token = str(body.get("access_token") or "").strip()
    next_refresh = str(body.get("refresh_token") or refresh_token).strip()
    expires_in = int(body.get("expires_in") or 3600)
    scope_raw = str(body.get("scope") or "")
    scopes = [s for s in scope_raw.split(" ") if s]

    if not access_token:
        raise JiraOAuthExchangeError(
            code="jira_oauth_access_token_missing",
            message="Jira OAuth refresh response missing access token",
            status_code=502,
        )

    return JiraOAuthTokens(
        access_token=access_token,
        refresh_token=next_refresh,
        expires_in=expires_in,
        scopes=scopes,
    )

def fetch_accessible_resource(*, access_token: str, settings: object | None = None) -> tuple[str, str]:
    cfg = settings or S
    resources_url = str(
        getattr(cfg, "jira_sync_oauth_resources_url", "https://api.atlassian.com/oauth/token/accessible-resources")
    ).strip()

    status, body = _json_get(resources_url, access_token=access_token)
    if status >= 400 or not isinstance(body, list) or not body:
        return "unknown", ""

    first = body[0] if isinstance(body[0], dict) else {}
    cloud_id = str(first.get("id") or "unknown")
    site_url = str(first.get("url") or "")
    return cloud_id, site_url
