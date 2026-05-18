from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
import secrets
import time

from app.core.settings import S


@dataclass(frozen=True)
class JiraOAuthState:
    state: str
    workspace_id: str
    user_sub: str
    redirect_uri: str
    created_at: int
    expires_at: int


@dataclass(frozen=True)
class JiraOAuthConfig:
    authorize_url: str
    audience: str
    client_id: str
    scopes: str
    state_ttl_seconds: int


class JiraOAuthConfigError(RuntimeError):
    def __init__(self, *, code: str, message: str, status_code: int = 500):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = int(status_code)


_state_lock = Lock()
_state_store: dict[str, JiraOAuthState] = {}


def _now_ts() -> int:
    return int(time.time())


def _prune_expired_states(now_ts: int) -> None:
    expired = [k for k, row in _state_store.items() if row.expires_at <= now_ts]
    for key in expired:
        _state_store.pop(key, None)


def get_jira_oauth_config(*, settings: object | None = None) -> JiraOAuthConfig:
    cfg = settings or S

    authorize_url = str(getattr(cfg, "jira_sync_oauth_authorize_url", "")).strip()
    audience = str(getattr(cfg, "jira_sync_oauth_audience", "api.atlassian.com")).strip()
    client_id = str(getattr(cfg, "jira_sync_oauth_client_id", "")).strip()
    scopes = str(getattr(cfg, "jira_sync_oauth_scopes", "read:jira-work write:jira-work offline_access")).strip()
    ttl = int(getattr(cfg, "jira_sync_oauth_state_ttl_seconds", 600) or 600)

    if not authorize_url:
        raise JiraOAuthConfigError(
            code="jira_oauth_authorize_url_missing",
            message="JIRA OAuth authorize URL missing; set JIRA_SYNC_OAUTH_AUTHORIZE_URL",
            status_code=500,
        )
    if not authorize_url.startswith("https://"):
        raise JiraOAuthConfigError(
            code="jira_oauth_authorize_url_invalid",
            message="JIRA OAuth authorize URL must be https://",
            status_code=500,
        )
    if not client_id:
        raise JiraOAuthConfigError(
            code="jira_oauth_client_id_missing",
            message="JIRA OAuth client id missing; set JIRA_SYNC_OAUTH_CLIENT_ID",
            status_code=500,
        )
    if ttl < 60 or ttl > 3600:
        raise JiraOAuthConfigError(
            code="jira_oauth_state_ttl_invalid",
            message="JIRA OAuth state TTL must be between 60 and 3600 seconds",
            status_code=500,
        )

    return JiraOAuthConfig(
        authorize_url=authorize_url,
        audience=audience,
        client_id=client_id,
        scopes=scopes,
        state_ttl_seconds=ttl,
    )


def create_and_store_oauth_state(
    *,
    workspace_id: str,
    user_sub: str,
    redirect_uri: str,
    state_ttl_seconds: int,
) -> JiraOAuthState:
    now = _now_ts()
    state = secrets.token_urlsafe(32)
    row = JiraOAuthState(
        state=state,
        workspace_id=workspace_id,
        user_sub=user_sub,
        redirect_uri=redirect_uri,
        created_at=now,
        expires_at=now + int(state_ttl_seconds),
    )
    with _state_lock:
        _prune_expired_states(now)
        _state_store[state] = row
    return row


def get_oauth_state(state: str) -> JiraOAuthState | None:
    with _state_lock:
        row = _state_store.get(state)
        if not row:
            return None
        if row.expires_at <= _now_ts():
            _state_store.pop(state, None)
            return None
        return row
