from __future__ import annotations

import time

from app.services.jira_oauth_exchange import JiraOAuthExchangeError, refresh_access_token
from app.services.jira_secret_refs import get_secret, put_secret
from app.services.jira_ticket_sync_store import JiraTicketSyncStore


class JiraConnectionLifecycleError(RuntimeError):
    def __init__(self, *, code: str, message: str, status_code: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = int(status_code)


_REFRESH_BUFFER_SECONDS = 120


def _now_ts() -> int:
    return int(time.time())


def _upsert_connection_with_status(store: JiraTicketSyncStore, row: dict, *, status: str, access_token_ref: str | None = None, refresh_token_ref: str | None = None, expires_at: int | None = None, scopes: list[str] | None = None) -> dict:
    return store.upsert_connection(
        workspace_id=row.get("workspace_id") or "",
        connection_id=row.get("connection_id") or "",
        user_id=row.get("user_id"),
        cloud_id=row.get("cloud_id") or "unknown",
        site_url=row.get("site_url") or "",
        auth_type=row.get("auth_type") or "oauth",
        scopes=scopes if scopes is not None else list(row.get("scopes") or []),
        access_token_ref=access_token_ref if access_token_ref is not None else str(row.get("access_token_ref") or ""),
        refresh_token_ref=refresh_token_ref if refresh_token_ref is not None else str(row.get("refresh_token_ref") or ""),
        expires_at=int(expires_at if expires_at is not None else row.get("expires_at") or 0),
        status=status,
    )


def get_or_refresh_access_token(*, workspace_id: str, connection_id: str, store: JiraTicketSyncStore | None = None) -> str:
    repo = store or JiraTicketSyncStore()
    row = repo.get_connection(workspace_id=workspace_id, connection_id=connection_id)
    if not row:
        raise JiraConnectionLifecycleError(code="jira_connection_not_found", message="Jira connection not found", status_code=404)

    if str(row.get("status") or "") not in {"active", "degraded"}:
        raise JiraConnectionLifecycleError(code="jira_connection_inactive", message="Jira connection is inactive", status_code=409)

    access_ref = str(row.get("access_token_ref") or "")
    access_token = get_secret(access_ref) if access_ref else None
    expires_at = int(row.get("expires_at") or 0)

    if access_token and expires_at > (_now_ts() + _REFRESH_BUFFER_SECONDS):
        return access_token

    refresh_ref = str(row.get("refresh_token_ref") or "")
    refresh_value = get_secret(refresh_ref) if refresh_ref else None
    if not refresh_value:
        _upsert_connection_with_status(repo, row, status="disconnected")
        raise JiraConnectionLifecycleError(
            code="jira_refresh_token_missing",
            message="Refresh token missing; connection moved to disconnected",
            status_code=401,
        )

    try:
        refreshed = refresh_access_token(refresh_token=refresh_value)
    except JiraOAuthExchangeError as exc:
        if exc.code == "jira_oauth_refresh_invalid":
            _upsert_connection_with_status(repo, row, status="disconnected")
            raise JiraConnectionLifecycleError(
                code="jira_connection_disconnected",
                message="Refresh token invalid/expired; connection moved to disconnected",
                status_code=401,
            ) from exc

        _upsert_connection_with_status(repo, row, status="degraded")
        raise JiraConnectionLifecycleError(
            code="jira_connection_degraded",
            message="Jira token refresh failed; connection moved to degraded",
            status_code=502,
        ) from exc

    new_access_ref = put_secret(refreshed.access_token, prefix="jira-oauth://access")
    new_refresh_ref = put_secret(refreshed.refresh_token, prefix="jira-oauth://refresh") if refreshed.refresh_token else refresh_ref
    updated = _upsert_connection_with_status(
        repo,
        row,
        status="active",
        access_token_ref=new_access_ref,
        refresh_token_ref=new_refresh_ref,
        expires_at=_now_ts() + max(60, int(refreshed.expires_in or 3600)),
        scopes=refreshed.scopes or list(row.get("scopes") or []),
    )

    token = get_secret(str(updated.get("access_token_ref") or ""))
    if not token:
        raise JiraConnectionLifecycleError(
            code="jira_access_token_unavailable",
            message="Refreshed access token unavailable after update",
            status_code=500,
        )
    return token
