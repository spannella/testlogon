from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any
from app.services.jira_api_client import JiraApiClient, JiraApiClientError
from app.services.jira_token_lifecycle import JiraConnectionLifecycleError, get_or_refresh_access_token
from app.services.jira_ticket_sync_store import JiraTicketSyncStore


@dataclass(frozen=True)
class JiraProjectRow:
    cloud_id: str
    project_id: str
    project_key: str
    name: str
    is_private: bool


@dataclass(frozen=True)
class JiraProjectListResult:
    items: list[JiraProjectRow]
    next_cursor: str | None


class JiraProjectDiscoveryError(RuntimeError):
    def __init__(self, *, code: str, message: str, status_code: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = int(status_code)


def _encode_cursor(*, start_at: int, connection_id: str) -> str:
    raw = json.dumps({"start_at": int(start_at), "connection_id": connection_id}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_cursor(cursor: str | None) -> tuple[int, str | None]:
    if not cursor:
        return 0, None
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
        return int(payload.get("start_at") or 0), str(payload.get("connection_id") or "") or None
    except Exception:
        raise JiraProjectDiscoveryError(code="jira_projects_cursor_invalid", message="Invalid cursor", status_code=400)


def _select_connection(*, store: JiraTicketSyncStore, workspace_id: str, user_sub: str, cloud_id: str, cursor_connection_id: str | None) -> dict[str, Any]:
    if cursor_connection_id:
        row = store.get_connection(workspace_id=workspace_id, connection_id=cursor_connection_id)
        if row and row.get("user_id") == user_sub and row.get("cloud_id") == cloud_id:
            return row

    candidates = store.list_workspace_connections(workspace_id=workspace_id, limit=100)
    for row in candidates:
        if row.get("entity_type") != "jira_connection":
            continue
        if row.get("user_id") != user_sub:
            continue
        if str(row.get("status") or "") not in {"active", "degraded"}:
            continue
        if str(row.get("cloud_id") or "") != cloud_id:
            continue
        return row

    raise JiraProjectDiscoveryError(
        code="jira_connection_not_found",
        message="No active Jira connection found for user/workspace/cloud",
        status_code=404,
    )


def list_projects(
    *,
    workspace_id: str,
    user_sub: str,
    cloud_id: str,
    q: str | None,
    project_keys: list[str] | None,
    cursor: str | None,
    limit: int,
    store: JiraTicketSyncStore | None = None,
    client: JiraApiClient | None = None,
) -> JiraProjectListResult:
    repo = store or JiraTicketSyncStore()
    start_at, cursor_connection_id = _decode_cursor(cursor)
    conn = _select_connection(
        store=repo,
        workspace_id=workspace_id,
        user_sub=user_sub,
        cloud_id=cloud_id,
        cursor_connection_id=cursor_connection_id,
    )

    try:
        access_token = get_or_refresh_access_token(
            workspace_id=workspace_id,
            connection_id=str(conn.get("connection_id") or ""),
            store=repo,
        )
    except JiraConnectionLifecycleError as exc:
        raise JiraProjectDiscoveryError(code=exc.code, message=exc.message, status_code=exc.status_code) from exc

    api = client or JiraApiClient()
    effective_limit = max(1, min(int(limit), 100))
    try:
        status, body = api.search_projects(
            cloud_id=cloud_id,
            access_token=access_token,
            start_at=start_at,
            max_results=effective_limit,
            query=q,
            project_keys=project_keys,
        )
    except JiraApiClientError as exc:
        raise JiraProjectDiscoveryError(code=exc.code, message=exc.message, status_code=exc.status_code) from exc
    if status >= 400:
        msg = str((body.get("errorMessages") or [""])[0] or body.get("message") or "Jira project query failed")
        raise JiraProjectDiscoveryError(code="jira_projects_query_failed", message=msg, status_code=502 if status >= 500 else 400)

    values = body.get("values") or []
    items: list[JiraProjectRow] = []
    for row in values:
        if not isinstance(row, dict):
            continue
        key = str(row.get("key") or "").strip()
        if project_keys and key and key not in project_keys:
            continue
        items.append(
            JiraProjectRow(
                cloud_id=cloud_id,
                project_id=str(row.get("id") or ""),
                project_key=key,
                name=str(row.get("name") or ""),
                is_private=bool(row.get("isPrivate") or False),
            )
        )

    is_last = bool(body.get("isLast") is True)
    next_start = int(body.get("startAt") or start_at) + int(body.get("maxResults") or effective_limit)
    next_cursor = None if is_last else _encode_cursor(start_at=next_start, connection_id=str(conn.get("connection_id") or ""))

    return JiraProjectListResult(items=items, next_cursor=next_cursor)
