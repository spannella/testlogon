from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import uuid

from app.services.jira_api_client import JiraApiClient
from app.services.jira_ticket_sync_store import JiraTicketSyncStore
from app.services.jira_token_lifecycle import get_or_refresh_access_token


@dataclass(frozen=True)
class JiraLinkCreateError(RuntimeError):
    code: str
    message: str
    status_code: int


def _select_active_connection(*, repo: JiraTicketSyncStore, workspace_id: str, user_sub: str) -> dict[str, Any]:
    connections = repo.list_connections_for_user(workspace_id=workspace_id, user_id=user_sub, limit=100)
    conn = next((row for row in connections if str(row.get("status") or "") in {"active", "degraded"}), None)
    if not conn:
        raise JiraLinkCreateError(
            code="jira_connection_not_found",
            message="No active Jira connection found for user/workspace",
            status_code=404,
        )
    return conn


def create_jira_issue_and_link(
    *,
    workspace_id: str,
    ticket_id: str,
    user_sub: str,
    project_key: str,
    issue_type: str,
    link_mode: str,
    store: JiraTicketSyncStore | None = None,
    api: JiraApiClient | None = None,
) -> dict[str, Any]:
    repo = store or JiraTicketSyncStore()
    client = api or JiraApiClient()

    conn = _select_active_connection(repo=repo, workspace_id=workspace_id, user_sub=user_sub)

    connection_id = str(conn.get("connection_id") or "")
    cloud_id = str(conn.get("cloud_id") or "")
    access_token = get_or_refresh_access_token(workspace_id=workspace_id, connection_id=connection_id, store=repo)

    status, issue_body = client.create_issue(
        cloud_id=cloud_id,
        access_token=access_token,
        project_key=project_key,
        issue_type=issue_type,
        summary=f"Ticket {ticket_id}",
        description=f"Created from internal ticket {ticket_id}",
    )
    if status >= 400:
        raise JiraLinkCreateError(
            code="jira_issue_create_failed",
            message="Failed to create Jira issue",
            status_code=502 if status >= 500 else 400,
        )

    external_issue_id = str(issue_body.get("id") or "")
    external_issue_key = str(issue_body.get("key") or "")
    if not external_issue_id or not external_issue_key:
        raise JiraLinkCreateError(
            code="jira_issue_create_invalid_response",
            message="Jira issue create response missing id/key",
            status_code=502,
        )

    try:
        link_row = repo.create_external_link(
            workspace_id=workspace_id,
            internal_ticket_id=ticket_id,
            external_issue_id=external_issue_id,
            external_issue_key=external_issue_key,
            project_key=project_key,
            link_mode=link_mode,
            sync_state="queued",
            created_by=user_sub,
        )
        return link_row
    except Exception as exc:
        client.delete_issue(cloud_id=cloud_id, access_token=access_token, issue_id=external_issue_id)
        raise JiraLinkCreateError(
            code="jira_link_create_compensated",
            message="Local link persistence failed; Jira issue create was compensated by delete",
            status_code=502,
        ) from exc


def link_existing_jira_issue_to_ticket(
    *,
    workspace_id: str,
    ticket_id: str,
    user_sub: str,
    external_issue_id: str | None,
    external_issue_key: str | None,
    link_mode: str,
    store: JiraTicketSyncStore | None = None,
    api: JiraApiClient | None = None,
) -> dict[str, Any]:
    repo = store or JiraTicketSyncStore()
    client = api or JiraApiClient()
    normalized_issue_id = str(external_issue_id or "").strip()
    normalized_issue_key = str(external_issue_key or "").strip()
    if not normalized_issue_id and not normalized_issue_key:
        raise JiraLinkCreateError(
            code="jira_issue_identifier_required",
            message="Provide external_issue_id or external_issue_key",
            status_code=400,
        )

    # Idempotency: if already linked for this ticket/issue, return existing row.
    existing = repo.find_active_link_for_ticket_issue(
        internal_ticket_id=ticket_id,
        external_issue_id=normalized_issue_id,
        external_issue_key=normalized_issue_key,
    )
    if existing is not None:
        return existing

    conn = _select_active_connection(repo=repo, workspace_id=workspace_id, user_sub=user_sub)
    connection_id = str(conn.get("connection_id") or "")
    cloud_id = str(conn.get("cloud_id") or "")
    access_token = get_or_refresh_access_token(workspace_id=workspace_id, connection_id=connection_id, store=repo)

    lookup_id = normalized_issue_id or normalized_issue_key
    status, issue = client.get_issue(cloud_id=cloud_id, access_token=access_token, issue_id_or_key=lookup_id)
    if status == 404:
        raise JiraLinkCreateError(code="jira_issue_not_found", message="Jira issue not found", status_code=404)
    if status == 403:
        raise JiraLinkCreateError(code="jira_issue_forbidden", message="Insufficient Jira permissions", status_code=403)
    if status >= 400:
        raise JiraLinkCreateError(code="jira_issue_lookup_failed", message="Failed to lookup Jira issue", status_code=502)

    resolved_issue_id = str(issue.get("id") or normalized_issue_id)
    resolved_issue_key = str(issue.get("key") or normalized_issue_key)
    if not resolved_issue_id or not resolved_issue_key:
        raise JiraLinkCreateError(
            code="jira_issue_lookup_invalid_response",
            message="Jira issue lookup response missing id/key",
            status_code=502,
        )

    try:
        return repo.create_external_link(
            workspace_id=workspace_id,
            internal_ticket_id=ticket_id,
            external_issue_id=resolved_issue_id,
            external_issue_key=resolved_issue_key,
            project_key=str(((issue.get("fields") or {}).get("project") or {}).get("key") or ""),
            link_mode=link_mode,
            sync_state="queued",
            created_by=user_sub,
        )
    except ValueError:
        # If create observed duplicate race, return existing mapping as idempotent behavior.
        existing = repo.find_active_link_for_ticket_issue(
            internal_ticket_id=ticket_id,
            external_issue_id=resolved_issue_id,
            external_issue_key=resolved_issue_key,
        )
        if existing is not None:
            return existing
        raise


def unlink_jira_issue_from_ticket(
    *,
    ticket_id: str,
    link_id: str,
    actor_user_id: str,
    store: JiraTicketSyncStore | None = None,
) -> dict[str, Any]:
    repo = store or JiraTicketSyncStore()
    current = repo.get_external_link(internal_ticket_id=ticket_id, link_id=link_id)
    if not current:
        raise JiraLinkCreateError(
            code="jira_link_not_found",
            message="Jira link not found for ticket",
            status_code=404,
        )
    updated = repo.deactivate_external_link(internal_ticket_id=ticket_id, link_id=link_id, actor_user_id=actor_user_id)
    if not updated:
        raise JiraLinkCreateError(
            code="jira_link_not_found",
            message="Jira link not found for ticket",
            status_code=404,
        )
    trace_id = f"jira-unlink-{uuid.uuid4().hex[:10]}"
    repo.append_sync_event(
        workspace_id=str(updated.get("workspace_id") or ""),
        internal_ticket_id=ticket_id,
        direction="internal_unlink",
        result="success",
        error_code="",
        payload_hash=f"unlink:{link_id}",
        trace_id=trace_id,
    )
    return {"ticket_id": ticket_id, "link_id": link_id, "unlinked": True, "trace_id": trace_id}
