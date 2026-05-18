from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from app.services.jira_outbound_sync import produce_outbound_sync_tasks
from app.services.jira_ticket_sync_store import JiraTicketSyncStore


@dataclass(frozen=True)
class JiraConflictResolutionError(RuntimeError):
    code: str
    message: str
    status_code: int


def resolve_link_conflict(
    *,
    workspace_id: str,
    ticket_id: str,
    link_id: str,
    action: str,
    current_ticket: dict[str, Any] | None = None,
    store: JiraTicketSyncStore | None = None,
    enqueue: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    repo = store or JiraTicketSyncStore()
    link = repo.get_external_link(internal_ticket_id=ticket_id, link_id=link_id)
    if not link:
        raise JiraConflictResolutionError(code="jira_link_not_found", message="Jira link not found", status_code=404)
    if str(link.get("sync_state") or "") != "conflict":
        raise JiraConflictResolutionError(code="jira_conflict_not_active", message="No active conflict to resolve", status_code=409)

    conflict_payload = link.get("conflict_payload") if isinstance(link.get("conflict_payload"), dict) else {}
    local_candidates = conflict_payload.get("local") if isinstance(conflict_payload.get("local"), dict) else {}
    remote_candidates = conflict_payload.get("remote") if isinstance(conflict_payload.get("remote"), dict) else {}
    conflict_fields = [str(x) for x in (link.get("conflict_fields") or [])]

    if action not in {"keep_internal", "keep_jira"}:
        raise JiraConflictResolutionError(code="jira_conflict_action_invalid", message="Unsupported conflict action", status_code=400)

    resolved_ticket = dict(current_ticket or {})
    follow_up_tasks: list[dict[str, Any]] = []
    if action == "keep_internal":
        for k, v in local_candidates.items():
            resolved_ticket[k] = v
        follow_up_tasks = produce_outbound_sync_tasks(
            workspace_id=workspace_id,
            ticket_id=ticket_id,
            mutation_type="update",
            previous_ticket=dict(remote_candidates),
            current_ticket=dict(local_candidates),
            actor_user_id="conflict_resolver",
            store=repo,
            enqueue=enqueue,
        )
        repo.clear_external_link_conflict(
            internal_ticket_id=ticket_id,
            link_id=link_id,
            last_sync_direction="outbound",
        )
    else:  # keep_jira
        for k, v in remote_candidates.items():
            resolved_ticket[k] = v
        repo.clear_external_link_conflict(
            internal_ticket_id=ticket_id,
            link_id=link_id,
            last_sync_direction="inbound",
        )

    repo.append_sync_event(
        workspace_id=workspace_id,
        internal_ticket_id=ticket_id,
        direction="conflict_resolution",
        result="success",
        error_code=action,
        payload_hash=f"resolve:{link_id}:{action}"[:64],
        trace_id=f"jira-conflict-{link_id[:8]}",
    )

    return {
        "ticket_id": ticket_id,
        "link_id": link_id,
        "action": action,
        "resolved_fields": conflict_fields,
        "resolved_ticket": resolved_ticket,
        "follow_up_tasks": follow_up_tasks,
        "sync_state": "in_sync",
    }
