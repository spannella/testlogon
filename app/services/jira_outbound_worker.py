from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
import threading
from typing import Any

from app.services.jira_api_client import JiraApiClient
from app.services.jira_ticket_sync_store import JiraTicketSyncStore
from app.services.jira_token_lifecycle import get_or_refresh_access_token

logger = logging.getLogger(__name__)

_IDEMPOTENCY_LOCK = threading.Lock()
_PROCESSED_KEYS: set[str] = set()

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


@dataclass(frozen=True)
class JiraOutboundWorkerResult:
    outcome: str
    idempotency_key: str
    status_code: int
    retryable: bool


def _idempotency_key(task: dict[str, Any]) -> str:
    explicit = str(task.get("idempotency_key") or "").strip()
    if explicit:
        return explicit
    raw = json.dumps(task, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _already_processed(key: str) -> bool:
    with _IDEMPOTENCY_LOCK:
        if key in _PROCESSED_KEYS:
            return True
        _PROCESSED_KEYS.add(key)
        return False


def _map_fields(payload_ticket: dict[str, Any], changed_fields: list[str]) -> dict[str, Any]:
    mapped: dict[str, Any] = {}
    if "title" in changed_fields:
        mapped["summary"] = payload_ticket.get("title")
    if "description" in changed_fields:
        mapped["description"] = payload_ticket.get("description")
    if "status" in changed_fields:
        status_name = payload_ticket.get("status")
        if status_name not in (None, ""):
            mapped["status"] = {"name": status_name}
    if "priority" in changed_fields:
        priority_name = payload_ticket.get("priority")
        if priority_name not in (None, ""):
            mapped["priority"] = {"name": priority_name}
    if "assignee" in changed_fields:
        assignee_id = payload_ticket.get("assignee")
        if assignee_id not in (None, ""):
            mapped["assignee"] = {"accountId": assignee_id}
    if "labels" in changed_fields:
        mapped["labels"] = payload_ticket.get("labels") or []
    return {k: v for k, v in mapped.items() if v not in (None, "")}


def process_outbound_sync_task(
    *,
    task: dict[str, Any],
    store: JiraTicketSyncStore | None = None,
    api: JiraApiClient | None = None,
) -> JiraOutboundWorkerResult:
    repo = store or JiraTicketSyncStore()
    client = api or JiraApiClient()
    idem = _idempotency_key(task)
    if _already_processed(idem):
        return JiraOutboundWorkerResult(outcome="replayed", idempotency_key=idem, status_code=200, retryable=False)

    workspace_id = str(task.get("workspace_id") or "")
    ticket_id = str(task.get("ticket_id") or "")
    link_id = str(task.get("link_id") or "")
    mutation_type = str(task.get("mutation_type") or "")
    issue_id = str(task.get("external_issue_id") or "")
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    payload_ticket = payload.get("ticket") if isinstance(payload.get("ticket"), dict) else {}
    changed_fields = [str(x) for x in (task.get("changed_fields") or [])]

    link = repo.get_external_link(internal_ticket_id=ticket_id, link_id=link_id)
    if not link or str(link.get("sync_state") or "") == "deleted":
        return JiraOutboundWorkerResult(outcome="skipped_unlinked", idempotency_key=idem, status_code=404, retryable=False)

    connections = repo.list_workspace_connections(workspace_id=workspace_id, limit=100)
    conn = next((row for row in connections if str(row.get("status") or "") in {"active", "degraded"}), None)
    if not conn:
        return JiraOutboundWorkerResult(outcome="terminal_failed", idempotency_key=idem, status_code=404, retryable=False)

    access_token = get_or_refresh_access_token(
        workspace_id=workspace_id,
        connection_id=str(conn.get("connection_id") or ""),
        store=repo,
    )
    cloud_id = str(conn.get("cloud_id") or "")

    if mutation_type == "comment":
        comment_text = str(((payload.get("comment") or {}).get("body") if isinstance(payload.get("comment"), dict) else "") or "")
        status, _ = client.add_comment(cloud_id=cloud_id, access_token=access_token, issue_id=issue_id, body_text=comment_text)
    else:
        status, _ = client.update_issue(
            cloud_id=cloud_id,
            access_token=access_token,
            issue_id=issue_id,
            fields=_map_fields(payload_ticket, changed_fields),
        )

    if status < 400:
        repo.update_external_link_sync_metadata(
            internal_ticket_id=ticket_id,
            link_id=link_id,
            sync_state="in_sync",
            last_sync_direction="outbound",
            outbound_update_token=idem,
        )
        repo.append_sync_event(
            workspace_id=workspace_id,
            internal_ticket_id=ticket_id,
            direction="outbound",
            result="success",
            error_code="",
            payload_hash=idem[:32],
            trace_id=f"jira-out-{idem[:12]}",
        )
        return JiraOutboundWorkerResult(outcome="success", idempotency_key=idem, status_code=status, retryable=False)

    retryable = status in RETRYABLE_STATUS_CODES
    code = "jira_retryable_error" if retryable else "jira_terminal_error"
    repo.append_sync_event(
        workspace_id=workspace_id,
        internal_ticket_id=ticket_id,
        direction="outbound",
        result="failed",
        error_code=code,
        payload_hash=idem[:32],
        trace_id=f"jira-out-{idem[:12]}",
    )
    if retryable:
        logger.warning("jira outbound sync retryable failure", extra={"status_code": status, "ticket_id": ticket_id, "link_id": link_id})
        return JiraOutboundWorkerResult(outcome="retryable_failed", idempotency_key=idem, status_code=status, retryable=True)
    logger.error("jira outbound sync terminal failure", extra={"status_code": status, "ticket_id": ticket_id, "link_id": link_id})
    return JiraOutboundWorkerResult(outcome="terminal_failed", idempotency_key=idem, status_code=status, retryable=False)
