from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Callable

from app.core.settings import S
from app.services.jira_ticket_sync_store import JiraTicketSyncStore

MAPPED_TICKET_FIELDS = ("title", "description", "status", "priority", "assignee", "labels")
SUPPORTED_MUTATIONS = {"create", "update", "status", "comment"}


def _queue_url() -> str:
    return str(os.getenv("JIRA_OUTBOUND_SYNC_QUEUE_URL", "")).strip()


def _enqueue_to_sqs(task: dict[str, Any]) -> bool:
    queue_url = _queue_url()
    if not queue_url:
        return False
    import boto3

    boto3.client("sqs", region_name=S.aws_region or "us-east-1").send_message(
        QueueUrl=queue_url,
        MessageBody=json.dumps(task, separators=(",", ":"), sort_keys=True),
    )
    return True


def _normalize_labels(raw: Any) -> list[str]:
    vals = [str(x).strip() for x in (raw or []) if str(x).strip()]
    return sorted(vals)


def _field_changed(field: str, previous_ticket: dict[str, Any] | None, current_ticket: dict[str, Any] | None) -> bool:
    prev = (previous_ticket or {}).get(field)
    curr = (current_ticket or {}).get(field)
    if field == "labels":
        return _normalize_labels(prev) != _normalize_labels(curr)
    return prev != curr


def _changed_fields(
    *,
    mutation_type: str,
    previous_ticket: dict[str, Any] | None,
    current_ticket: dict[str, Any] | None,
    comment: dict[str, Any] | None,
) -> list[str]:
    if mutation_type == "comment":
        body = str((comment or {}).get("body") or "").strip()
        return ["comment"] if body else []
    if mutation_type == "create":
        return [f for f in MAPPED_TICKET_FIELDS if (current_ticket or {}).get(f) is not None]
    if mutation_type == "status":
        return ["status"] if _field_changed("status", previous_ticket, current_ticket) else []
    if mutation_type == "update":
        return [f for f in MAPPED_TICKET_FIELDS if _field_changed(f, previous_ticket, current_ticket)]
    return []


def produce_outbound_sync_tasks(
    *,
    workspace_id: str,
    ticket_id: str,
    mutation_type: str,
    previous_ticket: dict[str, Any] | None,
    current_ticket: dict[str, Any] | None,
    comment: dict[str, Any] | None = None,
    actor_user_id: str = "system",
    store: JiraTicketSyncStore | None = None,
    enqueue: Callable[[dict[str, Any]], bool] | None = None,
) -> list[dict[str, Any]]:
    if mutation_type not in SUPPORTED_MUTATIONS:
        raise ValueError(f"unsupported mutation_type: {mutation_type}")

    repo = store or JiraTicketSyncStore()
    enqueue_fn = enqueue or _enqueue_to_sqs
    links = [
        row
        for row in repo.list_links_for_ticket(internal_ticket_id=ticket_id)
        if row.get("entity_type") == "ticket_external_link" and str(row.get("sync_state") or "") != "deleted"
    ]
    if not links:
        return []

    changed = _changed_fields(
        mutation_type=mutation_type,
        previous_ticket=previous_ticket,
        current_ticket=current_ticket,
        comment=comment,
    )
    if not changed:
        return []

    now = int(time.time())
    payload = {
        "ticket": {k: (current_ticket or {}).get(k) for k in MAPPED_TICKET_FIELDS},
        "comment": comment or {},
    }
    tasks: list[dict[str, Any]] = []
    for link in links:
        task = {
            "task_id": f"jira_out_{uuid.uuid4().hex[:12]}",
            "workspace_id": workspace_id,
            "ticket_id": ticket_id,
            "actor_user_id": actor_user_id,
            "mutation_type": mutation_type,
            "changed_fields": list(changed),
            "link_id": str(link.get("link_id") or ""),
            "external_issue_id": str(link.get("external_issue_id") or ""),
            "external_issue_key": str(link.get("external_issue_key") or ""),
            "created_at": now,
            "payload": payload,
        }
        enqueue_fn(task)
        tasks.append(task)
    return tasks
