from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from app.services.jira_ticket_sync_store import JiraTicketSyncStore


@dataclass(frozen=True)
class JiraInboundApplyResult:
    ticket_id: str
    link_id: str
    changed_fields: list[str]
    updated_ticket: dict[str, Any]
    sync_state: str
    skipped_echo: bool = False
    conflict_fields: list[str] | None = None


def _extract_origin_token(issue: dict[str, Any]) -> str:
    token = str(issue.get("sync_origin_token") or "").strip()
    if token:
        return token
    props = issue.get("properties") if isinstance(issue.get("properties"), dict) else {}
    return str(props.get("sync_origin_token") or "").strip()


def _jira_to_internal(issue: dict[str, Any]) -> dict[str, Any]:
    fields = issue.get("fields") if isinstance(issue.get("fields"), dict) else {}
    status_name = (fields.get("status") or {}).get("name") if isinstance(fields.get("status"), dict) else ""
    priority_name = (fields.get("priority") or {}).get("name") if isinstance(fields.get("priority"), dict) else ""
    assignee_id = (fields.get("assignee") or {}).get("accountId") if isinstance(fields.get("assignee"), dict) else ""
    return {
        "title": str(fields.get("summary") or ""),
        "description": str(fields.get("description") or ""),
        "status": str(status_name or ""),
        "priority": str(priority_name or ""),
        "assignee": str(assignee_id or ""),
        "labels": [str(x).strip() for x in (fields.get("labels") or []) if x is not None and str(x).strip()],
    }


def apply_inbound_issue_delta(
    *,
    workspace_id: str,
    ticket_id: str,
    link_id: str,
    jira_issue: dict[str, Any],
    current_ticket: dict[str, Any],
    store: JiraTicketSyncStore | None = None,
) -> JiraInboundApplyResult:
    repo = store or JiraTicketSyncStore()
    link = repo.get_external_link(internal_ticket_id=ticket_id, link_id=link_id)
    if not link or str(link.get("sync_state") or "") == "deleted":
        raise ValueError("jira link not found or inactive")
    inbound_token = _extract_origin_token(jira_issue)
    last_outbound_token = str(link.get("last_outbound_update_token") or "").strip()
    if inbound_token and last_outbound_token and inbound_token == last_outbound_token:
        payload_hash = hashlib.sha256(
            json.dumps({"echo_token": inbound_token, "issue_id": jira_issue.get("id")}, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        ).hexdigest()[:32]
        repo.append_sync_event(
            workspace_id=workspace_id,
            internal_ticket_id=ticket_id,
            direction="inbound",
            result="success",
            error_code="echo_skipped",
            payload_hash=payload_hash,
            trace_id=f"jira-in-echo-{payload_hash[:8]}",
        )
        return JiraInboundApplyResult(
            ticket_id=ticket_id,
            link_id=link_id,
            changed_fields=[],
            updated_ticket=dict(current_ticket),
            sync_state=str(link.get("sync_state") or "in_sync"),
            skipped_echo=True,
            conflict_fields=None,
        )

    mapped = _jira_to_internal(jira_issue)
    updated_ticket = dict(current_ticket)
    changed_fields: list[str] = []
    conflicting_fields: list[str] = []
    local_conflicts: dict[str, Any] = {}
    remote_conflicts: dict[str, Any] = {}
    last_sync_direction = str(link.get("last_sync_direction") or "")
    for field, inbound_value in mapped.items():
        current_value = updated_ticket.get(field)
        if field == "labels":
            left = sorted([str(x) for x in (current_value or [])])
            right = sorted([str(x) for x in (inbound_value or [])])
            if left != right:
                if last_sync_direction == "outbound":
                    conflicting_fields.append(field)
                    local_conflicts[field] = left
                    remote_conflicts[field] = right
                    continue
                updated_ticket[field] = right
                changed_fields.append(field)
            continue
        if inbound_value != current_value and inbound_value != "":
            if last_sync_direction == "outbound":
                conflicting_fields.append(field)
                local_conflicts[field] = current_value
                remote_conflicts[field] = inbound_value
                continue
            updated_ticket[field] = inbound_value
            changed_fields.append(field)

    if conflicting_fields:
        repo.persist_external_link_conflict(
            internal_ticket_id=ticket_id,
            link_id=link_id,
            conflict_fields=conflicting_fields,
            local_candidates=local_conflicts,
            remote_candidates=remote_conflicts,
        )
        payload_hash = hashlib.sha256(
            json.dumps(
                {"conflict_fields": sorted(conflicting_fields), "issue_id": jira_issue.get("id")},
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:32]
        repo.append_sync_event(
            workspace_id=workspace_id,
            internal_ticket_id=ticket_id,
            direction="inbound",
            result="failed",
            error_code="conflict_detected",
            payload_hash=payload_hash,
            trace_id=f"jira-in-conflict-{payload_hash[:8]}",
        )
        return JiraInboundApplyResult(
            ticket_id=ticket_id,
            link_id=link_id,
            changed_fields=[],
            updated_ticket=dict(current_ticket),
            sync_state="conflict",
            skipped_echo=False,
            conflict_fields=sorted(conflicting_fields),
        )

    sync_state = "in_sync"
    repo.update_external_link_sync_metadata(
        internal_ticket_id=ticket_id,
        link_id=link_id,
        sync_state=sync_state,
        last_sync_direction="inbound",
    )
    payload_hash = hashlib.sha256(
        json.dumps({"changed_fields": changed_fields, "issue_id": jira_issue.get("id")}, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    ).hexdigest()[:32]
    repo.append_sync_event(
        workspace_id=workspace_id,
        internal_ticket_id=ticket_id,
        direction="inbound",
        result="success",
        error_code="",
        payload_hash=payload_hash,
        trace_id=f"jira-in-{payload_hash[:10]}",
    )
    return JiraInboundApplyResult(
        ticket_id=ticket_id,
        link_id=link_id,
        changed_fields=changed_fields,
        updated_ticket=updated_ticket,
        sync_state=sync_state,
        skipped_echo=False,
        conflict_fields=None,
    )
