from __future__ import annotations

from typing import Any

from app.services.jira_inbound_apply import _jira_to_internal, apply_inbound_issue_delta


class _FakeStore:
    def __init__(self) -> None:
        self.link = {"link_id": "jlink_1", "sync_state": "queued", "last_outbound_update_token": ""}
        self.metadata_updates: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.conflicts: list[dict[str, Any]] = []

    def get_external_link(self, *, internal_ticket_id: str, link_id: str) -> dict[str, Any] | None:
        _ = internal_ticket_id
        if link_id == "jlink_1":
            return dict(self.link)
        return None

    def update_external_link_sync_metadata(self, **kwargs: Any) -> dict[str, Any]:
        self.metadata_updates.append(dict(kwargs))
        return {"sync_state": kwargs["sync_state"], "last_sync_direction": kwargs["last_sync_direction"]}

    def append_sync_event(self, **kwargs: Any) -> dict[str, Any]:
        self.events.append(dict(kwargs))
        return dict(kwargs)

    def persist_external_link_conflict(self, **kwargs: Any) -> dict[str, Any]:
        self.conflicts.append(dict(kwargs))
        return dict(kwargs)


def test_apply_inbound_issue_delta_updates_mapped_fields_and_sync_metadata() -> None:
    store = _FakeStore()
    current_ticket = {
        "title": "Old title",
        "description": "Old desc",
        "status": "To Do",
        "priority": "Low",
        "assignee": "acc-old",
        "labels": ["bug"],
    }
    jira_issue = {
        "id": "10001",
        "fields": {
            "summary": "New title",
            "description": "New desc",
            "status": {"name": "In Progress"},
            "priority": {"name": "High"},
            "assignee": {"accountId": "acc-new"},
            "labels": ["bug", "customer"],
        },
    }

    out = apply_inbound_issue_delta(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        link_id="jlink_1",
        jira_issue=jira_issue,
        current_ticket=current_ticket,
        store=store,  # type: ignore[arg-type]
    )

    assert sorted(out.changed_fields) == ["assignee", "description", "labels", "priority", "status", "title"]
    assert out.updated_ticket["title"] == "New title"
    assert out.sync_state == "in_sync"
    assert store.metadata_updates and store.metadata_updates[0]["sync_state"] == "in_sync"
    assert store.events and store.events[0]["direction"] == "inbound"


def test_apply_inbound_issue_delta_no_changes_still_marks_sync() -> None:
    store = _FakeStore()
    current_ticket = {
        "title": "Same",
        "description": "Same",
        "status": "To Do",
        "priority": "Low",
        "assignee": "acc-1",
        "labels": ["bug"],
    }
    jira_issue = {
        "id": "10001",
        "fields": {
            "summary": "Same",
            "description": "Same",
            "status": {"name": "To Do"},
            "priority": {"name": "Low"},
            "assignee": {"accountId": "acc-1"},
            "labels": ["bug"],
        },
    }
    out = apply_inbound_issue_delta(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        link_id="jlink_1",
        jira_issue=jira_issue,
        current_ticket=current_ticket,
        store=store,  # type: ignore[arg-type]
    )
    assert out.changed_fields == []
    assert out.sync_state == "in_sync"


def test_apply_inbound_issue_delta_skips_echo_update_by_origin_token() -> None:
    store = _FakeStore()
    store.link["last_outbound_update_token"] = "idem-123"
    current_ticket = {"title": "Same"}
    jira_issue = {
        "id": "10001",
        "sync_origin_token": "idem-123",
        "fields": {"summary": "Changed remotely but echo"},
    }
    out = apply_inbound_issue_delta(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        link_id="jlink_1",
        jira_issue=jira_issue,
        current_ticket=current_ticket,
        store=store,  # type: ignore[arg-type]
    )
    assert out.skipped_echo is True
    assert out.changed_fields == []
    assert out.updated_ticket["title"] == "Same"
    assert store.metadata_updates == []
    assert store.events and store.events[0]["error_code"] == "echo_skipped"


def test_apply_inbound_issue_delta_detects_conflict_and_transitions_state() -> None:
    store = _FakeStore()
    store.link["last_sync_direction"] = "outbound"
    current_ticket = {"title": "Local changed", "status": "To Do", "labels": ["bug"]}
    jira_issue = {
        "id": "10001",
        "fields": {
            "summary": "Remote changed",
            "status": {"name": "In Progress"},
            "labels": ["bug", "customer"],
        },
    }

    out = apply_inbound_issue_delta(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        link_id="jlink_1",
        jira_issue=jira_issue,
        current_ticket=current_ticket,
        store=store,  # type: ignore[arg-type]
    )
    assert out.sync_state == "conflict"
    assert out.conflict_fields == ["labels", "status", "title"]
    assert store.conflicts and store.conflicts[0]["local_candidates"]["title"] == "Local changed"
    assert store.conflicts and store.conflicts[0]["remote_candidates"]["title"] == "Remote changed"
    assert store.events and store.events[0]["error_code"] == "conflict_detected"


def test_jira_to_internal_mapping_handles_empty_null_and_malformed_fields() -> None:
    mapped = _jira_to_internal(
        {
            "fields": {
                "summary": None,
                "description": None,
                "status": None,
                "priority": {"name": None},
                "assignee": "not-a-dict",
                "labels": ["", " bug ", None, "customer"],
            }
        }
    )
    assert mapped["title"] == ""
    assert mapped["description"] == ""
    assert mapped["status"] == ""
    assert mapped["priority"] == ""
    assert mapped["assignee"] == ""
    assert mapped["labels"] == ["bug", "customer"]
