from __future__ import annotations

from typing import Any

from app.services.jira_conflict_resolution import resolve_link_conflict


class _FakeStore:
    def __init__(self) -> None:
        self.link = {
            "link_id": "jlink_1",
            "entity_type": "ticket_external_link",
            "sync_state": "conflict",
            "conflict_fields": ["title", "status"],
            "conflict_payload": {
                "local": {"title": "Local title", "status": "To Do"},
                "remote": {"title": "Remote title", "status": "In Progress"},
            },
            "external_issue_id": "10001",
            "external_issue_key": "PROJ-1",
        }
        self.clear_calls: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []

    def get_external_link(self, *, internal_ticket_id: str, link_id: str) -> dict[str, Any] | None:
        _ = internal_ticket_id
        if link_id == "jlink_1":
            return dict(self.link)
        return None

    def clear_external_link_conflict(self, **kwargs: Any) -> dict[str, Any]:
        self.clear_calls.append(dict(kwargs))
        self.link["sync_state"] = "in_sync"
        self.link["conflict_state"] = "none"
        return dict(self.link)

    def append_sync_event(self, **kwargs: Any) -> dict[str, Any]:
        self.events.append(dict(kwargs))
        return dict(kwargs)

    def list_links_for_ticket(self, *, internal_ticket_id: str) -> list[dict[str, Any]]:
        _ = internal_ticket_id
        return [dict(self.link)]


def test_resolve_conflict_keep_internal_supported_and_emits_follow_up() -> None:
    store = _FakeStore()
    emitted: list[dict[str, Any]] = []
    result = resolve_link_conflict(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        link_id="jlink_1",
        action="keep_internal",
        current_ticket={"title": "Local title", "status": "To Do"},
        store=store,  # type: ignore[arg-type]
        enqueue=lambda task: emitted.append(task) or True,
    )

    assert result["action"] == "keep_internal"
    assert result["sync_state"] == "in_sync"
    assert result["resolved_ticket"]["title"] == "Local title"
    assert len(result["follow_up_tasks"]) == 1
    assert store.clear_calls and store.clear_calls[0]["last_sync_direction"] == "outbound"
    assert store.events and store.events[0]["error_code"] == "keep_internal"


def test_resolve_conflict_keep_jira_supported_and_clears_conflict() -> None:
    store = _FakeStore()
    result = resolve_link_conflict(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        link_id="jlink_1",
        action="keep_jira",
        current_ticket={"title": "Local title", "status": "To Do"},
        store=store,  # type: ignore[arg-type]
        enqueue=lambda task: True,
    )

    assert result["action"] == "keep_jira"
    assert result["resolved_ticket"]["title"] == "Remote title"
    assert result["follow_up_tasks"] == []
    assert store.clear_calls and store.clear_calls[0]["last_sync_direction"] == "inbound"
    assert store.events and store.events[0]["error_code"] == "keep_jira"
