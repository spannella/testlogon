from __future__ import annotations

from typing import Any

from app.services.jira_outbound_sync import _normalize_labels, produce_outbound_sync_tasks


class _FakeStore:
    def __init__(self, links: list[dict[str, Any]]) -> None:
        self.links = links

    def list_links_for_ticket(self, *, internal_ticket_id: str) -> list[dict[str, Any]]:
        _ = internal_ticket_id
        return list(self.links)


def test_outbound_sync_emits_tasks_for_supported_mutations() -> None:
    store = _FakeStore(
        [
            {
                "entity_type": "ticket_external_link",
                "sync_state": "queued",
                "link_id": "jlink_1",
                "external_issue_id": "10001",
                "external_issue_key": "PROJ-1",
            }
        ]
    )
    emitted: list[dict[str, Any]] = []

    for mutation in ("create", "update", "status", "comment"):
        tasks = produce_outbound_sync_tasks(
            workspace_id="ws_1",
            ticket_id="tkt_1",
            mutation_type=mutation,
            previous_ticket={"title": "A", "status": "To Do", "labels": ["bug"]},
            current_ticket={"title": "B", "status": "In Progress", "labels": ["bug", "customer"]},
            comment={"body": "hello"} if mutation == "comment" else None,
            store=store,  # type: ignore[arg-type]
            enqueue=lambda t: emitted.append(t) or True,
        )
        assert len(tasks) == 1
        assert tasks[0]["mutation_type"] == mutation


def test_outbound_sync_skips_when_ticket_not_linked() -> None:
    store = _FakeStore([])
    tasks = produce_outbound_sync_tasks(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        mutation_type="update",
        previous_ticket={"title": "A"},
        current_ticket={"title": "B"},
        store=store,  # type: ignore[arg-type]
        enqueue=lambda t: True,
    )
    assert tasks == []


def test_outbound_sync_skips_when_mapped_fields_unchanged() -> None:
    store = _FakeStore(
        [
            {
                "entity_type": "ticket_external_link",
                "sync_state": "queued",
                "link_id": "jlink_1",
                "external_issue_id": "10001",
                "external_issue_key": "PROJ-1",
            }
        ]
    )
    tasks = produce_outbound_sync_tasks(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        mutation_type="update",
        previous_ticket={"title": "A", "description": "x", "status": "To Do", "labels": ["bug"]},
        current_ticket={"title": "A", "description": "x", "status": "To Do", "labels": ["bug"]},
        store=store,  # type: ignore[arg-type]
        enqueue=lambda t: True,
    )
    assert tasks == []


def test_normalize_labels_handles_empty_null_and_spacing() -> None:
    assert _normalize_labels(None) == []
    assert _normalize_labels(["", "  ", "bug", " customer "]) == ["bug", "customer"]
