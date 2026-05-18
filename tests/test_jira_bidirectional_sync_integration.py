from __future__ import annotations

from typing import Any

from app.services.jira_conflict_resolution import resolve_link_conflict
from app.services.jira_inbound_apply import apply_inbound_issue_delta
from app.services.jira_link_creation import create_jira_issue_and_link
from app.services.jira_outbound_sync import produce_outbound_sync_tasks
from app.services.jira_outbound_worker import process_outbound_sync_task
from app.services.jira_ticket_sync_store import JiraTicketSyncStore
from tests.test_jira_ticket_sync_store import FakeTable


class _FakeApi:
    def __init__(self) -> None:
        self.update_calls: list[dict[str, Any]] = []

    def create_issue(self, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        _ = kwargs
        return 201, {"id": "10001", "key": "PROJ-1"}

    def delete_issue(self, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        _ = kwargs
        return 204, {}

    def update_issue(self, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        self.update_calls.append(dict(kwargs))
        return 204, {}

    def add_comment(self, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        _ = kwargs
        return 201, {}


class _Store(JiraTicketSyncStore):
    def list_connections_for_user(self, *, workspace_id: str, user_id: str, limit: int = 50) -> list[dict[str, Any]]:
        _ = (workspace_id, user_id, limit)
        return [{"connection_id": "conn_1", "cloud_id": "cloud_1", "status": "active"}]

    def list_workspace_connections(self, *, workspace_id: str, limit: int = 50) -> list[dict[str, Any]]:
        _ = (workspace_id, limit)
        return [{"connection_id": "conn_1", "cloud_id": "cloud_1", "status": "active"}]

    def list_links_for_ticket(self, *, internal_ticket_id: str) -> list[dict[str, Any]]:
        pk = f"TICKET#{internal_ticket_id}"
        items = []
        for (item_pk, item_sk), row in self._table._items.items():  # type: ignore[attr-defined]
            if item_pk == pk and str(item_sk).startswith("JIRA_LINK#"):
                items.append(dict(row))
        return items


def _store_with_connection() -> JiraTicketSyncStore:
    table = FakeTable()
    store = _Store(_table=table)
    store.upsert_connection(
        workspace_id="ws_1",
        connection_id="conn_1",
        user_id="user_1",
        cloud_id="cloud_1",
        site_url="https://example.atlassian.net",
        auth_type="oauth",
        scopes=["read:jira-work", "write:jira-work"],
        access_token_ref="secret://at",
        refresh_token_ref="secret://rt",
        expires_at=9_999_999_999,
        status="active",
    )
    return store


def test_bidirectional_lifecycle_create_link_outbound_and_inbound_update(monkeypatch) -> None:
    store = _store_with_connection()
    api = _FakeApi()
    monkeypatch.setattr("app.services.jira_link_creation.get_or_refresh_access_token", lambda **kwargs: "token-1")
    monkeypatch.setattr("app.services.jira_outbound_worker.get_or_refresh_access_token", lambda **kwargs: "token-1")

    link = create_jira_issue_and_link(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        user_sub="user_1",
        project_key="PROJ",
        issue_type="Task",
        link_mode="bidirectional",
        store=store,
        api=api,  # type: ignore[arg-type]
    )
    assert link["sync_state"] == "queued"

    tasks = produce_outbound_sync_tasks(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        mutation_type="update",
        previous_ticket={"title": "Old title", "status": "To Do", "labels": []},
        current_ticket={"title": "New title", "status": "To Do", "labels": []},
        store=store,
        enqueue=lambda task: True,
    )
    assert len(tasks) == 1

    worker_out = process_outbound_sync_task(task=tasks[0], store=store, api=api)  # type: ignore[arg-type]
    assert worker_out.outcome == "success"
    post_outbound_link = store.get_external_link(internal_ticket_id="tkt_1", link_id=link["link_id"])
    assert post_outbound_link is not None
    assert post_outbound_link["last_sync_direction"] == "outbound"

    # Echo update should be skipped when origin token matches outbound idempotency token.
    echo = apply_inbound_issue_delta(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        link_id=link["link_id"],
        jira_issue={"id": "10001", "sync_origin_token": worker_out.idempotency_key, "fields": {"summary": "Echo title"}},
        current_ticket={"title": "New title"},
        store=store,
    )
    assert echo.skipped_echo is True

    # Inbound update path correctness when link direction is inbound-friendly.
    store.update_external_link_sync_metadata(
        internal_ticket_id="tkt_1",
        link_id=link["link_id"],
        sync_state="in_sync",
        last_sync_direction="inbound",
    )
    inbound = apply_inbound_issue_delta(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        link_id=link["link_id"],
        jira_issue={"id": "10001", "fields": {"status": {"name": "In Progress"}, "summary": "New title"}},
        current_ticket={"title": "New title", "status": "To Do", "labels": []},
        store=store,
    )
    assert inbound.sync_state == "in_sync"
    assert "status" in inbound.changed_fields


def test_bidirectional_lifecycle_conflict_detection_and_resolution(monkeypatch) -> None:
    store = _store_with_connection()
    api = _FakeApi()
    monkeypatch.setattr("app.services.jira_link_creation.get_or_refresh_access_token", lambda **kwargs: "token-1")

    link = create_jira_issue_and_link(
        workspace_id="ws_1",
        ticket_id="tkt_2",
        user_sub="user_1",
        project_key="PROJ",
        issue_type="Task",
        link_mode="bidirectional",
        store=store,
        api=api,  # type: ignore[arg-type]
    )
    store.update_external_link_sync_metadata(
        internal_ticket_id="tkt_2",
        link_id=link["link_id"],
        sync_state="in_sync",
        last_sync_direction="outbound",
    )

    conflict = apply_inbound_issue_delta(
        workspace_id="ws_1",
        ticket_id="tkt_2",
        link_id=link["link_id"],
        jira_issue={"id": "10001", "fields": {"summary": "Remote title", "status": {"name": "In Progress"}}},
        current_ticket={"title": "Local title", "status": "To Do", "labels": []},
        store=store,
    )
    assert conflict.sync_state == "conflict"
    assert set(conflict.conflict_fields or []) == {"title", "status"}

    follow_up = []
    resolved = resolve_link_conflict(
        workspace_id="ws_1",
        ticket_id="tkt_2",
        link_id=link["link_id"],
        action="keep_internal",
        current_ticket={"title": "Local title", "status": "To Do", "labels": []},
        store=store,
        enqueue=lambda task: follow_up.append(task) or True,
    )
    assert resolved["sync_state"] == "in_sync"
    assert resolved["action"] == "keep_internal"
    assert follow_up, "keep_internal should enqueue outbound follow-up sync task(s)"
    resolved_link = store.get_external_link(internal_ticket_id="tkt_2", link_id=link["link_id"])
    assert resolved_link is not None
    assert resolved_link["sync_state"] == "in_sync"
