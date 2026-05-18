from __future__ import annotations

from typing import Any

from app.services.jira_outbound_worker import _PROCESSED_KEYS, _IDEMPOTENCY_LOCK, _map_fields, process_outbound_sync_task


class _FakeStore:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.metadata_updates: list[dict[str, Any]] = []

    def get_external_link(self, *, internal_ticket_id: str, link_id: str) -> dict[str, Any] | None:
        _ = internal_ticket_id
        if link_id == "jlink_1":
            return {"link_id": "jlink_1", "sync_state": "queued"}
        return None

    def list_workspace_connections(self, *, workspace_id: str, limit: int = 100) -> list[dict[str, Any]]:
        _ = (workspace_id, limit)
        return [{"connection_id": "conn_1", "cloud_id": "cloud_1", "status": "active"}]

    def append_sync_event(self, **kwargs: Any) -> dict[str, Any]:
        self.events.append(dict(kwargs))
        return dict(kwargs)

    def update_external_link_sync_metadata(self, **kwargs: Any) -> dict[str, Any]:
        self.metadata_updates.append(dict(kwargs))
        return dict(kwargs)


class _FakeApi:
    def __init__(self, *, status_code: int = 204) -> None:
        self.status_code = status_code
        self.update_calls: list[dict[str, Any]] = []
        self.comment_calls: list[dict[str, Any]] = []

    def update_issue(self, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        self.update_calls.append(dict(kwargs))
        return self.status_code, {}

    def add_comment(self, **kwargs: Any) -> tuple[int, dict[str, Any]]:
        self.comment_calls.append(dict(kwargs))
        return self.status_code, {}


def _task() -> dict[str, Any]:
    return {
        "workspace_id": "ws_1",
        "ticket_id": "tkt_1",
        "link_id": "jlink_1",
        "external_issue_id": "10001",
        "mutation_type": "update",
        "changed_fields": ["title", "status"],
        "payload": {"ticket": {"title": "new", "status": "In Progress"}},
    }


def test_outbound_worker_applies_idempotency_key_and_replays_duplicate(monkeypatch) -> None:
    store = _FakeStore()
    api = _FakeApi(status_code=204)
    monkeypatch.setattr("app.services.jira_outbound_worker.get_or_refresh_access_token", lambda **kwargs: "token-1")
    with _IDEMPOTENCY_LOCK:
        _PROCESSED_KEYS.clear()

    first = process_outbound_sync_task(task=_task(), store=store, api=api)  # type: ignore[arg-type]
    second = process_outbound_sync_task(task=_task(), store=store, api=api)  # type: ignore[arg-type]

    assert first.outcome == "success"
    assert second.outcome == "replayed"
    assert len(api.update_calls) == 1
    assert store.metadata_updates and store.metadata_updates[0]["outbound_update_token"] == first.idempotency_key


def test_outbound_worker_classifies_retryable_failures(monkeypatch) -> None:
    store = _FakeStore()
    api = _FakeApi(status_code=503)
    monkeypatch.setattr("app.services.jira_outbound_worker.get_or_refresh_access_token", lambda **kwargs: "token-1")
    with _IDEMPOTENCY_LOCK:
        _PROCESSED_KEYS.clear()

    out = process_outbound_sync_task(task=_task(), store=store, api=api)  # type: ignore[arg-type]
    assert out.outcome == "retryable_failed"
    assert out.retryable is True
    assert store.events and store.events[0]["error_code"] == "jira_retryable_error"


def test_outbound_worker_classifies_terminal_failures(monkeypatch) -> None:
    store = _FakeStore()
    api = _FakeApi(status_code=404)
    monkeypatch.setattr("app.services.jira_outbound_worker.get_or_refresh_access_token", lambda **kwargs: "token-1")
    with _IDEMPOTENCY_LOCK:
        _PROCESSED_KEYS.clear()

    out = process_outbound_sync_task(task=_task(), store=store, api=api)  # type: ignore[arg-type]
    assert out.outcome == "terminal_failed"
    assert out.retryable is False
    assert store.events and store.events[0]["error_code"] == "jira_terminal_error"


def test_map_fields_drops_empty_values_and_maps_supported_fields() -> None:
    mapped = _map_fields(
        {
            "title": "New title",
            "description": "",
            "status": "In Progress",
            "priority": None,
            "assignee": "acc-1",
            "labels": None,
        },
        ["title", "description", "status", "priority", "assignee", "labels"],
    )
    assert mapped == {
        "summary": "New title",
        "status": {"name": "In Progress"},
        "assignee": {"accountId": "acc-1"},
        "labels": [],
    }
