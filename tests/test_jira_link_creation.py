from __future__ import annotations

from typing import Any

from app.services.jira_link_creation import (
    JiraLinkCreateError,
    create_jira_issue_and_link,
    link_existing_jira_issue_to_ticket,
    unlink_jira_issue_from_ticket,
)


class _FakeStore:
    def __init__(self, *, fail_create_link: bool = False) -> None:
        self.fail_create_link = fail_create_link
        self.create_link_calls: list[dict[str, Any]] = []
        self.active_link: dict[str, Any] | None = None
        self.sync_events: list[dict[str, Any]] = []

    def list_connections_for_user(self, *, workspace_id: str, user_id: str, limit: int = 100) -> list[dict[str, Any]]:
        _ = (workspace_id, user_id, limit)
        return [{"connection_id": "conn_1", "cloud_id": "cloud_1", "status": "active"}]

    def create_external_link(self, **kwargs: Any) -> dict[str, Any]:
        self.create_link_calls.append(dict(kwargs))
        if self.fail_create_link:
            raise RuntimeError("ddb unavailable")
        self.active_link = {
            "link_id": "jlink_1",
            "external_issue_id": kwargs["external_issue_id"],
            "external_issue_key": kwargs["external_issue_key"],
            "link_mode": kwargs["link_mode"],
            "sync_state": kwargs["sync_state"],
        }
        return dict(self.active_link)

    def find_active_link_for_ticket_issue(
        self, *, internal_ticket_id: str, external_issue_id: str, external_issue_key: str
    ) -> dict[str, Any] | None:
        _ = internal_ticket_id
        if not self.active_link:
            return None
        if external_issue_id and self.active_link.get("external_issue_id") == external_issue_id:
            return dict(self.active_link)
        if external_issue_key and self.active_link.get("external_issue_key") == external_issue_key:
            return dict(self.active_link)
        return None

    def get_external_link(self, *, internal_ticket_id: str, link_id: str) -> dict[str, Any] | None:
        _ = internal_ticket_id
        if self.active_link and self.active_link.get("link_id") == link_id:
            row = dict(self.active_link)
            row["workspace_id"] = "ws_1"
            return row
        return None

    def deactivate_external_link(self, *, internal_ticket_id: str, link_id: str, actor_user_id: str) -> dict[str, Any] | None:
        _ = (internal_ticket_id, actor_user_id)
        if self.active_link and self.active_link.get("link_id") == link_id:
            self.active_link["sync_state"] = "deleted"
            row = dict(self.active_link)
            row["workspace_id"] = "ws_1"
            return row
        return None

    def append_sync_event(self, **kwargs: Any) -> dict[str, Any]:
        self.sync_events.append(dict(kwargs))
        return dict(kwargs)


class _FakeApi:
    def __init__(self) -> None:
        self.delete_calls: list[dict[str, Any]] = []
        self.create_calls: list[dict[str, Any]] = []
        self.issue_lookup_status = 200

    def create_issue(
        self,
        *,
        cloud_id: str,
        access_token: str,
        project_key: str,
        issue_type: str,
        summary: str,
        description: str,
    ) -> tuple[int, dict[str, Any]]:
        self.create_calls.append(
            {
                "cloud_id": cloud_id,
                "access_token": access_token,
                "project_key": project_key,
                "issue_type": issue_type,
                "summary": summary,
                "description": description,
            }
        )
        return 201, {"id": "10001", "key": "PROJ-1"}

    def delete_issue(self, *, cloud_id: str, access_token: str, issue_id: str) -> tuple[int, dict[str, Any]]:
        self.delete_calls.append({"cloud_id": cloud_id, "access_token": access_token, "issue_id": issue_id})
        return 204, {}

    def get_issue(self, *, cloud_id: str, access_token: str, issue_id_or_key: str) -> tuple[int, dict[str, Any]]:
        _ = (cloud_id, access_token, issue_id_or_key)
        if self.issue_lookup_status != 200:
            return self.issue_lookup_status, {}
        return 200, {"id": "10001", "key": "PROJ-1", "fields": {"project": {"key": "PROJ"}}}


def test_create_jira_issue_and_link_returns_issue_key_id_and_sync_status(monkeypatch) -> None:
    store = _FakeStore()
    api = _FakeApi()
    monkeypatch.setattr("app.services.jira_link_creation.get_or_refresh_access_token", lambda **kwargs: "token-1")

    row = create_jira_issue_and_link(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        user_sub="user_1",
        project_key="PROJ",
        issue_type="Task",
        link_mode="bidirectional",
        store=store,  # type: ignore[arg-type]
        api=api,  # type: ignore[arg-type]
    )

    assert row["external_issue_id"] == "10001"
    assert row["external_issue_key"] == "PROJ-1"
    assert row["sync_state"] == "queued"
    assert api.delete_calls == []


def test_create_jira_issue_and_link_compensates_when_local_link_persist_fails(monkeypatch) -> None:
    store = _FakeStore(fail_create_link=True)
    api = _FakeApi()
    monkeypatch.setattr("app.services.jira_link_creation.get_or_refresh_access_token", lambda **kwargs: "token-1")
    try:
        create_jira_issue_and_link(
            workspace_id="ws_1",
            ticket_id="tkt_1",
            user_sub="user_1",
            project_key="PROJ",
            issue_type="Task",
            link_mode="bidirectional",
            store=store,  # type: ignore[arg-type]
            api=api,  # type: ignore[arg-type]
        )
        assert False, "expected compensated create error"
    except JiraLinkCreateError as exc:
        assert exc.code == "jira_link_create_compensated"
    assert api.delete_calls and api.delete_calls[0]["issue_id"] == "10001"


def test_link_existing_jira_issue_validates_issue_and_persists_link(monkeypatch) -> None:
    store = _FakeStore()
    api = _FakeApi()
    monkeypatch.setattr("app.services.jira_link_creation.get_or_refresh_access_token", lambda **kwargs: "token-1")

    row = link_existing_jira_issue_to_ticket(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        user_sub="user_1",
        external_issue_id=None,
        external_issue_key="PROJ-1",
        link_mode="bidirectional",
        store=store,  # type: ignore[arg-type]
        api=api,  # type: ignore[arg-type]
    )
    assert row["external_issue_key"] == "PROJ-1"
    assert row["sync_state"] == "queued"


def test_link_existing_jira_issue_is_idempotent_for_repeated_requests(monkeypatch) -> None:
    store = _FakeStore()
    api = _FakeApi()
    monkeypatch.setattr("app.services.jira_link_creation.get_or_refresh_access_token", lambda **kwargs: "token-1")

    first = link_existing_jira_issue_to_ticket(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        user_sub="user_1",
        external_issue_id=None,
        external_issue_key="PROJ-1",
        link_mode="bidirectional",
        store=store,  # type: ignore[arg-type]
        api=api,  # type: ignore[arg-type]
    )
    second = link_existing_jira_issue_to_ticket(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        user_sub="user_1",
        external_issue_id=None,
        external_issue_key="PROJ-1",
        link_mode="bidirectional",
        store=store,  # type: ignore[arg-type]
        api=api,  # type: ignore[arg-type]
    )
    assert first["link_id"] == second["link_id"] == "jlink_1"
    assert len(store.create_link_calls) == 1


def test_link_existing_jira_issue_returns_permission_error_when_forbidden(monkeypatch) -> None:
    store = _FakeStore()
    api = _FakeApi()
    api.issue_lookup_status = 403
    monkeypatch.setattr("app.services.jira_link_creation.get_or_refresh_access_token", lambda **kwargs: "token-1")
    try:
        link_existing_jira_issue_to_ticket(
            workspace_id="ws_1",
            ticket_id="tkt_1",
            user_sub="user_1",
            external_issue_id="10001",
            external_issue_key=None,
            link_mode="bidirectional",
            store=store,  # type: ignore[arg-type]
            api=api,  # type: ignore[arg-type]
        )
        assert False, "expected permission failure"
    except JiraLinkCreateError as exc:
        assert exc.code == "jira_issue_forbidden"


def test_link_existing_jira_issue_requires_identifier() -> None:
    store = _FakeStore()
    api = _FakeApi()
    try:
        link_existing_jira_issue_to_ticket(
            workspace_id="ws_1",
            ticket_id="tkt_1",
            user_sub="user_1",
            external_issue_id="",
            external_issue_key=" ",
            link_mode="bidirectional",
            store=store,  # type: ignore[arg-type]
            api=api,  # type: ignore[arg-type]
        )
        assert False, "expected validation failure"
    except JiraLinkCreateError as exc:
        assert exc.code == "jira_issue_identifier_required"
        assert exc.status_code == 400


def test_unlink_jira_issue_deactivates_link_and_appends_audit_event() -> None:
    store = _FakeStore()
    store.active_link = {
        "link_id": "jlink_1",
        "external_issue_id": "10001",
        "external_issue_key": "PROJ-1",
        "link_mode": "bidirectional",
        "sync_state": "queued",
    }

    out = unlink_jira_issue_from_ticket(ticket_id="tkt_1", link_id="jlink_1", actor_user_id="user_1", store=store)  # type: ignore[arg-type]
    assert out["unlinked"] is True
    assert store.active_link is not None
    assert store.active_link["sync_state"] == "deleted"
    assert store.sync_events and store.sync_events[0]["direction"] == "internal_unlink"
