from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient

from app.main import create_app
from app.routers import jira_integrations
from app.services import jira_webhook
from app.services.jira_inbound_apply import apply_inbound_issue_delta
from app.services.jira_ticket_sync_store import JiraTicketSyncStore
from tests.test_jira_ticket_sync_store import FakeTable


@dataclass(frozen=True)
class _StateRow:
    workspace_id: str
    user_sub: str
    redirect_uri: str
    created_at: int


def test_oauth_callback_lifecycle_persists_connection(monkeypatch) -> None:
    app = create_app()
    client = TestClient(app)
    saved: list[dict[str, Any]] = []

    class _Store:
        def upsert_connection(self, **kwargs: Any) -> dict[str, Any]:
            saved.append(dict(kwargs))
            return dict(kwargs)

    monkeypatch.setattr(jira_integrations, "get_oauth_state", lambda state: _StateRow("ws_1", "user_1", "https://app/settings", 1_700_000_000))
    monkeypatch.setattr(
        jira_integrations,
        "exchange_authorization_code",
        lambda **kwargs: SimpleNamespace(access_token="at", refresh_token="rt", expires_in=300, scopes=["read:jira-work"]),
    )
    monkeypatch.setattr(jira_integrations, "fetch_accessible_resource", lambda **kwargs: ("cloud_1", "https://example.atlassian.net"))
    monkeypatch.setattr(jira_integrations, "put_secret", lambda token, prefix: f"{prefix}/{token}")
    monkeypatch.setattr(jira_integrations, "JiraTicketSyncStore", lambda: _Store())

    resp = client.get("/integrations/jira/callback", params={"code": "abc", "state": "state_1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "connected"
    assert body["connection_id"].startswith("jira_conn_")
    assert saved and saved[0]["workspace_id"] == "ws_1"
    assert saved[0]["cloud_id"] == "cloud_1"
    assert saved[0]["access_token_ref"].startswith("jira-oauth://access/")


def test_webhook_route_enforces_signature_and_replay_rejection(monkeypatch) -> None:
    app = create_app()
    client = TestClient(app)
    payload = {"issue": {"id": "10001", "key": "PROJ-1"}}
    monkeypatch.setattr(jira_webhook, "_queue_url", lambda: "https://sqs.example/queue")
    monkeypatch.setattr(jira_webhook, "_enqueue_to_sqs", lambda *, envelope: True)
    monkeypatch.setattr(jira_webhook, "_signature_secret", lambda: "secret-1")
    with jira_webhook._REPLAY_LOCK:
        jira_webhook._REPLAY_KEYS.clear()

    sig = jira_webhook._payload_signature(payload, secret="secret-1")
    headers = {
        "X-Jira-Event": "jira:issue_updated",
        "X-Webhook-Id": "whk_1",
        "X-Jira-Signature": f"sha256={sig}",
    }
    body = {"event_type": "jira:issue_updated", "cloud_id": "cloud_1", "payload": payload}

    first = client.post("/integrations/jira/webhook", json=body, headers=headers)
    assert first.status_code == 200
    assert first.json()["enqueued"] is True
    assert first.json()["deduplicated"] is False

    second = client.post("/integrations/jira/webhook", json=body, headers=headers)
    assert second.status_code == 200
    assert second.json()["enqueued"] is False
    assert second.json()["deduplicated"] is True


def test_webhook_route_maps_source_ip_auth_error_code(monkeypatch) -> None:
    app = create_app()
    client = TestClient(app)

    def _raise_auth(**_kwargs: Any) -> Any:
        raise jira_webhook.JiraWebhookAuthError(message="jira webhook source ip not allowed", status_code=403)

    monkeypatch.setattr(jira_integrations, "process_jira_webhook", _raise_auth)
    resp = client.post(
        "/integrations/jira/webhook",
        json={"event_type": "jira:issue_updated", "cloud_id": "cloud_1", "payload": {"issue": {"id": "10001"}}},
        headers={"X-Jira-Event": "jira:issue_updated"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "jira_webhook_source_ip_not_allowed"


def test_webhook_route_maps_signature_required_error_code(monkeypatch) -> None:
    app = create_app()
    client = TestClient(app)

    def _raise_auth(**_kwargs: Any) -> Any:
        raise jira_webhook.JiraWebhookAuthError(message="jira webhook signature required", status_code=401)

    monkeypatch.setattr(jira_integrations, "process_jira_webhook", _raise_auth)
    resp = client.post(
        "/integrations/jira/webhook",
        json={"event_type": "jira:issue_updated", "cloud_id": "cloud_1", "payload": {"issue": {"id": "10001"}}},
        headers={"X-Jira-Event": "jira:issue_updated"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "jira_webhook_signature_required"


def test_inbound_apply_end_to_end_updates_link_sync_metadata() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)
    store.put_external_link(
        workspace_id="ws_1",
        internal_ticket_id="tkt_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        project_key="PROJ",
        link_mode="bidirectional",
        sync_state="queued",
        created_by="user_1",
        link_id="jlink_1",
    )

    out = apply_inbound_issue_delta(
        workspace_id="ws_1",
        ticket_id="tkt_1",
        link_id="jlink_1",
        jira_issue={
            "id": "10001",
            "fields": {
                "summary": "Updated title",
                "description": "Updated description",
                "status": {"name": "In Progress"},
                "priority": {"name": "High"},
                "assignee": {"accountId": "acc-2"},
                "labels": ["customer"],
            },
        },
        current_ticket={"title": "Old", "description": "Old", "status": "To Do", "priority": "Low", "assignee": "acc-1", "labels": []},
        store=store,
    )

    assert sorted(out.changed_fields) == ["assignee", "description", "labels", "priority", "status", "title"]
    link = store.get_external_link(internal_ticket_id="tkt_1", link_id="jlink_1")
    assert link is not None
    assert link["sync_state"] == "in_sync"
    assert link["last_sync_direction"] == "inbound"
