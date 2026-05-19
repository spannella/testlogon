from __future__ import annotations

from typing import Any

from app.services import payment_failure_alerts as alerts


class _Repo:
    def __init__(self):
        self.events: list[dict[str, Any]] = []

    def list_incident_events(self, *, incident_id: str, limit: int = 100):
        return [e for e in self.events if e.get("incident_id") == incident_id]

    def append_incident_event(self, *, incident_id: str, event_id: str, event_type: str, payload: dict[str, Any] | None = None):
        item = {"incident_id": incident_id, "event_id": event_id, "event_type": event_type, "payload": payload or {}}
        self.events.append(item)
        return item


class _AlertsTable:
    def __init__(self):
        self.items: dict[tuple[str, str], dict[str, Any]] = {}

    def query(self, **kwargs):
        user = kwargs["ExpressionAttributeValues"][":u"]
        out = [v for (u, _), v in self.items.items() if u == user]
        return {"Items": out}

    def update_item(self, *, Key: dict[str, str], UpdateExpression: str, ExpressionAttributeNames: dict[str, str], ExpressionAttributeValues: dict[str, Any], **kwargs):
        item = self.items[(Key["user_sub"], Key["alert_id"])]
        item["read"] = True
        item["read_at"] = ExpressionAttributeValues[":ts"]


def test_dispatch_emits_once_per_incident_status(monkeypatch):
    repo = _Repo()
    written = []
    emails = []
    monkeypatch.setattr(alerts, "write_alert", lambda *a, **k: written.append((a, k)) or {"alert_id": "a1"})
    monkeypatch.setattr(alerts, "get_alert_prefs", lambda user_sub: {"emails": ["u@example.com"]})
    monkeypatch.setattr(alerts, "send_alert_email", lambda to, subj, body: emails.append((to, subj, body)))

    incident = {
        "incident_id": "inc_1",
        "incident_type": "payment_failure",
        "status": "customer_action_required",
        "amount": "12.34",
        "currency": "usd",
        "response_due_at": "1700000000",
        "account_id": "user_1",
    }
    first = alerts.dispatch_auto_payment_failure_alert(repo, incident=incident)
    second = alerts.dispatch_auto_payment_failure_alert(repo, incident=incident)

    assert first is True
    assert second is False
    assert len(written) == 1
    assert len(emails) == 1


def test_clear_marks_matching_alerts_read(monkeypatch):
    repo = _Repo()
    table = _AlertsTable()
    original = alerts.T.alerts
    object.__setattr__(alerts.T, "alerts", table)

    table.items[("user_1", "a1")] = {
        "user_sub": "user_1",
        "alert_id": "a1",
        "event": "billing_auto_payment_failed",
        "details": {"incident_id": "inc_1"},
        "read": False,
        "read_at": 0,
    }
    table.items[("user_1", "a2")] = {
        "user_sub": "user_1",
        "alert_id": "a2",
        "event": "billing_auto_payment_failed",
        "details": {"incident_id": "inc_2"},
        "read": False,
        "read_at": 0,
    }

    incident = {"incident_id": "inc_1", "incident_type": "payment_failure", "status": "retry_succeeded", "account_id": "user_1"}
    try:
        cleared = alerts.clear_auto_payment_failure_alerts(repo, incident=incident)
    finally:
        object.__setattr__(alerts.T, "alerts", original)

    assert cleared == 1
    assert table.items[("user_1", "a1")]["read"] is True
    assert table.items[("user_1", "a2")]["read"] is False
    assert any(e["event_type"] == "auto_payment_failure_alert_cleared" for e in repo.events)
