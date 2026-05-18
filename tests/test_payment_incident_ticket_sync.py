from __future__ import annotations

from typing import Any

from app.services import payment_incident_ticket_sync as sync


class _Repo:
    def __init__(self, incident: dict[str, Any]):
        self.incident = incident
        self.link = None
        self.links = {}

    def get_ticket_link(self, *, incident_id: str):
        return self.links.get(incident_id)

    def put_ticket_link(self, *, incident_id: str, ticket_id: str, linked_by: str | None = None):
        self.links[incident_id] = {"incident_id": incident_id, "ticket_id": ticket_id, "linked_by": linked_by}
        return self.links[incident_id]

    def list_incidents(self, **kwargs):
        return [self.incident]

    def get_incident(self, incident_id: str):
        if self.incident.get("incident_id") == incident_id:
            return self.incident
        return None

    def update_incident_status(self, *, incident_id: str, status: str, status_reason: str | None = None):
        self.incident["status"] = status
        self.incident["status_reason"] = status_reason
        return self.incident


class _Store:
    def __init__(self):
        self.created = []
        self.tickets = {}

    def create_ticket(self, *, owner_sub: str, subject: str, description: str):
        ticket_id = f"tkt_{len(self.created)+1}"
        ticket = {"ticket_id": ticket_id, "owner_sub": owner_sub, "status": "open", "subject": subject, "description": description}
        self.created.append(ticket)
        self.tickets[ticket_id] = ticket
        return ticket

    def get_ticket(self, ticket_id: str):
        return self.tickets.get(ticket_id)

    def update_status(self, *, ticket_id: str, actor_sub: str, status: str):
        self.tickets[ticket_id]["status"] = status
        return self.tickets[ticket_id]


def test_evaluate_ticket_trigger_variants():
    assert sync.evaluate_ticket_trigger({"incident_type": "dispute", "status": "opened"}, ts=100) == "dispute_opened"
    assert sync.evaluate_ticket_trigger({"incident_type": "dispute", "status": "under_review", "response_due_at": "120"}, ts=100) == "dispute_deadline_nearing"
    assert sync.evaluate_ticket_trigger({"incident_type": "payment_failure", "status": "retry_failed_terminal"}, ts=100) == "terminal_retry_failure"
    assert sync.evaluate_ticket_trigger({"incident_type": "payment_failure", "status": "customer_action_required", "updated_at": "1"}, ts=200000) == "stalled_payment_failure"


def test_ensure_incident_ticket_link_creates_exactly_once(monkeypatch):
    store = _Store()
    monkeypatch.setattr(sync, "STORE", store)
    calls = []
    monkeypatch.setattr(sync, "record_ticket_linked", lambda **kwargs: calls.append(kwargs))

    incident = {"incident_id": "inc_1", "account_id": "user_1", "incident_type": "dispute", "status": "opened", "provider": "stripe"}
    repo = _Repo(incident)

    first = sync.ensure_incident_ticket_link(repo, incident=incident, trigger="dispute_opened")
    second = sync.ensure_incident_ticket_link(repo, incident=incident, trigger="dispute_opened")

    assert first.created is True
    assert second.created is False
    assert first.ticket_id == second.ticket_id
    assert len(store.created) == 1
    assert len(calls) == 1


def test_sync_ticket_from_incident_and_reverse_sync(monkeypatch):
    store = _Store()
    monkeypatch.setattr(sync, "STORE", store)

    incident = {"incident_id": "inc_1", "incident_type": "payment_failure", "status": "customer_action_required", "provider": "stripe", "account_id": "user_1"}
    repo = _Repo(incident)
    ticket = store.create_ticket(owner_sub="user_1", subject="s", description="d")
    repo.put_ticket_link(incident_id="inc_1", ticket_id=ticket["ticket_id"], linked_by="test")

    incident["status"] = "retry_succeeded"
    sync.sync_ticket_from_incident(repo, incident=incident)
    assert store.get_ticket(ticket["ticket_id"])["status"] == "done"

    incident["status"] = "customer_action_required"
    sync.sync_incident_from_ticket(repo, ticket_id=ticket["ticket_id"], ticket_status="done")
    assert incident["status"] == "retry_failed_terminal"
