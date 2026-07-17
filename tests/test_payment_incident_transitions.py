from __future__ import annotations

from app.services.payment_incident_transitions import (
    InMemoryIdempotencyStore,
    ListDomainEventSink,
    PaymentIncidentTransitionError,
    PaymentIncidentTransitionService,
)
from app.services.payment_incidents_domain import PaymentIncidentType


class _Repo:
    def __init__(self) -> None:
        self.incidents = {
            "inc_1": {"incident_id": "inc_1", "status": "opened"},
            "inc_pf": {"incident_id": "inc_pf", "status": "failed_initial"},
        }
        self.events: list[dict] = []

    def put_incident(self, incident: dict):
        self.incidents[incident["incident_id"]] = incident
        return incident

    def get_incident(self, incident_id: str):
        return self.incidents.get(incident_id)

    def update_incident_status(self, *, incident_id: str, status: str, status_reason: str | None = None):
        row = self.incidents.get(incident_id)
        if not row:
            return None
        row = dict(row)
        row["status"] = status
        if status_reason:
            row["status_reason"] = status_reason
        self.incidents[incident_id] = row
        return row

    def list_incidents_by_provider_incident(self, *, provider: str, provider_incident_id: str, limit: int = 25):
        return []

    def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 25):
        return []

    def list_incidents_by_customer(self, *, customer_id: str, limit: int = 25):
        return []

    def list_incidents_due_before(self, *, due_at_ts: int, limit: int = 25):
        return []

    def append_incident_event(self, *, incident_id: str, event_id: str, event_type: str, payload: dict | None = None):
        item = {
            "incident_id": incident_id,
            "event_id": event_id,
            "event_type": event_type,
            "payload": payload or {},
        }
        self.events.append(item)
        return item

    def list_incident_events(self, *, incident_id: str, limit: int = 100):
        return [e for e in self.events if e["incident_id"] == incident_id]

    def put_dispute_evidence(self, *, incident_id: str, version: int, evidence: dict):
        return {}

    def list_dispute_evidence(self, *, incident_id: str, limit: int = 50):
        return []

    def put_retry_attempt(self, *, incident_id: str, attempt_id: str, attempt: dict):
        return {}

    def list_retry_attempts(self, *, incident_id: str, limit: int = 50):
        return []

    def put_ticket_link(self, *, incident_id: str, ticket_id: str, linked_by: str | None = None):
        return {}

    def get_ticket_link(self, *, incident_id: str):
        return None


def test_provider_transition_updates_status_and_emits_events() -> None:
    repo = _Repo()
    sink = ListDomainEventSink()
    service = PaymentIncidentTransitionService(repository=repo, event_sink=sink)

    out = service.apply_provider_transition(
        incident_id="inc_1",
        incident_type=PaymentIncidentType.DISPUTE,
        target_status="evidence_required",
        provider="stripe",
        provider_event_id="evt_1",
        source_event_type="charge.dispute.updated",
        payload={"dispute_id": "dp_1"},
    )

    assert out.duplicate is False
    assert out.incident["status"] == "evidence_required"
    assert len(repo.events) == 1
    assert len(out.emitted_events) == 3
    assert len(sink.emitted) == 3


def test_duplicate_provider_event_is_deduped() -> None:
    repo = _Repo()
    idem = InMemoryIdempotencyStore()
    service = PaymentIncidentTransitionService(repository=repo, idempotency=idem)

    first = service.apply_provider_transition(
        incident_id="inc_1",
        incident_type=PaymentIncidentType.DISPUTE,
        target_status="evidence_required",
        provider="stripe",
        provider_event_id="evt_dup",
        source_event_type="charge.dispute.updated",
    )
    second = service.apply_provider_transition(
        incident_id="inc_1",
        incident_type=PaymentIncidentType.DISPUTE,
        target_status="evidence_required",
        provider="stripe",
        provider_event_id="evt_dup",
        source_event_type="charge.dispute.updated",
    )

    assert first.duplicate is False
    assert second.duplicate is True
    assert len(repo.events) == 1


def test_invalid_transition_raises_stable_error_code() -> None:
    repo = _Repo()
    service = PaymentIncidentTransitionService(repository=repo)

    # DISP E3 widened opened->{won,lost,accepted} (real Stripe closes directly),
    # so a backward hop OUT of a terminal is now the canonical invalid case.
    repo.incidents["inc_1"]["status"] = "won"
    try:
        service.apply_provider_transition(
            incident_id="inc_1",
            incident_type=PaymentIncidentType.DISPUTE,
            target_status="opened",
            provider="stripe",
            provider_event_id="evt_bad",
            source_event_type="charge.dispute.updated",
        )
        raise AssertionError("expected transition error")
    except PaymentIncidentTransitionError as exc:
        assert exc.code == "invalid_transition"


def test_internal_action_transition_supports_payment_failure() -> None:
    repo = _Repo()
    sink = ListDomainEventSink()
    service = PaymentIncidentTransitionService(repository=repo, event_sink=sink)

    out = service.apply_internal_action_transition(
        incident_id="inc_pf",
        incident_type=PaymentIncidentType.PAYMENT_FAILURE,
        target_status="customer_action_required",
        action_name="payment_failure.mark_customer_action_required",
        actor_id="admin_1",
        action_id="act_1",
        payload={"reason": "method_declined"},
    )

    assert out.duplicate is False
    assert out.incident["status"] == "customer_action_required"
    assert len(repo.events) == 1


def test_transition_records_metrics(monkeypatch) -> None:
    repo = _Repo()
    service = PaymentIncidentTransitionService(repository=repo)
    seen: list[dict] = []
    monkeypatch.setattr(
        "app.services.payment_incident_transitions.record_incident_transition",
        lambda **kwargs: seen.append(kwargs),
    )

    out = service.apply_provider_transition(
        incident_id="inc_pf",
        incident_type=PaymentIncidentType.PAYMENT_FAILURE,
        target_status="customer_action_required",
        provider="stripe",
        provider_event_id="evt_metric",
        source_event_type="invoice.payment_failed",
    )

    assert out.duplicate is False
    assert len(seen) == 1
    assert seen[0]["to_status"] == "customer_action_required"
