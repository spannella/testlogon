from __future__ import annotations

from app.services import payment_incident_metrics as pim


def test_record_incident_transition_response_submission_tracks_latency_and_sla(monkeypatch):
    calls: list[tuple[str, dict]] = []

    monkeypatch.setattr(pim, "now_ts", lambda: 2_000)
    monkeypatch.setattr(
        pim,
        "record_payment_incident_response_latency",
        lambda **kwargs: calls.append(("response_latency", kwargs)),
    )
    monkeypatch.setattr(
        pim,
        "record_payment_incident_response_sla_breach",
        lambda **kwargs: calls.append(("sla_breach", kwargs)),
    )
    monkeypatch.setattr(
        pim,
        "record_payment_incident_event",
        lambda **kwargs: calls.append(("event", kwargs)),
    )

    pim.record_incident_transition(
        incident={
            "provider": "stripe",
            "incident_type": "dispute",
            "created_at": "1000",
            "response_due_at": "1500",
        },
        from_status="evidence_required",
        to_status="response_submitted",
        source_event_type="admin.submit",
    )

    assert any(name == "response_latency" for name, _ in calls)
    assert any(name == "sla_breach" for name, _ in calls)


def test_record_incident_transition_retry_succeeded_tracks_recovery(monkeypatch):
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(pim, "now_ts", lambda: 10_000)
    monkeypatch.setattr(
        pim,
        "record_payment_incident_recovery_latency",
        lambda **kwargs: calls.append(("recovery_latency", kwargs)),
    )
    monkeypatch.setattr(
        pim,
        "record_payment_incident_event",
        lambda **kwargs: calls.append(("event", kwargs)),
    )

    pim.record_incident_transition(
        incident={"provider": "paypal", "incident_type": "payment_failure", "created_at": "9000"},
        from_status="retry_pending",
        to_status="retry_succeeded",
        source_event_type="provider.webhook",
    )

    assert any(name == "recovery_latency" for name, _ in calls)


def test_record_ticket_linked_tracks_mtta(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(
        pim,
        "record_payment_incident_ticket_latency",
        lambda **kwargs: calls.append(kwargs),
    )
    pim.record_ticket_linked(
        incident={"provider": "ccbill", "created_at": "100"},
        linked_at=160,
    )
    assert calls
    assert calls[0]["metric"] == "mtta"


def test_record_webhook_outcome_forwards_to_metrics(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(
        pim,
        "record_payment_incident_webhook_outcome",
        lambda **kwargs: calls.append(kwargs),
    )
    pim.record_webhook_outcome(provider="paypal", outcome="processed", reason="ok")
    assert calls == [{"provider": "paypal", "outcome": "processed", "reason": "ok"}]


def test_record_webhook_replay_event_forwards_to_metrics(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(
        pim,
        "record_payment_incident_webhook_replay_event",
        lambda **kwargs: calls.append(kwargs),
    )
    pim.record_webhook_replay_event(provider="stripe", event="checked")
    assert calls == [{"provider": "stripe", "event": "checked"}]


def test_set_webhook_replay_cache_entries_forwards_to_metrics(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(
        pim,
        "set_payment_incident_webhook_replay_cache_entries",
        lambda **kwargs: calls.append(kwargs),
    )
    pim.set_webhook_replay_cache_entries(entries=7)
    assert calls == [{"entries": 7}]
