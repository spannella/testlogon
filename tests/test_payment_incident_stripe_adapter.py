from __future__ import annotations

from unittest.mock import MagicMock

from app.services.payment_incident_stripe_adapter import StripePaymentIncidentAdapter


def test_stripe_adapter_verify_webhook_invalid_signature(monkeypatch) -> None:
    adapter = StripePaymentIncidentAdapter()

    class _Webhook:
        @staticmethod
        def construct_event(**kwargs):
            raise ValueError("bad sig")

    stripe_mock = MagicMock()
    stripe_mock.Webhook = _Webhook
    monkeypatch.setattr("app.services.payment_incident_stripe_adapter.stripe", stripe_mock)

    out = adapter.verify_webhook(signature="bad", body=b"{}")
    assert out.valid is False
    assert out.code == "invalid_signature"


def test_stripe_adapter_parses_dispute_and_payment_failure_events() -> None:
    adapter = StripePaymentIncidentAdapter()

    dispute = adapter.parse_webhook_events(
        body=b'{"id":"evt_1","type":"charge.dispute.created","data":{"object":{"id":"dp_1","charge":"ch_1","amount":1000,"currency":"usd"}}}'
    )
    payfail = adapter.parse_webhook_events(
        body=b'{"id":"evt_2","type":"invoice.payment_failed","data":{"object":{"id":"in_1"}}}'
    )

    assert len(dispute) == 1
    assert dispute[0].incident_type == "dispute"
    assert dispute[0].target_status == "opened"

    assert len(payfail) == 1
    assert payfail[0].incident_type == "payment_failure"
    assert payfail[0].target_status == "customer_action_required"
    assert payfail[0].payload["retry_mode"] == "autopay"


def test_stripe_adapter_retry_payment_maps_immediate_and_autopay(monkeypatch) -> None:
    adapter = StripePaymentIncidentAdapter()
    stripe_mock = MagicMock()
    stripe_mock.PaymentIntent.confirm.return_value = {"id": "pi_1"}
    stripe_mock.Invoice.retrieve.return_value = {"id": "in_1"}
    stripe_mock.Invoice.pay.return_value = {"id": "in_1", "paid": True}
    monkeypatch.setattr("app.services.payment_incident_stripe_adapter.stripe", stripe_mock)

    immediate = adapter.retry_payment(payment_reference="pi_1", metadata={"retry_mode": "immediate"})
    autopay = adapter.retry_payment(payment_reference="in_1", metadata={"retry_mode": "autopay"})

    assert immediate.ok is True
    assert "payment_intent" in immediate.payload
    assert autopay.ok is True
    assert "invoice" in autopay.payload
