from __future__ import annotations

from app.services.payment_incident_ccbill_adapter import CCBillPaymentIncidentAdapter


def test_ccbill_adapter_rejects_missing_signature() -> None:
    adapter = CCBillPaymentIncidentAdapter()
    out = adapter.verify_webhook(signature=None, body=b"{}")
    assert out.valid is False
    assert out.code == "invalid_signature"


def test_ccbill_adapter_verify_webhook_uses_signature_check(monkeypatch) -> None:
    adapter = CCBillPaymentIncidentAdapter()
    monkeypatch.setattr("app.services.payment_incident_ccbill_adapter._verify_ccbill_signature", lambda body, sig: sig == "good")

    bad = adapter.verify_webhook(signature="bad", body=b"{}")
    good = adapter.verify_webhook(signature="good", body=b"{}")

    assert bad.valid is False
    assert good.valid is True


def test_ccbill_adapter_parses_chargeback_and_rebill_failed() -> None:
    adapter = CCBillPaymentIncidentAdapter()

    chargeback = adapter.parse_webhook_events(
        body=b'{"eventId":"evt_1","eventType":"Chargeback","disputeId":"cb_1","transaction":{"transactionId":"tx_1","amount":"10.00","currency":"USD"}}'
    )
    rebill_failed = adapter.parse_webhook_events(
        body=b'{"eventId":"evt_2","eventType":"RebillDeclined","transaction":{"transactionId":"tx_2"}}'
    )

    assert len(chargeback) == 1
    assert chargeback[0].incident_type == "chargeback"
    assert chargeback[0].target_status == "opened"

    assert len(rebill_failed) == 1
    assert rebill_failed[0].incident_type == "payment_failure"
    assert rebill_failed[0].target_status == "customer_action_required"


def test_ccbill_adapter_retry_modes() -> None:
    adapter = CCBillPaymentIncidentAdapter()
    immediate = adapter.retry_payment(payment_reference="tx_1", metadata={"retry_mode": "immediate"})
    rebill = adapter.retry_payment(payment_reference="sub_1", metadata={"retry_mode": "autopay"})

    assert immediate.ok is True
    assert immediate.payload["action"] == "retry_transaction"
    assert rebill.ok is True
    assert rebill.payload["action"] == "retry_rebill"
