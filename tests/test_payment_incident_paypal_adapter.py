from __future__ import annotations

from datetime import datetime, timezone

from app.services.payment_incident_paypal_adapter import PayPalPaymentIncidentAdapter
from app.core.settings import S


def test_paypal_adapter_rejects_missing_signature_headers() -> None:
    adapter = PayPalPaymentIncidentAdapter()
    object.__setattr__(S, "paypal_webhook_id", "wh_1")

    out = adapter.verify_webhook(signature=None, body=b"{}", headers={})
    assert out.valid is False
    assert out.code == "invalid_signature"


def test_paypal_adapter_verify_webhook_success(monkeypatch) -> None:
    adapter = PayPalPaymentIncidentAdapter()
    object.__setattr__(S, "paypal_webhook_id", "wh_1")
    object.__setattr__(S, "paypal_webhook_tolerance_seconds", 600)

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    out = adapter.verify_webhook(
        signature="sig",
        body=b"{}",
        headers={
            "paypal-transmission-id": "t1",
            "paypal-transmission-time": now,
            "paypal-transmission-sig": "sig",
            "paypal-cert-url": "https://api-m.paypal.com/v1/notifications/certs/CERT-123",
            "paypal-auth-algo": "SHA256withRSA",
        },
    )
    assert out.valid is True


def test_paypal_adapter_parses_dispute_and_failure_events() -> None:
    adapter = PayPalPaymentIncidentAdapter()

    dispute = adapter.parse_webhook_events(
        body=b'{"id":"evt_1","event_type":"CUSTOMER.DISPUTE.CREATED","resource":{"dispute_id":"PP-D-1","status":"OPEN","dispute_amount":{"value":"10.00","currency_code":"USD"}}}'
    )
    sub_fail = adapter.parse_webhook_events(
        body=b'{"id":"evt_2","event_type":"BILLING.SUBSCRIPTION.PAYMENT.FAILED","resource":{"id":"I-SUB1"}}'
    )

    assert len(dispute) == 1
    assert dispute[0].incident_type == "dispute"
    assert dispute[0].target_status == "opened"

    assert len(sub_fail) == 1
    assert sub_fail[0].incident_type == "payment_failure"
    assert sub_fail[0].target_status == "customer_action_required"
    assert sub_fail[0].payload["retry_mode"] == "autopay"


def test_paypal_retry_payment_modes() -> None:
    adapter = PayPalPaymentIncidentAdapter()

    immediate = adapter.retry_payment(payment_reference="order_1", metadata={"retry_mode": "immediate"})
    autopay = adapter.retry_payment(payment_reference="sub_1", metadata={"retry_mode": "autopay"})

    assert immediate.ok is True
    assert immediate.payload["action"] == "retry_order_capture"
    assert autopay.ok is True
    assert autopay.payload["action"] == "retry_subscription_payment"


def test_paypal_adapter_rejects_stale_transmission_time() -> None:
    adapter = PayPalPaymentIncidentAdapter()
    object.__setattr__(S, "paypal_webhook_id", "wh_1")
    object.__setattr__(S, "paypal_webhook_tolerance_seconds", 1)
    out = adapter.verify_webhook(
        signature="sig",
        body=b"{}",
        headers={
            "paypal-transmission-id": "t1",
            "paypal-transmission-time": "2020-01-01T00:00:00Z",
            "paypal-transmission-sig": "sig",
            "paypal-cert-url": "https://api-m.paypal.com/v1/notifications/certs/CERT-123",
            "paypal-auth-algo": "SHA256withRSA",
        },
    )
    assert out.valid is False
    assert out.code == "expired_signature"


def test_paypal_adapter_rejects_invalid_cert_url_and_algo() -> None:
    adapter = PayPalPaymentIncidentAdapter()
    object.__setattr__(S, "paypal_webhook_id", "wh_1")
    object.__setattr__(S, "paypal_webhook_tolerance_seconds", 300)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    bad_cert = adapter.verify_webhook(
        signature="sig",
        body=b"{}",
        headers={
            "paypal-transmission-id": "t1",
            "paypal-transmission-time": now,
            "paypal-transmission-sig": "sig",
            "paypal-cert-url": "http://evil.example/cert",
            "paypal-auth-algo": "SHA256withRSA",
        },
    )
    assert bad_cert.valid is False
    assert bad_cert.code == "invalid_signature"

    bad_algo = adapter.verify_webhook(
        signature="sig",
        body=b"{}",
        headers={
            "paypal-transmission-id": "t1",
            "paypal-transmission-time": now,
            "paypal-transmission-sig": "sig",
            "paypal-cert-url": "https://api-m.paypal.com/v1/notifications/certs/CERT-123",
            "paypal-auth-algo": "MD5",
        },
    )
    assert bad_algo.valid is False
    assert bad_algo.code == "invalid_signature"


def test_paypal_adapter_optional_shared_secret_signature(monkeypatch) -> None:
    import hashlib
    import hmac

    adapter = PayPalPaymentIncidentAdapter()
    object.__setattr__(S, "paypal_webhook_id", "wh_1")
    object.__setattr__(S, "paypal_webhook_tolerance_seconds", 300)
    object.__setattr__(S, "paypal_webhook_signature_secret", "sec_test")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    body = b'{"id":"evt_1"}'
    signed = f"t1|{now}|".encode("utf-8") + body
    sig = hmac.new(b"sec_test", signed, hashlib.sha256).hexdigest()

    ok = adapter.verify_webhook(
        signature=sig,
        body=body,
        headers={
            "paypal-transmission-id": "t1",
            "paypal-transmission-time": now,
            "paypal-transmission-sig": sig,
            "paypal-cert-url": "https://api-m.paypal.com/v1/notifications/certs/CERT-123",
            "paypal-auth-algo": "SHA256withRSA",
        },
    )
    assert ok.valid is True

    bad = adapter.verify_webhook(
        signature="bad",
        body=body,
        headers={
            "paypal-transmission-id": "t1",
            "paypal-transmission-time": now,
            "paypal-transmission-sig": "bad",
            "paypal-cert-url": "https://api-m.paypal.com/v1/notifications/certs/CERT-123",
            "paypal-auth-algo": "SHA256withRSA",
        },
    )
    assert bad.valid is False
    assert bad.code == "invalid_signature"
