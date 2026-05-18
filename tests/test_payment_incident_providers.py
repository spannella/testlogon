from __future__ import annotations

from app.services.payment_incident_providers import (
    CanonicalProviderEvent,
    PaymentIncidentProviderRegistry,
    ProviderActionResult,
    VerificationResult,
)


class _MockStripeAdapter:
    provider_key = "stripe"

    def verify_webhook(self, *, signature: str | None, body: bytes, headers: dict[str, str] | None = None) -> VerificationResult:
        if signature == "ok":
            return VerificationResult(valid=True, code="ok", message="verified")
        return VerificationResult(valid=False, code="invalid_signature", message="signature mismatch")

    def parse_webhook_events(self, *, body: bytes, headers: dict[str, str] | None = None) -> list[CanonicalProviderEvent]:
        return [
            CanonicalProviderEvent(
                provider="stripe",
                provider_event_id="evt_123",
                incident_id="inc_1",
                incident_type="dispute",
                target_status="opened",
                payload={"raw": body.decode("utf-8")},
            )
        ]

    def fetch_dispute_details(self, *, provider_incident_id: str) -> ProviderActionResult:
        return ProviderActionResult(ok=True, code="ok", message="fetched", payload={"id": provider_incident_id})

    def submit_dispute_response(self, *, provider_incident_id: str, evidence: dict[str, object]) -> ProviderActionResult:
        return ProviderActionResult(ok=True, code="ok", message="submitted", payload={"id": provider_incident_id, "evidence": evidence})

    def retry_payment(self, *, payment_reference: str, metadata: dict[str, object] | None = None) -> ProviderActionResult:
        return ProviderActionResult(ok=True, code="ok", message="retried", payload={"ref": payment_reference, "metadata": metadata or {}})


def test_registry_resolves_supported_adapter_and_contract_methods() -> None:
    registry = PaymentIncidentProviderRegistry()
    registry.register(_MockStripeAdapter())

    adapter = registry.resolve("stripe")
    verify = adapter.verify_webhook(signature="ok", body=b"{}")
    events = adapter.parse_webhook_events(body=b'{"id":"evt_123"}')
    details = adapter.fetch_dispute_details(provider_incident_id="dp_1")
    submit = adapter.submit_dispute_response(provider_incident_id="dp_1", evidence={"receipt": "s3://file"})
    retry = adapter.retry_payment(payment_reference="pi_1", metadata={"source": "user_retry"})

    assert verify.valid is True
    assert len(events) == 1
    assert events[0].provider_event_id == "evt_123"
    assert details.ok is True
    assert submit.ok is True
    assert retry.ok is True
    assert registry.supported_providers() == ["stripe"]


def test_registry_returns_safe_unsupported_provider_adapter() -> None:
    registry = PaymentIncidentProviderRegistry()

    adapter = registry.resolve("unknownpay")
    verify = adapter.verify_webhook(signature="x", body=b"{}")
    events = adapter.parse_webhook_events(body=b"{}")
    details = adapter.fetch_dispute_details(provider_incident_id="dp_404")

    assert verify.valid is False
    assert verify.code == "unsupported_provider"
    assert events == []
    assert details.ok is False
    assert details.code == "unsupported_provider"
    assert "unknownpay" in details.message


def test_register_requires_non_empty_provider_key() -> None:
    registry = PaymentIncidentProviderRegistry()

    class _BadAdapter:
        provider_key = "   "

    try:
        registry.register(_BadAdapter())
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert str(exc) == "provider_key is required"
