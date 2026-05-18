from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    code: str
    message: str


@dataclass(frozen=True)
class CanonicalProviderEvent:
    provider: str
    provider_event_id: str
    incident_id: str | None
    incident_type: str
    target_status: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderActionResult:
    ok: bool
    code: str
    message: str
    payload: dict[str, Any] = field(default_factory=dict)


class PaymentIncidentProviderAdapter(Protocol):
    provider_key: str

    def verify_webhook(self, *, signature: str | None, body: bytes, headers: dict[str, str] | None = None) -> VerificationResult: ...

    def parse_webhook_events(self, *, body: bytes, headers: dict[str, str] | None = None) -> list[CanonicalProviderEvent]: ...

    def fetch_dispute_details(self, *, provider_incident_id: str) -> ProviderActionResult: ...

    def submit_dispute_response(self, *, provider_incident_id: str, evidence: dict[str, Any]) -> ProviderActionResult: ...

    def retry_payment(self, *, payment_reference: str, metadata: dict[str, Any] | None = None) -> ProviderActionResult: ...


@dataclass
class UnsupportedProviderAdapter:
    provider_key: str

    def verify_webhook(self, *, signature: str | None, body: bytes, headers: dict[str, str] | None = None) -> VerificationResult:
        return VerificationResult(valid=False, code="unsupported_provider", message=f"provider '{self.provider_key}' is not supported")

    def parse_webhook_events(self, *, body: bytes, headers: dict[str, str] | None = None) -> list[CanonicalProviderEvent]:
        return []

    def fetch_dispute_details(self, *, provider_incident_id: str) -> ProviderActionResult:
        return ProviderActionResult(
            ok=False,
            code="unsupported_provider",
            message=f"provider '{self.provider_key}' is not supported",
            payload={"provider_incident_id": provider_incident_id},
        )

    def submit_dispute_response(self, *, provider_incident_id: str, evidence: dict[str, Any]) -> ProviderActionResult:
        return ProviderActionResult(
            ok=False,
            code="unsupported_provider",
            message=f"provider '{self.provider_key}' is not supported",
            payload={"provider_incident_id": provider_incident_id, "evidence_keys": sorted(evidence.keys())},
        )

    def retry_payment(self, *, payment_reference: str, metadata: dict[str, Any] | None = None) -> ProviderActionResult:
        return ProviderActionResult(
            ok=False,
            code="unsupported_provider",
            message=f"provider '{self.provider_key}' is not supported",
            payload={"payment_reference": payment_reference, "metadata": metadata or {}},
        )


@dataclass
class PaymentIncidentProviderRegistry:
    _providers: dict[str, PaymentIncidentProviderAdapter] = field(default_factory=dict)

    def register(self, adapter: PaymentIncidentProviderAdapter) -> None:
        key = str(adapter.provider_key or "").strip().lower()
        if not key:
            raise ValueError("provider_key is required")
        self._providers[key] = adapter

    def resolve(self, provider_key: str) -> PaymentIncidentProviderAdapter:
        key = str(provider_key or "").strip().lower()
        adapter = self._providers.get(key)
        if adapter:
            return adapter
        return UnsupportedProviderAdapter(provider_key=key or "unknown")

    def supported_providers(self) -> list[str]:
        return sorted(self._providers.keys())


DEFAULT_PROVIDER_REGISTRY = PaymentIncidentProviderRegistry()


def resolve_provider_adapter(provider_key: str) -> PaymentIncidentProviderAdapter:
    return DEFAULT_PROVIDER_REGISTRY.resolve(provider_key)
