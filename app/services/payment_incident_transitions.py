from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import Any, Protocol

from app.services.payment_incidents_domain import PaymentIncidentType, validate_incident_status_transition
from app.services.payment_incidents_store import PaymentIncidentRepository
from app.services.payment_incident_metrics import record_incident_transition


class PaymentIncidentTransitionError(Exception):
    def __init__(self, *, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class IdempotencyStore(Protocol):
    def claim(self, key: str, *, ttl_seconds: int = 3600) -> bool: ...


class DomainEventSink(Protocol):
    def emit(self, *, event_type: str, payload: dict[str, Any]) -> None: ...


@dataclass
class InMemoryIdempotencyStore:
    _seen: dict[str, int] = field(default_factory=dict)

    def claim(self, key: str, *, ttl_seconds: int = 3600) -> bool:
        now = int(datetime.now(tz=timezone.utc).timestamp())
        expiry = self._seen.get(key)
        if expiry and expiry >= now:
            return False
        self._seen[key] = now + ttl_seconds
        return True


@dataclass
class ListDomainEventSink:
    emitted: list[dict[str, Any]] = field(default_factory=list)

    def emit(self, *, event_type: str, payload: dict[str, Any]) -> None:
        self.emitted.append({"event_type": event_type, "payload": payload})


@dataclass(frozen=True)
class TransitionResult:
    incident: dict[str, Any]
    duplicate: bool
    emitted_events: list[str]


@dataclass
class PaymentIncidentTransitionService:
    repository: PaymentIncidentRepository
    idempotency: IdempotencyStore = field(default_factory=InMemoryIdempotencyStore)
    event_sink: DomainEventSink | None = None

    def apply_provider_transition(
        self,
        *,
        incident_id: str,
        incident_type: PaymentIncidentType,
        target_status: str,
        provider: str,
        provider_event_id: str,
        source_event_type: str,
        payload: dict[str, Any] | None = None,
    ) -> TransitionResult:
        idempotency_key = build_provider_idempotency_key(provider=provider, provider_event_id=provider_event_id, incident_id=incident_id)
        return self._apply_transition(
            incident_id=incident_id,
            incident_type=incident_type,
            target_status=target_status,
            provider=provider,
            idempotency_key=idempotency_key,
            source_event_type=source_event_type,
            payload=payload or {},
        )

    def apply_internal_action_transition(
        self,
        *,
        incident_id: str,
        incident_type: PaymentIncidentType,
        target_status: str,
        action_name: str,
        actor_id: str,
        action_id: str,
        payload: dict[str, Any] | None = None,
    ) -> TransitionResult:
        key_seed = f"{incident_id}:{actor_id}:{action_name}:{action_id}"
        idempotency_key = "act_" + hashlib.sha256(key_seed.encode("utf-8")).hexdigest()[:24]
        enriched_payload = dict(payload or {})
        enriched_payload["actor_id"] = actor_id
        return self._apply_transition(
            incident_id=incident_id,
            incident_type=incident_type,
            target_status=target_status,
            provider="internal",
            idempotency_key=idempotency_key,
            source_event_type=action_name,
            payload=enriched_payload,
        )

    def _apply_transition(
        self,
        *,
        incident_id: str,
        incident_type: PaymentIncidentType,
        target_status: str,
        provider: str,
        idempotency_key: str,
        source_event_type: str,
        payload: dict[str, Any],
    ) -> TransitionResult:
        if not self.idempotency.claim(idempotency_key):
            incident = self.repository.get_incident(incident_id)
            if not incident:
                raise PaymentIncidentTransitionError(code="incident_not_found", message="payment incident not found")
            return TransitionResult(incident=incident, duplicate=True, emitted_events=[])

        incident = self.repository.get_incident(incident_id)
        if not incident:
            raise PaymentIncidentTransitionError(code="incident_not_found", message="payment incident not found")

        current_status = incident.get("status")
        if current_status == target_status:
            return TransitionResult(incident=incident, duplicate=False, emitted_events=[])

        try:
            validate_incident_status_transition(
                incident_type,
                _status_for_type(incident_type, str(current_status)),
                _status_for_type(incident_type, target_status),
            )
        except ValueError as exc:
            raise PaymentIncidentTransitionError(code="invalid_transition", message=str(exc)) from exc

        updated = self.repository.update_incident_status(
            incident_id=incident_id,
            status=target_status,
            status_reason=source_event_type,
        )
        if not updated:
            raise PaymentIncidentTransitionError(code="incident_not_found", message="payment incident not found")

        self.repository.append_incident_event(
            incident_id=incident_id,
            event_id=idempotency_key,
            event_type=source_event_type,
            payload={
                "from_status": current_status,
                "to_status": target_status,
                **payload,
            },
        )
        metric_incident = dict(updated)
        try:
            link = self.repository.get_ticket_link(incident_id=incident_id)
            if link:
                metric_incident["ticket_link"] = link
        except Exception:
            pass
        try:
            record_incident_transition(
                incident=metric_incident,
                from_status=str(current_status or ""),
                to_status=target_status,
                source_event_type=source_event_type,
            )
        except Exception:
            pass

        emitted = [
            "payment_incident.transitioned",
            "payment_incident.ticketing_candidate",
            "payment_incident.metrics",
        ]
        if self.event_sink:
            for event_type in emitted:
                self.event_sink.emit(
                    event_type=event_type,
                    payload={
                        "incident_id": incident_id,
                        "from_status": current_status,
                        "to_status": target_status,
                        "source_event_type": source_event_type,
                    },
                )

        return TransitionResult(incident=updated, duplicate=False, emitted_events=emitted)


def build_provider_idempotency_key(*, provider: str, provider_event_id: str, incident_id: str) -> str:
    seed = f"{provider}:{provider_event_id}:{incident_id}"
    return "evt_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def _status_for_type(incident_type: PaymentIncidentType, status: str):
    from app.services.payment_incidents_domain import DisputeStatus, PaymentFailureStatus

    if incident_type in {PaymentIncidentType.DISPUTE, PaymentIncidentType.CHARGEBACK}:
        return DisputeStatus(status)
    return PaymentFailureStatus(status)
