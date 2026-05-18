from __future__ import annotations

from typing import Any

from app.core.time import now_ts
try:
    from app.metrics import (
        record_payment_incident_event,
        record_payment_incident_recovery_latency,
        record_payment_incident_response_latency,
        record_payment_incident_response_sla_breach,
        record_payment_incident_retry_attempt,
        record_payment_incident_ticket_latency,
        record_payment_incident_webhook_outcome,
        record_payment_incident_webhook_replay_event,
        set_payment_incident_webhook_replay_cache_entries,
    )
except Exception:  # pragma: no cover - local/unit test fallback without web deps
    def record_payment_incident_event(**_kwargs: Any) -> None:
        return None

    def record_payment_incident_recovery_latency(**_kwargs: Any) -> None:
        return None

    def record_payment_incident_response_latency(**_kwargs: Any) -> None:
        return None

    def record_payment_incident_response_sla_breach(**_kwargs: Any) -> None:
        return None

    def record_payment_incident_retry_attempt(**_kwargs: Any) -> None:
        return None

    def record_payment_incident_ticket_latency(**_kwargs: Any) -> None:
        return None

    def record_payment_incident_webhook_outcome(**_kwargs: Any) -> None:
        return None

    def record_payment_incident_webhook_replay_event(**_kwargs: Any) -> None:
        return None

    def set_payment_incident_webhook_replay_cache_entries(**_kwargs: Any) -> None:
        return None

_DISPUTE_OUTCOME_STATUSES = {"won", "lost", "accepted", "canceled"}
_TERMINAL_STATUSES = {"won", "lost", "accepted", "canceled", "retry_succeeded", "retry_failed_terminal"}


def _safe_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except Exception:
        return None


def record_incident_created(*, incident: dict[str, Any]) -> None:
    provider = str(incident.get("provider") or "unknown")
    incident_type = str(incident.get("incident_type") or "unknown")
    status = str(incident.get("status") or "unknown")
    record_payment_incident_event(
        provider=provider,
        incident_type=incident_type,
        event="created",
        status=status,
        outcome="ok",
    )


def record_incident_transition(
    *,
    incident: dict[str, Any],
    from_status: str,
    to_status: str,
    source_event_type: str,
) -> None:
    provider = str(incident.get("provider") or "unknown")
    incident_type = str(incident.get("incident_type") or "unknown")

    record_payment_incident_event(
        provider=provider,
        incident_type=incident_type,
        event="transition",
        status=to_status or "unknown",
        outcome="ok",
    )

    if incident_type in {"dispute", "chargeback"} and to_status in _DISPUTE_OUTCOME_STATUSES:
        record_payment_incident_event(
            provider=provider,
            incident_type=incident_type,
            event="outcome",
            status=to_status,
            outcome=to_status,
        )

    if incident_type in {"dispute", "chargeback"} and to_status == "response_submitted":
        created_at = _safe_int(incident.get("created_at"))
        due_at = _safe_int(incident.get("response_due_at"))
        now = int(now_ts())
        if created_at is not None and now >= created_at:
            record_payment_incident_response_latency(
                provider=provider,
                incident_type=incident_type,
                elapsed_seconds=float(now - created_at),
            )
        if due_at is not None and due_at < now:
            record_payment_incident_response_sla_breach(provider=provider, incident_type=incident_type)

    if incident_type == "payment_failure" and to_status == "retry_succeeded":
        created_at = _safe_int(incident.get("created_at"))
        now = int(now_ts())
        if created_at is not None and now >= created_at:
            record_payment_incident_recovery_latency(
                provider=provider,
                elapsed_seconds=float(now - created_at),
            )

    if to_status in _TERMINAL_STATUSES:
        _record_ticket_mttr_if_linked(incident=incident, provider=provider)

    record_payment_incident_event(
        provider=provider,
        incident_type=incident_type,
        event="source",
        status=to_status or "unknown",
        outcome=(source_event_type or "unknown").lower(),
    )


def record_retry_attempt(*, incident: dict[str, Any], action: str, ok: bool, code: str | None = None) -> None:
    provider = str(incident.get("provider") or "unknown")
    record_payment_incident_retry_attempt(
        provider=provider,
        action=action or "retry",
        outcome="success" if ok else "failure",
        code=(code or "none"),
    )


def record_ticket_linked(*, incident: dict[str, Any], linked_at: int | None = None) -> None:
    provider = str(incident.get("provider") or "unknown")
    created_at = _safe_int(incident.get("created_at"))
    linked = int(linked_at) if linked_at is not None else int(now_ts())
    if created_at is not None and linked >= created_at:
        record_payment_incident_ticket_latency(
            provider=provider,
            metric="mtta",
            elapsed_seconds=float(linked - created_at),
        )


def _record_ticket_mttr_if_linked(*, incident: dict[str, Any], provider: str) -> None:
    link = incident.get("ticket_link")
    if not isinstance(link, dict):
        return
    linked_at = _safe_int(link.get("linked_at"))
    now = int(now_ts())
    if linked_at is not None and now >= linked_at:
        record_payment_incident_ticket_latency(
            provider=provider,
            metric="mttr",
            elapsed_seconds=float(now - linked_at),
        )


def record_webhook_outcome(*, provider: str, outcome: str, reason: str = "none") -> None:
    record_payment_incident_webhook_outcome(
        provider=provider,
        outcome=outcome,
        reason=reason,
    )


def record_webhook_replay_event(*, provider: str, event: str) -> None:
    record_payment_incident_webhook_replay_event(
        provider=provider,
        event=event,
    )


def set_webhook_replay_cache_entries(*, entries: int) -> None:
    set_payment_incident_webhook_replay_cache_entries(entries=entries)
