from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.time import now_ts
from app.services.payment_incident_transitions import PaymentIncidentTransitionService
from app.services.payment_incidents_domain import PaymentIncidentType
from app.services.payment_incidents_store import PaymentIncidentRepository
from app.services.payment_incident_metrics import record_ticket_linked
from app.services.tickets import STORE, TicketStateError


INCIDENT_TERMINAL_STATUSES = {"won", "lost", "accepted", "canceled", "retry_succeeded", "retry_failed_terminal"}


@dataclass
class TicketAutomationResult:
    created: bool
    ticket_id: str | None = None
    trigger: str | None = None


def evaluate_ticket_trigger(incident: dict[str, Any], *, ts: int | None = None) -> str | None:
    current_ts = int(ts or now_ts())
    incident_type = str(incident.get("incident_type") or "")
    status = str(incident.get("status") or "")

    if incident_type in {PaymentIncidentType.DISPUTE.value, PaymentIncidentType.CHARGEBACK.value} and status in {"opened", "evidence_required"}:
        return "dispute_opened"

    if incident_type in {PaymentIncidentType.DISPUTE.value, PaymentIncidentType.CHARGEBACK.value}:
        try:
            due_at = int(str(incident.get("response_due_at") or "0"))
        except Exception:
            due_at = 0
        if due_at and due_at <= current_ts + 24 * 3600 and status not in {"won", "lost", "accepted", "canceled"}:
            return "dispute_deadline_nearing"

    if incident_type == PaymentIncidentType.PAYMENT_FAILURE.value:
        if status == "retry_failed_terminal":
            return "terminal_retry_failure"
        try:
            updated_at = int(str(incident.get("updated_at") or "0"))
        except Exception:
            updated_at = 0
        if status in {"customer_action_required", "ready_to_retry"} and updated_at and updated_at <= current_ts - 24 * 3600:
            return "stalled_payment_failure"

    return None


def ensure_incident_ticket_link(repo: PaymentIncidentRepository, *, incident: dict[str, Any], trigger: str | None = None) -> TicketAutomationResult:
    incident_id = str(incident.get("incident_id") or "")
    if not incident_id:
        return TicketAutomationResult(created=False, ticket_id=None, trigger=trigger)

    existing = repo.get_ticket_link(incident_id=incident_id)
    if existing and existing.get("ticket_id"):
        return TicketAutomationResult(created=False, ticket_id=str(existing.get("ticket_id")), trigger=trigger)

    owner_sub = str(incident.get("account_id") or incident.get("customer_id") or "system")
    subject = f"Payment incident {incident_id}: {trigger or 'review_required'}"
    description = (
        f"Incident {incident_id} requires attention.\n"
        f"Type: {incident.get('incident_type')}\n"
        f"Status: {incident.get('status')}\n"
        f"Provider: {incident.get('provider')}"
    )
    ticket = STORE.create_ticket(owner_sub=owner_sub, subject=subject, description=description)
    ticket_id = str(ticket.get("ticket_id") or "")
    if ticket_id:
        link = repo.put_ticket_link(incident_id=incident_id, ticket_id=ticket_id, linked_by="payment_incident_automation")
        try:
            record_ticket_linked(incident={**incident, "ticket_link": link}, linked_at=int(str(link.get("linked_at") or "0")))
        except Exception:
            pass
    return TicketAutomationResult(created=bool(ticket_id), ticket_id=ticket_id or None, trigger=trigger)


def sync_ticket_from_incident(repo: PaymentIncidentRepository, *, incident: dict[str, Any]) -> None:
    link = repo.get_ticket_link(incident_id=str(incident.get("incident_id") or ""))
    if not link or not link.get("ticket_id"):
        return
    ticket_id = str(link["ticket_id"])
    ticket = STORE.get_ticket(ticket_id)
    if not ticket:
        return

    status = str(incident.get("status") or "")
    target_ticket_status = "done" if status in INCIDENT_TERMINAL_STATUSES else "open"
    if str(ticket.get("status") or "") == target_ticket_status:
        return
    try:
        STORE.update_status(ticket_id=ticket_id, actor_sub="payment_incident_sync", status=target_ticket_status)
    except TicketStateError:
        return


def sync_incident_from_ticket(repo: PaymentIncidentRepository, *, ticket_id: str, ticket_status: str) -> dict[str, Any] | None:
    incidents = repo.list_incidents(limit=250)
    linked_incident = None
    for incident in incidents:
        link = repo.get_ticket_link(incident_id=str(incident.get("incident_id") or ""))
        if link and str(link.get("ticket_id") or "") == ticket_id:
            linked_incident = incident
            break
    if not linked_incident:
        return None

    incident_id = str(linked_incident.get("incident_id") or "")
    incident_type = str(linked_incident.get("incident_type") or "")
    current_status = str(linked_incident.get("status") or "")
    if current_status in INCIDENT_TERMINAL_STATUSES and ticket_status != "done":
        return linked_incident

    if ticket_status != "done":
        return linked_incident

    if incident_type in {PaymentIncidentType.DISPUTE.value, PaymentIncidentType.CHARGEBACK.value}:
        target_status = "accepted"
    elif incident_type == PaymentIncidentType.PAYMENT_FAILURE.value:
        target_status = "retry_failed_terminal"
    else:
        return linked_incident

    if current_status == target_status:
        return linked_incident

    transition_service = PaymentIncidentTransitionService(repo)
    try:
        transition_service.apply_provider_transition(
            incident_id=incident_id,
            incident_type=PaymentIncidentType(incident_type),
            target_status=target_status,
            provider=str(linked_incident.get("provider") or "system"),
            provider_event_id=f"ticket_sync:{ticket_id}:{ticket_status}",
            source_event_type="ticket.status_sync",
            payload={"ticket_id": ticket_id, "ticket_status": ticket_status},
        )
    except Exception:
        repo.update_incident_status(incident_id=incident_id, status=target_status, status_reason="ticket_status_sync")
    return repo.get_incident(incident_id)
