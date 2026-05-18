from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from app.core.time import now_ts

INCIDENTS_GSI_PROVIDER_INCIDENT = "ByProviderIncidentUpdatedAt"
INCIDENTS_GSI_CUSTOMER_UPDATED = "ByCustomerUpdatedAt"
INCIDENTS_GSI_RESPONSE_DUE = "ByResponseDueAt"
TICKET_LINKS_GSI_TICKET = "ByTicketId"


class PaymentIncidentRepository(Protocol):
    def put_incident(self, incident: dict[str, Any]) -> dict[str, Any]: ...

    def get_incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def update_incident_status(self, *, incident_id: str, status: str, status_reason: str | None = None) -> dict[str, Any] | None: ...

    def list_incidents_by_provider_incident(self, *, provider: str, provider_incident_id: str, limit: int = 25) -> list[dict[str, Any]]: ...

    def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 25) -> list[dict[str, Any]]: ...

    def list_incidents_by_customer(self, *, customer_id: str, limit: int = 25) -> list[dict[str, Any]]: ...

    def list_incidents_due_before(self, *, due_at_ts: int, limit: int = 25) -> list[dict[str, Any]]: ...
    def list_incidents(
        self,
        *,
        provider: str | None = None,
        incident_type: str | None = None,
        status: str | None = None,
        customer_id: str | None = None,
        due_before_ts: int | None = None,
        min_amount: float | None = None,
        max_amount: float | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]: ...

    def append_incident_event(self, *, incident_id: str, event_id: str, event_type: str, payload: dict[str, Any] | None = None) -> dict[str, Any]: ...

    def list_incident_events(self, *, incident_id: str, limit: int = 100) -> list[dict[str, Any]]: ...

    def put_dispute_evidence(self, *, incident_id: str, version: int, evidence: dict[str, Any]) -> dict[str, Any]: ...

    def list_dispute_evidence(self, *, incident_id: str, limit: int = 50) -> list[dict[str, Any]]: ...

    def put_retry_attempt(self, *, incident_id: str, attempt_id: str, attempt: dict[str, Any]) -> dict[str, Any]: ...

    def list_retry_attempts(self, *, incident_id: str, limit: int = 50) -> list[dict[str, Any]]: ...

    def put_ticket_link(self, *, incident_id: str, ticket_id: str, linked_by: str | None = None) -> dict[str, Any]: ...

    def get_ticket_link(self, *, incident_id: str) -> dict[str, Any] | None: ...


@dataclass
class DynamoPaymentIncidentRepository:
    incidents_table: Any | None = field(default=None)
    events_table: Any | None = field(default=None)
    evidence_table: Any | None = field(default=None)
    retries_table: Any | None = field(default=None)
    ticket_links_table: Any | None = field(default=None)

    def __post_init__(self) -> None:
        if all(
            table is not None
            for table in (
                self.incidents_table,
                self.events_table,
                self.evidence_table,
                self.retries_table,
                self.ticket_links_table,
            )
        ):
            return

        from app.core.tables import T

        self.incidents_table = self.incidents_table or T.payment_incidents
        self.events_table = self.events_table or T.payment_incident_events
        self.evidence_table = self.evidence_table or T.payment_dispute_evidence
        self.retries_table = self.retries_table or T.payment_retry_attempts
        self.ticket_links_table = self.ticket_links_table or T.payment_incident_ticket_links

    def put_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        now = str(now_ts())
        payload = dict(incident)
        payload.setdefault("created_at", now)
        payload["updated_at"] = now
        payload["provider_incident_key"] = _provider_incident_key(payload["provider"], payload["provider_incident_id"])
        payload["response_due_scope"] = "ALL"
        if not payload.get("response_due_at"):
            payload["response_due_at"] = "9999999999"
        self.incidents_table.put_item(Item=payload)
        return payload

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        return self.incidents_table.get_item(Key={"incident_id": incident_id}).get("Item")

    def update_incident_status(self, *, incident_id: str, status: str, status_reason: str | None = None) -> dict[str, Any] | None:
        now = str(now_ts())
        expr = "SET #status = :status, updated_at = :updated_at"
        values: dict[str, Any] = {":status": status, ":updated_at": now}
        names = {"#status": "status"}
        if status_reason:
            expr += ", status_reason = :status_reason"
            values[":status_reason"] = status_reason
        self.incidents_table.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression=expr,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
        return self.get_incident(incident_id)

    def list_incidents_by_provider_incident(self, *, provider: str, provider_incident_id: str, limit: int = 25) -> list[dict[str, Any]]:
        key = _provider_incident_key(provider, provider_incident_id)
        out = self.incidents_table.query(
            IndexName=INCIDENTS_GSI_PROVIDER_INCIDENT,
            KeyConditionExpression="provider_incident_key = :pk",
            ExpressionAttributeValues={":pk": key},
            ScanIndexForward=False,
            Limit=limit,
        )
        return out.get("Items", [])

    def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 25) -> list[dict[str, Any]]:
        return self.list_incidents_by_provider_incident(
            provider=provider,
            provider_incident_id=case_id,
            limit=limit,
        )

    def list_incidents_by_customer(self, *, customer_id: str, limit: int = 25) -> list[dict[str, Any]]:
        out = self.incidents_table.query(
            IndexName=INCIDENTS_GSI_CUSTOMER_UPDATED,
            KeyConditionExpression="customer_id = :pk",
            ExpressionAttributeValues={":pk": customer_id},
            ScanIndexForward=False,
            Limit=limit,
        )
        return out.get("Items", [])

    def list_incidents_due_before(self, *, due_at_ts: int, limit: int = 25) -> list[dict[str, Any]]:
        out = self.incidents_table.query(
            IndexName=INCIDENTS_GSI_RESPONSE_DUE,
            KeyConditionExpression="response_due_scope = :scope AND response_due_at <= :due",
            ExpressionAttributeValues={":scope": "ALL", ":due": str(due_at_ts)},
            ScanIndexForward=True,
            Limit=limit,
        )
        return out.get("Items", [])

    def list_incidents(
        self,
        *,
        provider: str | None = None,
        incident_type: str | None = None,
        status: str | None = None,
        customer_id: str | None = None,
        due_before_ts: int | None = None,
        min_amount: float | None = None,
        max_amount: float | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if customer_id:
            items = self.list_incidents_by_customer(customer_id=customer_id, limit=max(limit, 25))
        elif due_before_ts is not None:
            items = self.list_incidents_due_before(due_at_ts=due_before_ts, limit=max(limit, 25))
        else:
            items = self.incidents_table.scan(Limit=max(limit, 25)).get("Items", [])

        out: list[dict[str, Any]] = []
        for item in items:
            if provider and str(item.get("provider") or "").lower() != provider.lower():
                continue
            if incident_type and str(item.get("incident_type") or "").lower() != incident_type.lower():
                continue
            if status and str(item.get("status") or "").lower() != status.lower():
                continue
            if customer_id and str(item.get("customer_id") or "") != customer_id:
                continue
            if due_before_ts is not None:
                due_value = item.get("response_due_at")
                try:
                    due_int = int(str(due_value))
                except Exception:
                    continue
                if due_int > int(due_before_ts):
                    continue
            try:
                amount = float(item.get("amount") or 0)
            except Exception:
                amount = 0.0
            if min_amount is not None and amount < float(min_amount):
                continue
            if max_amount is not None and amount > float(max_amount):
                continue
            out.append(item)
            if len(out) >= limit:
                break
        return out

    def append_incident_event(self, *, incident_id: str, event_id: str, event_type: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        ts = str(now_ts())
        item = {
            "incident_id": incident_id,
            "event_ts_id": f"{ts}#{event_id}",
            "event_id": event_id,
            "event_type": event_type,
            "payload": payload or {},
            "created_at": ts,
        }
        self.events_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(event_ts_id)",
        )
        return item

    def list_incident_events(self, *, incident_id: str, limit: int = 100) -> list[dict[str, Any]]:
        out = self.events_table.query(
            KeyConditionExpression="incident_id = :pk",
            ExpressionAttributeValues={":pk": incident_id},
            ScanIndexForward=False,
            Limit=limit,
        )
        return out.get("Items", [])

    def put_dispute_evidence(self, *, incident_id: str, version: int, evidence: dict[str, Any]) -> dict[str, Any]:
        ts = str(now_ts())
        item = {
            "incident_id": incident_id,
            "version": str(version),
            "payload": evidence,
            "created_at": ts,
        }
        self.evidence_table.put_item(Item=item)
        return item

    def list_dispute_evidence(self, *, incident_id: str, limit: int = 50) -> list[dict[str, Any]]:
        out = self.evidence_table.query(
            KeyConditionExpression="incident_id = :pk",
            ExpressionAttributeValues={":pk": incident_id},
            ScanIndexForward=False,
            Limit=limit,
        )
        return out.get("Items", [])

    def put_retry_attempt(self, *, incident_id: str, attempt_id: str, attempt: dict[str, Any]) -> dict[str, Any]:
        ts = str(now_ts())
        item = {
            "incident_id": incident_id,
            "attempt_id": f"{ts}#{attempt_id}",
            "payload": attempt,
            "created_at": ts,
        }
        self.retries_table.put_item(Item=item)
        return item

    def list_retry_attempts(self, *, incident_id: str, limit: int = 50) -> list[dict[str, Any]]:
        out = self.retries_table.query(
            KeyConditionExpression="incident_id = :pk",
            ExpressionAttributeValues={":pk": incident_id},
            ScanIndexForward=False,
            Limit=limit,
        )
        return out.get("Items", [])

    def put_ticket_link(self, *, incident_id: str, ticket_id: str, linked_by: str | None = None) -> dict[str, Any]:
        ts = str(now_ts())
        item = {
            "incident_id": incident_id,
            "ticket_id": ticket_id,
            "linked_by": linked_by or "system",
            "linked_at": ts,
        }
        self.ticket_links_table.put_item(Item=item)
        return item

    def get_ticket_link(self, *, incident_id: str) -> dict[str, Any] | None:
        return self.ticket_links_table.get_item(Key={"incident_id": incident_id}).get("Item")


def _provider_incident_key(provider: str, provider_incident_id: str) -> str:
    return f"{provider}#{provider_incident_id}"
