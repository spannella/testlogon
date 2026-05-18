from __future__ import annotations

from app.services.payment_incidents_store import (
    INCIDENTS_GSI_CUSTOMER_UPDATED,
    INCIDENTS_GSI_PROVIDER_INCIDENT,
    INCIDENTS_GSI_RESPONSE_DUE,
    DynamoPaymentIncidentRepository,
)


class _StubTable:
    def __init__(self, *, get_item_result: dict | None = None, query_items: list[dict] | None = None) -> None:
        self.put_calls: list[dict] = []
        self.query_calls: list[dict] = []
        self.get_calls: list[dict] = []
        self.update_calls: list[dict] = []
        self.scan_calls: list[dict] = []
        self._get_item_result = get_item_result or {}
        self._query_items = query_items or []

    def put_item(self, **kwargs):
        self.put_calls.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_item(self, **kwargs):
        self.get_calls.append(kwargs)
        return self._get_item_result

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        return {"Items": list(self._query_items)}

    def update_item(self, **kwargs):
        self.update_calls.append(kwargs)
        return {"Attributes": {}}

    def scan(self, **kwargs):
        self.scan_calls.append(kwargs)
        return {"Items": list(self._query_items)}


def test_put_incident_sets_index_keys_and_timestamps(monkeypatch) -> None:
    from app.services import payment_incidents_store as store

    incidents = _StubTable()
    repo = DynamoPaymentIncidentRepository(
        incidents_table=incidents,
        events_table=_StubTable(),
        evidence_table=_StubTable(),
        retries_table=_StubTable(),
        ticket_links_table=_StubTable(),
    )
    monkeypatch.setattr(store, "now_ts", lambda: 1700000010)

    result = repo.put_incident(
        {
            "incident_id": "inc_1",
            "provider": "stripe",
            "provider_incident_id": "dp_1",
            "customer_id": "cust_1",
            "status": "opened",
        }
    )

    assert result["provider_incident_key"] == "stripe#dp_1"
    assert result["updated_at"] == "1700000010"
    assert result["created_at"] == "1700000010"
    assert result["response_due_scope"] == "ALL"
    assert incidents.put_calls[0]["Item"]["response_due_at"] == "9999999999"


def test_list_incidents_queries_expected_indexes() -> None:
    incidents = _StubTable(query_items=[{"incident_id": "inc_a"}])
    repo = DynamoPaymentIncidentRepository(
        incidents_table=incidents,
        events_table=_StubTable(),
        evidence_table=_StubTable(),
        retries_table=_StubTable(),
        ticket_links_table=_StubTable(),
    )

    by_provider = repo.list_incidents_by_provider_incident(provider="paypal", provider_incident_id="dsp_9")
    by_case = repo.list_incidents_by_case(provider="paypal", case_id="dsp_9")
    by_customer = repo.list_incidents_by_customer(customer_id="cust_22")
    by_due = repo.list_incidents_due_before(due_at_ts=1700009999)

    assert by_provider == [{"incident_id": "inc_a"}]
    assert by_case == [{"incident_id": "inc_a"}]
    assert by_customer == [{"incident_id": "inc_a"}]
    assert by_due == [{"incident_id": "inc_a"}]

    assert incidents.query_calls[0]["IndexName"] == INCIDENTS_GSI_PROVIDER_INCIDENT
    assert incidents.query_calls[0]["ExpressionAttributeValues"][":pk"] == "paypal#dsp_9"

    assert incidents.query_calls[1]["IndexName"] == INCIDENTS_GSI_PROVIDER_INCIDENT
    assert incidents.query_calls[1]["ExpressionAttributeValues"][":pk"] == "paypal#dsp_9"

    assert incidents.query_calls[2]["IndexName"] == INCIDENTS_GSI_CUSTOMER_UPDATED
    assert incidents.query_calls[2]["ExpressionAttributeValues"][":pk"] == "cust_22"

    assert incidents.query_calls[3]["IndexName"] == INCIDENTS_GSI_RESPONSE_DUE
    assert incidents.query_calls[3]["ExpressionAttributeValues"][":due"] == "1700009999"


def test_append_event_uses_conditional_put(monkeypatch) -> None:
    from app.services import payment_incidents_store as store

    events = _StubTable()
    repo = DynamoPaymentIncidentRepository(
        incidents_table=_StubTable(),
        events_table=events,
        evidence_table=_StubTable(),
        retries_table=_StubTable(),
        ticket_links_table=_StubTable(),
    )
    monkeypatch.setattr(store, "now_ts", lambda: 1700000011)

    item = repo.append_incident_event(
        incident_id="inc_1",
        event_id="evt_1",
        event_type="provider.webhook",
        payload={"k": "v"},
    )

    assert item["event_ts_id"] == "1700000011#evt_1"
    assert events.put_calls[0]["ConditionExpression"] == "attribute_not_exists(event_ts_id)"


def test_evidence_retry_and_ticket_link_storage(monkeypatch) -> None:
    from app.services import payment_incidents_store as store

    evidence = _StubTable(query_items=[{"version": "2"}])
    retries = _StubTable(query_items=[{"attempt_id": "a1"}])
    links = _StubTable(get_item_result={"Item": {"incident_id": "inc_1", "ticket_id": "tk_1"}})
    repo = DynamoPaymentIncidentRepository(
        incidents_table=_StubTable(),
        events_table=_StubTable(),
        evidence_table=evidence,
        retries_table=retries,
        ticket_links_table=links,
    )
    monkeypatch.setattr(store, "now_ts", lambda: 1700000012)

    evidence_item = repo.put_dispute_evidence(incident_id="inc_1", version=2, evidence={"files": ["s3://f"]})
    retry_item = repo.put_retry_attempt(incident_id="inc_1", attempt_id="retry_1", attempt={"initiator": "customer"})
    link_item = repo.put_ticket_link(incident_id="inc_1", ticket_id="tk_1", linked_by="admin_9")

    assert evidence_item["version"] == "2"
    assert retry_item["attempt_id"] == "1700000012#retry_1"
    assert link_item["linked_by"] == "admin_9"

    assert repo.list_dispute_evidence(incident_id="inc_1") == [{"version": "2"}]
    assert repo.list_retry_attempts(incident_id="inc_1") == [{"attempt_id": "a1"}]
    assert repo.get_ticket_link(incident_id="inc_1") == {"incident_id": "inc_1", "ticket_id": "tk_1"}


def test_update_incident_status_writes_status_and_reason(monkeypatch) -> None:
    from app.services import payment_incidents_store as store

    incidents = _StubTable(get_item_result={"Item": {"incident_id": "inc_1", "status": "under_review"}})
    repo = DynamoPaymentIncidentRepository(
        incidents_table=incidents,
        events_table=_StubTable(),
        evidence_table=_StubTable(),
        retries_table=_StubTable(),
        ticket_links_table=_StubTable(),
    )
    monkeypatch.setattr(store, "now_ts", lambda: 1700000020)

    out = repo.update_incident_status(incident_id="inc_1", status="under_review", status_reason="provider_update")

    assert out == {"incident_id": "inc_1", "status": "under_review"}
    update = incidents.update_calls[0]
    assert update["ExpressionAttributeValues"][":status"] == "under_review"
    assert update["ExpressionAttributeValues"][":status_reason"] == "provider_update"


def test_list_incidents_applies_provider_status_and_amount_filters() -> None:
    incidents = _StubTable(
        query_items=[
            {"incident_id": "i1", "provider": "stripe", "incident_type": "dispute", "status": "opened", "amount": "10.00"},
            {"incident_id": "i2", "provider": "paypal", "incident_type": "payment_failure", "status": "failed_initial", "amount": "1.00"},
        ]
    )
    repo = DynamoPaymentIncidentRepository(
        incidents_table=incidents,
        events_table=_StubTable(),
        evidence_table=_StubTable(),
        retries_table=_StubTable(),
        ticket_links_table=_StubTable(),
    )

    out = repo.list_incidents(provider="stripe", status="opened", min_amount=5, limit=10)
    assert [x["incident_id"] for x in out] == ["i1"]
    assert incidents.scan_calls[0]["Limit"] >= 10
