from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


def _load_migration_module():
    path = Path("scripts/migrations/20260324_payment_incidents_schema.py")
    spec = importlib.util.spec_from_file_location("payment_incidents_migration", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _Waiter:
    def __init__(self, calls: list[dict]):
        self.calls = calls

    def wait(self, **kwargs):
        self.calls.append(kwargs)


class _Client:
    def __init__(self) -> None:
        self.tables = set()
        self.create_calls: list[dict] = []
        self.update_calls: list[dict] = []
        self.delete_calls: list[dict] = []
        self.wait_exists_calls: list[dict] = []
        self.wait_not_exists_calls: list[dict] = []

    def list_tables(self):
        return {"TableNames": sorted(self.tables)}

    def create_table(self, **kwargs):
        self.create_calls.append(kwargs)
        self.tables.add(kwargs["TableName"])
        return {"TableDescription": {"TableName": kwargs["TableName"]}}

    def describe_table(self, TableName: str):
        return {
            "Table": {
                "GlobalSecondaryIndexes": [],
                "AttributeDefinitions": [{"AttributeName": "incident_id", "AttributeType": "S"}],
            }
        }

    def update_table(self, **kwargs):
        self.update_calls.append(kwargs)
        return {"TableDescription": {"TableName": kwargs["TableName"]}}

    def delete_table(self, **kwargs):
        self.delete_calls.append(kwargs)
        self.tables.discard(kwargs["TableName"])
        return {"TableDescription": {"TableName": kwargs["TableName"]}}

    def get_waiter(self, name: str):
        if name == "table_exists":
            return _Waiter(self.wait_exists_calls)
        if name == "table_not_exists":
            return _Waiter(self.wait_not_exists_calls)
        raise AssertionError(f"unexpected waiter {name}")


def test_migrate_creates_all_payment_incident_tables(monkeypatch) -> None:
    module = _load_migration_module()
    client = _Client()
    monkeypatch.setattr(module, "ddb", SimpleNamespace(meta=SimpleNamespace(client=client)))
    monkeypatch.setattr(
        module,
        "S",
        SimpleNamespace(
            payment_incidents_table_name="payment_incidents",
            payment_incident_events_table_name="payment_incident_events",
            payment_dispute_evidence_table_name="payment_dispute_evidence",
            payment_retry_attempts_table_name="payment_retry_attempts",
            payment_incident_ticket_links_table_name="payment_incident_ticket_links",
        ),
    )

    module.migrate()

    created = {c["TableName"] for c in client.create_calls}
    assert created == {
        "payment_incidents",
        "payment_incident_events",
        "payment_dispute_evidence",
        "payment_retry_attempts",
        "payment_incident_ticket_links",
    }



def test_rollback_deletes_existing_payment_incident_tables(monkeypatch) -> None:
    module = _load_migration_module()
    client = _Client()
    client.tables = {
        "payment_incidents",
        "payment_incident_events",
        "payment_dispute_evidence",
        "payment_retry_attempts",
        "payment_incident_ticket_links",
    }
    monkeypatch.setattr(module, "ddb", SimpleNamespace(meta=SimpleNamespace(client=client)))
    monkeypatch.setattr(
        module,
        "S",
        SimpleNamespace(
            payment_incidents_table_name="payment_incidents",
            payment_incident_events_table_name="payment_incident_events",
            payment_dispute_evidence_table_name="payment_dispute_evidence",
            payment_retry_attempts_table_name="payment_retry_attempts",
            payment_incident_ticket_links_table_name="payment_incident_ticket_links",
        ),
    )

    module.rollback()

    deleted = [c["TableName"] for c in client.delete_calls]
    assert deleted == [
        "payment_incident_ticket_links",
        "payment_retry_attempts",
        "payment_dispute_evidence",
        "payment_incident_events",
        "payment_incidents",
    ]
    assert len(client.wait_not_exists_calls) == 5
