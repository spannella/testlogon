from __future__ import annotations

import importlib

migration = importlib.import_module("scripts.migrations.20260405_messaging_drafts_schema")


class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self):
        yield from self._pages


class FakeClient:
    def __init__(self, existing_tables: list[str] | None = None):
        self.tables = set(existing_tables or [])
        self.created_payloads = []
        self.ttl_updates = []
        self.ttl_description = {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}

    def get_paginator(self, name: str):
        assert name == "list_tables"
        return _Paginator([{"TableNames": sorted(self.tables)}])

    def create_table(self, **kwargs):
        self.created_payloads.append(kwargs)
        self.tables.add(kwargs["TableName"])

    def describe_time_to_live(self, TableName: str):
        assert TableName in self.tables
        return self.ttl_description

    def update_time_to_live(self, **kwargs):
        self.ttl_updates.append(kwargs)


def test_migrate_creates_table_with_required_indexes_and_ttl():
    client = FakeClient()

    migration.migrate(table_name="MessageDrafts", ttl_attr="ttl_epoch", client=client)

    assert len(client.created_payloads) == 1
    payload = client.created_payloads[0]
    assert payload["TableName"] == "MessageDrafts"

    gsi_names = {g["IndexName"] for g in payload["GlobalSecondaryIndexes"]}
    assert gsi_names == {"ByConversationUpdatedAt", "ByOwnerUpdatedAt"}

    assert len(client.ttl_updates) == 1
    assert client.ttl_updates[0]["TimeToLiveSpecification"]["AttributeName"] == "ttl_epoch"


def test_migrate_is_idempotent_when_table_and_ttl_already_present():
    client = FakeClient(existing_tables=["MessageDrafts"])
    client.ttl_description = {
        "TimeToLiveDescription": {
            "TimeToLiveStatus": "ENABLED",
            "AttributeName": "ttl_epoch",
        }
    }

    migration.migrate(table_name="MessageDrafts", ttl_attr="ttl_epoch", client=client)

    assert client.created_payloads == []
    assert client.ttl_updates == []
