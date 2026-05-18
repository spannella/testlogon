from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from botocore.exceptions import ClientError


def _load_module():
    path = Path("scripts/migrations/20260325_reply_threads_schema.py").resolve()
    spec = importlib.util.spec_from_file_location("reply_threads_schema_migration", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class _FakeClient:
    def __init__(self) -> None:
        self.tables = {"Messages"}
        self.created_tables: list[dict] = []
        self.updated_tables: list[dict] = []
        self.deleted_tables: list[str] = []
        self.message_attr_defs = {
            "conversation_id": {"AttributeName": "conversation_id", "AttributeType": "S"},
            "message_id": {"AttributeName": "message_id", "AttributeType": "S"},
        }
        self.message_gsis: list[dict] = []

    def list_tables(self):
        return {"TableNames": sorted(self.tables)}

    def create_table(self, **kwargs):
        self.created_tables.append(kwargs)
        self.tables.add(kwargs["TableName"])
        return {}

    def describe_table(self, **kwargs):
        table_name = kwargs["TableName"]
        if table_name == "Messages":
            return {
                "Table": {
                    "TableStatus": "ACTIVE",
                    "AttributeDefinitions": list(self.message_attr_defs.values()),
                    "GlobalSecondaryIndexes": list(self.message_gsis),
                }
            }
        if table_name in self.tables:
            return {"Table": {"TableStatus": "ACTIVE"}}
        raise ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "DescribeTable")

    def update_table(self, **kwargs):
        self.updated_tables.append(kwargs)
        for attr in kwargs.get("AttributeDefinitions", []):
            self.message_attr_defs[attr["AttributeName"]] = attr
        for upd in kwargs.get("GlobalSecondaryIndexUpdates", []):
            create = upd.get("Create", {})
            index_name = create.get("IndexName")
            if index_name and not any(g.get("IndexName") == index_name for g in self.message_gsis):
                self.message_gsis.append({"IndexName": index_name})
        return {}

    def delete_table(self, **kwargs):
        table_name = kwargs["TableName"]
        if table_name not in self.tables:
            raise ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "DeleteTable")
        self.deleted_tables.append(table_name)
        self.tables.remove(table_name)
        return {}


class _FakeClientDuplicateIndex(_FakeClient):
    def update_table(self, **kwargs):
        index_name = kwargs["GlobalSecondaryIndexUpdates"][0]["Create"]["IndexName"]
        if index_name == "ByParentMessageId":
            raise ClientError(
                {"Error": {"Code": "ValidationException", "Message": "Index already exists"}},
                "UpdateTable",
            )
        return super().update_table(**kwargs)


class _FakeDDB:
    def __init__(self, client):
        self.meta = type("Meta", (), {"client": client})()


def test_migration_creates_threads_table_and_message_indexes(monkeypatch) -> None:
    mod = _load_module()
    client = _FakeClient()
    monkeypatch.setattr(mod, "ddb", _FakeDDB(client))
    monkeypatch.setattr(mod.time, "sleep", lambda *_args, **_kwargs: None)

    mod.migrate()

    assert any(call["TableName"] == "MessageThreads" for call in client.created_tables)
    created_indexes = [c["GlobalSecondaryIndexUpdates"][0]["Create"]["IndexName"] for c in client.updated_tables]
    assert created_indexes == [
        "ByConversationCreatedAt",
        "ByParentMessageId",
        "ByThreadCreatedAt",
        "ByThreadRootMessageId",
    ]


def test_migration_apply_is_idempotent_on_repeat_runs(monkeypatch) -> None:
    mod = _load_module()
    client = _FakeClient()
    monkeypatch.setattr(mod, "ddb", _FakeDDB(client))
    monkeypatch.setattr(mod.time, "sleep", lambda *_args, **_kwargs: None)

    mod.migrate()
    first_create_count = len(client.created_tables)
    first_update_count = len(client.updated_tables)
    mod.migrate()

    assert len(client.created_tables) == first_create_count
    assert len(client.updated_tables) == first_update_count


def test_migration_apply_tolerates_duplicate_index_validation(monkeypatch) -> None:
    mod = _load_module()
    client = _FakeClientDuplicateIndex()
    monkeypatch.setattr(mod, "ddb", _FakeDDB(client))
    monkeypatch.setattr(mod.time, "sleep", lambda *_args, **_kwargs: None)

    mod.migrate()

    # Migration should complete even when one index create reports already-exists.
    assert any(call["TableName"] == "MessageThreads" for call in client.created_tables)


def test_migration_rollback_deletes_threads_table_and_is_idempotent(monkeypatch) -> None:
    mod = _load_module()
    client = _FakeClient()
    client.tables.add("MessageThreads")
    monkeypatch.setattr(mod, "ddb", _FakeDDB(client))
    monkeypatch.setattr(mod.time, "sleep", lambda *_args, **_kwargs: None)

    mod.rollback()
    mod.rollback()

    assert client.deleted_tables == ["MessageThreads"]
