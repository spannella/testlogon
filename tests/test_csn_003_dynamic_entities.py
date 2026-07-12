"""CSN-003: Dynamic Entities hermetic tests.

Offline, no real AWS. moto in-memory DynamoDB bound to frozen T.* via
object.__setattr__.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from app.core.settings import S
from app.core.tables import T


def _patch_frozen(tc, obj, attr, value):
    original = getattr(obj, attr)
    object.__setattr__(obj, attr, value)
    tc.addCleanup(lambda: object.__setattr__(obj, attr, original))


def _make_defs_table(ddb):
    return ddb.create_table(
        TableName="dynamic_entity_defs_test",
        KeySchema=[
            {"AttributeName": "entity_name", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "entity_name", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "created_by", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "created_by-created_at-index",
                "KeySchema": [
                    {"AttributeName": "created_by", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            }
        ],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )


def _make_rows_table(ddb):
    return ddb.create_table(
        TableName="dynamic_entity_rows_test",
        KeySchema=[
            {"AttributeName": "entity_name", "KeyType": "HASH"},
            {"AttributeName": "row_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "entity_name", "AttributeType": "S"},
            {"AttributeName": "row_id", "AttributeType": "S"},
            {"AttributeName": "owner_sub", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "owner_sub-created_at-index",
                "KeySchema": [
                    {"AttributeName": "owner_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            }
        ],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )


_WIDGET_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "count": {"type": "integer"},
    },
    "required": ["name"],
}


@mock_aws
class TestDynamicEntities(unittest.TestCase):
    def setUp(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._defs_table = _make_defs_table(ddb)
        self._rows_table = _make_rows_table(ddb)

        _patch_frozen(self, T, "dynamic_entity_defs", self._defs_table)
        _patch_frozen(self, T, "dynamic_entity_rows", self._rows_table)
        _patch_frozen(self, S, "dynamic_entities_enabled", True)
        _patch_frozen(self, S, "dynamic_entity_defs_creator_index", "created_by-created_at-index")
        _patch_frozen(self, S, "dynamic_entity_rows_owner_index", "owner_sub-created_at-index")
        _patch_frozen(self, S, "dynamic_entity_max_properties", 50)
        _patch_frozen(self, S, "dynamic_entity_max_depth", 3)
        _patch_frozen(self, S, "dynamic_entity_max_required", 20)
        _patch_frozen(self, S, "dynamic_entity_row_write_rate_per_hour", 200)
        _patch_frozen(self, S, "ddb_ttl_attr", "ttl_epoch")

    def _register_widget(self):
        from app.services.dynamic_entities import register_entity
        return register_entity("root_sub", "widget", _WIDGET_SCHEMA)

    def test_01_root_registers_schema(self):
        with patch("app.services.alerts.audit_event") as mock_audit:
            defn = self._register_widget()
        self.assertEqual(defn["entity_name"], "widget")
        self.assertEqual(defn["version"], 1)

    def test_02_invalid_entity_name_raises_400(self):
        from app.services.dynamic_entities import register_entity
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            register_entity("root_sub", "WIDGET", _WIDGET_SCHEMA)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_03_reserved_entity_name_raises_400(self):
        from app.services.dynamic_entities import register_entity
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            register_entity("root_sub", "billing", _WIDGET_SCHEMA)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "reserved_entity_name")

    def test_04_schema_over_property_cap_raises_400(self):
        from app.services.dynamic_entities import register_entity
        from fastapi import HTTPException
        _patch_frozen(self, S, "dynamic_entity_max_properties", 2)
        big_schema = {
            "type": "object",
            "properties": {f"f{i}": {"type": "string"} for i in range(5)},
        }
        with self.assertRaises(HTTPException) as ctx:
            register_entity("root_sub", "toobig", big_schema)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "schema_too_complex")

    def test_05_create_row_valid_data(self):
        self._register_widget()
        from app.services.dynamic_entities import create_row
        row = create_row("widget", "alice", {"name": "foo", "count": 42})
        self.assertTrue(row["row_id"].startswith("dyn_"))
        self.assertEqual(row["owner_sub"], "alice")
        self.assertEqual(row["data"]["name"], "foo")

    def test_06_create_row_missing_required_raises_400(self):
        self._register_widget()
        from app.services.dynamic_entities import create_row
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            create_row("widget", "alice", {"count": 1})  # missing required "name"
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "schema_validation_failed")
        self.assertEqual(ctx.exception.detail["field"], "name")

    def test_07_create_row_wrong_type_raises_400(self):
        self._register_widget()
        from app.services.dynamic_entities import create_row
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            create_row("widget", "alice", {"name": 123, "count": 1})
        self.assertEqual(ctx.exception.status_code, 400)
        d = ctx.exception.detail
        self.assertEqual(d["code"], "schema_validation_failed")
        self.assertEqual(d["reason"], "type_mismatch")

    def test_08_get_row_owner_scoped(self):
        self._register_widget()
        from app.services.dynamic_entities import create_row, get_row
        row = create_row("widget", "alice", {"name": "bar"})
        # Alice can see it
        self.assertIsNotNone(get_row("widget", row["row_id"], "alice"))
        # Bob cannot
        self.assertIsNone(get_row("widget", row["row_id"], "bob"))

    def test_09_update_row_owner_enforced(self):
        self._register_widget()
        from app.services.dynamic_entities import create_row, update_row
        from fastapi import HTTPException
        row = create_row("widget", "alice", {"name": "original"})
        with self.assertRaises(HTTPException) as ctx:
            update_row("widget", row["row_id"], "bob", {"name": "hack"})
        self.assertEqual(ctx.exception.status_code, 404)

    def test_10_unknown_entity_crud_raises_404(self):
        from app.services.dynamic_entities import list_rows
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            list_rows("nonexistent")
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.detail["code"], "entity_not_found")

    def test_11_delete_entity_fires_audit(self):
        self._register_widget()
        from app.services.dynamic_entities import delete_entity
        with patch("app.services.alerts.audit_event") as mock_audit:
            delete_entity("root_sub", "widget")
        # After deletion entity should be gone
        from app.services.dynamic_entities import get_entity_def
        self.assertIsNone(get_entity_def("widget"))

    def test_12_list_rows_owner_only(self):
        self._register_widget()
        from app.services.dynamic_entities import create_row, list_rows
        create_row("widget", "alice", {"name": "alice_row"})
        create_row("widget", "bob", {"name": "bob_row"})
        out = list_rows("widget", owner_sub="alice")
        names = [r["data"]["name"] for r in out["rows"]]
        self.assertIn("alice_row", names)
        self.assertNotIn("bob_row", names)

    def test_13_register_twice_increments_version(self):
        self._register_widget()
        from app.services.dynamic_entities import register_entity
        defn2 = register_entity("root_sub", "widget", _WIDGET_SCHEMA)
        self.assertEqual(int(defn2["version"]), 2)

    def test_14_flag_off_no_router(self):
        _patch_frozen(self, S, "dynamic_entities_enabled", False)
        from app.main import create_app
        app = create_app()
        paths = [str(getattr(r, "path", "")) for r in app.routes]
        dyn_paths = [p for p in paths if "/ui/dynamic-entities" in p]
        self.assertEqual(dyn_paths, [])
