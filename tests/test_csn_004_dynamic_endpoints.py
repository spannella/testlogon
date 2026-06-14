"""CSN-004: Dynamic Endpoints hermetic tests.

Offline, no real AWS. moto in-memory DynamoDB tables bound to frozen T.*.
"""
from __future__ import annotations

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


def _make_endpoints_table(ddb):
    return ddb.create_table(
        TableName="dynamic_endpoints_test",
        KeySchema=[
            {"AttributeName": "endpoint_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "endpoint_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "method_path", "AttributeType": "S"},
            {"AttributeName": "created_by", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "method_path-sk-index",
                "KeySchema": [
                    {"AttributeName": "method_path", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            },
            {
                "IndexName": "created_by-created_at-index",
                "KeySchema": [
                    {"AttributeName": "created_by", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            },
        ],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )


def _make_defs_table(ddb):
    return ddb.create_table(
        TableName="dyn_ent_defs_ep_test",
        KeySchema=[
            {"AttributeName": "entity_name", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "entity_name", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_rows_table(ddb):
    return ddb.create_table(
        TableName="dyn_ent_rows_ep_test",
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
                "IndexName": "owner_sub-created_at-index-ep",
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


def _make_sessions_table(ddb, name="sessions_ep_test"):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "session_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "session_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@mock_aws
class TestDynamicEndpoints(unittest.TestCase):
    def setUp(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._ep_table = _make_endpoints_table(ddb)
        self._defs_table = _make_defs_table(ddb)
        self._rows_table = _make_rows_table(ddb)
        self._sessions_table = _make_sessions_table(ddb)

        _patch_frozen(self, T, "dynamic_endpoints", self._ep_table)
        _patch_frozen(self, T, "dynamic_entity_defs", self._defs_table)
        _patch_frozen(self, T, "dynamic_entity_rows", self._rows_table)
        _patch_frozen(self, T, "sessions", self._sessions_table)
        _patch_frozen(self, S, "dynamic_endpoints_enabled", True)
        _patch_frozen(self, S, "dynamic_entities_enabled", True)
        _patch_frozen(self, S, "dynamic_endpoints_method_path_index", "method_path-sk-index")
        _patch_frozen(self, S, "dynamic_endpoints_created_by_index", "created_by-created_at-index")
        _patch_frozen(self, S, "dynamic_endpoints_invoke_rate_per_hour", 1000)
        _patch_frozen(self, S, "dynamic_entity_defs_creator_index", "created_by-created_at-index")
        _patch_frozen(self, S, "dynamic_entity_rows_owner_index", "owner_sub-created_at-index-ep")
        _patch_frozen(self, S, "dynamic_entity_max_properties", 50)
        _patch_frozen(self, S, "dynamic_entity_max_depth", 3)
        _patch_frozen(self, S, "dynamic_entity_max_required", 20)
        _patch_frozen(self, S, "dynamic_entity_row_write_rate_per_hour", 200)
        _patch_frozen(self, S, "ddb_ttl_attr", "ttl_epoch")
        _patch_frozen(self, S, "ddb_sessions_table", "sessions_ep_test")

    def _register_static(self, path="/custom/hello", method="GET",
                         body=None, status=200):
        from app.services.dynamic_endpoints import register_endpoint
        cfg = {"status": status, "body": body or {"msg": "hi"}}
        return register_endpoint("root_sub", method, path, "static_response", cfg)

    def test_01_register_static_response(self):
        ep = self._register_static()
        self.assertTrue(ep["endpoint_id"].startswith("dye_"))
        self.assertEqual(ep["method"], "GET")
        self.assertEqual(ep["path"], "/custom/hello")

    def test_02_invoke_static_response(self):
        ep = self._register_static()
        from app.services.dynamic_endpoints import invoke_endpoint
        resp = invoke_endpoint(ep, "GET", "/custom/hello", "alice", None, {})
        self.assertEqual(resp.status_code, 200)

    def test_03_path_not_under_custom_raises_400(self):
        from app.services.dynamic_endpoints import register_endpoint
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            register_endpoint("root_sub", "GET", "/ui/billing", "static_response",
                              {"status": 200, "body": {}})
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "invalid_path_prefix")

    def test_04_invalid_path_chars_raises_400(self):
        from app.services.dynamic_endpoints import register_endpoint
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            register_endpoint("root_sub", "GET", "/custom/<script>", "static_response",
                              {"status": 200, "body": {}})
        self.assertEqual(ctx.exception.status_code, 400)

    def test_05_unknown_connector_kind_raises_400(self):
        from app.services.dynamic_endpoints import register_endpoint
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            register_endpoint("root_sub", "GET", "/custom/test", "execute_code", {})
        self.assertEqual(ctx.exception.status_code, 400)

    def test_06_missing_connector_config_raises_400(self):
        from app.services.dynamic_endpoints import register_endpoint
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            register_endpoint("root_sub", "GET", "/custom/bad", "static_response", {})
        self.assertEqual(ctx.exception.status_code, 400)

    def test_07_duplicate_method_path_raises_409(self):
        self._register_static()
        from app.services.dynamic_endpoints import register_endpoint
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            register_endpoint("root_sub", "GET", "/custom/hello", "static_response",
                              {"status": 200, "body": {}})
        self.assertEqual(ctx.exception.status_code, 409)

    def test_08_unregistered_path_raises_404(self):
        from app.services.dynamic_endpoints import get_endpoint, invoke_endpoint
        from fastapi import HTTPException
        ep = get_endpoint("GET", "/custom/unknown")
        self.assertIsNone(ep)

    def test_09_incompatible_method_op_raises_400(self):
        # Register a widget entity first
        self._defs_table.put_item(Item={
            "entity_name": "widget", "sk": "DEF",
            "json_schema": {"type": "object", "properties": {}},
            "version": 1, "created_by": "root", "created_at": 1, "updated_at": 1,
        })
        from app.services.dynamic_endpoints import register_endpoint
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            register_endpoint("root_sub", "GET", "/custom/widgs", "dynamic_entity_proxy",
                              {"entity_name": "widget", "op": "create"})
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail["code"], "incompatible_method_op")

    def test_10_delete_endpoint_fires_audit(self):
        ep = self._register_static()
        from app.services.dynamic_endpoints import delete_endpoint, get_endpoint_by_id
        with patch("app.services.alerts.audit_event") as mock_audit:
            delete_endpoint("root_sub", ep["endpoint_id"])
        self.assertIsNone(get_endpoint_by_id(ep["endpoint_id"]))

    def test_11_dynamic_entity_proxy_list(self):
        """dynamic_entity_proxy list op returns entity rows."""
        # Register entity
        self._defs_table.put_item(Item={
            "entity_name": "widget", "sk": "DEF",
            "json_schema": {"type": "object", "properties": {"name": {"type": "string"}}},
            "version": 1, "created_by": "root", "created_at": 1, "updated_at": 1,
        })
        # Create a row directly
        from app.core.time import now_ts
        self._rows_table.put_item(Item={
            "entity_name": "widget", "row_id": "dyn_abc",
            "owner_sub": "alice", "data": {"name": "test"},
            "created_at": now_ts(), "updated_at": now_ts(),
        })
        # Register dynamic_entity_proxy endpoint
        from app.services.dynamic_endpoints import register_endpoint, invoke_endpoint
        ep = register_endpoint("root_sub", "GET", "/custom/widgets", "dynamic_entity_proxy",
                               {"entity_name": "widget", "op": "list"})
        resp = invoke_endpoint(ep, "GET", "/custom/widgets", "alice", None, {})
        self.assertEqual(resp.status_code, 200)

    def test_12_flag_off_no_router(self):
        _patch_frozen(self, S, "dynamic_endpoints_enabled", False)
        from app.main import create_app
        app = create_app()
        paths = [str(getattr(r, "path", "")) for r in app.routes]
        ep_paths = [p for p in paths if "/ui/dynamic-endpoints" in p]
        self.assertEqual(ep_paths, [])

    def test_13_rate_limit_invocation(self):
        """Rate limit fires on gateway invocations above cap."""
        ep = self._register_static()
        from app.services.dynamic_endpoints import invoke_endpoint
        from fastapi import HTTPException
        _patch_frozen(self, S, "dynamic_endpoints_invoke_rate_per_hour", 2)
        invoke_endpoint(ep, "GET", "/custom/hello", "alice", None, {})
        invoke_endpoint(ep, "GET", "/custom/hello", "alice", None, {})
        with self.assertRaises(HTTPException) as ctx:
            invoke_endpoint(ep, "GET", "/custom/hello", "alice", None, {})
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.detail["code"], "dynamic_endpoint_rate_limited")
