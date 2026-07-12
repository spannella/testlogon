"""CSN-005: Open Data (Branches + ATMs) hermetic tests.

Offline, no real AWS. moto in-memory DynamoDB bound to frozen T.open_data.
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


def _make_open_data_table(ddb):
    return ddb.create_table(
        TableName="open_data_test",
        KeySchema=[
            {"AttributeName": "kind", "KeyType": "HASH"},
            {"AttributeName": "resource_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "kind", "AttributeType": "S"},
            {"AttributeName": "resource_id", "AttributeType": "S"},
            {"AttributeName": "kind_active", "AttributeType": "S"},
            {"AttributeName": "name", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByActive",
                "KeySchema": [
                    {"AttributeName": "kind_active", "KeyType": "HASH"},
                    {"AttributeName": "name", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            }
        ],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )


def _make_branch_in(**kwargs):
    from app.models import BranchIn, LocationIn, OpenDataAddressIn
    defaults = dict(
        name="Test Branch",
        address=OpenDataAddressIn(line1="1 Main St", city="Springfield", country="US", postcode="12345"),
        location=LocationIn(lat=40.0, lng=-74.0),
        is_active=True,
    )
    defaults.update(kwargs)
    return BranchIn(**defaults)


def _make_atm_in(**kwargs):
    from app.models import AtmIn, LocationIn, OpenDataAddressIn
    defaults = dict(
        name="Test ATM",
        address=OpenDataAddressIn(line1="2 Bank St", city="Springfield", country="US", postcode="12345"),
        location=LocationIn(lat=40.1, lng=-74.1),
        is_active=True,
        has_deposit=False,
        is_accessible=True,
    )
    defaults.update(kwargs)
    return AtmIn(**defaults)


@mock_aws
class TestOpenData(unittest.TestCase):
    def setUp(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._table = _make_open_data_table(ddb)

        _patch_frozen(self, T, "open_data", self._table)
        _patch_frozen(self, S, "open_data_enabled", True)
        _patch_frozen(self, S, "open_data_active_index", "ByActive")
        _patch_frozen(self, S, "open_data_list_max_limit", 200)
        _patch_frozen(self, S, "ddb_ttl_attr", "ttl_epoch")

    def test_01_upsert_branch_creates_record(self):
        from app.services.open_data import get_branch, upsert_branch
        result = upsert_branch("root", _make_branch_in())
        self.assertIsNotNone(result["branch_id"])
        self.assertTrue(result["branch_id"].startswith("brn_"))
        fetched = get_branch(result["branch_id"])
        self.assertEqual(fetched["name"], "Test Branch")

    def test_02_upsert_atm_creates_record(self):
        from app.services.open_data import get_atm, upsert_atm
        result = upsert_atm("root", _make_atm_in())
        self.assertTrue(result["atm_id"].startswith("atm_"))
        fetched = get_atm(result["atm_id"])
        self.assertTrue(fetched["is_accessible"])
        self.assertFalse(fetched["has_deposit"])

    def test_03_list_branches_active_only(self):
        from app.services.open_data import list_branches, upsert_branch
        upsert_branch("root", _make_branch_in(is_active=True, name="Active"))
        upsert_branch("root", _make_branch_in(is_active=False, name="Inactive"))
        items, cursor = list_branches(active_only=True)
        names = [i["name"] for i in items]
        self.assertIn("Active", names)
        self.assertNotIn("Inactive", names)

    def test_04_list_atms_active_only(self):
        from app.services.open_data import list_atms, upsert_atm
        upsert_atm("root", _make_atm_in(is_active=True, name="ATM Active"))
        upsert_atm("root", _make_atm_in(is_active=False, name="ATM Inactive"))
        items, cursor = list_atms(active_only=True)
        names = [i["name"] for i in items]
        self.assertIn("ATM Active", names)
        self.assertNotIn("ATM Inactive", names)

    def test_05_admin_list_all_branches(self):
        from app.services.open_data import list_branches, upsert_branch
        upsert_branch("root", _make_branch_in(is_active=True, name="Active"))
        upsert_branch("root", _make_branch_in(is_active=False, name="Inactive"))
        items, _ = list_branches(active_only=False)
        names = [i["name"] for i in items]
        self.assertIn("Active", names)
        self.assertIn("Inactive", names)

    def test_06_public_get_inactive_branch_returns_none(self):
        from app.services.open_data import get_branch, upsert_branch
        result = upsert_branch("root", _make_branch_in(is_active=False))
        item = get_branch(result["branch_id"])
        self.assertFalse(item["is_active"])
        # Public read should 404 for inactive — tested at service level
        from app.routers.open_data import public_get_branch
        import asyncio
        loop = asyncio.new_event_loop()
        from fastapi import HTTPException
        try:
            try:
                loop.run_until_complete(public_get_branch(result["branch_id"]))
                self.fail("Should have raised 404")
            except HTTPException as e:
                self.assertEqual(e.status_code, 404)
        finally:
            loop.close()

    def test_07_delete_resource_removes_item(self):
        from app.services.open_data import delete_resource, get_branch, upsert_branch
        result = upsert_branch("root", _make_branch_in())
        delete_resource("BRANCH", result["branch_id"], "root")
        self.assertIsNone(get_branch(result["branch_id"]))

    def test_08_delete_idempotent(self):
        from app.services.open_data import delete_resource, upsert_branch
        result = upsert_branch("root", _make_branch_in())
        delete_resource("BRANCH", result["branch_id"], "root")
        # Second call should not raise
        delete_resource("BRANCH", result["branch_id"], "root")

    def test_09_invalid_country_raises_422(self):
        from app.models import OpenDataAddressIn
        with self.assertRaises(Exception):
            OpenDataAddressIn(line1="x", city="y", country="USA", postcode="z")

    def test_10_invalid_lat_raises_422(self):
        from app.models import LocationIn
        with self.assertRaises(Exception):
            LocationIn(lat=200, lng=0)

    def test_11_upsert_branch_fires_audit(self):
        from app.services.open_data import upsert_branch
        with patch("app.services.alerts.audit_event") as mock_audit:
            upsert_branch("root", _make_branch_in())
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args
        self.assertEqual(call_args[0][0], "open_data.branch_upsert")

    def test_12_delete_resource_fires_audit(self):
        from app.services.open_data import delete_resource, upsert_branch
        result = upsert_branch("root", _make_branch_in())
        with patch("app.services.alerts.audit_event") as mock_audit:
            delete_resource("BRANCH", result["branch_id"], "root")
        mock_audit.assert_called_once()
        self.assertEqual(mock_audit.call_args[0][0], "open_data.delete")

    def test_13_public_routes_in_exemptions(self):
        from app.services.api_key_route_scope_registry import API_KEY_ROUTE_EXEMPTIONS
        required = [
            "GET:/open-data/branches",
            "GET:/open-data/branches/{branch_id}",
            "GET:/open-data/atms",
            "GET:/open-data/atms/{atm_id}",
        ]
        for route_id in required:
            self.assertIn(route_id, API_KEY_ROUTE_EXEMPTIONS,
                          f"{route_id} missing from API_KEY_ROUTE_EXEMPTIONS")

    def test_14_flag_off_no_router(self):
        _patch_frozen(self, S, "open_data_enabled", False)
        from app.main import create_app
        app = create_app()
        paths = [str(getattr(r, "path", "")) for r in app.routes]
        od_paths = [p for p in paths if "/open-data" in p]
        self.assertEqual(od_paths, [])

    def test_15_kind_is_system_set_branch(self):
        """kind is always "BRANCH" regardless of what caller might try to inject."""
        from app.services.open_data import upsert_branch
        result = upsert_branch("root", _make_branch_in())
        # Check raw DDB item
        item = self._table.get_item(
            Key={"kind": "BRANCH", "resource_id": result["branch_id"]}
        ).get("Item")
        self.assertIsNotNone(item)
        self.assertEqual(item["kind"], "BRANCH")

    def test_16_opening_hours_invalid_time_raises(self):
        from app.models import OpeningHours
        with self.assertRaises(Exception):
            OpeningHours(day="Mon", opens="17:00", closes="09:00")  # opens >= closes
