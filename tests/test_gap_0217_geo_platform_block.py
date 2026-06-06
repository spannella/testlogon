"""Offline regression test for GAP-0217 (GEO-001).

The platform-level country block list (``geo_platform_block_countries``) used to
live *only* in an environment variable read once at process startup
(``app/services/geo_check.py``). There was no runtime mutation path: changing the
block list required a full backend redeployment, which fails the "block within
minutes" compliance SLA (OFAC/sanctions updates).

The fix makes the platform block list DynamoDB-backed and hot-reloadable:
``check_geo_access`` now calls ``get_platform_blocked_countries()`` which unions
the env-var value with a single DDB record (pk=PLATFORM, sk=GEO_BLOCK) behind a
short in-process TTL cache. ``set_platform_blocked_countries()`` persists the
list and invalidates the cache so the change is visible without a restart.

Test isolation (per repo rules): a real in-memory DynamoDB table is created with
moto and the *exact handle* used by the service (``app.core.tables.T``) is
patched to a ``SimpleNamespace`` pointing at it — we do NOT rely on global
@mock_aws interception leaking into the real ``T`` handles. The functions are
called directly with a fake ``Request``; no real AWS, no GeoIP, no network.

The settings singleton ``S`` is frozen, so any override uses
``object.__setattr__``.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3
from fastapi import HTTPException

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_geo_rules_table(ddb):
    """Mirror scripts/local-ddb-init.py: pk/sk string keys, no GSI."""
    return ddb.create_table(
        TableName="geo_rules",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _fake_request(*, ip: str = "203.0.113.7", geo_country: str | None = None):
    """Minimal stand-in for starlette.Request: only .headers and .client are read."""
    headers = {}
    if geo_country is not None:
        headers["x-geo-country"] = geo_country
    return SimpleNamespace(
        headers=headers,
        client=SimpleNamespace(host=ip),
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestPlatformBlockDdbBacked(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_geo_rules_table(ddb)

        import app.core.tables as tables_mod
        from app.services import geo_check
        from app.core.settings import S

        self.geo_check = geo_check
        self.S = S

        # Patch the EXACT handle the service imports (`from app.core.tables import T`).
        self.stack.enter_context(
            patch.object(tables_mod, "T", SimpleNamespace(geo_rules=self.table))
        )

        # Settings S is frozen -> object.__setattr__. Enable geo + dev mode (so the
        # X-Geo-Country header is honoured), clear the env-var block list, set a TTL.
        self._set("geo_blocking_enabled", True)
        self._set("dev_mode", True)
        self._set("geo_platform_block_countries", "")
        self._set("geo_platform_block_cache_ttl_seconds", 60)

        # Start each test with a clean cache.
        geo_check.reset_platform_block_cache()
        self.addCleanup(geo_check.reset_platform_block_cache)

    def _set(self, attr, value):
        old = getattr(self.S, attr)
        object.__setattr__(self.S, attr, value)
        self.addCleanup(lambda a=attr, v=old: object.__setattr__(self.S, a, v))

    def test_ddb_block_enforced_without_restart(self):
        """GAP-0217: a country added to the DDB record is blocked after cache reset.

        FAILS BEFORE FIX: check_geo_access read only the env-var (empty here), so a
        viewer from CN was allowed -> returns "CN" with no exception.
        PASSES AFTER FIX: the DDB-backed list is honoured -> HTTPException(403).
        """
        # Before seeding: CN is allowed (returns the resolved country, no raise).
        result = self.geo_check.check_geo_access(_fake_request(geo_country="CN"), None, None)
        self.assertEqual(result, "CN")

        # Operator updates the block list at runtime (no process restart).
        self.geo_check.set_platform_blocked_countries(["cn"], updated_by="root.admin@testdev.local")

        # The write persisted a normalised list.
        item = self.table.get_item(Key={"pk": "PLATFORM", "sk": "GEO_BLOCK"}).get("Item")
        self.assertEqual(item["countries"], ["CN"])
        self.assertEqual(item["updated_by"], "root.admin@testdev.local")

        # set_* invalidated the cache, so the next check sees CN immediately.
        with self.assertRaises(HTTPException) as cm:
            self.geo_check.check_geo_access(_fake_request(geo_country="CN"), None, None)
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.detail["code"], "geo_blocked")
        self.assertEqual(cm.exception.detail["country"], "CN")

        # A non-blocked country still passes.
        self.assertEqual(
            self.geo_check.check_geo_access(_fake_request(geo_country="US"), None, None),
            "US",
        )

    def test_env_var_still_honoured_with_empty_ddb(self):
        """Backward compat: env-var block list still applies (unioned with DDB)."""
        self._set("geo_platform_block_countries", "RU")
        self.geo_check.reset_platform_block_cache()

        with self.assertRaises(HTTPException) as cm:
            self.geo_check.check_geo_access(_fake_request(geo_country="RU"), None, None)
        self.assertEqual(cm.exception.status_code, 403)

    def test_env_and_ddb_are_unioned(self):
        """Both sources are blocked simultaneously."""
        self._set("geo_platform_block_countries", "RU")
        self.geo_check.set_platform_blocked_countries(["KP"], updated_by="root")
        self.geo_check.reset_platform_block_cache()

        for blocked in ("RU", "KP"):
            with self.assertRaises(HTTPException):
                self.geo_check.check_geo_access(_fake_request(geo_country=blocked), None, None)

    def test_invalid_country_code_rejected(self):
        """set_* validates ISO alpha-2 codes (400 on garbage)."""
        with self.assertRaises(HTTPException) as cm:
            self.geo_check.set_platform_blocked_countries(["USA"], updated_by="root")
        self.assertEqual(cm.exception.status_code, 400)
        # Nothing was written.
        self.assertIsNone(self.table.get_item(Key={"pk": "PLATFORM", "sk": "GEO_BLOCK"}).get("Item"))

    def test_ddb_read_failure_falls_back_to_env_var(self):
        """Fail-safe: a DDB read error is swallowed; env-var block still enforced."""
        self._set("geo_platform_block_countries", "IR")
        self.geo_check.reset_platform_block_cache()

        # Make the underlying DDB get_item raise; _load_platform_block_from_ddb
        # swallows it and returns an empty set, so only the env-var value remains.
        with patch.object(self.table, "get_item", side_effect=RuntimeError("ddb down")):
            blocked = self.geo_check.get_platform_blocked_countries()
        self.assertEqual(blocked, {"IR"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
