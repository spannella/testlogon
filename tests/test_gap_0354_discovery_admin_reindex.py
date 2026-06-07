"""Offline regression tests for GAP-0354 (SOC-003).

GAP-0354 — ``POST /ui/discover/reindex`` only reindexes the CALLER (self). There
was no admin/root bulk reindex and no ``reindex_all_users`` function anywhere.

The fix adds:
  * ``app.services.discovery.reindex_all_users()`` — iterates ALL users in the
    users table (paginating via ``LastEvaluatedKey``) and calls the existing
    ``index_user_for_discovery(user_sub)`` for each, best-effort per user.
  * ``POST /ui/discover/admin/reindex-all`` — admin/root-gated endpoint backed by
    ``reindex_all_users()``.

Fully offline: real in-memory DynamoDB tables via moto. The frozen ``T`` table
handles (``T.users``, ``T.profile``, ``T.account_state``) and the module-level
``discovery.tbl_discovery`` handle are rebound to the moto tables via
``object.__setattr__`` and restored on cleanup. The async route handlers are
called directly with a fake auth context (the FastAPI TestClient is unusable in
this repo).
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_users_table(ddb):
    return ddb.create_table(
        TableName="users",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_profile_table(ddb):
    return ddb.create_table(
        TableName="profiles",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_account_state_table(ddb):
    return ddb.create_table(
        TableName="account_state",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_discovery_table(ddb):
    return ddb.create_table(
        TableName="DiscoveryIndex",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestReindexAllUsersGap0354(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        self.users = _make_users_table(ddb)
        self.profile = _make_profile_table(ddb)
        self.account_state = _make_account_state_table(ddb)
        self.discovery_tbl = _make_discovery_table(ddb)

        from app.core.tables import T
        from app.services import discovery as discovery_svc

        self.T = T
        self.discovery_svc = discovery_svc

        # Rebind frozen T handles to moto tables; restore on cleanup.
        for attr, tbl in (
            ("users", self.users),
            ("profile", self.profile),
            ("account_state", self.account_state),
        ):
            old = getattr(T, attr)
            object.__setattr__(T, attr, tbl)
            self.addCleanup(lambda a=attr, o=old: object.__setattr__(T, a, o))

        # Rebind module-level discovery index handle.
        old_disc = discovery_svc.tbl_discovery
        discovery_svc.tbl_discovery = self.discovery_tbl
        self.addCleanup(
            lambda: setattr(discovery_svc, "tbl_discovery", old_disc)
        )

    def _seed_user(self, user_sub: str, display_name: str):
        self.users.put_item(Item={"user_sub": user_sub})
        self.profile.put_item(
            Item={
                "user_sub": user_sub,
                "profile": {"display_name": display_name},
            }
        )

    def test_reindex_all_iterates_every_user(self):
        """reindex_all_users indexes every seeded user (none truncated)."""
        names = {f"user_{i:03d}": f"Display Name {i}" for i in range(7)}
        for sub, name in names.items():
            self._seed_user(sub, name)

        summary = self.discovery_svc.reindex_all_users()

        self.assertEqual(summary["seen"], 7)
        self.assertEqual(summary["reindexed"], 7)
        self.assertEqual(summary["failed"], 0)

        # Discovery index now has TOKEN# rows for each user.
        scan = self.discovery_tbl.scan()
        indexed_subs = {it["user_id"] for it in scan["Items"]}
        self.assertEqual(indexed_subs, set(names.keys()))

    def test_reindex_all_calls_index_per_user(self):
        """Spy: index_user_for_discovery called exactly once per user."""
        from unittest.mock import patch

        for i in range(4):
            self._seed_user(f"u_{i}", f"Name {i}")

        with patch.object(
            self.discovery_svc,
            "index_user_for_discovery",
            wraps=self.discovery_svc.index_user_for_discovery,
        ) as spy:
            summary = self.discovery_svc.reindex_all_users()

        called = {c.args[0] for c in spy.call_args_list}
        self.assertEqual(called, {f"u_{i}" for i in range(4)})
        self.assertEqual(spy.call_count, 4)
        self.assertEqual(summary["seen"], 4)

    def test_reindex_all_best_effort_on_failure(self):
        """One user's failure is skipped, not fatal to the whole sweep."""
        from unittest.mock import patch

        for i in range(3):
            self._seed_user(f"f_{i}", f"FName {i}")

        real = self.discovery_svc.index_user_for_discovery

        def flaky(user_sub):
            if user_sub == "f_1":
                raise RuntimeError("boom")
            return real(user_sub)

        with patch.object(self.discovery_svc, "index_user_for_discovery", side_effect=flaky):
            summary = self.discovery_svc.reindex_all_users()

        self.assertEqual(summary["seen"], 3)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["reindexed"], 2)

    def test_reindex_all_paginates_beyond_one_scan_page(self):
        """LastEvaluatedKey is followed: all users across pages are indexed.

        moto returns up to 1MB per scan page; we force pagination by patching the
        bound users-table scan to return a single item per page so the loop must
        follow LastEvaluatedKey.
        """
        from unittest.mock import patch

        for i in range(5):
            self._seed_user(f"p_{i}", f"PName {i}")

        real_scan = self.users.scan
        all_items = self.users.scan()["Items"]

        def paged_scan(**kwargs):
            start = 0
            eks = kwargs.get("ExclusiveStartKey")
            if eks:
                for idx, it in enumerate(all_items):
                    if it["user_sub"] == eks["user_sub"]:
                        start = idx + 1
                        break
            page = all_items[start : start + 1]
            out = {"Items": page}
            if start + 1 < len(all_items):
                out["LastEvaluatedKey"] = {"user_sub": page[0]["user_sub"]}
            return out

        with patch.object(self.users, "scan", side_effect=paged_scan):
            summary = self.discovery_svc.reindex_all_users()

        self.assertEqual(summary["seen"], 5)
        self.assertEqual(summary["reindexed"], 5)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestAdminReindexEndpointGap0354(unittest.TestCase):
    def test_endpoint_gated_by_require_admin_or_root(self):
        """The /admin/reindex-all route uses the require_admin_or_root dep."""
        from app.routers import discovery as discovery_router
        from app.auth.policy import require_admin_or_root

        route = next(
            r
            for r in discovery_router.router.routes
            if getattr(r, "path", "") == "/ui/discover/admin/reindex-all"
        )
        self.assertIn("POST", route.methods)
        # Walk the dependant tree; require_admin_or_root should appear in it.
        all_deps = []

        def collect(dependant):
            all_deps.append(dependant.call)
            for sub in dependant.dependencies:
                collect(sub)

        collect(route.dependant)
        self.assertIn(require_admin_or_root, all_deps)

    def test_non_admin_ctx_rejected(self):
        """A non-admin context is rejected by require_admin_or_root (403)."""
        from fastapi import HTTPException

        from app.auth.policy import require_admin_or_root
        from app.auth.deps import AuthenticatedUser
        from app.auth.roles import Role

        ctx = AuthenticatedUser(sub="plain_user", role=Role.USER)
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(require_admin_or_root(user=ctx))
        self.assertEqual(cm.exception.status_code, 403)

    def test_admin_ctx_runs_and_returns_count(self):
        """An admin context passes the gate and the handler returns the summary."""
        from contextlib import ExitStack

        from app.auth.deps import AuthenticatedUser
        from app.auth.policy import require_admin_or_root
        from app.auth.roles import Role
        from app.routers import discovery as discovery_router

        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        users = _make_users_table(ddb)
        profile = _make_profile_table(ddb)
        account_state = _make_account_state_table(ddb)
        disc = _make_discovery_table(ddb)

        from app.core.tables import T
        from app.services import discovery as discovery_svc

        for attr, tbl in (
            ("users", users),
            ("profile", profile),
            ("account_state", account_state),
        ):
            old = getattr(T, attr)
            object.__setattr__(T, attr, tbl)
            self.addCleanup(lambda a=attr, o=old: object.__setattr__(T, a, o))
        old_disc = discovery_svc.tbl_discovery
        discovery_svc.tbl_discovery = disc
        self.addCleanup(lambda: setattr(discovery_svc, "tbl_discovery", old_disc))

        for i in range(3):
            users.put_item(Item={"user_sub": f"a_{i}"})
            profile.put_item(
                Item={"user_sub": f"a_{i}", "profile": {"display_name": f"Admin Seed {i}"}}
            )

        # Admin passes the gate.
        admin_ctx = AuthenticatedUser(sub="admin_sub", role=Role.ADMIN)
        gated = asyncio.run(require_admin_or_root(user=admin_ctx))
        self.assertEqual(gated.sub, "admin_sub")

        result = asyncio.run(discovery_router.discover_reindex_all(user=gated))
        self.assertTrue(result["ok"])
        self.assertEqual(result["seen"], 3)
        self.assertEqual(result["reindexed"], 3)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
