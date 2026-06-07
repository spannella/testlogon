"""Offline regression test for GAP-0346.

GAP-0346 — ``rootctl`` shipped ``user deactivate`` and ``user delete`` but had no
reversal commands. There was no audited CLI path to restore a ``deactivated``
account back to ``active`` (``user reactivate``) nor to restore a *soft*-deleted
account whose ``account_state.status`` is ``"deleted"`` (``user undelete``). The
fix adds both handlers + sub-parsers in ``app/cli/rootctl.py``.

This test drives the new handler functions directly (the rootctl handlers take a
single ``argparse.Namespace``), mirroring the table-isolation approach of
``tests/test_gap_0176_0177_org_service.py``: real in-memory DynamoDB tables are
created with moto and bound onto the FROZEN ``app.core.tables.T`` handles via
``object.__setattr__`` (restored on cleanup). ``audit_event`` is patched in the
rootctl namespace to capture emitted events without touching alert plumbing.

Fully offline — no real AWS, no live DynamoDB, no FastAPI client.
"""
from __future__ import annotations

import argparse
import unittest
from contextlib import ExitStack
from unittest.mock import patch

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


def _make_account_state_table(ddb):
    return ddb.create_table(
        TableName="account_state",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


ROOT_SUB = "root.admin@testdev.local"
TARGET = "alice@test.local"


def _args(command: str, **overrides) -> argparse.Namespace:
    base = dict(
        group="user",
        command=command,
        root_sub=ROOT_SUB,
        actor_sub=ROOT_SUB,
        target_user_sub=TARGET,
        reason="test reason",
        ticket="T-001",
        confirm="",
        output="json",
        dry_run=False,
        request_id="req-1",
        correlation_id="corr-1",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestUserReactivateUndelete(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.users = _make_users_table(ddb)
        self.account_state = _make_account_state_table(ddb)

        from app.cli import rootctl
        from app.core.tables import T

        self.rootctl = rootctl
        self.T = T

        # Bind moto tables onto the FROZEN T handles, restore on cleanup.
        for name, table in (("users", self.users), ("account_state", self.account_state)):
            original = getattr(T, name)
            object.__setattr__(T, name, table)
            self.addCleanup(object.__setattr__, T, name, original)

        # Capture audit events without exercising the alert plumbing.
        self.audit_calls = []

        def _capture_audit(event, user_sub, request=None, **fields):
            self.audit_calls.append({"event": event, "user_sub": user_sub, **fields})

        self.stack.enter_context(
            patch.object(rootctl, "audit_event", _capture_audit)
        )

    def _seed_user(self, status: str, *, user_exists: bool = True):
        if user_exists:
            self.users.put_item(Item={"user_sub": TARGET, "email": TARGET, "role": "user"})
        self.account_state.put_item(
            Item={"user_sub": TARGET, "status": status, "updated_at": 1}
        )

    def _state(self):
        return self.account_state.get_item(Key={"user_sub": TARGET}).get("Item") or {}

    # ----- reactivate ------------------------------------------------------

    def test_reactivate_restores_deactivated_to_active(self):
        self._seed_user("deactivated")
        result = self.rootctl._user_reactivate_command(_args("reactivate"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["new_status"], "active")
        self.assertEqual(result["previous_status"], "deactivated")
        self.assertEqual(self._state()["status"], "active")
        # audit emitted
        self.assertEqual(
            [c["event"] for c in self.audit_calls], ["user_reactivated_cli"]
        )
        # T.users carries reactivation audit metadata
        user = self.users.get_item(Key={"user_sub": TARGET}).get("Item")
        self.assertEqual(user["reactivated_by"], ROOT_SUB)
        self.assertEqual(user["reactivation_ticket"], "T-001")

    def test_reactivate_rejects_already_active(self):
        self._seed_user("active")
        with self.assertRaises(self.rootctl.CliPolicyError) as ctx:
            self.rootctl._user_reactivate_command(_args("reactivate"))
        self.assertEqual(ctx.exception.details.get("code"), "invalid_state_transition")
        # unchanged + no audit
        self.assertEqual(self._state()["status"], "active")
        self.assertEqual(self.audit_calls, [])

    def test_reactivate_rejects_soft_deleted(self):
        self._seed_user("deleted")
        with self.assertRaises(self.rootctl.CliPolicyError):
            self.rootctl._user_reactivate_command(_args("reactivate"))
        self.assertEqual(self._state()["status"], "deleted")

    def test_reactivate_dry_run_does_not_write(self):
        self._seed_user("deactivated")
        result = self.rootctl._user_reactivate_command(_args("reactivate", dry_run=True))
        self.assertTrue(result["dry_run"])
        self.assertEqual(self._state()["status"], "deactivated")
        self.assertEqual(self.audit_calls, [])

    # ----- undelete --------------------------------------------------------

    def test_undelete_restores_soft_deleted_to_active(self):
        self._seed_user("deleted")
        result = self.rootctl._user_undelete_command(_args("undelete"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["new_status"], "active")
        self.assertEqual(result["previous_status"], "deleted")
        self.assertEqual(self._state()["status"], "active")
        self.assertEqual(
            [c["event"] for c in self.audit_calls], ["user_undeleted_cli"]
        )
        user = self.users.get_item(Key={"user_sub": TARGET}).get("Item")
        self.assertEqual(user["undeleted_by"], ROOT_SUB)

    def test_undelete_rejects_hard_deleted_no_user_record(self):
        # Hard delete removes the T.users record (and account_state). Simulate
        # that: no users row, no account_state row.
        # (Nothing seeded.)
        with self.assertRaises(ValueError) as ctx:
            self.rootctl._user_undelete_command(_args("undelete"))
        self.assertIn("not found", str(ctx.exception).lower())
        self.assertEqual(self.audit_calls, [])

    def test_undelete_rejects_active_account(self):
        self._seed_user("active")
        with self.assertRaises(self.rootctl.CliPolicyError) as ctx:
            self.rootctl._user_undelete_command(_args("undelete"))
        self.assertEqual(ctx.exception.details.get("code"), "invalid_state_transition")
        self.assertEqual(self._state()["status"], "active")

    def test_undelete_dry_run_does_not_write(self):
        self._seed_user("deleted")
        result = self.rootctl._user_undelete_command(_args("undelete", dry_run=True))
        self.assertTrue(result["dry_run"])
        self.assertEqual(self._state()["status"], "deleted")
        self.assertEqual(self.audit_calls, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
