"""Offline regression tests for GAP-0338 and GAP-0339 (PRIVACY-001).

GAP-0338 — ``POST /ui/privacy/export`` ran ``process_export`` *synchronously
inline* inside the request handler (comment "Process inline for MVP"), blocking
the HTTP response on a multi-table query + ZipFile build + S3 upload. A raised
exception left the request stuck at ``status="pending"``. The fix schedules the
export as a background ``asyncio`` task (``_schedule_export`` /
``_run_export_safe``) that returns immediately and flips the request to
``"failed"`` on error.

GAP-0339 — ``process_deletion`` deleted ten table groups but NEVER touched the
messaging tables (Messages / Conversations / Participants), so a user's messages
survived a "full account deletion" (GDPR Art.17 breach). The fix adds Step 11
which, for every conversation the user participates in, deletes the user's
authored messages, deletes the user's Participant row, and removes the
Conversation when no participants remain.

Fully offline / hermetic: a real in-memory DynamoDB (moto) is created and the
EXACT frozen ``T.*`` handles + ``app.core.aws.ddb`` are patched to point at it
via ``object.__setattr__`` (restored on teardown). Async helpers are driven on a
fresh event loop. No real AWS, no network, no FastAPI TestClient (broken here).
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3
import boto3.dynamodb.conditions  # noqa: F401 - used via boto3.dynamodb.conditions.Key

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


# Tables that process_deletion touches via T.* handles (pk/sk schema is enough
# for these — process_deletion only put/get/query/delete by pk + sk).
_PKSK_TABLES = [
    "data_requests",
    "data_request_audit",
    "billing",
    "addresses",
    "contacts",
    "calendar",
    "subscriptions",
    "tickets",
    "video_metadata",
]
# Single-PK tables (profile/account_state are deleted by a single hash key).
_PK_ONLY = {
    "profile": "user_sub",
    "account_state": "user_sub",
}


def _create_pksk(ddb, name, pk="pk", sk="sk"):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": pk, "KeyType": "HASH"},
            {"AttributeName": sk, "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": pk, "AttributeType": "S"},
            {"AttributeName": sk, "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _create_pk_only(ddb, name, pk):
    return ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": pk, "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": pk, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _create_messaging(ddb):
    """Create the Messages / Conversations / Participants tables (string-named).

    Schema mirrors scripts/local-ddb-init.py. The Participants table has no
    by-conversation GSI in this repo, so the "delete empty conversation" check
    in Step 11 is best-effort (it falls back gracefully).
    """
    conv = ddb.create_table(
        TableName="Conversations",
        KeySchema=[{"AttributeName": "conversation_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "conversation_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    part = ddb.create_table(
        TableName="Participants",
        KeySchema=[
            {"AttributeName": "user_id", "KeyType": "HASH"},
            {"AttributeName": "conversation_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "conversation_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    msg = ddb.create_table(
        TableName="Messages",
        KeySchema=[
            {"AttributeName": "conversation_id", "KeyType": "HASH"},
            {"AttributeName": "message_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "conversation_id", "AttributeType": "S"},
            {"AttributeName": "message_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return conv, part, msg


@unittest.skipIf(mock_aws is None, "moto not installed")
class GdprPrivacyGapTests(unittest.TestCase):
    def setUp(self):
        self._stack = ExitStack()
        self._stack.enter_context(mock_aws())
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")

        import app.core.tables as tables_mod
        import app.services.gdpr_service as svc
        import app.core.aws as aws_mod

        self.svc = svc
        self.tables_mod = tables_mod
        self.aws_mod = aws_mod

        T = tables_mod.T

        # Create moto tables and bind the EXACT frozen handles the code uses.
        self._saved = {}
        for name in _PKSK_TABLES:
            tbl = _create_pksk(self.ddb, name)
            self._saved[name] = getattr(T, name)
            object.__setattr__(T, name, tbl)
        for name, pk in _PK_ONLY.items():
            tbl = _create_pk_only(self.ddb, name, pk)
            self._saved[name] = getattr(T, name)
            object.__setattr__(T, name, tbl)

        # Messaging tables are accessed via app.core.aws.ddb.Table(name).
        _create_messaging(self.ddb)
        self._saved_aws_ddb = aws_mod.ddb
        object.__setattr__(aws_mod, "ddb", self.ddb)

        self.T = T

    def tearDown(self):
        for name, handle in self._saved.items():
            object.__setattr__(self.T, name, handle)
        object.__setattr__(self.aws_mod, "ddb", self._saved_aws_ddb)
        self._stack.close()

    # ── GAP-0339: process_deletion removes messaging data ──────────────────

    def test_process_deletion_deletes_user_messages_and_participant(self):
        svc = self.svc
        user = "alice_sub"
        cid = "conv_dm_001"

        conv = self.ddb.Table("Conversations")
        part = self.ddb.Table("Participants")
        msg = self.ddb.Table("Messages")

        conv.put_item(Item={"conversation_id": cid, "kind": "dm"})
        # Both parties' participant rows.
        part.put_item(Item={"user_id": user, "conversation_id": cid})
        part.put_item(Item={"user_id": "bob_sub", "conversation_id": cid})
        # One message from alice, one from bob.
        msg.put_item(Item={"conversation_id": cid, "message_id": "m_001", "sender_id": user, "text": "hi"})
        msg.put_item(Item={"conversation_id": cid, "message_id": "m_002", "sender_id": "bob_sub", "text": "yo"})

        # Seed the deletion request record.
        req = svc.create_deletion_request(user)
        request_id = req["request_id"]

        import app.services.account as account_mod
        with patch.object(account_mod, "delete_user_data"), patch.object(svc, "write_alert"):
            summary = svc.process_deletion(user, request_id)

        # Result counts are present and non-zero.
        self.assertEqual(summary["messages_deleted"], 1)
        self.assertEqual(summary["participants_deleted"], 1)

        # Alice's message is gone; Bob's survives.
        remaining = msg.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("conversation_id").eq(cid)
        )["Items"]
        ids = {m["message_id"] for m in remaining}
        self.assertNotIn("m_001", ids)
        self.assertIn("m_002", ids)

        # Alice's participant row is gone; Bob's survives.
        self.assertIsNone(part.get_item(Key={"user_id": user, "conversation_id": cid}).get("Item"))
        self.assertIsNotNone(part.get_item(Key={"user_id": "bob_sub", "conversation_id": cid}).get("Item"))

        # Request finalized as completed with the summary persisted.
        rec = svc.get_request(user, request_id)
        self.assertEqual(rec["status"], "completed")
        self.assertIn("messages_deleted", rec["deletion_summary"])

    # ── GAP-0338: export runs in the background, not inline ────────────────

    def test_run_export_safe_success_runs_process_export(self):
        svc = self.svc
        import app.routers.privacy as privacy

        user = "alice_sub"
        req = svc.create_export_request(user, {"include_profile": True})
        request_id = req["request_id"]

        called = {}

        def _fake_process(u, rid, cats):
            called["args"] = (u, rid, cats)

        with patch.object(privacy, "process_export", side_effect=_fake_process):
            asyncio.new_event_loop().run_until_complete(
                privacy._run_export_safe(user, request_id, {"include_profile": True})
            )

        self.assertEqual(called["args"][0], user)
        self.assertEqual(called["args"][1], request_id)

    def test_run_export_safe_failure_marks_request_failed(self):
        svc = self.svc
        import app.routers.privacy as privacy

        user = "alice_sub"
        req = svc.create_export_request(user, {"include_profile": True})
        request_id = req["request_id"]
        self.assertEqual(svc.get_request(user, request_id)["status"], "pending")

        def _boom(u, rid, cats):
            raise RuntimeError("S3 down")

        with patch.object(privacy, "process_export", side_effect=_boom):
            asyncio.new_event_loop().run_until_complete(
                privacy._run_export_safe(user, request_id, {"include_profile": True})
            )

        # Status flipped to "failed" — never stuck at "pending".
        rec = svc.get_request(user, request_id)
        self.assertEqual(rec["status"], "failed")
        self.assertNotEqual(rec["status"], "pending")
        self.assertIn("error_message", rec)

    def test_schedule_export_returns_promptly_and_runs_in_background(self):
        """_schedule_export must NOT block on the (slow) export work."""
        svc = self.svc
        import app.routers.privacy as privacy
        import time

        user = "alice_sub"
        req = svc.create_export_request(user, {"include_profile": True})
        request_id = req["request_id"]

        ran = {"done": False}

        def _slow(u, rid, cats):
            time.sleep(0.2)
            ran["done"] = True

        async def _drive():
            with patch.object(privacy, "process_export", side_effect=_slow):
                t0 = time.monotonic()
                privacy._schedule_export(user, request_id, {"include_profile": True})
                elapsed = time.monotonic() - t0
                # Scheduling returns immediately, well under the 0.2s work time.
                self.assertLess(elapsed, 0.1)
                self.assertFalse(ran["done"])
                # Let the background task complete.
                for _ in range(50):
                    if ran["done"]:
                        break
                    await asyncio.sleep(0.02)
                self.assertTrue(ran["done"])

        asyncio.new_event_loop().run_until_complete(_drive())


if __name__ == "__main__":
    unittest.main()
