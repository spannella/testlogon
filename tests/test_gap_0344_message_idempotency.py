"""Offline regression test for GAP-0344 — message-send idempotency.

The send-text-message path (``app/routers/messaging.py:send_text_message``) had
no idempotency key: every call generated a fresh ``mid = "m_" + new_id()`` and
unconditionally ``put_item``'d a new row. A retried request (PWA offline replay,
dropped-response retry) therefore created a DUPLICATE message.

Fix: ``SendTextMessageIn`` gained an optional ``client_request_id``. When present,
the ``message_id`` is derived deterministically (sender|conversation|key) and the
row is written with a conditional ``attribute_not_exists(message_id)`` put. A
replay with the same key returns the SAME message and writes NO second row.

Fully offline: a real in-memory DynamoDB ``Messages`` table is created with moto
and bound to the exact ``tbl_msgs`` handle the code uses (via
``object.__setattr__`` / ``monkeypatch.setattr``). All SSE-fanout / search-index /
audit / quota / participant side effects are stubbed to no-ops. ``send_text_message``
(a sync function) is called directly — the repo's FastAPI TestClient is unusable.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

import app.routers.messaging as M


CONV_ID = "c_test_idem"
SENDER = "u_alice"


def _make_messages_table(ddb):
    """Create the Messages table: HASH=conversation_id, RANGE=message_id."""
    return ddb.create_table(
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


@unittest.skipIf(mock_aws is None, "moto not installed")
class MessageIdempotencyTest(unittest.TestCase):
    def setUp(self):
        self._stack = ExitStack()
        self._aws = mock_aws()
        self._aws.start()
        self.addCleanup(self._aws.stop)

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _make_messages_table(ddb)

        # Bind the moto table to the exact handle the code uses.
        self._stack.enter_context(patch.object(M, "tbl_msgs", self.tbl))
        self.addCleanup(self._stack.close)

        # Stub all collaborators with side effects so send_text_message reduces to
        # the message-id derivation + (conditional) put + return.
        for name in (
            "_enforce_messaging_internal_entitlement",
            "require_participant_active",
            "_enforce_helpdesk_send_constraints",
            "_enforce_message_send_quota_precheck",
            "_validate_reply_target",
            "_sync_gallery_index_message",
            "_send_single_destination_message",
            "_fanout_new_message_event",
            "_run_bot_trigger_evaluation",
            "audit_event",
            "_emit_message_lifecycle_archive_event_or_503",
            "_meter_message_send",
        ):
            self._stack.enter_context(patch.object(M, name, lambda *a, **k: None))

        # No participants → the per-participant block (blocking/subscription) is skipped.
        self._stack.enter_context(
            patch.object(M.tbl_parts, "query", lambda *a, **k: {"Items": []})
        )
        # A simple DM conversation; no retention TTL, no reply linkage.
        self._stack.enter_context(
            patch.object(M, "_get_conversation_or_404", lambda cid: {"type": "dm"})
        )
        self._stack.enter_context(patch.object(M, "_message_retention_ttl", lambda *a, **k: None))
        self._stack.enter_context(patch.object(M, "_build_reply_linkage_fields", lambda **k: {}))
        # Receipts pass-through (returns the MessageOut unchanged).
        self._stack.enter_context(
            patch.object(M, "_apply_message_receipts", lambda msg, *a, **k: msg)
        )

    def _send(self, text, client_request_id=None):
        inp = M.SendTextMessageIn(text=text, client_request_id=client_request_id)
        return M.send_text_message(
            conversation_id=CONV_ID,
            inp=inp,
            req=None,
            user_id=SENDER,
            _kyc=None,
        )

    def _count_rows(self):
        return self.tbl.scan().get("Count", 0)

    def test_retry_with_same_key_is_idempotent(self):
        """Two sends with the SAME client_request_id → same message_id, ONE row."""
        crid = "client-req-abc-123"
        r1 = self._send("Hello idempotent world", client_request_id=crid)
        self.assertEqual(self._count_rows(), 1)

        r2 = self._send("Hello idempotent world", client_request_id=crid)
        # Same message returned, no second row written.
        self.assertEqual(r1.message_id, r2.message_id)
        self.assertEqual(self._count_rows(), 1, "retry created a duplicate row")

    def test_different_key_creates_new_message(self):
        """A DIFFERENT client_request_id produces a distinct message + row."""
        r1 = self._send("msg one", client_request_id="key-1")
        r2 = self._send("msg two", client_request_id="key-2")
        self.assertNotEqual(r1.message_id, r2.message_id)
        self.assertEqual(self._count_rows(), 2)

    def test_no_key_creates_distinct_messages(self):
        """Without a key, behavior is unchanged: two sends → two random ids/rows."""
        r1 = self._send("no key one")
        r2 = self._send("no key two")
        self.assertNotEqual(r1.message_id, r2.message_id)
        self.assertTrue(r1.message_id.startswith("m_"))
        self.assertEqual(self._count_rows(), 2)

    def test_idempotent_id_is_deterministic(self):
        """The idempotent message_id matches the documented derivation."""
        crid = "stable-key-xyz"
        expected = M._lottery_dedupe_message_id(
            sender_id=SENDER, conversation_id=CONV_ID, idempotency_key=crid
        )
        r = self._send("deterministic", client_request_id=crid)
        self.assertEqual(r.message_id, expected)


if __name__ == "__main__":
    unittest.main()
