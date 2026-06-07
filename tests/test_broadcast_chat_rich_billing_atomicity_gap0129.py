"""Regression test for GAP-0129: atomic broadcast-chat rich billing.

Before the fix, ``_write_chat_billing`` (BCAST-015) wrote the payer debit and
the recipient credit as two independent ``put_item`` calls, each wrapped in its
own ``try/except Exception`` that swallowed all errors. A failure on the credit
write *after* a successful debit left the payer charged and the broadcaster
unpaid; worse, because the swallowed exception never propagated, the caller
``unlock_chat_message`` proceeded to write the ``unlocked_by`` map, releasing
content even when no debit had actually been collected.

After the fix, the debit/credit pair is written via DynamoDB
``TransactWriteItems`` (atomic: both rows or neither) and any failure is
re-raised as ``RuntimeError`` so the caller does not treat a failed billing
write as success — the ``unlocked_by`` update never runs and the message stays
locked.

Offline only: uses moto (in-memory DynamoDB). No real AWS is contacted.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3
from boto3.dynamodb.conditions import Key

try:
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

from app.services import broadcast_chat_rich

_BILLING_TABLE = "billing"


def _create_billing_table(ddb):
    return ddb.create_table(
        TableName=_BILLING_TABLE,
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


def _create_chat_messages_table(ddb):
    from app.core.settings import S

    return ddb.create_table(
        TableName=S.broadcast_chat_messages_table_name,
        KeySchema=[
            {"AttributeName": "session_id", "KeyType": "HASH"},
            {"AttributeName": "sort_key", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "session_id", "AttributeType": "S"},
            {"AttributeName": "sort_key", "AttributeType": "S"},
            {"AttributeName": "message_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "MessageIdIndex",
                "KeySchema": [
                    {"AttributeName": "message_id", "KeyType": "HASH"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestBroadcastChatBillingAtomicityGap0129(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _create_billing_table(self.ddb)
        self.msgs = _create_chat_messages_table(self.ddb)
        # Under mock_aws(), the fresh boto3 client that _write_chat_billing
        # builds is auto-intercepted by moto and shares this in-memory store.
        # The function reads S.billing_table_name; assert the default matches
        # the moto table so the test is config-independent.
        from app.core.settings import S

        assert S.billing_table_name == _BILLING_TABLE, (
            f"expected default billing table '{_BILLING_TABLE}', got "
            f"'{S.billing_table_name}'"
        )
        # Rebind the resource-level table handles used by the caller path
        # (unlock_chat_message reads/writes via T.*) to the moto tables.
        self._patch_tables()

    def _patch_tables(self):
        # ``T`` is a frozen dataclass, so ``patch.object`` (which assigns the
        # attribute) raises FrozenInstanceError. Swap the handles via
        # ``object.__setattr__`` and restore them on cleanup.
        from app.core import tables as tables_mod

        T = tables_mod.T
        originals = {
            "billing": T.billing,
            "broadcast_chat_messages": T.broadcast_chat_messages,
        }
        object.__setattr__(T, "billing", self.table)
        object.__setattr__(T, "broadcast_chat_messages", self.msgs)

        def _restore():
            for name, val in originals.items():
                object.__setattr__(T, name, val)

        self.addCleanup(_restore)

    def _rows_for(self, user_id: str):
        return self.table.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{user_id}")
        )["Items"]

    # ── _write_chat_billing: direct atomicity ──────────────────────

    def test_success_writes_both_rows(self):
        debit_id, credit_id = broadcast_chat_rich._write_chat_billing(
            payer_id="payer_p",
            recipient_id="creator_c",
            amount_cents=500,
            reason="Broadcast chat message unlock",
            content_type="broadcast_chat_unlock",
            content_id="msg_xyz",
            session_id="sess_xyz",
            payment_method_id="pm_test",
        )

        debits = self._rows_for("payer_p")
        credits = self._rows_for("creator_c")
        self.assertEqual(len(debits), 1)
        self.assertEqual(len(credits), 1)
        self.assertEqual(debits[0]["type"], "debit")
        self.assertEqual(credits[0]["type"], "credit")
        self.assertEqual(debits[0]["entry_id"], debit_id)
        self.assertEqual(credits[0]["entry_id"], credit_id)
        self.assertEqual(int(debits[0]["amount_cents"]), 500)
        # 20% platform fee → creator credited 400.
        self.assertEqual(int(credits[0]["amount_cents"]), 400)

    def test_failure_leaves_no_orphaned_debit(self):
        """A failed credit must NOT leave an orphaned debit row.

        Drives a REAL moto TransactWriteItems failure by forcing the debit and
        credit rows to share an identical primary key (duplicate keys in one
        transaction are rejected by DynamoDB).

        FAILS BEFORE FIX: two independent put_item calls; the debit commits,
        leaving the payer charged with no credit -> orphaned debit + no error.
        PASSES AFTER FIX: TransactWriteItems is atomic, so nothing commits and
        the error is re-raised as RuntimeError.
        """
        collide = "deadbeef"
        with patch.object(broadcast_chat_rich.uuid, "uuid4") as mock_uuid:
            mock_uuid.return_value.hex = collide
            with self.assertRaises(RuntimeError):
                broadcast_chat_rich._write_chat_billing(
                    payer_id="same_user",
                    recipient_id="same_user",
                    amount_cents=500,
                    reason="Broadcast chat message unlock",
                    content_type="broadcast_chat_unlock",
                    content_id="msg_dup",
                    session_id="sess_dup",
                    payment_method_id="pm_test",
                )

        # Atomic rollback: the partition must contain ZERO rows. The old,
        # non-atomic implementation would leave exactly one orphaned debit.
        self.assertEqual(self._rows_for("same_user"), [])

    # ── unlock_chat_message: content stays locked on billing failure ─

    def _seed_locked_message(self, session_id, message_id, sender_id, viewer_id):
        sort_key = f"{0:016d}#{message_id}"
        self.msgs.put_item(Item={
            "session_id": session_id,
            "sort_key": sort_key,
            "message_id": message_id,
            "sender_id": sender_id,
            "text": "secret locked content",
            "lock_price_cents": 500,
            "unlocked_by": {},
        })
        # Viewer needs a valid payment method row.
        self.table.put_item(Item={
            "pk": f"USER#{viewer_id}",
            "sk": "PM#pm_test",
            "brand": "visa",
        })
        return sort_key

    def test_unlock_succeeds_and_charges_when_billing_ok(self):
        broadcast_chat_rich.reset_rich_rate_limits()
        sort_key = self._seed_locked_message(
            "sess_ok", "msg_ok", sender_id="creator_c", viewer_id="viewer_v"
        )

        with patch.object(broadcast_chat_rich, "broadcast_sse_publish"):
            result = broadcast_chat_rich.unlock_chat_message(
                session_id="sess_ok",
                message_id="msg_ok",
                user_id="viewer_v",
                payment_method_id="pm_test",
                broadcaster_id="creator_c",
            )

        self.assertTrue(result["ok"])
        item = self.msgs.get_item(
            Key={"session_id": "sess_ok", "sort_key": sort_key}
        )["Item"]
        self.assertIn("viewer_v", item.get("unlocked_by") or {})
        # Both ledger rows present (viewer debit + creator credit). viewer_v
        # also has a seeded PM row, so filter to LEDGER# rows.
        ledger = [r for r in self._rows_for("viewer_v") if r["sk"].startswith("LEDGER#")]
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger[0]["type"], "debit")
        credits = [r for r in self._rows_for("creator_c") if r["sk"].startswith("LEDGER#")]
        self.assertEqual(len(credits), 1)
        self.assertEqual(credits[0]["type"], "credit")

    def test_unlock_blocked_when_billing_fails(self):
        """Billing failure must prevent the unlocked_by update (stays locked).

        Forces a real TransactWriteItems failure (collision) inside the billing
        write triggered by unlock_chat_message.

        FAILS BEFORE FIX: _write_chat_billing swallowed the error and returned;
        unlock proceeded, unlocked_by contained the viewer (free unlock), and an
        orphaned credit (recipient==viewer here, but in general an orphan) could
        exist.
        PASSES AFTER FIX: RuntimeError propagates out of _write_chat_billing,
        short-circuiting the unlocked_by update; the message remains locked and
        no ledger rows are written.
        """
        broadcast_chat_rich.reset_rich_rate_limits()
        # broadcaster_id == viewer forces debit/credit pk collision when ids
        # also collide, but we additionally pin uuid to guarantee duplicate sk.
        sort_key = self._seed_locked_message(
            "sess_fail", "msg_fail", sender_id="creator_c", viewer_id="viewer_v"
        )

        collide = "deadbeef"
        with patch.object(broadcast_chat_rich.uuid, "uuid4") as mock_uuid:
            # First uuid4() call is unlock_payment_id; subsequent are debit/credit.
            mock_uuid.return_value.hex = collide
            with patch.object(broadcast_chat_rich, "broadcast_sse_publish"):
                with self.assertRaises(RuntimeError):
                    broadcast_chat_rich.unlock_chat_message(
                        session_id="sess_fail",
                        message_id="msg_fail",
                        user_id="viewer_v",
                        payment_method_id="pm_test",
                        broadcaster_id="viewer_v",  # collide pk with payer
                    )

        # Message must remain locked: viewer NOT in unlocked_by.
        item = self.msgs.get_item(
            Key={"session_id": "sess_fail", "sort_key": sort_key}
        )["Item"]
        self.assertNotIn("viewer_v", item.get("unlocked_by") or {})
        # No ledger rows written (only the seeded PM row remains).
        ledger = [r for r in self._rows_for("viewer_v") if r["sk"].startswith("LEDGER#")]
        self.assertEqual(ledger, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
