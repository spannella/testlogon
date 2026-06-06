"""Regression test for GAP-0123: atomic private-session billing.

Before the fix, ``_write_private_billing`` wrote the viewer debit and the
creator credit as two independent ``put_item`` calls, each wrapped in its own
``try/except Exception`` that swallowed all errors. A failure on the credit
write *after* a successful debit left the viewer charged and the creator
unpaid, with no error surfaced to the caller.

After the fix, the pair is written via DynamoDB ``TransactWriteItems`` (atomic:
both rows or neither) and any failure is re-raised as ``RuntimeError`` so the
caller can mark the session ``billing_failed``.

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

from app.services import broadcast_private

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


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestPrivateBillingAtomicityGap0123(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _create_billing_table(self.ddb)
        # Under mock_aws(), the fresh boto3 client that _write_private_billing
        # builds is auto-intercepted by moto and shares this in-memory store.
        # `_write_private_billing` reads `S.billing_table_name`; assert the
        # default matches the moto table so the test is config-independent.
        from app.core.settings import S

        assert S.billing_table_name == _BILLING_TABLE, (
            f"expected default billing table '{_BILLING_TABLE}', got "
            f"'{S.billing_table_name}'"
        )

    def _rows_for(self, user_id: str):
        return self.table.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{user_id}")
        )["Items"]

    def test_success_writes_both_rows(self):
        debit_id, credit_id = broadcast_private._write_private_billing(
            viewer_id="viewer_v",
            creator_id="creator_c",
            amount_cents=500,
            private_session_id="priv_001",
            session_id="sess_001",
            payment_method_id="pm_test",
        )

        debits = self._rows_for("viewer_v")
        credits = self._rows_for("creator_c")
        self.assertEqual(len(debits), 1)
        self.assertEqual(len(credits), 1)
        self.assertEqual(debits[0]["type"], "debit")
        self.assertEqual(credits[0]["type"], "credit")
        self.assertEqual(debits[0]["entry_id"], debit_id)
        self.assertEqual(credits[0]["entry_id"], credit_id)
        self.assertEqual(int(debits[0]["amount_cents"]), 500)
        self.assertEqual(int(credits[0]["amount_cents"]), 500)

    def test_failure_leaves_no_orphaned_debit(self):
        """A failed credit must NOT leave an orphaned debit row.

        This drives a REAL DynamoDB (moto) transaction failure: by forcing the
        debit and credit rows to share an identical primary key, the underlying
        TransactWriteItems is rejected (duplicate keys in one transaction).

        FAILS BEFORE FIX: the old code issued two independent put_item calls;
        the first (debit) commits, leaving the viewer charged with no
        corresponding credit -> an orphaned debit row + no raised error.
        PASSES AFTER FIX: TransactWriteItems is atomic, so the rejected
        transaction commits nothing, and the error is re-raised as RuntimeError.
        """
        collide = "deadbeef"
        # Force debit_id == credit_id so that, with viewer_id == creator_id,
        # both ledger rows resolve to the same pk/sk -> transaction conflict.
        with patch.object(broadcast_private.uuid, "uuid4") as mock_uuid:
            mock_uuid.return_value.hex = collide
            with self.assertRaises(RuntimeError):
                broadcast_private._write_private_billing(
                    viewer_id="same_user",
                    creator_id="same_user",
                    amount_cents=500,
                    private_session_id="priv_002",
                    session_id="sess_002",
                    payment_method_id="pm_test",
                )

        # Atomic rollback: the partition must contain ZERO rows. The old,
        # non-atomic implementation would leave exactly one orphaned debit here.
        self.assertEqual(self._rows_for("same_user"), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
