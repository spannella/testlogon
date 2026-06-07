"""Regression test for GAP-0128: atomic lottery entry-fee billing.

Before the fix, ``_charge_entry_fee`` wrote the entrant debit and the
broadcaster credit as two independent ``put_item`` calls, each wrapped in its
own ``try/except Exception`` that swallowed all errors. A failure on the credit
write *after* a successful debit left the entrant charged and the broadcaster
unpaid, with no error surfaced to the caller.

After the fix, the pair is written via DynamoDB ``TransactWriteItems`` (atomic:
both rows or neither) and any failure is re-raised so the caller does not treat
a failed billing write as success.

Offline only: uses moto (in-memory DynamoDB). No real AWS is contacted.
"""
from __future__ import annotations

import unittest
import uuid as _uuid
from contextlib import ExitStack
from unittest.mock import patch

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

try:
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

from app.services import broadcast_lottery

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
class TestLotteryEntryFeeAtomicityGap0128(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        self.ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _create_billing_table(self.ddb)
        # Under mock_aws(), the fresh boto3 resource that _charge_entry_fee
        # imports (app.core.aws.ddb) is auto-intercepted by moto and shares
        # this in-memory store. The function reads S.billing_table_name;
        # assert the default matches the moto table so the test is
        # config-independent.
        from app.core.settings import S

        assert S.billing_table_name == _BILLING_TABLE, (
            f"expected default billing table '{_BILLING_TABLE}', got "
            f"'{S.billing_table_name}'"
        )

    def _seed_payment_method(self, user_id: str, pm_id: str) -> None:
        self.table.put_item(
            Item={"pk": f"USER#{user_id}", "sk": f"PM#{pm_id}", "type": "card"}
        )

    def _rows_for(self, user_id: str):
        return self.table.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{user_id}")
        )["Items"]

    def _ledger_rows_for(self, user_id: str):
        return [
            row
            for row in self._rows_for(user_id)
            if str(row.get("sk", "")).startswith("LEDGER#")
        ]

    def test_success_writes_both_rows(self):
        self._seed_payment_method("viewer_ok", "pm_test")

        fee_payment_id = broadcast_lottery._charge_entry_fee(
            user_id="viewer_ok",
            broadcaster_id="broadcaster_ok",
            entry_fee_cents=500,
            lottery_id="lot_ok",
            session_id="sess_ok",
            payment_method_id="pm_test",
        )
        self.assertTrue(fee_payment_id.startswith("lotfee_"))

        debits = self._ledger_rows_for("viewer_ok")
        credits = self._ledger_rows_for("broadcaster_ok")
        self.assertEqual(len(debits), 1)
        self.assertEqual(len(credits), 1)
        self.assertEqual(debits[0]["type"], "debit")
        self.assertEqual(credits[0]["type"], "credit")
        self.assertEqual(int(debits[0]["amount_cents"]), 500)
        self.assertEqual(int(credits[0]["amount_cents"]), 500)

    def test_failure_leaves_no_orphaned_debit(self):
        """A failed credit must NOT leave an orphaned debit row.

        This drives a REAL DynamoDB (moto) transaction failure: by forcing the
        debit and credit entry ids to collide while the entrant and broadcaster
        are the same user, both ledger rows resolve to the same pk/sk, so the
        underlying TransactWriteItems is rejected (duplicate keys in one
        transaction).

        FAILS BEFORE FIX: the old code issued two independent put_item calls;
        the first (debit) commits, leaving the entrant charged with no
        corresponding credit -> an orphaned debit row + no raised error.
        PASSES AFTER FIX: TransactWriteItems is atomic, so the rejected
        transaction commits nothing, and the error is re-raised.
        """
        self._seed_payment_method("same_user", "pm_test")

        collide = "deadbeef"
        # Force debit_entry_id == credit_entry_id so that, with
        # user_id == broadcaster_id, both ledger rows resolve to the same
        # pk/sk -> transaction conflict. _charge_entry_fee does a local
        # ``import uuid``, which resolves to the stdlib ``uuid`` module, so we
        # patch ``uuid.uuid4`` there.
        with patch.object(_uuid, "uuid4") as mock_uuid:
            mock_uuid.return_value.hex = collide
            with self.assertRaises(ClientError):
                broadcast_lottery._charge_entry_fee(
                    user_id="same_user",
                    broadcaster_id="same_user",
                    entry_fee_cents=500,
                    lottery_id="lot_fail",
                    session_id="sess_fail",
                    payment_method_id="pm_test",
                )

        # Atomic rollback: there must be ZERO ledger rows. The old,
        # non-atomic implementation would leave exactly one orphaned debit here.
        self.assertEqual(self._ledger_rows_for("same_user"), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
