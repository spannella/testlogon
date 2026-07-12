"""Offline regression tests for D1 (docs/CROSS_TICKET_AUDIT.md §A4 + §D1):
persisted ``signed_amount_cents`` on the billing ledger.

``new_ledger_entry`` now stamps a ``signed_amount_cents`` at write time:
  * an explicit ``signed_amount_cents=`` kwarg is persisted verbatim;
  * otherwise it is derived = sign(entry_type) * abs(amount_cents) via the
    canonical :data:`LEDGER_ENTRY_SIGN` map (credit +, charge/debit -;
    refund / adjustment / void-reversal = credit +; unknown -> default +).
``amount_cents`` STAYS UNSIGNED. Existing callers (no kwarg) keep working.

``scripts/backfill_signed_amount_cents.py`` stamps legacy rows missing the
field, deriving it from the stored ``type`` via the same map (idempotent).

Fully offline / hermetic. We build a real in-memory billing table with moto
(no real AWS) and patch the exact ``T`` handle the backfill code reads via
``object.__setattr__`` (``T`` is a frozen dataclass instance), restoring it on
cleanup. ``new_ledger_entry`` is a pure builder so it needs no table; we call
it directly and inspect the returned item.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from app.services.billing_shared import (
    LEDGER_ENTRY_SIGN,
    derive_signed_amount_cents,
    new_ledger_entry,
)


class TestNewLedgerEntrySignedAmount(unittest.TestCase):
    def test_explicit_signed_amount_persists_verbatim(self):
        # A refund: amount stays unsigned positive, signed is +amount.
        _sk, item = new_ledger_entry(
            key_name="pk",
            key_value="USER#u1",
            entry_type="adjustment",
            amount_cents=500,
            signed_amount_cents=500,
            state="settled",
            reason="refund",
        )
        self.assertEqual(item["amount_cents"], 500)
        self.assertEqual(item["signed_amount_cents"], 500)

    def test_explicit_signed_amount_can_be_negative_with_unsigned_amount(self):
        # Caller may force a negative signed value while amount_cents stays
        # unsigned (display value).
        _sk, item = new_ledger_entry(
            key_name="pk",
            key_value="USER#u1",
            entry_type="adjustment",
            amount_cents=750,
            signed_amount_cents=-750,
            state="settled",
            reason="manual debit adjustment",
        )
        self.assertEqual(item["amount_cents"], 750)
        self.assertEqual(item["signed_amount_cents"], -750)

    def test_derived_positive_for_credit(self):
        _sk, item = new_ledger_entry(
            key_name="pk",
            key_value="USER#u1",
            entry_type="credit",
            amount_cents=1200,
            state="settled",
            reason="wallet credit",
        )
        self.assertEqual(item["amount_cents"], 1200)
        self.assertEqual(item["signed_amount_cents"], 1200)

    def test_derived_negative_for_charge_and_debit(self):
        for etype in ("debit", "purchase", "click_charge"):
            with self.subTest(entry_type=etype):
                _sk, item = new_ledger_entry(
                    key_name="pk",
                    key_value="USER#u1",
                    entry_type=etype,
                    amount_cents=999,
                    state="settled",
                    reason="charge",
                )
                self.assertEqual(item["amount_cents"], 999)
                self.assertEqual(item["signed_amount_cents"], -999)

    def test_derived_positive_for_refund_and_adjustment_and_void_reversal(self):
        for etype in ("refund", "adjustment", "invoice_void_reversal", "shipping_refund"):
            with self.subTest(entry_type=etype):
                _sk, item = new_ledger_entry(
                    key_name="pk",
                    key_value="USER#u1",
                    entry_type=etype,
                    amount_cents=350,
                    state="settled",
                    reason="x",
                )
                self.assertEqual(item["amount_cents"], 350)
                self.assertEqual(item["signed_amount_cents"], 350)

    def test_existing_style_call_no_kwarg_still_succeeds_and_derives(self):
        # Mirrors a pre-existing caller that never passes signed_amount_cents.
        _sk, item = new_ledger_entry(
            key_name="pk",
            key_value="USER#u1",
            entry_type="debit",
            amount_cents=4200,
            state="pending",
            reason="legacy-style call",
        )
        self.assertEqual(item["amount_cents"], 4200)
        self.assertEqual(item["signed_amount_cents"], -4200)

    def test_unknown_entry_type_defaults_positive(self):
        _sk, item = new_ledger_entry(
            key_name="pk",
            key_value="USER#u1",
            entry_type="totally_unknown_type",
            amount_cents=10,
            state="settled",
            reason="x",
        )
        self.assertEqual(item["signed_amount_cents"], 10)

    def test_derive_uses_absolute_value_of_amount(self):
        # A caller that (wrongly) passed a negative amount still gets the
        # correct sign from the type map.
        self.assertEqual(derive_signed_amount_cents("debit", -500), -500)
        self.assertEqual(derive_signed_amount_cents("credit", -500), 500)

    def test_sign_map_internally_consistent(self):
        # Every value is exactly +1 or -1.
        for etype, sign in LEDGER_ENTRY_SIGN.items():
            with self.subTest(entry_type=etype):
                self.assertIn(sign, (1, -1))


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestBackfillSignedAmount(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = ddb.create_table(
            TableName="billing",
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

        # Swap the exact frozen T.billing handle the backfill reads.
        from app.core.tables import T

        self._T = T
        self._orig_billing = T.billing
        object.__setattr__(T, "billing", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "billing", self._orig_billing))

    def test_backfill_stamps_legacy_row_missing_field(self):
        # Legacy ledger row: unsigned amount, type, but NO signed_amount_cents.
        self.table.put_item(
            Item={
                "pk": "USER#u1",
                "sk": "LEDGER#1700000000#legacy1",
                "type": "debit",
                "amount_cents": 500,
                "state": "settled",
                "reason": "legacy charge",
            }
        )
        # A row that already has the field must be left untouched (idempotent).
        self.table.put_item(
            Item={
                "pk": "USER#u1",
                "sk": "LEDGER#1700000001#already",
                "type": "credit",
                "amount_cents": 700,
                "signed_amount_cents": 700,
                "state": "settled",
                "reason": "already stamped",
            }
        )
        # A non-ledger row (PM#) must be ignored.
        self.table.put_item(
            Item={"pk": "USER#u1", "sk": "PM#card1", "brand": "visa"}
        )

        import scripts.backfill_signed_amount_cents as bf

        summary = bf.run(dry_run=False)
        self.assertEqual(summary["stamped"], 1)
        self.assertEqual(summary["eligible"], 1)

        legacy = self.table.get_item(
            Key={"pk": "USER#u1", "sk": "LEDGER#1700000000#legacy1"}
        )["Item"]
        self.assertEqual(int(legacy["signed_amount_cents"]), -500)

        # Idempotent: running again stamps nothing.
        summary2 = bf.run(dry_run=False)
        self.assertEqual(summary2["stamped"], 0)
        self.assertEqual(summary2["eligible"], 0)

        # Untouched rows unchanged.
        already = self.table.get_item(
            Key={"pk": "USER#u1", "sk": "LEDGER#1700000001#already"}
        )["Item"]
        self.assertEqual(int(already["signed_amount_cents"]), 700)
        pm = self.table.get_item(Key={"pk": "USER#u1", "sk": "PM#card1"})["Item"]
        self.assertNotIn("signed_amount_cents", pm)

    def test_backfill_dry_run_does_not_write(self):
        self.table.put_item(
            Item={
                "pk": "USER#u2",
                "sk": "LEDGER#1700000002#dry",
                "type": "credit",
                "amount_cents": 333,
                "state": "settled",
                "reason": "x",
            }
        )
        import scripts.backfill_signed_amount_cents as bf

        summary = bf.run(dry_run=True)
        self.assertEqual(summary["stamped"], 1)
        row = self.table.get_item(
            Key={"pk": "USER#u2", "sk": "LEDGER#1700000002#dry"}
        )["Item"]
        self.assertNotIn("signed_amount_cents", row)


if __name__ == "__main__":
    unittest.main()
