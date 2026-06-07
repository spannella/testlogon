"""Offline regression test for GAP-0214 (FIN-018).

Gap: the runtime-configurable fee BPS settings in
``app/services/billing_config.py`` were defined (``get_fee_bps`` /
``_FEE_FIELD_BY_ENTRY_TYPE``) but never applied to any live billing path. Every
tip credited 100% of the gross amount to the creator regardless of the
admin-configured ``fee_tips_bps``, so the BillingConfig UI was cosmetic.

Fix:
  * ``billing_config.split_fee(entry_type, amount_cents)`` is the single
    canonical place that turns a configured BPS value into a concrete
    ``(platform_fee_cents, net_cents, fee_bps)`` split.
  * ``tip_ledger.write_tip_ledger`` now debits the tipper the full gross amount
    and credits the creator the *net* amount after the platform fee.

Isolation (per task rules): we do NOT rely on global moto interception leaking
to real AWS. A real in-memory DynamoDB is created with moto, and the exact
``T.billing`` / ``T.billing_config`` handles used by the production code are
swapped via ``object.__setattr__`` (``T`` is a frozen dataclass), and restored
afterwards. ``billing_config`` and ``tip_ledger`` both ``from app.core.tables
import T`` so they share the one ``T`` instance — patching its attributes covers
both. The functions are called directly (the FastAPI TestClient is unusable in
this repo).

FAILS BEFORE FIX:
  * ``split_fee`` does not exist (AttributeError / ImportError).
  * ``write_tip_ledger`` credit ``amount_cents == gross`` (no fee deducted).
PASSES AFTER FIX:
  * credit ``amount_cents == gross - platform_fee`` and meta carries the fee.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_billing_table(ddb, name: str):
    return ddb.create_table(
        TableName=name,
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
class TestFeeBpsWiredGap0214(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.billing = _make_billing_table(ddb, "billing")
        self.billing_config = _make_billing_table(ddb, "billing_config")

        from app.core.tables import T
        from app.services import billing_config

        self._T = T
        self.billing_config_mod = billing_config

        # Swap the exact table handles used by production code. T is frozen, so
        # use object.__setattr__ and restore the originals on cleanup.
        self._orig_billing = T.billing
        self._orig_billing_config = T.billing_config
        object.__setattr__(T, "billing", self.billing)
        object.__setattr__(T, "billing_config", self.billing_config)

        def _restore():
            object.__setattr__(T, "billing", self._orig_billing)
            object.__setattr__(T, "billing_config", self._orig_billing_config)

        self.addCleanup(_restore)

        # Clear the module cache before AND after the test so the configured fee
        # is read fresh from our moto table and never leaks to/from other tests.
        billing_config.invalidate_cache()
        self.addCleanup(billing_config.invalidate_cache)

    def _set_fee_tips_bps(self, bps: int):
        """Write a CURRENT billing-config override directly to the moto table."""
        self.billing_config.put_item(
            Item={
                "pk": "BILLING_CONFIG",
                "sk": "CURRENT",
                "fee_tips_bps": Decimal(str(bps)),
                "updated_at": Decimal("1700000000"),
                "updated_by": "root_test",
            }
        )
        self.billing_config_mod.invalidate_cache()

    def _read_entries(self, tipper: str, recipient: str):
        debit_items = self.billing.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{tipper}"),
        )["Items"]
        credit_items = self.billing.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{recipient}"),
        )["Items"]
        debit = next(i for i in debit_items if i["type"] == "debit")
        credit = next(i for i in credit_items if i["type"] == "credit")
        return debit, credit

    def test_split_fee_helper_math(self):
        """split_fee returns (fee, net, bps) summing to gross; floor favours net."""
        self._set_fee_tips_bps(2000)  # 20%
        fee, net, bps = self.billing_config_mod.split_fee("tip_debit", 1000)
        self.assertEqual(bps, 2000)
        self.assertEqual(fee, 200)
        self.assertEqual(net, 800)
        self.assertEqual(fee + net, 1000)

        # Rounding: 1bps of 999 -> floor(0.0999) == 0 fee, full net to creator.
        self._set_fee_tips_bps(1)
        fee, net, bps = self.billing_config_mod.split_fee("tip_debit", 999)
        self.assertEqual(fee, 0)
        self.assertEqual(net, 999)

    def test_tip_credit_is_net_after_platform_fee(self):
        """GAP-0214: creator credit = gross - platform fee; tipper pays gross.

        FAILS BEFORE FIX: credit amount_cents == 1000 (fee never deducted).
        PASSES AFTER FIX: credit amount_cents == 800 (20% fee applied).
        """
        self._set_fee_tips_bps(2000)  # 20%

        from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger

        entry = TipLedgerEntry(
            tipper_user_id="alice_214",
            recipient_user_id="bob_214",
            amount_cents=1000,
            content_type="message",
            content_id="msg_214_a",
        )
        write_tip_ledger(entry)

        debit, credit = self._read_entries("alice_214", "bob_214")

        self.assertEqual(int(debit["amount_cents"]), 1000, "tipper pays full gross")
        self.assertEqual(int(credit["amount_cents"]), 800, "creator gets net (80%)")
        self.assertEqual(int(credit["meta"]["platform_fee_bps"]), 2000)
        self.assertEqual(int(credit["meta"]["platform_fee_cents"]), 200)
        self.assertEqual(int(debit["meta"]["platform_fee_cents"]), 200)

    def test_tip_credit_tracks_runtime_fee_change(self):
        """Changing fee_tips_bps changes the credited net amount.

        Proves the fee is read live from billing config (not a hardcoded value).
        """
        from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger

        self._set_fee_tips_bps(1000)  # 10%
        write_tip_ledger(
            TipLedgerEntry(
                tipper_user_id="alice_chg",
                recipient_user_id="bob_chg",
                amount_cents=1000,
                content_type="message",
                content_id="msg_chg_1",
            )
        )
        _, credit = self._read_entries("alice_chg", "bob_chg")
        self.assertEqual(int(credit["amount_cents"]), 900)

    def test_tip_zero_fee_credits_full_amount(self):
        """0 BPS -> creator gets 100% (backward-compat edge case)."""
        self._set_fee_tips_bps(0)

        from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger

        write_tip_ledger(
            TipLedgerEntry(
                tipper_user_id="alice_zero",
                recipient_user_id="bob_zero",
                amount_cents=500,
                content_type="message",
                content_id="msg_zero_1",
            )
        )
        debit, credit = self._read_entries("alice_zero", "bob_zero")
        self.assertEqual(int(debit["amount_cents"]), 500)
        self.assertEqual(int(credit["amount_cents"]), 500)
        self.assertEqual(int(credit["meta"]["platform_fee_cents"]), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
