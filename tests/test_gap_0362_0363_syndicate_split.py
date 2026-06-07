"""Offline regression tests for GAP-0362 and GAP-0363 (SYND-003).

Both gaps live in ``execute_split`` in
``app/services/syndicate_revenue_split.py``:

GAP-0362 — financial-integrity invariants were enforced with bare Python
``assert`` statements, which are STRIPPED under ``python -O``. A distribution
mismatch would then silently credit wrong amounts. The fix replaces both
``assert``s with unconditional ``if ...: raise RuntimeError(...)`` guards that
run BEFORE the per-member loop, so a bad split raises and writes NOTHING.

GAP-0363 — ``execute_split`` wrote a ledger CREDIT row per member but never
incremented their spendable wallet balance (``wallet_balance_cents`` on the
billing WALLET row), so payout/wallet endpoints showed $0 despite earned
revenue. The fix calls ``apply_wallet_delta(T.billing, "USER#{id}", amount)``
inside the per-member loop alongside the ledger write.

Fully offline: real in-memory DynamoDB tables are created with moto (no real
AWS) and the FROZEN ``T.billing`` / ``T.syndicate_revenue_split`` handles are
patched to point at them via ``object.__setattr__`` (restored on cleanup).
Syndicate collaborators (``_get_meta``, ``list_members``) and
``get_split_config`` are patched directly. ``execute_split`` is then called and
the resulting DDB state is read back.
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


def _make_billing_table(ddb):
    return ddb.create_table(
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


def _make_split_table(ddb):
    return ddb.create_table(
        TableName="syndicate_revenue_split",
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


SYNDICATE_ID = "test-synd-split"


def _fake_meta():
    return {"admin_user_id": "admin", "status": "active", "name": "Test"}


def _fake_members():
    return [
        {"user_id": "alice", "display_name": "Alice"},
        {"user_id": "bob", "display_name": "Bob"},
    ]


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _SplitTestBase(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.billing = _make_billing_table(ddb)
        self.split_table = _make_split_table(ddb)

        from app.services import syndicate_revenue_split as svc

        self.svc = svc

        # Bind the FROZEN T handles to the moto tables via object.__setattr__,
        # restoring the originals on cleanup.
        orig_billing = svc.T.billing
        orig_split = svc.T.syndicate_revenue_split
        object.__setattr__(svc.T, "billing", self.billing)
        object.__setattr__(svc.T, "syndicate_revenue_split", self.split_table)
        self.addCleanup(object.__setattr__, svc.T, "billing", orig_billing)
        self.addCleanup(
            object.__setattr__, svc.T, "syndicate_revenue_split", orig_split
        )

        # Stub syndicate collaborators.
        self.stack.enter_context(
            patch.object(svc.syndicate_svc, "_get_meta", return_value=_fake_meta())
        )
        self.stack.enter_context(
            patch.object(svc.syndicate_svc, "list_members", return_value=_fake_members())
        )

    def _wallet_balance(self, user_id: str) -> int:
        resp = self.billing.get_item(Key={"pk": f"USER#{user_id}", "sk": "WALLET"})
        item = resp.get("Item")
        if not item:
            return 0
        return int(item.get("wallet_balance_cents", 0))

    def _ledger_rows(self, user_id: str):
        from boto3.dynamodb.conditions import Key as _Key

        resp = self.billing.query(
            KeyConditionExpression=_Key("pk").eq(f"USER#{user_id}")
            & _Key("sk").begins_with("LEDGER#")
        )
        return resp.get("Items", [])


class TestWalletDeltaGap0363(_SplitTestBase):
    def test_each_member_wallet_credited(self):
        """GAP-0363: each member's wallet_balance_cents must increase by their
        distribution amount, AND the ledger credit rows must still exist.

        FAILS BEFORE FIX: wallet stays 0 (apply_wallet_delta never called).
        PASSES AFTER FIX: wallet == distribution amount.
        """
        # 0% platform fee → equal split of 1000 = 500 each.
        with patch.object(
            self.svc,
            "get_split_config",
            return_value={"mode": "equal", "platform_fee_bps": 0},
        ):
            record = self.svc.execute_split(
                syndicate_id=SYNDICATE_ID,
                gross_amount_cents=1000,
            )

        # Sanity: distributions sum correctly.
        amounts = {d["user_id"]: int(d["amount_cents"]) for d in record["distributions"]}
        self.assertEqual(amounts, {"alice": 500, "bob": 500})

        # Wallet balances credited.
        self.assertEqual(self._wallet_balance("alice"), 500)
        self.assertEqual(self._wallet_balance("bob"), 500)

        # Ledger credit rows still present (one per member).
        for uid in ("alice", "bob"):
            rows = self._ledger_rows(uid)
            self.assertEqual(len(rows), 1, f"expected 1 ledger row for {uid}")
            self.assertEqual(rows[0]["type"], "credit")
            self.assertEqual(int(rows[0]["amount_cents"]), 500)

    def test_wallet_accumulates_across_splits(self):
        """A second split adds to the existing wallet balance (if_not_exists path)."""
        with patch.object(
            self.svc,
            "get_split_config",
            return_value={"mode": "equal", "platform_fee_bps": 0},
        ):
            self.svc.execute_split(syndicate_id=SYNDICATE_ID, gross_amount_cents=1000)
            self.svc.execute_split(syndicate_id=SYNDICATE_ID, gross_amount_cents=1000)

        self.assertEqual(self._wallet_balance("alice"), 1000)
        self.assertEqual(self._wallet_balance("bob"), 1000)


class TestInvariantGap0362(_SplitTestBase):
    @staticmethod
    def _bad_equal_calc(net_amount_cents, member_ids):
        """Buggy equal split: second member is 1 cent short of the total."""
        half = net_amount_cents // 2
        return [
            {"user_id": "alice", "amount_cents": half, "percentage_bps": 5000},
            {"user_id": "bob", "amount_cents": half - 1, "percentage_bps": 5000},
        ]

    def test_distribution_mismatch_raises_and_writes_nothing(self):
        """GAP-0362: a distribution mismatch must RAISE (RuntimeError) and write
        no ledger / wallet / split rows.

        FAILS BEFORE FIX: bare assert is stripped under -O (and even when
        enabled, the explicit guard semantics differ); the buggy split would be
        persisted. PASSES AFTER FIX: RuntimeError raised before the loop.
        """
        with patch.object(
            self.svc,
            "get_split_config",
            return_value={"mode": "equal", "platform_fee_bps": 1500},
        ), patch.object(self.svc, "_calculate_equal", side_effect=self._bad_equal_calc):
            with self.assertRaises(RuntimeError):
                self.svc.execute_split(
                    syndicate_id=SYNDICATE_ID,
                    gross_amount_cents=1000,
                )

        # No DDB writes: no ledger rows, no wallet rows, no split records.
        self.assertEqual(self._ledger_rows("alice"), [])
        self.assertEqual(self._ledger_rows("bob"), [])
        self.assertEqual(self._wallet_balance("alice"), 0)
        self.assertEqual(self._wallet_balance("bob"), 0)
        split_scan = self.split_table.scan().get("Items", [])
        self.assertEqual(
            [i for i in split_scan if str(i.get("sk", "")).startswith("SPLIT#")],
            [],
        )

    def test_valid_split_does_not_raise(self):
        """A correct split must NOT raise."""
        with patch.object(
            self.svc,
            "get_split_config",
            return_value={"mode": "equal", "platform_fee_bps": 1500},
        ):
            record = self.svc.execute_split(
                syndicate_id=SYNDICATE_ID,
                gross_amount_cents=1000,
            )
        # 15% fee of 1000 = 150 → net 850 → split 425/425.
        self.assertEqual(record["platform_fee_cents"], 150)
        self.assertEqual(record["net_amount_cents"], 850)
        amounts = {d["user_id"]: int(d["amount_cents"]) for d in record["distributions"]}
        self.assertEqual(amounts, {"alice": 425, "bob": 425})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
