"""Offline regression test for GAP-0307 (MON-003).

Subscription creator revenue is written to ``T.subscriptions`` under
``PK=CREATOR#{creator_id}`` (field ``entry_type``), but the creator earnings
dashboard (``creator_earnings._query_credit_entries``) and the payout balance
(``creator_payouts.get_available_balance``) query ``T.billing`` under
``PK=USER#{creator_id}`` with ``Attr("type").eq("credit")``. The two record sets
never overlap, so subscription revenue is INVISIBLE to earnings/payouts.

The fix adds ``subscription_server._mirror_creator_credit_to_billing`` which
mirrors the creator's NET subscription revenue (after platform fee) into
``T.billing`` in the exact shape the earnings query expects.

This test is fully hermetic: a real in-memory DynamoDB ``billing`` table is
created with moto and bound to the EXACT frozen handle the code uses
(``T.billing``) via ``object.__setattr__`` (restored on cleanup). Then:

* BEFORE the fix would: ``_query_credit_entries`` returns ``[]`` (nothing under
  ``USER#{creator}`` in ``T.billing``) and the earnings total is 0.
* AFTER the fix: calling the mirror helper writes a ``type=credit`` entry, and
  the SAME earnings query now returns it with the NET amount summing > 0.
"""
from __future__ import annotations

import unittest

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_billing_table(ddb):
    """Create the billing table mirroring scripts/local-ddb-init.py."""
    return ddb.create_table(
        TableName="billing",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "ledger_date", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_LEDGER_DATE",
                "KeySchema": [
                    {"AttributeName": "ledger_date", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto not installed")
class TestGap0307SubscriptionCreatorEarnings(unittest.TestCase):
    def setUp(self) -> None:
        self._mock = mock_aws()
        self._mock.start()

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._table = _make_billing_table(ddb)

        # Bind the moto table to the EXACT frozen handles both modules use.
        from app.core import tables as tables_mod
        from app.services import creator_earnings
        import app.routers.subscription_server as subscription_server

        self._tables_mod = tables_mod
        self._creator_earnings = creator_earnings
        self._subscription_server = subscription_server

        self._orig_billing = tables_mod.T.billing
        object.__setattr__(tables_mod.T, "billing", self._table)
        # creator_earnings and subscription_server import the same frozen ``T``
        # singleton, so patching tables_mod.T.billing covers all three.
        self.assertIs(creator_earnings.T, tables_mod.T)
        self.assertIs(subscription_server.T, tables_mod.T)

    def tearDown(self) -> None:
        object.__setattr__(self._tables_mod.T, "billing", self._orig_billing)
        self._mock.stop()

    def test_subscription_credit_visible_in_earnings_after_mirror(self) -> None:
        creator_id = "creator_0307"
        ce = self._creator_earnings
        ss = self._subscription_server

        # BEFORE: nothing in T.billing under USER#{creator} -> invisible.
        before = ce._query_credit_entries(user_id=creator_id)
        self.assertEqual(before, [], "no subscription credit should exist before mirror")
        before_summary = ce.get_earnings_summary(creator_id)
        self.assertEqual(before_summary["total_cents"], 0)

        # AFTER: mirror a subscription charge (gross $10.00, NET after fee = $9.00).
        gross_cents = 1000
        fee_cents = 100
        net_cents = gross_cents - fee_cents  # 900
        ss._mirror_creator_credit_to_billing(
            creator_id,
            net_cents,
            currency="USD",
            created_at=1700000000,
            subscription_id="sub_abc",
            subscriber_id="subscriber_xyz",
            invoice_id="inv_123",
        )

        after = ce._query_credit_entries(user_id=creator_id)
        self.assertEqual(len(after), 1, "mirrored credit must be queryable")
        self.assertEqual(int(after[0]["amount_cents"]), net_cents)
        self.assertEqual(after[0]["type"], "credit")

        # The summed earnings total reflects NET subscription revenue.
        after_summary = ce.get_earnings_summary(creator_id)
        self.assertEqual(after_summary["total_cents"], net_cents)
        self.assertGreater(after_summary["total_cents"], 0)
        # And it is classified under the "subscriptions" category.
        self.assertEqual(after_summary["breakdown"].get("subscriptions"), net_cents)

    def test_mirror_skips_non_positive_amount(self) -> None:
        creator_id = "creator_zero"
        ce = self._creator_earnings
        ss = self._subscription_server

        ss._mirror_creator_credit_to_billing(
            creator_id,
            0,
            currency="USD",
            created_at=1700000000,
            subscription_id="sub_zero",
            subscriber_id="subscriber_zero",
        )
        self.assertEqual(ce._query_credit_entries(user_id=creator_id), [])

    def test_mirror_failure_does_not_raise(self) -> None:
        """A billing put failure must be swallowed (best-effort)."""
        creator_id = "creator_fail"
        ss = self._subscription_server

        # Point the binding at the original (closed) handle is awkward; instead
        # temporarily swap in an object whose put_item raises.
        class _Boom:
            def put_item(self, **_kwargs):
                raise RuntimeError("billing table down")

        object.__setattr__(self._tables_mod.T, "billing", _Boom())
        try:
            # Must NOT raise.
            ss._mirror_creator_credit_to_billing(
                creator_id,
                500,
                currency="USD",
                created_at=1700000000,
                subscription_id="sub_fail",
                subscriber_id="subscriber_fail",
            )
        finally:
            object.__setattr__(self._tables_mod.T, "billing", self._table)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
