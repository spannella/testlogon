"""Offline regression tests for GAP-0308 and GAP-0309 (MON-004).

Both gaps live in ``app/services/creator_payouts.py``.

GAP-0308 — ``get_available_balance`` summed *every* ``type=credit`` LEDGER entry
with no exclusion of reversed/chargedback credits or zero-amount entitlement
records, so refunded tips / chargedback subscriptions inflated the withdrawable
balance. The fix adds ``Attr("state").ne("reversed") & Attr("amount_cents").gt(0)``
to the FilterExpression (``ne`` is True on items with no ``state`` attr, so
legacy credits still count — backward compatible).

GAP-0309 — ``request_payout`` did ``_has_active_payout`` + balance checks then an
unconditional ``put_item``: two concurrent requests could both pass the checks
and both write, creating duplicate payouts that together exceed the balance. The
fix claims a per-user atomic "active payout" sentinel (conditional ``update_item``
with ``attribute_not_exists(active_payout_id)``) before writing, and releases it
when the payout reaches a terminal state.

Fully offline: real in-memory DynamoDB tables (moto) bound to the EXACT frozen
``T.creator_payouts`` / ``T.billing`` handles via ``object.__setattr__`` (restored
on cleanup). The service functions are called directly.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_creator_payouts_table(ddb):
    """Mirror scripts/local-ddb-init.py CreatorPayouts table (HASH=payout_id)."""
    return ddb.create_table(
        TableName="CreatorPayouts",
        KeySchema=[{"AttributeName": "payout_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "payout_id", "AttributeType": "S"},
            {"AttributeName": "user_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByUserCreatedAt",
                "KeySchema": [
                    {"AttributeName": "user_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByStatusCreatedAt",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_billing_table(ddb):
    """Mirror scripts/local-ddb-init.py billing table (HASH=pk, RANGE=sk)."""
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


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _PayoutTestBase(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.payouts_tbl = _make_creator_payouts_table(ddb)
        self.billing_tbl = _make_billing_table(ddb)

        from app.core.tables import T
        from app.core.settings import S

        self.svc = __import__(
            "app.services.creator_payouts", fromlist=["creator_payouts"]
        )
        self.T = T
        self.S = S

        # Bind moto tables to the EXACT frozen T handles; restore on cleanup.
        self._bind("creator_payouts", self.payouts_tbl)
        self._bind("billing", self.billing_tbl)

        # Deterministic hold period: 0 so seeded credits are immediately available.
        self._set_setting("payout_hold_period_seconds", 0)
        self._set_setting("payout_minimum_cents", 1000)

    def _bind(self, attr, table):
        orig = getattr(self.T, attr)
        object.__setattr__(self.T, attr, table)
        self.addCleanup(lambda a=attr, o=orig: object.__setattr__(self.T, a, o))

    def _set_setting(self, attr, value):
        orig = getattr(self.S, attr)
        object.__setattr__(self.S, attr, value)
        self.addCleanup(lambda a=attr, o=orig: object.__setattr__(self.S, a, o))

    def _seed_credit(self, user_id, sk, amount_cents, *, ctype="credit", state=None, ts=0):
        item = {"pk": f"USER#{user_id}", "sk": sk, "type": ctype, "amount_cents": amount_cents, "ts": ts}
        if state is not None:
            item["state"] = state
        self.billing_tbl.put_item(Item=item)


class TestGetAvailableBalanceGap0308(_PayoutTestBase):
    def test_reversed_and_zero_credits_excluded(self):
        """GAP-0308: reversed credits + zero-amount entitlements must NOT count.

        FAILS BEFORE FIX: the old FilterExpression was ``Attr("type").eq("credit")``
        only, so the reversed ($50) and the zero-amount entitlement credits were
        summed → available_cents = 15000 instead of 10000.
        PASSES AFTER FIX: only the two valid credits ($60 + $40) count.
        """
        uid = "creator_0308"
        self._seed_credit(uid, "LEDGER#001", 6000)                       # valid
        self._seed_credit(uid, "LEDGER#002", 4000)                       # valid
        self._seed_credit(uid, "LEDGER#003", 5000, state="reversed")     # chargedback
        self._seed_credit(uid, "LEDGER#004", 0)                          # entitlement
        self._seed_credit(uid, "LEDGER#005", 0, state="active")          # entitlement

        bal = self.svc.get_available_balance(uid)

        self.assertEqual(bal["available_cents"], 10000)
        self.assertEqual(bal["total_earned_cents"], 10000)

    def test_legacy_credit_without_state_still_counts(self):
        """Backward compat: credits with NO ``state`` attr must still count.

        ``Attr("state").ne("reversed")`` is True on items missing the attribute.
        """
        uid = "creator_0308_legacy"
        self._seed_credit(uid, "LEDGER#001", 7000)  # no state attr at all
        bal = self.svc.get_available_balance(uid)
        self.assertEqual(bal["available_cents"], 7000)

    def test_debit_entries_ignored(self):
        uid = "creator_0308_debit"
        self._seed_credit(uid, "LEDGER#001", 9000)
        self._seed_credit(uid, "LEDGER#002", 3000, ctype="debit")
        bal = self.svc.get_available_balance(uid)
        self.assertEqual(bal["available_cents"], 9000)


class TestRequestPayoutAtomicGap0309(_PayoutTestBase):
    def test_single_payout_succeeds_end_to_end(self):
        uid = "creator_0309_single"
        self._seed_credit(uid, "LEDGER#001", 50000)

        out = self.svc.request_payout(uid, 20000)
        self.assertEqual(out["status"], "requested")
        self.assertTrue(out["payout_id"].startswith("payout_"))

        # Sentinel claimed.
        st = self.payouts_tbl.get_item(
            Key={"payout_id": f"PAYOUT_STATE#{uid}"}
        ).get("Item")
        self.assertIsNotNone(st)
        self.assertEqual(st["active_payout_id"], out["payout_id"])

        # Listing must NOT surface the sentinel row.
        listing = self.svc.list_user_payouts(uid)
        self.assertEqual(len(listing["items"]), 1)
        self.assertEqual(listing["items"][0]["payout_id"], out["payout_id"])

    def test_concurrent_second_request_rejected(self):
        """GAP-0309: the race — claim the slot once, then a second request_payout
        must be rejected even though it independently passes the balance check.

        FAILS BEFORE FIX: no sentinel existed, so both requests wrote payouts.
        PASSES AFTER FIX: the first holds the atomic slot; the second's
        conditional claim fails → DUPLICATE_PAYOUT.
        """
        uid = "creator_0309_race"
        self._seed_credit(uid, "LEDGER#001", 100000)

        first = self.svc.request_payout(uid, 30000)
        self.assertEqual(first["status"], "requested")

        with self.assertRaises(ValueError) as ctx:
            self.svc.request_payout(uid, 30000)
        self.assertIn("DUPLICATE_PAYOUT", str(ctx.exception))

        # Only one real payout exists.
        real = [
            i for i in self.payouts_tbl.scan().get("Items", [])
            if i.get("record_kind") not in ("payout_method", "payout_state")
        ]
        self.assertEqual(len(real), 1)

    def test_sentinel_released_allows_new_payout_after_completion(self):
        uid = "creator_0309_complete"
        self._seed_credit(uid, "LEDGER#001", 100000)
        self._set_setting("dev_mode", True)

        first = self.svc.request_payout(uid, 20000)
        # Approve so the dev-mode complete path is taken (approved -> completed).
        self.svc.approve_payout(first["payout_id"], "admin_x")
        self.svc.complete_payout(first["payout_id"])

        # Sentinel released.
        st = self.payouts_tbl.get_item(
            Key={"payout_id": f"PAYOUT_STATE#{uid}"}
        ).get("Item")
        self.assertNotIn("active_payout_id", st or {})

        # A new payout can now be requested.
        second = self.svc.request_payout(uid, 20000)
        self.assertEqual(second["status"], "requested")
        self.assertNotEqual(second["payout_id"], first["payout_id"])

    def test_sentinel_released_allows_new_payout_after_cancel(self):
        uid = "creator_0309_cancel"
        self._seed_credit(uid, "LEDGER#001", 100000)

        first = self.svc.request_payout(uid, 20000)
        self.svc.cancel_payout(first["payout_id"], uid)

        st = self.payouts_tbl.get_item(
            Key={"payout_id": f"PAYOUT_STATE#{uid}"}
        ).get("Item")
        self.assertNotIn("active_payout_id", st or {})

        second = self.svc.request_payout(uid, 20000)
        self.assertEqual(second["status"], "requested")

    def test_sentinel_released_on_reject(self):
        uid = "creator_0309_reject"
        self._seed_credit(uid, "LEDGER#001", 100000)

        first = self.svc.request_payout(uid, 20000)
        self.svc.reject_payout(first["payout_id"], "admin_x", reason="nope")

        st = self.payouts_tbl.get_item(
            Key={"payout_id": f"PAYOUT_STATE#{uid}"}
        ).get("Item")
        self.assertNotIn("active_payout_id", st or {})

        # And a new one can be requested.
        second = self.svc.request_payout(uid, 20000)
        self.assertEqual(second["status"], "requested")

    def test_insufficient_balance_releases_slot(self):
        """A failed validation (insufficient balance) must release the slot so
        the creator can retry — i.e. the sentinel is not leaked."""
        uid = "creator_0309_insuff"
        self._seed_credit(uid, "LEDGER#001", 5000)  # only $50 available

        # Request more than the available balance → insufficient (slot claimed
        # then released on the validation failure).
        with self.assertRaises(ValueError) as ctx:
            self.svc.request_payout(uid, 99999)
        self.assertIn("Insufficient", str(ctx.exception))

        # Slot not leaked — sentinel has no active payout.
        st = self.payouts_tbl.get_item(
            Key={"payout_id": f"PAYOUT_STATE#{uid}"}
        ).get("Item")
        self.assertNotIn("active_payout_id", st or {})

        # A valid request now succeeds.
        out = self.svc.request_payout(uid, 4000)
        self.assertEqual(out["status"], "requested")


if __name__ == "__main__":
    unittest.main()
