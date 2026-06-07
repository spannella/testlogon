"""Offline regression tests for GAP-0219 (GROUP-004).

``app/services/group_treasury.dissolve_treasury`` used to distribute treasury
funds via a sequence of independent ``put_item`` / ``update_item`` calls, zeroing
the balance only as the very last write. A failure mid-distribution left a
partially-distributed treasury with a non-zero balance, and a retry re-credited
everyone who had already been refunded (double-credit). There was no idempotency
guard against running twice.

The fix:
  * a conditional ``dissolution_state`` marker (``_begin_dissolution``) that
    raises 409 on a second/concurrent run,
  * ``TransactWriteItems`` batches so each contributor's wallet credit + both
    ledger entries commit atomically,
  * a saga checkpoint (``dissolution_completed_user_ids``) so a resumed run skips
    already-refunded contributors (no double credit),
  * the treasury-zero committed in the SAME final transaction as escrow.

Test isolation (per task rules): we do NOT depend on global moto interception
leaking everywhere. We create one in-memory billing table with moto and patch
the exact frozen ``T.billing`` handle (via ``object.__setattr__``) used by both
``group_treasury`` and ``billing_shared``. Every DDB op in the code under test —
including ``transact_write_items`` via ``T.billing.meta.client`` — flows through
that single patched handle while the ``mock_aws`` context is active. Functions
are called directly; no FastAPI TestClient, no real AWS.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_billing_table(ddb):
    """Create the billing table mirroring scripts/local-ddb-init.py (pk/sk)."""
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
class TestDissolveTreasuryAtomic(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        raw_table = _make_billing_table(ddb)

        from app.core.tables import T, _FloatSafeTable
        from app.services import group_treasury
        from app.services import billing_shared

        self.T = T
        self.gt = group_treasury
        self.billing_shared = billing_shared

        # Wrap exactly like production (_safe_table) so writes coerce floats and
        # .meta / .name / .query / .put_item / .update_item all delegate.
        wrapped = _FloatSafeTable(raw_table)

        # T is a frozen dataclass — set the field via object.__setattr__.
        self._orig_billing = T.billing
        object.__setattr__(T, "billing", wrapped)
        self.addCleanup(lambda: object.__setattr__(T, "billing", self._orig_billing))

        self.table = wrapped

    # -- seed helpers -------------------------------------------------------

    def _seed_treasury(self, group_id, balance, total_contributed, total_donated=0):
        self.table.put_item(Item={
            "pk": f"GROUP#{group_id}",
            "sk": "WALLET",
            "wallet_balance_cents": balance,
            "currency": "usd",
            "total_contributed_cents": total_contributed,
            "total_donated_cents": total_donated,
            "total_spent_cents": 0,
        })

    def _seed_contributor(self, group_id, uid, contributed):
        self.table.put_item(Item={
            "pk": f"GROUP#{group_id}",
            "sk": f"CONTRIB#{uid}",
            "user_id": uid,
            "total_contributed_cents": contributed,
        })

    def _wallet(self, uid):
        return self.billing_shared.get_wallet_balance(
            self.T.billing, self.billing_shared.user_pk(uid)
        )["wallet_balance_cents"]

    # -- tests --------------------------------------------------------------

    def test_balance_zeroed_and_marked_complete(self):
        """After a clean dissolution the treasury balance is 0 and marked complete."""
        gid = "g_zero"
        self._seed_treasury(gid, balance=3000, total_contributed=3000)
        self._seed_contributor(gid, "u1", 2000)
        self._seed_contributor(gid, "u2", 1000)

        result = self.gt.dissolve_treasury(gid)
        self.assertTrue(result["ok"])
        self.assertEqual(self.gt.get_treasury_balance(gid)["balance_cents"], 0)

        row = self.table.get_item(Key={"pk": f"GROUP#{gid}", "sk": "WALLET"})["Item"]
        self.assertEqual(row.get("dissolution_state"), "complete")

    def test_pro_rata_credits_each_contributor_once(self):
        """Each contributor is credited their pro-rata share exactly once."""
        gid = "g_prorata"
        self._seed_treasury(gid, balance=3000, total_contributed=3000)
        self._seed_contributor(gid, "u1", 2000)
        self._seed_contributor(gid, "u2", 1000)

        self.assertEqual(self._wallet("u1"), 0)
        self.assertEqual(self._wallet("u2"), 0)

        self.gt.dissolve_treasury(gid)

        # contribution_remaining = 3000 (all contributed). Shares 2/3 and 1/3.
        self.assertEqual(self._wallet("u1"), 2000)
        self.assertEqual(self._wallet("u2"), 1000)

    def test_no_double_credit_on_retry(self):
        """A second dissolve call must NOT re-credit contributors.

        FAILS BEFORE FIX: the old code had no marker; if the treasury still read
        non-zero on a retry it re-credited everyone. PASSES AFTER FIX: balance is
        zeroed atomically in the final transaction, and the early-return /
        dissolution_state marker block any re-distribution.
        """
        gid = "g_retry"
        self._seed_treasury(gid, balance=3000, total_contributed=3000)
        self._seed_contributor(gid, "u1", 2000)
        self._seed_contributor(gid, "u2", 1000)

        self.gt.dissolve_treasury(gid)
        after_first = {"u1": self._wallet("u1"), "u2": self._wallet("u2")}

        # Retry — balance is now 0 so it must early-return without crediting.
        retry = self.gt.dissolve_treasury(gid)
        self.assertEqual(retry["refunded_count"], 0)
        self.assertEqual({"u1": self._wallet("u1"), "u2": self._wallet("u2")}, after_first)

    def test_marker_blocks_rerun_when_balance_still_nonzero(self):
        """If the treasury is still marked in_progress with a non-zero balance,
        a fresh dissolve attempt is rejected with 409 (no double-credit window).

        This simulates a crash AFTER contributors were credited but BEFORE the
        treasury-zero — exactly the GAP-0219 partial-state failure mode.
        """
        from fastapi import HTTPException

        gid = "g_marker"
        self._seed_treasury(gid, balance=3000, total_contributed=3000)
        self._seed_contributor(gid, "u1", 3000)

        # Force the partial-crash state: marker stuck in_progress, balance non-zero.
        self.table.update_item(
            Key={"pk": f"GROUP#{gid}", "sk": "WALLET"},
            UpdateExpression="SET dissolution_state = :s, wallet_balance_cents = :b",
            ExpressionAttributeValues={":s": "in_progress", ":b": 3000},
        )

        with self.assertRaises(HTTPException) as ctx:
            self.gt.dissolve_treasury(gid)
        self.assertEqual(ctx.exception.status_code, 409)

        # Contributor was NOT credited a second time.
        self.assertEqual(self._wallet("u1"), 0)

    def test_saga_resume_skips_already_refunded(self):
        """A resumed dissolution skips contributors already in the saga checkpoint.

        Pre-seed dissolution_completed_user_ids=[u1] and clear the in-progress
        marker (so _begin_dissolution allows a resume). u1 must NOT be credited a
        second time; u2 (not yet done) is credited.
        """
        gid = "g_saga"
        self._seed_treasury(gid, balance=3000, total_contributed=3000)
        self._seed_contributor(gid, "u1", 2000)
        self._seed_contributor(gid, "u2", 1000)

        # Simulate: u1 already refunded in a prior partial run (wallet + checkpoint).
        self.table.update_item(
            Key={"pk": self.billing_shared.user_pk("u1"), "sk": "WALLET"},
            UpdateExpression="SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :d, updated_at = :t",
            ExpressionAttributeValues={":z": 0, ":d": 2000, ":t": 1},
        )
        self.table.update_item(
            Key={"pk": f"GROUP#{gid}", "sk": "WALLET"},
            UpdateExpression="SET dissolution_completed_user_ids = :u, dissolution_state = :n",
            ExpressionAttributeValues={":u": ["u1"], ":n": "none"},
        )

        self.gt.dissolve_treasury(gid)

        # u1 stays at its single 2000 credit (NOT 4000); u2 gets its 1000.
        self.assertEqual(self._wallet("u1"), 2000)
        self.assertEqual(self._wallet("u2"), 1000)
        self.assertEqual(self.gt.get_treasury_balance(gid)["balance_cents"], 0)

    def test_escrow_receives_donation_share(self):
        """Donation share + rounding remainder goes to PLATFORM#ESCROW atomically."""
        gid = "g_escrow"
        # 1000 total, half contributed half donated -> ~500 refund, ~500 escrow.
        self._seed_treasury(gid, balance=1000, total_contributed=1000, total_donated=1000)
        self._seed_contributor(gid, "u1", 1000)

        self.gt.dissolve_treasury(gid)

        escrow = self.billing_shared.get_wallet_balance(
            self.T.billing, "PLATFORM#ESCROW"
        )["wallet_balance_cents"]
        self.assertEqual(self._wallet("u1"), 500)
        self.assertEqual(escrow, 500)
        self.assertEqual(self.gt.get_treasury_balance(gid)["balance_cents"], 0)

    def test_large_group_batched_atomically(self):
        """More than one TransactWrite batch (>8 contributors) all credit once."""
        gid = "g_large"
        n = 20
        per = 100
        total = n * per
        self._seed_treasury(gid, balance=total, total_contributed=total)
        for i in range(n):
            self._seed_contributor(gid, f"u{i}", per)

        result = self.gt.dissolve_treasury(gid)
        self.assertEqual(result["refunded_count"], n)
        for i in range(n):
            self.assertEqual(self._wallet(f"u{i}"), per)
        self.assertEqual(self.gt.get_treasury_balance(gid)["balance_cents"], 0)


if __name__ == "__main__":
    unittest.main()
