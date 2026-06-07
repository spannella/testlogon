"""Offline regression test for GAP-0364 (SYND-004 §3.3).

Bug: ``leave_syndicate`` (``app/services/syndicates.py``) removed the departing
member (and dissolved the syndicate when the last member left) WITHOUT issuing
any proportional treasury refund of the member's contributed funds. Members lost
their money on departure because ``refund_on_member_leave`` /
``refund_on_dissolution`` did not exist and were never called.

Fix: SYND-004 §3.3 requires ``refund_on_member_leave`` to run BEFORE the member
is removed and ``refund_on_dissolution`` to run before the syndicate dissolves.

This test is fully hermetic: real in-memory DynamoDB tables (moto) for the
``syndicate_treasury``, ``syndicates`` and ``billing`` tables are created and
bound onto the EXACT frozen ``T`` handles via ``object.__setattr__`` (restored
on cleanup). No real AWS / no network. The service functions are called directly.

Fails-before / passes-after:
  * refund_on_member_leave: member with no refund hook → wallet unchanged,
    treasury unchanged. After fix → wallet up by their proportional share,
    treasury down by the same.
  * leave_syndicate: previously issued no refund at all.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from app.core.tables import T
from app.services import syndicate_treasury as st
from app.services import syndicates as syn
from app.services.billing_shared import WALLET_SK, user_pk


def _make_pk_sk_table(ddb, name):
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


def _wallet_balance(table, user_id):
    resp = table.get_item(Key={"pk": user_pk(user_id), "sk": WALLET_SK})
    item = resp.get("Item") or {}
    return int(item.get("wallet_balance_cents", 0))


@unittest.skipIf(mock_aws is None, "moto not installed")
class SyndicateLeaveRefundTest(unittest.TestCase):
    def setUp(self):
        self._stack = ExitStack()
        self._aws = mock_aws()
        self._aws.start()
        self.addCleanup(self._aws.stop)

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.treasury = _make_pk_sk_table(ddb, "syndicate_treasury")
        self.syndicates = _make_pk_sk_table(ddb, "syndicates")
        self.billing = _make_pk_sk_table(ddb, "billing")

        # Bind onto the frozen T handles, restore afterwards.
        orig_t = T.syndicate_treasury
        orig_s = T.syndicates
        orig_b = T.billing
        object.__setattr__(T, "syndicate_treasury", self.treasury)
        object.__setattr__(T, "syndicates", self.syndicates)
        object.__setattr__(T, "billing", self.billing)
        self.addCleanup(lambda: object.__setattr__(T, "syndicate_treasury", orig_t))
        self.addCleanup(lambda: object.__setattr__(T, "syndicates", orig_s))
        self.addCleanup(lambda: object.__setattr__(T, "billing", orig_b))

    # --- seeding helpers ------------------------------------------------

    def _seed_syndicate(self, sid, admin, members):
        """Seed META + MEMBER rows. members = [user_id, ...] incl. admin."""
        self.syndicates.put_item(Item={
            "pk": f"SYND#{sid}", "sk": "META",
            "syndicate_id": sid, "name": "Test Syndicate",
            "admin_user_id": admin, "status": "active",
            "member_count": len(members), "GSI1PK": "STATUS#active",
        })
        for m in members:
            self.syndicates.put_item(Item={
                "pk": f"SYND#{sid}", "sk": f"MEMBER#{m}",
                "user_id": m, "role": "admin" if m == admin else "member",
                "joined_at": 1000,
            })
            self.syndicates.put_item(Item={
                "pk": f"USER_SYND#{m}", "sk": f"SYND#{sid}",
                "syndicate_id": sid, "role": "admin" if m == admin else "member",
                "joined_at": 1000,
            })

    def _seed_treasury(self, sid, balance_cents, contributions):
        """contributions = {user_id: net_contributed_cents}."""
        self.treasury.put_item(Item={
            "pk": f"TREASURY#{sid}", "sk": "BALANCE",
            "syndicate_id": sid, "balance_cents": balance_cents,
            "total_deposited_cents": sum(contributions.values()),
            "total_disbursed_cents": 0, "currency": "usd", "updated_at": 1000,
        })
        for uid, net in contributions.items():
            self.treasury.put_item(Item={
                "pk": f"TREASURY#{sid}", "sk": f"CONTRIB#{uid}",
                "user_id": uid, "total_contributed_cents": net,
                "total_refunded_cents": 0, "contribution_count": 1,
                "last_contribution_at": 1000,
            })

    # --- tests ----------------------------------------------------------

    def test_refund_on_member_leave_proportional(self):
        sid = "synd_a"
        # Alice net $50, Bob net $30; $20 spent → balance $60.
        self._seed_treasury(sid, 6000, {"alice": 5000, "bob": 3000})

        # Alice leaves: floor(6000 * 5000 / 8000) = floor(3750) = 3750.
        res = st.refund_on_member_leave(sid, "alice")
        self.assertEqual(res["refunded_cents"], 3750)

        # Alice's wallet credited.
        self.assertEqual(_wallet_balance(self.billing, "alice"), 3750)
        # Treasury decreased.
        self.assertEqual(st.get_treasury_balance(sid)["balance_cents"], 6000 - 3750)
        # Contribution tracker refund bumped (so net shrinks).
        mine = st.get_my_contributions(sid, "alice")
        self.assertEqual(mine["total_refunded_cents"], 3750)
        self.assertEqual(mine["net_contributed_cents"], 5000 - 3750)

    def test_refund_on_member_leave_zero_for_non_contributor(self):
        sid = "synd_b"
        self._seed_treasury(sid, 6000, {"alice": 5000})
        res = st.refund_on_member_leave(sid, "charlie")
        self.assertEqual(res["refunded_cents"], 0)
        self.assertEqual(_wallet_balance(self.billing, "charlie"), 0)
        self.assertEqual(st.get_treasury_balance(sid)["balance_cents"], 6000)

    def test_refund_on_member_leave_zero_when_empty_treasury(self):
        sid = "synd_c"
        self._seed_treasury(sid, 0, {"alice": 5000})
        res = st.refund_on_member_leave(sid, "alice")
        self.assertEqual(res["refunded_cents"], 0)
        self.assertEqual(_wallet_balance(self.billing, "alice"), 0)

    def test_refund_on_dissolution_refunds_all_and_zeros(self):
        sid = "synd_d"
        # Three contributors, balance $90.
        self._seed_treasury(sid, 9000, {"alice": 5000, "bob": 3000, "charlie": 2000})
        res = st.refund_on_dissolution(sid)

        # Everyone refunded; total == balance; treasury zeroed.
        self.assertEqual(res["total_refunded"], 9000)
        by_user = {r["user_id"]: r["refunded_cents"] for r in res["refunds"]}
        # floor(9000*5000/10000)=4500, floor(9000*3000/10000)=2700, remainder=1800.
        self.assertEqual(by_user["alice"], 4500)
        self.assertEqual(by_user["bob"], 2700)
        self.assertEqual(by_user["charlie"], 1800)
        self.assertEqual(_wallet_balance(self.billing, "alice"), 4500)
        self.assertEqual(_wallet_balance(self.billing, "bob"), 2700)
        self.assertEqual(_wallet_balance(self.billing, "charlie"), 1800)
        self.assertEqual(st.get_treasury_balance(sid)["balance_cents"], 0)

    def test_leave_syndicate_issues_refund(self):
        """End-to-end via leave_syndicate (fails-before: no refund at all)."""
        sid = "synd_e"
        self._seed_syndicate(sid, admin="alice", members=["alice", "bob"])
        self._seed_treasury(sid, 6000, {"alice": 5000, "bob": 3000})

        res = syn.leave_syndicate(syndicate_id=sid, user_id="alice")
        self.assertFalse(res["dissolved"])
        self.assertEqual(res["refund"]["refunded_cents"], 3750)
        self.assertEqual(_wallet_balance(self.billing, "alice"), 3750)
        self.assertEqual(st.get_treasury_balance(sid)["balance_cents"], 2250)
        # Bob promoted to admin (alice was admin).
        meta = self.syndicates.get_item(
            Key={"pk": f"SYND#{sid}", "sk": "META"}).get("Item")
        self.assertEqual(meta["admin_user_id"], "bob")

    def test_leave_syndicate_last_member_dissolves_and_refunds(self):
        """Last member leaving triggers dissolution refund of everything."""
        sid = "synd_f"
        # Single member alice, net $40, balance $40.
        self._seed_syndicate(sid, admin="alice", members=["alice"])
        self._seed_treasury(sid, 4000, {"alice": 4000})

        res = syn.leave_syndicate(syndicate_id=sid, user_id="alice")
        self.assertTrue(res["dissolved"])
        # Sole member: refund_on_member_leave pays her the whole balance first.
        self.assertEqual(res["refund"]["refunded_cents"], 4000)
        self.assertEqual(_wallet_balance(self.billing, "alice"), 4000)
        # Treasury fully drained; dissolution refund finds nothing left.
        self.assertEqual(st.get_treasury_balance(sid)["balance_cents"], 0)
        self.assertEqual(res["dissolution_refund"]["total_refunded"], 0)
        # Syndicate archived.
        meta = self.syndicates.get_item(
            Key={"pk": f"SYND#{sid}", "sk": "META"}).get("Item")
        self.assertEqual(meta["status"], "archived")


if __name__ == "__main__":
    unittest.main()
