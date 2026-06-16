"""Offline hermetic tests for the ticket-bounty escrow subsystem (TBT-001..009).

Covers the full lifecycle: post (atomic escrow hold) → claim → submit → approve
(escrow release → assignee) and the cancel/refund path, plus the bounty board
query and the flag-off 404 behavior.

Hermetic / offline (TEST ISOLATION):
* Real in-memory DynamoDB tables via moto (``mock_aws``) bound to the exact
  frozen ``T.billing`` / ``T.tickets`` handles through ``object.__setattr__``
  (``T`` is a frozen dataclass), restored on cleanup.
* ``transact_write_items`` runs against moto because ``_transact_client`` builds
  its low-level boto3 client INSIDE the ``mock_aws`` context (botocore-level
  interception covers it too).
* The frozen ``Settings`` singleton ``S`` is mutated via ``object.__setattr__``.
* ``audit_event`` / ``write_alert`` / ``fraud_detection`` are patched so no real
  AWS / network / alert writes occur.
* Route-handler coroutines are NOT used (handlers here are sync); service
  functions are called directly.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.settings import S
from app.core.tables import T
import app.services.tickets as tickets_mod
import app.services.ticket_bounties as tbm
from app.services.ticket_bounties import (
    TicketBountyError,
    post_bounty,
    claim_bounty,
    unclaim_bounty,
    submit_bounty,
    approve_bounty,
    reject_bounty,
    cancel_bounty,
    list_open_bounties,
)
from app.services import billing_shared as bs
from fastapi import HTTPException


def _make_billing_table(ddb):
    return ddb.create_table(
        TableName="billing",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_tickets_table(ddb):
    return ddb.create_table(
        TableName="tickets",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi_bounty_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_bounty_sk", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": S.tickets_bounty_index_name,
            "KeySchema": [
                {"AttributeName": "gsi_bounty_pk", "KeyType": "HASH"},
                {"AttributeName": "gsi_bounty_sk", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
    )


def _seed_wallet(billing, user_sub, balance):
    billing.put_item(Item={"pk": bs.user_pk(user_sub), "sk": bs.WALLET_SK,
                           "wallet_balance_cents": balance, "currency": "usd"})


def _wallet(billing, user_sub):
    return bs.get_wallet_balance(billing, bs.user_pk(user_sub))["wallet_balance_cents"]


class TicketBountyTests(unittest.TestCase):
    def setUp(self):
        if mock_aws is None:
            self.skipTest("moto not available")
        self._stack = ExitStack()
        self._stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.billing = _make_billing_table(ddb)
        self.tickets = _make_tickets_table(ddb)

        self._orig_billing = T.billing
        self._orig_tickets = T.tickets
        object.__setattr__(T, "billing", self.billing)
        object.__setattr__(T, "tickets", self.tickets)
        # TicketStore singleton + module S references resolve through T at call time,
        # but STORE._table was bound at import to the original handle — repoint it.
        self._orig_store_table = tickets_mod.STORE._table
        object.__setattr__(tickets_mod.STORE, "_table", self.tickets)

        self._orig_flag = S.ticket_bounties_enabled
        object.__setattr__(S, "ticket_bounties_enabled", True)

        # Patch best-effort side effects + fraud gate (allow by default).
        self._stack.enter_context(patch.object(tbm, "_audit", lambda *a, **k: None))
        self._stack.enter_context(patch.object(tbm, "_notify", lambda *a, **k: None))
        fd_patch = patch("app.services.fraud_detection.is_frozen", return_value=False)
        self._stack.enter_context(fd_patch)
        ev_patch = patch("app.services.fraud_detection.evaluate_transaction",
                         return_value={"action": "allow"})
        self._stack.enter_context(ev_patch)

    def tearDown(self):
        object.__setattr__(T, "billing", self._orig_billing)
        object.__setattr__(T, "tickets", self._orig_tickets)
        object.__setattr__(tickets_mod.STORE, "_table", self._orig_store_table)
        object.__setattr__(S, "ticket_bounties_enabled", self._orig_flag)
        self._stack.close()

    # -- helpers --
    def _new_ticket(self, owner="alice", subject="Need help"):
        t = tickets_mod.STORE.create_ticket(owner_sub=owner, subject=subject, description="please")
        return t["ticket_id"]

    # ----------------------------------------------------------------- TBT-001
    def test_flag_off_404(self):
        object.__setattr__(S, "ticket_bounties_enabled", False)
        tid = self._new_ticket()
        with self.assertRaises(HTTPException) as ctx:
            post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
        self.assertEqual(ctx.exception.status_code, 404)

    # ----------------------------------------------------------------- TBT-003
    def test_post_bounty_success(self):
        tid = self._new_ticket()
        _seed_wallet(self.billing, "alice", 1000)
        t = post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
        self.assertEqual(t["bounty_status"], "funded")
        self.assertEqual(t["bounty_amount_cents"], 500)
        self.assertEqual(_wallet(self.billing, "alice"), 500)
        bid = t["bounty_id"]
        escrow = self.billing.get_item(Key={"pk": f"BOUNTY#{bid}", "sk": "ESCROW"})["Item"]
        self.assertEqual(escrow["escrow_status"], "held")
        self.assertEqual(int(escrow["amount_cents"]), 500)
        # ledger debit, signed negative
        items = self.billing.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
            ExpressionAttributeValues={":pk": bs.user_pk("alice"), ":p": "LEDGER#"},
        )["Items"]
        debits = [i for i in items if i.get("reason") == "bounty_escrow"]
        self.assertEqual(len(debits), 1)
        self.assertEqual(debits[0]["state"], "pending")
        self.assertEqual(int(debits[0]["signed_amount_cents"]), -500)

    def test_post_bounty_insufficient_balance(self):
        tid = self._new_ticket()
        _seed_wallet(self.billing, "alice", 100)
        with self.assertRaises(HTTPException) as ctx:
            post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
        self.assertEqual(ctx.exception.status_code, 402)
        self.assertEqual(_wallet(self.billing, "alice"), 100)

    def test_post_bounty_no_wallet(self):
        tid = self._new_ticket()
        with self.assertRaises(HTTPException) as ctx:
            post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
        self.assertEqual(ctx.exception.status_code, 402)

    def test_post_bounty_not_owner(self):
        tid = self._new_ticket(owner="alice")
        _seed_wallet(self.billing, "bob", 1000)
        with self.assertRaises(HTTPException) as ctx:
            post_bounty(ticket_id=tid, poster_sub="bob", amount_cents=500)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_post_bounty_below_min(self):
        tid = self._new_ticket()
        _seed_wallet(self.billing, "alice", 1000)
        with self.assertRaises(HTTPException) as ctx:
            post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=10)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_post_bounty_idempotent(self):
        tid = self._new_ticket()
        _seed_wallet(self.billing, "alice", 1000)
        post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
        # Second post: ticket is already funded → 409 (not a second debit).
        with self.assertRaises(HTTPException) as ctx:
            post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(_wallet(self.billing, "alice"), 500)

    def test_post_bounty_frozen(self):
        tid = self._new_ticket()
        _seed_wallet(self.billing, "alice", 1000)
        with patch("app.services.fraud_detection.is_frozen", return_value=True):
            with self.assertRaises(HTTPException) as ctx:
                post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(_wallet(self.billing, "alice"), 1000)

    def test_post_bounty_gsi_keys_set(self):
        tid = self._new_ticket()
        _seed_wallet(self.billing, "alice", 1000)
        post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
        meta = self.tickets.get_item(Key={"pk": f"TICKET#{tid}", "sk": "META"})["Item"]
        self.assertEqual(meta["gsi_bounty_pk"], "BOUNTY#OPEN")
        self.assertEqual(int(meta["gsi_bounty_sk"]), int(meta["created_at"]))

    # ----------------------------------------------------------------- TBT-005
    def _fund(self, owner="alice", amount=500, balance=1000):
        tid = self._new_ticket(owner=owner)
        _seed_wallet(self.billing, owner, balance)
        post_bounty(ticket_id=tid, poster_sub=owner, amount_cents=amount)
        return tid

    def test_claim_success(self):
        tid = self._fund()
        t = claim_bounty(ticket_id=tid, claimer_sub="bob")
        self.assertEqual(t["bounty_status"], "claimed")
        self.assertEqual(t["status"], "in_progress")
        self.assertEqual(t["claimed_by_sub"], "bob")
        meta = self.tickets.get_item(Key={"pk": f"TICKET#{tid}", "sk": "META"})["Item"]
        self.assertNotIn("gsi_bounty_pk", meta)

    def test_double_claim_409(self):
        tid = self._fund()
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        with self.assertRaises(TicketBountyError) as ctx:
            claim_bounty(ticket_id=tid, claimer_sub="carol")
        self.assertIn(ctx.exception.http_status, (409,))

    def test_claim_non_funded(self):
        tid = self._new_ticket()
        with self.assertRaises(TicketBountyError) as ctx:
            claim_bounty(ticket_id=tid, claimer_sub="bob")
        self.assertEqual(ctx.exception.code, "bounty_not_funded")

    def test_unclaim_restores_board(self):
        tid = self._fund()
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        t = unclaim_bounty(ticket_id=tid, claimer_sub="bob")
        self.assertEqual(t["bounty_status"], "funded")
        self.assertEqual(t["status"], "open")
        meta = self.tickets.get_item(Key={"pk": f"TICKET#{tid}", "sk": "META"})["Item"]
        self.assertEqual(meta["gsi_bounty_pk"], "BOUNTY#OPEN")

    def test_unclaim_wrong_caller(self):
        tid = self._fund()
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        with self.assertRaises(TicketBountyError) as ctx:
            unclaim_bounty(ticket_id=tid, claimer_sub="carol")
        self.assertEqual(ctx.exception.code, "not_claimant")

    # ----------------------------------------------------------------- TBT-006
    def test_submit_sets_pending_approval(self):
        tid = self._fund()
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        t = submit_bounty(ticket_id=tid, claimer_sub="bob")
        self.assertEqual(t["bounty_status"], "submitted")
        self.assertEqual(t["status"], "pending_approval")

    def test_submit_wrong_caller(self):
        tid = self._fund()
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        with self.assertRaises(TicketBountyError) as ctx:
            submit_bounty(ticket_id=tid, claimer_sub="carol")
        self.assertEqual(ctx.exception.code, "not_claimant")

    def test_approve_credits_assignee_once(self):
        tid = self._fund(amount=500)
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        submit_bounty(ticket_id=tid, claimer_sub="bob")
        t = approve_bounty(ticket_id=tid, admin_sub="root")
        self.assertEqual(t["bounty_status"], "paid_out")
        self.assertEqual(t["status"], "paid_out")
        self.assertEqual(_wallet(self.billing, "bob"), 500)
        # exactly one payout credit, signed positive
        items = self.billing.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
            ExpressionAttributeValues={":pk": bs.user_pk("bob"), ":p": "LEDGER#"},
        )["Items"]
        credits = [i for i in items if i.get("reason") == "bounty_payout"]
        self.assertEqual(len(credits), 1)
        self.assertEqual(int(credits[0]["signed_amount_cents"]), 500)
        # poster debit settled (not reversed)
        bid = t["bounty_id"]
        escrow = self.billing.get_item(Key={"pk": f"BOUNTY#{bid}", "sk": "ESCROW"})["Item"]
        self.assertEqual(escrow["escrow_status"], "released")

    def test_approve_idempotent(self):
        tid = self._fund(amount=500)
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        submit_bounty(ticket_id=tid, claimer_sub="bob")
        approve_bounty(ticket_id=tid, admin_sub="root")
        approve_bounty(ticket_id=tid, admin_sub="root")  # no-op
        self.assertEqual(_wallet(self.billing, "bob"), 500)
        items = self.billing.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
            ExpressionAttributeValues={":pk": bs.user_pk("bob"), ":p": "LEDGER#"},
        )["Items"]
        credits = [i for i in items if i.get("reason") == "bounty_payout"]
        self.assertEqual(len(credits), 1)

    def test_approve_wrong_state(self):
        tid = self._fund()
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        with self.assertRaises(TicketBountyError) as ctx:
            approve_bounty(ticket_id=tid, admin_sub="root")
        self.assertEqual(ctx.exception.code, "bounty_wrong_state")

    def test_fee_nonzero(self):
        orig_fee = S.ticket_bounty_fee_bps
        object.__setattr__(S, "ticket_bounty_fee_bps", 500)  # 5%
        try:
            tid = self._fund(amount=1000)
            claim_bounty(ticket_id=tid, claimer_sub="bob")
            submit_bounty(ticket_id=tid, claimer_sub="bob")
            approve_bounty(ticket_id=tid, admin_sub="root")
            self.assertEqual(_wallet(self.billing, "bob"), 950)
            fee_items = self.billing.query(
                KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
                ExpressionAttributeValues={":pk": "PLATFORM#ESCROW", ":p": "LEDGER#"},
            )["Items"]
            self.assertEqual(len(fee_items), 1)
            self.assertEqual(int(fee_items[0]["amount_cents"]), 50)
        finally:
            object.__setattr__(S, "ticket_bounty_fee_bps", orig_fee)

    def test_reject_returns_to_in_progress(self):
        tid = self._fund()
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        submit_bounty(ticket_id=tid, claimer_sub="bob")
        t = reject_bounty(ticket_id=tid, admin_sub="root", reason="needs work")
        self.assertEqual(t["bounty_status"], "claimed")
        self.assertEqual(t["status"], "in_progress")
        bid = t["bounty_id"]
        escrow = self.billing.get_item(Key={"pk": f"BOUNTY#{bid}", "sk": "ESCROW"})["Item"]
        self.assertEqual(escrow["escrow_status"], "held")  # money untouched

    def test_reject_then_resubmit_then_approve(self):
        tid = self._fund(amount=700)
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        submit_bounty(ticket_id=tid, claimer_sub="bob")
        reject_bounty(ticket_id=tid, admin_sub="root", reason="fix it")
        submit_bounty(ticket_id=tid, claimer_sub="bob")
        t = approve_bounty(ticket_id=tid, admin_sub="root")
        self.assertEqual(t["bounty_status"], "paid_out")
        self.assertEqual(_wallet(self.billing, "bob"), 700)

    # ----------------------------------------------------------------- TBT-007
    def test_cancel_funded_by_poster(self):
        tid = self._fund(amount=500)
        self.assertEqual(_wallet(self.billing, "alice"), 500)
        t = cancel_bounty(ticket_id=tid, actor_sub="alice", reason="changed mind", is_admin=False)
        self.assertEqual(t["bounty_status"], "cancelled")
        self.assertEqual(t["status"], "cancelled")
        self.assertEqual(_wallet(self.billing, "alice"), 1000)  # full refund
        bid = t["bounty_id"]
        escrow = self.billing.get_item(Key={"pk": f"BOUNTY#{bid}", "sk": "ESCROW"})["Item"]
        self.assertEqual(escrow["escrow_status"], "refunded")
        # original debit reversed; refund adjustment present + signed positive
        items = self.billing.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
            ExpressionAttributeValues={":pk": bs.user_pk("alice"), ":p": "LEDGER#"},
        )["Items"]
        debit = [i for i in items if i.get("reason") == "bounty_escrow"][0]
        refund = [i for i in items if i.get("reason") == "bounty_refund"][0]
        self.assertEqual(debit["state"], "reversed")
        self.assertEqual(refund["type"], "adjustment")
        self.assertEqual(int(refund["signed_amount_cents"]), 500)

    def test_cancel_double_is_noop(self):
        tid = self._fund(amount=500)
        cancel_bounty(ticket_id=tid, actor_sub="alice", reason="x", is_admin=False)
        cancel_bounty(ticket_id=tid, actor_sub="alice", reason="x", is_admin=False)
        self.assertEqual(_wallet(self.billing, "alice"), 1000)  # credited once

    def test_cancel_admin_after_claim(self):
        tid = self._fund(amount=500)
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        t = cancel_bounty(ticket_id=tid, actor_sub="root", reason="abuse", is_admin=True)
        self.assertEqual(t["bounty_status"], "cancelled")
        self.assertEqual(_wallet(self.billing, "alice"), 1000)

    def test_poster_cannot_cancel_after_claim(self):
        tid = self._fund(amount=500)
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        with self.assertRaises(TicketBountyError) as ctx:
            cancel_bounty(ticket_id=tid, actor_sub="alice", reason="x", is_admin=False)
        self.assertEqual(ctx.exception.code, "poster_cannot_cancel_after_claim")

    def test_cancel_after_paid_out_409(self):
        tid = self._fund(amount=500)
        claim_bounty(ticket_id=tid, claimer_sub="bob")
        submit_bounty(ticket_id=tid, claimer_sub="bob")
        approve_bounty(ticket_id=tid, admin_sub="root")
        with self.assertRaises(TicketBountyError) as ctx:
            cancel_bounty(ticket_id=tid, actor_sub="root", reason="x", is_admin=True)
        self.assertEqual(ctx.exception.code, "bounty_already_paid_out")

    def test_cancel_non_owner_non_admin_403(self):
        tid = self._fund(amount=500)
        with self.assertRaises(TicketBountyError) as ctx:
            cancel_bounty(ticket_id=tid, actor_sub="carol", reason="x", is_admin=False)
        self.assertEqual(ctx.exception.code, "forbidden")

    def test_cancel_then_repost(self):
        tid = self._fund(amount=500)
        first_bid = tickets_mod.STORE.get_ticket(tid)["bounty_id"]
        cancel_bounty(ticket_id=tid, actor_sub="alice", reason="x", is_admin=False)
        # repost: needs status back to open (cancel set it to cancelled). The
        # service requires status=="open"; flip it to simulate a fresh open ticket.
        self.tickets.update_item(
            Key={"pk": f"TICKET#{tid}", "sk": "META"},
            UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "open"},
        )
        _seed_wallet(self.billing, "alice", 1000)
        t = post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
        self.assertEqual(t["bounty_status"], "funded")
        self.assertNotEqual(t["bounty_id"], first_bid)  # collision-free repost id
        self.assertEqual(t["bounty_repost_count"], 1)

    # ----------------------------------------------------------------- TBT-008
    def test_list_open_bounties_newest_first(self):
        ids = []
        _seed_wallet(self.billing, "alice", 100000)
        for i in range(3):
            tid = self._new_ticket(owner="alice", subject=f"t{i}")
            # stagger created_at via direct update so ordering is deterministic
            self.tickets.update_item(
                Key={"pk": f"TICKET#{tid}", "sk": "META"},
                UpdateExpression="SET created_at = :c",
                ExpressionAttributeValues={":c": 1000 + i},
            )
            post_bounty(ticket_id=tid, poster_sub="alice", amount_cents=500)
            ids.append(tid)
        result = list_open_bounties(limit=25)
        got = [b["ticket_id"] for b in result["items"]]
        self.assertEqual(got, list(reversed(ids)))  # newest created_at first

    def test_list_open_bounties_excludes_claimed(self):
        _seed_wallet(self.billing, "alice", 100000)
        tid1 = self._new_ticket(owner="alice", subject="open")
        post_bounty(ticket_id=tid1, poster_sub="alice", amount_cents=500)
        tid2 = self._new_ticket(owner="alice", subject="claimed")
        post_bounty(ticket_id=tid2, poster_sub="alice", amount_cents=500)
        claim_bounty(ticket_id=tid2, claimer_sub="bob")
        result = list_open_bounties(limit=25)
        got = {b["ticket_id"] for b in result["items"]}
        self.assertIn(tid1, got)
        self.assertNotIn(tid2, got)

    def test_list_empty_board(self):
        result = list_open_bounties(limit=25)
        self.assertEqual(result["items"], [])

    def test_list_flag_off_404(self):
        object.__setattr__(S, "ticket_bounties_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            list_open_bounties(limit=25)
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
