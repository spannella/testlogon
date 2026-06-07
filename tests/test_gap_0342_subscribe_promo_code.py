"""Offline regression test for GAP-0342 (PROMO-001 second pass).

The platform promo-code system (``app/services/promo_codes.py``) was disconnected
from the only checkout flow that exists — the subscription ``subscribe`` handler in
``app/routers/subscription_server.py``. ``SubscribeIn`` only had the legacy
per-creator ``discount_code`` field; customers who entered a real promo code got no
discount and no redemption was ever recorded.

The fix adds an optional ``promo_code`` to ``SubscribeIn`` and wires
``promo_codes.validate_promo_code`` (before charge / TOCTOU guard) +
``promo_codes.redeem_promo_code`` (atomic conditional ``current_uses`` increment,
after charge) into the handler. ``promo_code`` takes precedence over the legacy
``discount_code`` and they do not stack.

Hermetic: moto provides in-memory ``PromoCodes`` + ``subscriptions`` tables bound to
the exact frozen ``T.promo_codes`` / ``T.subscriptions`` handles via
``object.__setattr__`` (restored on teardown). All heavy billing collaborators on
the router module are stubbed so no real Stripe / billing tables are touched. The
async ``subscribe`` coroutine is invoked directly on a fresh event loop (the FastAPI
TestClient is unusable in this repo).
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.tables import T
from app.services import promo_codes


CREATOR = "creator-uuid-0342"
SUBSCRIBER = "sub-uuid-0342"
PLAN_ID = "plan_0342"


def _make_promo_table(ddb):
    return ddb.create_table(
        TableName="PromoCodes",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "creator_scope", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "code_lookup_pk", "AttributeType": "S"},
            {"AttributeName": "code_lookup_sk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByCreatorCreatedAt",
                "KeySchema": [
                    {"AttributeName": "creator_scope", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByCodeString",
                "KeySchema": [
                    {"AttributeName": "code_lookup_pk", "KeyType": "HASH"},
                    {"AttributeName": "code_lookup_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_subscriptions_table(ddb):
    return ddb.create_table(
        TableName="subscriptions",
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


class _FakeRequest:
    """Minimal stand-in for fastapi.Request used by audit_event."""

    client = None
    headers: dict = {}

    def __init__(self):
        self.headers = {}


@unittest.skipIf(mock_aws is None, "moto not installed")
class SubscribePromoCodeTests(unittest.TestCase):
    def setUp(self):
        self._aws = mock_aws()
        self._aws.start()
        self._ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._promo_tbl = _make_promo_table(self._ddb)
        self._sub_tbl = _make_subscriptions_table(self._ddb)

        # Bind moto tables onto the exact frozen handles.
        self._orig_promo = T.promo_codes
        self._orig_sub = T.subscriptions
        object.__setattr__(T, "promo_codes", self._promo_tbl)
        object.__setattr__(T, "subscriptions", self._sub_tbl)

        # Seed an active subscription plan ($10.00/mo).
        from app.routers import subscription_server as ss

        self.ss = ss
        ss.ddb_put_item(
            {
                "pk": ss.pk_plan(PLAN_ID),
                "sk": "META",
                "plan_id": PLAN_ID,
                "creator_id": CREATOR,
                "name": "Test Plan",
                "price_cents": 1000,
                "currency": "usd",
                "interval": "month",
                "status": "active",
            }
        )

    def tearDown(self):
        object.__setattr__(T, "promo_codes", self._orig_promo)
        object.__setattr__(T, "subscriptions", self._orig_sub)
        self._aws.stop()

    # ── helpers ────────────────────────────────────────────────────

    def _seed_promo(self, code, discount_type="percentage", discount_value=20,
                    max_uses=0, **kw):
        item, err = promo_codes.create_promo_code(
            creator_id=CREATOR,
            code=code,
            discount_type=discount_type,
            discount_value=discount_value,
            applies_to=["subscription"],
            max_uses=max_uses,
            **kw,
        )
        self.assertIsNone(err, f"create_promo_code failed: {err}")
        return item

    def _stub_billing(self, stack):
        """Patch out every heavy collaborator the subscribe handler calls
        after price computation, so no real billing / Stripe runs."""
        ss = self.ss
        for name in (
            "record_billing_subscription",
            "save_invoice",
            "record_billing_payment",
            "record_billing_transaction",
            "save_ledger_entry",
            "_mirror_creator_credit_to_billing",
            "put_notification",
            "audit_event",
            "refresh_subscription_calendar_events",
            "_enforce_kyc_tier",
        ):
            stack.enter_context(patch.object(ss, name, lambda *a, **k: None))
        stack.enter_context(
            patch.object(
                ss,
                "emit_subscription_cycle_order_and_reconcile",
                lambda **k: {"order_id": "ord_stub"},
            )
        )
        stack.enter_context(
            patch.object(ss, "get_subscription_settings", lambda *a, **k: {})
        )
        stack.enter_context(
            patch.object(ss, "count_active_subscribers", lambda *a, **k: 1)
        )
        stack.enter_context(
            patch.object(ss, "attach_subscription_profiles", lambda sub: sub)
        )

    def _call_subscribe(self, body):
        ss = self.ss
        coro = ss.subscribe(
            plan_id=PLAN_ID,
            body=body,
            request=_FakeRequest(),
            x_user_id=SUBSCRIBER,
        )
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def _promo_current_uses(self, code_id):
        item = promo_codes.get_promo_code(code_id)
        return int(item.get("current_uses") or 0)

    # ── tests ──────────────────────────────────────────────────────

    def test_valid_percentage_promo_discounts_and_redeems(self):
        promo = self._seed_promo("SAVE20", "percentage", 20, max_uses=5)
        with ExitStack() as stack:
            self._stub_billing(stack)
            result = self._call_subscribe(self.ss.SubscribeIn(promo_code="SAVE20"))

        # 20% off $10.00 → $8.00 charged.
        self.assertEqual(int(result["price_cents"]), 800)
        # Redemption recorded (atomic increment ran).
        self.assertEqual(self._promo_current_uses(promo["code_id"]), 1)
        stats = promo_codes.get_promo_stats(promo["code_id"])
        self.assertEqual(stats["total_redemptions"], 1)
        self.assertEqual(stats["total_discount_cents"], 200)

    def test_fixed_amount_promo(self):
        promo = self._seed_promo("OFF3", "fixed_amount", 300)
        with ExitStack() as stack:
            self._stub_billing(stack)
            result = self._call_subscribe(self.ss.SubscribeIn(promo_code="OFF3"))
        self.assertEqual(int(result["price_cents"]), 700)  # $10 - $3
        self.assertEqual(self._promo_current_uses(promo["code_id"]), 1)

    def test_invalid_code_raises_400_and_no_charge(self):
        from fastapi import HTTPException

        with ExitStack() as stack:
            self._stub_billing(stack)
            with self.assertRaises(HTTPException) as ctx:
                self._call_subscribe(self.ss.SubscribeIn(promo_code="NOPE"))
        self.assertEqual(ctx.exception.status_code, 400)
        # No subscription persisted.
        items = self._sub_tbl.scan().get("Items", [])
        subs = [i for i in items if str(i.get("sk", "")).startswith("SUB#")
                or i.get("subscription_id")]
        self.assertEqual(subs, [])

    def test_exhausted_code_beyond_max_uses_raises_400(self):
        promo = self._seed_promo("ONE", "percentage", 10, max_uses=1)
        # First redemption consumes it.
        with ExitStack() as stack:
            self._stub_billing(stack)
            self._call_subscribe(self.ss.SubscribeIn(promo_code="ONE"))
        self.assertEqual(self._promo_current_uses(promo["code_id"]), 1)

        # A different subscriber tries again — usage limit hit at validation.
        from fastapi import HTTPException

        with ExitStack() as stack:
            self._stub_billing(stack)
            with patch.object(self.ss, "require_user", return_value="other-sub"):
                with self.assertRaises(HTTPException) as ctx:
                    self._call_subscribe(self.ss.SubscribeIn(promo_code="ONE"))
        self.assertEqual(ctx.exception.status_code, 400)
        # current_uses NOT incremented past max.
        self.assertEqual(self._promo_current_uses(promo["code_id"]), 1)

    def test_promo_takes_precedence_over_discount_code(self):
        """When both are supplied, promo wins and they do not stack."""
        promo = self._seed_promo("PREC50", "percentage", 50)
        with ExitStack() as stack:
            self._stub_billing(stack)
            result = self._call_subscribe(
                self.ss.SubscribeIn(promo_code="PREC50", discount_code="LEGACY")
            )
        # 50% off $10 → $5; legacy discount_code (which would 400 since it
        # doesn't exist) is never consulted.
        self.assertEqual(int(result["price_cents"]), 500)
        self.assertEqual(self._promo_current_uses(promo["code_id"]), 1)

    def test_no_promo_leaves_full_price(self):
        with ExitStack() as stack:
            self._stub_billing(stack)
            result = self._call_subscribe(self.ss.SubscribeIn())
        self.assertEqual(int(result["price_cents"]), 1000)


if __name__ == "__main__":
    unittest.main()
