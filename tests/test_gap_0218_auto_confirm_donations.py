"""Offline regression test for GAP-0218 (GROUP-003).

GAP-0218 — ``app/services/group_fundraising.py`` hardcoded
``_AUTO_CONFIRM_DONATIONS = True`` at module level, so EVERY donation (including
declined / fraudulent payments) was confirmed synchronously in
``create_donation`` and the group treasury credited, in production, without ever
waiting for a real Stripe ``payment_intent.succeeded`` webhook.

The fix gates auto-confirm on ``S.dev_mode`` (via ``_auto_confirm_donations()``):

* dev_mode=True  → donation auto-confirms (stripe-mock cannot complete
  off-session payments; determinism needed for e2e/dev) — unchanged behaviour.
* dev_mode=False (prod) → donation stays ``pending``; treasury NOT credited until
  a verified Stripe webhook (or the ROOT break-glass endpoint) calls
  ``confirm_donation`` / ``confirm_donation_by_payment_intent``.

Test isolation rules (per task): NO reliance on global moto interception leaking
to real AWS. We create real in-memory moto DynamoDB tables and monkeypatch the
exact frozen ``T`` handles (``T.group_fundraising_campaigns`` and ``T.billing``,
both used by the donation + treasury credit path) via ``object.__setattr__``.
``S`` is frozen too, so ``S.dev_mode`` is flipped via ``object.__setattr__`` and
restored in tearDown. No FastAPI TestClient — service functions are called
directly. Mirrors ``tests/test_gap_0176_0177_org_service.py``.

FAILS BEFORE FIX: with dev_mode=False the old unconditional
``_AUTO_CONFIRM_DONATIONS = True`` confirms the donation immediately, so
``status == "completed"`` and the treasury is already credited.
PASSES AFTER FIX: donation stays ``pending`` and the treasury is untouched until
confirm is called.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_simple_table(ddb, name: str):
    """pk(S)/sk(S) table mirroring scripts/local-ddb-init.py for both the
    fundraising-campaigns table and the billing (treasury) table."""
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
class TestAutoConfirmDonationsGap0218(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # moto is used ONLY to back the two table handles we explicitly patch;
        # nothing in the code under test resolves AWS clients globally.
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.fundraising_table = _make_simple_table(ddb, "group_fundraising_campaigns")
        self.billing_table = _make_simple_table(ddb, "billing")

        from app.core.settings import S
        from app.core.tables import T
        from app.services import group_fundraising as gf
        from app.services import group_treasury as gt

        self.S = S
        self.T = T
        self.gf = gf
        self.gt = gt

        # Patch the exact frozen table handles used by BOTH the donation path
        # (group_fundraising) and the treasury credit path (group_treasury).
        self._orig_fundraising = T.group_fundraising_campaigns
        self._orig_billing = T.billing
        object.__setattr__(T, "group_fundraising_campaigns", self.fundraising_table)
        object.__setattr__(T, "billing", self.billing_table)
        self.addCleanup(
            lambda: object.__setattr__(T, "group_fundraising_campaigns", self._orig_fundraising)
        )
        self.addCleanup(lambda: object.__setattr__(T, "billing", self._orig_billing))

        # S is frozen — flip dev_mode via object.__setattr__, restore on cleanup.
        self._orig_dev_mode = S.dev_mode
        self.addCleanup(lambda: object.__setattr__(S, "dev_mode", self._orig_dev_mode))

    # -- helpers -----------------------------------------------------------
    def _set_dev_mode(self, value: bool) -> None:
        object.__setattr__(self.S, "dev_mode", value)

    def _seed_fundraiser(self, group_id: str, fundraiser_id: str, *, goal_cents=None):
        ts = 1_000_000
        item = {
            "pk": f"GROUP#{group_id}",
            "sk": f"FUNDRAISER#{fundraiser_id}",
            "record_type": "fundraiser",
            "fundraiser_id": fundraiser_id,
            "group_id": group_id,
            "title": "Test Fundraiser",
            "raised_cents": 0,
            "donation_count": 0,
            "currency": "usd",
            "status": "active",
            "created_at": ts,
        }
        if goal_cents is not None:
            item["goal_cents"] = goal_cents
        self.fundraising_table.put_item(Item=item)
        # Pointer record so create_donation can resolve fundraiser by id alone.
        self.fundraising_table.put_item(
            Item={
                "pk": f"FUNDRAISER#{fundraiser_id}",
                "sk": "META",
                "record_type": "fundraiser_ptr",
                "fundraiser_id": fundraiser_id,
                "group_id": group_id,
                "created_at": ts,
            }
        )

    def _treasury_balance(self, group_id: str) -> int:
        return int(self.gt.get_treasury_balance(group_id)["balance_cents"])

    def _raised_cents(self, group_id: str, fundraiser_id: str) -> int:
        item = self.fundraising_table.get_item(
            Key={"pk": f"GROUP#{group_id}", "sk": f"FUNDRAISER#{fundraiser_id}"}
        )["Item"]
        return int(item.get("raised_cents", 0))

    # -- tests -------------------------------------------------------------
    def test_prod_donation_stays_pending_treasury_not_credited(self):
        """GAP-0218 core: in prod (dev_mode=False) the treasury must NOT be
        credited at donation-creation time.

        FAILS BEFORE FIX: _AUTO_CONFIRM_DONATIONS=True → status 'completed',
        treasury credited 5000.
        PASSES AFTER FIX: status 'pending', treasury 0, raised_cents 0.
        """
        self._set_dev_mode(False)
        group_id, fundraiser_id = "g_prod", "fr_prod1"
        self._seed_fundraiser(group_id, fundraiser_id)

        before = self._treasury_balance(group_id)
        out = self.gf.create_donation(fundraiser_id=fundraiser_id, amount_cents=5000)

        self.assertEqual(out["status"], "pending")
        self.assertEqual(self._treasury_balance(group_id), before)
        self.assertEqual(self._raised_cents(group_id, fundraiser_id), 0)

    def test_dev_donation_auto_confirms_and_credits(self):
        """Dev behaviour preserved: in dev_mode the donation auto-confirms and
        the treasury is credited synchronously (stripe-mock compatibility)."""
        self._set_dev_mode(True)
        group_id, fundraiser_id = "g_dev", "fr_dev1"
        self._seed_fundraiser(group_id, fundraiser_id)

        out = self.gf.create_donation(fundraiser_id=fundraiser_id, amount_cents=2500)

        self.assertEqual(out["status"], "completed")
        self.assertEqual(self._treasury_balance(group_id), 2500)
        self.assertEqual(self._raised_cents(group_id, fundraiser_id), 2500)

    def test_prod_webhook_confirm_credits_treasury(self):
        """After a (verified) Stripe webhook, confirm_donation_by_payment_intent
        credits the treasury for the previously-pending donation."""
        self._set_dev_mode(False)
        group_id, fundraiser_id = "g_wh", "fr_wh1"
        self._seed_fundraiser(group_id, fundraiser_id)

        out = self.gf.create_donation(fundraiser_id=fundraiser_id, amount_cents=4200)
        donation_id = out["donation_id"]
        self.assertEqual(out["status"], "pending")
        self.assertEqual(self._treasury_balance(group_id), 0)

        # Look up the stored payment-intent id (what the webhook event carries).
        donation = self.fundraising_table.get_item(
            Key={"pk": f"FUNDRAISER#{fundraiser_id}", "sk": f"DONATION#{donation_id}"}
        )["Item"]
        pi_id = donation["stripe_payment_intent_id"]

        result = self.gf.confirm_donation_by_payment_intent(
            fundraiser_id=fundraiser_id,
            donation_id=donation_id,
            stripe_pi_id=pi_id,
        )
        self.assertTrue(result.get("ok"))
        self.assertEqual(self._treasury_balance(group_id), 4200)
        self.assertEqual(self._raised_cents(group_id, fundraiser_id), 4200)

        confirmed = self.fundraising_table.get_item(
            Key={"pk": f"FUNDRAISER#{fundraiser_id}", "sk": f"DONATION#{donation_id}"}
        )["Item"]
        self.assertEqual(confirmed["status"], "completed")

    def test_webhook_confirm_idempotent_no_double_credit(self):
        """A retried Stripe webhook must not credit the treasury twice."""
        self._set_dev_mode(False)
        group_id, fundraiser_id = "g_idem", "fr_idem1"
        self._seed_fundraiser(group_id, fundraiser_id)

        out = self.gf.create_donation(fundraiser_id=fundraiser_id, amount_cents=1000)
        donation_id = out["donation_id"]
        donation = self.fundraising_table.get_item(
            Key={"pk": f"FUNDRAISER#{fundraiser_id}", "sk": f"DONATION#{donation_id}"}
        )["Item"]
        pi_id = donation["stripe_payment_intent_id"]

        self.gf.confirm_donation_by_payment_intent(
            fundraiser_id=fundraiser_id, donation_id=donation_id, stripe_pi_id=pi_id
        )
        second = self.gf.confirm_donation_by_payment_intent(
            fundraiser_id=fundraiser_id, donation_id=donation_id, stripe_pi_id=pi_id
        )
        self.assertTrue(second.get("already_confirmed"))
        self.assertEqual(self._treasury_balance(group_id), 1000)  # credited once

    def test_webhook_mismatched_payment_intent_rejected(self):
        """A webhook whose payment_intent id does not match the donation must be
        rejected (409), so one donation's webhook can't confirm another."""
        from fastapi import HTTPException

        self._set_dev_mode(False)
        group_id, fundraiser_id = "g_mis", "fr_mis1"
        self._seed_fundraiser(group_id, fundraiser_id)

        out = self.gf.create_donation(fundraiser_id=fundraiser_id, amount_cents=999)
        donation_id = out["donation_id"]

        with self.assertRaises(HTTPException) as cm:
            self.gf.confirm_donation_by_payment_intent(
                fundraiser_id=fundraiser_id,
                donation_id=donation_id,
                stripe_pi_id="pi_someone_elses",
            )
        self.assertEqual(cm.exception.status_code, 409)
        self.assertEqual(self._treasury_balance(group_id), 0)  # not credited


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
