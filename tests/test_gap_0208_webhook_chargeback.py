"""Offline regression test for GAP-0208 (FIN-015).

GAP-0208 — the primary Stripe webhook handler ``stripe_webhook`` in
``app/routers/billing.py`` handled ``charge.dispute.funds_withdrawn`` and
``charge.dispute.funds_reinstated`` for ledger purposes but never handled
``charge.dispute.created``. As a result ``fraud_detection.record_chargeback``
was never invoked from a live Stripe event, so the fraud engine's per-user
chargeback counter (and its auto-flag threshold rule) was blind to real
chargebacks — only manual admin POSTs incremented it.

The fix adds a ``charge.dispute.created`` branch that calls
``fd.record_chargeback(...)`` (wrapped in try/except so a fraud-store error can
never make the webhook return non-2xx and trigger a Stripe retry / double
count).

TEST ISOLATION
--------------
This test does NOT use moto / ``@mock_aws`` (which can leak to real AWS in this
environment). It does NOT touch DynamoDB at all: every DDB-backed helper used by
the dispute branch (``mark_event_processed``, ``user_id_from_customer``,
``ensure_balance_row``, ``audit_event``) is patched, and ``fd.record_chargeback``
is patched to a ``MagicMock``. The async ``stripe_webhook`` handler is called
directly with a fake ``Request`` (the FastAPI TestClient is unusable in this
repo). Settings ``S`` is frozen, so the webhook secret is set via
``object.__setattr__``.

FAILS BEFORE FIX: ``record_chargeback`` is never called on
``charge.dispute.created`` (no such branch) -> ``assert_called_once`` fails.
PASSES AFTER FIX: the new branch calls it exactly once with the resolved
user_id / amount / tx_id.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import MagicMock, patch

from app.routers import billing
from app.core.settings import S


class _FakeRequest:
    """Minimal async-body Request stand-in for the webhook handler."""

    def __init__(self, body: bytes = b"{}", signature: str = "t=1,v1=sig"):
        self._body = body
        self.headers = {"stripe-signature": signature}

    async def body(self) -> bytes:
        return self._body


def _dispute_event(event_type: str, dispute_id: str = "dp_gap0208") -> dict:
    return {
        "id": f"evt_{dispute_id}_{event_type.replace('.', '_')}",
        "type": event_type,
        "data": {
            "object": {
                "id": dispute_id,
                "charge": "ch_gap0208",
                "amount": 2500,
                "currency": "usd",
            }
        },
    }


class TestWebhookChargebackGap0208(unittest.TestCase):
    def setUp(self):
        # Frozen settings: set the webhook secret + a stripe secret so
        # ensure_stripe_configured() passes, restoring originals on teardown.
        self._orig_webhook_secret = S.stripe_webhook_secret
        self._orig_secret_key = S.stripe_secret_key
        object.__setattr__(S, "stripe_webhook_secret", "whsec_test")
        object.__setattr__(S, "stripe_secret_key", "sk_test")
        self.addCleanup(
            object.__setattr__, S, "stripe_webhook_secret", self._orig_webhook_secret
        )
        self.addCleanup(
            object.__setattr__, S, "stripe_secret_key", self._orig_secret_key
        )

    def _run(self, event_type: str, *, record_side_effect=None):
        """Drive stripe_webhook for one dispute event; return its dict result.

        Returns ``(result, record_mock)``.
        """
        charge_obj = MagicMock()
        charge_obj.get.side_effect = lambda k, d=None: {
            "payment_intent": "pi_gap0208",
            "customer": "cus_gap0208",
        }.get(k, d)

        record_mock = MagicMock(
            side_effect=record_side_effect,
            return_value={
                "user_id": "user_gap0208",
                "chargeback_count": 1,
                "auto_flagged": False,
                "flag_id": None,
            },
        )

        fake_stripe = MagicMock()
        fake_stripe.Webhook.construct_event.return_value = _dispute_event(event_type)
        fake_stripe.Charge.retrieve.return_value = charge_obj

        with patch.object(billing, "stripe", fake_stripe), patch.object(
            billing, "mark_event_processed", return_value=True
        ), patch.object(
            billing, "user_id_from_customer", return_value="user_gap0208"
        ), patch.object(
            billing, "ensure_balance_row"
        ), patch.object(
            billing, "audit_event"
        ), patch.object(
            billing, "fd"
        ) as fd_mod, patch.object(
            # Patch every DDB-backed helper so NO test path touches real AWS
            # (the funds_withdrawn branch reads/writes the billing table).
            billing, "ddb_get", return_value=None
        ), patch.object(
            billing, "ddb_put"
        ), patch.object(
            billing, "new_ledger_entry", return_value=("led_sk", {})
        ), patch.object(
            billing, "apply_balance_delta"
        ), patch.object(
            billing, "settle_or_reverse_ledger"
        ), patch.object(
            billing, "mark_reverted"
        ):
            fd_mod.record_chargeback = record_mock
            result = asyncio.run(billing.stripe_webhook(_FakeRequest()))
        return result, record_mock

    def test_dispute_created_records_chargeback(self):
        """charge.dispute.created must call fd.record_chargeback exactly once."""
        result, record_mock = self._run("charge.dispute.created")

        record_mock.assert_called_once()
        kwargs = record_mock.call_args.kwargs
        self.assertEqual(kwargs["user_id"], "user_gap0208")
        self.assertEqual(kwargs["amount_cents"], 2500)
        self.assertEqual(kwargs["tx_id"], "pi_gap0208")
        self.assertEqual(result.get("received"), True)

    def test_funds_withdrawn_does_not_record_chargeback(self):
        """The ledger-only funds_withdrawn event must NOT touch the fraud counter.

        (Guards against the fix over-firing on every dispute.* event.)
        """
        _result, record_mock = self._run("charge.dispute.funds_withdrawn")
        record_mock.assert_not_called()

    def test_dispute_created_failure_does_not_break_webhook(self):
        """A fraud-store error must not make the webhook return non-2xx.

        The handler swallows the exception and still returns {"received": True}
        so Stripe does not retry (which would double-count the chargeback).
        """
        result, record_mock = self._run(
            "charge.dispute.created",
            record_side_effect=RuntimeError("fraud store unavailable"),
        )
        record_mock.assert_called_once()
        self.assertEqual(result.get("received"), True)


if __name__ == "__main__":
    unittest.main()
