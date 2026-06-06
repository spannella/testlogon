"""Offline regression tests for GAP-0206 and GAP-0207.

GAP-0206 — the payment-provider enable/disable toggle (``is_provider_enabled`` /
``toggle_provider`` in ``app/services/payment_provider_health.py``) was never
consulted by any billing charge path. Disabling a provider had no effect on new
payment initiation. The fix adds a ``_require_provider_enabled(provider)`` guard
(returns 503 when disabled) at the start of each charge/payment-initiation path
in ``app/routers/billing.py`` (stripe), ``app/routers/paypal.py`` (paypal) and
``app/routers/billing_ccbill.py`` (ccbill).

GAP-0207 — ``app/routers/billing.py`` never called the fraud-detection service
(``evaluate_transaction`` / ``is_frozen`` in ``app/services/fraud_detection.py``).
Every payment initiation bypassed velocity / risk-score gating and freeze
enforcement. The fix adds a ``_fraud_gate(...)`` helper wired into each stripe
charge path: a frozen account or a fraud ``block`` action raises 403; a ``flag``
action is logged and allowed through.

Fully offline / hermetic. No real AWS, no moto global interception (which leaks
to real AWS in this repo). The router handlers are called directly (the FastAPI
TestClient is unusable here). Provider-health and fraud functions are patched at
the *router module* level (the exact names the handlers call), and the frozen DDB
read in ``_fraud_gate`` is exercised via a patched ``fd.is_frozen``. Each test is
constructed so the *old* (pre-fix) code path produces a wrong answer and the new
code path is correct.
"""
from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

import app.routers.billing as billing
import app.routers.paypal as paypal
import app.routers.billing_ccbill as ccbill

from app.models import (
    BillingCheckoutReq,
    PayBalanceReq,
    StripeChargeReq,
    WalletDepositReq,
)
from app.models import (
    OneTimeChargeIn as CCBillOneTimeChargeIn,
    PayBalanceIn as CCBillPayBalanceIn,
    SubscribeMonthlyIn as CCBillSubscribeMonthlyIn,
)


def _ctx(user_sub: str = "u_test"):
    return {"user_sub": user_sub, "actor_sub": user_sub}


def _allow():
    return {"triggered_rules": [], "risk_score": 0, "flagged": False, "action": "allow"}


# ---------------------------------------------------------------------------
# GAP-0206 — stripe provider gate in app/routers/billing.py
# ---------------------------------------------------------------------------
class TestStripeProviderGate0206(unittest.TestCase):
    def setUp(self):
        # Provider disabled for every test in this class.
        p = patch.object(billing, "is_provider_enabled", return_value=False)
        self.addCleanup(p.stop)
        p.start()
        # ensure_stripe_configured is a no-op so the guard order is what's tested.
        p2 = patch.object(billing, "ensure_stripe_configured", lambda: None)
        self.addCleanup(p2.stop)
        p2.start()

    def test_wallet_deposit_503_when_provider_disabled(self):
        with self.assertRaises(HTTPException) as cm:
            billing.wallet_deposit(
                WalletDepositReq(amount_cents=1000), req=None, ctx=_ctx()
            )
        self.assertEqual(cm.exception.status_code, 503)

    def test_charge_once_503_when_provider_disabled(self):
        with self.assertRaises(HTTPException) as cm:
            billing.charge_once(
                StripeChargeReq(amount_cents=5000, description="x"),
                req=None,
                ctx=_ctx(),
            )
        self.assertEqual(cm.exception.status_code, 503)

    def test_pay_balance_503_when_provider_disabled(self):
        with self.assertRaises(HTTPException) as cm:
            billing.pay_balance(PayBalanceReq(), req=None, ctx=_ctx())
        self.assertEqual(cm.exception.status_code, 503)

    def test_create_checkout_session_503_when_provider_disabled(self):
        with self.assertRaises(HTTPException) as cm:
            billing.create_checkout_session(
                BillingCheckoutReq(amount_cents=999, description="x"),
                req=None,
                ctx=_ctx(),
            )
        self.assertEqual(cm.exception.status_code, 503)

    def test_enabled_provider_passes_gate(self):
        """Sanity: when enabled, the provider gate does not raise 503.

        We let charge_once proceed past the gate with a frozen-account fraud
        check to short-circuit before any real DDB/stripe work, proving the 503
        is gone once the provider is enabled.
        """
        with patch.object(billing, "is_provider_enabled", return_value=True), patch.object(
            billing.fd, "is_frozen", return_value=True
        ):
            with self.assertRaises(HTTPException) as cm:
                billing.charge_once(
                    StripeChargeReq(amount_cents=100, description="x"),
                    req=None,
                    ctx=_ctx(),
                )
        # 403 (frozen) — NOT 503; the provider gate was passed.
        self.assertEqual(cm.exception.status_code, 403)


# ---------------------------------------------------------------------------
# GAP-0207 — fraud gate in app/routers/billing.py
# ---------------------------------------------------------------------------
class TestStripeFraudGate0207(unittest.TestCase):
    def setUp(self):
        p = patch.object(billing, "is_provider_enabled", return_value=True)
        self.addCleanup(p.stop)
        p.start()
        p2 = patch.object(billing, "ensure_stripe_configured", lambda: None)
        self.addCleanup(p2.stop)
        p2.start()

    def test_wallet_deposit_403_when_frozen(self):
        with patch.object(billing.fd, "is_frozen", return_value=True):
            with self.assertRaises(HTTPException) as cm:
                billing.wallet_deposit(
                    WalletDepositReq(amount_cents=1000), req=None, ctx=_ctx()
                )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertIn("frozen", cm.exception.detail.lower())

    def test_charge_once_403_when_frozen(self):
        with patch.object(billing.fd, "is_frozen", return_value=True):
            with self.assertRaises(HTTPException) as cm:
                billing.charge_once(
                    StripeChargeReq(amount_cents=5000, description="x"),
                    req=None,
                    ctx=_ctx(),
                )
        self.assertEqual(cm.exception.status_code, 403)

    def test_wallet_deposit_403_when_fraud_blocks(self):
        block = {
            "triggered_rules": [{"rule": "velocity_count"}],
            "risk_score": 95,
            "flagged": True,
            "action": "block",
        }
        with patch.object(billing.fd, "is_frozen", return_value=False), patch.object(
            billing.fd, "evaluate_transaction", return_value=block
        ):
            with self.assertRaises(HTTPException) as cm:
                billing.wallet_deposit(
                    WalletDepositReq(amount_cents=1000), req=None, ctx=_ctx()
                )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertIn("blocked", cm.exception.detail.lower())

    def test_charge_once_calls_evaluate_transaction_with_correct_args(self):
        """Allow path: fraud evaluation must be invoked with the real tx args.

        FAILS BEFORE FIX: evaluate_transaction is never called.
        """
        fake_stripe = MagicMock()
        fake_stripe.PaymentIntent.create.return_value = {
            "id": "pi_test",
            "status": "succeeded",
        }
        with patch.object(billing.fd, "is_frozen", return_value=False), patch.object(
            billing.fd, "evaluate_transaction", return_value=_allow()
        ) as mock_eval, patch.object(
            billing, "stripe", fake_stripe
        ), patch.object(
            billing, "get_or_create_customer", return_value="cus_test"
        ), patch.object(
            billing, "ensure_balance_row", lambda *a, **k: None
        ), patch.object(
            billing, "ddb_get", return_value={"currency": "usd", "default_payment_method_id": "pm_x"}
        ), patch.object(
            billing, "ddb_put", lambda *a, **k: None
        ), patch.object(
            billing, "new_ledger_entry", return_value=("LEDGER#1", {"sk": "LEDGER#1"})
        ), patch.object(
            billing, "record_billing_transaction", return_value="txn_1"
        ), patch.object(
            billing, "mark_completed", lambda *a, **k: None
        ), patch.object(
            billing, "audit_event", lambda *a, **k: None
        ), patch.object(
            billing, "settle_or_reverse_ledger", lambda *a, **k: None
        ), patch.object(
            billing, "apply_balance_delta", lambda *a, **k: None
        ), patch.object(
            billing, "put_payment_record", lambda *a, **k: None
        ):
            billing.charge_once(
                StripeChargeReq(amount_cents=5000, description="t"),
                req=None,
                ctx=_ctx("u_eval"),
            )
        mock_eval.assert_called_once()
        kw = mock_eval.call_args.kwargs
        self.assertEqual(kw["user_id"], "u_eval")
        self.assertEqual(kw["amount_cents"], 5000)
        self.assertEqual(kw["entry_type"], "credit")

    def test_checkout_session_does_not_block_on_fraud(self):
        """Redirect flow: a fraud 'block' must NOT raise (observe-only)."""
        block = {"triggered_rules": [], "risk_score": 99, "flagged": True, "action": "block"}
        fake_stripe = MagicMock()
        fake_stripe.checkout.Session.create.return_value = SimpleNamespace(
            id="cs_1", url="http://x"
        )
        with patch.object(billing.fd, "is_frozen", return_value=False), patch.object(
            billing.fd, "evaluate_transaction", return_value=block
        ), patch.object(billing, "stripe", fake_stripe), patch.object(
            billing, "build_return_url", lambda *a, **k: "http://x"
        ), patch.object(
            billing, "audit_event", lambda *a, **k: None
        ):
            out = billing.create_checkout_session(
                BillingCheckoutReq(amount_cents=999, description="x"),
                req=None,
                ctx=_ctx(),
            )
        self.assertEqual(out["session_id"], "cs_1")

    def test_checkout_session_403_when_frozen(self):
        """Redirect flow still enforces account freeze."""
        with patch.object(billing.fd, "is_frozen", return_value=True):
            with self.assertRaises(HTTPException) as cm:
                billing.create_checkout_session(
                    BillingCheckoutReq(amount_cents=999, description="x"),
                    req=None,
                    ctx=_ctx(),
                )
        self.assertEqual(cm.exception.status_code, 403)


# ---------------------------------------------------------------------------
# GAP-0206 — paypal provider gate
# ---------------------------------------------------------------------------
class TestPaypalProviderGate0206(unittest.TestCase):
    def test_charge_once_503_when_provider_disabled(self):
        with patch.object(paypal, "is_provider_enabled", return_value=False):
            with self.assertRaises(HTTPException) as cm:
                asyncio.run(
                    paypal.charge_once(
                        paypal.OneTimeChargeIn(amount_cents=1000),
                        request=None,
                        x_user_id="u_test",
                    )
                )
        self.assertEqual(cm.exception.status_code, 503)


# ---------------------------------------------------------------------------
# GAP-0206 — ccbill provider gate
# ---------------------------------------------------------------------------
class TestCCBillProviderGate0206(unittest.TestCase):
    def setUp(self):
        p = patch.object(ccbill, "is_provider_enabled", return_value=False)
        self.addCleanup(p.stop)
        p.start()

    def test_charge_once_503_when_provider_disabled(self):
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(
                ccbill.charge_once_endpoint(
                    CCBillOneTimeChargeIn(amount_cents=1000),
                    request=None,
                    ctx=_ctx(),
                )
            )
        self.assertEqual(cm.exception.status_code, 503)

    def test_pay_balance_503_when_provider_disabled(self):
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(
                ccbill.pay_balance_endpoint(
                    CCBillPayBalanceIn(amount_cents=1000),
                    request=None,
                    ctx=_ctx(),
                )
            )
        self.assertEqual(cm.exception.status_code, 503)

    def test_subscribe_monthly_503_when_provider_disabled(self):
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(
                ccbill.subscribe_monthly_endpoint(
                    CCBillSubscribeMonthlyIn(monthly_price_cents=1000),
                    request=None,
                    ctx=_ctx(),
                )
            )
        self.assertEqual(cm.exception.status_code, 503)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
