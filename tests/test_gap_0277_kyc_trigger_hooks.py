"""Offline regression tests for GAP-0277 (KYC-016).

GAP-0277 — the KYC ongoing-monitoring system (``app/services/kyc_monitoring.py``)
defines ``create_trigger_event`` with trigger types ``name_change``,
``country_change`` and ``large_transaction``, but neither the profile update path
nor the billing charge path ever called it. Profile name/country changes and
large payments were completely invisible to the monitoring layer.

The fix adds two best-effort hooks:
  * ``app/routers/profile.py::_maybe_fire_profile_kyc_triggers`` — fires
    ``name_change`` when a name field changes and ``country_change`` when
    ``mailing_address.country`` changes.
  * ``app/routers/billing.py::_maybe_fire_large_transaction_trigger`` — fires
    ``large_transaction`` when a settled charge meets/exceeds
    ``S.kyc_large_transaction_threshold_cents``.

These tests are fully hermetic: they NEVER touch DynamoDB or any real/mocked AWS
service. ``create_trigger_event`` is replaced with an in-memory spy on the
``app.services.kyc_monitoring`` module (the hooks import it lazily, so they pick
up the spy). The frozen ``Settings`` singleton ``S`` is mutated via
``object.__setattr__`` for the threshold test and restored afterwards.

Fails before the fix: the hook helpers do not exist (ImportError) / the
``create_trigger_event`` call sites are absent, so no event is recorded.
Passes after the fix: the spy records the expected trigger types.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import app.services.kyc_monitoring as kyc_monitoring
from app.core.settings import S
from app.routers import billing as billing_router
from app.routers import profile as profile_router


class _TriggerSpy:
    """Records ``create_trigger_event`` invocations without any AWS calls."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return {"event_id": "spy", **kwargs}

    def types(self) -> list[str]:
        return [c.get("trigger_type") for c in self.calls]


class ProfileKycTriggerHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spy = _TriggerSpy()
        # Hooks lazily ``from app.services.kyc_monitoring import create_trigger_event``,
        # so patching the module attribute is sufficient and stays offline.
        self._patcher = patch.object(
            kyc_monitoring, "create_trigger_event", self.spy
        )
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

    def test_name_change_fires_name_change_trigger(self) -> None:
        previous = {"first_name": "Alice", "last_name": "Smith", "mailing_address": None}
        updated = {"first_name": "Alicia", "last_name": "Smith", "mailing_address": None}

        profile_router._maybe_fire_profile_kyc_triggers("user_a", previous, updated)

        self.assertIn("name_change", self.spy.types())
        self.assertNotIn("country_change", self.spy.types())
        evt = next(c for c in self.spy.calls if c["trigger_type"] == "name_change")
        self.assertEqual(evt["user_sub"], "user_a")
        self.assertIn("first_name", evt["details"]["changed_fields"])

    def test_country_change_fires_country_change_trigger(self) -> None:
        previous = {
            "first_name": "Bob",
            "last_name": "Jones",
            "mailing_address": {"country": "US", "city": "NYC"},
        }
        updated = {
            "first_name": "Bob",
            "last_name": "Jones",
            "mailing_address": {"country": "DE", "city": "Berlin"},
        }

        profile_router._maybe_fire_profile_kyc_triggers("user_b", previous, updated)

        self.assertIn("country_change", self.spy.types())
        self.assertNotIn("name_change", self.spy.types())
        evt = next(c for c in self.spy.calls if c["trigger_type"] == "country_change")
        self.assertEqual(evt["details"]["from_country"], "US")
        self.assertEqual(evt["details"]["to_country"], "DE")

    def test_non_identity_change_fires_no_trigger(self) -> None:
        previous = {"display_name": "Carol", "first_name": "Carol", "mailing_address": None}
        updated = {"display_name": "Carol B.", "first_name": "Carol", "mailing_address": None}

        profile_router._maybe_fire_profile_kyc_triggers("user_c", previous, updated)

        self.assertEqual(self.spy.calls, [])

    def test_hook_swallows_monitoring_failure(self) -> None:
        # A monitoring failure must never propagate out of the hook.
        def _boom(**kwargs):
            raise RuntimeError("ddb down")

        with patch.object(kyc_monitoring, "create_trigger_event", _boom):
            previous = {"first_name": "X", "mailing_address": None}
            updated = {"first_name": "Y", "mailing_address": None}
            # Should not raise.
            profile_router._maybe_fire_profile_kyc_triggers("user_d", previous, updated)


class BillingLargeTransactionHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spy = _TriggerSpy()
        self._patcher = patch.object(
            kyc_monitoring, "create_trigger_event", self.spy
        )
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

        # S is a frozen dataclass — mutate via object.__setattr__ and restore.
        self._orig_threshold = S.kyc_large_transaction_threshold_cents
        object.__setattr__(S, "kyc_large_transaction_threshold_cents", 500_000)
        self.addCleanup(
            object.__setattr__,
            S,
            "kyc_large_transaction_threshold_cents",
            self._orig_threshold,
        )

    def test_large_charge_fires_large_transaction_trigger(self) -> None:
        billing_router._maybe_fire_large_transaction_trigger(
            "user_big",
            500_000,
            purpose="wallet_deposit",
            currency="usd",
            payment_intent_id="pi_123",
        )

        self.assertIn("large_transaction", self.spy.types())
        evt = next(c for c in self.spy.calls if c["trigger_type"] == "large_transaction")
        self.assertEqual(evt["user_sub"], "user_big")
        self.assertEqual(evt["details"]["amount_cents"], 500_000)
        self.assertEqual(evt["details"]["threshold_cents"], 500_000)

    def test_small_charge_fires_no_trigger(self) -> None:
        billing_router._maybe_fire_large_transaction_trigger(
            "user_small",
            499_999,
            purpose="charge_once",
            currency="usd",
        )

        self.assertEqual(self.spy.calls, [])

    def test_hook_swallows_monitoring_failure(self) -> None:
        def _boom(**kwargs):
            raise RuntimeError("ddb down")

        with patch.object(kyc_monitoring, "create_trigger_event", _boom):
            # Should not raise even though the charge is over threshold.
            billing_router._maybe_fire_large_transaction_trigger("user_e", 999_999)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
