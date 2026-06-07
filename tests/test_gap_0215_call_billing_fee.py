"""Offline regression test for GAP-0215 (FIN-018).

``app/services/call_billing_timer.py`` used to read the per-minute call
platform fee directly from the env-var-backed setting
``S.call_billing_platform_fee_percent`` (``* 100`` -> BPS) at three sites:
``start_call_billing`` (the rate locked into the call session record) and the
``or (...)`` fallbacks in ``process_heartbeat`` / ``finalize_call_billing``.

That meant a fee change made through the FIN-018 Billing Configuration UI
(stored in the ``billing_config`` DDB table under ``fee_call_bps``) had **no
effect** on new call sessions — they kept billing at the env-var default. The
fix:

  * adds ``fee_call_bps`` to the billing-config allowlist (default = the env
    percent default * 100, so deploy behaviour is unchanged), and
  * replaces all three reads with ``get_fee_bps("call")``.

This test seeds a billing-config override of 1500 BPS (15%), starts a call, and
asserts the locked-in ``platform_fee_bps`` on the session record is 1500 — not
the env-var-derived 2000.

Test isolation (per the repo rules): we do NOT rely on global moto interception
leaking to real AWS. A real in-memory DynamoDB is created inside ``mock_aws()``
and the exact table handles used by the services are monkeypatched on the
*frozen* ``T`` singleton via ``object.__setattr__`` (restored afterwards). The
service functions are called directly (the FastAPI TestClient is unusable here).
"""
from __future__ import annotations

import unittest

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_call_sessions_table(ddb):
    return ddb.create_table(
        TableName="MessageCallSessions",
        KeySchema=[{"AttributeName": "call_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "call_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_billing_config_table(ddb):
    return ddb.create_table(
        TableName="billing_config",
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
class TestCallBillingFeeGap0215(unittest.TestCase):
    def setUp(self):
        self._mock = mock_aws()
        self._mock.start()
        self.addCleanup(self._mock.stop)

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.call_table = _make_call_sessions_table(ddb)
        self.config_table = _make_billing_config_table(ddb)

        from app.core.tables import T
        from app.services import billing_config

        self.T = T
        self.billing_config = billing_config

        # Patch the exact frozen handles the services use (restore on cleanup).
        self._orig_call = T.message_call_sessions
        self._orig_config = T.billing_config
        object.__setattr__(T, "message_call_sessions", self.call_table)
        object.__setattr__(T, "billing_config", self.config_table)

        def _restore():
            object.__setattr__(T, "message_call_sessions", self._orig_call)
            object.__setattr__(T, "billing_config", self._orig_config)

        self.addCleanup(_restore)

        # Always start from a clean cache and reset it afterwards so this test
        # does not leak config state into other gap test files.
        billing_config.invalidate_cache()
        self.addCleanup(billing_config.invalidate_cache)

    def _seed_call_session(self, call_id: str):
        self.call_table.put_item(
            Item={
                "call_id": call_id,
                "caller_user_id": "user_alice",
                "callee_user_id": "user_bob",
                "state": "connected",
                "paid": True,
                "rate_cents_per_min": 200,
                "platform_fee_bps": 0,
                "total_billed_cents": 0,
                "total_billed_seconds": 0,
                "billing_cycle_count": 0,
            }
        )

    def test_fee_call_bps_is_editable_key(self):
        """fee_call_bps must be a valid billing-config key after the fix."""
        self.assertIn("fee_call_bps", self.billing_config.EDITABLE_KEYS)

    def test_default_fee_call_bps_matches_env_percent(self):
        """Default fee_call_bps == env percent (20) * 100 == 2000 BPS."""
        self.assertEqual(self.billing_config.get_fee_bps("call"), 2000)

    def test_start_call_billing_uses_billing_config_override(self):
        """GAP-0215: start_call_billing must lock in the billing-config fee.

        FAILS BEFORE FIX: start_call_billing reads
        ``S.call_billing_platform_fee_percent * 100`` (2000 BPS) regardless of
        the billing-config override, so the session records 2000.
        PASSES AFTER FIX: it reads ``get_fee_bps("call")`` -> 1500.
        """
        from app.services.call_billing_timer import start_call_billing

        # Admin sets the call fee to 15% (1500 BPS) via the billing config UI.
        self.billing_config.set_config("fee_call_bps", 1500, actor="admin_root")
        self.billing_config.invalidate_cache()

        call_id = "call_gap0215"
        self._seed_call_session(call_id)

        start_call_billing(
            call_id=call_id,
            rate_cents_per_min=200,
            caller_id="user_alice",
            callee_id="user_bob",
        )

        item = self.call_table.get_item(Key={"call_id": call_id}).get("Item")
        self.assertIsNotNone(item)
        self.assertEqual(
            int(item["platform_fee_bps"]),
            1500,
            "start_call_billing must lock in the billing-config call fee "
            "(1500 BPS), not the env-var default (2000 BPS)",
        )

    def test_start_call_billing_does_not_reference_env_fee(self):
        """The fix must not read S.call_billing_platform_fee_percent directly."""
        import inspect

        from app.services import call_billing_timer

        for fn_name in (
            "start_call_billing",
            "process_heartbeat",
            "finalize_call_billing",
        ):
            src = inspect.getsource(getattr(call_billing_timer, fn_name))
            self.assertNotIn(
                "call_billing_platform_fee_percent",
                src,
                f"{fn_name} still references the env-var fee directly",
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
