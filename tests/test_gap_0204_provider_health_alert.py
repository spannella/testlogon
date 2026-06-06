"""Offline regression tests for GAP-0204 (FIN-014).

GAP-0204 — ``check_and_alert`` in ``app/services/payment_provider_health.py``
was dead code: defined but never invoked. No background task, no startup hook,
no endpoint called it, so configured provider alert thresholds (error rate,
latency) were never evaluated automatically and provider degradation went
undetected. The fix adds ``start_provider_health_check_task`` /
``_provider_health_loop`` (registered as a FastAPI startup handler in
``app/main.py``) that calls ``check_and_alert`` for every provider on a timer.

Tests are fully offline and hermetic:

* The FastAPI TestClient is unusable in this repo, so functions are called
  directly.
* We do NOT rely on global moto/@mock_aws interception of the app's pre-bound
  boto3 clients (that leaks to real AWS when another test file imported the app
  first). Instead we build a real in-memory DynamoDB table with moto and swap
  the *exact* handle the code uses — ``T.payment_provider_health`` on the
  frozen ``Tables`` singleton — via ``object.__setattr__``, restoring it after.
* Settings ``S`` is a frozen dataclass; toggling the feature flag is done via
  ``object.__setattr__`` and restored after.

Each test is constructed so the *old* behaviour (no wiring) is wrong / the
symbol is absent, and the *new* behaviour is correct.
"""
from __future__ import annotations

import asyncio
import unittest
import uuid
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_health_table(ddb):
    """Create the payment_provider_health table with the GSI1 index.

    GSI1SK is numeric (N) to match ``record_provider_event`` which stores the
    integer timestamp as ``GSI1SK``.
    """
    return ddb.create_table(
        TableName="payment_provider_health",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _BaseHealthTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_health_table(ddb)

        from app.services import payment_provider_health as pph
        from app.core.tables import T

        self.pph = pph
        self.T = T

        # Swap the exact handle the code uses on the frozen Tables singleton,
        # restoring it on cleanup. No global client interception relied upon.
        original_handle = T.payment_provider_health
        object.__setattr__(T, "payment_provider_health", self.table)
        self.addCleanup(
            lambda: object.__setattr__(T, "payment_provider_health", original_handle)
        )

        # Ensure the feature flag is on for these tests (S is frozen).
        original_flag = pph.S.payment_provider_health_enabled
        object.__setattr__(pph.S, "payment_provider_health_enabled", True)
        self.addCleanup(
            lambda: object.__setattr__(
                pph.S, "payment_provider_health_enabled", original_flag
            )
        )

    def _seed_datapoint(self, provider: str, *, success: bool, latency_ms: int, ts: int):
        pk = f"PROVIDER#{provider}"
        self.table.put_item(
            Item={
                "pk": pk,
                "sk": f"DP#{ts}#{uuid.uuid4().hex}",
                "GSI1PK": pk,
                "GSI1SK": ts,
                "ts": ts,
                "success": bool(success),
                "latency_ms": latency_ms,
                "error_type": "",
                "op": "charge",
            }
        )

    def _set_config(self, provider: str, **fields):
        item = {"pk": f"PROVIDER#{provider}", "sk": "CONFIG", "enabled": True}
        item.update(fields)
        self.table.put_item(Item=item)


class TestCheckAndAlert(_BaseHealthTest):
    def test_returns_none_when_no_data(self):
        """No datapoints -> no alert."""
        self.assertIsNone(self.pph.check_and_alert("stripe"))

    def test_returns_breach_when_error_rate_exceeds_threshold(self):
        """High error rate over the configured threshold -> error_rate breach."""
        from app.core.time import now_ts

        now = now_ts()
        # 2 failures + 1 success = 6666 bps >> default 500 bps threshold.
        self._seed_datapoint("stripe", success=False, latency_ms=100, ts=now - 10)
        self._seed_datapoint("stripe", success=False, latency_ms=110, ts=now - 9)
        self._seed_datapoint("stripe", success=True, latency_ms=90, ts=now - 8)

        result = self.pph.check_and_alert("stripe")
        self.assertIsNotNone(result)
        self.assertIn("error_rate", result["breaches"])
        self.assertEqual(result["provider"], "stripe")

    def test_returns_none_when_within_thresholds(self):
        """All-success, low-latency -> no breach."""
        from app.core.time import now_ts

        now = now_ts()
        for i in range(20):
            self._seed_datapoint("paypal", success=True, latency_ms=50, ts=now - i)
        self.assertIsNone(self.pph.check_and_alert("paypal"))


class TestBackgroundTaskWiring(_BaseHealthTest):
    """GAP-0204 core: the periodic loop must actually exist and call
    check_and_alert for every provider. FAILS BEFORE FIX (symbols absent)."""

    def test_start_task_function_exists(self):
        self.assertTrue(
            hasattr(self.pph, "start_provider_health_check_task"),
            "GAP-0204: start_provider_health_check_task must exist to wire the "
            "periodic provider health check",
        )
        self.assertTrue(hasattr(self.pph, "_provider_health_loop"))

    def test_registered_as_startup_handler_in_main(self):
        """The task must be registered as a FastAPI startup handler."""
        import app.main as main_mod
        import inspect

        src = inspect.getsource(main_mod)
        self.assertIn(
            "start_provider_health_check_task",
            src,
            "GAP-0204: start_provider_health_check_task must be imported and "
            "registered as a startup event handler in app/main.py",
        )

    def test_loop_calls_check_for_all_providers(self):
        """_provider_health_loop iterates all PROVIDERS each cycle."""
        calls_seen = []

        async def fake_sleep(_):
            raise StopAsyncIteration  # break after the first iteration

        def fake_check(prov):
            calls_seen.append(prov)
            return None

        with patch.object(self.pph, "check_and_alert", side_effect=fake_check), \
                patch("asyncio.sleep", side_effect=fake_sleep):
            try:
                asyncio.run(self.pph._provider_health_loop(interval=60))
            except StopAsyncIteration:
                pass

        self.assertEqual(set(calls_seen), {"stripe", "paypal", "ccbill"})

    def test_loop_dispatches_alert_on_breach(self):
        """When check_and_alert returns a breach, _dispatch_alert is invoked."""
        dispatched = []

        async def fake_sleep(_):
            raise StopAsyncIteration

        def fake_check(prov):
            if prov == "stripe":
                return {"provider": prov, "status": "down", "breaches": ["error_rate"]}
            return None

        with patch.object(self.pph, "check_and_alert", side_effect=fake_check), \
                patch.object(self.pph, "_dispatch_alert",
                             side_effect=lambda a: dispatched.append(a)), \
                patch("asyncio.sleep", side_effect=fake_sleep):
            try:
                asyncio.run(self.pph._provider_health_loop(interval=60))
            except StopAsyncIteration:
                pass

        self.assertEqual(len(dispatched), 1)
        self.assertEqual(dispatched[0]["provider"], "stripe")

    def test_start_task_skips_loop_when_flag_disabled(self):
        """Feature flag off -> registers disabled, does not schedule the loop."""
        object.__setattr__(self.pph.S, "payment_provider_health_enabled", False)
        # register_task is imported lazily inside the function from job_registry.
        with patch("asyncio.create_task") as mock_create, \
                patch("app.services.job_registry.register_task") as mock_reg:
            self.pph.start_provider_health_check_task()
        mock_create.assert_not_called()
        mock_reg.assert_called_once()

    def test_start_task_schedules_loop_when_enabled(self):
        """Feature flag on -> schedules the loop via asyncio.create_task."""
        with patch("asyncio.create_task") as mock_create:
            self.pph.start_provider_health_check_task()
            mock_create.assert_called_once()
            # Close the un-awaited coroutine handed to the mocked create_task.
            coro = mock_create.call_args[0][0]
            coro.close()


if __name__ == "__main__":
    unittest.main()
