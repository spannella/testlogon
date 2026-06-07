"""Offline regression test for GAP-0326 (SEC-014): global SMS cost cap.

`app/services/sms_delivery.py` previously enforced only a *per-number* daily
message-count limit (`sms_daily_limit_per_number`). There was no platform-wide
ceiling on total daily SMS spend, so a toll-fraud pump-and-dump attack across
many phone numbers could rack up unlimited AWS SNS cost.

The fix adds:
  - setting `S.sms_daily_cost_cap_usd` (env SMS_DAILY_COST_CAP_USD, default 0 =
    disabled — backward compatible);
  - a global daily segment counter (`DAILY#GLOBAL` / `DAY#{day_key}`) incremented
    by `record_sms_sent` / `record_sms_dev_logged`;
  - `sms_global_cost_cap_exceeded(extra_segments)` + a check in `send_sms()`
    that returns `status="rate_limited"` (without publishing) once the estimated
    cumulative daily cost reaches the cap.

This test is fully hermetic: a real in-memory DynamoDB table is created with
moto (no real AWS), `sms_delivery.T` is patched to point at it, and the SNS
client is stubbed so no network/AWS call ever happens. `S` is frozen, so flags
are flipped via `object.__setattr__` and restored on cleanup.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_sms_delivery_table(ddb):
    """Mirror the SmsDelivery TableDef from scripts/local-ddb-init.py."""
    return ddb.create_table(
        TableName="sms_delivery",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByStatus",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestSmsGlobalCostCapGap0326(unittest.TestCase):
    PHONE = "+15551234567"
    COST_PER_SEGMENT = 0.00645

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_sms_delivery_table(ddb)

        from app.services import sms_delivery

        self.svc = sms_delivery
        # Bind the EXACT handle the code uses (sms_delivery.T.sms_delivery).
        self.stack.enter_context(
            patch.object(sms_delivery, "T", SimpleNamespace(sms_delivery=self.table))
        )

        # Frozen settings — set deterministic values, restore on cleanup.
        self.S = sms_delivery.S
        self._set_settings({
            "sms_cost_per_segment_usd": self.COST_PER_SEGMENT,
            "sms_suppression_enabled": False,
            "sms_daily_limit_per_number": 1_000_000,  # never the cause of a block
            "alerts_sms_enabled": True,
        })

        # Stub the SNS client so a real send never touches AWS, and so we can
        # assert publish was / was not called.
        self.sns = MagicMock()
        self.sns.publish.return_value = {"MessageId": "msg-test-1"}
        self.stack.enter_context(
            patch("app.core.aws.sns_client", return_value=self.sns)
        )

    def _set_settings(self, values: dict) -> None:
        for key, val in values.items():
            old = getattr(self.S, key)
            object.__setattr__(self.S, key, val)
            self.addCleanup(object.__setattr__, self.S, key, old)

    def _seed_global_segments(self, segments: int) -> None:
        """Directly seed today's global segment counter."""
        day_key = self.svc.now_ts() // 86400
        self.table.put_item(Item={
            "pk": self.svc._GLOBAL_DAILY_PK,
            "sk": f"DAY#{day_key}",
            "count": segments,
        })

    # ──────────────────────────────────────────────────────────────────

    def test_cap_disabled_sends_proceed(self):
        """cap=0 (default/disabled) → sends proceed even with huge prior usage."""
        self._set_settings({"sms_daily_cost_cap_usd": 0.0, "dev_mode": True})
        self._seed_global_segments(10_000)  # would be way over any real cap

        result = self.svc.send_sms(self.PHONE, "hello")

        self.assertEqual(result["status"], "dev_logged")

    def test_cap_blocks_when_exceeded_without_publishing(self):
        """Low positive cap + enough global segments → rate_limited, no SNS publish.

        FAILS BEFORE FIX: no global cap check → status="sent" (publish called).
        PASSES AFTER FIX: 100 prior + 1 this msg = 101 segs * 0.00645 = $0.65145
        which is >= the $0.50 cap → rate_limited, publish NOT called.
        """
        self._set_settings({"sms_daily_cost_cap_usd": 0.50, "dev_mode": False})
        self._seed_global_segments(100)

        result = self.svc.send_sms(self.PHONE, "hello")

        self.assertEqual(result["status"], "rate_limited")
        self.assertIsNone(result["message_id"])
        self.sns.publish.assert_not_called()

    def test_cap_allows_when_under(self):
        """Under the cap → send proceeds normally."""
        self._set_settings({"sms_daily_cost_cap_usd": 1.00, "dev_mode": True})
        self._seed_global_segments(10)  # 11 segs * 0.00645 = $0.071 << $1.00

        result = self.svc.send_sms(self.PHONE, "hello")

        self.assertEqual(result["status"], "dev_logged")

    def test_global_counter_increments_on_send(self):
        """record_sms_sent / dev path increments the DAILY#GLOBAL counter, so
        repeated sends accumulate toward the cap (drives real enforcement)."""
        self._set_settings({"sms_daily_cost_cap_usd": 0.0, "dev_mode": True})

        self.svc.send_sms(self.PHONE, "hello")  # 1 segment
        self.assertEqual(self.svc._global_daily_segments(), 1)

        self.svc.send_sms(self.PHONE, "hello again")  # 1 segment
        self.assertEqual(self.svc._global_daily_segments(), 2)

    def test_cap_enforced_after_cumulative_real_sends(self):
        """End-to-end: with a tiny cap, real (dev) sends accumulate until the
        cumulative cost trips the cap and the next send is rate_limited."""
        # Cap $0.02 → 0.02 / 0.00645 ≈ 3.1 → blocks once cumulative >= 4 segs.
        self._set_settings({"sms_daily_cost_cap_usd": 0.02, "dev_mode": True})

        statuses = [self.svc.send_sms(self.PHONE, "hi")["status"] for _ in range(5)]

        # First few proceed, then the cap trips.
        self.assertIn("dev_logged", statuses)
        self.assertIn("rate_limited", statuses)
        # Once rate_limited, all subsequent are too (monotonic kill switch).
        first_block = statuses.index("rate_limited")
        self.assertTrue(all(s == "rate_limited" for s in statuses[first_block:]))


if __name__ == "__main__":
    unittest.main()
