"""Offline regression tests for GAP-0205 (FIN-014).

``check_and_alert`` in ``app/services/payment_provider_health.py`` previously
built an alert dict (including the configured ``alert_email``) and returned it,
but nothing was ever delivered: there was no call to the platform email service
or the in-app notification service. The fix makes ``check_and_alert`` deliver
the breach via ``_dispatch_alert``, which calls ``send_alert_email`` (dev/prod
parity via ``S.dev_mode``) and ``write_alert`` (in-app), de-duped by a
per-provider cooldown sentinel row.

Fully offline & hermetic (mirrors tests/test_gap_0176_0177_org_service.py):

  * A real in-memory DynamoDB table is created with moto and bound onto the
    frozen ``T`` handle via ``object.__setattr__`` (T is a frozen dataclass) so
    the cooldown read/write path exercises real storage — no global @mock_aws
    interception relied upon.
  * The notification/email helpers are spied (patched on ``app.services.alerts``
    — that is where ``_dispatch_alert`` imports them from) so NO real email/SES
    or SSE send ever happens.
  * Threshold evaluation is driven by patching ``get_provider_status`` /
    ``get_provider_config`` so the breach state is deterministic.

Each test fails before the fix (no delivery / no ``_dispatch_alert`` call) and
passes after.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from app.services import payment_provider_health as pph

BREACH_STATUS = {
    "provider": "stripe",
    "status": "down",
    "total_success": 10,
    "total_failure": 50,  # ~83% error rate >> 5% threshold
    "error_rate_bps": 8333,
    "avg_latency_ms": 120,
}
BREACH_CONFIG = {
    "provider": "stripe",
    "enabled": True,
    "alert_error_rate_threshold": 500,
    "alert_latency_threshold_ms": 1000,
    "alert_email": "ops@example.com",
}
CLEAN_STATUS = {
    "provider": "stripe",
    "status": "healthy",
    "total_success": 100,
    "total_failure": 0,
    "error_rate_bps": 0,
    "avg_latency_ms": 50,
}


def _make_health_table(ddb):
    """Create the payment_provider_health table (pk/sk + GSI1)."""
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
class TestProviderHealthAlertDelivery(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_health_table(ddb)

        # Bind the moto table onto the exact handle the code uses. T is a frozen
        # dataclass -> object.__setattr__ + restore on cleanup.
        from app.core.tables import T

        self._orig_table = T.payment_provider_health
        object.__setattr__(T, "payment_provider_health", self.table)
        self.addCleanup(
            lambda: object.__setattr__(
                T, "payment_provider_health", self._orig_table
            )
        )

        # Spy the real notification/email helpers where _dispatch_alert imports
        # them from -> no external send happens.
        self.mock_email = self.stack.enter_context(
            patch("app.services.alerts.send_alert_email")
        )
        self.mock_write_alert = self.stack.enter_context(
            patch("app.services.alerts.write_alert")
        )

    # -- _dispatch_alert ---------------------------------------------------

    def test_dispatch_alert_sends_email_and_in_app(self):
        """_dispatch_alert delivers via email + in-app notification.

        FAILS BEFORE FIX: _dispatch_alert only logged; send_alert_email and
        write_alert were never called.
        """
        pph._dispatch_alert(
            {
                "provider": "stripe",
                "status": "down",
                "breaches": ["error_rate"],
                "error_rate_bps": 8333,
                "avg_latency_ms": 120,
                "alert_email": "ops@example.com",
                "at": 1700000000,
            }
        )

        self.mock_email.assert_called_once()
        to_emails, subject, body = self.mock_email.call_args[0]
        self.assertIn("ops@example.com", to_emails)
        self.assertIn("stripe", (subject + body).lower())

        self.mock_write_alert.assert_called_once()

    def test_dispatch_alert_skips_email_when_no_address(self):
        """No email send when alert_email is blank (in-app still fires)."""
        pph._dispatch_alert(
            {
                "provider": "paypal",
                "status": "degraded",
                "breaches": ["latency"],
                "error_rate_bps": 100,
                "avg_latency_ms": 900,
                "alert_email": "",
                "at": 1700000000,
            }
        )
        self.mock_email.assert_not_called()
        self.mock_write_alert.assert_called_once()

    def test_dispatch_alert_swallows_email_failure(self):
        """A delivery failure must not propagate (would kill the loop)."""
        self.mock_email.side_effect = Exception("SES throttled")
        # Must not raise.
        pph._dispatch_alert(
            {
                "provider": "ccbill",
                "status": "degraded",
                "breaches": ["latency"],
                "error_rate_bps": 200,
                "avg_latency_ms": 600,
                "alert_email": "ops@example.com",
                "at": 0,
            }
        )
        # In-app path still attempted despite email failure.
        self.mock_write_alert.assert_called_once()

    # -- check_and_alert ---------------------------------------------------

    def test_check_and_alert_dispatches_when_breached(self):
        """check_and_alert delivers the alert when a threshold is breached.

        FAILS BEFORE FIX: check_and_alert returned the dict but never delivered.
        """
        with patch.object(pph, "get_provider_status", return_value=BREACH_STATUS), \
             patch.object(pph, "get_provider_config", return_value=BREACH_CONFIG):
            result = pph.check_and_alert("stripe")

        self.assertIsNotNone(result)
        self.assertIn("error_rate", result["breaches"])
        self.mock_email.assert_called_once()
        self.mock_write_alert.assert_called_once()
        # Cooldown sentinel row must have been written.
        item = self.table.get_item(
            Key={"pk": pph._provider_pk("stripe"), "sk": "ALERT_COOLDOWN"}
        ).get("Item")
        self.assertIsNotNone(item)

    def test_check_and_alert_no_delivery_when_healthy(self):
        """No breach -> no delivery at all."""
        with patch.object(pph, "get_provider_status", return_value=CLEAN_STATUS), \
             patch.object(pph, "get_provider_config", return_value=BREACH_CONFIG):
            result = pph.check_and_alert("stripe")

        self.assertIsNone(result)
        self.mock_email.assert_not_called()
        self.mock_write_alert.assert_not_called()

    def test_check_and_alert_suppressed_during_cooldown(self):
        """A second breach within the cooldown window does not re-deliver."""
        with patch.object(pph, "get_provider_status", return_value=BREACH_STATUS), \
             patch.object(pph, "get_provider_config", return_value=BREACH_CONFIG):
            first = pph.check_and_alert("stripe")
            second = pph.check_and_alert("stripe")

        # Both calls still return the payload (for observability)...
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        # ...but delivery happened exactly once thanks to the cooldown.
        self.mock_email.assert_called_once()
        self.mock_write_alert.assert_called_once()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
