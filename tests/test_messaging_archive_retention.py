from __future__ import annotations

import unittest
from unittest.mock import patch

from app.services import messaging_archive_retention as retention


class TestMessagingArchiveRetention(unittest.TestCase):
    def test_retention_decision_defaults_are_deterministic_and_auditable(self):
        with patch.object(retention, "S") as settings:
            settings.messaging_archive_retention_default_class = "regulatory"
            settings.messaging_archive_retention_class_days_json = '{"short":30,"standard":365,"regulatory":2555}'
            settings.messaging_archive_retention_event_class_overrides_json = "{}"
            settings.messaging_archive_retention_tenant_overrides_json = "{}"
            d1 = retention.evaluate_archive_retention_decision(
                tenant_id="tenant-a",
                event_type="message.sent",
                event_ts=1700000000,
                now_ts=1700000100,
            )
            d2 = retention.evaluate_archive_retention_decision(
                tenant_id="tenant-a",
                event_type="message.sent",
                event_ts=1700000000,
                now_ts=1700000100,
            )

        self.assertEqual(d1.policy_fingerprint, d2.policy_fingerprint)
        self.assertEqual(d1.retain_until_ts, d2.retain_until_ts)
        self.assertEqual(d1.retention_class, "regulatory")
        self.assertFalse(d1.purge_eligible)

    def test_tenant_and_event_overrides_apply(self):
        with patch.object(retention, "S") as settings:
            settings.messaging_archive_retention_default_class = "standard"
            settings.messaging_archive_retention_class_days_json = '{"short":7,"standard":365,"regulatory":2555}'
            settings.messaging_archive_retention_event_class_overrides_json = '{"report.status_changed":"short"}'
            settings.messaging_archive_retention_tenant_overrides_json = '{"tenant-x":"regulatory"}'

            tenant_override = retention.evaluate_archive_retention_decision(
                tenant_id="tenant-x",
                event_type="report.status_changed",
                event_ts=100,
                now_ts=101,
            )
            event_override = retention.evaluate_archive_retention_decision(
                tenant_id="tenant-y",
                event_type="report.status_changed",
                event_ts=100,
                now_ts=101,
            )

        self.assertEqual(tenant_override.retention_class, "regulatory")
        self.assertEqual(event_override.retention_class, "short")
        self.assertEqual(event_override.retention_days, 7)

    def test_purge_eligibility_evaluator(self):
        with patch.object(retention, "S") as settings:
            settings.messaging_archive_retention_default_class = "short"
            settings.messaging_archive_retention_class_days_json = '{"short":1}'
            settings.messaging_archive_retention_event_class_overrides_json = "{}"
            settings.messaging_archive_retention_tenant_overrides_json = "{}"

            eligible = retention.evaluate_archive_purge_eligibility(
                tenant_id="tenant-a",
                event_type="message.sent",
                event_ts=0,
                now_ts=86500,
            )
            not_eligible = retention.evaluate_archive_purge_eligibility(
                tenant_id="tenant-a",
                event_type="message.sent",
                event_ts=0,
                now_ts=100,
            )

        self.assertTrue(eligible)
        self.assertFalse(not_eligible)

    def test_legal_hold_blocks_purge_even_after_retention_window(self):
        with patch.object(retention, "S") as settings:
            settings.messaging_archive_retention_default_class = "short"
            settings.messaging_archive_retention_class_days_json = '{"short":1}'
            settings.messaging_archive_retention_event_class_overrides_json = "{}"
            settings.messaging_archive_retention_tenant_overrides_json = "{}"

            decision = retention.evaluate_archive_retention_decision(
                tenant_id="tenant-a",
                event_type="message.sent",
                event_ts=0,
                now_ts=86500,
                legal_hold_active=True,
            )

        self.assertTrue(decision.legal_hold_active)
        self.assertFalse(decision.purge_eligible)


if __name__ == "__main__":
    unittest.main()
