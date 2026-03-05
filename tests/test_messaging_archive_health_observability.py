from __future__ import annotations

import json
import unittest
from pathlib import Path

from app.services.messaging_archive_alerts import ArchiveHealthSignals, evaluate_archive_health_alerts


class TestMessagingArchiveHealthObservability(unittest.TestCase):
    def test_dashboard_includes_ingest_error_integrity_panels(self):
        doc = json.loads(Path("docs/dashboards/messaging-archive-health-dashboard.json").read_text(encoding="utf-8"))
        text = json.dumps(doc)
        self.assertIn("messaging_archive_write_events_total", text)
        self.assertIn("messaging_archive_integrity_errors_total", text)
        self.assertIn("messaging_archive_export_outcomes_total", text)

    def test_alert_rules_include_sustained_write_failures_and_integrity_mismatch(self):
        packed = Path("docs/alerts/messaging-archive-health-alerts.yml").read_text(encoding="utf-8")
        self.assertIn("MessagingArchiveSustainedWriteFailures", packed)
        self.assertIn("MessagingArchiveIntegrityChainMismatch", packed)
        self.assertIn("for: 15m", packed)

    def test_controlled_simulation_triggers_expected_alerts(self):
        decision = evaluate_archive_health_alerts(
            ArchiveHealthSignals(
                write_failures=12,
                write_total=100,
                integrity_errors=0,
                export_failures=0,
                export_total=20,
                consecutive_write_failure_windows=3,
            )
        )
        self.assertTrue(decision.sustained_write_failure)
        self.assertFalse(decision.integrity_chain_mismatch)

        decision2 = evaluate_archive_health_alerts(
            ArchiveHealthSignals(
                write_failures=0,
                write_total=100,
                integrity_errors=1,
                export_failures=0,
                export_total=20,
                consecutive_write_failure_windows=0,
            )
        )
        self.assertTrue(decision2.integrity_chain_mismatch)


if __name__ == "__main__":
    unittest.main()
