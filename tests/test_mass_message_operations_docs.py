from __future__ import annotations

import unittest
from pathlib import Path


class TestMassMessageOperationsDocs(unittest.TestCase):
    def test_runbook_includes_diagnostics_remediation_and_escalation(self):
        content = Path("docs/mass-message-operations-runbook.md").read_text(encoding="utf-8")
        self.assertIn("Diagnostics playbook", content)
        self.assertIn("Remediation commands", content)
        self.assertIn("Escalation path", content)
        self.assertIn("MESSAGING_MASS_SEND_KILL_SWITCH", content)
        self.assertIn("messaging_mass_limit_events_total", content)

    def test_alert_definitions_include_failure_rate_and_worker_lag(self):
        packed = Path("docs/alerts/messaging-mass-campaign-alerts.yml").read_text(encoding="utf-8")
        self.assertIn("MessagingMassCampaignHighFailureRate", packed)
        self.assertIn("MessagingMassCampaignWorkerLagP95High", packed)
        self.assertIn("messaging_mass_destination_outcomes_total", packed)
        self.assertIn("messaging_mass_worker_latency_seconds_bucket", packed)
        self.assertIn("runbook: \"docs/mass-message-operations-runbook.md\"", packed)


if __name__ == "__main__":
    unittest.main()
