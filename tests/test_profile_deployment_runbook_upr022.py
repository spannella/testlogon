from __future__ import annotations

import unittest
from pathlib import Path


class TestProfileDeploymentRunbookUPR022(unittest.TestCase):
    def test_runbook_includes_required_ordered_steps(self):
        text = Path("docs/profile-deployment-runbook-upr022.md").read_text(encoding="utf-8")

        step1 = text.index("Step 1 — Migration / backfill")
        step2 = text.index("Step 2 — Backend deploy")
        step3 = text.index("Step 3 — Frontend deploy")
        step4 = text.index("Step 4 — Feature-flag enablement (staged)")

        self.assertLess(step1, step2)
        self.assertLess(step2, step3)
        self.assertLess(step3, step4)

    def test_runbook_covers_metrics_logs_error_budgets_and_rollback_owners(self):
        text = Path("docs/profile-deployment-runbook-upr022.md").read_text(encoding="utf-8")

        self.assertIn("profile_lookup_events_total", text)
        self.assertIn("profile_lookup_latency_seconds", text)
        self.assertIn("profile_lookup", text)
        self.assertIn("Error budgets", text)
        self.assertIn("Rollback plan", text)
        self.assertIn("On-call owners and responsibilities", text)
        self.assertIn("Backend on-call", text)
        self.assertIn("Frontend on-call", text)
        self.assertIn("SRE on-call", text)


if __name__ == "__main__":
    unittest.main()
