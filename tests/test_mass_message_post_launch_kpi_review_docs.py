from __future__ import annotations

import unittest
from pathlib import Path


class TestMassMessagePostLaunchKpiReviewDocs(unittest.TestCase):
    def test_kpi_report_includes_baseline_comparison_and_gap_status(self):
        report = Path("docs/reports/mass-message-post-launch-kpi-review-2026-04-05.md").read_text(encoding="utf-8")
        self.assertIn("Comparison baseline", report)
        self.assertIn("KPI summary (baseline vs launch)", report)
        self.assertIn("⚠️ gap", report)
        self.assertIn("Target/SLO", report)

    def test_follow_up_backlog_items_created_for_kpi_gaps(self):
        report = Path("docs/reports/mass-message-post-launch-kpi-review-2026-04-05.md").read_text(encoding="utf-8")
        tickets = Path("tickets.md").read_text(encoding="utf-8")
        for ticket_id in ("MSG-036", "MSG-037", "MSG-038", "MSG-039"):
            self.assertIn(ticket_id, report)
            self.assertIn(ticket_id, tickets)


if __name__ == "__main__":
    unittest.main()
