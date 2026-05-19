from __future__ import annotations

import subprocess
import sys
import unittest


class TestGoogleCalendarLaunchReportScript(unittest.TestCase):
    def test_launch_report_script_go_decision(self):
        out = subprocess.check_output(
            [
                sys.executable,
                "scripts/google_calendar_launch_report.py",
                "--cohort",
                "pilot",
                "--sync-sla",
                "met",
                "--error-budget",
                "within_budget",
                "--sev-open",
                "0",
                "--notes",
                "stable",
            ],
            text=True,
        )
        self.assertIn("go_no_go: go", out)

    def test_launch_report_script_no_go_decision(self):
        out = subprocess.check_output(
            [
                sys.executable,
                "scripts/google_calendar_launch_report.py",
                "--cohort",
                "broad",
                "--sync-sla",
                "not_met",
                "--error-budget",
                "exceeded",
                "--sev-open",
                "1",
            ],
            text=True,
        )
        self.assertIn("go_no_go: no_go", out)


if __name__ == "__main__":
    unittest.main()
