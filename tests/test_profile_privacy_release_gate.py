import unittest
from datetime import date, timedelta

from scripts.check_profile_privacy_release_gate import _validate_checklist


class TestProfilePrivacyReleaseGate(unittest.TestCase):
    def test_validate_passes_for_signed_off_closed_and_pen_tested_checklist(self):
        today = date(2026, 4, 5)
        data = {
            "release_gate": {
                "required_for_ga": True,
                "last_reviewed": "2026-04-04",
            },
            "privacy_security_review": {
                "sign_off": True,
                "approver": "security-privacy-council",
                "scope": "field classifications, discoverability suppression, telemetry redaction",
            },
            "remediations": {
                "all_closed_before_ga": True,
                "required": [
                    {"id": "UPR021-001", "status": "closed"},
                    {"id": "UPR021-002", "status": "closed"},
                ],
            },
            "pen_test": {
                "executed": True,
                "passed": True,
                "scenarios": ["enumeration", "data_leakage", "auth-bypass"],
            },
        }

        failures = _validate_checklist(data, max_age_days=45, today=today)
        self.assertEqual(failures, [])

    def test_validate_fails_for_open_remediation_missing_scenarios_and_stale_review(self):
        today = date(2026, 4, 5)
        stale = (today - timedelta(days=70)).isoformat()
        data = {
            "release_gate": {
                "required_for_ga": False,
                "last_reviewed": stale,
            },
            "privacy_security_review": {
                "sign_off": False,
                "approver": "",
                "scope": "",
            },
            "remediations": {
                "all_closed_before_ga": False,
                "required": [
                    {"id": "UPR021-001", "status": "open"},
                ],
            },
            "pen_test": {
                "executed": False,
                "passed": False,
                "scenarios": ["auth-bypass"],
            },
        }

        failures = _validate_checklist(data, max_age_days=45, today=today)
        messages = [f.message for f in failures]
        self.assertTrue(any("required_for_ga" in msg for msg in messages))
        self.assertTrue(any("stale" in msg for msg in messages))
        self.assertTrue(any("sign_off" in msg for msg in messages))
        self.assertTrue(any("UPR021-001" in msg for msg in messages))
        self.assertTrue(any("all_closed_before_ga" in msg for msg in messages))
        self.assertTrue(any("missing required item: enumeration" in msg for msg in messages))
        self.assertTrue(any("missing required item: data_leakage" in msg for msg in messages))


if __name__ == "__main__":
    unittest.main()
