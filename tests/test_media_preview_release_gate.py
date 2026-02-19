import unittest
from datetime import date, timedelta

from scripts.check_media_preview_release_gate import _validate_checklist


class TestMediaPreviewReleaseGate(unittest.TestCase):
    def test_validate_passes_when_all_gate_criteria_are_met(self):
        today = date(2026, 2, 19)
        data = {
            "feature_flag_strategy": {"validated": True},
            "derivative_generation": {
                "success_rate_threshold": 0.98,
                "success_rate_observed": 0.99,
            },
            "slo": {"queue_slo_met": True, "latency_slo_met": True},
            "security_review": {"sign_off": True, "approver": "platform-security"},
            "test_suites": {"all_green": True, "required": ["pytest", "vitest"]},
            "release_gate": {
                "required_for_release": True,
                "last_reviewed": "2026-02-10",
            },
        }

        failures = _validate_checklist(data, max_age_days=30, min_success_rate=0.95, today=today)
        self.assertEqual(failures, [])

    def test_validate_fails_when_any_release_gate_criterion_is_unmet(self):
        today = date(2026, 2, 19)
        stale = (today - timedelta(days=45)).isoformat()
        data = {
            "feature_flag_strategy": {"validated": False},
            "derivative_generation": {
                "success_rate_threshold": 0.90,
                "success_rate_observed": 0.82,
            },
            "slo": {"queue_slo_met": False, "latency_slo_met": False},
            "security_review": {"sign_off": False, "approver": ""},
            "test_suites": {"all_green": False, "required": []},
            "release_gate": {
                "required_for_release": False,
                "last_reviewed": stale,
            },
        }

        failures = _validate_checklist(data, max_age_days=30, min_success_rate=0.95, today=today)
        messages = [f.message for f in failures]

        self.assertTrue(any("required_for_release" in msg for msg in messages))
        self.assertTrue(any("feature_flag_strategy.validated" in msg for msg in messages))
        self.assertTrue(any("success_rate_threshold" in msg for msg in messages))
        self.assertTrue(any("success_rate_observed" in msg for msg in messages))
        self.assertTrue(any("queue_slo_met" in msg for msg in messages))
        self.assertTrue(any("latency_slo_met" in msg for msg in messages))
        self.assertTrue(any("security_review.sign_off" in msg for msg in messages))
        self.assertTrue(any("security_review.approver" in msg for msg in messages))
        self.assertTrue(any("test_suites.all_green" in msg for msg in messages))
        self.assertTrue(any("test_suites.required" in msg for msg in messages))
        self.assertTrue(any("stale" in msg for msg in messages))


if __name__ == "__main__":
    unittest.main()
