import unittest
from datetime import date, timedelta

from scripts.check_security_release_gate import _validate_checklist


class TestSecurityReleaseGate(unittest.TestCase):
    def test_validate_passes_when_all_tickets_closed_and_recent(self):
        today = date(2026, 2, 15)
        data = {
            "required_tickets": [
                {"id": "SEC-201", "status": "closed"},
                {"id": "SEC-202", "status": "closed"},
            ],
            "release_gate": {
                "all_required_closed": True,
                "last_reviewed": "2026-02-01",
                "cadence": "quarterly",
            },
        }

        failures = _validate_checklist(data, max_age_days=120, today=today)
        self.assertEqual(failures, [])

    def test_validate_fails_for_open_ticket_and_stale_review(self):
        today = date(2026, 2, 15)
        stale = (today - timedelta(days=180)).isoformat()
        data = {
            "required_tickets": [
                {"id": "SEC-201", "status": "closed"},
                {"id": "SEC-202", "status": "open"},
            ],
            "release_gate": {
                "all_required_closed": False,
                "last_reviewed": stale,
                "cadence": "quarterly",
            },
        }

        failures = _validate_checklist(data, max_age_days=120, today=today)
        messages = [f.message for f in failures]
        self.assertTrue(any("SEC-202" in msg for msg in messages))
        self.assertTrue(any("all_required_closed" in msg for msg in messages))
        self.assertTrue(any("stale" in msg for msg in messages))


if __name__ == "__main__":
    unittest.main()
