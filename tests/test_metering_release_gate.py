import unittest

from scripts.check_metering_release_gate import _validate_checklist


class TestMeteringReleaseGate(unittest.TestCase):
    def test_validate_passes_for_closed_tickets_and_passed_dod(self):
        data = {
            "required_tickets": [{"id": "MTR-110", "status": "closed"}],
            "definition_of_done": [{"criterion": "c1", "passed": True}],
            "release_gate": {"approved": True, "approver": "rb", "evidence_bundle": "bundle"},
        }
        failures = _validate_checklist(data)
        self.assertEqual(failures, [])

    def test_validate_fails_for_open_ticket_and_missing_dod(self):
        data = {
            "required_tickets": [{"id": "MTR-112", "status": "open"}],
            "definition_of_done": [{"criterion": "outage replay", "passed": False}],
            "release_gate": {"approved": False, "approver": "", "evidence_bundle": ""},
        }
        failures = _validate_checklist(data)
        messages = [f.message for f in failures]
        self.assertTrue(any("MTR-112" in msg for msg in messages))
        self.assertTrue(any("DoD criterion" in msg for msg in messages))
        self.assertTrue(any("release_gate.approved" in msg for msg in messages))


if __name__ == "__main__":
    unittest.main()
