from __future__ import annotations

import unittest

from app.services import google_calendar_conflicts as svc


class TestGoogleCalendarConflicts(unittest.TestCase):
    def test_detects_conflict_with_concurrent_internal_edit(self):
        out = svc.detect_sync_conflict(
            internal_event_snapshot={"updated_at_utc": "2026-01-02T00:00:00Z"},
            mapping_snapshot={"last_synced_at_utc": "2026-01-01T00:00:00Z"},
            provider_error={"provider_status_code": 412, "message": "Precondition Failed"},
        )
        self.assertTrue(out["is_conflict"])
        self.assertEqual(out["reason"], "etag_mismatch_with_concurrent_internal_edit")

    def test_non_conflict_path(self):
        out = svc.detect_sync_conflict(
            internal_event_snapshot={"updated_at_utc": "2026-01-01T00:00:00Z"},
            mapping_snapshot={"last_synced_at_utc": "2026-01-01T00:00:00Z"},
            provider_error={"provider_status_code": 500, "message": "backend"},
        )
        self.assertFalse(out["is_conflict"])


if __name__ == "__main__":
    unittest.main()
