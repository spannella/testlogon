from __future__ import annotations

import unittest

from app.services import google_calendar_transform as transform


class TestGoogleCalendarTransform(unittest.TestCase):
    def test_google_to_internal_is_deterministic(self):
        fixture = {
            "id": "evt-1",
            "etag": '"abc"',
            "updated": "2026-03-01T12:00:00Z",
            "summary": "Standup",
            "description": "Daily sync",
            "status": "confirmed",
            "start": {"dateTime": "2026-03-01T09:00:00-05:00", "timeZone": "America/New_York"},
            "end": {"dateTime": "2026-03-01T09:15:00-05:00", "timeZone": "America/New_York"},
            "recurrence": ["RRULE:FREQ=DAILY;INTERVAL=1"],
            "attendees": [{"email": "a@example.com"}, {"email": "b@example.com"}],
        }
        out1 = transform.map_google_event_to_internal(google_event=fixture, calendar_timezone="UTC")
        out2 = transform.map_google_event_to_internal(google_event=fixture, calendar_timezone="UTC")
        self.assertEqual(out1, out2)

    def test_timezone_boundary_all_day_mapping(self):
        fixture = {
            "id": "evt-all-day",
            "summary": "DST day",
            "status": "confirmed",
            "start": {"date": "2026-03-08", "timeZone": "America/Los_Angeles"},
            "end": {"date": "2026-03-09", "timeZone": "America/Los_Angeles"},
        }
        out = transform.map_google_event_to_internal(google_event=fixture, calendar_timezone="UTC")
        self.assertTrue(out["event"]["all_day"])
        self.assertEqual(out["event"]["all_day_date"], "2026-03-08")
        self.assertEqual(out["event"]["timezone"], "America/Los_Angeles")

    def test_recurrence_and_exdate_conversion(self):
        fixture = {
            "id": "evt-rrule",
            "summary": "Monthly Review",
            "status": "tentative",
            "start": {"dateTime": "2026-01-01T15:00:00Z", "timeZone": "UTC"},
            "end": {"dateTime": "2026-01-01T16:00:00Z", "timeZone": "UTC"},
            "recurrence": [
                "RRULE:FREQ=MONTHLY;BYDAY=MO,WE;COUNT=3",
                "EXDATE:20260201T150000Z,20260301T150000Z",
            ],
            "recurringEventId": "series-1",
            "originalStartTime": {"dateTime": "2026-01-01T15:00:00Z", "timeZone": "UTC"},
        }
        out = transform.map_google_event_to_internal(google_event=fixture, calendar_timezone="UTC")
        self.assertEqual(out["event"]["recurrence_rule"]["freq"], "MONTHLY")
        self.assertEqual(out["event"]["exdates_utc"], ["2026-02-01T15:00:00Z", "2026-03-01T15:00:00Z"])
        self.assertEqual(out["source_metadata"]["google_recurring_event_id"], "series-1")

    def test_unsupported_fields_degrade_with_warnings(self):
        fixture = {
            "id": "evt-unsupported",
            "summary": "Odd Event",
            "status": "mystery",
            "start": {"dateTime": "2026-01-01T15:00:00Z"},
            "end": {"dateTime": "2026-01-01T14:00:00Z"},
            "recurrence": ["RRULE:FREQ=YEARLY"],
        }
        out = transform.map_google_event_to_internal(google_event=fixture, calendar_timezone="UTC")
        self.assertGreaterEqual(len(out["warnings"]), 2)
        self.assertEqual(out["event"]["status"], "busy")

    def test_internal_to_google_and_fingerprint(self):
        internal = {
            "name": "Sync",
            "description": "desc",
            "timezone": "UTC",
            "start_utc": "2026-01-01T10:00:00Z",
            "end_utc": "2026-01-01T11:00:00Z",
            "all_day": False,
            "status": "free",
            "recurrence_rule": {"freq": "WEEKLY", "interval": 2, "byday": ["MO", "WE"]},
            "exdates_utc": ["2026-01-08T10:00:00Z"],
        }
        outbound = transform.map_internal_event_to_google(internal_event=internal)
        self.assertEqual(outbound["google_event"]["transparency"], "transparent")
        self.assertIn("RRULE:FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE", outbound["google_event"]["recurrence"])

        g_event = {
            "id": "evt-1",
            "etag": '"abc"',
            "updated": "2026-03-01T12:00:00Z",
            "status": "confirmed",
            "summary": "Sync",
            "description": "desc",
            "start": {"dateTime": "2026-01-01T10:00:00Z"},
            "end": {"dateTime": "2026-01-01T11:00:00Z"},
            "recurrence": ["RRULE:FREQ=WEEKLY"],
            "attendees": [{"email": "b@example.com"}, {"email": "a@example.com"}],
        }
        fp1 = transform.build_google_event_sync_fingerprint(google_event=g_event)
        fp2 = transform.build_google_event_sync_fingerprint(google_event=g_event)
        self.assertEqual(fp1, fp2)


if __name__ == "__main__":
    unittest.main()
