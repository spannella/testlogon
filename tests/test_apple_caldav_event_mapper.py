from __future__ import annotations

import unittest

from app.services.calendar_integrations.apple_caldav import map_ical_to_internal_events


class TestAppleCalDavEventMapper(unittest.TestCase):
    def test_map_vevent_fields_deterministically(self):
        payload = """BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:evt-123@example.com
SUMMARY:Team Sync
DESCRIPTION:Line1\\nLine2
LOCATION:Room 7
DTSTART;TZID=America/New_York:20260405T090000
DTEND;TZID=America/New_York:20260405T100000
STATUS:CONFIRMED
END:VEVENT
END:VCALENDAR
"""
        out = map_ical_to_internal_events(ical_payload=payload)
        self.assertEqual(out["errors"], [])
        self.assertEqual(len(out["events"]), 1)

        event = out["events"][0]
        self.assertEqual(event["remote_uid"], "evt-123@example.com")
        self.assertEqual(event["name"], "Team Sync")
        self.assertEqual(event["description"], "Line1\nLine2")
        self.assertEqual(event["location"], "Room 7")
        self.assertEqual(event["status"], "busy")
        self.assertEqual(event["timezone"], "America/New_York")
        self.assertEqual(event["start_utc"], "2026-04-05T13:00:00Z")
        self.assertEqual(event["end_utc"], "2026-04-05T14:00:00Z")
        self.assertFalse(event["all_day"])
        self.assertEqual(event["parse_errors"], [])

    def test_invalid_and_unsupported_fragments_return_structured_errors(self):
        payload = """BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
SUMMARY:Broken Event
DTSTART:bad-value
STATUS:INPROGRESS
RRULE:FREQ=YEARLY;BYSETPOS=1
END:VEVENT
END:VCALENDAR
"""
        out = map_ical_to_internal_events(ical_payload=payload)
        self.assertEqual(len(out["events"]), 1)
        event = out["events"][0]
        errors = event["parse_errors"]

        self.assertTrue(any(err["code"] == "missing_required_field" and err["field"] == "UID" for err in errors))
        self.assertTrue(any(err["code"] == "invalid_datetime" and err["field"] == "DTSTART" for err in errors))
        self.assertTrue(any(err["code"] == "unsupported_recurrence" and err["field"] == "RRULE" for err in errors))
        self.assertTrue(any(err["code"] == "unsupported_status" and err["field"] == "STATUS" for err in errors))

    def test_all_day_events_map_to_all_day_date(self):
        payload = """BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:allday-1
SUMMARY:Holiday
DTSTART;VALUE=DATE:20261225
DTEND;VALUE=DATE:20261226
STATUS:TENTATIVE
END:VEVENT
END:VCALENDAR
"""
        out = map_ical_to_internal_events(ical_payload=payload)
        event = out["events"][0]

        self.assertTrue(event["all_day"])
        self.assertEqual(event["all_day_date"], "2026-12-25")
        self.assertIsNone(event["start_utc"])
        self.assertIsNone(event["end_utc"])
        self.assertEqual(event["status"], "tentative")

    def test_invalid_rrule_numeric_values_return_structured_errors(self):
        payload = """BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:evt-invalid-rrule
SUMMARY:Broken Recurrence
DTSTART:20260405T090000Z
DTEND:20260405T100000Z
RRULE:FREQ=MONTHLY;INTERVAL=abc;COUNT=xyz;BYMONTHDAY=bad
END:VEVENT
END:VCALENDAR
"""
        out = map_ical_to_internal_events(ical_payload=payload)
        self.assertEqual(len(out["events"]), 1)
        event = out["events"][0]
        errors = event["parse_errors"]
        self.assertIsNone(event["recurrence_rule"])
        self.assertTrue(any(err["code"] == "invalid_recurrence_value" and "INTERVAL" in err["message"] for err in errors))

    def test_invalid_rrule_ranges_return_structured_errors(self):
        payload = """BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:evt-invalid-range
SUMMARY:Broken Range Recurrence
DTSTART:20260405T090000Z
DTEND:20260405T100000Z
RRULE:FREQ=MONTHLY;INTERVAL=0;BYMONTHDAY=0
END:VEVENT
END:VCALENDAR
"""
        out = map_ical_to_internal_events(ical_payload=payload)
        self.assertEqual(len(out["events"]), 1)
        errors = out["events"][0]["parse_errors"]
        self.assertTrue(any(err["code"] == "invalid_recurrence_value" for err in errors))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
