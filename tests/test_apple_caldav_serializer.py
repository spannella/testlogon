from __future__ import annotations

import unittest

from app.services.calendar_integrations.apple_caldav import (
    map_ical_to_internal_events,
    serialize_internal_event_to_ical,
)


class TestAppleCalDavSerializer(unittest.TestCase):
    def test_serializer_round_trip_timed_event(self):
        internal = {
            "internal_event_id": "evt-1",
            "name": "Planning",
            "description": "Discuss Q2",
            "location": "Zoom",
            "timezone": "America/New_York",
            "start_utc": "2026-04-06T14:00:00Z",
            "end_utc": "2026-04-06T15:00:00Z",
            "all_day": False,
            "status": "busy",
        }
        serialized = serialize_internal_event_to_ical(event=internal)
        parsed = map_ical_to_internal_events(ical_payload=serialized["ical"])

        self.assertEqual(parsed["errors"], [])
        self.assertEqual(len(parsed["events"]), 1)
        evt = parsed["events"][0]
        self.assertEqual(evt["remote_uid"], serialized["uid"])
        self.assertEqual(evt["name"], "Planning")
        self.assertEqual(evt["description"], "Discuss Q2")
        self.assertEqual(evt["location"], "Zoom")
        self.assertEqual(evt["start_utc"], "2026-04-06T14:00:00Z")
        self.assertEqual(evt["end_utc"], "2026-04-06T15:00:00Z")

    def test_serializer_round_trip_all_day_event(self):
        internal = {
            "internal_event_id": "evt-2",
            "name": "Holiday",
            "description": "",
            "location": "",
            "all_day": True,
            "all_day_date": "2026-12-25",
            "status": "tentative",
        }
        serialized = serialize_internal_event_to_ical(event=internal)
        parsed = map_ical_to_internal_events(ical_payload=serialized["ical"])
        evt = parsed["events"][0]

        self.assertTrue(evt["all_day"])
        self.assertEqual(evt["all_day_date"], "2026-12-25")
        self.assertEqual(evt["status"], "tentative")

    def test_uid_is_stable_across_updates_for_same_event(self):
        base = {
            "internal_event_id": "evt-42",
            "name": "Standup",
            "start_utc": "2026-04-06T14:00:00Z",
            "end_utc": "2026-04-06T14:30:00Z",
            "all_day": False,
            "status": "busy",
        }
        first = serialize_internal_event_to_ical(event=base)

        updated = dict(base)
        updated["name"] = "Daily Standup"
        second = serialize_internal_event_to_ical(event=updated)

        self.assertEqual(first["uid"], second["uid"])

    def test_recurrence_round_trip_weekly(self):
        internal = {
            "internal_event_id": "evt-r1",
            "name": "Weekly Sync",
            "start_utc": "2026-04-06T14:00:00Z",
            "end_utc": "2026-04-06T15:00:00Z",
            "timezone": "UTC",
            "all_day": False,
            "status": "busy",
            "recurrence_rule": {"freq": "WEEKLY", "interval": 1, "byday": ["MO", "WE"], "count": 10},
        }
        serialized = serialize_internal_event_to_ical(event=internal)
        parsed = map_ical_to_internal_events(ical_payload=serialized["ical"])
        evt = parsed["events"][0]
        self.assertEqual(evt["recurrence_rule"]["freq"], "WEEKLY")
        self.assertEqual(evt["recurrence_rule"]["byday"], ["MO", "WE"])
        self.assertEqual(evt["recurrence_rule"]["count"], 10)

    def test_unsupported_recurrence_is_rejected_with_clear_reason(self):
        internal = {
            "internal_event_id": "evt-r2",
            "name": "Unsupported",
            "start_utc": "2026-04-06T14:00:00Z",
            "end_utc": "2026-04-06T15:00:00Z",
            "all_day": False,
            "status": "busy",
            "recurrence_rule": {"freq": "MONTHLY", "interval": 1, "bysetpos": [1]},
        }
        with self.assertRaises(ValueError) as ctx:
            serialize_internal_event_to_ical(event=internal)

        self.assertIn("Unsupported recurrence pattern fields", str(ctx.exception))

    def test_detached_instance_and_exdate_round_trip(self):
        internal = {
            "internal_event_id": "evt-r3",
            "name": "Weekly Sync",
            "start_utc": "2026-04-06T14:00:00Z",
            "end_utc": "2026-04-06T15:00:00Z",
            "all_day": False,
            "status": "busy",
            "recurrence_rule": {"freq": "WEEKLY", "interval": 1, "byday": ["MO"]},
            "recurrence_id_utc": "2026-04-13T14:00:00Z",
            "exdates_utc": ["2026-04-20T14:00:00Z"],
        }
        serialized = serialize_internal_event_to_ical(event=internal)
        parsed = map_ical_to_internal_events(ical_payload=serialized["ical"])
        evt = parsed["events"][0]
        self.assertTrue(evt["is_detached_instance"])
        self.assertEqual(evt["recurrence_id_utc"], "2026-04-13T14:00:00Z")
        self.assertIn("2026-04-20T14:00:00Z", evt["exdates_utc"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
