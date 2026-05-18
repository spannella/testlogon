from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services import google_calendar_sync_full_import as svc


class _FakeCalendarTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key):
        item = self.items.get((Key["calendar_id"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def put_item(self, Item):
        self.items[(Item["calendar_id"], Item["sk"])] = dict(Item)


class TestGoogleCalendarFullImport(unittest.TestCase):
    def test_full_import_creates_events_and_mappings(self):
        table = _FakeCalendarTable()
        mapping_store: dict[tuple[str, str], dict] = {}
        index_by_google: dict[tuple[str, str], dict] = {}

        def _fake_upsert_event_mapping(**kwargs):
            item = dict(kwargs)
            mapping_store[(kwargs["internal_calendar_id"], kwargs["internal_event_id"])] = item
            index_by_google[(kwargs["google_calendar_id"], kwargs["google_event_id"])] = item
            return item

        def _fake_get_by_google_event(**kwargs):
            key = (kwargs["google_calendar_id"], kwargs["google_event_id"])
            item = index_by_google.get(key)
            if not item:
                raise svc.HTTPException(status_code=404, detail="not found")
            return item

        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(
                svc,
                "list_calendar_provider_mappings",
                return_value=[
                    {
                        "internal_calendar_id": "cal-1",
                        "google_calendar_id": "gcal-1",
                        "active": True,
                    }
                ],
            ),
            patch.object(
                svc,
                "list_google_calendar_events",
                return_value={
                    "items": [
                        {
                            "id": "ge-1",
                            "etag": '"e1"',
                            "updated": "2026-01-01T00:00:00Z",
                            "summary": "Event one",
                            "start": {"dateTime": "2026-01-01T10:00:00Z", "timeZone": "UTC"},
                            "end": {"dateTime": "2026-01-01T11:00:00Z", "timeZone": "UTC"},
                        }
                    ]
                },
            ),
            patch.object(
                svc,
                "map_google_event_to_internal",
                return_value={
                    "event": {
                        "name": "Event one",
                        "description": "",
                        "timezone": "UTC",
                        "start_utc": "2026-01-01T10:00:00Z",
                        "end_utc": "2026-01-01T11:00:00Z",
                        "all_day": False,
                        "all_day_date": None,
                        "attendees": [],
                        "status": "busy",
                        "recurrence_rule": None,
                        "exdates_utc": None,
                        "recurrence_overrides": None,
                    },
                    "source_metadata": {
                        "google_event_id": "ge-1",
                        "google_etag": '"e1"',
                        "google_updated": "2026-01-01T00:00:00Z",
                    },
                    "warnings": [],
                },
            ),
            patch.object(svc, "build_google_event_sync_fingerprint", return_value="fp-1"),
            patch.object(svc, "upsert_event_mapping", side_effect=_fake_upsert_event_mapping),
            patch.object(svc, "get_event_mapping_by_google_event", side_effect=_fake_get_by_google_event),
            patch.object(svc, "get_event_mapping", side_effect=lambda **kwargs: mapping_store[(kwargs["internal_calendar_id"], kwargs["internal_event_id"])]),
        ):
            first = svc.run_google_calendar_full_import_job(user_sub="user-1", connection_id="google-primary")
            second = svc.run_google_calendar_full_import_job(user_sub="user-1", connection_id="google-primary")

        self.assertEqual(first["created"], 1)
        self.assertEqual(first["updated"], 0)
        self.assertEqual(first["errors"], 0)
        self.assertEqual(second["skipped"], 1)
        self.assertEqual(second["created"], 0)
        self.assertEqual(second["updated"], 0)

    def test_queue_handler_requires_payload_fields(self):
        with self.assertRaises(svc.HTTPException):
            svc.handle_google_calendar_full_import_queue_job({})


if __name__ == "__main__":
    unittest.main()
