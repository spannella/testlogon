from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services import google_calendar_delete_propagation as svc


class _FakeTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key):
        item = self.items.get((Key["calendar_id"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def put_item(self, Item):
        self.items[(Item["calendar_id"], Item["sk"])] = dict(Item)

    def delete_item(self, Key):
        self.items.pop((Key["calendar_id"], Key["sk"]), None)


class TestGoogleCalendarDeletePropagation(unittest.TestCase):
    def test_cancelled_event_deletes_internal_event_and_tombstones_mapping(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "cal-1",
                "sk": "event#evt-1",
                "type": "event",
                "event_id": "evt-1",
            }
        )
        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(
                svc,
                "get_event_mapping_by_google_event",
                return_value={
                    "internal_calendar_id": "cal-1",
                    "internal_event_id": "evt-1",
                    "tombstone": False,
                },
            ),
            patch.object(svc, "mark_event_tombstone", return_value={"tombstone": True}) as mark,
        ):
            out = svc.handle_google_cancelled_event(
                user_sub="user-1",
                internal_calendar_id="cal-1",
                google_calendar_id="gcal-1",
                google_event_id="ge-1",
            )

        self.assertTrue(out["deleted"])
        self.assertTrue(out["tombstoned"])
        self.assertEqual(len(table.items), 0)
        mark.assert_called_once()

    def test_duplicate_cancelled_notification_is_idempotent(self):
        table = _FakeTable()
        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(
                svc,
                "get_event_mapping_by_google_event",
                return_value={
                    "internal_calendar_id": "cal-1",
                    "internal_event_id": "evt-1",
                    "tombstone": True,
                },
            ),
            patch.object(svc, "get_event_mapping", return_value={"tombstone": True}),
            patch.object(svc, "mark_event_tombstone") as mark,
        ):
            out = svc.handle_google_cancelled_event(
                user_sub="user-1",
                internal_calendar_id="cal-1",
                google_calendar_id="gcal-1",
                google_event_id="ge-1",
            )

        self.assertFalse(out["deleted"])
        self.assertTrue(out["idempotent"])
        mark.assert_not_called()


if __name__ == "__main__":
    unittest.main()
