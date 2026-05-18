from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services import google_calendar_outbound_jobs as svc


class _ConditionalCheckFailed(Exception):
    def __init__(self):
        super().__init__("duplicate")
        self.response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate"}}


class _FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item, ConditionExpression=None):
        key = (Item["calendar_id"], Item["sk"])
        if ConditionExpression and key in self.items:
            raise _ConditionalCheckFailed()
        self.items[key] = dict(Item)

    def get_item(self, Key):
        item = self.items.get((Key["calendar_id"], Key["sk"]))
        return {"Item": dict(item)} if item else {}


class TestGoogleCalendarOutboundJobs(unittest.TestCase):
    def test_enqueue_returns_single_logical_job_for_duplicates(self):
        table = _FakeTable()
        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(
                svc,
                "list_calendar_provider_mappings",
                return_value=[
                    {"internal_calendar_id": "cal-1", "google_calendar_id": "gcal-1", "active": True},
                    {"internal_calendar_id": "cal-1", "google_calendar_id": "gcal-2", "active": True},
                ],
            ),
        ):
            first = svc.enqueue_google_calendar_outbound_sync_job(
                owner_user_sub="owner-1",
                actor_user_sub="owner-1",
                action="update",
                internal_calendar_id="cal-1",
                internal_event_id="evt-1",
                event_snapshot={"updated_at_utc": "2026-01-01T00:00:00Z", "status": "busy"},
            )
            second = svc.enqueue_google_calendar_outbound_sync_job(
                owner_user_sub="owner-1",
                actor_user_sub="owner-1",
                action="update",
                internal_calendar_id="cal-1",
                internal_event_id="evt-1",
                event_snapshot={"updated_at_utc": "2026-01-01T00:00:00Z", "status": "busy"},
            )

        self.assertTrue(first["accepted"])
        self.assertFalse(first["duplicate"])
        self.assertTrue(second["accepted"])
        self.assertTrue(second["duplicate"])
        self.assertEqual(first["dedup_key"], second["dedup_key"])
        self.assertEqual(second["job"]["google_calendar_ids"], ["gcal-1", "gcal-2"])
        self.assertIn("correlation_id", first["job"])


if __name__ == "__main__":
    unittest.main()
