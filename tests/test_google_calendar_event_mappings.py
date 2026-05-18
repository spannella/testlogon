from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.services import google_calendar_event_mappings as svc


class _FakeTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item):
        self.items[(Item["calendar_id"], Item["sk"])] = dict(Item)

    def get_item(self, Key):
        item = self.items.get((Key["calendar_id"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def query(self, KeyConditionExpression):
        return {"Items": [dict(v) for v in self.items.values()]}

    def delete_item(self, Key):
        self.items.pop((Key["calendar_id"], Key["sk"]), None)


class TestGoogleCalendarEventMappings(unittest.TestCase):
    def test_upsert_creates_bi_directional_unique_mapping(self):
        table = _FakeTable()
        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            out = svc.upsert_event_mapping(
                user_sub="user-1",
                internal_calendar_id="cal-1",
                internal_event_id="evt-1",
                google_calendar_id="gcal-1",
                google_event_id="gevt-1",
                provider_etag='"abc"',
                sync_fingerprint="fp-1",
            )

        self.assertTrue(out["active"])
        self.assertEqual(out["google_event_id"], "gevt-1")

    def test_upsert_rejects_google_event_mapped_to_another_internal_event(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_evtmap#user-1",
                "sk": "map#cal-a#evt-a",
                "type": "calendar_event_provider_mapping",
                "provider": "google",
                "user_sub": "user-1",
                "internal_calendar_id": "cal-a",
                "internal_event_id": "evt-a",
                "google_calendar_id": "gcal-1",
                "google_event_id": "gevt-1",
                "active": True,
                "tombstone": False,
            }
        )

        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            with self.assertRaises(HTTPException):
                svc.upsert_event_mapping(
                    user_sub="user-1",
                    internal_calendar_id="cal-b",
                    internal_event_id="evt-b",
                    google_calendar_id="gcal-1",
                    google_event_id="gevt-1",
                    provider_etag=None,
                    sync_fingerprint=None,
                )

    def test_tombstone_prevents_accidental_recreate_until_expiry(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_evtmap#user-1",
                "sk": "map#cal-1#evt-1",
                "type": "calendar_event_provider_mapping",
                "provider": "google",
                "user_sub": "user-1",
                "internal_calendar_id": "cal-1",
                "internal_event_id": "evt-1",
                "google_calendar_id": "gcal-1",
                "google_event_id": "gevt-1",
                "active": False,
                "tombstone": True,
                "tombstone_expires_at_utc": "2099-01-01T00:00:00Z",
            }
        )

        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            with self.assertRaises(HTTPException):
                svc.upsert_event_mapping(
                    user_sub="user-1",
                    internal_calendar_id="cal-1",
                    internal_event_id="evt-1",
                    google_calendar_id="gcal-1",
                    google_event_id="gevt-1",
                    provider_etag=None,
                    sync_fingerprint=None,
                )

    def test_mark_tombstone_and_purge_expired(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_evtmap#user-1",
                "sk": "map#cal-1#evt-1",
                "type": "calendar_event_provider_mapping",
                "provider": "google",
                "user_sub": "user-1",
                "internal_calendar_id": "cal-1",
                "internal_event_id": "evt-1",
                "google_calendar_id": "gcal-1",
                "google_event_id": "gevt-1",
                "active": True,
                "tombstone": False,
                "provider_etag": "",
                "sync_fingerprint": "",
                "last_synced_at_utc": "",
            }
        )

        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(svc, "S", SimpleNamespace(google_calendar_event_tombstone_retention_days=1)),
        ):
            tomb = svc.mark_event_tombstone(
                user_sub="user-1",
                internal_calendar_id="cal-1",
                internal_event_id="evt-1",
                reason="deleted",
            )
            self.assertTrue(tomb["tombstone"])
            removed = svc.purge_expired_event_tombstones(
                user_sub="user-1",
                now_utc=datetime(2100, 1, 1, tzinfo=timezone.utc),
            )

        self.assertEqual(removed, 1)
        self.assertEqual(len(table.items), 0)

    def test_get_event_mapping_by_google_event(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_evtmap#user-1",
                "sk": "map#cal-1#evt-1",
                "type": "calendar_event_provider_mapping",
                "provider": "google",
                "user_sub": "user-1",
                "internal_calendar_id": "cal-1",
                "internal_event_id": "evt-1",
                "google_calendar_id": "gcal-1",
                "google_event_id": "gevt-1",
                "active": True,
                "tombstone": False,
                "provider_etag": '"abc"',
                "sync_fingerprint": "fp-1",
                "last_synced_at_utc": "2026-01-01T00:00:00Z",
            }
        )
        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            out = svc.get_event_mapping_by_google_event(
                user_sub="user-1",
                google_calendar_id="gcal-1",
                google_event_id="gevt-1",
            )

        self.assertEqual(out["internal_event_id"], "evt-1")

    def test_mark_event_sync_conflict_persists_conflict_state(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_evtmap#user-1",
                "sk": "map#cal-1#evt-1",
                "type": "calendar_event_provider_mapping",
                "provider": "google",
                "user_sub": "user-1",
                "internal_calendar_id": "cal-1",
                "internal_event_id": "evt-1",
                "google_calendar_id": "gcal-1",
                "google_event_id": "gevt-1",
                "active": True,
                "tombstone": False,
            }
        )
        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            out = svc.mark_event_sync_conflict(
                user_sub="user-1",
                internal_calendar_id="cal-1",
                internal_event_id="evt-1",
                reason="etag_mismatch",
                internal_snapshot={"name": "A"},
                provider_snapshot={"status": 412},
            )

        self.assertEqual(out["sync_state"], "conflict")
        self.assertEqual(out["conflict_reason"], "etag_mismatch")


if __name__ == "__main__":
    unittest.main()
