from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.services import google_calendar_mappings as svc


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


class TestGoogleCalendarMappings(unittest.TestCase):
    def test_create_mapping_requires_calendar_owner(self):
        table = _FakeTable()
        table.put_item(Item={"calendar_id": "cal-1", "sk": "meta", "owner_user_sub": "owner-1"})

        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            with self.assertRaises(HTTPException):
                svc.create_calendar_provider_mapping(
                    user_sub="user-2",
                    internal_calendar_id="cal-1",
                    google_calendar_id="google-cal-1",
                )

    def test_create_mapping_prevents_duplicate_active_internal_mapping(self):
        table = _FakeTable()
        table.put_item(Item={"calendar_id": "cal-1", "sk": "meta", "owner_user_sub": "user-1"})
        table.put_item(
            Item={
                "calendar_id": "gcal_map#user-1",
                "sk": "map#m1",
                "type": "calendar_provider_mapping",
                "provider": "google",
                "mapping_id": "m1",
                "user_sub": "user-1",
                "internal_calendar_id": "cal-1",
                "google_calendar_id": "google-cal-1",
                "active": True,
                "created_at_utc": "2026-01-01T00:00:00Z",
                "updated_at_utc": "2026-01-01T00:00:00Z",
                "unmapped_at_utc": "",
            }
        )

        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            with self.assertRaises(HTTPException):
                svc.create_calendar_provider_mapping(
                    user_sub="user-1",
                    internal_calendar_id="cal-1",
                    google_calendar_id="google-cal-2",
                )

    def test_reactivate_mapping_preserves_historical_record(self):
        table = _FakeTable()
        table.put_item(Item={"calendar_id": "cal-1", "sk": "meta", "owner_user_sub": "user-1"})
        table.put_item(
            Item={
                "calendar_id": "gcal_map#user-1",
                "sk": "map#m1",
                "type": "calendar_provider_mapping",
                "provider": "google",
                "mapping_id": "m1",
                "user_sub": "user-1",
                "internal_calendar_id": "cal-1",
                "google_calendar_id": "google-cal-1",
                "active": False,
                "created_at_utc": "2026-01-01T00:00:00Z",
                "updated_at_utc": "2026-01-02T00:00:00Z",
                "unmapped_at_utc": "2026-01-02T00:00:00Z",
            }
        )

        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(svc, "emit_google_calendar_audit_event") as audit,
        ):
            out = svc.create_calendar_provider_mapping(
                user_sub="user-1",
                internal_calendar_id="cal-1",
                google_calendar_id="google-cal-1",
            )

        self.assertEqual(out["mapping_id"], "m1")
        self.assertTrue(out["active"])
        self.assertEqual(table.items[("gcal_map#user-1", "map#m1")]["unmapped_at_utc"], "")
        audit.assert_called_once()

    def test_unmap_marks_inactive_and_preserves_record(self):
        table = _FakeTable()
        table.put_item(
            Item={
                "calendar_id": "gcal_map#user-1",
                "sk": "map#m1",
                "type": "calendar_provider_mapping",
                "provider": "google",
                "mapping_id": "m1",
                "user_sub": "user-1",
                "internal_calendar_id": "cal-1",
                "google_calendar_id": "google-cal-1",
                "active": True,
                "created_at_utc": "2026-01-01T00:00:00Z",
                "updated_at_utc": "2026-01-01T00:00:00Z",
                "unmapped_at_utc": "",
            }
        )

        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(svc, "emit_google_calendar_audit_event") as audit,
        ):
            out = svc.unmap_calendar_provider_mapping(user_sub="user-1", mapping_id="m1")

        self.assertFalse(out["active"])
        self.assertNotEqual(out["unmapped_at_utc"], "")
        self.assertIn(("gcal_map#user-1", "map#m1"), table.items)
        audit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
