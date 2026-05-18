from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services import google_calendar_sync_incremental as svc


class _FakeCalendarTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key):
        item = self.items.get((Key["calendar_id"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def put_item(self, Item):
        self.items[(Item["calendar_id"], Item["sk"])] = dict(Item)


class TestGoogleCalendarIncrementalSync(unittest.TestCase):
    def test_incremental_sync_uses_sync_token_and_commits_new_cursor(self):
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
                "get_calendar_provider_connection",
                return_value={"sync_cursor": '{"gcal-1":"sync-token-old"}'},
            ),
            patch.object(
                svc,
                "list_calendar_provider_mappings",
                return_value=[{"internal_calendar_id": "cal-1", "google_calendar_id": "gcal-1", "active": True}],
            ),
            patch.object(
                svc,
                "list_google_calendar_events",
                return_value={
                    "items": [
                        {
                            "id": "ge-1",
                            "etag": '"e1"',
                            "updated": "2026-01-02T00:00:00Z",
                            "summary": "Changed event",
                            "start": {"dateTime": "2026-01-02T10:00:00Z"},
                            "end": {"dateTime": "2026-01-02T11:00:00Z"},
                            "status": "confirmed",
                        }
                    ],
                    "nextSyncToken": "sync-token-new",
                },
            ),
            patch.object(
                svc,
                "map_google_event_to_internal",
                return_value={
                    "event": {
                        "name": "Changed event",
                        "description": "",
                        "timezone": "UTC",
                        "start_utc": "2026-01-02T10:00:00Z",
                        "end_utc": "2026-01-02T11:00:00Z",
                        "all_day": False,
                        "all_day_date": None,
                        "attendees": [],
                        "status": "busy",
                        "recurrence_rule": None,
                        "exdates_utc": None,
                        "recurrence_overrides": None,
                    },
                    "source_metadata": {"google_etag": '"e1"', "google_updated": "2026-01-02T00:00:00Z"},
                    "warnings": [],
                },
            ),
            patch.object(svc, "build_google_event_sync_fingerprint", return_value="fp-new"),
            patch.object(svc, "get_event_mapping_by_google_event", side_effect=_fake_get_by_google_event),
            patch.object(svc, "upsert_event_mapping", side_effect=_fake_upsert_event_mapping),
            patch.object(svc, "update_calendar_provider_connection_sync_status") as update_conn,
        ):
            out = svc.run_google_calendar_incremental_sync_job(user_sub="user-1", connection_id="google-primary")

        self.assertEqual(out["created"], 1)
        self.assertEqual(out["errors"], 0)
        self.assertEqual(out["fallback_full_syncs"], 0)
        update_conn.assert_called()
        args = update_conn.call_args.kwargs
        self.assertIn("sync-token-new", args["sync_cursor"])

    def test_cancelled_event_uses_delete_propagation(self):
        table = _FakeCalendarTable()
        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(svc, "get_calendar_provider_connection", return_value={"sync_cursor": '{"gcal-1":"sync-token-old"}'}),
            patch.object(
                svc,
                "list_calendar_provider_mappings",
                return_value=[{"internal_calendar_id": "cal-1", "google_calendar_id": "gcal-1", "active": True}],
            ),
            patch.object(
                svc,
                "list_google_calendar_events",
                return_value={
                    "items": [{"id": "ge-1", "status": "cancelled"}],
                    "nextSyncToken": "sync-token-new",
                },
            ),
            patch.object(svc, "handle_google_cancelled_event", return_value={"deleted": True}) as delete_handler,
            patch.object(svc, "update_calendar_provider_connection_sync_status"),
        ):
            out = svc.run_google_calendar_incremental_sync_job(user_sub="user-1", connection_id="google-primary")

        self.assertEqual(out["deleted"], 1)
        delete_handler.assert_called_once()

    def test_invalid_sync_token_falls_back_to_full_sync(self):
        table = _FakeCalendarTable()
        bad_exc = svc.HTTPException(
            status_code=400,
            detail={"provider_status_code": 410, "message": "Sync token is no longer valid"},
        )
        pages = [
            bad_exc,
            {"items": [], "nextSyncToken": "sync-after-full"},
        ]

        def _fake_list_events(**kwargs):
            value = pages.pop(0)
            if isinstance(value, Exception):
                raise value
            return value

        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(svc, "get_calendar_provider_connection", return_value={"sync_cursor": '{"gcal-1":"bad"}'}),
            patch.object(
                svc,
                "list_calendar_provider_mappings",
                return_value=[{"internal_calendar_id": "cal-1", "google_calendar_id": "gcal-1", "active": True}],
            ),
            patch.object(svc, "list_google_calendar_events", side_effect=_fake_list_events),
            patch.object(svc, "run_google_calendar_full_import_job", return_value={"created": 10}) as full_sync,
            patch.object(svc, "update_calendar_provider_connection_sync_status") as update_conn,
        ):
            out = svc.run_google_calendar_incremental_sync_job(user_sub="user-1", connection_id="google-primary")

        self.assertEqual(out["fallback_full_syncs"], 1)
        self.assertEqual(out["errors"], 0)
        full_sync.assert_called_once()
        update_conn.assert_called()


if __name__ == "__main__":
    unittest.main()
