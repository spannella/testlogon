from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services import google_calendar_sync_outbound as svc


class _FakeTable:
    def __init__(self, jobs=None, events=None):
        self.jobs = jobs or []
        self.events = events or {}
        self.items = {}

    def query(self, KeyConditionExpression):
        return {"Items": list(self.jobs)}

    def get_item(self, Key):
        if str(Key["calendar_id"]).startswith("gcal_outbox#"):
            item = self.items.get((Key["calendar_id"], Key["sk"]))
            return {"Item": dict(item)} if item else {}
        event = self.events.get((Key["calendar_id"], Key["sk"]))
        return {"Item": dict(event)} if event else {}

    def put_item(self, Item):
        self.items[(Item["calendar_id"], Item["sk"])] = dict(Item)


class TestGoogleCalendarSyncOutbound(unittest.TestCase):
    def test_update_conflict_sets_job_status_conflict(self):
        job = {
            "calendar_id": "gcal_outbox#owner-1",
            "sk": "job#abc",
            "type": "google_calendar_outbound_sync_job",
            "status": "pending",
            "action": "update",
            "internal_calendar_id": "cal-1",
            "internal_event_id": "evt-1",
            "enqueued_at_utc": "2026-01-01T00:00:00Z",
        }
        table = _FakeTable(jobs=[job], events={("cal-1", "event#evt-1"): {"type": "event", "name": "A"}})
        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(
                svc,
                "get_event_mapping",
                return_value={
                    "google_calendar_id": "gcal-1",
                    "google_event_id": "ge-1",
                    "provider_etag": '"etag-1"',
                },
            ),
            patch.object(svc, "map_internal_event_to_google", return_value={"google_event": {"summary": "A"}}),
            patch.object(svc, "detect_sync_conflict", return_value={"reason": "etag_mismatch", "is_conflict": True}),
            patch.object(svc, "mark_event_sync_conflict") as mark_conflict,
            patch.object(svc, "record_google_calendar_sync_conflict") as record_conflict_metric,
            patch.object(
                svc,
                "patch_google_calendar_event",
                side_effect=svc.HTTPException(
                    status_code=400,
                    detail={"provider_status_code": 412, "message": "Precondition Failed"},
                ),
            ),
        ):
            out = svc.process_google_calendar_outbound_jobs(owner_user_sub="owner-1", connection_id="google-primary")

        self.assertEqual(out["conflicts"], 1)
        stored = table.items[("gcal_outbox#owner-1", "job#abc")]
        self.assertEqual(stored["status"], "conflict")
        mark_conflict.assert_called_once()
        record_conflict_metric.assert_called_once()

    def test_create_success_updates_mapping_metadata(self):
        job = {
            "calendar_id": "gcal_outbox#owner-1",
            "sk": "job#create-1",
            "type": "google_calendar_outbound_sync_job",
            "status": "pending",
            "action": "create",
            "internal_calendar_id": "cal-1",
            "internal_event_id": "evt-1",
            "google_calendar_ids": ["gcal-1"],
            "enqueued_at_utc": "2026-01-01T00:00:00Z",
        }
        table = _FakeTable(
            jobs=[job],
            events={
                ("cal-1", "event#evt-1"): {
                    "type": "event",
                    "name": "A",
                    "description": "",
                    "timezone": "UTC",
                    "start_utc": "2026-01-01T10:00:00Z",
                    "end_utc": "2026-01-01T11:00:00Z",
                    "all_day": False,
                }
            },
        )
        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(svc, "map_internal_event_to_google", return_value={"google_event": {"summary": "A"}}),
            patch.object(
                svc,
                "create_google_calendar_event",
                return_value={
                    "id": "ge-1",
                    "etag": '"etag-2"',
                    "updated": "2026-01-01T12:00:00Z",
                    "summary": "A",
                    "start": {"dateTime": "2026-01-01T10:00:00Z"},
                    "end": {"dateTime": "2026-01-01T11:00:00Z"},
                },
            ),
            patch.object(svc, "build_google_event_sync_fingerprint", return_value="fp-1"),
            patch.object(svc, "upsert_event_mapping") as upsert_map,
        ):
            out = svc.process_google_calendar_outbound_jobs(owner_user_sub="owner-1", connection_id="google-primary")

        self.assertEqual(out["success"], 1)
        upsert_map.assert_called_once()
        stored = table.items[("gcal_outbox#owner-1", "job#create-1")]
        self.assertEqual(stored["status"], "done")

    def test_retryable_error_schedules_backoff_then_dead_letters_on_budget_exhaustion(self):
        job = {
            "calendar_id": "gcal_outbox#owner-1",
            "sk": "job#retry-1",
            "type": "google_calendar_outbound_sync_job",
            "status": "pending",
            "action": "create",
            "internal_calendar_id": "cal-1",
            "internal_event_id": "evt-1",
            "google_calendar_ids": ["gcal-1"],
            "enqueued_at_utc": "2026-01-01T00:00:00Z",
            "attempts": 0,
        }
        table = _FakeTable(
            jobs=[job],
            events={("cal-1", "event#evt-1"): {"type": "event", "name": "A"}},
        )
        retry_exc = svc.HTTPException(status_code=503, detail={"retryable": True, "message": "temporary"})
        with (
            patch.object(svc, "T", SimpleNamespace(calendar=table)),
            patch.object(svc, "set_google_calendar_outbox_backlog"),
            patch.object(svc, "record_google_calendar_sync_latency"),
            patch.object(svc, "record_google_calendar_sync_job"),
            patch.object(svc, "S", SimpleNamespace(
                google_calendar_connection_default_id="google-primary",
                google_calendar_outbound_retry_max_attempts=2,
                google_calendar_outbound_retry_base_seconds=2,
                google_calendar_outbound_retry_max_seconds=10,
                google_calendar_outbound_retry_jitter_ratio=0.0,
            )),
            patch.object(svc, "map_internal_event_to_google", return_value={"google_event": {"summary": "A"}}),
            patch.object(svc, "create_google_calendar_event", side_effect=retry_exc),
            patch.object(svc, "emit_google_calendar_audit_event"),
        ):
            first = svc.process_google_calendar_outbound_jobs(owner_user_sub="owner-1", connection_id="google-primary")
            first_stored = table.items[("gcal_outbox#owner-1", "job#retry-1")]
            self.assertEqual(first["retries_scheduled"], 1)
            self.assertEqual(first_stored["status"], "retry_pending")
            self.assertIn("next_attempt_at_utc", first_stored)

            replay_due = dict(first_stored)
            replay_due["next_attempt_at_utc"] = "2000-01-01T00:00:00Z"
            replay_due.setdefault("type", "google_calendar_outbound_sync_job")
            replay_due.setdefault("action", "create")
            replay_due.setdefault("internal_calendar_id", "cal-1")
            replay_due.setdefault("internal_event_id", "evt-1")
            replay_due.setdefault("google_calendar_ids", ["gcal-1"])
            replay_due.setdefault("enqueued_at_utc", "2026-01-01T00:00:00Z")
            table.jobs = [replay_due]
            second = svc.process_google_calendar_outbound_jobs(owner_user_sub="owner-1", connection_id="google-primary")

        self.assertEqual(second["dead_lettered"], 1)
        second_stored = table.items[("gcal_outbox#owner-1", "job#retry-1")]
        self.assertEqual(second_stored["status"], "dead_letter")
        self.assertEqual(second_stored["dead_letter_reason"], "retry_budget_exhausted")
        self.assertIn("replay_hint", second_stored)

    def test_replay_dead_letters_marks_jobs_pending(self):
        dead_letter = {
            "calendar_id": "gcal_outbox#owner-1",
            "sk": "job#dead-1",
            "type": "google_calendar_outbound_sync_job",
            "status": "dead_letter",
            "attempts": 3,
            "dead_lettered_at_utc": "2026-01-01T00:00:00Z",
        }
        table = _FakeTable(jobs=[dead_letter])
        table.items[("gcal_outbox#owner-1", "job#dead-1")] = dict(dead_letter)
        with patch.object(svc, "T", SimpleNamespace(calendar=table)):
            out = svc.replay_google_calendar_dead_letters(owner_user_sub="owner-1", limit=10)

        self.assertEqual(out["replayed"], 1)
        stored = table.items[("gcal_outbox#owner-1", "job#dead-1")]
        self.assertEqual(stored["status"], "pending")
        self.assertEqual(stored["replay_count"], 1)
        self.assertIn("dead_letter_replayed_at_utc", stored)


if __name__ == "__main__":
    unittest.main()
