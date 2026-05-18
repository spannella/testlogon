from __future__ import annotations

import unittest
from urllib import error as urlerror
from unittest.mock import MagicMock, patch

from app.services.calendar_integrations.apple_caldav import AppleCalDavConnectionService, AppleCalDavSyncService
from app.services.calendar_integrations.base import (
    CalendarIntegrationError,
    CalendarIntegrationErrorCode,
    CalendarProvider,
    CalendarProviderConfig,
)
from app.services.calendar_integrations.outbox import process_apple_push_outbox


class TestCalendarSyncObservability(unittest.TestCase):
    def _config(self) -> CalendarProviderConfig:
        return CalendarProviderConfig(
            provider=CalendarProvider.APPLE_CALDAV,
            enabled=True,
            base_url="https://caldav.icloud.com",
            connect_timeout_seconds=5.0,
            read_timeout_seconds=10.0,
            retry_max_attempts=3,
            poll_interval_seconds=300,
            poll_jitter_seconds=30,
            poll_batch_size=50,
        )

    def test_pull_records_success_run_and_latency_metrics(self):
        svc = AppleCalDavSyncService(self._config())
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_calendar_sync_state", return_value={"sync_token": None, "ctag": "ct-1"}),
            patch.object(svc, "_pull_with_ctag_or_window", return_value={"created": [], "updated": [], "deleted": [], "next_sync_token": None, "next_ctag": "ct-2"}),
            patch("app.services.calendar_integrations.apple_caldav.record_apple_caldav_sync_run_result"),
            patch("app.services.calendar_integrations.apple_caldav._record_calendar_metric") as rec_metric,
        ):
            out = svc.pull_changes(connection_id="conn-1", calendar_id="work")

        self.assertEqual(out, {"created": 0, "updated": 0, "deleted": 0})
        metric_names = [c.args[0] for c in rec_metric.call_args_list]
        self.assertIn("record_calendar_sync_run", metric_names)
        self.assertIn("record_calendar_sync_latency", metric_names)

    def test_push_conflict_records_conflict_and_latency_metrics(self):
        svc = AppleCalDavSyncService(self._config())
        existing_link = {
            "remote_uid": "evt-1@internal.calendar.local",
            "resource_url": "https://caldav.icloud.com/cal/work/evt-1.ics",
            "etag": "etag-old",
            "internal_event_id": "evt-1",
        }
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link_by_internal_event", return_value=existing_link),
            patch("app.services.calendar_integrations.apple_caldav.record_apple_conflict_audit"),
            patch.object(
                svc,
                "_caldav_upsert_event",
                side_effect=CalendarIntegrationError(
                    code=CalendarIntegrationErrorCode.PROTOCOL,
                    detail="etag_mismatch precondition failed",
                    retriable=False,
                ),
            ),
            patch("app.services.calendar_integrations.apple_caldav._record_calendar_metric") as rec_metric,
        ):
            out = svc.push_event(
                connection_id="conn-1",
                calendar_id="work",
                event={
                    "operation": "update",
                    "internal_event_id": "evt-1",
                    "name": "Planning Updated",
                    "start_utc": "2026-04-06T14:00:00Z",
                    "end_utc": "2026-04-06T15:00:00Z",
                    "all_day": False,
                    "status": "busy",
                },
            )

        self.assertEqual(out["status"], "conflict")
        metric_names = [c.args[0] for c in rec_metric.call_args_list]
        self.assertIn("record_calendar_sync_conflict", metric_names)
        self.assertIn("record_calendar_sync_run", metric_names)
        self.assertIn("record_calendar_sync_latency", metric_names)

    def test_validate_credentials_auth_failure_records_metric(self):
        svc = AppleCalDavConnectionService(self._config())
        with (
            patch(
                "app.services.calendar_integrations.apple_caldav._probe_caldav_credentials",
                side_effect=urlerror.HTTPError("", 401, "unauthorized", hdrs=None, fp=None),
            ),
            patch("app.services.calendar_integrations.apple_caldav._record_calendar_metric") as rec_metric,
        ):
            with self.assertRaises(CalendarIntegrationError):
                svc.validate_credentials(username="user@example.com", secret="bad-pass")

        rec_metric.assert_called_once_with("record_calendar_sync_auth_failure", provider="apple_caldav")

    def test_outbox_records_queue_backlog_metric(self):
        provider = MagicMock()
        provider.sync.push_event.return_value = {"status": "ok"}
        with (
            patch("app.services.calendar_integrations.outbox.get_provider_services", return_value=provider),
            patch("app.services.calendar_integrations.outbox.list_due_apple_push_outbox", return_value=[{"outbox_id": "o1", "connection_id": "c1", "external_calendar_id": "work", "operation": "update", "payload": {}}]),
            patch("app.services.calendar_integrations.outbox.finalize_apple_push_outbox_attempt", return_value={"status": "delivered"}),
            patch("app.services.calendar_integrations.outbox._record_calendar_metric") as rec_metric,
        ):
            out = process_apple_push_outbox()

        self.assertEqual(out["processed"], 1)
        rec_metric.assert_called_once_with(
            "record_calendar_sync_queue_backlog",
            provider="apple_caldav",
            queue="push_outbox_due",
            depth=1,
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
