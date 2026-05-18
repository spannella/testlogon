from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib import error as urlerror

from app.services.calendar_integrations.apple_caldav import AppleCalDavSyncService
from app.services.calendar_integrations.base import (
    CalendarIntegrationError,
    CalendarIntegrationErrorCode,
    CalendarProvider,
    CalendarProviderConfig,
)


class TestAppleCalDavPushSync(unittest.TestCase):
    def _service(self) -> AppleCalDavSyncService:
        cfg = CalendarProviderConfig(
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
        return AppleCalDavSyncService(config=cfg)

    def test_create_update_delete_propagate_and_update_links(self):
        svc = self._service()
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link_by_internal_event", return_value=None),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link", return_value=None),
            patch.object(svc, "_caldav_upsert_event", return_value={"resource_url": "https://caldav.icloud.com/cal/work/evt-1.ics", "etag": "etag-1"}),
            patch("app.services.calendar_integrations.apple_caldav.upsert_apple_caldav_event_link") as upsert_link,
        ):
            created = svc.push_event(
                connection_id="conn-1",
                calendar_id="work",
                event={
                    "operation": "create",
                    "internal_event_id": "evt-1",
                    "name": "Planning",
                    "start_utc": "2026-04-06T14:00:00Z",
                    "end_utc": "2026-04-06T15:00:00Z",
                    "all_day": False,
                    "status": "busy",
                },
            )

        self.assertEqual(created["status"], "ok")
        self.assertEqual(created["operation"], "upsert")
        upsert_link.assert_called_once()

        existing_link = {
            "remote_uid": created["remote_uid"],
            "resource_url": created["resource_url"],
            "etag": created["etag"],
            "internal_event_id": "evt-1",
        }
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link_by_internal_event", return_value=existing_link),
            patch.object(svc, "_caldav_upsert_event", return_value={"resource_url": existing_link["resource_url"], "etag": "etag-2"}),
            patch("app.services.calendar_integrations.apple_caldav.upsert_apple_caldav_event_link") as upsert_link_update,
        ):
            updated = svc.push_event(
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

        self.assertEqual(updated["status"], "ok")
        self.assertEqual(updated["etag"], "etag-2")
        upsert_link_update.assert_called_once()

        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link_by_internal_event", return_value=existing_link),
            patch.object(svc, "_caldav_delete_event"),
            patch("app.services.calendar_integrations.apple_caldav.mark_apple_caldav_event_link_deleted") as mark_deleted,
        ):
            deleted = svc.push_event(
                connection_id="conn-1",
                calendar_id="work",
                event={"operation": "delete", "internal_event_id": "evt-1"},
            )

        self.assertEqual(deleted["status"], "ok")
        self.assertEqual(deleted["operation"], "delete")
        mark_deleted.assert_called_once()

    def test_etag_mismatch_returns_conflict(self):
        svc = self._service()
        existing_link = {
            "remote_uid": "evt-1@internal.calendar.local",
            "resource_url": "https://caldav.icloud.com/cal/work/evt-1.ics",
            "etag": "etag-old",
            "internal_event_id": "evt-1",
        }
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link_by_internal_event", return_value=existing_link),
            patch("app.services.calendar_integrations.apple_caldav.record_apple_conflict_audit") as record_audit,
            patch.object(
                svc,
                "_caldav_upsert_event",
                side_effect=CalendarIntegrationError(
                    code=CalendarIntegrationErrorCode.PROTOCOL,
                    detail="etag_mismatch precondition failed",
                    retriable=False,
                ),
            ),
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
        self.assertEqual(out["conflict_reason"], "etag_mismatch")
        record_audit.assert_called_once()

    def test_delete_detached_instance_updates_exdate_without_deleting_series(self):
        svc = self._service()
        existing_link = {
            "remote_uid": "evt-series@internal.calendar.local",
            "resource_url": "https://caldav.icloud.com/cal/work/evt-series.ics",
            "etag": "etag-old",
            "internal_event_id": "evt-series",
        }
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link_by_internal_event", return_value=existing_link),
            patch.object(svc, "_caldav_upsert_event") as upsert,
            patch.object(svc, "_caldav_delete_event") as delete_call,
        ):
            out = svc.push_event(
                connection_id="conn-1",
                calendar_id="work",
                event={
                    "operation": "delete",
                    "internal_event_id": "evt-series",
                    "recurrence_id_utc": "2026-04-13T14:00:00Z",
                },
            )

        self.assertEqual(out["operation"], "delete_instance")
        upsert.assert_called_once()
        delete_call.assert_not_called()

    def test_caldav_upsert_event_uses_real_http_when_connection_provided(self):
        svc = self._service()

        class _Resp:
            headers = {"ETag": "etag-http-1"}

            def geturl(self):
                return "https://caldav.icloud.com/cal/work/evt-1.ics"

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with (
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
                return_value={"username": "user@example.com", "app_specific_password": "secret"},
            ),
            patch("app.services.calendar_integrations.apple_caldav.urlrequest.urlopen", return_value=_Resp()) as urlopen_mock,
        ):
            out = svc._caldav_upsert_event(
                connection_id="conn-1",
                calendar_id="work",
                resource_url="https://caldav.icloud.com/cal/work/evt-1.ics",
                ical_payload="BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
                if_match="etag-old",
            )

        self.assertEqual(out["etag"], "etag-http-1")
        req = urlopen_mock.call_args.args[0]
        self.assertEqual(req.get_method(), "PUT")
        self.assertEqual(req.get_header("If-match"), "etag-old")

    def test_caldav_delete_event_maps_404_to_idempotent_success(self):
        svc = self._service()
        with (
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
                return_value={"username": "user@example.com", "app_specific_password": "secret"},
            ),
            patch(
                "app.services.calendar_integrations.apple_caldav.urlrequest.urlopen",
                side_effect=urlerror.HTTPError(
                    "https://caldav.icloud.com/cal/work/evt-1.ics",
                    404,
                    "Not Found",
                    hdrs=None,
                    fp=None,
                ),
            ),
        ):
            svc._caldav_delete_event(
                connection_id="conn-1",
                calendar_id="work",
                resource_url="https://caldav.icloud.com/cal/work/evt-1.ics",
                if_match="etag-old",
            )

    def test_caldav_upsert_event_returns_auth_error_when_credentials_missing(self):
        svc = self._service()
        with patch(
            "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
            side_effect=KeyError("missing"),
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc._caldav_upsert_event(
                    connection_id="conn-1",
                    calendar_id="work",
                    resource_url="https://caldav.icloud.com/cal/work/evt-1.ics",
                    ical_payload="BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
                    if_match=None,
                )
        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.AUTH)

    def test_caldav_delete_event_returns_auth_error_when_credentials_incomplete(self):
        svc = self._service()
        with patch(
            "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
            return_value={"username": "user@example.com", "app_specific_password": ""},
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc._caldav_delete_event(
                    connection_id="conn-1",
                    calendar_id="work",
                    resource_url="https://caldav.icloud.com/cal/work/evt-1.ics",
                    if_match=None,
                )
        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.AUTH)

    def test_caldav_upsert_event_rejects_resource_url_host_mismatch(self):
        svc = self._service()
        with patch(
            "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
            return_value={"username": "user@example.com", "app_specific_password": "secret"},
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc._caldav_upsert_event(
                    connection_id="conn-1",
                    calendar_id="work",
                    resource_url="https://evil.example.com/cal/work/evt-1.ics",
                    ical_payload="BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
                    if_match=None,
                )
        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.PROTOCOL)

    def test_caldav_delete_event_rejects_forbidden_resource_host(self):
        svc = self._service()
        with patch(
            "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
            return_value={"username": "user@example.com", "app_specific_password": "secret"},
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc._caldav_delete_event(
                    connection_id="conn-1",
                    calendar_id="work",
                    resource_url="https://127.0.0.1/cal/work/evt-1.ics",
                    if_match=None,
                )
        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.PROTOCOL)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
