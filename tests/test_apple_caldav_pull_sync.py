from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from app.services.calendar_integrations.apple_caldav import AppleCalDavSyncService
from app.services.calendar_integrations.base import (
    CalendarIntegrationError,
    CalendarIntegrationErrorCode,
    CalendarProvider,
    CalendarProviderConfig,
)


class TestAppleCalDavPullSync(unittest.TestCase):
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

    def test_pull_sync_uses_sync_token_and_reconciles_changes(self):
        svc = self._service()
        pull_with_token = MagicMock(
            return_value={
                "created": [{"remote_uid": "uid-new", "etag": "e1", "resource_url": "u1"}],
                "updated": [{"remote_uid": "uid-upd", "etag": "e2", "resource_url": "u2"}],
                "deleted": [{"remote_uid": "uid-del"}],
                "next_sync_token": "tok-2",
                "next_ctag": "ct-2",
            }
        )
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_calendar_sync_state", return_value={"sync_token": "tok-1", "ctag": "ct-1", "calendar_url": "https://caldav.icloud.com/custom/work/"}),
            patch.object(svc, "_pull_with_sync_token", pull_with_token),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link") as get_link,
            patch.object(svc, "_upsert_internal_event_from_remote", side_effect=["evt-new", "evt-upd"]),
            patch("app.services.calendar_integrations.apple_caldav.upsert_apple_caldav_event_link") as upsert_link,
            patch.object(svc, "_soft_delete_internal_event") as soft_delete,
            patch("app.services.calendar_integrations.apple_caldav.mark_apple_caldav_event_link_deleted") as mark_deleted,
            patch("app.services.calendar_integrations.apple_caldav.record_apple_caldav_sync_run_result") as record_run,
        ):
            get_link.side_effect = [
                {"internal_event_id": "evt-upd"},
                {"internal_event_id": "evt-del"},
            ]
            stats = svc.pull_changes(connection_id="conn-1", calendar_id="work")

        self.assertEqual(stats, {"created": 1, "updated": 1, "deleted": 1})
        self.assertEqual(
            pull_with_token.call_args.kwargs["calendar_url"],
            "https://caldav.icloud.com/custom/work/",
        )
        self.assertEqual(upsert_link.call_count, 2)
        soft_delete.assert_called_once_with(connection_id="conn-1", calendar_id="work", internal_event_id="evt-del")
        mark_deleted.assert_called_once()
        self.assertEqual(record_run.call_args.kwargs["status"], "success")
        self.assertEqual(record_run.call_args.kwargs["sync_token"], "tok-2")
        self.assertEqual(record_run.call_args.kwargs["ctag"], "ct-2")

    def test_pull_with_sync_token_reports_created_updated_deleted_and_next_token(self):
        svc = self._service()

        class _Resp:
            def read(self):
                return b"""<?xml version='1.0' encoding='utf-8'?>
<d:multistatus xmlns:d='DAV:' xmlns:c='urn:ietf:params:xml:ns:caldav'>
  <d:sync-token>tok-next</d:sync-token>
  <d:response>
    <d:href>/cal/work/new.ics</d:href>
    <d:propstat><d:prop><d:getetag>etag-new</d:getetag><c:calendar-data>NEW</c:calendar-data></d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/cal/work/upd.ics</d:href>
    <d:propstat><d:prop><d:getetag>etag-upd</d:getetag><c:calendar-data>UPD</c:calendar-data></d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/cal/work/resource-key.ics</d:href>
    <d:status>HTTP/1.1 404 Not Found</d:status>
  </d:response>
</d:multistatus>"""

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with (
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
                return_value={"username": "user@example.com", "app_specific_password": "app-pass"},
            ),
            patch(
                "app.services.calendar_integrations.apple_caldav.map_ical_to_internal_events",
                side_effect=[
                    {"events": [{"remote_uid": "uid-new"}], "errors": []},
                    {"events": [{"remote_uid": "uid-upd"}], "errors": []},
                ],
            ),
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link",
                side_effect=[None, {"internal_event_id": "evt-upd"}],
            ),
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link_by_resource_url",
                return_value={"remote_uid": "uid-deleted-known"},
            ),
            patch("app.services.calendar_integrations.apple_caldav.urlrequest.urlopen", return_value=_Resp()),
        ):
            out = svc._pull_with_sync_token(connection_id="conn-1", calendar_id="work", sync_token="tok-prev")

        self.assertEqual(out["next_sync_token"], "tok-next")
        self.assertEqual(len(out["created"]), 1)
        self.assertEqual(len(out["updated"]), 1)
        self.assertEqual(len(out["deleted"]), 1)
        self.assertEqual(out["deleted"][0]["remote_uid"], "uid-deleted-known")

    def test_pull_with_sync_token_detects_delete_from_propstat_status(self):
        svc = self._service()

        class _Resp:
            def read(self):
                return b"""<?xml version='1.0' encoding='utf-8'?>
<d:multistatus xmlns:d='DAV:' xmlns:c='urn:ietf:params:xml:ns:caldav'>
  <d:sync-token>tok-next</d:sync-token>
  <d:response>
    <d:href>/cal/work/deleted-propstat.ics</d:href>
    <d:propstat>
      <d:status>HTTP/1.1 404 Not Found</d:status>
      <d:prop><d:getetag>etag-del</d:getetag></d:prop>
    </d:propstat>
  </d:response>
</d:multistatus>"""

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with (
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
                return_value={"username": "user@example.com", "app_specific_password": "app-pass"},
            ),
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link_by_resource_url",
                return_value={"remote_uid": "uid-del-propstat"},
            ),
            patch("app.services.calendar_integrations.apple_caldav.urlrequest.urlopen", return_value=_Resp()),
        ):
            out = svc._pull_with_sync_token(connection_id="conn-1", calendar_id="work", sync_token="tok-prev")

        self.assertEqual(out["next_sync_token"], "tok-next")
        self.assertEqual(len(out["deleted"]), 1)
        self.assertEqual(out["deleted"][0]["remote_uid"], "uid-del-propstat")

    def test_pull_sync_falls_back_to_ctag_when_sync_token_missing(self):
        svc = self._service()
        ctag_pull = MagicMock(return_value={"created": [], "updated": [], "deleted": [], "next_sync_token": None, "next_ctag": "ct-2"})
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_calendar_sync_state", return_value={"sync_token": None, "ctag": "ct-1", "calendar_url": "https://caldav.icloud.com/custom/work/"}),
            patch.object(svc, "_pull_with_ctag_or_window", ctag_pull),
            patch("app.services.calendar_integrations.apple_caldav.record_apple_caldav_sync_run_result") as record_run,
        ):
            stats = svc.pull_changes(connection_id="conn-1", calendar_id="work")

        self.assertEqual(stats, {"created": 0, "updated": 0, "deleted": 0})
        self.assertEqual(
            ctag_pull.call_args.kwargs["calendar_url"],
            "https://caldav.icloud.com/custom/work/",
        )
        self.assertEqual(record_run.call_args.kwargs["status"], "success")
        self.assertEqual(record_run.call_args.kwargs["ctag"], "ct-2")

    def test_pull_sync_falls_back_when_sync_token_is_invalid(self):
        svc = self._service()
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_calendar_sync_state", return_value={"sync_token": "tok-1", "ctag": "ct-1"}),
            patch.object(
                svc,
                "_pull_with_sync_token",
                side_effect=CalendarIntegrationError(
                    code=CalendarIntegrationErrorCode.PROTOCOL,
                    detail="Server rejected valid-sync-token; HTTP 410",
                    retriable=False,
                ),
            ),
            patch.object(svc, "_pull_with_ctag_or_window", return_value={"created": [], "updated": [], "deleted": [], "next_sync_token": None, "next_ctag": "ct-2"}) as fallback_pull,
            patch("app.services.calendar_integrations.apple_caldav.record_apple_caldav_sync_run_result") as record_run,
        ):
            stats = svc.pull_changes(connection_id="conn-1", calendar_id="work")

        self.assertEqual(stats, {"created": 0, "updated": 0, "deleted": 0})
        fallback_pull.assert_called_once_with(connection_id="conn-1", calendar_id="work", ctag="ct-1", calendar_url=None)
        self.assertEqual(record_run.call_args.kwargs["status"], "success")
        self.assertEqual(record_run.call_args.kwargs["ctag"], "ct-2")

    def test_pull_sync_does_not_fallback_for_non_protocol_sync_token_error(self):
        svc = self._service()
        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_calendar_sync_state", return_value={"sync_token": "tok-1", "ctag": "ct-1"}),
            patch.object(
                svc,
                "_pull_with_sync_token",
                side_effect=CalendarIntegrationError(
                    code=CalendarIntegrationErrorCode.AUTH,
                    detail="auth failed while reading sync token response",
                    retriable=False,
                ),
            ),
            patch.object(svc, "_pull_with_ctag_or_window") as fallback_pull,
            patch("app.services.calendar_integrations.apple_caldav.record_apple_caldav_sync_run_result") as record_run,
        ):
            with self.assertRaises(CalendarIntegrationError):
                svc.pull_changes(connection_id="conn-1", calendar_id="work")

        fallback_pull.assert_not_called()
        self.assertEqual(record_run.call_args.kwargs["status"], "failed")

    def test_pull_with_ctag_window_reports_created_and_updated(self):
        svc = self._service()

        class _Resp:
            def read(self):
                return b"""<?xml version='1.0' encoding='utf-8'?>
<d:multistatus xmlns:d='DAV:' xmlns:c='urn:ietf:params:xml:ns:caldav' xmlns:cs='http://calendarserver.org/ns/'>
  <d:response>
    <d:href>/cal/work/new.ics</d:href>
    <d:propstat><d:prop><d:getetag>etag-new</d:getetag><cs:getctag>ctag-new</cs:getctag><c:calendar-data>NEW</c:calendar-data></d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/cal/work/upd.ics</d:href>
    <d:propstat><d:prop><d:getetag>etag-upd</d:getetag><c:calendar-data>UPD</c:calendar-data></d:prop></d:propstat>
  </d:response>
</d:multistatus>"""

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with (
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
                return_value={"username": "user@example.com", "app_specific_password": "app-pass"},
            ),
            patch(
                "app.services.calendar_integrations.apple_caldav.map_ical_to_internal_events",
                side_effect=[
                    {"events": [{"remote_uid": "uid-new"}], "errors": []},
                    {"events": [{"remote_uid": "uid-upd"}], "errors": []},
                ],
            ),
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link",
                side_effect=[None, {"internal_event_id": "evt-upd"}],
            ),
            patch("app.services.calendar_integrations.apple_caldav.urlrequest.urlopen", return_value=_Resp()),
        ):
            out = svc._pull_with_ctag_or_window(connection_id="conn-1", calendar_id="work", ctag="ct-1")

        self.assertEqual(len(out["created"]), 1)
        self.assertEqual(len(out["updated"]), 1)
        self.assertEqual(out["created"][0]["etag"], "etag-new")
        self.assertEqual(out["updated"][0]["etag"], "etag-upd")
        self.assertEqual(out["next_ctag"], "ctag-new")

    def test_pull_with_ctag_window_maps_malformed_xml_to_protocol_error(self):
        svc = self._service()

        class _Resp:
            def read(self):
                return b"<not-xml"

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with (
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
                return_value={"username": "user@example.com", "app_specific_password": "app-pass"},
            ),
            patch("app.services.calendar_integrations.apple_caldav.urlrequest.urlopen", return_value=_Resp()),
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc._pull_with_ctag_or_window(connection_id="conn-1", calendar_id="work", ctag="ct-1")
        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.PROTOCOL)

    def test_pull_with_ctag_window_short_circuits_when_ctag_unchanged(self):
        svc = self._service()

        class _ProbeResp:
            def read(self):
                return b"""<?xml version='1.0' encoding='utf-8'?>
<d:multistatus xmlns:d='DAV:' xmlns:cs='http://calendarserver.org/ns/'>
  <d:response><d:propstat><d:prop><cs:getctag>ct-1</cs:getctag></d:prop></d:propstat></d:response>
</d:multistatus>"""

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with (
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_connection_by_connection_id",
                return_value={"username": "user@example.com", "app_specific_password": "app-pass"},
            ),
            patch("app.services.calendar_integrations.apple_caldav.urlrequest.urlopen", return_value=_ProbeResp()) as urlopen_mock,
        ):
            out = svc._pull_with_ctag_or_window(connection_id="conn-1", calendar_id="work", ctag="ct-1")

        self.assertEqual(out, {"created": [], "updated": [], "deleted": [], "next_sync_token": None, "next_ctag": "ct-1"})
        self.assertEqual(urlopen_mock.call_count, 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
