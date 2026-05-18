from __future__ import annotations

import unittest
from unittest.mock import patch

from app.services.calendar_integrations import apple_caldav
from app.services.calendar_integrations.apple_caldav import AppleCalDavSyncService
from app.services.calendar_integrations.base import (
    CalendarIntegrationError,
    CalendarIntegrationErrorCode,
    CalendarProvider,
    CalendarProviderConfig,
)


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestAppleCalDavContract(unittest.TestCase):
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

    def test_discovery_request_contract_and_apple_xml_edge_cases(self):
        captured = {}
        payload = b"""<?xml version='1.0' encoding='utf-8'?>
        <d:multistatus xmlns:d='DAV:' xmlns:c='urn:ietf:params:xml:ns:caldav'>
          <d:response>
            <d:href>/calendars/user1/work/</d:href>
            <d:propstat><d:prop>
              <d:displayname></d:displayname>
              <d:resourcetype><d:collection/><c:calendar/></d:resourcetype>
            </d:prop></d:propstat>
          </d:response>
          <d:response>
            <d:href>/calendars/user1/non-calendar/</d:href>
            <d:propstat><d:prop>
              <d:displayname>Ignore me</d:displayname>
              <d:resourcetype><d:collection/></d:resourcetype>
            </d:prop></d:propstat>
          </d:response>
        </d:multistatus>
        """

        def _fake_urlopen(req, timeout=0):
            captured["method"] = req.get_method()
            captured["url"] = req.full_url
            captured["depth"] = req.get_header("Depth")
            captured["auth"] = req.get_header("Authorization")
            captured["content_type"] = req.get_header("Content-type")
            captured["timeout"] = timeout
            captured["body"] = req.data.decode("utf-8") if req.data else ""
            return _FakeResponse(payload)

        with patch("app.services.calendar_integrations.apple_caldav.urlrequest.urlopen", side_effect=_fake_urlopen):
            out = apple_caldav._discover_caldav_collections(
                base_url="https://caldav.icloud.com",
                username="user@example.com",
                secret="app-pass",
                timeout_seconds=12.5,
            )

        self.assertEqual(captured["method"], "PROPFIND")
        self.assertEqual(captured["depth"], "1")
        self.assertIn("Basic ", captured["auth"])
        self.assertIn("application/xml", captured["content_type"])
        self.assertIn("displayname", captured["body"])
        self.assertEqual(captured["timeout"], 12.5)

        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["calendar_id"], "work")
        # Apple responses can omit display names; fallback should be stable.
        self.assertEqual(out[0]["display_name"], "work")

    def test_pull_prefers_sync_token_and_falls_back_to_ctag_on_token_gone(self):
        svc = AppleCalDavSyncService(self._config())

        with (
            patch("app.services.calendar_integrations.apple_caldav.assert_apple_caldav_connection_active"),
            patch(
                "app.services.calendar_integrations.apple_caldav.get_apple_caldav_calendar_sync_state",
                return_value={"sync_token": "tok-old", "ctag": "ct-prev"},
            ),
            patch.object(
                svc,
                "_pull_with_sync_token",
                side_effect=CalendarIntegrationError(
                    code=CalendarIntegrationErrorCode.PROTOCOL,
                    detail="HTTP 410 sync-token is no longer valid",
                    retriable=False,
                ),
            ) as pull_token,
            patch.object(
                svc,
                "_pull_with_ctag_or_window",
                return_value={"created": [], "updated": [], "deleted": [], "next_sync_token": None, "next_ctag": "ct-new"},
            ) as pull_ctag,
            patch("app.services.calendar_integrations.apple_caldav.record_apple_caldav_sync_run_result") as record_run,
        ):
            stats = svc.pull_changes(connection_id="conn-1", calendar_id="work")

        self.assertEqual(stats, {"created": 0, "updated": 0, "deleted": 0})
        pull_token.assert_called_once()
        pull_ctag.assert_called_once()
        self.assertEqual(record_run.call_args.kwargs["status"], "success")
        self.assertEqual(record_run.call_args.kwargs["ctag"], "ct-new")

    def test_etag_collision_returns_conflict_contract_payload(self):
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
        self.assertEqual(out["remote_uid"], "evt-1@internal.calendar.local")
        record_audit.assert_called_once()

    def test_delete_propagation_marks_link_deleted_even_without_internal_mapping(self):
        svc = AppleCalDavSyncService(self._config())

        with (
            patch("app.services.calendar_integrations.apple_caldav.get_apple_caldav_event_link", return_value=None),
            patch.object(svc, "_soft_delete_internal_event") as soft_delete,
            patch("app.services.calendar_integrations.apple_caldav.mark_apple_caldav_event_link_deleted") as mark_deleted,
        ):
            stats = svc._reconcile_remote_changes(
                connection_id="conn-1",
                calendar_id="work",
                run_id="run-1",
                remote_payload={
                    "created": [],
                    "updated": [],
                    "deleted": [{"remote_uid": "uid-1"}],
                },
            )

        self.assertEqual(stats, {"created": 0, "updated": 0, "deleted": 1})
        soft_delete.assert_not_called()
        mark_deleted.assert_called_once_with(
            connection_id="conn-1",
            external_calendar_id="work",
            remote_uid="uid-1",
            run_id="run-1",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
