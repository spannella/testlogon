from __future__ import annotations

import unittest
from urllib import error as urlerror

from app.services.calendar_integrations import apple_caldav
from app.services.calendar_integrations.base import (
    CalendarIntegrationError,
    CalendarIntegrationErrorCode,
    CalendarProvider,
    CalendarProviderConfig,
)


class TestAppleCalDavDiscovery(unittest.TestCase):
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

    def test_parse_discovery_xml_returns_normalized_calendar_dtos(self):
        payload = b"""<?xml version='1.0' encoding='utf-8'?>
        <d:multistatus xmlns:d='DAV:' xmlns:c='urn:ietf:params:xml:ns:caldav'>
          <d:response>
            <d:href>/calendars/user1/work/</d:href>
            <d:propstat><d:prop>
              <d:displayname>Work</d:displayname>
              <d:resourcetype><d:collection/><c:calendar/></d:resourcetype>
            </d:prop></d:propstat>
          </d:response>
          <d:response>
            <d:href>/calendars/user1/not-a-calendar/</d:href>
            <d:propstat><d:prop>
              <d:displayname>Ignored</d:displayname>
              <d:resourcetype><d:collection/></d:resourcetype>
            </d:prop></d:propstat>
          </d:response>
        </d:multistatus>
        """
        out = apple_caldav._parse_caldav_discovery_xml(payload=payload, base_url="https://caldav.icloud.com")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["calendar_id"], "work")
        self.assertEqual(out[0]["display_name"], "Work")
        self.assertTrue(out[0]["calendar_url"].startswith("https://caldav.icloud.com/"))

    def test_discovery_returns_empty_on_inaccessible_collections(self):
        svc = apple_caldav.AppleCalDavConnectionService(self._config())
        with (
            unittest.mock.patch.object(apple_caldav, "_probe_caldav_credentials", return_value=None),
            unittest.mock.patch.object(
                apple_caldav,
                "_discover_caldav_collections",
                side_effect=urlerror.HTTPError("", 404, "not found", hdrs=None, fp=None),
            ),
        ):
            out = svc.discover_calendars(username="user@example.com", secret="app-pass")

        self.assertEqual(out, [])

    def test_discovery_network_errors_are_retriable(self):
        svc = apple_caldav.AppleCalDavConnectionService(self._config())
        with (
            unittest.mock.patch.object(apple_caldav, "_probe_caldav_credentials", return_value=None),
            unittest.mock.patch.object(
                apple_caldav,
                "_discover_caldav_collections",
                side_effect=urlerror.URLError("timeout"),
            ),
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc.discover_calendars(username="user@example.com", secret="app-pass")

        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.NETWORK)
        self.assertTrue(ctx.exception.retriable)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
