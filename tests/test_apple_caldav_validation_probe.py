from __future__ import annotations

import unittest
from types import SimpleNamespace
from urllib import error as urlerror

from app.services.calendar_integrations import apple_caldav
from app.services.calendar_integrations.base import (
    CalendarIntegrationError,
    CalendarIntegrationErrorCode,
    CalendarProvider,
    CalendarProviderConfig,
)


class TestAppleCalDavValidationProbe(unittest.TestCase):
    def _config(self, enabled: bool = True, base_url: str = "https://caldav.icloud.com") -> CalendarProviderConfig:
        return CalendarProviderConfig(
            provider=CalendarProvider.APPLE_CALDAV,
            enabled=enabled,
            base_url=base_url,
            connect_timeout_seconds=5.0,
            read_timeout_seconds=10.0,
            retry_max_attempts=3,
            poll_interval_seconds=300,
            poll_jitter_seconds=30,
            poll_batch_size=50,
        )

    def test_invalid_credentials_return_actionable_auth_error(self):
        svc = apple_caldav.AppleCalDavConnectionService(self._config(enabled=True))

        with unittest.mock.patch.object(
            apple_caldav,
            "_probe_caldav_credentials",
            side_effect=urlerror.HTTPError("", 401, "unauthorized", hdrs=None, fp=None),
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc.validate_credentials(username="user@example.com", secret="bad")

        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.AUTH)
        self.assertIn("invalid", ctx.exception.detail.lower())

    def test_network_timeouts_are_retriable_network_errors(self):
        svc = apple_caldav.AppleCalDavConnectionService(self._config(enabled=True))

        with unittest.mock.patch.object(
            apple_caldav,
            "_probe_caldav_credentials",
            side_effect=urlerror.URLError("timeout"),
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc.validate_credentials(username="user@example.com", secret="app-pass")

        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.NETWORK)
        self.assertTrue(ctx.exception.retriable)

    def test_non_auth_http_errors_map_to_protocol_error(self):
        svc = apple_caldav.AppleCalDavConnectionService(self._config(enabled=True))

        with unittest.mock.patch.object(
            apple_caldav,
            "_probe_caldav_credentials",
            side_effect=urlerror.HTTPError("", 500, "server", hdrs=None, fp=None),
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc.validate_credentials(username="user@example.com", secret="app-pass")

        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.PROTOCOL)
        self.assertFalse(ctx.exception.retriable)

    def test_validate_credentials_rejects_non_https_base_url(self):
        svc = apple_caldav.AppleCalDavConnectionService(
            self._config(enabled=True, base_url="http://caldav.icloud.com")
        )
        with self.assertRaises(CalendarIntegrationError) as ctx:
            svc.validate_credentials(username="user@example.com", secret="app-pass")
        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.PROTOCOL)
        self.assertIn("https", ctx.exception.detail.lower())

    def test_validate_credentials_rejects_loopback_or_private_hosts(self):
        for unsafe_url in ("https://127.0.0.1", "https://localhost:8443", "https://10.0.0.5"):
            svc = apple_caldav.AppleCalDavConnectionService(
                self._config(enabled=True, base_url=unsafe_url)
            )
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc.validate_credentials(username="user@example.com", secret="app-pass")
            self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.PROTOCOL)
            self.assertIn("not allowed", ctx.exception.detail.lower())

    def test_validate_credentials_rejects_embedded_base_url_credentials(self):
        svc = apple_caldav.AppleCalDavConnectionService(
            self._config(enabled=True, base_url="https://user:pass@caldav.icloud.com")
        )
        with self.assertRaises(CalendarIntegrationError) as ctx:
            svc.validate_credentials(username="user@example.com", secret="app-pass")
        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.PROTOCOL)
        self.assertIn("embedded credentials", ctx.exception.detail.lower())

    def test_validate_credentials_rejects_hostnames_resolving_to_private_ips(self):
        svc = apple_caldav.AppleCalDavConnectionService(
            self._config(enabled=True, base_url="https://calendar.example.com")
        )
        with (
            unittest.mock.patch.object(
                apple_caldav.socket,
                "getaddrinfo",
                return_value=[(2, 1, 6, "", ("10.10.1.9", 443))],
            ),
            self.assertRaises(CalendarIntegrationError) as ctx,
        ):
            svc.validate_credentials(username="user@example.com", secret="app-pass")
        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.PROTOCOL)
        self.assertIn("resolved", ctx.exception.detail.lower())

    def test_validate_credentials_dns_resolution_errors_fall_back_to_probe_error_mapping(self):
        svc = apple_caldav.AppleCalDavConnectionService(
            self._config(enabled=True, base_url="https://calendar.example.com")
        )
        with (
            unittest.mock.patch.object(
                apple_caldav.socket,
                "getaddrinfo",
                side_effect=apple_caldav.socket.gaierror("dns-fail"),
            ),
            unittest.mock.patch.object(
                apple_caldav,
                "_probe_caldav_credentials",
                side_effect=urlerror.URLError("timeout"),
            ),
        ):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                svc.validate_credentials(username="user@example.com", secret="app-pass")
        self.assertEqual(ctx.exception.code, CalendarIntegrationErrorCode.NETWORK)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
