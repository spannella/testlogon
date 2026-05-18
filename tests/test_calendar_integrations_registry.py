from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.services.calendar_integrations import apple_caldav
from app.services.calendar_integrations import registry
from app.services.calendar_integrations.base import CalendarIntegrationError, CalendarProvider


class TestCalendarIntegrationRegistry(unittest.TestCase):
    @staticmethod
    def _settings(**overrides: object) -> SimpleNamespace:
        base = {
            "calendar_integrations_enabled": True,
            "apple_caldav_enabled": False,
            "apple_caldav_base_url": "https://caldav.icloud.com",
            "apple_caldav_connect_timeout_seconds": 5.0,
            "apple_caldav_read_timeout_seconds": 10.0,
            "apple_caldav_retry_max_attempts": 3,
            "apple_caldav_poll_interval_seconds": 300,
            "apple_caldav_poll_jitter_seconds": 30,
            "apple_caldav_poll_batch_size": 50,
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def test_build_registry_empty_when_calendar_integrations_globally_disabled(self):
        with patch.object(registry, "S", self._settings(calendar_integrations_enabled=False)):
            built = registry.build_calendar_integration_registry()

        self.assertEqual(built.providers(), [])

    def test_build_registry_registers_apple_provider_with_settings_config(self):
        with patch.object(
            registry,
            "S",
            self._settings(
                apple_caldav_enabled=True,
                apple_caldav_connect_timeout_seconds=7.0,
                apple_caldav_read_timeout_seconds=13.0,
                apple_caldav_retry_max_attempts=4,
                apple_caldav_poll_interval_seconds=600,
                apple_caldav_poll_jitter_seconds=45,
                apple_caldav_poll_batch_size=75,
            ),
        ):
            built = registry.build_calendar_integration_registry()

        provider_services = built.require(CalendarProvider.APPLE_CALDAV)
        self.assertEqual(provider_services.config.base_url, "https://caldav.icloud.com")
        self.assertEqual(provider_services.config.connect_timeout_seconds, 7.0)
        self.assertEqual(provider_services.config.read_timeout_seconds, 13.0)
        self.assertEqual(provider_services.config.retry_max_attempts, 4)
        self.assertEqual(provider_services.config.poll_interval_seconds, 600)
        self.assertEqual(provider_services.config.poll_jitter_seconds, 45)
        self.assertEqual(provider_services.config.poll_batch_size, 75)

    def test_apple_connection_validation_requires_non_empty_credentials(self):
        with patch.object(registry, "S", self._settings(apple_caldav_enabled=True)):
            built = registry.build_calendar_integration_registry()

        provider_services = built.require(CalendarProvider.APPLE_CALDAV)

        with self.assertRaises(CalendarIntegrationError) as ctx:
            provider_services.connection.validate_credentials(username="", secret="")

        self.assertEqual(ctx.exception.code.value, "auth_error")

    def test_apple_services_fail_fast_when_provider_disabled(self):
        with patch.object(registry, "S", self._settings(apple_caldav_enabled=False)):
            built = registry.build_calendar_integration_registry()

        provider_services = built.require(CalendarProvider.APPLE_CALDAV)

        with self.assertRaises(CalendarIntegrationError) as pull_ctx:
            provider_services.sync.pull_changes(connection_id="c-1", calendar_id="cal-1")
        self.assertEqual(pull_ctx.exception.code.value, "protocol_error")

        with self.assertRaises(CalendarIntegrationError) as discover_ctx:
            provider_services.connection.discover_calendars(username="user@example.com", secret="app-secret")
        self.assertEqual(discover_ctx.exception.code.value, "protocol_error")

    def test_runtime_registry_init_and_stable_provider_lookup(self):
        with patch.object(registry, "S", self._settings(apple_caldav_enabled=True)):
            initialized = registry.initialize_calendar_integration_registry()

        self.assertIsNotNone(initialized.require(CalendarProvider.APPLE_CALDAV))
        self.assertIsNotNone(registry.get_provider_services("apple_caldav"))
        self.assertIsNone(registry.get_provider_services("unknown_provider"))

    def test_sync_rejects_disconnected_connection(self):
        with patch.object(registry, "S", self._settings(apple_caldav_enabled=True)):
            built = registry.build_calendar_integration_registry()
        provider_services = built.require(CalendarProvider.APPLE_CALDAV)

        with patch.object(apple_caldav, "assert_apple_caldav_connection_active", side_effect=ValueError("calendar connection is disconnected")):
            with self.assertRaises(CalendarIntegrationError) as ctx:
                provider_services.sync.pull_changes(connection_id="c-1", calendar_id="cal-1")

        self.assertEqual(ctx.exception.code.value, "protocol_error")
        self.assertIn("disconnected", ctx.exception.detail)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
