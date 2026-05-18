from __future__ import annotations

from dataclasses import dataclass

from app.core.settings import S
from app.services.calendar_integrations.apple_caldav import (
    AppleCalDavConnectionService,
    AppleCalDavSyncService,
)
from app.services.calendar_integrations.base import (
    CalendarConnectionService,
    CalendarProvider,
    CalendarProviderConfig,
    CalendarSyncService,
)


@dataclass(frozen=True)
class CalendarProviderServices:
    config: CalendarProviderConfig
    connection: CalendarConnectionService
    sync: CalendarSyncService


class CalendarIntegrationRegistry:
    def __init__(self) -> None:
        self._providers: dict[CalendarProvider, CalendarProviderServices] = {}

    def register(self, provider_services: CalendarProviderServices) -> None:
        self._providers[provider_services.config.provider] = provider_services

    def get(self, provider: CalendarProvider) -> CalendarProviderServices | None:
        return self._providers.get(provider)

    def require(self, provider: CalendarProvider) -> CalendarProviderServices:
        provider_services = self.get(provider)
        if provider_services is None:
            raise KeyError(f"calendar provider not registered: {provider.value}")
        return provider_services

    def providers(self) -> list[CalendarProviderServices]:
        return list(self._providers.values())



def build_calendar_integration_registry() -> CalendarIntegrationRegistry:
    registry = CalendarIntegrationRegistry()

    if not S.calendar_integrations_enabled:
        return registry

    apple_config = CalendarProviderConfig(
        provider=CalendarProvider.APPLE_CALDAV,
        enabled=S.apple_caldav_enabled,
        base_url=S.apple_caldav_base_url,
        connect_timeout_seconds=S.apple_caldav_connect_timeout_seconds,
        read_timeout_seconds=S.apple_caldav_read_timeout_seconds,
        retry_max_attempts=S.apple_caldav_retry_max_attempts,
        poll_interval_seconds=S.apple_caldav_poll_interval_seconds,
        poll_jitter_seconds=S.apple_caldav_poll_jitter_seconds,
        poll_batch_size=S.apple_caldav_poll_batch_size,
    )
    registry.register(
        CalendarProviderServices(
            config=apple_config,
            connection=AppleCalDavConnectionService(config=apple_config),
            sync=AppleCalDavSyncService(config=apple_config),
        )
    )

    return registry


calendar_integration_registry = build_calendar_integration_registry()


def initialize_calendar_integration_registry() -> CalendarIntegrationRegistry:
    global calendar_integration_registry
    calendar_integration_registry = build_calendar_integration_registry()
    return calendar_integration_registry


def get_provider_services(provider_key: str) -> CalendarProviderServices | None:
    try:
        provider = CalendarProvider((provider_key or "").strip().lower())
    except ValueError:
        return None
    return calendar_integration_registry.get(provider)
