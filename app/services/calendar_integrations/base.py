from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol


class CalendarProvider(str, Enum):
    APPLE_CALDAV = "apple_caldav"


class CalendarIntegrationErrorCode(str, Enum):
    AUTH = "auth_error"
    NETWORK = "network_error"
    PROTOCOL = "protocol_error"


@dataclass(frozen=True)
class CalendarProviderConfig:
    provider: CalendarProvider
    enabled: bool
    base_url: str
    connect_timeout_seconds: float
    read_timeout_seconds: float
    retry_max_attempts: int
    poll_interval_seconds: int
    poll_jitter_seconds: int
    poll_batch_size: int


@dataclass(frozen=True)
class CalendarIntegrationError(Exception):
    code: CalendarIntegrationErrorCode
    detail: str
    retriable: bool = False

    def __str__(self) -> str:
        return f"{self.code.value}: {self.detail}"


class CalendarConnectionService(Protocol):
    provider: CalendarProvider

    def validate_credentials(self, *, username: str, secret: str) -> None:
        ...

    def discover_calendars(self, *, username: str, secret: str) -> list[dict[str, Any]]:
        ...


class CalendarSyncService(Protocol):
    provider: CalendarProvider

    def pull_changes(self, *, connection_id: str, calendar_id: str) -> dict[str, int]:
        ...

    def push_event(self, *, connection_id: str, calendar_id: str, event: dict[str, Any]) -> dict[str, Any]:
        ...
