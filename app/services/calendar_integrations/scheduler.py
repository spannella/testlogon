from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.services.calendar_integrations.credentials import (
    acquire_apple_caldav_pull_lock,
    list_connected_apple_caldav_connections,
    list_enabled_apple_caldav_external_calendar_ids,
    release_apple_caldav_pull_lock,
    should_run_apple_caldav_pull,
)
from app.services.calendar_integrations.registry import get_provider_services


def run_apple_caldav_pull_scheduler(*, now: datetime | None = None) -> dict[str, Any]:
    provider_services = get_provider_services("apple_caldav")
    if provider_services is None:
        return {"jobs_started": 0, "jobs_suppressed": 0, "jobs_skipped_interval": 0, "connections_seen": 0}

    current = now or datetime.now(timezone.utc)
    started = 0
    suppressed = 0
    skipped_interval = 0
    connections = list_connected_apple_caldav_connections()

    for connection_id in connections:
        if not should_run_apple_caldav_pull(
            connection_id=connection_id,
            poll_interval_seconds=int(provider_services.config.poll_interval_seconds),
            now=current,
        ):
            skipped_interval += 1
            continue

        if not acquire_apple_caldav_pull_lock(connection_id=connection_id):
            suppressed += 1
            continue

        try:
            calendars = list_enabled_apple_caldav_external_calendar_ids(connection_id=connection_id)
            for external_calendar_id in calendars:
                provider_services.sync.pull_changes(
                    connection_id=connection_id,
                    calendar_id=external_calendar_id,
                )
                started += 1
        finally:
            release_apple_caldav_pull_lock(connection_id=connection_id)

    return {
        "jobs_started": started,
        "jobs_suppressed": suppressed,
        "jobs_skipped_interval": skipped_interval,
        "connections_seen": len(connections),
    }
