from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from app.models import GoogleCalendarMappingCreateIn
from app.routers import calendar as calendar_router


def run_async(coro):
    if asyncio.iscoroutine(coro):
        return asyncio.run(coro)
    return coro


def test_e2e_connect_map_import_writeback_conflict_visibility_user_journey():
    ctx = {"user_sub": "user-1", "session_id": "sid-1"}

    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user"),
        patch.object(calendar_router, "create_connect_start_state", return_value={
            "provider": "google",
            "authorization_url": "https://accounts.google.test/auth",
            "state": "state-1",
            "nonce": "nonce-1",
            "expires_at_utc": "2099-01-01T00:00:00Z",
        }),
        patch.object(calendar_router, "handle_connect_callback", return_value={
            "provider": "google",
            "connection_id": "google-primary",
            "account_email": "user@example.com",
            "linked": True,
            "updated_at_utc": "2099-01-01T00:00:00Z",
        }),
        patch.object(calendar_router, "create_calendar_provider_mapping", return_value={
            "mapping_id": "map-1",
            "provider": "google",
            "user_sub": "user-1",
            "internal_calendar_id": "cal-1",
            "google_calendar_id": "gcal-1",
            "active": True,
            "created_at_utc": "2099-01-01T00:00:00Z",
            "updated_at_utc": "2099-01-01T00:00:00Z",
            "unmapped_at_utc": "",
        }),
        patch.object(calendar_router, "run_google_calendar_incremental_sync_job", return_value={"calendars_processed": 1, "errors": 0}),
        patch.object(calendar_router, "emit_google_calendar_audit_event"),
        patch.object(calendar_router, "rate_limit_admin_action"),
    ):
        connect_start = run_async(calendar_router.google_calendar_connect_start(ctx=ctx))
        connect_callback = run_async(calendar_router.google_calendar_connect_callback(code="code-1", state="state-1", error=None, ctx=ctx))
        mapping = run_async(
            calendar_router.google_calendar_create_mapping(
                body=GoogleCalendarMappingCreateIn(internal_calendar_id="cal-1", google_calendar_id="gcal-1"),
                ctx=ctx,
            )
        )
        sync_out = run_async(calendar_router.google_calendar_manual_sync_run(mode="incremental", ctx=ctx))

    assert connect_start.provider == "google"
    assert connect_callback.linked is True
    assert mapping.mapping_id == "map-1"
    assert sync_out.accepted is True
    assert sync_out.metrics["calendars_processed"] == 1
