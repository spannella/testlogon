from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest
from fastapi import HTTPException

from app.models import CalendarCreateIn, EventCreateIn
from app.routers import calendar as calendar_router


def run_async(coro):
    return asyncio.run(coro)


def build_ctx(user_sub: str = "user") -> dict[str, str]:
    return {"user_sub": user_sub, "session_id": "sid"}


def build_calendar_table(meta: dict | None = None, events: list[dict] | None = None) -> Mock:
    table = Mock()
    table.get_item.return_value = {"Item": meta} if meta else {}
    table.query.return_value = {"Items": events or []}
    return table


def build_calendar_table_with_event(meta: dict, event: dict | None) -> Mock:
    table = Mock()
    table.get_item.side_effect = [
        {"Item": meta},
        {"Item": event} if event else {},
    ]
    table.query.return_value = {"Items": []}
    return table


def build_calendar_table_with_batch(meta: dict, events: list[dict]) -> Mock:
    table = Mock()
    table.get_item.return_value = {"Item": meta}
    table.query.return_value = {"Items": events}
    batch = Mock()
    batch.__enter__ = Mock(return_value=batch)
    batch.__exit__ = Mock(return_value=None)
    table.batch_writer.return_value = batch
    return table


def build_calendar_table_map(metas: dict[str, dict], events_sequence: list[list[dict]]) -> Mock:
    table = Mock()

    def get_item_side_effect(**kwargs):
        key = kwargs.get("Key", {})
        calendar_id = key.get("calendar_id")
        meta = metas.get(calendar_id)
        return {"Item": meta} if meta else {}

    table.get_item.side_effect = get_item_side_effect
    table.query.side_effect = [{"Items": events} for events in events_sequence]
    return table


def test_create_calendar_sets_owner_and_timezone():
    table = build_calendar_table()
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        with patch.object(calendar_router.uuid, "uuid4", return_value=SimpleNamespace(hex="cal123")):
            resp = run_async(calendar_router.create_calendar(CalendarCreateIn(name="Team", timezone="UTC"), ctx=build_ctx()))

    assert resp.calendar_id == "cal123"
    assert resp.owner_user_id == "user"
    assert resp.timezone == "UTC"
    table.put_item.assert_called_once()


def test_create_event_requires_calendar_owner():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "owner", "timezone": "UTC"}
    table = build_calendar_table(meta=meta)
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        with pytest.raises(HTTPException):
            run_async(calendar_router.create_event(
                "cal123",
                EventCreateIn(name="Event", description="", all_day=True, all_day_date="2024-05-01"),
                ctx=build_ctx(user_sub="intruder"),
            ))


def test_create_event_all_day():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    table = build_calendar_table(meta=meta)
    with (
        patch.object(calendar_router, "T", SimpleNamespace(calendar=table)),
        patch.object(calendar_router.uuid, "uuid4", return_value=SimpleNamespace(hex="evt123")),
        patch.object(calendar_router, "enqueue_google_calendar_outbound_sync_job"),
        patch.object(calendar_router, "get_event_mapping", return_value={}),
    ):
        resp = run_async(calendar_router.create_event(
            "cal123",
            EventCreateIn(
                name="Holiday",
                description="Office closed",
                all_day=True,
                all_day_date="2024-05-01",
            ),
            ctx=build_ctx(),
        ))

    assert resp.event_id == "evt123"
    assert resp.all_day is True
    assert resp.all_day_date == "2024-05-01"


def test_create_event_enqueues_outbound_sync_job_once():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    table = build_calendar_table(meta=meta)
    with (
        patch.object(calendar_router, "T", SimpleNamespace(calendar=table)),
        patch.object(calendar_router.uuid, "uuid4", return_value=SimpleNamespace(hex="evt123")),
        patch.object(calendar_router, "enqueue_google_calendar_outbound_sync_job") as enqueue,
        patch.object(calendar_router, "get_event_mapping", return_value={}),
    ):
        run_async(calendar_router.create_event(
            "cal123",
            EventCreateIn(
                name="Holiday",
                description="Office closed",
                all_day=True,
                all_day_date="2024-05-01",
            ),
            ctx=build_ctx(),
        ))
    enqueue.assert_called_once()
    assert enqueue.call_args.kwargs["action"] == "create"


def test_list_openings_returns_free_windows():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    events = [
        {
            "event_id": "evt1",
            "name": "Standup",
            "timezone": "UTC",
            "start_utc": "2024-01-01T10:00:00Z",
            "end_utc": "2024-01-01T11:00:00Z",
            "all_day": False,
        },
        {
            "event_id": "evt2",
            "name": "Review",
            "timezone": "UTC",
            "start_utc": "2024-01-01T13:00:00Z",
            "end_utc": "2024-01-01T14:00:00Z",
            "all_day": False,
        },
    ]
    table = build_calendar_table(meta=meta, events=events)
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        openings = run_async(calendar_router.list_openings(
            "cal123",
            start_utc="2024-01-01T09:00:00Z",
            end_utc="2024-01-01T15:00:00Z",
            ctx=build_ctx(),
        ))

    assert [(o.start_utc, o.end_utc) for o in openings] == [
        ("2024-01-01T09:00:00Z", "2024-01-01T10:00:00Z"),
        ("2024-01-01T11:00:00Z", "2024-01-01T13:00:00Z"),
        ("2024-01-01T14:00:00Z", "2024-01-01T15:00:00Z"),
    ]


def test_invalid_timezone_rejected():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    table = build_calendar_table(meta=meta)
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        with pytest.raises(HTTPException):
            run_async(calendar_router.create_event(
                "cal123",
                EventCreateIn(
                    name="Bad TZ",
                    description="",
                    start_utc="2024-01-01T09:00:00Z",
                    end_utc="2024-01-01T10:00:00Z",
                    timezone="Not/AZone",
                ),
                ctx=build_ctx(),
            ))


def test_list_events_returns_items():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    events = [
        {
            "event_id": "evt1",
            "name": "Standup",
            "timezone": "UTC",
            "start_utc": "2024-01-01T10:00:00Z",
            "end_utc": "2024-01-01T11:00:00Z",
            "all_day": False,
            "description": "Daily sync",
            "created_at_utc": "2024-01-01T08:00:00Z",
        },
    ]
    table = build_calendar_table(meta=meta, events=events)
    with (
        patch.object(calendar_router, "T", SimpleNamespace(calendar=table)),
        patch.object(calendar_router, "get_event_mapping", return_value={}),
    ):
        resp = run_async(calendar_router.list_events("cal123", ctx=build_ctx()))

    assert len(resp.events) == 1
    assert resp.events[0].event_id == "evt1"
    assert resp.events[0].name == "Standup"
    assert resp.events[0].description == "Daily sync"


def test_openings_merge_overlapping_events():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    events = [
        {
            "event_id": "evt1",
            "name": "Block A",
            "timezone": "UTC",
            "start_utc": "2024-02-01T10:00:00Z",
            "end_utc": "2024-02-01T12:00:00Z",
            "all_day": False,
        },
        {
            "event_id": "evt2",
            "name": "Block B",
            "timezone": "UTC",
            "start_utc": "2024-02-01T11:30:00Z",
            "end_utc": "2024-02-01T13:00:00Z",
            "all_day": False,
        },
    ]
    table = build_calendar_table(meta=meta, events=events)
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        openings = run_async(calendar_router.list_openings(
            "cal123",
            start_utc="2024-02-01T09:00:00Z",
            end_utc="2024-02-01T15:00:00Z",
            ctx=build_ctx(),
        ))

    assert [(o.start_utc, o.end_utc) for o in openings] == [
        ("2024-02-01T09:00:00Z", "2024-02-01T10:00:00Z"),
        ("2024-02-01T13:00:00Z", "2024-02-01T15:00:00Z"),
    ]


def test_openings_all_day_event_blocks_day():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    events = [
        {
            "event_id": "evt1",
            "name": "Holiday",
            "timezone": "UTC",
            "all_day": True,
            "all_day_date": "2024-03-10",
        },
    ]
    table = build_calendar_table(meta=meta, events=events)
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        openings = run_async(calendar_router.list_openings(
            "cal123",
            start_utc="2024-03-10T00:00:00Z",
            end_utc="2024-03-11T00:00:00Z",
            ctx=build_ctx(),
        ))

    assert openings == []


def test_openings_rejects_invalid_window():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    table = build_calendar_table(meta=meta, events=[])
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        with pytest.raises(HTTPException):
            run_async(calendar_router.list_openings(
                "cal123",
                start_utc="2024-01-01T10:00:00Z",
                end_utc="2024-01-01T09:00:00Z",
                ctx=build_ctx(),
            ))


def test_team_openings_merge_multiple_calendars():
    metas = {
        "cal1": {"calendar_id": "cal1", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"},
        "cal2": {"calendar_id": "cal2", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"},
    }
    events_sequence = [
        [
            {
                "event_id": "evt1",
                "name": "Standup",
                "timezone": "UTC",
                "start_utc": "2024-04-01T10:00:00Z",
                "end_utc": "2024-04-01T11:00:00Z",
                "all_day": False,
            },
        ],
        [
            {
                "event_id": "evt2",
                "name": "Review",
                "timezone": "UTC",
                "start_utc": "2024-04-01T12:00:00Z",
                "end_utc": "2024-04-01T13:30:00Z",
                "all_day": False,
            },
        ],
    ]
    table = build_calendar_table_map(metas=metas, events_sequence=events_sequence)
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        openings = run_async(calendar_router.list_team_openings(
            body=calendar_router.TeamAvailabilityIn(
                calendar_ids=["cal1", "cal2"],
                start_utc="2024-04-01T09:00:00Z",
                end_utc="2024-04-01T15:00:00Z",
            ),
            ctx=build_ctx(),
        ))

    assert [(o.start_utc, o.end_utc) for o in openings] == [
        ("2024-04-01T09:00:00Z", "2024-04-01T10:00:00Z"),
        ("2024-04-01T11:00:00Z", "2024-04-01T12:00:00Z"),
        ("2024-04-01T13:30:00Z", "2024-04-01T15:00:00Z"),
    ]


def test_update_calendar_changes_name_and_timezone():
    meta = {
        "calendar_id": "cal123",
        "sk": "meta",
        "owner_user_sub": "user",
        "timezone": "UTC",
        "name": "Old",
        "created_at_utc": "2024-01-01T00:00:00Z",
    }
    table = build_calendar_table(meta=meta)
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        resp = run_async(calendar_router.update_calendar(
            "cal123",
            calendar_router.CalendarUpdateIn(name="New", timezone="UTC"),
            ctx=build_ctx(),
        ))

    assert resp.name == "New"
    assert resp.timezone == "UTC"
    table.put_item.assert_called_once()


def test_update_event_updates_times():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    event = {
        "calendar_id": "cal123",
        "sk": "event#evt1",
        "event_id": "evt1",
        "name": "Standup",
        "description": "Daily sync",
        "timezone": "UTC",
        "start_utc": "2024-01-01T10:00:00Z",
        "end_utc": "2024-01-01T11:00:00Z",
        "all_day": False,
        "created_at_utc": "2024-01-01T08:00:00Z",
    }
    table = build_calendar_table_with_event(meta=meta, event=event)
    with (
        patch.object(calendar_router, "T", SimpleNamespace(calendar=table)),
        patch.object(calendar_router, "enqueue_google_calendar_outbound_sync_job"),
        patch.object(calendar_router, "get_event_mapping", return_value={}),
    ):
        resp = run_async(calendar_router.update_event(
            "cal123",
            "evt1",
            calendar_router.EventUpdateIn(start_utc="2024-01-01T12:00:00Z", end_utc="2024-01-01T13:00:00Z"),
            ctx=build_ctx(),
        ))

    assert resp.start_utc == "2024-01-01T12:00:00Z"
    assert resp.end_utc == "2024-01-01T13:00:00Z"
    table.put_item.assert_called_once()


def test_update_event_enqueues_outbound_sync_job_once():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    event = {
        "calendar_id": "cal123",
        "sk": "event#evt1",
        "event_id": "evt1",
        "name": "Standup",
        "description": "Daily sync",
        "timezone": "UTC",
        "start_utc": "2024-01-01T10:00:00Z",
        "end_utc": "2024-01-01T11:00:00Z",
        "all_day": False,
        "created_at_utc": "2024-01-01T08:00:00Z",
    }
    table = build_calendar_table_with_event(meta=meta, event=event)
    with (
        patch.object(calendar_router, "T", SimpleNamespace(calendar=table)),
        patch.object(calendar_router, "enqueue_google_calendar_outbound_sync_job") as enqueue,
        patch.object(calendar_router, "get_event_mapping", return_value={}),
    ):
        run_async(calendar_router.update_event(
            "cal123",
            "evt1",
            calendar_router.EventUpdateIn(start_utc="2024-01-01T12:00:00Z", end_utc="2024-01-01T13:00:00Z"),
            ctx=build_ctx(),
        ))
    enqueue.assert_called_once()
    assert enqueue.call_args.kwargs["action"] == "update"


def test_delete_event_removes_item():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    event = {
        "calendar_id": "cal123",
        "sk": "event#evt1",
        "event_id": "evt1",
        "name": "Standup",
        "timezone": "UTC",
        "start_utc": "2024-01-01T10:00:00Z",
        "end_utc": "2024-01-01T11:00:00Z",
        "all_day": False,
    }
    table = build_calendar_table_with_event(meta=meta, event=event)
    with (
        patch.object(calendar_router, "T", SimpleNamespace(calendar=table)),
        patch.object(calendar_router, "enqueue_google_calendar_outbound_sync_job"),
    ):
        resp = run_async(calendar_router.delete_event("cal123", "evt1", ctx=build_ctx()))

    assert resp == {"ok": True}
    table.delete_item.assert_called_once_with(Key={"calendar_id": "cal123", "sk": "event#evt1"})


def test_delete_event_enqueues_outbound_sync_job_once():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    event = {
        "calendar_id": "cal123",
        "sk": "event#evt1",
        "event_id": "evt1",
        "name": "Standup",
        "timezone": "UTC",
        "start_utc": "2024-01-01T10:00:00Z",
        "end_utc": "2024-01-01T11:00:00Z",
        "all_day": False,
    }
    table = build_calendar_table_with_event(meta=meta, event=event)
    with (
        patch.object(calendar_router, "T", SimpleNamespace(calendar=table)),
        patch.object(calendar_router, "enqueue_google_calendar_outbound_sync_job") as enqueue,
    ):
        run_async(calendar_router.delete_event("cal123", "evt1", ctx=build_ctx()))
    enqueue.assert_called_once()
    assert enqueue.call_args.kwargs["action"] == "delete"


def test_delete_calendar_removes_meta_and_events():
    meta = {"calendar_id": "cal123", "sk": "meta", "owner_user_sub": "user", "timezone": "UTC"}
    events = [
        {
            "calendar_id": "cal123",
            "sk": "event#evt1",
            "event_id": "evt1",
            "name": "Standup",
            "timezone": "UTC",
            "start_utc": "2024-01-01T10:00:00Z",
            "end_utc": "2024-01-01T11:00:00Z",
            "all_day": False,
        },
    ]
    table = build_calendar_table_with_batch(meta=meta, events=events)
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        resp = run_async(calendar_router.delete_calendar("cal123", ctx=build_ctx()))

    assert resp == {"ok": True}
    table.batch_writer.assert_called_once()
    table.batch_writer.return_value.delete_item.assert_has_calls(
        [
            call(Key={"calendar_id": "cal123", "sk": "meta"}),
            call(Key={"calendar_id": "cal123", "sk": "event#evt1"}),
        ],
        any_order=True,
    )


def test_google_calendar_integration_status_returns_rollout_info():
    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user") as require_sync,
        patch.object(calendar_router, "is_google_calendar_writeback_enabled_for_user", return_value=False),
        patch.object(calendar_router, "rollout_mode", return_value="cohort"),
        patch.object(calendar_router, "rollout_percent", return_value=25),
        patch.object(calendar_router, "is_google_calendar_sync_enabled_for_user", return_value=True),
        patch.object(
            calendar_router,
            "get_calendar_provider_connection",
            return_value={
                "active": True,
                "sync_health": "healthy",
                "last_sync_status": "success",
                "last_sync_at_utc": "2026-01-01T00:00:00Z",
                "reauth_required": False,
            },
        ),
    ):
        resp = run_async(calendar_router.google_calendar_integration_status(ctx=build_ctx(user_sub="user-1")))

    require_sync.assert_called_once_with("user-1")
    assert resp.provider == "google"
    assert resp.sync_enabled is True
    assert resp.writeback_enabled is False
    assert resp.rollout_mode == "cohort"
    assert resp.rollout_percent == 25
    assert resp.in_rollout_cohort is True
    assert resp.connection_active is True


def test_google_calendar_provider_calendars_returns_mapping_context():
    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user"),
        patch.object(calendar_router, "S", SimpleNamespace(google_calendar_connection_default_id="google-primary")),
        patch.object(
            calendar_router,
            "list_google_calendars",
            return_value={
                "items": [
                    {"id": "gcal-1", "summary": "Primary", "accessRole": "owner", "primary": True},
                    {"id": "gcal-2", "summary": "Team", "accessRole": "writer", "primary": False},
                ]
            },
        ),
        patch.object(
            calendar_router,
            "list_calendar_provider_mappings",
            return_value=[{"internal_calendar_id": "cal-1", "google_calendar_id": "gcal-2", "active": True}],
        ),
    ):
        resp = run_async(calendar_router.google_calendar_provider_calendars(ctx=build_ctx(user_sub="user-1")))

    assert len(resp.calendars) == 2
    mapped = [c for c in resp.calendars if c.google_calendar_id == "gcal-2"][0]
    assert mapped.mapped_internal_calendar_id == "cal-1"


def test_google_calendar_create_mapping_uses_owner_validation():
    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user"),
        patch.object(
            calendar_router,
            "create_calendar_provider_mapping",
            return_value={
                "mapping_id": "m1",
                "provider": "google",
                "user_sub": "user-1",
                "internal_calendar_id": "cal-1",
                "google_calendar_id": "gcal-1",
                "active": True,
                "created_at_utc": "2026-01-01T00:00:00Z",
                "updated_at_utc": "2026-01-01T00:00:00Z",
                "unmapped_at_utc": "",
            },
        ) as create_mapping,
    ):
        resp = run_async(
            calendar_router.google_calendar_create_mapping(
                body=calendar_router.GoogleCalendarMappingCreateIn(
                    internal_calendar_id="cal-1",
                    google_calendar_id="gcal-1",
                ),
                ctx=build_ctx(user_sub="user-1"),
            )
        )

    create_mapping.assert_called_once()
    assert resp.mapping_id == "m1"


def test_google_calendar_manual_sync_run_rate_limited():
    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user"),
        patch.object(
            calendar_router,
            "rate_limit_admin_action",
            side_effect=HTTPException(status_code=429, detail="rate limited"),
        ),
    ):
        with pytest.raises(HTTPException):
            run_async(calendar_router.google_calendar_manual_sync_run(mode="incremental", ctx=build_ctx(user_sub="user-1")))


def test_google_calendar_manual_sync_run_success_audited():
    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user"),
        patch.object(calendar_router, "rate_limit_admin_action"),
        patch.object(
            calendar_router,
            "run_google_calendar_incremental_sync_job",
            return_value={"calendars_processed": 1, "errors": 0},
        ) as run_sync,
        patch.object(calendar_router, "audit_event") as audit,
        patch.object(calendar_router, "S", SimpleNamespace(google_calendar_connection_default_id="google-primary")),
    ):
        resp = run_async(calendar_router.google_calendar_manual_sync_run(mode="incremental", ctx=build_ctx(user_sub="user-1")))

    run_sync.assert_called_once()
    audit.assert_called_once()
    assert resp.accepted is True
    assert resp.mode == "incremental"


def test_google_calendar_integration_status_enforces_gate():
    with patch.object(
        calendar_router,
        "require_google_calendar_sync_enabled_for_user",
        side_effect=HTTPException(status_code=403, detail="disabled"),
    ):
        with pytest.raises(HTTPException):
            run_async(calendar_router.google_calendar_integration_status(ctx=build_ctx(user_sub="user-2")))


def test_google_calendar_connect_start_returns_oauth_url():
    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user") as require_sync,
        patch.object(
            calendar_router,
            "create_connect_start_state",
            return_value={
                "provider": "google",
                "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?x=1",
                "state": "state-token",
                "nonce": "nonce-token",
                "expires_at_utc": "2099-01-01T00:00:00Z",
            },
        ),
    ):
        resp = run_async(calendar_router.google_calendar_connect_start(ctx=build_ctx(user_sub="user-1")))

    require_sync.assert_called_once_with("user-1")
    assert resp.provider == "google"
    assert resp.state == "state-token"
    assert resp.nonce == "nonce-token"


def test_google_calendar_connect_start_enforces_gate():
    with patch.object(
        calendar_router,
        "require_google_calendar_sync_enabled_for_user",
        side_effect=HTTPException(status_code=403, detail="disabled"),
    ):
        with pytest.raises(HTTPException):
            run_async(calendar_router.google_calendar_connect_start(ctx=build_ctx(user_sub="user-1")))


def test_google_calendar_connect_callback_links_connection():
    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user") as require_sync,
        patch.object(
            calendar_router,
            "handle_connect_callback",
            return_value={
                "provider": "google",
                "connection_id": "google-google-sub-1",
                "account_email": "user@example.com",
                "linked": True,
                "updated_at_utc": "2099-01-01T00:00:00Z",
            },
        ) as cb,
    ):
        resp = run_async(
            calendar_router.google_calendar_connect_callback(
                code="auth-code",
                state="state-token-123456789",
                error=None,
                ctx=build_ctx(user_sub="user-1"),
            )
        )

    require_sync.assert_called_once_with("user-1")
    cb.assert_called_once_with(user_sub="user-1", state="state-token-123456789", code="auth-code")
    assert resp.linked is True
    assert resp.connection_id == "google-google-sub-1"


def test_google_calendar_connect_callback_handles_missing_parameters():
    with patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user"):
        with pytest.raises(HTTPException):
            run_async(
                calendar_router.google_calendar_connect_callback(
                    code=None,
                    state="state-token-123456789",
                    error=None,
                    ctx=build_ctx(user_sub="user-1"),
                )
            )


def test_google_calendar_connect_callback_handles_provider_error():
    with patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user"):
        with pytest.raises(HTTPException):
            run_async(
                calendar_router.google_calendar_connect_callback(
                    code=None,
                    state=None,
                    error="access_denied",
                    ctx=build_ctx(user_sub="user-1"),
                )
            )


def test_google_calendar_disconnect_revokes_connection():
    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user") as require_sync,
        patch.object(
            calendar_router,
            "handle_disconnect",
            return_value={
                "provider": "google",
                "connection_id": "google-primary",
                "account_email": "user@example.com",
                "active": False,
                "revoked": True,
                "revoke_status": "revoked",
                "disconnected_at_utc": "2099-01-01T00:00:00Z",
            },
        ) as disconnect,
        patch.object(calendar_router, "S", SimpleNamespace(google_calendar_connection_default_id="google-primary")),
    ):
        resp = run_async(calendar_router.google_calendar_disconnect(connection_id=None, ctx=build_ctx(user_sub="user-1")))

    require_sync.assert_called_once_with("user-1")
    disconnect.assert_called_once_with(user_sub="user-1", connection_id="google-primary")
    assert resp.revoked is True
    assert resp.active is False


def test_google_calendar_disconnect_propagates_retry_safe_failure():
    with (
        patch.object(calendar_router, "require_google_calendar_sync_enabled_for_user"),
        patch.object(
            calendar_router,
            "handle_disconnect",
            side_effect=HTTPException(status_code=502, detail="token revocation failed, retry later"),
        ),
        patch.object(calendar_router, "S", SimpleNamespace(google_calendar_connection_default_id="google-primary")),
    ):
        with pytest.raises(HTTPException):
            run_async(calendar_router.google_calendar_disconnect(connection_id="google-primary", ctx=build_ctx(user_sub="user-1")))
