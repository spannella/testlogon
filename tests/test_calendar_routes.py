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
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        with patch.object(calendar_router.uuid, "uuid4", return_value=SimpleNamespace(hex="evt123")):
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
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        resp = run_async(calendar_router.list_events("cal123", ctx=build_ctx()))

    assert len(resp) == 1
    assert resp[0].event_id == "evt1"
    assert resp[0].name == "Standup"
    assert resp[0].description == "Daily sync"


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
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        resp = run_async(calendar_router.update_event(
            "cal123",
            "evt1",
            calendar_router.EventUpdateIn(start_utc="2024-01-01T12:00:00Z", end_utc="2024-01-01T13:00:00Z"),
            ctx=build_ctx(),
        ))

    assert resp.start_utc == "2024-01-01T12:00:00Z"
    assert resp.end_utc == "2024-01-01T13:00:00Z"
    table.put_item.assert_called_once()


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
    with patch.object(calendar_router, "T", SimpleNamespace(calendar=table)):
        resp = run_async(calendar_router.delete_event("cal123", "evt1", ctx=build_ctx()))

    assert resp == {"ok": True}
    table.delete_item.assert_called_once_with(Key={"calendar_id": "cal123", "sk": "event#evt1"})


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
