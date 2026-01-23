from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import Mock, patch

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
