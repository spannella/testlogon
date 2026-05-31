"""Unit tests for ad scheduling & dayparting service (ADS-016)."""

from __future__ import annotations

from datetime import datetime, timezone

from app.services import ad_dayparting as dp


def _ts(year, month, day, hour, tz=timezone.utc) -> int:
    return int(datetime(year, month, day, hour, 0, 0, tzinfo=tz).timestamp())


def test_validate_valid_dayparting_config():
    cfg = {
        "timezone": "UTC",
        "schedule": {"monday": [9, 10, 11], "tuesday": [12]},
    }
    err, sanitized = dp.validate_dayparting_config(cfg)
    assert err is None
    assert sanitized["timezone"] == "UTC"
    assert sanitized["schedule"]["monday"] == [9, 10, 11]
    # Days not provided default to empty lists.
    assert sanitized["schedule"]["sunday"] == []


def test_reject_invalid_timezone():
    err, sanitized = dp.validate_dayparting_config(
        {"timezone": "Invalid/Zone", "schedule": {"monday": [9]}}
    )
    assert err is not None
    assert "timezone" in err.lower()
    assert sanitized is None


def test_reject_empty_schedule():
    err, sanitized = dp.validate_dayparting_config(
        {"timezone": "UTC", "schedule": {day: [] for day in dp.VALID_DAYS}}
    )
    assert err is not None
    assert "active hour" in err.lower()
    assert sanitized is None


def test_invalid_hours_silently_dropped():
    err, sanitized = dp.validate_dayparting_config(
        {"timezone": "UTC", "schedule": {"monday": [9, 25, -1, 23, "x"]}}
    )
    assert err is None
    assert sanitized["schedule"]["monday"] == [9, 23]


def test_eligibility_active_hour():
    # 2026-06-01 is a Monday. 14:00 UTC.
    cfg = {"timezone": "UTC", "schedule": {"monday": [10, 11, 12, 13, 14, 15]}}
    eligible, debug = dp.is_campaign_eligible_now(
        dayparting=cfg, now=_ts(2026, 6, 1, 14)
    )
    assert eligible is True
    assert debug["day"] == "monday"
    assert debug["hour"] == 14


def test_eligibility_inactive_hour():
    cfg = {"timezone": "UTC", "schedule": {"monday": [10, 11, 12]}}
    eligible, _ = dp.is_campaign_eligible_now(
        dayparting=cfg, now=_ts(2026, 6, 1, 3)
    )
    assert eligible is False


def test_eligibility_no_dayparting_always_eligible():
    eligible, debug = dp.is_campaign_eligible_now(dayparting=None)
    assert eligible is True
    assert debug["reason"] == "no_dayparting"


def test_eligibility_timezone_conversion():
    # 14:00 UTC == 10:00 America/New_York (EDT, UTC-4) on 2026-06-01.
    cfg = {"timezone": "America/New_York", "schedule": {"monday": [10]}}
    eligible, debug = dp.is_campaign_eligible_now(
        dayparting=cfg, now=_ts(2026, 6, 1, 14)
    )
    assert eligible is True
    assert debug["hour"] == 10


def test_flight_resolution_active_flight():
    flights = [
        {"flight_id": "fl1", "start_date": "2026-06-01", "end_date": "2026-06-14"},
        {"flight_id": "fl2", "start_date": "2026-06-15", "end_date": "2026-06-30"},
    ]
    active = dp.get_active_flight(flights=flights, now=_ts(2026, 6, 18, 12))
    assert active is not None
    assert active["flight_id"] == "fl2"


def test_flight_resolution_gap_returns_none():
    flights = [
        {"flight_id": "fl1", "start_date": "2026-06-01", "end_date": "2026-06-10"},
        {"flight_id": "fl2", "start_date": "2026-06-20", "end_date": "2026-06-30"},
    ]
    active = dp.get_active_flight(flights=flights, now=_ts(2026, 6, 15, 12))
    assert active is None


def test_flight_overlap_rejected():
    flights = [
        {
            "name": "A",
            "start_date": "2026-06-01",
            "end_date": "2026-06-15",
            "daily_budget_cents": 50000,
            "creative_ids": ["cr1"],
        },
        {
            "name": "B",
            "start_date": "2026-06-10",
            "end_date": "2026-06-20",
            "daily_budget_cents": 50000,
            "creative_ids": ["cr2"],
        },
    ]
    err, sanitized = dp.validate_flights(flights, "2026-06-01", "2026-06-30")
    assert err is not None
    assert "overlap" in err.lower()
    assert sanitized is None


def test_flight_outside_campaign_range_rejected():
    flights = [
        {
            "name": "A",
            "start_date": "2026-05-01",
            "end_date": "2026-06-15",
            "daily_budget_cents": 50000,
            "creative_ids": ["cr1"],
        },
    ]
    err, _ = dp.validate_flights(flights, "2026-06-01", "2026-06-30")
    assert err is not None
    assert "within campaign range" in err.lower()


def test_flight_valid_assigns_id():
    flights = [
        {
            "name": "A",
            "start_date": "2026-06-01",
            "end_date": "2026-06-15",
            "daily_budget_cents": 50000,
            "creative_ids": ["cr1", "cr2"],
        },
    ]
    err, sanitized = dp.validate_flights(flights, "2026-06-01", "2026-06-30")
    assert err is None
    assert sanitized[0]["flight_id"].startswith("fl_")
    assert sanitized[0]["status"] == "scheduled"


def test_budget_pacing_12h_active():
    # 12 active hours → hourly budget = daily / 12.
    cfg = {"timezone": "UTC", "schedule": {"monday": list(range(8, 20))}}
    pacing = dp.calculate_dayparted_budget(
        daily_budget_cents=120000, dayparting=cfg, now=_ts(2026, 6, 1, 8)
    )
    assert pacing["active_hours_today"] == 12
    assert pacing["hourly_budget_cents"] == 10000
    assert pacing["hours_remaining"] == 12  # 8..19 inclusive, current hour 8
    assert pacing["remaining_budget_cents"] == 120000


def test_budget_pacing_no_dayparting_24h():
    pacing = dp.calculate_dayparted_budget(
        daily_budget_cents=240000, dayparting=None, now=_ts(2026, 6, 1, 0)
    )
    assert pacing["active_hours_today"] == 24
    assert pacing["hourly_budget_cents"] == 10000


def test_budget_pacing_inactive_day_zero():
    cfg = {"timezone": "UTC", "schedule": {"monday": [9, 10]}}
    # 2026-06-07 is a Sunday → no active hours.
    pacing = dp.calculate_dayparted_budget(
        daily_budget_cents=120000, dayparting=cfg, now=_ts(2026, 6, 7, 9)
    )
    assert pacing["active_hours_today"] == 0
    assert pacing["remaining_budget_cents"] == 0
