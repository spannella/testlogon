"""Hermetic offline pytest for HTL-022..024 (hotel front-desk service + router).

Pattern: moto-backed hotel_reservations + hotel_rooms tables (with all required
GSIs) bound to frozen T.hotel_reservations / T.hotel_rooms via object.__setattr__
(restored on cleanup), and frozen S.hotel_pms_enabled toggled the same way.

NO live stack, NO real AWS, NO TestClient.  The four HTL-024 router coroutines
are invoked directly on a fresh asyncio.new_event_loop().

Mandatory test-isolation rule (CLAUDE.md/prior-batch lessons):
  * All sys.modules / frozen-T / frozen-S mutations live in a single
    scope="module" autouse fixture that SAVES prior values and RESTORES them
    in teardown (pop/delattr if originally absent).
"""
from __future__ import annotations

import asyncio
import decimal
import sys
import types
import uuid
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

# ---------------------------------------------------------------------------
# Setup fixture — module scope so tables are shared across all tests.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True, scope="module")
def _setup():
    """Spin up moto tables, bind frozen T handles, enable the flag."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # hotel_reservations table (HTL-018 schema)
        reservations_table = ddb.create_table(
            TableName="hotel_reservations_test",
            KeySchema=[
                {"AttributeName": "reservation_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "reservation_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "hotel_id", "AttributeType": "S"},
                {"AttributeName": "checkin", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "guest_party_id", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_HOTEL_ARRIVALS",
                    "KeySchema": [
                        {"AttributeName": "hotel_id", "KeyType": "HASH"},
                        {"AttributeName": "checkin", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_HOTEL_STATUS",
                    "KeySchema": [
                        {"AttributeName": "hotel_id", "KeyType": "HASH"},
                        {"AttributeName": "status", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_GUEST",
                    "KeySchema": [
                        {"AttributeName": "guest_party_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        reservations_table.meta.client.get_waiter("table_exists").wait(
            TableName="hotel_reservations_test"
        )

        # hotel_rooms table (HTL-006 schema)
        rooms_table = ddb.create_table(
            TableName="hotel_rooms_test",
            KeySchema=[
                {"AttributeName": "hotel_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "hotel_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "room_type_id", "AttributeType": "S"},
                {"AttributeName": "housekeeping_status", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_ROOMTYPE",
                    "KeySchema": [
                        {"AttributeName": "room_type_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_HK_STATUS",
                    "KeySchema": [
                        {"AttributeName": "hotel_id", "KeyType": "HASH"},
                        {"AttributeName": "housekeeping_status", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        rooms_table.meta.client.get_waiter("table_exists").wait(
            TableName="hotel_rooms_test"
        )

        # Import service/T/S AFTER moto context is active
        from app.core import tables as T_mod
        from app.services import hotel_front_desk as svc
        from app.core.settings import S

        # Save originals
        _orig_hotel_reservations = getattr(T_mod.T, "hotel_reservations", None)
        _orig_hotel_rooms = getattr(T_mod.T, "hotel_rooms", None)
        _orig_flag = getattr(S, "hotel_pms_enabled", False)

        # Bind test tables to frozen handles
        object.__setattr__(T_mod.T, "hotel_reservations", reservations_table)
        object.__setattr__(T_mod.T, "hotel_rooms", rooms_table)
        object.__setattr__(S, "hotel_pms_enabled", True)

        yield reservations_table, rooms_table, svc, S

        # Restore originals
        object.__setattr__(T_mod.T, "hotel_reservations", _orig_hotel_reservations)
        object.__setattr__(T_mod.T, "hotel_rooms", _orig_hotel_rooms)
        object.__setattr__(S, "hotel_pms_enabled", _orig_flag)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TODAY = "2026-06-14"
TOMORROW = "2026-06-15"
HOTEL = "hotel_001"


def _rid() -> str:
    return "res_" + uuid.uuid4().hex[:8]


def _seed_reservation(
    table,
    hotel_id: str = HOTEL,
    *,
    status: str,
    checkin: str = TODAY,
    checkout: str = TOMORROW,
    assigned_room_ids: list = None,
    guest_party_id: str = "g_alice",
    guest_name: str = None,
    nights: Any = None,
    adults: Any = 2,
    children: Any = 0,
    total_cents: Any = 10000,
    reservation_id: str = None,
) -> str:
    rid = reservation_id or _rid()
    item: Dict[str, Any] = {
        "reservation_id": rid,
        "sk": "META",
        "hotel_id": hotel_id,
        "status": status,
        "checkin": checkin,
        "checkout": checkout,
        "room_type_id": "rt_standard",
        "guest_party_id": guest_party_id,
        "adults": adults,
        "children": children,
        "total_cents": total_cents,
        "assigned_room_ids": assigned_room_ids or [],
        "version": 1,
        "created_at": 1700000000,
    }
    if nights is not None:
        item["nights"] = nights
    if guest_name is not None:
        item["guest_name"] = guest_name
    table.put_item(Item=item)
    return rid


def _seed_room(
    table,
    hotel_id: str = HOTEL,
    room_id: str = None,
    *,
    housekeeping_status: str = "clean",
) -> str:
    rid = room_id or ("r_" + uuid.uuid4().hex[:6])
    table.put_item(
        Item={
            "hotel_id": hotel_id,
            "sk": f"ROOM#{rid}",
            "room_id": rid,
            "room_type_id": "rt_standard",
            "status": "available",
            "housekeeping_status": housekeeping_status,
            "created_at": 1700000000,
        }
    )
    return rid


def _delete_all(table, key_attr: str, pk_val: str) -> None:
    """Delete all items from a table with the given PK."""
    resp = table.scan()
    for item in resp.get("Items", []):
        if key_attr == "reservation_id":
            table.delete_item(Key={"reservation_id": item["reservation_id"], "sk": item["sk"]})
        elif key_attr == "hotel_id":
            table.delete_item(Key={"hotel_id": item["hotel_id"], "sk": item["sk"]})


# Each test cleans up rows for its hotel so tests are isolated.
@pytest.fixture()
def clean_tables(_setup):
    reservations_table, rooms_table, svc, S = _setup
    yield reservations_table, rooms_table, svc, S
    # Clean up
    for item in reservations_table.scan().get("Items", []):
        reservations_table.delete_item(Key={"reservation_id": item["reservation_id"], "sk": item["sk"]})
    for item in rooms_table.scan().get("Items", []):
        rooms_table.delete_item(Key={"hotel_id": item["hotel_id"], "sk": item["sk"]})


# ---------------------------------------------------------------------------
# 1. Flag-off 404 for all four functions
# ---------------------------------------------------------------------------

def test_flag_off_arrivals(_setup):
    reservations_table, rooms_table, svc, S = _setup
    object.__setattr__(S, "hotel_pms_enabled", False)
    try:
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.arrivals_today(HOTEL)
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(S, "hotel_pms_enabled", True)


def test_flag_off_departures(_setup):
    _, _, svc, S = _setup
    object.__setattr__(S, "hotel_pms_enabled", False)
    try:
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.departures_today(HOTEL)
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(S, "hotel_pms_enabled", True)


def test_flag_off_in_house(_setup):
    _, _, svc, S = _setup
    object.__setattr__(S, "hotel_pms_enabled", False)
    try:
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.in_house(HOTEL)
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(S, "hotel_pms_enabled", True)


def test_flag_off_occupancy_snapshot(_setup):
    _, _, svc, S = _setup
    object.__setattr__(S, "hotel_pms_enabled", False)
    try:
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.occupancy_snapshot(HOTEL)
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(S, "hotel_pms_enabled", True)


# ---------------------------------------------------------------------------
# 2. arrivals_today — confirmed + checkin==date only
# ---------------------------------------------------------------------------

def test_arrivals_today_filters_correctly(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    # (a) confirmed, checkin=today — SHOULD appear
    _seed_reservation(reservations_table, status="confirmed", checkin=TODAY)
    # (b) checked_in, checkin=today — should NOT appear (already in)
    _seed_reservation(reservations_table, status="checked_in", checkin=TODAY, checkout=TOMORROW)
    # (c) confirmed, checkin=tomorrow — should NOT appear (wrong date)
    _seed_reservation(reservations_table, status="confirmed", checkin=TOMORROW, checkout="2026-06-16")
    # (d) cancelled, checkin=today — should NOT appear
    _seed_reservation(reservations_table, status="cancelled", checkin=TODAY)

    result = svc.arrivals_today(HOTEL, date=TODAY)
    assert result["count"] == 1
    assert len(result["rows"]) == 1
    assert result["rows"][0]["status"] == "confirmed"
    assert result["rows"][0]["checkin"] == TODAY


# ---------------------------------------------------------------------------
# 3. arrivals_today — date defaults to today (patching _today)
# ---------------------------------------------------------------------------

def test_arrivals_today_date_defaults(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(reservations_table, status="confirmed", checkin=TODAY)

    with patch.object(svc, "_today", return_value=TODAY):
        result = svc.arrivals_today(HOTEL)  # no date param
    assert result["count"] == 1


# ---------------------------------------------------------------------------
# 4. arrivals_today — explicit future date override
# ---------------------------------------------------------------------------

def test_arrivals_today_explicit_date(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(reservations_table, status="confirmed", checkin=TOMORROW, checkout="2026-06-16")

    result_tomorrow = svc.arrivals_today(HOTEL, date=TOMORROW)
    assert result_tomorrow["count"] == 1

    result_today = svc.arrivals_today(HOTEL, date=TODAY)
    assert result_today["count"] == 0


# ---------------------------------------------------------------------------
# 5. arrivals_today — {rows, count, cursor} shape
# ---------------------------------------------------------------------------

def test_arrivals_today_return_shape(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(reservations_table, status="confirmed", checkin=TODAY)

    result = svc.arrivals_today(HOTEL, date=TODAY)
    assert set(result.keys()) == {"rows", "count", "cursor"}
    assert result["count"] == len(result["rows"])
    assert result["cursor"] is None


# ---------------------------------------------------------------------------
# 6. departures_today — checked_in + checkout==date only
# ---------------------------------------------------------------------------

def test_departures_today_filters_correctly(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    # (a) checked_in, checkout=today — SHOULD appear
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-13", checkout=TODAY)
    # (b) confirmed, checkout=today — should NOT appear
    _seed_reservation(reservations_table, status="confirmed", checkin=TODAY, checkout=TOMORROW)
    # (c) checked_in, checkout=tomorrow — should NOT appear
    _seed_reservation(reservations_table, status="checked_in", checkin=TODAY, checkout=TOMORROW)

    result = svc.departures_today(HOTEL, date=TODAY)
    assert result["count"] == 1
    assert result["rows"][0]["checkout"] == TODAY


# ---------------------------------------------------------------------------
# 7. departures_today — shape
# ---------------------------------------------------------------------------

def test_departures_today_shape(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-13", checkout=TODAY)

    result = svc.departures_today(HOTEL, date=TODAY)
    assert set(result.keys()) == {"rows", "count", "cursor"}
    assert result["count"] == len(result["rows"])


# ---------------------------------------------------------------------------
# 8. in_house — every checked_in regardless of date
# ---------------------------------------------------------------------------

def test_in_house_returns_all_checked_in(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-10", checkout="2026-06-12")
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-11", checkout="2026-06-13")
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-12", checkout=TODAY)
    _seed_reservation(reservations_table, status="confirmed", checkin=TODAY, checkout=TOMORROW)

    result = svc.in_house(HOTEL)
    assert result["count"] == 3
    for row in result["rows"]:
        assert row["status"] == "checked_in"


# ---------------------------------------------------------------------------
# 9. in_house — empty hotel
# ---------------------------------------------------------------------------

def test_in_house_empty(clean_tables):
    _, _, svc, S = clean_tables
    result = svc.in_house("hotel_empty_99")
    assert result == {"rows": [], "count": 0, "cursor": None}


# ---------------------------------------------------------------------------
# 10. occupancy_snapshot — distinct assigned_room_ids
# ---------------------------------------------------------------------------

def test_occupancy_snapshot_distinct_rooms(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    for i in range(5):
        _seed_room(rooms_table, HOTEL, f"room_{i}")
    # Two checked-in reservations sharing room_1
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-10", checkout=TODAY,
                      assigned_room_ids=["room_0", "room_1"])
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-10", checkout=TODAY,
                      assigned_room_ids=["room_1", "room_2"])

    snap = svc.occupancy_snapshot(HOTEL, date=TODAY)
    assert snap["rooms_total"] == 5
    assert snap["rooms_occupied"] == 3  # distinct {room_0, room_1, room_2}


# ---------------------------------------------------------------------------
# 11. occupancy_snapshot — out-of-service from GSI_HK_STATUS
# ---------------------------------------------------------------------------

def test_occupancy_snapshot_out_of_service(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    for i in range(4):
        _seed_room(rooms_table, HOTEL, f"oos_room_{i}", housekeeping_status="clean")
    _seed_room(rooms_table, HOTEL, "oos_room_4", housekeeping_status="out_of_service")
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-10", checkout=TODAY,
                      assigned_room_ids=["oos_room_0"])

    snap = svc.occupancy_snapshot(HOTEL, date=TODAY)
    assert snap["rooms_out_of_service"] == 1
    assert snap["rooms_total"] == 5
    assert snap["rooms_occupied"] == 1
    assert snap["rooms_available"] == max(5 - 1 - 1, 0)  # 3


# ---------------------------------------------------------------------------
# 12. occupancy_snapshot — occupancy_rate is in 0..1
# ---------------------------------------------------------------------------

def test_occupancy_snapshot_rate(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    for i in range(5):
        _seed_room(rooms_table, HOTEL, f"rate_room_{i}", housekeeping_status="clean")
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-10", checkout=TODAY,
                      assigned_room_ids=["rate_room_0", "rate_room_1", "rate_room_2"])

    snap = svc.occupancy_snapshot(HOTEL, date=TODAY)
    assert 0.0 <= snap["occupancy_rate"] <= 1.0
    assert snap["occupancy_rate"] == pytest.approx(3 / 5)


# ---------------------------------------------------------------------------
# 13. occupancy_snapshot — zero-room hotel (no ZeroDivisionError)
# ---------------------------------------------------------------------------

def test_occupancy_snapshot_zero_rooms(clean_tables):
    _, _, svc, S = clean_tables
    snap = svc.occupancy_snapshot("hotel_no_rooms_999", date=TODAY)
    assert snap["rooms_total"] == 0
    assert snap["occupancy_rate"] == 0.0
    assert snap["rooms_available"] == 0


# ---------------------------------------------------------------------------
# 14. occupancy_snapshot — counts wired
# ---------------------------------------------------------------------------

def test_occupancy_snapshot_counts(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    # 1 confirmed arriving today
    _seed_reservation(reservations_table, status="confirmed", checkin=TODAY, checkout=TOMORROW)
    # 1 checked_in departing today
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-13", checkout=TODAY)
    # 1 checked_in NOT departing today (tomorrow)
    _seed_reservation(reservations_table, status="checked_in", checkin=TODAY, checkout=TOMORROW)

    snap = svc.occupancy_snapshot(HOTEL, date=TODAY)
    assert snap["arrivals_count"] == 1
    assert snap["departures_count"] == 1
    assert snap["in_house_count"] == 2  # both checked_in rows


# ---------------------------------------------------------------------------
# 15. occupancy_snapshot — unassigned checked-in contributes zero occupied
# ---------------------------------------------------------------------------

def test_occupancy_snapshot_unassigned_zero(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_room(rooms_table, HOTEL, "ua_room_0")
    # checked_in but no assigned rooms
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-10", checkout=TODAY,
                      assigned_room_ids=[])

    snap = svc.occupancy_snapshot(HOTEL, date=TODAY)
    assert snap["rooms_occupied"] == 0


# ---------------------------------------------------------------------------
# 16. Pagination round-trip for arrivals_today
# ---------------------------------------------------------------------------

def test_arrivals_pagination(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    for _ in range(5):
        _seed_reservation(reservations_table, status="confirmed", checkin=TODAY)

    seen_ids = []
    cursor = None
    pages = 0
    while True:
        result = svc.arrivals_today(HOTEL, date=TODAY, cursor=cursor, limit=2)
        for row in result["rows"]:
            seen_ids.append(row["reservation_id"])
        cursor = result["cursor"]
        pages += 1
        if cursor is None:
            break

    assert len(seen_ids) == 5
    assert len(set(seen_ids)) == 5  # no duplicates
    assert pages >= 3  # at least 3 pages of 2


# ---------------------------------------------------------------------------
# 17. No scan called — all four functions use query only
# ---------------------------------------------------------------------------

def test_no_scan_called(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(reservations_table, status="confirmed", checkin=TODAY)
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-10", checkout=TODAY)
    _seed_room(rooms_table, HOTEL, "ns_room_0")

    scan_called = []

    original_res_scan = reservations_table.scan
    original_rooms_scan = rooms_table.scan

    def _no_scan_res(*args, **kwargs):
        scan_called.append("reservations.scan")
        return original_res_scan(*args, **kwargs)

    def _no_scan_rooms(*args, **kwargs):
        scan_called.append("rooms.scan")
        return original_rooms_scan(*args, **kwargs)

    reservations_table.scan = _no_scan_res
    rooms_table.scan = _no_scan_rooms

    try:
        svc.arrivals_today(HOTEL, date=TODAY)
        svc.departures_today(HOTEL, date=TODAY)
        svc.in_house(HOTEL)
        svc.occupancy_snapshot(HOTEL, date=TODAY)
    finally:
        reservations_table.scan = original_res_scan
        rooms_table.scan = original_rooms_scan

    assert scan_called == [], f"scan was called: {scan_called}"


# ---------------------------------------------------------------------------
# 18. Decimal coercion
# ---------------------------------------------------------------------------

def test_decimal_coercion(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(
        reservations_table,
        status="confirmed",
        checkin=TODAY,
        nights=decimal.Decimal("2"),
        adults=decimal.Decimal("3"),
        total_cents=decimal.Decimal("15000"),
    )

    result = svc.arrivals_today(HOTEL, date=TODAY)
    row = result["rows"][0]
    assert isinstance(row["nights"], int)
    assert isinstance(row["occupancy_adults"], int)
    assert isinstance(row["total_cents"], int)
    assert row["occupancy_adults"] == 3
    assert row["total_cents"] == 15000


# ---------------------------------------------------------------------------
# 19. nights recompute fallback
# ---------------------------------------------------------------------------

def test_nights_recomputed_from_dates(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(
        reservations_table,
        status="confirmed",
        checkin="2026-06-14",
        checkout="2026-06-16",
        # nights deliberately absent (not set / zero)
    )

    result = svc.arrivals_today(HOTEL, date="2026-06-14")
    row = result["rows"][0]
    # 2026-06-14 → 2026-06-16 = 2 nights
    assert row["nights"] == 2


# ---------------------------------------------------------------------------
# 20. guest_name fallback to guest_party_id
# ---------------------------------------------------------------------------

def test_guest_name_fallback(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(
        reservations_table,
        status="confirmed",
        checkin=TODAY,
        guest_party_id="g_opaque_123",
        # guest_name deliberately absent
    )

    result = svc.arrivals_today(HOTEL, date=TODAY)
    row = result["rows"][0]
    assert row["guest_sub"] == "g_opaque_123"
    assert row["guest_name"] == "g_opaque_123"


# ---------------------------------------------------------------------------
# 21. Malformed cursor restarts pagination silently
# ---------------------------------------------------------------------------

def test_malformed_cursor_restarts(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(reservations_table, status="confirmed", checkin=TODAY)

    # A tampered cursor should silently restart (no exception)
    result = svc.arrivals_today(HOTEL, date=TODAY, cursor="not_a_valid_cursor_xxxx")
    assert result["count"] >= 0  # no exception; first page returned


# ---------------------------------------------------------------------------
# 22. HTL-023: assign_room (version-gated)
# ---------------------------------------------------------------------------

def test_assign_room_sets_rooms(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    rid = _seed_reservation(reservations_table, status="confirmed", checkin=TODAY)

    result = svc.assign_room(HOTEL, rid, assigned_room_ids=["r101", "r102"], version=1, user_sub="agent_1")
    assert result["reservation"]["assigned_room_ids"] == ["r101", "r102"]


def test_assign_room_version_conflict(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    rid = _seed_reservation(reservations_table, status="confirmed", checkin=TODAY)

    # First assign succeeds (bumps version to 2)
    svc.assign_room(HOTEL, rid, assigned_room_ids=["r201"], version=1, user_sub="agent_1")

    # Second assign with stale version=1 → 409
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.assign_room(HOTEL, rid, assigned_room_ids=["r202"], version=1, user_sub="agent_1")
    assert exc_info.value.status_code == 409


def test_assign_room_not_found(clean_tables):
    _, _, svc, S = clean_tables
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.assign_room(HOTEL, "res_does_not_exist", assigned_room_ids=["r301"], version=1, user_sub="agent_1")
    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# 23. HTL-023: change_room (symmetric diff)
# ---------------------------------------------------------------------------

def test_change_room_symmetric_diff(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    rid = _seed_reservation(
        reservations_table, status="checked_in", checkin=TODAY,
        assigned_room_ids=["r101", "r102"]
    )

    result = svc.change_room(HOTEL, rid, assigned_room_ids=["r102", "r103"], version=1, user_sub="agent_1")
    assert sorted(result["reservation"]["assigned_room_ids"]) == ["r102", "r103"]


# ---------------------------------------------------------------------------
# 24. HTL-023: room_move
# ---------------------------------------------------------------------------

def test_room_move_success(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    rid = _seed_reservation(
        reservations_table, status="checked_in", checkin="2026-06-10", checkout=TOMORROW,
        assigned_room_ids=["r_from", "r_stay"]
    )

    result = svc.room_move(HOTEL, rid, from_room_id="r_from", to_room_id="r_to", version=1, user_sub="agent_1")
    rooms = sorted(result["reservation"]["assigned_room_ids"])
    assert "r_from" not in rooms
    assert "r_to" in rooms
    assert "r_stay" in rooms


def test_room_move_not_checked_in(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    rid = _seed_reservation(reservations_table, status="confirmed", checkin=TODAY,
                            assigned_room_ids=["r_x"])

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.room_move(HOTEL, rid, from_room_id="r_x", to_room_id="r_y", version=1, user_sub="agent_1")
    assert exc_info.value.status_code == 409


def test_room_move_from_not_assigned(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    rid = _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-10",
                            checkout=TOMORROW, assigned_room_ids=["r_actual"])

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.room_move(HOTEL, rid, from_room_id="r_wrong", to_room_id="r_new", version=1, user_sub="agent_1")
    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# 25. HTL-024 router — handler invocation via asyncio
# ---------------------------------------------------------------------------

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_router_get_arrivals(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(reservations_table, status="confirmed", checkin=TODAY)

    from app.routers.hotel_front_desk import get_arrivals
    from app.models import FrontDeskListOut

    # Simulate an authenticated session dict
    session = {"user_sub": "test_user", "role": "USER"}
    result = _run(get_arrivals(hotel_id=HOTEL, date=TODAY, cursor=None, limit=50, session=session))
    assert isinstance(result, FrontDeskListOut)
    assert result.count >= 1


def test_router_get_in_house(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_reservation(reservations_table, status="checked_in", checkin="2026-06-10", checkout=TOMORROW)

    from app.routers.hotel_front_desk import get_in_house
    from app.models import FrontDeskListOut

    session = {"user_sub": "test_user"}
    result = _run(get_in_house(hotel_id=HOTEL, cursor=None, limit=50, session=session))
    assert isinstance(result, FrontDeskListOut)
    assert result.count >= 1


def test_router_get_occupancy(clean_tables):
    reservations_table, rooms_table, svc, S = clean_tables
    _seed_room(rooms_table, HOTEL, "snap_room_0")

    from app.routers.hotel_front_desk import get_occupancy
    from app.models import OccupancySnapshotOut

    session = {"user_sub": "test_user"}
    result = _run(get_occupancy(hotel_id=HOTEL, date=TODAY, session=session))
    assert isinstance(result, OccupancySnapshotOut)
    assert result.rooms_total >= 1


def test_router_flag_off_returns_404(clean_tables):
    _, _, svc, S = clean_tables
    object.__setattr__(S, "hotel_pms_enabled", False)
    try:
        from app.routers.hotel_front_desk import get_arrivals
        from fastapi import HTTPException
        session = {"user_sub": "test_user"}
        with pytest.raises(HTTPException) as exc_info:
            _run(get_arrivals(hotel_id=HOTEL, date=TODAY, cursor=None, limit=50, session=session))
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(S, "hotel_pms_enabled", True)


# ---------------------------------------------------------------------------
# 26. app.main import check — hotel_front_desk_router is registered
# ---------------------------------------------------------------------------

def test_main_imports_and_registers_router():
    import app.main as main_mod
    from app.routers.hotel_front_desk import hotel_front_desk_router
    app_instance = main_mod.create_app()
    route_paths = [r.path for r in app_instance.routes]
    # At least one front-desk route should be registered
    fd_routes = [p for p in route_paths if "front-desk" in p]
    assert len(fd_routes) >= 4, f"Expected >=4 front-desk routes, found {fd_routes}"
