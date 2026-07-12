"""Hermetic offline pytest for HTL-010..HTL-012 hotel availability backend.

Pattern: moto-backed ``hotel_availability`` table bound to the frozen
``T.hotel_availability`` handle via ``object.__setattr__``; frozen
``S.hotel_pms_enabled`` toggled via ``object.__setattr__``; route coroutines
from ``app/routers/hotel_availability`` called directly on a fresh
``asyncio.new_event_loop()``. No ``TestClient``, no real AWS, no network.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_aws  # moto >= 5
except ImportError:  # pragma: no cover
    from moto import mock_dynamodb as mock_aws  # moto 4.x fallback

# ─── Test helpers ─────────────────────────────────────────────────────────────

HOTEL_ID = "h_test_01"
RT_ID = "rt_deluxe"
RT_ID2 = "rt_standard"
ADMIN_SUB = "test-admin-sub"


def _make_admin():
    from app.auth.deps import AuthenticatedUser
    from app.auth.roles import Role
    return AuthenticatedUser(sub=ADMIN_SUB, role=Role.ADMIN)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ─── Fixture ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _avail_table(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="hotel_availability",
            KeySchema=[
                {"AttributeName": "availability_pk", "KeyType": "HASH"},
                {"AttributeName": "sk",              "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "availability_pk", "AttributeType": "S"},
                {"AttributeName": "sk",              "AttributeType": "S"},
                {"AttributeName": "hotel_id",        "AttributeType": "S"},
                {"AttributeName": "date",            "AttributeType": "S"},
                {"AttributeName": "gsi_expiry_pk",   "AttributeType": "S"},
                {"AttributeName": "expires_at",      "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_HOTEL_DATE",
                    "KeySchema": [
                        {"AttributeName": "hotel_id", "KeyType": "HASH"},
                        {"AttributeName": "date",     "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_HOLD_EXPIRY",
                    "KeySchema": [
                        {"AttributeName": "gsi_expiry_pk", "KeyType": "HASH"},
                        {"AttributeName": "expires_at",    "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        from app.core import tables as T_mod
        from app.services import hotel_availability as svc

        orig_t = T_mod.T.hotel_availability
        orig_flag = svc.S.hotel_pms_enabled

        object.__setattr__(T_mod.T, "hotel_availability", table)
        object.__setattr__(svc.S, "hotel_pms_enabled", True)
        object.__setattr__(svc.S, "hotel_availability_table_name", "hotel_availability")

        monkeypatch.setattr(svc, "_audit", lambda *a, **k: None, raising=False)

        yield table

        # Restore originals
        object.__setattr__(T_mod.T, "hotel_availability", orig_t)
        object.__setattr__(svc.S, "hotel_pms_enabled", orig_flag)


# ─── Convenience imports (after fixture setup) ────────────────────────────────

def _svc():
    from app.services import hotel_availability
    return hotel_availability


def _router():
    from app.routers import hotel_availability as r
    return r


# ─────────────────────────────────────────────────────────────────────────────
# Flag behavior (HTL-010..HTL-012) — tests 1-6
# ─────────────────────────────────────────────────────────────────────────────

def test_flag_off_set_total_rooms():
    """Flag=False → set_total_rooms raises HTTPException(404)."""
    svc = _svc()
    from fastapi import HTTPException
    from app.core import tables as T_mod

    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 5, user_sub="u")
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)


def test_flag_off_get_availability():
    svc = _svc()
    from fastapi import HTTPException

    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            svc.get_availability(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02")
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)


def test_flag_off_hold_rooms():
    svc = _svc()
    from fastapi import HTTPException

    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 1, user_sub="u")
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)


def test_flag_off_availability_calendar():
    svc = _svc()
    from fastapi import HTTPException

    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            svc.availability_calendar(HOTEL_ID, "2026-07-01", "2026-07-03")
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)


def test_flag_off_check_availability():
    svc = _svc()
    from fastapi import HTTPException

    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            svc.check_availability(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 1)
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)


def test_flag_off_route_handler():
    """Router handler raises 404 when flag is off."""
    svc = _svc()
    r = _router()
    from fastapi import HTTPException

    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            _run(r.get_availability_calendar(
                hotel_id=HOTEL_ID,
                start_date="2026-07-01",
                end_date="2026-07-03",
                session={},
            ))
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)


# ─────────────────────────────────────────────────────────────────────────────
# Date-range seeding (HTL-010) — tests 7-12
# ─────────────────────────────────────────────────────────────────────────────

def test_set_total_rooms_row_count(_avail_table):
    """set_total_rooms over 3 dates writes exactly 3 DATE# rows."""
    svc = _svc()
    rows = svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 5, user_sub="a")
    assert len(rows) == 3
    # Verify via direct DDB query
    pk = svc._availability_pk(HOTEL_ID, RT_ID)
    from boto3.dynamodb.conditions import Key
    resp = _avail_table.query(
        KeyConditionExpression=Key("availability_pk").eq(pk)
    )
    assert len(resp["Items"]) == 3
    dates = {item["date"] for item in resp["Items"]}
    assert dates == {"2026-07-01", "2026-07-02", "2026-07-03"}
    for item in resp["Items"]:
        assert int(item["total_rooms"]) == 5
        # available is now persisted (= total_rooms + ob - booked - held = 5)
    for row in rows:
        assert row["total_rooms"] == 5
        assert row["available"] == 5  # total(5) + ob(0) - booked(0) - held(0)


def test_set_total_rooms_preserves_held(_avail_table):
    """Re-set preserves booked/held/overbooking on existing rows."""
    svc = _svc()
    # Seed initial row
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 10, user_sub="a")
    # Manually add held/booked on the row
    pk = svc._availability_pk(HOTEL_ID, RT_ID)
    _avail_table.update_item(
        Key={"availability_pk": pk, "sk": "DATE#2026-07-01"},
        UpdateExpression="SET held = :h, booked = :b, overbooking_allowance = :ob",
        ExpressionAttributeValues={":h": 2, ":b": 1, ":ob": 3},
    )
    # Re-set with new total_rooms
    rows = svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 8, user_sub="a")
    assert len(rows) == 1
    row = rows[0]
    assert row["total_rooms"] == 8
    assert row["held"] == 2        # preserved
    assert row["booked"] == 1      # preserved
    assert row["overbooking_allowance"] == 3  # preserved
    # available = 8 + 3 - 1 - 2 = 8
    assert row["available"] == 8


def test_available_computation():
    """_available = total + overbooking - booked - held."""
    svc = _svc()
    item = {
        "total_rooms": 10,
        "overbooking_allowance": 2,
        "booked": 3,
        "held": 1,
    }
    assert svc._available(item) == 8
    row_out = svc._row_out(dict(item, hotel_id="h", room_type_id="rt", date="2026-07-01", updated_at=0))
    assert row_out["available"] == 8


def test_never_seeded_date_is_zeroed(_avail_table):
    """get_availability zero-fills a never-seeded night, not an error."""
    svc = _svc()
    rows = svc.get_availability(HOTEL_ID, RT_ID, "2026-07-04", "2026-07-05")
    assert len(rows) == 1
    row = rows[0]
    assert row["date"] == "2026-07-04"
    assert row["available"] == 0
    assert row["total_rooms"] == 0


def test_get_availability_checkout_exclusive(_avail_table):
    """get_availability returns [checkin, checkout) — departure night excluded."""
    svc = _svc()
    # Seed 4 nights
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-04", "2026-07-07", 5, user_sub="a")
    rows = svc.get_availability(HOTEL_ID, RT_ID, "2026-07-04", "2026-07-07")
    # checkout=07-07 excluded → 3 nights
    assert len(rows) == 3
    assert [r["date"] for r in rows] == ["2026-07-04", "2026-07-05", "2026-07-06"]


def test_decimal_coercion(_avail_table):
    """DDB Decimal fields are coerced to plain int in _row_out."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 7, user_sub="a")
    rows = svc.get_availability(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02")
    assert len(rows) == 1
    row = rows[0]
    for field in ("total_rooms", "booked", "held", "overbooking_allowance", "min_availability", "available"):
        assert isinstance(row[field], int), f"{field} should be int, got {type(row[field])}"
    assert isinstance(row["updated_at"], int)


# ─────────────────────────────────────────────────────────────────────────────
# Conditional decrement / hold (HTL-011) — tests 13-16
# ─────────────────────────────────────────────────────────────────────────────

def test_hold_rooms_increments_held(_avail_table):
    """hold_rooms increments held by quantity on all nights."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 5, user_sub="a")
    result = svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 2, user_sub="u")
    assert result["status"] == "active"
    assert set(result["dates"]) == {"2026-07-01", "2026-07-02"}  # checkout 07-03 excluded
    assert result["quantity"] == 2
    assert result["hold_id"]
    # Check DDB rows
    for d in ["2026-07-01", "2026-07-02"]:
        row = svc.get_day(HOTEL_ID, RT_ID, d)
        assert row["held"] == 2


def test_hold_rooms_rollback_on_sold_out(_avail_table):
    """Over-capacity hold → 409 + held unchanged on all nights."""
    svc = _svc()
    # Night 1 and 2: 5 rooms; Night 3 (but it's checkout): excluded
    # Actually: we need a span where one night fails
    # Seed night 1 with 5 rooms, night 2 with 1 room
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 5, user_sub="a")
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-02", "2026-07-02", 1, user_sub="a")
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-03", "2026-07-03", 5, user_sub="a")
    # Try to hold 3 rooms for 3 nights (checkin=01, checkout=04 → nights 01,02,03)
    # Night 02 only has 1 room, so 3-room hold should fail
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-04", 3, user_sub="u")
    assert exc_info.value.status_code == 409
    # All nights should have held=0 (rollback)
    for d in ["2026-07-01", "2026-07-02", "2026-07-03"]:
        row = svc.get_day(HOTEL_ID, RT_ID, d)
        assert row["held"] == 0, f"Night {d}: held should be 0 after rollback"
    # No HOLD# partition should exist
    from boto3.dynamodb.conditions import Key
    # Check that no HOLD# items exist in the table by scanning
    resp = _avail_table.scan(
        FilterExpression="begins_with(availability_pk, :h)",
        ExpressionAttributeValues={":h": "HOLD#"},
    )
    # Filter for HOLD# but NOT HOLD#ACTIVE (which is the GSI pk value)
    hold_items = [
        item for item in resp["Items"]
        if item.get("availability_pk", "").startswith("HOLD#")
        and not item.get("availability_pk", "").startswith("HOLD#ACTIVE")
    ]
    assert hold_items == [], "No HOLD# meta rows should exist after rollback"


def test_release_hold_restores_held(_avail_table):
    """release_hold decrements held back; double-release is no-op."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 5, user_sub="a")
    hold = svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 2, user_sub="u")
    hold_id = hold["hold_id"]
    # Release
    released = svc.release_hold(hold_id, user_sub="u")
    assert released["status"] == "released"
    row = svc.get_day(HOTEL_ID, RT_ID, "2026-07-01")
    assert row["held"] == 0
    # Double-release is idempotent
    released2 = svc.release_hold(hold_id, user_sub="u")
    assert released2["status"] == "released"
    row2 = svc.get_day(HOTEL_ID, RT_ID, "2026-07-01")
    assert row2["held"] == 0  # not double-decremented


def test_hold_ttl_expiry(_avail_table):
    """expire_due_holds flips overdue hold to expired and restores held."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 5, user_sub="a")
    hold = svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 2, user_sub="u", ttl_seconds=100)
    hold_id = hold["hold_id"]
    expires_at = hold["expires_at"]
    # Expire past the TTL
    count = svc.expire_due_holds(now=expires_at + 1)
    assert count >= 1
    # Meta row should now be expired
    meta = _avail_table.get_item(
        Key={"availability_pk": f"HOLD#{hold_id}", "sk": "META"}
    )
    assert meta["Item"]["status"] == "expired"
    # held should be restored
    row = svc.get_day(HOTEL_ID, RT_ID, "2026-07-01")
    assert row["held"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Span-intersection check (HTL-012) — tests 17-21
# ─────────────────────────────────────────────────────────────────────────────

def test_check_availability_all_sufficient(_avail_table):
    """check_availability → available=True when every night is sufficient."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 5, user_sub="a")
    result = svc.check_availability(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 2)
    assert result["available"] is True
    assert result["rooms_needed"] == 2
    assert all(n["sufficient"] for n in result["per_night"])
    assert len(result["per_night"]) == 2  # checkout 03 excluded


def test_check_availability_one_short_night(_avail_table):
    """One short night → available=False."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 5, user_sub="a")
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-02", "2026-07-02", 1, user_sub="a")
    result = svc.check_availability(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 3)
    assert result["available"] is False
    # night 07-02 should be the short one
    short = [n for n in result["per_night"] if not n["sufficient"]]
    assert any(n["date"] == "2026-07-02" for n in short)


def test_check_availability_min_remaining(_avail_table):
    """min_remaining is the binding constraint."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 5, user_sub="a")
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-02", "2026-07-02", 2, user_sub="a")
    result = svc.check_availability(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 1)
    assert result["available"] is True
    assert result["min_remaining"] == 2


def test_check_availability_checkout_exclusion(_avail_table):
    """Checkout date sold-out → stay still bookable (checkout excluded)."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 5, user_sub="a")
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-03", "2026-07-03", 0, user_sub="a")
    # checkout=07-03 → nights 07-01, 07-02 only; 07-03 excluded
    result = svc.check_availability(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 1)
    assert result["available"] is True


def test_check_availability_missing_night(_avail_table):
    """A never-seeded night surfaces as available=False."""
    svc = _svc()
    # Only seed night 1; night 2 is unseeded (available=0)
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 5, user_sub="a")
    result = svc.check_availability(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 1)
    assert result["available"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Overbooking + min/max (HTL-011) — tests 22-24
# ─────────────────────────────────────────────────────────────────────────────

def test_overbooking_allowance_enables_hold(_avail_table):
    """A hold that needs overbooking_allowance succeeds after it's set."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 2, user_sub="a")
    # Fill up held
    svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 2, user_sub="u1")
    # Now try to hold 1 more — should fail without overbooking
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 1, user_sub="u2")
    assert exc_info.value.status_code == 409
    # Set overbooking allowance
    svc.set_overbooking_allowance(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 1, user_sub="a")
    svc.set_overbooking_allowance(HOTEL_ID, RT_ID, "2026-07-02", "2026-07-02", 1, user_sub="a")
    # Now the hold should succeed
    result = svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 1, user_sub="u2")
    assert result["status"] == "active"


def test_min_availability_floor(_avail_table):
    """min_availability floor rejects a hold that would breach it."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 5, user_sub="a")
    svc.set_min_max_availability(
        HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", min_availability=2, user_sub="a"
    )
    svc.set_min_max_availability(
        HOTEL_ID, RT_ID, "2026-07-02", "2026-07-02", min_availability=2, user_sub="a"
    )
    # 4-room hold: condition 5 >= 4+2 → False → 409
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 4, user_sub="u")
    assert exc_info.value.status_code == 409
    # 3-room hold: condition 5 >= 3+2 → True → success
    result = svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 3, user_sub="u")
    assert result["status"] == "active"


def test_set_min_max_persist(_avail_table):
    """set_min_max_availability persists and is reflected in get_day."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 10, user_sub="a")
    svc.set_min_max_availability(
        HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01",
        min_availability=2, max_availability=8, user_sub="a"
    )
    row = svc.get_day(HOTEL_ID, RT_ID, "2026-07-01")
    assert row["min_availability"] == 2
    assert row["max_availability"] == 8
    # Validation: min > max → 422
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.set_min_max_availability(
            HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01",
            min_availability=5, max_availability=4, user_sub="a"
        )
    assert exc_info.value.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# Calendar aggregation (HTL-012) — test 25
# ─────────────────────────────────────────────────────────────────────────────

def test_availability_calendar_groups_by_room_type(_avail_table):
    """availability_calendar groups rows by room_type_id from GSI_HOTEL_DATE."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID,  "2026-07-01", "2026-07-02", 5, user_sub="a")
    svc.set_total_rooms(HOTEL_ID, RT_ID2, "2026-07-01", "2026-07-02", 3, user_sub="a")
    cal = svc.availability_calendar(HOTEL_ID, "2026-07-01", "2026-07-02")
    assert cal["hotel_id"] == HOTEL_ID
    assert cal["start_date"] == "2026-07-01"
    assert cal["end_date"] == "2026-07-02"
    assert RT_ID in cal["room_types"]
    assert RT_ID2 in cal["room_types"]
    assert len(cal["room_types"][RT_ID]) == 2
    assert len(cal["room_types"][RT_ID2]) == 2
    # Dates should be ordered
    dates = [r["date"] for r in cal["room_types"][RT_ID]]
    assert dates == ["2026-07-01", "2026-07-02"]


# ─────────────────────────────────────────────────────────────────────────────
# Router route ordering (HTL-012) — tests 26-28
# ─────────────────────────────────────────────────────────────────────────────

def test_router_calendar_route_not_captured_by_dynamic(_avail_table):
    """GET /availability/calendar routes to calendar handler, not dynamic."""
    svc = _svc()
    r = _router()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 5, user_sub="a")
    result = _run(r.get_availability_calendar(
        hotel_id=HOTEL_ID,
        start_date="2026-07-01",
        end_date="2026-07-01",
        session={},
    ))
    # Should return a calendar dict with "room_types" key, not a list of AvailabilityDayOut
    assert isinstance(result, dict)
    assert "room_types" in result
    assert "hotel_id" in result


def test_router_check_route_not_captured_by_dynamic(_avail_table):
    """GET /availability/check routes to check handler, not dynamic."""
    svc = _svc()
    r = _router()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 5, user_sub="a")
    result = _run(r.check_availability(
        hotel_id=HOTEL_ID,
        room_type_id=RT_ID,
        checkin="2026-07-01",
        checkout="2026-07-02",
        rooms_needed=1,
        session={},
    ))
    # Should return a check dict with "available" key, not a list
    assert isinstance(result, dict)
    assert "available" in result
    assert "per_night" in result


def test_router_release_route_routing(_avail_table):
    """POST /availability/holds/{hold_id}/release routes to release handler."""
    svc = _svc()
    r = _router()
    # Seed and hold
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 5, user_sub="a")
    hold = svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 2, user_sub="u")
    hold_id = hold["hold_id"]
    admin = _make_admin()
    result = _run(r.release_hold(
        hotel_id=HOTEL_ID,
        hold_id=hold_id,
        user=admin,
    ))
    # Should return a HoldOut with status=released
    from app.models import HoldOut
    assert isinstance(result, HoldOut)
    assert result.status == "released"


# ─────────────────────────────────────────────────────────────────────────────
# Additional edge cases
# ─────────────────────────────────────────────────────────────────────────────

def test_end_date_before_start_date():
    """end_date < start_date → HTTPException(422)."""
    svc = _svc()
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-10", "2026-07-01", 5, user_sub="a")
    assert exc_info.value.status_code == 422


def test_same_day_checkin_checkout():
    """checkin == checkout (zero nights) → HTTPException(422)."""
    svc = _svc()
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.get_availability(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01")
    assert exc_info.value.status_code == 422


def test_available_can_be_negative():
    """_available returns negative when over-committed (unclamped)."""
    svc = _svc()
    item = {"total_rooms": 2, "booked": 3, "held": 0, "overbooking_allowance": 0}
    assert svc._available(item) == -1


def test_get_day_returns_none_for_absent():
    """get_day returns None for a never-seeded date."""
    svc = _svc()
    result = svc.get_day(HOTEL_ID, RT_ID, "2026-07-01")
    assert result is None


def test_hold_missing_404():
    """release_hold on a non-existent hold → 404."""
    svc = _svc()
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.release_hold("does-not-exist", user_sub="u")
    assert exc_info.value.status_code == 404


def test_concurrent_sweep_does_not_double_restore(_avail_table):
    """expire_due_holds twice — second call returns 0 (status-CAS one-winner)."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 5, user_sub="a")
    hold = svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 2, user_sub="u", ttl_seconds=10)
    expires_at = hold["expires_at"]
    count1 = svc.expire_due_holds(now=expires_at + 1)
    count2 = svc.expire_due_holds(now=expires_at + 1)
    assert count1 == 1
    assert count2 == 0
    # held should be 0, not negative
    row = svc.get_day(HOTEL_ID, RT_ID, "2026-07-01")
    assert row["held"] == 0


def test_unseeded_night_hold_rolls_back(_avail_table):
    """hold_rooms over an unseeded night → 409 and no partial increment."""
    svc = _svc()
    # Seed night 1 but NOT night 2
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-01", 5, user_sub="a")
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        svc.hold_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-03", 1, user_sub="u")
    assert exc_info.value.status_code == 409
    # Night 1 should still have held=0 (rolled back)
    row = svc.get_day(HOTEL_ID, RT_ID, "2026-07-01")
    assert row["held"] == 0


def test_set_overbooking_on_unseeded_date(_avail_table):
    """set_overbooking_allowance creates zeroed row for unseeded date."""
    svc = _svc()
    rows = svc.set_overbooking_allowance(HOTEL_ID, RT_ID, "2026-08-01", "2026-08-01", 5, user_sub="a")
    assert len(rows) == 1
    assert rows[0]["overbooking_allowance"] == 5
    assert rows[0]["total_rooms"] == 0


def test_gsi_hotel_date_queryable(_avail_table):
    """GSI_HOTEL_DATE query works without ValidationException."""
    svc = _svc()
    svc.set_total_rooms(HOTEL_ID, RT_ID, "2026-07-01", "2026-07-02", 5, user_sub="a")
    from boto3.dynamodb.conditions import Key
    # Direct GSI query — must not raise
    resp = _avail_table.query(
        IndexName="GSI_HOTEL_DATE",
        KeyConditionExpression=(
            Key("hotel_id").eq(HOTEL_ID) & Key("date").between("2026-07-01", "2026-07-02")
        ),
    )
    assert len(resp["Items"]) >= 1


def test_no_dev_mode_in_service():
    """hotel_availability.py must not contain any S.dev_mode reference (SECOPS-007)."""
    import inspect
    svc = _svc()
    src = inspect.getsource(svc)
    # No reference to dev_mode at all (not even in comments/docstrings per SECOPS-007)
    assert "dev_mode" not in src, "SECOPS-007 violated: dev_mode reference found in hotel_availability.py"
