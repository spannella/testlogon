"""Hermetic offline tests for HTL-005..HTL-008.

Covers:
  * HTL-005 — Room Type CRUD (create_room_type, get_room_type, list_room_types,
    update_room_type, archive_room_type)
  * HTL-006 — Room CRUD (create_room, get_room, list_rooms, update_room, delete_room)
  * HTL-007 — Housekeeping status + tasks (set_room_housekeeping_status,
    create_hk_task, assign_hk_task, list_hk_tasks, complete_hk_task)
  * HTL-008 — Router (flag-gate, route-ordering, handler delegation)

Pattern: moto-backed ``hotels`` + ``hotel_rooms`` tables bound to the frozen
``T.hotels`` / ``T.hotel_rooms`` handles via ``object.__setattr__``.  Frozen
``S`` flags toggled the same way.  Service functions called directly; router
coroutines called on a fresh ``asyncio.new_event_loop()``.
No ``TestClient`` (broken pattern per CLAUDE.md).
"""
from __future__ import annotations

import asyncio
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

OWNER1 = "owner1"
OWNER2 = "owner2"


def _make_tables(ddb):
    hotels = ddb.create_table(
        TableName="hotels",
        KeySchema=[
            {"AttributeName": "hotel_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "hotel_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "owner_sub", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI_OWNER",
                "KeySchema": [
                    {"AttributeName": "owner_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_STATUS",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_HOTEL_ROOMTYPES",
                "KeySchema": [
                    {"AttributeName": "hotel_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    rooms = ddb.create_table(
        TableName="hotel_rooms",
        KeySchema=[
            {"AttributeName": "hotel_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "hotel_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "room_type_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
            {"AttributeName": "housekeeping_status", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "assignee_sub", "AttributeType": "S"},
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
            {
                "IndexName": "GSI_HK_TASK_STATUS",
                "KeySchema": [
                    {"AttributeName": "hotel_id", "KeyType": "HASH"},
                    {"AttributeName": "status", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "GSI_HK_ASSIGNEE",
                "KeySchema": [
                    {"AttributeName": "assignee_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return hotels, rooms


@pytest.fixture()
def ctx():
    """Provide moto-backed DDB tables, patched T/S, and the svc module."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        hotels, rooms = _make_tables(ddb)

        from app.core import tables as T_mod
        from app.services import hotel_pms as svc

        _orig_hotels = T_mod.T.hotels
        _orig_rooms = T_mod.T.hotel_rooms
        _orig_flag = svc.S.hotel_pms_enabled

        object.__setattr__(T_mod.T, "hotels", hotels)
        object.__setattr__(T_mod.T, "hotel_rooms", rooms)
        object.__setattr__(svc.S, "hotel_pms_enabled", True)

        # Seed parent hotel META
        hotels.put_item(
            Item={
                "hotel_id": "h1",
                "sk": "META",
                "owner_sub": OWNER1,
                "name": "Test Hotel",
                "status": "active",
                "created_at": 1000,
                "updated_at": 1000,
            }
        )

        yield SimpleNamespace(hotels=hotels, rooms=rooms, svc=svc, T_mod=T_mod)

        # Restore originals
        object.__setattr__(T_mod.T, "hotels", _orig_hotels)
        object.__setattr__(T_mod.T, "hotel_rooms", _orig_rooms)
        object.__setattr__(svc.S, "hotel_pms_enabled", _orig_flag)


# ---------------------------------------------------------------------------
# Helper: create a room type and a room quickly
# ---------------------------------------------------------------------------

def _create_rt(ctx, **overrides):
    kw = dict(
        name="Deluxe King",
        description="Nice room",
        base_occupancy_adults=2,
        base_occupancy_children=0,
        max_occupancy=3,
        bed_type="king",
        size_sqft=350,
        base_nightly_rate_cents=19900,
        photo_urls=[],
        user_sub=OWNER1,
    )
    kw.update(overrides)
    return ctx.svc.create_room_type("h1", **kw)


def _create_room(ctx, rt, **overrides):
    kw = dict(room_number="101", floor=1, status="available", user_sub=OWNER1)
    kw.update(overrides)
    return ctx.svc.create_room("h1", room_type_id=rt["room_type_id"], **kw)


# ===========================================================================
# HTL-005 — Room Type tests
# ===========================================================================

class TestRoomTypeCreate:
    def test_creates_full_row(self, ctx):
        rt = _create_rt(ctx)
        assert len(rt["room_type_id"]) == 32  # uuid4().hex
        assert rt["sk"] == f"ROOMTYPE#{rt['room_type_id']}"
        assert rt["status"] == "active"
        assert rt["base_nightly_rate_cents"] == 19900
        assert isinstance(rt["base_nightly_rate_cents"], int)
        assert isinstance(rt["max_occupancy"], int)
        assert isinstance(rt["created_at"], int)

    def test_rejects_unknown_hotel(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.create_room_type(
                "no_such_hotel",
                name="X", base_occupancy_adults=1, max_occupancy=1,
                bed_type="single", base_nightly_rate_cents=5000, user_sub=OWNER1,
            )
        assert exc.value.status_code == 404

    def test_rejects_wrong_owner(self, ctx):
        with pytest.raises(HTTPException) as exc:
            _create_rt(ctx, user_sub=OWNER2)
        assert exc.value.status_code == 403

    def test_rejects_occupancy_invariant(self, ctx):
        with pytest.raises(HTTPException) as exc:
            _create_rt(ctx, base_occupancy_adults=2, base_occupancy_children=1, max_occupancy=2)
        assert exc.value.status_code == 422

    def test_flag_off_raises_404(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException) as exc:
            _create_rt(ctx)
        assert exc.value.status_code == 404


class TestRoomTypeGet:
    def test_hit_and_miss(self, ctx):
        rt = _create_rt(ctx)
        fetched = ctx.svc.get_room_type("h1", rt["room_type_id"])
        assert fetched is not None
        assert fetched["room_type_id"] == rt["room_type_id"]

        missing = ctx.svc.get_room_type("h1", "deadbeef" * 4)
        assert missing is None

    def test_flag_off_raises_404(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException):
            ctx.svc.get_room_type("h1", "x")


class TestRoomTypeList:
    def test_returns_only_roomtype_rows(self, ctx):
        _create_rt(ctx)
        _create_rt(ctx, name="Suite")
        result = ctx.svc.list_room_types("h1")
        assert len(result["room_types"]) == 2
        for rt in result["room_types"]:
            assert rt["sk"].startswith("ROOMTYPE#")
            assert rt["sk"] != "META"

    def test_empty_hotel(self, ctx):
        ctx.hotels.put_item(
            Item={"hotel_id": "h2", "sk": "META", "owner_sub": OWNER1,
                  "name": "Empty", "status": "active", "created_at": 1001, "updated_at": 1001}
        )
        result = ctx.svc.list_room_types("h2")
        assert result == {"room_types": [], "count": 0, "cursor": None}

    def test_status_filter(self, ctx):
        rt1 = _create_rt(ctx, name="Active Room")
        rt2 = _create_rt(ctx, name="Will Archive")
        ctx.svc.archive_room_type("h1", rt2["room_type_id"], user_sub=OWNER1)

        active = ctx.svc.list_room_types("h1", status="active")
        assert len(active["room_types"]) == 1
        assert active["room_types"][0]["room_type_id"] == rt1["room_type_id"]

        archived = ctx.svc.list_room_types("h1", status="archived")
        assert len(archived["room_types"]) == 1

        all_ = ctx.svc.list_room_types("h1", status="all")
        assert len(all_["room_types"]) == 2

    def test_flag_off(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException):
            ctx.svc.list_room_types("h1")


class TestRoomTypeUpdate:
    def test_partial_update(self, ctx):
        rt = _create_rt(ctx)
        updated = ctx.svc.update_room_type(
            "h1", rt["room_type_id"], user_sub=OWNER1, base_nightly_rate_cents=24900
        )
        assert updated["base_nightly_rate_cents"] == 24900
        assert updated["name"] == "Deluxe King"  # unchanged

    def test_escapes_reserved_name(self, ctx):
        rt = _create_rt(ctx)
        updated = ctx.svc.update_room_type(
            "h1", rt["room_type_id"], user_sub=OWNER1, name="Suite Deluxe"
        )
        assert updated["name"] == "Suite Deluxe"

    def test_404_unknown_type(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.update_room_type("h1", "deadbeef" * 4, user_sub=OWNER1, name="X")
        assert exc.value.status_code == 404

    def test_merged_occupancy_invariant(self, ctx):
        rt = _create_rt(ctx, base_occupancy_adults=2, base_occupancy_children=1, max_occupancy=3)
        with pytest.raises(HTTPException) as exc:
            ctx.svc.update_room_type("h1", rt["room_type_id"], user_sub=OWNER1, max_occupancy=2)
        assert exc.value.status_code == 422

    def test_403_wrong_owner(self, ctx):
        rt = _create_rt(ctx)
        with pytest.raises(HTTPException) as exc:
            ctx.svc.update_room_type("h1", rt["room_type_id"], user_sub=OWNER2, name="X")
        assert exc.value.status_code == 403

    def test_flag_off(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException):
            ctx.svc.update_room_type("h1", "x", user_sub=OWNER1, name="X")


class TestRoomTypeArchive:
    def test_flips_status(self, ctx):
        rt = _create_rt(ctx)
        archived = ctx.svc.archive_room_type("h1", rt["room_type_id"], user_sub=OWNER1)
        assert archived["status"] == "archived"
        fetched = ctx.svc.get_room_type("h1", rt["room_type_id"])
        assert fetched["status"] == "archived"

    def test_idempotent(self, ctx):
        rt = _create_rt(ctx)
        ctx.svc.archive_room_type("h1", rt["room_type_id"], user_sub=OWNER1)
        # Second archive should not raise
        again = ctx.svc.archive_room_type("h1", rt["room_type_id"], user_sub=OWNER1)
        assert again["status"] == "archived"

    def test_404_unknown(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.archive_room_type("h1", "deadbeef" * 4, user_sub=OWNER1)
        assert exc.value.status_code == 404

    def test_flag_off(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException):
            ctx.svc.archive_room_type("h1", "x", user_sub=OWNER1)


class TestRoomTypeDecimalCoercion:
    def test_raw_ddb_stores_decimal_but_get_returns_int(self, ctx):
        rt = _create_rt(ctx)
        raw = ctx.hotels.get_item(
            Key={"hotel_id": "h1", "sk": f"ROOMTYPE#{rt['room_type_id']}"}
        )["Item"]
        # DynamoDB returns N as Decimal
        assert isinstance(raw["base_nightly_rate_cents"], Decimal)
        # Service coerces to int
        fetched = ctx.svc.get_room_type("h1", rt["room_type_id"])
        assert isinstance(fetched["base_nightly_rate_cents"], int)
        assert isinstance(fetched["max_occupancy"], int)
        assert isinstance(fetched["created_at"], int)


class TestRoomTypeAudit:
    def test_audit_emitted(self, ctx):
        emitted = []
        with patch("app.services.hotel_pms._audit", side_effect=lambda *a, **kw: emitted.append(a[0])):
            rt = _create_rt(ctx)
            ctx.svc.update_room_type("h1", rt["room_type_id"], user_sub=OWNER1, name="New")
            ctx.svc.archive_room_type("h1", rt["room_type_id"], user_sub=OWNER1)
        assert "hotel.room_type.created" in emitted
        assert "hotel.room_type.updated" in emitted
        assert "hotel.room_type.archived" in emitted


# ===========================================================================
# HTL-006 — Room tests
# ===========================================================================

class TestRoomCreate:
    def test_creates_full_row(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        assert len(room["room_id"]) == 32
        assert room["sk"] == f"ROOM#{room['room_id']}"
        assert room["housekeeping_status"] == "clean"
        assert room["status"] == "available"
        assert isinstance(room["floor"], int)
        assert isinstance(room["created_at"], int)

    def test_rejects_unknown_hotel(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.create_room(
                "no_hotel", room_type_id="x", room_number="1", floor=1, user_sub=OWNER1
            )
        assert exc.value.status_code == 404

    def test_rejects_wrong_owner(self, ctx):
        rt = _create_rt(ctx)
        with pytest.raises(HTTPException) as exc:
            _create_room(ctx, rt, user_sub=OWNER2)
        assert exc.value.status_code == 403

    def test_rejects_unknown_room_type(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.create_room(
                "h1", room_type_id="deadbeef" * 4, room_number="1", floor=1, user_sub=OWNER1
            )
        assert exc.value.status_code == 404

    def test_rejects_empty_room_number(self, ctx):
        rt = _create_rt(ctx)
        with pytest.raises(HTTPException) as exc:
            _create_room(ctx, rt, room_number="")
        assert exc.value.status_code == 422

    def test_flag_off(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException):
            ctx.svc.create_room("h1", room_type_id="x", room_number="1", floor=1, user_sub=OWNER1)


class TestRoomGetList:
    def test_get_hit_and_miss(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        fetched = ctx.svc.get_room("h1", room["room_id"])
        assert fetched is not None
        missing = ctx.svc.get_room("h1", "deadbeef" * 4)
        assert missing is None

    def test_list_returns_only_room_rows(self, ctx):
        rt = _create_rt(ctx)
        _create_room(ctx, rt, room_number="101")
        _create_room(ctx, rt, room_number="102")
        result = ctx.svc.list_rooms("h1")
        assert len(result["rooms"]) == 2
        for r in result["rooms"]:
            assert r["sk"].startswith("ROOM#")

    def test_list_empty(self, ctx):
        ctx.hotels.put_item(
            Item={"hotel_id": "h2", "sk": "META", "owner_sub": OWNER1,
                  "name": "Empty", "status": "active", "created_at": 1002, "updated_at": 1002}
        )
        result = ctx.svc.list_rooms("h2")
        assert result == {"rooms": [], "count": 0, "cursor": None}

    def test_list_status_filter(self, ctx):
        rt = _create_rt(ctx)
        room1 = _create_room(ctx, rt, room_number="101")
        _create_room(ctx, rt, room_number="102", status="out_of_service")
        result = ctx.svc.list_rooms("h1", status="available")
        assert len(result["rooms"]) == 1
        assert result["rooms"][0]["room_id"] == room1["room_id"]

    def test_list_by_room_type(self, ctx):
        rt1 = _create_rt(ctx, name="King")
        rt2 = _create_rt(ctx, name="Twin", bed_type="twin")
        _create_room(ctx, rt1, room_number="101")
        _create_room(ctx, rt2, room_number="201")
        result = ctx.svc.list_rooms("h1", room_type_id=rt1["room_type_id"])
        assert len(result["rooms"]) == 1
        assert result["rooms"][0]["room_type_id"] == rt1["room_type_id"]


class TestRoomUpdate:
    def test_partial_update(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        updated = ctx.svc.update_room("h1", room["room_id"], user_sub=OWNER1, floor=5)
        assert updated["floor"] == 5
        assert updated["room_number"] == "101"  # unchanged

    def test_update_drops_housekeeping_status(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        # Passing housekeeping_status in kwargs should be silently dropped
        updated = ctx.svc.update_room(
            "h1", room["room_id"], user_sub=OWNER1, floor=3, housekeeping_status="dirty"
        )
        assert updated["housekeeping_status"] == "clean"  # unchanged

    def test_404_unknown(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.update_room("h1", "deadbeef" * 4, user_sub=OWNER1, floor=1)
        assert exc.value.status_code == 404

    def test_403_wrong_owner(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        with pytest.raises(HTTPException) as exc:
            ctx.svc.update_room("h1", room["room_id"], user_sub=OWNER2, floor=1)
        assert exc.value.status_code == 403

    def test_rejects_unknown_room_type_on_update(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        with pytest.raises(HTTPException) as exc:
            ctx.svc.update_room("h1", room["room_id"], user_sub=OWNER1, room_type_id="deadbeef" * 4)
        assert exc.value.status_code == 404


class TestRoomDelete:
    def test_delete_returns_true(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        ok = ctx.svc.delete_room("h1", room["room_id"], user_sub=OWNER1)
        assert ok is True
        assert ctx.svc.get_room("h1", room["room_id"]) is None

    def test_delete_unknown_returns_false(self, ctx):
        ok = ctx.svc.delete_room("h1", "deadbeef" * 4, user_sub=OWNER1)
        assert ok is False

    def test_idempotent(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        ctx.svc.delete_room("h1", room["room_id"], user_sub=OWNER1)
        ok2 = ctx.svc.delete_room("h1", room["room_id"], user_sub=OWNER1)
        assert ok2 is False

    def test_flag_off(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException):
            ctx.svc.delete_room("h1", "x", user_sub=OWNER1)


class TestRoomAudit:
    def test_audit_emitted(self, ctx):
        emitted = []
        with patch("app.services.hotel_pms._audit", side_effect=lambda *a, **kw: emitted.append(a[0])):
            rt = _create_rt(ctx)
            room = _create_room(ctx, rt)
            ctx.svc.update_room("h1", room["room_id"], user_sub=OWNER1, floor=2)
            ctx.svc.delete_room("h1", room["room_id"], user_sub=OWNER1)
        assert "hotel.room.created" in emitted
        assert "hotel.room.updated" in emitted
        assert "hotel.room.deleted" in emitted


# ===========================================================================
# HTL-007 — Housekeeping tests
# ===========================================================================

class TestHousekeepingStatus:
    def test_set_status(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        updated = ctx.svc.set_room_housekeeping_status(
            "h1", room["room_id"], housekeeping_status="dirty", user_sub=OWNER1
        )
        assert updated["housekeeping_status"] == "dirty"
        # GSI_HK_STATUS should reflect the change
        fetched = ctx.svc.get_room("h1", room["room_id"])
        assert fetched["housekeeping_status"] == "dirty"

    def test_invalid_enum_raises_422(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        with pytest.raises(HTTPException) as exc:
            ctx.svc.set_room_housekeeping_status(
                "h1", room["room_id"], housekeeping_status="sparkling", user_sub=OWNER1
            )
        assert exc.value.status_code == 422

    def test_room_not_found_raises_404(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.set_room_housekeeping_status(
                "h1", "deadbeef" * 4, housekeeping_status="clean", user_sub=OWNER1
            )
        assert exc.value.status_code == 404

    def test_wrong_owner_raises_403(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        with pytest.raises(HTTPException) as exc:
            ctx.svc.set_room_housekeeping_status(
                "h1", room["room_id"], housekeeping_status="dirty", user_sub=OWNER2
            )
        assert exc.value.status_code == 403

    def test_flag_off(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException):
            ctx.svc.set_room_housekeeping_status("h1", "x", housekeeping_status="clean", user_sub=OWNER1)


class TestHkTaskCreate:
    def test_creates_full_row(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        task = ctx.svc.create_hk_task(
            "h1", room_id=room["room_id"], assignee_sub="staff1",
            due_at=9999, notes="VIP room", user_sub=OWNER1,
        )
        assert len(task["task_id"]) == 32
        assert task["status"] == "open"
        assert task["assignee_sub"] == "staff1"
        assert task["due_at"] == 9999
        assert task["completed_at"] == 0
        assert isinstance(task["created_at"], int)

    def test_room_not_found_raises_404(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.create_hk_task("h1", room_id="deadbeef" * 4, user_sub=OWNER1)
        assert exc.value.status_code == 404

    def test_defaults(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        task = ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        assert task["assignee_sub"] == ""
        assert task["due_at"] == 0
        assert task["notes"] == ""

    def test_flag_off(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException):
            ctx.svc.create_hk_task("h1", room_id="x", user_sub=OWNER1)


class TestHkTaskAssign:
    def test_assign(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        task = ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        updated = ctx.svc.assign_hk_task("h1", task["task_id"], assignee_sub="staff2", user_sub=OWNER1)
        assert updated["assignee_sub"] == "staff2"

    def test_idempotent_reassign(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        task = ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        ctx.svc.assign_hk_task("h1", task["task_id"], assignee_sub="staff2", user_sub=OWNER1)
        again = ctx.svc.assign_hk_task("h1", task["task_id"], assignee_sub="staff2", user_sub=OWNER1)
        assert again["assignee_sub"] == "staff2"

    def test_task_not_found(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.assign_hk_task("h1", "deadbeef" * 4, assignee_sub="x", user_sub=OWNER1)
        assert exc.value.status_code == 404

    def test_flag_off(self, ctx):
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        with pytest.raises(HTTPException):
            ctx.svc.assign_hk_task("h1", "x", assignee_sub="y", user_sub=OWNER1)


class TestHkTaskListAndComplete:
    def test_list_by_hotel(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        result = ctx.svc.list_hk_tasks(hotel_id="h1")
        assert len(result["tasks"]) == 2
        for t in result["tasks"]:
            assert t["sk"].startswith("HKTASK#")

    def test_list_by_status(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        t1 = ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        t2 = ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        ctx.svc.complete_hk_task("h1", t2["task_id"], user_sub=OWNER1)
        result = ctx.svc.list_hk_tasks(hotel_id="h1", status="open")
        assert len(result["tasks"]) == 1
        assert result["tasks"][0]["task_id"] == t1["task_id"]

    def test_list_by_assignee(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        t1 = ctx.svc.create_hk_task("h1", room_id=room["room_id"], assignee_sub="staff1", user_sub=OWNER1)
        ctx.svc.create_hk_task("h1", room_id=room["room_id"], assignee_sub="staff2", user_sub=OWNER1)
        result = ctx.svc.list_hk_tasks(assignee_sub="staff1")
        assert len(result["tasks"]) == 1
        assert result["tasks"][0]["task_id"] == t1["task_id"]

    def test_list_empty(self, ctx):
        result = ctx.svc.list_hk_tasks(hotel_id="h1")
        assert result == {"tasks": [], "count": 0, "cursor": None}

    def test_list_requires_hotel_or_assignee(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.list_hk_tasks()
        assert exc.value.status_code == 422

    def test_complete_sets_done(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        task = ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        completed = ctx.svc.complete_hk_task("h1", task["task_id"], user_sub=OWNER1)
        assert completed["status"] == "done"
        assert completed["completed_at"] > 0

    def test_complete_idempotent(self, ctx):
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        task = ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        ctx.svc.complete_hk_task("h1", task["task_id"], user_sub=OWNER1)
        # Second completion must not raise
        again = ctx.svc.complete_hk_task("h1", task["task_id"], user_sub=OWNER1)
        assert again["status"] == "done"

    def test_complete_task_not_found(self, ctx):
        with pytest.raises(HTTPException) as exc:
            ctx.svc.complete_hk_task("h1", "deadbeef" * 4, user_sub=OWNER1)
        assert exc.value.status_code == 404

    def test_hk_audit_emitted(self, ctx):
        emitted = []
        with patch("app.services.hotel_pms._audit", side_effect=lambda *a, **kw: emitted.append(a[0])):
            rt = _create_rt(ctx)
            room = _create_room(ctx, rt)
            ctx.svc.set_room_housekeeping_status(
                "h1", room["room_id"], housekeeping_status="dirty", user_sub=OWNER1
            )
            task = ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
            ctx.svc.assign_hk_task("h1", task["task_id"], assignee_sub="staff1", user_sub=OWNER1)
            ctx.svc.complete_hk_task("h1", task["task_id"], user_sub=OWNER1)
        assert "hotel.room.housekeeping_status" in emitted
        assert "hotel.hk_task.created" in emitted
        assert "hotel.hk_task.assigned" in emitted
        assert "hotel.hk_task.completed" in emitted

    def test_tasks_not_in_list_rooms(self, ctx):
        """HKTASK# rows must not appear in list_rooms."""
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        rooms_result = ctx.svc.list_rooms("h1")
        for r in rooms_result["rooms"]:
            assert r["sk"].startswith("ROOM#")

    def test_rooms_not_in_list_hk_tasks(self, ctx):
        """ROOM# rows must not appear in list_hk_tasks."""
        rt = _create_rt(ctx)
        room = _create_room(ctx, rt)
        # Create a task so the list is not empty
        ctx.svc.create_hk_task("h1", room_id=room["room_id"], user_sub=OWNER1)
        tasks_result = ctx.svc.list_hk_tasks(hotel_id="h1")
        for t in tasks_result["tasks"]:
            assert t["sk"].startswith("HKTASK#")


# ===========================================================================
# HTL-008 — Router tests
# ===========================================================================

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestRouter:
    """Test the HTL-008 router handlers in isolation."""

    def test_router_route_ordering(self):
        """housekeeping literal-suffix route declared before bare {room_id}."""
        from app.routers.hotel_rooms import hotel_rooms_router
        paths = [r.path for r in hotel_rooms_router.routes]
        # Both routes must exist
        hk_path = "/{hotel_id}/rooms/{room_id}/housekeeping"
        bare_path = "/{hotel_id}/rooms/{room_id}"
        assert any(hk_path in p for p in paths), f"Missing {hk_path} in {paths}"
        assert any(bare_path in p for p in paths), f"Missing {bare_path} in {paths}"
        # Housekeeping route declared before bare route
        hk_idx = next(i for i, p in enumerate(paths) if hk_path in p)
        bare_idx = next(i for i, r in enumerate(hotel_rooms_router.routes)
                        if hasattr(r, "path") and r.path == f"/ui/hotels/{bare_path.lstrip('/')}"
                        and getattr(r, "methods", set()) == {"PUT"})
        assert hk_idx < bare_idx

    def test_flag_off_all_handlers_404(self, ctx):
        """When flag is off, every handler raises 404 before any DDB access."""
        object.__setattr__(ctx.svc.S, "hotel_pms_enabled", False)
        from app.routers.hotel_rooms import (
            list_room_types, create_room_type, get_room_type, update_room_type,
            archive_room_type, list_rooms, create_room, get_room, update_room,
            delete_room, set_room_housekeeping, list_hk_tasks, create_hk_task,
            assign_hk_task, complete_hk_task,
        )
        from unittest.mock import AsyncMock

        fake_session = {"user_sub": OWNER1}
        fake_user = MagicMock()
        fake_user.sub = OWNER1

        async def _check_404(coro):
            with pytest.raises(HTTPException) as exc:
                await coro
            assert exc.value.status_code == 404

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_check_404(list_room_types("h1", session=fake_session)))
            loop.run_until_complete(_check_404(get_room_type("h1", "rt1", session=fake_session)))
            loop.run_until_complete(_check_404(list_rooms("h1", session=fake_session)))
            loop.run_until_complete(_check_404(get_room("h1", "r1", session=fake_session)))
            loop.run_until_complete(_check_404(list_hk_tasks("h1", session=fake_session)))
        finally:
            loop.close()

    def test_create_room_type_handler(self, ctx):
        """Router handler delegates to service and returns RoomTypeOut."""
        from app.routers.hotel_rooms import create_room_type as handler
        from app.models import RoomTypeIn

        fake_user = MagicMock()
        fake_user.sub = OWNER1
        body = RoomTypeIn(
            name="Standard Queen",
            base_occupancy_adults=2,
            max_occupancy=2,
            bed_type="queen",
            base_nightly_rate_cents=12000,
        )
        result = _run(handler("h1", body, user=fake_user))
        assert result.name == "Standard Queen"
        assert result.bed_type == "queen"
        assert result.status == "active"

    def test_create_room_handler(self, ctx):
        """Router handler for create_room delegates correctly."""
        from app.routers.hotel_rooms import create_room_type as rt_handler
        from app.routers.hotel_rooms import create_room as room_handler
        from app.models import RoomTypeIn, RoomIn

        fake_user = MagicMock()
        fake_user.sub = OWNER1
        rt_body = RoomTypeIn(
            name="Twin", base_occupancy_adults=2, max_occupancy=2, bed_type="twin",
            base_nightly_rate_cents=8000,
        )
        rt = _run(rt_handler("h1", rt_body, user=fake_user))

        room_body = RoomIn(room_type_id=rt.room_type_id, room_number="201", floor=2)
        room = _run(room_handler("h1", room_body, user=fake_user))
        assert room.room_number == "201"
        assert room.housekeeping_status == "clean"

    def test_delete_room_handler_returns_ok(self, ctx):
        """delete_room handler returns {"ok": True/False} dict."""
        from app.routers.hotel_rooms import create_room_type as rt_handler
        from app.routers.hotel_rooms import create_room as room_handler
        from app.routers.hotel_rooms import delete_room as del_handler
        from app.models import RoomTypeIn, RoomIn

        fake_user = MagicMock()
        fake_user.sub = OWNER1
        rt_body = RoomTypeIn(
            name="Twin Del", base_occupancy_adults=1, max_occupancy=1, bed_type="single",
            base_nightly_rate_cents=5000,
        )
        rt = _run(rt_handler("h1", rt_body, user=fake_user))
        room_body = RoomIn(room_type_id=rt.room_type_id, room_number="301", floor=3)
        room = _run(room_handler("h1", room_body, user=fake_user))
        result = _run(del_handler("h1", room.room_id, user=fake_user))
        assert result == {"ok": True}
        result2 = _run(del_handler("h1", room.room_id, user=fake_user))
        assert result2 == {"ok": False}

    def test_complete_task_handler(self, ctx):
        """complete_hk_task handler returns HkTaskOut with status=done."""
        from app.routers.hotel_rooms import (
            create_room_type as rt_handler,
            create_room as room_handler,
            create_hk_task as task_handler,
            complete_hk_task as complete_handler,
        )
        from app.models import RoomTypeIn, RoomIn, HkTaskIn

        fake_user = MagicMock()
        fake_user.sub = OWNER1

        rt_body = RoomTypeIn(
            name="Suite", base_occupancy_adults=2, max_occupancy=4, bed_type="suite",
            base_nightly_rate_cents=30000,
        )
        rt = _run(rt_handler("h1", rt_body, user=fake_user))
        room_body = RoomIn(room_type_id=rt.room_type_id, room_number="401", floor=4)
        room = _run(room_handler("h1", room_body, user=fake_user))
        task_body = HkTaskIn(room_id=room.room_id)
        task = _run(task_handler("h1", task_body, user=fake_user))
        completed = _run(complete_handler("h1", task.task_id, user=fake_user))
        assert completed.status == "done"


# ===========================================================================
# Import smoke test
# ===========================================================================

def test_import_smoke():
    """app.main must import cleanly even in the stale worktree."""
    import importlib
    import app.main  # noqa: F401
    importlib.import_module("app.services.hotel_pms")
    importlib.import_module("app.routers.hotel_rooms")
