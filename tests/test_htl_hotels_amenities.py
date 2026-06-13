"""Hermetic pytest — QloApps hotel-PMS vertical (HTL-001..HTL-004).

Tests run OFFLINE: no live stack, no real AWS.
Pattern: moto-backed 'hotels' + 'hotel_amenities' tables bound to the
frozen T.hotels / T.hotel_amenities handles via object.__setattr__;
frozen S.hotel_pms_enabled toggled via object.__setattr__;
route coroutines from app.routers.hotels called directly on a fresh
asyncio.new_event_loop() — NO TestClient.

Mirrors test_gap_0265_0266_kyc_risk_scoring.py /
test_gap_0286_0287_kyc_partner_api.py patterns.
"""
from __future__ import annotations

import asyncio
import hashlib
from decimal import Decimal

import boto3
import pytest

from moto import mock_aws


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _admin_user(sub: str = "admin-sub"):
    from app.auth.deps import AuthenticatedUser
    from app.auth.roles import Role
    return AuthenticatedUser(sub=sub, role=Role.ADMIN)


OWNER_SUB = "test-owner-sub"
MOCK_SESSION = {"user_sub": OWNER_SUB, "role": "ADMIN"}

_BASE_ADDR = {
    "line1": "123 Main St",
    "city": "Metropolis",
    "region": "NY",
    "postal_code": "10001",
    "country": "US",
}

_BASE_HOTEL = dict(
    name="Grand Hotel",
    description="A fine hotel",
    star_rating=4,
    address=_BASE_ADDR,
    check_in_time="15:00",
    check_out_time="11:00",
)


# ---------------------------------------------------------------------------
# Fixture — create moto tables and wire them into frozen T / S
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _htl_tables():
    """Set up moto DynamoDB tables and patch T + S for all tests."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        hotels = ddb.create_table(
            TableName="hotels",
            KeySchema=[
                {"AttributeName": "hotel_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "hotel_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "owner_sub", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
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
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        amenities = ddb.create_table(
            TableName="hotel_amenities",
            KeySchema=[
                {"AttributeName": "amenity_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "amenity_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "category", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_CATEGORY",
                    "KeySchema": [
                        {"AttributeName": "category", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        from app.core import tables as T_mod
        from app.services import hotel_pms as svc

        object.__setattr__(T_mod.T, "hotels", hotels)
        object.__setattr__(T_mod.T, "hotel_amenities", amenities)
        object.__setattr__(svc.S, "hotel_pms_enabled", True)
        object.__setattr__(svc.S, "hotels_table_name", "hotels")
        object.__setattr__(svc.S, "hotel_amenities_table_name", "hotel_amenities")

        yield {"hotels": hotels, "amenities": amenities}

        # Restore
        object.__setattr__(svc.S, "hotel_pms_enabled", False)


# ===========================================================================
# Flag behavior tests
# ===========================================================================


class TestFlagOff:
    """All service entrypoints must 404 when flag is off."""

    def _disable(self):
        from app.services import hotel_pms as svc
        object.__setattr__(svc.S, "hotel_pms_enabled", False)

    def _enable(self):
        from app.services import hotel_pms as svc
        object.__setattr__(svc.S, "hotel_pms_enabled", True)

    def test_create_hotel_flag_off(self):
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        self._disable()
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
            assert exc_info.value.status_code == 404
        finally:
            self._enable()

    def test_list_hotels_flag_off(self):
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        self._disable()
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.list_hotels(OWNER_SUB)
            assert exc_info.value.status_code == 404
        finally:
            self._enable()

    def test_create_amenity_flag_off(self):
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        self._disable()
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.create_amenity(name="WiFi", category="connectivity", user_sub=OWNER_SUB)
            assert exc_info.value.status_code == 404
        finally:
            self._enable()

    def test_attach_amenity_flag_off(self):
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        self._disable()
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.attach_amenity(
                    target_type="hotel",
                    target_id="fake",
                    amenity_id="fake",
                    user_sub=OWNER_SUB,
                )
            assert exc_info.value.status_code == 404
        finally:
            self._enable()

    def test_list_amenities_for_flag_off(self):
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        self._disable()
        try:
            with pytest.raises(HTTPException) as exc_info:
                svc.list_amenities_for(target_type="hotel", target_id="fake")
            assert exc_info.value.status_code == 404
        finally:
            self._enable()


# ===========================================================================
# Hotel CRUD tests
# ===========================================================================


class TestHotelCRUD:

    def test_create_hotel_success(self):
        from app.services import hotel_pms as svc
        result = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        assert result["hotel_id"]
        assert result["sk"] == "META"
        assert result["status"] == "active"
        assert result["name"] == "Grand Hotel"
        assert isinstance(result["star_rating"], int)
        assert isinstance(result["created_at"], int)
        assert isinstance(result["updated_at"], int)
        assert result["check_in_time"] == "15:00"
        assert result["check_out_time"] == "11:00"
        assert result["address"]["city"] == "Metropolis"

    def test_create_hotel_idempotency(self):
        from app.services import hotel_pms as svc
        r1 = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        r2 = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        assert r1["hotel_id"] == r2["hotel_id"]
        # Only one META row in DDB
        from app.core import tables as T_mod
        resp = T_mod.T.hotels.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("hotel_id").eq(r1["hotel_id"])
        )
        assert len(resp["Items"]) == 1

    def test_get_hotel_hit(self):
        from app.services import hotel_pms as svc
        created = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        fetched = svc.get_hotel(created["hotel_id"])
        assert fetched is not None
        assert fetched["hotel_id"] == created["hotel_id"]

    def test_get_hotel_miss(self):
        from app.services import hotel_pms as svc
        assert svc.get_hotel("nonexistent-id") is None

    def test_update_hotel_changes_fields(self):
        from app.services import hotel_pms as svc
        created = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        original_updated = created["updated_at"]
        updated = svc.update_hotel(
            created["hotel_id"],
            user_sub=OWNER_SUB,
            name="Updated Hotel",
            star_rating=5,
        )
        assert updated["name"] == "Updated Hotel"
        assert updated["star_rating"] == 5
        assert updated["updated_at"] >= original_updated

    def test_update_hotel_missing(self):
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        with pytest.raises(HTTPException) as exc_info:
            svc.update_hotel("nonexistent", user_sub=OWNER_SUB, name="X")
        assert exc_info.value.status_code == 404

    def test_update_hotel_empty_kwargs_stamps_updated_at(self):
        from app.services import hotel_pms as svc
        created = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        original_name = created["name"]
        # update with no meaningful field changes
        updated = svc.update_hotel(created["hotel_id"], user_sub=OWNER_SUB)
        assert updated["name"] == original_name
        assert updated["updated_at"] >= created["updated_at"]

    def test_archive_hotel(self):
        from app.services import hotel_pms as svc
        created = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        archived = svc.archive_hotel(created["hotel_id"], user_sub=OWNER_SUB)
        assert archived["status"] == "archived"
        # Verify via get
        fetched = svc.get_hotel(created["hotel_id"])
        assert fetched["status"] == "archived"

    def test_hotel_id_determinism(self):
        from app.services import hotel_pms as svc
        id1 = svc._hotel_id("alice", "Grand Plaza")
        id2 = svc._hotel_id("alice", "Grand Plaza")
        id3 = svc._hotel_id("bob", "Grand Plaza")
        id4 = svc._hotel_id("alice", "Seaside Inn")
        assert id1 == id2
        assert id1 != id3
        assert id1 != id4

    def test_address_round_trip(self):
        from app.services import hotel_pms as svc
        addr = {
            "line1": "1 Palace Rd",
            "line2": "Suite 5",
            "city": "London",
            "region": "England",
            "postal_code": "SW1A 1AA",
            "country": "GB",
        }
        created = svc.create_hotel(
            OWNER_SUB,
            name="Palace Hotel",
            star_rating=5,
            address=addr,
        )
        fetched = svc.get_hotel(created["hotel_id"])
        for k, v in addr.items():
            assert fetched["address"][k] == v

    def test_photo_urls_round_trip_non_empty(self):
        from app.services import hotel_pms as svc
        urls = ["https://example.com/img1.jpg", "https://example.com/img2.jpg"]
        created = svc.create_hotel(
            OWNER_SUB, name="Photo Hotel", star_rating=3,
            address=_BASE_ADDR, photo_urls=urls,
        )
        fetched = svc.get_hotel(created["hotel_id"])
        assert fetched["photo_urls"] == urls

    def test_photo_urls_round_trip_empty(self):
        from app.services import hotel_pms as svc
        created = svc.create_hotel(
            OWNER_SUB, name="Empty Photo Hotel", star_rating=3,
            address=_BASE_ADDR, photo_urls=[],
        )
        fetched = svc.get_hotel(created["hotel_id"])
        assert fetched["photo_urls"] == []

    def test_decimal_coercion(self):
        from app.services import hotel_pms as svc
        from app.core import tables as T_mod
        created = svc.create_hotel(OWNER_SUB, name="Decimal Hotel", star_rating=3, address=_BASE_ADDR)
        # Raw DDB item has Decimal
        raw = T_mod.T.hotels.get_item(
            Key={"hotel_id": created["hotel_id"], "sk": "META"}
        )["Item"]
        assert isinstance(raw["created_at"], Decimal)
        # Service returns int
        fetched = svc.get_hotel(created["hotel_id"])
        assert isinstance(fetched["star_rating"], int)
        assert isinstance(fetched["created_at"], int)
        assert isinstance(fetched["updated_at"], int)

    def test_gsi_owner_query_no_validation_exception(self):
        """Proves numeric created_at attr_type is correctly declared."""
        from app.services import hotel_pms as svc
        from app.core import tables as T_mod
        svc.create_hotel(OWNER_SUB, name="GSI Hotel 1", star_rating=3, address=_BASE_ADDR)
        svc.create_hotel(OWNER_SUB, name="GSI Hotel 2", star_rating=4, address=_BASE_ADDR)
        resp = T_mod.T.hotels.query(
            IndexName="GSI_OWNER",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("owner_sub").eq(OWNER_SUB),
        )
        assert len(resp["Items"]) >= 2


# ===========================================================================
# Pydantic model validation tests
# ===========================================================================


class TestHotelModelValidation:

    def test_star_rating_too_low(self):
        from pydantic import ValidationError
        from app.models import HotelIn
        with pytest.raises(ValidationError):
            HotelIn(name="X", star_rating=0, address=_BASE_ADDR)

    def test_star_rating_too_high(self):
        from pydantic import ValidationError
        from app.models import HotelIn
        with pytest.raises(ValidationError):
            HotelIn(name="X", star_rating=6, address=_BASE_ADDR)

    def test_check_in_time_invalid(self):
        from pydantic import ValidationError
        from app.models import HotelIn
        with pytest.raises(ValidationError):
            HotelIn(name="X", star_rating=3, address=_BASE_ADDR, check_in_time="25:00")

    def test_check_in_time_valid(self):
        from app.models import HotelIn
        h = HotelIn(name="X", star_rating=3, address=_BASE_ADDR, check_in_time="09:30")
        assert h.check_in_time == "09:30"

    def test_check_in_time_bad_format(self):
        from pydantic import ValidationError
        from app.models import HotelIn
        with pytest.raises(ValidationError):
            HotelIn(name="X", star_rating=3, address=_BASE_ADDR, check_in_time="9:5")


# ===========================================================================
# Amenity dictionary + attach/detach tests
# ===========================================================================


class TestAmenities:

    def test_create_amenity_success(self):
        from app.services import hotel_pms as svc
        result = svc.create_amenity(name="Free WiFi", category="connectivity", user_sub=OWNER_SUB)
        assert result["amenity_id"]
        assert result["sk"] == "META"
        assert result["name"] == "Free WiFi"
        assert result["category"] == "connectivity"
        assert isinstance(result["created_at"], int)

    def test_create_amenity_idempotency(self):
        from app.services import hotel_pms as svc
        r1 = svc.create_amenity(name="Free WiFi", category="connectivity", user_sub=OWNER_SUB)
        r2 = svc.create_amenity(name="Free WiFi", category="connectivity", user_sub=OWNER_SUB)
        assert r1["amenity_id"] == r2["amenity_id"]

    def test_amenity_id_determinism(self):
        from app.services import hotel_pms as svc
        id1 = svc._amenity_id("Free WiFi")
        id2 = svc._amenity_id("Free WiFi")
        id3 = svc._amenity_id("Pool")
        assert id1 == id2
        assert id1 != id3

    def test_list_amenities_by_category(self):
        from app.services import hotel_pms as svc
        svc.create_amenity(name="WiFi", category="connectivity", user_sub=OWNER_SUB)
        svc.create_amenity(name="Pool", category="wellness", user_sub=OWNER_SUB)
        results = svc.list_amenities(category="connectivity")
        assert len(results) == 1
        assert results[0]["name"] == "WiFi"

    def test_list_amenities_all(self):
        from app.services import hotel_pms as svc
        svc.create_amenity(name="WiFi A", category="connectivity", user_sub=OWNER_SUB)
        svc.create_amenity(name="Pool B", category="wellness", user_sub=OWNER_SUB)
        results = svc.list_amenities()
        names = [r["name"] for r in results]
        assert "WiFi A" in names
        assert "Pool B" in names

    def test_attach_amenity_happy_path(self):
        from app.services import hotel_pms as svc
        hotel = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        amenity = svc.create_amenity(name="WiFi", category="connectivity", user_sub=OWNER_SUB)
        result = svc.attach_amenity(
            target_type="hotel",
            target_id=hotel["hotel_id"],
            amenity_id=amenity["amenity_id"],
            user_sub=OWNER_SUB,
        )
        assert result["amenity_id"] == amenity["amenity_id"]
        assert result["target_type"] == "hotel"
        # Verify AMEN# row exists on hotels partition
        from app.core import tables as T_mod
        resp = T_mod.T.hotels.get_item(
            Key={"hotel_id": hotel["hotel_id"], "sk": f"AMEN#{amenity['amenity_id']}"}
        )
        assert resp.get("Item") is not None

    def test_attach_amenity_unknown_amenity(self):
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        hotel = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        with pytest.raises(HTTPException) as exc_info:
            svc.attach_amenity(
                target_type="hotel",
                target_id=hotel["hotel_id"],
                amenity_id="nonexistent-amenity",
                user_sub=OWNER_SUB,
            )
        assert exc_info.value.status_code == 404

    def test_attach_amenity_unknown_target(self):
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        amenity = svc.create_amenity(name="WiFi2", category="connectivity", user_sub=OWNER_SUB)
        with pytest.raises(HTTPException) as exc_info:
            svc.attach_amenity(
                target_type="hotel",
                target_id="nonexistent-hotel",
                amenity_id=amenity["amenity_id"],
                user_sub=OWNER_SUB,
            )
        assert exc_info.value.status_code == 404

    def test_attach_amenity_idempotent_re_attach(self):
        from app.services import hotel_pms as svc
        from app.core import tables as T_mod
        hotel = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        amenity = svc.create_amenity(name="Pool C", category="wellness", user_sub=OWNER_SUB)
        svc.attach_amenity(
            target_type="hotel", target_id=hotel["hotel_id"],
            amenity_id=amenity["amenity_id"], user_sub=OWNER_SUB,
        )
        svc.attach_amenity(
            target_type="hotel", target_id=hotel["hotel_id"],
            amenity_id=amenity["amenity_id"], user_sub=OWNER_SUB,
        )
        # Still only one AMEN# row
        resp = T_mod.T.hotels.query(
            KeyConditionExpression=(
                boto3.dynamodb.conditions.Key("hotel_id").eq(hotel["hotel_id"])
                & boto3.dynamodb.conditions.Key("sk").begins_with("AMEN#")
            )
        )
        assert len(resp["Items"]) == 1

    def test_detach_amenity_success(self):
        from app.services import hotel_pms as svc
        hotel = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        amenity = svc.create_amenity(name="Parking D", category="parking", user_sub=OWNER_SUB)
        svc.attach_amenity(
            target_type="hotel", target_id=hotel["hotel_id"],
            amenity_id=amenity["amenity_id"], user_sub=OWNER_SUB,
        )
        ok = svc.detach_amenity(
            target_type="hotel", target_id=hotel["hotel_id"],
            amenity_id=amenity["amenity_id"], user_sub=OWNER_SUB,
        )
        assert ok is True

    def test_detach_amenity_missing_no_raise(self):
        from app.services import hotel_pms as svc
        hotel = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        ok = svc.detach_amenity(
            target_type="hotel", target_id=hotel["hotel_id"],
            amenity_id="not-attached",
            user_sub=OWNER_SUB,
        )
        assert ok is False

    def test_list_amenities_for_hydration(self):
        from app.services import hotel_pms as svc
        hotel = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        a1 = svc.create_amenity(name="WiFi E", category="connectivity", user_sub=OWNER_SUB)
        a2 = svc.create_amenity(name="Spa E", category="wellness", user_sub=OWNER_SUB)
        svc.attach_amenity(
            target_type="hotel", target_id=hotel["hotel_id"],
            amenity_id=a1["amenity_id"], user_sub=OWNER_SUB,
        )
        svc.attach_amenity(
            target_type="hotel", target_id=hotel["hotel_id"],
            amenity_id=a2["amenity_id"], user_sub=OWNER_SUB,
        )
        rows = svc.list_amenities_for(target_type="hotel", target_id=hotel["hotel_id"])
        assert len(rows) == 2
        names = {r["name"] for r in rows}
        assert "WiFi E" in names
        assert "Spa E" in names
        # Must NOT include the META row
        for r in rows:
            assert r.get("sk") is None or "AMEN#" in r.get("sk", "AMEN#")

    def test_list_amenities_for_empty(self):
        from app.services import hotel_pms as svc
        hotel = svc.create_hotel(OWNER_SUB, **_BASE_HOTEL)
        rows = svc.list_amenities_for(target_type="hotel", target_id=hotel["hotel_id"])
        assert rows == []

    def test_room_type_forward_compat_model(self):
        """AmenityAttachIn accepts room_type at the model layer."""
        from app.models import AmenityAttachIn
        obj = AmenityAttachIn(
            target_type="room_type",
            target_id="some-room-type-id",
            amenity_id="some-amenity-id",
        )
        assert obj.target_type == "room_type"

    def test_room_type_raises_at_service(self):
        """room_type raises 422 at the service layer (no partition yet).
        Must use a real amenity so it passes the amenity-existence check first.
        """
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        # Create a real amenity so the first 404 check passes
        real_amenity = svc.create_amenity(
            name="Room Type Test Amenity", category="general", user_sub=OWNER_SUB
        )
        with pytest.raises(HTTPException) as exc_info:
            svc.attach_amenity(
                target_type="room_type",
                target_id="some-room",
                amenity_id=real_amenity["amenity_id"],
                user_sub=OWNER_SUB,
            )
        assert exc_info.value.status_code == 422

    def test_amenity_decimal_coercion(self):
        from app.services import hotel_pms as svc
        from app.core import tables as T_mod
        a = svc.create_amenity(name="Decimal Amenity", category="general", user_sub=OWNER_SUB)
        # Raw DDB
        raw = T_mod.T.hotel_amenities.get_item(
            Key={"amenity_id": a["amenity_id"], "sk": "META"}
        )["Item"]
        assert isinstance(raw["created_at"], Decimal)
        # Service coerces to int
        assert isinstance(a["created_at"], int)


# ===========================================================================
# list_hotels (pagination) tests
# ===========================================================================


class TestListHotels:

    def test_empty_portfolio(self):
        from app.services import hotel_pms as svc
        result = svc.list_hotels("nobody-sub")
        assert result["items"] == []
        assert result["count"] == 0
        assert result["cursor"] is None

    def test_basic_listing(self):
        from app.services import hotel_pms as svc
        svc.create_hotel(OWNER_SUB, name="Hotel A", star_rating=3, address=_BASE_ADDR)
        svc.create_hotel(OWNER_SUB, name="Hotel B", star_rating=4, address=_BASE_ADDR)
        svc.create_hotel(OWNER_SUB, name="Hotel C", star_rating=5, address=_BASE_ADDR)
        result = svc.list_hotels(OWNER_SUB)
        assert result["count"] == 3
        names = {h["name"] for h in result["items"]}
        assert {"Hotel A", "Hotel B", "Hotel C"}.issubset(names)

    def test_status_filter_active(self):
        from app.services import hotel_pms as svc
        h = svc.create_hotel(OWNER_SUB, name="Filter Hotel", star_rating=3, address=_BASE_ADDR)
        svc.archive_hotel(h["hotel_id"], user_sub=OWNER_SUB)
        result = svc.list_hotels(OWNER_SUB, status="active")
        hotel_ids = {h["hotel_id"] for h in result["items"]}
        assert h["hotel_id"] not in hotel_ids

    def test_status_filter_archived(self):
        from app.services import hotel_pms as svc
        h = svc.create_hotel(OWNER_SUB, name="Archived Hotel", star_rating=3, address=_BASE_ADDR)
        svc.archive_hotel(h["hotel_id"], user_sub=OWNER_SUB)
        result = svc.list_hotels(OWNER_SUB, status="archived")
        hotel_ids = {h["hotel_id"] for h in result["items"]}
        assert h["hotel_id"] in hotel_ids


# ===========================================================================
# Router route ordering test (HTL-003)
# ===========================================================================


class TestRouterOrdering:

    def test_amenities_route_before_hotel_id(self):
        """GET /amenities must be declared before GET /{hotel_id}."""
        from app.routers.hotels import hotels_router
        route_paths = [r.path for r in hotels_router.routes]
        # Find the index of the /amenities GET and the /{hotel_id} GET
        amenities_idx = next(
            (i for i, r in enumerate(hotels_router.routes)
             if hasattr(r, "path") and r.path == "/ui/hotels/amenities"
             and "GET" in getattr(r, "methods", set())),
            None,
        )
        hotel_id_idx = next(
            (i for i, r in enumerate(hotels_router.routes)
             if hasattr(r, "path") and r.path == "/ui/hotels/{hotel_id}"
             and "GET" in getattr(r, "methods", set())),
            None,
        )
        assert amenities_idx is not None, "GET /amenities route not found"
        assert hotel_id_idx is not None, "GET /{hotel_id} route not found"
        assert amenities_idx < hotel_id_idx, (
            f"GET /amenities (idx {amenities_idx}) must be declared before "
            f"GET /{{hotel_id}} (idx {hotel_id_idx})"
        )


# ===========================================================================
# Router handler tests (called directly, no TestClient)
# ===========================================================================


class TestRouterHandlers:

    def test_list_hotels_handler_flag_off(self):
        from fastapi import HTTPException
        from app.services import hotel_pms as svc
        from app.routers.hotels import list_hotels_endpoint
        object.__setattr__(svc.S, "hotel_pms_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                _run(list_hotels_endpoint(session=MOCK_SESSION))
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(svc.S, "hotel_pms_enabled", True)

    def test_get_hotel_handler_not_found(self):
        from fastapi import HTTPException
        from app.routers.hotels import get_hotel_endpoint
        with pytest.raises(HTTPException) as exc_info:
            _run(get_hotel_endpoint(hotel_id="nope", session=MOCK_SESSION))
        assert exc_info.value.status_code == 404

    def test_list_hotels_handler_valid_status_filter(self):
        from app.services import hotel_pms as svc
        from app.routers.hotels import list_hotels_endpoint
        svc.create_hotel(OWNER_SUB, name="Router Hotel", star_rating=3, address=_BASE_ADDR)
        result = _run(list_hotels_endpoint(status="active", session=MOCK_SESSION))
        assert "items" in result

    def test_list_hotels_handler_invalid_status(self):
        from fastapi import HTTPException
        from app.routers.hotels import list_hotels_endpoint
        with pytest.raises(HTTPException) as exc_info:
            _run(list_hotels_endpoint(status="badstatus", session=MOCK_SESSION))
        assert exc_info.value.status_code == 422

    def test_create_hotel_handler(self):
        from app.models import HotelIn
        from app.routers.hotels import create_hotel_endpoint
        body = HotelIn(name="Handler Hotel", star_rating=3, address=_BASE_ADDR)
        result = _run(create_hotel_endpoint(body=body, user=_admin_user()))
        assert result.hotel_id
        assert result.status == "active"

    def test_list_amenities_handler(self):
        from app.services import hotel_pms as svc
        from app.routers.hotels import list_amenities_endpoint
        svc.create_amenity(name="Handler WiFi", category="connectivity", user_sub=OWNER_SUB)
        results = _run(list_amenities_endpoint(session=MOCK_SESSION))
        assert any(a.name == "Handler WiFi" for a in results)

    def test_detach_amenity_handler_returns_ok_false(self):
        from app.services import hotel_pms as svc
        from app.models import AmenityAttachIn
        from app.routers.hotels import detach_amenity_endpoint
        hotel = svc.create_hotel(OWNER_SUB, name="Detach Handler Hotel", star_rating=3, address=_BASE_ADDR)
        body = AmenityAttachIn(target_type="hotel", target_id=hotel["hotel_id"], amenity_id="fake")
        result = _run(detach_amenity_endpoint(body=body, user=_admin_user()))
        assert result == {"ok": False}
