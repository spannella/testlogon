"""
tests/test_htl_025_026_027_booking_engine.py

Hermetic offline pytest for the QloApps Booking-Engine Storefront:
  HTL-025  — hotel_storefront.public_get_hotel / public_list_room_types
  HTL-026  — hotel_storefront.quote_stay
  HTL-027  — hotel_storefront.create_booking_cart / add_room_to_cart /
              set_guest_details / get_booking_cart / checkout_booking_cart
  Router   — booking_engine.py handlers on a fresh asyncio event loop

Pattern: moto-backed hotels + shopping_cart tables bound to frozen T via
object.__setattr__ (same recipe as test_gap_0265_0266_kyc_risk_scoring.py).
Forward-dep collaborators patched at the hotel_storefront module namespace
(KYC GAP-0262 idiom).
No TestClient; async handlers invoked on asyncio.new_event_loop().
"""

from __future__ import annotations

import asyncio
import sys
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import boto3
import pytest
from fastapi import HTTPException
from moto import mock_aws


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _run(coro: Any) -> Any:
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _fake_request(ip: str = "203.0.113.7") -> Any:
    return SimpleNamespace(client=SimpleNamespace(host=ip))


# ---------------------------------------------------------------------------
# Fixture — scope=module autouse (NOT session); saves/restores T+S mutations
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True, scope="module")
def _setup_moto_tables():
    """Create moto-backed hotels + shopping_cart tables, bind to frozen T, enable flag."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")

        # ---- hotels table (HTL-001 / HTL-005 schema) ----
        hotels_table = ddb.create_table(
            TableName="hotels",
            KeySchema=[
                {"AttributeName": "hotel_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "hotel_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "GSI_HOTEL_ROOMTYPES",
                "KeySchema": [
                    {"AttributeName": "hotel_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST",
        )

        # ---- shopping_cart table ----
        cart_table = ddb.create_table(
            TableName="shopping_cart",
            KeySchema=[
                {"AttributeName": "PK", "KeyType": "HASH"},
                {"AttributeName": "SK", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "PK", "AttributeType": "S"},
                {"AttributeName": "SK", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # ---- sessions table for rate-limit bucket ----
        sessions_table = ddb.create_table(
            TableName="sessions",
            KeySchema=[
                {"AttributeName": "user_sub", "KeyType": "HASH"},
                {"AttributeName": "session_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "user_sub", "AttributeType": "S"},
                {"AttributeName": "session_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # ---- Seed hotels ----
        # h1: published (active)
        hotels_table.put_item(Item={
            "hotel_id": "h1", "sk": "META",
            "owner_sub": "owner1", "name": "Grand Plaza",
            "description": "Downtown hotel", "star_rating": Decimal("4"),
            "address": {
                "line1": "1 Main St", "city": "Metropolis",
                "region": "NY", "postal_code": "10001", "country": "US",
            },
            "check_in_time": "15:00", "check_out_time": "11:00",
            "policies": {
                "cancellation_text": "24h", "pet_policy": "no",
                "smoking": False, "children": True,
            },
            "contact": {"phone": "555-1", "email": "h@x.com", "website": ""},
            "photo_urls": ["p1", "p2"],
            "status": "active",
            "created_at": Decimal("1000"), "updated_at": Decimal("1000"),
        })
        # h2: archived (must NOT be publicly visible)
        hotels_table.put_item(Item={
            "hotel_id": "h2", "sk": "META",
            "owner_sub": "owner1", "name": "Closed Inn",
            "star_rating": Decimal("2"), "status": "archived",
            "address": {"line1": "x", "city": "x", "region": "x",
                        "postal_code": "x", "country": "x"},
            "policies": {}, "contact": {}, "photo_urls": [],
            "created_at": Decimal("900"), "updated_at": Decimal("900"),
        })
        # rt1: published room type under h1
        hotels_table.put_item(Item={
            "hotel_id": "h1", "sk": "ROOMTYPE#rt1",
            "room_type_id": "rt1", "name": "Deluxe King", "description": "",
            "base_occupancy_adults": Decimal("2"),
            "base_occupancy_children": Decimal("1"),
            "max_occupancy": Decimal("3"),
            "bed_type": "king",
            "size_sqft": Decimal("320"),
            "base_nightly_rate_cents": Decimal("19900"),
            "photo_urls": ["r1"], "status": "active",
            "created_at": Decimal("1100"), "updated_at": Decimal("1100"),
        })
        # rt2: archived room type under h1 (must NOT appear)
        hotels_table.put_item(Item={
            "hotel_id": "h1", "sk": "ROOMTYPE#rt2",
            "room_type_id": "rt2", "name": "Old Standard", "description": "",
            "base_occupancy_adults": Decimal("2"),
            "base_occupancy_children": Decimal("0"),
            "max_occupancy": Decimal("2"),
            "bed_type": "double",
            "size_sqft": Decimal("200"),
            "base_nightly_rate_cents": Decimal("9900"),
            "photo_urls": [], "status": "archived",
            "created_at": Decimal("1050"), "updated_at": Decimal("1050"),
        })

        # ---- Bind to frozen T + S ----
        import app.core.tables as T_mod
        import app.services.hotel_storefront as hs
        import app.core.settings as S_mod

        _orig_T_hotels = T_mod.T.hotels
        _orig_T_cart = T_mod.T.shopping_cart
        _orig_T_sessions = T_mod.T.sessions
        _orig_S_pms = S_mod.S.hotel_pms_enabled
        _orig_S_rl_max = getattr(S_mod.S, "hotel_booking_search_rl_max", 60)
        _orig_S_rl_win = getattr(S_mod.S, "hotel_booking_search_rl_window", 3600)
        _orig_S_los = getattr(S_mod.S, "hotel_booking_search_max_los_nights", 30)
        _orig_S_ddb_sessions = getattr(S_mod.S, "ddb_sessions_table", "sessions")

        object.__setattr__(T_mod.T, "hotels", hotels_table)
        object.__setattr__(T_mod.T, "shopping_cart", cart_table)
        object.__setattr__(T_mod.T, "sessions", sessions_table)
        object.__setattr__(S_mod.S, "hotel_pms_enabled", True)
        object.__setattr__(S_mod.S, "hotel_booking_search_rl_max", 2)
        object.__setattr__(S_mod.S, "hotel_booking_search_rl_window", 3600)
        object.__setattr__(S_mod.S, "hotel_booking_search_max_los_nights", 30)
        object.__setattr__(S_mod.S, "ddb_sessions_table", "sessions")

        yield {
            "hotels": hotels_table,
            "cart": cart_table,
            "sessions": sessions_table,
            "hs": hs,
            "T": T_mod.T,
            "S": S_mod.S,
        }

        # ---- Restore ----
        object.__setattr__(T_mod.T, "hotels", _orig_T_hotels)
        object.__setattr__(T_mod.T, "shopping_cart", _orig_T_cart)
        object.__setattr__(T_mod.T, "sessions", _orig_T_sessions)
        object.__setattr__(S_mod.S, "hotel_pms_enabled", _orig_S_pms)
        object.__setattr__(S_mod.S, "hotel_booking_search_rl_max", _orig_S_rl_max)
        object.__setattr__(S_mod.S, "hotel_booking_search_rl_window", _orig_S_rl_win)
        object.__setattr__(S_mod.S, "hotel_booking_search_max_los_nights", _orig_S_los)
        object.__setattr__(S_mod.S, "ddb_sessions_table", _orig_S_ddb_sessions)


# ---------------------------------------------------------------------------
# Helper to reset flag between tests
# ---------------------------------------------------------------------------

def _set_flag(val: bool) -> None:
    import app.core.settings as S_mod
    object.__setattr__(S_mod.S, "hotel_pms_enabled", val)


# ============================================================================
# HTL-025 — public_get_hotel
# ============================================================================

class TestPublicGetHotel:
    def test_flag_off_404(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        _set_flag(False)
        try:
            with pytest.raises(HTTPException) as exc:
                hs.public_get_hotel("h1")
            assert exc.value.status_code == 404
        finally:
            _set_flag(True)

    def test_published_hit(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        result = hs.public_get_hotel("h1")
        assert result["hotel_id"] == "h1"
        assert result["name"] == "Grand Plaza"
        assert result["star_rating"] == 4
        assert result["photos"] == ["p1", "p2"]

    def test_address_roundtrips(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        result = hs.public_get_hotel("h1")
        assert result["address"]["city"] == "Metropolis"
        assert result["address"]["country"] == "US"

    def test_archived_404(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        with pytest.raises(HTTPException) as exc:
            hs.public_get_hotel("h2")
        assert exc.value.status_code == 404

    def test_nonexistent_404(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        with pytest.raises(HTTPException) as exc:
            hs.public_get_hotel("does_not_exist")
        assert exc.value.status_code == 404

    def test_no_leak_internal_fields(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        result = hs.public_get_hotel("h1")
        forbidden = {"owner_sub", "status", "created_at", "updated_at", "sk"}
        for field in forbidden:
            assert field not in result, f"Field {field!r} must not leak"

    def test_photos_maps_from_photo_urls(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        result = hs.public_get_hotel("h1")
        assert "photos" in result
        assert "photo_urls" not in result
        assert result["photos"] == ["p1", "p2"]

    def test_star_rating_is_int(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        result = hs.public_get_hotel("h1")
        assert isinstance(result["star_rating"], int)
        assert result["star_rating"] == 4

    def test_amenities_best_effort_empty(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        # With no HTL-002, amenities should default to []
        result = hs.public_get_hotel("h1")
        assert result["amenities"] == []


# ============================================================================
# HTL-025 — public_list_room_types
# ============================================================================

class TestPublicListRoomTypes:
    def test_flag_off_404(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        _set_flag(False)
        try:
            with pytest.raises(HTTPException) as exc:
                hs.public_list_room_types("h1")
            assert exc.value.status_code == 404
        finally:
            _set_flag(True)

    def test_returns_only_published(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        result = hs.public_list_room_types("h1")
        assert result["count"] == 1
        assert len(result["room_types"]) == 1
        assert result["room_types"][0]["room_type_id"] == "rt1"

    def test_field_mapping(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        result = hs.public_list_room_types("h1")
        rt = result["room_types"][0]
        assert rt["occupancy_adults"] == 2
        assert rt["occupancy_children"] == 1
        assert rt["max_occupancy"] == 3
        assert rt["base_rate_cents"] == 19900
        assert rt["bed_type"] == "king"
        assert rt["photos"] == ["r1"]

    def test_no_leak_room_type_fields(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        result = hs.public_list_room_types("h1")
        rt = result["room_types"][0]
        forbidden = {"status", "created_at", "updated_at", "base_nightly_rate_cents",
                     "base_occupancy_adults", "base_occupancy_children", "owner_sub"}
        for field in forbidden:
            assert field not in rt, f"Field {field!r} must not leak from room type"

    def test_archived_hotel_404(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        with pytest.raises(HTTPException) as exc:
            hs.public_list_room_types("h2")
        assert exc.value.status_code == 404

    def test_nonexistent_hotel_404(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        with pytest.raises(HTTPException) as exc:
            hs.public_list_room_types("no_such_hotel")
        assert exc.value.status_code == 404

    def test_published_hotel_zero_published_room_types(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        import app.core.tables as T_mod
        # Temporarily archive rt1
        T_mod.T.hotels.update_item(
            Key={"hotel_id": "h1", "sk": "ROOMTYPE#rt1"},
            UpdateExpression="SET #s = :v",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":v": "archived"},
        )
        try:
            result = hs.public_list_room_types("h1")
            assert result["count"] == 0
            assert result["room_types"] == []
        finally:
            T_mod.T.hotels.update_item(
                Key={"hotel_id": "h1", "sk": "ROOMTYPE#rt1"},
                UpdateExpression="SET #s = :v",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":v": "active"},
            )

    def test_decimal_coercion(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        import app.core.tables as T_mod
        raw = T_mod.T.hotels.get_item(Key={"hotel_id": "h1", "sk": "ROOMTYPE#rt1"}).get("Item")
        assert isinstance(raw["base_nightly_rate_cents"], Decimal)
        result = hs.public_list_room_types("h1")
        rt = result["room_types"][0]
        assert isinstance(rt["base_rate_cents"], int)
        assert isinstance(rt["occupancy_adults"], int)


# ============================================================================
# _is_published predicate
# ============================================================================

class TestIsPublished:
    def test_active_true(self) -> None:
        from app.services.hotel_storefront import _is_published
        assert _is_published({"status": "active"}) is True

    def test_archived_false(self) -> None:
        from app.services.hotel_storefront import _is_published
        assert _is_published({"status": "archived"}) is False

    def test_draft_false(self) -> None:
        from app.services.hotel_storefront import _is_published
        assert _is_published({"status": "draft"}) is False

    def test_published_true_flag(self) -> None:
        from app.services.hotel_storefront import _is_published
        assert _is_published({"published": True}) is True

    def test_published_false_flag(self) -> None:
        from app.services.hotel_storefront import _is_published
        assert _is_published({"published": False}) is False

    def test_none_false(self) -> None:
        from app.services.hotel_storefront import _is_published
        assert _is_published(None) is False


# ============================================================================
# HTL-026 — quote_stay (service-level; collaborators patched)
# ============================================================================

class TestQuoteStay:
    def _engine_result(self, items: Any) -> Any:
        results = [SimpleNamespace(
            hotel_id="h1", room_type_id=rid, name=f"RT {rid}", available=True,
            min_remaining=3, rooms=1, per_night=[], total_cents=tc,
            currency="usd", applied_rule_ids=[],
        ) for rid, tc in items]
        return SimpleNamespace(
            checkin="2026-07-01", checkout="2026-07-04", nights=3,
            adults=2, children=0, rooms=1,
            results=results, result_count=len(results),
        )

    def test_flag_off_404(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        _set_flag(False)
        try:
            with pytest.raises(HTTPException) as exc:
                hs.quote_stay(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-04", adults=2)
            assert exc.value.status_code == 404
        finally:
            _set_flag(True)

    def test_unpublished_hotel_404(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        with patch.object(hs, "public_get_hotel", side_effect=HTTPException(404)):
            with patch.object(hs, "search_stays", MagicMock()) as mock_ss:
                with pytest.raises(HTTPException) as exc:
                    hs.quote_stay(hotel_id="h_no", checkin="2026-07-01", checkout="2026-07-04", adults=2)
                assert exc.value.status_code == 404
                mock_ss.assert_not_called()

    def test_checkout_before_checkin_400(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
            with pytest.raises(HTTPException) as exc:
                hs.quote_stay(hotel_id="h1", checkin="2026-07-04", checkout="2026-07-01", adults=2)
            assert exc.value.status_code == 400
            assert "after checkin" in exc.value.detail

    def test_malformed_date_400(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
            with pytest.raises(HTTPException) as exc:
                hs.quote_stay(hotel_id="h1", checkin="2026-7-1", checkout="2026-07-04", adults=2)
            assert exc.value.status_code == 400

    def test_span_exceeds_max_los_400(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        import app.core.settings as S_mod
        object.__setattr__(S_mod.S, "hotel_booking_search_max_los_nights", 2)
        try:
            with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
                with pytest.raises(HTTPException) as exc:
                    hs.quote_stay(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-04", adults=2)
                assert exc.value.status_code == 400
                assert "maximum" in exc.value.detail
        finally:
            object.__setattr__(S_mod.S, "hotel_booking_search_max_los_nights", 30)

    def test_publication_before_span(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        # Unpublished hotel + malformed span → 404 (publication fires first)
        with patch.object(hs, "public_get_hotel", side_effect=HTTPException(404)):
            with pytest.raises(HTTPException) as exc:
                hs.quote_stay(hotel_id="h_no", checkin="bad", checkout="2026-07-01", adults=2)
            assert exc.value.status_code == 404

    def test_happy_path_projection(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        engine_res = self._engine_result([("rt_a", 30000)])
        with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
            with patch.object(hs, "search_stays", return_value=engine_res):
                result = hs.quote_stay(
                    hotel_id="h1", checkin="2026-07-01", checkout="2026-07-04", adults=2,
                )
        assert result["nights"] == 3
        assert len(result["results"]) == 1
        assert result["results"][0]["total_price_cents"] == 30000
        assert result["results"][0]["available_rooms"] == 3
        assert result["results"][0]["currency"] == "usd"
        assert result["results"][0]["room_type"]["room_type_id"] == "rt_a"

    def test_total_price_cents_copied_verbatim(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        engine_res = self._engine_result([("rt_x", 77777)])
        with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
            with patch.object(hs, "search_stays", return_value=engine_res):
                result = hs.quote_stay(
                    hotel_id="h1", checkin="2026-07-01", checkout="2026-07-04", adults=2,
                )
        assert result["results"][0]["total_price_cents"] == 77777

    def test_cheapest_first_ordering_preserved(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        engine_res = self._engine_result([("rt_x", 10000), ("rt_y", 15000)])
        with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
            with patch.object(hs, "search_stays", return_value=engine_res):
                result = hs.quote_stay(
                    hotel_id="h1", checkin="2026-07-01", checkout="2026-07-04", adults=2,
                )
        prices = [r["total_price_cents"] for r in result["results"]]
        assert prices == [10000, 15000]

    def test_empty_availability_no_error(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        engine_res = self._engine_result([])
        with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
            with patch.object(hs, "search_stays", return_value=engine_res):
                result = hs.quote_stay(
                    hotel_id="h1", checkin="2026-07-01", checkout="2026-07-04", adults=2,
                )
        assert result["results"] == []
        assert result["currency"] == "usd"

    def test_hotel_id_passed_not_city(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        engine_res = self._engine_result([])
        mock_ss = MagicMock(return_value=engine_res)
        with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
            with patch.object(hs, "search_stays", mock_ss):
                hs.quote_stay(
                    hotel_id="h1", checkin="2026-07-01", checkout="2026-07-04", adults=2,
                )
        call_kwargs = mock_ss.call_args[1]
        assert "hotel_id" in call_kwargs
        assert "city" not in call_kwargs

    def test_no_audit_emitted_on_quote(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        engine_res = self._engine_result([])
        audit_mock = MagicMock()
        with patch.object(hs, "_audit", audit_mock):
            with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
                with patch.object(hs, "search_stays", return_value=engine_res):
                    hs.quote_stay(
                        hotel_id="h1", checkin="2026-07-01", checkout="2026-07-04", adults=2,
                    )
        # quote_stay itself emits no audit (reads only)
        audit_mock.assert_not_called()


# ============================================================================
# HTL-026 — Router handler booking_engine_search (async, fresh loop)
# ============================================================================

class TestBookingEngineSearchHandler:
    def _engine_result(self) -> Any:
        return SimpleNamespace(
            checkin="2026-07-01", checkout="2026-07-04", nights=3,
            adults=2, children=0, rooms=1,
            results=[], result_count=0,
        )

    def test_handler_flag_off_404(self, _setup_moto_tables: Any) -> None:
        from app.routers.booking_engine import booking_engine_search
        _set_flag(False)
        try:
            with patch("app.services.hotel_storefront.search_stays", return_value=self._engine_result()):
                with pytest.raises(HTTPException) as exc:
                    _run(booking_engine_search(
                        _fake_request(), hotel="h1",
                        checkin="2026-07-01", checkout="2026-07-04",
                        adults=2, children=0, rooms=1,
                    ))
            assert exc.value.status_code == 404
        finally:
            _set_flag(True)

    def test_handler_rate_limit_429(self, _setup_moto_tables: Any) -> None:
        from app.routers.booking_engine import booking_engine_search
        import app.core.settings as S_mod
        object.__setattr__(S_mod.S, "hotel_booking_search_rl_max", 0)
        try:
            with pytest.raises(HTTPException) as exc:
                _run(booking_engine_search(
                    _fake_request(ip="10.0.0.1"), hotel="h1",
                    checkin="2026-07-01", checkout="2026-07-04",
                    adults=2, children=0, rooms=1,
                ))
            assert exc.value.status_code == 429
        finally:
            object.__setattr__(S_mod.S, "hotel_booking_search_rl_max", 2)

    def test_handler_happy_path(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        from app.routers.booking_engine import booking_engine_search
        engine_res = SimpleNamespace(
            checkin="2026-07-01", checkout="2026-07-04", nights=3,
            adults=2, children=0, rooms=1,
            results=[], result_count=0,
        )
        with patch.object(hs, "public_get_hotel", return_value={"hotel_id": "h1"}):
            with patch.object(hs, "search_stays", return_value=engine_res):
                result = _run(booking_engine_search(
                    _fake_request(), hotel="h1",
                    checkin="2026-07-01", checkout="2026-07-04",
                    adults=2, children=0, rooms=1,
                ))
        assert result.hotel_id == "h1"
        assert result.nights == 3
        assert result.results == []


# ============================================================================
# HTL-027 — Booking cart service (create + add + guest + get + checkout)
# ============================================================================

class TestBookingCart:
    def test_create_booking_cart(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        result = hs.create_booking_cart(hotel_id="h1")
        assert "booking_cart_id" in result
        assert result["hotel_id"] == "h1"
        assert result["status"] == "OPEN"
        assert result["total_cents"] == 0
        assert result["lines"] == []

    def test_create_booking_cart_flag_off(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        _set_flag(False)
        try:
            with pytest.raises(HTTPException) as exc:
                hs.create_booking_cart(hotel_id="h1")
            assert exc.value.status_code == 404
        finally:
            _set_flag(True)

    def test_create_booking_cart_unpublished_hotel(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        with pytest.raises(HTTPException) as exc:
            hs.create_booking_cart(hotel_id="h2")
        assert exc.value.status_code == 404

    def test_get_booking_cart(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        created = hs.create_booking_cart(hotel_id="h1")
        cart_id = created["booking_cart_id"]
        fetched = hs.get_booking_cart(cart_id)
        assert fetched["booking_cart_id"] == cart_id
        assert fetched["hotel_id"] == "h1"

    def test_get_booking_cart_not_found(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        with pytest.raises(HTTPException) as exc:
            hs.get_booking_cart("nonexistent_cart_id_abc123")
        assert exc.value.status_code == 404

    def test_set_guest_details(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        created = hs.create_booking_cart(hotel_id="h1")
        cart_id = created["booking_cart_id"]
        result = hs.set_guest_details(
            booking_cart_id=cart_id,
            name="Alice Smith",
            email="alice@example.com",
            phone="555-1234",
        )
        assert result["guest"] is not None
        assert result["guest"]["name"] == "Alice Smith"
        assert result["guest"]["email"] == "alice@example.com"

    def test_guest_party_id_deterministic(self, _setup_moto_tables: Any) -> None:
        from app.services.hotel_storefront import _guest_party_id
        gid1 = _guest_party_id("ALICE@EXAMPLE.COM")
        gid2 = _guest_party_id("alice@example.com")
        assert gid1 == gid2
        assert gid1.startswith("guest_")
        assert len(gid1) == 6 + 24  # "guest_" + 24 hex chars

    def test_add_room_to_cart(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        created = hs.create_booking_cart(hotel_id="h1")
        cart_id = created["booking_cart_id"]
        # Patch quote_stay to return availability for rt1
        fake_quote = {
            "hotel_id": "h1", "checkin": "2026-07-01", "checkout": "2026-07-04",
            "nights": 3, "adults": 2, "children": 0, "rooms": 1,
            "results": [{
                "room_type": {"room_type_id": "rt1", "name": "Deluxe King",
                              "description": "", "occupancy_adults": 2,
                              "occupancy_children": 1, "max_occupancy": 3,
                              "bed_type": "king", "size_sqft": 320,
                              "amenities": [], "photos": [], "base_rate_cents": 19900,
                              "currency": "usd"},
                "available_rooms": 5,
                "per_night": [],
                "total_price_cents": 59700,
                "currency": "usd",
            }],
            "currency": "usd",
        }
        with patch.object(hs, "quote_stay", return_value=fake_quote):
            result = hs.add_room_to_cart(
                booking_cart_id=cart_id,
                hotel_id="h1",
                room_type_id="rt1",
                checkin="2026-07-01",
                checkout="2026-07-04",
                adults=2,
            )
        assert len(result["lines"]) == 1
        assert result["lines"][0]["room_type_id"] == "rt1"
        assert result["lines"][0]["unit_price_cents"] == 59700
        assert result["total_cents"] == 59700

    def test_add_room_no_availability_409(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        created = hs.create_booking_cart(hotel_id="h1")
        cart_id = created["booking_cart_id"]
        fake_quote = {
            "hotel_id": "h1", "checkin": "2026-07-01", "checkout": "2026-07-04",
            "nights": 3, "adults": 2, "children": 0, "rooms": 1,
            "results": [],  # no results
            "currency": "usd",
        }
        with patch.object(hs, "quote_stay", return_value=fake_quote):
            with pytest.raises(HTTPException) as exc:
                hs.add_room_to_cart(
                    booking_cart_id=cart_id,
                    hotel_id="h1",
                    room_type_id="rt_no",
                    checkin="2026-07-01",
                    checkout="2026-07-04",
                )
        assert exc.value.status_code == 409

    def test_checkout_requires_guest(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        created = hs.create_booking_cart(hotel_id="h1")
        cart_id = created["booking_cart_id"]
        with pytest.raises(HTTPException) as exc:
            hs.checkout_booking_cart(booking_cart_id=cart_id)
        assert exc.value.status_code == 422
        assert "guest_required" in str(exc.value.detail)

    def test_checkout_requires_lines(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        created = hs.create_booking_cart(hotel_id="h1")
        cart_id = created["booking_cart_id"]
        # Set guest first
        hs.set_guest_details(
            booking_cart_id=cart_id,
            name="Bob", email="bob@example.com", phone="555-9999",
        )
        with pytest.raises(HTTPException) as exc:
            hs.checkout_booking_cart(booking_cart_id=cart_id)
        assert exc.value.status_code == 422
        assert "empty_cart" in str(exc.value.detail)

    def test_checkout_idempotent_purchased(self, _setup_moto_tables: Any) -> None:
        """A retry against a PURCHASED cart returns stored result without second charge."""
        import app.services.hotel_storefront as hs
        import app.core.tables as T_mod
        created = hs.create_booking_cart(hotel_id="h1")
        cart_id = created["booking_cart_id"]
        owner = hs._booking_owner_sub(cart_id)
        # Manually set cart to PURCHASED with pre-stored result
        T_mod.T.shopping_cart.update_item(
            Key={"PK": f"USER#{owner}", "SK": f"CART#{cart_id}"},
            UpdateExpression="SET #st = :s, guest_party_id = :gp, reservation_ids = :rids, last_order_id = :oid",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":s": "PURCHASED",
                ":gp": "guest_abc123",
                ":rids": ["res_111"],
                ":oid": "ord_999",
            },
        )
        # Patch list_items to return a fake line (needed for empty_cart check)
        # Write a fake line item directly to DDB so _list_booking_lines finds it
        import app.core.tables as T_mod
        owner = hs._booking_owner_sub(cart_id)
        sku = "ROOMNIGHT#rt1#2026-07-01_2026-07-04"
        T_mod.T.shopping_cart.put_item(Item={
            "PK": f"USER#{owner}",
            "SK": f"CART#{cart_id}#ITEM#{sku}",
            "type": "item",
            "cart_id": cart_id,
            "sku": sku,
            "name": "Deluxe King — 2026-07-01→2026-07-04 (3n)",
            "quantity": 1,
            "unit_price_cents": 59700,
            "line_total_cents": 59700,
            "booking_meta": {
                "room_type_id": "rt1", "checkin": "2026-07-01",
                "checkout": "2026-07-04", "adults": 2, "children": 0, "rooms": 1,
                "nights": 3, "currency": "usd",
            },
        })
        result = hs.checkout_booking_cart(booking_cart_id=cart_id)
        assert result["reservation_ids"] == ["res_111"]
        assert result["order_id"] == "ord_999"

    def test_booking_owner_sub(self) -> None:
        from app.services.hotel_storefront import _booking_owner_sub
        s = _booking_owner_sub("abc123")
        assert s == "booking_guest:abc123"


# ============================================================================
# HTL-027 Router handlers (async, fresh loop)
# ============================================================================

class TestBookingEngineCartHandlers:
    def test_router_create_cart(self, _setup_moto_tables: Any) -> None:
        from app.routers.booking_engine import booking_engine_create_cart
        result = _run(booking_engine_create_cart(
            request=_fake_request(),
            hotel_id="h1",
        ))
        assert result.hotel_id == "h1"
        assert result.status == "OPEN"

    def test_router_create_cart_flag_off(self, _setup_moto_tables: Any) -> None:
        from app.routers.booking_engine import booking_engine_create_cart
        _set_flag(False)
        try:
            with pytest.raises(HTTPException) as exc:
                _run(booking_engine_create_cart(
                    request=_fake_request(),
                    hotel_id="h1",
                ))
            assert exc.value.status_code == 404
        finally:
            _set_flag(True)

    def test_router_get_cart(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        from app.routers.booking_engine import booking_engine_get_cart
        created = hs.create_booking_cart(hotel_id="h1")
        cart_id = created["booking_cart_id"]
        result = _run(booking_engine_get_cart(booking_cart_id=cart_id))
        assert result.booking_cart_id == cart_id

    def test_router_set_guest(self, _setup_moto_tables: Any) -> None:
        import app.services.hotel_storefront as hs
        from app.routers.booking_engine import booking_engine_set_guest
        from app.models import GuestDetailsIn
        created = hs.create_booking_cart(hotel_id="h1")
        cart_id = created["booking_cart_id"]
        result = _run(booking_engine_set_guest(
            request=_fake_request(),
            booking_cart_id=cart_id,
            body=GuestDetailsIn(name="Test Guest", email="guest@test.com", phone="555-0000"),
        ))
        assert result.guest is not None
        assert result.guest.name == "Test Guest"

    def test_router_get_hotel(self, _setup_moto_tables: Any) -> None:
        from app.routers.booking_engine import booking_engine_get_hotel
        result = _run(booking_engine_get_hotel(hotel_id="h1"))
        assert result.hotel_id == "h1"
        assert result.name == "Grand Plaza"

    def test_router_get_hotel_archived_404(self, _setup_moto_tables: Any) -> None:
        from app.routers.booking_engine import booking_engine_get_hotel
        with pytest.raises(HTTPException) as exc:
            _run(booking_engine_get_hotel(hotel_id="h2"))
        assert exc.value.status_code == 404

    def test_router_list_room_types(self, _setup_moto_tables: Any) -> None:
        from app.routers.booking_engine import booking_engine_list_room_types
        result = _run(booking_engine_list_room_types(hotel_id="h1"))
        assert result.count == 1
        assert result.room_types[0].room_type_id == "rt1"

    def test_secops007_no_dev_mode(self) -> None:
        """Verify no S.dev_mode references exist in hotel_storefront service code."""
        import inspect
        import re
        import app.services.hotel_storefront as hs
        src = inspect.getsource(hs)
        # Remove docstrings and comments before scanning
        # Remove triple-quoted docstrings
        no_docs = re.sub(r'""".*?"""', '', src, flags=re.DOTALL)
        no_docs = re.sub(r"'''.*?'''", '', no_docs, flags=re.DOTALL)
        # Remove comment lines
        no_comments = re.sub(r'#[^\n]*', '', no_docs)
        matches = re.findall(r'S\.dev_mode', no_comments)
        assert matches == [], f"hotel_storefront.py must not reference S.dev_mode in code; found: {matches}"
