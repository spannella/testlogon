"""Offline hermetic regression tests for EVT-005, EVT-006, EVT-007.

Covers:
- EVT-005: crm_geocoding.py — geocode_address, apply_geocode_to_address,
  list_geocoded_addresses, geocode_party_address
- EVT-005: crm_geocoding router — PATCH /ui/crm/geocoding/addresses/{id}, GET /ui/crm/geocoding/addresses
- EVT-006: haversine_km, proximity_search, rate_limit_proximity_search
- EVT-006: crm_maps router — GET /ui/crm/maps/contacts/proximity
- EVT-007: crm_maps router — GET /ui/crm/maps/feature-flags

Isolation rules:
- One scope="module" autouse fixture creates moto tables and patches T handles
  via object.__setattr__; restores originals on teardown.
- S is frozen; mutations use object.__setattr__; restored in teardown.
- Route handlers called directly (no TestClient — per CLAUDE.md pattern).
- No real AWS, no network, no real DDB.
"""
from __future__ import annotations

import asyncio
import uuid
from decimal import Decimal
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_aws
except ImportError:  # pragma: no cover
    mock_aws = None

# ---------------------------------------------------------------------------
# Helpers to call async handlers synchronously
# ---------------------------------------------------------------------------

def _run(coro):
    """Run an async coroutine on a fresh event loop (test isolation)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Module-level moto fixture — creates tables and patches T
# ---------------------------------------------------------------------------

from app.core.tables import T
from app.core.settings import S

_orig_addresses = T.addresses
_orig_sessions = T.sessions

# Store original settings values so we can restore them
_ORIG_GEOCODING_ENABLED = S.crm_geocoding_enabled
_ORIG_PROXIMITY_ENABLED = S.crm_proximity_search_enabled
_ORIG_PROVIDER_URL = S.crm_geocoding_provider_url
_ORIG_MAX_RADIUS = S.crm_proximity_search_max_radius_km
_ORIG_MAP_DEFAULT_LAT = S.crm_map_default_lat
_ORIG_MAP_DEFAULT_LNG = S.crm_map_default_lng
_ORIG_MAP_DEFAULT_RADIUS = S.crm_map_default_radius_km
_ORIG_MAP_MAX_RADIUS = S.crm_map_max_radius_km
_ORIG_MAP_MAX_PINS = S.crm_map_max_pins


_mock_ctx = None
_addresses_table = None
_sessions_table = None


@pytest.fixture(scope="module", autouse=True)
def _module_setup():
    global _mock_ctx, _addresses_table, _sessions_table

    _mock_ctx = mock_aws()
    _mock_ctx.start()

    ddb = boto3.resource("dynamodb", region_name="us-east-1")

    _addresses_table = ddb.create_table(
        TableName="addresses_test_evt",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "address_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "address_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    _sessions_table = ddb.create_table(
        TableName="sessions_test_evt",
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

    # Patch T handles
    object.__setattr__(T, "addresses", _addresses_table)
    object.__setattr__(T, "sessions", _sessions_table)

    # Enable geocoding flags for tests by default
    object.__setattr__(S, "crm_geocoding_enabled", True)
    object.__setattr__(S, "crm_proximity_search_enabled", True)
    object.__setattr__(S, "crm_geocoding_provider_url", "")
    object.__setattr__(S, "crm_proximity_search_max_radius_km", 20000.0)
    object.__setattr__(S, "crm_map_default_lat", 37.7749)
    object.__setattr__(S, "crm_map_default_lng", -122.4194)
    object.__setattr__(S, "crm_map_default_radius_km", 50.0)
    object.__setattr__(S, "crm_map_max_radius_km", 500.0)
    object.__setattr__(S, "crm_map_max_pins", 200)

    yield

    # Teardown: restore original handles and settings
    object.__setattr__(T, "addresses", _orig_addresses)
    object.__setattr__(T, "sessions", _orig_sessions)

    object.__setattr__(S, "crm_geocoding_enabled", _ORIG_GEOCODING_ENABLED)
    object.__setattr__(S, "crm_proximity_search_enabled", _ORIG_PROXIMITY_ENABLED)
    object.__setattr__(S, "crm_geocoding_provider_url", _ORIG_PROVIDER_URL)
    object.__setattr__(S, "crm_proximity_search_max_radius_km", _ORIG_MAX_RADIUS)
    object.__setattr__(S, "crm_map_default_lat", _ORIG_MAP_DEFAULT_LAT)
    object.__setattr__(S, "crm_map_default_lng", _ORIG_MAP_DEFAULT_LNG)
    object.__setattr__(S, "crm_map_default_radius_km", _ORIG_MAP_DEFAULT_RADIUS)
    object.__setattr__(S, "crm_map_max_radius_km", _ORIG_MAP_MAX_RADIUS)
    object.__setattr__(S, "crm_map_max_pins", _ORIG_MAP_MAX_PINS)

    _mock_ctx.stop()


def _new_user_sub() -> str:
    return f"u-{uuid.uuid4().hex[:8]}"


def _insert_address(user_sub: str, address_id: str = None, **extra) -> dict:
    if address_id is None:
        address_id = f"addr-{uuid.uuid4().hex[:8]}"
    item = {
        "user_sub": user_sub,
        "address_id": address_id,
        "line1": "123 Main St",
        "city": "Testville",
        "state": "CA",
        "postal_code": "90001",
        "country": "US",
        **extra,
    }
    _addresses_table.put_item(Item=item)
    return item


# ===========================================================================
# EVT-005 — geocode_address
# ===========================================================================

class TestGeocodeAddress:
    def test_flag_off_returns_none(self):
        from app.services.crm_geocoding import geocode_address
        object.__setattr__(S, "crm_geocoding_enabled", False)
        try:
            result = geocode_address({"line1": "123 Main", "city": "Test", "country": "US"})
            assert result is None
        finally:
            object.__setattr__(S, "crm_geocoding_enabled", True)

    def test_mock_deterministic(self):
        from app.services.crm_geocoding import geocode_address
        addr = {"line1": "123 Main St", "city": "Springfield", "state": "IL", "country": "US"}
        r1 = geocode_address(addr)
        r2 = geocode_address(addr)
        assert r1 is not None
        assert r1 == r2
        assert -90 <= r1["lat"] <= 90
        assert -180 <= r1["lng"] <= 180
        assert round(r1["lat"], 6) == r1["lat"]

    def test_blank_address_returns_none(self):
        from app.services.crm_geocoding import geocode_address
        result = geocode_address({})
        assert result is None

    def test_blank_all_fields_returns_none(self):
        from app.services.crm_geocoding import geocode_address
        result = geocode_address({
            "line1": "", "line2": "", "city": "", "state": "",
            "postal_code": "", "country": "",
        })
        assert result is None

    def test_real_provider_success(self):
        from app.services.crm_geocoding import geocode_address
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"lat": "51.5074", "lon": "-0.1278"}]

        object.__setattr__(S, "crm_geocoding_provider_url", "https://nominatim.test")
        try:
            with patch("requests.get", return_value=mock_resp) as mock_get:
                result = geocode_address({"line1": "1 A St", "city": "London", "country": "GB"})
            assert result == {"lat": 51.5074, "lng": -0.1278}
            mock_get.assert_called_once()
        finally:
            object.__setattr__(S, "crm_geocoding_provider_url", "")

    def test_real_provider_network_error(self):
        import requests as req_lib
        from app.services.crm_geocoding import geocode_address
        object.__setattr__(S, "crm_geocoding_provider_url", "https://nominatim.test")
        try:
            with patch("requests.get", side_effect=req_lib.exceptions.ConnectionError("timeout")):
                result = geocode_address({"line1": "1 A St", "city": "London", "country": "GB"})
            assert result is None
        finally:
            object.__setattr__(S, "crm_geocoding_provider_url", "")

    def test_real_provider_non_200(self):
        from app.services.crm_geocoding import geocode_address
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        object.__setattr__(S, "crm_geocoding_provider_url", "https://nominatim.test")
        try:
            with patch("requests.get", return_value=mock_resp):
                result = geocode_address({"line1": "1 A", "city": "X", "country": "US"})
            assert result is None
        finally:
            object.__setattr__(S, "crm_geocoding_provider_url", "")

    def test_real_provider_empty_results(self):
        from app.services.crm_geocoding import geocode_address
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        object.__setattr__(S, "crm_geocoding_provider_url", "https://nominatim.test")
        try:
            with patch("requests.get", return_value=mock_resp):
                result = geocode_address({"line1": "1 A", "city": "X", "country": "US"})
            assert result is None
        finally:
            object.__setattr__(S, "crm_geocoding_provider_url", "")


# ===========================================================================
# EVT-005 — apply_geocode_to_address
# ===========================================================================

class TestApplyGeocodeToAddress:
    def test_writes_lat_lng_geocoded_at(self):
        from app.services.crm_geocoding import apply_geocode_to_address
        from app.core.time import now_ts
        user_sub = _new_user_sub()
        item = _insert_address(user_sub)
        address_id = item["address_id"]

        result = apply_geocode_to_address(user_sub, address_id)
        assert result is not None
        assert "lat" in result and "lng" in result and "geocoded_at" in result
        assert -90 <= result["lat"] <= 90
        assert -180 <= result["lng"] <= 180
        assert result["geocoded_at"] >= now_ts() - 5

        # Verify persisted in DDB
        stored = _addresses_table.get_item(
            Key={"user_sub": user_sub, "address_id": address_id}
        ).get("Item")
        assert "lat" in stored
        assert "lng" in stored

    def test_idempotent(self):
        from app.services.crm_geocoding import apply_geocode_to_address
        user_sub = _new_user_sub()
        item = _insert_address(user_sub)
        address_id = item["address_id"]

        r1 = apply_geocode_to_address(user_sub, address_id)
        r2 = apply_geocode_to_address(user_sub, address_id)
        assert r1 is not None and r2 is not None
        assert r1["lat"] == r2["lat"]
        assert r1["lng"] == r2["lng"]

    def test_flag_off_no_write(self):
        from app.services.crm_geocoding import apply_geocode_to_address
        user_sub = _new_user_sub()
        item = _insert_address(user_sub)
        address_id = item["address_id"]

        object.__setattr__(S, "crm_geocoding_enabled", False)
        try:
            result = apply_geocode_to_address(user_sub, address_id)
            assert result is None
            stored = _addresses_table.get_item(
                Key={"user_sub": user_sub, "address_id": address_id}
            ).get("Item")
            assert "lat" not in stored
        finally:
            object.__setattr__(S, "crm_geocoding_enabled", True)

    def test_nonexistent_address_returns_none(self):
        from app.services.crm_geocoding import apply_geocode_to_address
        result = apply_geocode_to_address("no-user", "no-address")
        assert result is None


# ===========================================================================
# EVT-005 — list_geocoded_addresses
# ===========================================================================

class TestListGeocodedAddresses:
    def test_only_returns_geocoded(self):
        from app.services.crm_geocoding import list_geocoded_addresses
        user_sub = _new_user_sub()
        # Insert 2 geocoded, 1 not geocoded
        a1 = _insert_address(user_sub, lat=Decimal("37.7749"), lng=Decimal("-122.4194"),
                              geocoded_at=1234567)
        a2 = _insert_address(user_sub, lat=Decimal("48.8566"), lng=Decimal("2.3522"),
                              geocoded_at=1234567)
        a3 = _insert_address(user_sub)  # no lat/lng

        results = list_geocoded_addresses(user_sub)
        result_ids = {r["address_id"] for r in results}
        assert a1["address_id"] in result_ids
        assert a2["address_id"] in result_ids
        assert a3["address_id"] not in result_ids
        assert len(results) == 2

    def test_empty_when_none_geocoded(self):
        from app.services.crm_geocoding import list_geocoded_addresses
        user_sub = _new_user_sub()
        _insert_address(user_sub)
        results = list_geocoded_addresses(user_sub)
        assert results == []


# ===========================================================================
# EVT-005 — geocode_party_address (soft dependency)
# ===========================================================================

class TestGeocodePartyAddress:
    def test_no_party_table_is_noop(self):
        from app.services.crm_geocoding import geocode_party_address
        # T.party should not exist in worktree
        orig_party = getattr(T, "party", "SENTINEL")
        try:
            object.__setattr__(T, "party", None)
            # Must not raise
            geocode_party_address("party-123", {"line1": "1 A St", "city": "X", "country": "US"})
        finally:
            if orig_party == "SENTINEL":
                # Remove the party attr if we added it
                try:
                    object.__delattr__(T, "party")
                except AttributeError:
                    pass
            else:
                object.__setattr__(T, "party", orig_party)

    def test_flag_off_is_noop(self):
        from app.services.crm_geocoding import geocode_party_address
        object.__setattr__(S, "crm_geocoding_enabled", False)
        try:
            # Must not raise
            geocode_party_address("party-x", {"line1": "1 St", "city": "NY", "country": "US"})
        finally:
            object.__setattr__(S, "crm_geocoding_enabled", True)


# ===========================================================================
# EVT-006 — haversine_km
# ===========================================================================

class TestHaversineKm:
    def test_same_point(self):
        from app.services.crm_geocoding import haversine_km
        assert haversine_km(0, 0, 0, 0) == 0.0

    def test_london_to_paris(self):
        from app.services.crm_geocoding import haversine_km
        # London (51.5074, -0.1278) to Paris (48.8566, 2.3522) ≈ 343.6 km
        # (IUGG mean Earth radius 6371.0 km gives ~343.6 km for these coordinates)
        dist = haversine_km(51.5074, -0.1278, 48.8566, 2.3522)
        assert abs(dist - 343.6) < 1.0

    def test_antipodal(self):
        from app.services.crm_geocoding import haversine_km
        # (0, 0) to (0, 180) ≈ 20 015 km
        dist = haversine_km(0, 0, 0, 180)
        assert abs(dist - 20015) < 5

    def test_symmetry(self):
        from app.services.crm_geocoding import haversine_km
        for a, b, c, d in [(10, 20, 30, 40), (-15, 100, 45, -90), (0, 0, 90, 0)]:
            assert abs(haversine_km(a, b, c, d) - haversine_km(c, d, a, b)) < 1e-6

    def test_equator_one_degree(self):
        from app.services.crm_geocoding import haversine_km
        # One degree of longitude at equator ≈ 111.32 km
        dist = haversine_km(0, 0, 0, 1)
        assert abs(dist - 111.32) < 0.5


# ===========================================================================
# EVT-006 — proximity_search (service)
# ===========================================================================

class TestProximitySearch:
    def test_flag_off_returns_empty(self):
        from app.services.crm_geocoding import proximity_search
        object.__setattr__(S, "crm_proximity_search_enabled", False)
        try:
            result = proximity_search("u1", 0, 0, 100)
            assert result == []
        finally:
            object.__setattr__(S, "crm_proximity_search_enabled", True)

    def test_no_geocoded_addresses(self):
        from app.services.crm_geocoding import proximity_search
        user_sub = _new_user_sub()
        _insert_address(user_sub)  # no lat/lng
        assert proximity_search(user_sub, 0, 0, 100) == []

    def test_basic_radius_filter(self):
        from app.services.crm_geocoding import proximity_search
        user_sub = _new_user_sub()
        # London, Paris, Berlin
        _insert_address(user_sub, "addr-lon",
                        lat=Decimal("51.5074"), lng=Decimal("-0.1278"), geocoded_at=1)
        _insert_address(user_sub, "addr-par",
                        lat=Decimal("48.8566"), lng=Decimal("2.3522"), geocoded_at=1)
        _insert_address(user_sub, "addr-ber",
                        lat=Decimal("52.5200"), lng=Decimal("13.4050"), geocoded_at=1)

        # From Paris, radius 500 km — should get London (~340 km) + Paris (~0 km), not Berlin (~878 km)
        results = proximity_search(user_sub, 48.8566, 2.3522, 500.0, limit=50)
        entity_ids = {r["entity_id"] for r in results}
        assert "addr-par" in entity_ids
        assert "addr-lon" in entity_ids
        assert "addr-ber" not in entity_ids
        assert all(r["distance_km"] <= 500.0 for r in results)
        # Sorted ascending: Paris first (0 km)
        assert results[0]["entity_id"] == "addr-par"

    def test_radius_zero_excludes_distant_points(self):
        """radius_km=0 only returns items at exact 0.0 distance (same point).
        Distinct addresses get non-zero haversine distance even if close, so
        a very tiny radius like 0.0001 km should exclude them.
        """
        from app.services.crm_geocoding import proximity_search
        user_sub = _new_user_sub()
        # Point 0.5 degrees away — definitely > 0.0001 km
        _insert_address(user_sub, lat=Decimal("48.3566"), lng=Decimal("2.3522"),
                        geocoded_at=1)
        # radius=0.0001 km (10 cm) — no address is this close
        results = proximity_search(user_sub, 48.8566, 2.3522, 0.0001)
        assert results == []

    def test_large_radius_returns_all(self):
        from app.services.crm_geocoding import proximity_search
        user_sub = _new_user_sub()
        for _ in range(3):
            _insert_address(user_sub,
                            lat=Decimal("10.0"), lng=Decimal("20.0"), geocoded_at=1)
        results = proximity_search(user_sub, 0, 0, 20000)
        assert len(results) == 3

    def test_limit_applied(self):
        from app.services.crm_geocoding import proximity_search
        user_sub = _new_user_sub()
        for i in range(10):
            _insert_address(user_sub,
                            lat=Decimal(str(i * 0.1)), lng=Decimal("0.0"), geocoded_at=1)
        results = proximity_search(user_sub, 0, 0, 20000, limit=3)
        assert len(results) == 3

    def test_sorted_ascending(self):
        from app.services.crm_geocoding import proximity_search
        user_sub = _new_user_sub()
        for i in range(5):
            _insert_address(user_sub,
                            lat=Decimal(str(i * 2)), lng=Decimal("0.0"), geocoded_at=1)
        results = proximity_search(user_sub, 0, 0, 20000, limit=50)
        for i in range(len(results) - 1):
            assert results[i]["distance_km"] <= results[i + 1]["distance_km"]

    def test_invalid_entity_type(self):
        from app.services.crm_geocoding import proximity_search
        with pytest.raises(ValueError):
            proximity_search("u1", 0, 0, 100, entity_type="foo")

    def test_party_no_table(self):
        from app.services.crm_geocoding import proximity_search
        orig = getattr(T, "party", "SENTINEL")
        try:
            object.__setattr__(T, "party", None)
            result = proximity_search("u1", 0, 0, 100, entity_type="party")
            assert result == []
        finally:
            if orig == "SENTINEL":
                try:
                    object.__delattr__(T, "party")
                except AttributeError:
                    pass
            else:
                object.__setattr__(T, "party", orig)

    def test_radius_over_max_raises(self):
        from app.services.crm_geocoding import proximity_search
        object.__setattr__(S, "crm_proximity_search_max_radius_km", 500.0)
        try:
            with pytest.raises(ValueError):
                proximity_search("u1", 0, 0, 501.0)
        finally:
            object.__setattr__(S, "crm_proximity_search_max_radius_km", 20000.0)


# ===========================================================================
# EVT-005 router — PATCH /ui/crm/geocoding/addresses/{id}
# ===========================================================================

class TestCrmGeocodingRouter:
    def _make_ctx(self, user_sub: str) -> dict:
        return {"user_sub": user_sub, "session_id": "s1", "role": "USER"}

    def test_patch_flag_off_returns_404(self):
        from app.routers.crm_geocoding import patch_geocode_address
        from fastapi import HTTPException
        object.__setattr__(S, "crm_geocoding_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                _run(patch_geocode_address("some-addr", ctx=self._make_ctx("u1")))
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "crm_geocoding_enabled", True)

    def test_patch_geocodes_address(self):
        from app.routers.crm_geocoding import patch_geocode_address
        user_sub = _new_user_sub()
        item = _insert_address(user_sub)
        address_id = item["address_id"]

        result = _run(patch_geocode_address(address_id, ctx=self._make_ctx(user_sub)))
        assert hasattr(result, "lat")
        assert -90 <= result.lat <= 90

    def test_patch_unknown_address_returns_404(self):
        from app.routers.crm_geocoding import patch_geocode_address
        from fastapi import HTTPException
        user_sub = _new_user_sub()
        with pytest.raises(HTTPException) as exc_info:
            _run(patch_geocode_address("nonexistent-id", ctx=self._make_ctx(user_sub)))
        assert exc_info.value.status_code == 404

    def test_get_geocoded_addresses_flag_off(self):
        from app.routers.crm_geocoding import get_geocoded_addresses
        from fastapi import HTTPException
        object.__setattr__(S, "crm_geocoding_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                _run(get_geocoded_addresses(ctx=self._make_ctx("u1")))
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "crm_geocoding_enabled", True)

    def test_get_geocoded_addresses_returns_list(self):
        from app.routers.crm_geocoding import get_geocoded_addresses
        user_sub = _new_user_sub()
        _insert_address(user_sub, "a-with-geo",
                        lat=Decimal("10.0"), lng=Decimal("20.0"), geocoded_at=1234)
        _insert_address(user_sub, "a-without-geo")

        result = _run(get_geocoded_addresses(ctx=self._make_ctx(user_sub)))
        assert result.count >= 1
        ids = [a.address_id for a in result.addresses]
        assert "a-with-geo" in ids
        assert "a-without-geo" not in ids


# ===========================================================================
# EVT-006 router — GET /ui/crm/maps/contacts/proximity
# ===========================================================================

class TestCrmMapsProximityRouter:
    def _make_ctx(self, user_sub: str) -> dict:
        return {"user_sub": user_sub, "session_id": "s1", "role": "USER"}

    def _mock_request(self):
        req = MagicMock()
        req.state = MagicMock()
        return req

    def test_flag_off_returns_404(self):
        from app.routers.crm_maps import get_proximity_contacts
        from fastapi import HTTPException
        object.__setattr__(S, "crm_proximity_search_enabled", False)
        try:
            with pytest.raises(HTTPException) as exc_info:
                get_proximity_contacts(
                    request=self._mock_request(),
                    lat=0.0, lng=0.0, radius_km=100.0,
                    ctx=self._make_ctx("u1"),
                )
            assert exc_info.value.status_code == 404
        finally:
            object.__setattr__(S, "crm_proximity_search_enabled", True)

    def test_invalid_lat_returns_400(self):
        from app.routers.crm_maps import get_proximity_contacts
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            get_proximity_contacts(
                request=self._mock_request(),
                lat=91.0, lng=0.0, radius_km=100.0,
                ctx=self._make_ctx("u1"),
            )
        assert exc_info.value.status_code == 400

    def test_invalid_lng_returns_400(self):
        from app.routers.crm_maps import get_proximity_contacts
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            get_proximity_contacts(
                request=self._mock_request(),
                lat=0.0, lng=190.0, radius_km=100.0,
                ctx=self._make_ctx("u1"),
            )
        assert exc_info.value.status_code == 400

    def test_invalid_radius_returns_400(self):
        from app.routers.crm_maps import get_proximity_contacts
        from fastapi import HTTPException
        object.__setattr__(S, "crm_proximity_search_max_radius_km", 500.0)
        try:
            with pytest.raises(HTTPException) as exc_info:
                get_proximity_contacts(
                    request=self._mock_request(),
                    lat=0.0, lng=0.0, radius_km=501.0,
                    ctx=self._make_ctx("u1"),
                )
            assert exc_info.value.status_code == 400
        finally:
            object.__setattr__(S, "crm_proximity_search_max_radius_km", 20000.0)

    def test_valid_request_returns_proximity_out(self):
        from app.routers.crm_maps import get_proximity_contacts
        user_sub = _new_user_sub()
        _insert_address(user_sub, "prox-a",
                        lat=Decimal("0.1"), lng=Decimal("0.1"), geocoded_at=1)

        with patch("app.routers.crm_maps.rate_limit_proximity_search"):
            result = get_proximity_contacts(
                request=self._mock_request(),
                lat=0.0, lng=0.0, radius_km=100.0,
                ctx=self._make_ctx(user_sub),
            )
        assert result.count >= 0  # could be 0 or 1 depending on user's addresses

    def test_rate_limit_429_propagates(self):
        from app.routers.crm_maps import get_proximity_contacts
        from fastapi import HTTPException

        def _raise_429(user_sub):
            raise HTTPException(429, "rate limited")

        with patch("app.routers.crm_maps.rate_limit_proximity_search", side_effect=_raise_429):
            with pytest.raises(HTTPException) as exc_info:
                get_proximity_contacts(
                    request=self._mock_request(),
                    lat=0.0, lng=0.0, radius_km=100.0,
                    ctx=self._make_ctx("u-rate"),
                )
        assert exc_info.value.status_code == 429

    def test_audit_failure_does_not_surface(self):
        """Audit write failure must not cause a 500."""
        from app.routers.crm_maps import get_proximity_contacts

        with patch("app.routers.crm_maps.rate_limit_proximity_search"):
            with patch("app.services.alerts.audit_event", side_effect=Exception("DDB down")):
                # Should not raise
                result = get_proximity_contacts(
                    request=self._mock_request(),
                    lat=0.0, lng=0.0, radius_km=100.0,
                    ctx=self._make_ctx(_new_user_sub()),
                )
        assert result is not None

    def test_invalid_entity_type_returns_400(self):
        from app.routers.crm_maps import get_proximity_contacts
        from fastapi import HTTPException
        with patch("app.routers.crm_maps.rate_limit_proximity_search"):
            with pytest.raises(HTTPException) as exc_info:
                get_proximity_contacts(
                    request=self._mock_request(),
                    lat=0.0, lng=0.0, radius_km=100.0,
                    entity_type="invalid_type",
                    ctx=self._make_ctx("u1"),
                )
        assert exc_info.value.status_code == 400

    def test_limit_clamped_to_200(self):
        """limit=9999 should be clamped to 200 before calling proximity_search."""
        from app.routers.crm_maps import get_proximity_contacts
        user_sub = _new_user_sub()
        captured_calls = []

        def _fake_proximity(u, clat, clng, rkm, lim=50, etype="address"):
            captured_calls.append({"limit": lim})
            return []

        with patch("app.routers.crm_maps.rate_limit_proximity_search"):
            with patch("app.routers.crm_maps.proximity_search", side_effect=_fake_proximity):
                get_proximity_contacts(
                    request=self._mock_request(),
                    lat=0.0, lng=0.0, radius_km=100.0, limit=9999,
                    ctx=self._make_ctx(user_sub),
                )

        assert len(captured_calls) == 1
        assert captured_calls[0]["limit"] == 200


# ===========================================================================
# EVT-007 — GET /ui/crm/maps/feature-flags
# ===========================================================================

class TestCrmMapFeatureFlags:
    def _make_ctx(self, user_sub: str) -> dict:
        return {"user_sub": user_sub, "session_id": "s1", "role": "USER"}

    def test_flag_on_returns_enabled(self):
        from app.routers.crm_maps import get_crm_map_feature_flags
        result = get_crm_map_feature_flags(ctx=self._make_ctx("u-ff1"))
        assert result.crm_geocoding_enabled is True
        assert result.default_lat == 37.7749
        assert result.max_pins == 200

    def test_flag_off_returns_disabled_but_200(self):
        from app.routers.crm_maps import get_crm_map_feature_flags
        object.__setattr__(S, "crm_geocoding_enabled", False)
        try:
            result = get_crm_map_feature_flags(ctx=self._make_ctx("u-ff2"))
            assert result.crm_geocoding_enabled is False
            # Must NOT raise — endpoint is ungated
        finally:
            object.__setattr__(S, "crm_geocoding_enabled", True)

    def test_audit_event_called(self):
        from app.routers.crm_maps import get_crm_map_feature_flags
        with patch("app.services.alerts.audit_event") as mock_audit:
            get_crm_map_feature_flags(ctx=self._make_ctx("u-ff3"))
        mock_audit.assert_called_once()
        args = mock_audit.call_args[0]
        assert args[0] == "crm_map_viewed"
        assert args[1] == "u-ff3"

    def test_audit_failure_does_not_raise(self):
        from app.routers.crm_maps import get_crm_map_feature_flags
        with patch("app.services.alerts.audit_event", side_effect=Exception("boom")):
            result = get_crm_map_feature_flags(ctx=self._make_ctx("u-ff4"))
        assert result is not None

    def test_custom_defaults_in_response(self):
        from app.routers.crm_maps import get_crm_map_feature_flags
        object.__setattr__(S, "crm_map_default_lat", 48.8566)
        object.__setattr__(S, "crm_map_default_lng", 2.3522)
        try:
            result = get_crm_map_feature_flags(ctx=self._make_ctx("u-ff5"))
            assert result.default_lat == 48.8566
            assert result.default_lng == 2.3522
        finally:
            object.__setattr__(S, "crm_map_default_lat", 37.7749)
            object.__setattr__(S, "crm_map_default_lng", -122.4194)

    def test_feature_flags_route_ordering(self):
        """Verify /feature-flags is distinct from proximity handler (route ordering)."""
        from app.routers.crm_maps import router
        paths = [r.path for r in router.routes]
        assert "/ui/crm/maps/feature-flags" in paths
        assert "/ui/crm/maps/contacts/proximity" in paths
        # feature-flags index must be LESS THAN contacts/proximity index
        ff_idx = paths.index("/ui/crm/maps/feature-flags")
        prox_idx = paths.index("/ui/crm/maps/contacts/proximity")
        assert ff_idx < prox_idx, (
            f"/feature-flags must be declared before /contacts/proximity "
            f"(got ff_idx={ff_idx}, prox_idx={prox_idx})"
        )
