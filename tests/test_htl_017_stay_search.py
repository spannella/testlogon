"""HTL-017 — Hermetic offline tests for the stay-search engine (search_stays).

All forward-dep collaborators (hotel_availability, hotel_pms, hotel_rate_plans)
are patched at the hotel_reservations namespace so no real AWS / DDB is needed.
The suite follows the KYC GAP-0262 patch-collaborators recipe.

TEST-ISOLATION: module-scoped stub fixtures install stubs ONLY for the
duration of the test session and restore originals on teardown.
"""
from __future__ import annotations

import inspect
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

# ---------------------------------------------------------------------------
# Module-scoped stub fixture — installs stubs for sibling modules that may not
# exist in this isolated worktree, saves + restores both sys.modules AND the
# parent package attribute.
# ---------------------------------------------------------------------------

_STUB_NAMES = [
    "app.services.hotel_availability",
    "app.services.hotel_pms",
    "app.services.hotel_rate_plans",
]


@pytest.fixture(scope="session", autouse=True)
def _install_module_stubs():
    """Install lightweight stubs for unbuilt forward-dep modules."""
    saved = {}
    for name in _STUB_NAMES:
        saved[name] = sys.modules.get(name)

    # Build minimal stubs
    ha_stub = SimpleNamespace(
        check_availability=MagicMock(),
        hold_rooms=MagicMock(),
        release_hold=MagicMock(),
    )
    pms_stub = SimpleNamespace(
        list_hotels=MagicMock(return_value={"hotels": [], "count": 0, "cursor": None}),
        list_room_types=MagicMock(return_value={"room_types": [], "count": 0, "cursor": None}),
        set_room_status=MagicMock(),
    )
    rp_stub = SimpleNamespace(compute_stay_price=MagicMock())

    sys.modules["app.services.hotel_availability"] = ha_stub  # type: ignore[assignment]
    sys.modules["app.services.hotel_pms"] = pms_stub  # type: ignore[assignment]
    sys.modules["app.services.hotel_rate_plans"] = rp_stub  # type: ignore[assignment]

    yield

    # Restore
    for name in _STUB_NAMES:
        orig = saved[name]
        if orig is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = orig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _avail(available=True, min_remaining=5):
    return {
        "available": available,
        "rooms_needed": 1,
        "per_night": [],
        "min_remaining": min_remaining,
    }


def _price(total_cents=10000, currency="usd", rule_ids=None):
    return SimpleNamespace(
        total_cents=total_cents,
        currency=currency,
        per_night=[],
        applied_rule_ids=rule_ids or [],
    )


def _rt(rid, name="Deluxe"):
    return {
        "room_type_id": rid,
        "name": name,
        "base_nightly_rate_cents": 5000,
        "max_occupancy": 3,
    }


# ---------------------------------------------------------------------------
# Fixture: enable flag and patch forward-deps per test
# ---------------------------------------------------------------------------

@pytest.fixture()
def setup(monkeypatch):
    from app.services import hotel_reservations as hr

    object.__setattr__(hr.S, "hotel_pms_enabled", True)

    fake_ha = SimpleNamespace(
        check_availability=MagicMock(return_value=_avail()),
        hold_rooms=MagicMock(return_value={"hold_id": "h1"}),
        release_hold=MagicMock(),
    )
    fake_pms = SimpleNamespace(
        list_hotels=MagicMock(return_value={"hotels": [], "count": 0, "cursor": None}),
        list_room_types=MagicMock(return_value={"room_types": [], "count": 0, "cursor": None}),
        set_room_status=MagicMock(),
    )
    fake_rp = SimpleNamespace(compute_stay_price=MagicMock(return_value=_price()))
    monkeypatch.setattr(hr, "ha", fake_ha)
    monkeypatch.setattr(hr, "hotel_pms", fake_pms)
    monkeypatch.setattr(hr, "hotel_rate_plans", fake_rp)

    yield hr, fake_ha, fake_pms, fake_rp

    object.__setattr__(hr.S, "hotel_pms_enabled", False)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_flag_off_raises_404_before_any_collaborator(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    object.__setattr__(hr.S, "hotel_pms_enabled", False)
    with pytest.raises(HTTPException) as exc_info:
        hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert exc_info.value.status_code == 404
    fake_ha.check_availability.assert_not_called()


def test_both_hotel_id_and_city_absent_raises_422(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    with pytest.raises(HTTPException) as exc_info:
        hr.search_stays(checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert exc_info.value.status_code == 422
    fake_ha.check_availability.assert_not_called()


def test_checkout_before_checkin_raises_422(setup):
    hr, *_ = setup
    with pytest.raises(HTTPException) as exc_info:
        hr.search_stays(
            hotel_id="h1", checkin="2026-07-03", checkout="2026-07-01", adults=2
        )
    assert exc_info.value.status_code == 422
    assert "checkout must be after checkin" in exc_info.value.detail


def test_malformed_date_raises_422(setup):
    hr, *_ = setup
    with pytest.raises(HTTPException) as exc_info:
        hr.search_stays(hotel_id="h1", checkin="2026-7-1", checkout="2026-07-03", adults=2)
    assert exc_info.value.status_code == 422


def test_available_room_types_only(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    rt_a = _rt("rt_a")
    rt_b = _rt("rt_b")
    fake_pms.list_room_types.return_value = {
        "room_types": [rt_a, rt_b], "count": 2, "cursor": None
    }

    def _avail_side(*args, **kwargs):
        rt_id = args[1] if len(args) > 1 else kwargs.get("room_type_id")
        if rt_id == "rt_a":
            return _avail(available=True, min_remaining=5)
        return _avail(available=False, min_remaining=0)

    fake_ha.check_availability.side_effect = _avail_side
    fake_rp.compute_stay_price.return_value = _price(total_cents=10000)

    result = hr.search_stays(
        hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2
    )
    assert result.result_count == 1
    assert result.results[0].room_type_id == "rt_a"
    # compute_stay_price must NOT be called for rt_b
    calls = [c.args[1] if c.args else c.kwargs.get("room_type_id")
              for c in fake_rp.compute_stay_price.call_args_list]
    assert "rt_b" not in calls


def test_partial_span_sold_out_excludes_room_type(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {
        "room_types": [_rt("rt_x")], "count": 1, "cursor": None
    }
    fake_ha.check_availability.return_value = _avail(available=False, min_remaining=1)

    result = hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert result.result_count == 0


def test_price_equals_compute_stay_price_output(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {
        "room_types": [_rt("rt_z")], "count": 1, "cursor": None
    }
    fake_ha.check_availability.return_value = _avail()
    fake_rp.compute_stay_price.return_value = _price(
        total_cents=55000, currency="gbp", rule_ids=["rule1"]
    )

    result = hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert result.result_count == 1
    r = result.results[0]
    assert r.total_cents == 55000
    assert r.currency == "gbp"
    assert r.applied_rule_ids == ["rule1"]


def test_los_rejection_excludes_one_room_type_search_continues(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {
        "room_types": [_rt("rt_a"), _rt("rt_b")], "count": 2, "cursor": None
    }
    fake_ha.check_availability.return_value = _avail()

    def _price_side(*args, **kwargs):
        rt_id = args[1] if len(args) > 1 else kwargs.get("room_type_id")
        if rt_id == "rt_a":
            raise HTTPException(status_code=422, detail="stay too short")
        return _price(total_cents=20000)

    fake_rp.compute_stay_price.side_effect = _price_side

    result = hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert result.result_count == 1
    assert result.results[0].room_type_id == "rt_b"


def test_non_422_price_error_propagates(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {
        "room_types": [_rt("rt_a")], "count": 1, "cursor": None
    }
    fake_ha.check_availability.return_value = _avail()
    fake_rp.compute_stay_price.side_effect = HTTPException(status_code=500, detail="internal")

    with pytest.raises(HTTPException) as exc_info:
        hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert exc_info.value.status_code == 500


def test_no_rate_plan_still_prices_off_base_rate(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {
        "room_types": [_rt("rt_a")], "count": 1, "cursor": None
    }
    fake_ha.check_availability.return_value = _avail()
    fake_rp.compute_stay_price.return_value = _price(total_cents=5000, rule_ids=[])

    result = hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert result.result_count == 1
    assert result.results[0].applied_rule_ids == []


def test_cheapest_first_ordering_with_deterministic_tiebreak(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {
        "room_types": [_rt("rt_z"), _rt("rt_x"), _rt("rt_a")],
        "count": 3,
        "cursor": None,
    }
    fake_ha.check_availability.return_value = _avail()

    prices = {"rt_z": 15000, "rt_x": 10000, "rt_a": 10000}

    def _price_side(*args, **kwargs):
        rt_id = args[1] if len(args) > 1 else kwargs.get("room_type_id")
        return _price(total_cents=prices[rt_id])

    fake_rp.compute_stay_price.side_effect = _price_side

    result = hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert result.result_count == 3
    assert result.results[0].room_type_id == "rt_a"   # 10000, tiebreak rt_a < rt_x
    assert result.results[1].room_type_id == "rt_x"   # 10000
    assert result.results[2].room_type_id == "rt_z"   # 15000


def test_result_count_equals_len_results_and_echoed_fields(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {
        "room_types": [_rt("rt_a"), _rt("rt_b")], "count": 2, "cursor": None
    }
    fake_ha.check_availability.return_value = _avail()
    fake_rp.compute_stay_price.return_value = _price()

    result = hr.search_stays(
        hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2, children=1, rooms=2
    )
    assert result.result_count == len(result.results)
    assert result.nights == 2
    assert result.checkin == "2026-07-01"
    assert result.checkout == "2026-07-03"
    assert result.adults == 2
    assert result.children == 1
    assert result.rooms == 2


def test_no_availability_for_any_room_type_returns_empty(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {
        "room_types": [_rt("rt_a"), _rt("rt_b")], "count": 2, "cursor": None
    }
    fake_ha.check_availability.return_value = _avail(available=False)

    result = hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert result.results == []
    assert result.result_count == 0


def test_no_candidate_room_types_returns_empty(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {"room_types": [], "count": 0, "cursor": None}

    result = hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert result.results == []
    fake_ha.check_availability.assert_not_called()
    fake_rp.compute_stay_price.assert_not_called()


def test_city_branch_resolves_hotels_then_room_types(setup):
    hr, fake_ha, fake_pms, fake_rp = setup

    fake_pms.list_hotels.return_value = {
        "hotels": [{"hotel_id": "h_paris_1"}, {"hotel_id": "h_paris_2"}],
        "count": 2,
        "cursor": None,
    }
    fake_pms.list_room_types.return_value = {
        "room_types": [_rt("rt_a")], "count": 1, "cursor": None
    }
    fake_ha.check_availability.return_value = _avail()
    fake_rp.compute_stay_price.return_value = _price()

    result = hr.search_stays(city="Paris", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert result.result_count == 2
    hotel_ids = {r.hotel_id for r in result.results}
    assert hotel_ids == {"h_paris_1", "h_paris_2"}


def test_hotel_id_precedence_when_both_supplied(setup):
    hr, fake_ha, fake_pms, fake_rp = setup
    fake_pms.list_room_types.return_value = {"room_types": [], "count": 0, "cursor": None}

    hr.search_stays(
        hotel_id="h1", city="Paris",
        checkin="2026-07-01", checkout="2026-07-03", adults=2,
    )
    # list_hotels should NOT be called when hotel_id is supplied
    fake_pms.list_hotels.assert_not_called()
    # list_room_types should be called with hotel_id
    assert fake_pms.list_room_types.call_count == 1


def test_pagination_of_candidate_room_types(setup):
    hr, fake_ha, fake_pms, fake_rp = setup

    page1 = {"room_types": [_rt("rt_1")], "count": 1, "cursor": "page2_cursor"}
    page2 = {"room_types": [_rt("rt_2")], "count": 1, "cursor": None}
    fake_pms.list_room_types.side_effect = [page1, page2]
    fake_ha.check_availability.return_value = _avail()
    fake_rp.compute_stay_price.return_value = _price()

    result = hr.search_stays(hotel_id="h1", checkin="2026-07-01", checkout="2026-07-03", adults=2)
    assert result.result_count == 2
    room_ids = {r.room_type_id for r in result.results}
    assert room_ids == {"rt_1", "rt_2"}


def test_no_dev_mode_in_search_stays_source(setup):
    hr, *_ = setup
    source = inspect.getsource(hr.search_stays)
    assert "dev_mode" not in source
