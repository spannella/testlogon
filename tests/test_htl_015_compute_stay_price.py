"""Hermetic pytest for HTL-015: compute_stay_price multi-night engine.

Offline; no live stack, no real AWS.
Pattern: moto-backed hotel_rate_plans table bound to frozen T via
object.__setattr__; frozen S flags toggled per test; now_ts patched where
needed for deterministic advance_days tests.  No TestClient.
"""
import inspect
import pytest
import boto3
from moto import mock_aws
from fastapi import HTTPException
from unittest.mock import patch


TABLE_NAME = "hotel_rate_plans"
HOTEL_ID = "h_csp"
RT_ID = "rt_csp"
ADMIN_SUB = "admin_csp"


# ─── table fixture ───────────────────────────────────────────────────────────

@pytest.fixture()
def svc_table():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "hotel_id#room_type_id", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "hotel_id#room_type_id", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "hotel_id", "AttributeType": "S"},
                {"AttributeName": "room_type_id", "AttributeType": "S"},
                {"AttributeName": "created_at", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "GSI_HOTEL",
                    "KeySchema": [
                        {"AttributeName": "hotel_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI_ROOM_TYPE",
                    "KeySchema": [
                        {"AttributeName": "room_type_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        from app.core import tables as T_mod
        from app.services import hotel_rate_plans as svc

        object.__setattr__(T_mod.T, "hotel_rate_plans", table)
        object.__setattr__(svc.S, "hotel_pms_enabled", True)
        object.__setattr__(svc.S, "hotel_rate_plans_table_name", TABLE_NAME)

        yield svc

        object.__setattr__(svc.S, "hotel_pms_enabled", False)


# ─── helpers ─────────────────────────────────────────────────────────────────

def _create_plan(svc, rate=10000, occ=2):
    return svc.create_rate_plan(
        HOTEL_ID, RT_ID,
        name="Test Plan",
        base_nightly_rate_cents=rate,
        base_occupancy=occ,
        user_sub=ADMIN_SUB,
    )


def _add_rule(svc, kind, cfg, priority=500):
    return svc.add_rule(HOTEL_ID, RT_ID, kind=kind, rule_config=cfg, priority=priority, user_sub=ADMIN_SUB)


def _quote(svc, checkin, checkout, adults=2, children=0, rooms=1, advance_days=30):
    return svc.compute_stay_price(
        HOTEL_ID, RT_ID,
        checkin=checkin, checkout=checkout,
        adults=adults, children=children,
        rooms=rooms, advance_days=advance_days,
    )


# ─── 1. Flag-off 404 ─────────────────────────────────────────────────────────

def test_flag_off(svc_table):
    svc = svc_table
    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            svc.compute_stay_price(HOTEL_ID, RT_ID, "2026-06-01", "2026-06-04", 2, 0)
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)


# ─── 2. Span summation + night count ─────────────────────────────────────────

def test_span_summation(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    res = _quote(svc, "2026-06-01", "2026-06-04")  # 3 nights
    assert res.nights == 3
    assert len(res.per_night) == 3
    for line in res.per_night:
        assert line.night_total_cents == 10000
    assert res.stay_subtotal_cents == 30000
    assert res.total_cents == 30000
    assert res.applied_rule_ids == []


def test_subtotal_identity_invariant(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    res = _quote(svc, "2026-06-01", "2026-06-04")
    assert res.stay_subtotal_cents == sum(l.night_total_cents for l in res.per_night)


# ─── 3. 1-night stay ─────────────────────────────────────────────────────────

def test_one_night_stay(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    res = _quote(svc, "2026-06-01", "2026-06-02")
    assert res.nights == 1
    assert len(res.per_night) == 1


# ─── 4. Season absolute ──────────────────────────────────────────────────────

def test_season_absolute(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "season", {"start_date": "2026-06-02", "end_date": "2026-06-03", "mode": "absolute", "value_cents": 15000})
    res = _quote(svc, "2026-06-01", "2026-06-04")  # Jun 1, 2, 3
    assert res.per_night[0].night_total_cents == 10000  # Jun 1: base
    assert res.per_night[1].night_total_cents == 15000  # Jun 2: absolute
    assert res.per_night[2].night_total_cents == 15000  # Jun 3: absolute
    assert res.per_night[1].season_delta_cents == 5000


# ─── 5. Season delta ─────────────────────────────────────────────────────────

def test_season_delta(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "season", {"start_date": "2026-06-02", "end_date": "2026-06-03", "mode": "delta", "value_cents": 2000})
    res = _quote(svc, "2026-06-01", "2026-06-04")
    assert res.per_night[0].night_total_cents == 10000
    assert res.per_night[1].night_total_cents == 12000
    assert res.per_night[1].season_delta_cents == 2000


# ─── 6. Season multi-match tiebreak ──────────────────────────────────────────

def test_season_multi_abs_tiebreak(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    # Two overlapping absolute rules — lowest-priority (lower number) wins
    r1 = _add_rule(svc, "season",
                   {"start_date": "2026-06-01", "end_date": "2026-06-10", "mode": "absolute", "value_cents": 20000},
                   priority=100)
    r2 = _add_rule(svc, "season",
                   {"start_date": "2026-06-01", "end_date": "2026-06-10", "mode": "absolute", "value_cents": 30000},
                   priority=200)
    res = _quote(svc, "2026-06-01", "2026-06-03")
    # priority=100 wins
    assert res.per_night[0].night_total_cents == 20000


def test_season_abs_plus_delta(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "season",
              {"start_date": "2026-06-01", "end_date": "2026-06-10", "mode": "absolute", "value_cents": 15000},
              priority=100)
    _add_rule(svc, "season",
              {"start_date": "2026-06-01", "end_date": "2026-06-10", "mode": "delta", "value_cents": 2000},
              priority=200)
    res = _quote(svc, "2026-06-01", "2026-06-03")
    # absolute sets 15000, delta adds 2000 → 17000
    assert res.per_night[0].night_total_cents == 17000


# ─── 7. Weekend delta + dow math ─────────────────────────────────────────────

def test_weekend_delta(svc_table):
    """2026-06-06 is a Saturday (isoweekday=6)."""
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "weekend", {"dow": [6, 7], "mode": "delta", "value_cents": 3000})
    # Jun 5 (Fri=5), Jun 6 (Sat=6), Jun 7 (Sun=7)
    res = _quote(svc, "2026-06-05", "2026-06-08", advance_days=30)
    from datetime import date
    assert date(2026, 6, 5).isoweekday() == 5  # Fri — not in dow
    assert date(2026, 6, 6).isoweekday() == 6  # Sat — in dow
    assert date(2026, 6, 7).isoweekday() == 7  # Sun — in dow
    assert res.per_night[0].night_total_cents == 10000   # Fri: unchanged
    assert res.per_night[1].night_total_cents == 13000   # Sat: +3000
    assert res.per_night[2].night_total_cents == 13000   # Sun: +3000
    assert res.per_night[0].weekend_delta_cents == 0


# ─── 8. Weekend absolute after season ────────────────────────────────────────

def test_weekend_absolute_after_season(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "season", {"start_date": "2026-06-01", "end_date": "2026-06-10", "mode": "absolute", "value_cents": 15000})
    # Sat absolute override to 12000 (< season 15000)
    _add_rule(svc, "weekend", {"dow": [6], "mode": "absolute", "value_cents": 12000})
    # 2026-06-06 = Saturday
    res = _quote(svc, "2026-06-06", "2026-06-07", advance_days=30)
    assert res.per_night[0].night_total_cents == 12000


# ─── 9. Occupancy surcharge ───────────────────────────────────────────────────

def test_occupancy_surcharge(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000, occ=2)
    _add_rule(svc, "occupancy", {"extra_adult_cents": 2500, "extra_child_cents": 1500})
    res = _quote(svc, "2026-06-01", "2026-06-04", adults=3, children=1, advance_days=30)
    # 1 extra adult × 2500 + 1 child × 1500 = 4000 per night
    for line in res.per_night:
        assert line.occupancy_cents == 4000
        assert line.night_total_cents == 14000


def test_occupancy_no_surcharge(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000, occ=2)
    _add_rule(svc, "occupancy", {"extra_adult_cents": 2500, "extra_child_cents": 1500})
    res = _quote(svc, "2026-06-01", "2026-06-04", adults=2, children=0, advance_days=30)
    for line in res.per_night:
        assert line.occupancy_cents == 0


# ─── 10. LOS too short ───────────────────────────────────────────────────────

def test_los_too_short(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "los", {"min_nights": 3, "max_nights": 7, "discount_type": "percentage", "discount_value": 10})
    with pytest.raises(HTTPException) as exc_info:
        _quote(svc, "2026-06-01", "2026-06-03", advance_days=30)  # 2 nights < 3
    assert exc_info.value.status_code == 422
    assert "too short" in exc_info.value.detail


# ─── 11. LOS too long ────────────────────────────────────────────────────────

def test_los_too_long(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "los", {"min_nights": 3, "max_nights": 7, "discount_type": "percentage", "discount_value": 10})
    with pytest.raises(HTTPException) as exc_info:
        _quote(svc, "2026-06-01", "2026-06-10", advance_days=30)  # 9 nights > 7
    assert exc_info.value.status_code == 422
    assert "too long" in exc_info.value.detail


# ─── 12. LOS null max ────────────────────────────────────────────────────────

def test_los_null_max(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "los", {"min_nights": 1, "max_nights": None, "discount_type": "percentage", "discount_value": 10})
    # 30-night stay should not raise
    res = _quote(svc, "2026-06-01", "2026-07-01", advance_days=30)
    assert res.nights == 30


# ─── 13. LOS percentage discount ─────────────────────────────────────────────

def test_los_percentage_discount(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "los", {"min_nights": 1, "max_nights": None, "discount_type": "percentage", "discount_value": 10})
    res = _quote(svc, "2026-06-01", "2026-06-04", advance_days=30)  # 3 nights × 10000 = 30000
    assert res.los_discount_cents == 3000  # 10% of 30000
    assert res.total_cents == 27000


# ─── 14. LOS fixed_cents discount + cap ──────────────────────────────────────

def test_los_fixed_cents_capped(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "los", {"min_nights": 1, "max_nights": None, "discount_type": "fixed_cents", "discount_value": 50000})
    res = _quote(svc, "2026-06-01", "2026-06-04", advance_days=30)  # subtotal 30000
    # discount capped to subtotal
    assert res.los_discount_cents == 30000
    assert res.total_cents == 0


# ─── 15. Advance gte (advance-purchase discount) ─────────────────────────────

def test_advance_gte_applies(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "advance", {"days_before_checkin": 30, "comparator": "gte", "mode": "percentage", "value": 5})
    # advance_days=45 >= 30 → modifier applies (negative = discount)
    res = _quote(svc, "2026-06-01", "2026-06-04", advance_days=45)  # subtotal 30000
    assert res.advance_modifier_cents == -1500  # -5% of 30000; negative = discount
    # total = (30000 - 0 + (-1500)) × 1 = 28500
    assert res.total_cents == 28500


def test_advance_gte_does_not_apply(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "advance", {"days_before_checkin": 30, "comparator": "gte", "mode": "percentage", "value": 5})
    res = _quote(svc, "2026-06-01", "2026-06-04", advance_days=10)  # 10 < 30 → does not apply
    assert res.advance_modifier_cents == 0
    assert res.total_cents == 30000


# ─── 16. Advance lte (last-minute surcharge) ─────────────────────────────────

def test_advance_lte_applies(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "advance", {"days_before_checkin": 7, "comparator": "lte", "mode": "fixed_cents", "value": 2000})
    res = _quote(svc, "2026-06-01", "2026-06-04", advance_days=3)  # 3 <= 7
    # lte → positive modifier (surcharge)
    assert res.advance_modifier_cents == 2000
    assert res.total_cents == 32000


# ─── 17. advance_days default derivation ─────────────────────────────────────

def test_advance_days_default(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "advance", {"days_before_checkin": 30, "comparator": "gte", "mode": "percentage", "value": 5})

    from datetime import date
    # Pin now_ts to a date 45 days before "2026-06-01"
    fixed_date = date(2026, 4, 17)  # 2026-06-01 - 45 days
    import time as time_mod
    fixed_ts = int(time_mod.mktime(fixed_date.timetuple()))

    with patch.object(svc, "now_ts", return_value=fixed_ts):
        # advance_days not supplied → derived from now_ts
        res = svc.compute_stay_price(HOTEL_ID, RT_ID, "2026-06-01", "2026-06-04", 2, 0)
    # advance_days ≥ 30 so modifier should apply
    assert res.advance_modifier_cents == -1500


# ─── 18. Rooms multiplier ────────────────────────────────────────────────────

def test_rooms_multiplier(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    res = _quote(svc, "2026-06-01", "2026-06-04", rooms=3, advance_days=30)
    assert res.total_cents == 90000


def test_rooms_multiplier_with_discount(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "los", {"min_nights": 1, "max_nights": None, "discount_type": "fixed_cents", "discount_value": 5000})
    # subtotal 30000, discount 5000, per-room total 25000, × 2 rooms = 50000
    res = _quote(svc, "2026-06-01", "2026-06-04", rooms=2, advance_days=30)
    assert res.total_cents == 50000


# ─── 19. Final negative-total floor ──────────────────────────────────────────

def test_final_total_floor(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "los", {"min_nights": 1, "max_nights": None, "discount_type": "fixed_cents", "discount_value": 50000})
    _add_rule(svc, "advance", {"days_before_checkin": 0, "comparator": "gte", "mode": "fixed_cents", "value": 5000})
    res = _quote(svc, "2026-06-01", "2026-06-04", advance_days=0)
    # subtotal=30000, los=30000 (capped), advance=−5000; total=(30000-30000-5000)*1=-5000→floor 0
    assert res.total_cents == 0


# ─── 20. Rounding determinism ────────────────────────────────────────────────

def test_rounding_determinism(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10001)  # non-round amount
    _add_rule(svc, "los", {"min_nights": 1, "max_nights": None, "discount_type": "percentage", "discount_value": 7})
    res1 = _quote(svc, "2026-06-01", "2026-06-04", advance_days=30)
    res2 = _quote(svc, "2026-06-01", "2026-06-04", advance_days=30)
    # 3 × 10001 = 30003; 7% of 30003 = 2100 (floor)
    assert res1.los_discount_cents == 2100
    assert res1.model_dump() == res2.model_dump()


# ─── 21. Full-stack composition ──────────────────────────────────────────────

def test_full_stack_composition(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000, occ=2)
    _add_rule(svc, "season", {"start_date": "2026-06-01", "end_date": "2026-06-10", "mode": "absolute", "value_cents": 12000})
    _add_rule(svc, "weekend", {"dow": [6, 7], "mode": "delta", "value_cents": 2000})
    _add_rule(svc, "occupancy", {"extra_adult_cents": 1000, "extra_child_cents": 500})
    _add_rule(svc, "los", {"min_nights": 1, "max_nights": None, "discount_type": "percentage", "discount_value": 10})
    _add_rule(svc, "advance", {"days_before_checkin": 20, "comparator": "gte", "mode": "fixed_cents", "value": 1000})

    # 2026-06-05 (Fri), 2026-06-06 (Sat), 2026-06-07 (Sun)  → 3 nights
    # Jun 5 (Fri): season absolute 12000 + occ(1 extra adult × 1000 + 1 child × 500)=1500 → 13500
    # Jun 6 (Sat): season absolute 12000 + weekend delta 2000 = 14000 + occ 1500 → 15500
    # Jun 7 (Sun): season absolute 12000 + weekend delta 2000 = 14000 + occ 1500 → 15500
    res = svc.compute_stay_price(
        HOTEL_ID, RT_ID, "2026-06-05", "2026-06-08",
        adults=3, children=1, rooms=1, advance_days=25,
    )
    assert res.nights == 3
    assert res.per_night[0].night_total_cents == 13500
    assert res.per_night[1].night_total_cents == 15500
    assert res.per_night[2].night_total_cents == 15500
    subtotal = 13500 + 15500 + 15500  # 44500
    assert res.stay_subtotal_cents == subtotal
    assert res.stay_subtotal_cents == sum(l.night_total_cents for l in res.per_night)
    los_disc = subtotal * 10 // 100  # 4450
    assert res.los_discount_cents == los_disc
    post_los = subtotal - los_disc  # 40050
    # gte advance-purchase rule → modifier is negated (discount) → -1000
    assert res.advance_modifier_cents == -1000
    adv_signed = -1000  # the signed advance_modifier_cents value
    expected_total = max(0, (post_los + adv_signed) * 1)  # 40050 + (-1000) = 39050
    assert res.total_cents == expected_total
    assert len(res.applied_rule_ids) > 0


# ─── 22. Empty rule set ───────────────────────────────────────────────────────

def test_empty_rule_set(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    res = _quote(svc, "2026-06-01", "2026-06-04", advance_days=30)
    assert res.total_cents == 30000
    assert res.applied_rule_ids == []
    assert res.los_discount_cents == 0
    assert res.advance_modifier_cents == 0


# ─── 23. No rate plan → 404 ──────────────────────────────────────────────────

def test_no_rate_plan(svc_table):
    svc = svc_table
    with pytest.raises(HTTPException) as exc_info:
        svc.compute_stay_price("unknown_hotel", "unknown_rt", "2026-06-01", "2026-06-04", 2, 0, advance_days=30)
    assert exc_info.value.status_code == 404


# ─── 24. Inverted span → 422 ─────────────────────────────────────────────────

def test_inverted_span(svc_table):
    svc = svc_table
    _create_plan(svc)
    with pytest.raises(HTTPException) as exc_info:
        _quote(svc, "2026-06-04", "2026-06-01", advance_days=30)
    assert exc_info.value.status_code == 422
    assert "checkout" in exc_info.value.detail.lower()


def test_same_day_span(svc_table):
    svc = svc_table
    _create_plan(svc)
    with pytest.raises(HTTPException) as exc_info:
        _quote(svc, "2026-06-01", "2026-06-01", advance_days=30)
    assert exc_info.value.status_code == 422


# ─── 25. Determinism ─────────────────────────────────────────────────────────

def test_determinism(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    _add_rule(svc, "season", {"start_date": "2026-06-01", "end_date": "2026-06-10", "mode": "delta", "value_cents": 500})
    res1 = _quote(svc, "2026-06-01", "2026-06-04", advance_days=30)
    res2 = _quote(svc, "2026-06-01", "2026-06-04", advance_days=30)
    assert res1.model_dump() == res2.model_dump()


# ─── 26. Decimal coercion ────────────────────────────────────────────────────

def test_decimal_coercion_in_result(svc_table):
    svc = svc_table
    _create_plan(svc, rate=10000)
    res = _quote(svc, "2026-06-01", "2026-06-04", advance_days=30)
    assert type(res.nights) is int
    assert type(res.stay_subtotal_cents) is int
    assert type(res.total_cents) is int
    for line in res.per_night:
        assert type(line.night_total_cents) is int


# ─── 27. No dev_mode branch (SECOPS-007) ─────────────────────────────────────

def test_no_dev_mode_branch():
    from app.services import hotel_rate_plans as svc
    src = inspect.getsource(svc.compute_stay_price)
    assert "S.dev_mode" not in src


# ─── per-night floor ─────────────────────────────────────────────────────────

def test_per_night_floor(svc_table):
    """A large negative delta rule cannot drive a night below 0."""
    svc = svc_table
    _create_plan(svc, rate=5000)
    _add_rule(svc, "season", {"start_date": "2026-06-01", "end_date": "2026-06-30", "mode": "delta", "value_cents": -10000})
    res = _quote(svc, "2026-06-01", "2026-06-04", advance_days=30)
    for line in res.per_night:
        assert line.night_total_cents >= 0


# ─── rooms must be >= 1 ──────────────────────────────────────────────────────

def test_rooms_must_be_positive(svc_table):
    svc = svc_table
    _create_plan(svc)
    with pytest.raises(HTTPException) as exc_info:
        svc.compute_stay_price(HOTEL_ID, RT_ID, "2026-06-01", "2026-06-04", 2, 0, rooms=0, advance_days=30)
    assert exc_info.value.status_code == 422
