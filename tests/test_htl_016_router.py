"""Hermetic pytest for HTL-016: hotel_rate_plans router + quote endpoint.

Tests the FastAPI route handlers directly (not via TestClient).
Pattern: moto-backed table + frozen T/S, async handlers called on a fresh
asyncio.new_event_loop(), auth dependencies stubbed via simple DI objects.
"""
import asyncio
import pytest
import boto3
from moto import mock_aws
from fastapi import HTTPException
from unittest.mock import MagicMock


TABLE_NAME = "hotel_rate_plans"
HOTEL_ID = "h_016"
RT_ID = "rt_016"
ADMIN_SUB = "admin_016"


# ─── fake auth objects ────────────────────────────────────────────────────────

class _FakeUser:
    sub = ADMIN_SUB

class _FakeSession:
    user_sub = ADMIN_SUB


# ─── table fixture ───────────────────────────────────────────────────────────

@pytest.fixture()
def rt_setup():
    """Set up moto DDB + inject into T + enable flag."""
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

        yield svc, table

        object.__setattr__(svc.S, "hotel_pms_enabled", False)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ─── router handler imports ───────────────────────────────────────────────────

from app.routers.hotel_rate_plans import (
    create_rate_plan,
    get_rate_plan,
    update_rate_plan,
    deactivate_rate_plan,
    list_rate_plans,
    list_rules,
    add_rule,
    update_rule,
    delete_rule,
    quote_stay,
)
from app.models import (
    RatePlanIn,
    RatePlanUpdateIn,
    RatePlanRuleIn,
    StayQuoteIn,
)


def _plan_body(**kwargs):
    return RatePlanIn(
        room_type_id=RT_ID,
        name=kwargs.get("name", "Test Plan"),
        base_nightly_rate_cents=kwargs.get("rate", 10000),
        base_occupancy=kwargs.get("occ", 2),
        currency=kwargs.get("currency", "USD"),
    )


# ─── test: create + get plan via router ──────────────────────────────────────

def test_router_create_plan(rt_setup):
    svc, _ = rt_setup
    body = _plan_body()
    result = _run(create_rate_plan(HOTEL_ID, body, _FakeUser()))
    assert result.hotel_id == HOTEL_ID
    assert result.room_type_id == RT_ID
    assert result.base_nightly_rate_cents == 10000
    assert result.active is True


def test_router_get_plan(rt_setup):
    svc, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    result = _run(get_rate_plan(HOTEL_ID, RT_ID, _FakeSession()))
    assert result.hotel_id == HOTEL_ID


def test_router_get_plan_missing(rt_setup):
    _, _ = rt_setup
    with pytest.raises(HTTPException) as exc_info:
        _run(get_rate_plan(HOTEL_ID, RT_ID, _FakeSession()))
    assert exc_info.value.status_code == 404


def test_router_update_plan(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    body = RatePlanUpdateIn(name="Luxury", base_nightly_rate_cents=20000)
    result = _run(update_rate_plan(HOTEL_ID, RT_ID, body, _FakeUser()))
    assert result.name == "Luxury"
    assert result.base_nightly_rate_cents == 20000


def test_router_deactivate_plan(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    result = _run(deactivate_rate_plan(HOTEL_ID, RT_ID, _FakeUser()))
    assert result.active is False


def test_router_list_rate_plans(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    result = _run(list_rate_plans(HOTEL_ID, session=_FakeSession()))
    assert "rate_plans" in result
    assert len(result["rate_plans"]) >= 1


# ─── test: rule CRUD via router ──────────────────────────────────────────────

def test_router_add_rule(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    body = RatePlanRuleIn(
        kind="occupancy",
        rule_config={"extra_adult_cents": 1000, "extra_child_cents": 500},
    )
    result = _run(add_rule(HOTEL_ID, RT_ID, body, _FakeUser()))
    assert result.kind == "occupancy"
    assert result.rule_config["extra_adult_cents"] == 1000


def test_router_list_rules(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    body = RatePlanRuleIn(
        kind="weekend",
        rule_config={"dow": [6, 7], "mode": "delta", "value_cents": 2000},
    )
    _run(add_rule(HOTEL_ID, RT_ID, body, _FakeUser()))
    rules = _run(list_rules(HOTEL_ID, RT_ID, _FakeSession()))
    assert len(rules) == 1
    assert rules[0].kind == "weekend"


def test_router_update_rule(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    add_body = RatePlanRuleIn(
        kind="occupancy",
        rule_config={"extra_adult_cents": 1000, "extra_child_cents": 500},
    )
    rule = _run(add_rule(HOTEL_ID, RT_ID, add_body, _FakeUser()))
    upd_body = RatePlanRuleIn(
        kind="occupancy",
        rule_config={"extra_adult_cents": 2000, "extra_child_cents": 1000},
        priority=300,
    )
    updated = _run(update_rule(HOTEL_ID, RT_ID, rule.rule_id, upd_body, _FakeUser()))
    assert updated.rule_config["extra_adult_cents"] == 2000
    assert updated.priority == 300


def test_router_delete_rule(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    add_body = RatePlanRuleIn(
        kind="weekend",
        rule_config={"dow": [6, 7], "mode": "delta", "value_cents": 1000},
    )
    rule = _run(add_rule(HOTEL_ID, RT_ID, add_body, _FakeUser()))
    result = _run(delete_rule(HOTEL_ID, RT_ID, rule.rule_id, "weekend", _FakeUser()))
    assert result["ok"] is True


def test_router_delete_rule_unknown(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    result = _run(delete_rule(HOTEL_ID, RT_ID, "nonexistent_rule_id", "season", _FakeUser()))
    assert result["ok"] is False


def test_router_delete_rule_invalid_kind(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(), _FakeUser()))
    with pytest.raises(HTTPException) as exc_info:
        _run(delete_rule(HOTEL_ID, RT_ID, "some_id", "invalid_kind", _FakeUser()))
    assert exc_info.value.status_code == 422


# ─── test: quote endpoint ─────────────────────────────────────────────────────

def test_router_quote_flat(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(rate=10000), _FakeUser()))
    body = StayQuoteIn(checkin="2026-06-01", checkout="2026-06-04", adults=2, advance_days=30)
    result = _run(quote_stay(HOTEL_ID, RT_ID, body, _FakeSession()))
    assert result.nights == 3
    assert result.total_cents == 30000
    assert result.currency == "USD"


def test_router_quote_with_rules(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(rate=10000), _FakeUser()))
    _run(add_rule(HOTEL_ID, RT_ID, RatePlanRuleIn(
        kind="los",
        rule_config={"min_nights": 1, "max_nights": None, "discount_type": "percentage", "discount_value": 10},
    ), _FakeUser()))
    body = StayQuoteIn(checkin="2026-06-01", checkout="2026-06-04", adults=2, advance_days=30)
    result = _run(quote_stay(HOTEL_ID, RT_ID, body, _FakeSession()))
    assert result.los_discount_cents == 3000
    assert result.total_cents == 27000


def test_router_quote_los_rejection(rt_setup):
    _, _ = rt_setup
    _run(create_rate_plan(HOTEL_ID, _plan_body(rate=10000), _FakeUser()))
    _run(add_rule(HOTEL_ID, RT_ID, RatePlanRuleIn(
        kind="los",
        rule_config={"min_nights": 5, "max_nights": None, "discount_type": "fixed_cents", "discount_value": 0},
    ), _FakeUser()))
    body = StayQuoteIn(checkin="2026-06-01", checkout="2026-06-03", adults=2, advance_days=30)
    with pytest.raises(HTTPException) as exc_info:
        _run(quote_stay(HOTEL_ID, RT_ID, body, _FakeSession()))
    assert exc_info.value.status_code == 422


def test_router_flag_off(rt_setup):
    svc, _ = rt_setup
    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        body = StayQuoteIn(checkin="2026-06-01", checkout="2026-06-04", adults=2, advance_days=30)
        with pytest.raises(HTTPException) as exc_info:
            _run(quote_stay(HOTEL_ID, RT_ID, body, _FakeSession()))
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)
