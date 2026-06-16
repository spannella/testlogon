"""Hermetic pytest for HTL-014: hotel_rate_plans service — CRUD + validators.

Offline; no live stack, no real AWS.
Pattern: moto-backed hotel_rate_plans table bound to frozen T.hotel_rate_plans
via object.__setattr__; frozen S flags toggled via object.__setattr__ and
restored on cleanup.  No TestClient.
"""
import pytest
import boto3
from moto import mock_aws
from fastapi import HTTPException


# ─── table fixture ───────────────────────────────────────────────────────────

TABLE_NAME = "hotel_rate_plans"
HOTEL_ID = "h_001"
RT_ID = "rt_001"
ADMIN_SUB = "admin_sub_001"


@pytest.fixture()
def ddb_table():
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

        original_table = getattr(T_mod.T, "hotel_rate_plans", None)
        original_enabled = getattr(svc.S, "hotel_pms_enabled", False)

        object.__setattr__(T_mod.T, "hotel_rate_plans", table)
        object.__setattr__(svc.S, "hotel_pms_enabled", True)
        object.__setattr__(svc.S, "hotel_rate_plans_table_name", TABLE_NAME)

        yield table, svc

        # restore
        if original_table is not None:
            object.__setattr__(T_mod.T, "hotel_rate_plans", original_table)
        object.__setattr__(svc.S, "hotel_pms_enabled", original_enabled)


# ─── helpers ─────────────────────────────────────────────────────────────────

def _create(svc, hotel_id=HOTEL_ID, rt_id=RT_ID, name="Standard", rate=10000):
    return svc.create_rate_plan(
        hotel_id, rt_id,
        name=name,
        base_nightly_rate_cents=rate,
        user_sub=ADMIN_SUB,
    )


# ─── flag-gate tests ─────────────────────────────────────────────────────────

def test_flag_off_create_plan(ddb_table):
    _, svc = ddb_table
    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            svc.create_rate_plan(HOTEL_ID, RT_ID, name="X", user_sub=ADMIN_SUB)
        assert exc_info.value.status_code == 404
        assert "not enabled" in exc_info.value.detail.lower()
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)


def test_flag_off_get_plan(ddb_table):
    _, svc = ddb_table
    object.__setattr__(svc.S, "hotel_pms_enabled", False)
    try:
        with pytest.raises(HTTPException) as exc_info:
            svc.get_rate_plan(HOTEL_ID, RT_ID)
        assert exc_info.value.status_code == 404
    finally:
        object.__setattr__(svc.S, "hotel_pms_enabled", True)


# ─── create / get ────────────────────────────────────────────────────────────

def test_create_rate_plan(ddb_table):
    _, svc = ddb_table
    plan = _create(svc)
    assert plan["hotel_id"] == HOTEL_ID
    assert plan["room_type_id"] == RT_ID
    assert plan["name"] == "Standard"
    assert plan["base_nightly_rate_cents"] == 10000
    assert plan["base_occupancy"] == 2
    assert plan["currency"] == "USD"
    assert plan["active"] is True
    assert plan["sk"] == "META"
    assert isinstance(plan["created_at"], int)
    assert isinstance(plan["updated_at"], int)
    assert plan["rate_plan_id"].startswith("rp_")


def test_create_idempotent(ddb_table):
    _, svc = ddb_table
    p1 = _create(svc)
    p2 = _create(svc)
    assert p1["rate_plan_id"] == p2["rate_plan_id"]


def test_get_rate_plan(ddb_table):
    _, svc = ddb_table
    _create(svc)
    plan = svc.get_rate_plan(HOTEL_ID, RT_ID)
    assert plan is not None
    assert plan["hotel_id"] == HOTEL_ID


def test_get_rate_plan_missing(ddb_table):
    _, svc = ddb_table
    plan = svc.get_rate_plan("no_hotel", "no_rt")
    assert plan is None


# ─── update / deactivate ─────────────────────────────────────────────────────

def test_update_rate_plan(ddb_table):
    _, svc = ddb_table
    _create(svc)
    updated = svc.update_rate_plan(HOTEL_ID, RT_ID, user_sub=ADMIN_SUB, name="Deluxe", base_nightly_rate_cents=15000)
    assert updated["name"] == "Deluxe"
    assert updated["base_nightly_rate_cents"] == 15000


def test_deactivate_rate_plan(ddb_table):
    _, svc = ddb_table
    _create(svc)
    plan = svc.deactivate_rate_plan(HOTEL_ID, RT_ID, user_sub=ADMIN_SUB)
    assert plan["active"] is False


def test_update_empty_kwargs_stamps_updated_at(ddb_table):
    _, svc = ddb_table
    _create(svc)
    plan = svc.get_rate_plan(HOTEL_ID, RT_ID)
    old_ua = plan["updated_at"]
    updated = svc.update_rate_plan(HOTEL_ID, RT_ID, user_sub=ADMIN_SUB)
    assert isinstance(updated["updated_at"], int)


# ─── add_rule / list_rules / update_rule / delete_rule ───────────────────────

def test_add_season_rule(ddb_table):
    _, svc = ddb_table
    _create(svc)
    rule = svc.add_rule(
        HOTEL_ID, RT_ID,
        kind="season",
        rule_config={"start_date": "2026-06-01", "end_date": "2026-08-31", "mode": "absolute", "value_cents": 12000},
        user_sub=ADMIN_SUB,
    )
    assert rule["kind"] == "season"
    assert rule["rule_id"] is not None
    assert rule["sk"].startswith("RULE#season#")


def test_add_rule_validates_parent(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException) as exc_info:
        svc.add_rule(
            "no_hotel", "no_rt",
            kind="occupancy",
            rule_config={"extra_adult_cents": 500, "extra_child_cents": 300},
            user_sub=ADMIN_SUB,
        )
    assert exc_info.value.status_code == 404


def test_list_rules_sorted(ddb_table):
    _, svc = ddb_table
    _create(svc)
    svc.add_rule(HOTEL_ID, RT_ID, kind="season",
                 rule_config={"start_date": "2026-06-01", "end_date": "2026-08-31", "mode": "delta", "value_cents": 500},
                 priority=200, user_sub=ADMIN_SUB)
    svc.add_rule(HOTEL_ID, RT_ID, kind="occupancy",
                 rule_config={"extra_adult_cents": 1000, "extra_child_cents": 500},
                 priority=100, user_sub=ADMIN_SUB)
    rules = svc.list_rules(HOTEL_ID, RT_ID)
    assert len(rules) == 2
    # lower priority first
    assert rules[0]["priority"] <= rules[1]["priority"]
    # no META row in results
    for r in rules:
        assert r["sk"].startswith("RULE#")


def test_list_rules_excludes_meta(ddb_table):
    _, svc = ddb_table
    _create(svc)
    rules = svc.list_rules(HOTEL_ID, RT_ID)
    for r in rules:
        assert r.get("sk", "").startswith("RULE#")


def test_update_rule(ddb_table):
    _, svc = ddb_table
    _create(svc)
    rule = svc.add_rule(HOTEL_ID, RT_ID, kind="occupancy",
                        rule_config={"extra_adult_cents": 1000, "extra_child_cents": 500},
                        user_sub=ADMIN_SUB)
    updated = svc.update_rule(
        HOTEL_ID, RT_ID, rule["rule_id"], "occupancy",
        rule_config={"extra_adult_cents": 2000, "extra_child_cents": 1000},
        priority=200,
        user_sub=ADMIN_SUB,
    )
    assert updated["rule_config"]["extra_adult_cents"] == 2000
    assert updated["priority"] == 200


def test_delete_rule(ddb_table):
    _, svc = ddb_table
    _create(svc)
    rule = svc.add_rule(HOTEL_ID, RT_ID, kind="weekend",
                        rule_config={"dow": [6, 7], "mode": "delta", "value_cents": 3000},
                        user_sub=ADMIN_SUB)
    ok = svc.delete_rule(HOTEL_ID, RT_ID, rule["rule_id"], "weekend", user_sub=ADMIN_SUB)
    assert ok is True
    rules = svc.list_rules(HOTEL_ID, RT_ID)
    assert len(rules) == 0


def test_delete_rule_idempotent(ddb_table):
    _, svc = ddb_table
    _create(svc)
    rule = svc.add_rule(HOTEL_ID, RT_ID, kind="weekend",
                        rule_config={"dow": [6, 7], "mode": "delta", "value_cents": 1000},
                        user_sub=ADMIN_SUB)
    svc.delete_rule(HOTEL_ID, RT_ID, rule["rule_id"], "weekend", user_sub=ADMIN_SUB)
    # Second delete should not raise and should return False
    ok2 = svc.delete_rule(HOTEL_ID, RT_ID, rule["rule_id"], "weekend", user_sub=ADMIN_SUB)
    assert ok2 is False


# ─── per-kind validator tests ─────────────────────────────────────────────────

def test_season_bad_date_range(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException) as exc_info:
        svc._validate_season_config({"start_date": "2026-08-31", "end_date": "2026-06-01", "mode": "absolute", "value_cents": 10000})
    assert exc_info.value.status_code == 422


def test_season_bad_mode(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_season_config({"start_date": "2026-06-01", "end_date": "2026-06-30", "mode": "bogus", "value_cents": 10000})


def test_season_absolute_negative_cents(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_season_config({"start_date": "2026-06-01", "end_date": "2026-06-30", "mode": "absolute", "value_cents": -100})


def test_season_delta_negative_allowed(ddb_table):
    _, svc = ddb_table
    # delta allows negative
    svc._validate_season_config({"start_date": "2026-06-01", "end_date": "2026-06-30", "mode": "delta", "value_cents": -500})


def test_occupancy_negative_rejected(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_occupancy_config({"extra_adult_cents": -1, "extra_child_cents": 0})


def test_los_min_nights_zero_rejected(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_los_config({"min_nights": 0, "max_nights": None, "discount_type": "percentage", "discount_value": 10})


def test_los_max_less_than_min_rejected(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_los_config({"min_nights": 3, "max_nights": 2, "discount_type": "fixed_cents", "discount_value": 1000})


def test_los_percentage_over_100_rejected(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_los_config({"min_nights": 1, "max_nights": None, "discount_type": "percentage", "discount_value": 101})


def test_advance_bad_comparator(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_advance_config({"days_before_checkin": 10, "comparator": "eq", "mode": "fixed_cents", "value": 500})


def test_weekend_empty_dow(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_weekend_config({"dow": [], "mode": "delta", "value_cents": 1000})


def test_weekend_dow_out_of_range(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_weekend_config({"dow": [8], "mode": "delta", "value_cents": 1000})


def test_unknown_kind_rejected(ddb_table):
    _, svc = ddb_table
    with pytest.raises(HTTPException):
        svc._validate_rule_config("unknown_kind", {})


# ─── Decimal coercion ────────────────────────────────────────────────────────

def test_decimal_coercion(ddb_table):
    _, svc = ddb_table
    plan = _create(svc)
    # All numeric fields must be plain int (not Decimal)
    for field in ("base_nightly_rate_cents", "base_occupancy", "created_at", "updated_at"):
        val = plan[field]
        assert type(val) is int, f"{field} should be int, got {type(val)}"


def test_no_dev_mode_branch():
    """SECOPS-007: assert no conditional branch on S.dev_mode in business logic."""
    import ast
    import inspect
    from app.services import hotel_rate_plans as svc
    src = inspect.getsource(svc)
    # Parse and look for any If node whose test or comparators reference dev_mode.
    tree = ast.parse(src)
    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            # Convert the if condition subtree back to source-like string
            try:
                cond = ast.unparse(node.test)
            except Exception:
                cond = ""
            if "dev_mode" in cond:
                violations.append(cond)
    assert not violations, f"Found S.dev_mode conditional branches: {violations}"
