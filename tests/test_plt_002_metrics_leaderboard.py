"""PLT-002 hermetic unit tests: Top-N API usage metrics leaderboard."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi import HTTPException


@pytest.fixture(autouse=True, scope="module")
def _setup_moto_and_settings():
    """Create moto api_usage_events table, toggle settings, restore on teardown."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = ddb.create_table(
            TableName="api_usage_events_test",
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
        tbl.meta.client.get_waiter("table_exists").wait(TableName="api_usage_events_test")

        from app.core.settings import S

        orig_obp = S.open_bank_project_enabled
        orig_lb = S.metrics_leaderboard_enabled
        orig_max = S.metrics_leaderboard_max_top_n
        orig_admin = getattr(S, "filemgr_admin_users", "")

        object.__setattr__(S, "open_bank_project_enabled", True)
        object.__setattr__(S, "metrics_leaderboard_enabled", True)
        object.__setattr__(S, "metrics_leaderboard_max_top_n", 100)
        object.__setattr__(S, "filemgr_admin_users", "admin_sub")

        yield tbl

        object.__setattr__(S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(S, "metrics_leaderboard_enabled", orig_lb)
        object.__setattr__(S, "metrics_leaderboard_max_top_n", orig_max)
        object.__setattr__(S, "filemgr_admin_users", orig_admin)


def _seed_key_row(tbl, user_sub, api_key_id, period_id, calls_total, cost=0, ru=0, billable=0):
    tbl.put_item(Item={
        "PK": f"USER#{user_sub}",
        "SK": f"API_USAGE#KEY#{api_key_id}#PERIOD#{period_id}",
        "entity_type": "api_key_usage_period_totals",
        "user_sub": user_sub,
        "api_key_id": api_key_id,
        "period_id": period_id,
        "calls_total": calls_total,
        "billable_calls_total": billable,
        "request_units_total": ru,
        "cost_subtotal_micros": cost,
    })


def _seed_route_row(tbl, user_sub, route_id, period_id, calls_total, cost=0, ru=0, billable=0):
    tbl.put_item(Item={
        "PK": f"USER#{user_sub}",
        "SK": f"API_USAGE#ROUTE#{route_id}#PERIOD#{period_id}",
        "entity_type": "api_route_usage_period_totals",
        "user_sub": user_sub,
        "route_id": route_id,
        "period_id": period_id,
        "calls_total": calls_total,
        "billable_calls_total": billable,
        "request_units_total": ru,
        "cost_subtotal_micros": cost,
        "unit_price_micros": 1000,
    })


# Test 1: Flag off returns 404
def test_flag_off_returns_404(_setup_moto_and_settings):
    from app.core.settings import S
    from app.routers.admin_usage import get_api_usage_leaderboard

    object.__setattr__(S, "metrics_leaderboard_enabled", False)
    try:
        req = MagicMock()
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(HTTPException) as exc_info:
                loop.run_until_complete(get_api_usage_leaderboard(
                    req=req, admin_user="admin_sub",
                ))
            assert exc_info.value.status_code == 404
        finally:
            loop.close()
    finally:
        object.__setattr__(S, "metrics_leaderboard_enabled", True)


# Test 2: Consumers ranked by calls_total descending
def test_consumers_ranking_by_calls_total(_setup_moto_and_settings):
    tbl = _setup_moto_and_settings
    _seed_key_row(tbl, "alice", "key_alice", "2026-06", 300)
    _seed_key_row(tbl, "bob", "key_bob", "2026-06", 100)
    _seed_key_row(tbl, "carol", "key_carol", "2026-06", 200)

    from app.services.api_usage_metering import aggregate_leaderboard

    with patch("app.routers.admin_usage._api_usage_table", return_value=tbl):
        result = aggregate_leaderboard(tbl, period_id="2026-06", dimension="consumers", metric="calls_total", top_n=10)

    items = result["items"]
    assert len(items) == 3
    assert items[0]["calls_total"] == 300
    assert items[1]["calls_total"] == 200
    assert items[2]["calls_total"] == 100
    assert result["total"] == 3


# Test 3: Endpoints cross-user merge
def test_endpoints_ranking_cross_user_merge(_setup_moto_and_settings):
    tbl = _setup_moto_and_settings
    # Two users each calling the same route
    _seed_route_row(tbl, "alice", "GET:/v1/accounts", "2026-06", calls_total=50, cost=5000)
    _seed_route_row(tbl, "bob", "GET:/v1/accounts", "2026-06", calls_total=30, cost=3000)
    _seed_route_row(tbl, "alice", "GET:/v1/transactions", "2026-06", calls_total=10, cost=1000)

    from app.services.api_usage_metering import aggregate_leaderboard

    result = aggregate_leaderboard(tbl, period_id="2026-06", dimension="endpoints", metric="cost_subtotal_micros", top_n=10)
    items = result["items"]
    # Find the merged accounts row
    accounts_row = next((r for r in items if r.get("route_id") == "GET:/v1/accounts"), None)
    assert accounts_row is not None
    assert accounts_row["cost_subtotal_micros"] == 8000  # 5000 + 3000
    assert accounts_row["user_sub"] == ""  # cross-user


# Test 4: top_n clamping
def test_top_n_clamp(_setup_moto_and_settings):
    tbl = _setup_moto_and_settings
    for i in range(5):
        _seed_key_row(tbl, f"user{i}", f"key{i}", "2026-07", i + 1)

    from app.services.api_usage_metering import aggregate_leaderboard
    result = aggregate_leaderboard(tbl, period_id="2026-07", dimension="consumers", metric="calls_total", top_n=2)
    assert len(result["items"]) == 2
    assert result["total"] == 5


# Test 5: max top_n clamp from S setting
def test_top_n_max_clamp(_setup_moto_and_settings):
    tbl = _setup_moto_and_settings
    from app.core.settings import S
    from app.routers.admin_usage import get_api_usage_leaderboard

    object.__setattr__(S, "metrics_leaderboard_max_top_n", 3)
    try:
        req = MagicMock()
        loop = asyncio.new_event_loop()
        try:
            with patch("app.routers.admin_usage._api_usage_table", return_value=tbl):
                with patch("app.routers.admin_usage.audit_event"):
                    result = loop.run_until_complete(
                        get_api_usage_leaderboard(req=req, top_n=200, admin_user="admin_sub")
                    )
            assert len(result.items) <= 3
        finally:
            loop.close()
    finally:
        object.__setattr__(S, "metrics_leaderboard_max_top_n", 100)


# Test 6: dimension=consumers vs dimension=endpoints
def test_dimension_consumers_vs_endpoints(_setup_moto_and_settings):
    tbl = _setup_moto_and_settings
    _seed_key_row(tbl, "uX", "keyX", "2026-08", 999)
    _seed_route_row(tbl, "uX", "GET:/v1/test", "2026-08", 888)

    from app.services.api_usage_metering import aggregate_leaderboard

    r_consumers = aggregate_leaderboard(tbl, period_id="2026-08", dimension="consumers", metric="calls_total", top_n=10)
    r_endpoints = aggregate_leaderboard(tbl, period_id="2026-08", dimension="endpoints", metric="calls_total", top_n=10)

    # Consumers should have api_key_id field
    assert all("api_key_id" in r for r in r_consumers["items"])
    # Endpoints should have route_id field
    assert all("route_id" in r for r in r_endpoints["items"])


# Test 7: Wrong period returns empty
def test_wrong_period_returns_empty(_setup_moto_and_settings):
    tbl = _setup_moto_and_settings
    _seed_key_row(tbl, "uW", "keyW", "2026-05", 100)

    from app.services.api_usage_metering import aggregate_leaderboard
    result = aggregate_leaderboard(tbl, period_id="2026-99", dimension="consumers", metric="calls_total", top_n=10)
    assert result["items"] == []


# Test 8: Admin auth required (403 for non-admin)
def test_admin_auth_required(_setup_moto_and_settings):
    from app.core.settings import S
    from app.routers.admin_usage import get_api_usage_leaderboard

    object.__setattr__(S, "filemgr_admin_users", "only_admin_sub")
    try:
        from app.routers.admin_usage import _require_admin_user
        with pytest.raises(HTTPException) as exc_info:
            _require_admin_user(user_sub="random_user")
        assert exc_info.value.status_code == 403
    finally:
        object.__setattr__(S, "filemgr_admin_users", "admin_sub")


# Test 9: Audit event emitted
def test_audit_event_emitted(_setup_moto_and_settings):
    tbl = _setup_moto_and_settings
    from app.routers.admin_usage import get_api_usage_leaderboard

    req = MagicMock()
    loop = asyncio.new_event_loop()
    try:
        with patch("app.routers.admin_usage._api_usage_table", return_value=tbl), \
             patch("app.routers.admin_usage.audit_event") as mock_audit:
            loop.run_until_complete(
                get_api_usage_leaderboard(req=req, admin_user="admin_sub")
            )
        mock_audit.assert_called_once()
        call_args = mock_audit.call_args
        assert call_args[0][0] == "api_usage_leaderboard_view"
    finally:
        loop.close()


# Test 10: Null table returns empty leaderboard
def test_null_table_returns_empty(_setup_moto_and_settings):
    from app.routers.admin_usage import get_api_usage_leaderboard

    req = MagicMock()
    loop = asyncio.new_event_loop()
    try:
        with patch("app.routers.admin_usage._api_usage_table", return_value=None), \
             patch("app.routers.admin_usage.audit_event"):
            result = loop.run_until_complete(
                get_api_usage_leaderboard(req=req, admin_user="admin_sub")
            )
        assert result.items == []
        assert result.total_rows_scanned == 0
    finally:
        loop.close()
