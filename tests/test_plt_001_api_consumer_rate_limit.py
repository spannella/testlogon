"""PLT-001 hermetic unit tests: per-consumer API rate-limit middleware."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Module-scope autouse fixture: save/restore frozen S and T.sessions
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True, scope="module")
def _patch_s_and_tables():
    """Bind moto sessions table and set S flags. Restores on teardown."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        tbl = ddb.create_table(
            TableName="sessions_test",
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
        tbl.meta.client.get_waiter("table_exists").wait(TableName="sessions_test")

        from app.core.tables import T
        from app.core.settings import S

        orig_sessions = T.sessions
        orig_obp = S.open_bank_project_enabled
        orig_enabled = S.api_consumer_rate_limit_enabled
        orig_minute = S.api_consumer_rate_limit_minute
        orig_hour = S.api_consumer_rate_limit_hour
        orig_day = S.api_consumer_rate_limit_day
        orig_week = S.api_consumer_rate_limit_week
        orig_month = S.api_consumer_rate_limit_month
        orig_ddb_sessions = S.ddb_sessions_table

        object.__setattr__(T, "sessions", tbl)
        object.__setattr__(S, "ddb_sessions_table", "sessions_test")  # enable bucket
        object.__setattr__(S, "open_bank_project_enabled", True)
        object.__setattr__(S, "api_consumer_rate_limit_enabled", True)
        object.__setattr__(S, "api_consumer_rate_limit_minute", 0)
        object.__setattr__(S, "api_consumer_rate_limit_hour", 0)
        object.__setattr__(S, "api_consumer_rate_limit_day", 0)
        object.__setattr__(S, "api_consumer_rate_limit_week", 0)
        object.__setattr__(S, "api_consumer_rate_limit_month", 0)

        yield tbl

        object.__setattr__(T, "sessions", orig_sessions)
        object.__setattr__(S, "ddb_sessions_table", orig_ddb_sessions)
        object.__setattr__(S, "open_bank_project_enabled", orig_obp)
        object.__setattr__(S, "api_consumer_rate_limit_enabled", orig_enabled)
        object.__setattr__(S, "api_consumer_rate_limit_minute", orig_minute)
        object.__setattr__(S, "api_consumer_rate_limit_hour", orig_hour)
        object.__setattr__(S, "api_consumer_rate_limit_day", orig_day)
        object.__setattr__(S, "api_consumer_rate_limit_week", orig_week)
        object.__setattr__(S, "api_consumer_rate_limit_month", orig_month)


def _reset_buckets(tbl):
    """Clear all rate-limit bucket rows between sub-tests."""
    resp = tbl.scan()
    with tbl.batch_writer() as batch:
        for item in resp.get("Items", []):
            batch.delete_item(Key={"user_sub": item["user_sub"], "session_id": item["session_id"]})


# ---------------------------------------------------------------------------
# Test 1: Flag off → no-op
# ---------------------------------------------------------------------------

def test_flag_off_noop(_patch_s_and_tables):
    """With PLT-001 flag off, rate_limit_api_consumer never raises."""
    from app.core.settings import S
    from app.services.rate_limit import rate_limit_api_consumer

    object.__setattr__(S, "api_consumer_rate_limit_enabled", False)
    object.__setattr__(S, "api_consumer_rate_limit_hour", 2)
    try:
        with patch("app.services.rate_limit._get_api_key_item_for_rl", return_value={"key_id": "k1"}):
            for _ in range(1000):
                rate_limit_api_consumer("k1", "GET:/v1/test")
    finally:
        object.__setattr__(S, "api_consumer_rate_limit_enabled", True)
        object.__setattr__(S, "api_consumer_rate_limit_hour", 0)


# ---------------------------------------------------------------------------
# Test 2: Single window allow → deny
# ---------------------------------------------------------------------------

def test_single_window_allow_then_deny(_patch_s_and_tables):
    """5 requests succeed, 6th raises 429 on hour window."""
    tbl = _patch_s_and_tables
    _reset_buckets(tbl)

    from app.core.settings import S
    from app.services.rate_limit import rate_limit_api_consumer

    object.__setattr__(S, "api_consumer_rate_limit_hour", 5)
    try:
        with patch("app.services.rate_limit._get_api_key_item_for_rl", return_value={"key_id": "ka1"}):
            for _ in range(5):
                rate_limit_api_consumer("ka1", "GET:/v1/test")
            with pytest.raises(HTTPException) as exc_info:
                rate_limit_api_consumer("ka1", "GET:/v1/test")
            assert exc_info.value.status_code == 429
            detail = exc_info.value.detail
            assert detail["code"] == "api_consumer_rate_limited"
            assert detail["window"] == "hour"
            assert detail["limit"] == 5
    finally:
        object.__setattr__(S, "api_consumer_rate_limit_hour", 0)
        _reset_buckets(tbl)


# ---------------------------------------------------------------------------
# Test 3: Window reset after expiry
# ---------------------------------------------------------------------------

def test_window_reset(_patch_s_and_tables):
    """After denial, advancing time beyond the window allows requests again."""
    tbl = _patch_s_and_tables
    _reset_buckets(tbl)

    from app.core.settings import S
    from app.services.rate_limit import rate_limit_api_consumer

    object.__setattr__(S, "api_consumer_rate_limit_hour", 2)
    _ts = [1000000]

    def fake_now():
        return _ts[0]

    try:
        with patch("app.services.rate_limit._get_api_key_item_for_rl", return_value={"key_id": "kb1"}), \
             patch("app.services.rate_limit.now_ts", side_effect=fake_now):
            rate_limit_api_consumer("kb1", "GET:/v1/test")
            rate_limit_api_consumer("kb1", "GET:/v1/test")
            with pytest.raises(HTTPException):
                rate_limit_api_consumer("kb1", "GET:/v1/test")
            # Advance time past the window
            _ts[0] += 3601
            # Should succeed now (bucket reset)
            rate_limit_api_consumer("kb1", "GET:/v1/test")
    finally:
        object.__setattr__(S, "api_consumer_rate_limit_hour", 0)
        _reset_buckets(tbl)


# ---------------------------------------------------------------------------
# Test 4: Narrowest window fires first
# ---------------------------------------------------------------------------

def test_narrowest_window_first(_patch_s_and_tables):
    """Minute window exhausted first even though hour cap is high."""
    tbl = _patch_s_and_tables
    _reset_buckets(tbl)

    from app.core.settings import S
    from app.services.rate_limit import rate_limit_api_consumer

    object.__setattr__(S, "api_consumer_rate_limit_minute", 2)
    object.__setattr__(S, "api_consumer_rate_limit_hour", 1000)
    try:
        with patch("app.services.rate_limit._get_api_key_item_for_rl", return_value={"key_id": "kc1"}):
            rate_limit_api_consumer("kc1", "GET:/v1/test")
            rate_limit_api_consumer("kc1", "GET:/v1/test")
            with pytest.raises(HTTPException) as exc_info:
                rate_limit_api_consumer("kc1", "GET:/v1/test")
            assert exc_info.value.detail["window"] == "minute"
    finally:
        object.__setattr__(S, "api_consumer_rate_limit_minute", 0)
        object.__setattr__(S, "api_consumer_rate_limit_hour", 0)
        _reset_buckets(tbl)


# ---------------------------------------------------------------------------
# Test 5: Zero cap skips window
# ---------------------------------------------------------------------------

def test_zero_cap_skips_window(_patch_s_and_tables):
    """minute=0 means disabled; hour=3 enforces correctly."""
    tbl = _patch_s_and_tables
    _reset_buckets(tbl)

    from app.core.settings import S
    from app.services.rate_limit import rate_limit_api_consumer

    object.__setattr__(S, "api_consumer_rate_limit_minute", 0)
    object.__setattr__(S, "api_consumer_rate_limit_hour", 3)
    try:
        with patch("app.services.rate_limit._get_api_key_item_for_rl", return_value={"key_id": "kd1"}):
            rate_limit_api_consumer("kd1", "GET:/v1/test")
            rate_limit_api_consumer("kd1", "GET:/v1/test")
            rate_limit_api_consumer("kd1", "GET:/v1/test")
            with pytest.raises(HTTPException) as exc_info:
                rate_limit_api_consumer("kd1", "GET:/v1/test")
            assert exc_info.value.detail["window"] == "hour"
    finally:
        object.__setattr__(S, "api_consumer_rate_limit_minute", 0)
        object.__setattr__(S, "api_consumer_rate_limit_hour", 0)
        _reset_buckets(tbl)


# ---------------------------------------------------------------------------
# Test 6: Per-key override supersedes account default
# ---------------------------------------------------------------------------

def test_per_key_override(_patch_s_and_tables):
    """rate_limit_overrides on the key item supersede account defaults."""
    tbl = _patch_s_and_tables
    _reset_buckets(tbl)

    from app.core.settings import S
    from app.services.rate_limit import rate_limit_api_consumer

    object.__setattr__(S, "api_consumer_rate_limit_hour", 10)
    try:
        fake_item = {"key_id": "ke1", "rate_limit_overrides": {"hour": 2}}
        with patch("app.services.rate_limit._get_api_key_item_for_rl", return_value=fake_item):
            rate_limit_api_consumer("ke1", "GET:/v1/test")
            rate_limit_api_consumer("ke1", "GET:/v1/test")
            with pytest.raises(HTTPException) as exc_info:
                rate_limit_api_consumer("ke1", "GET:/v1/test")
            assert exc_info.value.detail["limit"] == 2
    finally:
        object.__setattr__(S, "api_consumer_rate_limit_hour", 0)
        _reset_buckets(tbl)


# ---------------------------------------------------------------------------
# Test 7: Override guardrail
# ---------------------------------------------------------------------------

def test_override_guardrail(_patch_s_and_tables):
    """Attempting to set rate_limit_overrides above account ceiling raises 400."""
    from app.core.settings import S
    from app.services.api_keys import set_api_key_self_limits

    object.__setattr__(S, "api_consumer_rate_limit_hour", 100)
    try:
        # Mock T.api_keys.update_item to succeed; only guardrail should fire
        with patch("app.services.api_keys.T") as mock_T:
            mock_T.api_keys.update_item = MagicMock()
            with pytest.raises(HTTPException) as exc_info:
                set_api_key_self_limits(
                    "user1",
                    "key1",
                    monthly_calls_cap=0,
                    monthly_spend_cap_micros=0,
                    route_caps=None,
                    rate_limit_overrides={"hour": 200},
                )
            assert exc_info.value.status_code == 400
            assert "hour" in exc_info.value.detail
    finally:
        object.__setattr__(S, "api_consumer_rate_limit_hour", 0)


# ---------------------------------------------------------------------------
# Test 8: Separate keys have separate budgets
# ---------------------------------------------------------------------------

def test_separate_keys_have_separate_budgets(_patch_s_and_tables):
    """Exhausting key A's budget does not affect key B."""
    tbl = _patch_s_and_tables
    _reset_buckets(tbl)

    from app.core.settings import S
    from app.services.rate_limit import rate_limit_api_consumer

    object.__setattr__(S, "api_consumer_rate_limit_minute", 1)
    try:
        fake_a = {"key_id": "kf1"}
        fake_b = {"key_id": "kf2"}

        def side_effect(key_id):
            return fake_a if key_id == "kf1" else fake_b

        with patch("app.services.rate_limit._get_api_key_item_for_rl", side_effect=side_effect):
            rate_limit_api_consumer("kf1", "GET:/v1/test")  # allowed
            with pytest.raises(HTTPException):
                rate_limit_api_consumer("kf1", "GET:/v1/test")  # denied
            # key B still allowed
            rate_limit_api_consumer("kf2", "GET:/v1/test")
    finally:
        object.__setattr__(S, "api_consumer_rate_limit_minute", 0)
        _reset_buckets(tbl)


# ---------------------------------------------------------------------------
# Test 9: Revoked key skips throttling
# ---------------------------------------------------------------------------

def test_revoked_key_skips_throttling(_patch_s_and_tables):
    """Revoked key items are treated as missing — no throttling applied."""
    from app.services.rate_limit import rate_limit_api_consumer
    from app.core.settings import S

    object.__setattr__(S, "api_consumer_rate_limit_hour", 1)
    try:
        revoked_item = {"key_id": "kg1", "revoked": True}
        with patch("app.services.rate_limit._get_api_key_item_for_rl", return_value=revoked_item):
            # Should never raise even though cap=1
            for _ in range(10):
                rate_limit_api_consumer("kg1", "GET:/v1/test")
    finally:
        object.__setattr__(S, "api_consumer_rate_limit_hour", 0)
