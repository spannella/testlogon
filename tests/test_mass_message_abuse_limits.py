from __future__ import annotations

from collections import deque
from unittest.mock import patch

import pytest

pytest.importorskip("anyio")
pytest.importorskip("fastapi")

from fastapi import HTTPException

from app.routers import messaging


def _reset_mass_limit_state() -> None:
    with messaging._MASS_MESSAGE_RATE_LOCK:
        messaging._MASS_MESSAGE_USER_CREATE_TS.clear()
        messaging._MASS_MESSAGE_TENANT_CREATE_TS.clear()
        messaging._MASS_MESSAGE_ACTIVE_WORKERS = 0


def test_enforce_create_limits_blocks_excess_destinations_with_clear_error() -> None:
    _reset_mass_limit_state()
    with (
        patch.object(
            messaging,
            "_mass_message_limits_config",
            return_value={
                "campaigns_per_user_per_hour": 20,
                "campaigns_per_tenant_per_hour": 500,
                "max_destinations_per_campaign": 1,
                "max_concurrent_workers": 8,
            },
        ),
        patch.object(messaging, "record_mass_message_limit_event") as metric,
    ):
        with pytest.raises(HTTPException) as exc:
            messaging._enforce_mass_message_create_limits(user_id="u1", mode="immediate", destination_count=2)

    assert exc.value.status_code == 429
    assert exc.value.detail["code"] == "mass_send_destinations_limit_exceeded"
    metric.assert_called_with(scope="campaign", limit_name="destinations_per_campaign", outcome="blocked")


def test_enforce_create_limits_blocks_user_rate_limit() -> None:
    _reset_mass_limit_state()
    with messaging._MASS_MESSAGE_RATE_LOCK:
        messaging._MASS_MESSAGE_USER_CREATE_TS["u1"] = deque([1700000000])
        messaging._MASS_MESSAGE_TENANT_CREATE_TS["default"] = deque([])
    with (
        patch.object(messaging, "now_ts", return_value=1700000001),
        patch.object(
            messaging,
            "_mass_message_limits_config",
            return_value={
                "campaigns_per_user_per_hour": 1,
                "campaigns_per_tenant_per_hour": 500,
                "max_destinations_per_campaign": 100,
                "max_concurrent_workers": 8,
            },
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            messaging._enforce_mass_message_create_limits(user_id="u1", mode="immediate", destination_count=1)
    assert exc.value.status_code == 429
    assert exc.value.detail["code"] == "mass_send_user_rate_limited"


def test_enforce_create_limits_blocks_tenant_rate_limit() -> None:
    _reset_mass_limit_state()
    with messaging._MASS_MESSAGE_RATE_LOCK:
        messaging._MASS_MESSAGE_USER_CREATE_TS["u1"] = deque([])
        messaging._MASS_MESSAGE_TENANT_CREATE_TS["default"] = deque([1700000000])
    with (
        patch.object(messaging, "now_ts", return_value=1700000001),
        patch.object(
            messaging,
            "_mass_message_limits_config",
            return_value={
                "campaigns_per_user_per_hour": 10,
                "campaigns_per_tenant_per_hour": 1,
                "max_destinations_per_campaign": 100,
                "max_concurrent_workers": 8,
            },
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            messaging._enforce_mass_message_create_limits(user_id="u1", mode="scheduled", destination_count=1)
    assert exc.value.status_code == 429
    assert exc.value.detail["code"] == "mass_send_tenant_rate_limited"


def test_enforce_create_limits_blocks_immediate_when_worker_pool_full() -> None:
    _reset_mass_limit_state()
    with messaging._MASS_MESSAGE_RATE_LOCK:
        messaging._MASS_MESSAGE_ACTIVE_WORKERS = 2
    with patch.object(
        messaging,
        "_mass_message_limits_config",
        return_value={
            "campaigns_per_user_per_hour": 20,
            "campaigns_per_tenant_per_hour": 500,
            "max_destinations_per_campaign": 100,
            "max_concurrent_workers": 2,
        },
    ):
        with pytest.raises(HTTPException) as exc:
            messaging._enforce_mass_message_create_limits(user_id="u1", mode="immediate", destination_count=1)
    assert exc.value.status_code == 429
    assert exc.value.detail["code"] == "mass_send_worker_capacity_exceeded"


def test_create_campaign_endpoint_returns_clear_429_when_worker_pool_full() -> None:
    _reset_mass_limit_state()
    req = messaging.MassMessageCreateCampaignRequest(
        conversation_ids=["c1"],
        content={"kind": "text", "text": "hello"},
        mode="immediate",
    )
    with (
        patch.object(messaging, "_messaging_mass_send_enabled", return_value=True),
        patch.object(messaging, "_mass_message_limits_config", return_value={"campaigns_per_user_per_hour": 20, "campaigns_per_tenant_per_hour": 500, "max_destinations_per_campaign": 100, "max_concurrent_workers": 1}),
        patch.object(messaging, "_MASS_MESSAGE_ACTIVE_WORKERS", 1),
    ):
        with pytest.raises(HTTPException) as exc:
            messaging.create_mass_message_campaign(req, user_id="u1")
    assert exc.value.status_code == 429
    assert exc.value.detail["code"] == "mass_send_worker_capacity_exceeded"
