from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import api_metering_policy as policy


def test_parse_status_classes_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        policy._parse_status_classes("2xx,6xx", default={"2xx"})


def test_classify_api_call_default_policy() -> None:
    p = policy.ApiUsagePolicy(
        billable_status_classes={"2xx"},
        quota_status_classes={"2xx", "4xx", "5xx"},
        rate_limit_billable=False,
        rate_limit_counts_toward_quota=True,
        auth_failed_billable=False,
        auth_failed_counts_toward_quota=True,
    )

    success = policy.classify_api_call(200, policy=p)
    client_err = policy.classify_api_call(404, policy=p)
    server_err = policy.classify_api_call(503, policy=p)

    assert success.billable is True and success.counts_toward_quota is True
    assert client_err.billable is False and client_err.counts_toward_quota is True
    assert server_err.billable is False and server_err.counts_toward_quota is True


def test_classify_api_call_rate_limit_and_auth_overrides() -> None:
    p = policy.ApiUsagePolicy(
        billable_status_classes={"2xx"},
        quota_status_classes={"2xx", "4xx", "5xx"},
        rate_limit_billable=False,
        rate_limit_counts_toward_quota=True,
        auth_failed_billable=False,
        auth_failed_counts_toward_quota=True,
    )

    rate_limited = policy.classify_api_call(429, is_rate_limited=True, policy=p)
    auth_failed = policy.classify_api_call(401, is_auth_failed=True, policy=p)

    assert rate_limited.reason == "rate_limited"
    assert rate_limited.billable is False
    assert rate_limited.counts_toward_quota is True

    assert auth_failed.reason == "auth_failed"
    assert auth_failed.billable is False
    assert auth_failed.counts_toward_quota is True


def test_load_api_usage_policy_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        policy,
        "S",
        SimpleNamespace(
            api_usage_billable_status_classes="2xx,4xx",
            api_usage_quota_status_classes="2xx,4xx,5xx",
            api_usage_rate_limit_billable=True,
            api_usage_rate_limit_counts_toward_quota=True,
            api_usage_auth_failed_billable=False,
            api_usage_auth_failed_counts_toward_quota=False,
        ),
    )
    loaded = policy.load_api_usage_policy()
    assert loaded.billable_status_classes == {"2xx", "4xx"}
    assert loaded.quota_status_classes == {"2xx", "4xx", "5xx"}
    assert loaded.rate_limit_billable is True
    assert loaded.auth_failed_counts_toward_quota is False


def test_limit_denial_payload_contract_and_exception() -> None:
    detail = policy.build_limit_denial_detail(
        limit_type="monthly_calls",
        scope="api_key",
        current=1001,
        limit=1000,
        reset_at=1738368000,
        route_id="POST:/v1/messages/send",
        api_key_id="k_123",
    )
    assert detail == {
        "code": "api_limit_exceeded",
        "limit_type": "monthly_calls",
        "scope": "api_key",
        "current": 1001,
        "limit": 1000,
        "reset_at": 1738368000,
        "route_id": "POST:/v1/messages/send",
        "api_key_id": "k_123",
    }

    with pytest.raises(HTTPException) as exc:
        policy.raise_limit_denied(
            limit_type="monthly_calls",
            scope="account",
            current=5001,
            limit=5000,
            reset_at=1738368000,
        )
    assert exc.value.status_code == 429
    assert exc.value.detail["code"] == "api_limit_exceeded"


def test_limit_denial_headers_include_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy.time, "time", lambda: 1000)
    headers = policy.build_limit_denial_headers({
        "code": "api_limit_exceeded",
        "limit_type": "rpm",
        "scope": "account",
        "current": 10,
        "limit": 10,
        "reset_at": 1015,
    })

    assert headers["x-api-limit-code"] == "api_limit_exceeded"
    assert headers["x-api-limit-type"] == "rpm"
    assert headers["x-api-limit-current"] == "10"
    assert headers["x-api-limit-limit"] == "10"
    assert headers["x-api-limit-reset-at"] == "1015"
    assert headers["retry-after"] == "15"
