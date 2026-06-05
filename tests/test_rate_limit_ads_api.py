"""Regression test for GAP-0056 — per-API-key rate limiting on the advertiser API.

Drives the rate-limit middleware directly against a moto-backed DynamoDB
``rate_limits`` table (fully offline, no real AWS). Asserts that requests to
``/api/v1/ads/*`` carrying an API-key header are throttled per ``api_key_id``
once the ``ads_api`` group's ``max_requests_per_api_key`` window is exceeded.

Fails before fix: ``_extract_user_from_request`` never extracts an API-key
identity and the ``ads_api`` group does not exist, so no per-key bucket is
checked and the request is never rejected with 429.
"""
from __future__ import annotations

import asyncio

import boto3
import pytest
from moto import mock_aws
from starlette.datastructures import Headers


class _FakeURL:
    def __init__(self, path: str) -> None:
        self.path = path


class _FakeClient:
    host = "203.0.113.10"


class _FakeRequest:
    """Minimal stand-in for starlette Request sufficient for the middleware."""

    def __init__(self, path: str, headers: dict[str, str]) -> None:
        self.url = _FakeURL(path)
        self.method = "GET"
        self.headers = Headers(headers)
        self.cookies = {}
        self.client = _FakeClient()


# A well-formed API key (ak_<key_id>.<secret>); only the key_id is parsed.
_API_KEY = "ak_advkey0001.supersecretvalue"
_KEY_ID = "advkey0001"
_ADS_PATH = "/api/v1/ads/account"


def _make_table():
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    ddb.create_table(
        TableName="rate_limits",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return ddb.Table("rate_limits")


@mock_aws
def test_ads_api_per_key_rate_limit_returns_429_after_window_exceeded(monkeypatch, request):
    table = _make_table()

    # Wire the moto table into the store + config modules and disable the
    # dev-mode multiplier so the configured cap is enforced verbatim.
    from app.core import tables as tables_mod
    from app.services import rate_limit_config
    from app.core.settings import S
    from app.middleware import rate_limit as mw

    # T is a frozen dataclass and T.rate_limits is a _FloatSafeTable proxy with
    # __slots__; swap its wrapped boto3 table in for the moto one.
    rl_proxy = tables_mod.T.rate_limits
    original_inner = rl_proxy._t
    object.__setattr__(rl_proxy, "_t", table)
    request.addfinalizer(lambda: object.__setattr__(rl_proxy, "_t", original_inner))

    # Settings is a frozen dataclass singleton; patch via object.__setattr__ and
    # restore the originals afterward.
    def _set_setting(name, value):
        original = getattr(S, name)
        object.__setattr__(S, name, value)
        request.addfinalizer(lambda: object.__setattr__(S, name, original))

    _set_setting("dev_mode", False)
    _set_setting("rate_limit_global_enabled", True)
    _set_setting("rate_limit_per_endpoint_enabled", True)
    _set_setting("rate_limit_fail_open", False)
    _set_setting("rate_limit_global_ip_max_requests", 100000)

    # Bust the config cache so our patched table is read.
    rate_limit_config._CONFIG_CACHE.clear()
    rate_limit_config._CONFIG_CACHE_TS.clear()

    # Lower the ads_api per-key cap to make the test fast & deterministic.
    # (Guarded so this test exercises the *behavioral* 429 assertion below even
    # before the fix lands — i.e. it fails on missing throttling, not on setup.)
    cfg = rate_limit_config.ENDPOINT_GROUPS.get("ads_api")
    if cfg is not None:
        monkeypatch.setitem(cfg, "max_requests_per_api_key", 5)
        monkeypatch.setitem(cfg, "max_requests_per_ip", 100000)

    middleware = mw.rate_limit_middleware_factory()

    async def _passthrough(_request):
        from starlette.responses import JSONResponse
        return JSONResponse(status_code=200, content={"ok": True})

    async def _run():
        statuses = []
        for _ in range(8):
            req = _FakeRequest(_ADS_PATH, {"x-api-key": _API_KEY})
            resp = await middleware(req, _passthrough)
            statuses.append(resp.status_code)
        return statuses

    statuses = asyncio.run(_run())

    # First 5 allowed, 6th onward throttled with 429.
    assert statuses[:5] == [200, 200, 200, 200, 200], statuses
    assert statuses[5] == 429, statuses
    assert all(s == 429 for s in statuses[5:]), statuses

    # Confirm the per-key bucket key was used (keyed by api_key_id, not IP).
    item = table.get_item(
        Key={"pk": f"ENDPOINT#ads_api#APIKEY#{_KEY_ID}", "sk": "GLOBAL"}
    ).get("Item")
    assert item is not None
    assert int(item["count"]) >= 5
