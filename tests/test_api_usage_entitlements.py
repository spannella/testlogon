from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import api_usage_entitlements as svc


class _EntitlementsTable:
    name = "entitlements"

    def __init__(self, items):
        self.items = items

    def query(self, **_kwargs):
        return {"Items": list(self.items)}


class _UsageEventsTable:
    name = "entitlement_usage_events"


class _EntTableName:
    name = "entitlements"


class _Client:
    def __init__(self):
        self.calls = []
        self.raise_quota = False
        self.raise_duplicate = False

    def transact_write_items(self, **kwargs):
        self.calls.append(kwargs)
        if self.raise_quota:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "ConditionalCheckFailed"}}, "TransactWriteItems")
        if self.raise_duplicate:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "ConditionalCheckFailed"}}, "TransactWriteItems")


def _req(route="GET:/v1/x", user="u1", key="key_1", req_id="r1"):
    return SimpleNamespace(
        headers={"x-user-sub": user, "x-api-key": key, "x-request-id": req_id},
        scope={"method": route.split(":", 1)[0], "route": SimpleNamespace(path=route.split(":", 1)[1])},
        url=SimpleNamespace(path=route.split(":", 1)[1]),
        method=route.split(":", 1)[0],
    )


def test_denies_unauthorized_route_with_deterministic_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc)
    items = [{
        "entitlement_id": "e1",
        "product_type": "api_package",
        "status": "active",
        "starts_at": (now - timedelta(days=1)).isoformat(),
        "ends_at": (now + timedelta(days=1)).isoformat(),
        "access_template": {"route_allowlist": ["POST:/v1/allowed"]},
    }]
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable(items), entitlement_usage_events=_UsageEventsTable()))
    monkeypatch.setattr(svc, "ddb", SimpleNamespace(meta=SimpleNamespace(client=_Client())))
    monkeypatch.setattr(svc, "route_id_from_request", lambda _r: "GET:/v1/denied")
    monkeypatch.setattr(svc, "record_api_usage_limit_deny", lambda **_kwargs: None)

    with pytest.raises(HTTPException) as exc:
        svc.enforce_api_package_entitlement_pre_request(_req(route="GET:/v1/denied"))
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "api_entitlement_denied"
    assert exc.value.detail["reason"] == "unauthorized_route"


def test_quota_exceeded_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc)
    items = [{
        "entitlement_id": "e2",
        "product_type": "api_package",
        "status": "active",
        "starts_at": (now - timedelta(days=1)).isoformat(),
        "ends_at": (now + timedelta(days=1)).isoformat(),
        "limit_overrides": {"monthly_call_limit": 1},
    }]
    client = _Client(); client.raise_quota = True
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable(items), entitlement_usage_events=_UsageEventsTable()))
    monkeypatch.setattr(svc, "ddb", SimpleNamespace(meta=SimpleNamespace(client=client)))
    monkeypatch.setattr(svc, "route_id_from_request", lambda _r: "GET:/v1/ok")
    monkeypatch.setattr(svc, "record_api_usage_limit_deny", lambda **_kwargs: None)

    with pytest.raises(HTTPException) as exc:
        svc.enforce_api_package_entitlement_pre_request(_req(route="GET:/v1/ok"))
    assert exc.value.detail["reason"] == "quota_exceeded"


def test_success_sets_observability_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc)
    items = [{
        "entitlement_id": "e3",
        "product_type": "api_package",
        "status": "active",
        "starts_at": (now - timedelta(days=1)).isoformat(),
        "ends_at": None,
        "usage_limit": 100,
        "access_template": {"route_allowlist": ["GET:/v1/ok"]},
    }]
    client = _Client()
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable(items), entitlement_usage_events=_UsageEventsTable()))
    monkeypatch.setattr(svc, "ddb", SimpleNamespace(meta=SimpleNamespace(client=client)))
    monkeypatch.setattr(svc, "route_id_from_request", lambda _r: "GET:/v1/ok")
    monkeypatch.setattr(svc, "record_api_usage_limit_deny", lambda **_kwargs: None)
    threshold_calls = []
    monkeypatch.setattr(svc, "emit_usage_threshold_alerts", lambda **kwargs: threshold_calls.append(kwargs))

    headers = svc.enforce_api_package_entitlement_pre_request(_req(route="GET:/v1/ok"))
    assert headers["x-api-entitlement-id"] == "e3"
    assert headers["x-api-entitlement-route"] == "GET:/v1/ok"
    assert "x-api-entitlement-idempotency" in headers
    assert threshold_calls and threshold_calls[0]["usage_consumed"] == 1


def test_api_entitlement_bypassed_when_family_flag_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True, catalog_api_package_enabled=False))
    out = svc.enforce_api_package_entitlement_pre_request(_req(route="GET:/v1/denied"))
    assert out == {}
