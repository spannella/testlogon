from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import api_keys


class _FakeApiKeysTable:
    def __init__(self) -> None:
        self.items = {
            "k1": {"key_id": "k1", "user_sub": "u1"},
        }

    def update_item(self, *, Key, UpdateExpression, ConditionExpression=None, ExpressionAttributeValues=None):
        item = self.items.get(Key["key_id"])
        if not item or (ConditionExpression and item.get("user_sub") != ExpressionAttributeValues.get(":u")):
            raise RuntimeError("not found")
        item["monthly_calls_cap"] = int(ExpressionAttributeValues[":mc"])
        item["monthly_spend_cap_micros"] = int(ExpressionAttributeValues[":ms"])
        item["route_caps"] = ExpressionAttributeValues[":rc"]
        item["updated_at"] = int(ExpressionAttributeValues[":now"])

    def get_item(self, *, Key):
        it = self.items.get(Key["key_id"])
        return {"Item": dict(it)} if it else {}


class _FakeTables:
    def __init__(self) -> None:
        self.api_keys = _FakeApiKeysTable()


def test_set_api_key_self_limits_persists(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api_keys, "T", _FakeTables())
    monkeypatch.setattr(api_keys, "now_ts", lambda: 123)
    monkeypatch.setattr(
        api_keys,
        "S",
        SimpleNamespace(api_usage_account_monthly_calls_limit=1000, api_usage_account_monthly_spend_micros_limit=5000),
    )

    out = api_keys.set_api_key_self_limits(
        "u1",
        "k1",
        monthly_calls_cap=500,
        monthly_spend_cap_micros=2000,
        route_caps={"get:/ui/api_keys": {"monthly_calls_cap": 100, "monthly_spend_cap_micros": 400}},
    )

    assert out["monthly_calls_cap"] == 500
    assert out["monthly_spend_cap_micros"] == 2000
    assert "GET:/ui/api_keys" in out["route_caps"]

    stored = api_keys.get_api_key_item("k1")
    assert stored["monthly_calls_cap"] == 500


def test_set_api_key_self_limits_validates_guardrails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api_keys, "T", _FakeTables())
    monkeypatch.setattr(api_keys, "now_ts", lambda: 123)
    monkeypatch.setattr(
        api_keys,
        "S",
        SimpleNamespace(api_usage_account_monthly_calls_limit=100, api_usage_account_monthly_spend_micros_limit=1000),
    )

    with pytest.raises(HTTPException) as exc:
        api_keys.set_api_key_self_limits(
            "u1",
            "k1",
            monthly_calls_cap=200,
            monthly_spend_cap_micros=500,
            route_caps={},
        )
    assert exc.value.status_code == 400
