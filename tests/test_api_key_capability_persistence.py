from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import api_keys
from app.services.api_key_capabilities import CANONICAL_API_KEY_CAPABILITIES


class _FakeApiKeysTable:
    def __init__(self) -> None:
        self.items = {
            "legacy": {"key_id": "legacy", "user_sub": "u1", "label": "old", "created_at": 1},
        }

    def put_item(self, *, Item):
        self.items[Item["key_id"]] = dict(Item)

    def update_item(self, *, Key, UpdateExpression, ConditionExpression=None, ExpressionAttributeValues=None):
        item = self.items.get(Key["key_id"])
        if not item:
            raise RuntimeError("not found")
        if ConditionExpression and item.get("user_sub") != ExpressionAttributeValues.get(":u"):
            raise RuntimeError("not found")
        if "capabilities" in UpdateExpression:
            item["capabilities"] = list(ExpressionAttributeValues[":caps"])
            item["updated_at"] = int(ExpressionAttributeValues[":now"])

    def query(self, **kwargs):
        return {"Items": [dict(it) for it in self.items.values()]}

    def get_item(self, *, Key):
        it = self.items.get(Key["key_id"])
        return {"Item": dict(it)} if it else {}


class _FakeTables:
    def __init__(self) -> None:
        self.api_keys = _FakeApiKeysTable()
        self.entitlements = SimpleNamespace(query=lambda **_kwargs: {"Items": []})


def test_create_api_key_persists_normalized_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tables = _FakeTables()
    monkeypatch.setattr(api_keys, "T", fake_tables)
    monkeypatch.setattr(api_keys, "now_ts", lambda: 123)
    monkeypatch.setattr(api_keys, "new_api_key_secret", lambda: "secret")
    monkeypatch.setattr(api_keys, "api_key_hash", lambda secret: f"h::{secret}")
    monkeypatch.setattr(api_keys.secrets, "token_hex", lambda n: "kabc")

    out = api_keys.create_api_key("u1", "label", capabilities=[" TICKETS:READ ", "messager:write", "tickets:read"])

    assert out["capabilities"] == ["messager:write", "tickets:read"]
    stored = fake_tables.api_keys.items["kabc"]
    assert stored["capabilities"] == ["messager:write", "tickets:read"]


def test_set_api_key_capabilities_updates_existing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tables = _FakeTables()
    fake_tables.api_keys.items["k1"] = {"key_id": "k1", "user_sub": "u1"}
    monkeypatch.setattr(api_keys, "T", fake_tables)
    monkeypatch.setattr(api_keys, "now_ts", lambda: 555)

    out = api_keys.set_api_key_capabilities("u1", "k1", ["newsfeed:read", "tickets:read"])

    assert out == {"key_id": "k1", "capabilities": ["newsfeed:read", "tickets:read"]}
    assert fake_tables.api_keys.items["k1"]["capabilities"] == ["newsfeed:read", "tickets:read"]


def test_set_api_key_capabilities_rejects_unknown_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api_keys, "T", _FakeTables())

    with pytest.raises(HTTPException) as exc:
        api_keys.set_api_key_capabilities("u1", "legacy", ["tickets:delete"])
    assert exc.value.status_code == 400


def test_create_api_key_rejects_unknown_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api_keys, "T", _FakeTables())
    monkeypatch.setattr(api_keys, "now_ts", lambda: 123)
    monkeypatch.setattr(api_keys, "new_api_key_secret", lambda: "secret")
    monkeypatch.setattr(api_keys, "api_key_hash", lambda secret: f"h::{secret}")
    monkeypatch.setattr(api_keys.secrets, "token_hex", lambda n: "kxyz")

    with pytest.raises(HTTPException) as exc:
        api_keys.create_api_key("u1", "label", capabilities=["tickets:delete"])
    assert exc.value.status_code == 400


def test_list_api_keys_uses_legacy_full_capability_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tables = _FakeTables()
    monkeypatch.setattr(api_keys, "T", fake_tables)
    monkeypatch.setattr(api_keys, "S", SimpleNamespace(api_keys_user_index="user_sub-index"))

    keys = api_keys.list_api_keys("u1")

    assert len(keys) == 1
    assert keys[0]["capabilities"] == list(CANONICAL_API_KEY_CAPABILITIES)


def test_get_api_key_item_includes_legacy_full_capability_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tables = _FakeTables()
    monkeypatch.setattr(api_keys, "T", fake_tables)

    item = api_keys.get_api_key_item("legacy")
    assert item["capabilities"] == list(CANONICAL_API_KEY_CAPABILITIES)


def test_set_api_key_capabilities_rejects_out_of_plan_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tables = _FakeTables()
    fake_tables.api_keys.items["k1"] = {"key_id": "k1", "user_sub": "u1"}
    fake_tables.entitlements = SimpleNamespace(
        query=lambda **_kwargs: {
            "Items": [
                {
                    "status": "active",
                    "scope": {"route_allowlist": ["GET:/tickets"]},
                }
            ]
        }
    )
    monkeypatch.setattr(api_keys, "T", fake_tables)
    monkeypatch.setattr(api_keys, "now_ts", lambda: 100)

    with pytest.raises(HTTPException) as exc:
        api_keys.set_api_key_capabilities("u1", "k1", ["tickets:write"])
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "api_key_scopes_out_of_plan"
