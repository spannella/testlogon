from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.routers import newsfeed
from app.services.sessions import require_ui_session


class _FakeNewsfeedTable:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], Dict[str, Any]] = {}

    def put_item(self, *, Item: Dict[str, Any]) -> None:
        self.items[(Item["pk"], Item["sk"])] = deepcopy(Item)

    def get_item(self, *, Key: Dict[str, Any]) -> Dict[str, Any]:
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": deepcopy(item)} if item else {}

    def query(self, **kwargs) -> Dict[str, Any]:
        vals = kwargs.get("ExpressionAttributeValues", {})
        pk = vals.get(":pk")
        items = [deepcopy(item) for item in self.items.values() if item.get("GSI1PK") == pk]
        items.sort(key=lambda it: it.get("GSI1SK", ""), reverse=not kwargs.get("ScanIndexForward", True))
        limit = kwargs.get("Limit")
        if limit is not None:
            items = items[: int(limit)]
        return {"Items": items}


class _FakeDDB:
    def __init__(self, table: _FakeNewsfeedTable) -> None:
        self._table = table

    def batch_get_item(self, *, RequestItems: Dict[str, Any]) -> Dict[str, Any]:
        req = next(iter(RequestItems.values()))
        keys = req.get("Keys", [])
        rows = []
        for key in keys:
            item = self._table.items.get((key["pk"], key["sk"]))
            if item:
                rows.append(deepcopy(item))
        return {"Responses": {newsfeed.APP_TABLE: rows}}


def _build_client(user_sub: str, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, _FakeNewsfeedTable]:
    fake_table = _FakeNewsfeedTable()
    app = create_app()

    async def _session_override():
        return {"user_sub": user_sub, "session_id": "sess_1", "role": "user"}

    app.dependency_overrides[require_ui_session] = _session_override

    monkeypatch.setattr(newsfeed, "tbl", fake_table)
    monkeypatch.setattr(newsfeed, "ddb", _FakeDDB(fake_table))
    monkeypatch.setattr(newsfeed, "_enforce_newsfeed_post_quota_precheck", lambda user_id: None)
    monkeypatch.setattr(newsfeed, "_meter_newsfeed_post_publish", lambda user_id, post_id: None)

    # Patch services that view_feed calls via lazy imports (added after these tests were
    # first written) to prevent real DynamoDB calls in unit/integration tests.
    import app.services.blocking as _blocking_mod
    import app.services.social as _social_mod
    import app.services.ad_feedback as _ad_fb_mod
    import app.services.content_boost as _cb_mod
    monkeypatch.setattr(_blocking_mod, "get_blocked_set", lambda user_id: set())
    monkeypatch.setattr(_blocking_mod, "get_blocked_by_set", lambda user_id: set())
    monkeypatch.setattr(_social_mod, "get_snoozed_following_ids", lambda user_id: set())
    monkeypatch.setattr(_ad_fb_mod, "get_hidden_ad_ids", lambda user_id: set())
    monkeypatch.setattr(_cb_mod, "elevate_feed_items", lambda items, **kw: items)

    return TestClient(app), fake_table


def test_api_create_get_and_feed_include_tip_lottery_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    client, _ = _build_client("user-lottery", monkeypatch)

    created = client.post(
        "/posts",
        json={
            "body": "lottery post",
            "lock_type": "tip_lottery",
            "lottery_tip_cents": 125,
            "lottery_quiet_period_seconds": 90,
        },
    )
    assert created.status_code == 200
    body = created.json()
    assert body["lock_type"] == "tip_lottery"
    assert body["lottery_tip_cents"] == 125
    assert body["lottery_quiet_period_seconds"] == 90
    assert body["lottery_state"] == "open"
    assert body["lottery_version"] == 0

    post_id = body["post_id"]
    fetched = client.get(f"/posts/{post_id}")
    assert fetched.status_code == 200
    fetched_body = fetched.json()
    assert fetched_body["lock_type"] == "tip_lottery"
    assert fetched_body["lottery_tip_cents"] == 125
    assert fetched_body["lottery_quiet_period_seconds"] == 90

    feed = client.get("/feed")
    assert feed.status_code == 200
    items = feed.json().get("items", [])
    assert any(item["post_id"] == post_id and item["lock_type"] == "tip_lottery" for item in items)


def test_api_legacy_fixed_price_reads_infer_lock_type(monkeypatch: pytest.MonkeyPatch) -> None:
    client, table = _build_client("user-legacy", monkeypatch)

    post_id = "post_legacy_1"
    created_at = "2026-01-01T00:00:00+00:00"
    table.put_item(
        Item={
            "pk": newsfeed.pk_post(post_id),
            "sk": newsfeed.sk_post(),
            "Entity": "Post",
            "post_id": post_id,
            "user_id": "user-legacy",
            "created_at": created_at,
            "body": "legacy fixed body",
            "locked": True,
            "unlock_price_cents": 250,
        },
    )
    table.put_item(
        Item={
            "pk": newsfeed.pk_post(post_id),
            "sk": "FEEDREF#user-legacy",
            "Entity": "FeedRef",
            "post_id": post_id,
            "owner_user_id": "user-legacy",
            "created_at": created_at,
            "GSI1PK": "FEED#user-legacy",
            "GSI1SK": f"{created_at}#POST#{post_id}",
        },
    )

    fetched = client.get(f"/posts/{post_id}")
    assert fetched.status_code == 200
    assert fetched.json()["lock_type"] == "fixed_price"

    feed = client.get("/feed")
    assert feed.status_code == 200
    item = next(i for i in feed.json()["items"] if i["post_id"] == post_id)
    assert item["lock_type"] == "fixed_price"

    stored = table.items[(newsfeed.pk_post(post_id), newsfeed.sk_post())]
    assert "lock_type" not in stored
