from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import registration


class _FakeSessionsTable:
    def __init__(self):
        self.items = {}

    def put_item(self, Item, **kwargs):
        self.items[(Item["user_sub"], Item["session_id"])] = dict(Item)
        return {}

    def get_item(self, Key, **kwargs):
        item = self.items.get((Key["user_sub"], Key["session_id"]))
        return {"Item": dict(item)} if item else {}

    def delete_item(self, Key, **kwargs):
        self.items.pop((Key["user_sub"], Key["session_id"]), None)
        return {}

    def update_item(self, Key, UpdateExpression=None, ExpressionAttributeValues=None, **kwargs):
        item = self.items.get((Key["user_sub"], Key["session_id"]))
        if not item:
            return {}
        if "code_attempts" in (UpdateExpression or ""):
            item["code_attempts"] = ExpressionAttributeValues[":c"]
            item["last_failed_at"] = ExpressionAttributeValues[":t"]
        self.items[(Key["user_sub"], Key["session_id"])] = item
        return {}


@pytest.fixture
def fake_tables(monkeypatch):
    sessions = _FakeSessionsTable()
    monkeypatch.setattr(registration, "T", SimpleNamespace(sessions=sessions, users=SimpleNamespace(get_item=lambda **_: {})))
    return sessions


def test_create_registration_challenge_writes_latest_pointer(fake_tables):
    code = registration.create_registration_challenge(
        user_sub="jane@example.com",
        channel="email",
        send_to="jane@example.com",
    )
    assert len(code) == 6
    latest = fake_tables.get_item(
        Key={"user_sub": "jane@example.com", "session_id": registration.REGISTRATION_LATEST_POINTER_ID}
    ).get("Item")
    assert latest is not None
    assert latest["challenge_id"].startswith(registration.REGISTRATION_CHALLENGE_PREFIX)


def test_verify_registration_code_uses_latest_challenge_pointer(fake_tables):
    first = registration.create_registration_challenge(
        user_sub="jane@example.com",
        channel="email",
        send_to="jane@example.com",
    )
    second = registration.create_registration_challenge(
        user_sub="jane@example.com",
        channel="email",
        send_to="jane@example.com",
    )

    with pytest.raises(HTTPException):
        registration.verify_registration_code(user_sub="jane@example.com", code=first)

    verified = registration.verify_registration_code(user_sub="jane@example.com", code=second)
    assert verified["user_sub"] == "jane@example.com"
    latest = fake_tables.get_item(
        Key={"user_sub": "jane@example.com", "session_id": registration.REGISTRATION_LATEST_POINTER_ID}
    ).get("Item")
    assert latest is None


def test_verify_registration_code_replay_attempt_denied(fake_tables):
    code = registration.create_registration_challenge(
        user_sub="jane@example.com",
        channel="email",
        send_to="jane@example.com",
    )
    verified = registration.verify_registration_code(user_sub="jane@example.com", code=code)
    assert verified["user_sub"] == "jane@example.com"
    with pytest.raises(HTTPException):
        registration.verify_registration_code(user_sub="jane@example.com", code=code)
