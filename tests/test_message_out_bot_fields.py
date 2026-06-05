"""Regression test for GAP-0014.

`_message_out_from_item` declared five bot-specific fields on MessageOut
(`sender_type`, `bot_id`, `bot_name`, `bot_avatar_url`, `quick_replies`) but
never populated them from the stored DynamoDB item, so bot messages were
returned stripped of all bot metadata.

This test invokes `_message_out_from_item` directly with plain dicts (the same
offline, infrastructure-free pattern used by tests/test_voicemail.py). No dev
stack, no moto, no real AWS.

Before the fix: bot fields are all None even when present in the item -> FAIL.
After the fix:  bot fields are surfaced; non-bot messages keep them None.
"""
from __future__ import annotations

import os
import sys
import time
from unittest.mock import patch

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def _mock_env(monkeypatch):
    monkeypatch.setenv("DEV_MODE", "1")
    monkeypatch.setenv("DDB_ENDPOINT_URL", "http://localhost:8001")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("UI_ACCESS_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")


_CONV_ID = "c_bottest001"
_VIEWER = "alice"


def _project(item):
    from app.routers import messaging

    with patch.object(messaging, "S") as mock_s:
        mock_s.dev_mode = True
        return messaging._message_out_from_item(item, _VIEWER)


def _base_item(**overrides):
    item = {
        "conversation_id": _CONV_ID,
        "message_id": "m_" + "a" * 32,
        "sender_id": _VIEWER,
        "created_at": int(time.time()),
        "kind": "text",
        "text": "hello",
        "status": "active",
        "is_encrypted": False,
        "view_once": False,
        "reactions": {},
    }
    item.update(overrides)
    return item


def test_bot_fields_are_surfaced():
    item = _base_item(
        message_id="m_" + "b" * 32,
        sender_id="bot:bot_123",
        sender_type="bot",
        bot_id="bot_123",
        bot_name="HelperBot",
        bot_avatar_url="https://cdn.example.com/bot.png",
        quick_replies=[
            {"label": "Yes", "value": "yes"},
            {"label": "No", "value": "no"},
        ],
        text="Which option?",
    )

    out = _project(item)

    assert out.sender_type == "bot"
    assert out.bot_id == "bot_123"
    assert out.bot_name == "HelperBot"
    assert out.bot_avatar_url == "https://cdn.example.com/bot.png"
    assert isinstance(out.quick_replies, list) and len(out.quick_replies) == 2
    assert out.quick_replies[0]["label"] == "Yes"


def test_non_bot_message_has_no_bot_fields():
    out = _project(_base_item())

    assert out.sender_type is None
    assert out.bot_id is None
    assert out.bot_name is None
    assert out.bot_avatar_url is None
    # empty/absent quick_replies normalized to None (excluded by exclude_none)
    assert out.quick_replies is None


def test_empty_quick_replies_normalized_to_none():
    out = _project(_base_item(sender_type="user", quick_replies=[]))

    assert out.quick_replies is None
