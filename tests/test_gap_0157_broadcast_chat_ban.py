"""Regression test for GAP-0157.

A viewer who has been banned from a broadcast (per-session ban written to
``T.broadcast_moderation`` keyed ``SESSION#{session_id}`` / ``BAN#{user_id}`` by
``ban_viewer`` in ``app/services/delegate_broadcast.py``) must not be able to
post chat messages. Before the fix, ``send_chat_message`` only enforced the
per-session mute and rate limit and never consulted the ban record.

Fails-before: ``send_chat_message`` never calls ``is_viewer_banned`` so the
banned viewer's message is accepted.
Passes-after: ``_enforce_chat_ban`` consults the ban record and raises 403
``BROADCAST_CHAT_BANNED`` before the message is stored.

Fully offline: the broadcast-moderation / chat-message tables are replaced with
in-memory fakes and the SSE publish is stubbed, so no real AWS / DynamoDB access
occurs. ``S`` is frozen, so any settings override would use
``object.__setattr__`` (none needed here).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from fastapi import HTTPException

from app.services import broadcast_chat_store as store
from app.services import delegate_broadcast as delegate


@dataclass
class _FakeChatMessagesTable:
    """In-memory stand-in for T.broadcast_chat_messages."""

    items: dict[tuple[str, str], dict] = field(default_factory=dict)

    def put_item(self, *, Item):
        self.items[(Item["session_id"], Item["sort_key"])] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get((Key["session_id"], Key["sort_key"]))
        return {"Item": dict(item)} if item else {}


@dataclass
class _FakeChatMutesTable:
    """In-memory stand-in for T.broadcast_chat_mutes (never muted)."""

    def get_item(self, *, Key):
        return {}


def _patch(request, monkeypatch, banned: set[tuple[str, str]]):
    """Wire in-memory fakes.

    ``T`` (``app.core.tables.Tables``) is a frozen dataclass, so its table
    handles are swapped with ``object.__setattr__`` and restored on teardown via
    a finalizer. ``is_viewer_banned`` is patched to consult an in-memory ban set
    (the real one only reads ``T.broadcast_moderation``).
    """
    messages = _FakeChatMessagesTable()
    mutes = _FakeChatMutesTable()

    _orig_messages = store.T.broadcast_chat_messages
    _orig_mutes = store.T.broadcast_chat_mutes
    object.__setattr__(store.T, "broadcast_chat_messages", messages)
    object.__setattr__(store.T, "broadcast_chat_mutes", mutes)

    def _restore():
        object.__setattr__(store.T, "broadcast_chat_messages", _orig_messages)
        object.__setattr__(store.T, "broadcast_chat_mutes", _orig_mutes)

    request.addfinalizer(_restore)

    # _enforce_chat_ban does `from app.services.delegate_broadcast import
    # is_viewer_banned` at call time, so patching the module attribute works.
    monkeypatch.setattr(
        delegate,
        "is_viewer_banned",
        lambda session_id, user_id: (session_id, user_id) in banned,
    )

    # Avoid any real SSE side effect.
    monkeypatch.setattr(store, "broadcast_sse_publish", lambda *a, **k: None)

    store.reset_rate_limits()
    return messages


def test_banned_viewer_cannot_send_chat_message(request, monkeypatch):
    messages = _patch(request, monkeypatch, banned={("sess_test", "banned_user")})

    with pytest.raises(HTTPException) as exc_info:
        store.send_chat_message(
            session_id="sess_test",
            user_id="banned_user",
            display_name="Banned",
            text="hello",
            skip_rate_limit=True,
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["code"] == "BROADCAST_CHAT_BANNED"
    # The message must never have been stored.
    assert messages.items == {}


def test_non_banned_viewer_can_send_chat_message(request, monkeypatch):
    messages = _patch(request, monkeypatch, banned=set())
    # No ban record for normal_user.

    result = store.send_chat_message(
        session_id="sess_test",
        user_id="normal_user",
        display_name="Normal",
        text="hello",
        skip_rate_limit=True,
    )

    assert result["text"] == "hello"
    assert result["sender_id"] == "normal_user"
    # The message was stored.
    assert len(messages.items) == 1
