"""Regression tests for GAP-0117 (broadcast chat SEND access control).

GAP-0117: the chat SEND endpoint (``send_chat_message_route``) checked only
``session.status == "live"`` and never called ``check_viewer_access``. A
non-member could therefore POST a message into a *private* session's live chat
(and have it fanned out to legitimate viewers via SSE).

These tests call the route handler in ``app.routers.broadcast`` directly with a
fake ``ctx`` (same offline pattern as ``tests/test_broadcast_gap_0113_0114_0115.py``)
so they run fully offline — no real AWS / DynamoDB Local required. Each test is
written to FAIL before the fix and PASS after.

Sibling GAP-0116 (chat STREAM read path) and GAP-0118 (``_chat_msg_out``
viewer-aware redaction) are already covered by the GAP-0113 / GAP-0114 fixes
(see ``broadcast_chat_stream_route`` at ``app/routers/broadcast.py``), so this
file only covers the genuinely-new write-path fix.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import broadcast


def _ctx(role: str = "user", sub: str = "alice") -> dict:
    return {"user_sub": sub, "session_id": "sid-1", "role": role, "admin_profile": None}


def _session(created_by: str = "alice", status: str = "live", visibility: str = "public"):
    """A minimal stand-in for a BroadcastSessionModel."""
    return SimpleNamespace(
        id="sess_1",
        created_by=created_by,
        status=status,
        broadcast_privacy_visibility=visibility,
    )


def _send_body(text: str = "hello") -> "broadcast.BroadcastChatSendIn":
    return broadcast.BroadcastChatSendIn(text=text)


def _store_result(sender: str = "bob") -> dict:
    return {
        "message_id": "m1",
        "session_id": "sess_1",
        "sender_id": sender,
        "sender_display_name": sender,
        "text": "hello",
        "kind": "text",
        "created_at": 1700000000,
        "deleted": False,
    }


# ─────────────────────────────────────────────────────────────────────
# GAP-0117: chat send viewer access check
# ─────────────────────────────────────────────────────────────────────


def test_gap0117_send_chat_private_session_rejects_non_member() -> None:
    """A non-member must be refused when posting to a private session's chat.

    Before fix: handler proceeds past the status check straight to _store_send_chat.
    After fix: check_viewer_access raises 403 BROADCAST_PRIVATE_ACCESS_DENIED
    BEFORE any store write / SSE fan-out.
    """
    private_session = _session(created_by="alice", visibility="private", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=private_session),
        patch("app.services.broadcast_privacy.is_allowlisted", return_value=False),
        patch("app.services.broadcast_privacy.redeem_invite_token", return_value=False),
        patch.object(broadcast, "_store_send_chat") as store,
        pytest.raises(HTTPException) as exc,
    ):
        broadcast.send_chat_message_route(
            "sess_1", _send_body(), ctx=_ctx(role="user", sub="bob")
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "BROADCAST_PRIVATE_ACCESS_DENIED"
    # Must reject BEFORE writing / fanning out the message.
    store.assert_not_called()


def test_gap0117_send_chat_private_session_allows_creator() -> None:
    """The creator may always post to their own private session's chat."""
    private_session = _session(created_by="alice", visibility="private", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=private_session),
        patch.object(broadcast, "_store_send_chat", return_value=_store_result("alice")) as store,
    ):
        out = broadcast.send_chat_message_route(
            "sess_1", _send_body(), ctx=_ctx(role="user", sub="alice")
        )
    store.assert_called_once()
    assert out.message_id == "m1"


def test_gap0117_send_chat_private_session_allows_allowlisted_viewer() -> None:
    """An allowlisted viewer may post to a private session's chat."""
    private_session = _session(created_by="alice", visibility="private", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=private_session),
        patch("app.services.broadcast_privacy.is_allowlisted", return_value=True),
        patch.object(broadcast, "_store_send_chat", return_value=_store_result("bob")) as store,
    ):
        out = broadcast.send_chat_message_route(
            "sess_1", _send_body(), ctx=_ctx(role="user", sub="bob")
        )
    store.assert_called_once()
    assert out.message_id == "m1"


def test_gap0117_send_chat_public_session_allows_any_user() -> None:
    """Public sessions remain open to any authenticated user (no-op gate)."""
    public_session = _session(created_by="alice", visibility="public", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=public_session),
        patch.object(broadcast, "_store_send_chat", return_value=_store_result("bob")) as store,
    ):
        out = broadcast.send_chat_message_route(
            "sess_1", _send_body(), ctx=_ctx(role="user", sub="bob")
        )
    store.assert_called_once()
    assert out.message_id == "m1"
