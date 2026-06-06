"""Regression tests for GAP-0113, GAP-0114, GAP-0115 (broadcast access control).

These tests call the route handlers in ``app.routers.broadcast`` directly with a
fake ``ctx`` (the same pattern as ``tests/test_broadcast_gap_0110_0111_0112.py``)
so they run fully offline — no real AWS / DynamoDB Local required. Each test is
written to FAIL before the corresponding fix and PASS after.

- GAP-0113: chat SSE stream route must enforce ``check_viewer_access`` so a
  non-member cannot subscribe to a private session's live chat.
- GAP-0114: chat SSE stream must pass ``viewer_user_id`` to ``_chat_msg_out`` so
  per-viewer redaction (locked content / expiry / reactions) is applied — locked
  text must be ``None`` for a non-payer, and visible to the sender / a payer.
- GAP-0115: health-report and viewer-heartbeat routes must enforce the
  appropriate owner / viewer access check so a non-member cannot poison health
  metrics or a private session's viewer count. (The SSE event-stream half of
  GAP-0115 is the same handler already covered by GAP-0112.)
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import broadcast
from app.services.broadcast_chat_store import _chat_msg_out


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


def _locked_msg(sender: str = "alice", unlocked_by: dict | None = None) -> dict:
    return {
        "message_id": "m1",
        "session_id": "sess_1",
        "sender_id": sender,
        "sender_display_name": sender,
        "text": "secret locked content",
        "kind": "text",
        "created_at": 1700000000,
        "deleted": False,
        "sort_key": "sk001",
        "lock_price_cents": 100,
        "lock_description": "Unlock to read",
        "unlocked_by": unlocked_by or {},
    }


async def _drain_first_chat_message(resp) -> dict | None:
    """Iterate the SSE body of the chat stream until the first chat:* event,
    returning its parsed JSON payload. The generator raises CancelledError on
    its second fetch (driven by the test's _store_fetch_after side_effect), so
    iteration terminates after the first batch of messages is emitted."""
    body = resp.body_iterator
    async for chunk in body:
        text = chunk.decode() if isinstance(chunk, (bytes, bytearray)) else chunk
        for line in text.splitlines():
            if line.startswith("data:"):
                raw = line[len("data:"):].strip()
                if not raw or raw == "{}":
                    continue
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if payload.get("message_id"):
                    return payload
    return None


# ─────────────────────────────────────────────────────────────────────
# GAP-0113: chat SSE stream viewer access check
# ─────────────────────────────────────────────────────────────────────


def test_gap0113_chat_stream_private_session_rejects_non_member() -> None:
    """Non-member Bob must be refused the chat stream of Alice's private session.

    Before fix: the handler discards ctx and streams unconditionally.
    After fix: check_viewer_access raises 403 BROADCAST_PRIVATE_ACCESS_DENIED.
    """
    private_session = _session(created_by="alice", visibility="private", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=private_session),
        patch("app.services.broadcast_privacy.is_allowlisted", return_value=False),
        patch("app.services.broadcast_privacy.redeem_invite_token", return_value=False),
        patch.object(broadcast, "_store_fetch_after") as fetch,
        pytest.raises(HTTPException) as exc,
    ):
        asyncio.run(
            broadcast.broadcast_chat_stream_route(
                "sess_1",
                after=None,
                poll_ms=500,
                invite_token=None,
                ctx=_ctx(role="user", sub="bob"),
            )
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "BROADCAST_PRIVATE_ACCESS_DENIED"
    # Must reject BEFORE entering the streaming generator.
    fetch.assert_not_called()


def test_gap0113_chat_stream_private_session_allows_creator() -> None:
    """The creator may always subscribe to their own private session's chat."""
    private_session = _session(created_by="alice", visibility="private", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=private_session),
    ):
        resp = asyncio.run(
            broadcast.broadcast_chat_stream_route(
                "sess_1",
                after=None,
                poll_ms=500,
                invite_token=None,
                ctx=_ctx(role="user", sub="alice"),
            )
        )
    assert resp.media_type == "text/event-stream"


def test_gap0113_chat_stream_public_session_allows_any_user() -> None:
    """Public sessions remain accessible to any authenticated user."""
    public_session = _session(created_by="alice", visibility="public", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=public_session),
    ):
        resp = asyncio.run(
            broadcast.broadcast_chat_stream_route(
                "sess_1",
                after=None,
                poll_ms=500,
                invite_token=None,
                ctx=_ctx(role="user", sub="bob"),
            )
        )
    assert resp.media_type == "text/event-stream"


# ─────────────────────────────────────────────────────────────────────
# GAP-0114: chat SSE stream passes viewer_user_id to _chat_msg_out
# ─────────────────────────────────────────────────────────────────────


def test_gap0114_chat_stream_passes_viewer_user_id_to_chat_msg_out() -> None:
    """The stream must call _chat_msg_out with the caller's viewer_user_id.

    Before fix: _chat_msg_out(msg) is called positionally with no viewer id.
    After fix: viewer_user_id=ctx['user_sub'] is supplied.
    """
    public_session = _session(created_by="alice", visibility="public", status="live")
    seen = {}

    def _spy(item, viewer_user_id=None):
        seen["viewer_user_id"] = viewer_user_id
        return {"message_id": item["message_id"], "kind": "text", "text": None}

    call_count = {"n": 0}

    def _fetch_once(session_id, cursor, limit):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return [_locked_msg(sender="alice")]
        # stop the generator loop after the first batch
        raise asyncio.CancelledError()

    async def _run() -> None:
        resp = await broadcast.broadcast_chat_stream_route(
            "sess_1", after=None, poll_ms=500, invite_token=None,
            ctx=_ctx(role="user", sub="bob"),
        )
        try:
            await _drain_first_chat_message(resp)
        except asyncio.CancelledError:
            pass

    with (
        patch.object(broadcast, "get_session", return_value=public_session),
        patch.object(broadcast, "_store_fetch_after", side_effect=_fetch_once),
        patch.object(broadcast, "_chat_msg_out", side_effect=_spy),
    ):
        asyncio.run(_run())

    assert seen.get("viewer_user_id") == "bob", (
        "chat stream must pass viewer_user_id to _chat_msg_out (GAP-0114)"
    )


def test_gap0114_locked_text_redacted_for_non_payer_in_stream() -> None:
    """A non-payer subscriber must receive text=None / is_unlocked=False.

    End-to-end through the real _chat_msg_out using the viewer_user_id the
    stream now supplies.
    """
    public_session = _session(created_by="alice", visibility="public", status="live")

    call_count = {"n": 0}

    def _fetch_once(session_id, cursor, limit):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return [_locked_msg(sender="alice", unlocked_by={})]  # bob has NOT paid
        raise asyncio.CancelledError()

    captured = {}

    async def _run() -> None:
        resp = await broadcast.broadcast_chat_stream_route(
            "sess_1", after=None, poll_ms=500, invite_token=None,
            ctx=_ctx(role="user", sub="bob"),
        )
        try:
            payload = await _drain_first_chat_message(resp)
            if payload:
                captured.update(payload)
        except asyncio.CancelledError:
            pass

    with (
        patch.object(broadcast, "get_session", return_value=public_session),
        patch.object(broadcast, "_store_fetch_after", side_effect=_fetch_once),
    ):
        asyncio.run(_run())

    assert captured.get("message_id") == "m1"
    assert captured.get("is_unlocked") is False
    assert captured.get("text") is None


# Direct unit coverage of the per-viewer rules _chat_msg_out applies — these
# document the behaviour the stream relies on once viewer_user_id flows through.


def test_gap0114_chat_msg_out_sender_sees_own_locked_message() -> None:
    out = _chat_msg_out(_locked_msg(sender="alice"), viewer_user_id="alice")
    assert out["is_unlocked"] is True
    assert out["text"] == "secret locked content"


def test_gap0114_chat_msg_out_payer_sees_unlocked_message() -> None:
    out = _chat_msg_out(_locked_msg(sender="alice", unlocked_by={"bob": True}), viewer_user_id="bob")
    assert out["is_unlocked"] is True
    assert out["text"] == "secret locked content"


def test_gap0114_chat_msg_out_non_payer_sees_null_text() -> None:
    out = _chat_msg_out(_locked_msg(sender="alice"), viewer_user_id="carol")
    assert out["is_unlocked"] is False
    assert out["text"] is None


# ─────────────────────────────────────────────────────────────────────
# GAP-0115: health-report ownership + heartbeat viewer access
# ─────────────────────────────────────────────────────────────────────


def _health_body() -> "broadcast.BroadcastHealthReportIn":
    return broadcast.BroadcastHealthReportIn(
        ingest_bitrate_kbps=4000,
        ingest_framerate=30.0,
        dropped_frames=0,
        dropped_frames_pct=0.0,
        output_errors=0,
        input_loss_seconds=0.0,
    )


def test_gap0115_health_report_rejects_non_owner_non_operator() -> None:
    """A non-owner regular user must not be able to poison health metrics.

    Before fix: handler discards ctx and stores the snapshot.
    After fix: 403 BROADCAST_ROLE_FORBIDDEN before store_health_snapshot.
    """
    alice_session = _session(created_by="alice", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=alice_session),
        patch.object(broadcast, "store_health_snapshot") as store,
        pytest.raises(HTTPException) as exc,
    ):
        broadcast.report_session_health_route(
            "sess_1", _health_body(), ctx=_ctx(role="user", sub="bob")
        )
    assert exc.value.status_code == 403
    store.assert_not_called()


def test_gap0115_health_report_allows_owner() -> None:
    """The session owner (broadcaster) may report health."""
    alice_session = _session(created_by="alice", status="live")
    snapshot = {
        "session_id": "sess_1", "viewer_count": 0, "ingest_bitrate_kbps": 4000,
        "ingest_framerate": 30.0, "dropped_frames": 0, "dropped_frames_pct": 0.0,
        "connection_quality": "good", "output_errors": 0, "input_loss_seconds": 0.0,
        "updated_at": 1700000000,
    }
    with (
        patch.object(broadcast, "get_session", return_value=alice_session),
        patch.object(broadcast, "store_health_snapshot", return_value=snapshot) as store,
    ):
        out = broadcast.report_session_health_route(
            "sess_1", _health_body(), ctx=_ctx(role="user", sub="alice")
        )
    store.assert_called_once()
    assert out.session_id == "sess_1"


def test_gap0115_health_report_allows_operator() -> None:
    """An admin/root operator may report health for any session."""
    alice_session = _session(created_by="alice", status="live")
    snapshot = {
        "session_id": "sess_1", "viewer_count": 0, "ingest_bitrate_kbps": 4000,
        "ingest_framerate": 30.0, "dropped_frames": 0, "dropped_frames_pct": 0.0,
        "connection_quality": "good", "output_errors": 0, "input_loss_seconds": 0.0,
        "updated_at": 1700000000,
    }
    with (
        patch.object(broadcast, "get_session", return_value=alice_session),
        patch.object(broadcast, "store_health_snapshot", return_value=snapshot) as store,
    ):
        out = broadcast.report_session_health_route(
            "sess_1", _health_body(), ctx=_ctx(role="admin", sub="charlie")
        )
    store.assert_called_once()
    assert out.session_id == "sess_1"


def test_gap0115_heartbeat_rejects_non_member_on_private_session() -> None:
    """A non-member must not heartbeat (poison the viewer count of) a private session.

    Before fix: handler discards ctx and calls touch_viewer with any viewer_id.
    After fix: check_viewer_access raises 403 before touch_viewer.
    """
    private_session = _session(created_by="alice", visibility="private", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=private_session),
        patch("app.services.broadcast_privacy.is_allowlisted", return_value=False),
        patch("app.services.broadcast_privacy.redeem_invite_token", return_value=False),
        patch.object(broadcast, "touch_viewer") as touch,
        pytest.raises(HTTPException) as exc,
    ):
        broadcast.viewer_heartbeat_route(
            "sess_1", viewer_id="spoofed", invite_token=None,
            ctx=_ctx(role="user", sub="bob"),
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "BROADCAST_PRIVATE_ACCESS_DENIED"
    touch.assert_not_called()


def test_gap0115_heartbeat_allows_member_on_public_session() -> None:
    """Heartbeat still works for an authorised viewer on a public session."""
    public_session = _session(created_by="alice", visibility="public", status="live")
    with (
        patch.object(broadcast, "get_session", return_value=public_session),
        patch.object(broadcast, "touch_viewer", return_value=3) as touch,
    ):
        out = broadcast.viewer_heartbeat_route(
            "sess_1", viewer_id="v1", invite_token=None,
            ctx=_ctx(role="user", sub="bob"),
        )
    touch.assert_called_once()
    assert out.viewer_count == 3
