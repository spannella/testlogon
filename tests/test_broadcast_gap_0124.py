"""Regression tests for GAP-0124 (go-private ``behavior="end"`` not wired).

GAP-0124: ``accept_private_request_route`` in ``app/routers/broadcast.py``
handled ``behavior == "pause"`` explicitly but had no branch for
``behavior == "end"``. When the creator accepted a private request with
``behavior="end"``, the broadcast session was transitioned to ``"private"``
status but ``stop_session_with_provider()`` was never called — the underlying
live streaming provider (MediaLive / mock) kept running at platform expense.

The fix calls ``stop_session_with_provider(..., reason="go_private_end")``
*before* any status transition (so the ``status in {"ready","live"}`` guard in
``stop_session_with_provider`` is satisfied), and skips the ``"private"``
transition for the ``"end"`` behavior.

These tests call the route handler in ``app.routers.broadcast`` directly with a
fake ``ctx`` and a fake ``request`` (same offline pattern as
``tests/test_broadcast_gap_0117.py``) so they run fully offline — no real AWS /
DynamoDB Local required. The first test FAILS before the fix and PASSES after.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.routers import broadcast


def _ctx(sub: str = "alice") -> dict:
    return {"user_sub": sub, "session_id": "sess_1", "role": "user", "admin_profile": None}


def _session(created_by: str = "alice", status: str = "live"):
    """A minimal stand-in for a BroadcastSessionModel."""
    return SimpleNamespace(id="sess_1", created_by=created_by, status=status)


def _request():
    return SimpleNamespace(headers={})


def _accept(behavior: str):
    """Invoke the accept handler with the given behavior, returning the mock for
    ``stop_session_with_provider`` plus the handler's output."""
    body = broadcast.PrivateRequestAcceptIn(behavior=behavior)
    priv_item = {"viewer_id": "bob"}
    accept_result = {"rate_per_minute_cents": 250}

    with (
        patch.object(broadcast, "get_session", return_value=_session()),
        patch(
            "app.services.broadcast_private.get_private_session",
            return_value=priv_item,
        ),
        patch(
            "app.services.broadcast_private.accept_private_request",
            return_value=accept_result,
        ),
        patch("app.services.messaging_call_sessions.create_call_session"),
        patch.object(broadcast, "transition_session_status") as mock_transition,
        patch.object(broadcast, "record_broadcast_action"),
        patch.object(broadcast, "broadcast_sse_publish") as mock_sse,
        patch.object(
            broadcast,
            "stop_session_with_provider",
            return_value=MagicMock(status="stopped"),
        ) as mock_stop,
    ):
        out = broadcast.accept_private_request_route(
            session_id="sess_1",
            request_id="req_1",
            body=body,
            request=_request(),
            ctx=_ctx(sub="alice"),
        )
    return mock_stop, mock_transition, mock_sse, out


def test_gap0124_accept_behavior_end_stops_provider() -> None:
    """behavior='end' MUST call stop_session_with_provider with reason='go_private_end'.

    FAILS BEFORE FIX: stop_session_with_provider is never called.
    PASSES AFTER FIX: it is called once before any "private" transition.
    """
    mock_stop, mock_transition, mock_sse, out = _accept("end")

    mock_stop.assert_called_once()
    kwargs = mock_stop.call_args.kwargs
    assert kwargs["session_id"] == "sess_1"
    assert kwargs["actor"] == "alice"
    assert kwargs["reason"] == "go_private_end"

    # For "end", we do NOT transition to "private" (the session is over).
    for c in mock_transition.call_args_list:
        assert c.kwargs.get("to_status") != "private"

    # A broadcast_ended SSE event is emitted for clients.
    sse_types = [c.args[1]["_type"] for c in mock_sse.call_args_list]
    assert "private:broadcast_ended" in sse_types
    assert out.behavior == "end"


def test_gap0124_accept_behavior_pause_does_not_stop_provider() -> None:
    """behavior='pause' must NOT stop the provider (regression guard)."""
    mock_stop, mock_transition, mock_sse, out = _accept("pause")

    mock_stop.assert_not_called()
    # pause still transitions the session to "private".
    private_transitions = [
        c for c in mock_transition.call_args_list
        if c.kwargs.get("to_status") == "private"
    ]
    assert len(private_transitions) == 1
    sse_types = [c.args[1]["_type"] for c in mock_sse.call_args_list]
    assert "private:broadcast_paused" in sse_types
    assert out.behavior == "pause"


def test_gap0124_accept_behavior_continue_does_not_stop_provider() -> None:
    """behavior='continue' must NOT stop the provider."""
    mock_stop, mock_transition, _mock_sse, out = _accept("continue")

    mock_stop.assert_not_called()
    private_transitions = [
        c for c in mock_transition.call_args_list
        if c.kwargs.get("to_status") == "private"
    ]
    assert len(private_transitions) == 1
    assert out.behavior == "continue"
