"""Regression tests for GAP-0110, GAP-0111, GAP-0112 (broadcast access control).

These tests call the route handlers in ``app.routers.broadcast`` directly with a
fake ``ctx`` (the pattern used by ``tests/test_broadcast_routes.py``) so they run
fully offline — no real AWS / DynamoDB Local required. Each test is written to
FAIL before the corresponding fix and PASS after.

- GAP-0110: lifecycle routes (start/stop/delete) must enforce session ownership
  (owner OR root), not merely admin/root role.
- GAP-0111: ``?status=`` list must be scoped to the caller for non-operators.
- GAP-0112: SSE event-stream route must enforce ``check_viewer_access`` so a
  non-member cannot subscribe to a private session's stream.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import broadcast


def _ctx(role: str = "user", sub: str = "alice") -> dict:
    return {"user_sub": sub, "session_id": "sid-1", "role": role, "admin_profile": None}


def _req(cid: str = "cid-1"):
    return SimpleNamespace(headers={"x-correlation-id": cid})


def _session(created_by: str = "alice", status: str = "live", visibility: str = "public"):
    """A minimal stand-in for a BroadcastSessionModel."""
    return SimpleNamespace(
        id="sess_1",
        created_by=created_by,
        status=status,
        broadcast_privacy_visibility=visibility,
        profile_id="p1",
        ingest_url=None,
        stream_key_ref=None,
        started_at=None,
        stopped_at=None,
        created_at="2026-03-25T00:00:00+00:00",
        updated_at="2026-03-25T00:00:00+00:00",
        model_dump=lambda: {
            "id": "sess_1",
            "profile_id": "p1",
            "status": status,
            "ingest_url": None,
            "stream_key_ref": None,
            "started_at": None,
            "stopped_at": None,
            "created_by": created_by,
            "created_at": "2026-03-25T00:00:00+00:00",
            "updated_at": "2026-03-25T00:00:00+00:00",
        },
    )


# ─────────────────────────────────────────────────────────────────────
# GAP-0110: lifecycle ownership (start / stop / delete)
# ─────────────────────────────────────────────────────────────────────


def test_gap0110_non_owner_admin_cannot_start_session() -> None:
    """Admin Bob cannot start Alice's session — IDOR prevented.

    Before fix: returns 202 (start_session_with_provider called).
    After fix: raises 403 BROADCAST_OWNERSHIP_FORBIDDEN before the provider call.
    """
    alice_session = _session(created_by="alice")
    with (
        patch.object(broadcast, "get_session", return_value=alice_session),
        patch.object(broadcast, "start_session_with_provider") as start_provider,
        patch.object(broadcast, "record_broadcast_action"),
        patch.object(broadcast, "get_output", return_value=None),
        pytest.raises(HTTPException) as exc,
    ):
        broadcast.start_session_route(
            "sess_1",
            broadcast.BroadcastSessionActionIn(reason="x"),
            request=_req(),
            ctx=_ctx(role="admin", sub="bob"),
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "BROADCAST_OWNERSHIP_FORBIDDEN"
    start_provider.assert_not_called()


def test_gap0110_non_owner_admin_cannot_stop_session() -> None:
    """Admin Bob cannot stop Alice's running session."""
    alice_session = _session(created_by="alice")
    with (
        patch.object(broadcast, "get_session", return_value=alice_session),
        patch.object(broadcast, "stop_session_with_provider") as stop_provider,
        patch.object(broadcast, "record_broadcast_action"),
        patch.object(broadcast, "get_output", return_value=None),
        pytest.raises(HTTPException) as exc,
    ):
        broadcast.stop_session_route(
            "sess_1",
            broadcast.BroadcastSessionActionIn(reason="x"),
            request=_req(),
            ctx=_ctx(role="admin", sub="bob"),
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "BROADCAST_OWNERSHIP_FORBIDDEN"
    stop_provider.assert_not_called()


def test_gap0110_non_owner_admin_cannot_delete_session() -> None:
    """Admin Bob cannot delete Alice's session."""
    alice_session = _session(created_by="alice")
    with (
        patch.object(broadcast, "get_session", return_value=alice_session),
        patch.object(broadcast, "delete_session_with_provider") as delete_provider,
        patch.object(broadcast, "record_broadcast_action"),
        pytest.raises(HTTPException) as exc,
    ):
        broadcast.delete_session_route(
            "sess_1", request=_req(), ctx=_ctx(role="admin", sub="bob")
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "BROADCAST_OWNERSHIP_FORBIDDEN"
    delete_provider.assert_not_called()


def test_gap0110_owner_admin_can_start_own_session() -> None:
    """The session owner (also admin) can still start their own session."""
    alice_session = _session(created_by="alice")
    with (
        patch.object(broadcast, "get_session", return_value=alice_session),
        patch.object(
            broadcast, "start_session_with_provider", return_value=_session(status="live")
        ) as start_provider,
        patch.object(broadcast, "record_broadcast_action"),
        patch.object(broadcast, "get_output", return_value=None),
    ):
        out = broadcast.start_session_route(
            "sess_1",
            broadcast.BroadcastSessionActionIn(reason="x"),
            request=_req(),
            ctx=_ctx(role="admin", sub="alice"),
        )
    start_provider.assert_called_once()
    assert out.status == "live"


def test_gap0110_root_can_delete_any_session() -> None:
    """Root is permitted as an emergency super-user (policy = owner OR root)."""
    alice_session = _session(created_by="alice")
    with (
        patch.object(broadcast, "get_session", return_value=alice_session),
        patch.object(
            broadcast, "delete_session_with_provider", return_value={"ok": True}
        ) as delete_provider,
        patch.object(broadcast, "record_broadcast_action"),
    ):
        out = broadcast.delete_session_route(
            "sess_1", request=_req(), ctx=_ctx(role="root", sub="root-user")
        )
    delete_provider.assert_called_once()
    assert out.ok is True


# ─────────────────────────────────────────────────────────────────────
# GAP-0111: status-filter list scoping
# ─────────────────────────────────────────────────────────────────────


def test_gap0111_status_filter_scoped_to_caller_for_non_admin() -> None:
    """Non-admin Alice must only see her own sessions when ?status= is set.

    Before fix: list_sessions_by_status returns both Alice's and Bob's sessions.
    After fix: the router scopes to the caller via list_sessions_by_creator.
    """
    alice_session = _session(created_by="alice", status="live")
    bob_session = _session(created_by="bob", status="live")
    bob_session.id = "sess_bob"
    bob_session.model_dump = lambda: {**alice_session.model_dump(), "id": "sess_bob", "created_by": "bob"}

    with (
        # If the fix is missing, the router would call this and leak both sessions.
        patch.object(
            broadcast,
            "list_sessions_by_status",
            return_value={"items": [alice_session, bob_session], "cursor": None},
        ),
        # The fix routes non-operators here, scoped to the caller.
        patch.object(
            broadcast,
            "list_sessions_by_creator",
            return_value={"items": [alice_session], "cursor": None},
        ),
        patch.object(broadcast, "get_output", return_value=None),
    ):
        out = broadcast.list_sessions_route(
            status_filter="live", limit=50, ctx=_ctx(role="user", sub="alice")
        )
    ids = [s.id for s in out.items]
    assert "sess_1" in ids  # Alice's own session
    assert "sess_bob" not in ids  # Bob's session must NOT be leaked


def test_gap0111_status_filter_admin_sees_platform_wide() -> None:
    """Admin/root retain the platform-wide status feed."""
    alice_session = _session(created_by="alice", status="live")
    bob_session = _session(created_by="bob", status="live")
    bob_session.id = "sess_bob"
    bob_session.model_dump = lambda: {**alice_session.model_dump(), "id": "sess_bob", "created_by": "bob"}

    with (
        patch.object(
            broadcast,
            "list_sessions_by_status",
            return_value={"items": [alice_session, bob_session], "cursor": None},
        ) as by_status,
        patch.object(broadcast, "list_sessions_by_creator") as by_creator,
        patch.object(broadcast, "get_output", return_value=None),
    ):
        out = broadcast.list_sessions_route(
            status_filter="live", limit=50, ctx=_ctx(role="admin", sub="charlie")
        )
    by_status.assert_called_once()
    by_creator.assert_not_called()
    ids = [s.id for s in out.items]
    assert "sess_1" in ids
    assert "sess_bob" in ids


# ─────────────────────────────────────────────────────────────────────
# GAP-0112: SSE event-stream viewer access check
# ─────────────────────────────────────────────────────────────────────


def test_gap0112_sse_private_session_rejects_non_member() -> None:
    """Non-member Bob must be refused the SSE stream of Alice's private session.

    Before fix: the handler discards ctx and subscribes unconditionally.
    After fix: check_viewer_access raises 403 BROADCAST_PRIVATE_ACCESS_DENIED.
    """
    private_session = _session(created_by="alice", visibility="private")
    with (
        patch.object(broadcast, "get_session", return_value=private_session),
        patch("app.services.broadcast_privacy.is_allowlisted", return_value=False),
        patch("app.services.broadcast_privacy.redeem_invite_token", return_value=False),
        patch.object(broadcast, "broadcast_sse_subscribe") as subscribe,
        pytest.raises(HTTPException) as exc,
    ):
        asyncio.run(
            broadcast.broadcast_event_stream_route(
                "sess_1", invite_token=None, ctx=_ctx(role="user", sub="bob")
            )
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "BROADCAST_PRIVATE_ACCESS_DENIED"
    # Must reject BEFORE subscribing to the queue.
    subscribe.assert_not_called()


def test_gap0112_sse_private_session_allows_creator() -> None:
    """The creator may always subscribe to their own private session's stream."""
    private_session = _session(created_by="alice", visibility="private")
    with (
        patch.object(broadcast, "get_session", return_value=private_session),
        patch.object(broadcast, "broadcast_sse_subscribe", return_value=asyncio.Queue()) as subscribe,
        patch.object(broadcast, "broadcast_sse_unsubscribe"),
    ):
        resp = asyncio.run(
            broadcast.broadcast_event_stream_route(
                "sess_1", invite_token=None, ctx=_ctx(role="user", sub="alice")
            )
        )
    subscribe.assert_called_once()
    assert resp.media_type == "text/event-stream"


def test_gap0112_sse_public_session_allows_any_user() -> None:
    """Public sessions remain accessible to any authenticated user."""
    public_session = _session(created_by="alice", visibility="public")
    with (
        patch.object(broadcast, "get_session", return_value=public_session),
        patch.object(broadcast, "broadcast_sse_subscribe", return_value=asyncio.Queue()) as subscribe,
        patch.object(broadcast, "broadcast_sse_unsubscribe"),
    ):
        resp = asyncio.run(
            broadcast.broadcast_event_stream_route(
                "sess_1", invite_token=None, ctx=_ctx(role="user", sub="bob")
            )
        )
    subscribe.assert_called_once()
    assert resp.media_type == "text/event-stream"
