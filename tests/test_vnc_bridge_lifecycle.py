from __future__ import annotations

import time

import pytest

from app.services import vnc_sessions
from app.services.vnc_sessions import VncSessionError


@pytest.fixture(autouse=True)
def _reset_vnc_state() -> None:
    vnc_sessions.STORE._sessions.clear()  # noqa: SLF001
    vnc_sessions.STORE._consumed_jti_exp.clear()  # noqa: SLF001
    vnc_sessions.BRIDGE._states.clear()  # noqa: SLF001


def test_bridge_state_transitions_create_to_active_to_closed() -> None:
    created = vnc_sessions.create_session(user_sub="user-1", target_id="demo")
    session_id = created["session_id"]

    bridge_state = vnc_sessions.get_bridge_state(session_id=session_id)
    assert bridge_state is not None
    assert bridge_state["state"] == "active"

    closed = vnc_sessions.teardown_session(user_sub="user-1", session_id=session_id)
    assert closed["state"] == "closed"

    bridge_after = vnc_sessions.get_bridge_state(session_id=session_id)
    assert bridge_after is not None
    assert bridge_after["state"] == "closed"


def test_bridge_failure_maps_target_unreachable_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VNC_DEMO_WS_URL", "not-a-websocket-url")

    with pytest.raises(VncSessionError) as exc:
        vnc_sessions.create_session(user_sub="user-1", target_id="demo")

    assert exc.value.http_status == 502
    assert exc.value.code == "VNC_TARGET_UNREACHABLE"

    # a failed bridge session should be tracked and not left creating/active
    assert all(item.get("state") == "failed" for item in vnc_sessions.BRIDGE._states.values())  # noqa: SLF001


def test_timeout_cleanup_prevents_orphan_sessions() -> None:
    created = vnc_sessions.create_session(user_sub="user-1", target_id="demo")
    session_id = created["session_id"]

    # Force this session old enough for idle timeout and trigger lifecycle cleanup hook.
    vnc_sessions.BRIDGE._states[session_id]["last_activity_at"] = int(time.time()) - 99999  # noqa: SLF001
    vnc_sessions.teardown_session(user_sub="user-1", session_id=session_id)

    store_state = vnc_sessions.STORE.get(session_id)
    assert store_state is not None
    assert store_state["state"] == "closed"

    bridge_state = vnc_sessions.get_bridge_state(session_id=session_id)
    assert bridge_state is not None
    assert bridge_state["state"] == "closed"


def test_process_crash_cleanup_hook_closes_session() -> None:
    created = vnc_sessions.create_session(user_sub="user-1", target_id="demo")
    session_id = created["session_id"]

    closed = vnc_sessions.cleanup_bridge_crash(session_id=session_id)

    assert closed is not None
    assert closed["state"] == "closed"

    store_state = vnc_sessions.STORE.get(session_id)
    assert store_state is not None
    assert store_state["state"] == "closed"
    assert store_state.get("close_reason") == "process_crash"


def test_timeout_cleanup_emits_termination_audit(monkeypatch) -> None:
    events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def _audit(*args, **kwargs):
        events.append((args, kwargs))

    monkeypatch.setattr("app.services.vnc_sessions.audit_event", _audit)

    created = vnc_sessions.create_session(user_sub="user-1", target_id="demo")
    session_id = created["session_id"]

    vnc_sessions.BRIDGE._states[session_id]["last_activity_at"] = int(time.time()) - 99999  # noqa: SLF001

    # Trigger cleanup path (runs at start of create_session/teardown/get_transfer_fallback).
    with pytest.raises(VncSessionError):
        vnc_sessions.teardown_session(user_sub="other-user", session_id="missing")

    assert events
    latest = events[-1]
    assert latest[0][0] == "vnc_session_terminated"
    assert latest[1]["session_id"] == session_id
    assert latest[1]["error_code"] == "VNC_SESSION_TERMINATED"
