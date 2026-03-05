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
    vnc_sessions.RATE_LIMITER._entries.clear()  # noqa: SLF001


def test_create_verify_teardown_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VNC_SESSION_TOKEN_SECRET", "integration-secret")

    session = vnc_sessions.create_session(user_sub="user-1", target_id="demo")

    assert session["session_id"].startswith("vnc_")
    assert session["state"] == "active"
    assert session["capabilities"] == {
        "clipboard": True,
        "file_transfer": False,
        "drag_drop_upload": False,
    }

    claims = vnc_sessions.verify_connect_token(
        token=session["connect_params"]["token"],
        expected_session_id=session["session_id"],
        expected_target_id="demo",
    )
    assert claims["sid"] == session["session_id"]
    assert claims["target_id"] == "demo"

    closed = vnc_sessions.teardown_session(user_sub="user-1", session_id=session["session_id"])

    assert closed["state"] == "closed"
    assert closed["close_reason"] == "user_disconnect"


def test_integration_negative_paths_return_stable_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VNC_SESSION_TOKEN_SECRET", "integration-secret")

    with pytest.raises(VncSessionError) as unauthorized:
        vnc_sessions.create_session(user_sub="basic-user", target_id="ops-admin", user_role="user")
    assert unauthorized.value.code == "VNC_AUTH_UNAUTHORIZED"

    monkeypatch.setenv("VNC_DEMO_WS_URL", "invalid-url")
    with pytest.raises(VncSessionError) as unreachable:
        vnc_sessions.create_session(user_sub="user-1", target_id="demo")
    assert unreachable.value.code == "VNC_TARGET_UNREACHABLE"

    issued_at = int(time.time()) - 30
    expired = vnc_sessions.mint_connect_token(
        user_sub="user-1",
        session_id="sid-expired",
        target_id="demo",
        issued_at=issued_at,
        expires_at=issued_at + 1,
    )
    with pytest.raises(VncSessionError) as expired_err:
        vnc_sessions.verify_connect_token(
            token=expired,
            expected_session_id="sid-expired",
            expected_target_id="demo",
        )
    assert expired_err.value.code == "VNC_TOKEN_EXPIRED"


def test_bridge_behavior_fixture_supports_deterministic_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_unreachable(*, ws_url: str) -> None:
        raise vnc_sessions.BridgeLifecycleError(
            code="VNC_TARGET_UNREACHABLE",
            message=f"mock bridge cannot reach {ws_url}",
        )

    monkeypatch.setattr(vnc_sessions.BRIDGE, "validate_target_ws_url", _raise_unreachable)

    with pytest.raises(VncSessionError) as exc:
        vnc_sessions.create_session(user_sub="user-1", target_id="demo")

    assert exc.value.http_status == 502
    assert exc.value.code == "VNC_TARGET_UNREACHABLE"
