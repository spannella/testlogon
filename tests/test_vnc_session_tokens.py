from __future__ import annotations

import time

import jwt
import pytest

from app.services import vnc_sessions
from app.services.vnc_sessions import VncSessionError


def test_verify_connect_token_rejects_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VNC_SESSION_TOKEN_SECRET", "test-secret")
    issued_at = int(time.time()) - 20
    expires_at = issued_at + 1

    token = vnc_sessions.mint_connect_token(
        user_sub="user-1",
        session_id="sid-1",
        target_id="demo",
        issued_at=issued_at,
        expires_at=expires_at,
    )

    with pytest.raises(VncSessionError) as exc:
        vnc_sessions.verify_connect_token(token=token, expected_session_id="sid-1", expected_target_id="demo")

    assert exc.value.code == "VNC_TOKEN_EXPIRED"


def test_verify_connect_token_rejects_tampered_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VNC_SESSION_TOKEN_SECRET", "test-secret")
    issued_at = int(time.time())
    expires_at = issued_at + 120

    good = vnc_sessions.mint_connect_token(
        user_sub="user-1",
        session_id="sid-1",
        target_id="demo",
        issued_at=issued_at,
        expires_at=expires_at,
    )
    parts = good.split(".")
    tampered = f"{parts[0]}.{parts[1]}.invalidsig"

    with pytest.raises(VncSessionError) as exc:
        vnc_sessions.verify_connect_token(token=tampered, expected_session_id="sid-1", expected_target_id="demo")

    assert exc.value.code == "VNC_TOKEN_INVALID"


def test_verify_connect_token_rejects_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VNC_SESSION_TOKEN_SECRET", "test-secret")
    issued_at = int(time.time())
    expires_at = issued_at + 120

    token = vnc_sessions.mint_connect_token(
        user_sub="user-1",
        session_id="sid-1",
        target_id="demo",
        issued_at=issued_at,
        expires_at=expires_at,
    )

    first = vnc_sessions.verify_connect_token(token=token, expected_session_id="sid-1", expected_target_id="demo")
    assert first["sid"] == "sid-1"

    with pytest.raises(VncSessionError) as exc:
        vnc_sessions.verify_connect_token(token=token, expected_session_id="sid-1", expected_target_id="demo")

    assert exc.value.code == "VNC_TOKEN_INVALID"
    assert exc.value.details.get("reason") == "replay_detected"


def test_verify_connect_token_rejects_session_or_target_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VNC_SESSION_TOKEN_SECRET", "test-secret")
    issued_at = int(time.time())
    expires_at = issued_at + 120

    token = vnc_sessions.mint_connect_token(
        user_sub="user-1",
        session_id="sid-1",
        target_id="demo",
        issued_at=issued_at,
        expires_at=expires_at,
    )

    with pytest.raises(VncSessionError) as sid_exc:
        vnc_sessions.verify_connect_token(token=token, expected_session_id="sid-2", expected_target_id="demo")
    assert sid_exc.value.code == "VNC_TOKEN_INVALID"

    # build a new token (previous one is consumed only if sid/target checks passed)
    token2 = vnc_sessions.mint_connect_token(
        user_sub="user-1",
        session_id="sid-1",
        target_id="demo",
        issued_at=issued_at,
        expires_at=expires_at,
    )
    with pytest.raises(VncSessionError) as target_exc:
        vnc_sessions.verify_connect_token(token=token2, expected_session_id="sid-1", expected_target_id="other")
    assert target_exc.value.code == "VNC_TOKEN_INVALID"


def test_create_session_uses_ttl_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VNC_SESSION_TOKEN_SECRET", "test-secret")
    monkeypatch.setenv("VNC_SESSION_TOKEN_TTL_SECONDS", "9999")

    session = vnc_sessions.create_session(user_sub="user-1", target_id="demo")
    token = session["connect_params"]["token"]
    claims = jwt.decode(token, "test-secret", algorithms=["HS256"], audience="vnc-bridge")

    ttl = int(claims["exp"]) - int(claims["iat"])
    assert ttl == 300
