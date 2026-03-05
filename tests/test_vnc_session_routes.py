from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role
from app.routers.vnc_sessions import router as vnc_router
from app.services import vnc_sessions
from app.services.sessions import require_ui_session


def _build_client(user_sub: str, *, role: Role = Role.USER) -> TestClient:
    vnc_sessions.RATE_LIMITER._entries.clear()  # noqa: SLF001
    app = FastAPI()
    app.include_router(vnc_router)

    async def _auth_override() -> AuthenticatedUser:
        return AuthenticatedUser(sub=user_sub, role=role)

    async def _session_override():
        return {"user_sub": user_sub, "session_id": "sid"}

    app.dependency_overrides[get_authenticated_user] = _auth_override
    app.dependency_overrides[require_ui_session] = _session_override
    return TestClient(app)


def test_bootstrap_success_for_authorized_target() -> None:
    client = _build_client("user-123")

    resp = client.post("/api/vnc/session", json={"target_id": "demo"})

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["session_id"].startswith("vnc_")
    assert payload["ws_url"].startswith("ws://")
    assert "token" in payload["connect_params"]
    assert isinstance(payload["created_at"], int)
    assert payload["timeout_policy"] == {
        "idle_timeout_seconds": 300,
        "max_session_duration_seconds": 3600,
        "warning_seconds": 60,
    }
    assert payload["capabilities"] == {
        "clipboard": True,
        "file_transfer": False,
        "drag_drop_upload": False,
    }


def test_bootstrap_unauthorized_forbidden_with_stable_code() -> None:
    client = _build_client("user-123", role=Role.USER)

    resp = client.post("/api/vnc/session", json={"target_id": "ops-admin"})

    assert resp.status_code == 403
    payload = resp.json()
    assert payload["detail"]["error"]["code"] == "VNC_AUTH_UNAUTHORIZED"


def test_bootstrap_target_not_found() -> None:
    client = _build_client("user-123")

    resp = client.post("/api/vnc/session", json={"target_id": "missing-target"})

    assert resp.status_code == 404
    payload = resp.json()
    assert payload["detail"]["error"]["code"] == "VNC_TARGET_NOT_FOUND"


def test_teardown_closes_active_session() -> None:
    client = _build_client("user-123")
    created = client.post("/api/vnc/session", json={"target_id": "demo"})
    session_id = created.json()["session_id"]

    resp = client.delete(f"/api/vnc/session/{session_id}")

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["session_id"] == session_id
    assert payload["status"] == "closed"
    assert isinstance(payload["closed_at"], int)


def test_teardown_for_other_user_forbidden() -> None:
    owner = _build_client("owner")
    session_id = owner.post("/api/vnc/session", json={"target_id": "demo"}).json()["session_id"]

    other = _build_client("other-user")
    resp = other.delete(f"/api/vnc/session/{session_id}")

    assert resp.status_code == 403
    assert resp.json()["detail"]["error"]["code"] == "VNC_AUTH_UNAUTHORIZED"


def test_bootstrap_bridge_failure_returns_mapped_code(monkeypatch) -> None:
    monkeypatch.setenv("VNC_DEMO_WS_URL", "invalid-bridge-url")
    client = _build_client("user-123")

    resp = client.post("/api/vnc/session", json={"target_id": "demo"})

    assert resp.status_code == 502
    assert resp.json()["detail"]["error"]["code"] == "VNC_TARGET_UNREACHABLE"


def test_transfer_fallback_success_for_unsupported_target(monkeypatch) -> None:
    events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def _audit(*args, **kwargs):
        events.append((args, kwargs))

    monkeypatch.setattr("app.routers.vnc_sessions.audit_event", _audit)
    client = _build_client("user-123")
    created = client.post("/api/vnc/session", json={"target_id": "demo"})
    session_id = created.json()["session_id"]

    resp = client.get(f"/api/vnc/session/{session_id}/transfer-fallback")

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["session_id"] == session_id
    assert payload["method"] == "object_upload_link"
    assert isinstance(payload["expires_at"], int)
    assert events[-1][0][0] == "vnc_transfer_fallback_requested"
    assert events[-1][1]["outcome"] == "success"


def test_transfer_fallback_conflict_when_native_transfer_enabled(monkeypatch) -> None:
    events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def _audit(*args, **kwargs):
        events.append((args, kwargs))

    monkeypatch.setattr("app.routers.vnc_sessions.audit_event", _audit)
    client = _build_client("admin-user", role=Role.ADMIN)
    created = client.post("/api/vnc/session", json={"target_id": "ops-admin"})
    session_id = created.json()["session_id"]

    resp = client.get(f"/api/vnc/session/{session_id}/transfer-fallback")

    assert resp.status_code == 409
    assert resp.json()["detail"]["error"]["code"] == "VNC_TRANSFER_NATIVE_AVAILABLE"
    assert events[-1][0][0] == "vnc_transfer_fallback_requested"
    assert events[-1][1]["outcome"] == "failure"


def test_bootstrap_rate_limit_throttles_burst(monkeypatch) -> None:
    monkeypatch.setenv("VNC_BOOTSTRAP_RATE_LIMIT_COUNT", "2")
    monkeypatch.setenv("VNC_BOOTSTRAP_RATE_LIMIT_WINDOW_SECONDS", "60")
    client = _build_client("user-123")

    first = client.post("/api/vnc/session", json={"target_id": "demo"})
    second = client.post("/api/vnc/session", json={"target_id": "demo"})
    third = client.post("/api/vnc/session", json={"target_id": "demo"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json()["detail"]["error"]["code"] == "VNC_RATE_LIMITED"


def test_non_tls_ws_blocked_outside_dev(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("VNC_DEMO_WS_URL", "ws://localhost:6080/websockify")
    client = _build_client("user-123")

    resp = client.post("/api/vnc/session", json={"target_id": "demo"})

    assert resp.status_code == 500
    assert resp.json()["detail"]["error"]["code"] == "VNC_TLS_REQUIRED"


def test_vnc_feature_kill_switch_returns_503(monkeypatch) -> None:
    monkeypatch.setenv("VNC_FEATURE_ENABLED", "true")
    monkeypatch.setenv("VNC_FEATURE_KILL_SWITCH", "true")
    client = _build_client("user-123")

    resp = client.post("/api/vnc/session", json={"target_id": "demo"})

    assert resp.status_code == 503
    assert resp.json()["detail"]["error"]["code"] == "VNC_FEATURE_DISABLED"
