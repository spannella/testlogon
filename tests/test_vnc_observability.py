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


def test_bootstrap_audit_includes_correlation_id(monkeypatch) -> None:
    captured: list[dict[str, object]] = []

    def _audit(*_args, **kwargs):
        captured.append(kwargs)

    monkeypatch.setattr("app.routers.vnc_sessions.audit_event", _audit)
    client = _build_client("user-123")

    resp = client.post("/api/vnc/session", json={"target_id": "demo"}, headers={"x-correlation-id": "corr-123"})

    assert resp.status_code == 200
    assert captured
    assert captured[-1]["correlation_id"] == "corr-123"


def test_create_session_bridge_failure_records_metrics(monkeypatch) -> None:
    monkeypatch.setenv("VNC_DEMO_WS_URL", "invalid-url")
    events: list[tuple[str, str, str, str]] = []
    failures: list[tuple[str, str]] = []

    def _event(*, action: str, outcome: str, target_id: str = "unknown", error_code: str = "none") -> None:
        events.append((action, outcome, target_id, error_code))

    def _failure(*, target_id: str, error_code: str) -> None:
        failures.append((target_id, error_code))

    monkeypatch.setattr(vnc_sessions, "record_vnc_session_event", _event)
    monkeypatch.setattr(vnc_sessions, "record_vnc_bridge_failure", _failure)

    try:
        vnc_sessions.create_session(user_sub="user-123", target_id="demo")
    except vnc_sessions.VncSessionError as exc:
        assert exc.code == "VNC_TARGET_UNREACHABLE"

    assert events[-1][0] == "start"
    assert events[-1][1] == "failure"
    assert failures[-1] == ("demo", "VNC_TARGET_UNREACHABLE")


def test_teardown_records_duration_metric(monkeypatch) -> None:
    durations: list[tuple[str, str, float]] = []

    def _duration(*, target_id: str, outcome: str, elapsed_seconds: float) -> None:
        durations.append((target_id, outcome, elapsed_seconds))

    monkeypatch.setattr(vnc_sessions, "record_vnc_session_duration", _duration)
    session = vnc_sessions.create_session(user_sub="user-123", target_id="demo")

    closed = vnc_sessions.teardown_session(user_sub="user-123", session_id=session["session_id"])

    assert closed["state"] == "closed"
    assert durations
    assert durations[-1][0] == "demo"
    assert durations[-1][1] == "closed"
