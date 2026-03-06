from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.routers.vnc_sessions import router as vnc_router
from app.services.sessions import require_ui_session
from app.services.vnc_sessions import TargetConfig, resolve_session_capabilities


def _build_client(user_sub: str) -> TestClient:
    app = FastAPI()
    app.include_router(vnc_router)

    async def _auth_override() -> AuthenticatedUser:
        return AuthenticatedUser(sub=user_sub)

    async def _session_override():
        return {"user_sub": user_sub, "session_id": "sid"}

    app.dependency_overrides[get_authenticated_user] = _auth_override
    app.dependency_overrides[require_ui_session] = _session_override
    return TestClient(app)


def test_capability_resolver_returns_canonical_boolean_keys(monkeypatch) -> None:
    monkeypatch.setenv("VNC_RUNTIME_CLIPBOARD_ENABLED", "true")
    monkeypatch.setenv("VNC_RUNTIME_FILE_TRANSFER_ENABLED", "true")
    monkeypatch.setenv("VNC_RUNTIME_DRAG_DROP_UPLOAD_ENABLED", "true")
    target = TargetConfig(
        target_id="demo",
        ws_url="ws://localhost:6080/websockify",
        allowed_users=("*",),
        capabilities={"clipboard": True},
    )

    resolved = resolve_session_capabilities(target)

    assert resolved == {
        "clipboard": True,
        "file_transfer": False,
        "drag_drop_upload": False,
    }
    assert all(isinstance(v, bool) for v in resolved.values())


def test_capability_resolver_applies_runtime_gates_deterministically(monkeypatch) -> None:
    monkeypatch.setenv("VNC_RUNTIME_CLIPBOARD_ENABLED", "false")
    monkeypatch.setenv("VNC_RUNTIME_FILE_TRANSFER_ENABLED", "false")
    monkeypatch.setenv("VNC_RUNTIME_DRAG_DROP_UPLOAD_ENABLED", "true")
    target = TargetConfig(
        target_id="ops",
        ws_url="ws://localhost:6080/websockify",
        allowed_users=("*",),
        capabilities={"clipboard": True, "file_transfer": True, "drag_drop_upload": True},
    )

    resolved = resolve_session_capabilities(target)

    assert resolved == {
        "clipboard": False,
        "file_transfer": False,
        "drag_drop_upload": False,
    }


def test_bootstrap_response_always_includes_non_nullable_capabilities(monkeypatch) -> None:
    from app.services import vnc_sessions

    def _targets() -> dict[str, TargetConfig]:
        return {
            "minimal": TargetConfig(
                target_id="minimal",
                ws_url="ws://localhost:6080/websockify",
                allowed_users=("*",),
                capabilities={},
            )
        }

    monkeypatch.setattr(vnc_sessions, "_default_targets", _targets)
    monkeypatch.setenv("VNC_RUNTIME_CLIPBOARD_ENABLED", "true")
    monkeypatch.setenv("VNC_RUNTIME_FILE_TRANSFER_ENABLED", "true")
    monkeypatch.setenv("VNC_RUNTIME_DRAG_DROP_UPLOAD_ENABLED", "true")

    client = _build_client("user-123")
    resp = client.post("/api/vnc/session", json={"target_id": "minimal"})

    assert resp.status_code == 200
    capabilities = resp.json()["capabilities"]
    assert capabilities == {
        "clipboard": False,
        "file_transfer": False,
        "drag_drop_upload": False,
    }
    assert set(capabilities.keys()) == {"clipboard", "file_transfer", "drag_drop_upload"}
    assert all(isinstance(capabilities[key], bool) for key in capabilities)
