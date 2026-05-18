from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role
from app.main import create_app
from app.services.calendar_integrations.base import CalendarIntegrationError, CalendarIntegrationErrorCode
from app.services.sessions import require_ui_session


def _build_client(user_sub: str = "user-1") -> TestClient:
    app = create_app()

    async def _auth_override():
        return AuthenticatedUser(sub=user_sub, role=Role.USER)

    async def _session_override():
        return {"user_sub": user_sub, "session_id": "sess_1", "role": Role.USER.value}

    app.dependency_overrides[get_authenticated_user] = _auth_override
    app.dependency_overrides[require_ui_session] = _session_override
    return TestClient(app)


def _anon_client() -> TestClient:
    return TestClient(create_app())


def test_connection_lifecycle_and_selection_happy_path_with_redaction() -> None:
    client = _build_client("user-1")

    provider = MagicMock()
    connected = {
        "connection_id": "apple_caldav#user#user-1",
        "provider": "apple_caldav",
        "user_sub": "user-1",
        "status": "connected",
        "credential_ref": "cred_123",
        "credential_validation_status": "valid",
        "credential_last_validated_at": "2026-04-05T10:00:00+00:00",
        "credential_rotated_at": "2026-04-05T10:00:00+00:00",
        "created_at": "2026-04-05T10:00:00+00:00",
        "updated_at": "2026-04-05T10:00:00+00:00",
        "has_secret": True,
        "secret_ct_b64": "should_not_escape",
    }
    status_payload = {
        "provider": "apple_caldav",
        "connection_state": "connected",
        "is_connected": True,
        "connection_id": "apple_caldav#user#user-1",
        "credential_validation_status": "valid",
        "last_successful_sync_at": "2026-04-05T11:00:00+00:00",
        "last_error_snapshot": None,
        "selected_calendar_count": 1,
        "conflict_count": 1,
        "recent_conflicts": [
            {
                "audit_id": "conflict_1",
                "event_ref": "evt_123",
                "message": "We found overlapping edits for event evt_123. We kept the version from Apple Calendar.",
                "guidance": "Review the event details in Apple Calendar and re-apply changes here if needed.",
                "occurred_at": "2026-04-05T11:30:00+00:00",
            }
        ],
        "updated_at": "2026-04-05T11:00:00+00:00",
    }
    selected = [
        {
            "external_calendar_id": "work",
            "calendar_url": "https://cal.example/work",
            "display_name": "Work",
            "sync_enabled": True,
            "sync_direction": "two_way",
            "timezone": "UTC",
        }
    ]
    disconnected = {
        **connected,
        "status": "disconnected",
        "credential_ref": "",
        "credential_validation_status": "disconnected",
        "has_secret": False,
    }

    with (
        patch("app.routers.calendar.get_provider_services", return_value=provider),
        patch("app.routers.calendar.upsert_apple_caldav_credential", return_value=connected),
        patch("app.routers.calendar.get_apple_caldav_status", return_value=status_payload),
        patch("app.routers.calendar.select_apple_caldav_calendars", return_value=selected),
        patch("app.routers.calendar.disconnect_apple_caldav_credential", return_value=disconnected),
    ):
        connect_res = client.post(
            "/calendar/integrations/apple/connect",
            json={"username": "ada@example.com", "app_specific_password": "abcd-efgh"},
        )
        assert connect_res.status_code == 200
        connect_body = connect_res.json()
        assert connect_body["connection_id"] == "apple_caldav#user#user-1"
        assert "secret_ct_b64" not in connect_body
        assert "app_specific_password" not in connect_body

        status_res = client.get("/calendar/integrations/apple/status")
        assert status_res.status_code == 200
        assert status_res.json()["conflict_count"] == 1
        assert status_res.json()["recent_conflicts"][0]["event_ref"] == "evt_123"

        select_res = client.post(
            "/calendar/integrations/apple/calendars/select",
            json={
                "calendars": [
                    {
                        "external_calendar_id": "work",
                        "sync_enabled": True,
                        "sync_direction": "two_way",
                        "timezone": "UTC",
                    }
                ]
            },
        )
        assert select_res.status_code == 200
        assert select_res.json()[0]["external_calendar_id"] == "work"

        disconnect_res = client.post("/calendar/integrations/apple/disconnect")
        assert disconnect_res.status_code == 200
        assert disconnect_res.json()["status"] == "disconnected"



def test_connection_endpoints_require_authz() -> None:
    client = _anon_client()

    for method, path, payload in [
        (client.post, "/calendar/integrations/apple/connect", {"username": "u@example.com", "app_specific_password": "pw"}),
        (client.get, "/calendar/integrations/apple/status", None),
        (client.post, "/calendar/integrations/apple/disconnect", None),
        (client.post, "/calendar/integrations/apple/calendars/select", {"calendars": []}),
    ]:
        res = method(path, json=payload) if payload is not None else method(path)
        assert res.status_code in {401, 403}



def test_connect_validation_and_provider_unavailable_errors() -> None:
    client = _build_client("user-1")

    invalid = client.post(
        "/calendar/integrations/apple/connect",
        json={"username": "not-an-email", "app_specific_password": ""},
    )
    assert invalid.status_code == 422

    with patch("app.routers.calendar.get_provider_services", return_value=None):
        unavailable = client.post(
            "/calendar/integrations/apple/connect",
            json={"username": "ada@example.com", "app_specific_password": "abcd-efgh"},
        )
    assert unavailable.status_code == 503



def test_connect_maps_provider_failures_to_http_status_codes() -> None:
    client = _build_client("user-1")
    provider = MagicMock()
    provider.connection.validate_credentials.side_effect = CalendarIntegrationError(
        code=CalendarIntegrationErrorCode.AUTH,
        detail="Invalid app-specific password",
    )

    with patch("app.routers.calendar.get_provider_services", return_value=provider):
        auth_fail = client.post(
            "/calendar/integrations/apple/connect",
            json={"username": "ada@example.com", "app_specific_password": "bad-pass"},
        )

    assert auth_fail.status_code == 401
    assert "Invalid app-specific password" in auth_fail.json()["detail"]



def test_select_calendars_validation_failure_branch() -> None:
    client = _build_client("user-1")

    invalid = client.post(
        "/calendar/integrations/apple/calendars/select",
        json={
            "calendars": [
                {
                    "external_calendar_id": "work",
                    "sync_enabled": True,
                    "sync_direction": "invalid_mode",
                }
            ]
        },
    )
    assert invalid.status_code == 422
