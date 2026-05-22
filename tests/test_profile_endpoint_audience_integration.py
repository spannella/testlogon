from __future__ import annotations

from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import create_app
from app.core.settings import S
from app.routers import profile as profile_router
from app.services import profile as profile_service
from app.auth.deps import AuthenticatedUser


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())

@pytest.fixture(autouse=True)
def _profile_lookup_filtering_flag_enabled():
    previous = bool(getattr(S, "profile_lookup_audience_filtering_enabled", False))
    object.__setattr__(S, "profile_lookup_audience_filtering_enabled", True)
    try:
        yield
    finally:
        object.__setattr__(S, "profile_lookup_audience_filtering_enabled", previous)


def _sample_profile() -> dict[str, Any]:
    profile = profile_service.empty_profile()
    profile.update(
        {
            "display_name": "Public Name",
            "first_name": "Member First",
            "languages": [{"name": "English", "level": "native"}],
            "location": "New York",
            "birthday": "2000-01-01",
            "displayed_email": "private@example.com",
            "profile_photo_url": "https://cdn.example/avatar.png",
        }
    )
    return profile


def _install_common_mocks(monkeypatch: pytest.MonkeyPatch, discoverability_status: str = "active") -> None:
    monkeypatch.setattr(profile_router, "_resolve_profile_identifier_to_user_sub", lambda _identifier: "u_target")
    monkeypatch.setattr(profile_router, "rate_limit_profile_lookup", lambda _user_sub, _ip: None)
    monkeypatch.setattr(profile_router, "record_profile_lookup", lambda **_kwargs: None)
    monkeypatch.setattr(profile_router, "get_profile", lambda _user_sub: _sample_profile())
    monkeypatch.setattr(profile_service, "get_profile", lambda _user_sub: _sample_profile())
    monkeypatch.setattr(
        profile_router,
        "get_profile_discoverability_state",
        lambda _user_sub: {"discoverability_status": discoverability_status},
    )
    monkeypatch.setattr(
        profile_service,
        "get_profile_discoverability_state",
        lambda _user_sub: {"discoverability_status": discoverability_status},
    )


async def _require_session_owner(*args, **kwargs):
    return {"user_sub": "u_target", "session_id": "s_owner"}


async def _require_session_member(*args, **kwargs):
    return {"user_sub": "u_member", "session_id": "s_member"}


async def _require_session_anon(*args, **kwargs):
    raise HTTPException(status_code=401, detail="unauthorized")


async def _get_authenticated_user_owner(_req):
    return AuthenticatedUser(sub="u_target")


async def _get_authenticated_user_member(_req):
    return AuthenticatedUser(sub="u_member")


async def _get_authenticated_user_anon(_req):
    raise HTTPException(status_code=401, detail="unauthorized")


def test_profile_endpoint_returns_owner_field_set(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_common_mocks(monkeypatch, discoverability_status="active")
    monkeypatch.setattr(profile_router, "get_authenticated_user", _get_authenticated_user_owner)
    monkeypatch.setattr(profile_router, "require_ui_session", _require_session_owner)
    monkeypatch.setattr(profile_router, "_resolve_canonical_identifier_for_user_sub", lambda _user_sub: "ada.username")

    resp = client.get("/ui/profiles/u_target")
    assert resp.status_code == 200
    body = resp.json()

    assert body["audience"] == "owner"
    assert body["canonical_identifier"] == "ada.username"
    assert body["profile"]["display_name"] == "Public Name"
    assert body["profile"]["first_name"] == "Member First"
    assert body["profile"]["birthday"] == "2000-01-01"
    assert body["profile"]["displayed_email"] == "private@example.com"


def test_profile_endpoint_returns_member_field_set(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_common_mocks(monkeypatch, discoverability_status="active")
    monkeypatch.setattr(profile_router, "get_authenticated_user", _get_authenticated_user_member)
    monkeypatch.setattr(profile_router, "require_ui_session", _require_session_member)

    resp = client.get("/ui/profiles/u_target")
    assert resp.status_code == 200
    body = resp.json()

    assert body["audience"] == "member"
    assert body["profile"]["display_name"] == "Public Name"
    assert body["profile"]["first_name"] == "Member First"
    assert body["profile"]["languages"] == [{"name": "English", "level": "native"}]
    assert body["profile"]["birthday"] is None
    assert body["profile"]["displayed_email"] is None


def test_profile_endpoint_returns_public_field_set_for_anonymous(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_common_mocks(monkeypatch, discoverability_status="active")
    monkeypatch.setattr(profile_router, "require_ui_session", _require_session_anon)

    resp = client.get("/ui/profiles/u_target")
    assert resp.status_code == 200
    body = resp.json()

    assert body["audience"] == "public"
    assert body["profile"]["display_name"] == "Public Name"
    assert body["profile"]["profile_photo_url"] == "https://cdn.example/avatar.png"
    assert body["profile"]["first_name"] is None
    assert body["profile"]["languages"] == []
    assert body["profile"]["birthday"] is None
    assert body["profile"]["displayed_email"] is None


@pytest.mark.parametrize(
    "discoverability_status,session_impl,expected_status",
    [
        ("hidden", _require_session_member, 404),
        ("hidden", _require_session_anon, 404),
        ("deactivated", _require_session_member, 404),
        ("deactivated", _require_session_anon, 404),
        ("deleted", _require_session_owner, 404),
        ("deleted", _require_session_member, 404),
        ("deleted", _require_session_anon, 404),
    ],
)
def test_profile_endpoint_suppression_states(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    discoverability_status: str,
    session_impl,
    expected_status: int,
) -> None:
    _install_common_mocks(monkeypatch, discoverability_status=discoverability_status)
    monkeypatch.setattr(profile_router, "require_ui_session", session_impl)

    resp = client.get("/ui/profiles/u_target")
    assert resp.status_code == expected_status
    assert resp.json()["detail"] == profile_service.PROFILE_READ_NOT_FOUND_DETAIL


def test_profile_endpoint_hidden_owner_remains_visible(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_common_mocks(monkeypatch, discoverability_status="hidden")
    monkeypatch.setattr(profile_router, "get_authenticated_user", _get_authenticated_user_owner)
    monkeypatch.setattr(profile_router, "require_ui_session", _require_session_owner)

    resp = client.get("/ui/profiles/u_target")
    assert resp.status_code == 200
    body = resp.json()

    assert body["audience"] == "owner"
    assert body["profile"]["display_name"] == "Public Name"
    assert body["profile"]["displayed_email"] == "private@example.com"


def test_profile_endpoint_filtering_flag_off_returns_legacy_unfiltered_profile(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_common_mocks(monkeypatch, discoverability_status="hidden")
    monkeypatch.setattr(profile_router, "require_ui_session", _require_session_anon)
    object.__setattr__(S, "profile_lookup_audience_filtering_enabled", False)

    resp = client.get("/ui/profiles/u_target")
    assert resp.status_code == 200
    body = resp.json()
    assert body["audience"] == "public"
    assert body["profile"]["display_name"] == "Public Name"
    # Legacy behavior when filtering is disabled keeps full profile payload.
    assert body["profile"]["first_name"] == "Member First"
    assert body["profile"]["birthday"] == "2000-01-01"
    assert body["profile"]["displayed_email"] == "private@example.com"


def test_profile_endpoint_emits_etag_header(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_common_mocks(monkeypatch, discoverability_status="active")
    monkeypatch.setattr(profile_router, "require_ui_session", _require_session_member)

    resp = client.get("/ui/profiles/u_target")
    assert resp.status_code == 200
    assert resp.headers.get("etag", "").startswith('W/"')
    assert resp.headers.get("cache-control") == "private, no-store"
    assert resp.headers.get("pragma") == "no-cache"
    assert resp.headers.get("vary") == "Authorization, Cookie"


def test_profile_endpoint_returns_304_when_if_none_match_matches(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_common_mocks(monkeypatch, discoverability_status="active")
    monkeypatch.setattr(profile_router, "require_ui_session", _require_session_member)

    first = client.get("/ui/profiles/u_target")
    assert first.status_code == 200
    etag = first.headers.get("etag")
    assert etag

    second = client.get("/ui/profiles/u_target", headers={"If-None-Match": etag})
    assert second.status_code == 304
    assert second.content == b""
    assert second.headers.get("etag") == etag
    assert second.headers.get("cache-control") == "private, no-store"
    assert second.headers.get("pragma") == "no-cache"
    assert second.headers.get("vary") == "Authorization, Cookie"


def test_profile_endpoint_rejects_overly_long_identifier_without_resolution(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_common_mocks(monkeypatch, discoverability_status="active")
    monkeypatch.setattr(profile_router, "require_ui_session", _require_session_anon)
    monkeypatch.setattr(
        profile_router,
        "_resolve_profile_identifier_to_user_sub",
        lambda _identifier: (_ for _ in ()).throw(AssertionError("resolver should not be called")),
    )

    too_long = "a" * (profile_router._MAX_PROFILE_IDENTIFIER_LEN + 1)
    resp = client.get(f"/ui/profiles/{too_long}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == profile_service.PROFILE_READ_NOT_FOUND_DETAIL


def test_profile_endpoint_rejects_control_char_identifier_without_resolution(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_common_mocks(monkeypatch, discoverability_status="active")
    monkeypatch.setattr(profile_router, "require_ui_session", _require_session_anon)
    monkeypatch.setattr(
        profile_router,
        "_resolve_profile_identifier_to_user_sub",
        lambda _identifier: (_ for _ in ()).throw(AssertionError("resolver should not be called")),
    )

    resp = client.get("/ui/profiles/%00bad")
    assert resp.status_code == 404
    assert resp.json()["detail"] == profile_service.PROFILE_READ_NOT_FOUND_DETAIL
