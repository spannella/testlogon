from app.services import profile
from fastapi import HTTPException


def _sample_profile() -> dict:
    out = profile.empty_profile()
    out.update(
        {
            "display_name": "Public Name",      # public
            "first_name": "Member Name",       # member
            "birthday": "2000-01-01",          # private
            "languages": [{"name": "English", "level": "native"}],  # member
            "profile_photo_url": "https://cdn/avatar.png",  # public
        }
    )
    return out


def test_resolve_profile_audience_owner_member_public() -> None:
    assert profile.resolve_profile_audience(requester_user_sub="u1", target_user_sub="u1") == "owner"
    assert profile.resolve_profile_audience(requester_user_sub="u2", target_user_sub="u1") == "member"
    assert profile.resolve_profile_audience(requester_user_sub=None, target_user_sub="u1") == "public"


def test_filter_profile_by_audience_owner_gets_all_fields() -> None:
    data = _sample_profile()
    filtered = profile.filter_profile_by_audience(data, audience="owner")
    assert filtered["display_name"] == "Public Name"
    assert filtered["first_name"] == "Member Name"
    assert filtered["birthday"] == "2000-01-01"


def test_filter_profile_by_audience_member_excludes_private_fields() -> None:
    data = _sample_profile()
    filtered = profile.filter_profile_by_audience(data, audience="member")
    assert filtered["display_name"] == "Public Name"      # public allowed
    assert filtered["first_name"] == "Member Name"        # member allowed
    assert filtered["languages"] == [{"name": "English", "level": "native"}]  # member allowed
    assert filtered["birthday"] is None                    # private blocked


def test_filter_profile_by_audience_public_only_gets_public_fields() -> None:
    data = _sample_profile()
    filtered = profile.filter_profile_by_audience(data, audience="public")
    assert filtered["display_name"] == "Public Name"      # public allowed
    assert filtered["profile_photo_url"] == "https://cdn/avatar.png"  # public allowed
    assert filtered["first_name"] is None                  # member blocked
    assert filtered["birthday"] is None                    # private blocked


def test_get_profile_for_requester_applies_owner_member_public(monkeypatch) -> None:
    monkeypatch.setattr(profile, "get_profile", lambda _user_sub: _sample_profile())
    monkeypatch.setattr(
        profile,
        "get_profile_discoverability_state",
        lambda _user_sub: {"discoverability_status": "active"},
    )

    owner = profile.get_profile_for_requester(target_user_sub="u1", requester_user_sub="u1")
    member = profile.get_profile_for_requester(target_user_sub="u1", requester_user_sub="u2")
    public = profile.get_profile_for_requester(target_user_sub="u1", requester_user_sub=None)

    assert owner["birthday"] == "2000-01-01"
    assert member["birthday"] is None
    assert public["first_name"] is None


def test_filter_profile_by_audience_rejects_invalid_audience() -> None:
    try:
        profile.filter_profile_by_audience(_sample_profile(), audience="admin")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "invalid profile audience" in str(exc)


def test_hidden_profile_is_suppressed_for_member_and_public_but_visible_to_owner(monkeypatch) -> None:
    monkeypatch.setattr(profile, "get_profile", lambda _user_sub: _sample_profile())
    monkeypatch.setattr(
        profile,
        "get_profile_discoverability_state",
        lambda _user_sub: {"discoverability_status": "hidden"},
    )

    owner = profile.get_profile_for_requester(target_user_sub="u1", requester_user_sub="u1")
    assert owner["display_name"] == "Public Name"

    for requester in ("u2", None):
        try:
            profile.get_profile_for_requester(target_user_sub="u1", requester_user_sub=requester)
            assert False, "expected HTTPException"
        except HTTPException as exc:
            assert exc.status_code == 404
            assert exc.detail == profile.PROFILE_READ_NOT_FOUND_DETAIL


def test_deactivated_profile_is_suppressed_for_member_and_public_but_visible_to_owner(monkeypatch) -> None:
    monkeypatch.setattr(profile, "get_profile", lambda _user_sub: _sample_profile())
    monkeypatch.setattr(
        profile,
        "get_profile_discoverability_state",
        lambda _user_sub: {"discoverability_status": "deactivated"},
    )

    owner = profile.get_profile_for_requester(target_user_sub="u1", requester_user_sub="u1")
    assert owner["display_name"] == "Public Name"

    for requester in ("u2", None):
        try:
            profile.get_profile_for_requester(target_user_sub="u1", requester_user_sub=requester)
            assert False, "expected HTTPException"
        except HTTPException as exc:
            assert exc.status_code == 404
            assert exc.detail == profile.PROFILE_READ_NOT_FOUND_DETAIL


def test_deleted_profile_is_suppressed_for_owner_member_and_public(monkeypatch) -> None:
    monkeypatch.setattr(profile, "get_profile", lambda _user_sub: _sample_profile())
    monkeypatch.setattr(
        profile,
        "get_profile_discoverability_state",
        lambda _user_sub: {"discoverability_status": "deleted"},
    )

    for requester in ("u1", "u2", None):
        try:
            profile.get_profile_for_requester(target_user_sub="u1", requester_user_sub=requester)
            assert False, "expected HTTPException"
        except HTTPException as exc:
            assert exc.status_code == 404
            assert exc.detail == profile.PROFILE_READ_NOT_FOUND_DETAIL
