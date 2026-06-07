"""Regression tests for GAP-0037: bridge rootctl admin_capabilities → admin_profile JWT claim.

Before the fix, `mint_access_token` never wrote an `admin_profile` claim, so every
admin user's session was decoded as `AdminProfile(type=GENERAL)` (full access) by
`normalize_admin_profile(None)` — the rootctl capability system was dead code.

These tests run fully offline (no real AWS): DynamoDB access is replaced with an
in-memory fake patched onto `app.services.sessions.T`.
"""

from types import SimpleNamespace
from unittest.mock import patch

from app.services import sessions as sessions_service
from app.services.sessions import _build_admin_profile_claim


FAKE_SECRET = "test-secret-for-admin-caps"


def _fake_settings(root_user_sub="root@example.com"):
    return SimpleNamespace(
        ui_access_token_secret=FAKE_SECRET,
        ui_access_token_ttl_seconds=900,
        root_access_token_ttl_seconds=120,
        root_user_sub=root_user_sub,
    )


def _users_table(item):
    """Return an object exposing `.users.get_item(...)` like app.core.tables.T."""
    class _Users:
        def get_item(self, Key=None, **kwargs):  # noqa: N803 (boto3 kwarg name)
            return {"Item": item} if item is not None else {}

    return SimpleNamespace(users=_Users())


# ---------------------------------------------------------------------------
# _build_admin_profile_claim — the bridging logic
# ---------------------------------------------------------------------------

def test_admin_with_no_capabilities_gets_general_profile():
    """FAILS BEFORE FIX (no claim minted); PASSES AFTER FIX with general profile."""
    user_item = {"user_sub": "admin@example.com", "role": "admin", "admin_capabilities": []}
    with patch.object(sessions_service, "S", _fake_settings()):
        profile = _build_admin_profile_claim("admin@example.com", user_item)
    assert profile == {"type": "general"}


def test_admin_with_capabilities_gets_scoped_profile():
    """Capabilities map to canonical AdminScope values in a scoped profile."""
    user_item = {
        "user_sub": "admin@example.com",
        "role": "admin",
        "admin_capabilities": ["user_support"],
    }
    with patch.object(sessions_service, "S", _fake_settings()):
        profile = _build_admin_profile_claim("admin@example.com", user_item)
    assert profile == {"type": "scoped", "scopes": ["auth_support"]}


def test_admin_multiple_capabilities_dedupe_and_sort():
    """billing_ops + billing_read both map to billing_support → single scope; multiple distinct caps sorted."""
    user_item = {
        "user_sub": "admin@example.com",
        "role": "admin",
        "admin_capabilities": ["billing_read", "billing_ops", "file_content", "user_support"],
    }
    with patch.object(sessions_service, "S", _fake_settings()):
        profile = _build_admin_profile_claim("admin@example.com", user_item)
    assert profile == {
        "type": "scoped",
        "scopes": ["auth_support", "billing_support", "content_moderation"],
    }


def test_admin_with_unknown_capability_falls_back_to_general():
    """Unrecognized capability names map to no scope → general (fail-open, current default)."""
    user_item = {
        "user_sub": "admin@example.com",
        "role": "admin",
        "admin_capabilities": ["totally_unknown"],
    }
    with patch.object(sessions_service, "S", _fake_settings()):
        profile = _build_admin_profile_claim("admin@example.com", user_item)
    assert profile == {"type": "general"}


def test_root_user_gets_no_admin_profile():
    """Root bypasses scope checks; admin_profile must not be added."""
    user_item = {"user_sub": "root@example.com", "role": "root", "admin_capabilities": []}
    with patch.object(sessions_service, "S", _fake_settings(root_user_sub="root@example.com")):
        profile = _build_admin_profile_claim("root@example.com", user_item)
    assert profile is None


def test_plain_user_gets_no_admin_profile():
    user_item = {"user_sub": "user@example.com", "role": "user"}
    with patch.object(sessions_service, "S", _fake_settings()):
        profile = _build_admin_profile_claim("user@example.com", user_item)
    assert profile is None


# ---------------------------------------------------------------------------
# mint_access_token — end-to-end: the claim lands in the JWT payload
# ---------------------------------------------------------------------------

def _decode(token):
    return sessions_service.jwt.decode(
        token, FAKE_SECRET, algorithms=["HS256"], options={"verify_exp": False}
    )


def test_mint_access_token_embeds_scoped_admin_profile():
    """FAILS BEFORE FIX: payload has no 'admin_profile'. PASSES AFTER FIX."""
    user_item = {
        "user_sub": "admin@example.com",
        "role": "admin",
        "admin_capabilities": ["user_support"],
    }
    with patch.object(sessions_service, "S", _fake_settings()), patch.object(
        sessions_service, "T", _users_table(user_item)
    ), patch.object(sessions_service, "now_ts", return_value=1000):
        token = sessions_service.mint_access_token("admin@example.com", "sid-1")

    payload = _decode(token)
    assert payload["role"] == "admin"
    assert payload["admin_profile"] == {"type": "scoped", "scopes": ["auth_support"]}


def test_mint_access_token_general_admin_when_no_caps():
    user_item = {"user_sub": "admin@example.com", "role": "admin"}
    with patch.object(sessions_service, "S", _fake_settings()), patch.object(
        sessions_service, "T", _users_table(user_item)
    ), patch.object(sessions_service, "now_ts", return_value=1000):
        token = sessions_service.mint_access_token("admin@example.com", "sid-1")

    payload = _decode(token)
    assert payload["role"] == "admin"
    assert payload["admin_profile"] == {"type": "general"}


def test_mint_access_token_root_has_no_admin_profile():
    user_item = {"user_sub": "root@example.com", "role": "root"}
    with patch.object(sessions_service, "S", _fake_settings(root_user_sub="root@example.com")), patch.object(
        sessions_service, "T", _users_table(user_item)
    ), patch.object(sessions_service, "now_ts", return_value=1000):
        token = sessions_service.mint_access_token("root@example.com", "sid-1")

    payload = _decode(token)
    assert payload["role"] == "root"
    assert "admin_profile" not in payload


def test_mint_access_token_ddb_failure_does_not_break_minting():
    """A DDB read failure must not break login; falls back to plain user token."""
    class _Boom:
        def get_item(self, **kwargs):
            raise RuntimeError("ddb down")

    with patch.object(sessions_service, "S", _fake_settings()), patch.object(
        sessions_service, "T", SimpleNamespace(users=_Boom())
    ), patch.object(sessions_service, "now_ts", return_value=1000):
        token = sessions_service.mint_access_token("admin@example.com", "sid-1")

    payload = _decode(token)
    assert payload["role"] == "user"
    assert "admin_profile" not in payload


# ---------------------------------------------------------------------------
# Enforcement consistency: scoped profile is actually restricted
# ---------------------------------------------------------------------------

def test_scoped_admin_blocked_from_out_of_scope_endpoint():
    from app.auth.roles import (
        AdminProfile,
        AdminProfileType,
        AdminScope,
        admin_profile_has_scope,
        normalize_admin_profile,
    )

    # Round-trip the minted claim through normalization (what deps.py does).
    profile = normalize_admin_profile({"type": "scoped", "scopes": ["auth_support"]})
    assert profile == AdminProfile(
        type=AdminProfileType.SCOPED, scopes=(AdminScope.AUTH_SUPPORT,)
    )
    assert admin_profile_has_scope(profile, AdminScope.AUTH_SUPPORT)
    assert not admin_profile_has_scope(profile, AdminScope.BILLING_SUPPORT)


def test_general_admin_passes_all_scope_checks():
    from app.auth.roles import (
        AdminProfile,
        AdminProfileType,
        AdminScope,
        admin_profile_has_scope,
    )

    general = AdminProfile(type=AdminProfileType.GENERAL)
    for scope in AdminScope:
        assert admin_profile_has_scope(general, scope), f"General admin blocked from {scope}"
