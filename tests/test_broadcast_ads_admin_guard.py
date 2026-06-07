"""Regression test for GAP-0046.

The broadcaster-or-admin guards in ``app/routers/broadcast_ads.py`` compared
``ctx.get("role")`` against the plain-string set ``{"admin", "root"}``. That
only worked by accident of ``Role(str, Enum)`` making ``Role.ADMIN == "admin"``.
The fix compares against the enum members ``{Role.ADMIN, Role.ROOT}`` so the
guard is correct whether ``ctx["role"]`` is a role string OR a ``Role`` enum.

This exercises the route handler functions directly (the guard lives in the
handler body, not in a dependency), so the test is fully offline: the broadcast
store is patched and no DynamoDB / AWS access occurs. It avoids the HTTP
TestClient layer, which is broken in this environment by an httpx/starlette
version mismatch unrelated to this change.

Fails-before / passes-after: with the old string-set guard, the ``Role.ADMIN`` /
``Role.ROOT`` enum parametrisations would raise 403 the moment ``Role`` stopped
inheriting ``str`` (the latent defect). The enum-member guard accepts both the
string and enum forms by construction.
"""

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.auth.roles import Role
from app.routers import broadcast_ads
from app.routers.broadcast_ads import (
    BroadcastAdConfigIn,
    update_ad_config_route,
)


def _mock_session():
    return SimpleNamespace(
        id="sess_001",
        created_by="broadcaster_user",
        pre_roll_enabled=True,
        mid_roll_ad_break_duration_seconds=30,
        mid_roll_skip_after_seconds=15,
        ad_break_active=False,
        ad_break_started_at=None,
        total_ad_breaks=0,
    )


@pytest.mark.parametrize("role_val", ["admin", Role.ADMIN, "root", Role.ROOT])
def test_admin_or_root_can_update_ad_config_on_other_broadcaster(role_val):
    """Admin/root (string OR Role enum) must bypass the broadcaster-only guard."""
    ctx = {"user_sub": "other_user", "session_id": "s", "role": role_val, "ip": ""}
    with patch.object(
        broadcast_ads, "get_session", return_value=_mock_session()
    ), patch.object(
        broadcast_ads, "update_session_fields", return_value=_mock_session()
    ):
        # Must NOT raise — admin/root override the broadcaster-only check.
        out = update_ad_config_route(
            "sess_001",
            BroadcastAdConfigIn(pre_roll_enabled=False),
            ctx,
        )
    assert out.session_id == "sess_001"


def test_non_owner_regular_user_is_still_forbidden():
    """A regular user who is not the broadcaster must still get 403."""
    ctx = {"user_sub": "other_user", "session_id": "s", "role": "user", "ip": ""}
    with patch.object(
        broadcast_ads, "get_session", return_value=_mock_session()
    ), patch.object(
        broadcast_ads, "update_session_fields", return_value=_mock_session()
    ):
        with pytest.raises(HTTPException) as exc_info:
            update_ad_config_route(
                "sess_001",
                BroadcastAdConfigIn(pre_roll_enabled=False),
                ctx,
            )
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["code"] == "NOT_BROADCASTER"
