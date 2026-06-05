"""Regression test for GAP-0047.

The settings flags ``BROADCAST_PREROLL_ENABLED`` / ``BROADCAST_MIDROLL_ENABLED``
(``S.broadcast_preroll_enabled`` / ``S.broadcast_midroll_enabled``) existed in
``app/core/settings.py`` but were never consulted by the code paths that serve
ads. As a result, setting either env var to ``0`` had zero runtime effect — the
global operator kill-switch was inert.

The fix wires the flags into:
  * ``app.services.broadcast_ads.build_pre_roll`` (global pre-roll kill-switch)
  * ``app.routers.broadcast_ads.trigger_ad_break_route`` (global mid-roll kill-switch)
  * ``app.routers.broadcast_ads.update_ad_config_route`` (reject enabling pre-roll
    on a session while the platform flag is off)

These tests exercise the service/handler functions directly (the guards live in
the function bodies, not in a dependency), so they are fully offline: the
broadcast store and the ad-serving engine are patched and no DynamoDB / AWS
access occurs. This mirrors ``test_broadcast_ads_admin_guard.py`` and avoids the
HTTP TestClient layer, which is broken in this environment by an httpx/starlette
version mismatch unrelated to this change.

Fails-before / passes-after: with the unwired code, the disabled-flag tests
returned an ad / 200 / accepted the config; the wired guards now suppress them.
"""

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.auth.roles import Role
from app.routers import broadcast_ads as ads_router
from app.routers.broadcast_ads import (
    BroadcastAdConfigIn,
    trigger_ad_break_route,
    update_ad_config_route,
)
from app.services import broadcast_ads as ads_service
from app.services.broadcast_ads import build_pre_roll


@contextmanager
def _patch_flags(module, *, preroll=True, midroll=True):
    """Patch the module-level ``S`` singleton with a stand-in carrying the two
    broadcast flags. ``Settings`` is a frozen dataclass, so individual attributes
    can't be patched in place; we swap the module reference instead."""
    fake = SimpleNamespace(
        broadcast_preroll_enabled=preroll,
        broadcast_midroll_enabled=midroll,
    )
    with patch.object(module, "S", fake):
        yield


def _mock_session():
    return SimpleNamespace(
        id="sess_001",
        created_by="broadcaster_user",
        status="live",
        pre_roll_enabled=True,
        mid_roll_ad_break_duration_seconds=30,
        mid_roll_skip_after_seconds=15,
        ad_break_active=False,
        ad_break_started_at=None,
        total_ad_breaks=0,
    )


# ─── Pre-roll global flag (service) ──────────────────────────────────


def test_preroll_served_when_global_flag_enabled():
    """Pre-roll returns an ad when the global flag is True (default)."""
    with _patch_flags(ads_service, preroll=True), patch.object(
        ads_service, "is_ad_free", return_value=False
    ):
        result = build_pre_roll(_mock_session(), viewer_id="viewer_1")
    assert result["pre_roll"] is not None
    assert result["ad_free"] is False


def test_preroll_suppressed_when_global_flag_disabled():
    """Pre-roll returns None when the global flag is False, even though the
    per-session ``pre_roll_enabled`` is True. FAILS BEFORE FIX (ad still served)."""
    with _patch_flags(ads_service, preroll=False), patch.object(
        ads_service, "is_ad_free", return_value=False
    ):
        result = build_pre_roll(_mock_session(), viewer_id="viewer_1")
    assert result["pre_roll"] is None
    assert result["ad_free"] is True


def test_subscriber_still_adfree_when_preroll_flag_disabled():
    """Ad-free viewers keep ad_free=True even when the global flag is off."""
    with _patch_flags(ads_service, preroll=False), patch.object(
        ads_service, "is_ad_free", return_value=True
    ):
        result = build_pre_roll(_mock_session(), viewer_id="broadcaster_user")
    assert result["ad_free"] is True
    assert result["pre_roll"] is None


# ─── Mid-roll global flag (router) ───────────────────────────────────


def _broadcaster_ctx():
    return {"user_sub": "broadcaster_user", "session_id": "s", "role": Role.USER, "ip": ""}


def test_midroll_trigger_blocked_when_flag_off():
    """POST ad-break returns 403 MIDROLL_DISABLED when the global flag is off.
    FAILS BEFORE FIX (returns 200 with an active break payload)."""
    ctx = _broadcaster_ctx()
    with _patch_flags(ads_router, midroll=False), patch.object(
        ads_router, "get_session", return_value=_mock_session()
    ):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(trigger_ad_break_route("sess_001", ctx))
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["code"] == "MIDROLL_DISABLED"


def test_midroll_trigger_allowed_when_flag_on():
    """POST ad-break succeeds when the global flag is on."""
    ctx = _broadcaster_ctx()
    payload = {"duration_seconds": 30, "started_at": 1000, "skip_after_seconds": 15}

    async def _noop(*_a, **_k):
        return None

    with _patch_flags(ads_router, midroll=True), patch.object(
        ads_router, "get_session", return_value=_mock_session()
    ), patch.object(
        ads_router, "start_ad_break", return_value=payload
    ), patch.object(
        ads_router, "schedule_ad_break_end", _noop
    ):
        out = asyncio.run(trigger_ad_break_route("sess_001", ctx))
    assert out.ok is True
    assert out.duration_seconds == 30


# ─── Config PATCH guard (router) ─────────────────────────────────────


def test_enable_preroll_via_config_blocked_when_flag_off():
    """PATCH ad-config with pre_roll_enabled=True is rejected (400 PREROLL_DISABLED)
    when the global flag is off. FAILS BEFORE FIX (config accepted)."""
    ctx = _broadcaster_ctx()
    with _patch_flags(ads_router, preroll=False), patch.object(
        ads_router, "get_session", return_value=_mock_session()
    ), patch.object(
        ads_router, "update_session_fields", return_value=_mock_session()
    ):
        with pytest.raises(HTTPException) as exc_info:
            update_ad_config_route(
                "sess_001", BroadcastAdConfigIn(pre_roll_enabled=True), ctx
            )
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["code"] == "PREROLL_DISABLED"


def test_disable_preroll_via_config_allowed_when_flag_off():
    """Disabling pre-roll on a session is always allowed regardless of the flag."""
    ctx = _broadcaster_ctx()
    with _patch_flags(ads_router, preroll=False), patch.object(
        ads_router, "get_session", return_value=_mock_session()
    ), patch.object(
        ads_router, "update_session_fields", return_value=_mock_session()
    ):
        out = update_ad_config_route(
            "sess_001", BroadcastAdConfigIn(pre_roll_enabled=False), ctx
        )
    assert out.session_id == "sess_001"
