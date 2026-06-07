"""GAP-0383: watermarked-download endpoint must enforce VOD-019 download-tier entitlement.

Offline / hermetic regression test. No AWS, no TestClient (broken in this repo).
The endpoint handler ``request_watermarked_download`` is a plain sync function, so
we call it directly with a fake ctx and patch its collaborators in the watermark
module namespace:

  - ``get_video``                         → stubbed video object
  - ``check_entitlement_purchase_only``   → stubbed entitlement
  - watermark generator helpers           → stubbed so no real S3/DDB is touched

Scenarios:
  1. NON-owner, entitlement download_allowed=False  → 403, no watermark minted
  2. NON-owner, entitlement download_allowed=True   → proceeds (200 ready)
  3. OWNER                                           → proceeds regardless (bypass)
  4. vod_purchase_tiers_enabled=False               → proceeds (check skipped)

Fails-before: scenario 1 returned a watermarked MP4 instead of 403.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import app.routers.watermark as wm
from app.core.settings import S
from app.services.vod_purchase import EntitlementStatus


OWNER = "alice"
BUYER = "bob"


def _fake_video(*, owner=OWNER, purchase_gated=True):
    return SimpleNamespace(
        video_id="v_test",
        owner_user_id=owner,
        allow_download=True,
        download_mp4_key="v/test.mp4",
        download_mp4_status="ready",
        watermark_downloads=True,
        # purchase gate fields
        available_purchase_types=["permanent", "download"] if purchase_gated else None,
        price_cents=999 if purchase_gated else None,
        download_price_cents=None,
        entitlement_sku="sku_test" if purchase_gated else None,
    )


@pytest.fixture
def patched(monkeypatch):
    """Patch all collaborators of request_watermarked_download.

    Returns a dict capturing whether a watermark URL was ever minted.
    """
    captured = {"minted": False}

    def _no_cache(video_id, user_id):
        return None

    def _mint(*a, **k):
        captured["minted"] = True
        return "https://example.test/watermarked.mp4"

    def _create_job(*, video_id, user_id, source_mp4_key):
        return {"job_id": "job_1", "output_mp4_key": "wm/test.mp4"}

    def _complete(job):
        return None

    monkeypatch.setattr(wm, "find_cached_watermark", _no_cache)
    monkeypatch.setattr(wm, "count_active_jobs", lambda u: 0)
    monkeypatch.setattr(wm, "create_watermark_job", _create_job)
    monkeypatch.setattr(wm, "complete_watermark_job_mock", _complete)
    monkeypatch.setattr(wm, "mint_watermarked_download_url", _mint)
    # dev_mode True so a passing call completes synchronously to a ready URL
    object.__setattr__(S, "dev_mode", True)
    object.__setattr__(S, "watermark_downloads_enabled", True)
    return captured


def _call(user_sub):
    return wm.request_watermarked_download(
        video_id="v_test", ctx={"user_sub": user_sub}
    )


def test_non_owner_no_download_rights_rejected(patched, monkeypatch):
    """Scenario 1: non-owner, download_allowed=False → 403, nothing minted."""
    object.__setattr__(S, "vod_purchase_tiers_enabled", True)
    monkeypatch.setattr(wm, "get_video", lambda vid: _fake_video())
    monkeypatch.setattr(
        "app.services.vod_purchase.check_entitlement_purchase_only",
        lambda *, user_id, video_id: EntitlementStatus(
            entitled=True, download_allowed=False, purchase_type="permanent"
        ),
    )

    with pytest.raises(HTTPException) as ei:
        _call(BUYER)

    assert ei.value.status_code == 403
    assert "purchase" in ei.value.detail.lower()
    assert patched["minted"] is False, "must not mint a watermarked MP4 when denied"


def test_non_owner_with_download_rights_proceeds(patched, monkeypatch):
    """Scenario 2: non-owner, download_allowed=True → proceeds."""
    object.__setattr__(S, "vod_purchase_tiers_enabled", True)
    monkeypatch.setattr(wm, "get_video", lambda vid: _fake_video())
    monkeypatch.setattr(
        "app.services.vod_purchase.check_entitlement_purchase_only",
        lambda *, user_id, video_id: EntitlementStatus(
            entitled=True, download_allowed=True, purchase_type="download"
        ),
    )

    resp = _call(BUYER)
    assert resp.status == "ready"
    assert resp.download_url
    assert patched["minted"] is True


def test_owner_bypasses_entitlement(patched, monkeypatch):
    """Scenario 3: owner proceeds regardless of any entitlement (bypass)."""
    object.__setattr__(S, "vod_purchase_tiers_enabled", True)
    monkeypatch.setattr(wm, "get_video", lambda vid: _fake_video(owner=OWNER))

    def _boom(*a, **k):  # owner must NOT trigger the entitlement check
        raise AssertionError("owner should bypass the entitlement check")

    monkeypatch.setattr(
        "app.services.vod_purchase.check_entitlement_purchase_only", _boom
    )

    resp = _call(OWNER)
    assert resp.status == "ready"
    assert patched["minted"] is True


def test_tiers_disabled_skips_check(patched, monkeypatch):
    """Scenario 4: vod_purchase_tiers_enabled=False → check skipped, proceeds."""
    object.__setattr__(S, "vod_purchase_tiers_enabled", False)
    monkeypatch.setattr(wm, "get_video", lambda vid: _fake_video())

    def _boom(*a, **k):
        raise AssertionError("entitlement check must be skipped when tiers disabled")

    monkeypatch.setattr(
        "app.services.vod_purchase.check_entitlement_purchase_only", _boom
    )

    resp = _call(BUYER)
    assert resp.status == "ready"
    assert patched["minted"] is True
