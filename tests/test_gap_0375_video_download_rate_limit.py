"""GAP-0375: download-URL rate limiting on the VOD download endpoint.

The download endpoint mints a presigned URL on every call. Before this fix it
read ``S.video_download_rate_limit_per_10m`` nowhere and never returned 429, so a
single user could farm unlimited presigned URLs for a video. The fix wires a
per-user-per-video DDB-backed bucket counter (``_bucket_limit``) keyed on
``viddl:{video_id}`` and returns 429 once the configured limit is exceeded.

These tests are fully offline: ``_bucket_limit`` is patched in the
``video_listing`` module namespace to simulate under-limit / over-limit, and the
presign + counter helpers are stubbed so no real S3/DynamoDB/AWS is touched. The
endpoint coroutine is invoked directly with a fake auth ctx (TestClient is
unusable in this environment).

Fails-before: with no rate-limit call, the 6th download still mints a URL.
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
os.environ.setdefault("API_KEY_PEPPER", "test-pepper")
os.environ.setdefault("DEV_MODE", "1")

import pytest
from fastapi import HTTPException

from app.core.settings import S
import app.routers.video_listing as vl


def _fake_video(owner="owner_a"):
    """A downloadable, owner-accessible video object (passes all auth checks)."""
    return SimpleNamespace(
        video_id="vid_x",
        owner_user_id=owner,
        status="published",
        visibility="public",
        allow_download=True,
        download_mp4_key="s3://bucket/vid_x.mp4",
        download_mp4_status="ready",
        available_purchase_types=None,
        price_cents=None,
        download_price_cents=None,
        entitlement_sku=None,
    )


def _call(user_sub="owner_a", video_id="vid_x"):
    return vl.download_video_endpoint(video_id=video_id, user={"user_sub": user_sub})


def test_under_limit_mints_url():
    """When the bucket allows the request, the presigned URL is returned."""
    presign = MagicMock(return_value={"url": "https://signed.example/vid_x"})
    with patch.object(vl, "get_video", return_value=_fake_video()), \
         patch.object(vl, "_bucket_limit", return_value=True) as bucket, \
         patch("app.services.vod_mp4_generator.mint_video_download_url", presign), \
         patch("app.services.video_metadata_store.increment_download_count"):
        result = _call()

    assert result == {"url": "https://signed.example/vid_x"}
    presign.assert_called_once()
    # bucket key is per-user (subject) + per-video (sid)
    args = bucket.call_args.args
    assert args[0] == "owner_a"
    assert args[1] == "viddl:vid_x"


def test_over_limit_returns_429_and_does_not_mint():
    """When the bucket rejects the request, 429 is raised and presign is skipped."""
    presign = MagicMock(return_value={"url": "https://signed.example/vid_x"})
    with patch.object(vl, "get_video", return_value=_fake_video()), \
         patch.object(vl, "_bucket_limit", return_value=False), \
         patch("app.services.vod_mp4_generator.mint_video_download_url", presign), \
         patch("app.services.video_metadata_store.increment_download_count"):
        with pytest.raises(HTTPException) as exc_info:
            _call()

    assert exc_info.value.status_code == 429
    detail = exc_info.value.detail
    assert detail["code"] == "download_rate_limit_exceeded"
    assert (exc_info.value.headers or {}).get("Retry-After") == "600"
    presign.assert_not_called()


def test_limit_value_read_from_setting_not_hardcoded():
    """The configured limit (not a literal 5) flows into _bucket_limit and the 429 body."""
    orig = getattr(S, "video_download_rate_limit_per_10m", 5)
    object.__setattr__(S, "video_download_rate_limit_per_10m", 3)
    try:
        with patch.object(vl, "get_video", return_value=_fake_video()), \
             patch.object(vl, "_bucket_limit", return_value=True) as bucket, \
             patch("app.services.vod_mp4_generator.mint_video_download_url",
                   MagicMock(return_value={"url": "u"})), \
             patch("app.services.video_metadata_store.increment_download_count"):
            _call()
        # max_n positional arg == configured value, window == 600
        assert bucket.call_args.args[2] == 3
        assert bucket.call_args.args[3] == 600

        # And the 429 body echoes the configured limit
        with patch.object(vl, "get_video", return_value=_fake_video()), \
             patch.object(vl, "_bucket_limit", return_value=False), \
             patch("app.services.vod_mp4_generator.mint_video_download_url", MagicMock()), \
             patch("app.services.video_metadata_store.increment_download_count"):
            with pytest.raises(HTTPException) as exc_info:
                _call()
        assert exc_info.value.detail["limit"] == 3
    finally:
        object.__setattr__(S, "video_download_rate_limit_per_10m", orig)


def test_zero_limit_disables_throttle():
    """limit<=0 means disabled: bucket is never consulted and the URL is minted."""
    orig = getattr(S, "video_download_rate_limit_per_10m", 5)
    object.__setattr__(S, "video_download_rate_limit_per_10m", 0)
    presign = MagicMock(return_value={"url": "u"})
    try:
        with patch.object(vl, "get_video", return_value=_fake_video()), \
             patch.object(vl, "_bucket_limit", return_value=False) as bucket, \
             patch("app.services.vod_mp4_generator.mint_video_download_url", presign), \
             patch("app.services.video_metadata_store.increment_download_count"):
            result = _call()
        assert result == {"url": "u"}
        bucket.assert_not_called()
        presign.assert_called_once()
    finally:
        object.__setattr__(S, "video_download_rate_limit_per_10m", orig)
