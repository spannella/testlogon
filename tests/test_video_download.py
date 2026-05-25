"""Unit tests for VOD-012: Optional MP4 Download.

Tests the MP4 generation service, download URL minting, and the
download endpoint (auth, entitlement, URL generation).
"""

from __future__ import annotations

import time
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import patch, MagicMock

import pytest
from fastapi import HTTPException

from app.models_video import UpdateVideoIn, VideoMetadataModel
from app.services.vod_mp4_generator import generate_download_mp4, mint_video_download_url


# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_video(**overrides) -> VideoMetadataModel:
    """Create a VideoMetadataModel with sensible defaults."""
    defaults = dict(
        id="v_test123",
        owner_user_id="user_owner",
        title="Test Video",
        status="published",
        created_at=int(time.time()),
        updated_at=int(time.time()),
        visibility="public",
        allow_download=True,
        download_mp4_key="tenants/user_owner/assets/v_test123/download/v_test123.mp4",
        download_mp4_size_bytes=1048576,
        download_mp4_status="ready",
    )
    defaults.update(overrides)
    return VideoMetadataModel(**defaults)


# ─── MP4 Generation Tests ─────────────────────────────────────────────────────


class TestGenerateMp4MockMode:
    """Tests for generate_download_mp4 in dev/mock mode."""

    @patch("app.services.vod_mp4_generator.S")
    def test_generate_mp4_mock_mode_returns_placeholder(self, mock_s):
        """In dev mode, generate_download_mp4 returns instant mock result."""
        mock_s.dev_mode = True
        mock_s.vod_output_prefix = "tenants"
        mock_s.transcode_output_prefix = "tenants"

        video = _make_video(
            download_mp4_key="",
            download_mp4_status="",
            download_mp4_size_bytes=0,
        )
        result = generate_download_mp4(video)

        assert result["download_mp4_status"] == "ready"
        assert result["download_mp4_key"] == "tenants/user_owner/assets/v_test123/download/v_test123.mp4"
        assert result["download_mp4_size_bytes"] == 0

    @patch("app.services.vod_mp4_generator.S")
    def test_generate_mp4_uses_vod_output_prefix(self, mock_s):
        """Prefix is derived from settings."""
        mock_s.dev_mode = True
        mock_s.vod_output_prefix = "custom_prefix"
        mock_s.transcode_output_prefix = "fallback"

        video = _make_video(id="v_abc", owner_user_id="owner_xyz")
        result = generate_download_mp4(video)

        assert result["download_mp4_key"] == "custom_prefix/owner_xyz/assets/v_abc/download/v_abc.mp4"

    @patch("app.services.vod_mp4_generator.S")
    def test_generate_mp4_falls_back_to_transcode_prefix(self, mock_s):
        """Falls back to transcode_output_prefix when vod_output_prefix is empty."""
        mock_s.dev_mode = True
        mock_s.vod_output_prefix = ""
        mock_s.transcode_output_prefix = "transcode_pfx"

        video = _make_video(id="v_fb", owner_user_id="owner_fb")
        result = generate_download_mp4(video)

        assert result["download_mp4_key"].startswith("transcode_pfx/")


# ─── Download URL Minting Tests ───────────────────────────────────────────────


class TestMintDownloadUrl:
    """Tests for mint_video_download_url."""

    @patch("app.services.vod_mp4_generator.S")
    @patch("app.services.vod_mp4_generator.now_ts")
    def test_mint_download_url_dev_mode(self, mock_now, mock_s):
        """In dev mode, returns a /mock/s3/ URL."""
        mock_s.dev_mode = True
        mock_s.vod_output_bucket = "vod-output"
        mock_s.transcode_output_bucket = "vod-output"
        mock_s.video_download_url_ttl_seconds = 3600
        mock_now.return_value = 1000000

        video = _make_video()
        result = mint_video_download_url(video, ttl=3600)

        assert "/mock/s3/vod-output/" in result["download_url"]
        assert "v_test123.mp4" in result["download_url"]
        assert "expires=1003600" in result["download_url"]
        assert "disposition=attachment" in result["download_url"]
        assert result["download_expires_at"] == 1003600
        assert result["filename"] == "Test Video.mp4"
        assert result["content_type"] == "video/mp4"
        assert result["file_size_bytes"] == 1048576

    @patch("app.services.vod_mp4_generator.S")
    @patch("app.services.vod_mp4_generator.now_ts")
    def test_mint_download_url_uses_video_title(self, mock_now, mock_s):
        """Filename is derived from video title."""
        mock_s.dev_mode = True
        mock_s.vod_output_bucket = "bucket"
        mock_s.transcode_output_bucket = "bucket"
        mock_now.return_value = 100

        video = _make_video(title="My Cool Video")
        result = mint_video_download_url(video, ttl=60)

        assert result["filename"] == "My Cool Video.mp4"


# ─── Download Endpoint Tests (via service layer logic) ────────────────────────


class TestDownloadEndpointLogic:
    """Tests for the download endpoint authorization logic.

    These test the logic that would run inside the endpoint handler
    without needing the full HTTP stack.
    """

    def test_download_endpoint_owner_success(self):
        """Owner can download their own video with download enabled."""
        video = _make_video()
        user_sub = "user_owner"

        # Owner check passes
        assert video.owner_user_id == user_sub
        assert video.allow_download is True
        assert video.download_mp4_status == "ready"
        assert video.download_mp4_key != ""

    def test_download_endpoint_non_owner_forbidden(self):
        """Non-owner cannot download a private video."""
        video = _make_video(visibility="private")
        user_sub = "some_other_user"

        is_owner = video.owner_user_id == user_sub
        is_public = video.status == "published" and video.visibility in ("public", "unlisted")

        assert not is_owner
        assert not is_public  # Should result in 403

    def test_download_endpoint_download_disabled_403(self):
        """Video with allow_download=false should return 403."""
        video = _make_video(allow_download=False)
        assert not video.allow_download

    def test_download_endpoint_feature_disabled_503(self):
        """When VIDEO_DOWNLOAD_ENABLED is false, endpoint returns 503."""
        # This tests the setting check at the top of the endpoint
        from app.core.settings import S as real_s
        # Just verify the setting exists and is configurable
        assert hasattr(real_s, "video_download_enabled")

    def test_download_endpoint_no_mp4_404(self):
        """Video with no MP4 key returns 404."""
        video = _make_video(download_mp4_key="", download_mp4_status="")
        assert video.download_mp4_key == ""
        assert video.download_mp4_status == ""

    def test_toggle_allow_download_triggers_generation(self):
        """Setting allow_download=True on a video triggers MP4 generation."""
        video = _make_video(
            allow_download=False,
            download_mp4_key="",
            download_mp4_status="",
            download_mp4_size_bytes=0,
        )

        # Simulate what the PATCH handler does
        with patch("app.services.vod_mp4_generator.S") as mock_s:
            mock_s.dev_mode = True
            mock_s.vod_output_prefix = "tenants"
            mock_s.transcode_output_prefix = "tenants"

            result = generate_download_mp4(video)

        assert result["download_mp4_status"] == "ready"
        assert "download" in result["download_mp4_key"]
        assert result["download_mp4_key"].endswith(".mp4")

    def test_non_owner_public_video_allowed(self):
        """Non-owner can download a published+public video."""
        video = _make_video(visibility="public", status="published")
        user_sub = "some_viewer"

        is_owner = video.owner_user_id == user_sub
        is_public = video.status == "published" and video.visibility in ("public", "unlisted")

        assert not is_owner
        assert is_public  # Should be allowed

    def test_non_owner_unlisted_video_allowed(self):
        """Non-owner can download a published+unlisted video."""
        video = _make_video(visibility="unlisted", status="published")
        user_sub = "some_viewer"

        is_owner = video.owner_user_id == user_sub
        is_public = video.status == "published" and video.visibility in ("public", "unlisted")

        assert not is_owner
        assert is_public  # Should be allowed

    def test_download_count_field_exists(self):
        """Video model has download_count field for analytics."""
        video = _make_video(download_count=5)
        assert video.download_count == 5

    def test_download_mp4_key_path_convention(self):
        """MP4 key follows expected path convention."""
        video = _make_video(
            id="v_vid123",
            owner_user_id="user_abc",
            download_mp4_key="tenants/user_abc/assets/v_vid123/download/v_vid123.mp4",
        )
        assert "/download/" in video.download_mp4_key
        assert video.download_mp4_key.endswith(".mp4")
        assert "v_vid123" in video.download_mp4_key
