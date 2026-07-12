"""Unit tests for VOD DRM encryption layer (VOD-010).

Tests cover:
- Key derivation (consistency, uniqueness, length)
- Key ID derivation (URL-safe, deterministic)
- Key server endpoint (auth, asset validation, response format)
- Encryption params (keyinfo file generation, FFmpeg args)
- Integration with FFmpeg pipeline
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Set required env vars before importing app modules
os.environ.setdefault("VOD_DRM_ENABLED", "1")
os.environ.setdefault("VOD_DRM_KEY_ROOT", "test-vod-drm-root-key-for-unit-tests")
os.environ.setdefault("VOD_DRM_KEY_SERVER_BASE_URL", "http://localhost:8000/v1/vod/drm")
os.environ.setdefault("PLAYBACK_ENTITLEMENT_SECRET", "test-entitlement-secret")
os.environ.setdefault("UI_ACCESS_TOKEN_SECRET", "test-secret")
os.environ.setdefault("DEV_MODE", "1")


class TestKeyDerivation:
    """Test derive_content_key produces consistent 16-byte keys."""

    def test_derives_16_byte_key(self):
        from app.services.vod_drm_keys import derive_content_key

        key = derive_content_key("asset-123", "tenant-a")
        assert isinstance(key, bytes)
        assert len(key) == 16

    def test_deterministic_same_asset(self):
        from app.services.vod_drm_keys import derive_content_key

        key1 = derive_content_key("asset-abc", "tenant-a")
        key2 = derive_content_key("asset-abc", "tenant-a")
        assert key1 == key2

    def test_deterministic_same_asset_same_slot(self):
        from app.services.vod_drm_keys import derive_content_key

        key1 = derive_content_key("asset-xyz", "tenant-a", key_slot=3)
        key2 = derive_content_key("asset-xyz", "tenant-a", key_slot=3)
        assert key1 == key2

    def test_different_asset_produces_different_key(self):
        from app.services.vod_drm_keys import derive_content_key

        key1 = derive_content_key("asset-aaa", "tenant-a")
        key2 = derive_content_key("asset-bbb", "tenant-a")
        assert key1 != key2

    def test_different_slot_produces_different_key(self):
        from app.services.vod_drm_keys import derive_content_key

        key1 = derive_content_key("asset-123", "tenant-a", key_slot=0)
        key2 = derive_content_key("asset-123", "tenant-a", key_slot=1)
        assert key1 != key2

    def test_empty_asset_id_raises(self):
        from app.services.vod_drm_keys import VodDrmKeyError, derive_content_key

        with pytest.raises(VodDrmKeyError, match="asset_id must be non-empty"):
            derive_content_key("", "tenant-a")

    def test_whitespace_only_asset_id_raises(self):
        from app.services.vod_drm_keys import VodDrmKeyError, derive_content_key

        with pytest.raises(VodDrmKeyError, match="asset_id must be non-empty"):
            derive_content_key("   ", "tenant-a")


class TestKeyIdDerivation:
    """Test derive_key_id produces URL-safe identifiers."""

    def test_key_id_is_hex_string(self):
        from app.services.vod_drm_keys import derive_key_id

        key_id = derive_key_id("asset-123", "tenant-a")
        assert isinstance(key_id, str)
        assert len(key_id) == 32
        # Should be hex (URL-safe)
        int(key_id, 16)

    def test_key_id_is_deterministic(self):
        from app.services.vod_drm_keys import derive_key_id

        id1 = derive_key_id("my-video", "tenant-a")
        id2 = derive_key_id("my-video", "tenant-a")
        assert id1 == id2

    def test_different_asset_different_key_id(self):
        from app.services.vod_drm_keys import derive_key_id

        id1 = derive_key_id("video-1", "tenant-a")
        id2 = derive_key_id("video-2", "tenant-a")
        assert id1 != id2

    def test_key_id_url_safe(self):
        from app.services.vod_drm_keys import derive_key_id

        key_id = derive_key_id("asset/with/special chars!", "tenant-a")
        # Should only contain hex chars
        assert all(c in "0123456789abcdef" for c in key_id)


class TestKeyUri:
    """Test get_key_uri produces proper URLs."""

    def test_key_uri_format(self):
        from app.services.vod_drm_keys import derive_key_id, get_key_uri

        uri = get_key_uri("test-asset", "tenant-a")
        key_id = derive_key_id("test-asset", "tenant-a")
        assert f"/key/{key_id}" in uri
        assert "asset=test-asset" in uri
        assert uri.startswith("http://localhost:8000/v1/vod/drm/key/")


class TestValidateKeyId:
    """Test validate_key_id matches correctly."""

    def test_valid_key_id_matches(self):
        from app.services.vod_drm_keys import derive_key_id, validate_key_id

        key_id = derive_key_id("asset-test", "tenant-a")
        assert validate_key_id(key_id, "asset-test", "tenant-a") is True

    def test_invalid_key_id_does_not_match(self):
        from app.services.vod_drm_keys import validate_key_id

        assert validate_key_id("deadbeef" * 4, "asset-test", "tenant-a") is False


class TestKeyServerEndpoint:
    """Test the /v1/vod/drm/key/{key_id} endpoint."""

    @pytest.fixture(autouse=True)
    def _patch_playback_secret(self):
        """Ensure S.playback_entitlement_secret is set regardless of env var ordering."""
        from app.services import playback_entitlements as pe_svc
        orig = pe_svc.S.playback_entitlement_secret
        object.__setattr__(pe_svc.S, "playback_entitlement_secret", "test-entitlement-secret")
        yield
        object.__setattr__(pe_svc.S, "playback_entitlement_secret", orig)

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from app.main import create_app

        app = create_app()
        return TestClient(app)

    @pytest.fixture
    def valid_token(self):
        """Issue a valid playback entitlement token for testing."""
        from app.services.playback_entitlements import issue_playback_entitlement

        result = issue_playback_entitlement(
            tenant_id="test-tenant",
            asset_id="drm-test-asset",
            session_id="sess-001",
            device_id="dev-001",
            profile="hd_1080p",
            audience="playback",
            ttl_seconds=120,
        )
        return result["token"]

    def test_returns_401_without_token(self, client):
        from app.services.vod_drm_keys import derive_key_id

        key_id = derive_key_id("drm-test-asset", "test-tenant")
        resp = client.get(f"/v1/vod/drm/key/{key_id}?asset=drm-test-asset")
        assert resp.status_code == 422  # missing required query param 'token'

    def test_returns_401_with_invalid_token(self, client):
        from app.services.vod_drm_keys import derive_key_id

        key_id = derive_key_id("drm-test-asset", "test-tenant")
        resp = client.get(f"/v1/vod/drm/key/{key_id}?asset=drm-test-asset&token=invalid.token.here")
        assert resp.status_code in (401, 403)

    def test_returns_403_with_wrong_asset_id(self, client, valid_token):
        from app.services.vod_drm_keys import derive_key_id

        # Token was issued for "drm-test-asset" but we request for "other-asset"
        key_id = derive_key_id("other-asset", "test-tenant")
        resp = client.get(f"/v1/vod/drm/key/{key_id}?asset=other-asset&token={valid_token}")
        assert resp.status_code == 403
        detail = resp.json().get("detail", {})
        assert detail.get("code") == "asset_mismatch"

    def test_returns_200_with_valid_token(self, client, valid_token):
        from app.services.vod_drm_keys import derive_key_id

        key_id = derive_key_id("drm-test-asset", "test-tenant")
        resp = client.get(f"/v1/vod/drm/key/{key_id}?asset=drm-test-asset&token={valid_token}")
        assert resp.status_code == 200

    def test_response_is_16_bytes_octet_stream(self, client, valid_token):
        from app.services.vod_drm_keys import derive_key_id

        key_id = derive_key_id("drm-test-asset", "test-tenant")
        resp = client.get(f"/v1/vod/drm/key/{key_id}?asset=drm-test-asset&token={valid_token}")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/octet-stream"
        assert len(resp.content) == 16

    def test_response_is_consistent(self, client, valid_token):
        """Same request produces same key bytes."""
        from app.services.vod_drm_keys import derive_key_id

        key_id = derive_key_id("drm-test-asset", "test-tenant")
        url = f"/v1/vod/drm/key/{key_id}?asset=drm-test-asset&token={valid_token}"
        resp1 = client.get(url)
        # Need a new token since replay protection might block re-use
        from app.services.playback_entitlements import issue_playback_entitlement

        token2 = issue_playback_entitlement(
            tenant_id="test-tenant",
            asset_id="drm-test-asset",
            session_id="sess-002",
            device_id="dev-002",
            profile="hd_1080p",
            audience="playback",
            ttl_seconds=120,
        )["token"]
        resp2 = client.get(f"/v1/vod/drm/key/{key_id}?asset=drm-test-asset&token={token2}")
        assert resp1.content == resp2.content

    def test_nonexistent_key_id_returns_404(self, client, valid_token):
        resp = client.get(f"/v1/vod/drm/key/0000000000000000?asset=drm-test-asset&token={valid_token}")
        assert resp.status_code == 404
        detail = resp.json().get("detail", {})
        assert detail.get("code") == "key_not_found"

    def test_expired_token_returns_error(self, client):
        """Token with past expiry should fail."""
        import time

        from app.services.playback_entitlements import issue_playback_entitlement

        token = issue_playback_entitlement(
            tenant_id="test-tenant",
            asset_id="drm-test-asset",
            session_id="sess-exp",
            device_id="dev-exp",
            profile="hd_1080p",
            audience="playback",
            ttl_seconds=1,
            now_epoch=int(time.time()) - 1000,
        )["token"]

        from app.services.vod_drm_keys import derive_key_id

        key_id = derive_key_id("drm-test-asset", "test-tenant")
        resp = client.get(f"/v1/vod/drm/key/{key_id}?asset=drm-test-asset&token={token}")
        assert resp.status_code in (401, 403)


class TestDrmInfoEndpoint:
    """Test the /v1/vod/drm/info/{asset_id} endpoint."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from app.main import create_app

        app = create_app()
        return TestClient(app)

    def test_info_returns_drm_metadata(self, client):
        # GAP-0372: key id/uri are tenant-scoped; a tenant query param is required.
        resp = client.get("/v1/vod/drm/info/my-video-asset?tenant=tenant-a")
        assert resp.status_code == 200
        data = resp.json()
        assert data["drm_enabled"] is True
        assert data["asset_id"] == "my-video-asset"
        assert data["key_id"] is not None
        assert "key_uri" in data
        assert "/key/" in data["key_uri"]


class TestEncryptionParams:
    """Test vod_encryption.py helpers."""

    def test_prepare_encryption_params_creates_files(self):
        from app.services.vod_encryption import prepare_encryption_params

        with tempfile.TemporaryDirectory() as td:
            params = prepare_encryption_params("test-asset-enc", "tenant-a", scratch_dir=Path(td))
            assert params is not None
            assert params.asset_id == "test-asset-enc"
            assert len(params.key_bytes) == 16
            assert len(params.iv_hex) == 32
            assert Path(params.key_file_path).exists()
            assert Path(params.keyinfo_file_path).exists()

            # Verify key file content
            key_content = Path(params.key_file_path).read_bytes()
            assert key_content == params.key_bytes
            assert len(key_content) == 16

    def test_keyinfo_file_format(self):
        from app.services.vod_encryption import prepare_encryption_params

        with tempfile.TemporaryDirectory() as td:
            params = prepare_encryption_params("asset-keyinfo", "tenant-a", scratch_dir=Path(td))
            assert params is not None

            lines = Path(params.keyinfo_file_path).read_text().strip().split("\n")
            assert len(lines) == 3
            # Line 1: key URI
            assert lines[0].startswith("http")
            assert "/key/" in lines[0]
            # Line 2: key file path
            assert Path(lines[1]).exists()
            # Line 3: IV hex
            assert len(lines[2]) == 32
            int(lines[2], 16)  # should be valid hex

    def test_ffmpeg_encryption_args(self):
        from app.services.vod_encryption import (
            get_ffmpeg_encryption_args,
            prepare_encryption_params,
        )

        with tempfile.TemporaryDirectory() as td:
            params = prepare_encryption_params("asset-ffmpeg", "tenant-a", scratch_dir=Path(td))
            assert params is not None

            args = get_ffmpeg_encryption_args(params)
            assert "-hls_key_info_file" in args
            assert params.keyinfo_file_path in args

    def test_prepare_returns_none_when_disabled(self):
        from app.services.vod_encryption import prepare_encryption_params

        with patch("app.services.vod_encryption.is_drm_enabled", return_value=False):
            params = prepare_encryption_params("asset-disabled", "tenant-a")
            assert params is None

    def test_cleanup_removes_files(self):
        from app.services.vod_encryption import (
            cleanup_encryption_files,
            prepare_encryption_params,
        )

        with tempfile.TemporaryDirectory() as td:
            params = prepare_encryption_params("asset-cleanup", "tenant-a", scratch_dir=Path(td))
            assert params is not None
            assert Path(params.key_file_path).exists()
            assert Path(params.keyinfo_file_path).exists()

            cleanup_encryption_files(params)

            assert not Path(params.key_file_path).exists()
            assert not Path(params.keyinfo_file_path).exists()


class TestFfmpegPipelineIntegration:
    """Test that encryption args integrate with build_rendition_ffmpeg_args."""

    @patch("app.services.ffmpeg_abr_pipeline.get_ffmpeg_path", return_value="/usr/bin/ffmpeg")
    def test_build_args_without_encryption(self, _mock_ffmpeg):
        from app.contracts.watermark_policy import WatermarkPolicy
        from app.services.ffmpeg_abr_pipeline import build_rendition_ffmpeg_args

        with tempfile.TemporaryDirectory() as td:
            args = build_rendition_ffmpeg_args(
                input_url="http://example.com/input.mp4",
                output_dir=Path(td),
                rendition={"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 2500, "audio_bitrate_kbps": 128},
                watermark_policy=WatermarkPolicy(),
            )
            assert "-hls_key_info_file" not in args

    @patch("app.services.ffmpeg_abr_pipeline.get_ffmpeg_path", return_value="/usr/bin/ffmpeg")
    def test_build_args_with_encryption(self, _mock_ffmpeg):
        from app.contracts.watermark_policy import WatermarkPolicy
        from app.services.ffmpeg_abr_pipeline import build_rendition_ffmpeg_args
        from app.services.vod_encryption import prepare_encryption_params

        with tempfile.TemporaryDirectory() as td:
            params = prepare_encryption_params("pipeline-asset", "tenant-a", scratch_dir=Path(td))
            assert params is not None

            args = build_rendition_ffmpeg_args(
                input_url="http://example.com/input.mp4",
                output_dir=Path(td),
                rendition={"name": "720p", "width": 1280, "height": 720, "video_bitrate_kbps": 2500, "audio_bitrate_kbps": 128},
                watermark_policy=WatermarkPolicy(),
                encryption_keyinfo_file=params.keyinfo_file_path,
            )
            assert "-hls_key_info_file" in args
            idx = args.index("-hls_key_info_file")
            assert args[idx + 1] == params.keyinfo_file_path

    def test_ext_x_key_tag_generation(self):
        from app.services.vod_encryption import build_encrypted_manifest_ext_x_key

        tag = build_encrypted_manifest_ext_x_key("my-video-001", "tenant-a")
        assert tag.startswith("#EXT-X-KEY:METHOD=AES-128")
        assert 'URI="' in tag
        assert "IV=0x" in tag
        assert "{TOKEN}" in tag
