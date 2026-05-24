"""Unit tests for VOD S3 upload, thumbnail extraction, and playback URL (VOD-005).

Tests use moto-mocked S3 (same pattern as other tests in this project).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─── Environment setup (before any app imports) ─────────────────────────────

os.environ.setdefault("DEV_MODE", "1")
os.environ.setdefault("VOD_OUTPUT_BUCKET", "vod-output")
os.environ.setdefault("VOD_OUTPUT_PREFIX", "tenants")
os.environ.setdefault("VOD_OUTPUT_RETENTION_DAYS", "30")
os.environ.setdefault("VOD_UPLOAD_CONCURRENCY", "4")
os.environ.setdefault("VOD_UPLOAD_MULTIPART_THRESHOLD_MB", "8")
os.environ.setdefault("VOD_UPLOAD_MULTIPART_CHUNKSIZE_MB", "8")
os.environ.setdefault("VOD_PLAYBACK_URL_TTL_SECONDS", "3600")
os.environ.setdefault("VOD_CLOUDFRONT_DOMAIN", "")
os.environ.setdefault("VOD_CLOUDFRONT_SIGNING_SECRET", "dev-vod-cf-secret")
os.environ.setdefault("VOD_THUMBNAIL_ENABLED", "1")
os.environ.setdefault("VOD_THUMBNAIL_TIMESTAMPS", "0,10,30")
os.environ.setdefault("VOD_THUMBNAIL_WIDTH", "640")
os.environ.setdefault("VOD_THUMBNAIL_QUALITY", "5")
os.environ.setdefault("BROADCAST_CLOUDFRONT_SIGNING_SECRET", "dev-cloudfront-secret")
os.environ.setdefault("BROADCAST_CLOUDFRONT_DOMAIN", "")


# ─── Moto S3 fixture ────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def mock_s3(tmp_path, monkeypatch):
    """Set up moto S3 mock for all tests.

    Uses monkeypatch to avoid leaking moto context across test files.
    """
    import boto3
    from moto import mock_aws

    ctx = mock_aws()
    ctx.start()

    try:
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="vod-output")

        # Patch the module-level _s3 clients in the services
        monkeypatch.setattr("app.services.vod_s3_uploader._s3", s3)
        monkeypatch.setattr("app.services.vod_playback_url._s3", s3)
        monkeypatch.setattr("app.services.vod_thumbnail_extractor._s3", s3)
        yield s3
    finally:
        ctx.stop()


# ─── Helper to create test output directory ──────────────────────────────────

def _create_test_output_dir(tmp_path: Path) -> Path:
    """Create a realistic HLS output directory structure."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    # Master playlist
    master = output_dir / "master.m3u8"
    master.write_text(
        "#EXTM3U\n"
        "#EXT-X-STREAM-INF:BANDWIDTH=2800000,RESOLUTION=1280x720\n"
        "720p/index.m3u8\n"
        "#EXT-X-STREAM-INF:BANDWIDTH=1400000,RESOLUTION=854x480\n"
        "480p/index.m3u8\n"
    )

    # 720p rendition
    r720 = output_dir / "720p"
    r720.mkdir()
    (r720 / "index.m3u8").write_text(
        "#EXTM3U\n#EXT-X-TARGETDURATION:4\n#EXTINF:4.0,\nsegment_000.ts\n#EXT-X-ENDLIST\n"
    )
    (r720 / "segment_000.ts").write_bytes(b"\x47" * 1024)  # 1KB TS segment

    # 480p rendition
    r480 = output_dir / "480p"
    r480.mkdir()
    (r480 / "index.m3u8").write_text(
        "#EXTM3U\n#EXT-X-TARGETDURATION:4\n#EXTINF:4.0,\nsegment_000.ts\n#EXT-X-ENDLIST\n"
    )
    (r480 / "segment_000.ts").write_bytes(b"\x47" * 512)

    return output_dir


def _create_test_thumbnails(tmp_path: Path) -> Path:
    """Create test thumbnail files."""
    thumb_dir = tmp_path / "thumbnails"
    thumb_dir.mkdir()
    # Minimal JPEG header (not a valid image, but sufficient for upload tests)
    jpeg_header = b"\xff\xd8\xff\xe0" + b"\x00" * 100
    (thumb_dir / "poster_0s.jpg").write_bytes(jpeg_header)
    (thumb_dir / "poster_10s.jpg").write_bytes(jpeg_header)
    return thumb_dir


# ─── Tests: Content-Type inference ──────────────────────────────────────────


class TestContentTypeInference:
    def test_m3u8_content_type(self):
        from app.services.vod_s3_uploader import _infer_content_type

        assert _infer_content_type("index.m3u8") == "application/vnd.apple.mpegurl"

    def test_ts_content_type(self):
        from app.services.vod_s3_uploader import _infer_content_type

        assert _infer_content_type("segment_000.ts") == "video/mp2t"

    def test_jpg_content_type(self):
        from app.services.vod_s3_uploader import _infer_content_type

        assert _infer_content_type("poster_0s.jpg") == "image/jpeg"

    def test_json_content_type(self):
        from app.services.vod_s3_uploader import _infer_content_type

        assert _infer_content_type("metadata.json") == "application/json"

    def test_unknown_content_type(self):
        from app.services.vod_s3_uploader import _infer_content_type

        assert _infer_content_type("file.xyz") == "application/octet-stream"


class TestCacheControlInference:
    def test_master_playlist_short_cache(self):
        from app.services.vod_s3_uploader import _infer_cache_control

        assert _infer_cache_control("master.m3u8") == "max-age=5, stale-while-revalidate=10"

    def test_variant_playlist_immutable(self):
        from app.services.vod_s3_uploader import _infer_cache_control

        assert _infer_cache_control("index.m3u8") == "max-age=31536000, immutable"

    def test_ts_segment_immutable(self):
        from app.services.vod_s3_uploader import _infer_cache_control

        assert _infer_cache_control("segment_000.ts") == "max-age=31536000, immutable"

    def test_jpg_daily_cache(self):
        from app.services.vod_s3_uploader import _infer_cache_control

        assert _infer_cache_control("poster_0s.jpg") == "max-age=86400"

    def test_json_no_cache(self):
        from app.services.vod_s3_uploader import _infer_cache_control

        assert _infer_cache_control("metadata.json") == "no-cache"


# ─── Tests: Upload segment ──────────────────────────────────────────────────


class TestUploadSegment:
    def test_upload_sets_correct_content_type(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import upload_segment

        test_file = tmp_path / "segment_000.ts"
        test_file.write_bytes(b"\x47" * 256)

        upload_segment(
            local_path=test_file,
            bucket="vod-output",
            key="tenants/t1/assets/v1/hls/720p/segment_000.ts",
            content_type="video/mp2t",
            cache_control="max-age=31536000, immutable",
            tags="retention=vod",
        )

        head = mock_s3.head_object(
            Bucket="vod-output",
            Key="tenants/t1/assets/v1/hls/720p/segment_000.ts",
        )
        assert head["ContentType"] == "video/mp2t"

    def test_upload_sets_cache_headers(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import upload_segment

        test_file = tmp_path / "index.m3u8"
        test_file.write_text("#EXTM3U\n")

        upload_segment(
            local_path=test_file,
            bucket="vod-output",
            key="tenants/t1/assets/v1/hls/720p/index.m3u8",
            content_type="application/vnd.apple.mpegurl",
            cache_control="max-age=31536000, immutable",
            tags="retention=vod",
        )

        head = mock_s3.head_object(
            Bucket="vod-output",
            Key="tenants/t1/assets/v1/hls/720p/index.m3u8",
        )
        assert head["CacheControl"] == "max-age=31536000, immutable"

    def test_upload_progress_callback_invoked(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import upload_segment

        test_file = tmp_path / "segment.ts"
        test_file.write_bytes(b"\x47" * 1024)

        progress_calls = []

        def _on_progress(bytes_transferred: int):
            progress_calls.append(bytes_transferred)

        upload_segment(
            local_path=test_file,
            bucket="vod-output",
            key="test/segment.ts",
            content_type="video/mp2t",
            cache_control="max-age=31536000, immutable",
            tags="retention=vod",
            progress_callback=_on_progress,
        )

        assert len(progress_calls) > 0
        assert sum(progress_calls) == 1024


# ─── Tests: Upload transcode outputs ────────────────────────────────────────


class TestUploadTranscodeOutputs:
    def test_upload_creates_all_objects(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import upload_transcode_outputs

        output_dir = _create_test_output_dir(tmp_path)
        thumb_dir = _create_test_thumbnails(tmp_path)

        result = upload_transcode_outputs(
            job_id="tj_test123",
            video_id="vid_abc",
            tenant_id="tenant_1",
            output_dir=output_dir,
            thumbnail_dir=thumb_dir,
        )

        assert result.manifest_s3_uri == "s3://vod-output/tenants/tenant_1/assets/vid_abc/hls/master.m3u8"
        assert result.manifest_s3_key == "tenants/tenant_1/assets/vid_abc/hls/master.m3u8"
        assert result.total_bytes > 0
        assert result.files_uploaded > 0

        # Verify master playlist exists in S3
        obj = mock_s3.get_object(
            Bucket="vod-output",
            Key="tenants/tenant_1/assets/vid_abc/hls/master.m3u8",
        )
        content = obj["Body"].read().decode()
        assert "#EXTM3U" in content

        # Verify metadata.json
        meta_obj = mock_s3.get_object(
            Bucket="vod-output",
            Key="tenants/tenant_1/assets/vid_abc/metadata.json",
        )
        meta = json.loads(meta_obj["Body"].read())
        assert meta["job_id"] == "tj_test123"
        assert meta["tenant_id"] == "tenant_1"
        assert meta["video_id"] == "vid_abc"

    def test_upload_correct_content_types(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import upload_transcode_outputs

        output_dir = _create_test_output_dir(tmp_path)

        upload_transcode_outputs(
            job_id="tj_test",
            video_id="vid_1",
            tenant_id="t1",
            output_dir=output_dir,
        )

        # Check m3u8
        head = mock_s3.head_object(
            Bucket="vod-output",
            Key="tenants/t1/assets/vid_1/hls/720p/index.m3u8",
        )
        assert head["ContentType"] == "application/vnd.apple.mpegurl"

        # Check ts
        head = mock_s3.head_object(
            Bucket="vod-output",
            Key="tenants/t1/assets/vid_1/hls/720p/segment_000.ts",
        )
        assert head["ContentType"] == "video/mp2t"

    def test_upload_master_playlist_cache_control(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import upload_transcode_outputs

        output_dir = _create_test_output_dir(tmp_path)

        upload_transcode_outputs(
            job_id="tj_test",
            video_id="vid_1",
            tenant_id="t1",
            output_dir=output_dir,
        )

        # Master playlist should have short cache
        head = mock_s3.head_object(
            Bucket="vod-output",
            Key="tenants/t1/assets/vid_1/hls/master.m3u8",
        )
        assert head["CacheControl"] == "max-age=5, stale-while-revalidate=10"

        # Variant playlists should be immutable
        head = mock_s3.head_object(
            Bucket="vod-output",
            Key="tenants/t1/assets/vid_1/hls/720p/index.m3u8",
        )
        assert head["CacheControl"] == "max-age=31536000, immutable"

    def test_upload_master_last(self, mock_s3, tmp_path):
        """Verify master.m3u8 is uploaded last (atomic visibility)."""
        from app.services.vod_s3_uploader import upload_transcode_outputs

        output_dir = _create_test_output_dir(tmp_path)

        upload_order: List[str] = []
        original_upload_file = mock_s3.upload_file

        def tracking_upload_file(Filename, Bucket, Key, **kwargs):
            upload_order.append(Key)
            return original_upload_file(Filename=Filename, Bucket=Bucket, Key=Key, **kwargs)

        mock_s3.upload_file = tracking_upload_file

        upload_transcode_outputs(
            job_id="tj_test",
            video_id="vid_1",
            tenant_id="t1",
            output_dir=output_dir,
        )

        # master.m3u8 should be the last upload_file call
        master_indices = [i for i, k in enumerate(upload_order) if "master.m3u8" in k]
        assert master_indices, "master.m3u8 was not uploaded"
        assert master_indices[0] == len(upload_order) - 1

    def test_upload_progress_callback(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import upload_transcode_outputs

        output_dir = _create_test_output_dir(tmp_path)

        progress_calls: List[tuple] = []

        def _on_progress(files_done: int, total_files: int):
            progress_calls.append((files_done, total_files))

        upload_transcode_outputs(
            job_id="tj_test",
            video_id="vid_1",
            tenant_id="t1",
            output_dir=output_dir,
            on_progress=_on_progress,
        )

        assert len(progress_calls) > 0
        # Last call should have files_done == total_files
        last = progress_calls[-1]
        assert last[0] == last[1]

    def test_upload_handles_empty_output_dir(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import upload_transcode_outputs

        empty_dir = tmp_path / "empty_output"
        empty_dir.mkdir()

        result = upload_transcode_outputs(
            job_id="tj_empty",
            video_id="vid_empty",
            tenant_id="t1",
            output_dir=empty_dir,
        )

        assert result.manifest_s3_uri == ""
        assert result.total_bytes == 0
        assert result.files_uploaded == 0

    def test_upload_thumbnails_correct_keys(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import upload_transcode_outputs

        output_dir = _create_test_output_dir(tmp_path)
        thumb_dir = _create_test_thumbnails(tmp_path)

        result = upload_transcode_outputs(
            job_id="tj_test",
            video_id="vid_1",
            tenant_id="t1",
            output_dir=output_dir,
            thumbnail_dir=thumb_dir,
        )

        assert len(result.thumbnail_s3_keys) == 2
        assert "tenants/t1/assets/vid_1/thumbnails/poster_0s.jpg" in result.thumbnail_s3_keys
        assert "tenants/t1/assets/vid_1/thumbnails/poster_10s.jpg" in result.thumbnail_s3_keys

        # Verify thumbnail was actually uploaded
        head = mock_s3.head_object(
            Bucket="vod-output",
            Key="tenants/t1/assets/vid_1/thumbnails/poster_0s.jpg",
        )
        assert head["ContentType"] == "image/jpeg"


# ─── Tests: Abort incomplete uploads ────────────────────────────────────────


class TestAbortIncompleteUploads:
    def test_abort_cleans_up_multipart(self, mock_s3, tmp_path):
        from app.services.vod_s3_uploader import abort_incomplete_uploads

        # Start a multipart upload manually
        response = mock_s3.create_multipart_upload(
            Bucket="vod-output",
            Key="tenants/t1/assets/v1/hls/720p/segment_000.ts",
        )
        upload_id = response["UploadId"]

        # Verify it exists
        listing = mock_s3.list_multipart_uploads(
            Bucket="vod-output",
            Prefix="tenants/t1/assets/v1/",
        )
        assert len(listing.get("Uploads", [])) == 1

        # Abort
        aborted = abort_incomplete_uploads("vod-output", "tenants/t1/assets/v1/")
        assert aborted == 1

        # Verify cleaned up
        listing = mock_s3.list_multipart_uploads(
            Bucket="vod-output",
            Prefix="tenants/t1/assets/v1/",
        )
        assert len(listing.get("Uploads", [])) == 0


# ─── Tests: Playback URL generation ─────────────────────────────────────────


class TestMintVodPlaybackUrl:
    def test_dev_mode_url(self, mock_s3):
        """Dev mode should return /mock/s3/ URL."""
        with patch.dict(os.environ, {"DEV_MODE": "1", "VOD_CLOUDFRONT_DOMAIN": "", "BROADCAST_CLOUDFRONT_DOMAIN": ""}):
            # Force reload of settings
            from app.services.vod_playback_url import _mint_dev_url

            result = _mint_dev_url(video_id="vid_abc", tenant_id="tenant_1")

            assert result.mode == "dev"
            assert result.expires_at == 0
            assert "/mock/s3/vod-output/" in result.url
            assert "tenants/tenant_1/assets/vid_abc/hls/master.m3u8" in result.url
            assert result.manifest_key == "tenants/tenant_1/assets/vid_abc/hls/master.m3u8"

    def test_dev_mode_thumbnail_url(self, mock_s3):
        from app.services.vod_playback_url import _mint_dev_url

        result = _mint_dev_url(video_id="vid_abc", tenant_id="t1")
        assert result.thumbnail_url is not None
        assert "thumbnails/poster_0s.jpg" in result.thumbnail_url

    def test_cloudfront_url_format(self, mock_s3):
        """CloudFront mode should return signed HTTPS URL."""
        from app.services.vod_playback_url import _mint_cloudfront_url

        with patch("app.services.vod_playback_url.S") as mock_settings:
            mock_settings.vod_cloudfront_domain = "d123.cloudfront.net"
            mock_settings.vod_output_prefix = "tenants"
            mock_settings.transcode_output_prefix = "tenants"
            mock_settings.vod_playback_url_ttl_seconds = 3600
            mock_settings.broadcast_cloudfront_signing_secret = "test-secret"

            result = _mint_cloudfront_url(
                video_id="vid_abc", tenant_id="t1", ttl_seconds=3600
            )

            assert result.mode == "cloudfront"
            assert result.url.startswith("https://d123.cloudfront.net/")
            assert "cf_token=" in result.url
            assert "cf_expires=" in result.url
            assert result.expires_at > int(time.time())

    def test_cloudfront_url_thumbnail_included(self, mock_s3):
        """CloudFront URL should include thumbnail URL."""
        from app.services.vod_playback_url import _mint_cloudfront_url

        with patch("app.services.vod_playback_url.S") as mock_settings:
            mock_settings.vod_cloudfront_domain = "d123.cloudfront.net"
            mock_settings.vod_output_prefix = "tenants"
            mock_settings.transcode_output_prefix = "tenants"
            mock_settings.vod_playback_url_ttl_seconds = 3600
            mock_settings.broadcast_cloudfront_signing_secret = "test-secret"

            result = _mint_cloudfront_url(
                video_id="vid_abc", tenant_id="t1"
            )

            assert result.thumbnail_url is not None
            assert "thumbnails/poster_0s.jpg" in result.thumbnail_url
            assert "cf_token=" in result.thumbnail_url

    def test_presigned_url_format(self, mock_s3):
        """Presigned mode should return an S3 presigned URL."""
        from app.services.vod_playback_url import _mint_presigned_url

        result = _mint_presigned_url(
            video_id="vid_abc", tenant_id="t1", ttl_seconds=600
        )

        assert result.mode == "presigned"
        assert result.manifest_key == "tenants/t1/assets/vid_abc/hls/master.m3u8"
        assert result.expires_at > int(time.time())
        # Presigned URL should have signature params
        assert "Signature" in result.url or "X-Amz" in result.url

    def test_validate_vod_playback_token_valid(self, mock_s3):
        """Valid token should pass validation."""
        from app.services.vod_playback_url import _vod_sign, validate_vod_playback_token

        path = "/tenants/t1/assets/v1/hls/master.m3u8"
        expires = int(time.time()) + 3600
        token = _vod_sign(path, expires)

        assert validate_vod_playback_token(path, token, expires) is True

    def test_validate_vod_playback_token_expired(self, mock_s3):
        """Expired token should be rejected."""
        from app.services.vod_playback_url import _vod_sign, validate_vod_playback_token

        path = "/tenants/t1/assets/v1/hls/master.m3u8"
        expires = int(time.time()) - 10  # expired 10 seconds ago
        token = _vod_sign(path, expires)

        assert validate_vod_playback_token(path, token, expires) is False

    def test_validate_vod_playback_token_empty(self, mock_s3):
        """Empty token should be rejected."""
        from app.services.vod_playback_url import validate_vod_playback_token

        assert validate_vod_playback_token("/test", "", int(time.time()) + 100) is False

    def test_mint_vod_playback_url_auto_dispatch_dev(self, mock_s3):
        """mint_vod_playback_url should dispatch to dev mode when dev_mode=True."""
        from app.services.vod_playback_url import mint_vod_playback_url

        with patch("app.services.vod_playback_url.S") as mock_settings:
            mock_settings.dev_mode = True
            mock_settings.vod_output_bucket = "vod-output"
            mock_settings.transcode_output_bucket = "vod-output"
            mock_settings.vod_output_prefix = "tenants"
            mock_settings.transcode_output_prefix = "tenants"
            mock_settings.vod_cloudfront_domain = ""
            mock_settings.broadcast_cloudfront_domain = ""

            result = mint_vod_playback_url("vid_1", "t1")
            assert result.mode == "dev"


# ─── Tests: Thumbnail extraction (mocked subprocess) ────────────────────────


class TestExtractThumbnails:
    def test_extract_thumbnails_generates_jpgs(self, tmp_path):
        """Test that thumbnail extraction creates JPEG files (mocked FFmpeg)."""
        import asyncio
        from app.services.vod_thumbnail_extractor import extract_thumbnails

        source = tmp_path / "source.mp4"
        source.write_bytes(b"\x00" * 100)
        out_dir = tmp_path / "thumbs"

        # Mock asyncio subprocess to simulate successful ffmpeg
        async def mock_create_subprocess_exec(*cmd, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            # Create the output file that ffmpeg would create
            for arg in cmd:
                if str(arg).endswith(".jpg"):
                    Path(arg).parent.mkdir(parents=True, exist_ok=True)
                    Path(arg).write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50)
            proc.communicate.return_value = (b"", b"")
            return proc

        async def _run():
            with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess_exec):
                return await extract_thumbnails(
                    source_path=source,
                    output_dir=out_dir,
                    timestamps=[0.0, 5.0, 10.0],
                )

        results = asyncio.run(_run())

        assert len(results) == 3
        for p in results:
            assert p.exists()
            assert p.stat().st_size > 0
            assert p.suffix == ".jpg"

    def test_extract_thumbnails_handles_failure(self, tmp_path):
        """Failed FFmpeg extraction should return empty list, no exception."""
        import asyncio
        from app.services.vod_thumbnail_extractor import extract_thumbnails

        source = tmp_path / "source.mp4"
        source.write_bytes(b"\x00" * 100)
        out_dir = tmp_path / "thumbs"

        async def mock_fail_subprocess(*cmd, **kwargs):
            proc = AsyncMock()
            proc.returncode = 1
            proc.communicate.return_value = (b"", b"Error: file not found")
            return proc

        async def _run():
            with patch("asyncio.create_subprocess_exec", side_effect=mock_fail_subprocess):
                return await extract_thumbnails(
                    source_path=source,
                    output_dir=out_dir,
                    timestamps=[0.0],
                )

        results = asyncio.run(_run())
        assert results == []


class TestUploadThumbnails:
    def test_upload_thumbnails_correct_keys(self, mock_s3, tmp_path):
        """Upload thumbnails should put objects at correct S3 keys."""
        import asyncio
        from app.services.vod_thumbnail_extractor import upload_thumbnails

        thumb_dir = tmp_path / "thumbs"
        thumb_dir.mkdir()
        poster = thumb_dir / "poster_0s.jpg"
        poster.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50)

        async def _run():
            return await upload_thumbnails(
                paths=[poster],
                video_id="vid_1",
                tenant_id="t1",
            )

        keys = asyncio.run(_run())

        assert len(keys) == 1
        assert "tenants/t1/assets/vid_1/thumbnails/poster_0s.jpg" in keys[0]

        # Verify object exists
        head = mock_s3.head_object(
            Bucket="vod-output",
            Key="tenants/t1/assets/vid_1/thumbnails/poster_0s.jpg",
        )
        assert head["ContentType"] == "image/jpeg"


# ─── Tests: Lifecycle policy ─────────────────────────────────────────────────


class TestEnsureVodLifecyclePolicy:
    def test_lifecycle_policy_set(self, mock_s3):
        from app.services.vod_s3_uploader import ensure_vod_lifecycle_policy

        result = ensure_vod_lifecycle_policy(bucket="vod-output", default_retention_days=90)
        assert result is True

        # Verify lifecycle config was applied
        config = mock_s3.get_bucket_lifecycle_configuration(Bucket="vod-output")
        rules = config.get("Rules", [])
        assert len(rules) == 2

        retention_rule = next(r for r in rules if r["ID"] == "vod-output-retention")
        assert retention_rule["Expiration"]["Days"] == 90
        assert retention_rule["Filter"]["Tag"]["Key"] == "retention"
        assert retention_rule["Filter"]["Tag"]["Value"] == "vod"
