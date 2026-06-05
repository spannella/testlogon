"""GAP-0033 regression: transcode worker must download the s3:// source to a
local file before invoking FFmpeg, because standard FFmpeg builds lack the s3://
protocol demuxer.

Offline only — uses moto's in-memory S3 and mocks the FFmpeg execution. No real
AWS and no actual transcoding.

Before the fix:
  - app/services/vod_s3_downloader.py did not exist (ImportError on import).
  - The worker passed the raw "s3://bucket/key" URI to ffmpeg's -i.
After the fix:
  - download_source_to_scratch fetches the object to a local path.
  - The worker passes that local path (not the s3:// string) to ffmpeg.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import boto3
import pytest

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.services.vod_s3_downloader import download_source_to_scratch


@pytest.mark.skipif(mock_aws is None, reason="moto is not installed")
def test_download_source_fetches_s3_object_to_local_path(tmp_path):
    """download_source_to_scratch downloads the s3:// object to a local file
    whose contents match the original object body."""
    bucket = "my-uploads"
    key = "videos/sub/clip.mp4"
    body = b"\x00\x01fake-mp4-bytes\x02\x03" * 100

    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=bucket)
        s3.put_object(Bucket=bucket, Key=key, Body=body)

        # Force the downloader's s3_client() to use the moto-backed default client.
        with patch(
            "app.services.vod_s3_downloader.s3_client",
            return_value=boto3.client("s3", region_name="us-east-1"),
        ):
            result = download_source_to_scratch(f"s3://{bucket}/{key}", tmp_path)

        assert result == tmp_path / "source.mp4"
        assert result.exists()
        assert result.read_bytes() == body


def test_download_passthrough_for_non_s3_uri(tmp_path):
    """A non-s3:// value (already a local path) is returned unchanged, no S3 call."""
    with patch("app.services.vod_s3_downloader.s3_client") as mock_s3:
        result = download_source_to_scratch("/tmp/already/local.mp4", tmp_path)
    assert result == Path("/tmp/already/local.mp4")
    mock_s3.assert_not_called()


def test_worker_passes_local_path_not_s3_uri_to_ffmpeg(tmp_path):
    """execute_transcode_job must hand FFmpeg a LOCAL file path, never the raw
    s3:// URI. FFmpeg execution is mocked; nothing is actually transcoded."""
    from app.services import transcode_worker

    job = {
        "job_id": "job-gap0033",
        "video_id": "vid-1",
        "tenant_id": "tenant-1",
        "source_uri": "s3://my-uploads/videos/clip.mp4",
        "renditions": [{"name": "720p"}],
        "watermark": {},
        "attempt": 0,
    }

    local_source = tmp_path / "source.mp4"
    captured: dict = {}

    async def _fake_ffmpeg(*, source_uri, **kwargs):
        captured["source_uri"] = source_uri
        # Short-circuit after capturing the input so we don't need to mock the
        # entire upload/playlist/complete pipeline that follows the loop.
        raise RuntimeError("__stop_after_capture__")

    with patch.object(transcode_worker, "claim_job", return_value=True), \
         patch.object(transcode_worker, "update_job_progress"), \
         patch.object(
             transcode_worker,
             "download_source_to_scratch",
             return_value=local_source,
         ) as mock_dl, \
         patch.object(
             transcode_worker,
             "_run_ffmpeg_for_rendition",
             new=AsyncMock(side_effect=_fake_ffmpeg),
         ), \
         patch.object(transcode_worker, "fail_job") as mock_fail:
        asyncio.run(transcode_worker.execute_transcode_job(job))

    # Downloader was invoked with the s3:// URI from the job record.
    mock_dl.assert_called_once()
    assert mock_dl.call_args.args[0] == "s3://my-uploads/videos/clip.mp4"

    # FFmpeg received the LOCAL path, not the s3:// URI.
    assert "source_uri" in captured
    assert captured["source_uri"] == str(local_source)
    assert not captured["source_uri"].startswith("s3://")

    # Sanity: our short-circuit exception was the one that ended the run.
    assert mock_fail.called
