"""GAP-0377 regression: clip-job exception handler must call fail_job.

Before the fix, ``process_clip_job`` re-raised on any exception without ever
transitioning the job out of ``running`` state, so the job was stranded
forever. The fix calls ``fail_job(job_id, str(e), attempt)`` in the ``except``
block (defensively, so a bookkeeping failure can't mask the real error) before
re-raising.

Offline / hermetic: S3 (boto3), FFmpeg (execute_clip), and the job store are
all stubbed, so no real AWS / ffmpeg / DynamoDB is touched.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import app.services.video_clipper as vc


def _job() -> dict:
    return {
        "job_id": "job_clip_001",
        "video_id": "vid_001",
        "source_uri": "videos/owner/vid_001/source.mp4",
        "clip_start_seconds": "0",
        "clip_end_seconds": "10",
        "tenant_id": "user_001",
        "attempt": 0,
    }


def test_process_clip_job_calls_fail_job_on_exception():
    """On any error, fail_job is called with (job_id, error, attempt) AND the
    original exception is still re-raised."""
    job = _job()

    fail_spy = MagicMock()

    # Stub boto3.client so the S3 download step raises (forces the except path).
    fake_s3 = MagicMock()
    fake_s3.download_file.side_effect = RuntimeError("S3 access denied")
    fake_boto = MagicMock(return_value=fake_s3)

    with patch("boto3.client", fake_boto), \
         patch("app.services.transcode_job_store.fail_job", fail_spy):
        with pytest.raises(RuntimeError, match="S3 access denied"):
            asyncio.run(vc.process_clip_job(job))

    fail_spy.assert_called_once()
    args = fail_spy.call_args[0]
    assert args[0] == "job_clip_001"          # job_id
    assert "S3 access denied" in args[1]       # error message
    assert args[2] == 0                        # attempt


def test_fail_job_failure_does_not_mask_original_exception():
    """If fail_job itself raises, the original exception must still propagate."""
    job = _job()

    fake_s3 = MagicMock()
    fake_s3.download_file.side_effect = RuntimeError("download boom")
    fake_boto = MagicMock(return_value=fake_s3)

    fail_spy = MagicMock(side_effect=RuntimeError("ddb is down"))

    with patch("boto3.client", fake_boto), \
         patch("app.services.transcode_job_store.fail_job", fail_spy):
        with pytest.raises(RuntimeError, match="download boom"):
            asyncio.run(vc.process_clip_job(job))

    fail_spy.assert_called_once()


def test_process_clip_job_does_not_call_fail_job_on_success():
    """fail_job must NOT be called on the happy path."""
    job = {**_job(), "job_id": "job_clip_002"}

    fail_spy = MagicMock()
    fake_s3 = MagicMock()  # download_file / upload_file are no-ops
    fake_boto = MagicMock(return_value=fake_s3)

    async def _fake_execute_clip(**kwargs):
        return vc.ClipResult(
            output_path=Path("/tmp/clip.mp4"),
            duration_seconds=5.0,
            method="copy",
        )

    # T (Tables) and its table handles are frozen → swap video_metadata for a
    # MagicMock via object.__setattr__ and restore afterwards.
    orig_meta = vc.T.video_metadata
    object.__setattr__(vc.T, "video_metadata", MagicMock())
    try:
        with patch("boto3.client", fake_boto), \
             patch.object(vc, "execute_clip", _fake_execute_clip), \
             patch("app.services.transcode_job_store.create_job", MagicMock()), \
             patch("app.services.transcode_job_store.complete_job", MagicMock()), \
             patch("app.services.transcode_job_store.fail_job", fail_spy):
            asyncio.run(vc.process_clip_job(job))
    finally:
        object.__setattr__(vc.T, "video_metadata", orig_meta)

    fail_spy.assert_not_called()
