"""GAP-0379 regression: concat-job exception handler must call fail_job.

Before the fix, ``execute_concat`` re-raised on any exception without ever
transitioning the job out of ``running`` state, so the job was stranded
forever. The fix calls ``fail_job(job_id, str(e)[:4096], int(attempt))`` in the
``except`` block (defensively, so a bookkeeping failure can't mask the real
error) before re-raising.

Offline / hermetic: S3 (boto3), FFmpeg (_run_concat_*), the duration probe, and
the job store are all stubbed, so no real AWS / ffmpeg / DynamoDB is touched.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import app.services.video_concatenator as vc


def _job() -> dict:
    return {
        "job_id": "job_concat_001",
        "video_id": "vid_concat_001",
        "tenant_id": "user_001",
        "concat_source_s3_keys": [
            "videos/user_001/vid_a/source.mp4",
            "videos/user_001/vid_b/source.mp4",
        ],
        "concat_method": "demuxer",
        "concat_estimated_duration_seconds": "120",
        "attempt": 0,
    }


def test_execute_concat_calls_fail_job_on_s3_error():
    """On any error, fail_job is called with (job_id, error, attempt) AND the
    original exception is still re-raised."""
    job = _job()

    fail_spy = MagicMock()

    fake_s3 = MagicMock()
    fake_s3.download_file.side_effect = RuntimeError("S3 NoSuchKey")
    fake_boto = MagicMock(return_value=fake_s3)

    with patch("boto3.client", fake_boto), \
         patch("app.services.transcode_job_store.fail_job", fail_spy):
        with pytest.raises(RuntimeError, match="S3 NoSuchKey"):
            asyncio.run(vc.execute_concat(job))

    fail_spy.assert_called_once()
    args = fail_spy.call_args[0]
    assert args[0] == "job_concat_001"     # job_id
    assert "S3 NoSuchKey" in args[1]        # error message
    assert args[2] == 0                      # attempt


def test_execute_concat_calls_fail_job_on_ffmpeg_error():
    """fail_job is called (and attempt passed through) when the FFmpeg step fails."""
    job = {**_job(), "job_id": "job_concat_002", "concat_method": "filter", "attempt": 1}

    fail_spy = MagicMock()
    fake_s3 = MagicMock()  # downloads succeed
    fake_boto = MagicMock(return_value=fake_s3)

    with patch("boto3.client", fake_boto), \
         patch("app.services.transcode_job_store.update_job_progress", MagicMock()), \
         patch.object(vc, "_run_concat_filter",
                      new_callable=AsyncMock,
                      side_effect=RuntimeError("FFmpeg filter failed")), \
         patch("app.services.transcode_job_store.fail_job", fail_spy):
        with pytest.raises(RuntimeError, match="FFmpeg filter failed"):
            asyncio.run(vc.execute_concat(job))

    fail_spy.assert_called_once()
    args = fail_spy.call_args[0]
    assert args[0] == "job_concat_002"
    assert args[2] == 1                      # attempt passed through


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
            asyncio.run(vc.execute_concat(job))

    fail_spy.assert_called_once()


def test_execute_concat_does_not_call_fail_job_on_success():
    """fail_job must NOT be called on the happy path."""
    job = {**_job(), "job_id": "job_concat_003"}

    fail_spy = MagicMock()
    fake_s3 = MagicMock()  # download_file / upload_file are no-ops
    fake_boto = MagicMock(return_value=fake_s3)

    # T (Tables) and its handles are frozen → swap video_metadata for a MagicMock
    # via object.__setattr__ and restore afterwards.
    orig_meta = vc.T.video_metadata
    object.__setattr__(vc.T, "video_metadata", MagicMock())
    try:
        with patch("boto3.client", fake_boto), \
             patch.object(vc, "_run_concat_demuxer", new_callable=AsyncMock), \
             patch.object(vc, "_probe_duration",
                          new_callable=AsyncMock, return_value=30.0), \
             patch("app.services.transcode_job_store.update_job_progress", MagicMock()), \
             patch("app.services.transcode_job_store.complete_job", MagicMock()), \
             patch("app.services.transcode_job_store.create_job", MagicMock()), \
             patch("app.services.transcode_job_store.fail_job", fail_spy):
            asyncio.run(vc.execute_concat(job))
    finally:
        object.__setattr__(vc.T, "video_metadata", orig_meta)

    fail_spy.assert_not_called()
