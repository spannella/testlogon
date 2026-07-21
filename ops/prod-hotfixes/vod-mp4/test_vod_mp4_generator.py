"""Unit tests for the VOD-012 real download-MP4 generator (vod_mp4_generator).

Covers the non-dev enqueue branch, the no-source guard, the dev-mode
instant-ready branch (unchanged), and the transcode-worker job_type dispatch
(download_mp4 -> process_download_mp4_job; everything else -> the existing
execute_transcode_job so ABR transcodes are unaffected).

The heavy ffmpeg/S3 end-to-end path is exercised over a live server elsewhere;
here we assert the routing/guard logic with mocks.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import vod_mp4_generator as G


def _video(**over):
    base = dict(
        id="vid_1",
        owner_user_id="owner_1",
        source_s3_key="uploads/owner_1/vid_1/original.mp4",
        title="t",
        download_mp4_key="",
        download_mp4_size_bytes=0,
        download_mp4_status="",
    )
    base.update(over)
    return SimpleNamespace(**base)


def _expected_key(video):
    return (
        "tenants/"
        f"{video.owner_user_id}/assets/{video.id}/download/{video.id}.mp4"
    )


def _settings(dev_mode: bool):
    """A stand-in for the frozen Settings singleton so tests can flip dev_mode."""
    return SimpleNamespace(
        dev_mode=dev_mode,
        vod_output_prefix="tenants",
        transcode_output_prefix="tenants",
    )


# ─── generate_download_mp4: dev-mode branch UNCHANGED ─────────────────────────


def test_dev_mode_instant_ready_and_no_enqueue():
    video = _video()
    with patch.object(G, "S", _settings(dev_mode=True)), \
         patch("app.services.transcode_job_store.create_job") as create_job:
        out = G.generate_download_mp4(video)
    assert out["download_mp4_status"] == "ready"
    assert out["download_mp4_size_bytes"] == 0
    assert out["download_mp4_key"] == _expected_key(video)
    create_job.assert_not_called()  # dev mode must never enqueue a job


# ─── generate_download_mp4: production enqueue branch ─────────────────────────


def test_prod_enqueues_download_mp4_job_and_returns_processing():
    video = _video()
    with patch.object(G, "S", _settings(dev_mode=False)), \
         patch("app.services.transcode_job_store.create_job") as create_job:
        out = G.generate_download_mp4(video)

    assert out["download_mp4_status"] == "processing"
    assert out["download_mp4_size_bytes"] == 0
    assert out["download_mp4_key"] == _expected_key(video)
    create_job.assert_called_once()
    kwargs = create_job.call_args.kwargs
    assert kwargs["job_type"] == "download_mp4"
    assert kwargs["source_uri"] == video.source_s3_key
    assert kwargs["video_id"] == video.id
    assert kwargs["tenant_id"] == video.owner_user_id
    assert kwargs["rendition_profiles"] == []


def test_prod_no_source_guard_fails_and_does_not_enqueue():
    video = _video(source_s3_key="")
    with patch.object(G, "S", _settings(dev_mode=False)), \
         patch("app.services.transcode_job_store.create_job") as create_job:
        out = G.generate_download_mp4(video)
    # Guard: failed status, NOT a phantom-ready 0-byte download, no job.
    assert out["download_mp4_status"] == "failed"
    assert out["download_mp4_size_bytes"] == 0
    create_job.assert_not_called()


# ─── ffmpeg command shape (remux vs re-encode) ────────────────────────────────


def test_remux_command_uses_copy_and_faststart():
    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["cmd"] = list(args)
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"", b""))
        return proc

    with patch("app.services.ffmpeg_manager.get_ffmpeg_path", return_value="ffmpeg"), \
         patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
        ok, _tail = asyncio.run(
            G._run_download_mp4_ffmpeg(
                source_path="s.mp4", output_path="o.mp4",
                reencode=False, timeout_seconds=60,
            )
        )
    assert ok is True
    cmd = captured["cmd"]
    assert "-c" in cmd and "copy" in cmd
    assert "+faststart" in cmd
    assert "-movflags" in cmd


def test_reencode_command_uses_libx264_aac_and_faststart():
    captured = {}

    async def fake_exec(*args, **kwargs):
        captured["cmd"] = list(args)
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"", b""))
        return proc

    with patch("app.services.ffmpeg_manager.get_ffmpeg_path", return_value="ffmpeg"), \
         patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
        ok, _tail = asyncio.run(
            G._run_download_mp4_ffmpeg(
                source_path="s.mp4", output_path="o.mp4",
                reencode=True, timeout_seconds=60,
            )
        )
    assert ok is True
    cmd = captured["cmd"]
    assert "libx264" in cmd and "aac" in cmd
    assert "veryfast" in cmd
    assert "+faststart" in cmd


# ─── worker dispatch: job_type routing ────────────────────────────────────────


def test_worker_dispatches_download_mp4_vs_transcode():
    import app.services.transcode_worker as w

    async def run():
        w._CONCURRENCY_SEMAPHORE = asyncio.Semaphore(2)
        with patch.object(w, "execute_transcode_job", new=AsyncMock()) as et, \
             patch.object(w, "_execute_download_mp4_job", new=AsyncMock()) as ed:
            await w._process_job_with_semaphore({"job_id": "a", "job_type": "transcode"})
            await w._process_job_with_semaphore({"job_id": "b"})  # missing -> default
            await w._process_job_with_semaphore({"job_id": "c", "job_type": "download_mp4"})
            assert et.await_count == 2  # ABR path unchanged (default + missing)
            assert ed.await_count == 1  # only download_mp4 routed to new handler

    asyncio.run(run())
