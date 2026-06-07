"""GAP-0369 regression tests — transcode worker video-state transitions.

Two defects fixed:
  1. The worker never transitioned the video to "encoding" after claiming a job.
  2. On completion the worker attempted an ILLEGAL "published" transition
     (encoding -> published is not legal; published is only reachable from
     approved). The error was swallowed by a bare ``except Exception`` so the
     video never advanced. The correct completion target is "pending_review".

These tests are hermetic: no real ffmpeg, no real AWS/S3, no DynamoDB. The
worker is driven with an empty rendition list (so the ffmpeg loop is skipped)
and every heavy collaborator (S3 download/upload, playback URL minting, job
store, filesystem) is stubbed so that only the state transitions execute.

Run alone:
  .venv/bin/pytest tests/test_gap_0369_transcode_worker_transitions.py -q
"""
from __future__ import annotations

import asyncio
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_job(video_id: str = "vid_g369") -> dict:
    return {
        "job_id": "job_g369",
        "video_id": video_id,
        "tenant_id": "t_g369",
        "status": "queued",
        "attempt": 0,
        "renditions": [],  # empty -> ffmpeg loop is skipped entirely
        "source_uri": "s3://bucket/key.mp4",
        "watermark": {},
    }


def _run_worker_capturing_transitions() -> list[dict]:
    """Drive execute_transcode_job with all heavy steps stubbed.

    Returns the ordered list of kwargs passed to transition_video_status.
    """
    calls: list[dict] = []

    def _record_transition(**kw):
        calls.append(kw)
        return None

    upload_result = SimpleNamespace(
        thumbnail_s3_keys=[],
        hls_manifest_uri="s3://out/master.m3u8",
        thumbnail_url=None,
    )
    playback = SimpleNamespace(url="https://cdn/play", thumbnail_url=None)

    with ExitStack() as es:
        p = es.enter_context
        # Job store
        p(patch("app.services.transcode_worker.claim_job", return_value=True))
        p(patch("app.services.transcode_worker.update_job_progress"))
        p(patch("app.services.transcode_worker.fail_job"))
        # Source download (module-level import in transcode_worker)
        p(patch(
            "app.services.transcode_worker.download_source_to_scratch",
            return_value="/scratch/source.mp4",
        ))
        # Local-imported collaborators in the completion block (patched at source)
        p(patch("app.services.ffmpeg_abr_pipeline.write_master_playlist"))
        p(patch(
            "app.services.vod_s3_uploader.upload_transcode_outputs",
            return_value=upload_result,
        ))
        p(patch(
            "app.services.vod_playback_url.mint_vod_playback_url",
            return_value=playback,
        ))
        p(patch(
            "app.services.transcode_job_store.complete_job_with_outputs",
            return_value=None,
        ))
        p(patch("app.services.vod_file_bridge.link_video_to_filemanager"))
        # Thumbnail extractor is only imported when the flag is on; stub anyway
        p(patch(
            "app.services.vod_thumbnail_extractor.extract_thumbnails",
            new_callable=AsyncMock,
        ))
        # THE call under test (local import resolves to this source symbol for
        # BOTH the post-claim encoding transition and the completion transition)
        p(patch(
            "app.services.video_metadata_store.transition_video_status",
            side_effect=_record_transition,
        ))
        # Filesystem isolation
        p(patch("app.services.transcode_worker.Path.mkdir"))
        p(patch("app.services.transcode_worker.shutil.rmtree"))

        from app.services import transcode_worker

        asyncio.run(transcode_worker.execute_transcode_job(_make_job()))

    return calls


def test_worker_transitions_to_encoding_after_claim():
    """FAILS before fix (no encoding transition); PASSES after."""
    calls = _run_worker_capturing_transitions()
    encoding = [c for c in calls if c.get("to_status") == "encoding"]
    assert len(encoding) >= 1, (
        "GAP-0369: worker must transition video to 'encoding' immediately "
        "after claiming the job."
    )
    # And it must be the FIRST transition (before any completion transition).
    assert calls[0].get("to_status") == "encoding", (
        "encoding transition must occur before the completion transition; "
        f"got order: {[c.get('to_status') for c in calls]}"
    )


def test_worker_transitions_to_pending_review_on_completion():
    """FAILS before fix (to_status='published'); PASSES after."""
    calls = _run_worker_capturing_transitions()
    completion = [
        c for c in calls
        if c.get("to_status") in ("published", "pending_review")
    ]
    assert completion, "expected a completion status transition"
    final = completion[-1]["to_status"]
    assert final == "pending_review", (
        f"GAP-0369: completion must target 'pending_review', not '{final}'. "
        "'published' bypasses the mandatory human-review gate and is an "
        "illegal transition from 'encoding'."
    )
    # The illegal 'published' transition must be gone entirely.
    assert not any(c.get("to_status") == "published" for c in calls), (
        "worker must not attempt a 'published' transition"
    )


def test_full_transition_sequence_is_encoding_then_pending_review():
    calls = _run_worker_capturing_transitions()
    statuses = [c.get("to_status") for c in calls]
    assert statuses == ["encoding", "pending_review"], (
        f"expected ['encoding', 'pending_review'], got {statuses}"
    )


@pytest.mark.parametrize(
    "frm,to,legal",
    [
        ("pending_encoding", "encoding", True),
        ("encoding", "pending_review", True),
        # The illegal transitions the bug was attempting:
        ("encoding", "published", False),
        ("pending_encoding", "published", False),
        # Sanity: published is only reachable from approved.
        ("approved", "published", True),
    ],
)
def test_state_machine_legality(frm, to, legal):
    from app.services.video_state_machine import validate_transition

    result = validate_transition(frm, to)
    assert result.legal is legal, (
        f"validate_transition({frm!r}, {to!r}).legal expected {legal}"
    )


def test_source_no_longer_uses_published_in_execute_transcode_job():
    """Static guard: the function body must not contain to_status='published'
    and must contain both the encoding and pending_review transitions."""
    import inspect

    from app.services import transcode_worker

    src = inspect.getsource(transcode_worker.execute_transcode_job)
    assert 'to_status="published"' not in src, (
        "execute_transcode_job must not transition to 'published'"
    )
    assert 'to_status="encoding"' in src, "missing encoding transition"
    assert 'to_status="pending_review"' in src, "missing pending_review transition"
