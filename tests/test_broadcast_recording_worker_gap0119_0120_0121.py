"""Regression tests for GAP-0119, GAP-0120, GAP-0121 (recording/VOD pipeline).

All three gaps live in ``app/services/broadcast_recording_worker.py``:

* GAP-0119 ``inventory_segments`` returned ``[]`` even with FFmpeg present —
  now paginates ListObjectsV2 over the VOD bucket and returns the ``.ts`` keys.
* GAP-0120 ``concatenate_segments`` returned ``None`` — now downloads the
  segments, writes a concat list, runs FFmpeg (concat demuxer), and uploads the
  result.
* GAP-0121 ``_upload_to_s3`` helper was missing and ``generate_mp4`` never
  persisted the MP4 — now the helper exists and is wired into the MP4 step.

These run fully offline: moto provides the in-memory S3 store (NO real AWS) and
the FFmpeg subprocess is MOCKED (we never actually transcode). Each test is
written to FAIL before the fix and PASS after.
"""
from __future__ import annotations

import os
import shutil
from unittest.mock import patch

import boto3
from moto import mock_aws

from app.core.settings import S
from app.services.broadcast_recording import RecordingRecord
from app.services.broadcast_recording_worker import (
    _upload_to_s3,
    concatenate_segments,
    generate_mp4,
    inventory_segments,
)

BUCKET = S.broadcast_recording_vod_bucket


def _rec(prefix: str = "sess_001/hls/") -> RecordingRecord:
    return RecordingRecord(
        recording_id="rec_001",
        session_id="sess_001",
        profile_id="prof_001",
        created_by="alice",
        status="processing",
        s3_archive_prefix=prefix,
        retention_days=30,
        created_at=1_000_000,
    )


def _force_real_path():
    """Context manager that flips the worker out of mock mode.

    Settings ``S`` is a frozen dataclass, so we patch ``_should_mock`` directly
    rather than mutating the setting.
    """
    return patch("app.services.broadcast_recording_worker._should_mock", return_value=False)


def _force_mock_path():
    return patch("app.services.broadcast_recording_worker._should_mock", return_value=True)


# ── GAP-0119: inventory_segments ───────────────────────────────────────────


@mock_aws
def test_inventory_lists_seeded_s3_segments():
    """GAP-0119: returns the .ts keys for objects seeded in S3 (sorted),
    filtering out non-.ts files. Fails before fix (stub returned [])."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    prefix = "sess_001/hls/"
    for i in (2, 0, 4, 1, 3):  # insert out of order
        s3.put_object(Bucket=BUCKET, Key=f"{prefix}segment{i:04d}.ts", Body=b"ts")
    s3.put_object(Bucket=BUCKET, Key=f"{prefix}index.m3u8", Body=b"m3u8")  # ignored

    with _force_real_path():
        keys = inventory_segments(_rec(prefix))

    assert len(keys) == 5
    assert all(k.endswith(".ts") for k in keys)
    assert keys == sorted(keys)


@mock_aws
def test_inventory_empty_prefix_returns_empty():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    with _force_real_path():
        assert inventory_segments(_rec("")) == []


def test_inventory_mock_mode_returns_empty():
    with _force_mock_path():
        assert inventory_segments(_rec("sess_001/hls/")) == []


# ── GAP-0121: _upload_to_s3 ────────────────────────────────────────────────


@mock_aws
def test_upload_to_s3_puts_retrievable_object(tmp_path):
    """GAP-0121: _upload_to_s3 stores an object retrievable from moto."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)

    local = tmp_path / "full.mp4"
    local.write_bytes(b"\x00\x01\x02mp4-bytes")

    _upload_to_s3(str(local), bucket=BUCKET, key="sess_001/recording/full.mp4")

    got = s3.get_object(Bucket=BUCKET, Key="sess_001/recording/full.mp4")
    assert got["Body"].read() == b"\x00\x01\x02mp4-bytes"


@mock_aws
def test_generate_mp4_uploads_to_vod_bucket(tmp_path):
    """GAP-0121: generate_mp4 uploads the remuxed MP4 (ffmpeg mocked)."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)

    concat_path = str(tmp_path / "concatenated.ts")
    open(concat_path, "wb").write(b"\x47" * 188)

    def _fake_run(args, **kwargs):
        # last positional arg is the mp4 output path
        open(args[-1], "wb").write(b"\x00" * 4096)

        class R:
            returncode = 0
            stderr = ""

        return R()

    with _force_real_path(), patch("subprocess.run", side_effect=_fake_run):
        result = generate_mp4(_rec(), concat_path)

    assert result["mp4_s3_key"] == "sess_001/recording/full.mp4"
    assert result["mp4_size_bytes"] == 4096
    # Object actually landed in moto S3.
    head = s3.head_object(Bucket=BUCKET, Key="sess_001/recording/full.mp4")
    assert head["ContentLength"] == 4096


# ── GAP-0120: concatenate_segments ─────────────────────────────────────────


def test_concatenate_mock_mode_returns_none():
    with _force_mock_path():
        assert concatenate_segments(_rec(), ["sess_001/hls/seg0.ts"]) is None


def test_concatenate_empty_segments_returns_none():
    with _force_real_path():
        assert concatenate_segments(_rec(), []) is None


@mock_aws
def test_concatenate_downloads_runs_ffmpeg_and_uploads():
    """GAP-0120: downloads segments, runs FFmpeg over the LOCAL concat list,
    uploads the result, persists s3_concatenated_key, returns a local path.
    Fails before fix (stub returned None)."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    keys = []
    for i in range(3):
        key = f"sess_001/hls/seg{i:04d}.ts"
        s3.put_object(Bucket=BUCKET, Key=key, Body=b"\x47" + b"\x00" * 187)
        keys.append(key)

    captured = {}

    def _fake_run(args, **kwargs):
        captured["args"] = args
        # Read the concat list FFmpeg was pointed at and confirm it lists the
        # local downloaded segments (NOT the S3 keys).
        concat_list = args[args.index("-i") + 1]
        with open(concat_list) as fh:
            captured["concat_list"] = fh.read()
        output_path = args[-1]
        open(output_path, "wb").write(b"\x47" * 188)

        class R:
            returncode = 0
            stderr = ""

        return R()

    with _force_real_path(), \
         patch("subprocess.run", side_effect=_fake_run), \
         patch("app.services.broadcast_recording_worker.update_recording_status") as upd:
        result = concatenate_segments(_rec(), keys)

    try:
        # Returns a real local path that exists.
        assert result is not None
        assert os.path.exists(result)

        # FFmpeg invoked with the concat demuxer.
        assert "-f" in captured["args"] and "concat" in captured["args"]
        # Concat list references local seg files, three of them, not S3 keys.
        assert captured["concat_list"].count("file '") == 3
        assert "seg000000.ts" in captured["concat_list"]
        assert "sess_001/hls/" not in captured["concat_list"]

        # Concatenated .ts was uploaded to the VOD bucket.
        head = s3.head_object(Bucket=BUCKET, Key="sess_001/recording/concatenated.ts")
        assert head["ContentLength"] == 188

        # s3_concatenated_key persisted.
        assert any(
            kw.get("s3_concatenated_key") == "sess_001/recording/concatenated.ts"
            for _, kw in upd.call_args_list
        )
    finally:
        if result:
            shutil.rmtree(os.path.dirname(result), ignore_errors=True)
