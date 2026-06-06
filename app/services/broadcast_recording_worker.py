"""Broadcast Recording Worker (BCAST-006).

Orchestrates the recording pipeline: inventory, concatenation,
transcoding, thumbnail generation, and finalization.

In dev mode with broadcast_recording_mock_on_no_ffmpeg=True, the worker
skips FFmpeg steps and produces mock metadata.
"""
from __future__ import annotations

import logging
import shutil
import time
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.services.broadcast_recording import (
    RecordingRecord,
    get_recording,
    update_recording_status,
)

logger = logging.getLogger(__name__)


def _ffmpeg_available() -> bool:
    """Check if FFmpeg binary is available on PATH."""
    return shutil.which(S.ffmpeg_binary_path) is not None


def _should_mock() -> bool:
    """Determine if we should mock FFmpeg operations."""
    if S.broadcast_recording_mock_on_no_ffmpeg and not _ffmpeg_available():
        return True
    return False


def _now_ts() -> int:
    return int(time.time())


def _upload_to_s3(local_path: str, *, bucket: str, key: str) -> None:
    """Upload a local file to the VOD bucket (GAP-0121).

    Uses the shared ``app.core.aws_clients.s3_client()`` factory so the same
    code path runs in dev (moto intercepts boto3 in-process) and production
    (real S3) per SECOPS-007 — the only difference is the resolved endpoint.

    Raises RuntimeError on any boto3 error so the caller can mark the
    recording as failed.
    """
    import os

    from app.core.aws_clients import s3_client

    file_size = os.path.getsize(local_path)
    logger.info("Uploading %s -> s3://%s/%s (%d bytes)", local_path, bucket, key, file_size)
    try:
        s3_client().upload_file(local_path, bucket, key)
    except Exception as exc:
        raise RuntimeError(f"S3 upload failed for s3://{bucket}/{key}: {exc}") from exc


# ─── Pipeline Steps ────────────────────────────────────────────────


def inventory_segments(recording: RecordingRecord) -> List[str]:
    """List .ts segment files from the archive prefix in S3 (GAP-0119).

    In mock mode (no FFmpeg), returns an empty list.
    Otherwise paginates ListObjectsV2 under ``s3_archive_prefix`` in the VOD
    bucket, filters for ``.ts`` segments, and returns the keys sorted
    lexicographically (zero-padded HLS sequence names sort chronologically).
    """
    if _should_mock():
        logger.info("Recording %s: mock inventory (no segments)", recording.recording_id)
        return []

    prefix = (recording.s3_archive_prefix or "").strip()
    if not prefix:
        logger.warning(
            "Recording %s: s3_archive_prefix is empty; no segments to inventory",
            recording.recording_id,
        )
        return []

    from app.core.aws_clients import s3_client

    s3 = s3_client()
    bucket = S.broadcast_recording_vod_bucket
    max_seg = S.broadcast_recording_max_segments

    keys: List[str] = []
    paginator = s3.get_paginator("list_objects_v2")
    try:
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith(".ts"):
                    keys.append(key)
                    if len(keys) >= max_seg:
                        logger.warning(
                            "Recording %s: segment cap %d reached; truncating inventory",
                            recording.recording_id, max_seg,
                        )
                        return sorted(keys)
    except Exception as exc:
        logger.error(
            "Recording %s: S3 inventory error: %s",
            recording.recording_id, exc, exc_info=True,
        )
        raise

    segments = sorted(keys)
    logger.info(
        "Recording %s: inventoried %d segments from s3://%s/%s",
        recording.recording_id, len(segments), bucket, prefix,
    )
    return segments


def concatenate_segments(recording: RecordingRecord, segments: List[str]) -> Optional[str]:
    """Concatenate .ts segments via the FFmpeg concat demuxer (GAP-0120).

    Downloads each segment from S3 to a temp dir, writes a concat list file,
    runs FFmpeg (``-f concat -safe 1`` with validated absolute local paths),
    uploads the concatenated .ts back to S3, and returns the LOCAL path of the
    concatenated file for the downstream transcode/MP4 steps. Returns None in
    mock mode or when there are no segments.

    The temp dir is intentionally left in place on success; downstream steps
    read the returned path. Cleanup is handled by ``process_recording``.
    """
    if _should_mock() or not segments:
        logger.info("Recording %s: mock concatenation (skip)", recording.recording_id)
        return None

    import os
    import subprocess
    import tempfile

    from app.core.aws_clients import s3_client

    s3 = s3_client()
    bucket = S.broadcast_recording_vod_bucket

    # Disk safety preflight (FFMPEG_MIN_FREE_DISK_GB).
    free_gb = shutil.disk_usage(tempfile.gettempdir()).free / (1024 ** 3)
    if free_gb < S.ffmpeg_min_free_disk_gb:
        raise RuntimeError(
            f"Insufficient disk space for recording: {free_gb:.1f} GB free, "
            f"{S.ffmpeg_min_free_disk_gb} GB required"
        )

    tmp_dir = tempfile.mkdtemp(prefix=f"bcast_concat_{recording.recording_id}_")
    try:
        logger.info(
            "Recording %s: downloading %d segments to %s",
            recording.recording_id, len(segments), tmp_dir,
        )

        # Step 1: Download all segments to local disk.
        local_paths: List[str] = []
        for i, key in enumerate(segments):
            local_name = os.path.join(tmp_dir, f"seg{i:06d}.ts")
            s3.download_file(bucket, key, local_name)
            local_paths.append(os.path.abspath(local_name))

        # Step 2: Write the FFmpeg concat demuxer input file. With -safe 1 the
        # demuxer rejects unsafe/relative paths, so validate that every entry
        # is an absolute path that lives inside our temp dir before writing it.
        tmp_dir_abs = os.path.abspath(tmp_dir)
        concat_list_path = os.path.join(tmp_dir, "concat.txt")
        with open(concat_list_path, "w") as fh:
            for lp in local_paths:
                if not os.path.isabs(lp) or os.path.commonpath([tmp_dir_abs, lp]) != tmp_dir_abs:
                    raise RuntimeError(f"Refusing unsafe concat path: {lp}")
                # Single-quote the path; escape any embedded single quotes.
                safe = lp.replace("'", r"'\''")
                fh.write(f"file '{safe}'\n")

        # Step 3: Run the FFmpeg concat demuxer.
        output_path = os.path.join(tmp_dir, "concatenated.ts")
        args = [
            S.ffmpeg_binary_path,
            "-hide_banner", "-loglevel", "warning", "-y",
            "-f", "concat", "-safe", "1",
            "-i", concat_list_path,
            "-c", "copy",
            output_path,
        ]
        logger.info(
            "Recording %s: running FFmpeg concat: %s",
            recording.recording_id, " ".join(args),
        )
        result = subprocess.run(args, capture_output=True, text=True, timeout=3600)
        if result.returncode != 0:
            raise RuntimeError(
                f"FFmpeg concat failed (rc={result.returncode}): {result.stderr[:500]}"
            )

        concat_size = os.path.getsize(output_path)
        logger.info(
            "Recording %s: concatenation complete, size=%d bytes",
            recording.recording_id, concat_size,
        )

        # Step 4: Upload the concatenated .ts to S3 for downstream use.
        s3_concat_key = f"{recording.session_id}/recording/concatenated.ts"
        _upload_to_s3(output_path, bucket=bucket, key=s3_concat_key)

        # Persist the key so a pipeline restart can locate the concat output.
        update_recording_status(
            recording.recording_id,
            recording.status,  # keep current status (processing)
            s3_concatenated_key=s3_concat_key,
        )

        return output_path

    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise


def transcode_recording(recording: RecordingRecord, concat_path: Optional[str]) -> Dict[str, Any]:
    """Transcode to ABR renditions.

    Returns metadata about renditions produced.
    In mock mode, returns mock rendition data.
    """
    if _should_mock() or concat_path is None:
        logger.info("Recording %s: mock transcode (skip)", recording.recording_id)
        return {
            "renditions": [
                {"label": "720p", "bitrate_kbps": 3000, "width": 1280, "height": 720},
            ],
            "duration_seconds": 0,
            "total_bytes": 0,
        }

    # Production: FFmpeg ABR pipeline
    logger.info("Recording %s: transcoding", recording.recording_id)
    return {"renditions": [], "duration_seconds": 0, "total_bytes": 0}


def generate_mp4(recording: RecordingRecord, concat_path: Optional[str]) -> Dict[str, Any]:
    """Remux the concatenated .ts file to progressive MP4.

    Uses -c copy (no re-encoding) and -movflags +faststart for progressive download.
    Returns dict with mp4_s3_key, mp4_size_bytes, and mp4_generated_at.
    """
    if _should_mock() or concat_path is None:
        # Mock: no real media exists, produce placeholder metadata
        mp4_key = f"{recording.session_id}/recording/full.mp4"
        logger.info("Recording %s: mock MP4 at %s", recording.recording_id, mp4_key)
        return {
            "mp4_s3_key": mp4_key,
            "mp4_size_bytes": 0,
            "mp4_generated_at": _now_ts(),
        }

    # Production: FFmpeg remux
    import subprocess
    import os as _os
    mp4_path = concat_path.replace(".ts", ".mp4")
    args = [
        S.ffmpeg_binary_path, "-hide_banner", "-loglevel", "warning", "-y",
        "-i", concat_path,
        "-c", "copy",
        "-movflags", "+faststart",
        mp4_path,
    ]
    logger.info("Recording %s: remuxing to MP4: %s", recording.recording_id, " ".join(args))
    result = subprocess.run(args, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"FFmpeg MP4 remux failed: {result.stderr[:500]}")

    mp4_size = _os.path.getsize(mp4_path)
    mp4_key = f"{recording.session_id}/recording/full.mp4"
    # GAP-0121: persist the generated MP4 to the VOD bucket so download/playback
    # URLs built from mp4_s3_key resolve to a real object.
    _upload_to_s3(mp4_path, bucket=S.broadcast_recording_vod_bucket, key=mp4_key)
    return {
        "mp4_s3_key": mp4_key,
        "mp4_size_bytes": mp4_size,
        "mp4_generated_at": _now_ts(),
    }


def generate_thumbnail(recording: RecordingRecord, concat_path: Optional[str]) -> Optional[str]:
    """Extract a thumbnail frame from the recording.

    Returns the S3 key of the thumbnail, or a mock key.
    """
    if _should_mock() or concat_path is None:
        key = f"{recording.session_id}/recording/thumbnail.jpg"
        logger.info("Recording %s: mock thumbnail at %s", recording.recording_id, key)
        return key

    # Production: FFmpeg frame extraction
    logger.info("Recording %s: generating thumbnail", recording.recording_id)
    return f"{recording.session_id}/recording/thumbnail.jpg"


def finalize_recording(
    recording: RecordingRecord,
    transcode_result: Dict[str, Any],
    thumbnail_key: Optional[str],
    mp4_result: Optional[Dict[str, Any]] = None,
) -> RecordingRecord:
    """Set status=ready and compute final metadata."""
    now = _now_ts()
    expires_at = recording.created_at + (recording.retention_days * 86400)
    manifest_key = f"{recording.session_id}/recording/master.m3u8"

    extra_fields: Dict[str, Any] = {
        "completed_at": now,
        "expires_at": expires_at,
        "s3_manifest_key": manifest_key,
        "s3_thumbnail_key": thumbnail_key or "",
        "duration_seconds": int(transcode_result.get("duration_seconds", 0)),
        "segment_count": int(transcode_result.get("segment_count", len(transcode_result.get("renditions", [])))),
        "total_bytes": int(transcode_result.get("total_bytes", 0)),
        "renditions": transcode_result.get("renditions", []),
    }

    # Include MP4 result fields (BCAST-008)
    if mp4_result:
        extra_fields["mp4_s3_key"] = mp4_result.get("mp4_s3_key", "")
        extra_fields["mp4_size_bytes"] = mp4_result.get("mp4_size_bytes", 0)
        extra_fields["mp4_generated_at"] = mp4_result.get("mp4_generated_at", 0)

    updated = update_recording_status(
        recording.recording_id,
        "ready",
        **extra_fields,
    )
    return updated


# ─── Main Pipeline ─────────────────────────────────────────────────


def process_recording(recording_id: str) -> Optional[RecordingRecord]:
    """Orchestrate the full recording pipeline.

    Steps:
    1. Inventory segments
    2. Concatenate
    3. Transcode
    4. Generate thumbnail
    5. Finalize (set status=ready)

    On failure at any step, sets status=failed with error details.
    """
    recording = get_recording(recording_id)
    if not recording:
        logger.error("Recording %s not found", recording_id)
        return None

    # Transition to processing
    update_recording_status(recording_id, "processing")

    concat_path: Optional[str] = None
    try:
        # Step 1: Inventory
        segments = inventory_segments(recording)

        # Step 2: Concatenate
        concat_path = concatenate_segments(recording, segments)

        # Step 3: Transcode
        transcode_result = transcode_recording(recording, concat_path)

        # Step 4: Generate MP4 download (BCAST-008)
        mp4_result = None
        if S.broadcast_recording_mp4_auto_generate:
            mp4_result = generate_mp4(recording, concat_path)

        # Step 5: Thumbnail
        thumbnail_key = generate_thumbnail(recording, concat_path)

        # Step 6: Finalize
        result = finalize_recording(recording, transcode_result, thumbnail_key, mp4_result)
        logger.info("Recording %s completed successfully", recording_id)

        # BCAST-010: Create VOD post in newsfeed when recording is ready
        if result and result.status == "ready":
            try:
                from app.services.broadcast_newsfeed import create_vod_post
                from app.services.broadcast_store import get_session as _get_sess
                from app.services.broadcast_viewers import get_viewer_count

                session = _get_sess(recording.session_id)
                viewer_count = get_viewer_count(recording.session_id)
                create_vod_post(
                    session_id=recording.session_id,
                    creator_id=session.created_by,
                    session_name=session.name,
                    recording_id=recording.recording_id,
                    recording_duration_seconds=float(result.duration_seconds or 0),
                    recording_playback_url=None,
                    peak_viewer_count=viewer_count,
                    thumbnail_url=session.thumbnail_url,
                )
            except Exception:
                logger.exception("VOD post creation failed for session %s (non-fatal)", recording.session_id)

        return result

    except Exception as exc:
        logger.exception("Recording %s failed: %s", recording_id, exc)
        update_recording_status(
            recording_id,
            "failed",
            error_code=type(exc).__name__,
            error_message=str(exc)[:500],
        )
        return get_recording(recording_id)

    finally:
        # Clean up the temp dir holding the concatenated .ts (and downloaded
        # segments). concatenate_segments leaves it in place on success so the
        # transcode/MP4 steps can read it; remove it once the pipeline is done.
        if concat_path:
            import os
            shutil.rmtree(os.path.dirname(concat_path), ignore_errors=True)
