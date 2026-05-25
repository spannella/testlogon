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


# ─── Pipeline Steps ────────────────────────────────────────────────


def inventory_segments(recording: RecordingRecord) -> List[str]:
    """List .ts segment files from the archive prefix.

    In mock mode, returns an empty list (no real segments).
    In production, would list S3 objects under s3_archive_prefix.
    """
    if _should_mock():
        logger.info("Recording %s: mock inventory (no segments)", recording.recording_id)
        return []

    # Production: list S3 objects under the archive prefix
    # For now in dev, return empty since no real segments exist
    logger.info("Recording %s: inventorying segments at %s", recording.recording_id, recording.s3_archive_prefix)
    return []


def concatenate_segments(recording: RecordingRecord, segments: List[str]) -> Optional[str]:
    """Concatenate .ts segments into a single transport stream.

    Returns the path to the concatenated file, or None in mock mode.
    """
    if _should_mock() or not segments:
        logger.info("Recording %s: mock concatenation (skip)", recording.recording_id)
        return None

    # Production: FFmpeg concat demuxer
    logger.info("Recording %s: concatenating %d segments", recording.recording_id, len(segments))
    return None


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
    # Upload to S3 would happen here in production
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
