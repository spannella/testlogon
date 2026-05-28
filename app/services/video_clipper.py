"""Video clipping service (VOD-015).

Handles extraction of time-range clips from source videos using FFmpeg.
Attempts stream copy first, falls back to re-encode if duration deviates.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ─── Types ────────────────────────────────────────────────────────────────────


class ClipExtractionError(Exception):
    """Raised when both stream copy and re-encode fail."""
    pass


@dataclass
class ClipFfmpegResult:
    """Result of a single FFmpeg clip invocation."""
    success: bool
    stderr_tail: str = ""


@dataclass
class ClipResult:
    """Result of a clip extraction (may be stream copy or re-encode)."""
    output_path: Path
    duration_seconds: float
    method: str  # "copy" or "reencode"


# ─── Public API ───────────────────────────────────────────────────────────────


def create_clip(
    *,
    owner_user_id: str,
    source_video_id: str,
    start_seconds: float,
    end_seconds: float,
    title: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a clip from an existing video.

    1. Validates the source video (owner, status, duration).
    2. Creates a new video metadata record with clip provenance.
    3. Enqueues a clip job for async processing.

    Returns dict with new video and job info.
    """
    from fastapi import HTTPException
    from app.services.video_metadata_store import (
        get_video,
        create_video,
        update_clip_fields,
    )
    from app.services.transcode_job_store import create_job

    source = get_video(source_video_id)

    # Authorization
    if source.owner_user_id != owner_user_id:
        raise HTTPException(status_code=403, detail="forbidden")

    # Status check
    if source.status not in ("published", "approved"):
        raise HTTPException(
            status_code=400,
            detail="video must be published or approved",
        )

    # Source file availability
    if not source.source_s3_key:
        raise HTTPException(status_code=409, detail="source file not available")

    # Duration validation
    if source.duration_seconds is None:
        raise HTTPException(status_code=409, detail="video duration unknown")

    if start_seconds >= end_seconds:
        raise HTTPException(
            status_code=400,
            detail="start_seconds must be less than end_seconds",
        )

    if end_seconds > source.duration_seconds:
        raise HTTPException(
            status_code=400,
            detail="end_seconds exceeds video duration",
        )

    clip_duration = end_seconds - start_seconds
    min_dur = S.video_clip_min_duration_seconds
    if clip_duration < min_dur:
        raise HTTPException(
            status_code=400,
            detail=f"minimum clip length is {min_dur} seconds",
        )

    # Create new video record
    clip_title = title or f"{source.title} (clip)"
    new_video = create_video(
        owner_user_id=owner_user_id,
        title=clip_title,
        description=source.description,
        source_type="upload",
        visibility=source.visibility,
    )

    # Set provenance
    update_clip_fields(
        video_id=new_video.id,
        source_video_id=source_video_id,
        clip_start_seconds=start_seconds,
        clip_end_seconds=end_seconds,
        created_via="clip",
    )

    # Enqueue clip job
    job = create_job(
        video_id=new_video.id,
        tenant_id=owner_user_id,
        rendition_profiles=[],
        source_uri=source.source_s3_key,
        job_type="clip",
        extra_fields={
            "clip_source_video_id": source_video_id,
            "clip_start_seconds": Decimal(str(start_seconds)),
            "clip_end_seconds": Decimal(str(end_seconds)),
        },
    )

    return {
        "video_id": new_video.id,
        "title": clip_title,
        "status": "created",
        "source_video_id": source_video_id,
        "clip_start_seconds": start_seconds,
        "clip_end_seconds": end_seconds,
        "created_via": "clip",
        "clip_job_id": job["job_id"],
    }


async def execute_clip(
    *,
    source_path: Path,
    output_path: Path,
    start_seconds: float,
    end_seconds: float,
    timeout_seconds: int = 300,
) -> ClipResult:
    """Extract a clip from source using stream copy, falling back to re-encode.

    Returns ClipResult with output path, duration, and method used.
    """
    expected_duration = end_seconds - start_seconds
    tolerance = getattr(S, "video_clip_copy_tolerance_seconds", 2.0) or 2.0

    # Phase 1: Try stream copy
    copy_result = await _run_clip_ffmpeg(
        source_path=source_path,
        output_path=output_path,
        start_seconds=start_seconds,
        end_seconds=end_seconds,
        stream_copy=True,
        timeout_seconds=timeout_seconds,
    )

    if copy_result.success:
        actual_duration = await _probe_duration(output_path)
        if actual_duration is not None and abs(actual_duration - expected_duration) <= tolerance:
            return ClipResult(
                output_path=output_path,
                duration_seconds=actual_duration,
                method="copy",
            )
        else:
            logger.info(
                "Stream copy duration mismatch (expected=%.1f, actual=%.1f), retrying with re-encode",
                expected_duration,
                actual_duration or 0,
            )

    # Phase 2: Re-encode fallback
    reencode_result = await _run_clip_ffmpeg(
        source_path=source_path,
        output_path=output_path,
        start_seconds=start_seconds,
        end_seconds=end_seconds,
        stream_copy=False,
        timeout_seconds=timeout_seconds,
    )

    if not reencode_result.success:
        raise ClipExtractionError(
            f"Clip extraction failed: {reencode_result.stderr_tail[:200]}"
        )

    actual_duration = await _probe_duration(output_path)
    return ClipResult(
        output_path=output_path,
        duration_seconds=actual_duration or expected_duration,
        method="reencode",
    )


async def process_clip_job(job: Dict[str, Any]) -> None:
    """Process a clip extraction job end-to-end.

    1. Download source from S3
    2. Extract clip via FFmpeg (stream copy -> re-encode fallback)
    3. Upload result to S3
    4. Update video metadata
    5. Enqueue standard transcode job for ABR pipeline
    """
    import os
    import boto3

    job_id = job["job_id"]
    video_id = job["video_id"]
    source_s3_key = job.get("source_uri", "")
    start_seconds = float(job.get("clip_start_seconds", 0))
    end_seconds = float(job.get("clip_end_seconds", 0))
    owner = job.get("tenant_id", "")

    scratch_dir = Path(S.transcode_scratch_dir) / f"clip-{job_id}"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    ext = os.path.splitext(source_s3_key)[1] or ".mp4"
    source_path = scratch_dir / f"source{ext}"
    clip_path = scratch_dir / "clip.mp4"

    try:
        # Download source from S3
        bucket = S.video_upload_bucket
        s3 = boto3.client("s3", endpoint_url=S.s3_endpoint_url or None)
        s3.download_file(bucket, source_s3_key, str(source_path))

        # Extract clip
        timeout = getattr(S, "video_clip_timeout_seconds", 600) or 600
        result = await execute_clip(
            source_path=source_path,
            output_path=clip_path,
            start_seconds=start_seconds,
            end_seconds=end_seconds,
            timeout_seconds=timeout,
        )

        # Upload clip to S3
        clip_s3_key = f"videos/{owner}/{video_id}/clip.mp4"
        s3.upload_file(str(clip_path), bucket, clip_s3_key)

        # Update video metadata
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression=(
                "SET source_s3_key = :sk, #s = :status, "
                "duration_seconds = :dur, updated_at = :ua"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":sk": clip_s3_key,
                ":status": "pending_encoding",
                ":dur": Decimal(str(result.duration_seconds)),
                ":ua": now_ts(),
            },
        )

        # Enqueue standard transcode job for ABR processing
        from app.services.transcode_job_store import create_job
        create_job(
            video_id=video_id,
            tenant_id=owner,
            rendition_profiles=[],
            source_uri=clip_s3_key,
            job_type="transcode",
        )

        # Mark clip job completed
        from app.services.transcode_job_store import complete_job
        complete_job(job_id, output_manifest_uri=clip_s3_key)

        logger.info(
            "Clip job %s completed: method=%s, duration=%.1fs",
            job_id, result.method, result.duration_seconds,
        )

    except Exception:
        logger.exception("Clip job %s failed", job_id)
        raise
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)


# ─── Internal helpers ─────────────────────────────────────────────────────────


async def _run_clip_ffmpeg(
    *,
    source_path: Path,
    output_path: Path,
    start_seconds: float,
    end_seconds: float,
    stream_copy: bool,
    timeout_seconds: int = 300,
) -> ClipFfmpegResult:
    """Run a single FFmpeg clip command."""
    try:
        from app.services.ffmpeg_manager import get_ffmpeg_path
        ffmpeg_bin = get_ffmpeg_path()
    except Exception:
        ffmpeg_bin = "ffmpeg"

    cmd = [
        ffmpeg_bin,
        "-hide_banner", "-loglevel", "warning", "-y",
        "-ss", str(start_seconds),
        "-to", str(end_seconds),
        "-i", str(source_path),
    ]

    if stream_copy:
        cmd.extend(["-c", "copy", "-avoid_negative_ts", "make_zero"])
    else:
        cmd.extend([
            "-c:v", "libx264", "-preset", "medium", "-crf", "22",
            "-c:a", "aac", "-b:a", "128k",
        ])

    cmd.extend(["-movflags", "+faststart", str(output_path)])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds
        )
        stderr_text = stderr.decode("utf-8", errors="replace")[-4096:]
        return ClipFfmpegResult(
            success=(proc.returncode == 0),
            stderr_tail=stderr_text,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return ClipFfmpegResult(success=False, stderr_tail="timeout")
    except Exception as e:
        return ClipFfmpegResult(success=False, stderr_tail=str(e))


async def _probe_duration(path: Path) -> Optional[float]:
    """Get duration of a media file via ffprobe."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ffprobe", "-v", "quiet",
            "-print_format", "json",
            "-show_format", str(path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        data = json.loads(stdout)
        return float(data["format"]["duration"])
    except Exception:
        return None
