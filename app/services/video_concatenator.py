"""Video concatenation service (VOD-016).

Handles combining multiple source videos into a single output.
Supports two paths:
  - Concat demuxer (stream copy) when all inputs have the same codec/resolution/framerate
  - Concat filter (re-encode) when inputs differ

The create_concat_job function validates inputs and enqueues a job.
The execute_concat function performs the actual concatenation asynchronously.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models_video import VideoMetadataModel

logger = logging.getLogger(__name__)


# ─── Errors ──────────────────────────────────────────────────────────────────


class ConcatError(Exception):
    """Raised when a concatenation operation fails."""
    pass


# ─── Public API ──────────────────────────────────────────────────────────────


def create_concat_job(
    *,
    owner_user_id: str,
    source_video_ids: List[str],
    title: str,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a concat job from multiple source videos.

    1. Validates all source videos exist, same owner, published/approved status.
    2. Validates count limits and combined duration/size limits.
    3. Detects codec compatibility for demuxer vs filter path.
    4. Creates new video record with concat provenance.
    5. Enqueues transcode job with job_type="combine".
    6. Returns result dict.
    """
    from app.services.video_metadata_store import (
        get_video,
        create_video,
        update_concat_fields,
    )
    from app.services.transcode_job_store import create_job

    # Validate count
    max_inputs = S.video_concat_max_inputs
    if len(source_video_ids) < 2:
        raise HTTPException(status_code=400, detail="source_video_ids must contain at least 2 entries")
    if len(source_video_ids) > max_inputs:
        raise HTTPException(
            status_code=400,
            detail=f"source_video_ids must contain at most {max_inputs} entries",
        )

    # Check for duplicates
    if len(set(source_video_ids)) != len(source_video_ids):
        raise HTTPException(status_code=400, detail="source_video_ids contains duplicates")

    # Fetch and validate all source videos
    videos: List[VideoMetadataModel] = []
    total_duration = 0.0
    total_size = 0

    for vid in source_video_ids:
        try:
            video = get_video(vid)
        except HTTPException as e:
            if e.status_code == 404:
                raise HTTPException(status_code=404, detail=f"video not found: {vid}")
            raise

        if video.owner_user_id != owner_user_id:
            raise HTTPException(
                status_code=403,
                detail=f"forbidden: video {vid} is not owned by you",
            )

        if video.status not in ("published", "approved"):
            raise HTTPException(
                status_code=409,
                detail=f"video {vid} must be published or approved",
            )

        if not video.source_s3_key:
            raise HTTPException(
                status_code=409,
                detail=f"source file not available for video {vid}",
            )

        if video.duration_seconds is None:
            raise HTTPException(
                status_code=409,
                detail=f"duration unknown for video {vid}",
            )

        total_duration += video.duration_seconds
        total_size += video.file_size_bytes or 0
        videos.append(video)

    # Check combined limits
    if total_duration > S.video_concat_max_duration_seconds:
        raise HTTPException(
            status_code=400,
            detail=f"combined duration exceeds {S.video_concat_max_duration_seconds}s limit",
        )

    if total_size > S.video_concat_max_total_size_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"combined input size exceeds {S.video_concat_max_total_size_bytes // (1024**3)} GB limit",
        )

    # Determine concat method
    compatible = _check_codec_compatibility(videos)
    concat_method = "demuxer" if compatible else "filter"

    # Create new video metadata
    new_video = create_video(
        owner_user_id=owner_user_id,
        title=title,
        description=description,
        source_type="upload",
        visibility="private",
    )

    # Set concat provenance
    update_concat_fields(
        video_id=new_video.id,
        source_video_ids=source_video_ids,
        created_via="concat",
        duration_seconds=total_duration,
    )

    # Enqueue concat job
    job = create_job(
        video_id=new_video.id,
        tenant_id=owner_user_id,
        rendition_profiles=[],
        source_uri="",
        job_type="combine",
        extra_fields={
            "concat_source_video_ids": source_video_ids,
            "concat_source_s3_keys": [v.source_s3_key for v in videos],
            "concat_method": concat_method,
            "concat_estimated_duration_seconds": Decimal(str(total_duration)),
            "concat_compatible": compatible,
        },
    )

    return {
        "video_id": new_video.id,
        "title": title,
        "status": "created",
        "source_video_ids": source_video_ids,
        "created_via": "concat",
        "estimated_duration_seconds": total_duration,
        "concat_method": concat_method,
        "concat_job_id": job["job_id"],
    }


def _check_codec_compatibility(videos: List[VideoMetadataModel]) -> bool:
    """Check if all input videos can be concatenated via demuxer (stream copy).

    Returns True if all have the same video codec, audio codec, resolution,
    and frame rate. Returns False if any video is missing probe data (safe fallback).
    """
    if not videos or len(videos) < 2:
        return False

    ref = videos[0]

    # Missing probe data on reference -> incompatible
    if any(getattr(ref, f) is None for f in ("video_codec", "width", "height")):
        return False

    for v in videos[1:]:
        # Missing probe data -> incompatible
        if any(getattr(v, f) is None for f in ("video_codec", "width", "height")):
            return False

        if v.video_codec != ref.video_codec:
            return False
        if v.audio_codec != ref.audio_codec:
            return False
        if v.width != ref.width or v.height != ref.height:
            return False
        if v.frame_rate != ref.frame_rate:
            return False

    return True


# ─── Concat execution ────────────────────────────────────────────────────────


async def execute_concat(job: Dict[str, Any]) -> None:
    """Process a concat job end-to-end.

    1. Download all source files from S3 to scratch.
    2. Run FFmpeg concat (demuxer or filter based on method).
    3. Upload result to S3.
    4. Update video metadata with output.
    5. Enqueue standard transcode job for ABR pipeline.
    6. Mark concat job as completed.
    """
    import boto3

    job_id = job["job_id"]
    video_id = job["video_id"]
    owner = job.get("tenant_id", "")
    s3_keys = job.get("concat_source_s3_keys", [])
    method = job.get("concat_method", "filter")
    est_duration = float(job.get("concat_estimated_duration_seconds", 0))

    scratch_dir = Path(getattr(S, "transcode_scratch_dir", "/tmp/scratch")) / f"concat-{job_id}"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Download all sources
        bucket = S.video_upload_bucket
        s3 = boto3.client("s3", endpoint_url=S.s3_endpoint_url or None)
        input_paths: List[Path] = []

        for i, key in enumerate(s3_keys):
            ext = Path(key).suffix or ".mp4"
            local_path = scratch_dir / f"input_{i}{ext}"
            s3.download_file(bucket, key, str(local_path))
            input_paths.append(local_path)

        from app.services.transcode_job_store import update_job_progress
        update_job_progress(job_id, progress_pct=10, current_rendition="downloading")

        # 2. Run concat
        output_path = scratch_dir / "concat_output.mp4"

        if method == "demuxer":
            await _run_concat_demuxer(input_paths, output_path)
        else:
            await _run_concat_filter(
                input_paths, output_path,
                expected_duration_us=int(est_duration * 1_000_000),
            )

        update_job_progress(job_id, progress_pct=70, current_rendition="uploading")

        # 3. Upload to S3
        dest_key = f"videos/{owner}/{video_id}/concat.mp4"
        s3.upload_file(str(output_path), bucket, dest_key)

        # 4. Update video metadata
        actual_duration = await _probe_duration(output_path)
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression=(
                "SET source_s3_key = :sk, #s = :status, "
                "duration_seconds = :dur, updated_at = :ua"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":sk": dest_key,
                ":status": "pending_encoding",
                ":dur": Decimal(str(actual_duration or est_duration)),
                ":ua": now_ts(),
            },
        )

        update_job_progress(job_id, progress_pct=80, current_rendition="enqueuing_transcode")

        # 5. Enqueue standard transcode job for ABR
        from app.services.transcode_job_store import create_job
        create_job(
            video_id=video_id,
            tenant_id=owner,
            rendition_profiles=[],
            source_uri=dest_key,
            job_type="transcode",
        )

        # 6. Complete concat job
        from app.services.transcode_job_store import complete_job
        complete_job(job_id, output_manifest_uri=dest_key)
        update_job_progress(job_id, progress_pct=100)

        logger.info("Concat job %s completed: method=%s", job_id, method)

    except Exception:
        logger.exception("Concat job %s failed", job_id)
        raise
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)


# ─── Internal helpers ─────────────────────────────────────────────────────────


async def _run_concat_demuxer(
    input_paths: List[Path],
    output_path: Path,
    timeout_seconds: int = 600,
) -> None:
    """Concatenate via the concat demuxer (stream copy, fast)."""
    filelist_path = output_path.parent / "filelist.txt"
    with open(filelist_path, "w") as f:
        for p in input_paths:
            escaped = str(p).replace("'", "'\\''")
            f.write(f"file '{escaped}'\n")

    try:
        from app.services.ffmpeg_manager import get_ffmpeg_path
        ffmpeg_bin = get_ffmpeg_path()
    except Exception:
        ffmpeg_bin = "ffmpeg"

    cmd = [
        ffmpeg_bin, "-hide_banner", "-loglevel", "warning", "-y",
        "-f", "concat", "-safe", "0",
        "-i", str(filelist_path),
        "-c", "copy",
        "-movflags", "+faststart",
        str(output_path),
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    if proc.returncode != 0:
        stderr_text = stderr.decode("utf-8", errors="replace")[-2048:]
        raise ConcatError(f"Concat demuxer failed (exit={proc.returncode}): {stderr_text[:200]}")


async def _run_concat_filter(
    input_paths: List[Path],
    output_path: Path,
    timeout_seconds: int = 1800,
    expected_duration_us: int = 0,
) -> None:
    """Concatenate via the concat filter (re-encode, universal)."""
    n = len(input_paths)

    try:
        from app.services.ffmpeg_manager import get_ffmpeg_path
        ffmpeg_bin = get_ffmpeg_path()
    except Exception:
        ffmpeg_bin = "ffmpeg"

    cmd = [ffmpeg_bin, "-hide_banner", "-loglevel", "warning", "-y"]

    # Add all inputs
    for p in input_paths:
        cmd.extend(["-i", str(p)])

    # Build filter_complex
    filter_parts = []
    concat_inputs = []

    target_w, target_h = 1920, 1080  # Default target

    for i in range(n):
        filter_parts.append(
            f"[{i}:v]scale={target_w}:{target_h}:"
            f"force_original_aspect_ratio=decrease,"
            f"pad={target_w}:{target_h}:(ow-iw)/2:(oh-ih)/2,"
            f"setsar=1[v{i}]"
        )
        concat_inputs.append(f"[v{i}][{i}:a]")

    concat_inputs_str = "".join(concat_inputs)
    filter_parts.append(
        f"{concat_inputs_str}concat=n={n}:v=1:a=1[outv][outa]"
    )

    filter_complex = ";".join(filter_parts)

    cmd.extend([
        "-filter_complex", filter_complex,
        "-map", "[outv]", "-map", "[outa]",
        "-c:v", "libx264", "-preset", "medium", "-crf", "22",
        "-c:a", "aac", "-b:a", "128k", "-ar", "48000",
        "-movflags", "+faststart",
        str(output_path),
    ])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    if proc.returncode != 0:
        stderr_text = stderr.decode("utf-8", errors="replace")[-2048:]
        raise ConcatError(f"Concat filter failed (exit={proc.returncode}): {stderr_text[:200]}")


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
