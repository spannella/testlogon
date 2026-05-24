"""VOD thumbnail extraction service (VOD-005).

Extracts poster thumbnails at configurable timestamps from the source video
using FFmpeg subprocess calls. Uploads thumbnails to S3 alongside HLS outputs.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import List, Optional

from app.core.aws_clients import s3_client
from app.core.settings import S
from app.services.ffmpeg_manager import get_ffmpeg_path

logger = logging.getLogger(__name__)

_s3 = s3_client()

DEFAULT_THUMBNAIL_TIMESTAMPS = [0, 10, 30]


async def extract_thumbnails(
    *,
    source_path: Path,
    output_dir: Path,
    timestamps: Optional[List[float]] = None,
    width: int = 640,
    quality: int = 5,
) -> List[Path]:
    """
    Extract JPEG thumbnails at specified timestamps from a video file.

    Uses FFmpeg: ffmpeg -ss {ts} -i {source} -vframes 1 -vf scale={width}:-1 -q:v {quality} output.jpg
    Runs via asyncio.create_subprocess_exec.

    Args:
        source_path: Path to the source video file
        output_dir: Directory to write thumbnail files
        timestamps: List of seconds at which to extract frames (default: [0, 10, 30])
        width: Output thumbnail width in pixels (height is auto-scaled)
        quality: JPEG quality (2=best, 31=worst)

    Returns:
        List of generated thumbnail file paths
    """
    ts_list = timestamps if timestamps is not None else DEFAULT_THUMBNAIL_TIMESTAMPS
    output_dir.mkdir(parents=True, exist_ok=True)
    results: List[Path] = []

    try:
        ffmpeg_bin = get_ffmpeg_path()
    except Exception:
        ffmpeg_bin = S.ffmpeg_binary_path or "ffmpeg"

    for ts in ts_list:
        ts_label = f"{int(ts)}s" if ts == int(ts) else f"{ts}s"
        out_path = output_dir / f"poster_{ts_label}.jpg"
        cmd = [
            ffmpeg_bin, "-y",
            "-ss", str(ts),
            "-i", str(source_path),
            "-vframes", "1",
            "-vf", f"scale={width}:-1",
            "-q:v", str(quality),
            str(out_path),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            if proc.returncode == 0 and out_path.exists() and out_path.stat().st_size > 0:
                results.append(out_path)
                logger.debug("Extracted thumbnail at %ss -> %s", ts, out_path)
            else:
                # Timestamp may exceed video duration; skip silently
                logger.debug(
                    "Thumbnail extraction at %ss failed (rc=%s): %s",
                    ts,
                    proc.returncode,
                    (stderr or b"")[:200].decode(errors="replace"),
                )
        except asyncio.TimeoutError:
            logger.warning("Thumbnail extraction timed out at %ss", ts)
        except Exception:
            logger.warning("Thumbnail extraction error at %ss", ts, exc_info=True)

    return results


async def upload_thumbnails(
    *,
    paths: List[Path],
    video_id: str,
    tenant_id: str,
) -> List[str]:
    """
    Upload thumbnail files to S3.

    Uploads to tenants/{tenant_id}/assets/{video_id}/thumbnails/{filename}
    Returns list of S3 keys (or mock URLs in dev mode).
    """
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    base_key = f"{prefix}/{tenant_id}/assets/{video_id}/thumbnails"

    uploaded_keys: List[str] = []

    for path in paths:
        if not path.exists():
            continue
        s3_key = f"{base_key}/{path.name}"
        try:
            with open(path, "rb") as f:
                _s3.put_object(
                    Bucket=bucket,
                    Key=s3_key,
                    Body=f.read(),
                    ContentType="image/jpeg",
                    CacheControl="max-age=86400",
                    Tagging=f"retention=vod&tenant_id={tenant_id}&asset_id={video_id}",
                )
            uploaded_keys.append(s3_key)
        except Exception:
            logger.warning("Failed to upload thumbnail %s", path, exc_info=True)

    return uploaded_keys
