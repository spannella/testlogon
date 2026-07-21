"""VOD-012: MP4 Download Generation Service.

Generates a progressive MP4 file from the original source video
for download purposes. In dev mode, this is mocked (no FFmpeg).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import Dict, Any

from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _download_mp4_key(video) -> str:
    """Deterministic S3 key for a video's download MP4 (bucket = vod_output_bucket).

    Single source of truth so the enqueue path and the worker path agree on the
    key that ``mint_video_download_url`` later presigns.
    """
    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    tenant_id = video.owner_user_id
    video_id = video.id
    return f"{prefix}/{tenant_id}/assets/{video_id}/download/{video_id}.mp4"


def generate_download_mp4(video) -> Dict[str, Any]:
    """Generate a download MP4 for the given video.

    In dev/mock mode (no FFmpeg): sets download_mp4_key to a deterministic
    path, download_mp4_size_bytes=0, status="ready" (instant — preserves the
    test suite + /mock/s3 flow).

    In production mode: enqueues an async ``download_mp4`` transcode job that
    remuxes/re-encodes the original source (``video.source_s3_key``) into a real
    progressive MP4 via on-box FFmpeg. Status starts "processing"; the worker
    flips it to "ready" (with a real size) or "failed".

    Returns dict with fields to update on the video record.
    """
    mp4_key = _download_mp4_key(video)

    if S.dev_mode:
        # Mock mode: instant generation, no FFmpeg needed (UNCHANGED).
        return {
            "download_mp4_key": mp4_key,
            "download_mp4_size_bytes": 0,
            "download_mp4_status": "ready",
        }

    # ── Production: enqueue a real transcode job ──────────────────────────
    # Guard: without a source object there is nothing to transcode. Return a
    # failed status rather than a phantom-ready 0-byte download.
    if not getattr(video, "source_s3_key", None):
        logger.warning(
            "generate_download_mp4: video %s has no source_s3_key; cannot build MP4",
            getattr(video, "id", "?"),
        )
        return {
            "download_mp4_key": mp4_key,
            "download_mp4_size_bytes": 0,
            "download_mp4_status": "failed",
        }

    from app.services.transcode_job_store import create_job

    create_job(
        video_id=video.id,
        tenant_id=video.owner_user_id,
        rendition_profiles=[],
        source_uri=video.source_s3_key,
        job_type="download_mp4",
    )

    return {
        "download_mp4_key": mp4_key,
        "download_mp4_size_bytes": 0,
        "download_mp4_status": "processing",
    }


# ─── Async job processor (mirrors video_clipper.process_clip_job) ──────────────


async def _run_download_mp4_ffmpeg(
    *,
    source_path: Path,
    output_path: Path,
    reencode: bool,
    timeout_seconds: int,
) -> "tuple[bool, str]":
    """Run one FFmpeg invocation (remux via ``-c copy``, or re-encode).

    Returns (success, stderr_tail).
    """
    try:
        from app.services.ffmpeg_manager import get_ffmpeg_path
        ffmpeg_bin = get_ffmpeg_path()
    except Exception:
        ffmpeg_bin = "ffmpeg"

    cmd = [
        ffmpeg_bin,
        "-hide_banner", "-loglevel", "warning", "-y",
        "-i", str(source_path),
    ]
    if reencode:
        cmd.extend([
            "-c:v", "libx264", "-preset", "veryfast", "-crf", "22",
            "-c:a", "aac", "-b:a", "128k",
        ])
    else:
        cmd.extend(["-c", "copy"])
    cmd.extend(["-movflags", "+faststart", str(output_path)])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds
        )
        stderr_text = stderr.decode("utf-8", errors="replace")[-4096:]
        return (proc.returncode == 0, stderr_text)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return (False, "timeout")
    except Exception as e:  # pragma: no cover - defensive
        return (False, str(e))


async def process_download_mp4_job(job: Dict[str, Any]) -> None:
    """Process a ``download_mp4`` job end-to-end (mirrors process_clip_job).

    1. Download ``source_s3_key`` from ``S.video_upload_bucket`` to scratch.
    2. FFmpeg remux (``-c copy +faststart``); on non-zero exit, re-encode fallback.
    3. Upload to the deterministic key in ``S.vod_output_bucket`` (ContentType=video/mp4).
    4. Update video_metadata: status="ready", real stat size, updated_at.
    5. ``complete_job``.

    On any failure: set download_mp4_status="failed" + ``fail_job``.
    """
    from app.core.aws_clients import s3_client
    from app.core.tables import T
    from app.services.transcode_job_store import complete_job, fail_job
    from app.services.video_metadata_store import get_video

    job_id = job["job_id"]
    video_id = job["video_id"]
    source_s3_key = job.get("source_uri", "")

    # Scratch under the configured roomy scratch dir (NOT /tmp tmpfs) — same
    # pattern as the clipper.
    scratch_dir = Path(S.transcode_scratch_dir) / f"dlmp4-{job_id}"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    ext = os.path.splitext(source_s3_key)[1] or ".mp4"
    source_path = scratch_dir / f"source{ext}"
    out_path = scratch_dir / "download.mp4"

    try:
        if not source_s3_key:
            raise ValueError("download_mp4 job has no source_uri")

        # Recompute the deterministic output key from the live video record so
        # the enqueue path and the worker agree on what mint_video_download_url
        # will presign.
        video = get_video(video_id)
        out_key = _download_mp4_key(video)

        # ── 1. Download source from the upload bucket ────────────────────
        s3 = s3_client()
        upload_bucket = S.video_upload_bucket
        s3.download_file(upload_bucket, source_s3_key, str(source_path))

        # ── 2. FFmpeg: remux first, re-encode fallback ───────────────────
        timeout = getattr(S, "video_clip_timeout_seconds", 600) or 600
        ok, stderr_tail = await _run_download_mp4_ffmpeg(
            source_path=source_path,
            output_path=out_path,
            reencode=False,
            timeout_seconds=timeout,
        )
        method = "remux"
        if not ok:
            logger.info(
                "download_mp4 job %s: remux failed, re-encoding. stderr: %s",
                job_id, stderr_tail[:200],
            )
            ok, stderr_tail = await _run_download_mp4_ffmpeg(
                source_path=source_path,
                output_path=out_path,
                reencode=True,
                timeout_seconds=timeout,
            )
            method = "reencode"

        if not ok or not out_path.exists() or out_path.stat().st_size == 0:
            raise RuntimeError(
                f"ffmpeg download_mp4 produced no output: {stderr_tail[:300]}"
            )

        size_bytes = out_path.stat().st_size

        # ── 3. Upload to the vod_output bucket at the deterministic key ──
        out_bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
        s3.upload_file(
            str(out_path),
            out_bucket,
            out_key,
            ExtraArgs={"ContentType": "video/mp4"},
        )

        # ── 4. Flip the video record to ready with the real size ─────────
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression=(
                "SET download_mp4_key = :k, download_mp4_status = :st, "
                "download_mp4_size_bytes = :sz, updated_at = :ua"
            ),
            ExpressionAttributeValues={
                ":k": out_key,
                ":st": "ready",
                ":sz": size_bytes,
                ":ua": now_ts(),
            },
        )

        # ── 5. Mark the job complete ─────────────────────────────────────
        complete_job(job_id, output_manifest_uri=out_key)

        logger.info(
            "download_mp4 job %s completed: method=%s, size=%d bytes, key=%s",
            job_id, method, size_bytes, out_key,
        )

    except Exception as e:
        logger.exception("download_mp4 job %s failed", job_id)
        # Surface the failure on the video record so the UI stops showing
        # "processing" forever, then transition the job out of "running".
        try:
            T.video_metadata.update_item(
                Key={"video_id": video_id},
                UpdateExpression="SET download_mp4_status = :st, updated_at = :ua",
                ExpressionAttributeValues={":st": "failed", ":ua": now_ts()},
            )
        except Exception:
            logger.exception(
                "download_mp4 job %s: could not mark video %s failed",
                job_id, video_id,
            )
        try:
            fail_job(job_id, str(e)[:4096], int(job.get("attempt", 0)))
        except Exception:
            logger.exception("fail_job itself failed for download_mp4 job %s", job_id)
        raise
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)


def mint_video_download_url(video, ttl: int) -> Dict[str, Any]:
    """Mint a presigned download URL for the video's MP4 file.

    Returns dict with download_url, download_expires_at, file_size_bytes,
    filename, and content_type.
    """
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    key = video.download_mp4_key
    expires_at = now_ts() + ttl
    safe_title = (video.title or "video").replace('"', "'")[:200]
    filename = f"{safe_title}.mp4"

    if S.dev_mode:
        download_url = f"/mock/s3/{bucket}/{key}?expires={expires_at}&disposition=attachment"
    else:
        # Production: use S3 presigned URL
        from app.core.aws import get_s3_client

        _s3 = get_s3_client()
        download_url = _s3.generate_presigned_url(
            ClientMethod="get_object",
            Params={
                "Bucket": bucket,
                "Key": key,
                "ResponseContentDisposition": f'attachment; filename="{filename}"',
                "ResponseContentType": "video/mp4",
            },
            ExpiresIn=ttl,
        )

    return {
        "download_url": download_url,
        "download_expires_at": expires_at,
        "file_size_bytes": video.download_mp4_size_bytes or 0,
        "filename": filename,
        "content_type": "video/mp4",
    }
