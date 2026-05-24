"""Transcode worker background task (VOD-003).

In-process asyncio worker that polls for queued jobs and executes them
via FFmpeg subprocesses. Follows the same pattern as broadcast_reconciler
and other background tasks in this codebase.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.time import now_ts
from app.services.transcode_job_store import (
    claim_job,
    complete_job,
    fail_job,
    list_jobs_by_status,
    update_job_progress,
)

logger = logging.getLogger(__name__)

_CONCURRENCY_SEMAPHORE: Optional[asyncio.Semaphore] = None
_SHUTDOWN = False


def _worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


async def transcode_worker_loop() -> None:
    """Main polling loop for the transcode worker."""
    global _CONCURRENCY_SEMAPHORE
    max_concurrent = max(1, S.transcode_max_concurrent_jobs)
    _CONCURRENCY_SEMAPHORE = asyncio.Semaphore(max_concurrent)
    poll_interval = max(5, S.transcode_poll_interval_seconds)

    logger.info(
        "Transcode worker started: max_concurrent=%d, poll_interval=%ds",
        max_concurrent,
        poll_interval,
    )

    while not _SHUTDOWN:
        try:
            result = list_jobs_by_status("queued", limit=max_concurrent)
            jobs = result.get("items", [])
            for job in jobs:
                # Skip jobs with future retry time
                next_retry = job.get("next_retry_at")
                if next_retry and int(next_retry) > now_ts():
                    continue
                if _CONCURRENCY_SEMAPHORE.locked():
                    break
                asyncio.create_task(_process_job_with_semaphore(job))
        except Exception:
            logger.exception("Transcode worker poll failed")
        await asyncio.sleep(poll_interval)


async def _process_job_with_semaphore(job: Dict[str, Any]) -> None:
    """Wrapper that acquires the semaphore before processing."""
    async with _CONCURRENCY_SEMAPHORE:  # type: ignore[union-attr]
        await execute_transcode_job(job)


async def execute_transcode_job(job: Dict[str, Any]) -> None:
    """Execute a single transcode job end-to-end."""
    job_id = job["job_id"]
    wid = _worker_id()

    if not claim_job(job_id, wid):
        logger.debug("Job %s already claimed by another worker", job_id)
        return

    logger.info("Claimed transcode job %s", job_id)
    scratch_dir = Path(S.transcode_scratch_dir) / job_id
    scratch_dir.mkdir(parents=True, exist_ok=True)

    try:
        renditions: List[Dict[str, Any]] = job.get("renditions", [])
        source_uri = job.get("source_uri", "")
        watermark = job.get("watermark", {})

        completed_renditions: List[str] = []
        total = len(renditions)

        for i, rendition in enumerate(renditions):
            rendition_name = rendition.get("name", f"rendition_{i}")
            update_job_progress(
                job_id,
                progress_pct=int((i / max(total, 1)) * 100),
                current_rendition=rendition_name,
                renditions_completed=completed_renditions,
            )

            await _run_ffmpeg_for_rendition(
                job_id=job_id,
                source_uri=source_uri,
                rendition=rendition,
                watermark=watermark,
                scratch_dir=scratch_dir,
                rendition_idx=i,
                total_renditions=total,
            )
            completed_renditions.append(rendition_name)

        # Write master playlist
        from app.services.ffmpeg_abr_pipeline import write_master_playlist

        output_dir = scratch_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        write_master_playlist(output_dir)

        # Build output URI
        output_prefix = (
            f"{S.transcode_output_prefix}/{job['tenant_id']}/assets/{job['video_id']}/hls"
        )
        manifest_uri = f"s3://{S.transcode_output_bucket}/{output_prefix}/master.m3u8"

        complete_job(job_id, manifest_uri, completed_renditions)
        logger.info("Transcode job %s completed successfully", job_id)

        # Transition video to published if video_metadata store is available
        try:
            from app.services.video_metadata_store import transition_video_status

            transition_video_status(video_id=job["video_id"], to_status="published")
        except Exception:
            logger.warning("Could not transition video %s to published", job["video_id"])

    except Exception as e:
        error_msg = str(e)[:4096]
        attempt = int(job.get("attempt", 0))
        logger.warning("Transcode job %s failed (attempt %d): %s", job_id, attempt, error_msg)
        fail_job(job_id, error_msg, attempt)
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)


async def _run_ffmpeg_for_rendition(
    *,
    job_id: str,
    source_uri: str,
    rendition: Dict[str, Any],
    watermark: Dict[str, Any],
    scratch_dir: Path,
    rendition_idx: int,
    total_renditions: int,
) -> None:
    """Run FFmpeg for a single rendition using asyncio subprocess."""
    from app.contracts.watermark_policy import WatermarkPolicy
    from app.services.ffmpeg_abr_pipeline import build_rendition_ffmpeg_args

    watermark_policy = WatermarkPolicy(**(watermark or {}))
    output_dir = scratch_dir / "output"

    args = build_rendition_ffmpeg_args(
        input_url=source_uri,
        output_dir=output_dir,
        rendition=rendition,
        watermark_policy=watermark_policy,
    )

    # Add progress output for tracking
    # Insert -progress pipe:1 after -hide_banner
    prog_args = list(args)
    try:
        idx = prog_args.index("-hide_banner")
        prog_args.insert(idx + 1, "-progress")
        prog_args.insert(idx + 2, "pipe:1")
    except ValueError:
        pass

    proc = await asyncio.create_subprocess_exec(
        *prog_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    last_update = 0
    if proc.stdout:
        async for line in proc.stdout:
            decoded = line.decode().strip()
            if decoded.startswith("out_time_us="):
                try:
                    current_us = int(decoded.split("=")[1])
                    # Rough progress estimate
                    if current_us > 0 and now_ts() - last_update >= S.transcode_progress_update_interval_seconds:
                        overall_pct = int(
                            ((rendition_idx + 0.5) / max(total_renditions, 1)) * 100
                        )
                        update_job_progress(job_id, progress_pct=overall_pct)
                        last_update = now_ts()
                except (ValueError, IndexError):
                    pass

    await proc.wait()
    if proc.returncode != 0:
        stderr_bytes = await proc.stderr.read() if proc.stderr else b""
        stderr_text = stderr_bytes.decode(errors="replace")[:4096]
        raise RuntimeError(f"FFmpeg exit code {proc.returncode}: {stderr_text}")


def start_transcode_worker_task() -> None:
    """Register the transcode worker as a startup task. Follows broadcast_reconciler pattern."""
    if not S.transcode_worker_enabled:
        logger.info("Transcode worker disabled (TRANSCODE_WORKER_ENABLED=0)")
        return
    logger.info("Registering transcode worker background task")
    asyncio.create_task(transcode_worker_loop())
