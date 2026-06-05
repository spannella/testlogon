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
from app.services.vod_s3_downloader import download_source_to_scratch
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
    import time as _time
    from app.services.job_registry import register_task, report_error, report_poll

    global _CONCURRENCY_SEMAPHORE
    max_concurrent = max(1, S.transcode_max_concurrent_jobs)
    _CONCURRENCY_SEMAPHORE = asyncio.Semaphore(max_concurrent)
    poll_interval = max(5, S.transcode_poll_interval_seconds)

    register_task("transcode_worker", poll_interval, enabled=True,
                   description="Processes video transcode jobs via FFmpeg")

    logger.info(
        "Transcode worker started: max_concurrent=%d, poll_interval=%ds",
        max_concurrent,
        poll_interval,
    )

    while not _SHUTDOWN:
        _start = _time.perf_counter()
        try:
            result = list_jobs_by_status("queued", limit=max_concurrent)
            jobs = result.get("items", [])
            _dispatched = 0
            for job in jobs:
                # Skip jobs with future retry time
                next_retry = job.get("next_retry_at")
                if next_retry and int(next_retry) > now_ts():
                    continue
                if _CONCURRENCY_SEMAPHORE.locked():
                    break
                asyncio.create_task(_process_job_with_semaphore(job))
                _dispatched += 1
            _dur = (_time.perf_counter() - _start) * 1000
            report_poll("transcode_worker", items_processed=_dispatched, duration_ms=_dur)
        except Exception as exc:
            report_error("transcode_worker", str(exc))
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

        # Download source to local scratch before passing to FFmpeg.
        # Standard FFmpeg builds do not support the s3:// protocol natively,
        # so ffmpeg must receive a local file path as its -i input.
        source_uri = str(download_source_to_scratch(source_uri, scratch_dir))

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

        # ─── VOD-005: Extract thumbnails ────────────────────────────────
        thumbnail_dir = scratch_dir / "thumbnails"
        thumbnail_dir.mkdir(parents=True, exist_ok=True)
        if S.vod_thumbnail_enabled:
            from app.services.vod_thumbnail_extractor import extract_thumbnails

            timestamps = [
                float(t.strip())
                for t in (S.vod_thumbnail_timestamps or "0,10,30").split(",")
                if t.strip()
            ]
            source_path = scratch_dir / "source"
            # Find source file in scratch dir (download step places it here)
            source_candidates = list(scratch_dir.glob("source*"))
            if source_candidates:
                source_path = source_candidates[0]

            try:
                await extract_thumbnails(
                    source_path=source_path,
                    output_dir=thumbnail_dir,
                    timestamps=timestamps,
                    width=S.vod_thumbnail_width,
                    quality=S.vod_thumbnail_quality,
                )
            except Exception:
                logger.warning("Thumbnail extraction failed for job %s", job_id, exc_info=True)

        # ─── VOD-005: Upload all outputs to S3 ─────────────────────────
        from app.services.vod_s3_uploader import upload_transcode_outputs

        def _upload_progress(files_done: int, total_files: int) -> None:
            # Map upload progress to 90-100% range (0-90% was transcode)
            pct = 90 + int((files_done / max(1, total_files)) * 10)
            update_job_progress(job_id, progress_pct=pct, current_rendition="uploading")

        upload_result = upload_transcode_outputs(
            job_id=job_id,
            video_id=job["video_id"],
            tenant_id=job["tenant_id"],
            output_dir=output_dir,
            thumbnail_dir=thumbnail_dir,
            on_progress=_upload_progress,
        )

        # ─── VOD-005: Generate signed playback URL ─────────────────────
        from app.services.vod_playback_url import mint_vod_playback_url

        playback_url = mint_vod_playback_url(
            video_id=job["video_id"],
            tenant_id=job["tenant_id"],
        )

        # ─── VOD-005: Complete with full output metadata ───────────────
        from app.services.transcode_job_store import complete_job_with_outputs

        complete_job_with_outputs(
            job_id=job_id,
            worker_id=wid,
            upload_result=upload_result,
            playback_url=playback_url,
            renditions_completed=completed_renditions,
        )
        logger.info("Transcode job %s completed successfully", job_id)

        # Transition video to published if video_metadata store is available
        try:
            from app.services.video_metadata_store import transition_video_status

            transition_video_status(video_id=job["video_id"], to_status="published")
        except Exception:
            logger.warning("Could not transition video %s to published", job["video_id"])

        # VOD-014: Auto-link to file manager
        try:
            from app.services.vod_file_bridge import link_video_to_filemanager
            link_video_to_filemanager(job["video_id"])
        except Exception:
            logger.warning("VOD-014: Could not link video %s to file manager", job["video_id"], exc_info=True)

    except Exception as e:
        error_msg = str(e)[:4096]
        attempt = int(job.get("attempt", 0))
        logger.warning("Transcode job %s failed (attempt %d): %s", job_id, attempt, error_msg)

        # VOD-005: Abort any incomplete multipart uploads on failure
        try:
            from app.services.vod_s3_uploader import abort_incomplete_uploads

            bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
            prefix = f"{S.vod_output_prefix or S.transcode_output_prefix or 'tenants'}/{job['tenant_id']}/assets/{job['video_id']}"
            abort_incomplete_uploads(bucket, prefix)
        except Exception:
            logger.warning("Failed to abort incomplete multipart uploads for job %s", job_id, exc_info=True)

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
    cancel_event: Optional[asyncio.Event] = None,
) -> None:
    """Run FFmpeg for a single rendition using the VOD-004 executor."""
    import time as _time

    from app.contracts.watermark_policy import WatermarkPolicy
    from app.services.ffmpeg_abr_pipeline import build_rendition_ffmpeg_args
    from app.services.ffmpeg_executor import classify_error, execute_rendition
    from app.services.ffmpeg_executor_types import (
        NonRetryableError,
        RenditionTimeoutError,
        RetryableError,
    )
    from app.services.ffmpeg_watermark_lifecycle import (
        patch_watermark_input,
        prepare_watermark_asset,
    )

    watermark_policy = WatermarkPolicy(**(watermark or {}))
    output_dir = scratch_dir / "output"

    args = build_rendition_ffmpeg_args(
        input_url=source_uri,
        output_dir=output_dir,
        rendition=rendition,
        watermark_policy=watermark_policy,
    )

    # Prepare watermark asset if needed
    local_wm = await prepare_watermark_asset(watermark or {}, scratch_dir)
    if local_wm:
        args = patch_watermark_input(args, local_wm)

    # VOD-010: Inject HLS encryption args if DRM is enabled for this job
    _encryption_params = None
    if rendition.get("drm_enabled") or rendition.get("_drm_enabled"):
        from app.services.vod_encryption import (
            get_ffmpeg_encryption_args,
            prepare_encryption_params,
        )

        _asset_id = rendition.get("_asset_id", job_id)
        _encryption_params = prepare_encryption_params(_asset_id, scratch_dir=scratch_dir)
        if _encryption_params:
            enc_args = get_ffmpeg_encryption_args(_encryption_params)
            # Insert encryption args before the output playlist path (last arg)
            args = args[:-1] + enc_args + args[-1:]

    rendition_name = rendition.get("name", f"rendition_{rendition_idx}")

    # Estimate expected duration (default 10 minutes if unknown)
    expected_duration_us = int(rendition.get("expected_duration_us", 600_000_000))

    # Throttled progress callback
    last_db_write = 0.0

    async def _on_progress(sample, overall_pct: int) -> None:
        nonlocal last_db_write
        now = _time.time()
        if now - last_db_write >= S.transcode_progress_update_interval_seconds:
            update_job_progress(
                job_id,
                progress_pct=overall_pct,
                current_rendition=rendition_name,
            )
            last_db_write = now

    try:
        result = await execute_rendition(
            args=args,
            rendition_name=rendition_name,
            expected_duration_us=expected_duration_us,
            timeout_seconds=S.transcode_rendition_timeout_seconds,
            on_progress=_on_progress,
            cancel_event=cancel_event,
        )
    except RenditionTimeoutError:
        raise
    except RetryableError:
        raise
    except NonRetryableError:
        raise

    if not result.success:
        error_code, is_retryable = classify_error(result.returncode, result.stderr_tail)
        if is_retryable:
            raise RetryableError(error_code, result.stderr_tail[:4096])
        else:
            raise NonRetryableError(error_code, result.stderr_tail[:4096])


def start_transcode_worker_task() -> None:
    """Register the transcode worker as a startup task. Follows broadcast_reconciler pattern."""
    from app.services.job_registry import register_task

    if not S.transcode_worker_enabled:
        register_task("transcode_worker", 30, enabled=False,
                       description="Processes video transcode jobs via FFmpeg")
        logger.info("Transcode worker disabled (TRANSCODE_WORKER_ENABLED=0)")
        return
    logger.info("Registering transcode worker background task")
    asyncio.create_task(transcode_worker_loop())
