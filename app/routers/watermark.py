"""VOD-020: Watermarked Downloads — Router.

Endpoints:
  POST /ui/videos/{video_id}/download/watermarked     — request watermarked download
  GET  /ui/videos/{video_id}/download/watermarked/status — poll job status
  PATCH /ui/videos/{video_id}/watermark                — toggle watermark_downloads
  POST /internal/watermark/extract                     — admin extraction tool (mock)
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.sessions import require_ui_session
from app.services.video_metadata_store import get_video
from app.services.watermark_generator import (
    build_watermark_payload,
    complete_watermark_job_mock,
    count_active_jobs,
    create_watermark_job,
    decode_watermark_payload,
    find_cached_watermark,
    get_watermark_job,
    list_download_history,
    list_user_downloads,
    mint_watermarked_download_url,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/videos", tags=["watermark"])
internal_router = APIRouter(prefix="/internal/watermark", tags=["watermark-internal"])


# ─── Response Models ─────────────────────────────────────────────────────────


class WatermarkDownloadResponse(BaseModel):
    status: str  # "ready" | "processing"
    download_url: Optional[str] = None
    cached: bool = False
    job_id: str


class WatermarkStatusResponse(BaseModel):
    status: str  # "ready" | "processing" | "failed"
    job_id: Optional[str] = None
    download_url: Optional[str] = None
    output_size_bytes: Optional[int] = None
    created_at: Optional[int] = None
    error: Optional[str] = None


class WatermarkToggleIn(BaseModel):
    watermark_downloads: bool


class WatermarkToggleOut(BaseModel):
    ok: bool
    watermark_downloads: bool


class WatermarkExtractResponse(BaseModel):
    found: bool
    payload: Optional[str] = None
    decoded: Optional[dict] = None


class DownloadHistoryItem(BaseModel):
    job_id: str
    video_id: str
    user_id: str
    watermark_payload: str
    created_at: int
    output_size_bytes: Optional[int] = None


class DownloadHistoryOut(BaseModel):
    items: List[DownloadHistoryItem]


# ─── Endpoints ───────────────────────────────────────────────────────────────


@router.post("/{video_id}/download/watermarked", response_model=WatermarkDownloadResponse)
def request_watermarked_download(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    """Request a watermarked download of a video.

    In dev mode, the job completes synchronously (no FFmpeg needed).
    Returns a presigned URL if the watermarked file is cached, or a job_id
    for polling if it needs to be generated.
    """
    user_id = ctx["user_sub"]
    video = get_video(video_id)

    if not video.allow_download:
        raise HTTPException(status_code=403, detail="downloads not enabled for this video")

    if not video.download_mp4_key or video.download_mp4_status != "ready":
        raise HTTPException(status_code=409, detail="download MP4 not yet generated")

    # If watermarking is disabled globally OR on the video, return plain download
    if not S.watermark_downloads_enabled or not video.watermark_downloads:
        from app.services.vod_mp4_generator import mint_video_download_url

        ttl = S.video_download_url_ttl_seconds
        result = mint_video_download_url(video, ttl)
        # Return in watermark response shape for uniform frontend handling
        return WatermarkDownloadResponse(
            status="ready",
            download_url=result["download_url"],
            cached=False,
            job_id="plain",
        )

    # Check for cached watermarked version
    cached = find_cached_watermark(video_id, user_id)
    if cached and cached.get("status") == "completed":
        url = mint_watermarked_download_url(cached["output_mp4_key"], ttl=3600)
        return WatermarkDownloadResponse(
            status="ready",
            download_url=url,
            cached=True,
            job_id=cached["job_id"],
        )

    if cached and cached.get("status") in ("queued", "running"):
        return WatermarkDownloadResponse(
            status="processing",
            job_id=cached["job_id"],
        )

    # Rate limit: max concurrent jobs per user
    active = count_active_jobs(user_id)
    if active >= S.watermark_max_concurrent_jobs:
        raise HTTPException(status_code=429, detail="too many concurrent watermark requests")

    # Create new watermark job
    job = create_watermark_job(
        video_id=video_id,
        user_id=user_id,
        source_mp4_key=video.download_mp4_key,
    )

    # In dev mode: process synchronously (no FFmpeg, mock watermark)
    if S.dev_mode:
        complete_watermark_job_mock(job)
        url = mint_watermarked_download_url(job["output_mp4_key"], ttl=3600)
        return WatermarkDownloadResponse(
            status="ready",
            download_url=url,
            cached=False,
            job_id=job["job_id"],
        )

    return WatermarkDownloadResponse(
        status="processing",
        job_id=job["job_id"],
    )


@router.get("/{video_id}/download/watermarked/status", response_model=WatermarkStatusResponse)
def poll_watermark_status(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    """Poll the status of a watermark job for the current user + video."""
    user_id = ctx["user_sub"]

    cached = find_cached_watermark(video_id, user_id)
    if not cached:
        return WatermarkStatusResponse(status="not_found")

    status = cached.get("status", "unknown")

    if status == "completed":
        url = mint_watermarked_download_url(cached["output_mp4_key"], ttl=3600)
        return WatermarkStatusResponse(
            status="ready",
            job_id=cached["job_id"],
            download_url=url,
            output_size_bytes=int(cached.get("output_size_bytes", 0)),
        )

    if status == "failed":
        return WatermarkStatusResponse(
            status="failed",
            job_id=cached["job_id"],
            error=cached.get("error_message", "watermark generation failed"),
        )

    return WatermarkStatusResponse(
        status="processing",
        job_id=cached["job_id"],
        created_at=int(cached.get("created_at", 0)),
    )


@router.patch("/{video_id}/watermark", response_model=WatermarkToggleOut)
def toggle_watermark_setting(
    video_id: str,
    body: WatermarkToggleIn,
    ctx=Depends(require_ui_session),
):
    """Toggle the ``watermark_downloads`` setting on a video (owner only)."""
    user_id = ctx["user_sub"]
    video = get_video(video_id)

    if video.owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="forbidden")

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET watermark_downloads = :wd, updated_at = :ua",
        ExpressionAttributeValues={
            ":wd": body.watermark_downloads,
            ":ua": now_ts(),
        },
    )

    return WatermarkToggleOut(ok=True, watermark_downloads=body.watermark_downloads)


@router.get("/{video_id}/download-history", response_model=DownloadHistoryOut)
def get_download_history(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    """List watermarked download history for a video (owner only)."""
    user_id = ctx["user_sub"]
    video = get_video(video_id)

    if video.owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="forbidden")

    items = list_download_history(video_id)
    return DownloadHistoryOut(
        items=[
            DownloadHistoryItem(
                job_id=item["job_id"],
                video_id=item["video_id"],
                user_id=item["user_id"],
                watermark_payload=item.get("watermark_payload", ""),
                created_at=int(item.get("created_at", 0)),
                output_size_bytes=int(item["output_size_bytes"]) if item.get("output_size_bytes") else None,
            )
            for item in items
        ]
    )


@router.get("/my-downloads", response_model=DownloadHistoryOut)
def get_my_downloads(
    ctx=Depends(require_ui_session),
):
    """List the current user's own watermarked download history."""
    user_id = ctx["user_sub"]
    items = list_user_downloads(user_id)
    return DownloadHistoryOut(
        items=[
            DownloadHistoryItem(
                job_id=item["job_id"],
                video_id=item["video_id"],
                user_id=item["user_id"],
                watermark_payload=item.get("watermark_payload", ""),
                created_at=int(item.get("created_at", 0)),
                output_size_bytes=int(item["output_size_bytes"]) if item.get("output_size_bytes") else None,
            )
            for item in items
        ]
    )


# ─── Internal / Admin Endpoints ──────────────────────────────────────────────


@internal_router.post("/extract", response_model=WatermarkExtractResponse)
def extract_watermark_endpoint():
    """Extract watermark payload from an uploaded video file.

    In dev mode, returns a mock payload demonstrating the decode flow.
    In production, this would accept a multipart file upload and use
    FFmpeg + OCR to extract the watermark text.
    """
    if S.dev_mode:
        # Mock extraction: return a sample payload for testing
        mock_ts = now_ts()
        mock_payload = build_watermark_payload("mock-user-id", mock_ts)
        decoded = decode_watermark_payload(mock_payload)
        return WatermarkExtractResponse(
            found=True,
            payload=mock_payload,
            decoded=decoded,
        )

    # Production: would parse multipart upload, run FFmpeg contrast boost,
    # run OCR on the extracted frame, and search for WM:v1:... pattern.
    return WatermarkExtractResponse(found=False, payload=None, decoded=None)
