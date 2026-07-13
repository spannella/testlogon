"""Transcode job API endpoints (VOD-003).

Provides endpoints to submit transcode jobs, check status, and list jobs.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from pydantic import BaseModel, Field

from app.services.sessions import require_ui_session
from app.core.settings import S
from app.services.transcode_job_store import (
    create_job,
    get_job,
    list_jobs_by_status,
    list_jobs_by_video,
)
from app.services.video_metadata_store import get_video, transition_video_status

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/transcode-jobs", tags=["transcode"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])


# ─── Request / Response models ───────────────────────────────────────────────


class SubmitTranscodeJobIn(BaseModel):
    video_id: str = Field(..., min_length=1)
    rendition_profiles: list[dict] = Field(default_factory=list, min_length=1)
    source_uri: str = Field(default="", min_length=0)
    watermark_policy: Optional[dict] = None
    drm_policy: Optional[dict] = None
    priority: int = Field(default=0, ge=-10, le=10)


class TranscodeJobOut(BaseModel):
    job_id: str
    video_id: str
    tenant_id: str
    status: str
    created_at: int
    updated_at: int
    attempt: int
    progress_pct: int = 0
    current_rendition: Optional[str] = None
    renditions_completed: list[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    output_hls_manifest_uri: Optional[str] = None


class TranscodeJobListOut(BaseModel):
    items: list[TranscodeJobOut]
    cursor: Optional[str] = None


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", status_code=201)
async def submit_transcode_job(
    body: SubmitTranscodeJobIn,
    session=Depends(require_ui_session),
) -> TranscodeJobOut:
    """Submit a new transcode job for a video."""
    user_sub = session["user_sub"]

    # Verify video exists and user owns it (get_video raises 404 if not found)
    video = get_video(body.video_id)
    if video.owner_user_id != user_sub:
        role = session.get("role", "")
        if role not in ("admin", "root", "ADMIN", "ROOT"):
            raise HTTPException(status_code=403, detail="Not authorized")

    # Use user_sub as tenant_id in dev mode
    tenant_id = getattr(video, "tenant_id", None) or user_sub

    # Determine source URI
    source_uri = body.source_uri
    if not source_uri:
        s3_key = video.source_s3_key or ""
        if s3_key:
            bucket = S.video_upload_bucket or "local-uploads"
            source_uri = f"s3://{bucket}/{s3_key}"

    # Create the job
    job = create_job(
        video_id=body.video_id,
        tenant_id=tenant_id,
        rendition_profiles=body.rendition_profiles,
        source_uri=source_uri,
        watermark_policy=body.watermark_policy,
        drm_policy=body.drm_policy,
        priority=body.priority,
    )

    # Transition video status to pending_encoding
    try:
        transition_video_status(video_id=body.video_id, to_status="pending_encoding")
    except Exception:
        logger.warning(
            "Could not transition video %s to pending_encoding", body.video_id
        )

    return _job_to_out(job)


@router.get("/{job_id}")
async def get_transcode_job_status(
    job_id: str,
    session=Depends(require_ui_session),
) -> TranscodeJobOut:
    """Get current status and progress for a transcode job."""
    job = get_job(job_id)
    return _job_to_out(job)


@router.get("")
async def list_transcode_jobs(
    status: Optional[str] = Query(default=None),
    video_id: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
) -> TranscodeJobListOut:
    """List transcode jobs, optionally filtered by status or video_id."""
    if video_id:
        items = list_jobs_by_video(video_id)
        return TranscodeJobListOut(
            items=[_job_to_out(j) for j in items],
            cursor=None,
        )

    if status:
        result = list_jobs_by_status(status, limit=limit, cursor=cursor)
    else:
        # Default to listing queued + running
        result = list_jobs_by_status("queued", limit=limit, cursor=cursor)

    return TranscodeJobListOut(
        items=[_job_to_out(j) for j in result.get("items", [])],
        cursor=result.get("cursor"),
    )


# ─── Video-scoped convenience endpoints ──────────────────────────────────────


video_router = APIRouter(prefix="/ui/videos", tags=["transcode"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])


@video_router.post("/{video_id}/transcode", status_code=201)
async def submit_video_transcode(
    video_id: str,
    body: SubmitTranscodeJobIn = None,
    session=Depends(require_ui_session),
) -> TranscodeJobOut:
    """Submit a transcode job for a specific video (convenience endpoint)."""
    if body is None:
        body = SubmitTranscodeJobIn(video_id=video_id, rendition_profiles=[])

    # Override video_id from path
    body.video_id = video_id
    if not body.rendition_profiles:
        # Use canonical ABR ladder as default
        from app.contracts.video_rendition_profiles import CANONICAL_ABR_LADDER

        body.rendition_profiles = list(CANONICAL_ABR_LADDER)

    return await submit_transcode_job(body, session)


@video_router.get("/{video_id}/transcode/status")
async def get_video_transcode_status(
    video_id: str,
    session=Depends(require_ui_session),
) -> TranscodeJobOut:
    """Get the most recent transcode job status for a video."""
    jobs = list_jobs_by_video(video_id)
    if not jobs:
        raise HTTPException(status_code=404, detail="No transcode jobs for this video")
    # Return most recent (first since sorted by created_at desc)
    return _job_to_out(jobs[0])


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _job_to_out(job: dict) -> TranscodeJobOut:
    return TranscodeJobOut(
        job_id=job["job_id"],
        video_id=job.get("video_id", ""),
        tenant_id=job.get("tenant_id", ""),
        status=job.get("status", ""),
        created_at=int(job.get("created_at", 0)),
        updated_at=int(job.get("updated_at", 0)),
        attempt=int(job.get("attempt", 0)),
        progress_pct=int(job.get("progress_pct", 0)),
        current_rendition=job.get("current_rendition"),
        renditions_completed=job.get("renditions_completed", []),
        error_message=job.get("error_message"),
        output_hls_manifest_uri=job.get("output_hls_manifest_uri"),
    )
