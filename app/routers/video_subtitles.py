"""Video subtitle management endpoints (VOD-021).

Upload, list, delete, and update subtitle tracks on videos.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from pydantic import BaseModel, Field

from app.core.settings import S
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/videos", tags=["video-subtitles"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])


# ─── Response Models ─────────────────────────────────────────────────────────


class SubtitleTrackOut(BaseModel):
    track_id: str
    video_id: str = ""
    language: str
    label: str
    format: str = "vtt"
    vtt_url: str = ""
    is_default: bool = False
    is_auto_generated: bool = False
    created_at: int = 0


class SubtitleListOut(BaseModel):
    video_id: str
    tracks: List[SubtitleTrackOut] = Field(default_factory=list)


class SubtitleDeleteOut(BaseModel):
    ok: bool
    track_id: str
    video_id: str


class UpdateSubtitleIn(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=100)
    is_default: Optional[bool] = None


# ─── Endpoints ───────────────────────────────────────────────────────────────


@router.post("/{video_id}/subtitles", status_code=201, response_model=SubtitleTrackOut)
async def upload_subtitle_endpoint(
    video_id: str,
    file: UploadFile = File(...),
    language: str = Form(...),
    label: str = Form(...),
    is_default: bool = Form(False),
    ctx=Depends(require_ui_session),
):
    """Upload a subtitle file (VTT or SRT) for a video."""
    if not S.video_subtitle_enabled:
        raise HTTPException(status_code=403, detail="video subtitles are not enabled")

    user_sub = ctx["user_sub"]

    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="subtitle file is empty")

    # Detect format from extension
    filename = file.filename.lower()
    allowed_formats = S.video_subtitle_allowed_formats.split(",")
    file_ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
    if file_ext not in allowed_formats:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported subtitle format; accepted: {', '.join(allowed_formats)}",
        )

    # Read content
    raw_bytes = await file.read()
    if len(raw_bytes) == 0:
        raise HTTPException(status_code=400, detail="subtitle file is empty")

    # Size check
    max_size = S.video_subtitle_max_file_size_kb * 1024
    if len(raw_bytes) > max_size:
        raise HTTPException(
            status_code=400,
            detail=f"subtitle file exceeds maximum size of {S.video_subtitle_max_file_size_kb}KB",
        )

    # Decode as UTF-8
    try:
        content = raw_bytes.decode("utf-8-sig")
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="subtitle file must be UTF-8 encoded")

    from app.services.vod_subtitle_manager import upload_subtitle

    result = upload_subtitle(
        video_id=video_id,
        owner_id=user_sub,
        language=language,
        label=label,
        content=content,
        file_format=file_ext,
        is_default=is_default,
    )

    return SubtitleTrackOut(**result)


@router.get("/{video_id}/subtitles", response_model=SubtitleListOut)
def list_subtitles_endpoint(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    """List all subtitle tracks for a video."""
    from app.services.vod_subtitle_manager import list_subtitles

    result = list_subtitles(video_id)
    tracks = [SubtitleTrackOut(**t) for t in result["tracks"]]
    return SubtitleListOut(video_id=result["video_id"], tracks=tracks)


@router.delete("/{video_id}/subtitles/{track_id}", response_model=SubtitleDeleteOut)
def delete_subtitle_endpoint(
    video_id: str,
    track_id: str,
    ctx=Depends(require_ui_session),
):
    """Delete a subtitle track."""
    if not S.video_subtitle_enabled:
        raise HTTPException(status_code=403, detail="video subtitles are not enabled")

    user_sub = ctx["user_sub"]

    from app.services.vod_subtitle_manager import delete_subtitle

    result = delete_subtitle(video_id=video_id, track_id=track_id, owner_id=user_sub)
    return SubtitleDeleteOut(**result)


@router.patch("/{video_id}/subtitles/{track_id}", response_model=SubtitleTrackOut)
def update_subtitle_endpoint(
    video_id: str,
    track_id: str,
    body: UpdateSubtitleIn,
    ctx=Depends(require_ui_session),
):
    """Update a subtitle track's label or default status."""
    user_sub = ctx["user_sub"]

    from app.services.vod_subtitle_manager import update_subtitle

    result = update_subtitle(
        video_id=video_id,
        track_id=track_id,
        owner_id=user_sub,
        label=body.label,
        is_default=body.is_default,
    )

    return SubtitleTrackOut(**result)
