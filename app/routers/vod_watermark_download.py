"""VOD-020: Watermarked Downloads — per-viewer render router (distinct pipeline).

Prefix: ``/ui/vod/watermark-download``

Endpoints:
  POST  /ui/vod/watermark-download/{video_id}            — request watermarked download
  GET   /ui/vod/watermark-download/{video_id}/status     — poll render status
  GET   /ui/vod/watermark-download/{video_id}/renders    — list renders (owner forensic view)
  POST  /ui/vod/watermark-download/extract               — decode/extract a forensic payload

Entitlement gating reuses the VOD-019 purchase entitlement check
(``check_entitlement_purchase_only``) alongside the per-video ``allow_download``
flag. The per-viewer render itself reuses the existing watermark services via
``app/services/vod_watermark_download.py``.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.settings import S
from app.services.sessions import require_ui_session
from app.services.video_metadata_store import get_video
from app.services import vod_watermark_download as svc

logger = logging.getLogger(__name__)

vod_watermark_download_router = APIRouter(
    prefix="/ui/vod/watermark-download", tags=["vod-watermark-download"]
)


# ─── Request / Response models (inline; not part of shared models.py) ─────────


class VodWatermarkDownloadResponse(BaseModel):
    status: str  # "ready" | "processing" | "failed"
    render_id: str
    download_url: Optional[str] = None
    cached: bool = False
    watermark_payload: Optional[str] = None
    output_size_bytes: Optional[int] = None


class VodWatermarkDownloadStatusResponse(BaseModel):
    status: str  # "ready" | "processing" | "failed" | "not_found"
    render_id: Optional[str] = None
    download_url: Optional[str] = None
    output_size_bytes: Optional[int] = None
    created_at: Optional[int] = None
    error: Optional[str] = None


class VodWatermarkRenderItem(BaseModel):
    render_id: str
    video_id: str
    viewer_id: str
    watermark_payload: str
    status: str
    created_at: int
    output_size_bytes: Optional[int] = None


class VodWatermarkRenderListResponse(BaseModel):
    items: List[VodWatermarkRenderItem]


class VodWatermarkExtractIn(BaseModel):
    payload: Optional[str] = None


class VodWatermarkExtractResponse(BaseModel):
    found: bool
    payload: Optional[str] = None
    decoded: Optional[dict] = None


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _check_download_entitlement(video, viewer_id: str) -> None:
    """Gate the request on download entitlement.

    Owners always pass. For non-owners we require the video to be publicly
    reachable AND (when purchase tiers are enabled) a download entitlement.
    """
    if not video.allow_download:
        raise HTTPException(status_code=403, detail="downloads not enabled for this video")

    if video.owner_user_id == viewer_id:
        return

    is_public = video.status == "published" and video.visibility in ("public", "unlisted")
    if not is_public:
        raise HTTPException(status_code=403, detail="forbidden")

    if S.vod_purchase_tiers_enabled:
        from app.services.vod_purchase import check_entitlement_purchase_only

        ent = check_entitlement_purchase_only(user_id=viewer_id, video_id=video.id)
        if not ent.entitled or not ent.download_allowed:
            raise HTTPException(
                status_code=403,
                detail="Download access not included in your purchase",
            )


# ─── Endpoints ──────────────────────────────────────────────────────────────


# NOTE: This static-path route must be declared BEFORE the dynamic
# ``POST /{video_id}`` route below, otherwise FastAPI matches "/extract" as a
# video_id and the request 404s ("video not found").
@vod_watermark_download_router.post(
    "/extract", response_model=VodWatermarkExtractResponse
)
def extract_vod_watermark(
    body: VodWatermarkExtractIn,
    ctx=Depends(require_ui_session),
):
    """Decode/validate a forensic watermark payload (admin/forensic helper)."""
    result = svc.extract_payload(body.payload)
    return VodWatermarkExtractResponse(
        found=result["found"],
        payload=result["payload"],
        decoded=result["decoded"],
    )


@vod_watermark_download_router.post(
    "/{video_id}", response_model=VodWatermarkDownloadResponse
)
def request_vod_watermark_download(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    """Request a per-viewer watermarked download (entitlement gated).

    Idempotent within the cache window: a re-request returns the existing
    render. In dev mode (or when real FFmpeg is disabled) the render completes
    synchronously and a ``/mock/s3/...`` download URL is returned immediately.
    """
    viewer_id = ctx["user_sub"]
    video = get_video(video_id)

    _check_download_entitlement(video, viewer_id)

    if not video.download_mp4_key or video.download_mp4_status != "ready":
        raise HTTPException(status_code=409, detail="download MP4 not yet generated")

    if not S.vod_watermark_download_enabled or not video.watermark_downloads:
        # Feature disabled (globally or per-video): fall back to the plain MP4.
        from app.services.vod_mp4_generator import mint_video_download_url

        result = mint_video_download_url(video, S.video_download_url_ttl_seconds)
        return VodWatermarkDownloadResponse(
            status="ready",
            render_id="plain",
            download_url=result["download_url"],
            cached=False,
        )

    # Idempotent: reuse an existing render within the cache window.
    existing = svc.find_render(video_id, viewer_id)
    if existing:
        status = existing.get("status")
        if status == svc.STATUS_READY:
            url = svc.mint_download_url(existing["output_mp4_key"])
            return VodWatermarkDownloadResponse(
                status="ready",
                render_id=existing["render_id"],
                download_url=url,
                cached=True,
                watermark_payload=existing.get("watermark_payload"),
                output_size_bytes=int(existing.get("output_size_bytes", 0)) or None,
            )
        if status in (svc.STATUS_QUEUED, svc.STATUS_RENDERING):
            return VodWatermarkDownloadResponse(
                status="processing",
                render_id=existing["render_id"],
                cached=True,
                watermark_payload=existing.get("watermark_payload"),
            )

    # Rate limit concurrent renders per viewer.
    if svc.count_active_renders(viewer_id) >= S.vod_watermark_download_max_concurrent:
        raise HTTPException(status_code=429, detail="too many concurrent watermark requests")

    render = svc.create_render(
        video_id=video_id,
        viewer_id=viewer_id,
        source_mp4_key=video.download_mp4_key,
    )

    if S.dev_mode or not S.vod_watermark_download_real_ffmpeg:
        render = svc.process_render(render)
        if render.get("status") == svc.STATUS_READY:
            url = svc.mint_download_url(render["output_mp4_key"])
            return VodWatermarkDownloadResponse(
                status="ready",
                render_id=render["render_id"],
                download_url=url,
                cached=False,
                watermark_payload=render.get("watermark_payload"),
                output_size_bytes=int(render.get("output_size_bytes", 0)) or None,
            )
        return VodWatermarkDownloadResponse(
            status="failed",
            render_id=render["render_id"],
        )

    return VodWatermarkDownloadResponse(
        status="processing",
        render_id=render["render_id"],
        watermark_payload=render.get("watermark_payload"),
    )


@vod_watermark_download_router.get(
    "/{video_id}/status", response_model=VodWatermarkDownloadStatusResponse
)
def poll_vod_watermark_status(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    """Poll the latest render status for the current viewer + video."""
    viewer_id = ctx["user_sub"]
    render = svc.find_render(video_id, viewer_id)
    if not render:
        return VodWatermarkDownloadStatusResponse(status="not_found")

    status = render.get("status")
    if status == svc.STATUS_READY:
        url = svc.mint_download_url(render["output_mp4_key"])
        return VodWatermarkDownloadStatusResponse(
            status="ready",
            render_id=render["render_id"],
            download_url=url,
            output_size_bytes=int(render.get("output_size_bytes", 0)) or None,
        )
    if status == svc.STATUS_FAILED:
        return VodWatermarkDownloadStatusResponse(
            status="failed",
            render_id=render["render_id"],
            error=render.get("error_message", "watermark render failed"),
        )
    return VodWatermarkDownloadStatusResponse(
        status="processing",
        render_id=render["render_id"],
        created_at=int(render.get("created_at", 0)),
    )


@vod_watermark_download_router.get(
    "/{video_id}/renders", response_model=VodWatermarkRenderListResponse
)
def list_vod_watermark_renders(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    """List watermarked download renders for a video (owner forensic view)."""
    viewer_id = ctx["user_sub"]
    video = get_video(video_id)
    if video.owner_user_id != viewer_id:
        raise HTTPException(status_code=403, detail="forbidden")

    items = svc.list_video_renders(video_id)
    return VodWatermarkRenderListResponse(
        items=[
            VodWatermarkRenderItem(
                render_id=it["render_id"],
                video_id=it["video_id"],
                viewer_id=it["viewer_id"],
                watermark_payload=it.get("watermark_payload", ""),
                status=it.get("status", ""),
                created_at=int(it.get("created_at", 0)),
                output_size_bytes=int(it["output_size_bytes"]) if it.get("output_size_bytes") else None,
            )
            for it in items
        ]
    )
