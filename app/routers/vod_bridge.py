"""VOD ↔ File Manager bridge endpoints (VOD-014)."""
from __future__ import annotations
from typing import Literal, Optional
from fastapi import APIRouter, Depends, HTTPException
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from pydantic import BaseModel, Field
from app.services.sessions import require_ui_session
from app.core.settings import S
from app.services.vod_file_bridge import link_video_to_filemanager, import_file_to_vod, unlink_video_from_filemanager
from app.services.video_metadata_store import get_video

router = APIRouter(prefix="/ui/vod-bridge", tags=["vod-bridge"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])


def _require_bridge_enabled():
    if not getattr(S, "vod_file_bridge_enabled", True):
        raise HTTPException(404, "VOD file bridge is not enabled")


class ImportToVodIn(BaseModel):
    file_path: str = Field(..., min_length=1)
    title: Optional[str] = Field(default=None, max_length=256)
    visibility: Literal["private", "unlisted", "public"] = "private"

class ImportToVodOut(BaseModel):
    video_id: str
    status: str
    file_path: str

class BridgeStatusOut(BaseModel):
    video_id: str
    vod_status: str
    file_path: Optional[str] = None
    hls_manifest_url: Optional[str] = None
    thumbnail_url: Optional[str] = None
    duration_seconds: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None


@router.post("/import", response_model=ImportToVodOut)
def api_import_to_vod(inp: ImportToVodIn, user=Depends(require_ui_session)):
    _require_bridge_enabled()
    result = import_file_to_vod(owner=user["user_sub"], file_path=inp.file_path, title=inp.title, visibility=inp.visibility)
    return ImportToVodOut(**result)


@router.get("/status/{video_id}", response_model=BridgeStatusOut)
def api_get_bridge_status(video_id: str, user=Depends(require_ui_session)):
    _require_bridge_enabled()
    video = get_video(video_id)
    if video.owner_user_id != user["user_sub"]:
        raise HTTPException(403, "not your video")
    return BridgeStatusOut(
        video_id=video_id,
        vod_status=video.status,
        file_path=video.source_file_node_id,
        hls_manifest_url=video.hls_manifest_url,
        thumbnail_url=video.thumbnail_url,
        duration_seconds=video.duration_seconds,
        width=video.width,
        height=video.height,
    )


@router.delete("/{video_id}/link")
def api_unlink(video_id: str, user=Depends(require_ui_session)):
    _require_bridge_enabled()
    result = unlink_video_from_filemanager(video_id, user["user_sub"])
    return result
