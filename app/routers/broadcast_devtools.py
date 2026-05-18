from __future__ import annotations

from pathlib import Path
from typing import List, Optional
from urllib.request import urlopen

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.settings import S
from app.services.broadcast_playback import mint_local_playback_url
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/internal/broadcast-dev", tags=["broadcast-devtools"])


class BroadcastIngestStatusOut(BaseModel):
    healthy: bool
    endpoint: str


class BroadcastDebugStatusOut(BaseModel):
    ingest: BroadcastIngestStatusOut
    stream_keys: List[str] = Field(default_factory=list)
    manifest_url: Optional[str] = None
    transcoder_log_tail: List[str] = Field(default_factory=list)
    archive_objects: List[str] = Field(default_factory=list)
    cache_proxy_base_url: str
    minio_endpoint: str = "http://localhost:9000"


def _require_broadcast_devtools(ctx: dict) -> None:
    if not (S.dev_mode and S.broadcast_devtools_enabled):
        raise HTTPException(status_code=404, detail={"code": "broadcast_devtools_disabled", "detail": "not available"})
    if ctx.get("role") not in {"admin", "root"}:
        raise HTTPException(status_code=403, detail={"code": "BROADCAST_ROLE_FORBIDDEN", "detail": "admin or root role required"})


def _tail_lines(path: Path, max_lines: int = 80) -> List[str]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]


def _ingest_status() -> BroadcastIngestStatusOut:
    endpoint = "http://localhost:8088/healthz"
    healthy = False
    try:
        with urlopen(endpoint, timeout=1.5) as resp:
            healthy = int(resp.status) == 200
    except Exception:
        healthy = False
    return BroadcastIngestStatusOut(healthy=healthy, endpoint=endpoint)


@router.get("/status", response_model=BroadcastDebugStatusOut)
def get_broadcast_debug_status(ctx: dict = Depends(require_ui_session)) -> BroadcastDebugStatusOut:
    _require_broadcast_devtools(ctx)

    hls_root = Path(S.broadcast_local_hls_root or "tmp/broadcast-hls")
    archive_root = Path(S.broadcast_local_archive_root or "tmp/broadcast-archive")
    ffmpeg_log_path = Path(S.broadcast_local_ffmpeg_log_path or "tmp/broadcast-logs/ffmpeg-worker.log")

    stream_keys = sorted([p.name for p in hls_root.iterdir() if p.is_dir()]) if hls_root.exists() else []
    manifest_url = mint_local_playback_url(stream_keys[0]).url if stream_keys else None
    archive_objects = sorted(
        [str(p.relative_to(archive_root)) for p in archive_root.rglob("*") if p.is_file()]
    )[:200] if archive_root.exists() else []

    return BroadcastDebugStatusOut(
        ingest=_ingest_status(),
        stream_keys=stream_keys,
        manifest_url=manifest_url,
        transcoder_log_tail=_tail_lines(ffmpeg_log_path),
        archive_objects=archive_objects,
        cache_proxy_base_url=S.broadcast_local_cache_public_base_url or "http://localhost:8090",
    )
