"""On-demand image optimization router (PLATFORM-004).

Distinct from the upload-time variant generation that lives inside the newsfeed
upload endpoint. This router lets a client request optimization of an already
uploaded image (by its S3 key/URL) at serving time, persists an optimization
*record* in the ``image_optimizations`` table, caches the result, and exposes a
fetch path for previously generated records.

Prefix: ``/ui/images/optimize``
Auth: owner-scoped UI session (``require_ui_session``).
"""
from __future__ import annotations

import logging
import os
from urllib.parse import parse_qs, unquote, urlparse
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from app.core.settings import S
from app.core.aws_clients import s3_client
from app.models import ImageOptimizeRequest, ImageOptimizationRecord
from app.services.image_optimization import (
    get_optimization_record,
    optimize_source_image,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

image_optimization_router = APIRouter(prefix="/ui/images/optimize", tags=["image_optimization"])

UPLOAD_BUCKET = os.environ.get("UPLOAD_BUCKET")
_s3 = s3_client() if UPLOAD_BUCKET else None


def _extract_source_key(req: ImageOptimizeRequest) -> str:
    """Resolve the S3 key from either ``source_key`` or a ``source_url``."""
    if req.source_key:
        return req.source_key.strip()
    if req.source_url:
        parsed = urlparse(req.source_url)
        qs = parse_qs(parsed.query or "")
        keys = qs.get("s3_key")
        if keys:
            return unquote(keys[0])
    raise HTTPException(status_code=422, detail="source_key or source_url is required")


@image_optimization_router.post("", response_model=ImageOptimizationRecord)
def request_optimization(
    req: ImageOptimizeRequest,
    session: Dict[str, str] = Depends(require_ui_session),
):
    if not S.image_optimization_enabled:
        raise HTTPException(status_code=403, detail="Image optimization is disabled")
    if not UPLOAD_BUCKET or not _s3:
        raise HTTPException(status_code=500, detail="UPLOAD_BUCKET not configured")

    fmt = (req.format or "webp").lower()
    if fmt not in ("webp", "jpeg"):
        raise HTTPException(status_code=422, detail="format must be 'webp' or 'jpeg'")

    source_key = _extract_source_key(req)
    if ".." in source_key or source_key.startswith("/"):
        raise HTTPException(status_code=422, detail="invalid source_key")

    owner_sub = session["user_sub"]
    record = optimize_source_image(
        owner_sub,
        source_key,
        s3_client=_s3,
        bucket=UPLOAD_BUCKET,
        formats=[fmt],
        use_cache=req.use_cache,
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Source image not found")
    return record


@image_optimization_router.get("/{optimization_id}", response_model=ImageOptimizationRecord)
def fetch_optimization(
    optimization_id: str,
    session: Dict[str, str] = Depends(require_ui_session),
):
    record = get_optimization_record(session["user_sub"], optimization_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Optimization record not found")
    return record
