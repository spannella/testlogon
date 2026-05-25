"""VOD-012: MP4 Download Generation Service.

Generates a progressive MP4 file from the original source video
for download purposes. In dev mode, this is mocked (no FFmpeg).
"""

from __future__ import annotations

import logging
from typing import Dict, Any

from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def generate_download_mp4(video) -> Dict[str, Any]:
    """Generate a download MP4 for the given video.

    In dev/mock mode (no FFmpeg available): sets download_mp4_key
    to a deterministic path, download_mp4_size_bytes=0, status="ready".

    In production mode: would transcode from original source file
    with watermark to progressive MP4 (not implemented here).

    Returns dict with fields to update on the video record.
    """
    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    tenant_id = video.owner_user_id
    video_id = video.id

    # Deterministic S3 key for the download MP4
    mp4_key = f"{prefix}/{tenant_id}/assets/{video_id}/download/{video_id}.mp4"

    if S.dev_mode:
        # Mock mode: instant generation, no FFmpeg needed
        return {
            "download_mp4_key": mp4_key,
            "download_mp4_size_bytes": 0,
            "download_mp4_status": "ready",
        }

    # Production mode would:
    # 1. Download source from S3
    # 2. Run FFmpeg transcode with watermark
    # 3. Upload result to S3
    # 4. Return actual file size
    # For now, behave the same as dev mode
    return {
        "download_mp4_key": mp4_key,
        "download_mp4_size_bytes": 0,
        "download_mp4_status": "ready",
    }


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
