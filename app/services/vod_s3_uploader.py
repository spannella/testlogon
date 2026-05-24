"""VOD S3 upload service (VOD-005).

Uploads HLS transcode outputs (master playlist, variant playlists, TS segments)
to S3 with correct content types, cache headers, and lifecycle tagging.
Supports multipart upload for large segments via boto3 Transfer Manager.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from boto3.s3.transfer import TransferConfig

from app.core.aws_clients import s3_client
from app.core.settings import S

logger = logging.getLogger(__name__)

_s3 = s3_client()

# ─── Content-Type and Cache-Control maps ────────────────────────────────────

_CONTENT_TYPE_MAP = {
    ".m3u8": "application/vnd.apple.mpegurl",
    ".ts": "video/mp2t",
    ".mp4": "video/mp4",
    ".mpd": "application/dash+xml",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".json": "application/json",
    ".vtt": "text/vtt",
}

_CACHE_CONTROL_MAP = {
    ".m3u8": "max-age=31536000, immutable",  # variant playlists are immutable after transcode
    ".ts": "max-age=31536000, immutable",
    ".mp4": "max-age=31536000, immutable",
    ".jpg": "max-age=86400",
    ".png": "max-age=86400",
    ".json": "no-cache",
}

# Override for master playlist (detected by filename, not extension)
_MASTER_PLAYLIST_CACHE = "max-age=5, stale-while-revalidate=10"


def _infer_content_type(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return _CONTENT_TYPE_MAP.get(ext, "application/octet-stream")


def _infer_cache_control(filename: str) -> str:
    if filename == "master.m3u8":
        return _MASTER_PLAYLIST_CACHE
    ext = Path(filename).suffix.lower()
    return _CACHE_CONTROL_MAP.get(ext, "max-age=3600")


# ─── Transfer configuration ─────────────────────────────────────────────────

def _build_transfer_config() -> TransferConfig:
    threshold = max(1, S.vod_upload_multipart_threshold_mb) * 1024 * 1024
    chunksize = max(1, S.vod_upload_multipart_chunksize_mb) * 1024 * 1024
    concurrency = max(1, S.vod_upload_concurrency)
    return TransferConfig(
        multipart_threshold=threshold,
        multipart_chunksize=chunksize,
        max_concurrency=concurrency,
        use_threads=True,
    )


# ─── Data classes ────────────────────────────────────────────────────────────


@dataclass
class UploadResult:
    """Result of uploading all VOD outputs to S3."""
    manifest_s3_uri: str
    manifest_s3_key: str
    thumbnail_s3_keys: List[str] = field(default_factory=list)
    total_bytes: int = 0
    files_uploaded: int = 0
    upload_duration_seconds: float = 0.0


# ─── Upload functions ────────────────────────────────────────────────────────


def upload_segment(
    *,
    local_path: Path,
    bucket: str,
    key: str,
    content_type: str,
    cache_control: str,
    tags: str,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> str:
    """Upload a single file to S3 with multipart support. Returns ETag."""
    extra_args: Dict[str, Any] = {
        "ContentType": content_type,
        "CacheControl": cache_control,
        "Tagging": tags,
    }
    config = _build_transfer_config()
    _s3.upload_file(
        Filename=str(local_path),
        Bucket=bucket,
        Key=key,
        ExtraArgs=extra_args,
        Config=config,
        Callback=progress_callback,
    )
    head = _s3.head_object(Bucket=bucket, Key=key)
    return head.get("ETag", "")


def abort_incomplete_uploads(bucket: str, prefix: str) -> int:
    """Abort all incomplete multipart uploads under a prefix. Returns count aborted."""
    resp = _s3.list_multipart_uploads(Bucket=bucket, Prefix=prefix)
    aborted = 0
    for upload in resp.get("Uploads", []):
        try:
            _s3.abort_multipart_upload(
                Bucket=bucket,
                Key=upload["Key"],
                UploadId=upload["UploadId"],
            )
            aborted += 1
        except Exception:
            logger.warning("Failed to abort multipart upload %s", upload.get("UploadId"))
    return aborted


def upload_transcode_outputs(
    *,
    job_id: str,
    video_id: str,
    tenant_id: str,
    output_dir: Path,
    thumbnail_dir: Optional[Path] = None,
    retention_days: Optional[int] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> UploadResult:
    """
    Upload all HLS outputs and thumbnails to S3.

    Walks the output directory, uploads all files (m3u8, ts segments) to S3.
    S3 key convention: tenants/{tenant_id}/assets/{video_id}/hls/{rendition}/filename
    Uploads master.m3u8 last for atomic visibility.

    Args:
        job_id: Transcode job identifier
        video_id: Video/asset identifier
        tenant_id: Tenant identifier
        output_dir: Local directory containing hls/ subdirectory
        thumbnail_dir: Optional directory containing poster thumbnails
        retention_days: Object lifecycle retention days (default from settings)
        on_progress: Callback with (files_uploaded, total_files)

    Returns:
        UploadResult with manifest URL and metadata
    """
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"
    base_key = f"{prefix}/{tenant_id}/assets/{video_id}"
    ret_days = retention_days if retention_days is not None else S.vod_output_retention_days
    tags = f"retention=vod&tenant_id={tenant_id}&asset_id={video_id}&retention_days={ret_days}"

    t0 = time.monotonic()

    # 1. Enumerate all local files to upload
    upload_manifest: List[tuple] = []
    master_entry: Optional[tuple] = None

    if output_dir.exists():
        for local_path in sorted(output_dir.rglob("*")):
            if not local_path.is_file():
                continue
            relative = local_path.relative_to(output_dir)
            s3_key = f"{base_key}/hls/{relative}"
            content_type = _infer_content_type(local_path.name)
            cache_control = _infer_cache_control(local_path.name)

            # Hold back master.m3u8 to upload last
            if local_path.name == "master.m3u8" and local_path.parent == output_dir:
                master_entry = (local_path, s3_key, content_type, cache_control)
            else:
                upload_manifest.append((local_path, s3_key, content_type, cache_control))

    # 2. Add thumbnail files
    thumbnail_keys: List[str] = []
    if thumbnail_dir and thumbnail_dir.exists():
        for local_path in sorted(thumbnail_dir.rglob("*")):
            if not local_path.is_file():
                continue
            s3_key = f"{base_key}/thumbnails/{local_path.name}"
            content_type = _infer_content_type(local_path.name)
            cache_control = _infer_cache_control(local_path.name)
            upload_manifest.append((local_path, s3_key, content_type, cache_control))
            thumbnail_keys.append(s3_key)

    # Append master.m3u8 last for atomic visibility
    if master_entry:
        upload_manifest.append(master_entry)

    if not upload_manifest:
        return UploadResult(
            manifest_s3_uri="",
            manifest_s3_key="",
            thumbnail_s3_keys=[],
            total_bytes=0,
            files_uploaded=0,
            upload_duration_seconds=0.0,
        )

    # 3. Calculate total bytes for progress tracking
    total_bytes = sum(p.stat().st_size for p, _, _, _ in upload_manifest)
    total_files = len(upload_manifest)
    uploaded_bytes = 0
    files_done = 0

    # 4. Upload each file
    for local_path, s3_key, content_type, cache_control in upload_manifest:
        def _byte_progress(bytes_transferred: int) -> None:
            nonlocal uploaded_bytes
            uploaded_bytes += bytes_transferred

        upload_segment(
            local_path=local_path,
            bucket=bucket,
            key=s3_key,
            content_type=content_type,
            cache_control=cache_control,
            tags=tags,
            progress_callback=_byte_progress,
        )
        files_done += 1
        if on_progress:
            on_progress(files_done, total_files)

    # 5. Upload metadata.json
    renditions = []
    hls_dir = output_dir
    if hls_dir.exists():
        renditions = [d.name for d in hls_dir.iterdir() if d.is_dir()]

    metadata = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "video_id": video_id,
        "created_at": int(time.time()),
        "object_count": total_files + 1,
        "total_bytes": total_bytes,
        "renditions": renditions,
        "thumbnails": [Path(k).name for k in thumbnail_keys],
        "retention_days": ret_days,
    }
    metadata_key = f"{base_key}/metadata.json"
    _s3.put_object(
        Bucket=bucket,
        Key=metadata_key,
        Body=json.dumps(metadata, indent=2).encode(),
        ContentType="application/json",
        CacheControl="no-cache",
        Tagging=tags,
    )

    manifest_key = f"{base_key}/hls/master.m3u8"
    elapsed = time.monotonic() - t0

    return UploadResult(
        manifest_s3_uri=f"s3://{bucket}/{manifest_key}",
        manifest_s3_key=manifest_key,
        thumbnail_s3_keys=thumbnail_keys,
        total_bytes=total_bytes,
        files_uploaded=total_files + 1,  # +1 for metadata.json
        upload_duration_seconds=elapsed,
    )


# ─── Lifecycle policy ────────────────────────────────────────────────────────


def ensure_vod_lifecycle_policy(
    *,
    bucket: Optional[str] = None,
    default_retention_days: Optional[int] = None,
) -> bool:
    """Set lifecycle rules for VOD output objects tagged with retention=vod."""
    target_bucket = bucket or S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    days = default_retention_days or S.vod_output_retention_days
    rules = [
        {
            "ID": "vod-output-retention",
            "Status": "Enabled",
            "Filter": {"Tag": {"Key": "retention", "Value": "vod"}},
            "Expiration": {"Days": int(days)},
        },
        {
            "ID": "vod-abort-incomplete-multipart",
            "Status": "Enabled",
            "Filter": {"Prefix": ""},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
        },
    ]
    try:
        _s3.put_bucket_lifecycle_configuration(
            Bucket=target_bucket,
            LifecycleConfiguration={"Rules": rules},
        )
        return True
    except Exception:
        logger.exception("Failed to set VOD lifecycle policy on bucket %s", target_bucket)
        return False
