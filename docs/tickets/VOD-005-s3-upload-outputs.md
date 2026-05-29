# VOD-005: Upload Transcode Outputs to S3 and Generate Manifest URLs

**Ticket**: VOD-005
**Status**: Implemented
**Author**: Platform Engineering
**Date**: 2026-05-24
**Dependencies**: VOD-003 (Transcode Job Queue), VOD-002 (Upload Endpoint)

---

## 1. Overview & Motivation

### Problem Statement

The transcode worker (VOD-003) produces HLS outputs on local scratch disk: a master playlist (`master.m3u8`), per-rendition variant playlists (`<rendition>/index.m3u8`), and thousands of `.ts` media segments. These outputs must be uploaded to S3 so they can be served to viewers through CloudFront. Additionally, the platform needs signed manifest URLs that grant time-limited access and thumbnail poster images extracted from the source video at configurable timestamps.

Today, the broadcast system (`app/services/broadcast_archive.py`) handles live-to-S3 archiving via MediaLive output groups that write directly to S3 during a broadcast session. However, for VOD assets processed locally by FFmpeg, there is no equivalent upload pipeline. The local HLS outputs exist only on ephemeral scratch disk (`tmp/transcode-scratch/<job_id>/output/`) and are lost if the worker restarts or disk is reclaimed.

### Goals

1. **Durable storage**: All transcode outputs (manifests, segments, thumbnails) are uploaded to S3 with correct content types, cache headers, and lifecycle tagging.
2. **Manifest URL generation**: Generate signed playback URLs for both direct S3 access (presigned URLs) and CloudFront-fronted access (custom token signing), following the established patterns in `broadcast_playback.py` and `broadcast_cloudfront.py`.
3. **Thumbnail extraction**: Extract poster thumbnails at configurable timestamps from the source video and upload them alongside the HLS outputs.
4. **Video record update**: Upon successful upload, update the transcode job DynamoDB record with output URIs, thumbnail URLs, total byte count, and transition the job status to `completed`.
5. **Multipart upload for large segments**: Support segments exceeding 100MB (possible in high-bitrate 1080p streams with long segment durations) via S3 multipart upload with proper cleanup on failure.

### Scope

This ticket covers the S3 upload logic invoked by the transcode worker after FFmpeg completes, the manifest URL signing utilities, and the thumbnail extraction step. It does NOT cover CDN cache invalidation, DRM key packaging for manifests, or the viewer-facing playback API endpoint (which will consume the URLs this ticket generates).

---

## 2. Current State Analysis

### 2.1 Existing S3 Client Infrastructure

**Client factory** (`app/core/aws_clients.py`, lines 114-122):

```python
def s3_client():
    endpoint_url = _s3_endpoint_url()
    return boto3.client(
        "s3",
        region_name=_aws_region(),
        endpoint_url=endpoint_url,
        config=_s3_config(),
        **_local_credentials_kwargs(endpoint_url),
    )
```

The client supports path-style addressing (`S.s3_use_path_style`) for compatibility with MinIO/LocalStack. In dev mode, `_s3_endpoint_url()` returns `None` because moto intercepts boto3 calls in-process (lines 78-83 of `aws_clients.py`).

**In-process moto mock** (`app/core/dev_s3.py`):

The `start_s3_mock(bucket_names)` function activates `moto.mock_aws()` at startup and pre-creates buckets. Any new bucket needed for VOD outputs must be added to the bucket list passed to `start_s3_mock()` in `app/main.py`.

**Module-level client pattern**: Both `app/services/filemanager.py` and `app/routers/s3_mock.py` create a module-level `_s3 = s3_client()` singleton. This works because moto patches botocore's HTTP layer globally -- the client created before `mock_aws().start()` still has its calls intercepted once the mock is active.

### 2.2 Existing S3 Upload Patterns

**Simple `put_object`** (`app/services/filemanager.py`, line 2395):

```python
resp = _s3.put_object(Bucket=bucket, Key=s3_key, Body=content, **extra_args)
```

Used for small objects (file manager uploads, PDF documents). The `Body` parameter accepts `bytes` or file-like objects up to 5GB (single PUT limit).

**`upload_fileobj` for streaming** (`app/services/filemanager.py`, lines 2127-2132):

```python
_s3.upload_fileobj(
    Fileobj=file.file,
    Bucket=bucket,
    Key=s3_key,
    ExtraArgs={"ContentType": file.content_type or "application/octet-stream"},
)
```

The `upload_fileobj` method from boto3's S3 Transfer Manager automatically uses multipart upload for objects exceeding `multipart_threshold` (default 8MB). This is the preferred method for uploading files of unknown or large size.

**Mock S3 HTTP proxy** (`app/routers/s3_mock.py`): Exposes `/mock/s3/{bucket}/{key}` routes so browsers can directly access objects stored in moto. Used for image thumbnails and file downloads in dev mode. VOD manifest URLs in dev mode will follow this pattern: `http://localhost:8000/mock/s3/<bucket>/<key>`.

### 2.3 Signed URL Generation Patterns

**Local playback URLs** (`app/services/broadcast_playback.py`):

The `mint_local_playback_url(stream_key)` function generates nginx `secure_link`-compatible URLs with MD5 token + expiry:

```python
def mint_local_playback_url(stream_key: str, *, ttl_seconds: int | None = None) -> LocalPlaybackUrl:
    ttl = int(ttl_seconds or S.broadcast_local_cache_token_ttl_seconds or 600)
    expires_at = int(time.time()) + max(30, ttl)
    path = f"/hls/{key}/master.m3u8"
    token_payload = f"{expires_at}{path} {S.broadcast_local_cache_token_secret or 'local-cache-secret'}"
    md5_token = _b64url_md5(token_payload)
    url = f"{base}{path}?md5={md5_token}&expires={expires_at}"
    return LocalPlaybackUrl(url=url, expires_at=expires_at)
```

**CloudFront signed URLs** (`app/services/broadcast_cloudfront.py`):

The `mint_cloudfront_signed_playback_url(origin_url=..., ttl_seconds=...)` function generates CloudFront-compatible signed URLs with HMAC-SHA256 tokens:

```python
def _sign(path: str, expires_at: int) -> str:
    secret = (S.broadcast_cloudfront_signing_secret or "dev-cloudfront-secret").encode("utf-8")
    payload = f"{path}:{expires_at}".encode("utf-8")
    return _b64url(hmac.new(secret, payload, hashlib.sha256).digest())
```

The signed URL format is: `https://<cf-domain><path>?cf_token=<token>&cf_expires=<timestamp>`

Token validation (`validate_cloudfront_token`) enforces: non-empty token, expiry in the future, expiry not beyond max TTL + skew buffer, path normalization (no traversal), and constant-time comparison.

**S3 presigned URLs**: The filemanager uses `generate_presigned_url` (line 2226) for direct S3 access:

```python
_s3.generate_presigned_url(
    ClientMethod="put_object",
    Params={"Bucket": bucket, "Key": key},
    ExpiresIn=3600,
)
```

### 2.4 Broadcast Archive S3 Path Structure

`app/services/broadcast_archive.py` defines the archive path convention:

```python
def build_archive_s3_prefix(*, bucket: str, prefix_root: str, session_id: str) -> str:
    base = prefix_root.strip("/").strip()
    return f"s3://{bucket}/{base}/{session_id}/"
```

Settings: `S.broadcast_archive_bucket` ("broadcast-archive"), `S.broadcast_archive_prefix_root` ("sessions"), `S.broadcast_archive_retention_days` (30).

The `ensure_archive_lifecycle_policy()` function sets S3 lifecycle rules with tag-based expiration. This same pattern will be used for VOD outputs.

### 2.5 Existing Video Rendition Path Convention

`app/contracts/video_rendition_profiles.py` (line 60-61) defines the canonical path structure for VOD assets:

```python
def manifest_variant_path(*, tenant_id: str, asset_id: str, rendition: RenditionName) -> str:
    return f"tenants/{tenant_id}/assets/{asset_id}/hls/{rendition}/index.m3u8"
```

This establishes the S3 key prefix convention: `tenants/<tenant_id>/assets/<asset_id>/hls/`.

### 2.6 CloudFront Configuration

Settings from `app/core/settings.py` (lines 468-478):

| Setting | Default | Purpose |
|---------|---------|---------|
| `broadcast_cloudfront_domain` | (empty) | CloudFront distribution domain |
| `broadcast_cloudfront_signing_secret` | `dev-cloudfront-secret` | HMAC secret for URL tokens |
| `broadcast_cloudfront_token_ttl_seconds` | 600 | Signed URL validity period |
| `broadcast_cloudfront_cache_policy_id` | `managed-caching-optimized` | CloudFront cache behavior |
| `broadcast_cloudfront_response_headers_policy_id` | `managed-security-headers` | Response headers policy |
| `broadcast_cloudfront_waf_acl_arn` | (empty) | WAF ACL for geo/rate limiting |
| `broadcast_cloudfront_geo_allowlist` | (empty) | Comma-separated country codes |

The `cloudfront_security_defaults()` function returns these as a dict for downstream consumers.

### 2.7 What Does NOT Exist Today

- **No VOD-specific S3 upload service**: The transcode worker design (VOD-003) references `_upload_outputs()` but does not implement it.
- **No thumbnail extraction utility**: No FFmpeg-based frame extraction function exists in the services layer.
- **No VOD manifest URL signing**: The existing URL signing functions target live broadcast paths (`/hls/{stream_key}/master.m3u8`), not VOD S3 paths.
- **No multipart upload with progress tracking**: Existing uploads use `put_object` or `upload_fileobj` without reporting upload progress back to the job record.
- **No lifecycle tagging for VOD objects**: The broadcast archive uses `retention=broadcast` tags; VOD needs its own tag scheme.

---

## 3. Technical Design

### 3.1 S3 Path Structure for HLS Outputs

All VOD outputs follow the path convention established in `video_rendition_profiles.py`:

```
s3://<bucket>/<prefix>/<tenant_id>/assets/<asset_id>/
    hls/
        master.m3u8                          # HLS master playlist
        1080p/
            index.m3u8                       # Variant playlist
            segment_000.ts                   # Media segments
            segment_001.ts
            ...
        720p/
            index.m3u8
            segment_000.ts
            ...
        540p/
            index.m3u8
            ...
        360p/
            index.m3u8
            ...
    thumbnails/
        poster_0s.jpg                        # Thumbnail at 0s
        poster_10s.jpg                       # Thumbnail at 10s
        poster_30s.jpg                       # Thumbnail at 30s (or custom times)
        sprite_timeline.jpg                  # Timeline scrub sprite sheet (optional)
    metadata.json                            # Upload manifest metadata
```

**Bucket**: `S.vod_output_bucket` (default: `vod-output`, same as `S.transcode_output_bucket` from VOD-003)

**Prefix root**: `S.vod_output_prefix` (default: `tenants`)

**Full S3 key for master manifest**: `tenants/<tenant_id>/assets/<asset_id>/hls/master.m3u8`

**Content types** (set via `ContentType` on upload):

| File pattern | Content-Type |
|-------------|--------------|
| `*.m3u8` | `application/vnd.apple.mpegurl` |
| `*.ts` | `video/mp2t` |
| `*.jpg` | `image/jpeg` |
| `*.png` | `image/png` |
| `*.json` | `application/json` |
| `*.mpd` | `application/dash+xml` |

**Cache-Control headers** (set via `CacheControl` metadata):

| File type | Cache-Control | Rationale |
|-----------|--------------|-----------|
| Master playlist | `max-age=5, stale-while-revalidate=10` | May be updated if renditions are added |
| Variant playlist | `max-age=31536000, immutable` | Immutable after transcode completes |
| `.ts` segments | `max-age=31536000, immutable` | Immutable media |
| Thumbnails | `max-age=86400` | Rarely change, but not truly immutable |
| metadata.json | `no-cache` | Always fetch latest |

**S3 object tags** (for lifecycle management):

```python
Tagging="retention=vod&tenant_id={tenant_id}&asset_id={asset_id}&retention_days={retention_days}"
```

### 3.2 Multipart Upload for Large Segments

High-bitrate streams (6000kbps video + 192kbps audio at 1080p) with 10-second segments produce ~7.7MB per segment. With longer segment durations (e.g., 60-second archive segments from `broadcast_archive.py`'s `RolloverInterval: 60`), individual files can reach 46MB+. boto3's `upload_fileobj` handles multipart automatically, but we need explicit control for:

1. **Progress reporting**: Track bytes uploaded per segment to update job `progress_pct` during the upload phase.
2. **Abort on cancellation**: If the job is cancelled during upload, abort incomplete multipart uploads to avoid S3 storage leaks.
3. **Retry individual parts**: If a single part upload fails, retry that part without re-uploading the entire file.

**Implementation approach**: Use boto3's `S3Transfer` with a custom `TransferConfig` and progress callback:

```python
from boto3.s3.transfer import TransferConfig

_TRANSFER_CONFIG = TransferConfig(
    multipart_threshold=8 * 1024 * 1024,    # 8MB: switch to multipart
    multipart_chunksize=8 * 1024 * 1024,    # 8MB per part
    max_concurrency=4,                       # parallel part uploads
    use_threads=True,
)

def upload_segment(
    *,
    local_path: Path,
    bucket: str,
    key: str,
    content_type: str,
    cache_control: str,
    tags: str,
    progress_callback: Callable[[int], None] | None = None,
) -> str:
    """Upload a single file to S3 with multipart support. Returns ETag."""
    extra_args = {
        "ContentType": content_type,
        "CacheControl": cache_control,
        "Tagging": tags,
    }
    _s3.upload_file(
        Filename=str(local_path),
        Bucket=bucket,
        Key=key,
        ExtraArgs=extra_args,
        Config=_TRANSFER_CONFIG,
        Callback=progress_callback,
    )
    head = _s3.head_object(Bucket=bucket, Key=key)
    return head.get("ETag", "")
```

**Abort cleanup**: If the upload phase fails or the job is cancelled, call `list_multipart_uploads` + `abort_multipart_upload` to clean up incomplete uploads:

```python
def abort_incomplete_uploads(bucket: str, prefix: str) -> int:
    """Abort all incomplete multipart uploads under a prefix. Returns count aborted."""
    resp = _s3.list_multipart_uploads(Bucket=bucket, Prefix=prefix)
    aborted = 0
    for upload in resp.get("Uploads", []):
        _s3.abort_multipart_upload(
            Bucket=bucket,
            Key=upload["Key"],
            UploadId=upload["UploadId"],
        )
        aborted += 1
    return aborted
```

### 3.3 Manifest URL Generation

Two URL generation modes are supported, following the broadcast system's dual-mode pattern:

#### 3.3.1 Dev Mode: Mock S3 Direct URLs

In dev mode (moto S3), manifests are accessible through the mock S3 proxy:

```python
def mint_vod_dev_playback_url(*, tenant_id: str, asset_id: str) -> VodPlaybackUrl:
    """Generate a dev-mode playback URL via the /mock/s3 proxy."""
    bucket = S.vod_output_bucket or "vod-output"
    prefix = S.vod_output_prefix or "tenants"
    manifest_key = f"{prefix}/{tenant_id}/assets/{asset_id}/hls/master.m3u8"
    url = f"http://localhost:8000/mock/s3/{bucket}/{manifest_key}"
    return VodPlaybackUrl(
        playback_url=url,
        expires_at=0,  # no expiry in dev mode
        mode="dev",
    )
```

#### 3.3.2 Production Mode: CloudFront Signed URLs

In production, VOD manifests are served through CloudFront with the same HMAC signing used for live broadcasts. The `_sign()` function and `validate_cloudfront_token()` from `broadcast_cloudfront.py` are reused directly:

```python
from app.services.broadcast_cloudfront import (
    _sign,
    _normalize_token_path,
    resolve_cloudfront_base_domain,
)

@dataclass(frozen=True)
class VodPlaybackUrl:
    playback_url: str
    expires_at: int
    mode: str  # "dev" | "cloudfront" | "presigned"
    thumbnail_url: str | None = None

def mint_vod_cloudfront_playback_url(
    *,
    tenant_id: str,
    asset_id: str,
    ttl_seconds: int | None = None,
) -> VodPlaybackUrl:
    """Generate a CloudFront-signed playback URL for a VOD asset."""
    ttl = int(ttl_seconds or S.vod_playback_url_ttl_seconds or 3600)
    expires_at = int(time.time()) + max(60, ttl)

    prefix = S.vod_output_prefix or "tenants"
    path = f"/{prefix}/{tenant_id}/assets/{asset_id}/hls/master.m3u8"
    normalized = _normalize_token_path(path)
    token = _sign(normalized, expires_at)

    domain = resolve_cloudfront_base_domain()
    signed_url = f"https://{domain}{path}?cf_token={token}&cf_expires={expires_at}"

    # Also sign thumbnail URL
    thumb_path = f"/{prefix}/{tenant_id}/assets/{asset_id}/thumbnails/poster_0s.jpg"
    thumb_token = _sign(_normalize_token_path(thumb_path), expires_at)
    thumb_url = f"https://{domain}{thumb_path}?cf_token={thumb_token}&cf_expires={expires_at}"

    return VodPlaybackUrl(
        playback_url=signed_url,
        expires_at=expires_at,
        mode="cloudfront",
        thumbnail_url=thumb_url,
    )
```

#### 3.3.3 Fallback: S3 Presigned URLs

For deployments without CloudFront, generate S3 presigned GET URLs:

```python
def mint_vod_presigned_playback_url(
    *,
    tenant_id: str,
    asset_id: str,
    ttl_seconds: int | None = None,
) -> VodPlaybackUrl:
    """Generate an S3 presigned URL for direct bucket access."""
    ttl = int(ttl_seconds or S.vod_playback_url_ttl_seconds or 3600)
    bucket = S.vod_output_bucket or "vod-output"
    prefix = S.vod_output_prefix or "tenants"
    key = f"{prefix}/{tenant_id}/assets/{asset_id}/hls/master.m3u8"

    url = _s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=ttl,
    )
    return VodPlaybackUrl(
        playback_url=url,
        expires_at=int(time.time()) + ttl,
        mode="presigned",
    )
```

#### 3.3.4 Unified Entry Point

A single `mint_vod_playback_url()` function dispatches to the appropriate mode:

```python
def mint_vod_playback_url(*, tenant_id: str, asset_id: str, ttl_seconds: int | None = None) -> VodPlaybackUrl:
    if S.dev_mode:
        return mint_vod_dev_playback_url(tenant_id=tenant_id, asset_id=asset_id)
    if S.broadcast_cloudfront_domain:
        return mint_vod_cloudfront_playback_url(tenant_id=tenant_id, asset_id=asset_id, ttl_seconds=ttl_seconds)
    return mint_vod_presigned_playback_url(tenant_id=tenant_id, asset_id=asset_id, ttl_seconds=ttl_seconds)
```

### 3.4 Thumbnail Extraction and Upload

Thumbnails are extracted using FFmpeg after the transcode completes but before the upload phase. This avoids downloading the source a second time (the source is still on scratch disk).

**Extraction function**:

```python
import subprocess
from pathlib import Path

DEFAULT_THUMBNAIL_TIMESTAMPS = [0, 10, 30]  # seconds into the video

def extract_thumbnails(
    *,
    source_path: Path,
    output_dir: Path,
    timestamps_seconds: list[int] | None = None,
    width: int = 640,
    quality: int = 5,  # FFmpeg JPEG quality (2=best, 31=worst)
) -> list[Path]:
    """Extract JPEG thumbnails at specified timestamps. Returns list of output paths."""
    timestamps = timestamps_seconds or DEFAULT_THUMBNAIL_TIMESTAMPS
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []

    for ts in timestamps:
        out_path = output_dir / f"poster_{ts}s.jpg"
        cmd = [
            "ffmpeg", "-y",
            "-ss", str(ts),
            "-i", str(source_path),
            "-vframes", "1",
            "-vf", f"scale={width}:-1",
            "-q:v", str(quality),
            str(out_path),
        ]
        proc = subprocess.run(cmd, capture_output=True, timeout=30)
        if proc.returncode == 0 and out_path.exists():
            results.append(out_path)
        # If a timestamp exceeds video duration, FFmpeg produces no output -- skip silently

    return results
```

**Timeline sprite sheet** (optional enhancement for video scrubbing):

```python
def extract_sprite_sheet(
    *,
    source_path: Path,
    output_path: Path,
    interval_seconds: int = 10,
    tile_width: int = 160,
    tile_height: int = 90,
    columns: int = 10,
) -> Path | None:
    """Generate a sprite sheet for timeline scrubbing. Returns output path or None on failure."""
    cmd = [
        "ffmpeg", "-y",
        "-i", str(source_path),
        "-vf", f"fps=1/{interval_seconds},scale={tile_width}:{tile_height},tile={columns}x0",
        "-q:v", "5",
        str(output_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, timeout=120)
    if proc.returncode == 0 and output_path.exists():
        return output_path
    return None
```

### 3.5 Upload Orchestration

The main upload function is called by the transcode worker after all renditions are complete:

```python
@dataclass
class VodUploadResult:
    manifest_s3_uri: str          # s3://bucket/prefix/.../hls/master.m3u8
    manifest_s3_key: str          # prefix/.../hls/master.m3u8
    thumbnail_s3_keys: list[str]  # keys for uploaded thumbnails
    total_bytes: int              # sum of all uploaded objects
    object_count: int             # total number of S3 objects created
    upload_duration_seconds: float

async def upload_vod_outputs(
    *,
    job_id: str,
    tenant_id: str,
    asset_id: str,
    output_dir: Path,
    thumbnail_dir: Path,
    retention_days: int,
    progress_callback: Callable[[int, int], None] | None = None,
) -> VodUploadResult:
    """
    Upload all HLS outputs and thumbnails to S3.

    Args:
        output_dir: Local directory containing hls/ subdirectory with master.m3u8 and rendition dirs
        thumbnail_dir: Local directory containing poster_*.jpg files
        progress_callback: Called with (bytes_uploaded_so_far, total_bytes) for progress tracking
    """
    bucket = S.vod_output_bucket or "vod-output"
    prefix = S.vod_output_prefix or "tenants"
    base_key = f"{prefix}/{tenant_id}/assets/{asset_id}"
    tags = f"retention=vod&tenant_id={tenant_id}&asset_id={asset_id}&retention_days={retention_days}"

    t0 = time.monotonic()

    # 1. Enumerate all local files to upload
    upload_manifest = []
    for local_path in sorted(output_dir.rglob("*")):
        if not local_path.is_file():
            continue
        relative = local_path.relative_to(output_dir)
        s3_key = f"{base_key}/{relative}"
        content_type = _infer_content_type(local_path.name)
        cache_control = _infer_cache_control(local_path.name)
        upload_manifest.append((local_path, s3_key, content_type, cache_control))

    for local_path in sorted(thumbnail_dir.rglob("*")):
        if not local_path.is_file():
            continue
        s3_key = f"{base_key}/thumbnails/{local_path.name}"
        upload_manifest.append((local_path, s3_key, "image/jpeg", "max-age=86400"))

    # 2. Calculate total bytes for progress
    total_bytes = sum(p.stat().st_size for p, _, _, _ in upload_manifest)
    uploaded_bytes = 0

    # 3. Upload each file
    thumbnail_keys = []
    for local_path, s3_key, content_type, cache_control in upload_manifest:
        file_size = local_path.stat().st_size

        def _progress_cb(bytes_transferred: int) -> None:
            nonlocal uploaded_bytes
            uploaded_bytes += bytes_transferred
            if progress_callback:
                progress_callback(uploaded_bytes, total_bytes)

        upload_segment(
            local_path=local_path,
            bucket=bucket,
            key=s3_key,
            content_type=content_type,
            cache_control=cache_control,
            tags=tags,
            progress_callback=_progress_cb,
        )

        if "thumbnails/" in s3_key:
            thumbnail_keys.append(s3_key)

    # 4. Upload metadata.json
    metadata = {
        "job_id": job_id,
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "created_at": int(time.time()),
        "object_count": len(upload_manifest) + 1,
        "total_bytes": total_bytes,
        "renditions": [d.name for d in (output_dir / "hls").iterdir() if d.is_dir()],
        "thumbnails": [Path(k).name for k in thumbnail_keys],
        "retention_days": retention_days,
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
    return VodUploadResult(
        manifest_s3_uri=f"s3://{bucket}/{manifest_key}",
        manifest_s3_key=manifest_key,
        thumbnail_s3_keys=thumbnail_keys,
        total_bytes=total_bytes,
        object_count=len(upload_manifest) + 1,
        upload_duration_seconds=time.monotonic() - t0,
    )
```

### 3.6 Video Record Status Update

After upload completes, the transcode job record is updated with output information:

```python
def complete_job_with_outputs(
    *,
    job_id: str,
    worker_id: str,
    upload_result: VodUploadResult,
    playback_url: VodPlaybackUrl,
) -> None:
    """Atomically mark job as completed and store output metadata."""
    now = now_ts()
    T.transcode_jobs.update_item(
        Key={"job_id": job_id},
        UpdateExpression=(
            "SET #s = :completed, "
            "completed_at = :now, "
            "updated_at = :now, "
            "status_created_at = :sc, "
            "output_hls_manifest_uri = :hls_uri, "
            "output_s3_prefix = :prefix, "
            "output_total_bytes = :bytes, "
            "output_object_count = :count, "
            "output_upload_duration_seconds = :dur, "
            "output_thumbnail_keys = :thumbs, "
            "output_playback_url = :purl, "
            "output_playback_expires_at = :pexp, "
            "progress_pct = :hundred"
        ),
        ConditionExpression="#s = :running AND worker_id = :wid",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":completed": "completed",
            ":now": now,
            ":sc": f"completed#{now}",
            ":hls_uri": upload_result.manifest_s3_uri,
            ":prefix": upload_result.manifest_s3_key.rsplit("/hls/", 1)[0],
            ":bytes": upload_result.total_bytes,
            ":count": upload_result.object_count,
            ":dur": int(upload_result.upload_duration_seconds),
            ":thumbs": upload_result.thumbnail_s3_keys,
            ":purl": playback_url.playback_url,
            ":pexp": playback_url.expires_at,
            ":hundred": 100,
            ":running": "running",
            ":wid": worker_id,
        },
    )
```

### 3.7 Content-Type and Cache-Control Inference

```python
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
```

### 3.8 S3 Lifecycle Policy for VOD Assets

Following the pattern in `broadcast_archive.py:ensure_archive_lifecycle_policy()`:

```python
def ensure_vod_lifecycle_policy(*, s3_client, bucket: str, default_retention_days: int = 30) -> bool:
    """Set lifecycle rules for VOD output objects tagged with retention=vod."""
    rules = [
        {
            "ID": "vod-output-retention",
            "Status": "Enabled",
            "Filter": {"Tag": {"Key": "retention", "Value": "vod"}},
            "Expiration": {"Days": int(default_retention_days)},
        },
        {
            "ID": "vod-abort-incomplete-multipart",
            "Status": "Enabled",
            "Filter": {"Prefix": ""},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
        },
    ]
    s3_client.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={"Rules": rules},
    )
    return True
```

---

## 4. Implementation Plan

### 4.1 Files

<!-- NOTE: All files listed below ALREADY EXIST (with slightly different names than the spec proposed). -->

| File | Purpose | Status |
|------|---------|--------|
| `app/services/vod_s3_uploader.py` | Core upload logic: `upload_segment()` (line 96), `upload_transcode_outputs()` (line 142), `abort_incomplete_uploads()` (line 125), `ensure_vod_lifecycle_policy()` (line 292) | **Already exists** (not `vod_s3_upload.py`) |
| `app/services/vod_thumbnail_extractor.py` | Thumbnail extraction: `extract_thumbnails()` (line 25), `upload_thumbnails()` (line 98) | **Already exists** (not `vod_thumbnail.py`) |
| `app/services/vod_playback_url.py` | URL generation: `mint_vod_playback_url()` (line 40), `validate_vod_playback_token()` (line 65), `_mint_dev_url()` (line 118), `_mint_cloudfront_url()` (line 138), `_mint_presigned_url()` (line 171) | **Already exists** |
| `tests/test_vod_s3_upload.py` | Unit tests for upload logic |
| `tests/test_vod_thumbnail.py` | Unit tests for thumbnail extraction |
| `tests/test_vod_playback_url.py` | Unit tests for URL signing |

### 4.2 Modified Files

| File | Change |
|------|--------|
| `app/core/settings.py` | Add VOD-specific settings (see 4.3) |
| `app/core/dev_s3.py` / `app/main.py` | Add `vod-output` to `start_s3_mock()` bucket list |
| `app/services/transcode_worker.py` | **Already integrated**: calls upload after transcode at line ~165. |
| `app/services/transcode_job_store.py` | `complete_job_with_outputs()` **already exists** at line 181. |
| `scripts/local-ddb-init.py` | No changes (job table from VOD-003 is sufficient) |

### 4.3 Settings Additions

Add to `app/core/settings.py`:

```python
# VOD S3 output
vod_output_bucket: str = os.environ.get("VOD_OUTPUT_BUCKET", "vod-output")
vod_output_prefix: str = os.environ.get("VOD_OUTPUT_PREFIX", "tenants")
vod_output_retention_days: int = int(os.environ.get("VOD_OUTPUT_RETENTION_DAYS", "30"))
vod_upload_concurrency: int = int(os.environ.get("VOD_UPLOAD_CONCURRENCY", "4"))
vod_upload_multipart_threshold_mb: int = int(os.environ.get("VOD_UPLOAD_MULTIPART_THRESHOLD_MB", "8"))
vod_upload_multipart_chunksize_mb: int = int(os.environ.get("VOD_UPLOAD_MULTIPART_CHUNKSIZE_MB", "8"))

# VOD playback URLs
vod_playback_url_ttl_seconds: int = int(os.environ.get("VOD_PLAYBACK_URL_TTL_SECONDS", "3600"))
vod_playback_url_mode: str = os.environ.get("VOD_PLAYBACK_URL_MODE", "auto")  # auto | cloudfront | presigned | dev

# VOD thumbnails
vod_thumbnail_enabled: bool = os.environ.get("VOD_THUMBNAIL_ENABLED", "1") not in ("0", "false", "False")
vod_thumbnail_timestamps: str = os.environ.get("VOD_THUMBNAIL_TIMESTAMPS", "0,10,30")
vod_thumbnail_width: int = int(os.environ.get("VOD_THUMBNAIL_WIDTH", "640"))
vod_thumbnail_quality: int = int(os.environ.get("VOD_THUMBNAIL_QUALITY", "5"))
vod_sprite_sheet_enabled: bool = os.environ.get("VOD_SPRITE_SHEET_ENABLED", "0") not in ("0", "false", "False")
vod_sprite_sheet_interval_seconds: int = int(os.environ.get("VOD_SPRITE_SHEET_INTERVAL_SECONDS", "10"))
```

### 4.4 Integration into Transcode Worker

Update the `execute_transcode_job()` flow in `app/services/transcode_worker.py` (from VOD-003 design):

```python
async def execute_transcode_job(job: dict) -> None:
    job_id = job["job_id"]
    worker_id = f"{socket.gethostname()}:{os.getpid()}"

    if not claim_job(job_id, worker_id):
        return

    scratch_dir = Path(S.transcode_scratch_dir) / job_id
    scratch_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Download source from S3 to scratch
        source_path = await _download_source(job["source_uri"], scratch_dir)

        # 2. Transcode each rendition
        output_dir = scratch_dir / "output"
        # ... (existing rendition loop from VOD-003) ...

        # 3. NEW: Extract thumbnails
        thumbnail_dir = scratch_dir / "thumbnails"
        if S.vod_thumbnail_enabled:
            timestamps = [int(t) for t in S.vod_thumbnail_timestamps.split(",") if t.strip()]
            extract_thumbnails(
                source_path=source_path,
                output_dir=thumbnail_dir,
                timestamps_seconds=timestamps,
                width=S.vod_thumbnail_width,
                quality=S.vod_thumbnail_quality,
            )
            if S.vod_sprite_sheet_enabled:
                extract_sprite_sheet(
                    source_path=source_path,
                    output_path=thumbnail_dir / "sprite_timeline.jpg",
                    interval_seconds=S.vod_sprite_sheet_interval_seconds,
                )

        # 4. NEW: Upload all outputs to S3
        def _upload_progress(uploaded: int, total: int) -> None:
            # Map upload progress to 90-100% range (0-90% was transcode)
            pct = 90 + int((uploaded / max(1, total)) * 10)
            update_progress(job_id, worker_id, pct, "uploading", list(completed_renditions), None)

        upload_result = await upload_vod_outputs(
            job_id=job_id,
            tenant_id=job["tenant_id"],
            asset_id=job["asset_id"],
            output_dir=output_dir,
            thumbnail_dir=thumbnail_dir,
            retention_days=job.get("retention_days", S.vod_output_retention_days),
            progress_callback=_upload_progress,
        )

        # 5. NEW: Generate signed playback URL
        playback_url = mint_vod_playback_url(
            tenant_id=job["tenant_id"],
            asset_id=job["asset_id"],
        )

        # 6. NEW: Complete with full output metadata
        complete_job_with_outputs(
            job_id=job_id,
            worker_id=worker_id,
            upload_result=upload_result,
            playback_url=playback_url,
        )

    except NonRetryableError as e:
        fail_job(job_id, worker_id, e.code, str(e))
    except Exception as e:
        # Abort any incomplete multipart uploads on failure
        try:
            bucket = S.vod_output_bucket or "vod-output"
            prefix = f"{S.vod_output_prefix}/{job['tenant_id']}/assets/{job['asset_id']}"
            abort_incomplete_uploads(bucket, prefix)
        except Exception:
            logger.warning("Failed to abort incomplete multipart uploads", exc_info=True)
        _handle_retryable_failure(job_id, worker_id, job["attempt"], job["max_attempts"], str(e))
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)
```

### 4.5 Bucket Initialization in Dev Mode

Add `vod-output` to the bucket list in `app/main.py` where `start_s3_mock()` is called:

```python
from app.core.dev_s3 import start_s3_mock

# In startup event handler:
if S.dev_mode:
    buckets = [
        S.filemgr_bucket,
        S.broadcast_archive_bucket,
        S.vod_output_bucket or "vod-output",  # NEW
    ]
    start_s3_mock([b for b in buckets if b])
```

### 4.6 Lifecycle Policy Application

Called once at startup (similar to how `ensure_archive_lifecycle_policy` is used):

```python
# In startup event handler, after S3 mock is active:
if not S.dev_mode:
    from app.services.vod_s3_upload import ensure_vod_lifecycle_policy
    ensure_vod_lifecycle_policy(
        s3_client=_s3,
        bucket=S.vod_output_bucket or "vod-output",
        default_retention_days=S.vod_output_retention_days,
    )
```

---

## 5. Testing Strategy

### 5.1 Unit Tests: S3 Upload (`tests/test_vod_s3_upload.py`)

All tests use moto-mocked S3 (same pattern as `tests/conftest.py`). No external services required.

**Test cases:**

1. **`test_upload_segment_small_file`** - Upload a 1KB file via `upload_segment()`. Verify: object exists in S3, `ContentType` is correct, `CacheControl` header is set, S3 tags are applied.

2. **`test_upload_segment_triggers_multipart_for_large_file`** - Upload a 12MB file (above 8MB threshold). Verify: upload completes successfully, ETag contains `-` (multipart ETag indicator).

3. **`test_upload_segment_progress_callback_invoked`** - Upload a 1MB file with a mock progress callback. Verify: callback is invoked at least once with positive `bytes_transferred`.

4. **`test_upload_vod_outputs_creates_all_objects`** - Create a mock output directory with `hls/master.m3u8`, `hls/720p/index.m3u8`, `hls/720p/segment_000.ts`, and a thumbnail. Call `upload_vod_outputs()`. Verify: all objects exist in S3 at expected keys, `metadata.json` is created with correct contents.

5. **`test_upload_vod_outputs_correct_content_types`** - After upload, verify each object has the correct `ContentType`: `.m3u8` -> `application/vnd.apple.mpegurl`, `.ts` -> `video/mp2t`, `.jpg` -> `image/jpeg`.

6. **`test_upload_vod_outputs_master_playlist_cache_control`** - Verify `master.m3u8` has `max-age=5, stale-while-revalidate=10` while variant playlists have `max-age=31536000, immutable`.

7. **`test_abort_incomplete_uploads`** - Start a multipart upload (via low-level `create_multipart_upload`), call `abort_incomplete_uploads()`, verify: no multipart uploads remain (`list_multipart_uploads` returns empty).

8. **`test_upload_vod_outputs_empty_thumbnail_dir`** - Call with an empty thumbnail directory. Verify: upload succeeds, `thumbnail_s3_keys` is empty list, `metadata.json` has empty `thumbnails` array.

9. **`test_ensure_vod_lifecycle_policy`** - Call `ensure_vod_lifecycle_policy()`. Verify: `get_bucket_lifecycle_configuration()` returns rules with correct `Tag` filter and expiration days.

10. **`test_upload_respects_retention_days_in_tags`** - Upload with `retention_days=90`. Verify: S3 object tags include `retention_days=90`.

### 5.2 Unit Tests: Thumbnail Extraction (`tests/test_vod_thumbnail.py`)

Tests require `ffmpeg` on PATH. Skip gracefully if unavailable:

```python
import shutil
import pytest

pytestmark = pytest.mark.skipif(
    not shutil.which("ffmpeg"),
    reason="ffmpeg not available"
)
```

**Test cases:**

1. **`test_extract_thumbnails_produces_jpegs`** - Generate a 3-second test video with `ffmpeg -f lavfi -i testsrc`. Extract thumbnails at [0, 1, 2]. Verify: 3 JPEG files created, each >0 bytes, image dimensions match expected width.

2. **`test_extract_thumbnails_skips_timestamps_beyond_duration`** - Extract at [0, 100] from a 3-second video. Verify: only 1 thumbnail produced (for t=0), no error raised.

3. **`test_extract_thumbnails_custom_width`** - Extract with `width=320`. Verify: output JPEG width is 320px (use PIL or `ffprobe` to check).

4. **`test_extract_thumbnails_empty_on_invalid_input`** - Pass a non-video file (e.g., a text file). Verify: returns empty list, no exception raised.

5. **`test_extract_sprite_sheet_produces_tiled_image`** - Generate a 10-second test video. Extract sprite sheet with `interval_seconds=2`. Verify: output file exists, width = `tile_width * columns`, height = `tile_height * ceil(frames / columns)`.

6. **`test_extract_sprite_sheet_returns_none_on_failure`** - Pass invalid input. Verify: returns `None`, no exception raised.

### 5.3 Unit Tests: Playback URL Generation (`tests/test_vod_playback_url.py`)

**Test cases:**

1. **`test_mint_vod_dev_playback_url`** - With `S.dev_mode=True`, verify URL format is `http://localhost:8000/mock/s3/vod-output/tenants/<tenant>/assets/<asset>/hls/master.m3u8`.

2. **`test_mint_vod_cloudfront_playback_url`** - Set `broadcast_cloudfront_domain="d123.cloudfront.net"`. Verify: URL starts with `https://d123.cloudfront.net/`, contains `cf_token=` and `cf_expires=` params, `expires_at` is approximately `now + ttl`.

3. **`test_mint_vod_cloudfront_url_validates_with_existing_validator`** - Generate a signed URL, extract path/token/expires, call `validate_cloudfront_token()`. Verify: returns `True`.

4. **`test_mint_vod_cloudfront_url_expires_correctly`** - Generate with `ttl_seconds=60`. Verify `expires_at` is within [now+60, now+62] (allowing 2s test execution time).

5. **`test_mint_vod_presigned_playback_url`** - With no CloudFront domain set and `dev_mode=False`, verify: returns an S3 presigned URL containing `X-Amz-Signature` and `X-Amz-Expires`.

6. **`test_mint_vod_playback_url_auto_dispatch_dev`** - `dev_mode=True` -> mode is "dev".

7. **`test_mint_vod_playback_url_auto_dispatch_cloudfront`** - `dev_mode=False`, `cloudfront_domain` set -> mode is "cloudfront".

8. **`test_mint_vod_playback_url_auto_dispatch_presigned`** - `dev_mode=False`, `cloudfront_domain=""` -> mode is "presigned".

9. **`test_cloudfront_url_thumbnail_included`** - Verify `thumbnail_url` field is populated with a signed URL pointing to `thumbnails/poster_0s.jpg`.

10. **`test_url_path_normalization_prevents_traversal`** - Attempt to generate URL with `asset_id="../../../etc/passwd"`. Verify: raises `ValueError` from `_normalize_token_path`.

### 5.4 Integration Test: Full Upload Pipeline

Combines transcode output simulation with S3 upload and URL generation:

1. **`test_full_upload_pipeline_end_to_end`** - Create a realistic output directory structure (master.m3u8 + 2 renditions + segments + thumbnails). Run `upload_vod_outputs()` against moto S3. Then call `mint_vod_playback_url()`. Verify: all objects in S3, playback URL resolves to a valid manifest via `_s3.get_object()`.

2. **`test_complete_job_with_outputs_updates_ddb`** - Insert a job with `status=running`, call `complete_job_with_outputs()`, verify: DDB record has `status=completed`, all output fields populated, `progress_pct=100`.

3. **`test_upload_failure_aborts_multipart_and_retries`** - Mock `_s3.upload_file` to raise `ClientError` on the third file. Verify: `abort_incomplete_uploads()` is called, job transitions to `pending` (retry) not `completed`.

### 5.5 E2E Test (`frontend/e2e/vod-s3-upload.spec.ts`)

Lightweight E2E test exercising the upload outputs through the API:

1. **Submit a transcode job** via `POST /ui/transcode-jobs` with a short test asset (pre-seeded in moto S3 by `beforeAll`).

2. **Wait for completion** by polling `GET /ui/transcode-jobs/{id}` until `status=completed` (max 60s timeout).

3. **Verify output fields**: Response includes `output_hls_manifest_uri`, `output_playback_url`, `output_thumbnail_keys`.

4. **Fetch manifest via dev URL**: `GET /mock/s3/vod-output/tenants/<tenant>/assets/<asset>/hls/master.m3u8` returns 200 with `content-type: application/vnd.apple.mpegurl`.

5. **Fetch thumbnail via dev URL**: `GET /mock/s3/vod-output/tenants/<tenant>/assets/<asset>/thumbnails/poster_0s.jpg` returns 200 with `content-type: image/jpeg`.

6. **Verify metadata.json**: `GET /mock/s3/vod-output/tenants/<tenant>/assets/<asset>/metadata.json` returns valid JSON with expected fields.

### 5.6 Performance and Stress Tests (Manual/CI)

These are not part of the automated test suite but are defined for load testing:

1. **Large asset upload**: Transcode a 30-minute 1080p source (4 renditions). Measure total upload time and verify all ~2000 segments are uploaded correctly.

2. **Concurrent uploads**: Submit 4 transcode jobs simultaneously (at `max_concurrent_jobs=4`). Verify all 4 complete without S3 throttling errors (moto does not throttle, but the test validates code correctness under concurrency).

3. **Upload interruption recovery**: Kill the worker mid-upload (SIGKILL). Restart. Verify: incomplete multipart uploads are cleaned up on retry, job re-enters `pending` state and completes on second attempt.

---

## Appendix A: Configuration Reference

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `VOD_OUTPUT_BUCKET` | `vod-output` | S3 bucket for transcode outputs |
| `VOD_OUTPUT_PREFIX` | `tenants` | S3 key prefix (before tenant_id) |
| `VOD_OUTPUT_RETENTION_DAYS` | `30` | Default lifecycle expiration |
| `VOD_UPLOAD_CONCURRENCY` | `4` | Parallel part upload threads |
| `VOD_UPLOAD_MULTIPART_THRESHOLD_MB` | `8` | Switch to multipart above this size |
| `VOD_UPLOAD_MULTIPART_CHUNKSIZE_MB` | `8` | Size of each multipart part |
| `VOD_PLAYBACK_URL_TTL_SECONDS` | `3600` | Signed URL validity (1 hour) |
| `VOD_PLAYBACK_URL_MODE` | `auto` | URL generation strategy |
| `VOD_THUMBNAIL_ENABLED` | `1` | Enable thumbnail extraction |
| `VOD_THUMBNAIL_TIMESTAMPS` | `0,10,30` | Comma-separated seconds |
| `VOD_THUMBNAIL_WIDTH` | `640` | Thumbnail output width (px) |
| `VOD_THUMBNAIL_QUALITY` | `5` | JPEG quality (2=best, 31=worst) |
| `VOD_SPRITE_SHEET_ENABLED` | `0` | Enable sprite sheet generation |
| `VOD_SPRITE_SHEET_INTERVAL_SECONDS` | `10` | Seconds between sprite frames |

## Appendix B: S3 Object Inventory (Typical 30-min 1080p Asset)

For a 30-minute source transcoded to 4 renditions with 4-second segments:

| Category | Count | Total Size (approx) |
|----------|-------|-------------------|
| Master playlist | 1 | ~200 bytes |
| Variant playlists (4) | 4 | ~15KB each |
| 1080p segments | 450 | ~13.5GB |
| 720p segments | 450 | ~7.9GB |
| 540p segments | 450 | ~5.0GB |
| 360p segments | 450 | ~2.7GB |
| Thumbnails | 3-5 | ~150KB total |
| Sprite sheet | 0-1 | ~500KB |
| metadata.json | 1 | ~1KB |
| **Total** | **~1,810** | **~29.1GB** |

Upload time at 500 Mbps network: ~8 minutes. With 4-thread multipart: ~2 minutes per rendition, ~8 minutes total (bottleneck is largest rendition).

## Appendix C: Error Handling Matrix

| Error | Retryable? | Handling |
|-------|-----------|----------|
| `NoSuchBucket` | No | Fail immediately; misconfiguration |
| `AccessDenied` | No | Fail immediately; IAM misconfiguration |
| `SlowDown` (S3 throttle) | Yes | Exponential backoff (boto3 handles automatically) |
| `InternalError` (S3 500) | Yes | Retry via boto3 built-in retry |
| `RequestTimeout` | Yes | Retry individual part/file |
| `EntityTooLarge` (>5GB single PUT) | No | Should not occur with multipart; indicates bug |
| Network timeout | Yes | Retry file upload from scratch |
| Disk full (scratch space) | Yes | Clean scratch, retry job on next poll |
| `ConditionalCheckFailedException` | No | Another worker completed/cancelled; abandon |

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/services/vod_s3_uploader.py` | 96 | `upload_segment()` |
| `app/services/vod_s3_uploader.py` | 125 | `abort_incomplete_uploads()` |
| `app/services/vod_s3_uploader.py` | 142 | `upload_transcode_outputs()` |
| `app/services/vod_s3_uploader.py` | 292 | `ensure_vod_lifecycle_policy()` |
| `app/services/vod_thumbnail_extractor.py` | 25 | `extract_thumbnails()` |
| `app/services/vod_thumbnail_extractor.py` | 98 | `upload_thumbnails()` |
| `app/services/vod_playback_url.py` | 40 | `mint_vod_playback_url()` |
| `app/services/vod_playback_url.py` | 65 | `validate_vod_playback_token()` |
| `app/services/vod_playback_url.py` | 118 | `_mint_dev_url()` |
| `app/services/vod_playback_url.py` | 138 | `_mint_cloudfront_url()` |
| `app/services/vod_playback_url.py` | 171 | `_mint_presigned_url()` |
| `app/services/transcode_job_store.py` | 181 | `complete_job_with_outputs()` |
| `app/services/transcode_worker.py` | 165 | Upload progress callback integration |
| `app/core/aws_clients.py` | 114 | `s3_client()` factory |
| `app/core/settings.py` | 1094 | `vod_output_bucket` setting |
| `app/main.py` | 369 | `vod_output_bucket` in dev bucket list |
| `app/services/broadcast_playback.py` | -- | Reference pattern for local playback URLs |
| `app/services/broadcast_cloudfront.py` | -- | Reference pattern for CloudFront signed URLs |
