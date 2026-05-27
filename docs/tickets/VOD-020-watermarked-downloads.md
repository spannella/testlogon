# VOD-020: Watermarked Downloads

**Ticket**: VOD-020
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 10-12 days

---

## 1. Executive Summary

Watermarked downloads solve the piracy attribution problem for downloadable video content. VOD-012 introduced MP4 downloads and VOD-019 added tiered access (rental/purchase), but downloaded files contain no identifying information about who downloaded them. If a video is leaked or shared without authorization, the platform has no forensic mechanism to trace the file back to the user responsible. This gap undermines creator confidence in offering downloads and is the most frequently requested anti-piracy feature from professional content creators.

This design introduces invisible per-user watermarking that embeds a unique identifier (hashed user ID + download timestamp + CRC checksum) into each downloaded MP4 using FFmpeg's `drawtext` filter at near-zero opacity (0.02). The watermark is imperceptible during normal playback but recoverable by boosting contrast and applying OCR. Watermarked files are generated on-demand per user (not pre-computed), cached in S3 for 24 hours, and tracked via a dedicated `WatermarkJobs` DynamoDB table. An admin extraction tool recovers the watermark payload from any copy of the file.

The system reuses the existing FFmpeg infrastructure from VOD-004 (`ffmpeg_executor.py`) and VOD-015 (clipping). In dev mode, watermark jobs complete synchronously with a mock payload (no FFmpeg binary required). In production, jobs run asynchronously with a progress-polling frontend UX. Creators opt in per video via a `watermark_downloads` toggle, and the entire feature can be disabled via the `WATERMARK_DOWNLOADS_ENABLED` environment variable.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want downloaded copies of my video to contain invisible watermarks. | Toggle `watermark_downloads`; subsequent downloads embed user-specific watermark. |
| Creator | I want to control whether watermarking is enabled per video. | Per-video toggle in video edit settings. Default: disabled. |
| Creator | I want to know that watermarking does not degrade video quality. | Downloaded file plays identically to the non-watermarked version in any standard player. Side-by-side comparison shows no visible difference. |
| Viewer | I want to download a video without noticing the watermark. | Downloaded file plays identically in VLC, QuickTime, and browser players. |
| Viewer | I want my download to be ready quickly. | Short videos (<5 min): <10 seconds. Long videos: progress indicator with estimated time, cached for 24h. |
| Viewer | I want to re-download without waiting again. | Repeated downloads within 24 hours serve the cached watermarked file instantly (`cached: true`). |
| Admin | I want to identify who leaked a video from a pirated copy. | Run extraction tool on the file; outputs user ID hash + download timestamp. |
| Admin | I want to see watermark generation metrics. | Admin dashboard shows watermark jobs count, success rate, average duration. |
| Admin | I want to look up the actual user from a watermark hash. | Extraction tool returns the hash; admin can query DDB for the matching job record which contains the full `user_id`. |

### 2.2 Pain Points

1. **No piracy deterrence**: Downloaded MP4 files are byte-identical for all users. A leaked file cannot be attributed to any individual downloader.
2. **Creator hesitancy**: Professional creators who sell premium video content (courses, fitness programs, tutorials) report reluctance to enable downloads because of piracy risk.
3. **Legal gap**: Without forensic evidence linking a leaked file to a specific user, DMCA takedown requests lack the attribution needed for repeat-infringer policies.
4. **Revenue loss**: Unauthorized redistribution of downloadable content directly competes with legitimate access, reducing subscription and purchase revenue.

### 2.3 Competitive Analysis

| Platform | Approach |
|----------|----------|
| Netflix | Frame-level temporal watermarking (A/B variant encoding) for forensic tracking. Invisible to viewers. |
| Disney+ | Similar to Netflix; invisible watermarks survive re-encoding and screen recording. |
| Vimeo | Per-download watermarking available on Premium plans. Uses visible text overlay (configurable) or invisible metadata. |
| Patreon | No built-in watermarking. Creators must watermark manually before uploading. |

Phase 1 of this ticket uses the `drawtext` approach (fast, no special libraries), which is sufficient for casual piracy deterrence. Phase 2 documents a more robust temporal PTS-based watermarking technique that survives re-encoding.

### 2.4 Watermarking Techniques

**Technique 1: FFmpeg drawtext with near-zero opacity (Phase 1)**
- Overlay a text string (user ID + timestamp hash) using FFmpeg's `drawtext` filter at opacity 0.01-0.02.
- The text is invisible to the naked eye but recoverable by boosting contrast/gamma.
- Fast (adds ~10-20% to transcode time), no special libraries needed.
- Fragile: defeated by re-encoding at lower quality or cropping. Sufficient for casual piracy deterrence.

**Technique 2: Temporal metadata watermark (Phase 2, future ticket)**
- Embed a binary ID in the frame presentation timestamps (PTS) of the video stream.
- Imperceptible because PTS jitter of 1-2ms is below human perception threshold.
- Survives re-encoding but requires custom extraction tooling.

---

## 3. Current State Analysis

### 3.1 VOD-012: MP4 Download Generation (`app/services/vod_mp4_generator.py`) <!-- VERIFIED: file exists -->

The existing download system generates a single static MP4 per video:

```python
def generate_download_mp4(video) -> Dict[str, Any]:  # <!-- VERIFIED: vod_mp4_generator.py:17 -->
    prefix = S.vod_output_prefix or S.transcode_output_prefix or "tenants"  # <!-- VERIFIED: S.vod_output_prefix at settings.py:1049, S.transcode_output_prefix at settings.py:1042 -->
    tenant_id = video.owner_user_id
    video_id = video.id
    mp4_key = f"{prefix}/{tenant_id}/assets/{video_id}/download/{video_id}.mp4"
    return {
        "download_mp4_key": mp4_key,
        "download_mp4_size_bytes": 0,
        "download_mp4_status": "ready",
    }
```

The static MP4 is at a deterministic S3 path. The watermarked version will be at a user-specific path alongside it.

### 3.2 Download URL Minting

```python
def mint_video_download_url(video, ttl: int) -> Dict[str, Any]:  # <!-- VERIFIED: vod_mp4_generator.py:56 -->
    bucket = S.vod_output_bucket or S.transcode_output_bucket or "vod-output"
    key = video.download_mp4_key
    # Returns presigned URL with content-disposition: attachment
```

The watermarked download flow replaces this function when `watermark_downloads` is enabled on the video.

### 3.3 VOD-019: Download Tiers

VOD-019 adds rental and purchase access modes for downloads. The watermarking system operates downstream of access control -- it does not change who can download, only what they download (watermarked vs. plain MP4).

### 3.4 FFmpeg Infrastructure

- `app/services/ffmpeg_executor.py` (VOD-004): Async subprocess wrapper with timeout, cancellation, resource limits. <!-- VERIFIED: file exists -->
- `app/services/ffmpeg_manager.py` (MEDIA-002): Binary path resolution via `get_ffmpeg_path()` (line 116) and `get_ffmpeg_info()` (line 81), health checks. Uses `S.ffmpeg_binary_path` (settings.py:1074). <!-- VERIFIED: ffmpeg_manager.py exists; get_ffmpeg_path at line 116 -->
- Both are used by VOD-015 (clipping) and the ABR pipeline. The watermark job reuses this infrastructure.

### 3.5 Gaps

1. No per-user watermark generation pipeline
2. No `watermark_downloads` toggle on video metadata
3. No watermark job queue or caching mechanism
4. No watermark extraction tool for admin forensics
5. No "Preparing your download" progress UX in the frontend

---

## 4. Technical Architecture

### 4.1 System Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                       Frontend (React/Vite)                          │
│                                                                      │
│  VideoPlayerPage                                                     │
│    └── WatermarkedDownloadButton                                     │
│          ├── [idle] "Download" button                                │
│          ├── [processing] "Preparing download..." + spinner          │
│          └── [ready] Auto-trigger browser download via presigned URL │
│                                                                      │
│  VideoEditPage                                                       │
│    └── "Watermark downloads" Switch toggle                           │
└──────────────────┬───────────────────────────────────────────────────┘
                   │
          Vite proxy :3000 → :8000
                   │
┌──────────────────▼───────────────────────────────────────────────────┐
│                     FastAPI Backend (:8000)                           │
│                                                                      │
│  POST /ui/videos/{id}/download/watermarked                           │
│    ├── Check download access (VOD-012 + VOD-019)                     │
│    ├── Check cache (GSI1: WM#{video_id}#{user_id})                   │
│    │     └── Cache hit + completed → return presigned URL             │
│    │     └── Cache hit + running → return job_id for polling          │
│    └── Cache miss → create_watermark_job()                           │
│          ├── [dev mode] complete_watermark_job_mock() → instant URL   │
│          └── [prod] return job_id → background FFmpeg processing      │
│                                                                      │
│  Background: execute_watermark()                                     │
│    ├── Download source MP4 from S3 to temp file                      │
│    ├── FFmpeg drawtext filter (opacity 0.02, 8px, bottom-right)      │
│    ├── Upload watermarked MP4 to S3 (user-specific path)             │
│    └── Update WatermarkJobs record (status=completed)                │
│                                                                      │
│  GET /ui/videos/{id}/download/watermarked/status                     │
│    └── Query latest job → return status + download_url if ready      │
│                                                                      │
│  POST /internal/watermark/extract                                    │
│    ├── FFmpeg crop + contrast boost → extract frame PNG               │
│    └── OCR (pytesseract) → extract WM:v1:... payload string          │
│                                                                      │
│  ┌────────────────────────────────────────────┐                      │
│  │ DynamoDB: WatermarkJobs                     │                      │
│  │   PK: job_id                                │                      │
│  │   GSI1: WM#{video_id}#{user_id} → created_at│                     │
│  │   TTL: ttl_epoch (24h auto-cleanup)         │                      │
│  └────────────────────────────────────────────┘                      │
│                                                                      │
│  ┌────────────────────────────────────────────┐                      │
│  │ S3: Watermarked MP4 storage                 │                      │
│  │   Key: tenants/watermarked/{vid}/{uid}/{jid}.mp4                  │
│  │   Lifecycle: 24h expiry (S3 lifecycle rule)  │                     │
│  └────────────────────────────────────────────┘                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.2 Data Flow

1. **Viewer clicks Download**: Frontend calls `POST /ui/videos/{id}/download/watermarked`.
2. **Access check**: Backend verifies download access (VOD-012 `allow_download` + VOD-019 tier check).
3. **Cache lookup**: Query GSI1 with `WM#{video_id}#{user_id}` to find recent completed job.
4. **Cache hit**: Return presigned S3 URL for the cached watermarked file.
5. **Cache miss**: Create a new `WatermarkJobs` record with `status=queued`.
6. **Dev mode**: Process synchronously (mock watermark, copy source file to output path).
7. **Prod mode**: Return `{ status: "processing", job_id }`. Frontend polls `GET /status`.
8. **Background job**: Download source MP4, run FFmpeg `drawtext`, upload result to S3, mark job `completed`.
9. **Poll response**: Once completed, return `{ status: "ready", download_url }`.
10. **Browser download**: Frontend auto-triggers `window.location.href = download_url`.

### 4.3 Component Interactions

- `watermark_generator.py` handles FFmpeg execution and payload encoding/decoding. It imports `get_ffmpeg_path()` from `ffmpeg_manager.py` and uses the async subprocess pattern from `ffmpeg_executor.py`.
- `watermark.py` (router) handles HTTP endpoints and delegates to the generator service.
- The `video_listing.py` router adds the `PATCH /{id}/watermark` toggle endpoint alongside existing video management endpoints.
- The `vod_mp4_generator.py` `mint_video_download_url` function is modified to check `video.watermark_downloads` and redirect to the watermark flow when enabled.

---

## 5. Data Model Deep Dive

### 5.1 Video Metadata Fields

Add to `VideoMetadataModel` in `app/models_video.py` (line 35-141): <!-- VERIFIED: VideoMetadataModel exists with download fields at lines 103-108 -->

| Field | Type | Description |
|-------|------|-------------|
| `watermark_downloads` | Boolean | `false` by default; when `true`, downloads are watermarked |
<!-- NOTE: VideoMetadataModel already has download-related fields: allow_download (line 104), download_mp4_key (line 105), download_mp4_size_bytes (line 106), download_mp4_status (line 107), download_count (line 108). The new watermark_downloads field fits naturally alongside these. -->

### 5.2 WatermarkJobs DynamoDB Table

| Field | Type | Description |
|-------|------|-------------|
| `job_id` | S (PK) | `wj_<uuid4_hex>` |
| `video_id` | S | Source video ID |
| `user_id` | S | Downloader's user sub |
| `status` | S | `"queued"`, `"running"`, `"completed"`, `"failed"` |
| `source_mp4_key` | S | S3 key of the base MP4 (from VOD-012) |
| `output_mp4_key` | S | S3 key of the watermarked MP4 |
| `output_size_bytes` | N | File size after watermarking |
| `watermark_payload` | S | Encoded payload embedded in the video |
| `created_at` | N | Unix timestamp |
| `completed_at` | N (optional) | When the job finished |
| `duration_ms` | N (optional) | FFmpeg processing time in milliseconds |
| `ttl_epoch` | N | `created_at + 86400` (DDB TTL, cleanup after 24h) |
| `error_message` | S (optional) | Error detail on failure |
| `GSI1PK` | S | `WM#{video_id}#{user_id}` |
| `GSI1SK` | N | `created_at` |

### 5.3 Table Definition for local-ddb-init.py

```python
TableDef(
    _resolve_table_name(S.watermark_jobs_table_name, "watermark_jobs"),
    "job_id",
    gsi=[
        {"index_name": "GSI1", "partition_key": "GSI1PK", "sort_key": "GSI1SK"},
    ],
    attr_types={"GSI1SK": "N"},
),
```

**Critical note**: The `GSI1SK` is `created_at` which is a number (Unix timestamp). It must be declared in `attr_types={"GSI1SK": "N"}` or DynamoDB will treat it as a string, causing `ValidationException` when queried with an integer value (per the CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha).

### 5.4 Example DynamoDB Items

**Queued watermark job:**
```json
{
  "job_id": "wj_a1b2c3d4e5f6789012345678abcdef01",
  "video_id": "vid_tutorial_101",
  "user_id": "alice-sub-001",
  "status": "queued",
  "source_mp4_key": "tenants/alice-sub-001/assets/vid_tutorial_101/download/vid_tutorial_101.mp4",
  "output_mp4_key": "tenants/watermarked/vid_tutorial_101/alice-sub-001/wj_a1b2c3d4e5f6789012345678abcdef01.mp4",
  "watermark_payload": "WM:v1:a1b2c3d4e5f6g7h8:6839F400:3A7B",
  "created_at": 1748361600,
  "ttl_epoch": 1748448000,
  "GSI1PK": "WM#vid_tutorial_101#alice-sub-001",
  "GSI1SK": 1748361600
}
```

**Completed watermark job:**
```json
{
  "job_id": "wj_a1b2c3d4e5f6789012345678abcdef01",
  "video_id": "vid_tutorial_101",
  "user_id": "alice-sub-001",
  "status": "completed",
  "source_mp4_key": "tenants/alice-sub-001/assets/vid_tutorial_101/download/vid_tutorial_101.mp4",
  "output_mp4_key": "tenants/watermarked/vid_tutorial_101/alice-sub-001/wj_a1b2c3d4e5f6789012345678abcdef01.mp4",
  "output_size_bytes": 15728640,
  "watermark_payload": "WM:v1:a1b2c3d4e5f6g7h8:6839F400:3A7B",
  "created_at": 1748361600,
  "completed_at": 1748361615,
  "duration_ms": 14800,
  "ttl_epoch": 1748448000,
  "GSI1PK": "WM#vid_tutorial_101#alice-sub-001",
  "GSI1SK": 1748361600
}
```

### 5.5 Access Patterns Table

| Access Pattern | Table | Key Condition | Notes |
|----------------|-------|---------------|-------|
| Get watermark job by ID | `watermark_jobs` | PK = `job_id` | Single-item get for status polling |
| Find cached watermark for video+user | `watermark_jobs` GSI1 | `GSI1PK = WM#{video_id}#{user_id}`, `ScanIndexForward=False`, `Limit=1` | Most recent job; check `status=completed` and `created_at > now - 86400` |
| List all watermark jobs for a video (admin) | Scan with FilterExpression | `video_id = :vid` | Infrequent admin forensic query |
| Find job by watermark payload (admin) | Scan with FilterExpression | `watermark_payload = :payload` | After extraction, lookup who downloaded |

### 5.6 Watermark Payload Format

The watermark payload is a compact string encoding:

```
WM:v1:{user_id_hash}:{timestamp_hex}:{checksum}
```

- `user_id_hash`: First 16 chars of SHA-256 of the user sub (not the raw sub, for privacy)
- `timestamp_hex`: Download timestamp as 8-char hex (uppercase)
- `checksum`: CRC-16 of the above fields for validation

Example: `WM:v1:a1b2c3d4e5f6g7h8:6839F400:3A7B`

The payload is kept under 50 characters to fit in a small region of the video frame with a legible font size.

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/videos/{video_id}/download/watermarked` | `require_ui_session` | Request a watermarked download |
| GET | `/ui/videos/{video_id}/download/watermarked/status` | `require_ui_session` | Poll watermark job status |
| PATCH | `/ui/videos/{video_id}/watermark` | `require_ui_session` | Toggle `watermark_downloads` (owner only) |
| POST | `/internal/watermark/extract` | Internal API | Extract watermark from uploaded file (admin) |

### 6.2 Request Watermarked Download (POST)

**Request**: No body required. The video ID and user are derived from the path and session.

**Response (instant cache hit, 200):**
```json
{
  "status": "ready",
  "download_url": "https://s3.amazonaws.com/vod-output/tenants/watermarked/vid_101/alice/wj_abc.mp4?X-Amz-...",
  "cached": true,
  "job_id": "wj_abc123def456"
}
```

**Response (job in progress, 200):**
```json
{
  "status": "processing",
  "job_id": "wj_abc123def456"
}
```

**Response (dev mode instant, 200):**
```json
{
  "status": "ready",
  "download_url": "/mock/s3/vod-output/tenants/watermarked/vid_101/alice/wj_abc.mp4",
  "cached": false,
  "job_id": "wj_abc123def456"
}
```

**Error responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 403 | Downloads not enabled on video | `{ "detail": "downloads not enabled for this video" }` |
| 409 | Download MP4 not yet generated (VOD-012 still processing) | `{ "detail": "download MP4 not yet generated" }` |
| 429 | Too many concurrent watermark jobs for this user | `{ "detail": "too many concurrent watermark requests" }` |

### 6.3 Poll Job Status (GET)

**Response (processing, 200):**
```json
{
  "status": "processing",
  "job_id": "wj_abc123def456",
  "created_at": 1748361600
}
```

**Response (completed, 200):**
```json
{
  "status": "ready",
  "download_url": "https://s3.amazonaws.com/...",
  "job_id": "wj_abc123def456",
  "output_size_bytes": 15728640
}
```

**Response (failed, 200):**
```json
{
  "status": "failed",
  "job_id": "wj_abc123def456",
  "error": "FFmpeg exit code 1: insufficient disk space"
}
```

### 6.4 Toggle Watermark Setting (PATCH)

**Request:**
```json
{
  "watermark_downloads": true
}
```

**Response (200):**
```json
{
  "ok": true,
  "watermark_downloads": true
}
```

**Error responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 403 | Non-owner | `{ "detail": "forbidden" }` |
| 404 | Video not found | `{ "detail": "Video not found" }` |

### 6.5 Extract Watermark (POST /internal/watermark/extract)

**Request**: Multipart form upload with the video file.

**Response (found, 200):**
```json
{
  "found": true,
  "payload": "WM:v1:a1b2c3d4e5f6g7h8:6839F400:3A7B",
  "decoded": {
    "version": "v1",
    "user_id_hash": "a1b2c3d4e5f6g7h8",
    "download_timestamp": 1748361216,
    "download_datetime": "2025-05-27T12:00:16+00:00"
  }
}
```

**Response (not found, 200):**
```json
{
  "found": false,
  "payload": null,
  "decoded": null
}
```

### 6.6 Rate Limits

- Watermarked download requests: Max 5 concurrent jobs per user. Additional requests return 429.
- Poll endpoint: No special rate limit (standard per-user rate limiting applies).
- Extract endpoint: Internal only (not exposed via public proxy); rate limited to 10 requests/minute per admin.

---

## 7. Backend Implementation

### 7.1 Watermarked Download Request

```python
@router.post("/{video_id}/download/watermarked")
def request_watermarked_download(
    video_id: str,
    ctx=Depends(require_ui_session),
):
    user_id = ctx["user_sub"]
    video = get_video(video_id)

    if not video.allow_download:
        raise HTTPException(status_code=403, detail="downloads not enabled for this video")
    if video.download_mp4_status != "ready":
        raise HTTPException(status_code=409, detail="download MP4 not yet generated")

    # Check for cached watermarked version (< 24h old)
    cached = _find_cached_watermark(video_id, user_id)
    if cached and cached["status"] == "completed":
        url = mint_watermarked_download_url(cached["output_mp4_key"], ttl=3600)
        return {"status": "ready", "download_url": url, "cached": True, "job_id": cached["job_id"]}

    if cached and cached["status"] in ("queued", "running"):
        return {"status": "processing", "job_id": cached["job_id"]}

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
        return {"status": "ready", "download_url": url, "cached": False, "job_id": job["job_id"]}

    return {"status": "processing", "job_id": job["job_id"]}
```

### 7.2 Watermark Job Creation

```python
def create_watermark_job(video_id: str, user_id: str, source_mp4_key: str) -> Dict[str, Any]:
    job_id = f"wj_{uuid.uuid4().hex}"
    now = now_ts()
    payload = _build_watermark_payload(user_id, now)

    prefix = S.vod_output_prefix or "tenants"
    output_key = f"{prefix}/watermarked/{video_id}/{user_id}/{job_id}.mp4"

    item = {
        "job_id": job_id,
        "video_id": video_id,
        "user_id": user_id,
        "status": "queued",
        "source_mp4_key": source_mp4_key,
        "output_mp4_key": output_key,
        "watermark_payload": payload,
        "created_at": now,
        "ttl_epoch": now + 86400,
        "GSI1PK": f"WM#{video_id}#{user_id}",
        "GSI1SK": now,
    }
    T.watermark_jobs.put_item(Item=item)
    return item
```

### 7.3 FFmpeg Watermark Execution

```python
async def execute_watermark(
    source_path: Path,
    output_path: Path,
    payload: str,
    timeout_seconds: int = 600,
) -> WatermarkResult:
    """Embed invisible text watermark using FFmpeg drawtext filter."""

    ffmpeg_path = get_ffmpeg_path()

    drawtext_filter = (
        f"drawtext=text='{payload}'"
        f":fontsize=8"
        f":fontcolor=white@0.02"
        f":x=w-tw-10"
        f":y=h-th-10"
        f":font=monospace"
    )

    cmd = [
        ffmpeg_path,
        "-hide_banner", "-loglevel", "warning", "-y",
        "-i", str(source_path),
        "-vf", drawtext_filter,
        "-c:v", "libx264", "-preset", "fast", "-crf", "18",
        "-c:a", "copy",
        "-movflags", "+faststart",
        str(output_path),
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_build_restricted_env(),
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise WatermarkTimeoutError(f"FFmpeg timed out after {timeout_seconds}s")

    if proc.returncode != 0:
        raise WatermarkError(f"FFmpeg exit code {proc.returncode}: {stderr.decode()[-500:]}")

    output_size = output_path.stat().st_size
    return WatermarkResult(output_path=output_path, output_size_bytes=output_size, payload=payload)
```

### 7.4 Watermark Extraction (Admin Tool)

```python
async def extract_watermark(file_path: Path) -> Optional[str]:
    """Extract watermark from a video file by boosting contrast."""
    ffmpeg_path = get_ffmpeg_path()

    frame_path = file_path.parent / "extract_frame.png"
    cmd = [
        ffmpeg_path,
        "-hide_banner", "-loglevel", "warning", "-y",
        "-i", str(file_path),
        "-vf", "crop=400:100:iw-410:ih-110,eq=contrast=50:brightness=0.5",
        "-vframes", "1",
        str(frame_path),
    ]

    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    await proc.communicate()

    if not frame_path.exists():
        return None

    if S.dev_mode:
        return _mock_extract_payload(frame_path)

    try:
        import pytesseract
        from PIL import Image
        img = Image.open(frame_path)
        text = pytesseract.image_to_string(img, config="--psm 7")
        match = re.search(r"WM:v1:[a-f0-9]{16}:[a-f0-9A-F]{8}:[a-f0-9A-F]{4}", text)
        return match.group(0) if match else None
    except Exception:
        logger.warning("Watermark extraction failed", exc_info=True)
        return None
    finally:
        frame_path.unlink(missing_ok=True)
```

### 7.5 Payload Encode/Decode

```python
import binascii
import hashlib
import re
from datetime import datetime, timezone

def _build_watermark_payload(user_id: str, timestamp: int) -> str:
    user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    ts_hex = format(timestamp, "08X")
    check_input = f"WM:v1:{user_hash}:{ts_hex}"
    checksum = format(binascii.crc_hqx(check_input.encode(), 0), "04X")
    return f"{check_input}:{checksum}"

def decode_watermark_payload(payload: str) -> Optional[Dict[str, Any]]:
    match = re.match(r"^WM:v1:([a-f0-9]{16}):([a-fA-F0-9]{8}):([a-fA-F0-9]{4})$", payload)
    if not match:
        return None
    user_hash, ts_hex, checksum = match.group(1), match.group(2), match.group(3)
    check_input = f"WM:v1:{user_hash}:{ts_hex}"
    expected_crc = format(binascii.crc_hqx(check_input.encode(), 0), "04X")
    if checksum.upper() != expected_crc:
        return None
    timestamp = int(ts_hex, 16)
    return {
        "version": "v1",
        "user_id_hash": user_hash,
        "download_timestamp": timestamp,
        "download_datetime": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
    }
```

---

## 8. Frontend Component Design

### 8.1 Component Tree

```
VideoPlayerPage
  ├── VideoPlayer (existing)
  ├── VideoDetails (existing)
  └── [video.watermark_downloads ? WatermarkedDownloadButton : DownloadButton]
        ├── [idle] Button: "Download" + Download icon
        ├── [processing] Button: "Preparing download..." + Loader2 spinner (disabled)
        └── [ready] Auto-triggers browser download

VideoEditPage
  └── Settings section
        └── Switch: "Watermark downloads"
              └── Label: "Embed invisible watermarks in downloaded copies for piracy tracking"
```

### 8.2 New Files

| File | Purpose |
|------|---------|
| `frontend/src/pages/videos/WatermarkedDownloadButton.tsx` | Download button with progress/polling UI |
| `frontend/src/api/endpoints/watermark.ts` | API client for watermark endpoints |
| `frontend/e2e/watermarked-downloads.spec.ts` | E2E tests |

### 8.3 WatermarkedDownloadButton Component

```tsx
function WatermarkedDownloadButton({ videoId }: { videoId: string }) {
  const [status, setStatus] = useState<"idle" | "processing" | "ready">("idle");
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);

  const requestMutation = useMutation({
    mutationFn: () => requestWatermarkedDownload(videoId),
    onSuccess: (data) => {
      if (data.status === "ready") {
        setDownloadUrl(data.download_url);
        setStatus("ready");
        window.location.href = data.download_url;
      } else {
        setStatus("processing");
        startPolling(data.job_id);
      }
    },
  });

  const startPolling = (jobId: string) => {
    const interval = setInterval(async () => {
      const result = await pollWatermarkStatus(videoId);
      if (result.status === "ready") {
        clearInterval(interval);
        setDownloadUrl(result.download_url);
        setStatus("ready");
        window.location.href = result.download_url;
      } else if (result.status === "failed") {
        clearInterval(interval);
        setStatus("idle");
        toast.error("Download preparation failed. Please try again.");
      }
    }, 2000);
  };

  return (
    <Button
      onClick={() => requestMutation.mutate()}
      disabled={status === "processing" || requestMutation.isPending}
      className="gap-2"
    >
      {status === "processing" ? (
        <>
          <Loader2 className="h-4 w-4 animate-spin" />
          Preparing download...
        </>
      ) : (
        <>
          <Download className="h-4 w-4" />
          Download
        </>
      )}
    </Button>
  );
}
```

### 8.4 State Management

- No new Zustand store. The download state is local to `WatermarkedDownloadButton` (ephemeral, per-button-instance).
- The polling interval is cleared on component unmount via a `useEffect` cleanup.
- The video edit page toggle uses `useMutation` to call `PATCH /ui/videos/{id}/watermark` and invalidates the `["video", videoId]` query key on success.

### 8.5 React Query Hooks

```typescript
// frontend/src/api/endpoints/watermark.ts

export async function requestWatermarkedDownload(videoId: string) {
  return client.post(`/ui/videos/${videoId}/download/watermarked`).then(r => r.data);
}

export async function pollWatermarkStatus(videoId: string) {
  return client.get(`/ui/videos/${videoId}/download/watermarked/status`).then(r => r.data);
}

export function useToggleWatermark(videoId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (enabled: boolean) =>
      client.patch(`/ui/videos/${videoId}/watermark`, { watermark_downloads: enabled }).then(r => r.data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["video", videoId] }),
  });
}
```

---

## 9. Security & Privacy Considerations

### 9.1 Authentication

All watermark endpoints require `require_ui_session`. The extraction endpoint is internal-only (`/internal/watermark/extract`) and should not be exposed through the public proxy. In production, internal endpoints are restricted to admin VPN or service mesh.

### 9.2 Privacy

- The watermark payload contains a **hash** of the user sub, not the raw user sub. This prevents casual identification if someone extracts the watermark text.
- The admin can reverse the hash by querying the `WatermarkJobs` table for the matching `watermark_payload`, which contains the full `user_id`.
- Watermarked files in S3 use user-specific paths. Users cannot access each other's watermarked files because presigned URLs are scoped to their own path.

### 9.3 Input Validation

- The watermark toggle only accepts boolean values.
- The extraction endpoint accepts file uploads; file size should be limited (e.g., 10GB max) to prevent denial-of-service via large uploads.
- FFmpeg commands are constructed with parameterized values (no shell injection risk via `create_subprocess_exec`).

### 9.4 Abuse Prevention

- **Concurrent job limit**: Max 5 concurrent watermark jobs per user prevents resource exhaustion.
- **TTL cleanup**: Jobs auto-expire after 24 hours, preventing indefinite storage growth.
- **FFmpeg timeout**: 600-second timeout kills runaway processes.
- **Restricted env**: FFmpeg runs in a restricted environment (`_build_restricted_env()`) with no network access and limited file system visibility.

---

## 10. Performance & Scalability

### 10.1 FFmpeg Processing Times

| Video Duration | Resolution | Estimated Watermark Time | Notes |
|----------------|-----------|-------------------------|-------|
| <1 min | 1080p | 2-5 seconds | Near-instant for short clips |
| 5 min | 1080p | 10-20 seconds | Acceptable for single-click download |
| 30 min | 1080p | 60-120 seconds | Requires progress UI |
| 60 min | 4K | 300-600 seconds | Near timeout; consider raising limit |

### 10.2 Query Costs

- **Cache lookup**: 1 DDB query on GSI1 (single partition, `Limit=1`, `ScanIndexForward=False`). Cost: 0.5 RCU (eventually consistent).
- **Job creation**: 1 DDB `put_item`. Cost: depends on item size (~200 bytes = 1 WCU).
- **Status poll**: 1 DDB `get_item` by `job_id`. Cost: 0.5 RCU.

### 10.3 S3 Storage

- Each watermarked file is roughly the same size as the source MP4 (CRF 18 produces near-identical quality).
- With 24-hour TTL and S3 lifecycle rules, storage is bounded to `active_users_per_day * avg_video_size`.
- Estimated: 1,000 daily downloads of 100MB average = 100GB of watermarked cache. At S3 Standard pricing (~$0.023/GB/month), this is ~$2.30/month.

### 10.4 Caching Strategy

- **24-hour S3 cache**: Once a user's watermarked file is generated, subsequent download requests within 24 hours return the cached file instantly (no FFmpeg re-processing).
- **DDB TTL auto-cleanup**: Job records are automatically deleted by DynamoDB TTL after 24 hours, matching the S3 lifecycle.
- **Cache hit rate**: Expected >80% if users frequently re-download the same video (e.g., downloading on multiple devices).

### 10.5 Known Bottlenecks

- **Concurrent FFmpeg processes**: Each watermark job spawns an FFmpeg process that consumes 1-2 CPU cores. The `WATERMARK_MAX_CONCURRENT_JOBS` setting (default 5) limits resource usage per worker.
- **Disk I/O**: FFmpeg reads the full source MP4 and writes the full output. For large videos (>1GB), this can saturate disk I/O on EBS volumes. Consider using local NVMe instance storage for temp files.
- **Single-worker limitation**: In dev mode (`--workers 1`), all watermark jobs are serialized. In production, multiple workers can process jobs in parallel, but S3 mock state is per-process (moto limitation).

---

## 11. Migration & Rollback Plan

### 11.1 Feature Flag

`WATERMARK_DOWNLOADS_ENABLED` (default `true`) is the master kill switch. When `false`:
- The `POST /download/watermarked` endpoint returns the plain (non-watermarked) download URL instead.
- The `PATCH /watermark` toggle still works (creators can configure it, but it has no effect on downloads).
- No FFmpeg jobs are created.

### 11.2 Incremental Deployment

| Day | Task | Viewer Impact |
|-----|------|---------------|
| 1 | Deploy backend with `WatermarkJobs` table, service, and router. Feature flag ON. | None (no video has `watermark_downloads=true` yet). |
| 2 | Deploy frontend with `WatermarkedDownloadButton`. | None (toggle not yet visible on video edit). |
| 3 | Enable video edit toggle. Creators can opt in. | First watermarked downloads. Monitor FFmpeg latency. |
| 5 | Monitor metrics for 48h. Adjust CRF, timeout, and concurrency. | Stable. |

### 11.3 Rollback Steps

1. Set `WATERMARK_DOWNLOADS_ENABLED=false`.
2. Restart backend. All downloads revert to plain MP4.
3. Existing watermarked files in S3 will auto-expire after 24 hours.
4. DDB job records will auto-expire via TTL.

### 11.4 DynamoDB Table Removal

If the feature is permanently removed:
1. Delete the `watermark_jobs` table from DDB (no data dependencies).
2. Remove `watermark_downloads` field from `VideoMetadataModel`.
3. Remove the `watermark` router from `main.py`.

---

## 12. Testing Strategy

### 12.1 Unit Tests (pytest)

| Test | Module | Description |
|------|--------|-------------|
| `test_build_watermark_payload` | `watermark_generator.py` | Payload format is `WM:v1:{hash}:{hex}:{crc}` |
| `test_decode_watermark_payload_valid` | `watermark_generator.py` | Decode returns correct components |
| `test_decode_watermark_payload_invalid` | `watermark_generator.py` | Garbled string returns None |
| `test_decode_watermark_payload_bad_checksum` | `watermark_generator.py` | Tampered checksum returns None |
| `test_create_watermark_job` | `watermark_generator.py` | Job created in DDB with correct fields and GSI keys |
| `test_find_cached_watermark_hit` | `watermark_generator.py` | GSI1 query returns completed job within 24h |
| `test_find_cached_watermark_expired` | `watermark_generator.py` | Job older than 24h is not returned |
| `test_complete_watermark_job_mock` | `watermark_generator.py` | Dev mode mock updates status to completed |
| `test_concurrent_job_limit` | `watermark.py` | 6th concurrent request returns 429 |

### 12.2 Integration Tests

| Test | Description |
|------|-------------|
| `test_watermarked_download_e2e_dev_mode` | POST download in dev mode returns instant `ready` with URL |
| `test_watermarked_download_cached` | Second POST within 24h returns `cached: true` |
| `test_download_denied_no_access` | Video with `allow_download=false` returns 403 |
| `test_toggle_watermark_owner` | Owner can toggle `watermark_downloads` |
| `test_toggle_watermark_non_owner` | Non-owner gets 403 |

### 12.3 E2E Test Matrix

**File**: `frontend/e2e/watermarked-downloads.spec.ts`

**Section 1: Watermark Settings API (4 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Enable watermark downloads on video | PATCH watermark; 200; GET video shows `watermark_downloads: true` |
| 2 | Disable watermark downloads | PATCH with `false`; 200; GET shows `false` |
| 3 | Non-owner cannot toggle watermark | PATCH as different user; 403 |
| 4 | Watermark setting persists across video detail fetches | Enable; fetch; confirm field present |

**Section 2: Watermarked Download API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 5 | Request watermarked download (dev mode: instant) | POST download; 200; `status: "ready"`; `download_url` present |
| 6 | Cached download returns instantly | Second POST within 24h; `cached: true` |
| 7 | Download URL is valid presigned URL | Follow URL; 200 response (or mock S3 200 in dev) |
| 8 | Download denied when `allow_download` is false | Disable download; POST; 403 |
| 9 | Non-watermarked download when `watermark_downloads` is false | Disable watermark; download uses plain MP4 endpoint |

**Section 3: Watermark Extraction API (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 10 | Extract watermark from generated file (mock) | POST extract with job output; returns `watermark_payload` |
| 11 | Decode watermark payload | Payload contains valid `user_id_hash`, `download_timestamp`, `checksum` |
| 12 | Invalid payload returns null | Decode garbled string; returns null |

**Section 4: Download UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | Download button visible for video with downloads enabled | Navigate to video page; "Download" button visible |
| 14 | Watermark toggle visible on video edit page | Owner navigates to edit; "Watermark downloads" switch visible |
| 15 | Clicking download shows preparing state | Click download; "Preparing download..." text visible briefly |

---

## 13. Monitoring & Alerting

### 13.1 Metrics to Track

| Metric | Type | Description |
|--------|------|-------------|
| `watermark_job_created_total` | Counter | Total watermark jobs created, labeled by `video_id` (top 20) |
| `watermark_job_completed_total` | Counter | Completed jobs, labeled by `cached` (true/false) |
| `watermark_job_failed_total` | Counter | Failed jobs, labeled by `reason` (timeout, ffmpeg_error, s3_error) |
| `watermark_job_duration_seconds` | Histogram | FFmpeg processing time |
| `watermark_cache_hit_total` | Counter | Cache hits (24h window) |
| `watermark_active_jobs` | Gauge | Currently running FFmpeg watermark processes |
| `watermark_output_size_bytes` | Histogram | Output file sizes |

### 13.2 Dashboard Queries

- **Watermark success rate**: `rate(watermark_job_completed_total[5m]) / rate(watermark_job_created_total[5m])` -- should be >98%.
- **Average processing time**: `histogram_quantile(0.50, watermark_job_duration_seconds)` -- P50 should be <30s for most videos.
- **Cache efficiency**: `rate(watermark_cache_hit_total[1h]) / rate(watermark_job_created_total[1h])` -- higher is better.

### 13.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| Watermark failures elevated | `rate(watermark_job_failed_total[5m]) > 5` | Warning |
| FFmpeg timeout spike | `rate(watermark_job_failed_total{reason="timeout"}[5m]) > 2` | Warning |
| Active jobs at capacity | `watermark_active_jobs >= WATERMARK_MAX_CONCURRENT_JOBS` for >5 min | Info |
| Disk space low (temp dir) | Available space in temp directory < 10GB | Critical |

---

## 14. Open Questions & Risks

### 14.1 Unresolved Decisions

1. **Visible vs invisible watermarks**: Should creators also have the option for a visible watermark (semi-transparent text/logo overlay)? This is a different use case (branding vs forensics) and could be a follow-up feature.
2. **Watermark persistence on re-upload**: If a creator replaces the source video, should existing cached watermarked files be invalidated immediately? The current TTL approach means they expire naturally after 24h, but there could be a 24h window where old watermarked files are served for the new video content.
3. **Multi-watermark for DRM**: Should the system support embedding multiple watermarks (e.g., user ID + device ID + session ID) for more precise forensic attribution?

### 14.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| `drawtext` watermark defeated by re-encoding | High | Medium | Documented limitation; Phase 2 adds temporal watermarking |
| FFmpeg not available on production host | Low | High | Health check at startup; `ffmpeg_manager.py` validates binary |
| Large video files exhaust disk space during processing | Medium | High | Temp directory monitoring + disk space alert; configurable temp path |
| `pytesseract` extraction unreliable for small text | Medium | Medium | Admin can also manually inspect contrast-boosted frame |

### 14.3 Dependency Risks

- **FFmpeg availability**: Required in production. The `ffmpeg_manager.py` module validates the binary at startup. In dev mode, FFmpeg is not required (mock mode).
- **pytesseract for extraction**: Optional production dependency for automated extraction. Admin can fall back to manual frame inspection.
- **S3 storage costs**: Watermarked files are temporary (24h) but can accumulate if many users download many videos. S3 lifecycle rules are essential.

---

## 15. Settings / Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WATERMARK_DOWNLOADS_ENABLED` | `true` | Master feature flag |
| `WATERMARK_JOBS_TABLE_NAME` | `watermark_jobs` | DynamoDB table name |
| `WATERMARK_OPACITY` | `0.02` | Text opacity (0.01-0.05 range) |
| `WATERMARK_FONT_SIZE` | `8` | Font size for drawtext filter |
| `WATERMARK_CRF` | `18` | H.264 CRF quality (lower = higher quality, larger file) |
| `WATERMARK_PRESET` | `fast` | FFmpeg encoding preset |
| `WATERMARK_TIMEOUT_SECONDS` | `600` | FFmpeg process timeout |
| `WATERMARK_CACHE_TTL_SECONDS` | `86400` | How long to keep cached watermarked files (24h) |
| `WATERMARK_MAX_CONCURRENT_JOBS` | `5` | Max concurrent watermark jobs per worker |

---

## 16. Implementation Plan

### 16.1 Files to Create

| File | Purpose |
|------|---------|
| `app/services/watermark_generator.py` | Watermark embedding via FFmpeg, payload encoding/decoding, extraction tool |
| `app/routers/watermark.py` | Watermarked download request, status polling, admin extraction endpoints |
| `frontend/src/pages/videos/WatermarkedDownloadButton.tsx` | Download button with progress UI |
| `frontend/src/api/endpoints/watermark.ts` | API client |
| `frontend/e2e/watermarked-downloads.spec.ts` | E2E tests |
| `scripts/watermark_extract.py` | CLI tool for admin watermark extraction |

### 16.2 Files to Modify

| File | Change |
|------|--------|
| `app/models_video.py` | Add `watermark_downloads` boolean field (alongside existing download fields at lines 103-108) | <!-- VERIFIED -->
| `app/services/video_metadata_store.py` | Serialize/deserialize `watermark_downloads` (update_video at line 316, get_video at line 307) | <!-- VERIFIED: file exists with these functions -->
| `app/services/vod_mp4_generator.py` | `mint_video_download_url` (line 56) delegates to watermark flow when enabled | <!-- VERIFIED -->
| `app/routers/video_listing.py` | Add `PATCH /{video_id}/watermark` toggle endpoint | <!-- VERIFIED: file exists -->
| `app/main.py` | Register watermark router | <!-- VERIFIED -->
| `app/core/settings.py` | Add `WATERMARK_*` settings (currently 1197 lines, none of these settings exist yet) | <!-- VERIFIED -->
| `app/core/tables.py` | Add `watermark_jobs` table handle (currently 177 lines, no such handle exists yet) | <!-- VERIFIED -->
| `scripts/local-ddb-init.py` | Add `WatermarkJobs` table with GSI1 and TTL (remember `attr_types={"GSI1SK": "N"}` for numeric sort key) | <!-- VERIFIED: numeric GSI SK pattern per CLAUDE.md gotchas -->
| `frontend/src/api/types.ts` | Add `WatermarkJobStatus`, `WatermarkDownloadResponse` interfaces |
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | Use `WatermarkedDownloadButton` when `watermark_downloads` is true |

---

## 17. Implementation Timeline

| Day | Task | Deliverable |
|-----|------|-------------|
| 1 | Add `watermark_downloads` field to `VideoMetadataModel`; add settings to `settings.py` | Schema + config |
| 1 | Add `WatermarkJobs` table to `local-ddb-init.py`; add handle to `tables.py` | DDB infrastructure |
| 2 | Create `app/services/watermark_generator.py` (payload encode/decode, job CRUD, mock completion) | Service layer |
| 3 | Create `app/services/watermark_generator.py` (FFmpeg execution, extraction) | FFmpeg pipeline |
| 4 | Create `app/routers/watermark.py` (download request, status poll, extraction) | HTTP API |
| 4 | Add `PATCH /{video_id}/watermark` to `video_listing.py`; register router in `main.py` | Toggle endpoint |
| 5 | Modify `vod_mp4_generator.py` to delegate to watermark flow when enabled | Integration |
| 6 | Create `WatermarkedDownloadButton.tsx` and `watermark.ts` API client | Frontend |
| 7 | Integrate button into `VideoPlayerPage.tsx`; add toggle to video edit page | UI integration |
| 8 | Create `scripts/watermark_extract.py` CLI tool | Admin tooling |
| 9 | Write pytest unit tests for payload encode/decode and job management | Backend tests |
| 10-11 | Write E2E tests (`watermarked-downloads.spec.ts`) | E2E suite |
| 12 | Final integration testing, monitoring setup, documentation | Ship |

---

## 18. Dependencies

- **VOD-012 (MP4 Download)**: The base MP4 file that gets watermarked. Must exist before watermarking can proceed.
- **VOD-019 (Download Tiers)**: Access control logic. Watermarking operates downstream of access checks.
- **VOD-004 (FFmpeg Execution)**: Subprocess wrapper, resource limits, error classification.
- **MEDIA-002 (FFmpeg Binary)**: FFmpeg path resolution and validation. Requires `libx264` codec and `drawtext` filter.
- **pytesseract + Pillow**: Optional dependency for automated watermark extraction (admin tool only).

---

## 19. Acceptance Criteria

1. Creator can enable `watermark_downloads` on a video; subsequent downloads embed per-user watermarks.
2. Watermarked downloads are imperceptible -- the video plays identically in any standard player.
3. Download button shows "Preparing download..." with spinner during watermark generation.
4. Repeated downloads within 24 hours serve the cached watermarked file instantly.
5. Admin can run the extraction tool on a file and recover the user ID hash + download timestamp.
6. Watermark payload includes a checksum for validation.
7. Dev mode processes watermark jobs synchronously (mock, no FFmpeg needed).
8. Production mode uses FFmpeg `drawtext` filter at configured opacity and quality settings.
9. Watermark jobs have a 24-hour TTL in DynamoDB (auto-cleanup).
10. Creator can disable `watermark_downloads` at any time; subsequent downloads serve the plain MP4.
11. All 15 E2E tests pass.
12. Feature can be disabled via `WATERMARK_DOWNLOADS_ENABLED=false` with graceful fallback to plain downloads.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `generate_download_mp4` function | `app/services/vod_mp4_generator.py` | 17 | VERIFIED |
| `mint_video_download_url` function | `app/services/vod_mp4_generator.py` | 56 | VERIFIED |
| `S.vod_output_prefix` | `app/core/settings.py` | 1049 | VERIFIED |
| `S.transcode_output_prefix` | `app/core/settings.py` | 1042 | VERIFIED |
| `S.ffmpeg_binary_path` | `app/core/settings.py` | 1074 | VERIFIED |
| `S.dev_mode` | `app/core/settings.py` | 239 | VERIFIED |
| `app/services/ffmpeg_executor.py` | `app/services/ffmpeg_executor.py` | exists | VERIFIED |
| `app/services/ffmpeg_manager.py` | `app/services/ffmpeg_manager.py` | exists | VERIFIED |
| `get_ffmpeg_path()` | `app/services/ffmpeg_manager.py` | 116 | VERIFIED |
| `get_ffmpeg_info()` | `app/services/ffmpeg_manager.py` | 81 | VERIFIED |
| `VideoMetadataModel` | `app/models_video.py` | 35-141 | VERIFIED |
| Existing download fields on VideoMetadataModel | `app/models_video.py` | 103-108 | VERIFIED: `allow_download`, `download_mp4_key`, `download_mp4_size_bytes`, `download_mp4_status`, `download_count` |
| `app/services/video_metadata_store.py` | `app/services/video_metadata_store.py` | exists | VERIFIED: `get_video` at line 307, `update_video` at line 316 |
| `app/routers/video_listing.py` | `app/routers/video_listing.py` | exists | VERIFIED |
| VideoMetadata DDB table | `scripts/local-ddb-init.py` | 702 | VERIFIED: PK=video_id |
| `app/core/settings.py` | `app/core/settings.py` | 1-1197 | VERIFIED: frozen dataclass; no `WATERMARK_*` settings exist yet |
| `app/core/tables.py` | `app/core/tables.py` | 1-177 | VERIFIED: no `watermark_jobs` handle exists yet |
| `require_ui_session` auth dependency | `app/auth/deps.py` | 184+ | VERIFIED |
| `now_ts()` function | `app/core/time.py` | 2 | VERIFIED |

### Key Corrections Summary

All file references in VOD-020 are verified correct. No significant corrections needed. The ticket correctly identifies:
- `vod_mp4_generator.py` functions and their signatures
- `ffmpeg_executor.py` and `ffmpeg_manager.py` infrastructure
- `VideoMetadataModel` and its existing download-related fields
- The need for `attr_types={"GSI1SK": "N"}` on the WatermarkJobs table (per the CLAUDE.md DynamoDB numeric GSI sort key gotcha)
