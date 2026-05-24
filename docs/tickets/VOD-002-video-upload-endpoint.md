# VOD-002: Implement Video Upload Endpoint with S3 Presigned URL

**Ticket**: VOD-002
**Status**: Design
**Author**: Engineering
**Date**: 2026-05-24

---

## 1. Overview & Motivation

### Problem Statement

The platform needs a dedicated video upload endpoint that supports large file uploads (up to several gigabytes) without proxying binary data through the FastAPI backend. Video files are inherently large and streaming them through the application server would exhaust memory, consume worker threads, and increase latency.

### Two-Step Upload Pattern

The solution follows a **presigned URL upload pattern** already established in the codebase (file manager and messaging image uploads):

1. **Step 1 - Request Presigned URL**: Client sends metadata (filename, content type, file size) to the backend. Backend validates the request (auth, content-type allowlist, size limits), generates an S3 presigned PUT URL with a 15-minute TTL, stores an upload ticket in DynamoDB, and returns the presigned URL + ticket ID to the client.

2. **Step 2 - Direct Upload to S3**: Client performs an HTTP PUT directly to the presigned S3 URL (or the `/mock/s3/` proxy route in dev mode), uploading the video binary without involving the backend.

3. **Step 3 - Confirm Upload**: Client calls a confirmation endpoint with the ticket ID and S3 key. Backend validates the ticket, performs `HeadObject` on S3 to verify the object exists and matches expectations (size, content-type metadata), records the video asset in DynamoDB, and returns the finalized video record.

### Why This Pattern

- **Scalability**: Binary data never passes through uvicorn workers. S3 handles throughput.
- **Reliability**: S3 presigned URLs support multipart upload for very large files. Client retries go to S3, not the backend.
- **Security**: Presigned URLs are scoped to a specific key, bucket, and content-type. They expire after 15 minutes. The ticket links the presigned key to the authenticated user.
- **Consistency**: Matches the existing `presign_upload` / `register_presigned_upload` flow in `app/services/filemanager.py` and the `images/presign` flow in `app/routers/messaging.py`.

---

## 2. Current State Analysis

### S3 Client Infrastructure

**Client creation** (`app/core/aws_clients.py`):
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

In dev mode, `_s3_endpoint_url()` returns `None` because moto intercepts all boto3 S3 calls in-process (no external endpoint). The `s3_client()` factory is used by both `app/services/filemanager.py` (line 57: `_s3 = s3_client()`) and `app/routers/messaging.py` (line 218: `s3 = s3_client()`).

**Dev-mode S3 mock** (`app/core/dev_s3.py`): Uses `moto.mock_aws()` to patch botocore globally. Buckets are pre-created at startup from `app/main.py` (line 273-278):
```python
_dev_buckets = [b for b in [
    _S.filemgr_bucket,
    os.environ.get("UPLOAD_BUCKET", ""),
    os.environ.get("S3_BUCKET_IMAGES", ""),
] if b]
```

Current env values: `FILEMGR_BUCKET=local-filemgr`, `UPLOAD_BUCKET=local-uploads`, `S3_BUCKET_IMAGES=local-chat-images`.

**Mock S3 HTTP proxy** (`app/routers/s3_mock.py`): Mounted at `/mock/s3` in `main.py`. Provides `PUT /{bucket}/{key:path}`, `GET /{bucket}/{key:path}`, `HEAD /{bucket}/{key:path}`, and `DELETE /{bucket}/{key:path}` routes that forward to the moto-intercepted boto3 client. This allows browser-based uploads to work in dev mode since moto presigned URLs point to inaccessible AWS endpoints.

### Existing Presigned Upload Flow (File Manager)

**Router** (`app/routers/filemanager.py`, lines 1881-1936):

- `POST /v1/fs/presign-upload` (request model: `PresignUploadIn` with `path` + optional `content_type`)
- Returns `PresignUploadOut`: `upload_url`, `bucket`, `key`, `ticket_id`, `path`, `content_type`
- `POST /v1/fs/complete-upload` (request model: `CompleteUploadIn` with `path`, `key`, `ticket_id`, optional `content_type`, `encrypted`, `enc_meta`)
- Returns `{ ok, path, size, content_type }`

**Service** (`app/services/filemanager.py`, lines 2206-2369):

`presign_upload(user, path, content_type)`:
- Generates a UUID-based S3 key: `{user}/objects/{uuid4()}`
- In dev mode: returns `/mock/s3/{bucket}/{key}` URL
- In production: calls `_s3.generate_presigned_url("put_object", ...)` with 900s expiry
- Stores upload ticket in DynamoDB with `PK=USER#{user}`, `SK=UPLOAD_TICKET#{ticket_id}`
- Ticket contains: `ticket_id`, `path`, `s3_key`, `content_type`, `expires_at`

`register_presigned_upload(user, path, s3_key, ticket_id, content_type, encryption_meta)`:
- Validates ticket exists and matches (path, s3_key)
- Checks ticket expiry
- Calls `_s3.head_object()` to verify the S3 object was actually uploaded
- Extracts `ContentLength`, `ETag`, and validates metadata tags (`filemgr-ticket`, `filemgr-user`)
- Enforces upload/storage quotas (deletes object if over-quota)
- Creates file node in DynamoDB with full metadata
- Deletes the ticket after successful registration

### Existing Presigned Upload Flow (Messaging Images)

**Router** (`app/routers/messaging.py`, lines 7711-7727):

- `POST /messaging/conversations/{id}/images/presign` with `SendImagePresignIn` (content_type, filename)
- Returns `PresignOut`: `upload_url`, `bucket`, `key`, `content_type`
- S3 key format: `{conversation_id}/{user_id}/{timestamp}_{uuid}_{filename}`
- Uses `S3_BUCKET_IMAGES` bucket (env: `S3_BUCKET_IMAGES`, default: `my-chat-images`)

### Frontend Upload Pattern

**File manager** (`frontend/src/pages/files/FilesPage.tsx`, lines 771-836):
- `PRESIGN_THRESHOLD = 5 * 1024 * 1024` (5 MB)
- Files above threshold use presigned path; smaller files use direct multipart upload
- Flow: `fsPresignUpload()` -> `fetch(PUT)` -> `completeUpload()`

**API client** (`frontend/src/api/endpoints/files.ts`, lines 235-265):
- `fsPresignUpload(path, contentType)` - POST to `/v1/fs/presign-upload`
- `completeUpload(path, key, ticketId, contentType, opts)` - POST to `/v1/fs/complete-upload`

---

## 3. Technical Design

### 3.1 Endpoint Specifications

#### `POST /v1/vod/upload/presign`

**Auth**: `Depends(require_ui_session)` (cookie-based with CSRF) or Bearer token.

**Request Body** (`VideoUploadPresignIn`):
```python
class VideoUploadPresignIn(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)
    content_type: str = Field(..., pattern=r"^video/(mp4|quicktime|x-msvideo|x-matroska|webm|mpeg|ogg|x-flv|3gpp|3gpp2)$")
    file_size_bytes: int = Field(..., ge=1, le=10_737_418_240)  # 1 byte to 10 GB
    title: Optional[str] = Field(default=None, max_length=500)
    description: Optional[str] = Field(default=None, max_length=5000)
    folder_path: Optional[str] = Field(default=None, max_length=1024)
```

**Response** (`VideoUploadPresignOut`):
```python
class VideoUploadPresignOut(BaseModel):
    upload_url: str           # Presigned PUT URL (or /mock/s3/... in dev)
    bucket: str               # S3 bucket name
    key: str                  # S3 object key
    ticket_id: str            # UUID ticket for confirmation step
    content_type: str         # Resolved content type
    expires_at: str           # ISO8601 presign expiry timestamp
    max_size_bytes: int       # Server-enforced max (echoed for client validation)
```

**Validation Logic**:
1. Validate `content_type` against video MIME type allowlist
2. Validate `file_size_bytes` against per-user and global limits
3. Check user upload quota (reuse `_enforce_upload_and_storage_quotas` pattern)
4. Generate S3 key and presigned URL
5. Store upload ticket in DynamoDB

**Error Responses**:
- `400`: Invalid content type, filename too long, size exceeds limit
- `403`: User not authenticated or quota exceeded
- `413`: File size exceeds maximum (10 GB default)
- `429`: Upload rate limit exceeded

#### `POST /v1/vod/upload/complete`

**Auth**: Same as presign endpoint.

**Request Body** (`VideoUploadCompleteIn`):
```python
class VideoUploadCompleteIn(BaseModel):
    ticket_id: str = Field(..., description="Ticket ID from presign response")
    key: str = Field(..., description="S3 object key from presign response")
    content_type: Optional[str] = Field(default=None, description="Override content type")
    client_checksum: Optional[str] = Field(default=None, description="Optional client-computed SHA-256 for integrity")
```

**Response** (`VideoUploadCompleteOut`):
```python
class VideoUploadCompleteOut(BaseModel):
    ok: bool
    video_id: str             # Unique video asset ID
    s3_key: str
    size_bytes: int
    content_type: str
    duration_seconds: Optional[float]
    thumbnail_url: Optional[str]
    status: str               # "uploaded" | "processing"
    created_at: str
```

**Validation Logic**:
1. Look up ticket by `ticket_id` for authenticated user
2. Verify ticket not expired (15-minute TTL)
3. Verify `key` matches ticket's `s3_key`
4. Call `s3.head_object(Bucket, Key)` to confirm object exists
5. Validate `ContentLength` matches expected `file_size_bytes` from ticket (within 1% tolerance for multipart overhead)
6. Validate `ContentType` from S3 metadata matches expected video type
7. Optional: verify `client_checksum` against S3 ETag (only for non-multipart uploads where ETag = MD5)
8. Create video asset record in DynamoDB
9. Delete the upload ticket
10. Optionally enqueue transcoding/thumbnail job

### 3.2 Presigned URL Generation

Following the filemanager pattern (`app/services/filemanager.py:2220-2237`):

```python
def _generate_video_presigned_url(bucket: str, key: str, content_type: str, user: str, ticket_id: str) -> str:
    if S.dev_mode:
        return f"{S.public_base_url}/mock/s3/{bucket}/{key}"
    
    return _s3.generate_presigned_url(
        ClientMethod="put_object",
        Params={
            "Bucket": bucket,
            "Key": key,
            "ContentType": content_type,
            "Metadata": {
                "vod-ticket": ticket_id,
                "vod-user": user,
            },
        },
        ExpiresIn=900,  # 15 minutes
    )
```

### 3.3 Content-Type Validation

Allowed video MIME types:
```python
ALLOWED_VIDEO_CONTENT_TYPES = frozenset({
    "video/mp4",
    "video/quicktime",       # .mov
    "video/x-msvideo",      # .avi
    "video/x-matroska",     # .mkv
    "video/webm",
    "video/mpeg",
    "video/ogg",
    "video/x-flv",
    "video/3gpp",
    "video/3gpp2",
})
```

Validation occurs at both the presign step (server rejects early) and the complete step (verifies S3 object metadata matches).

### 3.4 Size Limits

| Limit | Value | Configurable Via |
|-------|-------|-----------------|
| Minimum file size | 1 byte | N/A |
| Maximum file size | 10 GB | `VOD_UPLOAD_MAX_BYTES` env var |
| Per-user daily upload volume | 50 GB | `VOD_UPLOAD_DAILY_LIMIT_BYTES` env var |
| Per-user concurrent uploads | 5 | `VOD_UPLOAD_MAX_CONCURRENT` env var |
| Presigned URL TTL | 900 seconds | `VOD_PRESIGN_TTL_SECONDS` env var |

### 3.5 S3 Path Convention

```
{bucket}/vod/{user_sub}/raw/{year}/{month}/{video_id}/{original_filename}
```

Example: `local-uploads/vod/user123/raw/2026/05/a1b2c3d4/my-video.mp4`

Rationale:
- `vod/` prefix isolates video objects from other upload types in the same bucket
- `{user_sub}/` enables per-user S3 lifecycle policies and IAM scoping
- `raw/` distinguishes original uploads from transcoded derivatives (future: `transcoded/`, `thumbnails/`)
- `{year}/{month}/` enables time-based partitioning for lifecycle rules and cost analysis
- `{video_id}/` groups the original file with future derivatives (HLS segments, thumbnails)
- Original filename preserved for download `Content-Disposition`

### 3.6 Upload Ticket DynamoDB Schema

Stored in the same table as file manager upload tickets (or a dedicated `vod_uploads` table):

| Attribute | Value |
|-----------|-------|
| PK | `USER#{user_sub}` |
| SK | `VOD_TICKET#{ticket_id}` |
| ticket_id | UUID |
| video_id | UUID (pre-generated for the asset) |
| filename | Original filename |
| s3_key | Full S3 key |
| content_type | Validated MIME type |
| expected_size_bytes | Declared file size |
| status | `pending` / `completed` / `expired` |
| expires_at | ISO8601 (now + 15 min) |
| created_at | ISO8601 |
| ttl_epoch | Unix timestamp for DDB TTL auto-delete (24h after creation) |

### 3.7 Video Asset DynamoDB Record

| Attribute | Value |
|-----------|-------|
| PK | `USER#{user_sub}` |
| SK | `VIDEO#{video_id}` |
| video_id | UUID |
| title | User-provided title or filename |
| description | Optional description |
| filename | Original filename |
| s3_bucket | Bucket name |
| s3_key | Object key |
| size_bytes | Actual size from HeadObject |
| content_type | MIME type |
| duration_seconds | Probed via ffprobe (nullable) |
| thumbnail_s3_key | Generated thumbnail key (nullable) |
| status | `uploaded` / `processing` / `ready` / `error` |
| created_at | ISO8601 |
| updated_at | ISO8601 |
| etag | S3 ETag |
| folder_path | Optional folder path for organization |
| GSI1PK | `USER#{user_sub}` |
| GSI1SK | `CREATED#{created_at}` (for listing by recency) |

### 3.8 HeadObject Validation on Complete

The confirmation step performs a critical `HeadObject` call (same pattern as `register_presigned_upload` at line 2296 of `app/services/filemanager.py`):

```python
head = _s3.head_object(Bucket=bucket, Key=s3_key)
actual_size = int(head.get("ContentLength", 0))
actual_ct = head.get("ContentType", "application/octet-stream")
etag = head.get("ETag")
metadata = head.get("Metadata") or {}

# Verify metadata tags match ticket
if metadata.get("vod-ticket") != ticket_id:
    raise HTTPException(403, "uploaded object metadata mismatch")
if metadata.get("vod-user") != user:
    raise HTTPException(403, "uploaded object user mismatch")

# Verify content type is still a valid video type
if actual_ct not in ALLOWED_VIDEO_CONTENT_TYPES:
    _s3.delete_object(Bucket=bucket, Key=s3_key)
    raise HTTPException(400, "uploaded content type does not match allowed video types")

# Verify size within tolerance of declared size
if actual_size > max_size_bytes:
    _s3.delete_object(Bucket=bucket, Key=s3_key)
    raise HTTPException(413, "uploaded file exceeds maximum size")
```

This prevents:
- Upload of non-video content using a video presigned URL
- Size limit bypass (client declares 100MB, uploads 10GB)
- Cross-user object injection (metadata mismatch)

---

## 4. Implementation Plan

### 4.1 Backend Changes

#### New Files

| File | Purpose |
|------|---------|
| `app/routers/vod.py` | Router with presign + complete + list + get + delete endpoints |
| `app/services/vod_upload.py` | Service layer: presign generation, ticket management, HeadObject validation, asset record creation |

#### Modifications to Existing Files

| File | Change |
|------|--------|
| `app/main.py` | Register `vod_router` with prefix `/v1/vod`; add VOD bucket to `_dev_buckets` list |
| `app/core/settings.py` | Add settings: `vod_bucket`, `vod_upload_max_bytes`, `vod_upload_daily_limit_bytes`, `vod_upload_max_concurrent`, `vod_presign_ttl_seconds`, `vod_table_name` |
| `app/core/tables.py` | Add `T.vod` table handle (or reuse `file_manager` table with VOD prefix) |
| `app/models.py` | Add Pydantic models: `VideoUploadPresignIn`, `VideoUploadPresignOut`, `VideoUploadCompleteIn`, `VideoUploadCompleteOut`, `VideoAsset` |
| `scripts/local-ddb-init.py` | Add `vod_uploads` table definition with GSI for user listing |
| `.env.local.example` | Add `VOD_BUCKET=local-vod`, `VOD_UPLOAD_MAX_BYTES=10737418240` |

#### Router Structure (`app/routers/vod.py`)

```python
from fastapi import APIRouter, Depends, HTTPException, Request
from app.auth.deps import require_ui_session
from app.services.vod_upload import (
    presign_video_upload,
    complete_video_upload,
    list_user_videos,
    get_video_asset,
    delete_video_asset,
)

router = APIRouter(prefix="/v1/vod", tags=["vod"])

@router.post("/upload/presign")
def vod_presign(inp: VideoUploadPresignIn, user=Depends(require_ui_session)):
    ...

@router.post("/upload/complete")
def vod_complete(inp: VideoUploadCompleteIn, user=Depends(require_ui_session)):
    ...

@router.get("/videos")
def vod_list(user=Depends(require_ui_session)):
    ...

@router.get("/videos/{video_id}")
def vod_get(video_id: str, user=Depends(require_ui_session)):
    ...

@router.delete("/videos/{video_id}")
def vod_delete(video_id: str, user=Depends(require_ui_session)):
    ...
```

#### Service Layer (`app/services/vod_upload.py`)

Key functions:
- `presign_video_upload(user_sub, filename, content_type, file_size_bytes, title, description, folder_path)` - Validates inputs, generates S3 key, creates presigned URL, stores ticket
- `complete_video_upload(user_sub, ticket_id, key, content_type_override, client_checksum)` - Validates ticket, HeadObject verification, creates asset record, optional media probe
- `list_user_videos(user_sub, cursor, limit)` - Paginated listing via GSI
- `get_video_asset(user_sub, video_id)` - Single asset fetch
- `delete_video_asset(user_sub, video_id)` - Soft-delete asset + S3 object cleanup

The S3 client instantiation follows the established pattern:
```python
from app.core.aws_clients import s3_client
_s3 = s3_client()
```

### 4.2 Frontend Changes

#### New Files

| File | Purpose |
|------|---------|
| `frontend/src/api/endpoints/vod.ts` | API wrapper functions |
| `frontend/src/pages/vod/VideoUploadPage.tsx` | Upload UI with progress tracking |

#### API Client (`frontend/src/api/endpoints/vod.ts`)

```typescript
import api from "../client";

export interface VideoPresignRequest {
  filename: string;
  content_type: string;
  file_size_bytes: number;
  title?: string;
  description?: string;
  folder_path?: string;
}

export interface VideoPresignResponse {
  upload_url: string;
  bucket: string;
  key: string;
  ticket_id: string;
  content_type: string;
  expires_at: string;
  max_size_bytes: number;
}

export interface VideoCompleteRequest {
  ticket_id: string;
  key: string;
  content_type?: string;
  client_checksum?: string;
}

export interface VideoAsset {
  video_id: string;
  title: string;
  filename: string;
  size_bytes: number;
  content_type: string;
  duration_seconds?: number;
  thumbnail_url?: string;
  status: string;
  created_at: string;
}

export const presignVideoUpload = (body: VideoPresignRequest) =>
  api.post<VideoPresignResponse>("/v1/vod/upload/presign", body);

export const completeVideoUpload = (body: VideoCompleteRequest) =>
  api.post<VideoAsset>("/v1/vod/upload/complete", body);

export const listVideos = (cursor?: string) =>
  api.get<{ videos: VideoAsset[]; next_cursor?: string }>("/v1/vod/videos", { cursor });

export const deleteVideo = (videoId: string) =>
  api.del<{ ok: boolean }>(`/v1/vod/videos/${videoId}`);
```

#### Upload Flow (Frontend)

```typescript
const uploadVideo = async (file: File, title?: string) => {
  // Step 1: Get presigned URL
  const presign = await presignVideoUpload({
    filename: file.name,
    content_type: file.type,
    file_size_bytes: file.size,
    title,
  });

  // Step 2: Upload directly to S3 (with progress via XMLHttpRequest)
  await new Promise<void>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) setProgress(e.loaded / e.total);
    });
    xhr.addEventListener("load", () => xhr.status === 200 ? resolve() : reject());
    xhr.addEventListener("error", reject);
    xhr.open("PUT", presign.upload_url);
    xhr.setRequestHeader("Content-Type", presign.content_type);
    xhr.send(file);
  });

  // Step 3: Confirm upload
  const asset = await completeVideoUpload({
    ticket_id: presign.ticket_id,
    key: presign.key,
  });
  return asset;
};
```

### 4.3 Settings Additions (`app/core/settings.py`)

```python
# VOD (Video on Demand) upload
vod_bucket: str = os.environ.get("VOD_BUCKET", "")
vod_table_name: str = os.environ.get("VOD_TABLE_NAME", "vod_assets")
vod_upload_max_bytes: int = int(os.environ.get("VOD_UPLOAD_MAX_BYTES", "10737418240"))  # 10 GB
vod_upload_daily_limit_bytes: int = int(os.environ.get("VOD_UPLOAD_DAILY_LIMIT_BYTES", "53687091200"))  # 50 GB
vod_upload_max_concurrent: int = int(os.environ.get("VOD_UPLOAD_MAX_CONCURRENT", "5"))
vod_presign_ttl_seconds: int = int(os.environ.get("VOD_PRESIGN_TTL_SECONDS", "900"))
vod_allowed_content_types: str = os.environ.get(
    "VOD_ALLOWED_CONTENT_TYPES",
    "video/mp4,video/quicktime,video/x-msvideo,video/x-matroska,video/webm,video/mpeg,video/ogg"
)
vod_thumbnail_enabled: bool = os.environ.get("VOD_THUMBNAIL_ENABLED", "true").lower() in ("1", "true", "yes", "on")
vod_probe_duration_enabled: bool = os.environ.get("VOD_PROBE_DURATION_ENABLED", "true").lower() in ("1", "true", "yes", "on")
```

### 4.4 DynamoDB Table Definition (`scripts/local-ddb-init.py`)

```python
TableDef(
    name="vod_assets",
    pk="PK",
    sk="SK",
    gsis=[
        GsiDef(name="GSI1", pk="GSI1PK", sk="GSI1SK"),
    ],
    attr_types={"GSI1SK": "S"},
)
```

### 4.5 Main App Registration (`app/main.py`)

```python
from app.routers.vod import router as vod_router
app.include_router(vod_router)

# In dev bucket list:
_dev_buckets = [b for b in [
    _S.filemgr_bucket,
    os.environ.get("UPLOAD_BUCKET", ""),
    os.environ.get("S3_BUCKET_IMAGES", ""),
    _S.vod_bucket,  # NEW
] if b]
```

---

## 5. Testing Strategy

### 5.1 Unit Tests with moto (`tests/test_vod_upload.py`)

Tests use the same in-memory DynamoDB + moto S3 pattern from `tests/conftest.py`. The moto mock intercepts all boto3 calls, so `generate_presigned_url`, `head_object`, `put_object`, and `delete_object` all work without external services.

**Test cases**:

```python
class TestVodPresign:
    def test_presign_returns_valid_upload_url_and_ticket(self):
        """POST /v1/vod/upload/presign with valid video content type returns upload_url, ticket_id."""

    def test_presign_rejects_non_video_content_type(self):
        """content_type='application/pdf' returns 400."""

    def test_presign_rejects_oversized_file(self):
        """file_size_bytes > VOD_UPLOAD_MAX_BYTES returns 413."""

    def test_presign_rejects_zero_size_file(self):
        """file_size_bytes=0 returns 400 (Pydantic ge=1 validation)."""

    def test_presign_requires_authentication(self):
        """No auth cookie/token returns 401."""

    def test_presign_enforces_daily_upload_quota(self):
        """User who has uploaded 50GB today gets 429."""

    def test_presign_enforces_concurrent_upload_limit(self):
        """User with 5 pending tickets gets 429."""

    def test_presign_s3_key_follows_path_convention(self):
        """S3 key matches vod/{user}/raw/{year}/{month}/{video_id}/{filename}."""

    def test_presign_dev_mode_returns_mock_url(self):
        """In dev mode, upload_url starts with /mock/s3/."""

    def test_presign_stores_ticket_in_dynamodb(self):
        """After presign, ticket exists in DDB with correct attributes."""


class TestVodComplete:
    def test_complete_with_valid_ticket_creates_asset(self):
        """After uploading to S3, complete returns video asset record."""

    def test_complete_validates_head_object_exists(self):
        """Complete without actual S3 upload returns 500 (HeadObject fails)."""

    def test_complete_rejects_expired_ticket(self):
        """Ticket older than 15 minutes returns 403."""

    def test_complete_rejects_mismatched_key(self):
        """key != ticket.s3_key returns 403."""

    def test_complete_rejects_wrong_user_ticket(self):
        """User A cannot complete User B's ticket."""

    def test_complete_validates_content_type_from_s3(self):
        """If S3 object ContentType is not video/*, reject and delete object."""

    def test_complete_validates_size_limit(self):
        """If actual ContentLength > max, reject and delete object."""

    def test_complete_deletes_ticket_after_success(self):
        """Ticket is removed from DDB after successful completion."""

    def test_complete_records_video_asset_in_dynamodb(self):
        """Video asset record exists with correct PK/SK/GSI after completion."""

    def test_complete_probes_duration_for_mp4(self):
        """For video/mp4, duration_seconds is populated (or None if ffprobe unavailable)."""

    def test_complete_idempotent_on_replay(self):
        """Calling complete twice with same ticket returns 403 (ticket already consumed)."""
```

### 5.2 E2E Tests (`frontend/e2e/vod-upload.spec.ts`)

Following the established E2E patterns (inject auth, CSRF headers, session-based API calls):

```typescript
import { test, expect } from "@playwright/test";
import { injectAuth, sessions } from "./helpers";

test.describe("VOD Upload API", () => {
  const ALICE = "alice";

  test("presign returns upload URL and ticket for valid video", async ({ page }) => {
    await injectAuth(page, ALICE);
    const resp = await page.request.post("/v1/vod/upload/presign", {
      headers: { "x-csrf-token": sessions[ALICE].csrf_token },
      data: {
        filename: "test-video.mp4",
        content_type: "video/mp4",
        file_size_bytes: 1024 * 1024,  // 1 MB
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.upload_url).toBeTruthy();
    expect(body.ticket_id).toBeTruthy();
    expect(body.key).toContain("vod/");
    expect(body.content_type).toBe("video/mp4");
  });

  test("presign rejects non-video content type", async ({ page }) => {
    await injectAuth(page, ALICE);
    const resp = await page.request.post("/v1/vod/upload/presign", {
      headers: { "x-csrf-token": sessions[ALICE].csrf_token },
      data: {
        filename: "document.pdf",
        content_type: "application/pdf",
        file_size_bytes: 1024,
      },
    });
    expect(resp.status()).toBe(422);  // Pydantic pattern validation
  });

  test("presign rejects file exceeding size limit", async ({ page }) => {
    await injectAuth(page, ALICE);
    const resp = await page.request.post("/v1/vod/upload/presign", {
      headers: { "x-csrf-token": sessions[ALICE].csrf_token },
      data: {
        filename: "huge.mp4",
        content_type: "video/mp4",
        file_size_bytes: 20_000_000_000,  // 20 GB > 10 GB limit
      },
    });
    expect(resp.status()).toBe(422);  // Pydantic le= validation
  });

  test("full upload flow: presign -> PUT -> complete", async ({ page }) => {
    await injectAuth(page, ALICE);

    // Step 1: Presign
    const presignResp = await page.request.post("/v1/vod/upload/presign", {
      headers: { "x-csrf-token": sessions[ALICE].csrf_token },
      data: {
        filename: "e2e-test.mp4",
        content_type: "video/mp4",
        file_size_bytes: 256,
        title: "E2E Test Video",
      },
    });
    expect(presignResp.status()).toBe(200);
    const presign = await presignResp.json();

    // Step 2: Upload to mock S3
    const videoBytes = Buffer.alloc(256, 0x00);
    const putResp = await page.request.put(presign.upload_url, {
      headers: { "Content-Type": "video/mp4" },
      data: videoBytes,
    });
    expect(putResp.status()).toBe(200);

    // Step 3: Complete
    const completeResp = await page.request.post("/v1/vod/upload/complete", {
      headers: { "x-csrf-token": sessions[ALICE].csrf_token },
      data: {
        ticket_id: presign.ticket_id,
        key: presign.key,
      },
    });
    expect(completeResp.status()).toBe(200);
    const asset = await completeResp.json();
    expect(asset.ok).toBe(true);
    expect(asset.video_id).toBeTruthy();
    expect(asset.size_bytes).toBe(256);
    expect(asset.status).toBe("uploaded");
  });

  test("complete rejects expired ticket", async ({ page }) => {
    // Create ticket, wait/mock expiry, attempt complete
    // (Would require DDB manipulation to backdate expires_at)
  });

  test("complete rejects mismatched S3 key", async ({ page }) => {
    await injectAuth(page, ALICE);
    const presignResp = await page.request.post("/v1/vod/upload/presign", {
      headers: { "x-csrf-token": sessions[ALICE].csrf_token },
      data: { filename: "test.mp4", content_type: "video/mp4", file_size_bytes: 100 },
    });
    const presign = await presignResp.json();

    const completeResp = await page.request.post("/v1/vod/upload/complete", {
      headers: { "x-csrf-token": sessions[ALICE].csrf_token },
      data: { ticket_id: presign.ticket_id, key: "wrong/key/path.mp4" },
    });
    expect(completeResp.status()).toBe(403);
  });
});
```

### 5.3 Testing S3 Path Correctness

Unit test verifies the generated S3 key matches the expected convention:

```python
def test_s3_key_format():
    key = generate_vod_s3_key(user_sub="user123", video_id="abc-def", filename="my video.mp4")
    # Expected: vod/user123/raw/2026/05/abc-def/my video.mp4
    assert key.startswith("vod/user123/raw/")
    parts = key.split("/")
    assert parts[0] == "vod"
    assert parts[1] == "user123"
    assert parts[2] == "raw"
    assert len(parts[3]) == 4  # year
    assert len(parts[4]) == 2  # month
    assert parts[5] == "abc-def"  # video_id
    assert parts[6] == "my video.mp4"  # filename preserved
```

### 5.4 Testing Size and Type Rejection

Both Pydantic model validation (returns 422) and server-side enforcement (returns 400/413) should be tested:

- **Pydantic-level**: `file_size_bytes > 10GB` fails the `le=10_737_418_240` constraint -> 422
- **Service-level**: Even if client lies about size, `HeadObject` ContentLength check at complete time catches oversized uploads and triggers S3 cleanup (`delete_object`)
- **Content-type bypass**: Client declares `video/mp4`, uploads `text/plain` content. The presigned URL enforces `ContentType` in the `Params`, but a crafty client could override the header. The `HeadObject` check at complete time verifies the stored ContentType matches the allowlist.

### 5.5 Integration Test Checklist

| Scenario | Expected Outcome |
|----------|-----------------|
| Valid MP4 upload (256 bytes) | 200 + asset record created |
| Valid WebM upload | 200 + correct content_type stored |
| PDF masquerading as video/mp4 | Presign succeeds, complete succeeds (S3 stores ContentType from presign params, not from actual content) - acceptable since content is opaque bytes |
| File > 10GB declared | 422 at presign (Pydantic validation) |
| Presign then wait 16 minutes then complete | 403 "upload ticket expired" |
| Two users: A presigns, B tries to complete | 403 (ticket not found for user B) |
| Complete without uploading to S3 | 500 (HeadObject returns NoSuchKey) |
| Exceed daily quota | 429 at presign |
| Delete uploaded video | S3 object removed, DDB record soft-deleted |

---

## Appendix: File Reference

| Path | Role |
|------|------|
| `app/core/aws_clients.py` | S3 client factory (`s3_client()`) |
| `app/core/dev_s3.py` | Moto in-process S3 mock activation |
| `app/core/settings.py` | All configuration including bucket names |
| `app/routers/s3_mock.py` | Dev-mode HTTP proxy for mock S3 operations |
| `app/routers/filemanager.py:1881-1936` | Existing presign/complete endpoints (reference implementation) |
| `app/services/filemanager.py:2206-2369` | Existing presign_upload + register_presigned_upload (reference implementation) |
| `app/routers/messaging.py:7711-7727` | Image presign endpoint (simpler reference) |
| `app/main.py:273-278` | Dev bucket list for moto initialization |
| `frontend/src/api/endpoints/files.ts:235-265` | Frontend presign + complete API wrappers |
| `frontend/src/pages/files/FilesPage.tsx:808-821` | Frontend presigned upload flow with fetch PUT |
| `.env.local` | Bucket config: `FILEMGR_BUCKET`, `UPLOAD_BUCKET`, `S3_BUCKET_IMAGES` |
