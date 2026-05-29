# VOD-002: Implement Video Upload Endpoint with S3 Presigned URL

**Ticket**: VOD-002
**Status**: Implemented
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
- **Consistency**: Matches the existing `presign_upload` / `register_presigned_upload` flow in `app/services/filemanager.py` (see `app/services/filemanager.py:2207` and `:2264`) and the `images/presign` flow in `app/routers/messaging.py` (see `app/routers/messaging.py:7914`).

---

## 2. Current State Analysis

### S3 Client Infrastructure

**Client creation** (`app/core/aws_clients.py:114`):
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

In dev mode, `_s3_endpoint_url()` returns `None` because moto intercepts all boto3 S3 calls in-process (no external endpoint). The `s3_client()` factory is used by both `app/services/filemanager.py` (line 58: `_s3 = s3_client()`) and `app/routers/messaging.py` (line 219: `s3 = s3_client()`).

**Dev-mode S3 mock** (`app/core/dev_s3.py`): Uses `moto.mock_aws()` to patch botocore globally. Buckets are pre-created at startup from `app/main.py` (lines 364-370):
```python
_dev_buckets = [b for b in [
    _S.filemgr_bucket,
    os.environ.get("UPLOAD_BUCKET", ""),
    os.environ.get("S3_BUCKET_IMAGES", ""),
    _S.video_upload_bucket,
    _S.vod_output_bucket or "vod-output",
] if b]
```
<!-- NOTE: The VOD buckets (video_upload_bucket, vod_output_bucket) are ALREADY included in the dev bucket list at main.py:368-369. -->

Current env values: `FILEMGR_BUCKET=local-filemgr`, `UPLOAD_BUCKET=local-uploads`, `S3_BUCKET_IMAGES=local-chat-images`.

**Mock S3 HTTP proxy** (`app/routers/s3_mock.py`): Mounted at `/mock/s3` in `main.py`. Provides `PUT /{bucket}/{key:path}`, `GET /{bucket}/{key:path}`, `HEAD /{bucket}/{key:path}`, and `DELETE /{bucket}/{key:path}` routes that forward to the moto-intercepted boto3 client. This allows browser-based uploads to work in dev mode since moto presigned URLs point to inaccessible AWS endpoints.

### Existing Presigned Upload Flow (File Manager)

**Router** (`app/routers/filemanager.py`, lines 1921-1943):

- `POST /presign-upload` (line 1921, model: `PresignUploadIn` at line 642) with `path` + optional `content_type`
- Returns `PresignUploadOut` (line 647): `upload_url`, `bucket`, `key`, `ticket_id`, `path`, `content_type`
- `POST /complete-upload` (line 1942, model: `CompleteUploadIn` at line 656) with `path`, `key`, `ticket_id`, optional `content_type`, `encrypted`, `enc_meta`
- Returns `{ ok, path, size, content_type }`

**Service** (`app/services/filemanager.py`, lines 2207-2369):

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

**Router** (`app/routers/messaging.py`, lines 7914-7930):

- `POST /conversations/{conversation_id}/images/presign` (line 7914, model: `SendImagePresignIn` at line 1899)
- Returns `PresignOut` (line 1904): `upload_url`, `bucket`, `key`, `content_type`
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

Following the filemanager pattern (`app/services/filemanager.py:2226-2237`):

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

The confirmation step performs a critical `HeadObject` call (same pattern as `register_presigned_upload` at line 2297 of `app/services/filemanager.py`):

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

<!-- NOTE: Both files listed below ALREADY EXIST in the codebase. -->

| File | Purpose | Status |
|------|---------|--------|
| `app/routers/vod.py` | Router with presign + complete endpoints (prefix `/ui/videos`, 279 lines) | **Already exists** (see `app/routers/vod.py:30` — `APIRouter(prefix="/ui/videos", tags=["vod"])`) |
| `app/services/vod_s3_uploader.py` | Service layer: S3 upload, segment transfer, lifecycle management | **Already exists** (not `vod_upload.py` — the actual service file is `vod_s3_uploader.py`) |

#### Modifications to Existing Files

| File | Change |
|------|--------|
| `app/main.py` | Register `vod_router` — **Already done** at line 97 (import) and line 421 (`app.include_router(vod_router)`). Prefix is `/ui/videos`, NOT `/v1/vod`. VOD buckets already in `_dev_buckets` at lines 368-369. |
| `app/core/settings.py` | VOD settings **already exist**: `video_upload_bucket` (line 1079), `video_metadata_table_name` (line 1075), `vod_entitlements_table_name` (line 1076), `transcode_jobs_table_name` (line 1082), `vod_output_bucket` (line 1094). Setting names differ from spec — e.g., `video_upload_bucket` not `vod_bucket`. |
| `app/core/tables.py` | <!-- NOTE: Table handles wired via `app/core/tables.py` — verify T.video_metadata etc. --> |
| `app/models.py` | <!-- NOTE: VOD Pydantic models are NOT in `app/models.py`. They are defined INLINE in `app/routers/vod.py` (lines 51-66): `VideoUploadPresignIn`, `VideoUploadPresignOut`, `VideoUploadCompleteOut`. Additional models in `app/models_video.py` (e.g., `VideoMetadataModel`, `VideoStatus`, `UpdateVideoIn`). --> |
| `scripts/local-ddb-init.py` | The table is `VideoMetadata` (not `vod_uploads`/`vod_assets`) — **already exists** at lines 707-737 with GSIs: `ByOwnerCreatedAt`, `ByStatusCreatedAt`, `BySourceBroadcast`, `ByCategory`, `ByGalleryPublished`. |
| `.env.local.example` | Bucket env var is `VIDEO_UPLOAD_BUCKET` (not `VOD_BUCKET`), default `"local-uploads"`. |

#### Router Structure (`app/routers/vod.py`)

<!-- NOTE: This router ALREADY EXISTS. The actual prefix is `/ui/videos` (not `/v1/vod`).
     Actual endpoints (see app/routers/vod.py):
       - POST /ui/videos/upload/presign (line 88, function `vod_presign_upload`)
       - POST /ui/videos/upload/complete (line 167, function `vod_complete_upload`)
     Models defined inline: VideoUploadPresignIn (line 51), VideoUploadPresignOut (line 57), VideoUploadCompleteOut (line 64).
     Video listing, detail, update, and delete are in `app/routers/video_listing.py` (prefix `/ui/videos`, 1539 lines).
-->

```python
# ACTUAL implementation (differs from original spec):
router = APIRouter(prefix="/ui/videos", tags=["vod"])

@router.post("/upload/presign")
def vod_presign_upload(inp: VideoUploadPresignIn, user=Depends(require_ui_session)):
    ...

@router.post("/upload/complete")
def vod_complete_upload(video_id: str, user=Depends(require_ui_session)):
    ...
```

#### Service Layer

<!-- NOTE: `app/services/vod_upload.py` does not exist. The upload-related service logic is split across:
     - `app/services/vod_s3_uploader.py` — S3 upload/transfer functions (upload_segment, upload_transcode_outputs, etc.)
     - `app/services/video_metadata_store.py` — DDB CRUD for video records (create_video, get_video, update_video, list_videos_by_owner, etc.)
     The presign/complete logic is implemented directly in `app/routers/vod.py` (lines 88-279).
-->

Key existing service functions in `app/services/video_metadata_store.py`:
- `create_video(...)` (line 283) — Creates video record in DDB
- `get_video(video_id)` (line 323) — Single video fetch
- `update_video(video_id, updates)` (line 332) — Update video fields
- `soft_delete_video(video_id)` (line 349) — Soft-delete
- `list_videos_by_owner(...)` (line 402) — Paginated listing via GSI
- `delete_video(video_id, owner_user_id)` (line 590) — Hard delete

Key existing functions in `app/services/vod_s3_uploader.py`:
- `upload_segment(...)` (line 96) — Upload HLS segment to S3
- `upload_transcode_outputs(...)` (line 142) — Batch upload transcoded files
- `abort_incomplete_uploads(...)` (line 125) — Cleanup incomplete multipart uploads

The S3 client instantiation follows the established pattern (see `app/services/filemanager.py:33,58`):
```python
from app.core.aws_clients import s3_client
_s3 = s3_client()
```

### 4.2 Frontend Changes

#### Frontend Files

<!-- NOTE: Both files below ALREADY EXIST (though paths differ slightly from spec). -->

| File | Purpose | Status |
|------|---------|--------|
| `frontend/src/api/endpoints/vod.ts` | API wrapper functions (112 lines) | **Already exists** — exports `presignVideoUpload`, `completeVideoUpload`, `getVideoDetail`, `listOwnVideos`, `listPublicVideos` |
| `frontend/src/pages/videos/VideosPage.tsx` | Video management page | **Already exists** at `pages/videos/` (not `pages/vod/`). Also: `VideoPlayerPage.tsx`, `ForYouTab.tsx`, `SimilarVideos.tsx`, `CreatorSuggestions.tsx`, `WatermarkedDownloadButton.tsx` |

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

### 4.3 Settings (`app/core/settings.py`)

<!-- NOTE: The actual settings names differ from this spec. Existing VOD settings: -->

```python
# ACTUAL existing settings (already in app/core/settings.py):
video_metadata_table_name: str = os.environ.get("DDB_VIDEO_METADATA", "VideoMetadata")   # line 1075
vod_entitlements_table_name: str = os.environ.get("DDB_VOD_ENTITLEMENTS", "VodEntitlements")  # line 1076
video_upload_bucket: str = os.environ.get("VIDEO_UPLOAD_BUCKET", "local-uploads")         # line 1079
transcode_jobs_table_name: str = os.environ.get("DDB_TRANSCODE_JOBS", "TranscodeJobs")    # line 1082
vod_output_bucket: str = os.environ.get("VOD_OUTPUT_BUCKET", "vod-output")                 # line 1094
video_views_table_name: str = os.environ.get("DDB_VIDEO_VIEWS", "VideoViews")             # line 1234
video_likes_table_name: str = os.environ.get("DDB_VIDEO_LIKES", "VideoLikes")             # line 1235
vod_ad_cpm_cents: int = int(os.environ.get("VOD_AD_CPM_CENTS", "500"))                    # line 1241
ad_impressions_table_name: str = os.environ.get("DDB_AD_IMPRESSIONS", "AdImpressions")    # line 1242
watermark_jobs_table_name: str = os.environ.get("WATERMARK_JOBS_TABLE_NAME", "watermark_jobs")  # line 1349
```

### 4.4 DynamoDB Table Definition (`scripts/local-ddb-init.py`)

<!-- NOTE: The table is called `VideoMetadata` (not `vod_assets`). It ALREADY EXISTS at lines 707-737.
     PK: `video_id`, SK: `video_id` (single-item table pattern).
     GSIs: ByOwnerCreatedAt, ByStatusCreatedAt, BySourceBroadcast, ByCategory, ByGalleryPublished.
     The spec's proposed `PK=USER#{user_sub}`, `SK=VIDEO#{video_id}` schema was NOT used.
     Instead, owner lookup uses the `ByOwnerCreatedAt` GSI with `owner_user_id` as PK.
-->

```python
# ACTUAL table definition (already in scripts/local-ddb-init.py:707-737):
TableDef(
    _resolve_table_name(S.video_metadata_table_name, "VideoMetadata"),
    pk="video_id",
    sk="video_id",
    gsis=[
        GsiDef(name="ByOwnerCreatedAt", pk="owner_user_id", sk="created_at"),
        GsiDef(name="ByStatusCreatedAt", pk="status", sk="created_at"),
        GsiDef(name="BySourceBroadcast", pk="source_broadcast_session_id", sk="created_at"),
        GsiDef(name="ByCategory", pk="category", sk="created_at"),
        GsiDef(name="ByGalleryPublished", pk="gallery_status", sk="published_at"),
    ],
    attr_types={"created_at": "N", "published_at": "N"},
)
```

### 4.5 Main App Registration (`app/main.py`)

<!-- NOTE: All of this is ALREADY DONE. -->

```python
# ACTUAL (already in app/main.py):
# Import at line 97:
from app.routers.vod import router as vod_router
# Registration at line 421:
app.include_router(vod_router)

# Dev bucket list at lines 364-370 already includes VOD buckets:
_dev_buckets = [b for b in [
    _S.filemgr_bucket,
    os.environ.get("UPLOAD_BUCKET", ""),
    os.environ.get("S3_BUCKET_IMAGES", ""),
    _S.video_upload_bucket,      # line 368
    _S.vod_output_bucket or "vod-output",  # line 369
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

### 5.2 E2E Tests (`frontend/e2e/video-upload.spec.ts`)

<!-- NOTE: The actual E2E test file is `video-upload.spec.ts` (not `vod-upload.spec.ts`). It already exists. -->

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

## Testing Strategy

### Unit Tests (pytest)

| Test | Description |
|------|-------------|
| `test_presign_returns_valid_upload_url_and_ticket` | POST with valid video content type returns `upload_url`, `ticket_id`, `key` |
| `test_presign_rejects_non_video_content_type` | `content_type='application/pdf'` returns 400/422 |
| `test_presign_rejects_oversized_file` | `file_size_bytes > 10GB` returns 422 (Pydantic `le=` validation) |
| `test_presign_rejects_zero_size_file` | `file_size_bytes=0` returns 422 (Pydantic `ge=1` validation) |
| `test_presign_requires_authentication` | No auth cookie/token returns 401 |
| `test_presign_s3_key_follows_path_convention` | S3 key matches `vod/{user}/raw/{year}/{month}/{video_id}/{filename}` |
| `test_presign_dev_mode_returns_mock_url` | In dev mode, `upload_url` starts with `/mock/s3/` |
| `test_complete_with_valid_ticket_creates_asset` | After uploading to S3, complete returns video asset record with `video_id` |
| `test_complete_validates_head_object_exists` | Complete without actual S3 upload returns error (HeadObject fails) |
| `test_complete_rejects_expired_ticket` | Ticket older than 15 minutes returns 403 |
| `test_complete_rejects_mismatched_key` | `key != ticket.s3_key` returns 403 |
| `test_complete_deletes_ticket_after_success` | Ticket is removed from DDB after successful completion |

**Framework**: pytest + moto (DynamoDB mock + S3 mock)
**Test file**: `tests/test_vod_upload.py`

### Integration Tests

| Scenario | Services | Assertion |
|----------|----------|-----------|
| Valid MP4 upload (256 bytes) | vod.py + S3 mock | 200 + asset record created in VideoMetadata table |
| Valid WebM upload | vod.py + S3 mock | 200 + correct `content_type` stored |
| Presign then complete without S3 PUT | vod.py + S3 mock | HeadObject returns NoSuchKey; error response |
| Two users: A presigns, B tries to complete | vod.py + sessions | 403 (ticket not found for user B) |

### E2E Tests (Playwright)

| # | Test | Assertion |
|---|------|-----------|
| 1 | Presign returns upload URL for valid video | 200; `upload_url` truthy; `key` contains `vod/` |
| 2 | Presign rejects non-video content type | 422 (Pydantic pattern validation) |
| 3 | Presign rejects file exceeding size limit | 422 (Pydantic `le` validation) |
| 4 | Full presign -> PUT -> complete flow | 200; asset has `video_id`, `status` |
| 5 | Complete rejects mismatched S3 key | 403 |
| 6 | Complete rejects nonexistent ticket | 403 or 404 |
| 7 | Full upload creates video record with size_bytes | `asset.size_bytes` matches uploaded file size |
| 8 | Presign stores ticket in DynamoDB | After presign, ticket exists with correct attributes |

**Auth**: `injectAuth(page, "alice")` + CSRF header via `x-csrf-token`
**Test file**: `frontend/e2e/video-upload.spec.ts`

### Test Data Requirements
- DDB tables: `VideoMetadata` (with GSIs), `sessions`
- S3 bucket: `video_upload_bucket` (`local-uploads`) pre-created by moto in dev mode
- Test users: Alice (USER), Bob (USER)
- Sessions seeded by `e2e_session_setup.py`

### CI/Pipeline
- Feature flag: None required (endpoints are additive under `/ui/videos/upload/*`)
- Serial execution with `workers: 1`
- Retry-safe (each test presigns a fresh ticket; no shared state between tests)

---

## Appendix: File Reference

| Path | Role |
|------|------|
| `app/core/aws_clients.py:114` | S3 client factory (`s3_client()`) |
| `app/core/dev_s3.py` | Moto in-process S3 mock activation |
| `app/core/settings.py:1075-1094` | VOD settings (`video_upload_bucket`, `video_metadata_table_name`, etc.) |
| `app/routers/s3_mock.py` | Dev-mode HTTP proxy for mock S3 operations |
| `app/routers/vod.py:30` | **Existing** VOD router (prefix `/ui/videos`, models at lines 51-66) |
| `app/routers/video_listing.py:40` | **Existing** video listing router (prefix `/ui/videos`, 1539 lines) |
| `app/routers/filemanager.py:1921-1943` | Existing presign/complete endpoints (reference implementation) |
| `app/services/filemanager.py:2207-2369` | Existing presign_upload + register_presigned_upload (reference implementation) |
| `app/services/vod_s3_uploader.py` | **Existing** VOD S3 upload service |
| `app/services/video_metadata_store.py` | **Existing** video DDB CRUD service |
| `app/models_video.py` | **Existing** VOD Pydantic models (`VideoMetadataModel`, `VideoStatus`, `UpdateVideoIn`) |
| `app/routers/messaging.py:7914-7930` | Image presign endpoint (simpler reference) |
| `app/main.py:364-370` | Dev bucket list for moto initialization (already includes VOD buckets) |
| `app/main.py:97,421` | VOD router import and registration |
| `scripts/local-ddb-init.py:707-737` | **Existing** `VideoMetadata` DDB table definition |
| `frontend/src/api/endpoints/vod.ts` | **Existing** frontend VOD API wrappers (112 lines) |
| `frontend/src/pages/videos/VideosPage.tsx` | **Existing** video management page |
| `frontend/e2e/video-upload.spec.ts` | **Existing** E2E upload tests |
| `.env.local` | Bucket config: `VIDEO_UPLOAD_BUCKET`, `VOD_OUTPUT_BUCKET` |

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/core/aws_clients.py` | 114 | `s3_client()` factory |
| `app/core/settings.py` | 1075 | `video_metadata_table_name` setting |
| `app/core/settings.py` | 1079 | `video_upload_bucket` setting |
| `app/core/settings.py` | 1082 | `transcode_jobs_table_name` setting |
| `app/core/settings.py` | 1094 | `vod_output_bucket` setting |
| `app/main.py` | 97 | `from app.routers.vod import router as vod_router` |
| `app/main.py` | 421 | `app.include_router(vod_router)` |
| `app/main.py` | 364-370 | `_dev_buckets` list with VOD buckets |
| `app/routers/vod.py` | 30 | `APIRouter(prefix="/ui/videos", tags=["vod"])` |
| `app/routers/vod.py` | 51-66 | `VideoUploadPresignIn`, `VideoUploadPresignOut`, `VideoUploadCompleteOut` |
| `app/routers/vod.py` | 88 | `vod_presign_upload` endpoint |
| `app/routers/vod.py` | 167 | `vod_complete_upload` endpoint |
| `app/routers/video_listing.py` | 40 | `APIRouter(prefix="/ui/videos", tags=["video-listing"])` |
| `app/models_video.py` | 7-23 | `VideoStatus`, `VideoVisibility` type aliases |
| `app/models_video.py` | 36 | `VideoMetadataModel` class |
| `app/services/video_metadata_store.py` | 283 | `create_video()` |
| `app/services/video_metadata_store.py` | 323 | `get_video()` |
| `app/services/video_metadata_store.py` | 402 | `list_videos_by_owner()` |
| `app/services/vod_s3_uploader.py` | 96 | `upload_segment()` |
| `app/services/vod_s3_uploader.py` | 142 | `upload_transcode_outputs()` |
| `app/services/filemanager.py` | 33, 58 | `s3_client` import and instantiation pattern |
| `app/services/filemanager.py` | 2207 | `presign_upload()` |
| `app/services/filemanager.py` | 2264 | `register_presigned_upload()` |
| `app/services/filemanager.py` | 2297 | `head_object()` call for upload validation |
| `app/routers/messaging.py` | 219 | `s3 = s3_client()` |
| `app/routers/messaging.py` | 7914 | `presign_image_upload()` endpoint |
| `app/routers/filemanager.py` | 642-660 | `PresignUploadIn`, `PresignUploadOut`, `CompleteUploadIn` models |
| `app/routers/filemanager.py` | 1921 | `presign_fs_upload` endpoint |
| `app/routers/filemanager.py` | 1942 | `complete_fs_upload` endpoint |
| `scripts/local-ddb-init.py` | 707-737 | `VideoMetadata` table with 5 GSIs |
| `frontend/src/api/endpoints/vod.ts` | 81-84 | `presignVideoUpload`, `completeVideoUpload` |
| `frontend/src/pages/videos/VideosPage.tsx` | — | Video management page |
| `frontend/e2e/video-upload.spec.ts` | — | E2E upload tests |

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|--------------|
| VOD-001 | `VideoMetadata` DynamoDB table, `VideoMetadataModel`, `video_metadata_store.py` CRUD | Implemented | Yes -- VOD-002 only writes records; schema must be stable |
| MEDIA-002 | FFmpeg binary manager (optional: `ffprobe` for duration probing on complete) | Implemented | Yes -- duration probing is optional at upload time |

### Depended On By

| Ticket | What It Needs from VOD-002 |
|--------|---------------------------|
| VOD-003 | Source S3 URI from upload ticket for transcode job input |
| VOD-005 | S3 bucket and key conventions for output uploads |
| VOD-007 | Frontend presign/complete API wrappers (`presignVideoUpload`, `completeVideoUpload`) |
| VOD-011 | E2E test helpers that exercise the upload flow |
| VOD-012 | Source MP4 key for download generation |
| VOD-014 | Upload ticket pattern reused for file-bridge imports |
| VOD-015 | Source file download from S3 for clip extraction |
| VOD-016 | Source file download from S3 for concatenation |

### Merge Strategy

**Independent** -- VOD-002 can be merged independently once VOD-001 is in place. No feature flag required; the endpoints are additive. The router prefix (`/ui/videos`) is shared with VOD-006's listing router but uses distinct path segments (`/upload/presign`, `/upload/complete`).

### Merge Checklist

- [ ] `VideoMetadata` table exists in `scripts/local-ddb-init.py` (VOD-001)
- [ ] `video_upload_bucket` setting populated in `.env.local`
- [ ] VOD buckets included in `_dev_buckets` list in `app/main.py`
- [ ] `vod_router` registered in `app/main.py`
- [ ] E2E sessions seeded (`python3 e2e_session_setup.py`)
- [ ] `just test` passes (unit tests with moto)
- [ ] `just e2e` passes (E2E upload flow tests)
