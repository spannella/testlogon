# BCAST-006: Recording + VOD Archive

**Status**: Implemented

## 1. Overview & Motivation

### Problem Statement

The broadcast system currently supports live streaming with RTMP ingest, ABR transcoding,
and signed playback URLs. When a session stops (transitions from `live` -> `stopping` ->
`stopped`), the S3 archive prefix is stored in `BroadcastOutputModel.s3_archive_prefix`
but there is **no mechanism** to:
<!-- NOTE: This claim is NOW OUTDATED. Recording infrastructure exists:
  `app/services/broadcast_recording.py`, `app/services/broadcast_recording_worker.py`,
  `app/services/broadcast_archive.py`, BroadcastRecordings table (DDB init:567),
  `T.broadcast_recordings` (tables.py:82), `broadcast_recordings_table_name` (settings.py:1137),
  `frontend/e2e/broadcast-recording.spec.ts` -->

1. Register the archive as a playable VOD asset
2. Generate a signed URL for post-live playback
3. Create VOD metadata (duration, thumbnail, manifest) from the raw archive segments
4. Enforce retention policies with proper 410 Gone responses for expired recordings
5. Surface recordings in the frontend dashboard

The raw archive data written by MediaLive's ArchiveGroupSettings (60-second `.ts` segment
rolls configured in `app/services/broadcast_archive.py`) sits in S3 indefinitely, inaccessible
to end users. The only visibility into archive state is via the devtools endpoint
(`/internal/broadcast-dev/status`) which lists raw file paths.

### User Stories

1. **As a broadcaster**, I want my live stream to be automatically recorded so viewers who
   missed the live event can watch the full recording afterward.
2. **As a viewer**, I want to access a VOD recording within 5 minutes of the broadcast ending
   so I can catch up on content I missed.
3. **As a broadcaster**, I want time-limited signed URLs for recordings so I can control who
   has access and for how long.
4. **As a platform operator**, I want recordings to be automatically deleted after the
   configured retention period (default 30 days) so storage costs stay bounded.
5. **As a broadcaster**, I want a "Watch Recording" button on stopped sessions in the
   dashboard so I can preview and share the recording.
6. **As a viewer**, I want expired recordings to return a clear 410 Gone error so I understand
   the content is no longer available (rather than a cryptic 403 or 404).

### Key Acceptance Criteria

- Recording is available within 5 minutes of broadcast end
- Signed URL provides time-limited access (configurable TTL, default 4 hours)
- Recording plays from start to finish without gaps (validated by segment continuity check)
- Expired recordings return HTTP 410 Gone
- Integration with the existing playback entitlement system for access control

---

## 2. Current State Analysis

### 2.1 Broadcast Stop Flow (`app/services/broadcast_orchestrator.py`)

When `stop_session_with_provider()` is called:

```python
def stop_session_with_provider(*, session_id, actor, reason, correlation_id, idempotency_key):
    provider = get_broadcast_provider()
    current = get_session(session_id)
    if current.status in {"ready", "live"}:
        transition_session_status(session_id, to_status="stopping", reason, actor)
        provider.stop(current, correlation_id, idempotency_key)
        current = transition_session_status(session_id, to_status="stopped", reason="provider-stopped", actor)
    return current
```

The flow transitions `live -> stopping -> stopped` but performs **no post-stop processing**.
Once the status reaches `stopped`, the orchestrator returns immediately. There is no hook
to initiate recording finalization.

### 2.2 S3 Archive Structure

The `broadcast_archive.py` module configures MediaLive's `ArchiveGroupSettings`:
- **Bucket**: `S.broadcast_archive_bucket` (default: `"broadcast-archive"`)
- **Prefix root**: `S.broadcast_archive_prefix_root` (default: `"sessions"`)
- **Session path**: `s3://{bucket}/{prefix_root}/{session_id}/`
- **Rollover interval**: 60 seconds (each segment is ~60s of media)
- **Segment naming**: `_archive` name modifier (MediaLive generates: `{prefix}_{timestamp}_archive_{index}.ts`)
- **Retention tag**: `retention: "broadcast"` on the channel, with lifecycle policy via `ensure_archive_lifecycle_policy()`

For the local provider, the archive root is `S.broadcast_local_archive_root` (default:
`"tmp/broadcast-archive"`). The devtools endpoint already lists files in this directory.

### 2.3 FFmpeg ABR Pipeline (`app/services/ffmpeg_abr_pipeline.py`)

The existing FFmpeg pipeline supports:
- Multi-rendition ABR transcoding (1080p, 720p, 540p, 360p via `CANONICAL_ABR_LADDER`)
- HLS output with 2-second segments (`-hls_time 2`)
- Watermark overlay (dynamic text or static image via `WatermarkPolicy`)
- Master playlist generation (`write_master_playlist()`)

Key function: `build_rendition_ffmpeg_args()` accepts an `input_url` (can be a file path or
network URL) and produces HLS output. This can be reused for VOD transcoding by pointing the
input at the concatenated archive file.

> **NOTE**: FFmpeg concat demuxer logic does NOT currently exist in the codebase. The concat
> file format generation and execution must be built from scratch as part of this ticket.
> No existing function handles segment concatenation.

### 2.4 Video Pipeline Contract (`app/contracts/video_pipeline_contract.py`)

The existing `VideoPipelineJobRequest` model defines the interface for submitting transcode
jobs:

```python
class VideoPipelineJobRequest(BaseModel):
    contract_version: Literal["2026-03-video-pipeline-v1"]
    asset: VideoAssetSpec          # asset_id, tenant_id, source_uri, codec info
    renditions: list[VideoRenditionProfile]
    watermark: WatermarkPolicy
    drm: DrmPolicy
    retention_days: int = 30
```

The `VideoPipelineJobEvent` model includes `output_hls_manifest_uri` and
`output_dash_manifest_uri` fields for completed jobs -- these are the playback endpoints
we need to generate for recordings.

### 2.5 Playback Entitlements (`app/services/playback_entitlements.py`)

The entitlement system issues signed JWTs containing:
- `tenant_id`, `asset_id`, `session_id`, `device_id`
- `profile` (rendition)
- Expiration and revocation support

This system can be reused for recording access by treating each recording as a VOD asset with
`asset_id = "recording_{session_id}"`.

### 2.6 Settings Already in Place (`app/core/settings.py`)

Relevant broadcast settings that already exist:
- `broadcast_archive_bucket` / `broadcast_archive_prefix_root` -- S3 location
- `broadcast_archive_retention_days` -- default 30 days
- `broadcast_local_archive_bucket` / `broadcast_local_archive_prefix` / `broadcast_local_archive_root`
- `broadcast_cloudfront_signing_secret` / `broadcast_cloudfront_token_ttl_seconds`

### 2.7 Integration Points Summary

| Component | How it connects to recording |
|-----------|------------------------------|
| `broadcast_orchestrator.stop_session_with_provider` | Post-stop hook triggers recording job |
| `broadcast_archive.build_archive_s3_prefix` | Determines where raw segments live |
| `broadcast_store.get_output` | Reads `s3_archive_prefix` for the session |
| `ffmpeg_abr_pipeline.build_rendition_ffmpeg_args` | Transcodes concatenated archive to ABR HLS |
| `video_pipeline_contract.VideoPipelineJobEvent` | Event model for recording job completion |
| `playback_entitlements.issue_playback_entitlement` | Issues signed token for recording access |
| `broadcast_cloudfront.mint_cloudfront_signed_playback_url` | Generates time-limited signed URL |

---

## 3. Technical Design

### 3.1 Architecture Overview

```
[Broadcast Stop]
       |
       v
[Recording Job Created] ──> DynamoDB: BroadcastRecordings table
       |
       v
[Segment Inventory] ──> S3 ListObjectsV2 on archive prefix
       |
       v
[Segment Concatenation] ──> FFmpeg concat demuxer -> single .ts file
       |
       v
[VOD Transcode] ──> ffmpeg_abr_pipeline -> HLS multi-rendition
       |
       v
[Thumbnail Generation] ──> FFmpeg seek to 10% duration -> single JPEG
       |
       v
[Metadata Finalization] ──> DynamoDB update: duration, manifest_uri, thumbnail_uri, status=ready
       |
       v
[Signed URL Minting] ──> GET /broadcast/sessions/{id}/recording -> signed playback URL
```

### 3.2 Recording Trigger (on Session Stop)

Modify `stop_session_with_provider()` in `app/services/broadcast_orchestrator.py` to invoke
a recording finalization step after the status reaches `stopped`:

```python
def stop_session_with_provider(*, session_id, actor, reason, correlation_id, idempotency_key):
    # ... existing stop logic ...
    current = transition_session_status(session_id, to_status="stopped", ...)

    # NEW: Trigger recording finalization
    _initiate_recording(session_id=session_id, actor=actor, correlation_id=correlation_id)

    return current
```

The `_initiate_recording` function creates a `BroadcastRecordingModel` in DynamoDB with
`status="pending"` and dispatches the processing to a background worker (or executes inline
in dev mode).

### 3.3 Data Model: BroadcastRecordingModel

New Pydantic model in `app/models_broadcast.py`:

```python
BroadcastRecordingStatus = Literal[
    "pending",        # Job created, not yet processing
    "inventorying",   # Listing S3 segments
    "concatenating",  # Merging segments into single file
    "transcoding",    # ABR transcode in progress
    "finalizing",     # Writing metadata, generating thumbnail
    "ready",          # Available for playback
    "expired",        # Past retention period
    "failed",         # Processing failed
]

class BroadcastRecordingModel(BaseModel):
    recording_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    profile_id: str = Field(min_length=1)
    created_by: str = Field(min_length=1)
    status: BroadcastRecordingStatus = "pending"
    s3_archive_prefix: str = ""
    s3_concatenated_key: Optional[str] = None
    s3_manifest_key: Optional[str] = None
    s3_thumbnail_key: Optional[str] = None
    duration_seconds: Optional[float] = None
    segment_count: Optional[int] = None
    total_bytes: Optional[int] = None
    renditions: list[str] = Field(default_factory=list)
    retention_days: int = 30
    expires_at: Optional[str] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    completed_at: Optional[str] = None
```

### 3.4 DynamoDB Table: BroadcastRecordings

| Attribute | Type | Description |
|-----------|------|-------------|
| `recording_id` (PK) | S | UUID |
| `session_id` | S | FK to BroadcastSessions |
| `status` | S | Recording processing status |
| `created_at` | S | ISO timestamp |
| `expires_at` | S | ISO timestamp for retention expiry |

**GSIs:**
- `BySessionId`: PK=`session_id`, SK=`created_at` -- lookup recording by broadcast session
- `ByStatusCreatedAt`: PK=`status`, SK=`created_at` -- find pending/failed recordings
- `ByExpiresAt`: PK=`scope` (fixed "ALL"), SK=`expires_at` -- retention cleanup scan

### 3.5 S3 Segment Storage and Inventory

The recording pipeline starts by inventorying all segments under the archive prefix:

```python
def inventory_recording_segments(*, s3, bucket: str, prefix: str) -> list[RecordingSegment]:
    """List all .ts segments under the archive prefix, sorted by LastModified."""
    segments = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".ts"):
                segments.append(RecordingSegment(
                    key=key,
                    size=obj["Size"],
                    last_modified=obj["LastModified"],
                ))
    segments.sort(key=lambda s: s.last_modified)
    return segments
```

For the local provider, this reads from the filesystem at `S.broadcast_local_archive_root`.

### 3.6 Post-Stream Concatenation

Segments are concatenated using FFmpeg's concat demuxer. This produces a single continuous
transport stream file suitable for ABR transcoding:

```python
def concatenate_segments(
    *,
    segment_paths: list[str],
    output_path: str,
) -> ConcatResult:
    """Generate FFmpeg concat file list and merge segments into one .ts file."""
    concat_list_path = output_path + ".concat.txt"
    with open(concat_list_path, "w") as f:
        for seg in segment_paths:
            f.write(f"file '{seg}'\n")

    args = [
        "ffmpeg", "-hide_banner", "-loglevel", "warning", "-y",
        "-f", "concat", "-safe", "0",
        "-i", concat_list_path,
        "-c", "copy",  # No re-encoding during concat
        output_path,
    ]
    # Execute FFmpeg...
    return ConcatResult(output_path=output_path, duration_seconds=probe_duration(output_path))
```

The concatenated file is stored at:
`s3://{bucket}/{prefix_root}/{session_id}/recording/full.ts`

### 3.7 VOD Metadata Creation and Transcode

After concatenation, a `VideoPipelineJobRequest` is submitted using the existing contract:

```python
def create_vod_transcode_job(*, recording: BroadcastRecordingModel, profile: BroadcastProfileModel) -> str:
    """Submit the concatenated recording to the ABR transcode pipeline."""
    job_request = VideoPipelineJobRequest(
        asset=VideoAssetSpec(
            asset_id=f"recording_{recording.recording_id}",
            tenant_id=recording.created_by,
            source_uri=f"s3://{bucket}/{recording.s3_concatenated_key}",
            input_codec="h264",
            input_fps=30,
            input_width=1920,
            input_height=1080,
            audio_layout="stereo",
        ),
        renditions=[
            VideoRenditionProfile(**r) for r in CANONICAL_ABR_LADDER
        ],
        watermark=WatermarkPolicy(),  # Inherit from profile if configured
        drm=DrmPolicy(profile="none"),
        retention_days=recording.retention_days,
    )
    # Submit to job queue...
    return job_id
```

For the local dev stack (where no SQS job queue exists), the transcode executes inline using
`build_rendition_ffmpeg_args()` from `ffmpeg_abr_pipeline.py` and `write_master_playlist()`.

### 3.8 Thumbnail Generation

A single-frame JPEG thumbnail is extracted at 10% of the recording duration:

```python
def generate_thumbnail(*, input_path: str, output_path: str, seek_percent: float = 0.10, duration_seconds: float) -> str:
    seek_seconds = duration_seconds * seek_percent
    args = [
        "ffmpeg", "-hide_banner", "-loglevel", "warning", "-y",
        "-ss", str(seek_seconds),
        "-i", input_path,
        "-frames:v", "1",
        "-q:v", "2",
        output_path,
    ]
    # Execute FFmpeg...
    return output_path
```

Thumbnail is stored at: `s3://{bucket}/{prefix_root}/{session_id}/recording/thumbnail.jpg`

### 3.9 Recording Playback Endpoint

New endpoint in `app/routers/broadcast.py`:

```python
@router.get("/sessions/{session_id}/recording", response_model=BroadcastRecordingOut)
def get_recording_route(session_id: str, ctx: dict = Depends(_ctx)):
    """Return recording metadata + signed playback URL for a stopped session."""
    recording = get_recording_by_session(session_id)
    if not recording:
        raise HTTPException(status_code=404, detail={
            "code": "BROADCAST_RECORDING_NOT_FOUND",
            "detail": "no recording available for this session"
        })
    if recording.status == "expired":
        raise HTTPException(status_code=410, detail={
            "code": "BROADCAST_RECORDING_EXPIRED",
            "detail": "recording has expired and been deleted"
        })
    if recording.status != "ready":
        raise HTTPException(status_code=202, detail={
            "code": "BROADCAST_RECORDING_PROCESSING",
            "detail": f"recording is being processed (status: {recording.status})"
        })
    # Mint signed playback URL
    signed = mint_recording_playback_url(recording)
    return BroadcastRecordingOut(
        recording_id=recording.recording_id,
        session_id=recording.session_id,
        status=recording.status,
        duration_seconds=recording.duration_seconds,
        playback_url=signed.url,
        playback_expires_at=signed.expires_at,
        thumbnail_url=mint_recording_thumbnail_url(recording),
        created_at=recording.created_at,
        completed_at=recording.completed_at,
    )
```

### 3.10 Signed URL Generation for Recordings

Recording playback URLs follow the same pattern as live CloudFront signed URLs
(`broadcast_cloudfront.py`), with a longer TTL (default 4 hours):

```python
def mint_recording_playback_url(recording: BroadcastRecordingModel, *, ttl_seconds: int | None = None) -> LocalPlaybackUrl:
    ttl = ttl_seconds or S.broadcast_recording_playback_ttl_seconds or 14400  # 4 hours
    path = f"/vod/{recording.session_id}/master.m3u8"
    # Use same signing mechanism as broadcast_cloudfront or broadcast_playback
    ...
```

### 3.11 Retention and Expiry

A background reconciler loop (extending `broadcast_reconciler.py`) scans for recordings past
their `expires_at` timestamp:

```python
def expire_stale_recordings(*, now_ts: int | None = None) -> int:
    """Transition ready recordings past expires_at to 'expired' and delete S3 objects."""
    now = now_ts or _now_ts()
    # Query ByExpiresAt GSI for recordings where expires_at < now
    # For each: delete S3 objects, update status to "expired"
    ...
```

The existing `ensure_archive_lifecycle_policy()` in `broadcast_archive.py` already sets S3
lifecycle rules with the `retention: "broadcast"` tag. This covers the raw segments. The
processed VOD output also gets the same tag applied during upload.

### 3.12 Local Dev Mode (Mock Recording Flow)

In dev mode (`S.dev_mode = True` and `S.broadcast_provider = "local"`), the recording
pipeline operates on the local filesystem:

1. **Segments**: Read from `S.broadcast_local_archive_root / session_id /`
2. **Concatenation**: Local FFmpeg execution (or skip if no segments exist -- write a
   placeholder)
3. **Transcode**: Inline execution using `build_rendition_ffmpeg_args()` (or skip with
   mock manifest if FFmpeg is not available)
4. **Storage**: Output to `tmp/broadcast-vod/{session_id}/` directory
5. **Playback**: Served via `/mock/s3/broadcast-vod/{session_id}/master.m3u8` path (same
   pattern as file manager mock S3 URLs)

For E2E tests where FFmpeg may not be installed, the recording service detects the
absence and creates a mock recording with placeholder metadata (`duration_seconds=0`,
`status="ready"`, synthetic manifest URL).

---

## 4. Implementation Plan

### 4.1 New Files to Create

| File | Purpose |
|------|---------|
| `app/services/broadcast_recording.py` | Recording lifecycle: create, process, query, expire |
| `app/services/broadcast_recording_worker.py` | Background processing: inventory, concat, transcode, thumbnail |
| `tests/test_broadcast_recording.py` | Unit tests for recording service |
| `tests/test_broadcast_recording_worker.py` | Unit tests for worker pipeline |
| `frontend/e2e/broadcast-recording.spec.ts` | E2E tests for recording API + UI |

### 4.2 Files to Modify

| File | Changes |
|------|---------|
| `app/models_broadcast.py` | Add `BroadcastRecordingStatus`, `BroadcastRecordingModel` |
| `app/routers/broadcast.py` | Add `GET /sessions/{id}/recording` endpoint, `BroadcastRecordingOut` model |
| `app/services/broadcast_orchestrator.py` | Add `_initiate_recording()` call in `stop_session_with_provider()` |
| `app/services/broadcast_store.py` | Add recording CRUD functions: `create_recording`, `get_recording_by_session`, `update_recording_status`, `list_expired_recordings` |
| `app/services/broadcast_reconciler.py` | Add `expire_stale_recordings()` to reconciler loop |
| `app/core/settings.py` | Add recording-specific settings (TTL, VOD bucket, worker config) |
| `app/core/tables.py` | Add `T.broadcast_recordings` table handle |
| `scripts/local-ddb-init.py` | Add `BroadcastRecordings` table definition with GSIs |
| `app/main.py` | Register recording background task (if using FastAPI lifespan) |
| `frontend/src/api/endpoints/broadcast.ts` | Add `getRecording()` API wrapper |
| `frontend/src/pages/broadcaster/SessionDetailDialog.tsx` | Add "Watch Recording" button for stopped sessions |

### 4.3 New Settings (`app/core/settings.py`)

```python
# Recording pipeline
broadcast_recording_enabled: bool = os.environ.get("BROADCAST_RECORDING_ENABLED", "1") not in ("0", "false", "False")
broadcast_recording_playback_ttl_seconds: int = int(os.environ.get("BROADCAST_RECORDING_PLAYBACK_TTL_SECONDS", "14400"))  # 4 hours
broadcast_recording_vod_bucket: str = os.environ.get("BROADCAST_RECORDING_VOD_BUCKET", "broadcast-vod")
broadcast_recording_vod_prefix: str = os.environ.get("BROADCAST_RECORDING_VOD_PREFIX", "recordings")
broadcast_recording_thumbnail_quality: int = int(os.environ.get("BROADCAST_RECORDING_THUMBNAIL_QUALITY", "2"))  # FFmpeg -q:v
broadcast_recording_max_segments: int = int(os.environ.get("BROADCAST_RECORDING_MAX_SEGMENTS", "10000"))  # Safety cap
broadcast_recording_worker_inline: bool = os.environ.get("BROADCAST_RECORDING_WORKER_INLINE", os.environ.get("DEV_MODE", "1")) not in ("0", "false", "False")
broadcast_recording_mock_on_no_ffmpeg: bool = os.environ.get("BROADCAST_RECORDING_MOCK_ON_NO_FFMPEG", "1") not in ("0", "false", "False")
```

### 4.4 DynamoDB Table Definition (`scripts/local-ddb-init.py`)

```python
TableDef(
    _resolve_table_name(S.broadcast_recordings_table_name, "BroadcastRecordings"),
    "recording_id",
    gsi=[
        {"index_name": "BySessionId", "partition_key": "session_id", "sort_key": "created_at"},
        {"index_name": "ByStatusCreatedAt", "partition_key": "status", "sort_key": "created_at"},
        {"index_name": "ByExpiresAt", "partition_key": "scope", "sort_key": "expires_at"},
    ],
),
```

### 4.5 Step-by-Step Implementation Order

**Phase 1: Data Model + Storage Layer (2 hours)**

1. Add `BroadcastRecordingStatus` and `BroadcastRecordingModel` to `app/models_broadcast.py`
2. Add `broadcast_recordings_table_name` setting to `app/core/settings.py`
3. Add `T.broadcast_recordings` to `app/core/tables.py`
4. Add table definition to `scripts/local-ddb-init.py`
5. Implement CRUD in `app/services/broadcast_store.py`:
   - `create_recording(session_id, profile_id, created_by, s3_archive_prefix, retention_days)`
   - `get_recording(recording_id)`
   - `get_recording_by_session(session_id)` (query BySessionId GSI, return latest)
   - `update_recording_status(recording_id, status, **kwargs)`
   - `list_recordings_by_status(status, limit)`
   - `list_expired_recordings(now_iso, limit)`

**Phase 2: Recording Service Core (3 hours)**

1. Create `app/services/broadcast_recording.py`:
   - `initiate_recording(session_id, actor, correlation_id)` -- creates recording row, returns model
   - `inventory_segments(recording_id)` -- lists S3/local segments, updates segment_count + total_bytes
   - `concatenate_recording(recording_id)` -- FFmpeg concat, updates s3_concatenated_key
   - `transcode_recording(recording_id)` -- ABR pipeline, updates s3_manifest_key + renditions
   - `generate_recording_thumbnail(recording_id)` -- extracts JPEG, updates s3_thumbnail_key
   - `finalize_recording(recording_id)` -- sets status=ready, computes expires_at
   - `fail_recording(recording_id, error_code, error_message)` -- sets status=failed

2. Create `app/services/broadcast_recording_worker.py`:
   - `process_recording(recording_id)` -- orchestrates the full pipeline (inventory -> concat -> transcode -> thumbnail -> finalize)
   - Handles each step with try/except, updating status on failure
   - In dev mode with `broadcast_recording_worker_inline=True`, runs synchronously
   - In production, this would be triggered by SQS message (future ticket)

**Phase 3: Orchestrator Integration (1 hour)**

1. Modify `stop_session_with_provider()` in `app/services/broadcast_orchestrator.py`:
   - After successful stop, call `initiate_recording()` if `S.broadcast_recording_enabled`
   - If `S.broadcast_recording_worker_inline`, call `process_recording()` directly
   - Otherwise, publish to SQS queue (stubbed for now, full SQS wiring is out of scope)

2. Add audit logging: `record_broadcast_action(action="initiate_recording", ...)`

**Phase 4: API Endpoint (1 hour)**

1. Add `BroadcastRecordingOut` response model to `app/routers/broadcast.py`:
   ```python
   class BroadcastRecordingOut(BaseModel):
       recording_id: str
       session_id: str
       status: str
       duration_seconds: Optional[float] = None
       playback_url: Optional[str] = None
       playback_expires_at: Optional[int] = None
       thumbnail_url: Optional[str] = None
       segment_count: Optional[int] = None
       total_bytes: Optional[int] = None
       renditions: list[str] = Field(default_factory=list)
       created_at: str
       completed_at: Optional[str] = None
       expires_at: Optional[str] = None
   ```

2. Add `GET /broadcast/sessions/{session_id}/recording` endpoint:
   - Returns 404 if no recording exists
   - Returns 410 if recording is expired
   - Returns 202 (with body) if recording is still processing
   - Returns 200 with signed playback URL if recording is ready

3. Add signed URL minting (reuse `broadcast_playback.py` pattern with VOD-specific path)

**Phase 5: Retention + Reconciler (1 hour)**

1. Add `expire_stale_recordings()` to `app/services/broadcast_reconciler.py`:
   - Query `ByExpiresAt` GSI for recordings where `expires_at < now`
   - Delete S3 objects (concatenated file, VOD renditions, thumbnail)
   - Update status to `"expired"`

2. Wire into existing reconciler loop (runs every `broadcast_reconciler_interval_seconds`)

**Phase 6: Frontend Integration (2 hours)**

1. Add `getRecording` to `frontend/src/api/endpoints/broadcast.ts`:
   ```typescript
   export interface BroadcastRecording {
     recording_id: string;
     session_id: string;
     status: string;
     duration_seconds: number | null;
     playback_url: string | null;
     playback_expires_at: number | null;
     thumbnail_url: string | null;
     segment_count: number | null;
     total_bytes: number | null;
     renditions: string[];
     created_at: string;
     completed_at: string | null;
     expires_at: string | null;
   }

   export const getRecording = (sessionId: string) =>
     api.get<BroadcastRecording>(`/broadcast/sessions/${sessionId}/recording`);
   ```

2. Add "Watch Recording" button to `SessionDetailDialog.tsx`:
   - Visible only when session status is `"stopped"`
   - Uses `useQuery` with key `["broadcast", "recording", sessionId]`
   - Shows loading state while recording is processing (status != "ready")
   - Opens video player dialog with signed HLS URL when ready
   - Shows "Recording expired" message if 410

3. Reuse `LivePlayer` component in VOD mode (set `autoplay=false`, show duration/seek bar)

### 4.6 Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| BCAST-003 (MediaLive execution) | Required | Real archive writes depend on MediaLive being wired |
| FFmpeg binary on host | Optional | Mock recording if unavailable (dev/CI) |
| S3 bucket for VOD output | Required | `broadcast-vod` bucket must exist (add to `local-ddb-init.py` or startup) |
| `broadcast_archive.py` (archive prefix) | Exists | Used to locate raw segments |
| `ffmpeg_abr_pipeline.py` (transcode) | Exists | Reused for VOD rendition generation |
| `broadcast_playback.py` (URL signing) | Exists | Pattern reused for recording URLs |
| `broadcast_store.py` (DDB CRUD) | Exists | Extended with recording functions |

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_recording.py`

**Mock setup**: moto mock for DynamoDB (broadcast tables). Mock broadcast provider for instant state transitions.

| Test Function | Description |
|---|---|
| `test_create_bcast006_resource` | Create primary resource; verify stored in DDB with correct fields |
| `test_get_bcast006_resource` | Get resource by ID; verify all fields returned |
| `test_list_bcast006_resources` | List resources; verify pagination and filtering |
| `test_update_bcast006_resource` | Update resource; verify changed fields persisted |
| `test_delete_bcast006_resource` | Delete resource; verify removed from DDB |
| `test_validation_rejects_invalid_input` | Missing required fields returns 422; invalid values return 400 |
| `test_authorization_enforced` | Non-owner/non-admin access returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle: create -> read -> update -> delete through real DDB
2. Cross-service integration with broadcast session store
3. Concurrent operations do not corrupt shared state

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcast-recording.spec.ts`

**Auth pattern**: `injectAuth(page, "root")` for admin operations; `injectAuth(page, "alice")` for viewer operations; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates resource successfully | POST returns 200/201 with resource ID |
| 2 | API returns resource by ID | GET returns full resource with all expected fields |
| 3 | API lists resources with pagination | GET list returns array; supports cursor pagination |
| 4 | API updates resource fields | PATCH/PUT returns updated resource |
| 5 | API deletes resource | DELETE returns 200; subsequent GET returns 404 |
| 6 | UI page loads with expected heading | Navigate to page; heading visible |
| 7 | UI form creates new resource | Fill form; submit; resource appears in list |
| 8 | UI shows error for invalid input | Submit empty form; validation messages visible |
| 9 | Unauthenticated request returns 401 | No session cookies -> 401 |
| 10 | Non-owner access returns 403 | Wrong user -> 403 |
| 11 | Non-existent resource returns 404 | GET invalid ID -> 404 |
| 12 | Duplicate creation returns 409 | Create same resource twice -> 409 or idempotent success |

**Negative tests**: 401 unauthenticated, 403 non-owner, 404 not found, 409 conflict/duplicate, 422 validation

**Edge cases**: Empty state (no resources), concurrent mutations, resource with max-length fields, Unicode content

### Test Data Requirements

Seed broadcast session in `beforeAll`. Create test resources via API with unique `Date.now()` suffixed names.

**Test users**: Root (ROOT, admin operations), Alice (USER, standard operations), Bob (USER, cross-user isolation)

### CI/Pipeline

Serial execution. `BROADCAST_PROVIDER=local`. Retry-safe with unique resource names.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| BCAST-001 | Broadcast session lifecycle and S3 archive prefix | Implemented | Yes |

### Depended On By

| Ticket | What It Needs |
|---|---|
| BCAST-008 | Recording storage for MP4 download conversion |

### Merge Strategy

Independent. New DDB table (`BroadcastRecordings`), new service (`broadcast_recording.py`). Feature-flag-gated via `broadcast_recording_enabled`.

### Merge Checklist

- [ ] DDB table/fields added to `scripts/local-ddb-init.py` (if new table needed)
- [ ] Settings added to `app/core/settings.py`
- [ ] Service and router files created/modified
- [ ] Frontend components and API wrappers created
- [ ] E2E test passes in CI
- [ ] No breaking changes to existing endpoints

---

## Codebase References

| File | Status | Notes |
|------|--------|-------|
| `app/services/broadcast_recording.py` | EXISTS | Recording service |
| `app/services/broadcast_recording_worker.py` | EXISTS | Background recording worker |
| `app/services/broadcast_archive.py` | EXISTS | S3 archive helpers |
| `app/core/settings.py:1137` | EXISTS | `broadcast_recordings_table_name` |
| `app/core/settings.py:480-482` | EXISTS | Archive bucket, prefix, retention settings |
| `app/core/tables.py:82` | EXISTS | `T.broadcast_recordings` handle |
| `scripts/local-ddb-init.py:567-576` | EXISTS | BroadcastRecordings table with GSI |
| `frontend/e2e/broadcast-recording.spec.ts` | EXISTS | E2E tests |
| `frontend/src/api/endpoints/broadcast.ts` | EXISTS | API wrappers |

### Key Note
- Ticket references `frontend/src/pages/broadcaster/SessionDetailDialog.tsx` but broadcast pages are at `frontend/src/pages/broadcast/` (not `broadcaster/`). No `SessionDetailDialog.tsx` exists as a separate file; session detail may be inline in `BroadcastPage.tsx`.
