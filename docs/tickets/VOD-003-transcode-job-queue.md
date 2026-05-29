# VOD-003: Async Transcode Job Queue and Worker

**Ticket**: VOD-003
**Status**: Implemented
**Author**: Platform Engineering
**Date**: 2026-05-24

---

## 1. Overview & Motivation

### Problem Statement

The video pipeline contract (`app/contracts/video_pipeline_contract.py` -- see `VideoPipelineJobRequest` at line 41, `VideoPipelineJobEvent` at line 56) defines a structured job submission schema and event model for multi-rendition ABR transcoding. The FFmpeg ABR pipeline (`app/services/ffmpeg_abr_pipeline.py` -- see `build_rendition_ffmpeg_args()` at line 50, `write_master_playlist()` at line 145) provides the building blocks to construct per-rendition FFmpeg command lines with watermark overlays. However, there is no orchestration layer that accepts a job request, persists it, tracks its progress through states (accepted -> running -> completed/failed), manages concurrency, or retries on failure.

Today, any video processing that happens in the platform occurs either synchronously within a request handler (the `_run_media_tool` function in `app/services/filemanager.py`, used for thumbnail generation and media inspection) or as ad-hoc shell invocations. Neither approach is suitable for long-running multi-rendition transcoding jobs that may take 5-60+ minutes per asset.

### Why Async Processing Is Required

1. **Request timeout constraints**: HTTP requests cannot block for the duration of a transcode job. The platform runs behind ALBs/CloudFront with 60-second idle timeouts. A 4-rendition 1080p transcode of a 30-minute source takes 15-45 minutes.

2. **Resource isolation**: FFmpeg processes consume significant CPU, memory, and disk I/O. Running them inline with the API process would starve request handling. The existing `filemanager._run_media_tool` uses `subprocess.run` with a 120-second timeout - acceptable for thumbnails, not for full transcodes.

3. **Observability**: Transcoding must report progress (percentage, current rendition, ETA) to both the submitter (via polling/SSE) and admin dashboards.

4. **Reliability**: Transient failures (disk full, source unavailable, OOM kill) must trigger automatic retry with exponential backoff, without requiring the user to resubmit.

5. **Concurrency control**: A single host can process at most N concurrent transcode jobs (bounded by CPU cores and available disk). Without a queue, burst uploads would fork unbounded FFmpeg processes.

### Dev Mode vs. Production Mode

The design follows the same dual-mode pattern used throughout the platform:

- **Dev mode** (`S.dev_mode = True`): An in-process asyncio worker loop polls DynamoDB for pending jobs and runs FFmpeg locally via `subprocess`. No external queue infrastructure required. Mirrors the pattern used by `start_broadcast_reconciler_task()`, `start_billing_reconcile_task()`, `start_billing_dunning_task()`, and `start_scheduled_messages_task()`.

<!-- NOTE: The transcode worker ALREADY EXISTS at `app/services/transcode_worker.py`.
     It implements `transcode_worker_loop()` (line 38), `execute_transcode_job()` (line 86),
     `_run_ffmpeg_for_rendition()` (line 234), and `start_transcode_worker_task()` (line 334).
     Registration is at `app/main.py:471`. -->

- **Production mode**: SQS queue + Lambda (or ECS Fargate task) workers. The API writes a job record to DynamoDB and publishes a message to SQS. Workers pull from SQS, perform the transcode, upload outputs to S3, and update the DynamoDB job record. The existing `sqs_client()` factory in `app/core/aws_clients.py` and the SQS poller pattern in `app/routers/newsfeed.py` (lines 1955-1996) provide working precedent for SQS integration.

---

## 2. Current State Analysis

### Existing Background Task Patterns

The codebase uses a consistent pattern for long-running background loops, visible in six places:

| Task | Source | Interval | Registration |
|------|--------|----------|--------------|
| Broadcast reconciler | `app/services/broadcast_reconciler.py` | 30s | `app.add_event_handler("startup", start_broadcast_reconciler_task)` |
| Billing reconciliation | `app/services/billing_reconcile.py` | 60s | `app.add_event_handler("startup", start_billing_reconcile_task)` |
| Billing dunning | `app/services/billing_dunning.py` | 60s | `app.add_event_handler("startup", start_billing_dunning_task)` |
| Scheduled messages | `app/routers/messaging.py` | 30s | `app.add_event_handler("startup", start_scheduled_messages_task)` |
| File purge | `app/services/filemanager.py` | configurable | `app.add_event_handler("startup", start_filemgr_purge_task)` |
| Projects reconcile | `app/services/projects_reconcile.py` | 30s | `app.add_event_handler("startup", start_projects_reconcile_task)` |
| Mount reconcile | `app/services/filemanager_mount_reconcile.py` | configurable | `app.add_event_handler("startup", start_filemgr_mount_reconcile_task)` |

**Common anatomy:**

```python
async def some_loop() -> None:
    interval = max(MIN, int(S.some_interval_seconds))
    while True:
        try:
            do_work()
        except Exception:
            logger.exception("loop failed")
        await asyncio.sleep(interval)

def start_some_task() -> None:
    if not S.some_enabled:
        return
    asyncio.create_task(some_loop())
```

This pattern is well-understood, reliable for single-process dev mode, and easily testable (call `do_work()` directly in unit tests).

### Broadcast Reconciler as Direct Precedent

The broadcast reconciler (`app/services/broadcast_reconciler.py`) is the closest architectural precedent for the transcode worker because:

1. It iterates over items in a specific state (`ACTIVE_STATES`) from DynamoDB.
2. It evaluates each item against desired vs. actual state.
3. It transitions items to new states on drift detection (analogous to job state transitions).
4. It records metrics (`record_broadcast_drift_incident`).
5. It has configurable parameters (`broadcast_reconciler_interval_seconds`, `broadcast_drift_sla_seconds`, `broadcast_stale_session_seconds`).
6. It is gated by a feature flag (`broadcast_reconciler_enabled`).

### What Does NOT Exist Today

<!-- NOTE: ALL of the items below have SINCE BEEN IMPLEMENTED. This section is outdated. -->

- **~~No job queue table~~**: `TranscodeJobs` table EXISTS at `scripts/local-ddb-init.py:739-760` with GSIs `ByStatusCreatedAt`, `ByVideoId`, `ByTenantStatus`.
- **~~No worker process~~**: `app/services/transcode_worker.py` EXISTS with `transcode_worker_loop()` (line 38), `execute_transcode_job()` (line 86), registered at `app/main.py:471`.
- **~~No progress tracking~~**: `app/services/transcode_job_store.py:update_job_progress()` (line 116) persists progress. `complete_job_with_outputs()` (line 181) records outputs.
- **~~No concurrency limiter~~**: `_process_job_with_semaphore()` at `app/services/transcode_worker.py:80` uses `asyncio.Semaphore`.
- **~~No retry logic~~**: `_compute_next_retry_at()` at `app/services/transcode_job_store.py:344` implements exponential backoff. `fail_job()` (line 244) handles retry vs terminal failure.
- **No SQS queue for video jobs**: The only SQS integration is the newsfeed SSE fan-out poller (`EVENTS_SQS_URL`) and the Jira outbound sync (`app/services/jira_outbound_sync.py`). SQS for transcode is still not implemented (dev mode only).

### Video Pipeline Components Already Built

The following building blocks are in place and ready for orchestration:

- `app/contracts/video_pipeline_contract.py` - Job request/response/event Pydantic models (`VideoPipelineJobRequest` at line 41, `VideoPipelineJobEvent` at line 56)
- `app/contracts/video_rendition_profiles.py` - Canonical ABR ladder (`CanonicalRenditionProfile` TypedDict at line 8, helper functions at lines 60-64)
- `app/contracts/watermark_policy.py` - Watermark configuration model (`WatermarkPolicy` at line 43, `TenantWatermarkSettings` at line 69)
- `app/services/ffmpeg_abr_pipeline.py` - `build_rendition_ffmpeg_args()` (line 50) constructs FFmpeg CLI for one rendition; `write_master_playlist()` (line 145) writes the HLS master manifest
- `app/services/video_pipeline_contract_service.py` - `validate_video_pipeline_job()` (line 17) validates incoming payloads; `contract_capabilities_snapshot()` (line 38) returns pipeline metadata
- `app/services/video_abr_profile_exports.py` - Exports rendition profiles for FFmpeg and MediaLive
- `app/services/watermark_profile_renderers.py` - Generates FFmpeg filter strings and MediaLive settings from watermark policy

---

## 3. Technical Design

### 3.1 Architecture Diagram

```
  +-----------------+
  |   Creator UI    |
  | (VideosPage)    |
  +-----------------+
        |
        | POST /ui/transcode-jobs (submit)
        | GET  /ui/transcode-jobs/{id} (poll status)
        | GET  /ui/transcode-jobs (list)
        | DELETE /ui/transcode-jobs/{id} (cancel)
        v
  +-----------------+       +-----------------------+
  | transcode_jobs  |       | transcode_job_submit  |
  |   Router        |------>|   Service             |
  +-----------------+       +-----------------------+
                                   |
                                   | 1. Validate via VideoPipelineJobRequest
                                   | 2. create_job() -> DDB (status=pending)
                                   | 3. [prod] SQS send_message()
                                   v
                            +-----------------------+
                            | transcode_job_store   |
                            |   (DDB CRUD)          |
                            +-----------------------+
                                   |
                                   | TranscodeJobs table
                                   v
                            +-----------------------+
                            |   TranscodeJobs DDB   |
                            +-----------------------+
                            | PK: job_id            |
                            | ByStatusCreatedAt:    |
                            |   status / created_at |
                            | ByVideoId:            |
                            |   video_id / created_at|
                            | ByTenantStatus:       |
                            |   tenant_id /         |
                            |   status_created_at   |
                            +-----------------------+
<!-- NOTE: Actual GSI names (see local-ddb-init.py:739-760) are
     `ByStatusCreatedAt`, `ByVideoId`, `ByTenantStatus`
     — not `GSI-Status` and `GSI-TenantStatus` as in the original spec. -->
                                   ^
                                   |
                    +--------------+------------------+
                    |                                  |
          [Dev Mode]                        [Prod Mode]
  +---------------------+            +---------------------+
  | transcode_worker    |            |   SQS FIFO Queue    |
  |  (asyncio loop)     |            +---------------------+
  +---------------------+                     |
  | 1. poll_pending()   |            +---------------------+
  | 2. claim_job()      |            | Lambda / ECS Worker |
  | 3. download source  |            +---------------------+
  | 4. per-rendition:   |            | 1. receive message  |
  |    FFmpeg exec      |            | 2. claim_job()      |
  |    progress update  |            | 3. transcode        |
  | 5. upload outputs   |            | 4. upload outputs   |
  | 6. complete/fail    |            | 5. complete/fail    |
  +---------------------+            | 6. delete message   |
        |                            +---------------------+
        | asyncio.create_subprocess_exec
        v
  +---------------------+
  |   FFmpeg Process    |
  | -progress pipe:1    |
  | (per rendition)     |
  +---------------------+
        |
        | stdout: out_time_us=...
        v
  +---------------------+       +---------------------+
  | Progress Parser     |------>| update_progress()   |
  | (throttled 5s)      |       | (DDB conditional)   |
  +---------------------+       +---------------------+
        |
        | On success:
        v
  +---------------------+       +---------------------+
  | write_master_       |------>| S3 upload           |
  |  playlist()         |       | (outputs to bucket) |
  +---------------------+       +---------------------+
        |
        v
  +---------------------+       +---------------------+
  | complete_job()      |------>| _emit_job_event()   |
  | (DDB update)        |       | (alerts/SSE)        |
  +---------------------+       +---------------------+

Retry Flow:
  FFmpeg fails -> RetryableError
    -> attempt < max_attempts?
       Yes -> status=pending, next_retry_at=now+backoff, attempt++
       No  -> status=failed, emit alert
```

### 3.2 DynamoDB Job Model

**Table**: `TranscodeJobs`
**Partition key**: `job_id` (S)
**Sort key**: None (single-item table, one row per job)

**GSIs** (actual names from `scripts/local-ddb-init.py:739-760`):
- `ByStatusCreatedAt`: PK = `status` (S), SK = `created_at` (N)
  - Enables: worker polling for `status=pending` jobs ordered by creation time
  - `attr_types={"created_at": "N"}` required (numeric GSI sort key - see CLAUDE.md gotchas)
- `ByVideoId`: PK = `video_id` (S), SK = `created_at` (N)
  - Enables: listing all jobs for a given video
- `ByTenantStatus`: PK = `tenant_id` (S), SK = `status_created_at` (S)
  - Enables: "list all pending jobs for tenant X", "list all failed jobs for tenant X"
<!-- NOTE: The original spec used names `GSI-Status` and `GSI-TenantStatus`.
     The actual implementation uses `ByStatusCreatedAt`, `ByVideoId`, `ByTenantStatus`. -->

**Item schema**:

```python
{
    "job_id": "tj_<uuid4-hex>",               # PK
    "tenant_id": "tenant_abc",
    "asset_id": "asset_xyz",
    "status": "pending",                       # pending | running | completed | failed | cancelled
    "created_at": 1716508800,                  # now_ts()
    "updated_at": 1716508800,
    "started_at": None,                        # set when worker picks up
    "completed_at": None,                      # set on success/failure
    "worker_id": None,                         # hostname/pid of worker that claimed it
    "attempt": 0,                              # current attempt number (0-indexed)
    "max_attempts": 3,
    "next_retry_at": None,                     # for failed jobs awaiting retry
    "priority": 0,                             # 0=normal, negative=higher priority

    # Input (stored from VideoPipelineJobRequest)
    "contract_version": "2026-03-video-pipeline-v1",
    "source_uri": "s3://uploads/raw/video.mp4",
    "input_codec": "h264",
    "input_fps": 30,
    "input_width": 1920,
    "input_height": 1080,
    "audio_layout": "stereo",
    "renditions": [...],                       # list of VideoRenditionProfile dicts
    "watermark": {...},                        # WatermarkPolicy dict
    "drm": {...},                              # DrmPolicy dict
    "retention_days": 30,

    # Progress (updated by worker)
    "progress_pct": 0,                         # 0-100
    "current_rendition": None,                 # e.g. "720p"
    "renditions_completed": [],                # ["360p", "540p"]
    "eta_seconds": None,

    # Output (populated on success)
    "output_hls_manifest_uri": None,
    "output_dash_manifest_uri": None,
    "output_s3_prefix": None,

    # Error (populated on failure)
    "error_code": None,                        # "ffmpeg_exit_1", "source_not_found", "disk_full", "timeout"
    "error_message": None,
    "error_details": None,                     # stack trace or FFmpeg stderr (truncated to 4KB)

    # TTL
    "ttl": 1716508800 + (30 * 86400),         # auto-delete after retention_days
}
```

### 3.3 DynamoDB Access Patterns

| Access Pattern | Table | PK | SK / Index | Operation | Expected Latency |
|---------------|-------|-----|------------|-----------|-----------------|
| Get job by ID | TranscodeJobs | `job_id` | Table PK | `get_item(ConsistentRead=True)` | ~5ms |
| Create job | TranscodeJobs | `job_id` | Table PK | `put_item(Condition=attr_not_exists)` | ~8ms |
| Claim job (worker) | TranscodeJobs | `job_id` | Table PK | `update_item(Condition=status=pending)` | ~8ms |
| Update progress | TranscodeJobs | `job_id` | Table PK | `update_item(Condition=worker_id=me)` | ~8ms |
| Complete job | TranscodeJobs | `job_id` | Table PK | `update_item(Condition=worker_id=me)` | ~8ms |
| Fail job (retry) | TranscodeJobs | `job_id` | Table PK | `update_item` | ~8ms |
| Cancel job | TranscodeJobs | `job_id` | Table PK | `update_item(Condition=status IN pending,running)` | ~8ms |
| Poll pending jobs | TranscodeJobs | `status=pending` | GSI-Status, `ScanIndexForward=True` | `query(Limit=N)` | ~10ms |
| List tenant jobs | TranscodeJobs | `tenant_id` | GSI-TenantStatus, begins_with `status#` | `query` | ~10ms |

#### Example DynamoDB Items

**Newly submitted job** (status=pending):
```json
{
  "job_id": "tj_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "tenant_id": "tenant_abc",
  "asset_id": "v_f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6",
  "status": "pending",
  "status_created_at": "pending#1748500000",
  "created_at": 1748500000,
  "updated_at": 1748500000,
  "attempt": 0,
  "max_attempts": 3,
  "priority": 0,
  "contract_version": "2026-03-video-pipeline-v1",
  "source_uri": "s3://uploads/raw/e2e_alice/tutorial.mp4",
  "input_codec": "h264",
  "input_fps": 30,
  "input_width": 1920,
  "input_height": 1080,
  "audio_layout": "stereo",
  "renditions": [
    {"name": "1080p", "width": 1920, "height": 1080, "bitrate_kbps": 5000},
    {"name": "720p", "width": 1280, "height": 720, "bitrate_kbps": 2500},
    {"name": "480p", "width": 854, "height": 480, "bitrate_kbps": 1200}
  ],
  "watermark": {"mode": "none"},
  "drm": {"profile": "none"},
  "retention_days": 30,
  "progress_pct": 0,
  "renditions_completed": [],
  "ttl": 1751092000
}
```

**Running job with progress** (status=running, 2 of 3 renditions done):
```json
{
  "job_id": "tj_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "tenant_id": "tenant_abc",
  "asset_id": "v_f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6",
  "status": "running",
  "status_created_at": "running#1748500000",
  "created_at": 1748500000,
  "updated_at": 1748501500,
  "started_at": 1748500010,
  "worker_id": "devhost:12345",
  "attempt": 0,
  "progress_pct": 78,
  "current_rendition": "1080p",
  "renditions_completed": ["480p", "720p"],
  "eta_seconds": 180
}
```

**Completed job** (status=completed):
```json
{
  "job_id": "tj_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "status": "completed",
  "status_created_at": "completed#1748500000",
  "completed_at": 1748502000,
  "progress_pct": 100,
  "renditions_completed": ["480p", "720p", "1080p"],
  "output_hls_manifest_uri": "s3://vod-output/tenants/tenant_abc/assets/v_f1e2d3/hls/master.m3u8",
  "output_s3_prefix": "tenants/tenant_abc/assets/v_f1e2d3/hls/"
}
```

**Failed job after max retries** (status=failed):
```json
{
  "job_id": "tj_b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7",
  "status": "failed",
  "status_created_at": "failed#1748510000",
  "completed_at": 1748512000,
  "attempt": 3,
  "max_attempts": 3,
  "error_code": "ffmpeg_exit_nonzero",
  "error_message": "FFmpeg exited with code 1",
  "error_details": "[libx264 @ 0x...] Error: height not divisible by 2 (1920x1079)\n..."
}
```

### 3.4 Job State Machine

```
                 submit
                   |
                   v
              [pending] -----> [cancelled]  (user cancellation)
                   |
                   | worker claims (conditional write: status=pending)
                   v
              [running] -----> [cancelled]  (user cancellation, sends SIGTERM)
                   |
          +--------+--------+
          |                 |
     (success)         (failure)
          |                 |
          v                 v
     [completed]     attempt < max_attempts?
                        |           |
                       yes          no
                        |           |
                        v           v
                   [pending]    [failed]
                   (next_retry_at set,
                    attempt incremented)
```

**State transition rules** (enforced via DynamoDB conditional expressions):

| From | To | Condition |
|------|----|-----------|
| pending | running | `status = pending AND (next_retry_at IS NULL OR next_retry_at <= now)` |
| pending | cancelled | `status = pending` |
| running | completed | `status = running AND worker_id = <this_worker>` |
| running | pending | `status = running AND worker_id = <this_worker>` (retry) |
| running | failed | `status = running AND worker_id = <this_worker> AND attempt >= max_attempts` |
| running | cancelled | `status IN (pending, running)` |

All transitions use `ConditionExpression` to prevent race conditions. If the conditional write fails with `ConditionalCheckFailedException`, the worker abandons the job (another worker or cancellation won).

### 3.5 Error Handling Matrix

| Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---------------|-------------|------------|---------------------|-----------------|
| Job not found | 404 | `JOB_NOT_FOUND` | "Transcode job not found" | Verify job ID |
| Invalid job request (validation) | 422 | `VALIDATION_ERROR` | "Invalid transcode job request: {details}" | Fix request fields |
| Source file not found in S3 | 400 | `SOURCE_NOT_FOUND` | "Source video file not found" | Re-upload source file |
| Invalid codec in source | 400 | `INVALID_CODEC` | "Source video codec not supported" | Convert to supported codec |
| Cancel completed job | 409 | `CANNOT_CANCEL_COMPLETED` | "Cannot cancel a completed job" | None |
| Cancel already-cancelled job | 409 | `ALREADY_CANCELLED` | "Job is already cancelled" | None |
| FFmpeg process crashed | N/A (internal) | `ffmpeg_exit_nonzero` | "Transcoding failed (will retry)" | Automatic retry |
| Disk full during transcode | N/A (internal) | `disk_full` | "Transcoding failed due to disk space" | Automatic retry |
| Rendition timeout | N/A (internal) | `timeout` | "Transcoding timed out" | Automatic retry |
| S3 upload failed | N/A (internal) | `s3_upload_failed` | "Failed to upload outputs" | Automatic retry |
| Max retries exhausted | N/A (internal) | `max_retries_exhausted` | "Transcoding failed after {N} attempts" | Manual re-submit |
| Per-tenant concurrency limit | 429 | `TENANT_THROTTLED` | "Too many concurrent jobs. Please wait." | Wait for running jobs |
| Contract validation failed | 422 | `CONTRACT_VALIDATION_ERROR` | "Job specification does not match pipeline contract" | Fix rendition profiles |
| Worker claim race condition | N/A (internal) | `claim_failed` | N/A (transparent to user) | Another worker processes job |

### 3.6 Pydantic Models for API Layer

```python
# -- Transcode Job API Models (VOD-003) --

class TranscodeJobSubmitIn(BaseModel):
    """Request body for job submission."""
    asset_id: str = Field(min_length=1, max_length=100)
    source_uri: str = Field(min_length=1, max_length=500)
    renditions: List[Dict[str, Any]] = Field(min_length=1, max_length=6)
    watermark: Optional[Dict[str, Any]] = None
    drm: Optional[Dict[str, Any]] = None
    priority: int = Field(default=0, ge=-10, le=10)
    max_attempts: int = Field(default=3, ge=1, le=10)
    retention_days: int = Field(default=30, ge=1, le=365)

    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": "v_abc123",
                "source_uri": "s3://uploads/raw/video.mp4",
                "renditions": [
                    {"name": "1080p", "width": 1920, "height": 1080, "bitrate_kbps": 5000},
                    {"name": "720p", "width": 1280, "height": 720, "bitrate_kbps": 2500}
                ],
                "priority": 0,
                "max_attempts": 3,
            }
        }

class TranscodeJobOut(BaseModel):
    """Response model for job status."""
    job_id: str
    tenant_id: str
    asset_id: str
    status: str  # pending | running | completed | failed | cancelled
    created_at: int
    updated_at: int
    started_at: Optional[int] = None
    completed_at: Optional[int] = None
    attempt: int = 0
    max_attempts: int = 3
    progress_pct: int = 0
    current_rendition: Optional[str] = None
    renditions_completed: List[str] = Field(default_factory=list)
    eta_seconds: Optional[int] = None
    output_hls_manifest_uri: Optional[str] = None
    output_s3_prefix: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "job_id": "tj_a1b2c3d4",
                "tenant_id": "tenant_abc",
                "asset_id": "v_abc123",
                "status": "running",
                "created_at": 1748500000,
                "updated_at": 1748501000,
                "started_at": 1748500010,
                "attempt": 0,
                "max_attempts": 3,
                "progress_pct": 45,
                "current_rendition": "720p",
                "renditions_completed": ["480p"],
                "eta_seconds": 300,
            }
        }

class TranscodeJobListOut(BaseModel):
    """Response model for job listing."""
    items: List[TranscodeJobOut] = Field(default_factory=list)
    cursor: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "items": [],
                "cursor": None,
            }
        }
```

### 3.7 In-Process Asyncio Worker (Dev Mode)

For `S.dev_mode = True`, the worker runs as an asyncio background task, identical in structure to the broadcast reconciler:

```python
# app/services/transcode_worker.py

_CONCURRENCY_SEMAPHORE: asyncio.Semaphore | None = None

async def transcode_worker_loop() -> None:
    global _CONCURRENCY_SEMAPHORE
    max_concurrent = max(1, int(S.transcode_max_concurrent_jobs or 2))
    _CONCURRENCY_SEMAPHORE = asyncio.Semaphore(max_concurrent)
    poll_interval = max(5, int(S.transcode_worker_poll_interval_seconds or 10))

    while True:
        try:
            jobs = poll_pending_jobs(limit=max_concurrent)
            for job in jobs:
                if _CONCURRENCY_SEMAPHORE.locked():
                    break
                asyncio.create_task(_process_job_with_semaphore(job))
        except Exception:
            logger.exception("Transcode worker poll failed")
        await asyncio.sleep(poll_interval)

async def _process_job_with_semaphore(job: dict) -> None:
    async with _CONCURRENCY_SEMAPHORE:
        await execute_transcode_job(job)

def start_transcode_worker_task() -> None:
    if not S.transcode_worker_enabled:
        return
    asyncio.create_task(transcode_worker_loop())
```

**FFmpeg execution**: Uses `asyncio.create_subprocess_exec` (not `subprocess.run`) to avoid blocking the event loop. Progress is parsed from FFmpeg's `-progress pipe:1` output and written to DynamoDB every 5 seconds.

### 3.8 SQS + Lambda Architecture (Production)

In production, the in-process worker loop is disabled (`transcode_worker_enabled=false`). Instead:

1. **Job submission** (API handler): Writes job record to DynamoDB with `status=pending`, then publishes message to SQS:
   ```python
   sqs.send_message(
       QueueUrl=S.transcode_sqs_queue_url,
       MessageBody=json.dumps({"job_id": job_id, "tenant_id": tenant_id}),
       MessageGroupId=tenant_id,  # FIFO queue: one tenant's jobs are ordered
       MessageDeduplicationId=job_id,
   )
   ```

2. **SQS queue**: FIFO queue with visibility timeout = 900s (15 minutes). Dead-letter queue after 3 receives. Content-based deduplication disabled (we use explicit `MessageDeduplicationId`).

3. **Lambda/ECS worker**: Triggered by SQS event (Lambda) or long-polling (ECS). Claims the job via conditional DynamoDB write, downloads source from S3, runs FFmpeg, uploads outputs to S3, updates job record.

4. **Heartbeat**: Long-running workers extend SQS visibility timeout every 60 seconds via `ChangeMessageVisibility`. If the worker crashes, the message becomes visible again after 900s and another worker picks it up.

The SQS client factory already exists (`app/core/aws_clients.py:sqs_client()`), and the pattern for SQS message publishing is demonstrated in `app/services/jira_outbound_sync.py:_enqueue_to_sqs()`.

### 3.9 Progress Tracking

Progress is tracked at two granularities:

**Per-rendition progress**: Each rendition is processed sequentially (to limit peak disk usage). The worker updates `current_rendition` and `renditions_completed` as it moves through the ABR ladder.

**Per-frame progress within a rendition**: FFmpeg's `-progress pipe:1` output emits `out_time_us=<microseconds>` every second. The worker calculates:
```
rendition_pct = (out_time_us / total_duration_us) * 100
overall_pct = ((completed_renditions + rendition_pct/100) / total_renditions) * 100
```

DynamoDB updates are throttled to one write per 5 seconds to avoid exceeding provisioned capacity.

**Client-side polling**: The API exposes `GET /ui/transcode-jobs/{job_id}` which returns the current job state including `progress_pct`, `current_rendition`, and `eta_seconds`. Clients poll every 3-5 seconds. Future enhancement: SSE endpoint following the `app/services/alerts.py` subscriber pattern.

### 3.10 Retry Logic

Retry follows exponential backoff with jitter:

```python
def _compute_next_retry_at(attempt: int) -> int:
    base_delay = 30  # seconds
    max_delay = 600  # 10 minutes
    delay = min(max_delay, base_delay * (2 ** attempt))
    jitter = random.randint(0, delay // 4)
    return now_ts() + delay + jitter
```

| Attempt | Base delay | Max with jitter |
|---------|-----------|-----------------|
| 0 (first retry) | 30s | ~37s |
| 1 | 60s | ~75s |
| 2 | 120s | ~150s |

Default `max_attempts = 3` (configurable per-job). After exhausting retries, the job transitions to `failed` and an alert is raised via the existing `app/services/alerts.py` system.

**Non-retryable errors** (immediate failure, no retry):
- `source_not_found` - source S3 object does not exist
- `invalid_codec` - source codec not supported
- `cancelled` - user-initiated cancellation
- `contract_validation_error` - malformed job spec

**Retryable errors**:
- `ffmpeg_exit_nonzero` - FFmpeg crashed (may be transient OOM)
- `disk_full` - local scratch space exhausted
- `timeout` - exceeded per-rendition time limit
- `s3_upload_failed` - network error uploading output

### 3.11 Concurrency Limits

**Dev mode**: `asyncio.Semaphore(S.transcode_max_concurrent_jobs)` (default: 2). This prevents the single-process backend from spawning more FFmpeg processes than the dev machine can handle.

**Production**: Concurrency is controlled at two levels:
1. **SQS Lambda concurrency**: Reserved concurrency setting on the Lambda function (e.g., 10 concurrent invocations across the fleet).
2. **Per-tenant throttle**: Before claiming a job, the worker queries `GSI-TenantStatus` for `status=running` count. If `>= S.transcode_max_per_tenant` (default: 3), the message is returned to the queue (visibility timeout reset to 30s).

### 3.12 API Request/Response Examples

**Submit a transcode job**:
```bash
curl -X POST http://localhost:8000/ui/transcode-jobs \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": "v_abc123",
    "source_uri": "s3://uploads/raw/e2e_alice/tutorial.mp4",
    "renditions": [
      {"name": "1080p", "width": 1920, "height": 1080, "bitrate_kbps": 5000},
      {"name": "720p", "width": 1280, "height": 720, "bitrate_kbps": 2500}
    ],
    "priority": 0,
    "max_attempts": 3
  }'

# 201 Created
{
  "job_id": "tj_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "tenant_id": "tenant_abc",
  "asset_id": "v_abc123",
  "status": "pending",
  "created_at": 1748500000,
  "updated_at": 1748500000,
  "attempt": 0,
  "max_attempts": 3,
  "progress_pct": 0,
  "renditions_completed": []
}
```

**Poll job status**:
```bash
curl http://localhost:8000/ui/transcode-jobs/tj_a1b2c3d4 \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx"

# 200 OK
{
  "job_id": "tj_a1b2c3d4",
  "status": "running",
  "progress_pct": 45,
  "current_rendition": "720p",
  "renditions_completed": ["480p"],
  "eta_seconds": 300,
  "attempt": 0
}
```

**Cancel a job**:
```bash
curl -X DELETE http://localhost:8000/ui/transcode-jobs/tj_a1b2c3d4 \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx"

# 200 OK
{"ok": true, "job_id": "tj_a1b2c3d4", "status": "cancelled"}
```

**List jobs** (paginated):
```bash
curl "http://localhost:8000/ui/transcode-jobs?limit=10" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx"

# 200 OK
{
  "items": [
    {"job_id": "tj_a1b2c3d4", "status": "running", "progress_pct": 45, "asset_id": "v_abc123"}
  ],
  "cursor": null
}
```

---

## 4. Implementation Plan

### 4.1 Files

<!-- NOTE: All backend files listed below ALREADY EXIST. -->

| File | Purpose | Status |
|------|---------|--------|
| `app/services/transcode_job_store.py` | DDB CRUD: `create_job()` (line 31), `claim_job()` (line 86), `update_job_progress()` (line 116), `complete_job()` (line 147), `complete_job_with_outputs()` (line 181), `fail_job()` (line 244), `get_job()` (line 75), `list_jobs_by_status()` (line 297), `list_jobs_by_video()` (line 329) | **Already exists** |
| `app/services/transcode_worker.py` | Asyncio worker: `transcode_worker_loop()` (line 38), `execute_transcode_job()` (line 86), `_run_ffmpeg_for_rendition()` (line 234), `start_transcode_worker_task()` (line 334) | **Already exists** |
| `app/services/transcode_job_submit.py` | <!-- NOTE: This file does NOT exist. Job submission is handled directly in the router (`app/routers/transcode_jobs.py`). --> | **Does not exist** (logic is in router) |
| `app/routers/transcode_jobs.py` | API endpoints: router at line 26 (`prefix="/ui/transcode-jobs"`), plus `video_router` at line 151 (`prefix="/ui/videos"`). Models: `SubmitTranscodeJobIn` (line 32), `TranscodeJobOut` (line 41), `TranscodeJobListOut` (line 56). | **Already exists** (205 lines) |
| `app/services/ffmpeg_executor.py` | FFmpeg subprocess execution: `execute_rendition()` (line 70), `classify_error()` (line 510), `validate_output()` (line 531) | **Already exists** |

### 4.2 DynamoDB Table Definition

<!-- NOTE: This table ALREADY EXISTS at `scripts/local-ddb-init.py:739-760`. -->

```python
# ACTUAL definition (already in scripts/local-ddb-init.py:739-760):
TableDef(
    _resolve_table_name(S.transcode_jobs_table_name, "TranscodeJobs"),
    pk="job_id",
    sk="job_id",
    gsis=[
        GsiDef(name="ByStatusCreatedAt", pk="status", sk="created_at"),
        GsiDef(name="ByVideoId", pk="video_id", sk="created_at"),
        GsiDef(name="ByTenantStatus", pk="tenant_id", sk="status_created_at"),
    ],
    attr_types={"created_at": "N"},
)
```

Note: `status_created_at` is a composite sort key string `"{status}#{created_at}"` that enables prefix queries like `begins_with(status_created_at, "pending#")` on the tenant GSI. The `ByStatusCreatedAt` index uses a numeric `created_at` sort key to support the worker's oldest-first polling.

### 4.3 Settings

<!-- NOTE: `transcode_jobs_table_name` ALREADY EXISTS at `app/core/settings.py:1082`. -->

```python
# ACTUAL existing setting (app/core/settings.py:1082):
transcode_jobs_table_name: str = os.environ.get("DDB_TRANSCODE_JOBS", "TranscodeJobs")
transcode_worker_enabled: bool = os.environ.get("TRANSCODE_WORKER_ENABLED", os.environ.get("DEV_MODE", "0")) not in ("0", "false", "False")
transcode_worker_poll_interval_seconds: int = int(os.environ.get("TRANSCODE_WORKER_POLL_INTERVAL_SECONDS", "10"))
transcode_max_concurrent_jobs: int = int(os.environ.get("TRANSCODE_MAX_CONCURRENT_JOBS", "2"))
transcode_max_per_tenant: int = int(os.environ.get("TRANSCODE_MAX_PER_TENANT", "3"))
transcode_max_attempts: int = int(os.environ.get("TRANSCODE_MAX_ATTEMPTS", "3"))
transcode_rendition_timeout_seconds: int = int(os.environ.get("TRANSCODE_RENDITION_TIMEOUT_SECONDS", "1800"))
transcode_output_bucket: str = os.environ.get("TRANSCODE_OUTPUT_BUCKET", "vod-output")
transcode_output_prefix: str = os.environ.get("TRANSCODE_OUTPUT_PREFIX", "tenants")
transcode_scratch_dir: str = os.environ.get("TRANSCODE_SCRATCH_DIR", "tmp/transcode-scratch")
transcode_sqs_queue_url: str = os.environ.get("TRANSCODE_SQS_QUEUE_URL", "")
transcode_progress_update_interval_seconds: int = int(os.environ.get("TRANSCODE_PROGRESS_UPDATE_INTERVAL_SECONDS", "5"))
```

### 4.4 Tables Registration

Add to `app/core/tables.py`:

```python
# In Tables dataclass:
transcode_jobs: Any

# In T = Tables(...):
transcode_jobs=ddb.Table(S.transcode_jobs_table_name),
```

### 4.5 Worker Loop Registration in main.py

<!-- NOTE: ALREADY DONE at `app/main.py:471`. Import at line 101. -->

```python
# ACTUAL (app/main.py:101, 471):
from app.routers.transcode_jobs import router as transcode_jobs_router  # also imports worker
# Registration:
app.add_event_handler("startup", start_transcode_worker_task)  # line 471
```

### 4.6 Job Store Implementation (`app/services/transcode_job_store.py`)

Key functions:

```python
def create_job(request: VideoPipelineJobRequest, tenant_id: str) -> str:
    """Create a new job in pending state. Returns job_id."""
    job_id = f"tj_{uuid4().hex}"
    T.transcode_jobs.put_item(Item={
        "job_id": job_id,
        "tenant_id": tenant_id,
        "status": "pending",
        "status_created_at": f"pending#{now_ts()}",
        "created_at": now_ts(),
        "updated_at": now_ts(),
        "attempt": 0,
        "max_attempts": S.transcode_max_attempts,
        ...  # full item from request
    })
    return job_id

def claim_job(job_id: str, worker_id: str) -> bool:
    """Atomically claim a pending job. Returns False if already claimed."""
    try:
        T.transcode_jobs.update_item(
            Key={"job_id": job_id},
            UpdateExpression="SET #s = :running, worker_id = :wid, started_at = :now, updated_at = :now, status_created_at = :sc",
            ConditionExpression="#s = :pending AND (attribute_not_exists(next_retry_at) OR next_retry_at <= :now)",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":running": "running",
                ":pending": "pending",
                ":wid": worker_id,
                ":now": now_ts(),
                ":sc": f"running#{now_ts()}",
            },
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise

def update_progress(job_id: str, worker_id: str, progress_pct: int, current_rendition: str, renditions_completed: list[str], eta_seconds: int | None) -> None:
    """Update progress fields. Only succeeds if worker still owns the job."""
    T.transcode_jobs.update_item(
        Key={"job_id": job_id},
        UpdateExpression="SET progress_pct = :p, current_rendition = :cr, renditions_completed = :rc, eta_seconds = :eta, updated_at = :now",
        ConditionExpression="worker_id = :wid AND #s = :running",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={...},
    )
```

### 4.7 Worker Execution Flow (`app/services/transcode_worker.py`)

```python
async def execute_transcode_job(job: dict) -> None:
    job_id = job["job_id"]
    worker_id = f"{socket.gethostname()}:{os.getpid()}"

    if not claim_job(job_id, worker_id):
        return  # another worker got it

    scratch_dir = Path(S.transcode_scratch_dir) / job_id
    scratch_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Download source from S3 to scratch
        source_path = await _download_source(job["source_uri"], scratch_dir)

        # 2. Transcode each rendition sequentially
        renditions = job["renditions"]
        completed = []
        for i, rendition in enumerate(renditions):
            args = build_rendition_ffmpeg_args(
                input_url=str(source_path),
                output_dir=scratch_dir / "output",
                rendition=rendition,
                watermark_policy=WatermarkPolicy(**job.get("watermark", {})),
            )
            await _run_ffmpeg_async(job_id, worker_id, args, rendition["name"], i, len(renditions))
            completed.append(rendition["name"])

        # 3. Write master playlist
        write_master_playlist(scratch_dir / "output")

        # 4. Upload outputs to S3
        output_prefix = f"{S.transcode_output_prefix}/{job['tenant_id']}/assets/{job['asset_id']}/hls"
        manifest_uri = await _upload_outputs(scratch_dir / "output", S.transcode_output_bucket, output_prefix)

        # 5. Mark complete
        complete_job(job_id, worker_id, manifest_uri)

    except NonRetryableError as e:
        fail_job(job_id, worker_id, e.code, str(e))
    except Exception as e:
        _handle_retryable_failure(job_id, worker_id, job["attempt"], job["max_attempts"], str(e))
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)
```

### 4.8 Progress Update Mechanism

FFmpeg emits progress to stdout when invoked with `-progress pipe:1`. The worker reads this asynchronously:

```python
async def _run_ffmpeg_async(job_id: str, worker_id: str, args: list[str], rendition_name: str, rendition_idx: int, total_renditions: int) -> None:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    last_update = 0
    async for line in proc.stdout:
        decoded = line.decode().strip()
        if decoded.startswith("out_time_us="):
            current_us = int(decoded.split("=")[1])
            overall_pct = int(((rendition_idx + current_us / total_duration_us) / total_renditions) * 100)
            if now_ts() - last_update >= S.transcode_progress_update_interval_seconds:
                update_progress(job_id, worker_id, overall_pct, rendition_name, completed_renditions, eta)
                last_update = now_ts()

    await proc.wait()
    if proc.returncode != 0:
        stderr = await proc.stderr.read()
        raise RetryableError("ffmpeg_exit_nonzero", stderr.decode()[:4096])
```

---

## 5. Observability & Monitoring

### 5.1 Metrics to Track

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `transcode_job_submitted_total` | Counter | `tenant_id` | Jobs submitted |
| `transcode_job_completed_total` | Counter | `tenant_id`, `rendition_count` | Jobs completed successfully |
| `transcode_job_failed_total` | Counter | `tenant_id`, `error_code` | Jobs failed (terminal) |
| `transcode_job_retried_total` | Counter | `tenant_id`, `attempt` | Retry events |
| `transcode_job_cancelled_total` | Counter | `tenant_id` | Jobs cancelled by user |
| `transcode_job_duration_seconds` | Histogram | `rendition_count` | Wall-clock time from submit to complete |
| `transcode_rendition_duration_seconds` | Histogram | `rendition_label` | Per-rendition encoding time |
| `transcode_worker_active_jobs` | Gauge | | Currently running jobs |
| `transcode_worker_poll_empty` | Counter | | Poll cycles with no pending jobs |
| `transcode_progress_update_total` | Counter | | DDB progress writes |

### 5.2 Log Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `transcode.submitted` | INFO | `job_id`, `tenant_id`, `asset_id`, `rendition_count` | Job created |
| `transcode.claimed` | INFO | `job_id`, `worker_id` | Worker claims job |
| `transcode.rendition_started` | INFO | `job_id`, `rendition_name`, `rendition_idx` | FFmpeg started for rendition |
| `transcode.rendition_completed` | INFO | `job_id`, `rendition_name`, `duration_seconds` | Rendition done |
| `transcode.completed` | INFO | `job_id`, `total_duration_seconds`, `output_uri` | Job fully done |
| `transcode.failed` | ERROR | `job_id`, `error_code`, `error_message`, `attempt` | Job failed |
| `transcode.retrying` | WARN | `job_id`, `attempt`, `next_retry_at` | Scheduling retry |
| `transcode.cancelled` | INFO | `job_id`, `cancelled_by` | User cancelled |
| `transcode.claim_failed` | DEBUG | `job_id`, `worker_id` | Conditional write failed (another worker) |
| `transcode.progress` | DEBUG | `job_id`, `progress_pct`, `current_rendition` | Progress update |

### 5.3 Alert Thresholds

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Job failure rate > 20% | > 20% of completed jobs are `failed` in 1h | Critical | Check FFmpeg/disk/S3 |
| Job queue backing up | > 50 pending jobs | Warning | Scale workers or increase concurrency |
| Worker stalled | No progress update for running job in > 5 min | Warning | Worker may have crashed |
| Disk usage high | Scratch dir > 80% capacity | Warning | Clean up or expand storage |
| All retries exhausted | Any `max_retries_exhausted` alert | Critical | Manual intervention needed |

### 5.4 Dashboard Queries

**Jobs by status** (admin overview):
```
SELECT status, COUNT(*) as count,
       AVG(progress_pct) as avg_progress
FROM transcode_jobs
GROUP BY status
```

**Average encoding time by rendition**:
```
SELECT rendition_name,
       AVG(rendition_duration_seconds) as avg_time,
       p95(rendition_duration_seconds) as p95_time
FROM transcode_rendition_metrics
WHERE completed_at > now() - interval '7 days'
GROUP BY rendition_name
```

---

## 6. Rollout Plan

### 6.1 Feature Flag Strategy

| Flag | Default | Description |
|------|---------|-------------|
| `TRANSCODE_WORKER_ENABLED` | `true` (dev), `false` (prod) | Enable in-process worker loop |
| `TRANSCODE_API_ENABLED` | `true` (dev), `true` (prod) | Enable job submission API |
| `TRANSCODE_SQS_ENABLED` | `false` (dev), `true` (prod) | Enable SQS message publishing |

### 6.2 Migration Steps

1. **Phase 1 -- Table and store**: Deploy TranscodeJobs DDB table + store module. No API or worker.
2. **Phase 2 -- API endpoints**: Deploy submission, status, list, cancel endpoints. Jobs go to `pending` state.
3. **Phase 3 -- Dev worker**: Enable in-process worker. Jobs start processing locally.
4. **Phase 4 -- SQS integration**: Deploy SQS queue. Enable `TRANSCODE_SQS_ENABLED`. Messages published on submit.
5. **Phase 5 -- Lambda worker**: Deploy Lambda worker. Disable in-process worker in prod.

### 6.3 Canary Deployment

- Start with `TRANSCODE_MAX_CONCURRENT_JOBS=1` in production.
- Monitor for 48h with real workloads.
- Gradually increase to target concurrency.

### 6.4 Rollback Procedure

1. Set `TRANSCODE_WORKER_ENABLED=false` to stop the in-process worker.
2. Set `TRANSCODE_API_ENABLED=false` to reject new submissions (returns 503).
3. Running jobs will complete or timeout (no new jobs claimed).
4. Pending jobs remain in DDB; resume processing when re-enabled.
5. SQS messages in DLQ can be redriven when ready.

---

## 7. Performance Considerations

### 7.1 Query Cost Analysis

| Operation | DDB Reads | DDB Writes | Expected Latency |
|-----------|-----------|------------|-------------------|
| Create job | 0 | 1 (conditional put) | ~8ms |
| Claim job | 0 | 1 (conditional update) | ~8ms |
| Update progress | 0 | 1 (conditional update) | ~8ms |
| Complete job | 0 | 1 (update) | ~8ms |
| Poll pending (10 jobs) | 1 query | 0 | ~10ms |
| List tenant jobs (50) | 1 query | 0 | ~12ms |
| Get job status | 1 get | 0 | ~5ms |

### 7.2 Progress Update Throttling

Progress writes are throttled to 1 per 5 seconds (`TRANSCODE_PROGRESS_UPDATE_INTERVAL_SECONDS`). For a 30-minute transcode, this is ~360 writes per job. At 10 concurrent jobs, ~72 writes/minute -- well within DDB on-demand throughput.

### 7.3 Scratch Disk Management

- Each job uses `{TRANSCODE_SCRATCH_DIR}/{job_id}/` for source download and output.
- Cleanup: `shutil.rmtree` in `finally` block ensures cleanup even on failure.
- Disk pressure monitoring: Worker should check available disk before accepting a job.
- Estimated disk usage per job: source file size x 2 (source + outputs). For a 1GB source with 4 renditions, ~3-4GB peak.

### 7.4 FFmpeg Memory Usage

- FFmpeg memory scales with resolution and GOP length.
- 1080p with GOP=60: ~200-400MB per process.
- With 2 concurrent jobs: ~400-800MB peak.
- Monitor with `psutil.Process(proc.pid).memory_info().rss`.

### 7.5 GSI Hot Partition: `status=pending`

The `GSI-Status` index has `status` as PK. During burst submissions, many jobs will have `status=pending`, creating a hot partition. DDB on-demand mode auto-scales, but if sustained write rate exceeds 1000 WCU/s on this partition, consider:
- Adding a shard key (`status#shard_N` with N = job_id hash % 4).
- Using SQS as the primary dispatch mechanism (not DDB polling) in production.

---

## 8. Testing Strategy

### 8.1 Unit Tests for Job State Machine (`tests/test_transcode_job_store.py`)

Tests run against moto-mocked DynamoDB (same pattern as all other unit tests in `tests/`).

**Test cases:**

1. `test_create_job_stores_all_fields` - Verify all fields from `VideoPipelineJobRequest` are persisted correctly, including computed fields (`status_created_at`, `ttl`).

2. `test_claim_job_succeeds_for_pending` - Create a pending job, claim it, verify status=running and worker_id is set.

3. `test_claim_job_fails_if_already_claimed` - Two concurrent claims; first succeeds, second returns False.

4. `test_claim_job_respects_next_retry_at` - Job with `next_retry_at` in the future cannot be claimed; job with `next_retry_at` in the past can be claimed.

5. `test_complete_job_sets_output_fields` - After completion, verify `output_hls_manifest_uri`, `completed_at`, `status=completed`.

6. `test_complete_job_fails_if_wrong_worker` - Worker B cannot complete a job owned by Worker A.

7. `test_fail_job_increments_attempt_and_sets_retry` - On retryable failure with attempts remaining, verify `status=pending`, `attempt` incremented, `next_retry_at` set.

8. `test_fail_job_terminal_when_max_attempts_exhausted` - After `max_attempts` failures, verify `status=failed`, no `next_retry_at`.

9. `test_cancel_job_from_pending` - Cancel a pending job; verify `status=cancelled`.

10. `test_cancel_job_from_running` - Cancel a running job; verify `status=cancelled`.

11. `test_cancel_fails_for_completed` - Cannot cancel an already-completed job.

12. `test_poll_pending_jobs_returns_oldest_first` - Create 5 jobs with staggered `created_at`; verify poll returns them in FIFO order.

13. `test_poll_pending_jobs_skips_future_retry` - Jobs with `next_retry_at > now` are not returned by poll.

14. `test_list_jobs_by_tenant_filters_correctly` - Create jobs for two tenants; verify tenant-scoped listing.

15. `test_update_progress_only_if_owner` - Worker that does not own the job gets `ConditionalCheckFailedException`.

### 8.2 Integration Test with FFmpeg Execution (`tests/test_transcode_worker.py`)

These tests require `ffmpeg` on PATH (skip with `pytest.mark.skipif(not shutil.which("ffmpeg"))`).

**Test cases:**

1. `test_execute_transcode_job_single_rendition` - Submit a job with one 360p rendition pointing to a short (5-second) test video. Verify:
   - Job transitions: pending -> running -> completed
   - Output HLS segments exist on disk (or mock S3)
   - Master playlist references the correct rendition path
   - `progress_pct` reached 100

2. `test_execute_transcode_job_with_watermark` - Submit a job with `watermark.mode=dynamic_text`. Verify FFmpeg args include `drawtext` filter (by mocking `asyncio.create_subprocess_exec` and inspecting args).

3. `test_worker_loop_picks_up_pending_job` - Start the worker loop, insert a pending job, verify it gets claimed and processed within 2 poll cycles.

4. `test_worker_respects_concurrency_semaphore` - Set `max_concurrent=1`, submit 3 jobs, verify only 1 is running at a time (others remain pending until the first completes).

5. `test_ffmpeg_crash_triggers_retry` - Mock FFmpeg to exit with code 1. Verify:
   - Job transitions: pending -> running -> pending (with attempt=1)
   - `next_retry_at` is set
   - `error_code` = "ffmpeg_exit_nonzero"

6. `test_source_not_found_is_non_retryable` - Point `source_uri` to nonexistent S3 key. Verify immediate failure with `status=failed` (no retry).

### 8.3 Testing Retry Behavior

1. `test_exponential_backoff_calculation` - Unit test for `_compute_next_retry_at()`:
   - attempt=0 -> delay in [30, 37]
   - attempt=1 -> delay in [60, 75]
   - attempt=2 -> delay in [120, 150]
   - attempt=10 -> delay capped at 600 + jitter

2. `test_retry_resets_worker_id` - After failure+retry, verify `worker_id` is cleared so any worker can claim it.

3. `test_retry_preserves_attempt_history` - After each retry, `attempt` field increments. `error_message` reflects the most recent failure.

4. `test_max_attempts_exhaustion_emits_alert` - After final failure, verify an alert is created in the alerts table for the tenant (using `app/services/alerts.py:write_alert()`).

### 8.4 Testing Concurrency Limits

1. `test_per_tenant_throttle` - Set `max_per_tenant=2`. Submit 4 jobs for same tenant. Start worker. Verify at most 2 are `status=running` simultaneously (third waits).

2. `test_global_semaphore_limits_ffmpeg_processes` - Set `max_concurrent=1`. Submit 2 jobs for different tenants. Verify only 1 FFmpeg process runs at a time (mock `asyncio.create_subprocess_exec` to track active calls).

3. `test_cancelled_job_releases_concurrency_slot` - Start a job, cancel it, verify the semaphore slot is released and the next pending job is picked up immediately.

### 8.5 E2E Test (`frontend/e2e/vod-pipeline.spec.ts`)

<!-- NOTE: Actual E2E file is `vod-pipeline.spec.ts`, not `transcode-jobs.spec.ts`. -->

A lightweight E2E test that exercises the API endpoints through the browser context:

| # | Test Title | Assertion |
|---|-----------|-----------|
| 1 | Submit transcode job returns 201 | POST with valid body; response has `job_id`, `status=pending` |
| 2 | Get job status returns progress | GET after submission; response has `progress_pct`, `current_rendition` |
| 3 | Cancel pending job | DELETE; response `status=cancelled` |
| 4 | List jobs includes submitted job | GET list; contains the submitted job |
| 5 | Cancelled job cannot be cancelled again | DELETE cancelled job; 409 |
| 6 | Pagination works for job list | Submit 5 jobs; list with `limit=2`; cursor returned |

### 8.6 Test Fixtures

Add a short (2-second, 320x240) test video to `tests/fixtures/test_video.mp4` for integration tests. Generate with:
```bash
ffmpeg -f lavfi -i testsrc=duration=2:size=320x240:rate=30 -c:v libx264 -pix_fmt yuv420p tests/fixtures/test_video.mp4
```

---

## Testing Strategy

### Unit Tests (pytest)

| Test | Description |
|------|-------------|
| `test_create_job_stores_all_fields` | Verify all fields from `VideoPipelineJobRequest` are persisted including `status_created_at` and `ttl` |
| `test_claim_job_succeeds_for_pending` | Create pending job, claim it; verify `status=running` and `worker_id` set |
| `test_claim_job_fails_if_already_claimed` | Two concurrent claims; first succeeds, second returns `False` |
| `test_claim_job_respects_next_retry_at` | Job with `next_retry_at` in the future cannot be claimed |
| `test_complete_job_sets_output_fields` | Verify `output_hls_manifest_uri`, `completed_at`, `status=completed` after completion |
| `test_complete_job_fails_if_wrong_worker` | Worker B cannot complete a job owned by Worker A |
| `test_fail_job_increments_attempt_and_sets_retry` | Retryable failure: `status=pending`, `attempt` incremented, `next_retry_at` set |
| `test_fail_job_terminal_when_max_attempts_exhausted` | After `max_attempts` failures: `status=failed`, no `next_retry_at` |
| `test_cancel_job_from_pending` | Cancel pending job; verify `status=cancelled` |
| `test_poll_pending_jobs_returns_oldest_first` | Create 5 jobs with staggered `created_at`; poll returns FIFO order |

**Framework**: pytest + moto (DynamoDB mock)
**Test file**: `tests/test_transcode_job_store.py`

### Integration Tests

| Scenario | Services | Assertion |
|----------|----------|-----------|
| Worker loop picks up pending job | `transcode_worker.py` + `transcode_job_store.py` | Pending job claimed and processed within 2 poll cycles |
| Worker respects concurrency semaphore | `transcode_worker.py` | With `max_concurrent=1`, only 1 job running at a time |
| FFmpeg crash triggers retry | `transcode_worker.py` + `ffmpeg_executor.py` | Job transitions pending -> running -> pending with `attempt=1` |
| Source not found is non-retryable | `transcode_worker.py` | Nonexistent S3 key causes immediate `status=failed` |
| Exponential backoff calculation | `_compute_next_retry_at()` | attempt=0 -> 30-37s; attempt=1 -> 60-75s; capped at 600s |

### E2E Tests (Playwright)

| # | Test | Assertion |
|---|------|-----------|
| 1 | Submit transcode job returns 201 | POST with valid body; response has `job_id`, `status=pending` |
| 2 | Get job status returns progress | GET after submission; response has `progress_pct`, `current_rendition` |
| 3 | Cancel pending job | DELETE; response `status=cancelled` |
| 4 | List jobs includes submitted job | GET list; contains the submitted job |
| 5 | Cancelled job cannot be cancelled again | DELETE cancelled job; 409 |
| 6 | Pagination works for job list | Submit 5 jobs; list with `limit=2`; cursor returned |
| 7 | Job submission validates rendition spec | POST with empty `renditions` list; 422 |
| 8 | Per-tenant throttle rejects excess jobs | Submit beyond `max_per_tenant` limit; 429 |

**Auth**: `injectAuth(page, "alice")` + CSRF header
**Test file**: `frontend/e2e/vod-pipeline.spec.ts`

### Test Data Requirements
- DDB tables: `TranscodeJobs` (with GSIs `ByStatusCreatedAt`, `ByVideoId`, `ByTenantStatus`)
- `attr_types={"created_at": "N"}` for numeric GSI sort key
- Test users: Alice (USER), Bob (USER), Root (ROOT)
- Short test video fixture: `tests/fixtures/test_video.mp4` (2-second, 320x240, ~30KB)

### CI/Pipeline
- Feature flag: `TRANSCODE_WORKER_ENABLED=true` in dev mode
- Serial execution with `workers: 1`
- Retry-safe (each test submits fresh jobs with unique `asset_id`)
- Integration tests require `ffmpeg` on PATH (skip gracefully if unavailable)

---

## Appendix A: Configuration Reference

| Env Variable | Default (dev) | Default (prod) | Description |
|-------------|---------------|----------------|-------------|
| `TRANSCODE_WORKER_ENABLED` | `1` (via DEV_MODE) | `0` | Enable in-process worker loop |
| `TRANSCODE_WORKER_POLL_INTERVAL_SECONDS` | `10` | N/A | How often the worker checks for pending jobs |
| `TRANSCODE_MAX_CONCURRENT_JOBS` | `2` | N/A (Lambda concurrency) | Max parallel FFmpeg processes |
| `TRANSCODE_MAX_PER_TENANT` | `3` | `3` | Max concurrent jobs per tenant |
| `TRANSCODE_MAX_ATTEMPTS` | `3` | `3` | Retry limit before terminal failure |
| `TRANSCODE_RENDITION_TIMEOUT_SECONDS` | `1800` | `3600` | Per-rendition FFmpeg timeout |
| `TRANSCODE_OUTPUT_BUCKET` | `vod-output` | `<prod-bucket>` | S3 bucket for HLS/DASH output |
| `TRANSCODE_OUTPUT_PREFIX` | `tenants` | `tenants` | S3 key prefix |
| `TRANSCODE_SCRATCH_DIR` | `tmp/transcode-scratch` | `/tmp/transcode` | Local disk for FFmpeg work |
| `TRANSCODE_SQS_QUEUE_URL` | (empty) | `https://sqs...` | SQS FIFO queue URL (prod only) |
| `TRANSCODE_PROGRESS_UPDATE_INTERVAL_SECONDS` | `5` | `5` | Min seconds between DDB progress writes |
| `DDB_TRANSCODE_JOBS` | `transcode_jobs` | `transcode_jobs` | DynamoDB table name |

## Appendix B: Event Emission

On each state transition, emit a `VideoPipelineJobEvent` to the existing alerts/SSE infrastructure:

```python
from app.contracts.video_pipeline_contract import VideoPipelineJobEvent

def _emit_job_event(job: dict, event_type: str) -> None:
    event = VideoPipelineJobEvent(
        event_type=event_type,
        job_id=job["job_id"],
        asset_id=job["asset_id"],
        tenant_id=job["tenant_id"],
        status=job["status"],
        error_code=job.get("error_code"),
        error_message=job.get("error_message"),
        output_hls_manifest_uri=job.get("output_hls_manifest_uri"),
        output_dash_manifest_uri=job.get("output_dash_manifest_uri"),
    )
    # Publish to tenant's SSE channel
    write_alert(
        user_sub=job["tenant_id"],
        alert_type="transcode_job_event",
        payload=event.model_dump(),
    )
```

This integrates with the existing `app/services/alerts.py` SSE subscriber system (in-memory `asyncio.Queue` per connected client) for real-time UI updates.

## Appendix C: Frontend Component Tree (for TranscodeJobs UI)

```
TranscodeJobsPanel (embedded in VideosPage, VOD-007)
├── JobProgressCard (for each active/recent job)
│   ├── Card
│   │   ├── CardHeader
│   │   │   ├── Asset title (or asset_id)
│   │   │   └── StatusBadge: "pending" | "running" | "completed" | "failed" | "cancelled"
│   │   ├── CardContent
│   │   │   ├── ProgressBar (progress_pct%)
│   │   │   ├── Current rendition label: "Encoding 720p..."
│   │   │   ├── Renditions completed checklist: [x] 480p [x] 720p [ ] 1080p
│   │   │   ├── ETA display: "~5 minutes remaining"
│   │   │   └── Error display (if failed): error_code + error_message
│   │   └── CardFooter
│   │       └── Button: "Cancel" (visible for pending/running, disabled for others)
│   └── [Polling: useQuery with refetchInterval=3000 while status=running]
├── JobHistoryTable (expandable)
│   ├── DataTable columns: job_id, asset, status, progress, created_at, duration
│   ├── Sortable by created_at
│   └── Pagination (cursor-based)
└── EmptyState: "No transcode jobs" (when no jobs exist)
```

## Codebase References

| File | Line(s) | What |
|------|---------|------|
| `app/routers/transcode_jobs.py` | 26 | `APIRouter(prefix="/ui/transcode-jobs")` |
| `app/routers/transcode_jobs.py` | 32, 41, 56 | `SubmitTranscodeJobIn`, `TranscodeJobOut`, `TranscodeJobListOut` |
| `app/routers/transcode_jobs.py` | 151 | `video_router = APIRouter(prefix="/ui/videos")` |
| `app/services/transcode_job_store.py` | 31 | `create_job()` |
| `app/services/transcode_job_store.py` | 75 | `get_job()` |
| `app/services/transcode_job_store.py` | 86 | `claim_job()` |
| `app/services/transcode_job_store.py` | 116 | `update_job_progress()` |
| `app/services/transcode_job_store.py` | 147 | `complete_job()` |
| `app/services/transcode_job_store.py` | 181 | `complete_job_with_outputs()` |
| `app/services/transcode_job_store.py` | 244 | `fail_job()` |
| `app/services/transcode_job_store.py` | 297 | `list_jobs_by_status()` |
| `app/services/transcode_job_store.py` | 344 | `_compute_next_retry_at()` |
| `app/services/transcode_worker.py` | 38 | `transcode_worker_loop()` |
| `app/services/transcode_worker.py` | 80 | `_process_job_with_semaphore()` (asyncio.Semaphore) |
| `app/services/transcode_worker.py` | 86 | `execute_transcode_job()` |
| `app/services/transcode_worker.py` | 234 | `_run_ffmpeg_for_rendition()` |
| `app/services/transcode_worker.py` | 334 | `start_transcode_worker_task()` |
| `app/services/ffmpeg_executor.py` | 70 | `execute_rendition()` |
| `app/services/ffmpeg_executor.py` | 510 | `classify_error()` |
| `app/services/ffmpeg_executor.py` | 531 | `validate_output()` |
| `app/services/ffmpeg_abr_pipeline.py` | 50 | `build_rendition_ffmpeg_args()` |
| `app/services/ffmpeg_abr_pipeline.py` | 145 | `write_master_playlist()` |
| `app/services/vod_s3_uploader.py` | 142 | `upload_transcode_outputs()` |
| `app/contracts/video_pipeline_contract.py` | 41 | `VideoPipelineJobRequest` |
| `app/contracts/video_pipeline_contract.py` | 56 | `VideoPipelineJobEvent` |
| `app/contracts/video_rendition_profiles.py` | 8 | `CanonicalRenditionProfile` |
| `app/contracts/watermark_policy.py` | 43 | `WatermarkPolicy` |
| `app/services/video_pipeline_contract_service.py` | 17, 38 | `validate_video_pipeline_job()`, `contract_capabilities_snapshot()` |
| `app/main.py` | 101 | `from app.routers.transcode_jobs import ...` |
| `app/main.py` | 423 | `app.include_router(transcode_jobs_router)` |
| `app/main.py` | 471 | `start_transcode_worker_task` startup registration |
| `app/core/settings.py` | 1082 | `transcode_jobs_table_name` setting |
| `scripts/local-ddb-init.py` | 739-760 | `TranscodeJobs` table definition with 3 GSIs |
| `frontend/e2e/vod-pipeline.spec.ts` | -- | E2E pipeline tests |

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|--------------|
| VOD-001 | `VideoMetadata` table and `video_metadata_store.py` for video record updates on job completion | Implemented | Yes -- VOD-003 writes to `TranscodeJobs`, only reads/updates VideoMetadata |
| VOD-002 | Source S3 URI from upload flow; presigned upload ticket establishes the raw file location | Implemented | Yes -- VOD-003 can be developed with hardcoded test URIs |

### Depended On By

| Ticket | What It Needs from VOD-003 |
|--------|---------------------------|
| VOD-004 | Job lifecycle (claim, progress update, complete/fail) for FFmpeg executor integration |
| VOD-005 | Job `complete_job_with_outputs()` to record S3 output URIs after upload |
| VOD-010 | DRM key injection integrated into the transcode pipeline |
| VOD-011 | E2E test coverage of job submission, polling, and cancellation |
| VOD-012 | Reuses `TranscodeJobs` table for MP4 mux jobs (`job_type="mp4_mux"`) |
| VOD-015 | Creates clip jobs (`job_type="clip"`) in the same queue |
| VOD-016 | Creates concat jobs (`job_type="concat"`) in the same queue |

### Merge Strategy

**Sequential after VOD-001 + VOD-002** -- The transcode queue is the core orchestration layer; it should be merged before VOD-004 and VOD-005. Feature-flag-gated: `TRANSCODE_WORKER_ENABLED` controls the in-process worker loop, `TRANSCODE_API_ENABLED` controls API endpoint availability.

### Merge Checklist

- [ ] `TranscodeJobs` table exists in `scripts/local-ddb-init.py` with GSIs `ByStatusCreatedAt`, `ByVideoId`, `ByTenantStatus`
- [ ] `attr_types={"created_at": "N"}` set for numeric GSI sort key
- [ ] `transcode_jobs_router` registered in `app/main.py`
- [ ] `start_transcode_worker_task` registered as startup event handler
- [ ] `TRANSCODE_WORKER_ENABLED` defaults to `true` in dev mode
- [ ] `just test` passes (job store unit tests with moto)
- [ ] `just e2e` passes (pipeline E2E tests)
- [ ] Worker loop does not crash when no pending jobs (empty poll returns gracefully)
