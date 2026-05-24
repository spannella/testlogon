# VOD-003: Async Transcode Job Queue and Worker

**Ticket**: VOD-003
**Status**: Design
**Author**: Platform Engineering
**Date**: 2026-05-24

---

## 1. Overview & Motivation

### Problem Statement

The video pipeline contract (`app/contracts/video_pipeline_contract.py`) defines a structured job submission schema (`VideoPipelineJobRequest`) and event model (`VideoPipelineJobEvent`) for multi-rendition ABR transcoding. The FFmpeg ABR pipeline (`app/services/ffmpeg_abr_pipeline.py`) provides the building blocks to construct per-rendition FFmpeg command lines with watermark overlays. However, there is no orchestration layer that accepts a job request, persists it, tracks its progress through states (accepted -> running -> completed/failed), manages concurrency, or retries on failure.

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

- **No job queue table**: There is no DynamoDB table for transcode jobs.
- **No worker process**: There is no asyncio task or external worker that picks up and executes transcode jobs.
- **No progress tracking**: `VideoPipelineJobEvent` defines event types (`job.accepted`, `job.running`, `job.failed`, `job.completed`) but nothing persists or emits them.
- **No concurrency limiter**: No `asyncio.Semaphore` or similar mechanism exists in the services layer.
- **No retry logic**: The existing background loops have bare `except Exception: pass` - they retry on the *next* interval tick but have no per-item retry count or backoff.
- **No SQS queue for video jobs**: The only SQS integration is the newsfeed SSE fan-out poller (`EVENTS_SQS_URL`) and the Jira outbound sync (`app/services/jira_outbound_sync.py`).

### Video Pipeline Components Already Built

The following building blocks are in place and ready for orchestration:

- `app/contracts/video_pipeline_contract.py` - Job request/response/event Pydantic models
- `app/contracts/video_rendition_profiles.py` - Canonical ABR ladder (1080p/720p/540p/360p)
- `app/contracts/watermark_policy.py` - Watermark configuration model with validation
- `app/services/ffmpeg_abr_pipeline.py` - `build_rendition_ffmpeg_args()` constructs FFmpeg CLI for one rendition; `write_master_playlist()` writes the HLS master manifest
- `app/services/video_pipeline_contract_service.py` - `validate_video_pipeline_job()` validates incoming payloads; `contract_capabilities_snapshot()` returns pipeline metadata
- `app/services/video_abr_profile_exports.py` - Exports rendition profiles for FFmpeg and MediaLive
- `app/services/watermark_profile_renderers.py` - Generates FFmpeg filter strings and MediaLive settings from watermark policy

---

## 3. Technical Design

### 3.1 DynamoDB Job Model

**Table**: `TranscodeJobs`
**Partition key**: `job_id` (S)
**Sort key**: None (single-item table, one row per job)

**GSIs**:
- `GSI-TenantStatus`: PK = `tenant_id` (S), SK = `status#created_at` (S)
  - Enables: "list all pending jobs for tenant X", "list all failed jobs for tenant X"
- `GSI-Status`: PK = `status` (S), SK = `created_at` (N)
  - Enables: worker polling for `status=pending` jobs ordered by creation time
  - `attr_types={"created_at": "N"}` required (numeric GSI sort key - see CLAUDE.md gotchas)

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

### 3.2 Job State Machine

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

### 3.3 In-Process Asyncio Worker (Dev Mode)

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

### 3.4 SQS + Lambda Architecture (Production)

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

### 3.5 Progress Tracking

Progress is tracked at two granularities:

**Per-rendition progress**: Each rendition is processed sequentially (to limit peak disk usage). The worker updates `current_rendition` and `renditions_completed` as it moves through the ABR ladder.

**Per-frame progress within a rendition**: FFmpeg's `-progress pipe:1` output emits `out_time_us=<microseconds>` every second. The worker calculates:
```
rendition_pct = (out_time_us / total_duration_us) * 100
overall_pct = ((completed_renditions + rendition_pct/100) / total_renditions) * 100
```

DynamoDB updates are throttled to one write per 5 seconds to avoid exceeding provisioned capacity.

**Client-side polling**: The API exposes `GET /ui/transcode-jobs/{job_id}` which returns the current job state including `progress_pct`, `current_rendition`, and `eta_seconds`. Clients poll every 3-5 seconds. Future enhancement: SSE endpoint following the `app/services/alerts.py` subscriber pattern.

### 3.6 Retry Logic

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

### 3.7 Concurrency Limits

**Dev mode**: `asyncio.Semaphore(S.transcode_max_concurrent_jobs)` (default: 2). This prevents the single-process backend from spawning more FFmpeg processes than the dev machine can handle.

**Production**: Concurrency is controlled at two levels:
1. **SQS Lambda concurrency**: Reserved concurrency setting on the Lambda function (e.g., 10 concurrent invocations across the fleet).
2. **Per-tenant throttle**: Before claiming a job, the worker queries `GSI-TenantStatus` for `status=running` count. If `>= S.transcode_max_per_tenant` (default: 3), the message is returned to the queue (visibility timeout reset to 30s).

---

## 4. Implementation Plan

### 4.1 New Files

| File | Purpose |
|------|---------|
| `app/services/transcode_job_store.py` | DynamoDB CRUD for transcode jobs: `create_job()`, `claim_job()`, `update_progress()`, `complete_job()`, `fail_job()`, `cancel_job()`, `get_job()`, `list_jobs_by_tenant()`, `poll_pending_jobs()` |
| `app/services/transcode_worker.py` | In-process asyncio worker: `transcode_worker_loop()`, `execute_transcode_job()`, `_run_ffmpeg_rendition()`, `_parse_progress()`, `start_transcode_worker_task()` |
| `app/services/transcode_job_submit.py` | Job submission orchestration: `submit_transcode_job()` validates input, writes DDB record, optionally enqueues to SQS |
| `app/routers/transcode_jobs.py` | API endpoints: `POST /ui/transcode-jobs` (submit), `GET /ui/transcode-jobs/{job_id}` (status), `GET /ui/transcode-jobs` (list), `DELETE /ui/transcode-jobs/{job_id}` (cancel) |
| `tests/test_transcode_job_store.py` | Unit tests for the DDB store |
| `tests/test_transcode_worker.py` | Unit tests for the worker state machine |
| `tests/test_transcode_job_submit.py` | Unit tests for job submission |

### 4.2 DynamoDB Table Definition

Add to `scripts/local-ddb-init.py`:

```python
TableDef(
    _resolve_table_name(S.transcode_jobs_table_name, "transcode_jobs"),
    "job_id",
    gsi=[
        {
            "index_name": "GSI-TenantStatus",
            "partition_key": "tenant_id",
            "sort_key": "status_created_at",
        },
        {
            "index_name": "GSI-Status",
            "partition_key": "status",
            "sort_key": "created_at",
        },
    ],
    attr_types={"created_at": "N"},
),
```

Note: `status_created_at` is a composite sort key string `"{status}#{created_at}"` that enables prefix queries like `begins_with(status_created_at, "pending#")` on the tenant GSI. The `GSI-Status` index uses a numeric `created_at` sort key to support the worker's oldest-first polling.

### 4.3 Settings additions

Add to `app/core/settings.py`:

```python
# Transcode worker
transcode_jobs_table_name: str = os.environ.get("DDB_TRANSCODE_JOBS", "transcode_jobs")
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

Add to `app/main.py`, following the existing pattern at line 312:

```python
from app.services.transcode_worker import start_transcode_worker_task

# After start_broadcast_reconciler_task registration:
app.add_event_handler("startup", start_transcode_worker_task)
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

## 5. Testing Strategy

### 5.1 Unit Tests for Job State Machine (`tests/test_transcode_job_store.py`)

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

### 5.2 Integration Test with FFmpeg Execution (`tests/test_transcode_worker.py`)

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

### 5.3 Testing Retry Behavior

1. `test_exponential_backoff_calculation` - Unit test for `_compute_next_retry_at()`:
   - attempt=0 -> delay in [30, 37]
   - attempt=1 -> delay in [60, 75]
   - attempt=2 -> delay in [120, 150]
   - attempt=10 -> delay capped at 600 + jitter

2. `test_retry_resets_worker_id` - After failure+retry, verify `worker_id` is cleared so any worker can claim it.

3. `test_retry_preserves_attempt_history` - After each retry, `attempt` field increments. `error_message` reflects the most recent failure.

4. `test_max_attempts_exhaustion_emits_alert` - After final failure, verify an alert is created in the alerts table for the tenant (using `app/services/alerts.py:create_alert()`).

### 5.4 Testing Concurrency Limits

1. `test_per_tenant_throttle` - Set `max_per_tenant=2`. Submit 4 jobs for same tenant. Start worker. Verify at most 2 are `status=running` simultaneously (third waits).

2. `test_global_semaphore_limits_ffmpeg_processes` - Set `max_concurrent=1`. Submit 2 jobs for different tenants. Verify only 1 FFmpeg process runs at a time (mock `asyncio.create_subprocess_exec` to track active calls).

3. `test_cancelled_job_releases_concurrency_slot` - Start a job, cancel it, verify the semaphore slot is released and the next pending job is picked up immediately.

### 5.5 E2E Test (`frontend/e2e/transcode-jobs.spec.ts`)

A lightweight E2E test that exercises the API endpoints through the browser context:

1. Submit a transcode job via `POST /ui/transcode-jobs` with a test asset.
2. Poll `GET /ui/transcode-jobs/{id}` until `status != pending`.
3. Verify the response includes `progress_pct`, `current_rendition`.
4. Cancel a second job via `DELETE /ui/transcode-jobs/{id}`.
5. Verify cancelled job has `status=cancelled`.
6. List jobs via `GET /ui/transcode-jobs` and verify pagination.

### 5.6 Test Fixtures

Add a short (2-second, 320x240) test video to `tests/fixtures/test_video.mp4` for integration tests. Generate with:
```bash
ffmpeg -f lavfi -i testsrc=duration=2:size=320x240:rate=30 -c:v libx264 -pix_fmt yuv420p tests/fixtures/test_video.mp4
```

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
    create_alert(
        user_sub=job["tenant_id"],
        alert_type="transcode_job_event",
        payload=event.model_dump(),
    )
```

This integrates with the existing `app/services/alerts.py` SSE subscriber system (in-memory `asyncio.Queue` per connected client) for real-time UI updates.
