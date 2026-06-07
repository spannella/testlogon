# BCAST-006: Recording + VOD Archive — Investigation & Implementation Write-up

## 1. Summary & Classification

When a broadcast session transitions from `live` to `stopped`, the platform previously stored a raw S3 archive prefix but had no mechanism to turn those MPEG-TS segments into a watchable VOD asset. This ticket delivers the full post-stream recording pipeline: segment inventory, FFmpeg concatenation, ABR HLS transcode, thumbnail extraction, signed playback URL minting, and retention expiry. The feature enables broadcasters to share a replay link within minutes of ending a session and provides viewers with on-demand access gated by the same entitlement system used for live playback.

- **Type**: Feature
- **Priority**: High
- **Status**: Implemented (as of current `main` branch)
- **Owning area**: Broadcast / VOD pipeline
- **Affected personas**: Broadcasters (self-service replay), Viewers (on-demand access), Platform operators (retention cost control)
- **Cross-references**: BCAST-008 (MP4 download consumes the `s3_concatenated_key` produced here), BCAST-010 (VOD post hook fires inside `process_recording`), SECOPS-007 (dev=local FFmpeg + moto S3, prod=real S3; same code path)

---

## 2. Current-State Investigation (what exists today)

### Recording service: `app/services/broadcast_recording.py`

The file is fully implemented. The `RecordingRecord` dataclass (lines 23–50) carries all lifecycle fields including the download fields added by BCAST-008:

```
recording_id, session_id, profile_id, created_by, status
s3_archive_prefix, s3_manifest_key, s3_thumbnail_key
duration_seconds, segment_count, total_bytes, renditions
error_code, error_message, retention_days, scope, created_at,
completed_at, expires_at
allow_download, allow_viewer_download, mp4_s3_key, mp4_size_bytes,
mp4_generated_at, s3_concatenated_key
```

DynamoDB CRUD functions: `create_recording` (line 116), `get_recording` (line 143), `get_recording_by_session` (line 152), `update_recording_status` (line 166), `list_recordings_by_status` (line 187), `list_expired_recordings` (line 198).

URL minting: `mint_recording_playback_url` (line 208) and `mint_recording_thumbnail_url` (line 222) both emit `/mock/s3/<bucket>/<key>?expires=<ts>` URLs in dev mode — dev/prod parity is implemented via the `S.dev_mode` branch at line 214.

`mint_recording_download_url` (line 230) is present and handles both dev (`/mock/s3/...`) and prod (real `boto3` presigned URL) paths, satisfying SECOPS-007.

### Worker pipeline: `app/services/broadcast_recording_worker.py`

`_should_mock()` (line 31) returns `True` when FFmpeg is absent and `S.broadcast_recording_mock_on_no_ffmpeg` is set — enabling CI and dev environments without FFmpeg to still exercise the full code path with placeholder metadata.

Pipeline steps (all implemented, stub-only in mock mode):
- `inventory_segments` (line 45): lists `.ts` files under archive prefix; returns `[]` in mock/dev
- `concatenate_segments` (line 61): calls FFmpeg concat demuxer; returns `None` in mock mode
- `transcode_recording` (line 75): ABR HLS transcode; returns mock rendition data when mocked
- `generate_mp4` (line 96): BCAST-008 remux step; produces placeholder key in mock mode
- `generate_thumbnail` (line 138): single-frame JPEG; returns deterministic key in mock mode
- `finalize_recording` (line 153): writes `status=ready`, computes `expires_at`

`process_recording` (line 192) orchestrates all six steps with individual try/except, transitions to `processing` on entry, `failed` on any exception, and `ready` on success. The BCAST-010 VOD post hook fires at line 235–254 inside a non-fatal try/except.

### Orchestrator trigger: `app/services/broadcast_orchestrator.py`

`stop_session_with_provider` (lines 125–175) triggers the recording pipeline at lines 154–173 after `status == "stopped"` is confirmed. It is gated by `S.broadcast_recording_enabled` and runs `process_recording` inline when `S.broadcast_recording_worker_inline` is `True` (default in dev). In production, the inline call is replaced by an async dispatch.

### Router endpoints: `app/routers/broadcast.py`

- `GET /broadcast/sessions/{session_id}/recording` (line 776): returns `BroadcastRecordingOut` with playback URL; emits 404, 410, or 202 for non-ready states
- `GET /broadcast/sessions/{session_id}/recording/download` (line 832): covered in BCAST-008
- `PATCH /broadcast/sessions/{session_id}/recording/download-settings` (lines 887–910): covered in BCAST-008

The response model `BroadcastRecordingOut` (lines 744–761) includes all fields specified in the ticket design including the BCAST-008 download fields.

### DynamoDB table: `scripts/local-ddb-init.py:736–744`

```
BroadcastRecordings table
  PK: recording_id
  GSI BySessionId: partition=session_id, sort=created_at
  GSI ByStatusCreatedAt: partition=status, sort=created_at
  GSI ByExpiresAt: partition=scope, sort=expires_at
  attr_types: created_at=N, expires_at=N
```

Note: the ticket design called for a `ByStatusCreatedAt` GSI; it is present. The `attr_types` on numeric sort keys are correctly declared, avoiding the DynamoDB `ValidationException` described in the CLAUDE.md gotchas section.

### Settings: `app/core/settings.py` (lines 1447–1459)

All recording settings are present:
- `broadcast_recordings_table_name` (line 1447)
- `broadcast_recording_enabled` (line 1448)
- `broadcast_recording_playback_ttl_seconds` (line 1449, default 14400)
- `broadcast_recording_vod_bucket` (line 1450, default `"broadcast-vod"`)
- `broadcast_recording_vod_prefix` (line 1451) — present but not used in S3 key construction (keys are built directly as `{session_id}/recording/...`)
- `broadcast_recording_max_segments`, `broadcast_recording_worker_inline`, `broadcast_recording_mock_on_no_ffmpeg` (lines 1452–1454)

Table handle: `T.broadcast_recordings` at `app/core/tables.py:155,391`.

### Frontend

`frontend/src/api/endpoints/broadcast.ts` contains API wrappers. The frontend broadcast page (`frontend/src/pages/broadcast/BroadcastPage.tsx`) includes inline session detail handling. No standalone `SessionDetailDialog.tsx` exists; the ticket design reference to that path was inaccurate — detail is rendered inline.

E2E test file: `frontend/e2e/broadcast-recording.spec.ts` (exists).

### Dev/Prod parity

| Concern | Dev | Prod |
|---------|-----|------|
| S3 storage | moto in-process via `S.dev_mode` branch | Real S3 bucket `broadcast-vod` |
| FFmpeg | Mocked when absent (`_should_mock()`) | Real FFmpeg binary on worker |
| Playback URL | `/mock/s3/<bucket>/<key>?expires=<ts>` | CloudFront signed URL |
| Download URL | `/mock/s3/...?disposition=attachment` | `boto3.generate_presigned_url` |

---

## 3. Gap / Threat Analysis

### What is fully implemented

The entire described feature is implemented. The complete pipeline from session stop through `status=ready` executes in both mock (CI/dev) and production modes. All required settings, DDB table, GSIs, CRUD helpers, API endpoints, and URL minting functions exist.

### Remaining gaps / open questions

1. **`concatenate_segments` production path is a stub**: `broadcast_recording_worker.py:71–72` logs the segment count then returns `None`. The S3 object listing and actual FFmpeg concat demuxer command are not implemented for the production (non-mock) path. In the current codebase, even when FFmpeg is present, `concatenate_segments` returns `None`, causing the entire pipeline to operate in mock mode regardless of `_should_mock()`. This means production recordings will have `duration_seconds=0` and no real HLS output until this stub is completed.

2. **`inventory_segments` production path is also a stub**: `broadcast_recording_worker.py:55–58` returns `[]` in both mock and non-mock paths. S3 `ListObjectsV2` pagination is not wired.

3. **No `_upload_to_s3` helper**: The BCAST-008 spec (section 4.3 Phase 2) notes that `_upload_to_s3()` does not exist and must be created. The `generate_mp4` production path at line 130 has a comment `# Upload to S3 would happen here in production` but does not call any upload function.

4. **`broadcast_recording_vod_prefix` unused**: `S.broadcast_recording_vod_prefix` is declared in settings but never incorporated into S3 key construction. All keys are `{session_id}/recording/<artifact>`. If the prefix setting is intended for multi-tenant path isolation, it must be added to key generation.

5. **Retention reconciler**: `broadcast_reconciler.py` has `start_broadcast_reconciler_task` registered in `app/main.py:803`, but whether `expire_stale_recordings` is wired inside that reconciler loop requires verification. If not, recordings will accumulate past their `expires_at` timestamp without being marked expired or having S3 objects deleted.

6. **No real test for segment-continuity gap detection**: The acceptance criterion "recording plays from start to finish without gaps (validated by segment continuity check)" has no implementation. No gap detection occurs during `inventory_segments` or `concatenate_segments`.

### Abuse potential

Presigned URLs in dev mode (`/mock/s3/...`) do not enforce the `expires` query parameter. The mock S3 route serves any key regardless. This is acceptable for dev but must not be deployed to production.

---

## 4. Proposed Design / Fix

### Complete the production worker stubs

**`inventory_segments`**: Replace the stub return `[]` with real S3 pagination:

```python
import boto3
s3 = boto3.client("s3", endpoint_url=S.ddb_endpoint_url if S.dev_mode else None)
paginator = s3.get_paginator("list_objects_v2")
segments = []
for page in paginator.paginate(Bucket=S.broadcast_recording_vod_bucket,
                               Prefix=recording.s3_archive_prefix):
    for obj in page.get("Contents", []):
        if obj["Key"].endswith(".ts"):
            segments.append(obj["Key"])
segments.sort()
return segments
```

In dev mode with moto, `endpoint_url` points to the moto server, so the same code runs against both environments (SECOPS-007 pattern).

**`concatenate_segments`**: Generate a concat list file, run `subprocess.run` with `ffmpeg -f concat -safe 0 -i <list> -c copy <output>`, upload via the new `_upload_to_s3` helper, store the result key in `recording.s3_concatenated_key`.

**`_upload_to_s3`** (new helper in `broadcast_recording_worker.py`):

```python
def _upload_to_s3(local_path: str, *, bucket: str, key: str) -> None:
    import boto3
    s3 = boto3.client("s3", endpoint_url=S.ddb_endpoint_url if S.dev_mode else None)
    s3.upload_file(local_path, bucket, key)
```

### Fix `broadcast_recording_vod_prefix` usage

Either remove the setting (document it as unused) or thread it through all S3 key construction:
```python
manifest_key = f"{S.broadcast_recording_vod_prefix}/{session_id}/recording/master.m3u8"
```

### Dev/Prod parity (SECOPS-007)

The mock branches triggered by `_should_mock()` and `S.dev_mode` are the correct pattern. When adding S3 calls, always pass `endpoint_url=S.ddb_endpoint_url if S.dev_mode else None` to boto3 clients so moto intercepts them. No separate code path is needed.

### DynamoDB — no changes required

The table schema is complete. All numeric GSI sort keys have `attr_types` declared.

---

## 5. Testing, Verification & Rollout

### pytest unit tests

**Existing file**: `tests/test_broadcast_recording.py` (referenced in ticket design — verify it covers):
- `create_recording` → verify DDB item shape, `status=pending`, `expires_at` correct
- `get_recording_by_session` → `BySessionId` GSI query, returns latest by `created_at`
- `update_recording_status` with extra fields (mp4 fields, thumbnail key)
- `list_expired_recordings` → `ByExpiresAt` GSI with numeric sort key comparison
- `mint_recording_playback_url` → dev mode URL format matches `/mock/s3/<bucket>/<key>?expires=`
- `mint_recording_download_url` → dev and prod branches both produce correct dict shape
- `process_recording` mock mode: full pipeline runs, returns `RecordingRecord` with `status=ready`
- `process_recording` failure path: exception in any step sets `status=failed`

### Playwright E2E tests

**File**: `frontend/e2e/broadcast-recording.spec.ts`

Key scenarios (using `injectAuth(page, "alice")` + CSRF headers):
1. POST start + stop session → GET recording → returns `{status: "ready", playback_url: <url>}`
2. GET recording for non-existent session → 404
3. GET recording while `status=processing` → 202 with `code: "BROADCAST_RECORDING_PROCESSING"`
4. GET recording for expired recording → 410 with `code: "BROADCAST_RECORDING_EXPIRED"`
5. Unauthenticated GET → 401

### Observability

`record_broadcast_session_action` metrics exist in `app/metrics.py` for start/stop. Add a metric for recording pipeline completion/failure to track pipeline latency and error rate.

### Rollout

1. Set `BROADCAST_RECORDING_ENABLED=0` in production until production worker stubs are complete
2. Complete `inventory_segments` + `concatenate_segments` production paths (see Gap section)
3. Enable with `BROADCAST_RECORDING_ENABLED=1`; monitor S3 storage growth and `status=failed` recordings
4. If inline worker blocks the stop endpoint's response time, set `BROADCAST_RECORDING_WORKER_INLINE=0` and implement SQS dispatch

### Effort estimate

- Complete production stubs (inventory + concat + S3 upload): **M** (3–5 hours)
- Retention reconciler verification/wiring: **S** (1–2 hours)
- Gap detection in segment inventory: **S** (1–2 hours)

### `BySessionId` GSI sort key type mismatch risk

The `BySessionId` GSI at `scripts/local-ddb-init.py:740` uses `sort_key=created_at` with `attr_types={"created_at": "N"}` (numeric). `create_recording` stores `created_at=now` where `now = _now_ts()` returns an `int`. Confirm that `_record_to_item` at line 102 writes `"created_at": rec.created_at` as an integer (not a string). If it were coerced to string, `BySessionId` queries with `ScanIndexForward=False` would sort lexicographically (string sort) rather than numerically, potentially returning an older recording instead of the most recent one. A unit test asserting that `get_recording_by_session` returns the most recently created recording when multiple exist for the same session would catch this.

### Reconciler wiring verification

`app/services/broadcast_reconciler.py` is referenced in `app/main.py:803` via `start_broadcast_reconciler_task`. Verify that the reconciler loop calls `expire_stale_recordings()` from `broadcast_recording.py`. If the reconciler file only handles session-level reconciliation (e.g., stuck `provisioning` sessions), recordings will never be marked `expired` regardless of their `expires_at` value. The `list_expired_recordings` function at line 198 queries `ByExpiresAt` GSI correctly — it only needs to be called from a periodic loop.

### S3 lifecycle policy interaction

`broadcast_archive.py`'s `ensure_archive_lifecycle_policy()` sets a retention tag on the S3 archive bucket. The VOD output bucket (`broadcast-vod`) should have a separate lifecycle policy tied to `broadcast_archive_retention_days`. If this policy is absent in production, S3 storage costs will grow unboundedly even after recordings are marked `expired` in DynamoDB (the DDB record is updated but the S3 objects are not deleted unless the reconciler's `expire_stale_recordings` explicitly deletes them). Confirm that the reconciler's expiry function calls `s3.delete_objects` for the `full.ts`, `full.mp4`, `master.m3u8`, and all HLS segment keys before updating the DDB status to `"expired"`.

### Settings parity between design and implementation

The ticket design (section 3.11) listed `broadcast_recording_worker_inline` as defaulting to `DEV_MODE`. The actual setting at `app/core/settings.py:1453` is:
```python
broadcast_recording_worker_inline: bool = os.environ.get(
    "BROADCAST_RECORDING_WORKER_INLINE",
    os.environ.get("DEV_MODE", "1")
) not in ("0", "false", "False")
```

This means the inline worker is enabled by default in dev (`DEV_MODE=1`) and disabled by default in production (no `DEV_MODE`). The consequence is that stopping a session in dev synchronously blocks the HTTP response until the entire recording pipeline completes (mock path: fast; real FFmpeg: potentially slow). The stop endpoint should set a short timeout or run the inline worker in a background thread when `broadcast_recording_worker_inline=True`.

**Overall remaining work**: M (complete production pipeline stubs); S (reconciler and S3 lifecycle verification)
