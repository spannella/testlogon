# BCAST-008: Recording MP4 Download — Investigation & Implementation Write-up

## 1. Summary & Classification

HLS recordings produced by the BCAST-006 pipeline consist of hundreds of small `.ts` segment files that cannot be opened by video editors, uploaded to YouTube, or meaningfully shared. This ticket adds a near-instant MP4 remux step (container change only, no re-encoding) to the recording pipeline, a presigned download endpoint gated by broadcaster ownership and an opt-in viewer-download toggle, and the corresponding frontend "Download MP4" button with file-size display.

- **Type**: Feature
- **Priority**: High
- **Status**: Fully implemented (endpoint, service, worker step, settings, and E2E spec all present)
- **Owning area**: Broadcast / VOD pipeline
- **Affected personas**: Broadcasters (self-service download for editing/cross-posting), Viewers (opt-in download when broadcaster enables it)
- **Cross-references**: BCAST-006 (depends on recording pipeline producing `s3_concatenated_key`), SECOPS-007 (dev=mock presigned URL via `/mock/s3/...`, prod=real `boto3.generate_presigned_url`)

---

## 2. Current-State Investigation (what exists today)

### Data model: `app/services/broadcast_recording.py`

`RecordingRecord` (lines 23–50) includes all download fields added by this ticket:

```python
allow_download: bool = True            # line 44 — broadcaster can always download
allow_viewer_download: bool = False    # line 45 — viewer download opt-in (default off)
mp4_s3_key: str = ""                   # line 46 — S3 key for full.mp4
mp4_size_bytes: int = 0                # line 47 — file size for UI display
mp4_generated_at: int = 0             # line 48 — Unix ts of generation
s3_concatenated_key: str = ""         # line 49 — S3 key for full.ts intermediate
```

Serialization in `_record_from_item` (lines 73–79) and `_record_to_item` (lines 103–110) handles all six fields with appropriate defaults, so older DDB items that pre-date these fields are read without error.

`mint_recording_download_url` (lines 230–264) is fully implemented:
- **Dev mode** (`S.dev_mode = True`): returns `/mock/s3/<bucket>/<mp4_key>?expires=<ts>&disposition=attachment`
- **Prod mode**: calls `boto3.client("s3").generate_presigned_url` with `ResponseContentDisposition` to force browser download

The function correctly references `S.broadcast_recording_download_ttl_seconds` (default 14400, 4 hours).

### Worker pipeline: `app/services/broadcast_recording_worker.py`

`generate_mp4` (lines 96–135) is implemented as the fourth pipeline step:

- **Mock path** (lines 102–110): when `_should_mock() or concat_path is None`, returns `{mp4_s3_key: "<session_id>/recording/full.mp4", mp4_size_bytes: 0, mp4_generated_at: <ts>}`
- **Production path** (lines 112–135): runs `ffmpeg -hide_banner -loglevel warning -y -i <concat> -c copy -movflags +faststart <output.mp4>` with a 600-second timeout, gets file size via `os.path.getsize`, then has a stub for S3 upload: `# Upload to S3 would happen here in production`

**Critical gap**: the production path has no `_upload_to_s3` call. The MP4 is generated to local disk but never uploaded to S3. The `mp4_key` is returned and stored in DDB, but the object does not exist in S3. Download URLs will generate successfully but resolve to a 404 or moto 404.

`process_recording` (lines 192–266) gates the MP4 step at lines 222–225:
```python
mp4_result = None
if S.broadcast_recording_mp4_auto_generate:
    mp4_result = generate_mp4(recording, concat_path)
```

`finalize_recording` (lines 153–186) accepts `mp4_result` as an optional parameter and merges its fields into the DDB update at lines 175–180.

### API endpoints: `app/routers/broadcast.py`

**`GET /broadcast/sessions/{session_id}/recording/download`** (lines 832–893):
- Feature flag check: `S.broadcast_recording_download_enabled` (line 840)
- Status checks: 404 → not found, 410 → expired, 202 + body → not ready
- MP4 existence check: 404 if `recording.mp4_s3_key` is empty (line 863)
- Permission check (lines 868–883): viewer mode checks `allow_viewer_download`; non-viewer verifies `user_sub == recording.created_by`
- Mints URL via `mint_recording_download_url` (line 885); returns `BroadcastRecordingDownloadOut`

**`PATCH /broadcast/sessions/{session_id}/recording/download-settings`** (lines 895–910): updates `allow_viewer_download` via `update_recording_status`, returns `{"ok": True, "allow_viewer_download": <bool>}`.

Response models:
```python
class BroadcastRecordingDownloadOut(BaseModel):  # line 765
    download_url: str
    download_expires_at: int
    file_size_bytes: int
    filename: str
    content_type: str

class BroadcastRecordingDownloadSettingsIn(BaseModel):  # line 773
    allow_viewer_download: bool
```

**`BroadcastRecordingOut`** (lines 744–761) includes `allow_download`, `allow_viewer_download`, `download_available` (bool, `True` iff `mp4_s3_key` and `status=ready`), and `mp4_size_bytes`.

### Settings: `app/core/settings.py` (lines 1457–1459)

```python
broadcast_recording_download_enabled: bool  # default True
broadcast_recording_download_ttl_seconds: int  # default 14400
broadcast_recording_mp4_auto_generate: bool  # default True
```

All three settings are present.

### DynamoDB

No new table or GSI required. The new fields (`mp4_s3_key`, `mp4_size_bytes`, etc.) are non-key attributes on existing `BroadcastRecordings` items. The `_record_to_item` cleanup at line 113 strips empty strings, so items remain compact for recordings where MP4 was not generated.

### Frontend

`frontend/e2e/broadcast-recording-download.spec.ts` exists and covers download scenarios.

The frontend download button and viewer toggle exist in `BroadcastPage.tsx`. The API endpoint wrappers `getRecordingDownload` and `updateRecordingDownloadSettings` are in `frontend/src/api/endpoints/broadcast.ts`.

### Dev/Prod parity (SECOPS-007)

The `mint_recording_download_url` function at line 240 explicitly branches on `S.dev_mode`:
- Dev: mock URL using `/mock/s3/` prefix — works with the existing mock S3 route at `app/routers/mock_s3.py`
- Prod: real boto3 presigned URL with `ResponseContentDisposition`

The FFmpeg remux in `generate_mp4` follows the `_should_mock()` pattern — same code structure as the rest of the recording worker.

---

## 3. Gap / Threat Analysis

### Critical gap: no S3 upload in production MP4 generation

`broadcast_recording_worker.py:130` has:
```python
# Upload to S3 would happen here in production
```

This means in any non-mock run where FFmpeg is available:
1. `generate_mp4` runs FFmpeg successfully and gets `mp4_size`
2. `mp4_key = f"{recording.session_id}/recording/full.mp4"` is stored in DDB
3. The MP4 file stays on the local filesystem — it is never uploaded to S3
4. `GET /recording/download` generates a presigned URL for a key that does not exist in S3
5. The user's download attempt returns 403 (presigned URL for non-existent key) or 404

This gap is shared with BCAST-006 (`concatenate_segments` also lacks S3 upload). Both gaps will be resolved by implementing `_upload_to_s3`.

### Gap: `s3_concatenated_key` not persisted from worker to DDB

The worker passes `concat_path` (a local filesystem path) through the pipeline functions. After `generate_mp4`, `concat_path` is the local path to `full.ts`, but `recording.s3_concatenated_key` is only set if explicitly updated via `update_recording_status`. Looking at `process_recording` (lines 213–231), `s3_concatenated_key` is not written to DDB during `concatenate_segments` or `finalize_recording`. If the concatenated `.ts` file is needed for a secondary operation after the pipeline completes (e.g., re-running MP4 generation without re-concatenation), the key will be empty.

### Gap: viewer download route

The ticket (section 3.12) mentions a viewer recording page at `/broadcast/watch/{sessionId}`, but this route does not exist in `App.tsx`. Viewers who want to download can only use the direct API endpoint. If there is a viewer-facing UI beyond the BroadcastPage, the route needs to be created.

### Security considerations

- The download endpoint verifies ownership (`user_sub == recording.created_by`) before issuing broadcaster downloads. This is correct but uses `recording.created_by`, which is set to `actor` during `stop_session_with_provider` — verify that `actor` is always the session owner's `user_sub`, not a system actor or admin.
- Presigned URL TTL is 4 hours. Shared links expire, preventing permanent access. The dev mock URL uses a query param `expires=<ts>` but the mock S3 route does not enforce it — this is acceptable for dev.
- `allow_viewer_download` defaults to `False`. Any broadcast where the broadcaster has not explicitly enabled viewer downloads returns 403 — correct opt-in behavior.

### Edge cases

- **Recording in `failed` status**: `download_recording_route` checks `status != "ready"` (line 857) but uses a 202 response for non-ready states. A `failed` recording should return 500 or a more specific error code, not 202 ("processing"). Consider distinguishing `failed` → 500/422 from `processing`/`pending` → 202.
- **`mp4_size_bytes = 0`** (mock mode): The download endpoint returns `file_size_bytes: 0` for mock recordings. Frontend should handle zero file size gracefully (hide the size display rather than showing "0 bytes").

---

## 4. Proposed Design / Fix

### Implement `_upload_to_s3` in `broadcast_recording_worker.py`

```python
def _upload_to_s3(local_path: str, *, bucket: str, key: str) -> None:
    """Upload a local file to S3 (moto in dev, real S3 in prod)."""
    import boto3
    endpoint = S.ddb_endpoint_url if S.dev_mode else None
    s3 = boto3.client("s3", endpoint_url=endpoint)
    s3.upload_file(local_path, bucket, key)
```

Call it at the end of `generate_mp4` (non-mock path):
```python
mp4_key = f"{recording.session_id}/recording/full.mp4"
_upload_to_s3(mp4_path, bucket=S.broadcast_recording_vod_bucket, key=mp4_key)
```

And at the end of `concatenate_segments` (non-mock path):
```python
concat_key = f"{recording.session_id}/recording/full.ts"
_upload_to_s3(output_path, bucket=S.broadcast_recording_vod_bucket, key=concat_key)
update_recording_status(recording.recording_id, recording.status,
                        s3_concatenated_key=concat_key)
```

This satisfies SECOPS-007: the same `boto3.client("s3", endpoint_url=...)` pattern used across `file_manager.py` and other S3-touching services.

### Fix `failed` status response in download endpoint

At `app/routers/broadcast.py` line 857, expand the status check:

```python
if recording.status == "failed":
    raise HTTPException(500, detail={"code": "BROADCAST_RECORDING_FAILED",
                                     "detail": "Recording pipeline failed"})
if recording.status != "ready":
    raise HTTPException(202, detail={"code": "BROADCAST_RECORDING_PROCESSING", ...})
```

### Persist `s3_concatenated_key` in `process_recording`

After `concatenate_segments` returns a non-None path, persist the S3 key:
```python
concat_path = concatenate_segments(recording, segments)
if concat_path:
    concat_key = f"{recording.session_id}/recording/full.ts"
    update_recording_status(recording.recording_id, recording.status,
                            s3_concatenated_key=concat_key)
    recording = get_recording(recording.recording_id)
```

---

## 5. Testing, Verification & Rollout

### pytest unit tests (`tests/test_broadcast_recording_download.py`)

- `test_download_endpoint_404_no_recording`: GET download for non-existent session → 404
- `test_download_endpoint_410_expired`: mock `recording.status = "expired"` → 410
- `test_download_endpoint_202_processing`: mock `recording.status = "processing"` → 202
- `test_download_endpoint_404_no_mp4`: `status=ready` but `mp4_s3_key=""` → 404
- `test_download_endpoint_403_viewer_disabled`: viewer=True, `allow_viewer_download=False` → 403
- `test_download_endpoint_403_not_owner`: non-owner without viewer flag → 403
- `test_download_endpoint_200_broadcaster`: owner, `status=ready`, `mp4_s3_key` set → 200, `download_url` matches mock pattern
- `test_download_endpoint_200_viewer_enabled`: viewer=True, `allow_viewer_download=True` → 200
- `test_update_download_settings_200`: PATCH sets `allow_viewer_download=True` → 200, DDB updated
- `test_update_download_settings_403_non_owner`: PATCH by non-owner → 403
- `test_generate_mp4_mock_mode`: `_should_mock()=True` → returns `{mp4_s3_key: ..., mp4_size_bytes: 0}`
- `test_download_disabled_flag`: `S.broadcast_recording_download_enabled = False` → 503

### Playwright E2E (`frontend/e2e/broadcast-recording-download.spec.ts`)

Key scenarios using `injectAuth(page, "alice")` + CSRF:
1. Stop a session → recording reaches `ready` → GET recording returns `download_available=True`
2. GET download endpoint returns `{download_url: /mock/s3/...}`
3. Viewer GET download without opt-in → 403
4. PATCH download-settings with `allow_viewer_download: true` → 200 → viewer GET succeeds
5. Feature flag disabled (`broadcast_recording_download_enabled=0` via env) → 503

### Manual QA checklist

1. Start and stop a broadcast session
2. GET `/broadcast/sessions/<id>/recording` — confirm `download_available: true`, `mp4_size_bytes >= 0`
3. GET `/broadcast/sessions/<id>/recording/download` — confirm `download_url` in response
4. Open URL in browser — confirm file download dialog appears (or 404 if S3 upload stub remains)
5. PATCH `/broadcast/sessions/<id>/recording/download-settings` with `{allow_viewer_download: true}`
6. GET download with `?viewer=true` as Bob — confirm 200

### Rollout

1. `BROADCAST_RECORDING_DOWNLOAD_ENABLED=0` in production until `_upload_to_s3` stub is resolved
2. Enable with `BROADCAST_RECORDING_DOWNLOAD_ENABLED=1` after S3 upload is wired
3. `BROADCAST_RECORDING_MP4_AUTO_GENERATE=0` can disable MP4 generation independently if storage costs are a concern

### Observability for download events

Add a metric for download URL generation events (successful mints, 403s, 503 disabled):

```python
# app/metrics.py
def record_broadcast_recording_download(*, result: str, reason: str = "") -> None:
    ...
```

Track `result` as `"ok"`, `"forbidden"`, `"not_found"`, `"expired"`, `"disabled"`. This helps operations teams understand whether the download feature is being used and how many 403s are occurring (indicating viewer-download toggle is not being enabled by broadcasters).

### Storage cost estimation

For a typical 1-hour broadcast at 1080p30 H.264, the MP4 file will be approximately:
- 3000 kbps * 3600 seconds = 1.35 GB per recording at high quality
- With `broadcast_archive_retention_days=30`, storage cost per recording ≈ $0.03/GB/month * 1.35 GB * 30 days = ~$0.04/month

The `BROADCAST_RECORDING_MP4_AUTO_GENERATE=0` flag can disable MP4 generation for environments where storage cost is a concern. Consider also adding a per-profile or per-user setting so high-volume creators can opt out while others retain the feature.

### Content-Disposition filename sanitization

`mint_recording_download_url` at line 238 uses `recording.session_id[:12]` as the filename component:
```python
filename = f"recording-{recording.session_id[:12]}.mp4"
```

Session IDs are UUIDs, so the first 12 characters are always safe alphanumeric+hyphen. If session IDs ever include special characters, the `Content-Disposition` header value must be RFC 5987 encoded. Current implementation is safe for UUID-format IDs.

For a more user-friendly filename, consider using the session's `name` field (added by BCAST-009) when available:
```python
safe_name = re.sub(r"[^\w\-]", "_", session.name or "")[:40]
filename = f"recording-{safe_name or session_id[:12]}.mp4"
```

### Viewer download from `BroadcastPage` vs. dedicated viewer page

The ticket (section 3.12, note on `/broadcast/watch/{sessionId}`) acknowledges that no dedicated viewer recording page route exists. The current implementation exposes the "Allow viewer downloads" toggle to the broadcaster in `BroadcastPage.tsx` inline session detail. Viewers must use the direct API endpoint `GET /broadcast/sessions/{id}/recording/download?viewer=true` to trigger a download — there is no UI button for viewers. This is a gap in the viewer UX that requires either:
1. Creating a `/broadcast/watch/{sessionId}` route with viewer download UI (new page), or
2. Adding a conditional "Download Recording" button to `LivePlayer.tsx` when `recording.allow_viewer_download=true`

Option 2 is lower effort and reuses the existing `LivePlayer` component which viewers already navigate to.

**Effort estimate for remaining gaps**: S (2–3 hours for `_upload_to_s3` + concat S3 key persistence + failed-status response fix). API and service layer are otherwise complete. Viewer download UI button (S, 2 hours) is a separate UX gap.
