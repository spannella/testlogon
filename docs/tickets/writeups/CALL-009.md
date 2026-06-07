# CALL-009: WebRTC Call Recording with Mutual Consent — Investigation & Implementation Write-up

## 1. Summary & Classification

Once a WebRTC call ends all audio/video content is permanently lost. Creators and users who conduct business consultations, coaching sessions, or legal discussions have no platform-native way to create a persistent record. This ticket implements client-side composite call recording using the browser MediaRecorder API, a mutual-consent signaling protocol (both parties must explicitly opt-in before recording begins), server-side recording metadata in DynamoDB, binary upload to S3 (moto in dev, AWS S3 in prod), and a download path for both participants.

**Type**: Feature (media / compliance)
**Priority**: Medium (P1)
**Status**: Fully implemented across all layers; one unimplemented piece is the post-call recording system message in the conversation timeline (the `complete_recording_upload` endpoint does not insert a system message).
**Owning area**: Messaging / Calls / Media Storage
**Cross-references**: CALL-002 (RTCPeerConnection for stream access), CALL-008 (ICE restart does not interrupt recording), CALL-010 (wires this into ConversationView), SECOPS-007 (dev/prod parity — `S.dev_mode` selects mock S3 path vs real presigned URL; same code path)
**Affected users**: Both participants in a 1-on-1 WebRTC call.

---

## 2. Current-State Investigation

### 2.1 Backend Router

`app/routers/call_recording.py` (576 lines) provides all recording endpoints, registered in `app/main.py:144,608`:

| Method | Path | Line | Purpose |
|--------|------|------|---------|
| `POST` | `/messages/calls/{call_id}/recording/request` | 141 | Create recording record after signaling consent is in flight |
| `POST` | `/messages/calls/{call_id}/recording/consent` | 183 | Record consent from peer; transitions status `pending_consent → recording` |
| `POST` | `/messages/calls/{call_id}/recording/decline` | 227 | Decline recording request; soft-deletes the pending record |
| `POST` | `/messages/calls/{call_id}/recording/upload/presign` | 258 | Return presigned PUT URL (dev: `/mock/s3/...`, prod: real S3 presigned URL) |
| `POST` | `/messages/calls/{call_id}/recording/upload/complete` | 322 | Mark upload complete; verifies file exists; transitions `uploading → ready` |
| `GET`  | `/messages/calls/{call_id}/recording` | 396 | Get recording metadata for a call |
| `GET`  | `/messages/recordings` | 439 | List recordings for user (with optional `conversation_id` query param, line 443) |
| `GET`  | `/messages/recordings/{recording_id}/download` | 492 | Return presigned GET URL (dev: `/mock/s3/...`, prod: real S3 URL) |
| `DELETE` | `/messages/recordings/{recording_id}` | 528 | Soft-delete a recording |

All endpoints use `Depends(_get_user_id)` which delegates to `get_messaging_user_id` from the messaging router, supporting both cookie-based UI sessions and bearer-token auth.

### 2.2 Dev/Prod S3 Parity

`app/routers/call_recording.py:301-312` implements the presigned upload URL:
```python
if S.dev_mode:
    upload_url = f"/mock/s3/{bucket}/{s3_key}"
else:
    upload_url = s3_client().generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket, "Key": s3_key, "ContentType": body.content_type},
        ExpiresIn=S.call_recording_upload_ttl_seconds,
    )
```

In dev mode, moto is running in-process (initialized by `app/core/dev_s3.py` at startup). The `S3_BUCKET` (`filemgr_bucket`) stores recordings in the same mock S3 instance that the file manager uses. The `/mock/s3/` proxy endpoint handles the actual PUT. The download endpoint mirrors this pattern at `:560-569`. This is correct SECOPS-007 behavior: same upload/download logic, flag-selected S3 path.

### 2.3 DynamoDB Table

`scripts/local-ddb-init.py:640-650` defines `CallRecordings` with PK `recording_id` (String) and three GSIs:
- `ByCallIdCreatedAt` (PK: `call_id`, SK: `created_at`)
- `ByConversationCreatedAt` (PK: `conversation_id`, SK: `created_at`)
- `ByStatus` (PK: `status`, SK: `created_at`)
with `attr_types={"created_at": "N"}` to avoid the `ValidationException` from string-typed numeric GSI sort keys.

### 2.4 `call_recording_store.py` Service

`app/services/call_recording_store.py` (279 lines):
- `:15`: `RecordingStatus` Literal — `"pending_consent" | "recording" | "uploading" | "ready" | "failed" | "deleted"`.
- `:19-26`: `_VALID_TRANSITIONS` dict enforces status state machine.
- `:35-55`: `CallRecordingRecord` dataclass with `recording_id`, `call_id`, `conversation_id`, `initiated_by`, `participants: list[str]`, `status`, `s3_key`, `s3_bucket`, `mime_type`, `duration_seconds`, `file_size_bytes`, `consent_ts`, `started_at`, `completed_at`, `created_at`, `updated_at`, `upload_ticket_id`, `download_count`, `error_message`, `ttl`.
- `:117`: `create_recording()`.
- `:144`: `get_recording()`.
- `:152`: `get_recordings_for_call()` — queries `ByCallIdCreatedAt` GSI.
- `:163`: `get_active_recording_for_call()` — returns first non-deleted, non-failed recording for a call.
- `:172`: `get_recordings_for_conversation()` — queries `ByConversationCreatedAt` GSI.
- `:188`: `update_recording_status()` — validates transitions via `_VALID_TRANSITIONS`.

### 2.5 Configuration Settings

`app/core/settings.py:1468-1475`:

| Setting | Default | Purpose |
|---------|---------|---------|
| `call_recording_enabled` | `True` (env `"1"`) | Master feature flag |
| `call_recording_max_duration_seconds` | `3600` | Auto-stop recording after 1 hour |
| `call_recording_upload_ttl_seconds` | `600` | Presigned PUT URL validity |
| `call_recording_max_file_size_bytes` | `2 GB` | Reject uploads exceeding this |
| `call_recording_retention_days` | `90` | DDB TTL in days |
| `call_recording_s3_prefix` | `"call-recordings/"` | S3 key prefix |
| `call_recordings_table_name` | `"CallRecordings"` | DDB table name |
| `call_recording_download_ttl_seconds` | `3600` | Presigned GET URL expiry |

### 2.6 Signaling Types

`app/services/messaging_call_signaling.py:23-27` includes all five recording event types in `ALLOWED_SIGNALING_TYPES`. `STATE_ALLOWED_SIGNALING_TYPES["connected"]` (`:49-50`) allows them only during `connected` state. The relay endpoint validates these constraints and forwards the event as an SSE payload to the recipient.

### 2.7 Frontend Recording Hook

`frontend/src/hooks/useCallRecording.ts` (322 lines) manages the full client-side recording lifecycle:
- **Params**: `callId`, `userId`, `localStream`, `remoteStream`, `isConnected`, `enabled`.
- **State**: `recordingState` (`"idle" | "requesting" | "consent_pending" | "recording" | "stopping" | "uploading" | "complete" | "error"`), `recordingId`, `duration`, `isInitiator`, `consentPendingFrom`, `error`.
- **Internal SSE listener**: listens to `"messaging:call-event"` CustomEvents for the five `call.recording_*` types (`:105-136`), updating hook state directly.
- **Canvas composition**: Two video tracks rendered side-by-side on an `OffscreenCanvas`; two audio tracks mixed via `AudioContext` + `MediaStreamAudioDestinationNode`.
- **MediaRecorder**: probes `MediaRecorder.isTypeSupported()` for `"video/webm;codecs=vp8,opus"` first; falls back to `"video/mp4;codecs=h264,aac"` for Safari.

### 2.8 Frontend State Machine Extensions

`frontend/src/pages/messages/callStateMachine.ts:17-19`: `recordingState`, `recordingId`, `recordingRequestedBy` fields on `CallMachineState`.

`callStateMachine.ts:40-45`: Six recording events (`RECORDING_REQUEST_SENT`, `RECORDING_REQUEST_RECEIVED`, `RECORDING_ACCEPTED`, `RECORDING_DECLINED`, `RECORDING_STARTED`, `RECORDING_STOPPED`).

`callStateMachine.ts:164-183`: Recording state reducer. All recording events are guarded by `phase === "connected"` except `RECORDING_STOPPED`.

### 2.9 Overlay UI

`frontend/src/pages/messages/CallSessionOverlay.tsx:42-70`: Props include `isRecording`, `recordingDuration`, `onRequestRecording`, `onStopRecording`, `recordingEnabled`, `showRecordingConsent`, `recordingConsentFrom`, `onConsentRecording`.

`:222-235`: Record button in `CallControls`. `:425`: Red "REC" animated badge. Consent dialog is integrated directly into the overlay (not a separate component); rendered when `showRecordingConsent` is truthy.

### 2.10 SSE Event Registration

`frontend/src/hooks/useMessagingStream.ts:173-177` registers all five `call.recording_*` event types in `EVENT_TYPES`. They are dispatched as `"messaging:call-event"` CustomEvents (same as other `call.*` events), so the `useCallRecording` hook's internal listener receives them.

### 2.11 Feature Flag

`frontend/src/lib/featureFlags.ts:126-127`: `callRecordingEnabled` (read from `VITE_CALL_RECORDING_ENABLED`) and `isCallRecordingEnabled()` function.

---

## 3. Gap / Threat Analysis

### 3.1 Missing Timeline System Message on Recording Completion

The `complete_recording_upload` endpoint (`app/routers/call_recording.py:322`) transitions the recording to `"ready"` but does **not** insert a system message into the conversation timeline. The CALL-009 spec (section 3.10) describes a `call_recording_available` system message that would render a download button in the message bubble. Without this, users have no in-conversation notification that a recording is available — they must navigate to a separate recordings panel (which also does not exist as a frontend component; see CALL-010).

**Impact**: Users cannot discover recordings from the conversation view; they must know to visit a separate page.

### 3.2 No IndexedDB Fallback for Interrupted Uploads

If the user refreshes the page during an active recording or upload, the in-memory `MediaRecorder` Blob is lost. The backend recording record remains in `"recording"` or `"uploading"` status indefinitely (no cleanup job targets these stale records).

**Impact**: Lost recording data on page refresh or crash during recording; orphaned DDB records accumulating in `"recording"` status.

### 3.3 Abuse Vector: Consent Signal Bypassing

The consent protocol relies on signaling events being routed honestly. An attacker controlling a custom client could send a `call.recording_accept` signal without ever having received a `call.recording_request`. The backend `consent` endpoint (`app/routers/call_recording.py:183`) validates that a `CallRecordingRecord` with status `pending_consent` exists for the `call_id` and that the requester is a participant — but it does not verify that the consenting user received the request signal. An attacker who knows the `call_id` and `recording_id` (both guessable only by a call participant) could call the consent endpoint directly.

**Impact**: Low risk in practice — both values require being a call participant to know. The two-party consent audit trail still records both the request and the acceptance with timestamps. For legal jurisdictions requiring documented consent, this is adequate. However, for maximum assurance, the `consent` endpoint should verify that the accepting user is NOT the initiating user (`initiated_by != user_id`).

### 3.4 File Size Validation at Upload Time Only

The `presign_recording_upload` endpoint validates `file_size_bytes` against `S.call_recording_max_file_size_bytes` at presign time (`:286-290`). The `complete_recording_upload` endpoint does not re-validate the actual uploaded file size against the declared size (it skips `head_object` in dev mode, `:363`). In prod, the `head_object` call at completion time should compare the S3 object's `ContentLength` against the declared `file_size_bytes`.

**Impact**: In prod, a client could lie about file size at presign time (passing a small value to bypass the quota check) and then upload a larger file. The `head_object` validation gap allows quota evasion.

### 3.5 GSI Scan for Global Recordings List

`list_user_recordings` without `conversation_id` performs a full table scan with `Limit=200` (`:455-463`). As the table grows with recordings from many users, this scan becomes expensive in both latency and read capacity.

**Impact**: Production scaling issue. The `ByParticipantCreatedAt` GSI described in the spec (section 3.3) was not implemented; instead the v1 simplification uses `ByConversationCreatedAt`. A per-user GSI would avoid the scan.

---

## 4. Proposed Design / Fix

### 4.1 Insert Timeline System Message on Upload Complete

In `app/routers/call_recording.py:322`, after setting `status = "ready"`, call `emit_call_timeline_event` from `app/services/messaging_call_timeline.py`:

```python
from app.services.messaging_call_timeline import emit_call_timeline_event
emit_call_timeline_event(
    call_id=call_session.call_id,
    conversation_id=call_session.conversation_id,
    actor_user_id=user_id,
    event_type="call.recording_available",
    call_state="ended",
    reason=recording.recording_id,
    event_ts=int(now_ts()),
)
```

Add `"call.recording_available"` to `_preview_for_event` in `messaging_call_timeline.py:21-43`, returning `"Call recording available"`. The frontend `MessageBubble` component should render `system_event === "call_recording_available"` with a Download button linking to `GET /messages/recordings/{recording_id}/download`.

### 4.2 Stale Recording Cleanup Job

Add a background task step to `_messaging_background_loop()` (messaging.py:13350):

```python
# D) Clean up stale recordings (no upload within TTL)
await _cleanup_stale_recordings()
```

`_cleanup_stale_recordings()` scans `ByStatus` GSI with `status="uploading"` and `created_at < now - upload_ttl * 2`, transitions them to `"failed"` via `update_recording_status`. This prevents DDB pollution from abandoned uploads.

### 4.3 Fix Consent Endpoint: Requester Must Not Be Initiator

In `app/routers/call_recording.py:183`, add:

```python
if recording.initiated_by == user_id:
    raise HTTPException(400, detail={"code": "cannot_consent_own_request", "message": "Cannot consent to your own recording request"})
```

This closes the gap described in 3.3 and is consistent with the spec's two-party consent requirement.

### 4.4 Add `head_object` Size Validation in `complete_recording_upload`

Remove the `# In dev mode, skip head_object verification (moto mock)` short-circuit at `:363` and replace it with a conditional that uses moto's in-process S3 in dev (moto supports `head_object`). Validate `object["ContentLength"]` is within 5% of `body.file_size_bytes` in all environments.

### 4.5 Add `ByParticipantCreatedAt` GSI for Efficient Per-User Listing

Add to `scripts/local-ddb-init.py:640-650`:
```python
{"index_name": "ByParticipantCreatedAt", "partition_key": "participant_key", "sort_key": "created_at"},
```
In `create_recording()`, write two DDB items: the main recording record and a secondary GSI-index item per participant with `participant_key = f"USER#{participant_id}"`. This enables `O(1)` per-user recording lookups instead of the current full-table scan.

### 4.6 Dev/Prod Parity (SECOPS-007)

The `S.dev_mode` branch in `presign_recording_upload` (`:301-312`) and `download_recording` (`:560-569`) are the only deviations from a single code path. Both branches perform the same logical operation (generate a URL to access the S3 object) with flag-selected backends. The moto S3 instance runs in-process during dev startup via `app/core/dev_s3.py`, so the same boto3 API calls that generate real presigned URLs in prod are used in dev — moto intercepts them at the botocore layer. This satisfies SECOPS-007: the code path is the same; only the URL format differs.

For the `head_object` gap (4.4), moto supports `head_object` natively, so the `dev_mode` skip is not needed and should be removed.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest Unit Tests

**File**: `tests/test_call_recording_integration.py` (571 lines, exists)

Additional cases needed:
- `test_consent_endpoint_rejects_own_request`: Initiator calling `/recording/consent` returns 400 `cannot_consent_own_request`.
- `test_upload_complete_verifies_s3_object_size`: Mock `head_object` to return a different `ContentLength`; verify 400 error.
- `test_stale_recording_cleanup`: Seed a recording with `status="uploading"` and `created_at` in the past; run cleanup; verify status transitions to `"failed"`.
- `test_list_recordings_by_conversation_id`: Create two recordings for different conversations; query with `conversation_id`; verify correct filtering.

**Mock setup**: moto `@mock_aws` on DynamoDB and S3; `CALL_RECORDING_ENABLED=1`; no real AWS required.

### 5.2 Playwright E2E Tests

**Files**: `frontend/e2e/call-recording.spec.ts` (724 lines), `frontend/e2e/call-recording-integration.spec.ts` (601 lines)

Key scenarios to verify:
1. Alice presses Record during a connected call; Bob sees consent dialog; Bob accepts; both see "REC" badge.
2. Bob declines; Alice sees "Recording declined" toast; no REC badge appears.
3. Feature flag `CALL_RECORDING_ENABLED=0` → Record button hidden.
4. `POST /messages/calls/{id}/recording/upload/complete` → recording appears in `GET /messages/recordings?conversation_id=...` response.
5. After recording completes, conversation timeline shows "Call recording available" system message (once 4.1 is implemented).
6. `GET /messages/recordings/{id}/download` returns a valid URL for both Alice and Bob; 403 for a third party.

**Media setup**: Playwright `--use-fake-device-for-media-stream` flag. The `MediaRecorder` in Chromium works with fake camera/mic streams.

### 5.3 Manual QA

1. Start a video call between two browser windows.
2. Click Record; accept consent in the second window.
3. Verify red "REC" badge animates in both windows.
4. End the call after 10 seconds.
5. Verify a toast "Uploading call recording..." appears, followed by "Call recording saved."
6. Navigate to `GET /messages/recordings?conversation_id={id}` (raw API); verify a `ready` status recording with non-zero `duration_seconds` and `file_size_bytes`.
7. Fetch the download URL; verify the file is a valid WebM/MP4 playable in a browser.

### 5.4 Metrics and Observability

Add to `app/metrics.py`:
- `record_call_recording_started(mode: str)` — `mode` is `"video"` or `"audio"`.
- `record_call_recording_uploaded(duration_seconds: float, file_size_bytes: int)`.
- `record_call_recording_failed(reason: str)`.

### 5.5 Rollback

`call_recording_enabled` env var set to `"0"` disables all recording API endpoints (`:39-41` of router). The DDB table and S3 objects persist harmlessly. The frontend feature flag `VITE_CALL_RECORDING_ENABLED` independently hides the Record button.

**Effort**: Gap 4.1 (timeline message): **S** (1 day). Gap 4.3 (consent self-check): **S** (0.5 day). Gap 4.4 (head_object validation): **S** (0.5 day). Gap 4.2 (stale cleanup): **M** (1.5 days). Gap 4.5 (participant GSI): **M** (2 days).
