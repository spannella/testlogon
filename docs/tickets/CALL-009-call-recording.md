# CALL-009: WebRTC Call Recording with Mutual Consent

**Status**: Implemented  
**Author**: Engineering  
**Date**: 2026-05-24  
**Priority**: Medium  
**Estimated effort**: 8-12 days  
**Dependencies**: CALL-002 (RTCPeerConnection), CALL-008 (ICE Restart)

> **NOTE: This feature is FULLY IMPLEMENTED.** Backend: `app/routers/call_recording.py` (576 lines), `app/services/call_recording_store.py` (279 lines). Frontend: `frontend/src/hooks/useCallRecording.ts` (322 lines), recording UI in `CallSessionOverlay.tsx`, state machine fields in `callStateMachine.ts`. Settings in `app/core/settings.py:1157-1165`. DDB table in `scripts/local-ddb-init.py:640-650`. E2E tests in `frontend/e2e/call-recording.spec.ts` (724 lines). See Codebase References at the bottom.

---

## 1. Overview & Motivation

### Problem Statement

Users conducting business calls, interviews, consultations, and legal discussions through the platform's WebRTC calling system currently have no way to create a persistent record of their conversations. Once a call ends, all audio/video content is lost. This forces users to rely on external recording tools (screen capture software, separate devices) which produce suboptimal quality, require manual setup, and bypass the platform's consent and access-control mechanisms.

### Goals

1. Allow either participant in a 1-on-1 call to initiate a recording request during an active call.
2. Enforce **mutual consent**: recording only begins after BOTH participants explicitly opt-in via an in-call consent dialog.
3. Display a persistent, highly visible **recording indicator** ("REC" badge with red dot) to both participants for the entire duration of the recording.
4. Capture a composite stream (both participants' audio + video) and store the result server-side in S3.
5. After the call ends, make the recording available for download by **either** participant as an MP4 file.
6. Provide administrative controls: feature flag, max duration limit, and storage quota enforcement.

### User Stories

| # | As a... | I want to... | So that... |
|---|---------|-------------|-----------|
| 1 | Caller (Alice) | Press a "Record" button during an active call | I can initiate a recording of this conversation |
| 2 | Callee (Bob) | See a consent dialog when Alice requests recording | I can choose to accept or decline the recording |
| 3 | Participant | See a red "REC" indicator while recording is active | I always know when I'm being recorded |
| 4 | Participant | Download the recording after the call | I have a persistent record of the conversation |
| 5 | Participant (declining) | Decline a recording request | My privacy is protected — no recording occurs |
| 6 | Participant | Stop a recording mid-call | I can control what portions are recorded |
| 7 | Admin | Disable call recording platform-wide | I can comply with regional regulations |

### Privacy and Legal/Compliance Considerations

- **Two-party consent**: Recording NEVER starts without explicit acceptance from both parties. This aligns with two-party consent laws (California, EU GDPR Article 6, etc.).
- **Recording indicator**: The red "REC" badge is mandatory and cannot be hidden or suppressed while recording is active. This satisfies FTC disclosure requirements.
- **Consent audit trail**: Both the recording request and acceptance are logged as signaling events with timestamps, providing a verifiable consent audit trail.
- **No silent recording**: There is no API or backend mechanism to initiate recording without the consent signaling protocol. The backend rejects upload completion unless a valid consent record exists.
- **Retention policy**: Recordings are subject to the platform's data retention policy. A TTL can be configured (`CALL_RECORDING_RETENTION_DAYS`) after which recordings are auto-deleted from S3.
- **Right to deletion**: Either participant can request deletion of a recording they participated in (via the existing content deletion workflow).

### Scope for v1

- **In scope**: Client-side recording via MediaRecorder API, mutual consent protocol, S3 upload, download by both participants, recording metadata in DynamoDB.
- **Out of scope for v1**: Server-side recording (SFU/MCU), transcription, searchable recording archives, recording during group calls, real-time streaming of recordings to third parties, post-processing (noise reduction, normalization), integration with external storage providers.

---

## 2. Current State Analysis

### 2.1 Call Lifecycle Flow

The current call flow managed by `app/services/messaging_call_lifecycle.py`:

```
Alice                         Backend                          Bob
  |-- POST /calls/invite ----->|-- SSE call.invite ----------->|
  |                            |                               |
  |<-- SSE call.accept --------|<-- POST /calls/{id}/accept ---|
  |                            |  (state: invited -> accepted) |
  |                            |                               |
  |-- POST /signal (offer) --->|-- SSE webrtc.offer ---------->|
  |<-- SSE webrtc.answer ------|<-- POST /signal (answer) -----|
  |<-> ICE trickle <---------->|<-> ICE trickle <------------->|
  |                            |  (state: accepted -> connected)|
  |                            |                               |
  |   [CALL ACTIVE — RECORDING WOULD HAPPEN HERE]             |
  |                            |                               |
  |-- POST /calls/{id}/end --->|-- SSE call.end -------------->|
  |                            |  (state: connected -> ended)  |
```

### 2.2 MediaRecorder API Availability

The MediaRecorder API is well-supported across modern browsers:

| Browser | Supported Codecs | Notes |
|---------|-----------------|-------|
| Chromium 90+ | `video/webm;codecs=vp8,opus`, `video/webm;codecs=vp9,opus`, `video/webm;codecs=h264,opus` | Full support, stable |
| Firefox 79+ | `video/webm;codecs=vp8,opus` | No H.264 in MediaRecorder |
| Safari 14.1+ | `video/mp4;codecs=h264,aac` | Does NOT support WebM; requires MP4 container |

For maximum compatibility, the recording hook will probe `MediaRecorder.isTypeSupported()` at initialization and select the best available codec:
1. `video/webm;codecs=vp8,opus` (universal WebM)
2. `video/mp4;codecs=h264,aac` (Safari fallback)

### 2.3 Stream Access in `useRtcPeerConnection.ts`

The existing hook (see `frontend/src/hooks/useRtcPeerConnection.ts:85-88`) exposes both streams as React state:

```typescript
const [localStream, setLocalStream] = React.useState<MediaStream | null>(null);
const [remoteStream, setRemoteStream] = React.useState<MediaStream | null>(null);
```

These are also exposed on `window` in dev mode (lines 152-156):
```typescript
if (import.meta.env.DEV) {
  (window as unknown as Record<string, unknown>).__rtcPeerConnection = pc;
  (window as unknown as Record<string, unknown>).__rtcLocalStream = localMediaStream;
  (window as unknown as Record<string, unknown>).__rtcRemoteStream = null;
}
```

The `CallSessionOverlay.tsx` receives both streams as props (lines 44-45):
```typescript
localStream?: MediaStream | null;
remoteStream?: MediaStream | null;
```

This means the recording hook can access both streams without any refactoring to the existing call infrastructure.

### 2.4 `CallRuntimeResources` Interface

(See `frontend/src/pages/messages/callStateMachine.ts:190-197`.)

```typescript
export interface CallRuntimeResources {
  peerConnection?: RTCPeerConnection | null;
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  detachListeners?: Array<() => void>;
  teardownTimers?: Array<number>;
  cleanedUp?: boolean;
}
```

The `useCallRecording` hook (see `frontend/src/hooks/useCallRecording.ts`) manages its own cleanup for the `MediaRecorder`.

### 2.5 Call Session DDB Model

`CallSessionRecord` in `app/services/messaging_call_sessions.py` (see `:19-50`, includes billing fields 37-48 and voicemail_message_id at 50):

| Field | Type | Purpose |
|-------|------|---------|
| `call_id` | str (PK) | Unique call identifier |
| `conversation_id` | str | DM conversation this call belongs to |
| `caller_user_id` | str | Who initiated the call |
| `callee_user_id` | str | Who received the call |
| `initial_mode` | "audio" \| "video" | Call type |
| `state` | CallState | Current lifecycle state |
| `start_ts` | int | When the call was initiated |
| `connect_ts` | int \| None | When media connected |
| `end_ts` | int \| None | When the call ended |
| `end_reason` | str \| None | Why the call ended (e.g., "user_hangup", "timeout") |
| `updated_at` | int \| None | Last modification timestamp |
| `network_path` | "p2p" \| "turn" \| None | Connection type |
| `lifecycle_events` | list[dict] | Ordered log of state transitions with timestamps |
| `idempotency_records` | dict \| None | Tracks processed idempotency keys to prevent duplicate actions |

Recording metadata will reference `call_id` as a foreign key, linking recordings to their parent call session.

### 2.6 Existing Upload Patterns

The file manager (`app/services/filemanager.py`) implements a presigned upload flow:

1. **Request upload URL**: `presign_upload(user, path, content_type=...)` generates a presigned S3 PUT URL (line 2207)
2. **Client uploads directly to S3** via the presigned URL
3. **Register upload**: `register_presigned_upload(user, path, ticket_id, ...)` validates the upload completed and creates the file record (line 2264)

In dev mode (moto), presigned URLs don't resolve to an external host, so a proxy endpoint (`/mock/s3/...`) is used instead (line 2221). The recording upload will follow the same pattern.

### 2.7 `CallSessionOverlay.tsx` UI Layout — IMPLEMENTED

The overlay Props (see `frontend/src/pages/messages/CallSessionOverlay.tsx:42-70`) include recording-related props:

```typescript
interface Props {
  session: CallSessionUi;
  // ...streams, mute, camera, accept/decline/end/dismiss...
  isRecording?: boolean;           // line 58
  recordingDuration?: number;
  onRequestRecording?: () => void; // line 60
  onStopRecording?: () => void;    // line 61
  recordingEnabled?: boolean;      // line 62
  showRecordingConsent?: boolean;   // line 63
  // ...screen share props...
}
```

The `CallControls` component (see `:150-245`) renders controls in order: Mute, Camera, Record, Screen Share, End Call. The recording button is at `:222-235`, with the "REC" indicator at `:425`.

### 2.8 Signaling Infrastructure — IMPLEMENTED

The signaling types for recording are already in `ALLOWED_SIGNALING_TYPES` (see `app/services/messaging_call_signaling.py:23-27`) and in `STATE_ALLOWED_SIGNALING_TYPES["connected"]` (see `:49-50`).

---

## 3. Technical Design

### 3.1 Recording Approach: Client-Side Composite Stream

The recording is performed client-side using the browser's MediaRecorder API. This approach:
- Requires no server-side media infrastructure (no SFU/MCU)
- Captures the exact audio/video the user sees/hears
- Leverages existing stream access from `useRtcPeerConnection`
- Only uploads the final file (not real-time streaming)

**Composite stream construction**:

```
Local Video Track ──┐
                    ├──> OffscreenCanvas (side-by-side) ──> canvas.captureStream() ──┐
Remote Video Track ─┘                                                                ├──> MediaRecorder
                                                                                     │
Local Audio Track ──┐                                                                │
                    ├──> AudioContext + MediaStreamAudioDestinationNode ──────────────┘
Remote Audio Track ─┘
```

**Canvas composition** (side-by-side layout):
- Canvas resolution: 1280x480 (640x480 per participant) for video calls
- Audio-only calls: no canvas needed, just mix audio tracks
- Frame rate: 30fps (matching typical webcam output)
- The local participant is rendered on the left, remote on the right
- Participant name labels overlaid at the bottom of each half

**Audio mixing**:
```typescript
const audioCtx = new AudioContext();
const localSource = audioCtx.createMediaStreamSource(localStream);
const remoteSource = audioCtx.createMediaStreamSource(remoteStream);
const destination = audioCtx.createMediaStreamDestination();

localSource.connect(destination);
remoteSource.connect(destination);

// destination.stream contains the mixed audio track
```

**MediaRecorder configuration**:
```typescript
const compositeStream = new MediaStream([
  ...canvasCaptureStream.getVideoTracks(),  // composite video
  ...destination.stream.getAudioTracks(),    // mixed audio
]);

const mimeType = MediaRecorder.isTypeSupported("video/webm;codecs=vp8,opus")
  ? "video/webm;codecs=vp8,opus"
  : "video/mp4;codecs=h264,aac";  // Safari fallback

const recorder = new MediaRecorder(compositeStream, {
  mimeType,
  videoBitsPerSecond: 1_500_000,  // 1.5 Mbps video
  audioBitsPerSecond: 128_000,     // 128 kbps audio
});
```

### 3.2 Consent Protocol

Recording requires mutual consent via signaling events. The protocol:

```
Alice (initiator)                Backend                        Bob (responder)
     |                              |                               |
     |-- [presses Record] -------->|                               |
     |                              |                               |
     |-- POST /signal ------------>|                               |
     |   type: call.recording_request                              |
     |   payload: { requested_by: alice_id }                       |
     |                              |-- SSE call.recording_request ->|
     |                              |                               |
     |                              |       [Bob sees consent dialog]|
     |                              |                               |
     |                              |<-- POST /signal --------------|
     |                              |    type: call.recording_accept |
     |<-- SSE call.recording_accept |    payload: { consented: true }|
     |                              |                               |
     |   [Both start recording]     |   [Both show REC indicator]   |
     |                              |                               |
     |-- POST /signal ------------>|-- SSE call.recording_started ->|
     |   type: call.recording_started                               |
     |   payload: { recording_id }  |                               |
```

**Decline flow**:
```
     |                              |<-- POST /signal --------------|
     |                              |    type: call.recording_decline|
     |<-- SSE call.recording_decline|    payload: { reason: "user" }|
     |                              |                               |
     |   [Show "Recording declined" toast]                          |
```

**Stop recording**:
```
     |-- POST /signal ------------>|-- SSE call.recording_stopped ->|
     |   type: call.recording_stopped                               |
     |   payload: { recording_id, reason: "user_stopped" }          |
```

**Key rules**:
- Either party can initiate a recording request at any time during `connected` state
- Only ONE active recording per call (second request returns error if one is active)
- Either party can stop the recording
- If the call ends while recording, the recording is automatically finalized
- Recording requests are only valid in `connected` state

### 3.3 Data Model: `CallRecordings` DynamoDB Table — IMPLEMENTED

**Table name**: `CallRecordings` (env: `DDB_CALL_RECORDINGS_TABLE`, see `app/core/settings.py:1164`)  
**Partition key**: `recording_id` (String)  
(See `scripts/local-ddb-init.py:640-650` for table definition, `app/services/call_recording_store.py:35-55` for `CallRecordingRecord` dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `recording_id` | S (PK) | `"rec_" + uuid4().hex` |
| `call_id` | S | FK to CallSessionRecord |
| `conversation_id` | S | Conversation the call belongs to |
| `initiated_by` | S | User who pressed "Record" |
| `participants` | L[S] | List of user IDs who consented [`[alice_id, bob_id]`] |
| `status` | S | `pending_consent` \| `recording` \| `uploading` \| `processing` \| `ready` \| `failed` \| `deleted` |
| `s3_key` | S \| null | S3 object key after upload (e.g., `call-recordings/{recording_id}/recording.webm`) |
| `s3_bucket` | S \| null | S3 bucket name |
| `mime_type` | S \| null | `video/webm` or `video/mp4` |
| `duration_seconds` | N \| null | Recording duration (set on completion) |
| `file_size_bytes` | N \| null | File size in bytes |
| `consent_ts` | N | Unix timestamp when both parties consented |
| `started_at` | N | Unix timestamp when recording actually began |
| `completed_at` | N \| null | Unix timestamp when upload finished |
| `created_at` | N | Unix timestamp of record creation |
| `updated_at` | N | Last modification timestamp |
| `upload_ticket_id` | S \| null | Presigned upload ticket for validation |
| `ttl` | N | DynamoDB TTL for auto-deletion (retention policy) |

**GSIs**:

| GSI Name | Partition Key | Sort Key | Purpose |
|----------|--------------|----------|---------|
| `ByCallId` | `call_id` | `created_at` (N) | Find recordings for a specific call |
| `ByParticipantCreatedAt` | `participant_key` | `created_at` (N) | List recordings a user participated in |
| `ByStatus` | `status` | `created_at` (N) | Admin: find stuck/failed recordings |

The `participant_key` GSI uses a denormalized field: for a recording with participants `[alice, bob]`, two items are written to a secondary "participant index" table, OR the GSI is written per-participant at recording creation time. For simplicity in v1, we write a single record and use the `ByCallId` GSI to find recordings, then filter by participant in the service layer.

**Alternative (v1 simplification)**: Use a single GSI `ByConversationCreatedAt` (partition: `conversation_id`, sort: `created_at`). Since both participants are in the conversation, both can query this GSI.

### 3.4 Upload Flow

After the call ends (or recording is stopped), the client-side recording is finalized and uploaded:

```
Client                           Backend                          S3
  |                                 |                              |
  |-- POST /calls/{call_id}/       |                              |
  |   recordings/{rec_id}/         |                              |
  |   upload-url                   |                              |
  |   { mime_type, file_size }     |                              |
  |                                 |-- generate_presigned_url() ->|
  |<-- { upload_url, ticket_id } --|                              |
  |                                 |                              |
  |-- PUT upload_url (binary) -----|---[direct to S3]------------>|
  |                                 |                              |
  |-- POST /calls/{call_id}/       |                              |
  |   recordings/{rec_id}/         |                              |
  |   complete                     |                              |
  |   { ticket_id, duration_s,     |                              |
  |     file_size_bytes }          |                              |
  |                                 |-- head_object (verify) ----->|
  |                                 |<-- 200 (exists, size ok) ----|
  |                                 |                              |
  |<-- { status: "ready",          |                              |
  |      download_url: ... } ------|                              |
```

**Dev mode**: In dev mode (moto S3), the presigned URL is replaced with a `/mock/s3/call-recordings/...` proxy path, following the same pattern as file manager uploads.

### 3.5 Download Endpoint

```
GET /messaging/messages/calls/{call_id}/recording/{recording_id}/download
```

**Auth**: `Depends(get_messaging_user_id)` — standard call auth  
**Access control**: Requester must be in `participants[]` list OR have admin role  
**Response**: 302 redirect to a time-limited presigned S3 GET URL (60-minute expiry)  
**Error cases**: 404 if recording not found or not `ready`, 403 if not a participant

### 3.6 Server-Side WebM-to-MP4 Conversion (Optional, Post-v1)

WebM files from Chromium/Firefox may not play natively on iOS/Safari devices. A post-upload conversion step can be added:

1. After `complete` endpoint is called, set `status = "processing"`
2. Enqueue an async job (same pattern as VOD transcode in `app/services/vod_transcode_queue.py`)
3. Job runs FFmpeg: `ffmpeg -i input.webm -c:v libx264 -c:a aac -movflags +faststart output.mp4`
4. Upload MP4 to S3 alongside WebM original
5. Update record with MP4 S3 key, set `status = "ready"`

For v1, we skip conversion and serve the original WebM/MP4 as-is. The download endpoint returns the file in whatever format was uploaded.

### 3.7 Signaling Event Types — IMPLEMENTED

Recording event types are in `ALLOWED_SIGNALING_TYPES` (see `app/services/messaging_call_signaling.py:23-27`) and in `STATE_ALLOWED_SIGNALING_TYPES["connected"]` (see `:49-50`):

```python
# In ALLOWED_SIGNALING_TYPES (line 23-27):
"call.recording_request",
"call.recording_accept",
"call.recording_decline",
"call.recording_started",
"call.recording_stopped",

# In STATE_ALLOWED_SIGNALING_TYPES["connected"] (line 47-52):
"connected": {
    "webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end",
    "call.recording_request", "call.recording_accept", "call.recording_decline",
    "call.recording_started", "call.recording_stopped",
    "webrtc.screen_share_start", "webrtc.screen_share_stop",
},
```

### 3.8 State Machine Additions — IMPLEMENTED

The state machine (see `frontend/src/pages/messages/callStateMachine.ts`) has recording events and fields:

```typescript
// Events (lines 40-45):
| { type: "RECORDING_REQUESTED"; requestedBy: string }
| { type: "RECORDING_ACCEPTED"; recordingId: string }
| { type: "RECORDING_DECLINED" }
| { type: "RECORDING_STARTED"; recordingId: string }
| { type: "RECORDING_STOPPED" }
```

<!-- NOTE: The actual events differ slightly from the spec:
  - RECORDING_REQUESTED has no recordingId (only requestedBy)
  - RECORDING_CONSENT_RECEIVED is named RECORDING_ACCEPTED
  - RECORDING_DECLINED has no reason field -->

State fields (see `:17-19`):
```typescript
recordingState: "idle" | "requesting" | "consent_pending" | "recording" | "stopped";
recordingId: string | null;
recordingRequestedBy: string | null;
```

<!-- NOTE: The actual recordingState includes an extra "requesting" state not in the original spec. -->

The recording state is orthogonal to the call phase (it only applies during `connected`). Recording events are ignored unless `phase === "connected"`.

### 3.9 Configuration Settings — IMPLEMENTED

(See `app/core/settings.py:1157-1165`.)

| Setting | Env Variable | Default | Purpose |
|---------|-------------|---------|---------|
| Feature flag | `CALL_RECORDING_ENABLED` | `true` (default "1") | Master on/off switch |
| Max duration | `CALL_RECORDING_MAX_DURATION_SECONDS` | `3600` (1 hour) | Auto-stop after this duration |
| Upload TTL | `CALL_RECORDING_UPLOAD_TTL_SECONDS` | `600` (10 min) | Presigned URL validity |
| Max file size | `CALL_RECORDING_MAX_FILE_SIZE_BYTES` | `2147483648` (2 GB) | Reject uploads exceeding this |
| Retention | `CALL_RECORDING_RETENTION_DAYS` | `90` | Auto-delete recordings after this |
| S3 prefix | `CALL_RECORDING_S3_PREFIX` | `call-recordings/` | S3 key prefix |
| DDB table name | `DDB_CALL_RECORDINGS_TABLE` | `CallRecordings` | DynamoDB table for recording metadata |
| Download TTL | `CALL_RECORDING_DOWNLOAD_TTL_SECONDS` | `3600` | Presigned download URL expiry |

<!-- NOTE: The default for CALL_RECORDING_ENABLED is "1" (true) in the actual implementation, NOT "false" as originally specified. Also there is an additional setting call_recording_download_ttl_seconds at line 1165. -->

### 3.10 Recording Timeline Message

When a recording completes, a system message is inserted into the conversation timeline:

```python
# In app/services/messaging_call_timeline.py (or new call_recording_store.py)
system_message = {
    "kind": "system",
    "system_event": "call_recording_available",
    "metadata": {
        "recording_id": recording_id,
        "call_id": call_id,
        "duration_seconds": duration,
        "file_size_bytes": file_size,
    },
}
```

The frontend renders this as a special message bubble:
```
  ┌────────────��───────────────────────┐
  │  [Recording icon] Call Recording   │
  │  Duration: 12:34                   │
  │  [Download button]                 │
  └────────────────────────────────────┘
```

---

## 4. Implementation Plan

### Phase 1: Backend Infrastructure (Days 1-3) — IMPLEMENTED

#### Files (all exist)

| File | Lines | Purpose |
|------|-------|---------|
| `app/services/call_recording_store.py` | 279 | DynamoDB CRUD for `CallRecordings` table |
| `app/routers/call_recording.py` | 576 | HTTP endpoints for recording lifecycle |

#### `app/services/call_recording_store.py` — IMPLEMENTED (279 lines)

Key components (see `app/services/call_recording_store.py`):
- `RecordingStatus` Literal type (`:15`)
- `CallRecordingRecord` dataclass (`:35-55`)
- `create_recording()` (`:117`)
- `get_recording()` (`:144`)
- `get_recordings_for_call()` (`:152`)
- `get_active_recording_for_call()` (`:163`)
- `get_recordings_for_conversation()` (`:172`)
- `update_recording_status()` (`:188`)

#### `app/routers/call_recording.py` — IMPLEMENTED (576 lines)

<!-- NOTE: The actual endpoint paths differ from the original spec. The actual paths are listed below. -->

Endpoints (see `app/routers/call_recording.py`):

| Method | Path | Line | Purpose |
|--------|------|------|---------|
| `POST` | `/messages/calls/{call_id}/recording/request` | 141 | Request recording (after consent initiation) |
| `POST` | `/messages/calls/{call_id}/recording/consent` | 183 | Record consent from peer |
| `POST` | `/messages/calls/{call_id}/recording/decline` | 227 | Decline recording request |
| `POST` | `/messages/calls/{call_id}/recording/upload/presign` | 258 | Get presigned upload URL |
| `POST` | `/messages/calls/{call_id}/recording/upload/complete` | 322 | Mark upload complete |
| `GET` | `/messages/calls/{call_id}/recording` | 396 | Get recording metadata for a call |
| `GET` | `/messages/recordings` | 439 | List recordings for user |
| `GET` | `/messages/recordings/{recording_id}/download` | 492 | Get download URL |
| `DELETE` | `/messages/recordings/{recording_id}` | 528 | Soft-delete a recording |

Router registered in `app/main.py:102,425`.

#### `scripts/local-ddb-init.py` — IMPLEMENTED

The settings field exists at `app/core/settings.py:1164` and the table definition is at `scripts/local-ddb-init.py:640-650`:

```python
TableDef(
    _resolve_table_name(S.call_recordings_table_name, "CallRecordings"),
    "recording_id",
    gsi=[
        {"index_name": "ByCallIdCreatedAt", "partition_key": "call_id", "sort_key": "created_at"},
        {"index_name": "ByConversationCreatedAt", "partition_key": "conversation_id", "sort_key": "created_at"},
        {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

#### `app/services/messaging_call_signaling.py` — IMPLEMENTED

Recording event types are in both `ALLOWED_SIGNALING_TYPES` (`:23-27`) and `STATE_ALLOWED_SIGNALING_TYPES["connected"]` (`:49-50`).

#### `app/core/settings.py` — IMPLEMENTED

Settings at lines 1157-1165. See section 3.9 above for the full list.

#### `app/main.py` — IMPLEMENTED

`call_recording_router` registered at lines 102, 425.

### Phase 2: Frontend Recording Hook (Days 4-6) — IMPLEMENTED

#### Files (all exist)

| File | Lines | Purpose |
|------|-------|---------|
| `frontend/src/hooks/useCallRecording.ts` | 322 | MediaRecorder lifecycle, consent flow, upload |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 671 | Consent dialog + REC indicator integrated in overlay |

<!-- NOTE: No separate RecordingConsentDialog.tsx or RecordingIndicator.tsx files were created. The consent dialog and recording indicator are integrated directly into CallSessionOverlay.tsx (consent dialog around line 435+, REC indicator at line 425). -->

#### `frontend/src/hooks/useCallRecording.ts`

```typescript
export interface UseCallRecordingParams {
  callId: string | undefined;
  conversationId: string;
  userId: string;
  peerId: string;
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  isConnected: boolean;
  enabled: boolean;  // feature flag
}

export interface UseCallRecordingReturn {
  recordingState: "idle" | "consent_pending" | "recording" | "stopped" | "uploading" | "complete";
  recordingId: string | null;
  duration: number;  // seconds elapsed
  isInitiator: boolean;
  requestRecording: () => void;
  respondToRequest: (accept: boolean) => void;
  stopRecording: () => void;
  error: string | null;
}
```

**Internal state machine**:

```
idle ──[requestRecording()]──> consent_pending
consent_pending ──[peer accepts]──> recording
consent_pending ──[peer declines]──> idle
consent_pending ──[timeout 30s]──> idle
recording ──[stopRecording()]──> stopped
recording ──[call ends]──> stopped
recording ──[max duration]──> stopped
stopped ──[upload starts]──> uploading
uploading ──[upload complete]──> complete
uploading ──[upload fails]──> error
```

**Canvas rendering loop**:

```typescript
function startCanvasLoop(
  canvas: OffscreenCanvas,
  localVideo: HTMLVideoElement,
  remoteVideo: HTMLVideoElement,
) {
  const ctx = canvas.getContext("2d")!;
  const W = 1280, H = 480;
  canvas.width = W;
  canvas.height = H;

  function draw() {
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, W, H);
    // Left half: local
    ctx.drawImage(localVideo, 0, 0, W / 2, H);
    // Right half: remote
    ctx.drawImage(remoteVideo, W / 2, 0, W / 2, H);
    requestAnimationFrame(draw);
  }
  draw();
}
```

#### `frontend/src/pages/messages/RecordingConsentDialog.tsx`

A modal dialog shown when the peer requests recording:

```tsx
<Dialog open={showConsentDialog}>
  <DialogContent>
    <DialogHeader>
      <DialogTitle>Recording Request</DialogTitle>
      <DialogDescription>
        {peerName} wants to record this call. Both audio and video will be
        captured. Do you consent to being recorded?
      </DialogDescription>
    </DialogHeader>
    <DialogFooter>
      <Button variant="outline" onClick={() => respond(false)}>Decline</Button>
      <Button variant="destructive" onClick={() => respond(true)}>
        <Circle className="h-3 w-3 fill-current mr-2" /> Allow Recording
      </Button>
    </DialogFooter>
  </DialogContent>
</Dialog>
```

#### Modify: `frontend/src/pages/messages/CallSessionOverlay.tsx`

Add to Props:
```typescript
isRecording?: boolean;
recordingDuration?: number;
onRequestRecording?: () => void;
onStopRecording?: () => void;
recordingEnabled?: boolean;
```

Add recording button to controls row (after End Call button):
```tsx
{recordingEnabled && session.state === "connected" && (
  <Tooltip>
    <TooltipTrigger asChild>
      <Button
        size="icon"
        variant={isRecording ? "destructive" : "outline"}
        onClick={isRecording ? onStopRecording : onRequestRecording}
      >
        <Circle className={cn("h-4 w-4", isRecording && "fill-red-500 animate-pulse")} />
      </Button>
    </TooltipTrigger>
    <TooltipContent>{isRecording ? "Stop Recording" : "Record Call"}</TooltipContent>
  </Tooltip>
)}
```

Add recording indicator (top-right of overlay):
```tsx
{isRecording && (
  <div className="absolute top-4 right-4 flex items-center gap-2 bg-red-600/90 text-white px-3 py-1 rounded-full text-sm font-medium animate-pulse">
    <Circle className="h-2 w-2 fill-white" />
    REC {formatDuration(recordingDuration)}
  </div>
)}
```

#### Modify: `frontend/src/pages/messages/callStateMachine.ts`

Add recording-related fields to `CallMachineState` and events to `CallMachineEvent`. The recording state is orthogonal — it does not affect call phase transitions.

#### `frontend/src/hooks/useMessagingStream.ts` — IMPLEMENTED

Recording event types are in `EVENT_TYPES` at lines 173-177:
```typescript
"call.recording_request",   // line 173
"call.recording_accept",    // line 174
"call.recording_decline",   // line 175
"call.recording_started",   // line 176
"call.recording_stopped",   // line 177
```

### Phase 3: Integration & Polish (Days 7-8)

#### Post-call recording notification

Insert a system message into the conversation when recording completes. The frontend `MessageBubble` component renders `system_event === "call_recording_available"` with a download button.

#### Recording list in conversation info panel

Add a "Recordings" tab/section to the conversation detail panel showing all recordings for that conversation, with download links and metadata (date, duration, size).

#### Upload progress indicator

After the call ends, if a recording is being uploaded, show a progress bar in the conversation view header. Use `XMLHttpRequest` (not fetch) for upload progress events.

#### Error recovery

If the upload fails (network error, tab closure), the recording Blob is persisted to IndexedDB. On next page load, detect pending uploads and resume.

### Phase 4: Backend API Endpoints Detail (Days 2-3)

#### `POST /messages/calls/{call_id}/recordings`

**Purpose**: Create a recording record after consent is confirmed.

```python
class CreateRecordingIn(BaseModel):
    recording_id: str = Field(..., pattern=r"^rec_[a-f0-9]{32}$")
    consent_timestamp: int

class CreateRecordingOut(BaseModel):
    recording_id: str
    status: str
    created_at: int
```

**Validation**:
- Call must be in `connected` state
- Requester must be a call participant
- No other recording with status `recording` exists for this call
- `CALL_RECORDING_ENABLED` must be true

#### `POST /messages/calls/{call_id}/recordings/{recording_id}/upload-url`

```python
class RecordingUploadUrlIn(BaseModel):
    mime_type: str = Field(..., pattern=r"^video/(webm|mp4)$")
    file_size_bytes: int = Field(..., gt=0, le=2_147_483_648)

class RecordingUploadUrlOut(BaseModel):
    upload_url: str
    ticket_id: str
    expires_in_seconds: int
```

**Validation**:
- Recording must exist with status `recording` or `uploading`
- Requester must be a participant
- File size within configured limit

#### `POST /messages/calls/{call_id}/recordings/{recording_id}/complete`

```python
class RecordingCompleteIn(BaseModel):
    ticket_id: str
    duration_seconds: int = Field(..., gt=0)
    file_size_bytes: int = Field(..., gt=0)

class RecordingCompleteOut(BaseModel):
    recording_id: str
    status: str
    download_url: str | None
```

**Validation**:
- Verify S3 object exists via `head_object`
- Verify file size matches (within 5% tolerance for chunked uploads)
- Update status to `ready`
- Insert system message into conversation timeline

#### `GET /messages/calls/{call_id}/recordings/{recording_id}/download`

**Response**: 302 redirect to presigned S3 GET URL (60-minute expiry)  
**Auth**: Must be participant OR admin

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_call_9.py`

**Mock setup**: moto mock for DynamoDB (call session tables). Mock RTCPeerConnection for frontend unit tests. Chromium fake media devices for E2E.

| Test Function | Description |
|---|---|
| `test_create_resource` | Create primary resource; verify stored correctly |
| `test_lifecycle_transitions` | Verify allowed state transitions succeed |
| `test_invalid_transition_rejected` | Invalid transition returns 409 |
| `test_authorization_check` | Non-participant returns 403 |
| `test_idempotent_operation` | Repeated call returns same result |
| `test_cleanup_on_end` | Resources cleaned up after call ends |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full call lifecycle through real DDB (invite -> accept -> connect -> end)
2. Signaling relay: offer/answer/ICE exchange between two sessions
3. State machine transitions verified end-to-end

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/call-9.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for caller; `injectAuth(page, "bob")` for callee; separate browser contexts for two-peer tests

| # | Test Name | Assertion |
|---|---|---|
| 1 | Call invite creates session | POST invite -> 200 with call_id |
| 2 | Call accept transitions state | POST accept -> state = accepted |
| 3 | Signaling relay delivers events | POST signal -> SSE event received by peer |
| 4 | Connected state shows overlay | Both peers reach connected; overlay visible |
| 5 | End call cleans up resources | POST end -> state = ended; tracks stopped |
| 6 | Call overlay shows correct UI | Ringing/connected/ended states render correctly |
| 7 | Feature flag gates functionality | Disabled flag -> call button hidden |
| 8 | Unauthenticated returns 401 | No session -> 401 |
| 9 | Non-participant returns 403 | Third party -> 403 |
| 10 | Non-existent call returns 404 | Invalid call_id -> 404 |
| 11 | Invalid transition returns 409 | End already-ended call -> 409 |

**Negative tests**: 401 unauthenticated, 403 non-participant, 404 non-existent call, 409 invalid transition, 422 invalid payload

**Edge cases**: Concurrent accept/decline, call timeout (30s), ICE restart during connected state, tab backgrounding, network offline

### Test Data Requirements

Create DM conversation between Alice and Bob in `beforeAll`. Use `--use-fake-device-for-media-stream` Chromium flag for media tests.

**Test users**: Alice (USER, caller), Bob (USER, callee), Root (ROOT, admin for feature flags)

### CI/Pipeline

Serial execution (WebRTC requires sequential peer setup). `VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED=true`. Retry-safe.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| CALL-002 | RTCPeerConnection for MediaRecorder integration | Implemented | No -- must merge after |
| CALL-008 | ICE restart for recording during reconnection | Implemented | Yes |

### Depended On By

| Ticket | What It Needs |
|---|---|
| CALL-010 | Recording hook for ConversationView integration |

### Merge Strategy

Sequential after CALL-002. New backend endpoints + frontend hook + DDB table.

### Merge Checklist

- [ ] Backend endpoint/service changes registered in `app/main.py`
- [ ] Frontend hooks and components created/modified
- [ ] Settings and feature flags configured
- [ ] DDB tables added if needed (`scripts/local-ddb-init.py`)
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing call endpoints

---

## Codebase References

| File | Lines | What |
|------|-------|------|
| `app/routers/call_recording.py` | 1-576 | Recording HTTP endpoints (request, consent, decline, upload, complete, download, delete) |
| `app/routers/call_recording.py` | 141 | `POST /messages/calls/{call_id}/recording/request` |
| `app/routers/call_recording.py` | 183 | `POST /messages/calls/{call_id}/recording/consent` |
| `app/routers/call_recording.py` | 258 | `POST /messages/calls/{call_id}/recording/upload/presign` |
| `app/routers/call_recording.py` | 322 | `POST /messages/calls/{call_id}/recording/upload/complete` |
| `app/routers/call_recording.py` | 492 | `GET /messages/recordings/{recording_id}/download` |
| `app/services/call_recording_store.py` | 1-279 | DynamoDB CRUD for CallRecordings table |
| `app/services/call_recording_store.py` | 15 | `RecordingStatus` Literal type |
| `app/services/call_recording_store.py` | 35 | `CallRecordingRecord` dataclass |
| `app/services/call_recording_store.py` | 117 | `create_recording()` |
| `app/services/messaging_call_signaling.py` | 23-27 | Recording signaling types in `ALLOWED_SIGNALING_TYPES` |
| `app/services/messaging_call_signaling.py` | 49-50 | Recording types in `STATE_ALLOWED_SIGNALING_TYPES["connected"]` |
| `app/core/settings.py` | 1157-1165 | Recording settings (enabled, max_duration, upload_ttl, max_file_size, retention, s3_prefix, table, download_ttl) |
| `app/main.py` | 102, 425 | `call_recording_router` import and registration |
| `scripts/local-ddb-init.py` | 640-650 | `CallRecordings` table definition (3 GSIs) |
| `frontend/src/hooks/useCallRecording.ts` | 1-322 | MediaRecorder lifecycle, consent flow, upload |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 42-70 | Props including recording fields |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 222-235 | Recording button in CallControls |
| `frontend/src/pages/messages/CallSessionOverlay.tsx` | 425 | "REC" indicator badge |
| `frontend/src/pages/messages/callStateMachine.ts` | 17-19 | `recordingState`, `recordingId`, `recordingRequestedBy` fields |
| `frontend/src/pages/messages/callStateMachine.ts` | 40-45 | Recording events (REQUESTED, ACCEPTED, DECLINED, STARTED, STOPPED) |
| `frontend/src/pages/messages/callStateMachine.ts` | 164-183 | Recording state reducer cases |
| `frontend/src/pages/messages/ConversationView.tsx` | 51, 640 | `useCallRecording` import and usage |
| `frontend/src/hooks/useMessagingStream.ts` | 173-177 | Recording SSE event types |
| `frontend/src/lib/featureFlags.ts` | 127 | `isCallRecordingEnabled` flag |
| `frontend/e2e/call-recording.spec.ts` | 1-724 | E2E tests for call recording |
