# CALL-009: WebRTC Call Recording with Mutual Consent

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-24  
**Priority**: Medium  
**Estimated effort**: 8-12 days  
**Dependencies**: CALL-002 (RTCPeerConnection), CALL-008 (ICE Restart)

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

The existing hook (lines 85-88) exposes both streams as React state:

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

The recording hook will extend this (or maintain its own parallel cleanup) to ensure the `MediaRecorder` is stopped and all Blob data is finalized when `teardownCallResources()` is called.

### 2.5 Call Session DDB Model

`CallSessionRecord` in `app/services/messaging_call_sessions.py` (lines 18-33):

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
| `network_path` | "p2p" \| "turn" \| None | Connection type |

Recording metadata will reference `call_id` as a foreign key, linking recordings to their parent call session.

### 2.6 Existing Upload Patterns

The file manager (`app/services/filemanager.py`) implements a presigned upload flow:

1. **Request upload URL**: `presign_upload(user, path, content_type=...)` generates a presigned S3 PUT URL (line 2207)
2. **Client uploads directly to S3** via the presigned URL
3. **Register upload**: `register_presigned_upload(user, path, ticket_id, ...)` validates the upload completed and creates the file record (line 2264)

In dev mode (moto), presigned URLs don't resolve to an external host, so a proxy endpoint (`/mock/s3/...`) is used instead (line 2221). The recording upload will follow the same pattern.

### 2.7 `CallSessionOverlay.tsx` UI Layout

The overlay (lines 41-55) has a controls panel at the bottom:

```typescript
interface Props {
  session: CallSessionUi;
  localStream?: MediaStream | null;
  remoteStream?: MediaStream | null;
  peerConnection?: RTCPeerConnection | null;
  isMuted?: boolean;
  isCameraOff?: boolean;
  onAccept: () => void;
  onDecline: () => void;
  onEnd: () => void;
  onDismiss: () => void;
  onToggleMute?: () => void;
  onToggleCamera?: () => void;
}
```

The controls section contains: Mute, Camera toggle, and End Call buttons. The recording button will be added to this row, between Camera and End Call.

### 2.8 Signaling Infrastructure

The signaling endpoint (`POST /messages/calls/{call_id}/signal`) from CALL-001 accepts arbitrary event types within the `ALLOWED_SIGNALING_TYPES` set. For recording, we need to add new event types to this set. The `STATE_ALLOWED_SIGNALING_TYPES` map must also be updated to permit recording events in the `connected` state.

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

### 3.3 Data Model: `CallRecordings` DynamoDB Table

**Table name**: `CallRecordings` (env: `DDB_CALL_RECORDINGS`)  
**Partition key**: `recording_id` (String)

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

### 3.7 Signaling Event Types

Add to `ALLOWED_SIGNALING_TYPES` in `app/services/messaging_call_signaling.py`:

```python
ALLOWED_SIGNALING_TYPES = {
    # ... existing types ...
    "call.recording_request",
    "call.recording_accept",
    "call.recording_decline",
    "call.recording_started",
    "call.recording_stopped",
}
```

Update `STATE_ALLOWED_SIGNALING_TYPES`:

```python
STATE_ALLOWED_SIGNALING_TYPES: dict[str, set[str]] = {
    "invited": {"call.invite", "call.ring", "call.accept", "call.decline", "call.end"},
    "accepted": {"webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end"},
    "connected": {
        "webrtc.offer", "webrtc.answer", "webrtc.ice_candidate", "call.end",
        "call.recording_request", "call.recording_accept", "call.recording_decline",
        "call.recording_started", "call.recording_stopped",
    },
}
```

### 3.8 State Machine Additions

New events for `callStateMachine.ts`:

```typescript
export type CallMachineEvent =
  | // ... existing events ...
  | { type: "RECORDING_REQUESTED"; recordingId: string; requestedBy: string }
  | { type: "RECORDING_CONSENT_RECEIVED" }
  | { type: "RECORDING_DECLINED"; reason?: string }
  | { type: "RECORDING_STARTED"; recordingId: string }
  | { type: "RECORDING_STOPPED"; reason?: string };
```

New state fields in `CallMachineState`:

```typescript
export interface CallMachineState {
  // ... existing fields ...
  recordingState: "idle" | "consent_pending" | "recording" | "stopped";
  recordingId?: string;
  recordingRequestedBy?: string;
}
```

The recording state is orthogonal to the call phase (it only applies during `connected`). Recording events are ignored unless `phase === "connected"`.

### 3.9 Configuration Settings

| Setting | Env Variable | Default | Purpose |
|---------|-------------|---------|---------|
| Feature flag | `CALL_RECORDING_ENABLED` | `false` | Master on/off switch |
| Max duration | `CALL_RECORDING_MAX_DURATION_SECONDS` | `3600` (1 hour) | Auto-stop after this duration |
| Upload TTL | `CALL_RECORDING_UPLOAD_TTL_SECONDS` | `600` (10 min) | Presigned URL validity |
| Max file size | `CALL_RECORDING_MAX_FILE_SIZE_BYTES` | `2147483648` (2 GB) | Reject uploads exceeding this |
| Retention | `CALL_RECORDING_RETENTION_DAYS` | `90` | Auto-delete recordings after this |
| S3 prefix | `CALL_RECORDING_S3_PREFIX` | `call-recordings/` | S3 key prefix |

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

### Phase 1: Backend Infrastructure (Days 1-3)

#### New Files

| File | Purpose |
|------|---------|
| `app/services/call_recording_store.py` | DynamoDB CRUD for `CallRecordings` table |
| `app/routers/call_recording.py` | HTTP endpoints for recording lifecycle |

#### `app/services/call_recording_store.py`

```python
"""DynamoDB operations for call recording metadata."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Optional
from app.core.time import now_ts

RecordingStatus = Literal[
    "pending_consent", "recording", "uploading", "processing", "ready", "failed", "deleted"
]

@dataclass
class CallRecordingRecord:
    recording_id: str
    call_id: str
    conversation_id: str
    initiated_by: str
    participants: list[str]
    status: RecordingStatus
    s3_key: Optional[str] = None
    s3_bucket: Optional[str] = None
    mime_type: Optional[str] = None
    duration_seconds: Optional[int] = None
    file_size_bytes: Optional[int] = None
    consent_ts: Optional[int] = None
    started_at: Optional[int] = None
    completed_at: Optional[int] = None
    created_at: Optional[int] = None
    updated_at: Optional[int] = None
    upload_ticket_id: Optional[str] = None

def create_recording(*, recording_id: str, call_id: str, conversation_id: str,
                     initiated_by: str, participants: list[str]) -> CallRecordingRecord: ...

def update_recording_status(recording_id: str, status: RecordingStatus, **fields) -> CallRecordingRecord: ...

def get_recording(recording_id: str) -> Optional[CallRecordingRecord]: ...

def get_recordings_for_call(call_id: str) -> list[CallRecordingRecord]: ...

def get_active_recording_for_call(call_id: str) -> Optional[CallRecordingRecord]: ...
```

#### `app/routers/call_recording.py`

Endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/messages/calls/{call_id}/recordings` | Create recording record (after consent) |
| `GET` | `/messages/calls/{call_id}/recordings` | List recordings for a call |
| `POST` | `/messages/calls/{call_id}/recordings/{recording_id}/upload-url` | Get presigned upload URL |
| `POST` | `/messages/calls/{call_id}/recordings/{recording_id}/complete` | Mark upload complete |
| `GET` | `/messages/calls/{call_id}/recordings/{recording_id}/download` | Get download URL |
| `DELETE` | `/messages/calls/{call_id}/recordings/{recording_id}` | Soft-delete a recording |

#### Modify: `scripts/local-ddb-init.py`

Add `CallRecordings` table definition:

```python
TableDef(
    os.getenv("DDB_CALL_RECORDINGS", "CallRecordings"),
    "recording_id",
    gsi=[
        {"index_name": "ByCallIdCreatedAt", "partition_key": "call_id", "sort_key": "created_at"},
        {"index_name": "ByConversationCreatedAt", "partition_key": "conversation_id", "sort_key": "created_at"},
        {"index_name": "ByStatus", "partition_key": "status", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
),
```

#### Modify: `app/services/messaging_call_signaling.py`

Add recording event types to `ALLOWED_SIGNALING_TYPES` and update `STATE_ALLOWED_SIGNALING_TYPES["connected"]` to include them.

#### Modify: `app/core/settings.py`

Add settings:
```python
call_recording_enabled: bool = Field(default=False)
call_recording_max_duration_seconds: int = Field(default=3600)
call_recording_upload_ttl_seconds: int = Field(default=600)
call_recording_max_file_size_bytes: int = Field(default=2_147_483_648)
call_recording_retention_days: int = Field(default=90)
call_recording_s3_prefix: str = Field(default="call-recordings/")
```

#### Modify: `app/main.py`

Register `call_recording_router`.

### Phase 2: Frontend Recording Hook (Days 4-6)

#### New Files

| File | Purpose |
|------|---------|
| `frontend/src/hooks/useCallRecording.ts` | MediaRecorder lifecycle, consent flow, upload |
| `frontend/src/pages/messages/RecordingConsentDialog.tsx` | Consent UI for the non-initiating participant |
| `frontend/src/pages/messages/RecordingIndicator.tsx` | Red "REC" badge component |

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

Add recording button to controls row (between Camera and End Call):
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

#### Modify: `frontend/src/hooks/useMessagingStream.ts`

Add recording event types to `EVENT_TYPES`:
```typescript
"call.recording_request",
"call.recording_accept",
"call.recording_decline",
"call.recording_started",
"call.recording_stopped",
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

## 5. Testing Strategy

### 5.1 Unit Tests: Recording Store (`tests/test_call_recording_store.py`)

| # | Test Case | Assertions |
|---|-----------|-----------|
| 1 | Create recording with valid data | Record created, status=`pending_consent`, timestamps set |
| 2 | Update status transitions (happy path) | `pending_consent` -> `recording` -> `uploading` -> `ready` |
| 3 | Invalid status transition rejected | `ready` -> `recording` raises ValueError |
| 4 | Get recording by ID | Returns correct record |
| 5 | Get recordings for call (GSI query) | Returns all recordings sorted by created_at |
| 6 | Get active recording (status filter) | Returns only `recording` status records |
| 7 | Duplicate recording_id rejected | ConditionalCheckFailed on second create |
| 8 | Soft delete sets status to `deleted` | Status updated, S3 key preserved for admin recovery |
| 9 | TTL calculated from retention config | `ttl = created_at + retention_days * 86400` |

### 5.2 Unit Tests: Recording Endpoints (`tests/test_call_recording_endpoints.py`)

| # | Test Case | Expected |
|---|-----------|----------|
| 1 | Create recording — happy path | 201, recording_id returned |
| 2 | Create recording — feature disabled | 403 |
| 3 | Create recording — call not connected | 409, "call must be in connected state" |
| 4 | Create recording — not a participant | 403 |
| 5 | Create recording — duplicate active recording | 409, "recording already active" |
| 6 | Upload URL — happy path | 200, presigned URL + ticket_id |
| 7 | Upload URL — file too large | 400, "exceeds maximum file size" |
| 8 | Upload URL — recording not found | 404 |
| 9 | Complete — happy path | 200, status=ready, download_url populated |
| 10 | Complete — S3 object missing | 400, "upload not found in storage" |
| 11 | Complete — size mismatch | 400, "file size mismatch" |
| 12 | Download — happy path (participant) | 302, Location header with presigned URL |
| 13 | Download — not participant | 403 |
| 14 | Download — recording not ready | 404 |
| 15 | Download — admin access (non-participant) | 302, allowed |
| 16 | Delete recording — participant | 200, status=deleted |
| 17 | Delete recording — non-participant | 403 |

### 5.3 Unit Tests: Consent Protocol Validation (`tests/test_call_recording_consent.py`)

| # | Test Case | Expected |
|---|-----------|----------|
| 1 | Recording signaling events allowed in connected state | Routed successfully |
| 2 | Recording signaling events rejected in accepted state | `invalid_state` error |
| 3 | Recording signaling events rejected in ended state | `invalid_state` error |
| 4 | `call.recording_request` payload validated | Must include `requested_by` |
| 5 | `call.recording_accept` updates recording status | Status -> `recording` |
| 6 | `call.recording_decline` updates recording status | Status -> `deleted` |

### 5.4 E2E Tests (`frontend/e2e/call-recording.spec.ts`)

Since real WebRTC media is not available in Playwright, E2E tests focus on the signaling protocol, API endpoints, and UI state transitions.

**Section 90: Recording Consent API (6 tests)**

```typescript
test("Alice can request recording on an active call", async () => {
  // Seed call in connected state, send recording_request signaling event
  // Verify 200, event delivered to Bob
});

test("Bob can accept recording request", async () => {
  // Send recording_accept signaling event from Bob
  // Verify 200, event delivered to Alice
});

test("Bob can decline recording request", async () => {
  // Send recording_decline signaling event from Bob
  // Verify 200, event delivered to Alice
});

test("Recording request rejected when call not connected", async () => {
  // Call in 'accepted' state, send recording_request
  // Verify 409
});

test("Only one active recording per call", async () => {
  // Create recording, try to create second -> 409
});

test("Either party can stop recording", async () => {
  // Send recording_stopped from Bob (non-initiator)
  // Verify 200, event delivered
});
```

**Section 91: Recording Upload & Download API (7 tests)**

```typescript
test("Get presigned upload URL for recording", async () => {
  // POST upload-url with mime_type and file_size
  // Verify 200, upload_url and ticket_id returned
});

test("Upload URL rejected for oversized file", async () => {
  // POST with file_size > max
  // Verify 400
});

test("Complete recording upload", async () => {
  // Upload a small WebM to the presigned URL (via S3 mock)
  // POST complete with ticket_id, duration, size
  // Verify 200, status=ready
});

test("Download URL accessible by both participants", async () => {
  // Alice requests download -> 302
  // Bob requests download -> 302
});

test("Download URL rejected for non-participant", async () => {
  // Charlie requests download -> 403
});

test("Complete rejected when S3 object missing", async () => {
  // POST complete without uploading -> 400
});

test("Delete recording soft-deletes record", async () => {
  // DELETE endpoint -> status=deleted
  // Subsequent download -> 404
});
```

**Section 92: Recording UI State (5 tests)**

```typescript
test("Record button visible during connected call", async () => {
  // Simulate connected state via CustomEvent dispatch
  // Verify Record button visible in overlay
});

test("Consent dialog shown when peer requests recording", async () => {
  // Dispatch call.recording_request CustomEvent
  // Verify RecordingConsentDialog visible
});

test("REC indicator shown after consent", async () => {
  // Dispatch call.recording_accept CustomEvent
  // Verify red REC badge visible
});

test("REC indicator disappears when recording stopped", async () => {
  // Dispatch call.recording_stopped CustomEvent
  // Verify REC badge removed
});

test("Recording system message appears in conversation after call", async () => {
  // Seed a completed recording in DDB
  // Navigate to conversation
  // Verify "Call Recording" system message with download button
});
```

### 5.5 MediaRecorder Mocking in Playwright

Chromium supports fake media devices via launch flags (already configured in `playwright.config.ts` for call tests):

```typescript
use: {
  launchOptions: {
    args: [
      "--use-fake-device-for-media-stream",
      "--use-fake-ui-for-media-stream",
    ],
  },
},
```

For recording-specific tests, the `MediaRecorder` constructor can be mocked via `page.addInitScript`:

```typescript
await page.addInitScript(() => {
  const originalMediaRecorder = window.MediaRecorder;
  window.MediaRecorder = class MockMediaRecorder extends originalMediaRecorder {
    constructor(stream: MediaStream, options?: MediaRecorderOptions) {
      super(stream, options);
      // Expose for test assertions
      (window as any).__mockMediaRecorder = this;
    }
  };
});
```

### 5.6 Edge Cases

| Scenario | Expected Behavior |
|----------|------------------|
| One party hangs up during recording | Recording auto-stops, Blob finalized, upload initiated by the remaining party |
| Network interruption during recording | MediaRecorder continues locally (it records from local stream objects). If ICE restart succeeds, remote stream resumes in recording. If call fails, recording stops at disconnection point. |
| Very long call (>1 hour) | Auto-stop at `CALL_RECORDING_MAX_DURATION_SECONDS`. Toast notification: "Maximum recording duration reached." |
| Consent declined mid-request | Initiator sees "Recording declined" toast. No recording created. Button returns to "Record" state. |
| Tab backgrounded during recording | Browser may throttle `requestAnimationFrame` (canvas freezes). Audio continues. On tab restore, canvas resumes. The recording will have frozen video frames during background period. Acceptable for v1. |
| Browser crash during recording | Recording data is lost (MediaRecorder data is in-memory). Future enhancement: periodic flush to IndexedDB. |
| Large recording upload on slow connection | Upload progress shown. If browser is closed, IndexedDB fallback attempts resume on next load. |
| Both parties press Record simultaneously | First `recording_request` signaling event wins. Second party's request is suppressed (they receive a consent dialog instead of sending a request). The hook checks if a consent dialog is already showing before sending a new request. |
| Recording during ICE restart | MediaRecorder records from the stream objects, not the network transport. During ICE restart, `remoteStream` tracks go muted (no frames/audio), producing silence/black in the recording. When ICE reconnects, the tracks resume. This is acceptable — the recording reflects what the user experienced. |
| Safari MP4 recording | Safari uses `video/mp4` container. Upload proceeds identically. No conversion needed for Safari-produced files. |

### 5.7 Performance Considerations

| Metric | Target | Notes |
|--------|--------|-------|
| Recording CPU overhead | <15% additional | Canvas rendering at 30fps + MediaRecorder encoding |
| Memory usage during recording | <200 MB for 1-hour call | MediaRecorder flushes to Blob periodically (every 10s via `timeslice` parameter) |
| Upload size (1-hour video call) | ~500-700 MB | At 1.5 Mbps video + 128 kbps audio |
| Upload size (1-hour audio-only call) | ~55 MB | At 128 kbps audio only |
| Upload time (500 MB on 10 Mbps uplink) | ~7 minutes | Progress indicator shown |
| S3 storage cost per recording (1 hour video) | ~$0.015/month | Standard tier, before lifecycle rules |

### 5.8 Regression Concerns

1. **Call teardown must wait for recording finalization**: `teardownCallResources` should call `recorder.stop()` and wait for the `dataavailable` event before stopping tracks. Otherwise the final recording chunk is lost.
2. **Stream track removal during recording**: If a user disables camera mid-recording, the video track is removed from the peer connection. The canvas loop must handle `null` video gracefully (draw black frame for that participant).
3. **Existing call overlay layout**: Adding the Record button must not break the responsive layout of the controls row on mobile viewports.
4. **Consent dialog z-index**: Must appear above the call overlay (which itself is a fixed-position full-screen element).
5. **Memory leak on long recordings**: MediaRecorder with `timeslice` parameter collects Blobs in an array. For 1-hour calls this can be 360 chunks. Ensure these are released after concatenation into the final Blob.
