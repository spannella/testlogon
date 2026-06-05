---
id: AND-302
title: Call recording consent + upload
milestone: M7
epic: E40
priority: P2
size: M
status: draft
depends_on: [AND-296, AND-129]
blocks: []
---

# AND-302 — Call recording consent + upload

## 1. Overview & Goal

This ticket adds **call recording with explicit two-party consent** and **post-call
upload** to the TestLogon native Android client. During an active 1:1 call (provided by
the outgoing-call flow in AND-296), either participant may **request** to record. The
remote party must explicitly **consent** or **decline**. Recording may only begin once
consent is recorded by the backend, and recording must stop immediately if consent is
later withdrawn or the call ends. After the call terminates with a captured recording,
the client uploads the audio artifact through the reusable presign→PUT→confirm uploader
(AND-129), surfacing progress and supporting cancel/retry.

The goal is a legally-defensible, server-authoritative consent gate plus a resilient
upload path. The consent state is owned by the backend; the client never records local
audio before the server reports `consent=granted`. "Done" means: a user can request
recording, the peer can consent or decline, recording is gated correctly on that
decision, and a completed recording uploads end-to-end with visible progress.

Out of scope: group-call recording, server-side transcription, playback UI of uploaded
recordings (separate M7 ticket), and storage retention policy (backend concern).

## 2. Context & References

- **Module placement:** `feature-call` (Compose UI + ViewModel for the in-call consent
  surface) and `core-data` (recording repository + upload orchestration). DI wiring via
  Hilt/KSP. Namespace base `com.testlogon.android` (e.g.
  `com.testlogon.android.feature.call.recording`).
- **AND-296 (Outgoing call flow):** Owns the call session lifecycle, `CallId`, peer
  identity, and the in-call screen this feature mounts a control into. AND-302 consumes
  the existing `CallSession`/`CallUiState` and adds a recording sub-state.
- **AND-129 (Attachment pipeline):** Provides the reusable
  `Uploader.upload(request): Flow<UploadProgress>` with progress, cancel, and retry,
  built on presign→PUT→confirm. AND-302 calls it with a recording-specific presign
  request and confirm payload; it does **not** reimplement upload transport.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable). OpenAPI at `/openapi.json`. Cookie-based session with `ui_csrf` echoed as
  `X-CSRF-Token`; 401 triggers a single `POST /ui/session/refresh` then retry. Web
  reference under `frontend/src/api/endpoints/*.ts`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Retrofit 2.11 / OkHttp 4.12 / Moshi
  1.15, Coroutines/Flow, DataStore for transient prefs, minSdk 24 / target 35, JDK 17.
- Audio capture uses `MediaRecorder` (AAC in an `.m4a`/MPEG-4 container) writing to app
  cache; no third-party media library is required for mono voice capture.

## 3. Functional Requirements

FR-1. **Request recording.** While a call is `Connected`, the local user can tap a
"Record" control. This issues a consent request to the backend and moves local recording
state to `RequestPending`. The control is disabled while pending.

FR-2. **Receive request.** When the remote party requests recording, the local client
receives a consent prompt (via the call signaling channel owned by AND-296, surfaced as a
`RecordingConsentRequested` event) and shows a modal with **Consent** and **Decline**
actions plus the requester's display name.

FR-3. **Consent / Decline.** The prompted user's choice is POSTed to the backend. The
backend is the source of truth: only after the server reports the aggregate state as
`granted` does recording start on the recording-capturing device.

FR-4. **Gated capture.** Audio capture (`MediaRecorder`) starts **only** when consent
state becomes `granted` and the requester runs `start`. Capture must not begin before the
server confirms consent. If consent is `declined` or the request times out, no capture
occurs and the UI returns to idle with a non-blocking message.

FR-5. **Withdraw / stop.** Either party may withdraw consent mid-call (`POST .../consent`
with `decision=withdraw`). On withdrawal the recorder stops within 500 ms, the partial
file is **discarded**, and no upload is attempted.

FR-6. **Auto-stop on end.** When the call ends (any reason) with active recording, the
recorder is finalized, the file flushed, and the recording transitions to
`PendingUpload`.

FR-7. **Upload.** A finalized recording is uploaded via the AND-129 uploader: request a
recording presign, PUT the file to the returned storage URL, then confirm. Progress
(0–100%), cancel, and retry are exposed in the UI. On `Cancelled`, the local file is
deleted and the server recording record is abandoned.

FR-8. **Permission.** `RECORD_AUDIO` runtime permission is requested at the moment the
local user attempts to **start** capture (requester side) and before consenting if the
consenting device also captures. Denial cancels the request and surfaces rationale.

FR-9. **Persistence across process death.** A `PendingUpload`/`Uploading` recording is
recorded in a durable queue so an interrupted upload can resume/retry on next app launch.

## 4. Technical Design

### State model

```kotlin
enum class RecordingPhase { Idle, RequestPending, ConsentPrompt, Granted,
    Declined, Recording, PendingUpload, Uploading, Uploaded, Failed, Cancelled }

data class RecordingUiState(
    val phase: RecordingPhase = RecordingPhase.Idle,
    val callId: String,
    val requesterName: String? = null,   // set in ConsentPrompt
    val isLocalRequester: Boolean = false,
    val elapsedSeconds: Long = 0,         // Recording
    val uploadPercent: Int = 0,           // Uploading
    val error: AppError? = null,
)
```

### ViewModel (feature-call)

```kotlin
@HiltViewModel
class CallRecordingViewModel @Inject constructor(
    private val repo: CallRecordingRepository,
    private val recorder: AudioRecorder,
    private val savedState: SavedStateHandle,
) : ViewModel() {
    val state: StateFlow<RecordingUiState>

    fun requestRecording()
    fun respondToPrompt(consent: Boolean)
    fun withdraw()
    fun onCallEnded(reason: CallEndReason)   // called by CallSession observer
    fun retryUpload()
    fun cancelUpload()
    fun onPermissionResult(granted: Boolean)
}
```

The ViewModel subscribes to `repo.consentEvents(callId): Flow<ConsentEvent>` which merges
server-pushed consent transitions (delivered over the AND-296 signaling channel) with
local actions, and drives `AudioRecorder` accordingly.

### Audio capture

```kotlin
interface AudioRecorder {
    fun start(outputFile: File): Result<Unit>   // MediaRecorder; AAC mono 44.1k, 64kbps
    fun stop(): File?                            // finalizes; null if never started
    fun discard()                                // stop + delete partial
}
```

`MediaRecorder` config: `setAudioSource(MIC)`, `setOutputFormat(MPEG_4)`,
`setAudioEncoder(AAC)`, single channel, 64 kbps. Output written to
`cacheDir/recordings/<callId>.m4a`. On API < 26 the `MediaRecorder(Context)` constructor
is unavailable; use the deprecated no-arg constructor (minSdk 24).

### Repository (core-data)

```kotlin
interface CallRecordingRepository {
    suspend fun requestConsent(callId: String): ApiResult<ConsentState>
    suspend fun respondConsent(callId: String, decision: ConsentDecision): ApiResult<ConsentState>
    suspend fun presign(callId: String, sizeBytes: Long): ApiResult<RecordingPresign>
    suspend fun confirm(callId: String, recordingId: String, key: String): ApiResult<RecordingMeta>
    fun consentEvents(callId: String): Flow<ConsentEvent>
    fun pendingUploads(): Flow<List<PendingRecording>>   // durable queue (Room)
}

enum class ConsentDecision { Request, Grant, Decline, Withdraw }
```

Upload itself is delegated to AND-129's `Uploader`, fed by `presign()` output and
completed via `confirm()`. The repository wraps the uploader's `Flow<UploadProgress>` and
maps terminal states into `RecordingPhase`.

## 5. API Contract

All endpoints are session-cookie authenticated; mutations send `X-CSRF-Token`
(`ui_csrf`). Paths assume the call-recording surface under `/ui/calls`; confirm exact
shapes against `/openapi.json` and `frontend/src/api/endpoints/calls.ts` during
implementation, mapping any drift in a follow-up.

**Request / respond consent**
`POST /ui/calls/{call_id}/recording/consent`
```json
// request
{ "decision": "request" | "grant" | "decline" | "withdraw" }
// response 200
{ "recording_id": "rec_01H. . .", "consent": "pending" | "granted" | "declined" | "withdrawn",
  "requested_by": "user_42", "participants": [{"user_id":"user_42","decision":"grant"}] }
```

**Presign upload** (after capture finalized)
`POST /ui/calls/{call_id}/recording/{recording_id}/presign`
```json
// request
{ "content_type": "audio/mp4", "size_bytes": 184320, "duration_ms": 73400 }
// response 200
{ "upload_url": "https://. . ./put?X-Amz-Signature=. . .", "method": "PUT",
  "headers": {"Content-Type": "audio/mp4"}, "key": "recordings/rec_01H.m4a", "expires_in": 900 }
```

**PUT** to `upload_url` (storage, no app cookies) with the file body and echoed headers —
handled by AND-129 uploader.

**Confirm**
`POST /ui/calls/{call_id}/recording/{recording_id}/confirm`
```json
// request
{ "key": "recordings/rec_01H.m4a", "size_bytes": 184320, "duration_ms": 73400 }
// response 200
{ "recording_id": "rec_01H. . .", "status": "ready", "created_at": "2026-06-05T18:22:11Z" }
```

**Errors** follow the standard FastAPI `detail` shape (`string | [{msg}] | {code,...}`)
mapped through the shared `AppError` mapper. Notable codes: `409 consent_not_granted`
(presign before grant), `410 recording_expired`, `403 not_a_participant`.

## 6. Data & State Management

- **UiState:** `StateFlow<RecordingUiState>` per the model in §4; collected with
  `collectAsStateWithLifecycle()`. Transient prompt data (`requesterName`) lives in state
  only, never persisted.
- **Durable upload queue (Room, core-data):** table `pending_recording`
  (`recording_id` PK, `call_id`, `file_path`, `size_bytes`, `duration_ms`, `phase`,
  `attempts`, `created_at`). Inserted at `PendingUpload`; deleted on `Uploaded` or
  `Cancelled`. Enables resume after process death (FR-9).
- **Files:** capture file in `cacheDir/recordings/`; deleted on discard, cancel, or
  successful confirm. A startup sweep deletes orphaned files with no queue row.
- **DataStore:** stores only a per-user "remember rationale shown" flag for the
  `RECORD_AUDIO` permission; no PII.
- **Single source of truth:** consent state is server-authoritative; the client mirrors
  the latest `consent` value from responses/events and never advances to `Recording`
  without `granted`.

## 7. Error Handling & Resilience

- **Consent timeout:** if no consent event within 30 s of a `request`, transition to
  `Idle` with "No response — recording not started". Requester device never captured, so
  nothing to clean up.
- **Backend unreliability (~20 s timeouts):** all calls use the project-wide 20 s
  read/connect timeout. Idempotent `presign`/`confirm` retries use bounded exponential
  backoff (e.g. 3 attempts, 0.5→2 s, jitter). Consent mutations are **not** auto-retried
  (non-idempotent intent); the user re-taps.
- **401 handling:** the OkHttp authenticator performs a single
  `POST /ui/session/refresh` then retries, per project policy; on second 401 surface
  re-auth.
- **Upload failure:** terminal failure moves to `Failed` with a Retry action; the file
  and queue row are preserved. Retry reuses `recordingId`, re-presigning if the prior URL
  expired (`410`).
- **Process death mid-upload:** on next launch, `pendingUploads()` rehydrates and offers
  resume; `Uploading` rows are reset to `PendingUpload`.
- **Recorder errors:** `MediaRecorder` `onError`/`IllegalStateException` discards the
  partial file, notifies the peer of a recording stop, and surfaces a recoverable error.
- **Disk/permission:** `IOException` on capture → discard + user message; no upload.

## 8. Security & Privacy

- **Explicit consent gate:** capture is impossible until the server reports `granted`;
  this is enforced in the repository, not just the UI. Both participants' decisions are
  visible in the consent response for auditability.
- **Withdrawal is immediate:** partial recordings created before a withdrawal are
  discarded and never uploaded (FR-5).
- **Runtime permission:** `RECORD_AUDIO` requested just-in-time with rationale; declared
  in `feature-call`'s manifest. No background capture; recording is bound to an active,
  foregrounded call.
- **Transport:** dev host is plaintext HTTP (test env only); production must be HTTPS.
  Presigned PUT goes directly to storage and must **not** carry session cookies or the
  CSRF header (enforced by the AND-129 uploader using a cookie-less client).
- **CSRF:** all `/ui/calls/.../recording/...` mutations send `X-CSRF-Token`.
- **Data minimization:** local files in app-private `cacheDir`; deleted on terminal
  states; no recording content logged.

## 9. Accessibility & i18n

- Consent modal uses Material 3 `AlertDialog` with focus moved to the dialog; Consent /
  Decline buttons have `contentDescription` and a minimum 48 dp touch target.
- Recording state is announced via `liveRegion` (e.g. "Recording started",
  "Recording stopped"); a visible non-color-only indicator (icon + "REC" text + elapsed
  timer) for color-blind users.
- Upload progress exposes `progressBarRangeInfo` semantics; Cancel/Retry are
  keyboard/TalkBack reachable.
- All strings in `strings.xml`: `call_recording_request`, `call_recording_prompt_title`,
  `call_recording_consent`, `call_recording_decline`, `call_recording_uploading`,
  `call_recording_failed`, etc. Elapsed/percent formatted via `NumberFormat`/duration
  formatters; no concatenated sentences.

## 10. Telemetry & Logging

- Structured events (no audio content, no PII beyond opaque ids):
  `call_recording_requested`, `call_recording_consent_decision {decision}`,
  `call_recording_started`, `call_recording_stopped {reason}`,
  `call_recording_upload_started`, `call_recording_upload_progress {pct}` (sampled),
  `call_recording_upload_succeeded {bytes,duration_ms}`,
  `call_recording_upload_failed {code}`, `call_recording_cancelled`.
- Each event carries `call_id` and `recording_id` (opaque). Debug logs gated behind
  `BuildConfig.DEBUG`; never log file paths or signed URLs at info level.
- Surface upload latency and failure rate to monitor the unreliable dev backend.

## 11. Testing Strategy

- **Unit (core-testing + MockWebServer):**
  - Consent gate: capture never starts unless server returns `granted`; `declined` and
    timeout paths leave `Idle`.
  - Withdrawal discards partial file and aborts upload.
  - State machine transitions for every `RecordingPhase` edge.
  - `AppError` mapping for `409 consent_not_granted`, `410 recording_expired`, `403`.
- **Upload (MockWebServer, reusing AND-129 harness):** presign→PUT→confirm happy path
  asserts progress 0→100 and `Uploaded`; PUT 5xx → `Failed` then Retry succeeds; cancel
  deletes file + queue row; expired URL (`410`) triggers re-presign.
- **Recorder:** fake `AudioRecorder` verifies start/stop/discard call ordering and
  on-call-end finalization; real `MediaRecorder` smoke-tested on an instrumented device.
- **Persistence:** Room test confirms `pending_recording` survives simulated process
  death and rehydrates to resumable state.
- **UI (Compose test):** consent dialog renders requester name; Consent/Decline emit
  correct intents; progress + Cancel/Retry visible per phase; permission-denied path.
- **Coverage target:** repository + ViewModel ≥ 85% line coverage.

## 12. Dependencies & Sequencing

- **Depends on AND-296 (Outgoing call flow):** requires a `Connected` `CallSession`,
  `CallId`, peer identity, and the signaling channel to deliver `RecordingConsentRequested`
  / consent-transition events. Must be merged first.
- **Depends on AND-129 (Attachment pipeline):** the reusable `Uploader` (presign→PUT→
  confirm, progress/cancel/retry). AND-302 supplies recording-specific presign/confirm
  payloads only.
- **Blocks:** none recorded in backlog. A future recording-playback ticket will consume
  the `recording_id` produced here.
- **Sequencing:** (1) repository + consent endpoints behind a fake signaling source;
  (2) `AudioRecorder` + gate logic; (3) Compose consent/progress UI on the AND-296 call
  screen; (4) wire AND-129 uploader + durable queue; (5) integration + instrumented pass.

## 13. Risks & Open Questions

- **Signaling delivery (Q):** AND-296's channel for delivering consent events to the peer
  is unconfirmed (push/poll/websocket). Assumed: exposed as a `Flow<ConsentEvent>`. If
  only polling exists, prompt latency may rise; revisit timeout (§7).
- **Who captures audio (Q):** this spec assumes the **requester** device captures and
  uploads after both consent. If the backend expects both sides to upload (mixed
  server-side), `presign`/`confirm` must run per-participant — confirm with backend.
- **Exact endpoint shapes (Risk):** `/ui/calls/.../recording/*` paths inferred; verify
  against `/openapi.json` and `frontend/` before coding; map drift in a follow-up note.
- **Telephony audio routing (Risk):** capturing mic during an active VoIP call may
  conflict with the call's audio stack from AND-296; validate `MediaRecorder` coexists
  with the call audio session on device.
- **Legal jurisdiction (Q):** two-party consent UX assumed sufficient; retention is a
  backend policy, out of scope here.

## 14. Acceptance Criteria

AC-1. From a `Connected` call, tapping Record sends `decision=request`; UI shows
`RequestPending`; the peer receives a consent prompt with the requester's name.
AC-2. Peer **Consent** → server returns `consent=granted` → capture starts; **Decline** →
no capture, both sides return to idle with a message (FR-3, FR-4).
AC-3. Capture provably never begins before the server reports `granted` (asserted by
unit test on the gate).
AC-4. Withdrawal mid-recording stops capture ≤ 500 ms and discards the partial file with
no upload (FR-5).
AC-5. Call end with an active recording finalizes the file and transitions to
`PendingUpload` (FR-6).
AC-6. A finalized recording uploads end-to-end (presign→PUT→confirm) with visible 0→100%
progress, verified with MockWebServer; Cancel and Retry work (FR-7, AND-129).
AC-7. `RECORD_AUDIO` is requested just-in-time; denial cancels cleanly with rationale
(FR-8).
AC-8. An interrupted upload survives process death and resumes/retries from the durable
queue (FR-9).
AC-9. All consent mutations send `X-CSRF-Token`; presigned PUT carries no session
cookies.

## 15. Definition of Done

- All FRs and ACs implemented and green in CI on the `android-port` branch.
- `feature-call` recording UI + `core-data` repository merged with Hilt wiring; package
  `com.testlogon.android.feature.call.recording`.
- Consent gate enforced in the repository layer (not UI-only), with unit coverage.
- Upload delegated to the AND-129 `Uploader`; no duplicated transport code.
- Strings externalized; TalkBack pass on consent dialog and progress; no color-only
  state.
- Telemetry events emitted; no audio content, file paths, or signed URLs logged at info.
- Unit + Compose + MockWebServer tests pass; repository/ViewModel ≥ 85% coverage; one
  instrumented smoke test of real capture.
- Endpoint shapes reconciled against `/openapi.json`; any drift documented.
- Lint/detekt/ktlint clean; PR reviewed and approved.
