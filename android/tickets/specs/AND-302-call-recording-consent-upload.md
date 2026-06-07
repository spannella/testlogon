---
id: AND-302
title: Call recording consent + upload
milestone: M7
epic: E40
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  `X-CSRF-Token`; 401 triggers a single `POST /ui/session/refresh` then retry (verified in
  `src/api/client.ts`). Web reference for this feature is the hook
  `src/hooks/useCallRecording.ts` (the consent/upload protocol is implemented there, not in
  `src/api/endpoints/*.ts`).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Retrofit 2.11 / OkHttp 4.12 / Moshi
  1.15, Coroutines/Flow, DataStore for transient prefs, minSdk 24 / target 35, JDK 17.
- Capture uses `MediaRecorder` writing to app cache; no third-party media library is
  required. **CORRECTION:** the backend presign endpoint constrains `content_type` to
  `^video/(webm|mp4)$` (`RecordingUploadPresignIn`), so the uploaded artifact MUST be a
  **video container** — use `MediaRecorder` with `setOutputFormat(MPEG_4)` producing an
  `.mp4` advertised as `video/mp4`. The web client likewise records `video/webm`/`video/mp4`
  (see `useCallRecording.ts`) and mixes both call streams. An audio-only `audio/mp4`/`.m4a`
  artifact (as assumed in earlier drafts) would be rejected by the presign validator.

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

FR-5. **Withdraw / stop.** Either party may stop an in-progress recording mid-call; the
recorder stops within 500 ms, the partial file is **discarded**, and no upload is attempted.
**CORRECTION:** there is **no backend `withdraw` endpoint** (`POST .../recording/consent`
takes no body and only means "accept"; no `decision=withdraw` exists). Stop is therefore
**client-local** in v1: the stopping client tears down its own `MediaRecorder` and emits a
`call.recording_stopped` signaling event (matching the web `useCallRecording` SSE
`call.recording_stopped` handler) so the peer reflects the stop. Server-side revocation of
consent is an open question for backend (see §13/§16). The web client also has no withdraw
call — it only exposes `stopRecording()`, confirming this gap.

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
`setAudioEncoder(AAC)`, single channel, 64 kbps. **Output MUST be a video container**
(`video/mp4`) to satisfy the backend presign regex `^video/(webm|mp4)$`; write to
`cacheDir/recordings/<callId>.mp4` and presign with `content_type = "video/mp4"`. (If only
mic audio is captured the MPEG-4 file still validates as `video/mp4`; if video frames are
also captured, add `setVideoSource`/`setVideoEncoder`. The exact field-side capture content
is an open question — see §13.) On API < 26 the `MediaRecorder(Context)` constructor is
unavailable; use the deprecated no-arg constructor (minSdk 24).

### Repository (core-data)

```kotlin
interface CallRecordingRepository {
    // POST .../recording/request  → RecordingRequestOut
    suspend fun requestRecording(callId: String): ApiResult<RecordingRequestOut>
    // POST .../recording/consent  → RecordingConsentOut
    suspend fun consent(callId: String): ApiResult<RecordingConsentOut>
    // POST .../recording/decline  → RecordingDeclineOut ({ ok: true })
    suspend fun decline(callId: String): ApiResult<RecordingDeclineOut>
    // POST .../recording/upload/presign  body: { content_type, file_size_bytes }
    suspend fun presign(callId: String, contentType: String, fileSizeBytes: Long): ApiResult<RecordingPresign>
    // POST .../recording/upload/complete  body: { recording_id, duration_seconds }
    suspend fun complete(callId: String, recordingId: String, durationSeconds: Double): ApiResult<RecordingMeta>
    fun consentEvents(callId: String): Flow<ConsentEvent>
    fun pendingUploads(): Flow<List<PendingRecording>>   // durable queue (Room)
}
// CORRECTION: request/consent/decline are three separate parameterless POSTs; there is no
// `decision` field and no `withdraw` action (no backend endpoint exists for withdraw).
```

Upload itself is delegated to AND-129's `Uploader`, fed by `presign()` output and
completed via `complete()` (the backend op is `/upload/complete`, not "confirm"). The
repository wraps the uploader's `Flow<UploadProgress>` and maps terminal states into
`RecordingPhase`.

## 5. API Contract

All endpoints are session-cookie authenticated; mutations send `X-CSRF-Token`
(`ui_csrf`), verified against `src/api/client.ts`. **CORRECTION (verified against
`openapi.index.txt` and `src/hooks/useCallRecording.ts`):** the call-recording surface
lives under **`/messages/calls/{call_id}/recording/...`**, NOT `/ui/calls/...`. The
consent protocol is **three distinct endpoints** (request / consent / decline) — there is
no single `consent` endpoint that takes a `decision` field, and **there is no withdraw
endpoint** anywhere in the backend (`grep withdraw` over `openapi.index.txt` returns only
billing/license/appeals routes). See §13 and FR-5 for the implication. Upload uses
**`/recording/upload/presign`** and **`/recording/upload/complete`** ("complete", not
"confirm"). Timestamps in responses are **integer epoch** (e.g. `started_at`,
`created_at`), not ISO strings.

**Request recording** (initiator)
`POST /messages/calls/{call_id}/recording/request` — req: none; resp 200
`RecordingRequestOut`:
```json
{ "recording_id": "rec_...", "status": "...", "created_at": 1749146531 }
```

**Consent** (peer accepts)
`POST /messages/calls/{call_id}/recording/consent` — req: none; resp 200
`RecordingConsentOut`:
```json
{ "recording_id": "rec_...", "status": "...", "started_at": 1749146540 }
```

**Decline** (peer rejects)
`POST /messages/calls/{call_id}/recording/decline` — req: none; resp 200
`RecordingDeclineOut`:
```json
{ "ok": true }
```

**Presign upload** (after capture finalized)
`POST /messages/calls/{call_id}/recording/upload/presign` — req `RecordingUploadPresignIn`:
```json
// request
{ "content_type": "video/mp4", "file_size_bytes": 184320 }
// response 200 (RecordingUploadPresignOut)
{ "upload_url": "https://. . ./put?X-Amz-Signature=. . .", "recording_id": "rec_...",
  "s3_key": "recordings/rec_....mp4", "expires_at": 1749147431 }
```
**CORRECTION:** the presign request field is `file_size_bytes` (not `size_bytes`); there is
**no** `duration_ms` field on presign. `content_type` is constrained by the backend to
the regex `^video/(webm|mp4)$` — i.e. the artifact MUST be a **video** container
(`video/webm` or `video/mp4`), NOT `audio/mp4`. The response returns `s3_key` (not `key`),
`expires_at` epoch (not `expires_in`), and the canonical `recording_id`; it does **not**
return a `method` or `headers` object — the client PUTs with `Content-Type` set to the
same `content_type` it presigned with (per `useCallRecording.ts`).

**PUT** to `upload_url` (storage, no app cookies) with the file body and the
`Content-Type` header — handled by AND-129 uploader.

**Complete** (not "confirm")
`POST /messages/calls/{call_id}/recording/upload/complete` — req `RecordingUploadCompleteIn`:
```json
// request
{ "recording_id": "rec_...", "duration_seconds": 73.4 }
// response 200 (RecordingUploadCompleteOut)
{ "recording_id": "rec_...", "status": "...", "download_url": null, "download_expires_at": null }
```
**CORRECTION:** the complete request takes `recording_id` + `duration_seconds` (a float,
seconds) — NOT `key`, `size_bytes`, or `duration_ms`. The response has `recording_id` +
`status` (required) plus nullable `download_url`/`download_expires_at`; there is no
`created_at` on this response.

**Errors** follow the standard FastAPI `detail` shape. All recording endpoints document
only `422 HTTPValidationError` in the OpenAPI spec (request-validation errors). **The
codes `409 consent_not_granted`, `410 recording_expired`, and `403 not_a_participant`
named in earlier drafts are NOT documented in the OpenAPI spec for these routes and are
treated as Unverified-assumptions** (see §16); handle them defensively but do not rely on
the exact `code` strings. Map all errors through the shared `AppError` mapper.

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
  expired (presign returns `expires_at` epoch; treat the URL as expired once `now >=
  expires_at` or on a storage 403/expiry response — the `410 recording_expired` code is an
  unverified assumption, see §16).
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
  - `AppError` mapping for `422` (documented) plus defensive handling of `409`/`410`/`403`
    (these recording-specific codes are NOT documented in OpenAPI — see §16; assert on
    generic status mapping, not on `code` strings).
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
- **Exact endpoint shapes (RESOLVED in review):** earlier `/ui/calls/.../recording/*`
  paths were wrong. Verified paths are `/messages/calls/{call_id}/recording/{request|
  consent|decline}` and `/recording/upload/{presign|complete}` with the shapes in §5/§16.
  Remaining gap: **no server-side withdraw/revoke endpoint exists** — stop is client-local
  in v1; raise with backend if server-authoritative revocation is legally required.
- **Telephony audio routing (Risk):** capturing mic during an active VoIP call may
  conflict with the call's audio stack from AND-296; validate `MediaRecorder` coexists
  with the call audio session on device.
- **Legal jurisdiction (Q):** two-party consent UX assumed sufficient; retention is a
  backend policy, out of scope here.

## 14. Acceptance Criteria

AC-1. From a `Connected` call, tapping Record POSTs `/recording/request`; UI shows
`RequestPending`; the peer receives a consent prompt with the requester's name.
AC-2. Peer **Consent** POSTs `/recording/consent` (200 `RecordingConsentOut` with
`started_at`) → capture starts; **Decline** POSTs `/recording/decline` (200 `{ ok: true }`)
→ no capture, both sides return to idle with a message (FR-3, FR-4).
AC-3. Capture provably never begins before the server reports `granted` (asserted by
unit test on the gate).
AC-4. Withdrawal mid-recording stops capture ≤ 500 ms and discards the partial file with
no upload (FR-5).
AC-5. Call end with an active recording finalizes the file and transitions to
`PendingUpload` (FR-6).
AC-6. A finalized recording uploads end-to-end (presign→PUT→complete) with visible 0→100%
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

## 16. Citations & Assumption Audit

Each claim below is paired with a VERDICT (Verified / Corrected / Unverified-assumption)
and an exact SOURCE pointer.

1. **Consent surface lives under `/messages/calls/{call_id}/recording/...` (request /
   consent / decline as three separate POSTs).** VERDICT: Corrected (draft used
   `/ui/calls/.../recording/consent` with a single `decision` body). SOURCE: OpenAPI
   `POST /messages/calls/{call_id}/recording/request`, `POST .../recording/consent`,
   `POST .../recording/decline` (openapi.index.txt L295–297); frontend
   `src/hooks/useCallRecording.ts: apiRequestRecording/apiConsentRecording/apiDeclineRecording`.
2. **`RecordingRequestOut` = `{ recording_id, status, created_at:int }`.** VERDICT:
   Verified. SOURCE: `openapi.pretty.json` components.schemas.RecordingRequestOut.
3. **`RecordingConsentOut` = `{ recording_id, status, started_at:int }`.** VERDICT:
   Verified. SOURCE: components.schemas.RecordingConsentOut.
4. **`RecordingDeclineOut` = `{ ok:boolean=true }`.** VERDICT: Verified. SOURCE:
   components.schemas.RecordingDeclineOut.
5. **Consent/request/decline take NO request body.** VERDICT: Verified. SOURCE:
   openapi.index.txt L295–297 (`req=` empty); `useCallRecording.ts` posts with no payload.
6. **Presign path is `POST .../recording/upload/presign`; request =
   `{ content_type, file_size_bytes }`.** VERDICT: Corrected (draft used `.../{recording_id}/presign`
   and field `size_bytes` plus a `duration_ms`). SOURCE: OpenAPI
   `POST /messages/calls/{call_id}/recording/upload/presign`, req=RecordingUploadPresignIn
   (openapi.index.txt L299); components.schemas.RecordingUploadPresignIn (fields
   `content_type`, `file_size_bytes` only); `useCallRecording.ts: apiPresignUpload`.
7. **`content_type` is constrained to `^video/(webm|mp4)$` (video container required;
   `audio/mp4` is rejected).** VERDICT: Corrected (draft assumed `audio/mp4` / `.m4a`).
   SOURCE: components.schemas.RecordingUploadPresignIn.content_type.pattern; corroborated by
   `useCallRecording.ts: selectMimeType()` returning `video/webm`/`video/mp4`.
8. **`RecordingUploadPresignOut` = `{ upload_url, recording_id, s3_key, expires_at:int }`
   (no `method`, no `headers`, no `expires_in`, key is `s3_key`).** VERDICT: Corrected.
   SOURCE: components.schemas.RecordingUploadPresignOut.
9. **Upload finalize is `POST .../recording/upload/complete` ("complete", not "confirm");
   request = `{ recording_id, duration_seconds:float }`.** VERDICT: Corrected (draft used
   `/confirm` with `{ key, size_bytes, duration_ms }`). SOURCE: OpenAPI
   `POST /messages/calls/{call_id}/recording/upload/complete`, req=RecordingUploadCompleteIn
   (openapi.index.txt L298); components.schemas.RecordingUploadCompleteIn;
   `useCallRecording.ts: apiCompleteUpload`.
10. **`RecordingUploadCompleteOut` = `{ recording_id, status, download_url?, download_expires_at? }`
    (no `created_at`).** VERDICT: Corrected. SOURCE: components.schemas.RecordingUploadCompleteOut.
11. **PUT to `upload_url` carries only `Content-Type` (the presigned content_type) and no
    app cookies/CSRF.** VERDICT: Verified. SOURCE: `useCallRecording.ts: stopRecording()`
    (plain `fetch(presignData.upload_url, { method:"PUT", headers:{ "Content-Type": mimeType } })`,
    no credentials); reinforced by §8 cookie-less uploader requirement.
12. **There is NO server-side withdraw/revoke endpoint.** VERDICT: Corrected (draft FR-5
    posted `consent` with `decision=withdraw`). SOURCE: `grep withdraw openapi.index.txt`
    returns only billing/license/appeals routes (L52, L1203, L1617, L2191); no recording
    withdraw; `useCallRecording.ts` exposes only `stopRecording()` (client-local).
13. **Auth: cookie session; mutations echo `ui_csrf` cookie as `X-CSRF-Token`.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` L167–171 (`getCookie("ui_csrf")` → `X-CSRF-Token`).
14. **401 → single `POST /ui/session/refresh` then one retry; second failure logs out.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession()` L121–130 and 401 block
    L194–237 (`refreshPromise` dedup, one retry, `logout("session_expired")`).
15. **Consent events reach the peer via a push/signaling channel (web uses SSE
    `messaging:call-event` with `call.recording_request` / `_accept` / `_decline` /
    `_started` / `_stopped`).** VERDICT: Verified (web mechanism). SOURCE:
    `src/hooks/useCallRecording.ts` L104–136. NOTE: Android delivery mechanism is owned by
    AND-296 and is an Unverified-assumption here (see §13).
16. **Web client records the REMOTE stream (mixing local+remote audio when both present),
    not a mic-only artifact.** VERDICT: Verified. SOURCE: `useCallRecording.ts` L193–268.
    Implication: "who captures / what is captured" remains an open question for Android
    (see §13, audit item below).
17. **`RecordingMetadataOut` (GET `.../recording`) fields incl. `mime_type`,
    `duration_seconds:number`, `file_size_bytes`, epoch timestamps, `participants:[str]`.**
    VERDICT: Verified (reference for the metadata model). SOURCE:
    components.schemas.RecordingMetadataOut; OpenAPI GET
    `/messages/calls/{call_id}/recording` (openapi.index.txt L294).
18. **Error codes `409 consent_not_granted`, `410 recording_expired`,
    `403 not_a_participant`.** VERDICT: Unverified-assumption. SOURCE: not present in OpenAPI
    — all recording routes document only `200` + `422 HTTPValidationError`
    (openapi.index.txt L294–299). No `code` strings appear in the schemas. Handle
    defensively by HTTP status, do not assert on `code`.
19. **`MediaRecorder` co-exists with the active VoIP call audio session (AND-296).**
    VERDICT: Unverified-assumption. SOURCE: framework ref —
    https://developer.android.com/reference/android/media/MediaRecorder and
    https://developer.android.com/media/optimize/audio-focus ; must be validated on the
    physical device (mic contention with the WebRTC/Telecom audio stack).
20. **`RECORD_AUDIO` is a runtime (dangerous) permission requested just-in-time.** VERDICT:
    Verified. SOURCE: framework ref —
    https://developer.android.com/reference/android/Manifest.permission#RECORD_AUDIO and
    https://developer.android.com/training/permissions/requesting .
21. **API < 26: `MediaRecorder(Context)` ctor unavailable; use deprecated no-arg ctor
    (minSdk 24).** VERDICT: Verified. SOURCE: framework ref —
    https://developer.android.com/reference/android/media/MediaRecorder#MediaRecorder(android.content.Context)
    (added in API 31; deprecated no-arg ctor otherwise).

### Corrections made

- §2/§4: capture artifact changed from `audio/mp4` `.m4a` to a **video container**
  `video/mp4` `.mp4` (presign regex `^video/(webm|mp4)$`). [items 7, 8]
- §5 fully rewritten: paths moved from `/ui/calls/...` to `/messages/calls/.../recording/...`;
  single `consent{decision}` endpoint split into request/consent/decline; presign field
  `size_bytes`→`file_size_bytes` and `duration_ms` removed; presign response `key`→`s3_key`,
  `expires_in`→`expires_at`, `method`/`headers` removed; `/confirm`→`/upload/complete` with
  body `{ recording_id, duration_seconds }`; timestamps are integer epoch. [items 1, 6, 8, 9, 10]
- §4 repository interface and `ConsentDecision` enum: replaced single
  `respondConsent(decision)` with `requestRecording()/consent()/decline()`; removed
  `Withdraw`; updated `presign`/`complete` signatures. [items 1, 6, 9, 12]
- FR-5 / §13 / AC: removed the nonexistent `decision=withdraw` POST; stop is now defined as
  client-local with a `call.recording_stopped` signaling event. [item 12]
- §5/§7/§11: error codes `409`/`410`/`403` reclassified as Unverified-assumptions; retry
  expiry keyed off `expires_at`. [item 18]
- §2: web reference corrected from `endpoints/calls.ts` (does not exist for this feature) to
  `src/hooks/useCallRecording.ts`. [item 1]

### Open assumptions

- **Signaling transport on Android (consent + stop events).** Owned by AND-296; web uses
  SSE. Mechanism (FCM push / poll / WS) unconfirmed — affects prompt/stop latency and the
  30 s consent timeout. [item 15]
- **Who captures and what is captured.** Web records the remote (or mixed) stream as
  *video*; this spec assumes the requester device captures a `video/mp4`. Whether Android
  should capture mic-only-in-mp4, remote stream, or both per-participant is unconfirmed with
  backend. [items 7, 16]
- **Server-side consent revocation.** No backend endpoint; legal sufficiency of a
  client-local stop is unconfirmed. [item 12]
- **Recording-specific error codes (`409`/`410`/`403`).** Not in OpenAPI; cannot be verified
  without backend confirmation. [item 18]
- **`MediaRecorder` vs. live VoIP audio-session contention.** Cannot be verified from
  sources; requires on-device validation. [item 19]

## 17. Test Plan

IDs `TC-AND-302-NN`. "Physical device" = Samsung Galaxy A15 5G (SM-A156U, API 34, arm64,
serial R5CX821TA9R). "Emulator" = AVD `test35` (API 35, x86_64). JVM = local Robolectric/unit.

- **TC-AND-302-01 — Request recording happy path.** Type: contract/MockWebServer. Target:
  JVM. Preconditions: `Connected` call, MockWebServer queues `POST .../recording/request` →
  200 `{recording_id, status, created_at}`. Steps: call `requestRecording()`. Expected:
  exactly one `POST /messages/calls/{id}/recording/request` with header `X-CSRF-Token`
  present and empty body; phase → `RequestPending`; `recording_id` captured; Record control
  disabled. Traces: AC-1, AC-9.

- **TC-AND-302-02 — Peer consent starts gated capture.** Type: contract/MockWebServer +
  unit. Target: JVM. Preconditions: incoming `call.recording_request` event delivered;
  MockWebServer queues `POST .../recording/consent` → 200 `RecordingConsentOut`. Steps:
  `respondToPrompt(consent=true)`. Expected: `POST .../recording/consent` (no body) sent;
  only after the 200 does the gate permit `AudioRecorder.start()`; phase → `Recording`.
  Traces: AC-2, AC-3.

- **TC-AND-302-03 — Consent gate negative (never capture before server grant).** Type: unit.
  Target: JVM. Preconditions: fake `AudioRecorder`; consent response delayed/withheld.
  Steps: drive `requestRecording()` and assert recorder state while server response is
  pending and after a `decline`. Expected: `AudioRecorder.start()` is NEVER invoked unless a
  successful consent/started state is observed; gate lives in the repository, not the UI.
  Traces: AC-3.

- **TC-AND-302-04 — Decline path.** Type: contract/MockWebServer. Target: JVM.
  Preconditions: prompt shown; MockWebServer queues `POST .../recording/decline` → 200
  `{ ok: true }`. Steps: `respondToPrompt(consent=false)`. Expected: decline POST sent; no
  capture; both phases → `Idle` with non-blocking message; no file created. Traces: AC-2.

- **TC-AND-302-05 — Stop mid-recording discards partial, no upload.** Type: unit. Target:
  JVM. Preconditions: phase `Recording` with a partial file present; fake recorder. Steps:
  invoke local stop (the v1 client-local stop). Expected: `AudioRecorder.discard()` called
  within 500 ms (assert via virtual clock), partial file deleted, NO presign/PUT/complete
  request issued, a `call.recording_stopped` signaling event emitted. Traces: AC-4.

- **TC-AND-302-06 — Auto-finalize on call end.** Type: unit. Target: JVM. Preconditions:
  phase `Recording`. Steps: `onCallEnded(reason)` from the CallSession observer. Expected:
  recorder finalized (`stop()` returns the file), phase → `PendingUpload`, a
  `pending_recording` Room row inserted. Traces: AC-5.

- **TC-AND-302-07 — Upload happy path presign→PUT→complete.** Type: contract/MockWebServer
  (reusing AND-129 harness). Target: JVM. Preconditions: finalized `video/mp4` file;
  MockWebServer queues presign 200 (`upload_url`,`recording_id`,`s3_key`,`expires_at`), the
  storage PUT 200, and complete 200. Steps: run upload. Expected: presign body =
  `{content_type:"video/mp4", file_size_bytes:<n>}`; PUT to `upload_url` carries
  `Content-Type: video/mp4` and **no** Cookie/`X-CSRF-Token` header; complete body =
  `{recording_id, duration_seconds:<float>}`; progress emits 0→100; phase → `Uploaded`; Room
  row deleted; cache file deleted. Traces: AC-6, AC-9.

- **TC-AND-302-08 — Upload failure then Retry succeeds; expiry re-presign.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: presign 200 with near-past
  `expires_at`; first PUT → 5xx (or 403 expiry). Steps: run upload, observe `Failed`, tap
  Retry. Expected: phase → `Failed` with file + Room row preserved; Retry re-presigns
  (because `now >= expires_at`) reusing the same `recording_id`, re-PUTs, completes →
  `Uploaded`. (Do not assert on a `410 code` string — unverified.) Traces: AC-6.

- **TC-AND-302-09 — Cancel deletes file + queue row.** Type: contract/MockWebServer. Target:
  JVM. Preconditions: phase `Uploading`. Steps: `cancelUpload()`. Expected: in-flight PUT
  cancelled; phase → `Cancelled`; cache file deleted; `pending_recording` row removed; no
  `complete` call issued. Traces: AC-6.

- **TC-AND-302-10 — Process-death resume from durable queue.** Type: integration
  (Room in-memory + restart). Target: JVM (Robolectric) for the queue logic; optionally
  emulator for full Application restart. Preconditions: a row in state `Uploading`. Steps:
  simulate process death, re-create the repository, call `pendingUploads()`. Expected:
  `Uploading` rows reset to `PendingUpload` and surfaced as resumable; resume re-presigns and
  completes. Traces: AC-8.

- **TC-AND-302-11 — RECORD_AUDIO just-in-time grant + denial.** Type: instrumented/e2e.
  Target: PHYSICAL DEVICE (real runtime-permission dialog and mic; must be physical because
  it exercises the actual mic and permission grant, not a mock). Preconditions: permission
  not yet granted. Steps: (a) grant on prompt → start capture; (b) revoke + retry, deny on
  prompt. Expected: (a) capture starts and writes a non-empty `video/mp4`; (b) denial
  cancels the request cleanly, shows rationale, no file, no crash. Also assert no background
  capture after the call is foreground-dismissed. Traces: AC-7.

- **TC-AND-302-12 — MediaRecorder coexists with live VoIP audio (real hardware).** Type:
  instrumented/e2e. Target: PHYSICAL DEVICE (mic contention with the WebRTC/Telecom audio
  session cannot be validated on the emulator; arm64/API-34 is the shipping target). Pre:
  active AND-296 call with mic in use. Steps: grant consent, start capture during the call.
  Expected: `MediaRecorder.start()` succeeds without `IllegalStateException`/audio-focus
  loss; recorded file is non-empty and contains audio; call audio unaffected. On failure,
  recorder error path discards the partial and surfaces a recoverable error. Traces: AC-4,
  AC-5 (capture viability underpins these).

- **TC-AND-302-13 — Consent dialog accessibility (TalkBack).** Type: Compose-UI +
  instrumented. Target: emulator `test35` (TalkBack/semantics; physical device optional).
  Preconditions: consent prompt shown. Steps: traverse with accessibility semantics
  enabled. Expected: dialog takes focus; Consent/Decline have `contentDescription` and ≥48 dp
  targets; recording state announced via `liveRegion`; REC indicator is icon+text (not
  color-only); upload progress exposes `progressBarRangeInfo`; Cancel/Retry are
  TalkBack-reachable. Traces: AC-2, AC-6, AC-7.

- **TC-AND-302-14 — Flaky/offline dev-host resilience.** Type: contract/MockWebServer +
  manual. Target: JVM for simulated faults; manual smoke against dev host
  `http://18.222.237.167:8000`. Preconditions: MockWebServer set to drop/delay > 20 s and to
  return 401 once. Steps: drive request/consent and an upload through (a) a network drop
  (offline), (b) a 20 s timeout, (c) a single 401. Expected: (a) offline → `AppError(0)`
  surfaced, no crash, state recoverable; (b) timeout respects the 20 s read/connect bound and
  presign/complete retry with bounded backoff while consent mutations do NOT auto-retry;
  (c) a single 401 triggers one `POST /ui/session/refresh` then one retry, second 401 →
  re-auth. Traces: AC-9 (and resilience for AC-1/AC-6).

### Coverage matrix

| AC | Covered by |
|----|-----------|
| AC-1 (request → RequestPending, peer prompt) | TC-01, TC-14 |
| AC-2 (consent→capture / decline→idle) | TC-02, TC-04, TC-13 |
| AC-3 (capture never before server grant) | TC-02, TC-03 |
| AC-4 (stop ≤500 ms, discard, no upload) | TC-05, TC-12 |
| AC-5 (call-end finalize → PendingUpload) | TC-06, TC-12 |
| AC-6 (upload e2e + progress + cancel/retry) | TC-07, TC-08, TC-09, TC-13 |
| AC-7 (RECORD_AUDIO JIT + denial) | TC-11, TC-13 |
| AC-8 (process-death resume) | TC-10 |
| AC-9 (CSRF on mutations; PUT no cookies) | TC-01, TC-07, TC-14 |
