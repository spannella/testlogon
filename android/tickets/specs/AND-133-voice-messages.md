---
id: AND-133
title: Voice messages
milestone: M3
epic: E19
priority: P1
size: L
depends_on: [AND-129]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-133 — Voice messages

## 1. Overview & Goal

Add the ability to record, send, and play back voice messages inside the TestLogon
Android chat/message surface. A user holds (or taps) a record control, the app captures
audio to a compressed local file, renders a live amplitude waveform during capture, lets
the user preview/cancel/send, uploads the recorded file through the existing reusable
attachment pipeline (AND-129: presign → PUT → confirm), associates it as a
`voice-message` attachment on a message, and renders an inline player with a static
waveform, scrubbing, and play/pause for received and sent voice messages.

The goal of this ticket is a complete **record → send → play round-trip** that works
against the dev FastAPI backend. The upload transport itself is **owned by AND-129**;
AND-133 supplies the recorder, the waveform UI (capture + playback), the player, and the
`voice-message`-specific presign/confirm metadata. Success means a voice clip recorded on
one device can be uploaded, confirmed, retrieved, and played back with an accurate
duration and seekable waveform.

Out of scope: real-time/streaming voice, voice-to-text transcription, call/VoIP features,
and any message-list composition plumbing beyond attaching a confirmed voice message
(message send itself is the host feature's concern).

## 2. Context & References

- Module placement: a new `feature-voice` module (`com.testlogon.android.feature.voice`)
  depending on `core-ui`, `core-data`, `core-network`, `core-model`, and the uploader
  abstraction exposed by AND-129 (assumed in `core-data`, `UploaderRepository`).
- Layering: `app -> feature-voice -> core-*`. ViewModels expose `StateFlow<UiState>`;
  all network calls return typed `ApiResult<T>`; FastAPI `detail` mapping (string |
  `[{msg}]` | `{code,...}`) is handled by `core-network`.
- Web reference: voice presign + create endpoints in `src/api/endpoints/messaging.ts`
  (`presignVoiceMessage`, `createVoiceMessage`, `sendVoiceMessage`) and shared types in
  `src/api/types.ts` (`Message.voice_message`). **Correction:** there is **no generic
  "confirm" step and no `kind: "voice-message"` flag** — voice has a *dedicated* two-call
  flow: presign (allocates `message_id` + `upload_url` + `s3_key`) → PUT to `upload_url` →
  `POST .../voice-message` (create message record). The wire field is `waveform_data`
  (a JSON `number[]`, **not** base64) and `duration_seconds` (**not** `duration_ms`). The
  server message `kind` enum value is `voice_message` (underscore, not hyphen). See §5 and
  §16 for the verified shapes.
- Auth: cookie-based session with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie
  jar; on 401 the client calls `POST /ui/session/refresh` once then retries. This is the
  shared OkHttp stack from `core-network`; AND-133 adds no new auth logic.
- Dev backend `http://18.222.237.167:8000` is plaintext HTTP and unreliable: ~20s
  timeouts, bounded backoff retry for idempotent GETs only, offline/stale UI states. The
  PUT-to-storage step is owned by AND-129.
- Audio: `androidx.media3` (ExoPlayer 1.4) is already a project dependency (HLS); reuse
  ExoPlayer for playback. Recording uses platform `MediaRecorder`.

## 3. Functional Requirements

FR-1 **Record.** From the message composer, a microphone affordance starts recording. The
default interaction is press-and-hold (release to finish); a sticky/lock mode lets the user
slide up to lock and continue hands-free, then tap stop. A tap-only fallback (tap to start,
tap to stop) is available for accessibility.

FR-2 **Live waveform.** While recording, render a scrolling amplitude waveform driven by
periodic max-amplitude sampling (~60 ms cadence), plus an elapsed-time mm:ss counter.

FR-3 **Limits.** Maximum clip length is 120 s; at 110 s show a countdown and auto-stop at
120 s, keeping the captured audio. Minimum valid clip is 1 s; releasing before 1 s cancels
with a "hold to record" hint and no file is kept.

FR-4 **Cancel.** During press-and-hold, sliding left past a threshold (or tapping the trash
control in locked mode) cancels recording and deletes the temp file.

FR-5 **Preview.** After stopping (locked/tap modes), the user can play the local clip,
re-record (discard + start over), cancel, or send.

FR-6 **Send.** On send, the recorder downsamples the captured amplitudes into a normalized
waveform — a `List<Float>` in 0.0..1.0 (default ~64 buckets; the API accepts 10..200), then
hands the file plus `VoiceMessageMeta` to the send flow (presign → PUT via AND-129 →
`POST .../voice-message` create). Upload progress and cancel/retry are surfaced by the
uploader's own UI/state.

FR-7 **Playback.** A confirmed voice message renders as an inline player: play/pause,
elapsed/total duration, a static waveform that fills as playback progresses, and tap/drag
seek on the waveform. Only one voice message plays at a time across the screen.

FR-8 **Round-trip (acceptance).** A clip recorded on the device uploads, confirms, and can
be fetched and played back with correct duration and waveform — verified end-to-end.

FR-9 **Permissions.** `RECORD_AUDIO` is requested on first record. If denied, show a
rationale with a settings deep-link; recording controls are disabled until granted.

FR-10 **Interruptions.** Incoming call / audio-focus loss / app backgrounding stops an
active recording, preserving captured audio as a finished preview rather than discarding it.

## 4. Technical Design

New module `feature-voice`. Audio format: AAC-LC in an MP4/M4A container via
`MediaRecorder` (`OutputFormat.MPEG_4`, `AudioEncoder.AAC`, mono, 44.1 kHz, 64 kbps) —
small, broadly decodable by ExoPlayer, and accepted by the backend object store.

Recorder abstraction (testable; `MediaRecorder` hidden behind an interface):

```kotlin
interface VoiceRecorder {
    val state: StateFlow<RecorderState>
    /** Emits max amplitude (0..32767) at ~60ms cadence while recording. */
    val amplitudes: SharedFlow<Int>
    fun start(outputFile: File)
    fun stop(): RecordingResult?   // null if below MIN_DURATION_MS
    fun cancel()                   // stops and deletes the temp file
}

sealed interface RecorderState {
    data object Idle : RecorderState
    data class Recording(val elapsedMs: Long) : RecorderState
    data class Stopped(val result: RecordingResult) : RecorderState
    data class Error(val cause: VoiceError) : RecorderState
}

data class RecordingResult(
    val file: File,
    val durationMs: Long,
    val amplitudes: List<Int>,     // raw samples captured during recording
)

const val MIN_DURATION_MS = 1_000L
const val MAX_DURATION_MS = 120_000L
const val WAVEFORM_BUCKETS = 64
```

`MediaRecorderVoiceRecorder` implements the interface, polling `getMaxAmplitude()` on a
coroutine ticker, accumulating elapsed time, and enforcing `MAX_DURATION_MS`. Temp files
live in `context.cacheDir/voice/<uuid>.m4a`.

Waveform downsampling (pure, unit-tested):

```kotlin
object Waveform {
    /**
     * Collapse raw samples into [buckets] normalized peaks. The wire format is a JSON
     * array of floats in 0.0..1.0 (matching the web client and OpenAPI
     * CreateVoiceMessageRequest.waveform_data: number[], 10..200 items) — NOT base64 and
     * NOT a fixed 64-byte field. WAVEFORM_BUCKETS=64 is a client default within [10,200].
     */
    fun normalize(raw: List<Int>, buckets: Int = WAVEFORM_BUCKETS): List<Float>  // 0f..1f
}
```
Correction: there is **no base64 encode/decode** on the wire. `waveform_data` is sent and
received as a plain `List<Float>` (JSON `number[]`). Base64 is used only for the local Room
TEXT column if a compact at-rest form is desired (an internal choice, not the API).

ViewModels:

```kotlin
@HiltViewModel
class VoiceComposerViewModel @Inject constructor(
    private val recorder: VoiceRecorder,
    private val uploader: UploaderRepository,       // from AND-129
    private val voiceRepo: VoiceMessageRepository,
) : ViewModel() {
    val uiState: StateFlow<VoiceComposerUiState>
    fun onRecordPressed(); fun onRecordReleased()
    fun onLock(); fun onCancel(); fun onReRecord()
    fun onSend(conversationId: String)
}

@HiltViewModel
class VoiceMessageViewModel @Inject constructor(
    private val player: VoicePlayerController,       // wraps ExoPlayer
    private val voiceRepo: VoiceMessageRepository,
) : ViewModel() {
    val uiState: StateFlow<VoicePlayerUiState>
    fun bind(message: VoiceMessage)
    fun onTogglePlay(); fun onSeekTo(fraction: Float)
}
```

UI state:

```kotlin
sealed interface VoiceComposerUiState {
    data object Idle : VoiceComposerUiState
    data class Recording(val elapsedMs: Long, val peaks: List<Int>, val locked: Boolean) : VoiceComposerUiState
    data class Preview(val result: RecordingResult, val playing: Boolean) : VoiceComposerUiState
    data class Sending(val progress: Float, val cancelable: Boolean) : VoiceComposerUiState
    data class Failed(val error: VoiceError, val retryable: Boolean) : VoiceComposerUiState
}

data class VoicePlayerUiState(
    val durationMs: Long,
    val positionMs: Long,
    val playing: Boolean,
    val waveform: List<Int>,
    val loading: Boolean,
    val error: VoiceError? = null,
)
```

Compose surfaces (`core-ui` Material 3 theme): `VoiceComposerBar`, `RecordingOverlay`
(live waveform + timer + slide-to-cancel + lock), `VoicePreviewCard`, and `VoiceMessageBubble`
(static waveform + play/pause + scrubber). `WaveformView` is a shared `Canvas` composable
used by both capture and playback (bars positioned by bucket, progress overlay color).

Playback uses a single shared `VoicePlayerController` (Hilt `@Singleton`) wrapping one
`ExoPlayer` instance so starting a new clip stops the previous one. ExoPlayer streams the
`voice_message.audio_url` (signed S3 URL) with the cookie/CSRF OkHttp `DataSource.Factory`
from `core-network`.

## 5. API Contract

AND-133 uses a **dedicated voice-message endpoint pair** (verified against `openapi.index.txt`
and `src/api/endpoints/messaging.ts`); it reuses only the AND-129 PUT-to-storage step.
**The open question in the original draft is resolved: dedicated `/voice-message/*` routes
exist** (see §16). All field names below are verified against the OpenAPI schemas
`PresignVoiceMessageRequest` / `CreateVoiceMessageRequest` / `MessageOut` and the web client.

The flow is **presign → PUT → create** (there is no "confirm" op):

**1. Presign** — `POST /messaging/conversations/{conversation_id}/voice-message/presign`
(`conversation_id` is a path param; OpenAPI schema `PresignVoiceMessageRequest`).

Request:
```json
{ "content_type": "audio/mp4", "size_bytes": 184320, "duration_seconds": 7.4 }
```
Constraints: `content_type` must match `^audio/(webm|mp4|ogg|wav)`; `size_bytes` 1..52428800
(50 MB); `duration_seconds` 0.5..300 (float). Response is untyped in OpenAPI (`schema: {}`)
but the web client and image-presign sibling (`PresignOut`) confirm the shape:
```json
{
  "message_id": "m_0123456789abcdef0123456789abcdef",
  "upload_url": "https://<bucket>/...signed",
  "s3_key": "<object-key>"
}
```
Note: **`message_id` is allocated by the server at presign time** (pattern
`^m_[a-f0-9]{32}$`) and is echoed back in the create call below.

**2. PUT to storage** (owned by AND-129): `PUT upload_url` with header
`Content-Type: <content_type>` and the raw audio bytes.

**3. Create** — `POST /messaging/conversations/{conversation_id}/voice-message`
(OpenAPI schema `CreateVoiceMessageRequest`; response `MessageOut`).

Request:
```json
{
  "message_id": "m_0123456789abcdef0123456789abcdef",
  "s3_key": "<object-key>",
  "content_type": "audio/mp4",
  "size_bytes": 184320,
  "duration_seconds": 7.4,
  "waveform_data": [0.0, 0.12, 0.34, 0.51, 0.22, 0.07],
  "consumption_policy": "none",
  "reply_to_message_id": null,
  "send_at": null
}
```
Required: `message_id, s3_key, content_type, size_bytes, duration_seconds, waveform_data`.
`waveform_data` is a JSON **array of numbers** (OpenAPI: 10..200 items; the web recorder
emits floats in 0..1 with ~30..100 entries), **not** a base64 string and **not** a fixed
64-byte field. `consumption_policy` is `none` (default) or `listen_once`.

Response is a full `MessageOut` (the standard message envelope). Voice-specific fields live
in `message.voice_message` and top-level identity/timestamps differ from the original draft:
```json
{
  "message_id": "m_0123456789abcdef0123456789abcdef",
  "conversation_id": "conv_123",
  "sender_id": "u_...",
  "kind": "voice_message",
  "created_at": 1749124800,
  "consumption_policy": "none",
  "consumption_state": "pending",
  "voice_message": {
    "audio_url": "https://<bucket>/...signed",
    "audio_content_type": "audio/mp4",
    "audio_size_bytes": 184320,
    "duration_seconds": 7.4,
    "waveform_data": [0.0, 0.12, 0.34, 0.51, 0.22, 0.07]
  }
}
```
Corrections vs the original draft: the playback URL is `voice_message.audio_url` (not a
top-level `media_url`); the identifier is `message_id` (not `id`); `created_at` is an
**integer epoch (seconds)**, not an ISO-8601 string; sizes/durations are
`audio_size_bytes`/`duration_seconds`, not `size_bytes`/`duration_ms`; and `kind` is
`voice_message`.

Retrofit:
```kotlin
interface VoiceApi {
    @POST("messaging/conversations/{conversationId}/voice-message/presign")
    suspend fun presign(
        @Path("conversationId") conversationId: String,
        @Body body: PresignVoiceRequest,        // content_type, size_bytes, duration_seconds
    ): ApiResult<PresignVoiceResponse>           // message_id, upload_url, s3_key

    @POST("messaging/conversations/{conversationId}/voice-message")
    suspend fun create(
        @Path("conversationId") conversationId: String,
        @Body body: CreateVoiceRequest,          // message_id, s3_key, content_type, size_bytes,
                                                 // duration_seconds, waveform_data, ...
    ): ApiResult<MessageDto>                      // MessageOut; voice in .voiceMessage
}
```

All calls carry the session cookies + `X-CSRF-Token` via the shared OkHttp interceptor
(verified in `src/api/client.ts`: `ui_csrf` cookie echoed as `X-CSRF-Token`, credentials
included). Presign and create are **non-idempotent POSTs**: no automatic retry beyond the
shared client's single 401→`POST /ui/session/refresh`→retry. Because `message_id` and
`s3_key` are stable after presign, a failed create can be safely re-issued with the same
`message_id`/`s3_key` without re-uploading (de-dupe by `message_id`).

## 6. Data & State Management

- **Repository.** `VoiceMessageRepository` exposes `suspend fun send(file, meta,
  conversationId): ApiResult<VoiceMessage>` (presign → PUT via AND-129 uploader → create)
  and a refresh path that re-reads the parent message to obtain a fresh signed `audio_url`
  (there is no dedicated `GET /voice-message/{id}` — see §16).
- **Domain model** in `core-model`:
  ```kotlin
  // Mapped from MessageOut + MessageOut.voice_message (see §5). `id` is the server
  // `message_id`; `audioUrl` is `voice_message.audio_url`; `createdAt` is an epoch-seconds
  // integer on the wire, parsed to Instant on the client.
  data class VoiceMessage(
      val id: String, val conversationId: String, val audioUrl: String,
      val durationSeconds: Double, val sizeBytes: Long, val waveform: List<Float>,
      val createdAt: Instant,
  )
  data class VoiceMessageMeta(
      val durationSeconds: Double, val waveform: List<Float>,
      val contentType: String = "audio/mp4",
  )
  ```
- **Room cache (`core-data`).** `voice_message` table keyed by `id` (= server
  `message_id`; cols: conversationId, audioUrl, durationSeconds, sizeBytes, waveform TEXT
  [JSON or base64, an at-rest choice], createdAt epoch) so bubbles render offline with
  their waveform; the signed `audio_url` is treated as short-lived and re-fetched (by
  re-reading the message) on a 403/expired-URL playback failure. Note: the OpenAPI index
  exposes no standalone `GET /voice-message/{id}`; URL refresh must come from re-fetching
  the parent message via the host conversation/message API (see §16 open assumptions).
- **DataStore prefs.** Persist the user's preferred record interaction mode (hold vs tap)
  and a one-time "slide to cancel" coachmark-seen flag.
- **Temp files.** Recordings live in `cacheDir/voice`; deleted on cancel, on successful
  confirm, and via a startup sweep of files older than 24h.
- **State flow.** `VoiceRecorder.amplitudes` (SharedFlow) → throttled into the `Recording`
  UI state's `peaks`. Player position polled at ~50 ms from ExoPlayer into
  `VoicePlayerUiState.positionMs` while playing only (no polling when paused).

## 7. Error Handling & Resilience

- **Recorder errors.** `MediaRecorder` start/prepare failures, mic-in-use (audio focus
  denied), and storage-full map to `VoiceError.RecorderUnavailable` / `.StorageFull`;
  surfaced as a `Failed` composer state with retry; temp file deleted.
- **Permission denied.** `VoiceError.PermissionDenied` → rationale + settings deep-link;
  controls disabled, no crash.
- **Interruptions.** Audio-focus loss / phone call / background stops recording and
  preserves audio as `Preview` (FR-10); a second interruption during preview playback
  pauses playback.
- **Upload errors.** PUT delegated to AND-129 (progress/cancel/retry). Presign/create
  transport errors map via `ApiResult.Error` + FastAPI `detail` (string | `[{msg}]` |
  `{code,...}`); create is **not** auto-retried beyond the shared 401 path — the user retries
  explicitly, and a retry re-issues create with the same `message_id`/`s3_key` (allocated at
  presign) so the already-uploaded object is re-used rather than re-uploaded. Validation
  failures (422 `HTTPValidationError`) on presign/create surface as a `Failed` state.
- **Network.** ~20s OkHttp timeouts; offline → `Failed(retryable=true)` with a "saved,
  tap to retry" affordance keyed to the cached temp file until confirmed.
- **Playback.** Stream/decode error → `VoicePlayerUiState.error`; on a 403/expired URL,
  one transparent re-fetch of the parent message to refresh `voice_message.audio_url` then a
  single replay attempt (idempotent GET, eligible for bounded backoff).

## 8. Security & Privacy

- Microphone is captured only during an explicit, visible recording session; a persistent
  recording indicator is shown, and recording stops on background (FR-10).
- `RECORD_AUDIO` is the only new runtime permission. No `READ/WRITE_EXTERNAL_STORAGE`:
  files stay in app-internal `cacheDir`.
- Temp audio never leaves the device except via the authenticated AND-129 upload; temp
  files are deleted promptly (§6) and excluded from Auto Backup
  (`android:fullBackupContent` rule excluding `voice/`).
- All API/media traffic uses the shared cookie + `X-CSRF-Token` client; `audio_url` signed
  URLs are not logged. Note the dev backend is plaintext HTTP (cleartext allowed only for
  the dev host via the existing network-security-config); production requires TLS.
- No transcription or third-party audio processing; audio bytes are not inspected on-device
  beyond amplitude sampling for the waveform.

## 9. Accessibility & i18n

- Record control has a `contentDescription` and a tap-only fallback (FR-1) so it does not
  require a press-and-hold gesture; slide-to-cancel has an equivalent visible button.
- The player exposes semantics: state-described play/pause toggle, and the scrubber as a
  `progressSemantics` / seekable slider operable by TalkBack and switch access. Waveform
  bars are decorative (`contentDescription = null`); the accessible label conveys duration
  and position ("Voice message, 7 seconds, paused").
- Live region announces recording start, lock, auto-stop, and cancel.
- All strings (timer format, hints, errors, "Voice message", durations) are in
  `strings.xml`; durations formatted via locale-aware `mm:ss`. Respects large font scaling
  and high-contrast; touch targets ≥ 48 dp.

## 10. Telemetry & Logging

- Events (via the project analytics façade in `core-data`): `voice_record_start`,
  `voice_record_complete{duration_ms, canceled}`, `voice_send_start`,
  `voice_send_result{success, error_code, duration_ms, size_bytes}`,
  `voice_play_start`, `voice_play_complete{completed_fraction}`.
- No PII and no audio content/waveform/`audio_url` in telemetry — durations and sizes only.
  (Telemetry field names like `duration_ms` are the app's own analytics schema, independent
  of the wire `duration_seconds`.)
- Logging via the shared logger; `MediaRecorder`/ExoPlayer errors logged at WARN with
  error class only (DEBUG builds include stack). Upload transport logging is AND-129's.

## 11. Testing Strategy

- **Unit (JVM, `core-testing`).**
  - `Waveform.normalize` — bucket count within [10,200], normalization to 0.0..1.0,
    empty/short input, constant-amplitude, single-sample edge cases.
  - `VoiceComposerViewModel` with a fake `VoiceRecorder` + fake `UploaderRepository`:
    min-duration cancel (<1s), max-duration auto-stop (120s), cancel deletes temp file,
    send happy path emits `Sending`→success, send failure → `Failed(retryable)`.
  - `VoiceMessageViewModel` with a fake `VoicePlayerController`: play/pause toggling, seek
    mapping fraction→positionMs, expired-URL refresh path.
- **Repository (MockWebServer).** Presign + create request/response shapes (verified field
  names per §5), `X-CSRF-Token` header present, FastAPI `detail` error variants mapped, 422
  `HTTPValidationError` handled, create not retried on 5xx, 401→`/ui/session/refresh`→retry
  once.
- **Instrumented/Compose.** `RecordingOverlay` shows timer + waveform; slide-to-cancel
  threshold; `VoiceMessageBubble` play/pause and scrub update position; permission-denied
  state disables controls; one-player-at-a-time (starting B pauses A).
- **End-to-end round-trip (acceptance).** Against MockWebServer-backed presign/PUT/create
  (and a smoke run vs the dev host): record a synthesized clip → send → create → read back
  `voice_message` → play, asserting `duration_seconds` and `waveform_data` length match.
- ExoPlayer/`MediaRecorder` are wrapped behind interfaces so all logic is testable without
  device hardware; a thin instrumented smoke test exercises the real `MediaRecorder`.

## 12. Dependencies & Sequencing

- **Depends on AND-129** (Attachment pipeline: presign→PUT→confirm). AND-133 consumes
  `UploaderRepository` for upload progress/cancel/retry; only the `voice-message`-specific
  presign/confirm metadata is added here. AND-129 transitively depends on AND-117.
- Reuses existing `core-network` cookie/CSRF OkHttp client and the Media3/ExoPlayer
  dependency already present for HLS.
- No new third-party libraries (uses platform `MediaRecorder` + existing ExoPlayer/OkHttp).
- Sequencing: land AND-129 first; AND-133 can develop the recorder/waveform/player UI in
  parallel behind a fake uploader, integrating once AND-129's `UploaderRepository` is
  merged. Host message-list integration of `VoiceMessageBubble` is the chat feature's
  concern and not blocked by this ticket's internals.

## 13. Risks & Open Questions

- **Endpoint shape (RESOLVED).** Verified: the backend exposes **dedicated** routes
  `POST /messaging/conversations/{conversation_id}/voice-message/presign` and
  `POST /messaging/conversations/{conversation_id}/voice-message` (create). There is **no**
  generic-attachment fallback and **no** `kind:"voice-message"` flag; the create call writes
  a message with `kind: "voice_message"` server-side. Fields are `duration_seconds` (not
  `_ms`) and `waveform_data: number[]` (not base64). See §5/§16.
- **Waveform persistence (RESOLVED).** Verified: the backend stores and echoes
  `waveform_data` on `MessageOut.voice_message`, so the receiver renders the server-provided
  array; no client re-derivation is needed.
- **Object-store CORS/Content-Type.** PUT must send `Content-Type: audio/mp4` matching
  presign headers or the store may reject — coordinate with AND-129 fixtures.
- **Codec compatibility.** AAC-LC/M4A decodes on minSdk 24 + ExoPlayer; verify on a
  low-end emulator. Risk: some OEM `MediaRecorder` AAC quirks → keep format configurable.
- **Dev host unreliability.** ~20s timeouts + flaky uploads; rely on AND-129 retry/cancel
  and keep the local temp file until confirm succeeds.

## 14. Acceptance Criteria

- AC-1 (source): **Record → send → play round-trip works** — a clip recorded on device is
  uploaded (presign→PUT→create), and can be read back and played with correct duration.
- AC-2: Recording shows a live waveform and an mm:ss timer; auto-stops at 120 s; clips
  under 1 s are canceled with a hint and no file kept.
- AC-3: Slide-to-cancel and trash (locked) discard the recording and delete the temp file.
- AC-4: Preview allows play, re-record, cancel, and send.
- AC-5: Send shows upload progress and supports cancel/retry (via AND-129); the create call
  sends `duration_seconds` + `waveform_data` (a `number[]` of 10..200 floats in 0..1).
- AC-6: Playback bubble supports play/pause, shows elapsed/total, fills the static
  waveform with progress, and supports tap/drag seek; only one clip plays at a time.
- AC-7: `RECORD_AUDIO` denial shows rationale + settings link and disables controls without
  crashing.
- AC-8: Round-trip and waveform/codec logic verified by unit + MockWebServer tests; an
  expired `audio_url` triggers one transparent message re-fetch + replay.

## 15. Definition of Done

- `feature-voice` module merged into `android-port` under `com.testlogon.android.feature.voice`,
  building on Gradle 8.9 / AGP 8.7.3 / JDK 17, minSdk 24 / target 35.
- Recorder, waveform, composer, and player implemented per §4 with `MediaRecorder`/ExoPlayer
  hidden behind interfaces; Hilt (KSP) wiring complete; ViewModels expose `StateFlow`.
- Presign/create `VoiceApi` returns `ApiResult<T>`, uses the shared cookie/CSRF client, and
  matches the verified OpenAPI schemas (`PresignVoiceMessageRequest`,
  `CreateVoiceMessageRequest`, `MessageOut`).
- All §11 tests pass in CI (unit + MockWebServer + Compose); the e2e round-trip test is
  green and a manual smoke test against the dev host succeeds.
- Strings externalized; TalkBack pass on composer + player; no `audio_url`/audio in logs or
  telemetry; temp files excluded from backup and swept.
- Lint/detekt clean; ticket open questions (§13) resolved or filed as follow-ups; PR
  reviewed and merged.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Voice presign endpoint is `POST /messaging/conversations/{conversation_id}/voice-message/presign`.**
   VERDICT: Corrected (original draft said `POST /voice-message/presign`).
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/voice-message/presign`
   (op=`presign_voice_message...`, req=`PresignVoiceMessageRequest`);
   `src/api/endpoints/messaging.ts: presignVoiceMessage`.
2. **The third step is a "create" call `POST /messaging/conversations/{conversation_id}/voice-message`, not a "confirm" call.**
   VERDICT: Corrected (original draft said `POST /voice-message/confirm`).
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/voice-message`
   (op=`create_voice_message...`, req=`CreateVoiceMessageRequest`, resp=`200:MessageOut`);
   `src/api/endpoints/messaging.ts: createVoiceMessage`.
3. **`conversation_id` is a path parameter (not a request-body field).**
   VERDICT: Corrected (draft put `conversation_id` in the confirm body).
   SOURCE: OpenAPI path templates above; `src/api/endpoints/messaging.ts` URL interpolation.
4. **Presign request fields: `content_type`, `size_bytes`, `duration_seconds`** (content_type
   must match `^audio/(webm|mp4|ogg|wav)`; size 1..52428800; duration 0.5..300).
   VERDICT: Corrected (draft used `duration_ms`).
   SOURCE: OpenAPI `components.schemas.PresignVoiceMessageRequest`;
   `src/api/endpoints/messaging.ts: PresignVoiceReq`.
5. **Presign response is `{ message_id, upload_url, s3_key }`; `message_id` is allocated at
   presign (pattern `^m_[a-f0-9]{32}$`).**
   VERDICT: Corrected (draft used `upload_id`/`url`/`method`/`headers`/`expires_in`).
   SOURCE: `src/api/endpoints/messaging.ts: presignVoiceMessage` return type; OpenAPI presign
   response is untyped (`schema: {}`) so the web client is authoritative; sibling
   `PresignOut` (image) corroborates the `upload_url`/`key` naming.
6. **Create request fields: `message_id`, `s3_key`, `content_type`, `size_bytes`,
   `duration_seconds`, `waveform_data` (+ optional `consumption_policy`, `reply_to_message_id`,
   `send_at`).**
   VERDICT: Corrected (draft used `upload_id`, `conversation_id`, `duration_ms`, base64 `waveform`).
   SOURCE: OpenAPI `components.schemas.CreateVoiceMessageRequest`;
   `src/api/endpoints/messaging.ts: CreateVoiceReq`.
7. **`waveform_data` is a JSON `number[]` (10..200 items; web emits floats 0.0..1.0), not a
   base64 string and not a fixed 64-byte field.**
   VERDICT: Corrected.
   SOURCE: OpenAPI `CreateVoiceMessageRequest.waveform_data` (`type: array, items: number,
   minItems 10, maxItems 200`); `src/pages/messages/VoiceRecorder.tsx` (RMS normalized to
   0..1, downsample target `min(100, max(30, len))`).
8. **Create response is a full `MessageOut`; voice fields are under `voice_message`
   (`audio_url`, `audio_content_type`, `audio_size_bytes`, `duration_seconds`,
   `waveform_data`).**
   VERDICT: Corrected (draft returned a flat `VoiceMessage` with `media_url`).
   SOURCE: OpenAPI `components.schemas.MessageOut` (required: conversation_id, message_id,
   sender_id, created_at, kind; `voice_message` object); `src/api/types.ts: Message.voice_message`.
9. **Message identity is `message_id` and `created_at` is an integer epoch (seconds), not
   `id`/ISO-8601.**
   VERDICT: Corrected.
   SOURCE: OpenAPI `MessageOut` (`message_id`; `created_at: {type: integer}`).
10. **Message `kind` enum value is `voice_message` (underscore), not `voice-message`.**
    VERDICT: Corrected.
    SOURCE: OpenAPI `MessageOut.kind` enum; `src/api/types.ts` Message.kind union.
11. **There is no generic-attachment fallback and no `kind: "voice-message"` flag.**
    VERDICT: Corrected (resolves §13 open question).
    SOURCE: dedicated routes in OpenAPI index; no such param in `CreateVoiceMessageRequest`.
12. **The server stores and echoes `waveform_data` on read (no client re-derivation needed).**
    VERDICT: Verified (resolves §13 open question).
    SOURCE: `src/api/types.ts: Message.voice_message.waveform_data`; OpenAPI `MessageOut`.
13. **Auth: cookie session with `ui_csrf` echoed as `X-CSRF-Token`; credentials included.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`,
    `credentials: "include"`).
14. **On 401 the client refreshes once via `POST /ui/session/refresh` then retries.**
    VERDICT: Verified.
    SOURCE: `src/api/client.ts: refreshSession` (`fetch("/ui/session/refresh", {method:"POST"})`)
    and the single-retry 401 path.
15. **PUT-to-storage uses `Content-Type: <content_type>` to the presigned `upload_url`.**
    VERDICT: Verified.
    SOURCE: `src/api/endpoints/messaging.ts: sendVoiceMessage` (PUT with
    `headers: { "Content-Type": meta.contentType }`).
16. **Server max clip length is 300 s; the app's 120 s cap is a stricter client choice.**
    VERDICT: Verified (300 s server) / Unverified-assumption (120 s is a product decision).
    SOURCE: OpenAPI `PresignVoiceMessageRequest.duration_seconds.maximum = 300`.
17. **Audio format AAC-LC in MP4/M4A as `audio/mp4`.**
    VERDICT: Verified-compatible (server accepts `^audio/(webm|mp4|ogg|wav)`; web defaults to
    `audio/webm`). The specific AAC-LC/mono/44.1 kHz/64 kbps profile is an Android client
    choice, not specified by the backend.
    SOURCE: OpenAPI `PresignVoiceMessageRequest.content_type` pattern; framework ref:
    https://developer.android.com/reference/android/media/MediaRecorder.AudioEncoder#AAC
18. **Recording captured via platform `MediaRecorder`; playback via Media3/ExoPlayer.**
    VERDICT: Unverified-assumption (Android client architecture; not in the sources).
    SOURCE: framework ref https://developer.android.com/reference/android/media/MediaRecorder
    and https://developer.android.com/media/media3/exoplayer.
19. **`RECORD_AUDIO` runtime permission with rationale + settings deep-link.**
    VERDICT: Unverified-assumption (Android platform requirement; not in backend/web sources).
    SOURCE: framework ref https://developer.android.com/training/permissions/requesting.

### Corrections made

- Endpoint paths rewritten to the dedicated, conversation-scoped routes (§2, §5, §13, AC-1).
- "Confirm" step renamed to "create" (`POST .../voice-message`) throughout (§1 prose retained
  where it refers to AND-129's own pipeline) (§5, §6, §7, §11, §13).
- `conversation_id` moved from request body to path param (§5).
- `duration_ms` → `duration_seconds` (float) everywhere on the wire (§2, §5, §6, AC-5).
- Presign response corrected to `{ message_id, upload_url, s3_key }` (§5).
- Create request/response fields corrected; response is `MessageOut` with nested
  `voice_message` (§5, §6).
- `media_url` → `voice_message.audio_url`; `id` → `message_id`; `created_at` ISO → epoch int
  (§4, §5, §6, §7, §8, AC-8, DoD).
- Waveform wire form corrected from base64/64×(0..100) to `number[]` floats 0..1, 10..200
  items; removed `Waveform.encode/decode` from the API surface (§4, §6, FR-6, §11, AC-5).
- `kind` corrected to `voice_message` (underscore) (§2).
- §13 "endpoint shape" and "waveform persistence" open questions marked RESOLVED.

### Open assumptions

- **120 s client cap** — a product decision below the 300 s server limit; not verifiable from
  sources (only the 300 s server max is verified).
- **AAC-LC mono 44.1 kHz / 64 kbps profile** — server only constrains the MIME container; the
  exact codec profile is a client choice and must be smoke-tested for OEM `MediaRecorder`
  quirks and ExoPlayer decode (§13).
- **URL refresh on expiry** — there is no `GET /voice-message/{id}`; refreshing
  `audio_url` requires re-reading the parent message via the host conversation/message API.
  The exact read endpoint is owned by the chat feature and not pinned in this ticket.
- **Android recorder/player stack** (`MediaRecorder`, ExoPlayer) and **`RECORD_AUDIO`
  permission flow** — Android-platform choices, not derivable from the backend/web sources;
  cited to Android framework docs only.
- **Telemetry field names** (e.g. `duration_ms`) are the app's internal analytics schema and
  intentionally not aligned to the wire `duration_seconds`.

## 17. Test Plan

Test-target legend: JVM = JVM/Robolectric unit (no device); MWS = MockWebServer contract;
EMU = headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). Cases needing real microphone/recording hardware or ABI/API
differences MUST run on DEV; UI/Compose cases may run on EMU.

- **TC-AND-133-01** — Type: unit (JVM). Target: `Waveform.normalize`.
  Preconditions: pure function, no device. Steps: feed (a) empty list, (b) single sample,
  (c) shorter-than-buckets input, (d) constant amplitude, (e) long noisy input; request
  bucket counts at the 10/64/200 boundaries. Expected: output length == requested buckets
  (clamped to [10,200]); all values in 0.0..1.0; constant input yields equal buckets; no
  exceptions on empty/short input. Traces: AC-2, AC-5, AC-8.

- **TC-AND-133-02** — Type: contract (MWS). Target: `VoiceApi.presign`.
  Preconditions: MockWebServer enqueues `200 {message_id, upload_url, s3_key}`. Steps: call
  presign with `content_type="audio/mp4"`, `size_bytes`, `duration_seconds`. Expected:
  request path `…/{conversationId}/voice-message/presign`; body has exactly `content_type`,
  `size_bytes`, `duration_seconds` (no `duration_ms`); `X-CSRF-Token` header present; parsed
  result exposes `message_id`/`upload_url`/`s3_key`. Traces: AC-1, AC-5.

- **TC-AND-133-03** — Type: contract (MWS). Target: `VoiceApi.create`.
  Preconditions: MWS enqueues `200 MessageOut` with nested `voice_message`. Steps: call create
  with `message_id`, `s3_key`, `content_type`, `size_bytes`, `duration_seconds`,
  `waveform_data` (List<Float>). Expected: request body field names match
  `CreateVoiceMessageRequest`; `waveform_data` serialized as JSON number array (not base64);
  response maps to domain `VoiceMessage` reading `voice_message.audio_url`, `duration_seconds`,
  `waveform_data`, top-level `message_id`, epoch `created_at`. Traces: AC-1, AC-5.

- **TC-AND-133-04** — Type: contract (MWS). Target: presign/create validation errors.
  Preconditions: MWS enqueues `422 HTTPValidationError` (e.g. bad `content_type` not matching
  `^audio/(webm|mp4|ogg|wav)`, or `size_bytes` > 50 MB). Steps: call presign. Expected:
  `ApiResult.Error` with FastAPI `detail` mapped (string | `[{msg}]` | `{code}`); UI reaches
  `Failed(retryable)`; no crash. Traces: AC-5, AC-8.

- **TC-AND-133-05** — Type: contract (MWS). Target: 401 refresh + non-idempotent create.
  Preconditions: MWS enqueues `401`, then `200` for `POST /ui/session/refresh`, then `200`
  create. Steps: call create. Expected: exactly one refresh then one create retry; total two
  create attempts max; no auto-retry on a 5xx create. Traces: AC-1, AC-8.

- **TC-AND-133-06** — Type: unit (JVM). Target: `VoiceComposerViewModel` with fake recorder +
  fake uploader. Preconditions: fakes injected. Steps: simulate (a) release < 1 s, (b) reach
  120 s, (c) cancel, (d) happy send, (e) send failure. Expected: (a) min-duration cancel, no
  file kept, "hold to record" hint; (b) auto-stop at 120 s keeping audio → `Preview`;
  (c) temp file deleted; (d) `Sending`→success; (e) `Failed(retryable=true)`. Traces: AC-2,
  AC-3, AC-4, AC-5.

- **TC-AND-133-07** — Type: unit (JVM). Target: `VoiceMessageViewModel` with fake player.
  Preconditions: fake `VoicePlayerController`. Steps: toggle play/pause; seek fraction 0.5;
  simulate 403/expired `audio_url`. Expected: play/pause state flips; `onSeekTo` maps fraction
  → positionMs correctly; expired URL triggers exactly one transparent message re-fetch then a
  single replay. Traces: AC-6, AC-8.

- **TC-AND-133-08** — Type: Compose-UI (EMU). Target: `RecordingOverlay` + `VoiceMessageBubble`.
  Preconditions: fake state flows. Steps: drive Recording state (timer + live waveform);
  perform slide-to-cancel past threshold; drive a player bubble play/pause and drag-scrub.
  Expected: mm:ss timer and waveform render; slide past threshold cancels; bubble play/pause
  toggles and scrub updates position; starting clip B pauses clip A (one-at-a-time). Traces:
  AC-2, AC-3, AC-6.

- **TC-AND-133-09** — Type: Compose-UI / accessibility (EMU). Target: composer + player semantics.
  Preconditions: TalkBack assertions via semantics tree. Steps: inspect record control
  (contentDescription + tap-only fallback), scrubber (`progressSemantics`/seekable), waveform
  bars (decorative, null description), live-region announcements (start/lock/auto-stop/cancel);
  verify touch targets ≥ 48 dp and large-font scaling. Expected: all semantics present;
  player label conveys duration + state. Traces: AC-2, AC-6, AC-7.

- **TC-AND-133-10** — Type: instrumented (DEV — physical device required). Target: real
  `MediaRecorder` capture + amplitude sampling. Preconditions: `RECORD_AUDIO` granted on
  SM-A156U. Steps: record ~3 s into `cacheDir/voice/<uuid>.m4a`; collect `getMaxAmplitude()`
  ticks; stop. Expected: non-empty m4a produced (`audio/mp4`/AAC-LC), `durationSeconds` within
  tolerance, amplitudes captured; ExoPlayer decodes the file locally. MUST run on DEV (real
  mic hardware + arm64-v8a / API-34 decode). Traces: AC-1, AC-2, AC-8.

- **TC-AND-133-11** — Type: instrumented permission (DEV/EMU). Target: `RECORD_AUDIO` denial.
  Preconditions: permission denied (or "deny & don't ask again"). Steps: tap record. Expected:
  rationale shown with settings deep-link; record controls disabled; no crash; granting later
  re-enables. Run on DEV for the real permission dialog; EMU acceptable for the deny path.
  Traces: AC-7.

- **TC-AND-133-12** — Type: instrumented interruption (DEV — physical device required).
  Target: FR-10 audio-focus loss. Preconditions: active recording on SM-A156U. Steps: trigger
  an incoming call / audio-focus loss / background the app mid-recording. Expected: recording
  stops and captured audio is preserved as a `Preview` (not discarded); a second interruption
  during preview playback pauses playback. MUST run on DEV (real telephony/audio-focus).
  Traces: AC-2, AC-4.

- **TC-AND-133-13** — Type: integration / flaky-host + offline (MWS, EMU). Target: send under
  unreliable network. Preconditions: MWS configured with ~20 s delay / socket drop on PUT and
  create; then airplane mode. Steps: record → send while offline/slow. Expected: state reaches
  `Failed(retryable=true)` with "saved, tap to retry"; temp file retained until create
  succeeds; retry re-issues create with the same `message_id`/`s3_key` (no re-upload). Traces:
  AC-5, AC-8.

- **TC-AND-133-14** — Type: e2e round-trip (MWS, plus DEV smoke vs dev host). Target: full
  record→send→play. Preconditions: MWS-backed presign/PUT/create; optional smoke vs
  `http://18.222.237.167:8000`. Steps: record (synth clip in MWS run; real mic on DEV smoke) →
  presign → PUT → create → read back `voice_message` → play. Expected: `duration_seconds`
  matches and `waveform_data` length matches what was sent; playback completes. DEV smoke
  confirms arm64/API-34 codec + real cleartext-HTTP path. Traces: AC-1, AC-8.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (record→send→play round-trip) | TC-02, TC-03, TC-05, TC-10, TC-14 |
| AC-2 (live waveform, mm:ss, 120 s auto-stop, <1 s cancel) | TC-01, TC-06, TC-08, TC-09, TC-10, TC-12 |
| AC-3 (slide-to-cancel / trash deletes temp) | TC-06, TC-08 |
| AC-4 (preview: play / re-record / cancel / send) | TC-06, TC-12 |
| AC-5 (upload progress + cancel/retry; `duration_seconds` + `waveform_data`) | TC-01, TC-02, TC-03, TC-04, TC-06, TC-13 |
| AC-6 (player play/pause, elapsed/total, fill, seek, one-at-a-time) | TC-07, TC-08, TC-09 |
| AC-7 (`RECORD_AUDIO` denial: rationale + settings, controls disabled, no crash) | TC-09, TC-11 |
| AC-8 (round-trip + waveform/codec via unit + MWS; expired-URL refresh + replay) | TC-01, TC-03, TC-04, TC-05, TC-07, TC-10, TC-13, TC-14 |
