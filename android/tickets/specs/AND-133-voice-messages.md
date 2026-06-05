---
id: AND-133
title: Voice messages
milestone: M3
epic: E19
priority: P1
size: L
status: draft
depends_on: [AND-129]
blocks: []
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
- Web reference: presign/confirm endpoints in `frontend/src/api/endpoints/*.ts` and shared
  types in `frontend/src/api/types.ts`; confirm OpenAPI shapes at `/openapi.json`. The web
  app uses the same presign contract for generic attachments; voice adds `kind:
  "voice-message"` plus `duration_ms` and `waveform` metadata on confirm.
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

FR-6 **Send.** On send, the recorder downsamples the captured amplitudes into a fixed-length
normalized waveform (default 64 buckets, 0–100), then hands the file plus
`VoiceMessageMeta` to the AND-129 uploader (presign → PUT → confirm). Upload progress and
cancel/retry are surfaced by the uploader's own UI/state.

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
    /** Collapse raw samples into [buckets] normalized peaks in 0..100. */
    fun normalize(raw: List<Int>, buckets: Int = WAVEFORM_BUCKETS): List<Int>
    /** Pack/unpack the compact wire form: base64 of one byte per bucket. */
    fun encode(buckets: List<Int>): String
    fun decode(encoded: String): List<Int>
}
```

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
confirmed media URL with the cookie/CSRF OkHttp `DataSource.Factory` from `core-network`.

## 5. API Contract

AND-133 reuses the AND-129 presign/PUT/confirm transport; this section specifies the
**voice-specific request/response fields** only. The PUT-to-storage call is owned by AND-129.

**Presign** — `POST /voice-message/presign`

Request:
```json
{ "content_type": "audio/mp4", "size_bytes": 184320, "duration_ms": 7400 }
```
Response:
```json
{
  "upload_id": "att_01J...",
  "url": "https://<bucket>/...",
  "method": "PUT",
  "headers": { "Content-Type": "audio/mp4" },
  "expires_in": 900
}
```

**Confirm** — `POST /voice-message/confirm`

Request:
```json
{
  "upload_id": "att_01J...",
  "conversation_id": "conv_123",
  "duration_ms": 7400,
  "waveform": "BQ8WHx4..."   // base64, one byte (0..100) per bucket, 64 bytes
}
```
Response (`VoiceMessage`):
```json
{
  "id": "vm_456",
  "conversation_id": "conv_123",
  "media_url": "https://<bucket>/...signed",
  "content_type": "audio/mp4",
  "duration_ms": 7400,
  "size_bytes": 184320,
  "waveform": "BQ8WHx4...",
  "created_at": "2026-06-05T12:00:00Z"
}
```

Retrofit:
```kotlin
interface VoiceApi {
    @POST("voice-message/presign")
    suspend fun presign(@Body body: PresignVoiceRequest): ApiResult<PresignResponse>

    @POST("voice-message/confirm")
    suspend fun confirm(@Body body: ConfirmVoiceRequest): ApiResult<VoiceMessageDto>
}
```

All calls carry the session cookies + `X-CSRF-Token` via the shared OkHttp interceptor.
Presign/confirm are **non-idempotent POSTs**: no automatic retry (only one 401→refresh→
retry as per the shared client). Field names must be reconciled against `/openapi.json`
during implementation; if the dev backend lacks a dedicated `/voice-message/*` route, fall
back to the generic AND-129 attachment endpoints with `kind: "voice-message"` and carry
`duration_ms`/`waveform` in the confirm body — this is an open question (§13).

## 6. Data & State Management

- **Repository.** `VoiceMessageRepository` exposes `suspend fun send(file, meta,
  conversationId): ApiResult<VoiceMessage>` (presign via AND-129 uploader, then confirm)
  and `suspend fun get(id): ApiResult<VoiceMessage>`.
- **Domain model** in `core-model`:
  ```kotlin
  data class VoiceMessage(
      val id: String, val conversationId: String, val mediaUrl: String,
      val durationMs: Long, val sizeBytes: Long, val waveform: List<Int>,
      val createdAt: Instant,
  )
  data class VoiceMessageMeta(val durationMs: Long, val waveform: List<Int>, val contentType: String = "audio/mp4")
  ```
- **Room cache (`core-data`).** `voice_message` table keyed by `id` (cols:
  conversationId, mediaUrl, durationMs, sizeBytes, waveform TEXT base64, createdAt) so
  bubbles render offline with their waveform; the signed `mediaUrl` is treated as
  short-lived and re-fetched via `get(id)` on a 403/expired-URL playback failure.
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
- **Upload errors.** Delegated to AND-129 (progress/cancel/retry). Presign/confirm
  transport errors map via `ApiResult.Error` + FastAPI `detail`; confirm is **not**
  auto-retried (non-idempotent) — the user retries explicitly, and the uploader dedupes by
  `upload_id` so a retry confirms the already-uploaded object rather than re-uploading.
- **Network.** ~20s OkHttp timeouts; offline → `Failed(retryable=true)` with a "saved,
  tap to retry" affordance keyed to the cached temp file until confirmed.
- **Playback.** Stream/decode error → `VoicePlayerUiState.error`; on a 403/expired URL,
  one transparent `get(id)` refresh of `mediaUrl` then a single replay attempt (idempotent
  GET, eligible for bounded backoff).

## 8. Security & Privacy

- Microphone is captured only during an explicit, visible recording session; a persistent
  recording indicator is shown, and recording stops on background (FR-10).
- `RECORD_AUDIO` is the only new runtime permission. No `READ/WRITE_EXTERNAL_STORAGE`:
  files stay in app-internal `cacheDir`.
- Temp audio never leaves the device except via the authenticated AND-129 upload; temp
  files are deleted promptly (§6) and excluded from Auto Backup
  (`android:fullBackupContent` rule excluding `voice/`).
- All API/media traffic uses the shared cookie + `X-CSRF-Token` client; `mediaUrl` signed
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
- No PII and no audio content/waveform/`mediaUrl` in telemetry — durations and sizes only.
- Logging via the shared logger; `MediaRecorder`/ExoPlayer errors logged at WARN with
  error class only (DEBUG builds include stack). Upload transport logging is AND-129's.

## 11. Testing Strategy

- **Unit (JVM, `core-testing`).**
  - `Waveform.normalize` — bucket count, normalization to 0..100, empty/short input,
    constant-amplitude, single-sample edge cases.
  - `Waveform.encode/decode` round-trip (64 bytes ↔ base64).
  - `VoiceComposerViewModel` with a fake `VoiceRecorder` + fake `UploaderRepository`:
    min-duration cancel (<1s), max-duration auto-stop (120s), cancel deletes temp file,
    send happy path emits `Sending`→success, send failure → `Failed(retryable)`.
  - `VoiceMessageViewModel` with a fake `VoicePlayerController`: play/pause toggling, seek
    mapping fraction→positionMs, expired-URL refresh path.
- **Repository (MockWebServer).** Presign + confirm request/response shapes, `X-CSRF-Token`
  header present, FastAPI `detail` error variants mapped, confirm not retried on 5xx, 401→
  refresh→retry once.
- **Instrumented/Compose.** `RecordingOverlay` shows timer + waveform; slide-to-cancel
  threshold; `VoiceMessageBubble` play/pause and scrub update position; permission-denied
  state disables controls; one-player-at-a-time (starting B pauses A).
- **End-to-end round-trip (acceptance).** Against MockWebServer-backed presign/PUT/confirm
  (and a smoke run vs the dev host): record a synthesized clip → send → confirm → fetch via
  `get(id)` → play, asserting `duration_ms` and decoded waveform length (64) match.
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

- **Endpoint shape (open).** Does the dev backend expose dedicated `/voice-message/presign`
  + `/voice-message/confirm`, or only the generic AND-129 attachment routes? Confirm
  against `/openapi.json`; if generic, carry `kind:"voice-message"`, `duration_ms`, and
  `waveform` on the generic confirm (§5).
- **Waveform persistence (open).** Is `waveform` stored/returned by the backend, or must it
  be derived client-side on playback? Spec assumes server echoes it; if not, decode it on
  the sender and accept "no waveform until re-derived" on the receiver.
- **Object-store CORS/Content-Type.** PUT must send `Content-Type: audio/mp4` matching
  presign headers or the store may reject — coordinate with AND-129 fixtures.
- **Codec compatibility.** AAC-LC/M4A decodes on minSdk 24 + ExoPlayer; verify on a
  low-end emulator. Risk: some OEM `MediaRecorder` AAC quirks → keep format configurable.
- **Dev host unreliability.** ~20s timeouts + flaky uploads; rely on AND-129 retry/cancel
  and keep the local temp file until confirm succeeds.

## 14. Acceptance Criteria

- AC-1 (source): **Record → send → play round-trip works** — a clip recorded on device is
  uploaded (presign→PUT→confirm), and can be fetched and played back with correct duration.
- AC-2: Recording shows a live waveform and an mm:ss timer; auto-stops at 120 s; clips
  under 1 s are canceled with a hint and no file kept.
- AC-3: Slide-to-cancel and trash (locked) discard the recording and delete the temp file.
- AC-4: Preview allows play, re-record, cancel, and send.
- AC-5: Send shows upload progress and supports cancel/retry (via AND-129); confirm sends
  `duration_ms` + 64-bucket base64 `waveform`.
- AC-6: Playback bubble supports play/pause, shows elapsed/total, fills the static
  waveform with progress, and supports tap/drag seek; only one clip plays at a time.
- AC-7: `RECORD_AUDIO` denial shows rationale + settings link and disables controls without
  crashing.
- AC-8: Round-trip and waveform/codec logic verified by unit + MockWebServer tests; an
  expired `mediaUrl` triggers one transparent refresh + replay.

## 15. Definition of Done

- `feature-voice` module merged into `android-port` under `com.testlogon.android.feature.voice`,
  building on Gradle 8.9 / AGP 8.7.3 / JDK 17, minSdk 24 / target 35.
- Recorder, waveform, composer, and player implemented per §4 with `MediaRecorder`/ExoPlayer
  hidden behind interfaces; Hilt (KSP) wiring complete; ViewModels expose `StateFlow`.
- Presign/confirm `VoiceApi` returns `ApiResult<T>`, uses the shared cookie/CSRF client, and
  is reconciled with `/openapi.json`.
- All §11 tests pass in CI (unit + MockWebServer + Compose); the e2e round-trip test is
  green and a manual smoke test against the dev host succeeds.
- Strings externalized; TalkBack pass on composer + player; no `mediaUrl`/audio in logs or
  telemetry; temp files excluded from backup and swept.
- Lint/detekt clean; ticket open questions (§13) resolved or filed as follow-ups; PR
  reviewed and merged.
