---
id: AND-308
title: WebRTC ingest
milestone: M7
epic: E41
priority: P0
size: XL
status: draft
depends_on: [AND-307, AND-290]
blocks: [AND-309]
---

# AND-308 — WebRTC ingest

## 1. Overview & Goal

This ticket implements the host-side **WebRTC ingest** path for live broadcasts in the
TestLogon native Android app. The host captures device camera and microphone, builds a
local `MediaStream`, negotiates a single publish PeerConnection with the backend SFU/MCU
ingest endpoint via the `inputs` + `webrtc-offer` API surface, and streams audio/video so
the broadcast is ingested and viewable by remote viewers.

The deliverable is a `feature-host-ingest` module that, given a session created by
AND-307 and signaling transport provided by AND-290, performs the full SDP offer/answer
and ICE exchange, pumps `CameraVideoCapturer` and audio frames into the connection, and
surfaces ingest state (`Idle → Negotiating → Connected → Failed`) as a
`StateFlow<IngestUiState>` to the host UI.

**Done means:** A host on a physical device can start ingest, the local preview renders,
the offer is published through `webrtc-offer`, the remote answer + ICE complete the
PeerConnection (ICE `CONNECTED`/`COMPLETED`), and the produced stream is viewable by a
second client. Lifecycle controls (start/stop/resume) are explicitly out of scope and
owned by **AND-309**, which consumes the engine this ticket exposes.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`. This feature module is
  `com.testlogon.android.feature.hostingest`.
- **Dependencies:**
  - **AND-307 — Host session create/schedule** provides the `sessionId`/`broadcastId`
    and session lifecycle metadata that ingest binds to.
  - **AND-290 — Signaling transport** provides the backend signaling channel (`/signal`,
    SSE/poll for remote SDP/ICE). This ticket consumes that transport; it MUST NOT
    re-implement signaling.
- **Blocks:** **AND-309 — Host controls** (start/stop/resume/reschedule, health report)
  drives the engine defined here.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`,
  shared types `frontend/src/api/types.ts` (inspect the host/broadcast `inputs` and
  `webrtc-offer` calls there to mirror request/response shapes).
- **WebRTC stack:** `io.github.webrtc-sdk:android:125.6422.07` (Google libwebrtc fork,
  the maintained Maven artifact). Media3/ExoPlayer (HLS) is for the *viewer* playback path
  and is not used for ingest.

## 3. Functional Requirements

FR-1. Provide an `IngestEngine` abstraction that owns a single publish
`PeerConnection`, the local `MediaStream` (one audio + one video track), and the
`EglBase` rendering context for the lifetime of an ingest session.

FR-2. Acquire camera + microphone via `Camera2Enumerator`/`CameraVideoCapturer`,
defaulting to the front camera, 1280×720 @ 30fps target (negotiable down on capture
failure to 640×480 @ 24fps).

FR-3. Render a local preview into a Compose-hosted `SurfaceViewRenderer` before and
during ingest.

FR-4. Create an SDP offer (`createOffer`), set it as local description, then publish it
to the backend via the `inputs`/`webrtc-offer` POST and apply the returned remote answer
(`setRemoteDescription`).

FR-5. Trickle local ICE candidates to the backend through AND-290 signaling, and apply
remote ICE candidates received from the signaling channel.

FR-6. Expose ingest state as `StateFlow<IngestUiState>` with at minimum:
`Idle`, `RequestingPermissions`, `Negotiating`, `Connected(ingestId)`,
`Reconnecting`, `Failed(reason)`, `Stopped`.

FR-7. Request `CAMERA` and `RECORD_AUDIO` runtime permissions; if denied, surface a
recoverable `Failed(PermissionDenied)` state with a rationale path. No ingest is
attempted without both grants.

FR-8. Provide `start(sessionId)`, `stop()`, and `mute(audio: Boolean)/enableVideo(Boolean)`
control points. (Full lifecycle/health UI is AND-309; this ticket exposes the callable
engine + a minimal host preview screen to validate ingest.)

FR-9. Release all native resources (capturer, tracks, peer connection, factory,
`EglBase`, renderers) deterministically on `stop()` and on `ViewModel.onCleared()`.

## 4. Technical Design

**Module layout** (`feature-host-ingest` → `core-network`, `core-model`, `core-ui`,
`core-data`):

```
feature/host-ingest/
  ingest/IngestEngine.kt
  ingest/WebRtcIngestEngine.kt
  ingest/PeerConnectionFactoryProvider.kt
  ingest/SignalingBridge.kt          // adapts AND-290 transport to ICE/SDP callbacks
  ui/HostIngestViewModel.kt
  ui/HostIngestScreen.kt
  ui/LocalPreview.kt                 // AndroidView wrapping SurfaceViewRenderer
  di/HostIngestModule.kt
```

**Core interfaces:**

```kotlin
interface IngestEngine {
    val state: StateFlow<IngestUiState>
    val localRenderer: VideoSink           // attach to SurfaceViewRenderer
    suspend fun start(sessionId: String): ApiResult<IngestSession>
    fun setAudioMuted(muted: Boolean)
    fun setVideoEnabled(enabled: Boolean)
    fun stop()
}

@Singleton
class WebRtcIngestEngine @Inject constructor(
    private val factoryProvider: PeerConnectionFactoryProvider,
    private val signaling: SignalingTransport,      // from AND-290
    private val ingestApi: IngestApi,               // Retrofit, this ticket
    private val eglBase: EglBase,
    @ApplicationContext private val context: Context,
    @IoDispatcher private val io: CoroutineDispatcher,
) : IngestEngine { ... }
```

**PeerConnectionFactory init** (one-time, app scope): `PeerConnectionFactory
.initialize(...)`, then build with
`DefaultVideoEncoderFactory(eglBase.eglBaseContext, enableIntelVp8 = true,
enableH264HighProfile = true)` and `DefaultVideoDecoderFactory`. Provide a single
`@Provides @Singleton EglBase` in `HostIngestModule`.

**Capture pipeline:** `Camera2Enumerator(context)` → `createCapturer(frontDeviceName)`
→ `SurfaceTextureHelper.create("CaptureThread", eglBase.eglBaseContext)` →
`VideoSource` → `videoCapturer.initialize(helper, context, videoSource.capturerObserver)`
→ `startCapture(1280, 720, 30)`. Audio: `factory.createAudioSource(MediaConstraints())`
→ `createAudioTrack`.

**Negotiation flow (host = offerer):**
1. `addTrack(audioTrack)` and `addTrack(videoTrack)` on the connection (Unified Plan;
   `sdpSemantics = UNIFIED_PLAN`).
2. `createOffer` → `setLocalDescription(offer)`.
3. `POST {inputs/webrtc-offer}` with the SDP (see §5) → receive answer.
4. `setRemoteDescription(answer)`.
5. `onIceCandidate` → publish each candidate via signaling; remote candidates from
   signaling → `addIceCandidate`.
6. Connection reaches `PeerConnectionState.CONNECTED` → emit `Connected(ingestId)`.

**ICE servers:** fetched from the offer/inputs response (`ice_servers`); fall back to a
configured STUN server. The publish connection uses `IceTransportsType.ALL`.

**Threading:** all libwebrtc native calls are marshalled onto a single
`PeerConnection.Observer` callback path; engine public API uses `io` dispatcher.
StateFlow updates are posted with `MutableStateFlow.value =` (thread-safe).

## 5. API Contract

Two HTTP calls plus the AND-290 signaling channel. Endpoints are confirmed against
`/openapi.json` and `frontend/src/api/endpoints/*.ts` at implementation time; shapes below
are the expected contract.

**Register input + publish offer** (`IngestApi`):

```kotlin
interface IngestApi {
    @POST("/ui/broadcasts/{id}/inputs")
    suspend fun createInput(
        @Path("id") broadcastId: String,
        @Body body: CreateInputRequest,
    ): Response<CreateInputResponse>

    @POST("/ui/broadcasts/{id}/inputs/{inputId}/webrtc-offer")
    suspend fun publishOffer(
        @Path("id") broadcastId: String,
        @Path("inputId") inputId: String,
        @Body body: WebRtcOfferRequest,
    ): Response<WebRtcOfferResponse>
}
```

Request/response JSON:

```json
// POST /ui/broadcasts/{id}/inputs
{ "kind": "webrtc", "audio": true, "video": true }
// -> 201
{ "input_id": "in_abc123", "ingest_id": "ing_xyz",
  "ice_servers": [ { "urls": ["stun:stun.l.google.com:19302"] } ] }

// POST /ui/broadcasts/{id}/inputs/{inputId}/webrtc-offer
{ "sdp": "v=0\r\no=- ...", "type": "offer" }
// -> 200
{ "sdp": "v=0\r\no=- ...", "type": "answer",
  "ice_servers": [ ... ] }
```

**ICE/SDP signaling** uses AND-290's transport. The bridge maps to it:

```kotlin
class SignalingBridge(private val transport: SignalingTransport) {
    fun candidates(ingestId: String): Flow<IceCandidatePayload>   // SSE/poll /signal
    suspend fun sendCandidate(ingestId: String, c: IceCandidatePayload): ApiResult<Unit>
}
// POST /signal { "ingest_id":"ing_xyz", "type":"candidate",
//   "candidate":"candidate:...", "sdpMid":"0", "sdpMLineIndex":0 }
```

All authenticated calls ride the cookie session + `X-CSRF-Token` (from `ui_csrf`) per the
shared OkHttp client; on 401 the client refreshes once via `POST /ui/session/refresh` then
retries (existing `core-network` interceptor — not re-implemented here).

Moshi models: `CreateInputRequest`, `CreateInputResponse`, `WebRtcOfferRequest`,
`WebRtcOfferResponse`, `IceServerDto(urls, username?, credential?)`,
`IceCandidatePayload(candidate, sdpMid, sdpMLineIndex)` live in `core-model`.

## 6. Data & State Management

`HostIngestViewModel` exposes `StateFlow<IngestUiState>` and delegates to `IngestEngine`:

```kotlin
sealed interface IngestUiState {
    data object Idle : IngestUiState
    data object RequestingPermissions : IngestUiState
    data object Negotiating : IngestUiState
    data class Connected(val ingestId: String, val muted: Boolean,
                         val videoEnabled: Boolean) : IngestUiState
    data class Reconnecting(val attempt: Int) : IngestUiState
    data class Failed(val reason: IngestError) : IngestUiState
    data object Stopped : IngestUiState
}

@HiltViewModel
class HostIngestViewModel @Inject constructor(
    private val engine: IngestEngine,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<IngestUiState> = engine.state
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), IngestUiState.Idle)
    fun start() { viewModelScope.launch { engine.start(sessionId) } }
    override fun onCleared() { engine.stop() }
}
```

**Persistence:** ingest is ephemeral; no Room caching of media. The active
`broadcastId`/`sessionId` come from AND-307 via nav args / `SavedStateHandle`. The
last-selected camera facing and default mute state are persisted in **DataStore**
(`prefs_host_ingest`: `camera_facing: Int`, `start_muted: Boolean`). No PII is stored.

**Configuration changes:** the `IngestEngine` is `@Singleton` (process-scoped), so a
rotation does not tear down the PeerConnection; the renderer is re-attached in
`onResume`. Native resources are released only on explicit `stop()` / process death.

## 7. Error Handling & Resilience

- **Permission denied:** emit `Failed(PermissionDenied)`; UI offers Settings deep-link.
- **Capture failure** (`CameraVideoCapturer.startCapture` error / camera in use): retry
  once at the lower 640×480/24fps profile; on second failure emit `Failed(CaptureFailed)`.
- **Offer publish failure:** `inputs`/`webrtc-offer` are **POST (non-idempotent)** — do
  **not** auto-retry blindly. On network/timeout, emit `Failed(SignalingUnavailable)` and
  allow a user-initiated retry that first DELETEs/re-creates the input. The
  `createInput` GET-equivalent of ICE-server fetch, if exposed as a GET, may use the
  standard bounded backoff for idempotent GETs.
- **Timeouts:** all ingest HTTP calls use the project ~20s timeout (unreliable dev host).
- **ICE failure / disconnect:** on `PeerConnectionState.DISCONNECTED`, enter
  `Reconnecting(attempt)` and call `peerConnection.restartIce()` (ICE restart, new offer)
  with bounded attempts (max 3, exponential 2s/4s/8s). On `FAILED` after exhaustion →
  `Failed(IceFailed)`.
- **Backend down / stale:** surface offline state; preview still renders locally so the
  host sees the camera works even when ingest can't connect.
- **Error mapping:** FastAPI `detail` (string | `[{msg}]` | `{code,...}`) is mapped by the
  shared `core-network` `ApiResult` mapper into `IngestError`.

```kotlin
sealed interface IngestError {
    data object PermissionDenied : IngestError
    data object CaptureFailed : IngestError
    data object SignalingUnavailable : IngestError
    data object IceFailed : IngestError
    data class Backend(val message: String, val code: String?) : IngestError
}
```

## 8. Security & Privacy

- Camera/mic are sensitive; request permissions only at ingest start, show in-context
  rationale, and stop capture immediately on `stop()` so the OS camera/mic indicators
  clear. Never hold the capturer while not actively ingesting.
- Add `<uses-feature android:name="android.hardware.camera" android:required="false"/>`
  and declare `CAMERA`, `RECORD_AUDIO`, plus `FOREGROUND_SERVICE` +
  `FOREGROUND_SERVICE_CAMERA`/`FOREGROUND_SERVICE_MICROPHONE` (the foreground service that
  keeps ingest alive in background is wired in AND-309; this ticket declares the manifest
  entries it depends on).
- All API auth is cookie + `X-CSRF-Token` via the shared persistent cookie jar; no tokens
  are logged. SDP/ICE payloads can contain local IP candidates — treat as sensitive and
  never log full SDP at non-debug levels (redact to candidate counts).
- Dev backend is plaintext HTTP; `usesCleartextTraffic` is dev-only via the existing
  `network_security_config` allowlist for `18.222.237.167`. Production ingest MUST be
  HTTPS/WSS; flag in §13.

## 9. Accessibility & i18n

- Local preview `AndroidView` carries `contentDescription = stringResource(R.string.
  ingest_preview_cd)`; decorative renderer is not the sole information source — state is
  also announced via text + `liveRegion = LiveRegionMode.Polite` on the status label.
- All controls (Start, Stop, Mute, Camera toggle) are Material 3 buttons/icon-toggles
  with text labels and ≥48dp touch targets; mute/video toggles expose
  `Modifier.toggleable` state for TalkBack.
- All user-facing strings (states, errors, rationale) in `res/values/strings.xml`; no
  hardcoded text. Numbers/timers formatted with locale-aware formatters.
- Respects system font scaling; preview aspect ratio is fixed but does not clip controls.

## 10. Telemetry & Logging

- Structured events via the project analytics interface: `ingest_start_requested`,
  `ingest_negotiating`, `ingest_connected` (with `ingest_id`, `negotiation_ms`,
  `selected_resolution`, `selected_codec`), `ingest_ice_restart` (`attempt`),
  `ingest_failed` (`reason`), `ingest_stopped` (`duration_ms`).
- WebRTC `getStats()` sampled every 5s while `Connected`: outbound bitrate,
  `framesEncoded`, `packetsLost`, RTT, current resolution — emitted as
  `ingest_health_sample` for the AND-309 health report and for debugging the flaky dev
  host. (The health *UI* is AND-309; this ticket produces the underlying samples.)
- Logging via Timber; SDP redacted (log candidate type/count only). No PII, no full
  candidate strings at INFO.

## 11. Testing Strategy

- **Unit (`core-testing`, JUnit + Turbine + MockWebServer):**
  - `WebRtcIngestEngine` state machine with a faked `PeerConnectionFactoryProvider`
    and `SignalingTransport`: assert `Idle → Negotiating → Connected` on a stubbed
    answer + ICE; assert `Failed(SignalingUnavailable)` on a 503 offer; assert
    `Reconnecting → Connected` on a simulated `DISCONNECTED`/restart.
  - `IngestApi` Retrofit/Moshi (de)serialization against fixtures from
    `frontend/src/api/types.ts`; verify `X-CSRF-Token` header presence via MockWebServer.
  - `IceCandidatePayload` ↔ `IceCandidate` mapping round-trips `sdpMid`/`sdpMLineIndex`.
- **ViewModel tests:** permission-denied path emits `Failed(PermissionDenied)`;
  `onCleared()` calls `engine.stop()`.
- **Instrumented (Compose UI test):** `HostIngestScreen` renders preview placeholder,
  Start enabled when permissions granted, status `liveRegion` updates on state change.
- **Manual / staged E2E (acceptance gate):** on a physical device, start ingest against a
  staged broadcast; confirm ICE reaches `CONNECTED`, then open a second client (web
  viewer or another device) and confirm the host stream is **viewable**. Native libwebrtc
  cannot be exercised in CI emulators reliably — this E2E is the authoritative acceptance
  check and is documented in the PR.

## 12. Dependencies & Sequencing

- **Blocked by AND-307:** needs a real `broadcastId`/`sessionId`. Until merged, develop
  against a stubbed session id behind a debug flag.
- **Blocked by AND-290:** consumes `SignalingTransport` for SDP/ICE over `/signal`
  (SSE/poll). Do not start the negotiation integration until AND-290's transport interface
  is stable; mock it for unit work.
- **Blocks AND-309:** AND-309 (start/stop/resume/reschedule, health report) builds the
  lifecycle UI + foreground service + health screen on top of `IngestEngine`, the
  `getStats()` samples, and the manifest service entries declared here.
- **New library:** add `io.github.webrtc-sdk:android` to the version catalog and
  `feature-host-ingest`. Add ProGuard/R8 keep rules for `org.webrtc.**`.
- **Suggested order:** factory/EGL + capture + local preview → API models + offer publish
  → signaling bridge + ICE → state machine + reconnect → telemetry/stats → tests + staged
  E2E.

## 13. Risks & Open Questions

- **R1 — Exact endpoint shape.** `inputs` + `webrtc-offer` paths/bodies above are inferred;
  confirm against `/openapi.json` and `frontend/src/api/endpoints/*.ts` before coding.
  *Open:* is the answer returned inline from `webrtc-offer` or delivered async over
  `/signal`? Design supports inline (primary) with a fallback to signaling-delivered answer.
- **R2 — SFU vs P2P.** Whether the backend ingest is an SFU (single publish PC, viewers
  fan out) or relays to a viewer PC affects ICE config. Assumed SFU single-publish.
- **R3 — Codec negotiation.** H.264 vs VP8 support on the SFU; default factory enables
  both — confirm SFU accepts the offered codec to avoid black-video ingest.
- **R4 — Plaintext dev host.** Production ingest must be HTTPS/WSS; mixed-cleartext is
  dev-only. Open: production ingest URL + TURN credentials source.
- **R5 — CI coverage.** libwebrtc native path is not CI-testable on emulators; acceptance
  relies on manual staged E2E. Risk of regressions undetected in CI.
- **R6 — Battery/thermal.** 720p30 encode is power-heavy; may need adaptive bitrate /
  resolution downscaling (degradation preference `MAINTAIN_FRAMERATE`).

## 14. Acceptance Criteria

AC-1. On a physical device with permissions granted, tapping Start renders a live local
camera preview within 2s.

AC-2. The app POSTs to `/ui/broadcasts/{id}/inputs` then `.../webrtc-offer`, applies the
returned answer, and trickles ICE via `/signal`; the publish `PeerConnection` reaches
`CONNECTED`/`COMPLETED`. (Verified via logs + `getStats()` showing outbound video
bitrate > 0.)

AC-3. **Host stream is ingested and viewable:** a second client viewing the same broadcast
sees the host's audio + video (the source ticket acceptance).

AC-4. Denying camera or mic yields `Failed(PermissionDenied)` with a recoverable
Settings path; no crash, no ingest attempt.

AC-5. `stop()` and `onCleared()` release all native resources and clear the OS
camera/mic indicators (no leaked capturer/PeerConnection — verified via no dangling
`org.webrtc` threads in a memory/thread dump).

AC-6. On a simulated ICE `DISCONNECTED`, the engine enters `Reconnecting`, performs ICE
restart, and returns to `Connected` (unit test) — bounded to 3 attempts.

AC-7. `StateFlow<IngestUiState>` emits the documented transitions and survives a screen
rotation without tearing down the connection.

AC-8. No full SDP or raw ICE candidate strings are logged at INFO; auth uses cookie +
`X-CSRF-Token`.

## 15. Definition of Done

- `feature-host-ingest` module merged on `android-port` under
  `com.testlogon.android.feature.hostingest`, depending only on `core-*` per the layering
  rules.
- `IngestEngine`/`WebRtcIngestEngine`, `IngestApi` + Moshi models, `SignalingBridge`,
  `HostIngestViewModel`, and `HostIngestScreen` with local preview implemented and wired
  via Hilt (KSP).
- WebRTC dependency added to the version catalog; R8 keep rules added; manifest perms +
  foreground-service entries declared.
- All §11 unit/ViewModel/Compose tests pass in CI; staged manual E2E (AC-2/AC-3)
  documented with evidence (logs/screen recording) in the PR.
- Telemetry events + `getStats()` health samples emitted and consumable by AND-309.
- All user-facing strings localized; accessibility (contentDescription, liveRegion,
  touch targets) verified with TalkBack.
- No lint/detekt regressions; PR reviewed and approved; AND-309 unblocked.
