---
id: AND-308
title: WebRTC ingest
milestone: M7
epic: E41
priority: P0
size: XL
status: reviewed
reviewed_on: 2026-06-06
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
  - **AND-290 — Signaling transport** provides the backend signaling/transport plumbing
    (auth, refresh, SSE event stream). This ticket consumes that transport; it MUST NOT
    re-implement signaling. **NOTE (review):** the broadcast ingest contract does NOT use a
    per-candidate trickle-ICE `/signal` endpoint — the verified SDP exchange is a single
    request/response (`POST .../webrtc-offer` returns the answer inline; see §5). There is
    no broadcast-input `/signal` endpoint in the OpenAPI; the `/signal` routes that exist
    (`/messaging/messages/calls/{call_id}/signal`, `/ui/calls/group/{call_id}/signal`)
    belong to the 1:1/group calling feature, not broadcast ingest. ICE candidates are
    therefore exchanged non-trickle (gathered into the SDP before the offer is sent).
- **Blocks:** **AND-309 — Host controls** (start/stop/resume/reschedule, health report)
  drives the engine defined here.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI at `/openapi.json`. Web reference (verified in review):
  `src/api/endpoints/broadcast-inputs.ts` (`addInput`, `sendWebRTCOffer`,
  `activateInput`/`deactivateInput`, `removeInput`) and shared types `src/api/types.ts`
  (`BroadcastInputCreated`, `BroadcastWebRTCAnswer`). §5 below reflects the verified shapes.
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

FR-5. **(Corrected in review.)** The verified broadcast contract is a single
offer/answer exchange with **no trickle-ICE signaling channel** (no broadcast `/signal`
endpoint exists). Gather local ICE candidates fully before publishing (non-trickle /
"vanilla ICE": wait for `IceGatheringState.COMPLETE`, or apply a short gathering timeout)
so the candidates are embedded in the SDP offer; the backend's `sdp_answer` likewise
carries its candidates. The engine MUST still expose an `onIceCandidate` path so that if
AND-290 later adds a trickle channel it can be wired in without redesign, but the default
and acceptance path is non-trickle.

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
  ingest/SignalingBridge.kt          // (review) thin adapter over AND-290 transport for the
                                     // shared SSE event stream + auth; NO trickle-ICE /signal
                                     // (broadcast has no such endpoint — see §5)
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
2. `createOffer` → `setLocalDescription(offer)` → **wait for ICE gathering to complete**
   (non-trickle; see FR-5) so candidates are in the local SDP.
3. `POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer` with body
   `{ "sdp_offer": "<full SDP>" }` (see §5) → receive `{ sdp_answer, session_id,
   input_id }`.
4. `setRemoteDescription(SessionDescription(ANSWER, sdp_answer))`.
5. (Optional/idempotent) `POST .../inputs/{input_id}/activate` to mark the input live, and
   `.../deactivate` on stop. **(Corrected in review:** there is no per-candidate signaling
   step — remote candidates arrive inside `sdp_answer`.)
6. Connection reaches `PeerConnectionState.CONNECTED` → emit `Connected(inputId)`.
   **(Corrected:** the identifier is `input_id`; the API returns no separate `ingest_id`.)

**ICE servers:** **(Corrected in review.)** The `inputs`/`webrtc-offer` responses do **not**
contain an `ice_servers` field (verified against `BroadcastInputCreateOut` and
`BroadcastWebRTCOfferOut`). ICE servers MUST be sourced from app configuration (a default
STUN server, plus TURN credentials from a configured source — see R4). The publish
connection uses `IceTransportsType.ALL`.

**Threading:** all libwebrtc native calls are marshalled onto a single
`PeerConnection.Observer` callback path; engine public API uses `io` dispatcher.
StateFlow updates are posted with `MutableStateFlow.value =` (thread-safe).

## 5. API Contract

**(Section corrected in review against `openapi.index.txt`, the `BroadcastInput*` /
`BroadcastWebRTC*` schemas in `openapi.pretty.json`, and `src/api/endpoints/broadcast-inputs.ts`.)**
The ingest contract is **two HTTP calls** (`POST inputs`, `POST webrtc-offer`) with a
single inline SDP exchange — **no trickle-ICE `/signal` channel** (the broadcast API has
no such endpoint). Optional `activate`/`deactivate`/`DELETE` input calls manage the
input's lifecycle.

> Original draft used `/ui/broadcasts/{id}/inputs...`, a `{kind,audio,video}` body, and
> `ingest_id`/`ice_servers`/`{sdp,type}` fields. **All of those were wrong** and are
> corrected below.

**Verified endpoints** (base path `/broadcast/sessions`, path param is `session_id` —
the `sessionId` from AND-307, not a separate `broadcastId`):

```kotlin
interface IngestApi {
    @POST("/broadcast/sessions/{sessionId}/inputs")
    suspend fun createInput(
        @Path("sessionId") sessionId: String,
        @Body body: CreateInputRequest,        // BroadcastInputCreateIn
    ): Response<CreateInputResponse>            // 201 BroadcastInputCreateOut

    @POST("/broadcast/sessions/{sessionId}/inputs/{inputId}/webrtc-offer")
    suspend fun publishOffer(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
        @Body body: WebRtcOfferRequest,         // BroadcastWebRTCOfferIn
    ): Response<WebRtcOfferResponse>            // 200 BroadcastWebRTCOfferOut

    @POST("/broadcast/sessions/{sessionId}/inputs/{inputId}/activate")
    suspend fun activateInput(@Path("sessionId") s: String, @Path("inputId") i: String): Response<Unit>

    @POST("/broadcast/sessions/{sessionId}/inputs/{inputId}/deactivate")
    suspend fun deactivateInput(@Path("sessionId") s: String, @Path("inputId") i: String): Response<Unit>

    @DELETE("/broadcast/sessions/{sessionId}/inputs/{inputId}")
    suspend fun removeInput(@Path("sessionId") s: String, @Path("inputId") i: String): Response<Unit>
}
```

Verified request/response JSON:

```json
// POST /broadcast/sessions/{session_id}/inputs   (BroadcastInputCreateIn)
{ "input_type": "primary", "label": "Host camera" }
//   input_type ∈ {primary|guest|screen} (default "guest"); label optional (max 100).
//   There is NO kind/audio/video field. Use "primary" for the host's own camera/mic feed.
// -> 201  (BroadcastInputCreateOut)
{ "input_id": "...", "session_id": "...", "input_type": "primary",
  "label": "Host camera", "ingest_url": "...", "stream_key": "...",
  "position": 0, "aws_input_arn": null }
//   NO ingest_id, NO ice_servers.

// POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer  (BroadcastWebRTCOfferIn)
{ "sdp_offer": "v=0\r\no=- ..." }
//   single field "sdp_offer" (string, 1..65536). NO "type" field.
// -> 200  (BroadcastWebRTCOfferOut)
{ "sdp_answer": "v=0\r\no=- ...", "session_id": "...", "input_id": "..." }
//   NO "type" field, NO ice_servers. Remote ICE candidates are inside sdp_answer.
```

**No `SignalingBridge`/`/signal` for broadcast.** The previous `SignalingBridge` mapping
to a `/signal` candidate stream is removed: the broadcast contract has no per-candidate
endpoint. Build the offer SDP only after ICE gathering completes (FR-5), POST it, and
apply `sdp_answer`. AND-290's transport is still used for the shared SSE event stream
(e.g. `/broadcast/sessions/{session_id}/stream`) and for auth/refresh plumbing, not for
SDP/ICE trickle.

**Auth (corrected/clarified).** Per `src/api/client.ts`, authenticated calls send
**`Authorization: Bearer <accessToken>`** AND **`X-CSRF-Token`** (from the `ui_csrf`
cookie) AND ride the session cookie (`credentials: include`), plus an optional
`X-IMPERSONATION-TOKEN`. The OpenAPI further documents `X-SESSION-ID` (and `user_sub`,
server-derived) on these routes. The draft's "cookie + X-CSRF-Token" was incomplete — the
`Authorization: Bearer` header and `X-SESSION-ID` are also required and are provided by the
shared `core-network` client (AND-290). On 401 the client refreshes once via
`POST /ui/session/refresh` (verified to exist) then retries.

Moshi models (renamed to match verified schemas): `CreateInputRequest(input_type,
label?)`, `CreateInputResponse(input_id, session_id, input_type, label, ingest_url,
stream_key, position, aws_input_arn?)`, `WebRtcOfferRequest(sdp_offer)`,
`WebRtcOfferResponse(sdp_answer, session_id, input_id)`. `IceServerDto(urls, username?,
credential?)` is **config-sourced** (not from the API). No `IceCandidatePayload` /
trickle DTO is needed for the broadcast path.

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
  allow a user-initiated retry that first `DELETE`s the stale input
  (`DELETE /broadcast/sessions/{session_id}/inputs/{input_id}`, verified to exist) and
  re-creates it. **(Corrected in review:** there is no ICE-server fetch endpoint and no GET
  on `webrtc-offer`; ICE servers are config-sourced, so the prior "GET-equivalent of
  ICE-server fetch" note is removed. `GET /broadcast/sessions/{session_id}/inputs` exists
  and is idempotent, so listing/reconciling inputs may use bounded backoff.)
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
- All API auth uses `Authorization: Bearer` + `X-CSRF-Token` (from `ui_csrf`) + the session
  cookie jar (and `X-SESSION-ID`/optional `X-IMPERSONATION-TOKEN`) via the shared
  `core-network` client — see §5 (corrected). No tokens, cookies, or CSRF values are logged. SDP/ICE payloads can contain local IP candidates — treat as sensitive and
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
  - `IngestApi` Retrofit/Moshi (de)serialization against fixtures matching the verified
    `BroadcastInputCreateOut` / `BroadcastWebRTCOfferOut` shapes (§5); verify
    `Authorization`, `X-CSRF-Token`, and `X-SESSION-ID` header presence via MockWebServer.
  - SDP request/response mapping: `WebRtcOfferRequest(sdp_offer)` serializes to a single
    `sdp_offer` field; `WebRtcOfferResponse.sdp_answer` maps to an `ANSWER`
    `SessionDescription`. (No trickle `IceCandidatePayload` mapping — broadcast is
    non-trickle; see §5.)
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

- **R1 — Exact endpoint shape. RESOLVED in review.** Paths/bodies are now verified against
  `openapi.index.txt` + `BroadcastWebRTCOfferIn/Out` and `src/api/endpoints/broadcast-inputs.ts`
  (see §5). The answer **is returned inline** from `webrtc-offer` (`sdp_answer`); there is
  **no** `/signal` trickle channel for broadcast, so the async/trickle fallback is dropped.
  Remaining unknown: server-side ICE gathering timing within the single answer (treat as
  non-trickle vanilla ICE).
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

AC-2. **(Corrected.)** The app POSTs to `/broadcast/sessions/{session_id}/inputs` then
`.../inputs/{input_id}/webrtc-offer` (body `{sdp_offer}`), applies the inline `sdp_answer`,
and (non-trickle) completes ICE gathering before publish — there is no `/signal` trickle;
the publish `PeerConnection` reaches `CONNECTED`/`COMPLETED`. (Verified via logs +
`getStats()` showing outbound video bitrate > 0.)

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

AC-8. No full SDP or raw ICE candidate strings are logged at INFO; auth uses
`Authorization: Bearer` + `X-CSRF-Token` + session cookie + `X-SESSION-ID` (see §5).

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
`reference/openapi.index.txt` (index), `reference/openapi.pretty.json`
(`components.schemas.*`), and the frontend at `reference/src/...`.

1. **Create-input endpoint is `POST /broadcast/sessions/{session_id}/inputs`** (not
   `/ui/broadcasts/{id}/inputs`). **VERDICT: Corrected.** Source: OpenAPI
   `POST /broadcast/sessions/{session_id}/inputs` (op `add_input_route...`,
   req=`BroadcastInputCreateIn`, resp `201:BroadcastInputCreateOut`); frontend
   `src/api/endpoints/broadcast-inputs.ts: addInput` (`BASE = "/broadcast/sessions"`).

2. **Create-input request body is `{input_type?: primary|guest|screen, label?}`** (not
   `{kind, audio, video}`). **VERDICT: Corrected.** Source: schema
   `components.schemas.BroadcastInputCreateIn` (props `input_type` pattern
   `^(primary|guest|screen)$` default `guest`, `label` maxLength 100); frontend
   `src/api/endpoints/broadcast-inputs.ts: addInput` body `{ input_type?, label? }`.

3. **Create-input response is `{input_id, session_id, input_type, label, ingest_url,
   stream_key, position, aws_input_arn?}` — no `ingest_id`, no `ice_servers`.**
   **VERDICT: Corrected.** Source: `components.schemas.BroadcastInputCreateOut` (required:
   input_id, session_id, input_type, label, ingest_url, stream_key, position);
   `src/api/types.ts: BroadcastInputCreated`.

4. **webrtc-offer endpoint is `POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer`.**
   **VERDICT: Corrected** (path prefix/param names). Source: OpenAPI
   `POST /broadcast/sessions/{session_id}/inputs/{input_id}/webrtc-offer` (op
   `webrtc_offer_route...`, req=`BroadcastWebRTCOfferIn`, resp `200:BroadcastWebRTCOfferOut`);
   frontend `src/api/endpoints/broadcast-inputs.ts: sendWebRTCOffer`.

5. **webrtc-offer request body is `{sdp_offer: string}`** (single field; not `{sdp, type}`).
   **VERDICT: Corrected.** Source: `components.schemas.BroadcastWebRTCOfferIn` (only prop
   `sdp_offer`, minLength 1 / maxLength 65536, required); frontend `sendWebRTCOffer` body
   `{ sdp_offer: string }`.

6. **webrtc-offer response is `{sdp_answer, session_id, input_id}` — no `type`, no
   `ice_servers`; answer is returned inline.** **VERDICT: Corrected.** Source:
   `components.schemas.BroadcastWebRTCOfferOut` (required: sdp_answer, session_id, input_id);
   `src/api/types.ts: BroadcastWebRTCAnswer`.

7. **There is no trickle-ICE `/signal` endpoint for broadcast ingest; SDP exchange is a
   single request/response and ICE is non-trickle.** **VERDICT: Corrected.** Source:
   negative result — no broadcast `/signal` in `openapi.index.txt`; the only `/signal`
   routes are `POST /messaging/messages/calls/{call_id}/signal` and
   `POST /ui/calls/group/{call_id}/signal` (calling feature, not broadcast). No
   `IceCandidate*`/candidate request schema exists for broadcast.

8. **ICE servers must be config-sourced (STUN/TURN); the API returns none.**
   **VERDICT: Corrected.** Source: absence of any `ice_servers` field in
   `BroadcastInputCreateOut` and `BroadcastWebRTCOfferOut`.

9. **Input lifecycle endpoints exist: `activate`, `deactivate`, `DELETE` input, `GET`
   list.** **VERDICT: Verified.** Source: OpenAPI
   `POST .../inputs/{input_id}/activate`, `POST .../inputs/{input_id}/deactivate`,
   `DELETE .../inputs/{input_id}`, `GET /broadcast/sessions/{session_id}/inputs`
   (`resp 200:BroadcastInputListOut`); frontend `activateInput`/`deactivateInput`/
   `removeInput`/`listInputs`.

10. **Auth = `Authorization: Bearer` + `X-CSRF-Token` (cookie `ui_csrf`) + session cookie
    (+ optional `X-IMPERSONATION-TOKEN`); server also expects `X-SESSION-ID`.**
    **VERDICT: Corrected** (draft said only "cookie + X-CSRF-Token"). Source:
    `src/api/client.ts` lines ~158-171 (`Authorization: Bearer <accessToken>`,
    `X-CSRF-Token` from `getCookie("ui_csrf")`, `credentials: "include"`,
    `X-IMPERSONATION-TOKEN`); OpenAPI input routes list params
    `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`.

11. **On 401 the client refreshes once via `POST /ui/session/refresh` then retries.**
    **VERDICT: Verified.** Source: `src/api/client.ts: refreshSession()` (POST
    `/ui/session/refresh`, `credentials: include`); OpenAPI
    `POST /ui/session/refresh` (op `ui_session_refresh...`, resp `200`).

12. **Status codes: createInput → 201, webrtc-offer → 200.** **VERDICT: Verified.** Source:
    OpenAPI `resp=201:BroadcastInputCreateOut` and `resp=200:BroadcastWebRTCOfferOut`.

13. **Validation errors are `422 HTTPValidationError = {detail:[{loc,msg,type}]}`; these
    routes do not declare an `ErrorEnvelope`.** **VERDICT: Verified.** Source: index shows
    `resp=...;422:HTTPValidationError` only (plus 201/200) for the input routes;
    `components.schemas.HTTPValidationError` → `detail: ValidationError[]`,
    `components.schemas.ValidationError` (`loc, msg, type`).

14. **`broadcastId`/`sessionId` are the same identifier (the path param is `session_id`).**
    **VERDICT: Corrected** (draft modeled a separate `broadcastId`). Source: all input
    routes use `{session_id}`; frontend passes `sessionId`. AND-307 supplies it.

15. **WebRTC stack `io.github.webrtc-sdk:android` (Google libwebrtc fork) for native
    ingest.** **VERDICT: Unverified-assumption** (framework choice — not derivable from
    backend/frontend sources). Treat the exact version `125.6422.07` as unverified; pin to
    a current published artifact at implementation time. (framework ref:
    https://github.com/webrtc-sdk/android — Maven `io.github.webrtc-sdk:android`.)

16. **Camera2/CameraVideoCapturer, EglBase, SurfaceViewRenderer, Unified Plan, ICE restart
    via `restartIce()`.** **VERDICT: Unverified-assumption** (libwebrtc/Android API usage;
    not in repo sources). (framework ref: org.webrtc API docs,
    https://webrtc.github.io/webrtc-org/native-code/android/ and
    https://developer.android.com/media/camera/camera2.)

17. **Foreground-service types `FOREGROUND_SERVICE_CAMERA`/`_MICROPHONE` required for
    background camera/mic on Android 14+ (API 34+).** **VERDICT: Verified** as a platform
    requirement (framework ref:
    https://developer.android.com/about/versions/14/changes/fgs-types-required). The
    service itself is wired in AND-309; this ticket only declares manifest entries.

### Corrections made

- §2, §5, AC-2, AC-8: endpoint base path corrected `/ui/broadcasts/{id}/...` →
  `/broadcast/sessions/{session_id}/...` (items 1, 4, 14).
- §5: request bodies corrected — create-input `{kind,audio,video}` → `{input_type,label}`;
  webrtc-offer `{sdp,type}` → `{sdp_offer}` (items 2, 5).
- §5, §4: responses corrected — removed nonexistent `ingest_id`, `ice_servers`, and SDP
  `type`; create-input/answer shapes aligned to verified schemas; `Connected(ingestId)` →
  `Connected(inputId)` (items 3, 6).
- §2, §4 (module layout + flow), §5, FR-5, §11, §13-R1, AC-2: removed the trickle-ICE
  `/signal` design — broadcast has no such endpoint; switched to non-trickle (gather-then-
  publish) with inline answer (items 7, 8).
- §5, §8, AC-8: auth model corrected to include `Authorization: Bearer` and `X-SESSION-ID`
  alongside `X-CSRF-Token`/cookie (item 10).
- §4, §7: ICE-server sourcing corrected to config/STUN+TURN; removed the bogus
  "GET-equivalent of ICE-server fetch"; retry-via-`DELETE`+recreate confirmed valid
  (items 8, 9).

### Open assumptions

- **WebRTC artifact + exact version (item 15):** not derivable from backend/frontend;
  the pinned `125.6422.07` is an assumption — verify against the published Maven artifact
  at implementation time.
- **All native libwebrtc/Camera2 API usage (item 16):** validated only by framework docs,
  not repo sources; details (codec factory flags, capturer threading) are engineering
  assumptions to confirm on-device.
- **SFU vs P2P + accepted codec (§13 R2/R3):** the backend topology and codec acceptance
  cannot be determined from OpenAPI/frontend (the SDP is an opaque string); remains an
  on-device verification (does the SFU accept the offered H.264/VP8?).
- **Server-side ICE/answer timing:** whether `webrtc-offer` blocks until the server has
  gathered its candidates is not specified; assumed inline-complete answer (non-trickle).
- **`X-SESSION-ID` value source:** OpenAPI lists it as a required param but its provenance
  (set by AND-290's client) is assumed; confirm AND-290 injects it.

## 17. Test Plan

Test targets: **JVM** = local JUnit/Robolectric (no device); **emu35** = headless AVD
`test35` (x86_64, API 35) — note x86_64 has no usable camera and libwebrtc native encode is
unreliable on emulators; **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a, serial R5CX821TA9R) — required for real camera/mic, native encode, and the
ingest/viewable acceptance gate.

- **TC-AND-308-01 — Happy-path negotiation state machine (faked WebRTC).**
  Type: unit (JVM, Turbine). Target: JVM. Preconditions: faked
  `PeerConnectionFactoryProvider` + `SignalingTransport`; MockWebServer returns
  `201 BroadcastInputCreateOut` then `200 {sdp_answer,...}`. Steps: call
  `engine.start(sessionId)`; feed a stubbed answer and drive PC to `CONNECTED`. Expected:
  state emits `RequestingPermissions?→Negotiating→Connected(inputId)`; `setRemoteDescription`
  called with an ANSWER built from `sdp_answer`. Traces: AC-2, AC-7.

- **TC-AND-308-02 — IngestApi contract (MockWebServer) for create-input + webrtc-offer.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: Retrofit/Moshi wired to
  MockWebServer; fixtures match §5 verified shapes. Steps: call `createInput` with
  `{input_type:"primary", label:"Host camera"}`; assert recorded path
  `/broadcast/sessions/{id}/inputs`, method POST, parsed `BroadcastInputCreateOut` (has
  `ingest_url`, `stream_key`, `position`; no `ingest_id`/`ice_servers`). Then `publishOffer`
  with `{sdp_offer:"..."}`; assert path `.../inputs/{inputId}/webrtc-offer`, body has only
  `sdp_offer`, parsed `sdp_answer` present. Expected: all assertions pass; deserialization
  ignores unknown fields. Traces: AC-2.

- **TC-AND-308-03 — Auth headers present on ingest calls.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: shared client configured with a
  test access token, `ui_csrf` cookie, and `X-SESSION-ID`. Steps: issue any ingest POST.
  Expected: recorded request contains `Authorization: Bearer <token>`, `X-CSRF-Token`,
  `X-SESSION-ID`, and the session cookie; values are never logged. Traces: AC-8.

- **TC-AND-308-04 — 422 validation error mapping.**
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer returns
  `422 {"detail":[{"loc":["body","sdp_offer"],"msg":"field required","type":"missing"}]}`
  for webrtc-offer. Steps: call `publishOffer`. Expected: mapped to
  `Failed(IngestError.Backend(message, code?))` (or `SignalingUnavailable` per mapper);
  `detail[0].msg` surfaced; no crash. Traces: AC-2.

- **TC-AND-308-05 — Offer publish network failure is not blindly retried.**
  Type: unit/contract. Target: JVM. Preconditions: MockWebServer drops/returns
  `503`/timeout on webrtc-offer (~20s timeout). Steps: `engine.start`. Expected: emits
  `Failed(SignalingUnavailable)`; no automatic re-POST of the non-idempotent offer; a
  user-initiated retry first issues `DELETE .../inputs/{inputId}` then recreates. Traces:
  AC-2.

- **TC-AND-308-06 — ICE disconnect → bounded reconnect via ICE restart.**
  Type: unit (JVM, Turbine). Target: JVM. Preconditions: faked PC emits
  `PeerConnectionState.DISCONNECTED`. Steps: simulate disconnect, then a successful restart.
  Expected: `Reconnecting(attempt=1)` then `Connected`; `restartIce()` invoked; max 3
  attempts (2s/4s/8s) then `Failed(IceFailed)`. Traces: AC-6.

- **TC-AND-308-07 — Permission-denied path.**
  Type: unit (ViewModel) + Compose-UI. Target: JVM (Robolectric) for VM; emu35 for UI.
  Preconditions: CAMERA and/or RECORD_AUDIO denied. Steps: tap Start. Expected: state
  `Failed(PermissionDenied)`; no `createInput`/`webrtc-offer` issued; UI offers a Settings
  deep-link; no crash. Traces: AC-4.

- **TC-AND-308-08 — Deterministic resource release on stop()/onCleared().**
  Type: unit + instrumented. Target: JVM for call-verification (capturer.stopCapture,
  track.dispose, pc.dispose, factory.dispose, eglBase.release, renderer.release all
  invoked once); **A15** for the indicator check (must be physical: real camera/mic OS
  indicators). Steps: start ingest, then `stop()` / destroy ViewModel; inspect a
  thread/memory dump for dangling `org.webrtc` threads. Expected: all native handles
  released; OS camera/mic indicators clear; no leaked threads. Traces: AC-5.

- **TC-AND-308-09 — Compose UI: preview + live status announcements + a11y.**
  Type: Compose-UI / instrumented. Target: emu35 (UI logic), A15 for real preview frames.
  Preconditions: permissions granted (stubbed for emu). Steps: render `HostIngestScreen`;
  toggle state Idle→Negotiating→Connected. Expected: preview `AndroidView` exposes
  `contentDescription` (R.string.ingest_preview_cd); status label uses
  `liveRegion = Polite` and announces transitions; Start/Stop/Mute/Camera controls have
  text labels, `toggleable`/`role` semantics, and ≥48dp targets; layout survives font
  scaling. Traces: AC-1, AC-7, AC-8 (no SDP in UI/logs).

- **TC-AND-308-10 — Local preview renders within 2s on real hardware.**
  Type: instrumented/e2e. Target: **A15 (must be physical** — emu35 x86_64 has no real
  camera). Preconditions: permissions granted, front camera available. Steps: tap Start,
  measure time to first rendered preview frame. Expected: live preview ≤2s; on capture
  error, one retry at 640×480/24fps then `Failed(CaptureFailed)`. Traces: AC-1.

- **TC-AND-308-11 — End-to-end ingest is viewable (acceptance gate).**
  Type: manual/e2e. Target: **A15 (must be physical** — native libwebrtc encode + real
  network; not CI-testable). Preconditions: a real/staged broadcast session from AND-307;
  reachable backend; configured STUN/TURN. Steps: Start ingest on A15; confirm
  `createInput`→`webrtc-offer`→inline `sdp_answer`→`setRemoteDescription`; PC reaches
  `CONNECTED`/`COMPLETED` and `getStats()` outbound video bitrate > 0; (optionally)
  `activate` the input; open a second client (web viewer or second device) on the same
  broadcast. Expected: second client sees the host audio + video. Capture logs/recording in
  PR. Traces: AC-2, AC-3.

- **TC-AND-308-12 — Flaky/offline dev-host path; local preview still works.**
  Type: integration/manual. Target: A15 (real preview) with backend unreachable, or
  emu35 with MockWebServer offline for the VM portion. Preconditions: backend down /
  cleartext dev host unreachable. Steps: Start ingest. Expected: ingest enters offline
  `Failed(SignalingUnavailable)`; local camera preview still renders so the host sees the
  camera works; user-initiated retry path available. Traces: AC-2, AC-1.

- **TC-AND-308-13 — Cleartext config is dev-only; SDP/credentials never logged.**
  Type: unit + instrumented (security). Target: JVM (log assertions) + A15 (manifest/
  network-security-config). Preconditions: release-like build config. Steps: drive a full
  ingest; scan Timber output. Expected: no full SDP or raw candidate strings at INFO (only
  candidate type/count); no tokens/cookies/CSRF logged; `usesCleartextTraffic` /
  `18.222.237.167` allow only in dev `network_security_config`. Traces: AC-8.

- **TC-AND-308-14 — ABI/API-level smoke (arm64 vs x86, API 34 vs 35).**
  Type: instrumented. Target: run the JVM/Compose suites on both emu35 (x86_64, API 35) and
  **A15 (arm64-v8a, API 34)**; native encode/preview cases (TC-10/11) on A15 only.
  Preconditions: both targets available. Steps: run the suite on each. Expected: behavior
  consistent across ABI/API; foreground-service-type manifest entries valid on API 34+;
  no arm64-only crashes in the webrtc native lib. Traces: AC-1, AC-2, AC-5.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (preview ≤2s) | TC-09, TC-10, TC-12, TC-14 |
| AC-2 (POST inputs→webrtc-offer→answer→CONNECTED) | TC-01, TC-02, TC-04, TC-05, TC-11, TC-12, TC-14 |
| AC-3 (stream viewable by 2nd client) | TC-11 |
| AC-4 (permission denied, recoverable) | TC-07 |
| AC-5 (resource release / indicators clear) | TC-08, TC-14 |
| AC-6 (ICE disconnect → bounded reconnect) | TC-06 |
| AC-7 (StateFlow transitions survive rotation) | TC-01, TC-09 |
| AC-8 (no SDP/candidate logging; correct auth) | TC-03, TC-09, TC-13 |
