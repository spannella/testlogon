---
id: AND-324
title: Liveness call
milestone: M7
epic: E42
priority: P2
size: L
status: draft
depends_on: [AND-290, AND-323]
blocks: []
---

# AND-324 — Liveness call

## 1. Overview & Goal

This ticket delivers `kycLivenessCall`: a real-time **liveness verification
session** in which the user joins a WebRTC video call — either with an automated
liveness bot or a live human compliance agent — so the backend can confirm the
person submitting KYC is a live human (anti-spoof / presentation-attack
detection) rather than a replayed photo or video. It is the most interactive
rung of the KYC tier-advancement ladder, complementing the still-image
**facial comparison** flow (AND-323).

The deliverable is a `feature-kyc` sub-flow comprising a `LivenessCallScreen`
(Compose, single video surface + prompt overlay + status chrome), a
`LivenessCallViewModel` exposing `StateFlow<LivenessUiState>`, and a thin
`LivenessCoordinator` in `core-data` that orchestrates three already-built
layers: (1) the KYC HTTP surface (`KycApi`, AND-319) to start a liveness session
and poll its result, (2) the **signaling transport** (`SignalingClient`,
AND-290) to exchange SDP/ICE with the verifier through the backend `/signal`
relay, and (3) the **PeerConnection wrapper** (`RtcPeerConnection`, AND-289 via
AND-290) to carry the encrypted media. AND-324 owns the *liveness-specific
orchestration and UI*; it does not re-implement WebRTC, signaling, or the KYC
DTO layer.

**Definition of success (source acceptance — "Liveness session connects +
completes"):** from the KYC requirements screen the user starts a liveness
session, the WebRTC call reaches `RtcSessionState.Connected`, the user completes
the on-screen liveness prompts (e.g. "turn your head left", "blink"), and the
backend returns a terminal verdict (`passed` / `failed` / `review`) that is
surfaced to the user and reflected in their refreshed KYC status.

## 2. Context & References

- **Module / location:** `feature-kyc` (UI + ViewModel) under
  `com.testlogon.android.feature.kyc.liveness`; orchestration in `core-data`
  under `com.testlogon.android.core.data.kyc`. Layering respected: `app ->
  feature-kyc -> core-* (core-data, core-network, core-webrtc, core-signaling,
  core-model, core-ui)`. No `feature-*` symbol leaks into `core-*`.
- **AND-323 (Facial comparison, dep):** sibling KYC requirement (`type ==
  "selfie"` / `liveness`). AND-324 reuses AND-323's camera permission gate,
  `CameraPermissionGate` composable, front-camera preview plumbing, and the
  shared `KycRepository` entry point. The two are alternative/competing
  requirement satisfiers for a tier; the requirements list (AND-319
  `KycRequirement.type`) decides which is shown. AND-324 starts only when its
  requirement key (`liveness_call`) is present and unsatisfied.
- **AND-290 (Signaling transport, dep):** provides `SignalingClient`
  (`open`/`send`/`close`, `incoming: Flow<SignalingEnvelope>`,
  `state: StateFlow<SignalingState>`) over backend `/signal` (SSE + poll
  fallback). AND-324 consumes it unchanged; the `roomId` is the liveness
  `session_id` and `peerId` is the device peer id returned at session start.
- **AND-289 (PeerConnection wrapper, transitive):** `RtcPeerConnection` /
  `RtcPeerConnectionFactory`, `RtcConfig`, `RtcSessionState`, `SignalingPort`,
  SDP/ICE Moshi shapes. AND-324 acts as the **Offerer** and bridges
  `SignalingPort` ↔ `SignalingClient`.
- **AND-319 (KYC API + DTOs, transitive):** `KycApi`, `KycStatus`, `KycTierId`,
  the `/v1/kyc/*` seam and the cookie/CSRF/refresh pipeline. AND-324 adds the
  liveness sub-endpoints (`/v1/kyc/liveness/*`) to that same authenticated
  Retrofit.
- **AND-291 (TURN/STUN credentials):** if merged, supplies `RtcConfig.iceServers`
  for NAT traversal; otherwise the liveness session-start response carries an
  `ice_servers` list (§5). Treated as soft — see §13.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable; ~20s timeouts, bounded backoff for idempotent
  GETs only). OpenAPI at `/openapi.json`; web reference
  `frontend/src/api/endpoints/kyc.ts` (look for `liveness`/`call` routes) and
  `frontend/src/api/types.ts`. The exact `/v1/kyc/liveness/*` schema MUST be
  reconciled against `/openapi.json` before coding (OQ-1).
- **Stack pins:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP),
  Coroutines/Flow, Media3 not used here (WebRTC owns its own surface), webrtc-
  android (via AND-288/289), minSdk 24 / compileSdk/targetSdk 35, JDK 17,
  AGP 8.7.3 / Gradle 8.9.

## 3. Functional Requirements

FR-1 **Entry & gating.** The liveness flow is reachable only from the KYC
requirements screen when a `KycRequirement` with `key == "liveness_call"` (or
`type == "liveness"`) is present and `satisfied == false`. Camera + microphone
permissions are checked (reusing AND-323's `CameraPermissionGate`); audio may be
optional per backend config (`require_audio`).

FR-2 **Start session.** On entry, `POST /v1/kyc/liveness/start` returns a
`session_id`, this device's `peer_id`, the `verifier` mode
(`automated | agent`), the `signal_room` id, the prompt script (for automated
mode), and `ice_servers` (when AND-291 is not the source). The ViewModel moves
`Idle → Starting → Connecting`.

FR-3 **Establish media.** AND-324 opens the `SignalingClient` on the
`signal_room`, creates an Offerer `RtcPeerConnection` with the front camera +
(optional) mic, and runs the offer/answer/ICE exchange via signaling until
`RtcSessionState.Connected`. The remote (bot/agent) video renders in the same
surface as a small self-preview PiP.

FR-4 **Liveness prompts.** In `automated` mode the backend drives the user
through a scripted challenge sequence (head turn, blink, smile, read-a-number).
Prompts arrive either in the start response (static script with step ordering)
or as in-call signaling `control` messages (§5); each prompt is rendered as an
overlay with a progress indicator. The user advances by performing the action;
the backend evaluates from the media stream. In `agent` mode the human agent
drives the conversation and the app shows an "in review with an agent" status.

FR-5 **Completion & verdict.** The session ends when the backend posts a
terminal verdict. The app learns the verdict by (a) an in-call signaling
`control` message of type `liveness_result`, and/or (b) polling
`GET /v1/kyc/liveness/{sessionId}` (idempotent) until `status` is terminal. On
verdict the call is torn down and `LivenessUiState.Result(verdict)` is shown.

FR-6 **Result reflection.** A `passed` verdict refreshes KYC status via
`KycApi.me()` (AND-319) so the requirement shows `satisfied`; `failed` offers a
bounded retry (subject to `max_attempts`); `review` shows "your verification is
being reviewed" with the opened `case_id` (deep-link to the cases list).

FR-7 **Cancel / abandon.** The user may cancel at any point; cancelling calls
`POST /v1/kyc/liveness/{sessionId}/cancel`, tears down the call (signaling
`BYE` + `RtcPeerConnection.close()`), and returns to requirements without a
verdict. Backgrounding the app pauses the call surface and, if not resumed
within `RESUME_GRACE_MS`, treats the session as abandoned.

FR-8 **Single active session.** Only one liveness session may be active per
device; starting a new one while one is live is rejected client-side. The
ViewModel guards against duplicate `start` calls (in-flight latch).

## 4. Technical Design

### 4.1 UI state

```kotlin
package com.testlogon.android.feature.kyc.liveness

sealed interface LivenessUiState {
    data object Idle : LivenessUiState
    data object NeedsPermission : LivenessUiState
    data object Starting : LivenessUiState                       // POST /start in flight
    data class  Connecting(val attempt: Int) : LivenessUiState   // signaling + ICE
    data class  InCall(
        val mode: VerifierMode,                                  // AUTOMATED | AGENT
        val prompt: LivenessPrompt?,                             // current automated prompt
        val stepIndex: Int,
        val stepCount: Int,
        val micEnabled: Boolean,
    ) : LivenessUiState
    data class  Result(val verdict: LivenessVerdict, val caseId: String?) : LivenessUiState
    data class  Error(val error: KycError, val recoverable: Boolean) : LivenessUiState
}

enum class VerifierMode { AUTOMATED, AGENT }
enum class LivenessVerdict { PASSED, FAILED, REVIEW, EXPIRED, CANCELLED }

data class LivenessPrompt(val id: String, val kind: PromptKind, val instructionKey: String, val timeoutMs: Long)
enum class PromptKind { TURN_LEFT, TURN_RIGHT, BLINK, SMILE, NOD, READ_NUMBER, HOLD_STILL, UNKNOWN }
```

### 4.2 ViewModel

```kotlin
@HiltViewModel
class LivenessCallViewModel @Inject constructor(
    private val coordinator: LivenessCoordinator,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    val uiState: StateFlow<LivenessUiState>      // backed by coordinator.flow + permission state

    fun onPermissionsGranted()
    fun start()                                   // begins start → connect → in-call
    fun onPromptCompletedHint(promptId: String)   // optional client-side "I did it" nudge
    fun toggleMic()
    fun cancel()
    fun retry()
    fun onStop()                                  // lifecycle pause
    fun onStart()                                 // lifecycle resume within grace
    override fun onCleared()                       // guarantees teardown
}
```

The ViewModel never touches libwebrtc or signaling directly; it drives the
`LivenessCoordinator` and maps `LivenessSessionState` → `LivenessUiState`.

### 4.3 Coordinator (orchestration, `core-data`)

```kotlin
package com.testlogon.android.core.data.kyc

interface LivenessCoordinator {
    val state: StateFlow<LivenessSessionState>
    suspend fun start(): ApiResult<Unit>          // POST /start, open signaling, negotiate
    fun completePromptHint(promptId: String)
    fun setMicEnabled(enabled: Boolean)
    suspend fun cancel()                           // /cancel + BYE + close()
    suspend fun shutdown()                         // idempotent teardown
}

class DefaultLivenessCoordinator @Inject constructor(
    private val kycApi: KycApi,                                 // AND-319 (+ liveness methods)
    private val signalingFactory: SignalingClientFactory,        // AND-290
    private val rtcFactory: RtcPeerConnectionFactory,            // AND-289
    private val kycRepository: KycRepository,                    // for me() refresh
    @Dispatcher(IO) private val io: CoroutineDispatcher,
    private val clock: Clock,
    private val metrics: KycMetrics,
) : LivenessCoordinator
```

`LivenessSessionState` mirrors `LivenessUiState` minus permission concerns and
carries the raw `RtcSessionState` / `SignalingState` for diagnostics.

### 4.4 Signaling ↔ PeerConnection bridge

AND-324 implements `SignalingPort` (AND-289) by serializing local SDP/ICE into
`SignalingEnvelope`s (AND-290) and feeding remote envelopes back into the
`RtcPeerConnection`:

```kotlin
private inner class LivenessSignalingBridge(
    private val client: SignalingClient,
    private val peer: RtcPeerConnection,
    private val selfPeerId: String,
    private val roomId: String,
) : SignalingPort {

    override fun onLocalSessionDescription(sdp: RtcSessionDescription) {
        scope.launch { client.send(sdp.toEnvelope(roomId, selfPeerId)) }
    }
    override fun onLocalIceCandidate(candidate: RtcIceCandidate) {
        scope.launch { client.send(candidate.toEnvelope(roomId, selfPeerId)) }
    }

    fun pump() = client.incoming
        .filter { it.from != selfPeerId }
        .onEach { env -> when (env.type) {
            SignalType.OFFER, SignalType.ANSWER -> peer.setRemoteDescription(env.toSdp())
            SignalType.ICE                       -> peer.addIceCandidate(env.toIce())
            SignalType.BYE                       -> shutdown()
        } }
}
```

Liveness *prompts and verdicts* travel as a `control`-typed signaling message
(an additive `SignalType.CONTROL` with a typed `payload.control`), parsed by the
coordinator and not forwarded to the PeerConnection.

### 4.5 Negotiation flow (Offerer)

1. `kycApi.startLiveness(...)` → `session_id`, `peer_id`, `signal_room`, `mode`,
   `ice_servers`, `prompts`, `require_audio`, `max_attempts`.
2. `signaling = signalingFactory.create(); signaling.open(signal_room, peer_id)`.
3. `peer = rtcFactory.create(RtcConfig(iceServers, role = Offerer,
   enableVideo = true, enableAudio = require_audio), bridge)`.
4. `bridge.pump()` collected on `io`; `peer.createOffer()` → emitted via
   `SignalingPort` → relayed; remote answer + ICE flow back; `peer.state`
   reaches `Connected`.
5. Prompts rendered; verdict awaited via control message or poll loop (§7).
6. Terminal → `signaling.send(BYE)`, `peer.close()`, `signaling.close()`,
   `kycRepository.refreshMe()`.

### 4.6 Hilt wiring

```kotlin
@Module @InstallIn(SingletonComponent::class)
abstract class LivenessModule {
    @Binds abstract fun bindCoordinator(impl: DefaultLivenessCoordinator): LivenessCoordinator
}
```

`feature-kyc` declares `implementation(project(":core-data"))`,
`":core-signaling"`, `":core-webrtc"`, `":core-network"`, `":core-model"`,
`":core-ui"`. No new third-party dependency is introduced (WebRTC artifact comes
from AND-288).

## 5. API Contract

> The `/v1/kyc/liveness/*` surface is **not yet confirmed against
> `/openapi.json`** (OQ-1). Shapes below are the target contract; the Retrofit
> methods + Moshi DTOs are the single point of change if the schema differs.
> Methods are added to `KycApi` (AND-319), reusing the cookie/CSRF/refresh
> pipeline; paths declared without a leading slash.

```kotlin
// added to KycApi (AND-319), package com.testlogon.android.core.network.kyc
@Headers("Content-Type: application/json")
@POST("v1/kyc/liveness/start")
suspend fun startLiveness(@Body body: LivenessStartReq): LivenessStartResp   // non-idempotent

@GET("v1/kyc/liveness/{sessionId}")
suspend fun livenessStatus(@Path("sessionId") sessionId: String): LivenessStatusResp // idempotent

@Headers("Content-Type: application/json")
@POST("v1/kyc/liveness/{sessionId}/cancel")
suspend fun cancelLiveness(@Path("sessionId") sessionId: String): LivenessStatusResp // non-idempotent
```

**POST `v1/kyc/liveness/start`** (auth cookies + `X-CSRF-Token`)
Request:
```json
{ "target_tier": "tier2", "requirement_key": "liveness_call", "platform": "android" }
```
Response `200`:
```json
{
  "session_id": "lv_9f1c",
  "peer_id": "peer-android-77",
  "signal_room": "lv_9f1c",
  "mode": "automated",
  "require_audio": false,
  "max_attempts": 3,
  "expires_at": "2026-06-05T12:10:00Z",
  "ice_servers": [
    { "urls": ["stun:18.222.237.167:3478"] },
    { "urls": ["turn:18.222.237.167:3478?transport=udp"], "username": "lv_9f1c", "credential": "..." }
  ],
  "prompts": [
    { "id": "p1", "kind": "turn_left",  "instruction": "Turn your head to the left",  "timeout_ms": 8000 },
    { "id": "p2", "kind": "blink",      "instruction": "Blink twice",                 "timeout_ms": 6000 },
    { "id": "p3", "kind": "read_number","instruction": "Read aloud: 4 7 2",           "timeout_ms": 10000 }
  ]
}
```
Errors: `401` (refresh+retry once), `403` (CSRF), `409` (a session already
active or attempts exhausted), `422` (validation), `503` (verifier unavailable).

**GET `v1/kyc/liveness/{sessionId}`** (poll; idempotent → AND-016 backoff)
Response `200`:
```json
{ "session_id": "lv_9f1c", "status": "in_progress",
  "verdict": null, "current_prompt": "p2", "case_id": null,
  "score": null, "attempts_used": 1 }
```
Terminal example:
```json
{ "session_id": "lv_9f1c", "status": "completed",
  "verdict": "passed", "current_prompt": null, "case_id": null,
  "score": 0.97, "attempts_used": 1 }
```
`status ∈ {pending,in_progress,completed,failed,expired,cancelled}`;
`verdict ∈ {passed,failed,review,null}`. `404` on unknown/foreign session id.

**POST `v1/kyc/liveness/{sessionId}/cancel`** → terminal `LivenessStatusResp`
with `status:"cancelled"`.

**In-call control message (over AND-290 signaling)** — additive
`SignalType.CONTROL`; `payload.control` JSON:
```json
{ "kind": "prompt",  "prompt": { "id": "p2", "kind": "blink", "instruction": "Blink twice", "timeout_ms": 6000 } }
{ "kind": "prompt_ack", "prompt_id": "p2", "ok": true }
{ "kind": "liveness_result", "verdict": "passed", "case_id": null, "score": 0.97 }
```

**DTOs** (`core-model/.../kyc`, `@JsonClass(generateAdapter = true)`, snake_case
via `@Json(name=)`, enums with `UNKNOWN` fallback like AND-319): `LivenessStartReq`,
`LivenessStartResp`, `LivenessPromptDto`, `LivenessIceServerDto`,
`LivenessStatusResp`, `LivenessControl`. `LivenessIceServerDto` maps 1:1 to
AND-289 `RtcIceServer`. FastAPI `detail` union mapped by AND-015 → `KycError`.

## 6. Data & State Management

- **No Room persistence.** A liveness session is ephemeral, time-boxed
  (`expires_at`), and never cached to disk. Signaling envelopes and SDP/ICE are
  in-memory only (AND-290 policy). The only persisted artifact is the cookie jar
  (AND-011), reused so signaling + KYC HTTP share the live session.
- **Source of truth:** `LivenessCoordinator.state: StateFlow<LivenessSessionState>`
  is derived by `combine`-ing `RtcPeerConnection.state` (AND-289),
  `SignalingClient.state` (AND-290), and the liveness verdict (control message
  or poll). The ViewModel layers permission state on top to produce
  `LivenessUiState`.
- **`SavedStateHandle`:** stores `session_id` + `peer_id` so a configuration
  change (rotation) re-attaches to the *coordinator* (a `@ViewModelScoped`/
  retained singleton for the flow) without restarting the call; if the process
  is killed, the session is treated as abandoned on relaunch (no resume).
- **Verdict reconciliation:** the control-message verdict and the poll verdict
  must agree; the coordinator takes the first terminal signal and confirms it
  with one `livenessStatus` GET before showing `Result` (so a spoofed control
  message can't fake a pass — §8).
- **KYC status refresh:** on `passed`, `kycRepository.refreshMe()` invalidates
  the cached `KycMeResp` (owned by the KYC repository ticket) so the requirements
  screen re-renders `satisfied`.

## 7. Error Handling & Resilience

- **Timeouts:** ~20s connect/read on all liveness HTTP calls (AND-009). The poll
  loop uses `livenessStatus` with bounded exponential backoff (full jitter,
  `BASE=1s`, `MAX=8s`) — idempotent GET only (AND-016). `startLiveness` /
  `cancelLiveness` (POST, non-idempotent) are **not** retried automatically;
  `start` connection-level failures surface `Error(recoverable = true)` for a
  user-driven retry.
- **Negotiation timeout:** AND-289's `RtcConfig.negotiationTimeoutMs` (20s)
  bounds offer→`Connected`; on timeout → `Error(KycError.MediaTimeout,
  recoverable = true)` and full teardown (BYE + close).
- **ICE / connection loss:** `RtcSessionState.Disconnected(recoverable = true)`
  shows a transient "reconnecting" overlay while signaling reconnects (AND-290
  backoff); `Disconnected(recoverable = false)` or `Failed` → tear down and
  offer retry (counts against `max_attempts`).
- **Signaling degrade:** SSE→poll degrade (AND-290) is invisible to the user;
  the call surface shows a subtle "connection unstable" hint only when
  `SignalingState.Degraded`.
- **401:** handled once by the shared `Authenticator` (AND-013); a second 401
  ends the session with `Error(AuthExpired)` and routes to login (AND-025).
- **Verdict path failure:** if the control message never arrives, the poll loop
  is the fallback; if both stall past `expires_at`, the session →
  `Result(EXPIRED)`.
- **`409` on start:** "a verification is already in progress" → reconcile by
  GETting the existing session if its id is recoverable, else surface a clear
  retry-later error. Attempts-exhausted `409` → non-recoverable
  `Error(KycError.AttemptsExhausted)`.
- **Idempotent teardown:** `shutdown()` is guarded by an `AtomicBoolean`; double
  cancel/close is a no-op; `onCleared()` always tears down.

```kotlin
sealed interface KycError {                       // shared with AND-323 where overlapping
    data object AuthExpired : KycError
    data object MediaTimeout : KycError
    data object VerifierUnavailable : KycError    // 503
    data object AttemptsExhausted : KycError      // 409
    data class  Transport(val httpCode: Int?) : KycError
    data class  Unknown(val message: String?) : KycError
}
```

## 8. Security & Privacy

- **Biometric sensitivity.** Live face/voice video is highly sensitive biometric
  PII. Media is **never** persisted by the app (no recording, no frame capture to
  disk, no screenshot of the call surface — set `FLAG_SECURE` on the liveness
  Activity/window). Media is consumed only by the WebRTC stream and discarded.
- **Media encryption.** WebRTC media is DTLS-SRTP encrypted end-to-end by
  libwebrtc default (AND-289 §8); even on the plaintext dev host the *media* is
  encrypted. **Signaling** (SDP/ICE, which leak local IPs) is plaintext on the
  dev host — a known dev-only risk gated by the scoped
  `network_security_config.xml` cleartext entry (AND-006/AND-290); production is
  HTTPS-only.
- **Anti-spoof of the verdict.** A `passed` verdict is trusted only after
  confirmation via the authenticated `GET /v1/kyc/liveness/{id}` (server-side
  truth), not from the in-call control message alone — the control channel is
  routing convenience, the HTTP GET is authority (§6). The server enforces that
  the session belongs to the caller's authenticated principal; the client sends
  no user id in liveness paths.
- **Auth:** all `/v1/kyc/liveness/*` ride session cookies + `X-CSRF-Token` on
  mutating POSTs; no bearer tokens or app-stored secrets. TURN credentials in
  `ice_servers[].credential` are ephemeral, never logged, never persisted.
- **Permissions:** `CAMERA` and (when `require_audio`) `RECORD_AUDIO`, requested
  via AND-323's gate; denied → `NeedsPermission` with a rationale, never a crash.
- **Redaction:** SDP/ICE/candidate strings, TURN credentials, and any score are
  excluded from logs (lengths/types only — §10).

## 9. Accessibility & i18n

- **Prompts must be accessible.** Each `LivenessPrompt.instruction` is rendered
  as visible text **and** announced via TalkBack (`liveError`/live region
  `Modifier.semantics { liveRegion = LiveRegionMode.Assertive }`) so a low-vision
  user hears each step. Prompt timers expose remaining time as content
  description, not color alone.
- **Localization.** Prompt copy is backend-supplied (`instruction`) and rendered
  verbatim *only when no local key exists*; preferred path is to map
  `LivenessPrompt.kind` (`PromptKind`) → a localized `R.string.liveness_prompt_*`
  in `feature-kyc` so prompts honor device locale and RTL. All UI chrome
  ("Connecting…", "Verification passed", "Cancel", error copy) are string
  resources — no hard-coded English. Numbers in `read_number` prompts use
  locale-aware formatting.
- **Touch targets / focus:** Cancel and mic-toggle buttons ≥48dp with content
  descriptions; the call surface itself is decorative for a11y but the status and
  prompt overlays carry the semantic state.
- **Captions/agent mode:** in `agent` mode, surface a text status for
  Deaf/hard-of-hearing users ("An agent has joined") since the interaction is
  otherwise audio/visual.

## 10. Telemetry & Logging

- **Events** (shared analytics seam / `KycMetrics`, no new SDK):
  `liveness_start{mode, requirementKey, requireAudio}`,
  `liveness_connect_result{result: connected|timeout|failed, durationMs, attempt}`,
  `liveness_prompt{promptKind, result: ok|timeout|skip, ms}`,
  `liveness_transport_switch{from, to}` (from AND-290),
  `liveness_complete{verdict, attemptsUsed, totalMs}`,
  `liveness_error{code, httpCode}`.
- **Redaction (strict):** never log media, SDP, ICE candidates, TURN
  credentials, `score`, or any biometric data. Log `session_id`/`peer_id` as
  short ids; prompt `kind` (not free-text instruction); verdict as the enum.
- **Levels:** state transitions at `DEBUG`; degrade/reconnect/timeout at
  `INFO`/`WARN`; auth/verifier failures at `ERROR`. No raw frame or signaling
  logging in release builds.

## 11. Testing Strategy

**Unit (JVM, `core-testing` fakes):**
- T-1 Coordinator happy path with a **fake signaling** (`InMemorySignalingTransport`,
  AND-289/290) + a fake `RtcPeerConnection` that reports `Connected`: `start()`
  → POST observed → offer sent → state reaches `InCall` → control
  `liveness_result: passed` → one confirming `livenessStatus` GET → `refreshMe()`
  called → `Result(PASSED)`.
- T-2 Verdict authority: a spoofed control `passed` whose confirming GET returns
  `verdict: failed` yields `Result(FAILED)` (GET is authoritative).
- T-3 Poll fallback: no control message arrives; poll loop transitions
  `in_progress → completed(passed)` with bounded backoff (assert backoff schedule,
  idempotent GET only).
- T-4 Negotiation timeout: fake peer never reaches `Connected` →
  `Error(MediaTimeout, recoverable)` and teardown (BYE sent, `close()` called).
- T-5 Cancel: `cancel()` calls `/cancel`, sends `BYE`, closes peer + signaling;
  idempotent (double cancel is a no-op).
- T-6 `409` attempts-exhausted on start → `Error(AttemptsExhausted,
  recoverable=false)`; `503` → `VerifierUnavailable`.
- T-7 401 path: first call 401 → refresh stub 200 → retried once; second 401 →
  `Error(AuthExpired)`.
- T-8 Lifecycle: `onStop` pauses; resume within `RESUME_GRACE_MS` keeps the
  session; beyond grace → abandoned + teardown.

**MockWebServer (`core-network`):**
- T-9 `startLiveness` issues `POST /v1/kyc/liveness/start` with body + CSRF;
  decodes `mode`, `prompts`, `ice_servers`. `livenessStatus` →
  `GET /v1/kyc/liveness/{id}`; `cancelLiveness` → POST `/cancel`. Snake_case +
  enum-`UNKNOWN` fallback (mirrors AND-319 round-trip tests, committed fixtures
  under `core-model/src/test/resources/kyc/liveness/`).

**Compose UI (`feature-kyc` androidTest):**
- T-10 `LivenessCallScreen` renders permission gate → `Connecting` spinner →
  `InCall` with prompt overlay + step indicator → `Result` card; TalkBack live
  region announces prompt changes; Cancel invokes `viewModel.cancel()`.

**Instrumented / staged (acceptance):**
- E-1 Against a staged backend (or the `frontend/` web app acting as the
  verifier), an emulator starts a liveness session, the call reaches
  `Connected`, prompts are completed, and a terminal verdict is returned and
  shown — the source acceptance "Liveness session connects + completes". Flaky
  dev host mitigated by treating E-1 as confirmatory with T-1..T-9 as the gate.

Coverage gate: ≥80% line coverage on `DefaultLivenessCoordinator` and the
ViewModel mapping (non-DI, non-UI-surface code).

## 12. Dependencies & Sequencing

- **AND-290 (Signaling transport) — hard dep.** Provides `SignalingClient` and
  the `/signal` SSE/poll relay used to negotiate the call and to carry liveness
  control messages. Transitively pulls AND-289 (PeerConnection wrapper) and the
  WebRTC stack (AND-288). AND-324 can be built against `InMemorySignalingTransport`
  but cannot be *accepted* without a real signaling round-trip (E-1).
- **AND-323 (Facial comparison) — hard dep.** Provides the camera permission
  gate, front-camera preview plumbing, and the KYC requirement/`KycRepository`
  entry point that AND-324 reuses; the two are alternative requirement satisfiers
  and must share the gate + status-refresh path rather than duplicate them.
- **Transitive:** AND-319 (`KycApi` + KYC DTO/enum conventions; AND-324 *adds*
  the three liveness methods to it), AND-291 (TURN/STUN — soft; `ice_servers`
  fallback in the start response if absent), AND-015/016/018 (error map, backoff,
  `ApiResult`), AND-025 (auth-gated routing), AND-022 (nav host).
- **Sequencing within the ticket:** (1) confirm `/v1/kyc/liveness/*` against
  `/openapi.json` + `frontend/src/api/endpoints/kyc.ts` (OQ-1); (2) add liveness
  DTOs/methods to `KycApi` + round-trip tests (T-9); (3) build
  `DefaultLivenessCoordinator` against fakes (T-1..T-8); (4) `LivenessCallViewModel`
  + `LivenessCallScreen` (T-10); (5) staged E-1.
- **Blocks:** none in the source backlog (leaf of the KYC liveness sub-flow).

## 13. Risks & Open Questions

- **OQ-1 (highest):** Do `/v1/kyc/liveness/start`, `/{id}`, and `/{id}/cancel`
  exist with these shapes, and is the verifier driven by automated prompts vs. a
  human agent (or both)? Confirm against `/openapi.json` and
  `frontend/src/api/endpoints/kyc.ts`. If the backend uses a third-party liveness
  SDK (e.g. a hosted vendor) instead of a raw WebRTC call, the *transport* changes
  substantially while the screen/ViewModel contract can largely stand — **resolve
  before coding**.
- **OQ-2:** Are liveness prompts/verdict delivered over the `/signal` control
  channel, over the HTTP poll, or both? The design supports both with HTTP as the
  verdict authority; confirm which is canonical to avoid dead code.
- **OQ-3:** Is `ice_servers` sourced from the liveness start response or from
  AND-291's credential endpoint? Determines whether AND-291 is a hard dep.
  Current assumption: start-response fallback, AND-291 preferred when available.
- **OQ-4:** `max_attempts` / cooldown semantics and whether a `failed` verdict
  permits immediate retry or imposes a backoff window (server-enforced).
- **R-1:** Unreliable plaintext dev host makes E-1 flaky; mitigated by fakes
  (T-1..T-9) as the gate and E-1 as confirmatory.
- **R-2:** WebRTC on emulators can be unstable (camera/codec); CI runs the
  coordinator/ViewModel tests with fakes, and E-1 is run on a physical device or
  a webrtc-capable emulator profile.
- **R-3:** Biometric privacy — accidental media persistence or logging.
  Mitigated by `FLAG_SECURE`, no recording path, and strict §10 redaction
  (verified by code review).
- **R-4:** Verdict spoofing via the control channel — mitigated by the HTTP-GET
  authority rule (§6/§8, T-2).

## 14. Acceptance Criteria

- **AC-1 (source acceptance).** From the KYC requirements screen the user starts
  a liveness session, the WebRTC call reaches `RtcSessionState.Connected`, prompts
  are completed, and a terminal verdict is returned and displayed — proven in the
  staged E-1 run; "Liveness session connects + completes."
- **AC-2.** `LivenessCallViewModel.uiState` traverses `Idle/NeedsPermission →
  Starting → Connecting → InCall → Result`, and `Error` on failure, observable as
  a `StateFlow` (T-1, T-10).
- **AC-3.** `startLiveness` posts to `POST /v1/kyc/liveness/start` with cookies +
  `X-CSRF-Token`; `livenessStatus` is the idempotent `GET /v1/kyc/liveness/{id}`;
  `cancelLiveness` POSTs `/cancel`; all DTOs (de)serialize the §5 JSON exactly
  with snake_case keys and `UNKNOWN` enum fallback (T-9).
- **AC-4.** SDP/ICE are exchanged via AND-290 signaling (Offerer role), and
  liveness control messages are parsed without being forwarded to the
  PeerConnection (T-1).
- **AC-5.** A `passed` verdict is shown **only** after confirmation by the
  authenticated status GET, then `KycApi.me()` is refreshed so the requirement
  shows `satisfied` (T-1, T-2).
- **AC-6.** Negotiation timeout, ICE failure, `409` attempts-exhausted, `503`
  verifier-unavailable, and double-401 each map to the correct `KycError` and
  always tear the session down (BYE + `close()`, idempotent) (T-4..T-7).
- **AC-7.** Cancel and lifecycle abandon both tear down cleanly; no media is
  recorded/persisted; the window is `FLAG_SECURE`; no SDP/ICE/credential/score is
  logged (T-5, T-8; code-review verified).
- **AC-8.** Prompts are announced to TalkBack and localized via `PromptKind` →
  string resources; all UI chrome is string-resourced and RTL-safe (T-10).

## 15. Definition of Done

- `LivenessCallScreen`, `LivenessCallViewModel`, `LivenessUiState`, and
  `DefaultLivenessCoordinator` implemented under
  `com.testlogon.android.feature.kyc.liveness` / `core.data.kyc`, building on
  Kotlin 2.0.21 / AGP 8.7.3 / Gradle 8.9 / JDK 17 with Hilt+KSP, layering
  respected (`feature-kyc -> core-data/-network/-webrtc/-signaling/-model/-ui`).
- The three liveness methods + DTOs are added to `KycApi`/`core-model` (AND-319
  conventions), reconciled with `/openapi.json` (OQ-1..OQ-3 resolved and recorded
  in the PR).
- All §11 unit + MockWebServer + Compose tests green; ≥80% coverage on the
  coordinator/ViewModel; staged E-1 demonstrated and captured (recording/log
  linked in the PR).
- Signaling/PeerConnection consumed via the existing AND-289/290 APIs (no
  duplication of WebRTC or signaling logic); camera-gate + KYC refresh shared with
  AND-323.
- `FLAG_SECURE` set; no media recording path; telemetry emitted with strict
  redaction; cleartext scoped to the dev host only.
- All prompts/UI strings localized + a11y-announced; no hard-coded English.
- Code review approved on `android-port`; no new lint/Detekt errors; public
  coordinator/ViewModel API KDoc'd.
