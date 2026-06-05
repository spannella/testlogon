---
id: AND-289
title: PeerConnection wrapper + lifecycle
milestone: M7
epic: E39
priority: P0
size: L
status: draft
depends_on: [AND-288]
blocks: [AND-290]
---

# AND-289 — PeerConnection wrapper + lifecycle

## 1. Overview & Goal

Provide a Kotlin-idiomatic wrapper around the native `org.webrtc.PeerConnection`
(supplied by the `webrtc-android` dependency wired in AND-288) that owns the full
WebRTC offer/answer/ICE negotiation cycle and the deterministic teardown of all
native resources. This ticket delivers a `core-webrtc` module abstraction —
`RtcPeerConnection` plus a `RtcPeerConnectionFactory` — that exposes the
callback-driven libwebrtc API as suspend functions and a single
`StateFlow<RtcSessionState>`, so that higher layers (signaling in AND-290, the
call/broadcast feature) never touch the raw libwebrtc threading model.

Out of scope: actual signaling transport over the backend `/signal` endpoint
(owned by AND-290), media capture/render surface construction (camera/mic
permission + capturer come from AND-288), and any UI. The deliverable is proven
when an in-process test harness runs two `RtcPeerConnection` instances against
each other and an offer → answer → ICE-candidate exchange drives both to
`RtcSessionState.Connected`.

## 2. Context & References

- **Module:** new `core-webrtc` under the `core-*` layer
  (`com.testlogon.android.core.webrtc`). Layering rule: `app -> feature-* ->
  core-*`; `core-webrtc` may depend on `core-model` and `core-testing` only.
  It must NOT depend on `core-network` — signaling is injected as an interface.
- **Upstream (AND-288):** `webrtc-android` artifact, `EglBase` provisioning,
  `CAMERA`/`RECORD_AUDIO` runtime permissions, loopback sample. This ticket
  consumes the `EglBase.Context` and `PeerConnectionFactory` bootstrap done
  there.
- **Downstream (AND-290):** signaling transport. AND-289 defines the
  `SignalingPort` SAM interface and the local-SDP/local-ICE callbacks that
  AND-290 will pump over `/signal` (SSE/poll). This ticket includes a fake
  in-memory transport in `core-testing` to satisfy acceptance without a backend.
- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP) for DI, JDK 17, minSdk
  24 / compileSdk 35, Gradle 8.9 / AGP 8.7.3.
- **Note:** WebRTC negotiation is peer-to-peer and does not transit FastAPI
  except for the signaling relay; the unreliable dev host
  (`http://18.222.237.167:8000`) is irrelevant to this module's correctness.

## 3. Functional Requirements

FR-1. **Factory.** `RtcPeerConnectionFactory.create(config)` returns a fully
initialized `RtcPeerConnection` bound to a single negotiation session, reusing
the shared `PeerConnectionFactory` and `EglBase.Context` from AND-288.

FR-2. **Offerer role.** `createOffer()` generates a local SDP offer, calls
`setLocalDescription`, and emits the resulting SDP via `localDescriptions`
Flow / `SignalingPort.onLocalSessionDescription`.

FR-3. **Answerer role.** `setRemoteDescription(offer)` followed by
`createAnswer()` produces and sets a local answer and emits it the same way.

FR-4. **ICE.** Locally gathered `IceCandidate`s are emitted as
`RtcIceCandidate`; remote candidates are accepted via `addIceCandidate(...)`.
Candidates received before the remote description is set MUST be buffered and
flushed after `setRemoteDescription` succeeds (ICE-before-SDP race).

FR-5. **State.** A single `StateFlow<RtcSessionState>` reflects the merged
peer-connection state (signaling + ICE connection + PeerConnection state),
collapsed into a small sealed hierarchy (see §6).

FR-6. **Teardown.** `close()` is idempotent, disposes the `PeerConnection`,
detaches all observers, cancels the internal coroutine scope, and transitions
state to `Closed`. After `close()`, every public suspend method fails fast with
`IllegalStateException` / `RtcException.Closed`.

FR-7. **Renegotiation guard (MVP).** Concurrent `createOffer`/`createAnswer`
calls are serialized via an internal `Mutex`; `onRenegotiationNeeded` is surfaced
as a state/event but auto-renegotiation is explicitly deferred to a later ticket.

## 4. Technical Design

New module `core-webrtc`. All public types in
`com.testlogon.android.core.webrtc`.

### 4.1 Public API

```kotlin
package com.testlogon.android.core.webrtc

interface RtcPeerConnectionFactory {
    fun create(config: RtcConfig, signaling: SignalingPort): RtcPeerConnection
}

class RtcConfig(
    val iceServers: List<RtcIceServer> = emptyList(),
    val role: RtcRole,                       // Offerer | Answerer
    val enableAudio: Boolean = true,
    val enableVideo: Boolean = true,
    val negotiationTimeoutMs: Long = 20_000, // bound the gathering/answer wait
)

enum class RtcRole { Offerer, Answerer }

data class RtcIceServer(val urls: List<String>, val username: String? = null, val credential: String? = null)

interface RtcPeerConnection : AutoCloseable {
    val state: StateFlow<RtcSessionState>

    suspend fun createOffer(): RtcSessionDescription            // Offerer only
    suspend fun setRemoteDescription(sdp: RtcSessionDescription)
    suspend fun createAnswer(): RtcSessionDescription           // Answerer only
    suspend fun addIceCandidate(candidate: RtcIceCandidate)

    override fun close()   // idempotent, synchronous, disposes native refs
}

// Emitted locally; consumed by AND-290.
interface SignalingPort {
    fun onLocalSessionDescription(sdp: RtcSessionDescription)
    fun onLocalIceCandidate(candidate: RtcIceCandidate)
}
```

### 4.2 Value types (in `core-model` or `core-webrtc`)

```kotlin
data class RtcSessionDescription(val type: SdpType, val sdp: String)   // OFFER | ANSWER | PRANSWER
data class RtcIceCandidate(val sdpMid: String?, val sdpMLineIndex: Int, val candidate: String)
```

### 4.3 Threading & coroutine bridge

libwebrtc is callback-driven and threading-sensitive: native callbacks arrive on
the signaling thread and `PeerConnection` methods must be invoked off the main
thread. The implementation:

- Owns a `CoroutineScope(SupervisorJob() + singleThreadDispatcher)` where
  `singleThreadDispatcher` is `Executors.newSingleThreadExecutor { "rtc-pc" }
  .asCoroutineDispatcher()`. All native `PeerConnection` mutations run on this
  dispatcher to serialize access.
- `createOffer/createAnswer/setLocalDescription/setRemoteDescription` wrap the
  `SdpObserver` callbacks in `suspendCancellableCoroutine`. Helper:

```kotlin
private suspend fun PeerConnection.createOfferAwait(c: MediaConstraints): SessionDescription =
    suspendCancellableCoroutine { cont ->
        createOffer(object : SdpObserver {
            override fun onCreateSuccess(sdp: SessionDescription) = cont.resume(sdp)
            override fun onCreateFailure(err: String?) =
                cont.resumeWithException(RtcException.SdpFailed(err.orEmpty()))
            override fun onSetSuccess() {}
            override fun onSetFailure(err: String?) {}
        }, c)
    }
```

- The libwebrtc `PeerConnection.Observer` is adapted into internal `MutableSharedFlow`s
  (`onIceCandidate`, `onIceConnectionChange`, `onConnectionChange`,
  `onSignalingChange`, `onRenegotiationNeeded`) which are merged into `state` via
  `combine`/`stateIn(scope)`.

### 4.4 ICE buffering

```kotlin
private val pendingRemoteCandidates = ArrayDeque<RtcIceCandidate>()
private var remoteDescriptionSet = false   // guarded by the rtc dispatcher
```

`addIceCandidate` enqueues if `!remoteDescriptionSet`; `setRemoteDescription`
sets the flag then drains the deque.

### 4.5 Hilt wiring

```kotlin
@Module @InstallIn(SingletonComponent::class)
abstract class WebRtcModule {
    @Binds abstract fun bindFactory(impl: DefaultRtcPeerConnectionFactory): RtcPeerConnectionFactory
}
```

`DefaultRtcPeerConnectionFactory` `@Inject`s the shared `PeerConnectionFactory`
and `EglBase` provided by AND-288's module.

## 5. API Contract

No HTTP/REST contract is owned by this ticket. WebRTC negotiation is peer-to-peer;
the only "wire" artifacts are the SDP/ICE payloads that AND-290 will serialize to
the backend `/signal` endpoint. For forward compatibility, this ticket fixes the
JSON shape that `RtcSessionDescription`/`RtcIceCandidate` MUST serialize to so
AND-290 can adopt it without changing model classes:

```json
// session description
{ "type": "offer", "sdp": "v=0\r\no=- 46117341 2 IN IP4 127.0.0.1\r\n..." }

// ice candidate
{ "sdpMid": "0", "sdpMLineIndex": 0, "candidate": "candidate:842163049 1 udp 1677729535 ..." }
```

`type` is the lowercase libwebrtc SDP type (`offer`|`answer`|`pranswer`).
Moshi adapters for these two types are provided in `core-webrtc` and reused by
AND-290. The actual `POST /signal` request/response envelope (challenge_id /
session correlation, CSRF via `X-CSRF-Token`, SSE framing) is **defined and
owned by AND-290** and is N/A here.

## 6. Data & State Management

`RtcSessionState` is the single source of truth for the negotiation lifecycle:

```kotlin
sealed interface RtcSessionState {
    data object Idle : RtcSessionState                 // factory created, no offer/answer yet
    data object Negotiating : RtcSessionState          // creating/exchanging SDP
    data object IceGathering : RtcSessionState          // local description set, gathering candidates
    data object Connecting : RtcSessionState            // ICE checking
    data object Connected : RtcSessionState             // PeerConnectionState.CONNECTED
    data class  Disconnected(val recoverable: Boolean) : RtcSessionState // ICE disconnected/failed
    data object Closed : RtcSessionState                // disposed
    data class  Failed(val error: RtcException) : RtcSessionState
}
```

Mapping rules:
- `PeerConnection.PeerConnectionState.CONNECTED` → `Connected`.
- `IceConnectionState.DISCONNECTED` → `Disconnected(recoverable = true)`;
  `FAILED`/`PeerConnectionState.FAILED` → `Disconnected(recoverable = false)`.
- `SignalingState.HAVE_LOCAL_OFFER`/`HAVE_REMOTE_OFFER` → `Negotiating`.

State is exposed as a hot `StateFlow` via `stateIn(scope, SharingStarted.Eagerly,
RtcSessionState.Idle)`. There is no persistence: a WebRTC session is ephemeral
and is not written to Room or DataStore. No cache, no Paging — negotiation state
lives only in-memory for the session lifetime and is reconstructed from a fresh
factory call after teardown.

## 7. Error Handling & Resilience

Errors funnel through a sealed `RtcException`:

```kotlin
sealed class RtcException(msg: String, cause: Throwable? = null) : Exception(msg, cause) {
    class SdpFailed(detail: String) : RtcException("SDP op failed: $detail")
    class SetDescriptionFailed(detail: String) : RtcException("setDescription failed: $detail")
    class IceFailed(detail: String) : RtcException("ICE failed: $detail")
    class NegotiationTimeout : RtcException("Negotiation exceeded timeout")
    object Closed : RtcException("PeerConnection is closed")
}
```

- **Timeout:** `createOffer`/`createAnswer` and the gather-to-`Connecting`
  transition are wrapped in `withTimeout(config.negotiationTimeoutMs)`
  (default 20s, matching the project-wide bounded-wait convention). Timeout →
  `Failed(NegotiationTimeout)` and an automatic `close()`.
- **ICE failure:** `IceConnectionState.FAILED` → `Disconnected(recoverable=false)`;
  the wrapper does NOT auto-restart ICE in this ticket (ICE-restart is a future
  ticket); it surfaces state so the caller can re-create the session.
- **Idempotent teardown:** double `close()` is a no-op; native disposal is
  guarded by an `AtomicBoolean disposed`. Calls after close throw
  `RtcException.Closed` rather than crashing on freed native pointers.
- **Cancellation:** all suspend ops are cooperative — coroutine cancellation
  cancels the underlying `suspendCancellableCoroutine` and leaves the
  `PeerConnection` in a consistent state (no half-applied descriptions because
  the rtc dispatcher serializes mutations).
- No retry/backoff here — that belongs to the signaling layer (AND-290), and
  only for idempotent GETs per project policy.

## 8. Security & Privacy

- **Permissions:** `CAMERA` and `RECORD_AUDIO` are requested/enforced by AND-288;
  `create()` assumes they are already granted and fails fast with a clear
  message if the capturer is unavailable. No new manifest permissions are added
  here beyond `INTERNET` (already present).
- **DTLS-SRTP:** media is encrypted by libwebrtc default (DTLS-SRTP, mandatory);
  no plaintext media path. SDP is exchanged out-of-band via signaling and must
  travel over the secure signaling channel owned by AND-290.
- **No secrets logged:** SDP and ICE candidate strings can leak local network
  topology (host IP candidates) and MUST NOT be logged at INFO in release
  builds; see §10. TURN credentials in `RtcIceServer.credential` are never
  logged.
- **No PII storage:** nothing from a session is persisted.
- This module performs no auth; it consumes already-authenticated signaling
  injected by AND-290 (cookie/CSRF session handling stays in `core-network`).

## 9. Accessibility & i18n

No UI surface in this ticket — Compose, content descriptions, TalkBack, and
RTL/locale concerns are N/A and are owned by the call/broadcast feature ticket
that renders the video surface. The only user-visible artifacts are error
states, which are exposed as typed `RtcException`/`RtcSessionState` values (not
strings); the consuming feature module is responsible for mapping them to
localized strings in its `strings.xml`. No hardcoded user-facing copy is
introduced here.

## 10. Telemetry & Logging

- Use a tagged logger `Log.d("RtcPeerConnection", ...)` gated on `BuildConfig.DEBUG`.
- Lifecycle transitions (`RtcSessionState` changes) logged at DEBUG only.
- **Redaction:** SDP bodies and ICE candidate strings are logged only in debug
  builds and only as a length + type summary (e.g. `"local offer sdp len=2143"`),
  never the full candidate string, to avoid leaking host IPs.
- Counters/timers to emit (via the app's existing analytics seam, no new SDK):
  `rtc_negotiation_duration_ms` (offer start → `Connected`),
  `rtc_negotiation_result` (`connected`|`timeout`|`failed`),
  `rtc_ice_candidates_local` / `rtc_ice_candidates_remote` counts. These are
  emitted through a `RtcMetrics` interface injected via Hilt, with a no-op
  default so the module stays testable and decoupled.

## 11. Testing Strategy

Primary acceptance vehicle is an **in-process loopback harness** in
`core-webrtc` `androidTest` (libwebrtc requires the Android runtime; these are
instrumented tests, not pure JVM unit tests).

- `RtcLoopbackTest` (androidTest):
  1. Build a fake `SignalingPort` that cross-wires two `RtcPeerConnection`
     instances (offerer + answerer) on a test dispatcher.
  2. `offerer.createOffer()` → fake forwards SDP to `answerer.setRemoteDescription`
     → `answerer.createAnswer()` → forwarded back → ICE candidates relayed both
     ways (verifying the ICE-before-SDP buffering path by deliberately
     delivering one candidate early).
  3. Assert both `state` flows reach `RtcSessionState.Connected` within the
     timeout using `Turbine` (`app.cash.turbine`) on the `StateFlow`.
- `RtcTeardownTest`: assert `close()` is idempotent, post-close calls throw
  `RtcException.Closed`, and no native objects are double-disposed (assert no
  crash + state == `Closed`).
- `RtcTimeoutTest`: inject a `SignalingPort` that drops the answer; assert
  `Failed(NegotiationTimeout)` and auto-close after `negotiationTimeoutMs`
  (use a short test timeout).
- `RtcSerializationTest` (JVM unit): Moshi round-trip of `RtcSessionDescription`
  and `RtcIceCandidate` matches the §5 JSON shapes.
- The reusable fake (`InMemorySignalingTransport`) lives in `core-testing` so
  AND-290 can reuse it.
- Coverage target: every public method of `RtcPeerConnection` and every
  `RtcSessionState` transition exercised.

## 12. Dependencies & Sequencing

- **Depends on AND-288** (`webrtc-android` integration + permissions): provides
  `PeerConnectionFactory`, `EglBase`, the artifact on the classpath, and granted
  camera/mic permissions. AND-289 cannot start until AND-288's loopback sample
  renders.
- **Blocks AND-290** (Signaling transport): AND-290 implements `SignalingPort`
  over backend `/signal` (SSE/poll) and reuses the SDP/ICE Moshi adapters and
  the `InMemorySignalingTransport` fake defined here.
- Transitively part of milestone **M7**, epic **E39** (real-time/WebRTC).
- No dependency on `core-network` or the feature layer. New Gradle module
  `core-webrtc` must be registered in `settings.gradle.kts` and the version
  catalog entries for `webrtc-android` and `app.cash.turbine` confirmed present
  (added by AND-288 for the former).

## 13. Risks & Open Questions

- **R1 — Threading correctness:** misuse of the libwebrtc signaling thread vs.
  the wrapper's single-thread dispatcher can cause deadlocks or native crashes.
  Mitigation: all native mutations confined to one dispatcher; observers only
  publish to flows, never call back into the PeerConnection synchronously.
- **R2 — Native resource leaks:** failing to `dispose()` the `PeerConnection`,
  tracks, or sources leaks native memory. Mitigation: `AutoCloseable` + idempotent
  `close()` + leak assertions in `RtcTeardownTest`.
- **R3 — ICE timing race:** remote candidates arriving before remote SDP. Handled
  by the buffering deque (FR-4) and explicitly tested.
- **OQ1:** Do we need an explicit `restartIce()` / ICE-restart path in MVP, or
  defer to a follow-up? Current assumption: defer; surface non-recoverable
  `Disconnected` and let the caller recreate.
- **OQ2:** STUN/TURN server list source — hardcoded dev STUN vs. fetched from
  backend config? Assumed injected via `RtcConfig.iceServers`; population is
  AND-290's concern.
- **OQ3:** Unified-plan vs. plan-B SDP semantics — assume unified-plan
  (libwebrtc default); confirm no legacy peers.

## 14. Acceptance Criteria

AC-1. A new `core-webrtc` Gradle module exists under
`com.testlogon.android.core.webrtc`, builds with the project toolchain
(Kotlin 2.0.21 / AGP 8.7.3 / JDK 17), and depends only on `core-model` +
`core-testing`.

AC-2. `RtcPeerConnectionFactory.create(...)` returns a working
`RtcPeerConnection` using the shared factory/EGL context from AND-288.

AC-3. **(Source acceptance)** The instrumented loopback harness drives two
wrapped peers through a full offer → answer → ICE-candidate cycle and both
`state` flows reach `RtcSessionState.Connected`. Test passes in CI.

AC-4. Remote ICE candidates delivered before `setRemoteDescription` are buffered
and applied afterward (covered by a passing test).

AC-5. `close()` is idempotent; post-close public calls throw
`RtcException.Closed`; no native double-dispose crash (passing teardown test).

AC-6. A negotiation that never receives an answer transitions to
`Failed(NegotiationTimeout)` and auto-closes within `negotiationTimeoutMs`.

AC-7. Moshi round-trip tests for `RtcSessionDescription` and `RtcIceCandidate`
match the §5 JSON shapes.

AC-8. No full SDP/ICE candidate strings are logged in release builds (verified by
code review of log sites; redaction summaries only).

## 15. Definition of Done

- All §14 acceptance criteria met and the AND-289 source acceptance
  ("Offer/answer/ICE cycle completes in a test harness") demonstrably passing in
  CI on the `android-port` branch.
- Public API (`RtcPeerConnection`, `RtcPeerConnectionFactory`, `SignalingPort`,
  `RtcConfig`, `RtcSessionState`, `RtcException`) is KDoc-documented and stable
  for AND-290 to build on.
- `InMemorySignalingTransport` fake and the SDP/ICE Moshi adapters are in
  `core-testing`/`core-webrtc` and reused by the tests.
- Hilt module `WebRtcModule` wires the factory; module registered in
  `settings.gradle.kts`.
- All new code passes ktlint/detekt and the module's lint baseline; no new lint
  errors.
- Instrumented tests (`RtcLoopbackTest`, `RtcTeardownTest`, `RtcTimeoutTest`) and
  JVM `RtcSerializationTest` green.
- No native leaks under repeated create/close (verified in teardown test).
- Code reviewed and merged; AND-290 unblocked.
