---
id: AND-289
title: PeerConnection wrapper + lifecycle
milestone: M7
epic: E39
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
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

Out of scope: actual signaling transport over the backend call-signaling
endpoint `POST /messaging/messages/calls/{call_id}/signal` (owned by AND-290;
the spec previously called this `/signal`, which does not exist as a top-level
path), media capture/render surface construction (camera/mic
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
  AND-290 will pump over `POST /messaging/messages/calls/{call_id}/signal`
  (the web client uses request/response POST, not SSE — `sendSignalingEvent`
  in `src/api/endpoints/messaging.ts` is a plain `api.post`; the SSE/poll
  delivery model is an unverified assumption, see §16). This ticket includes a fake
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
the backend call-signaling endpoint. For forward compatibility, this ticket fixes
the JSON shape that `RtcSessionDescription`/`RtcIceCandidate` MUST serialize to so
AND-290 can adopt it without changing model classes:

```json
// session description (RtcSessionDescription)
{ "type": "offer", "sdp": "v=0\r\no=- 46117341 2 IN IP4 127.0.0.1\r\n..." }

// ice candidate (RtcIceCandidate)
{ "sdpMid": "0", "sdpMLineIndex": 0, "candidate": "candidate:842163049 1 udp 1677729535 ..." }
```

`type` is the lowercase libwebrtc SDP type (`offer`|`answer`|`pranswer`).
Moshi adapters for these two types are provided in `core-webrtc` and reused by
AND-290.

> **Correction (verified against backend OpenAPI + web client).** These two
> JSON objects are NOT sent at the top level of the signaling request. The
> verified endpoint is `POST /messaging/messages/calls/{call_id}/signal`
> (op `send_signaling_event_...`, request schema `CallSignalingIn`, success
> `200:CallSignalingOut`). The backend `CallSignalingIn` envelope is:
>
> ```json
> {
>   "type": "webrtc.offer",            // pattern: webrtc.offer|webrtc.answer|
>                                      //   webrtc.ice_candidate|
>                                      //   webrtc.screen_share_start|
>                                      //   webrtc.screen_share_stop
>   "event_id": "<=128 chars",
>   "conversation_id": "<=128 chars",
>   "recipient_user_id": "<=128 chars",
>   "nonce": "8..128 chars",
>   "sent_at": 1717795200,             // integer (epoch)
>   "payload": { /* arbitrary object */ }
> }
> ```
>
> The two `RtcSessionDescription`/`RtcIceCandidate` JSON objects above belong
> INSIDE `payload`, and the discriminator is the envelope's `type`
> (`webrtc.offer` / `webrtc.answer` / `webrtc.ice_candidate`) — NOT the bare
> SDP `type` field. The success response `CallSignalingOut` is
> `{ event_id, call_id, conversation_id, event_type, delivered_to, status }`
> (`status` is `delivered`|`duplicate` per the web client). Envelope
> construction, `call_id`/`conversation_id`/`nonce` correlation, CSRF via
> `X-CSRF-Token`, and the `authorization` + `X-SESSION-ID` headers the endpoint
> declares are **defined and owned by AND-290** and remain N/A to this wrapper.
> This ticket only guarantees the `payload`-level SDP/ICE shapes shown above.
>
> TURN/STUN servers (referenced by `RtcConfig.iceServers` in §4) are issued by
> a separate endpoint `POST /messaging/messages/calls/{call_id}/turn-credentials`
> (`200:TurnCredentialsOut` = `{ ttl_seconds, expires_at, ice_servers[] }`,
> each `TurnIceServerOut` = `{ urls[], username, credential }`). That fetch is
> AND-290's responsibility; `RtcIceServer` in §4.1 already matches this shape
> (`urls`/`username`/`credential`).

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
  injected by AND-290. Auth/CSRF handling stays in `core-network`: the web
  client (`src/api/client.ts`) sends `Authorization: Bearer <token>`, an
  `X-CSRF-Token` header read from the `ui_csrf` cookie, and `credentials:
  "include"`. The signaling endpoints additionally declare `authorization` and
  `X-SESSION-ID` parameters in the OpenAPI index — AND-290 owns supplying these;
  none of it is handled in `core-webrtc`.

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
  over backend `POST /messaging/messages/calls/{call_id}/signal` (verified
  endpoint; delivery model SSE-vs-poll unconfirmed, see §16) plus
  `POST /messaging/messages/calls/{call_id}/turn-credentials`, and reuses the
  SDP/ICE Moshi adapters and the `InMemorySignalingTransport` fake defined here.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Claim:** The signaling transport endpoint is `/signal`.
   **VERDICT: Corrected.** No top-level `/signal` path exists. The verified
   endpoint is `POST /messaging/messages/calls/{call_id}/signal`.
   **Source:** OpenAPI `POST /messaging/messages/calls/{call_id}/signal`
   (op `send_signaling_event_messaging_messages_calls__call_id__signal_post`);
   `src/api/endpoints/messaging.ts: sendSignalingEvent`.

2. **Claim:** The wire JSON for a session description is
   `{ "type": "offer", "sdp": "..." }` sent at the top level.
   **VERDICT: Corrected.** That object is valid only INSIDE the envelope's
   `payload`. The request body is `CallSignalingIn` with required fields
   `type, event_id, conversation_id, recipient_user_id, nonce, sent_at` and an
   optional `payload` object; `type` is the envelope discriminator
   (`webrtc.offer|webrtc.answer|webrtc.ice_candidate|webrtc.screen_share_start|webrtc.screen_share_stop`).
   **Source:** OpenAPI schema `CallSignalingIn`; `src/api/endpoints/messaging.ts:
   SignalingPayload`.

3. **Claim:** The signaling response is an SSE-framed envelope with
   challenge_id / session correlation.
   **VERDICT: Corrected (partial) / Unverified-assumption (SSE).** The success
   response is `CallSignalingOut` =
   `{ event_id, call_id, conversation_id, event_type, delivered_to, status }`
   (`status` ∈ `delivered|duplicate` per the web client). There is no
   `challenge_id`. SSE framing is not evidenced — `sendSignalingEvent` is a
   plain request/response `api.post`. SSE/poll inbound delivery is an open
   assumption (see Open assumptions).
   **Source:** OpenAPI schema `CallSignalingOut`; `src/api/endpoints/messaging.ts:
   SignalingAck` and `sendSignalingEvent`.

4. **Claim:** STUN/TURN servers are injected via `RtcConfig.iceServers`;
   population is AND-290's concern (§13 OQ2).
   **VERDICT: Verified.** A dedicated endpoint issues them:
   `POST /messaging/messages/calls/{call_id}/turn-credentials` →
   `TurnCredentialsOut` = `{ ttl_seconds, expires_at, ice_servers[] }`, each
   `TurnIceServerOut` = `{ urls[], username, credential }`. The §4.1
   `RtcIceServer(urls, username, credential)` shape matches exactly.
   **Source:** OpenAPI `POST /messaging/messages/calls/{call_id}/turn-credentials`,
   schemas `TurnCredentialsOut` / `TurnIceServerOut`; `src/api/endpoints/messaging.ts:
   TurnIceServer`, `fetchTurnCredentials`.

5. **Claim:** Signaling is protected by CSRF via `X-CSRF-Token`.
   **VERDICT: Verified (and expanded).** The web transport sets `X-CSRF-Token`
   from the `ui_csrf` cookie, `Authorization: Bearer <token>`, and
   `credentials: "include"`. The signaling endpoints also declare
   `authorization` and `X-SESSION-ID` parameters.
   **Source:** `src/api/client.ts` (lines ~158-170, `getCookie("ui_csrf")` →
   `X-CSRF-Token`; `Authorization`; `credentials: "include"`); OpenAPI index
   `params=call_id,authorization,X-SESSION-ID` on the signal endpoint.

6. **Claim:** Media is encrypted by libwebrtc default (DTLS-SRTP, mandatory);
   no plaintext media path.
   **VERDICT: Verified (framework ref).** DTLS-SRTP is mandatory in WebRTC; SRTP
   keying is negotiated via DTLS and unencrypted RTP is not permitted.
   **Source:** framework ref — WebRTC security architecture
   (https://datatracker.ietf.org/doc/html/rfc8827, RFC 8827 "WebRTC Security
   Architecture"; DTLS-SRTP keying per RFC 5764).

7. **Claim:** libwebrtc is callback/threading-sensitive; `PeerConnection`
   mutations must be serialized off the signaling thread, and SDP/ICE callbacks
   arrive via `SdpObserver` / `PeerConnection.Observer`.
   **VERDICT: Verified (framework ref).** Matches the org.webrtc Android API
   (Observer/SdpObserver callback model; single-threaded access guidance).
   **Source:** framework ref — WebRTC Android (org.webrtc) native API docs
   (https://webrtc.github.io/webrtc-org/native-code/android/).

8. **Claim:** SDP type values are lowercase `offer|answer|pranswer`.
   **VERDICT: Verified (framework ref).** Matches `RTCSdpType`; libwebrtc
   `SessionDescription.Type` serializes to lowercase canonical form.
   **Source:** framework ref — `RTCSdpType` enum
   (https://www.w3.org/TR/webrtc/#dom-rtcsdptype).

9. **Claim:** Unified-plan is the libwebrtc default (§13 OQ3).
   **VERDICT: Verified (framework ref).** Plan-B was removed; Unified Plan is
   the only supported semantics in current libwebrtc / per spec.
   **Source:** framework ref — Unified Plan transition
   (https://www.w3.org/TR/webrtc/#rtcsdptype) and WebRTC project Plan-B
   deprecation notes.

10. **Claim:** The Android port serializes models with Moshi.
    **VERDICT: Verified (project convention, not frontend).** The frontend is
    TypeScript and has no Moshi; Moshi is the established Android-port choice in
    sibling specs (version catalog `moshi = "1.15.1"`, `core-network` uses
    Retrofit/Moshi).
    **Source:** `specs/AND-001-gradle-project-skeleton.md` (version catalog
    `moshi`, `retrofit-moshi`, `network` bundle); `specs/AND-003-core-module-structure.md`
    (Moshi codegen in `core-network`/AND-018).

11. **Claim:** The dev backend host is `http://18.222.237.167:8000` and is
    irrelevant to this peer-to-peer module (§2 Note).
    **VERDICT: Unverified-assumption (host) / Verified (irrelevance).** The host
    IP is an environment/build-server detail not present in frontend source
    (which resolves base URL from `VITE_API_BASE_URL`); its irrelevance to
    peer-to-peer media is sound since WebRTC media does not transit FastAPI.
    **Source:** `src/api/client.ts: API_BASE_URL` (env-derived);
    `specs/AND-003-core-module-structure.md` §16 note classifying the IP as an
    unverified Android-side assumption.

12. **Claim (framework choices, no external contract):** `core-webrtc` depends
    only on `core-model` + `core-testing`, uses Hilt (KSP) DI, Coroutines/Flow,
    a single-thread dispatcher for native access, `AutoCloseable` teardown,
    `suspendCancellableCoroutine` bridges, and `Turbine` for flow assertions.
    **VERDICT: Unverified-assumption (internal design).** These are
    AND-289-internal design decisions with no backend/frontend contract to
    verify against; they are consistent with the project's Kotlin/Hilt/Coroutines
    stack declared in §2 and sibling specs.
    **Source:** N/A external — internal design; stack corroborated by
    `specs/AND-001-gradle-project-skeleton.md` (Turbine, Hilt/KSP, Coroutines).

### Corrections made

- **§2 (Overview/Out of scope, Context):** replaced the non-existent `/signal`
  path with the verified `POST /messaging/messages/calls/{call_id}/signal`;
  reclassified "SSE/poll" delivery as an unverified assumption (the web client
  uses request/response POST).
- **§5 (API Contract):** added a correction block — the bare
  `{type,sdp}` / `{sdpMid,sdpMLineIndex,candidate}` objects live inside the
  `CallSignalingIn.payload`, not at the top level; documented the real envelope
  (`type` discriminator is `webrtc.offer|webrtc.answer|webrtc.ice_candidate`,
  plus `event_id/conversation_id/recipient_user_id/nonce/sent_at`), the
  `CallSignalingOut` response, removed the fictional `challenge_id`, and added
  the TURN-credentials endpoint/shape.
- **§8 (Security):** expanded the CSRF claim with the verified
  `Authorization: Bearer` + `X-CSRF-Token` (from `ui_csrf` cookie) +
  `credentials: "include"` transport, and the endpoint-declared `authorization`
  / `X-SESSION-ID` params.
- **§12 (Dependencies):** corrected the AND-290 signaling endpoint reference and
  added the TURN-credentials endpoint.

### Open assumptions

- **Inbound signaling delivery model (SSE vs. long-poll vs. WebSocket).** The
  outbound send is a verified POST, but how AND-290 receives the peer's SDP/ICE
  is not evidenced in the OpenAPI index or the web client snippets reviewed;
  only the POST send path is confirmed. Owned by AND-290.
- **Dev host `http://18.222.237.167:8000`.** Environment detail, not in frontend
  source; carried forward from sibling specs as unverified. Irrelevant to this
  module's correctness (peer-to-peer media).
- **Internal wrapper design** (dispatcher model, state-collapse mapping, Hilt
  binding, timeout semantics): no external contract exists to verify; treated as
  design decisions, not facts.
- **`PRANSWER` usage.** §4.2 lists `pranswer` as a valid SDP type; the call flow
  in scope (offer/answer) does not exercise it. Included for completeness; not
  required by the verified envelope.

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric unit (no device);
**EMU** = headless emulator AVD `test35` (x86_64, API 35); **DEV** = physical
Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, arm64-v8a, API 34).
libwebrtc requires the Android runtime, so any test that instantiates a real
`PeerConnection` is instrumented (EMU or DEV), never pure JVM.

- **TC-AND-289-01 — Happy-path loopback offer/answer/ICE to Connected**
  Type: instrumented/e2e (loopback harness).
  Target: EMU (`test35`).
  Preconditions: `core-webrtc` built; AND-288 `PeerConnectionFactory`+`EglBase`
  available; fake `InMemorySignalingTransport` cross-wires two peers.
  Steps: (1) create offerer + answerer via factory; (2) `offerer.createOffer()`;
  (3) fake forwards SDP → `answerer.setRemoteDescription`; (4)
  `answerer.createAnswer()` forwarded back to offerer; (5) relay ICE candidates
  both ways; (6) collect both `state` flows with Turbine.
  Expected: both `state` flows reach `RtcSessionState.Connected` within
  `negotiationTimeoutMs`; no exceptions.
  Traces: AC-2, AC-3.

- **TC-AND-289-02 — ICE-before-SDP buffering**
  Type: instrumented/integration.
  Target: EMU.
  Preconditions: loopback harness with the fake configured to deliver one remote
  ICE candidate to the answerer BEFORE its `setRemoteDescription`.
  Steps: (1) deliver one remote candidate early via `addIceCandidate`; assert it
  is buffered (not applied / no throw); (2) complete `setRemoteDescription`;
  (3) verify the buffered candidate is flushed; (4) drive to Connected.
  Expected: early candidate is queued then applied after remote SDP; session
  reaches `Connected`; no `IceFailed`.
  Traces: AC-4, AC-3.

- **TC-AND-289-03 — Idempotent teardown + post-close fail-fast**
  Type: instrumented/integration.
  Target: EMU.
  Preconditions: a created `RtcPeerConnection`.
  Steps: (1) call `close()`; (2) call `close()` again; (3) call each public
  suspend method (`createOffer`, `setRemoteDescription`, `createAnswer`,
  `addIceCandidate`) after close.
  Expected: second `close()` is a no-op (no crash, no native double-dispose);
  state == `RtcSessionState.Closed`; every post-close call throws
  `RtcException.Closed`.
  Traces: AC-5.

- **TC-AND-289-04 — Negotiation timeout → Failed(NegotiationTimeout) + auto-close**
  Type: instrumented/integration.
  Target: EMU.
  Preconditions: fake `SignalingPort` that drops the answer; short
  `negotiationTimeoutMs` (e.g. 500 ms).
  Steps: (1) `offerer.createOffer()`; (2) never deliver an answer; (3) observe
  `state`.
  Expected: state transitions to `Failed(RtcException.NegotiationTimeout)` and
  the connection auto-closes (subsequent calls throw `RtcException.Closed`)
  within the configured timeout.
  Traces: AC-6.

- **TC-AND-289-05 — Moshi round-trip of RtcSessionDescription**
  Type: unit (JVM).
  Target: JVM.
  Preconditions: Moshi adapters registered.
  Steps: serialize `RtcSessionDescription(SdpType.OFFER, "v=0...")` → JSON →
  deserialize.
  Expected: JSON is `{ "type": "offer", "sdp": "..." }` (lowercase type) and the
  round-trip is value-equal. (This object is what goes inside
  `CallSignalingIn.payload`.)
  Traces: AC-7.

- **TC-AND-289-06 — Moshi round-trip of RtcIceCandidate (incl. null sdpMid)**
  Type: unit (JVM).
  Target: JVM.
  Preconditions: Moshi adapters registered.
  Steps: round-trip `RtcIceCandidate("0", 0, "candidate:...")` and a variant with
  `sdpMid = null`.
  Expected: JSON is `{ "sdpMid": ..., "sdpMLineIndex": 0, "candidate": "..." }`;
  null `sdpMid` round-trips correctly; value-equal.
  Traces: AC-7.

- **TC-AND-289-07 — Contract: payload nests inside CallSignalingIn envelope**
  Type: contract/MockWebServer.
  Target: JVM (MockWebServer; no real PeerConnection needed).
  Preconditions: a thin serializer that wraps an `RtcSessionDescription` into the
  AND-290 envelope shape (test-only stand-in to lock the §5 contract for the fake
  transport).
  Steps: (1) build a `CallSignalingIn`-shaped body with the SDP JSON under
  `payload` and `type="webrtc.offer"`; (2) POST to MockWebServer; (3) inspect the
  recorded request body.
  Expected: top-level keys are exactly
  `type, event_id, conversation_id, recipient_user_id, nonce, sent_at, payload`;
  the SDP `{type,sdp}` object appears under `payload`, NOT at top level; `type`
  matches the envelope pattern. Guards against the corrected §5 mistake.
  Traces: AC-7 (serialization contract), AC-3 (transport-shape compatibility).

- **TC-AND-289-08 — ICE FAILED maps to Disconnected(recoverable=false), no auto-restart**
  Type: instrumented/integration.
  Target: EMU.
  Preconditions: harness able to force `IceConnectionState.FAILED` (e.g. invalid
  ICE servers / no connectivity path).
  Steps: (1) drive negotiation; (2) induce ICE failure; (3) observe `state`.
  Expected: state == `Disconnected(recoverable = false)`; wrapper does NOT
  auto-restart ICE; session remains usable only via re-creation.
  Traces: AC-3 (state mapping correctness; §6/§7 rules).

- **TC-AND-289-09 — Coroutine cancellation leaves PeerConnection consistent**
  Type: instrumented/integration.
  Target: EMU.
  Preconditions: a created peer mid-`createOffer`.
  Steps: (1) launch `createOffer()` in a job; (2) cancel the job before
  completion; (3) inspect state / attempt a fresh `close()`.
  Expected: `suspendCancellableCoroutine` is cancelled cleanly; no half-applied
  description; `close()` still succeeds; no native crash.
  Traces: AC-5 (consistency/teardown), AC-3.

- **TC-AND-289-10 — Security: no full SDP/ICE strings in release logs (redaction)**
  Type: manual + unit (JVM static check).
  Target: JVM (log-site assertion) + manual code review.
  Preconditions: release build config (`BuildConfig.DEBUG == false`).
  Steps: (1) run negotiation through a capturing logger with DEBUG off;
  (2) assert no log line contains a full `candidate:` string or full SDP body;
  (3) confirm only length+type summaries (e.g. `"local offer sdp len=2143"`)
  are emitted.
  Expected: zero full-SDP/full-candidate log lines in release; TURN
  `credential` never logged.
  Traces: AC-8.

- **TC-AND-289-11 — Permission/availability fail-fast when capturer unavailable**
  Type: instrumented/integration.
  Target: DEV (physical Galaxy A15) — MUST run on the physical device because
  real `CAMERA`/`RECORD_AUDIO` capturer availability and runtime-permission
  state are hardware-backed and not faithfully reproduced on the emulator.
  Preconditions: revoke `CAMERA`/`RECORD_AUDIO` (or make the capturer
  unavailable) with `enableVideo/enableAudio = true`.
  Steps: (1) call `factory.create(config)`; (2) observe failure.
  Expected: `create()` fails fast with a clear message (no native crash, no
  silent black media); does not add new manifest permissions beyond AND-288.
  Traces: AC-2 (creation contract; §8 permission rule).

- **TC-AND-289-12 — Real-network negotiation over TURN on physical device (ABI/API parity)**
  Type: instrumented/e2e.
  Target: DEV (physical Galaxy A15, arm64-v8a, API 34) — MUST run on the
  physical device to exercise the arm64 libwebrtc binary and real-network
  ICE/TURN behavior that the x86_64/API-35 emulator does not represent.
  Preconditions: real `RtcIceServer` list (STUN+TURN) injected via `RtcConfig`;
  network reachable.
  Steps: (1) run the loopback/relay flow with real ICE servers; (2) drive to
  Connected; (3) compare against the EMU run of TC-01 for behavioral parity.
  Expected: reaches `RtcSessionState.Connected` on arm64/API 34; no ABI- or
  API-level regressions vs. emulator; DTLS-SRTP media path established.
  Traces: AC-2, AC-3.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (module exists, builds, deps `core-model`+`core-testing`) | Verified by build/CI (compile of TC-01..12); no behavioral TC needed |
| AC-2 (factory returns working connection from shared factory/EGL) | TC-01, TC-11, TC-12 |
| AC-3 (loopback offer→answer→ICE → Connected, CI) | TC-01, TC-02, TC-07, TC-08, TC-09, TC-12 |
| AC-4 (ICE-before-SDP buffered then applied) | TC-02 |
| AC-5 (idempotent close, post-close throws, no double-dispose) | TC-03, TC-09 |
| AC-6 (no-answer → Failed(NegotiationTimeout) + auto-close) | TC-04 |
| AC-7 (Moshi round-trip matches §5 shapes) | TC-05, TC-06, TC-07 |
| AC-8 (no full SDP/ICE strings in release logs) | TC-10 |

Note: AC-1 is a build/structure criterion satisfied by successful compilation in
CI rather than a dedicated runtime case; every other AC has at least one
explicit TC.
