---
id: AND-294
title: WebRTC foundation tests
milestone: M7
epic: E39
priority: P1
size: M
status: draft
depends_on: [AND-290, AND-289]
blocks: [AND-295]
---

# AND-294 — WebRTC foundation tests

## 1. Overview & Goal

This ticket delivers the automated test suite that validates the WebRTC
"foundation" layer of the TestLogon Android app — namely the signaling
transport (`AND-290`) and the `PeerConnection` wrapper / lifecycle state
machine (`AND-289`). The goal is a fast, deterministic, JVM-only test suite
that exercises the full signaling exchange and connection lifecycle **with a
fully mocked transport and a fully mocked native WebRTC layer**, so the suite
runs on `core-testing` / Robolectric-free JUnit without an emulator, a real
backend, or the unreliable dev host at `http://18.222.237.167:8000`.

The deliverable is test code plus the thin seams (interfaces, fakes) required
to make the production code testable. No new product behavior is introduced;
where production code must be refactored to accept an injected transport or
`PeerConnectionFactory`, those seams are part of this ticket's scope. The
acceptance bar from the backlog is simply **"Pass"** — i.e. a green,
non-flaky suite wired into CI.

These tests live in `feature-call` (the WebRTC call feature module) and in
`core-network`, alongside the code under test. They are the regression gate
for every subsequent M7 call-feature ticket.

## 2. Context & References

- **Epic E39 / Milestone M7** — native WebRTC calling. This ticket is the
  test foundation; product UI tickets build on top of it.
- **`AND-289` — PeerConnection wrapper + lifecycle** (dep): provides
  `PeerConnectionController` (factory/wrapper, SDP/ICE handling, teardown).
  Acceptance there is "offer/answer/ICE cycle completes in a test harness" —
  **this ticket owns that harness.**
- **`AND-290` — Signaling transport** (dep): signaling over backend `/signal`,
  with SSE/poll for remote SDP/ICE. This ticket mocks that transport.
- `AND-291` (TURN/STUN credentials) is **not** a hard dependency: ICE-server
  configuration is injected as test fixtures here, not fetched live.
- `AND-288` (WebRTC dependency/Gradle wiring, transitive via AND-289) supplies
  the `org.webrtc` artifact; tests never touch the native `.so`.
- **Stack**: Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Retrofit 2.11 /
  OkHttp 4.12 / Moshi 1.15. Test stack from `core-testing`: JUnit4,
  `kotlinx-coroutines-test` (`runTest`, `StandardTestDispatcher`,
  `TestScope`), MockK 1.13, Turbine 1.x (Flow assertions), OkHttp
  `MockWebServer` (for the Retrofit signaling client only).
- **Package base**: `com.testlogon.android`. Code under test lives in
  `com.testlogon.android.feature.call.webrtc` and
  `com.testlogon.android.core.network.signaling`.
- Web reference: signaling endpoint shapes mirror `frontend/src/api/endpoints/`
  (`/signal` POST + SSE stream); JSON field names must match `frontend/src/api/types.ts`.

## 3. Functional Requirements

The suite MUST cover the following observable behaviors of the foundation
layer. Each requirement maps to one or more test cases in §11.

**FR-1 Signaling round-trip (mocked transport).** Given a fake transport, a
local offer SDP posted via the signaling client is delivered to the transport,
and a remote answer + ICE candidates injected into the transport are surfaced
as `SignalEvent`s in order.

**FR-2 Offer/answer SDP exchange.** `PeerConnectionController.createOffer()`
produces an offer, applying it as local description; an injected remote answer
is applied as remote description; the controller transitions through the
expected `CallConnectionState` sequence.

**FR-3 ICE candidate exchange.** Locally generated ICE candidates are forwarded
to the transport as `signal` messages; remote candidates received from the
transport are added to the peer connection. Candidates generated before the
remote description is set are buffered and flushed afterwards (ordering test).

**FR-4 Lifecycle state machine.** The controller exposes
`StateFlow<CallConnectionState>` that transitions
`Idle → Creating → Connecting → Connected → (Disconnected | Failed | Closed)`
driven by mocked `PeerConnection.Observer` callbacks. Illegal transitions are
ignored, not crashes.

**FR-5 Teardown / resource release.** `close()` disposes the peer connection,
cancels the signaling subscription/coroutine scope, and is idempotent
(double-close is a no-op). No leaked coroutines after `close()`.

**FR-6 Error & disconnect paths.** Transport failures, SDP set failures, and
`PeerConnectionState.FAILED` map to `CallConnectionState.Failed(reason)` and
trigger teardown.

**FR-7 Determinism.** All async work routes through an injected
`CoroutineDispatcher`; tests use a virtual-time test dispatcher so there is no
wall-clock dependency and zero flakiness.

## 4. Technical Design

### 4.1 Seams introduced

To test without native WebRTC, the production wrapper from AND-289 must depend
on small injectable interfaces rather than concrete `org.webrtc` types at its
public boundary. This ticket finalizes those seams:

```kotlin
package com.testlogon.android.feature.call.webrtc

/** Production-facing controller under test (delivered by AND-289). */
interface PeerConnectionController {
    val connectionState: StateFlow<CallConnectionState>
    val localSignals: Flow<OutboundSignal>      // local SDP + ICE to send

    suspend fun createOffer(): SessionDescription
    suspend fun acceptRemoteOffer(remote: SessionDescription): SessionDescription
    suspend fun applyRemoteAnswer(remote: SessionDescription)
    suspend fun addRemoteIceCandidate(candidate: IceCandidate)
    fun close()
}

/** Thin factory seam so a fake PeerConnection can be injected. */
fun interface PeerConnectionFactoryWrapper {
    fun create(
        iceServers: List<PeerConnection.IceServer>,
        observer: PeerConnection.Observer,
    ): PeerConnection
}
```

```kotlin
package com.testlogon.android.core.network.signaling

/** Signaling transport seam (AND-290). Mocked in this suite. */
interface SignalingTransport {
    suspend fun send(signal: OutboundSignal): ApiResult<Unit>
    fun events(callId: String): Flow<SignalEvent>   // SSE/poll merged stream
}
```

`CallConnectionState`:

```kotlin
sealed interface CallConnectionState {
    data object Idle : CallConnectionState
    data object Creating : CallConnectionState
    data object Connecting : CallConnectionState
    data object Connected : CallConnectionState
    data object Disconnected : CallConnectionState
    data class  Failed(val reason: String) : CallConnectionState
    data object Closed : CallConnectionState
}
```

### 4.2 Test doubles (in `core-testing` + module `testFixtures`)

```kotlin
package com.testlogon.android.feature.call.webrtc.test

/** In-memory transport: tests push remote events; assert sent signals. */
class FakeSignalingTransport : SignalingTransport {
    val sent = mutableListOf<OutboundSignal>()
    private val incoming = MutableSharedFlow<SignalEvent>(replay = 0, extraBufferCapacity = 64)
    var sendResult: ApiResult<Unit> = ApiResult.Success(Unit)

    override suspend fun send(signal: OutboundSignal): ApiResult<Unit> {
        sent += signal; return sendResult
    }
    override fun events(callId: String): Flow<SignalEvent> = incoming
    suspend fun emit(event: SignalEvent) = incoming.emit(event)
}

/** Fake PeerConnection capturing SDP/ICE and replaying observer callbacks. */
class FakePeerConnection(private val observer: PeerConnection.Observer) {
    val localDescriptions = mutableListOf<SessionDescription>()
    val remoteDescriptions = mutableListOf<SessionDescription>()
    val addedCandidates = mutableListOf<IceCandidate>()
    var disposed = false
    fun fireIceCandidate(c: IceCandidate) = observer.onIceCandidate(c)
    fun fireState(s: PeerConnection.PeerConnectionState) = observer.onConnectionChange(s)
}
```

`MockK` mocks the concrete `org.webrtc.PeerConnection` where the fake above is
insufficient (e.g. verifying `createOffer`/`setLocalDescription` `SdpObserver`
callback invocation), wrapping the asynchronous `SdpObserver` API into the
suspend functions and asserting the bridge.

### 4.3 Dispatcher injection

The controller and the signaling client accept a `CoroutineDispatcher`
(provided by Hilt in production via `@IoDispatcher`). Tests pass
`StandardTestDispatcher(testScheduler)` so `advanceUntilIdle()` drains all
work deterministically.

### 4.4 Retrofit/SSE client test (`core-network`)

The concrete `RetrofitSignalingTransport` is tested against OkHttp
`MockWebServer`: enqueue a `200` for `POST /signal` and a chunked
`text/event-stream` body for the SSE subscription, asserting parsed
`SignalEvent`s. This validates Moshi adapters and the X-CSRF-Token header
plumbing without the dev backend.

## 5. API Contract

This is a test ticket; it does not define new endpoints. It asserts conformance
to the signaling contract owned by **AND-290**. The shapes exercised:

**`POST /signal`** (auth via session cookies + `X-CSRF-Token`):
```json
{
  "call_id": "c_01HZ...",
  "type": "offer",            // offer | answer | ice | bye
  "sdp": "v=0\r\no=- ...",    // present for offer/answer
  "candidate": null           // present only for type=ice
}
```
Response `200`: `{ "accepted": true }`.

**`GET /signal/{call_id}/events`** (SSE, `text/event-stream`): each event:
```
event: signal
data: {"type":"answer","sdp":"v=0\r\n...","candidate":null}

event: signal
data: {"type":"ice","sdp":null,"candidate":{"sdpMid":"0","sdpMLineIndex":0,"candidate":"candidate:..."}}
```

The `MockWebServer` test asserts: request path/method, `X-CSRF-Token` header
present, request body Moshi shape, and that streamed `data:` frames decode to
`SignalEvent.Answer` / `SignalEvent.Ice`. FastAPI `detail` error mapping
(string | `[{msg}]` | `{code,...}`) is asserted by enqueuing a `422` body and
verifying it surfaces as `ApiResult.Error` with the parsed message.

## 6. Data & State Management

No persistence (Room/DataStore) is involved in the foundation layer, so this
suite asserts only **in-memory state**:

- `connectionState: StateFlow<CallConnectionState>` — asserted with Turbine,
  capturing the full emission sequence per scenario and verifying ordering and
  the absence of illegal transitions.
- ICE-candidate buffering: a list inside the controller holding locally
  generated candidates until `localSignals` has a collector / remote
  description is set; the test verifies the buffer is flushed in FIFO order
  and cleared after flush.
- `OutboundSignal` emission ordering on `localSignals` (Turbine assertion).

All Flows are cold/hot as designed; tests subscribe before driving the fakes to
avoid lost emissions, and use `StandardTestDispatcher` + `advanceUntilIdle()`
to make the hot `StateFlow` deterministic.

## 7. Error Handling & Resilience

The suite is the primary place these paths are proven:

- **Transport send failure**: `FakeSignalingTransport.sendResult =
  ApiResult.Error(...)` → controller emits `Failed(reason)` and tears down; the
  test asserts no further signals are sent.
- **SDP set failure**: the `SdpObserver.onSetFailure(msg)` callback is fired →
  the suspend bridge throws / returns `ApiResult.Error`; controller maps to
  `Failed`.
- **`PeerConnectionState.FAILED` / `DISCONNECTED`**: fired via
  `FakePeerConnection.fireState(...)` → mapped to `Failed` / `Disconnected`.
- **Timeout/backoff**: because the dev backend is unreliable, the controller's
  ~20s connection-establishment timeout is tested with virtual time:
  `advanceTimeBy(20_000)` with no `Connected` callback must yield
  `Failed("connect_timeout")`. Backoff/retry for the idempotent SSE
  subscription GET is asserted at the `MockWebServer` layer (one reconnect on
  stream drop), and explicitly **not** applied to the non-idempotent
  `POST /signal`.
- **Double-close idempotency** and **post-close event drops** (events arriving
  after `close()` are ignored) are asserted.

## 8. Security & Privacy

- Tests run entirely offline; no real credentials, cookies, or SDP from real
  sessions are used. SDP/ICE fixtures are synthetic constants.
- The `MockWebServer` test asserts the `X-CSRF-Token` header is sent on
  `POST /signal`, guarding the CSRF requirement from the auth design, but uses
  a dummy token value.
- No PII is logged by the code under test; a test asserts that failure
  `reason` strings contain no SDP/candidate payloads (privacy: SDP can carry
  IP addresses), only stable error codes.
- No secrets committed in fixtures; TURN credentials (AND-291) are stubbed
  placeholders.

## 9. Accessibility & i18n

N/A for this ticket. This is a non-UI test suite for the transport/lifecycle
layer; there are no Composables, strings, or user-facing surfaces.
Accessibility and i18n for the call UI are owned by the downstream call-screen
UI ticket in E39 (the consumer of this foundation), not here.

## 10. Telemetry & Logging

No analytics events are emitted by the foundation layer. This ticket adds:

- Assertions that the controller logs lifecycle transitions via the injected
  `Logger` seam (a `FakeLogger` from `core-testing`) at `DEBUG`, and failures
  at `WARN`, with **redacted** payloads (see §8).
- A test verifying that a `FakeLogger` capture contains exactly one entry per
  state transition (no duplicate/noisy logging), so production log volume on
  the flaky dev host stays bounded.

The CI test task produces a JUnit XML + HTML report under
`feature-call/build/reports/tests/` and a coverage report; these are the
telemetry of the suite itself.

## 11. Testing Strategy

All tests are JVM unit tests (`src/test/...`), no emulator. Test classes:

**`SignalingExchangeTest`** (FR-1, FR-3)
- `local_offer_is_sent_via_transport`
- `remote_answer_event_is_delivered_in_order`
- `remote_ice_candidates_are_forwarded_to_peer_connection`
- `local_ice_before_remote_description_is_buffered_then_flushed_fifo`

**`PeerConnectionLifecycleTest`** (FR-2, FR-4)
- `offer_answer_ice_cycle_reaches_connected`
- `state_sequence_is_idle_creating_connecting_connected` (Turbine)
- `illegal_transition_after_closed_is_ignored`

**`PeerConnectionTeardownTest`** (FR-5)
- `close_disposes_peer_connection_and_cancels_scope`
- `double_close_is_noop`
- `events_after_close_are_dropped`
- `no_leaked_coroutines_after_close` (assert `TestScope` completes)

**`FailurePathsTest`** (FR-6, §7)
- `transport_send_error_maps_to_failed`
- `sdp_set_failure_maps_to_failed`
- `peer_state_failed_maps_to_failed_and_tears_down`
- `connect_timeout_maps_to_failed` (virtual time)

**`RetrofitSignalingTransportTest`** (`core-network`, MockWebServer) — §5
- `post_signal_serializes_offer_and_sends_csrf_header`
- `sse_stream_decodes_answer_and_ice_events`
- `http_422_maps_detail_to_api_result_error`
- `sse_reconnects_once_on_stream_drop`

**Conventions**: every test wrapped in `runTest`; `MockK` `verify`/`coVerify`
for interaction assertions; Turbine for Flow ordering; `advanceUntilIdle()` /
`advanceTimeBy()` for time control. Target: suite runs in < 5s locally,
**zero flakiness over 100 CI iterations** (a `--rerun-tasks` loop is part of
the DoD check). Line coverage of the AND-289/AND-290 production classes ≥ 85%.

## 12. Dependencies & Sequencing

- **Hard deps**: `AND-289` (PeerConnection wrapper + lifecycle) and
  `AND-290` (signaling transport) must be merged on `android-port`, since this
  suite tests their public APIs and finalizes their injection seams. The
  backlog lists only `AND-290`; `AND-289` is added here because the lifecycle
  tests in scope cannot exist without it (it is `AND-290`'s own dependency,
  so already upstream).
- **Soft**: `core-testing` must expose the shared `TestDispatcherRule`,
  `FakeLogger`, and Turbine/MockK/MockWebServer dependencies.
- **Blocks**: downstream E39 call-UI and call-orchestration tickets (e.g.
  `AND-295`) should not merge until this gate is green, as it is their
  regression guard.
- **Not required**: `AND-291` (TURN/STUN) — ICE servers are fixtures here.
- **Sequencing**: implement seams/refactors in AND-289/290 modules first (if
  not already present), add `testFixtures` doubles, then test classes, then
  wire into the CI `:feature-call:testDebugUnitTest` and
  `:core-network:testDebugUnitTest` tasks.

## 13. Risks & Open Questions

- **R1 — Native API surface in tests.** `org.webrtc.PeerConnection` is
  `final`/JNI-backed and awkward to mock. Mitigation: hide it behind
  `PeerConnectionFactoryWrapper` so tests inject `FakePeerConnection`; only
  the SDP-observer bridge touches the real type via MockK relaxed mocks. If
  MockK cannot mock a sealed/final native class, fall back to wrapping that
  call in a thin interface (small refactor in AND-289).
- **R2 — SSE framing in MockWebServer.** Chunked `text/event-stream` parsing
  edge cases (multi-line `data:`, comment/heartbeat `:` lines). Mitigation:
  fixture covers heartbeat and multi-line frames.
- **R3 — StateFlow conflation** can hide intermediate states from Turbine.
  Mitigation: assert with a subscribed `test {}` block started before driving
  fakes; if conflation drops a needed state, expose a non-conflated
  `SharedFlow<CallConnectionState>` event channel for tests.
- **OQ1**: Does AND-290 expose SSE *and* poll as one merged `events()` Flow, or
  two? This suite assumes a single merged Flow; confirm with AND-290 owner.
- **OQ2**: Exact `OutboundSignal`/`SignalEvent` field names — must match
  `frontend/src/api/types.ts`; verify before locking Moshi fixtures.

## 14. Acceptance Criteria

1. All test classes in §11 exist and **pass** (backlog acceptance: "Pass").
2. The full suite runs JVM-only (no emulator, no network to
   `18.222.237.167`) and completes in < 5s.
3. The offer/answer/ICE cycle test reaches `CallConnectionState.Connected`
   using only fakes — satisfying AND-289's "cycle completes in a test harness".
4. Signaling round-trip test proves local offer → transport and remote
   answer/ICE → controller, with correct ordering and ICE buffering/flush.
5. All §7 error/disconnect/timeout paths map to `Failed`/`Disconnected` and
   trigger idempotent teardown; double-close is a no-op; no coroutine leaks.
6. `RetrofitSignalingTransportTest` asserts `POST /signal` body shape,
   `X-CSRF-Token` header, SSE decoding, `422` `detail` mapping, and one SSE
   reconnect.
7. Line coverage of AND-289/AND-290 production classes ≥ 85%.
8. Suite is non-flaky: green across 100 consecutive CI reruns.
9. No PII/SDP payloads appear in log/error `reason` assertions.

## 15. Definition of Done

- [ ] Seams (`PeerConnectionFactoryWrapper`, `SignalingTransport`, injected
      `CoroutineDispatcher`/`Logger`) present and used by production code.
- [ ] Test doubles published in `core-testing` / module `testFixtures`.
- [ ] All §11 test classes implemented and green on `android-port`.
- [ ] Wired into `:feature-call:testDebugUnitTest` and
      `:core-network:testDebugUnitTest`; both run in CI on PR.
- [ ] Coverage gate ≥ 85% on foundation classes enforced in CI.
- [ ] 100x rerun flakiness check passes; report archived as a CI artifact.
- [ ] No new lint/Detekt warnings; KSP/Hilt build clean; JDK 17 / AGP 8.7.3 /
      Gradle 8.9.
- [ ] Open questions OQ1/OQ2 resolved or recorded as follow-ups against the
      AND-290 owner.
- [ ] PR reviewed and merged; downstream E39 tickets unblocked.
