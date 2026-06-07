---
id: AND-294
title: WebRTC foundation tests
milestone: M7
epic: E39
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **`AND-290` — Signaling transport** (dep): signaling over backend
  `POST /messaging/messages/calls/{call_id}/signal` (verified), with **inbound
  remote SDP/ICE delivered over the shared messaging SSE stream
  `GET /messaging/events/stream`** (EventSource, `withCredentials`), *not* a
  per-call `/signal/{call_id}/events` endpoint — there is no such endpoint
  (corrected; see §16). This ticket mocks that transport.
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
- Web reference: signaling endpoint shapes mirror
  `src/api/endpoints/messaging.ts` (`sendSignalingEvent` →
  `POST /messaging/messages/calls/{callId}/signal`) and the inbound SSE handling
  in `src/hooks/useMessagingStream.ts` (`MESSAGING_STREAM_URL =
  "/messaging/events/stream"`, dispatching `webrtc.*` events). JSON field names
  must match `SignalingPayload`/`SignalingAck` in `src/api/endpoints/messaging.ts`
  (the canonical DTOs live there, not in `src/api/types.ts`).

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
`MockWebServer`: enqueue a `200` `CallSignalingOut` for
`POST /messaging/messages/calls/{call_id}/signal` and a chunked
`text/event-stream` body for the SSE subscription on
`GET /messaging/events/stream`, asserting parsed `SignalEvent`s. This validates
Moshi adapters and the `Authorization` / `X-SESSION-ID` / `X-CSRF-Token` header
plumbing without the dev backend.

## 5. API Contract

This is a test ticket; it does not define new endpoints. It asserts conformance
to the signaling contract owned by **AND-290**. The shapes exercised:

> **CORRECTED against OpenAPI + frontend.** The earlier draft of this section
> claimed a `POST /signal` endpoint with a `{call_id,type,sdp,candidate}` body,
> a `{accepted:true}` response, and a per-call `GET /signal/{call_id}/events`
> SSE endpoint. **None of those exist.** The real contract is below; see §16
> for the source pointers.

**`POST /messaging/messages/calls/{call_id}/signal`** — request `CallSignalingIn`
(verified: OpenAPI `components.schemas.CallSignalingIn`; frontend
`SignalingPayload` in `src/api/endpoints/messaging.ts`). Auth headers:
`Authorization: Bearer <token>` **and** `X-SESSION-ID` (OpenAPI `params=call_id,
authorization,X-SESSION-ID`), plus CSRF via `X-CSRF-Token` (from the `ui_csrf`
cookie, set by `src/api/client.ts`; requests use `credentials: include`).
```json
{
  "type": "webrtc.offer",       // ^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate|webrtc\.screen_share_start|webrtc\.screen_share_stop)$
  "event_id": "evt_...",        // required, 1..128
  "conversation_id": "conv_...",// required, 1..128
  "recipient_user_id": "u_...", // required, 1..128
  "nonce": "abcd1234...",       // required, 8..128
  "sent_at": 1717718400,        // required, integer (epoch)
  "payload": { "sdp": "v=0\r\n..." }  // free-form object; carries SDP / ICE candidate
}
```
Note: there is **no top-level `sdp`/`candidate`/`call_id` field**. `call_id` is a
path param; the SDP/ICE body rides inside the free-form `payload` object.
Response `200` is `CallSignalingOut` (frontend `SignalingAck`), **not**
`{accepted:true}`:
```json
{
  "event_id": "evt_...",
  "call_id": "c_...",
  "conversation_id": "conv_...",
  "event_type": "webrtc.offer",
  "delivered_to": "u_...",
  "status": "delivered"          // "delivered" | "duplicate" (frontend SignalingAck)
}
```
Error responses for this endpoint are `CallSignalingErrorOut` =
`{ "code": string, "message": string }` for status `400/403/404/409/429/503`
(verified: OpenAPI resp list + schema), and the generic FastAPI
`HTTPValidationError` (`{detail:[{loc,msg,type}]}`) for `422`.

**Inbound remote signals — shared SSE stream `GET /messaging/events/stream`**
(verified: OpenAPI op `events_stream_messaging_events_stream_get`, params
`after,limit,poll_ms,x_request_id,authorization,X-SESSION-ID`; frontend
`src/hooks/useMessagingStream.ts`). This is the **only** inbound channel — a
single per-user stream, not per-call. The web client opens an `EventSource`
with `withCredentials: true` and registers named listeners; WebRTC frames arrive
as typed events `webrtc.offer` / `webrtc.answer` / `webrtc.ice_candidate` whose
`data` JSON carries `conversation_id`, `type`/`event_type`, and the SDP/ICE in
the event body. (Exact inner payload key names for SDP/ICE are not pinned by a
schema in the OpenAPI — see §16 Open assumptions.)

The `MockWebServer`/contract test asserts: request path
`/messaging/messages/calls/{call_id}/signal` + method `POST`, presence of
`Authorization`, `X-SESSION-ID`, and `X-CSRF-Token` headers, the `CallSignalingIn`
Moshi request shape, and that streamed `data:` frames from the SSE fixture decode
to `SignalEvent.Answer` / `SignalEvent.Ice`. Error mapping is asserted two ways:
(a) a `422` `HTTPValidationError` body (`detail` as string | `[{msg}]`) surfaces
as `ApiResult.Error` with the parsed message (matches
`normalizeErrorDetail` in `src/api/client.ts`); (b) a `409`/`503`
`CallSignalingErrorOut` (`{code,message}`) surfaces as `ApiResult.Error`
carrying the `code` and `message`.

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
  subscription GET (`/messaging/events/stream`) is asserted at the
  `MockWebServer` layer (one reconnect on stream drop), and explicitly **not**
  applied to the non-idempotent
  `POST /messaging/messages/calls/{call_id}/signal`.
- **Double-close idempotency** and **post-close event drops** (events arriving
  after `close()` are ignored) are asserted.

## 8. Security & Privacy

- Tests run entirely offline; no real credentials, cookies, or SDP from real
  sessions are used. SDP/ICE fixtures are synthetic constants.
- The `MockWebServer` test asserts the auth headers are sent on
  `POST /messaging/messages/calls/{call_id}/signal` — `Authorization: Bearer`,
  `X-SESSION-ID`, and `X-CSRF-Token` (verified against OpenAPI params and
  `src/api/client.ts`) — guarding the auth/CSRF requirement, but uses dummy
  token values.
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
- **OQ1**: *Resolved.* The web client uses a **single shared SSE stream**
  `GET /messaging/events/stream` (`src/hooks/useMessagingStream.ts`) for all
  inbound events, including `webrtc.*` frames; there is no per-call poll. The
  `events(callId)` Flow seam should therefore subscribe to the one shared stream
  and filter by `conversation_id`/call. (The OpenAPI op also exposes `after`,
  `limit`, `poll_ms` query params, i.e. a long-poll fallback variant on the same
  path — the merged-Flow seam can wrap either; confirm with AND-290 owner which
  mode the Android client adopts.)
- **OQ2**: *Partially resolved.* Outbound `CallSignalingIn` field names are
  verified (`type,event_id,conversation_id,recipient_user_id,nonce,sent_at,
  payload`) against OpenAPI and `SignalingPayload` in
  `src/api/endpoints/messaging.ts`; the response `CallSignalingOut`/`SignalingAck`
  is verified. **Still open:** the exact key names *inside* the free-form
  `payload` object (SDP string key, ICE candidate sub-fields) and the inbound
  SSE `data` JSON for `webrtc.ice_candidate` are not pinned by any OpenAPI schema
  (`payload` is `additionalProperties:true`); confirm with AND-290 owner before
  locking Moshi fixtures (see §16 Open assumptions).

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Signaling endpoint is `POST /messaging/messages/calls/{call_id}/signal`**
   (not `POST /signal`). **VERDICT: Corrected.** Source: OpenAPI
   `POST /messaging/messages/calls/{call_id}/signal`
   (op `send_signaling_event_messaging_messages_calls__call_id__signal_post`);
   frontend `src/api/endpoints/messaging.ts: sendSignalingEvent`.
2. **Request body schema = `CallSignalingIn`** with fields
   `type, event_id, conversation_id, recipient_user_id, nonce, sent_at, payload`
   (no top-level `sdp`/`candidate`/`call_id`). **VERDICT: Corrected.** Source:
   OpenAPI `components.schemas.CallSignalingIn`; frontend
   `src/api/endpoints/messaging.ts: SignalingPayload`.
3. **`type` enum is `webrtc.offer | webrtc.answer | webrtc.ice_candidate |
   webrtc.screen_share_start | webrtc.screen_share_stop`** (dotted, not
   `offer|answer|ice|bye`). **VERDICT: Corrected.** Source: OpenAPI
   `CallSignalingIn.properties.type.pattern`; frontend `SignalingPayload.type`
   (subset: offer/answer/ice_candidate).
4. **Success response = `CallSignalingOut`** = `{event_id, call_id,
   conversation_id, event_type, delivered_to, status}` (not `{accepted:true}`);
   `status` ∈ `delivered|duplicate`. **VERDICT: Corrected.** Source: OpenAPI
   `components.schemas.CallSignalingOut`; frontend
   `src/api/endpoints/messaging.ts: SignalingAck`.
5. **Signaling-specific error body = `CallSignalingErrorOut` = `{code, message}`**
   for `400/403/404/409/429/503`. **VERDICT: Corrected** (spec implied only a
   FastAPI `detail` shape for this endpoint). Source: OpenAPI resp list on
   `POST .../signal` + `components.schemas.CallSignalingErrorOut`.
6. **Generic validation error = `HTTPValidationError` `{detail:[{loc,msg,type}]}`
   on `422`; client flattens `detail` (string | `[{msg}]`) to a message.**
   **VERDICT: Verified.** Source: OpenAPI `components.schemas.HTTPValidationError`
   / `ValidationError`; frontend `src/api/client.ts: normalizeErrorDetail`.
7. **Inbound remote SDP/ICE arrives over the shared SSE stream
   `GET /messaging/events/stream`** as typed events `webrtc.offer/answer/
   ice_candidate`; there is **no** per-call `GET /signal/{call_id}/events`.
   **VERDICT: Corrected.** Source: OpenAPI
   `GET /messaging/events/stream` (op `events_stream_messaging_events_stream_get`);
   frontend `src/hooks/useMessagingStream.ts`
   (`MESSAGING_STREAM_URL = "/messaging/events/stream"`, `webrtc.*` dispatch).
8. **SSE transport = `EventSource` with `withCredentials: true`; named
   listeners per event type.** **VERDICT: Verified.** Source:
   `src/hooks/useMessagingStream.ts` (`new EventSource(MESSAGING_STREAM_URL,
   { withCredentials: true })`, `EVENT_TYPES`).
9. **Auth = `Authorization: Bearer <token>` + `X-SESSION-ID` headers
   + CSRF `X-CSRF-Token` (from `ui_csrf` cookie) + `credentials: include`.**
   **VERDICT: Corrected** (spec said "session cookies + X-CSRF-Token" only,
   omitting Bearer/X-SESSION-ID). Source: OpenAPI `params=...,authorization,
   X-SESSION-ID` on `POST .../signal` and `GET .../events/stream`; frontend
   `src/api/client.ts` (lines ~158 Authorization, ~168 `ui_csrf`→`X-CSRF-Token`,
   ~183 `credentials:"include"`).
10. **TURN/ICE servers come from
    `POST /messaging/messages/calls/{call_id}/turn-credentials` →
    `TurnCredentialsOut {ttl_seconds, expires_at, ice_servers:[{urls[],username,
    credential}]}`.** **VERDICT: Verified** (AND-291; used here only as fixture
    shape, not fetched live). Source: OpenAPI
    `components.schemas.TurnCredentialsOut` / `TurnIceServerOut`; frontend
    `src/api/endpoints/messaging.ts: fetchTurnCredentials` / `TurnCredentialsResp`.
11. **`POST .../signal` is non-idempotent; the SSE GET is idempotent and may be
    safely retried.** **VERDICT: Verified (by HTTP method semantics + server
    `status:"duplicate"` dedupe via `nonce`/`event_id`).** Source: OpenAPI
    method (POST vs GET); `SignalingAck.status` includes `duplicate`.
12. **Web client maps WebRTC connection lifecycle in a hook + state machine.**
    **VERDICT: Verified** (used only as behavioral reference for the Android
    state machine; the Kotlin `CallConnectionState` enum is an Android-side
    design, not a backend contract). Source: frontend
    `src/hooks/useRtcPeerConnection.ts`, `src/pages/messages/callStateMachine.ts`.
13. **Framework/test-stack choices** (JUnit4, kotlinx-coroutines-test
    `runTest`/`StandardTestDispatcher`, MockK, Turbine, OkHttp `MockWebServer`).
    **VERDICT: Unverified-assumption** (no authoritative source in-repo; these
    are Android testing conventions). framework ref:
    https://developer.android.com/kotlin/coroutines/test and
    https://github.com/square/okhttp/tree/master/mockwebserver .
14. **`org.webrtc.PeerConnection` is final/JNI-backed and hard to mock; hide
    behind a factory seam.** **VERDICT: Unverified-assumption** (design choice;
    no in-repo source). framework ref: https://webrtc.github.io/webrtc-org/native-code/android/ .
15. **Connection-establishment timeout ≈ 20s mapping to
    `Failed("connect_timeout")`.** **VERDICT: Unverified-assumption** (AND-289
    internal behavior; no source in OpenAPI/frontend). Recorded as an open
    assumption pending AND-289.

### Corrections made

- §2/§5/§4.4/§7/§8/§11/§13: endpoint path `POST /signal` →
  `POST /messaging/messages/calls/{call_id}/signal` (#1).
- §5: request body shape replaced with the real `CallSignalingIn` (#2, #3).
- §5: response `{accepted:true}` → `CallSignalingOut` (#4).
- §5: error shapes corrected to `CallSignalingErrorOut {code,message}` for
  4xx/5xx and `HTTPValidationError` for 422 (#5, #6).
- §2/§5/§13: removed the non-existent `GET /signal/{call_id}/events`; inbound
  signals corrected to the shared SSE stream `GET /messaging/events/stream` (#7).
- §5/§8: auth corrected to `Authorization: Bearer` + `X-SESSION-ID` +
  `X-CSRF-Token` (was "session cookies + X-CSRF-Token") (#9).
- §13 OQ1 resolved (single shared SSE stream); OQ2 partially resolved (outbound
  field names verified; inner `payload` keys still open).

### Open assumptions

- **Inner `payload` key names** for SDP and ICE candidate (and the inbound SSE
  `webrtc.ice_candidate` `data` JSON) are not pinned by any schema —
  `CallSignalingIn.payload` is `additionalProperties:true`. Cannot verify from
  OpenAPI; must confirm with the AND-290 owner before locking Moshi fixtures.
- **20s connect timeout / `connect_timeout` reason string** is AND-289-internal;
  not derivable from the backend contract or frontend.
- **Test-stack & WebRTC-mocking strategy** (#13, #14) are Android conventions,
  not repo-sourced; labelled framework refs above.
- **`@IoDispatcher` Hilt qualifier and `Logger`/`FakeLogger` seams** are assumed
  to exist in `core-testing`/`core-network`; not verifiable from the provided
  sources (no Android module source in the reference set).
- **Long-poll vs SSE mode** for the Android `events()` seam: the stream path
  exposes `after/limit/poll_ms` (poll) and an SSE mode; which one the Android
  client uses is an open design point for AND-290.

## 17. Test Plan

IDs `TC-AND-294-NN`. "AC-#" refers to §14 Acceptance Criteria. Unless noted,
cases are JVM unit / contract tests on the **JVM unit/Robolectric (local,
no device)** target — appropriate because this is a mocked-transport,
mocked-native foundation suite with no UI and no hardware dependency.

- **TC-AND-294-01 — Signaling round-trip happy path.**
  Type: unit. Target: JVM unit (local). Preconditions: `FakeSignalingTransport`
  with `sendResult=Success`; controller wired with `StandardTestDispatcher`.
  Steps: subscribe to `localSignals` via Turbine; call `createOffer()`;
  `emit()` a remote `webrtc.answer` then a `webrtc.ice_candidate` `SignalEvent`.
  Expected: the offer is recorded in `FakeSignalingTransport.sent` as a
  `CallSignalingIn` with `type="webrtc.offer"`; remote answer then ICE surface
  as ordered `SignalEvent.Answer`, `SignalEvent.Ice`. Traces: AC-1, AC-4.

- **TC-AND-294-02 — Offer/answer/ICE cycle reaches Connected.**
  Type: unit. Target: JVM unit (local). Preconditions: `FakePeerConnection`
  injected via `PeerConnectionFactoryWrapper`. Steps: `createOffer()`; apply
  injected remote answer; `fireState(CONNECTED)`. Expected: `connectionState`
  emits `Idle → Creating → Connecting → Connected` (Turbine), with local/remote
  descriptions captured on the fake. Traces: AC-1, AC-3.

- **TC-AND-294-03 — Local ICE before remote description is buffered then
  flushed FIFO.** Type: unit. Target: JVM unit (local). Preconditions: remote
  description not yet set. Steps: fire 3 local ICE candidates via
  `FakePeerConnection.fireIceCandidate`; then apply remote answer. Expected:
  no ICE `CallSignalingIn` sent before remote description; after it, all 3 are
  flushed to the transport in original order and the buffer is cleared.
  Traces: AC-4.

- **TC-AND-294-04 — Remote ICE candidates are added to the peer connection.**
  Type: unit. Target: JVM unit (local). Steps: `emit()` a remote
  `webrtc.ice_candidate` event. Expected: `FakePeerConnection.addedCandidates`
  contains the decoded candidate. Traces: AC-4.

- **TC-AND-294-05 — Teardown disposes peer connection and cancels scope;
  double-close is a no-op; no coroutine leaks.** Type: unit. Target: JVM unit
  (local). Steps: drive to `Connected`; call `close()` twice. Expected:
  `FakePeerConnection.disposed == true`, signaling subscription cancelled,
  `connectionState` ends `Closed`, second `close()` causes no extra disposal /
  no exception, and the `TestScope` completes with no active jobs
  (`advanceUntilIdle()` then assert scheduler idle / no leaked coroutines).
  Traces: AC-5.

- **TC-AND-294-06 — Events after close are dropped.** Type: unit. Target: JVM
  unit (local). Steps: `close()`, then `emit()` a remote answer/ICE. Expected:
  no state change, no new `addedCandidates`, no emission past `Closed`.
  Traces: AC-5.

- **TC-AND-294-07 — Transport send error maps to Failed and tears down.**
  Type: unit. Target: JVM unit (local). Preconditions:
  `FakeSignalingTransport.sendResult = ApiResult.Error(CallSignalingErrorOut
  code="rate_limited", message=...)` (real `{code,message}` shape, e.g. the
  429 path). Steps: `createOffer()`. Expected: `connectionState` emits
  `Failed(reason)`; teardown runs; no further signals sent; `reason` carries the
  stable `code`, not SDP. Traces: AC-5, AC-9.

- **TC-AND-294-08 — SDP set failure and PeerConnectionState.FAILED map to
  Failed.** Type: unit. Target: JVM unit (local). Steps: (a) fire
  `SdpObserver.onSetFailure(msg)` during `applyRemoteAnswer`; (b) separately,
  `fireState(FAILED)`. Expected: both map to `CallConnectionState.Failed` and
  trigger idempotent teardown; `DISCONNECTED` maps to `Disconnected`.
  Traces: AC-5.

- **TC-AND-294-09 — Connect timeout (virtual time) maps to
  Failed("connect_timeout").** Type: unit. Target: JVM unit (local).
  Preconditions: virtual-time dispatcher; no `CONNECTED` callback fired. Steps:
  `createOffer()`; `advanceTimeBy(20_000)`. Expected: `connectionState` ends
  `Failed("connect_timeout")` with zero wall-clock dependency. (Marks the
  unverified 20s assumption from §16.) Traces: AC-5.

- **TC-AND-294-10 — Illegal transition after Closed is ignored, not a crash.**
  Type: unit. Target: JVM unit (local). Steps: reach `Closed`; fire
  `fireState(CONNECTED)`. Expected: state stays `Closed`; no exception.
  Traces: AC-5.

- **TC-AND-294-11 — `POST .../signal` serializes `CallSignalingIn` and sends
  auth/CSRF headers.** Type: contract/MockWebServer. Target: JVM unit (local,
  OkHttp MockWebServer). Preconditions: enqueue `200` `CallSignalingOut`. Steps:
  send a `webrtc.offer` via `RetrofitSignalingTransport`. Expected: recorded
  request path == `/messaging/messages/calls/{call_id}/signal`, method `POST`;
  headers `Authorization`, `X-SESSION-ID`, `X-CSRF-Token` present; JSON body has
  exactly `type,event_id,conversation_id,recipient_user_id,nonce,sent_at,payload`
  (Moshi); response decodes to `SignalingAck` with `status`. Traces: AC-6, AC-9.

- **TC-AND-294-12 — SSE stream decodes `webrtc.answer` and
  `webrtc.ice_candidate`; reconnects once on drop.** Type: contract/MockWebServer.
  Target: JVM unit (local, MockWebServer). Preconditions: enqueue a chunked
  `text/event-stream` body with a heartbeat `:` line, a multi-line `data:`
  answer frame, and an ICE frame, then close the stream; enqueue a second
  stream for the reconnect. Steps: subscribe to `events()` on
  `/messaging/events/stream`. Expected: frames decode to `SignalEvent.Answer` /
  `SignalEvent.Ice` (heartbeats ignored); exactly one reconnect after the drop.
  Traces: AC-6.

- **TC-AND-294-13 — Error mapping: `422` HTTPValidationError and `409`/`503`
  CallSignalingErrorOut both surface as `ApiResult.Error`.** Type:
  contract/MockWebServer. Target: JVM unit (local, MockWebServer).
  Steps: (a) enqueue `422` with `detail:[{loc,msg,type}]` → assert message
  equals the flattened `msg` (matches `normalizeErrorDetail`); (b) enqueue `503`
  with `{code:"unavailable",message:"..."}` → assert `ApiResult.Error` carries
  `code` and `message`. Expected: both map to `ApiResult.Error`; no crash on the
  differing shapes. Traces: AC-6.

- **TC-AND-294-14 — Privacy: failure `reason` and logs contain no SDP/ICE
  payloads.** Type: unit. Target: JVM unit (local). Preconditions: `FakeLogger`
  installed; SDP/ICE fixtures contain a recognizable IP/candidate token. Steps:
  drive transport-error and FAILED paths. Expected: `Failed.reason` and all
  captured log lines contain stable codes only and **none** of the SDP/candidate
  fixture tokens; exactly one log entry per state transition (no noisy/duplicate
  logging). Traces: AC-9.

> **Device-target note.** No case in this suite requires the headless emulator
> AVD `test35` or the physical Samsung Galaxy A15 (SM-A156U). The foundation
> layer is fully exercised with mocked transport + mocked native WebRTC on the
> JVM unit target (AC-2: JVM-only, no emulator). The real-hardware WebRTC paths
> (mic/camera capture, real TURN/ICE gathering, arm64-v8a `.so` loading,
> API-34-vs-35 behavior) belong to downstream E39 UI/orchestration tickets and
> **MUST** run on the physical device there; they are explicitly out of scope
> here and are listed so the gap is intentional, not an omission.

### Coverage matrix (§14 AC → TC)

| AC | Acceptance criterion (abbrev.) | Covered by |
|----|-------------------------------|------------|
| AC-1 | All §11 classes exist and pass | TC-01, TC-02 (representative; full suite = all TCs) |
| AC-2 | JVM-only, no emulator/dev-host, < 5s | All TCs (JVM target; see device-target note) |
| AC-3 | Offer/answer/ICE cycle reaches `Connected` via fakes | TC-02 |
| AC-4 | Round-trip ordering + ICE buffer/flush | TC-01, TC-03, TC-04 |
| AC-5 | Error/disconnect/timeout → Failed/Disconnected; idempotent teardown; no leaks | TC-05, TC-06, TC-07, TC-08, TC-09, TC-10 |
| AC-6 | Contract: body, headers, SSE decode, 422/4xx mapping, 1 reconnect | TC-11, TC-12, TC-13 |
| AC-7 | Coverage ≥ 85% of AND-289/290 classes | (gate; achieved by the union of all TCs — measured in CI, not a single TC) |
| AC-8 | Non-flaky over 100 reruns | (CI rerun harness over all TCs; virtual time in TC-09 removes wall-clock flakiness) |
| AC-9 | No PII/SDP in log/reason assertions | TC-07, TC-11, TC-14 |
