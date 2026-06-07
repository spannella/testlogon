---
id: AND-306
title: Calls tests
milestone: M7
epic: E40
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-305]
blocks: []
---

# AND-306 — Calls tests

## 1. Overview & Goal

AND-306 delivers the automated test suite that locks down the call lifecycle
state machine and its signaling layer produced by AND-305 (`Calls ViewModels +
state machine`). This is a **Test** ticket: it adds no shipping UI or new
production behavior. Its goal is to make the call state machine and the
signaling adapter that drives it provably correct, deterministic, and
regression-proof before the dependent feature tickets (incoming call UX,
group grid, billing, recording, history) build on top of it.

Concretely, the suite must:

- Exhaustively exercise the `CallState` transition table — every legal
  edge, and rejection of every illegal edge — for both outgoing (AND-296)
  and incoming (AND-297) flows.
- Verify the `CallViewModel` emits the correct ordered `StateFlow<CallUiState>`
  sequence in response to user intents and inbound signaling events.
- Verify the signaling adapter correctly serializes/deserializes the
  REST signaling envelopes (auth = `Authorization: Bearer <accessToken>` +
  `X-CSRF-Token` from the `ui_csrf` cookie + cookie jar; see §5 — CORRECTED:
  the web client is not purely cookie-authenticated) and the **SSE** inbound
  stream, and maps transport failures into the right terminal states.
- Run fully offline against fakes (no network, no real WebRTC, no Telecom),
  on a single virtual-time dispatcher so the suite is fast and flake-free.

"Pass" (the backlog acceptance) is defined here as: the suite is green in CI on
the `android-port` branch, covers the criteria in §14, and meets the coverage
floor in §11.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace base `com.testlogon.android`.
- Unit under test (UUT): `:feature-calls` (the state machine + ViewModels from
  AND-305) and the signaling adapter in `:core-network` /
  `:feature-calls:signaling`.
- Module layering: `app -> feature-calls -> core-* (core-network, core-model,
  core-ui, core-data, core-testing)`. Test doubles live in `:core-testing`.
- Dependency: **AND-305** (state machine + ViewModels). This ticket cannot be
  authored until AND-305's public types are merged; it is the validation gate
  for AND-305 and indirectly for AND-296/AND-297.
- Downstream consumers whose own tests rely on this fixture base:
  AND-300 (group grid), AND-301 (billing), AND-302 (recording consent),
  AND-303 (history), AND-304 (ConnectionService/Telecom).
- Backend signaling contract: FastAPI dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). Tests **do not** hit it; the OpenAPI at
  `/openapi.json` and the web reference (`frontend/src/api/endpoints/*.ts`,
  `frontend/src/api/types.ts`) are the source of truth for the JSON shapes the
  fakes must reproduce. CORRECTED: the 1:1 call endpoints live under the
  `/messaging/messages/calls/...` prefix (the web client's `api` wrapper
  prepends `/messaging`), NOT under `/ui/calls/...` (that prefix is the
  separate *group* call API + history/rates/stats). See §5 and §16.
- Test stack: JUnit4 + Kotlin, `kotlinx-coroutines-test` 1.8 (`runTest`,
  `StandardTestDispatcher`, `TestScope`), Turbine 1.1 for `Flow` assertions,
  Truth 1.4 for fluent assertions, MockK 1.13 for protocol fakes, Robolectric
  4.13 only where an Android type (`SavedStateHandle`) is unavoidable. Pure JVM
  (`src/test`) is strongly preferred; no instrumented/`androidTest` is required
  by this ticket.

## 3. Functional Requirements

The suite is organized into four test classes. Each requirement is testable.

FR-1 — **State machine transition coverage.** For the `CallStateMachine` from
AND-305, assert every transition in the canonical table (§6) maps
`(currentState, event) -> nextState`. Illegal `(state, event)` pairs must be
rejected without mutating state and surface a `CallError.IllegalTransition`.

FR-2 — **Terminal-state immutability.** Once in `Ended` or `Failed`, any further
event is a no-op (state unchanged, no new effects emitted).

FR-3 — **Outgoing flow E2E (AND-296).** Driving the machine through
`Idle -> Dialing -> Ringing -> Connecting -> Active -> Ending -> Ended`
produces exactly that ordered state sequence and the expected `CallEffect`
side-effects (send invite, start media, send bye).

FR-4 — **Incoming flow E2E (AND-297).** An inbound `InviteReceived` from
`Idle` reaches `Incoming`, then `Accept` -> `Connecting -> Active`, and
`Decline`/`InviteTimeout` reach `Ended` with the correct `EndReason`.

FR-5 — **Timeout/ring-no-answer.** A `Dialing`/`Ringing` call with no `Accepted`
within the ring window (configurable, default 45s) transitions to
`Ended(reason = NoAnswer)` driven purely by virtual time.

FR-6 — **ViewModel projection.** `CallViewModel.uiState: StateFlow<CallUiState>`
emits the correct projected UI state per machine state, including
duration-ticking while `Active`, and is correctly restored from
`SavedStateHandle`.

FR-7 — **Signaling serialization round-trip.** Every signaling envelope
round-trips through Moshi without loss. CORRECTED vocabulary (§5): the outbound
`/signal` envelope `type` is `webrtc.offer | webrtc.answer | webrtc.ice_candidate`
(+ `webrtc.screen_share_start|stop`) with SDP/candidate in `payload`; inbound SSE
events are `call.*` (lifecycle) and `webrtc.*` (media). FastAPI `detail` error
shapes (string | `[{loc,msg,type}]` | `{code,message}`) map to typed
`ApiResult.Error`.

FR-8 — **Signaling transport mapping.** Network failures from the fake transport
(timeout, 401, 5xx, malformed body) map to the documented `CallError`/terminal
state per §7. A single 401 triggers exactly one `POST /ui/session/refresh`
then a retry (AND-305 contract); a second 401 fails the call.

FR-9 — **Determinism.** No test depends on wall-clock time, real threads,
`Dispatchers.Main`, network, or test execution order. Each test seeds its own
`TestScope`.

## 4. Technical Design

### 4.1 Source set & module placement

```
feature-calls/
  src/test/java/com/testlogon/android/feature/calls/
    state/CallStateMachineTest.kt
    vm/CallViewModelTest.kt
    signaling/SignalingCodecTest.kt
    signaling/SignalingTransportMappingTest.kt
core-testing/
  src/main/java/com/testlogon/android/core/testing/calls/
    FakeSignalingTransport.kt
    CallFixtures.kt
    MainDispatcherRule.kt
```

`:core-testing` is an `implementation`/`testFixtures`-style module already on the
test classpath of every feature module; the call fakes and fixtures live there so
downstream tickets (AND-300..304) reuse them.

### 4.2 Coroutine/time control

A reusable JUnit rule swaps the main dispatcher and exposes the scheduler:

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}
```

All timing assertions use `advanceTimeBy(...)` / `advanceUntilIdle()` against
`dispatcher.scheduler`. The ring-timeout and duration ticker injected into the
machine/ViewModel in AND-305 must accept this scheduler (constructor injection
of a `CoroutineScope`/`TestDispatcher`), which this ticket assumes and asserts.

### 4.3 Fake signaling transport

The production `SignalingTransport` interface (owned by AND-305) is faked:

```kotlin
interface SignalingTransport {
    suspend fun send(envelope: SignalEnvelope): ApiResult<Unit>
    fun inbound(): Flow<SignalEnvelope>          // server-pushed events
}

class FakeSignalingTransport : SignalingTransport {
    val sent = mutableListOf<SignalEnvelope>()
    private val inbound = MutableSharedFlow<SignalEnvelope>(extraBufferCapacity = 16)
    var nextResult: () -> ApiResult<Unit> = { ApiResult.Success(Unit) }

    override suspend fun send(e: SignalEnvelope): ApiResult<Unit> {
        sent += e; return nextResult()
    }
    override fun inbound(): Flow<SignalEnvelope> = inbound
    suspend fun emit(e: SignalEnvelope) = inbound.emit(e)
    fun fail(error: ApiResult.Error) { nextResult = { error } }
}
```

This lets tests script server pushes (`emit`) and inject failures (`fail`)
without OkHttp/MockWebServer, while still allowing a couple of
`SignalingCodecTest` cases to use `MockWebServer` for true HTTP-level
serialization round-trips against the §5 contract.

### 4.4 Assertion style

`StateFlow`/`Flow` are asserted with Turbine; the machine's pure
`reduce(state, event)` is asserted with parameterized JUnit cases generated from
the transition table so adding a transition in AND-305 forces a corresponding
table row here.

```kotlin
@Test fun outgoing_happy_path_emits_ordered_states() = runTest {
    val vm = buildCallViewModel(transport = fake, dispatcher = dispatcher)
    vm.uiState.test {
        assertThat(awaitItem()).isInstanceOf(CallUiState.Idle::class.java)
        vm.onIntent(CallIntent.Dial(peerId = "u_42"))
        assertThat(awaitItem().phase).isEqualTo(Phase.DIALING)
        fake.emit(answer(callId))             // server: callee answered
        assertThat(awaitItem().phase).isEqualTo(Phase.CONNECTING)
        fake.emit(connected(callId))
        assertThat(awaitItem().phase).isEqualTo(Phase.ACTIVE)
        vm.onIntent(CallIntent.HangUp)
        assertThat(awaitItem().phase).isEqualTo(Phase.ENDED)
        cancelAndIgnoreRemainingEvents()
    }
    assertThat(fake.sent.map { it.type })
        .containsExactly(SignalType.INVITE, SignalType.BYE).inOrder()
}
```

> NOTE (review): `SignalType.INVITE`/`BYE` here are the state machine's internal
> *effect* names, not wire `type` values. On the wire (§5) the invite is
> `POST /messaging/messages/calls/invite` and the hang-up is
> `POST /messaging/messages/calls/{call_id}/end`; the `/signal` envelope `type`
> field only ever holds `webrtc.*` values. The fake records effects either way,
> but contract/MockWebServer tests must assert the corrected REST paths/bodies.

## 5. API Contract

This ticket consumes, and asserts against, the AND-305/AND-296 signaling
contract; it defines none. The fakes and codec tests reproduce these shapes
(derived from `frontend/src/api/types.ts` and `/openapi.json`).

**CORRECTED against OpenAPI + `frontend/src/api/endpoints/messaging.ts`.** The
original draft invented `/ui/calls/invite`, an `sdp_offer` field on the invite,
and an `ice_servers`/`challenge_id` invite response; none of those exist. The
real contract follows.

Outgoing invite — `POST /messaging/messages/calls/invite` (`req=CallInviteIn`,
`resp=200:CallInviteOut`). SDP is **not** carried here; it is sent separately
via the `/signal` endpoint:

```json
{ "call_id": "c_9f3", "conversation_id": "conv_1", "callee_user_id": "u_42",
  "initial_mode": "audio", "paid": false, "rate_cents_per_min": null,
  "idempotency_key": "..." }
```
Response (`CallInviteOut` — no `ice_servers`, no `challenge_id`):
```json
{ "call_id": "c_9f3", "conversation_id": "conv_1", "caller_user_id": "u_77",
  "callee_user_id": "u_42", "state": "ringing", "initial_mode": "audio",
  "start_ts": 1717545600, "paid": false, "rate_cents_per_minute": null }
```

Lifecycle actions (`call_id` in path; bodies optional):
`POST .../{call_id}/accept` (`CallAcceptIn {idempotency_key?}`),
`POST .../{call_id}/decline` (`CallDeclineIn {reason="declined"}`),
`POST .../{call_id}/end` (`CallEndIn {reason="ended", idempotency_key?}`),
`POST .../{call_id}/timeout` (`CallTimeoutIn {reason="no_answer", idempotency_key?}`).
All return `200:CallActionOut`:
```json
{ "call_id": "c_9f3", "conversation_id": "conv_1", "state": "ended",
  "event_ts": 1717545600, "from_state": "active", "reason": "ended",
  "voicemail_eligible": false }
```

SDP/ICE signaling — `POST /messaging/messages/calls/{call_id}/signal`
(`req=CallSignalingIn`, `resp=200:CallSignalingOut`). The SDP/candidate lives in
`payload`; `type` is one of
`webrtc.offer | webrtc.answer | webrtc.ice_candidate | webrtc.screen_share_start
| webrtc.screen_share_stop`:
```json
{ "type": "webrtc.offer", "event_id": "evt_1", "conversation_id": "conv_1",
  "recipient_user_id": "u_42", "nonce": "12345678", "sent_at": 1717545600,
  "payload": { "sdp": "v=0..." } }
```
Ack (`CallSignalingOut`):
```json
{ "event_id": "evt_1", "call_id": "c_9f3", "conversation_id": "conv_1",
  "event_type": "webrtc.offer", "delivered_to": "u_42", "status": "delivered" }
```

ICE/TURN servers — separate `POST /messaging/messages/calls/{call_id}/turn-credentials`
(`resp=200:TurnCredentialsOut`):
```json
{ "ttl_seconds": 300, "expires_at": 1717545900, "ice_servers": [
  { "urls": ["turn:..."], "username": "...", "credential": "..." } ] }
```

Inbound signaling — CORRECTED: arrives over **Server-Sent Events**
(`GET /messaging/events/stream`, `EventSource` with `withCredentials`), NOT FCM
data push and NOT REST long-poll. The web client (`useMessagingStream.ts`)
registers named listeners for typed events `call.invite | call.accept |
call.decline | call.end | call.missed | call.recording_* | call.voicemail_* |
call.billing_tick | call.balance_low | call.balance_depleted` and
`webrtc.offer | webrtc.answer | webrtc.ice_candidate`. The fake's
`inbound(): Flow<SignalEnvelope>` models this SSE stream.

Auth — CORRECTED: each REST call carries `Authorization: Bearer <accessToken>`
**and** the `ui_csrf` cookie echoed as `X-CSRF-Token`, sent with the cookie jar
(`credentials: "include"`). It is NOT purely cookie-authenticated. Codec tests
with MockWebServer assert both `Authorization` and `X-CSRF-Token` are present.
On a `401` for an *authenticated* caller, the client issues exactly one
`POST /ui/session/refresh` (empty body, deduplicated via a shared promise) then
retries the original request once; a 401 on retry (or a failed refresh) logs the
user out (`session_expired`).

Error `detail` shapes the codec must decode into `ApiResult.Error`
(verified against `normalizeErrorDetail` in `src/api/client.ts`):

```json
"not in call"                                  // string
[{ "loc": ["body","callee_user_id"], "msg": "field required", "type": "missing" }]  // FastAPI 422 array
{ "code": "peer_busy", "message": "callee busy" }          // object (matches CallSignalingErrorOut)
```
The `/signal` endpoint additionally returns typed `CallSignalingErrorOut
{code, message}` on 400/403/404/409/429/503.

## 6. Data & State Management

Canonical state set (from AND-305) the suite pins via the transition table:

```
Idle, Dialing, Ringing, Incoming, Connecting, Active, Ending, Ended, Failed
```

Transition table asserted by `CallStateMachineTest` (legal edges):

| From       | Event             | To         |
|------------|-------------------|------------|
| Idle       | Dial              | Dialing    |
| Idle       | InviteReceived    | Incoming   |
| Dialing    | InviteSent        | Ringing    |
| Dialing    | Failure           | Failed     |
| Ringing    | Answered          | Connecting |
| Ringing    | RemoteBye/Timeout | Ended      |
| Incoming   | Accept            | Connecting |
| Incoming   | Decline/Timeout   | Ended      |
| Connecting | MediaConnected    | Active     |
| Connecting | Failure           | Failed     |
| Active     | HangUp/RemoteBye  | Ending     |
| Ending     | ByeAcked          | Ended      |
| Ended      | (any)             | Ended      |
| Failed     | (any)             | Failed     |

Every cell **not** in the table is an illegal edge and must be enumerated as a
negative test producing `CallError.IllegalTransition` with no state change.

`CallUiState` projection asserted by `CallViewModelTest`: `phase`, `peer`,
`durationSeconds` (0 until `Active`, monotonically increasing while `Active`,
frozen on `Ended`), `isMuted`, `endReason`. State survives process death via
`SavedStateHandle["call_state"]`; a test reconstructs the ViewModel from a
seeded handle and asserts re-projection.

## 7. Error Handling & Resilience

The suite is the primary verifier of AND-305's resilience contract:

- **Send failure** (`ApiResult.Error.Network`/timeout): from `Dialing` ->
  `Failed(reason = SignalingUnreachable)`; no retry of the non-idempotent invite.
- **Single 401**: any 401 for an authenticated caller (CORRECTED: not gated on a
  `{"detail":"csrf"}` body — `src/api/client.ts` refreshes on any authenticated
  401) triggers exactly one `POST /ui/session/refresh` then one retry of the
  original send; assert call count via the fake. Success after refresh keeps the
  call alive. (An *unauthenticated* 401 propagates directly without refresh.)
- **Double 401**: refresh + retry both 401 -> `Failed(reason = AuthExpired)`
  (web behavior: `logout("session_expired")`); assert no infinite refresh loop
  (refresh invoked once; deduplicated via the shared `refreshPromise`).
- **5xx on send**: mapped to `Failed(reason = ServerError)`.
- **Malformed inbound envelope**: dropped with a logged warning; state
  unchanged; the call is NOT failed by a single bad push (resilience to the
  unreliable dev host).
- **Ring timeout**: covered by FR-5 via virtual time only.
- The unreliable-dev-host posture (≈20s timeout, bounded backoff) is asserted at
  the transport-mapping layer. CORRECTED (§5): inbound signaling is an **SSE
  stream** (`GET /messaging/events/stream`), so the backoff applies to *SSE
  reconnection* (the web client backs off up to ~30s, `MAX_RETRY_DELAY` in
  `useMessagingStream.ts`), not to a REST long-poll. The non-idempotent
  `invite`/`end`/`signal` POSTs are not retried on the wire by this adapter (a
  single transport failure on `invite` -> `Failed`). The fake models SSE
  reconnect by re-emitting on `inbound()` after a simulated drop.

## 8. Security & Privacy

No new attack surface; this is test code. Constraints the tests enforce:

- Fixtures use synthetic data only (`u_42`, `c_9f3`); no real credentials,
  cookies, or tokens are committed. Any captured `Set-Cookie`/CSRF value in a
  MockWebServer test is a hard-coded dummy.
- Codec tests assert both the `X-CSRF-Token` header (from the `ui_csrf` cookie)
  and the `Authorization: Bearer` header are sent (regression guard against
  AND-305 dropping CSRF or the access token — CORRECTED: web client sends both)
  and that SDP/ICE payloads are not written to logs.
- No test writes to the real DataStore/cookie jar; all persistence uses an
  in-memory fake so secrets never touch disk in CI.
- SDP/ICE strings in fixtures are non-routable placeholders.

## 9. Accessibility & i18n

Not applicable to this ticket — no UI is added. Accessibility and string
localization for call screens are owned and tested by the call UI tickets
(AND-296/AND-297 for the in-call/incoming surfaces and AND-300 for the grid).
This ticket only asserts that `CallUiState` exposes the semantic fields
(`endReason`, `phase`) those UIs will map to localized strings/`contentDescription`,
so the projection is stable for downstream a11y tests.

## 10. Telemetry & Logging

This ticket adds no production telemetry. It verifies the analytics/logging
contract from AND-305 by injecting a fake recorder:

```kotlin
class FakeCallAnalytics : CallAnalytics {
    val events = mutableListOf<CallEvent>()
    override fun log(e: CallEvent) { events += e }
}
```

Assertions: `call_started`, `call_connected`, `call_ended(reason)`, and
`call_failed(reason)` are emitted exactly once at the correct transitions and
in order. The suite asserts that no PII (peer id is hashed/opaque, no SDP) is
present in event payloads. Test logging itself uses JUnit output only.

## 11. Testing Strategy

- **Framework**: JUnit4, `runTest`, `StandardTestDispatcher`, Turbine, Truth,
  MockK, MockWebServer (codec only), Robolectric only for `SavedStateHandle`.
- **Test classes**:
  - `CallStateMachineTest` — parameterized over the §6 table; one positive case
    per legal edge, one negative case per illegal edge; terminal-state
    immutability; ring timeout.
  - `CallViewModelTest` — outgoing E2E, incoming E2E, decline, timeout, mute
    toggle, duration ticking, `SavedStateHandle` restore.
  - `SignalingCodecTest` — Moshi round-trip for the `CallSignalingIn`/`Out`,
    `CallInviteIn`/`Out`, `CallActionOut`, `TurnCredentialsOut`, and inbound
    `call.*`/`webrtc.*` SSE envelopes; all three `detail` error shapes +
    `CallSignalingErrorOut`; `X-CSRF-Token` **and** `Authorization` header
    presence via MockWebServer.
  - `SignalingTransportMappingTest` — §7 failure matrix (send failure, single
    401 + refresh, double 401, 5xx, malformed inbound, backoff for idempotent
    poll only).
- **Coverage floor**: ≥ 90% line coverage of `state/` and `signaling/` packages
  in `:feature-calls`, measured by JaCoCo; build fails below the floor.
- **Determinism gate**: suite runs with `--rerun-tasks` and a fixed seed in CI;
  any test touching `System.currentTimeMillis`, `Thread.sleep`, real
  `Dispatchers`, or network is rejected in review.
- **Runtime**: full suite < 10s on CI (pure JVM, no emulator).
- **Command**: `./gradlew :feature-calls:testDebugUnitTest
  :core-testing:assemble jacocoTestReport`.

## 12. Dependencies & Sequencing

- **Depends on AND-305** (state machine + ViewModels) — provides
  `CallStateMachine`, `CallViewModel`, `CallState`/`CallIntent`/`CallEffect`,
  `SignalingTransport`, `CallAnalytics`. Must be merged first.
- Transitively validates **AND-296** (outgoing) and **AND-297** (incoming) flows
  since AND-305 implements both; this suite is the regression gate for them.
- **Blocks nothing directly**, but provides the shared `:core-testing` call
  fixtures/fakes that AND-300, AND-301, AND-302, AND-303, AND-304 reuse; those
  tickets should land after these fakes exist to avoid duplicate doubles.
- No backend changes; no Telecom (AND-304) coupling — Telecom is faked/out of
  scope here and tested in its own ticket.

## 13. Risks & Open Questions

- **R1 — AND-305 API churn.** If AND-305's state/event names or the
  `SignalingTransport` interface shift after this suite is written, the table
  and fakes break. Mitigation: keep the transition table the single source of
  truth and gate AND-305 merges on this suite.
- **R2 — Timeout source injection.** Tests require the ring timeout and duration
  ticker to be driven by an injectable scheduler. If AND-305 hard-codes
  `delay`/`Dispatchers.Default`, FR-5/FR-6 cannot be made deterministic.
  **Open question / action on AND-305**: confirm constructor injection of the
  scheduler.
- **R3 — Push vs. poll signaling.** RESOLVED by this review: the web reference
  uses neither FCM push nor REST long-poll for inbound signaling — it is a
  **Server-Sent Events** stream (`GET /messaging/events/stream`, `EventSource`),
  carrying `call.*` and `webrtc.*` events (see `useMessagingStream.ts`). The fake
  still abstracts the source behind `inbound(): Flow`. Residual open question for
  AND-305: whether the *Android* client mirrors the web SSE transport or layers
  FCM high-priority data pushes for incoming-call wake-up while backgrounded
  (FCM is the only reliable background wake path on Android; SSE dies when the
  process is backgrounded). The §7 backoff assertion now targets SSE reconnect.
- **R4 — Coverage floor friction.** 90% on `signaling/` may be hard if AND-305
  leaves unreachable defensive branches; resolve by adding negative cases rather
  than lowering the floor.

## 14. Acceptance Criteria

- AC-1: `CallStateMachineTest` covers every legal edge in the §6 table (one
  passing assertion each) and rejects every illegal edge with
  `CallError.IllegalTransition` and no state mutation.
- AC-2: Terminal states `Ended`/`Failed` are immutable under any subsequent
  event.
- AC-3: Outgoing happy path emits `Idle->Dialing->Ringing->Connecting->Active->
  Ending->Ended` and sends exactly `INVITE` then `BYE`.
- AC-4: Incoming path covers accept (-> Active), decline (-> Ended/Declined),
  and timeout (-> Ended/NoAnswer).
- AC-5: Ring-no-answer reaches `Ended(NoAnswer)` via virtual time only.
- AC-6: `CallUiState` duration ticks only while `Active`, freezes on `Ended`,
  and survives a `SavedStateHandle` round-trip.
- AC-7: All signaling envelopes (§5: `CallSignalingIn/Out`, `CallInviteIn/Out`,
  `CallActionOut`, `TurnCredentialsOut`, inbound `call.*`/`webrtc.*`)
  Moshi-round-trip; all three FastAPI `detail` shapes plus `CallSignalingErrorOut`
  decode to typed `ApiResult.Error`; both `X-CSRF-Token` and `Authorization`
  headers are sent (CORRECTED).
- AC-8: Single 401 -> one `session/refresh` + retry; double 401 ->
  `Failed(AuthExpired)` with refresh invoked exactly once.
- AC-9: Analytics events emitted once each at correct transitions, no PII.
- AC-10: Suite is fully offline/deterministic, runs < 10s, ≥ 90% coverage of
  `state/` + `signaling/`, green in CI on `android-port`. (Backlog: "Pass".)

## 15. Definition of Done

- All §14 acceptance criteria met; `:feature-calls:testDebugUnitTest` green in
  CI on `android-port`.
- JaCoCo report shows ≥ 90% line coverage for `state/` and `signaling/`; the
  coverage gate is wired into the CI Gradle invocation.
- Reusable fakes/fixtures (`FakeSignalingTransport`, `CallFixtures`,
  `MainDispatcherRule`, `FakeCallAnalytics`) live in `:core-testing` and are
  documented with KDoc for downstream tickets.
- No test references the live dev host, real dispatchers, wall clock, or disk.
- Code reviewed and merged; transition table comment in `CallStateMachineTest`
  cross-references the AND-305 state definition so future edits stay in sync.
- R2/R3 open questions resolved with AND-305 author and reflected in the final
  test setup.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index/spec (`reference/openapi.index.txt`, `reference/openapi.pretty.json`,
schema names under `components.schemas`) and the web reference under `reference/src`.

1. **Outgoing invite is `POST /messaging/messages/calls/invite`** (not
   `/ui/calls/invite`). VERDICT: Corrected. SOURCE: OpenAPI `POST
   /messaging/messages/calls/invite` (op `create_call_invite...`,
   `req=CallInviteIn`, `resp=200:CallInviteOut`); `src/api/endpoints/messaging.ts`
   (`api.post("/messages/calls/invite", ...)`, base `/messaging` prepended).
2. **Invite request body = `CallInviteIn {call_id, conversation_id,
   callee_user_id, initial_mode="audio", paid, rate_cents_per_min,
   idempotency_key?}`** — there is no `peer_id`, `call_type`, or `sdp_offer`.
   VERDICT: Corrected. SOURCE: `components.schemas.CallInviteIn`.
3. **Invite response = `CallInviteOut {call_id, conversation_id, caller_user_id,
   callee_user_id, state, initial_mode, start_ts, paid, rate_cents_per_minute}`**
   — no `challenge_id`, no inline `ice_servers`. VERDICT: Corrected. SOURCE:
   `components.schemas.CallInviteOut`.
4. **SDP/ICE are sent via `POST /messaging/messages/calls/{call_id}/signal`
   (`CallSignalingIn`), with SDP/candidate inside `payload`; `type` matches
   `^(webrtc\.offer|webrtc\.answer|webrtc\.ice_candidate|webrtc\.screen_share_start|
   webrtc\.screen_share_stop)$`.** VERDICT: Corrected (draft used
   `invite|answer|ice|bye|error`). SOURCE: OpenAPI `POST
   /messaging/messages/calls/{call_id}/signal` (`req=CallSignalingIn`,
   `resp=200:CallSignalingOut`); `components.schemas.CallSignalingIn` (`type`
   pattern); `src/api/endpoints/messaging.ts: sendSignalingEvent` /
   `SignalingPayload`.
5. **Signaling ack = `CallSignalingOut {event_id, call_id, conversation_id,
   event_type, delivered_to, status}`.** VERDICT: Verified. SOURCE:
   `components.schemas.CallSignalingOut`; `messaging.ts: SignalingAck`.
6. **ICE/TURN servers come from a separate `POST
   /messaging/messages/calls/{call_id}/turn-credentials` ->
   `TurnCredentialsOut {ttl_seconds, expires_at, ice_servers:[{urls, username,
   credential}]}`.** VERDICT: Corrected (draft put ICE on the invite response).
   SOURCE: OpenAPI `POST .../turn-credentials` (`resp=200:TurnCredentialsOut`);
   `components.schemas.TurnCredentialsOut` + `TurnIceServerOut`;
   `messaging.ts: fetchTurnCredentials` / `TurnCredentialsResp`.
7. **Lifecycle actions: accept/decline/end/timeout are `POST
   .../{call_id}/{accept|decline|end|timeout}` -> `CallActionOut`, with bodies
   `CallAcceptIn{idempotency_key?}`, `CallDeclineIn{reason="declined"}`,
   `CallEndIn{reason="ended",idempotency_key?}`,
   `CallTimeoutIn{reason="no_answer",idempotency_key?}`.** VERDICT: Verified.
   SOURCE: OpenAPI rows for those paths; `components.schemas.CallActionOut`,
   `CallAcceptIn`, `CallDeclineIn`, `CallEndIn`, `CallTimeoutIn`;
   `messaging.ts: acceptCallInvite/declineCallInvite/endCall/timeoutCall`.
8. **Inbound signaling arrives via SSE (`GET /messaging/events/stream`,
   `EventSource` with `withCredentials`), event types `call.*` and `webrtc.*`** —
   not FCM data push, not REST long-poll. VERDICT: Corrected. SOURCE:
   `src/hooks/useMessagingStream.ts` (`MESSAGING_STREAM_URL =
   "/messaging/events/stream"`, `EVENT_TYPES`, `messaging:call-event` /
   `messaging:webrtc-signal` dispatch).
9. **Auth = `Authorization: Bearer <accessToken>` + `X-CSRF-Token` (from the
   `ui_csrf` cookie) + cookie jar (`credentials: "include"`).** VERDICT:
   Corrected (draft said purely cookie-authenticated). SOURCE:
   `src/api/client.ts` (sets `Authorization` from `useAuthStore.accessToken`;
   `getCookie("ui_csrf")` -> `X-CSRF-Token`; `credentials: "include"`).
10. **401 handling: authenticated 401 -> exactly one `POST /ui/session/refresh`
    (empty body, deduplicated via shared `refreshPromise`) -> one retry; failure
    on retry or refresh -> `logout("session_expired")`. Unauthenticated 401
    propagates without refresh.** VERDICT: Verified. SOURCE: `src/api/client.ts`
    (`refreshSession`, the `res.status === 401` block); OpenAPI `POST
    /ui/session/refresh` (`req=` empty, `resp=200:`).
11. **`/signal` is not retried on transport failure; the SSE stream reconnects
    with bounded backoff (~30s cap).** VERDICT: Verified (backoff target
    corrected from "idempotent REST poll" to SSE). SOURCE:
    `useMessagingStream.ts` (`MAX_RETRY_DELAY = 30_000`, retry/`connect` logic);
    POST endpoints have no retry wrapper in `client.ts`.
12. **FastAPI 422 validation body = `{detail:[{loc, msg, type}]}`; client error
    normalization accepts string | array-of-`{msg}` | object-with-`{code|msg}`.**
    VERDICT: Verified. SOURCE: `components.schemas.HTTPValidationError` +
    `ValidationError`; `src/api/client.ts: normalizeErrorDetail`.
13. **`/signal` typed error body = `CallSignalingErrorOut {code, message}` on
    400/403/404/409/429/503.** VERDICT: Verified. SOURCE: OpenAPI `POST
    .../{call_id}/signal` resp map; `components.schemas.CallSignalingErrorOut`.
14. **Call/event vocabulary the SSE carries (`call.invite|accept|decline|end|
    missed|recording_*|voicemail_*|billing_tick|balance_low|balance_depleted`,
    `webrtc.offer|answer|ice_candidate`).** VERDICT: Verified. SOURCE:
    `useMessagingStream.ts: EVENT_TYPES`.
15. **`SavedStateHandle`, `StandardTestDispatcher`, `runTest`/`advanceTimeBy`,
    `TestWatcher`-based main-dispatcher rule, Turbine, Robolectric for Android
    types.** VERDICT: Unverified-assumption (framework choices, not derivable
    from the backend/web sources). SOURCE (framework ref): kotlinx-coroutines-test
    `runTest`/`StandardTestDispatcher`
    (https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/);
    AndroidX `SavedStateHandle`
    (https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate);
    Turbine (https://github.com/cashapp/turbine).
16. **`CallStateMachine`, `CallViewModel`, `SignalingTransport`, `CallIntent`,
    `CallEffect`, `CallError.IllegalTransition`, `EndReason`, `CallAnalytics`,
    and the §6 state set/transition table.** VERDICT: Unverified-assumption —
    these are AND-305-owned Android types not present in the backend/web sources;
    the table is the spec's own normative contract, gated on AND-305 (see R1).
    SOURCE: none external (depends_on AND-305).
17. **`initial_mode` enum.** VERDICT: Unverified-assumption for the exact enum
    set. `CallInviteIn.initial_mode` is a free `string` (default `"audio"`) in
    the schema, though the web `DirectCallMode` type and `CallRecordIn.call_type`
    enum (`audio|video`) imply `audio|video`. SOURCE: `components.schemas.
    CallInviteIn` (string, no enum) vs `CallRecordIn.call_type`
    (`enum:[audio,video]`); `messaging.ts: DirectCallMode`.

### Corrections made

- C1: Invite endpoint `POST /ui/calls/invite` -> `POST
  /messaging/messages/calls/invite` (§2, §5, §4.4 note).
- C2: Invite request fields `{peer_id, call_type, sdp_offer}` -> `CallInviteIn`
  (`call_id, conversation_id, callee_user_id, initial_mode, paid,
  rate_cents_per_min, idempotency_key`); SDP removed from invite (§5).
- C3: Invite response `{call_id, challenge_id, ice_servers}` -> `CallInviteOut`
  (no `challenge_id`, no inline ICE) (§5).
- C4: ICE/TURN moved to a dedicated `turn-credentials` endpoint
  (`TurnCredentialsOut`) (§5).
- C5: Signal envelope `type` enum `invite|answer|ice|bye|error` -> `webrtc.*`,
  SDP/candidate carried in `payload`; ack is `CallSignalingOut` (§3 FR-7, §5).
- C6: Inbound transport "FCM push / REST long-poll" -> **SSE**
  `GET /messaging/events/stream` with `call.*`/`webrtc.*` events (§2, §5, §7, R3).
- C7: Auth "cookie-authenticated only" -> `Authorization: Bearer` + `X-CSRF-Token`
  + cookie jar; codec/MockWebServer tests assert both headers (§2, §5, §8, §11,
  §14 AC-7).
- C8: 401 trigger gated on `{"detail":"csrf"}` -> any authenticated 401; double
  401 -> `logout("session_expired")` (§7).
- C9: §7 backoff "idempotent REST poll only" -> SSE reconnect backoff (~30s cap);
  R3 reframed as resolved-to-SSE with an Android-FCM residual question.

### Open assumptions

- OA1: All AND-305 public Kotlin types (state machine, ViewModel, transport
  interface, errors, analytics) and the §6 transition table are unverifiable
  from backend/web sources — they are produced by the dependency (AND-305) and
  are the spec's own normative contract. Gated by R1.
- OA2: Test-framework selections (coroutines-test, Turbine, Truth, MockK,
  Robolectric, MockWebServer) are engineering choices, not contract facts; cited
  as framework refs only.
- OA3: Exact `initial_mode` enum — schema types it as a free string; `audio|video`
  is inferred from related schemas/web types, not pinned by `CallInviteIn`.
- OA4: Whether the Android client uses SSE (as web) or adds an FCM high-priority
  data-push path for backgrounded incoming-call wake-up is unresolved (R3); the
  fake abstracts the source so the suite is agnostic.
- OA5: The unreliable-dev-host "≈20s timeout" figure is an operational assumption
  from the spec, not asserted by any source; tests inject the timeout, they do
  not pin a specific value against the backend.

## 17. Test Plan

Test IDs `TC-AND-306-NN`. Targets: JVM = local JUnit/Robolectric (no device);
emulator = headless AVD `test35` (x86_64, API 35); device = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This is a pure-JVM unit/contract
ticket, so almost every case runs JVM-local; emulator/device notes are included
only where a downstream/realism check is warranted.

- **TC-AND-306-01** — Type: unit (JVM). Target: JVM (`CallStateMachineTest`,
  parameterized over §6 table). Preconditions: AND-305 `CallStateMachine`
  available; one `TestScope`. Steps: for each legal `(from, event)` row, seed the
  machine in `from`, apply `event`, read next state. Expected: result equals the
  table's `To` for every row; emitted `CallEffect`s match (e.g. `Dial` ->
  `Dialing` + send-invite effect). Traces: AC-1, AC-3 (partial).
- **TC-AND-306-02** — Type: unit (JVM). Target: JVM (`CallStateMachineTest`).
  Preconditions: as 01. Steps: enumerate every `(state, event)` pair NOT in the
  §6 table; apply each from that state. Expected: state unchanged AND a
  `CallError.IllegalTransition` surfaced; no effects emitted. Traces: AC-1.
- **TC-AND-306-03** — Type: unit (JVM). Target: JVM. Preconditions: machine in
  `Ended`, then separately in `Failed`. Steps: apply each event type to each
  terminal state. Expected: state stays `Ended`/`Failed`; no new effect/analytics
  emitted. Traces: AC-2.
- **TC-AND-306-04** — Type: integration (JVM, fakes). Target: JVM
  (`CallViewModelTest` + `FakeSignalingTransport`, Turbine). Preconditions:
  `buildCallViewModel(transport=fake, dispatcher)`. Steps: collect `uiState`;
  `Dial` -> assert `INVITE` effect/REST invite recorded; `fake.emit(call.accept)`
  then `webrtc.answer`; `webrtc.*` connected; `HangUp`. Expected: ordered phases
  `Idle->Dialing->Ringing->Connecting->Active->Ending->Ended`; transport records
  exactly invite then end (BYE), in order. Traces: AC-3.
- **TC-AND-306-05** — Type: integration (JVM, fakes). Target: JVM
  (`CallViewModelTest`). Preconditions: fresh VM. Steps: `fake.emit` an inbound
  `call.invite` -> assert `Incoming`; branch A `Accept` -> `Connecting`->`Active`;
  branch B `Decline` -> `Ended(Declined)`; branch C let ring window elapse via
  `advanceTimeBy` -> `Ended(NoAnswer)`. Expected: each branch reaches the stated
  terminal state with correct `EndReason`; decline/timeout post the corresponding
  REST action (`decline`/`timeout`). Traces: AC-4, AC-5 (partial).
- **TC-AND-306-06** — Type: unit (JVM, virtual time). Target: JVM
  (`CallStateMachineTest`/`CallViewModelTest`). Preconditions: ring window
  default 45s, injected scheduler. Steps: enter `Dialing`/`Ringing`, no
  `Answered`; `advanceTimeBy(45_000)`. Expected: transitions to
  `Ended(reason=NoAnswer)` driven purely by virtual time; no wall-clock/thread
  use. Traces: AC-5.
- **TC-AND-306-07** — Type: Robolectric unit (JVM). Target: JVM (Robolectric for
  `SavedStateHandle`). Preconditions: VM driven to `Active`, duration > 0. Steps:
  observe `durationSeconds` ticking only while `Active`; drive to `Ended` and
  assert frozen; serialize state to a `SavedStateHandle["call_state"]`,
  reconstruct VM from the seeded handle, re-read `uiState`. Expected: duration is
  0 until `Active`, monotonic while `Active`, frozen on `Ended`; restored VM
  re-projects the same `phase`/`peer`/`endReason`. Traces: AC-6.
- **TC-AND-306-08** — Type: contract/MockWebServer (JVM). Target: JVM
  (`SignalingCodecTest`). Preconditions: MockWebServer enqueues canned 200s.
  Steps: round-trip each envelope (`CallInviteIn/Out`, `CallSignalingIn/Out`,
  `CallActionOut`, `TurnCredentialsOut`, inbound `call.*`/`webrtc.*`) through
  Moshi; POST invite + signal and inspect recorded requests. Expected: lossless
  round-trip; recorded requests carry `Authorization: Bearer ...` AND
  `X-CSRF-Token: ...`; bodies match §5 field names exactly (`callee_user_id`,
  `payload`, etc.). Traces: AC-7.
- **TC-AND-306-09** — Type: contract (JVM). Target: JVM (`SignalingCodecTest`).
  Preconditions: three canned error bodies. Steps: decode string `detail`, the
  FastAPI 422 array `[{loc,msg,type}]`, the object `{code,message}` /
  `CallSignalingErrorOut`. Expected: each maps to a typed `ApiResult.Error` with
  the right message/code; no unhandled-shape exception. Traces: AC-7.
- **TC-AND-306-10** — Type: contract/MockWebServer (JVM). Target: JVM
  (`SignalingTransportMappingTest`). Preconditions: MockWebServer scripts a 401
  on the first signal/invite POST, 200 on retry, and a 200 for
  `/ui/session/refresh`. Steps: issue an authenticated send. Expected: exactly
  one `POST /ui/session/refresh` (empty body) then exactly one retry of the
  original request; call stays alive. Assert request count via dispatcher.
  Traces: AC-8.
- **TC-AND-306-11** — Type: contract/MockWebServer (JVM). Target: JVM
  (`SignalingTransportMappingTest`). Preconditions: 401 on send, 200 on refresh,
  401 again on retry. Steps: issue send. Expected: `Failed(reason=AuthExpired)`
  (web: `session_expired` logout); refresh invoked exactly once (no loop).
  Traces: AC-8.
- **TC-AND-306-12** — Type: contract (JVM). Target: JVM
  (`SignalingTransportMappingTest`). Preconditions: fake transport scripted per
  §7. Steps: (a) network/timeout on `invite` from `Dialing`; (b) 5xx on send;
  (c) malformed inbound SSE envelope; (d) `/signal` POST failure. Expected: (a)
  `Failed(SignalingUnreachable)`, no retry of the non-idempotent invite; (b)
  `Failed(ServerError)`; (c) dropped + logged warning, state unchanged, call NOT
  failed; (d) no on-wire retry of `/signal`. Traces: AC-8 (partial), AC-10
  (resilience/offline path).
- **TC-AND-306-13** — Type: unit (JVM, fakes). Target: JVM
  (`CallViewModelTest` + `FakeCallAnalytics`). Preconditions: VM driven through
  happy path and through a failure path. Steps: capture `FakeCallAnalytics.events`.
  Expected: `call_started`, `call_connected`, `call_ended(reason)` (or
  `call_failed(reason)`) emitted exactly once each at the correct transitions and
  order; assert no PII (no raw SDP, peer id opaque/hashed). Traces: AC-9.
- **TC-AND-306-14** — Type: unit (JVM, security). Target: JVM
  (`SignalingCodecTest`/`SignalingTransportMappingTest`). Preconditions:
  fixtures with synthetic IDs and a dummy `ui_csrf`. Steps: round-trip envelopes
  carrying SDP/ICE and dummy cookies; inspect captured log output. Expected:
  SDP/ICE payloads and CSRF/cookie values never appear in logs; fixtures contain
  no real credentials; in-memory persistence only (nothing written to disk).
  Traces: AC-9, AC-10 (security/privacy).
- **TC-AND-306-15** — Type: unit (JVM, determinism gate). Target: JVM (whole
  suite under `--rerun-tasks`). Preconditions: CI Gradle invocation with JaCoCo.
  Steps: run `:feature-calls:testDebugUnitTest jacocoTestReport` twice with a
  fixed seed. Expected: identical green results both runs; no test references
  `System.currentTimeMillis`/`Thread.sleep`/real `Dispatchers`/network/disk;
  runtime < 10s; line coverage of `state/` + `signaling/` >= 90% (build fails
  below floor). Traces: AC-10.
- **TC-AND-306-16** — Type: instrumented/e2e smoke (emulator; device for
  realism). Target: emulator `test35` first; MUST also run on the physical
  Galaxy A15 (SM-A156U, API 34, arm64-v8a) once AND-296/297 wire real signaling,
  to catch arm64-vs-x86 / API-34-vs-35 ABI differences in the Moshi/codec layer
  and confirm the SSE/FCM inbound path actually wakes the app. Preconditions:
  AND-305 + a minimal harness Activity; this case is OUT OF SCOPE for AND-306's
  green bar (pure-JVM) and is documented as a forward-looking handoff to the UI
  tickets. Steps: drive an outgoing invite against a MockWebServer-on-device or
  staging; observe state transitions on hardware. Expected: same ordered phases
  as TC-04 on real hardware. Traces: AC-3, AC-10 (realism caveat — not a CI gate
  for this ticket).

### Coverage matrix

| §14 AC | Covered by |
|--------|------------|
| AC-1   | TC-01, TC-02 |
| AC-2   | TC-03 |
| AC-3   | TC-01 (effects), TC-04, TC-16 (realism) |
| AC-4   | TC-05 |
| AC-5   | TC-05 (timeout branch), TC-06 |
| AC-6   | TC-07 |
| AC-7   | TC-08, TC-09 |
| AC-8   | TC-10, TC-11, TC-12 |
| AC-9   | TC-13, TC-14 |
| AC-10  | TC-12, TC-14, TC-15, TC-16 (realism caveat) |
