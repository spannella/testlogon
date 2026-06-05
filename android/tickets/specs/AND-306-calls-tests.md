---
id: AND-306
title: Calls tests
milestone: M7
epic: E40
priority: P1
size: M
status: draft
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
  cookie-authenticated REST + push signaling envelopes and maps transport
  failures into the right terminal states.
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
  fakes must reproduce.
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
(invite, answer, ICE candidate, bye, error) round-trips through Moshi without
loss; FastAPI `detail` error shapes (string | `[{msg}]` | `{code,...}`) map to
typed `ApiResult.Error`.

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

## 5. API Contract

This ticket consumes, and asserts against, the AND-305/AND-296 signaling
contract; it defines none. The fakes and codec tests reproduce these shapes
(derived from `frontend/src/api/types.ts` and `/openapi.json`).

Outgoing invite (`POST /ui/calls/invite`):

```json
{ "peer_id": "u_42", "call_type": "audio", "sdp_offer": "v=0..." }
```
Response:
```json
{ "call_id": "c_9f3", "challenge_id": null, "ice_servers": [
  { "urls": ["stun:18.222.237.167:3478"] } ] }
```

Inbound push / poll envelope (the shape `FakeSignalingTransport.emit` produces):

```json
{ "type": "answer", "call_id": "c_9f3", "sdp_answer": "v=0...",
  "from": "u_77", "ts": 1717545600 }
```
`type` enumerates `invite | answer | ice | bye | error`. `bye` carries
`{ "reason": "hangup|declined|no_answer|failed" }`.

Auth: every signaling call rides the persistent cookie jar plus the `ui_csrf`
cookie echoed as `X-CSRF-Token`. Codec tests with MockWebServer assert the
header is present and the body matches. A `401` body of
`{ "detail": "csrf" }` must trigger one `POST /ui/session/refresh` then retry.

Error `detail` shapes the codec must decode into `ApiResult.Error`:

```json
"not in call"                                  // string
[{ "loc": ["body","peer_id"], "msg": "field required" }]   // array
{ "code": "peer_busy", "message": "callee busy" }          // object
```

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
- **Single 401**: exactly one `POST /ui/session/refresh` then one retry of the
  original send; assert call count via the fake. Success after refresh keeps the
  call alive.
- **Double 401**: refresh + retry both 401 -> `Failed(reason = AuthExpired)`;
  assert no infinite refresh loop (refresh invoked once).
- **5xx on send**: mapped to `Failed(reason = ServerError)`.
- **Malformed inbound envelope**: dropped with a logged warning; state
  unchanged; the call is NOT failed by a single bad push (resilience to the
  unreliable dev host).
- **Ring timeout**: covered by FR-5 via virtual time only.
- The unreliable-dev-host posture (≈20s timeout, bounded backoff for idempotent
  GETs only) is asserted at the transport-mapping layer: a `poll`-style
  idempotent fetch is retried with backoff in the fake; the non-idempotent
  invite/bye are not retried.

## 8. Security & Privacy

No new attack surface; this is test code. Constraints the tests enforce:

- Fixtures use synthetic data only (`u_42`, `c_9f3`); no real credentials,
  cookies, or tokens are committed. Any captured `Set-Cookie`/CSRF value in a
  MockWebServer test is a hard-coded dummy.
- Codec tests assert the `X-CSRF-Token` header is sent (regression guard against
  AND-305 dropping CSRF) and that SDP/ICE payloads are not written to logs.
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
  - `SignalingCodecTest` — Moshi round-trip for all five envelope types; all
    three `detail` error shapes; CSRF header presence via MockWebServer.
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
- **R3 — Push vs. poll signaling.** It is unconfirmed whether inbound signaling
  arrives via FCM data push (AND-297) or REST long-poll for the audio call path.
  The fake abstracts both behind `inbound(): Flow`, but the §7 backoff
  assertion only applies if a poll path exists. **Open question for AND-305.**
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
- AC-7: All five signaling envelopes Moshi-round-trip; all three FastAPI
  `detail` shapes decode to typed `ApiResult.Error`; `X-CSRF-Token` is sent.
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
