---
id: AND-318
title: Broadcast host tests
milestone: M7
epic: E41
priority: P2
size: M
status: draft
depends_on: [AND-317]
blocks: []
---

# AND-318 — Broadcast host tests

## 1. Overview & Goal

AND-318 delivers the automated test suite for the broadcast **host session
state machine** and **host control surface** introduced by AND-317
(`feature-broadcast-host`). AND-317 ships the ViewModels that drive a creator's
live broadcast: going live, ingest lifecycle wiring (AND-308 WebRTC ingest),
viewer/earnings counters, goals/products, tips config, private-show requests,
and ad-break control. This ticket adds the unit and ViewModel-level tests that
prove every state transition is correct, every host control mutates state and
emits the intended side effects, and every failure path resolves to a defined
UI state.

The goal is a deterministic, fast (JVM-only, no instrumentation), and
maintainable test suite that pins the host state machine so later edits cannot
silently regress it. Per the source backlog, scope is **"State + control
tests"** and acceptance is simply **"Pass."** — i.e., green, meaningful, and
covering the documented transitions. This is a Test-type ticket: it adds no
production behavior. Any test that reveals a defect in AND-317 is fixed in
AND-317, not here, but the test still lands in this ticket.

Module: `:feature-broadcast-host` test source set (`src/test/...`), with shared
fakes contributed to `:core-testing` where reusable.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), JDK 17, Gradle 8.9,
  AGP 8.7.3. ViewModels expose `StateFlow<UiState>`; typed `ApiResult<T>`;
  FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`).
- **System under test (AND-317):** `com.testlogon.android.feature.broadcast.host.*`
  host ViewModels and the `HostSessionStateMachine` reducer.
- **Upstream deps:** AND-308 (WebRTC ingest — `inputs` + `webrtc-offer`),
  AND-282/AND-283 (broadcast core/session), AND-314 (goals/products), AND-315
  (tips config / private shows), AND-316 (ad breaks / ad config).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). Tests **never** hit the network; all transport is
  faked. Endpoint shapes mirror `/openapi.json` and the web reference under
  `frontend/src/api/endpoints/*.ts`.
- **Testing libraries:** JUnit4, `kotlinx-coroutines-test` 1.9
  (`StandardTestDispatcher`, `runTest`, `TestScope`), Turbine 1.1 for Flow
  assertions, Truth 1.4 for fluent assertions, MockK 1.13 for stubbing
  collaborators. These are provided by `:core-testing` (AND-005-class
  infrastructure) and added to `:feature-broadcast-host` as `testImplementation`.

## 3. Functional Requirements

The suite MUST cover the following, expressed as behaviors of AND-317:

1. **State machine transitions.** `HostSessionStateMachine` must be exercised
   as a pure reducer: `reduce(state, event) -> state`. Every legal transition
   in the table (§4) has at least one test; every illegal event is asserted to
   be a no-op (state unchanged) rather than a crash.
2. **Go-live / end-show lifecycle.** `HostSessionViewModel` transitions
   `Idle -> Connecting -> Live -> Ending -> Ended`, and the error branches
   `Connecting -> Failed` and `Live -> Reconnecting -> Live | Failed`.
3. **Host controls.** Each control method produces the correct state delta and,
   where applicable, the correct outbound call on the (faked) repositories:
   toggle mic/camera, start/stop ad break (AND-316), apply tips config
   (AND-315), accept/decline/end private show (AND-315), update goal/product
   (AND-314).
4. **Counters & telemetry projection.** Viewer-count and tip/earnings events
   fold into `HostSessionUiState` monotonically and are not lost across
   reconnect.
5. **Idempotency & guards.** Calling `goLive()` twice, `endShow()` while already
   `Ended`, or `startAdBreak()` during an active ad break must be ignored
   (single side effect, stable state).
6. **Error mapping.** Repository `ApiResult.Error` (FastAPI `detail` variants)
   maps to a user-facing `HostError` and the documented terminal/recoverable
   state.
7. **Coverage gate.** Line + branch coverage of the host package
   (`...host.state` and `...host.vm`) ≥ 85% via JaCoCo, enforced in CI.

## 4. Technical Design

### 4.1 System under test (from AND-317, restated for test contracts)

```kotlin
package com.testlogon.android.feature.broadcast.host.state

enum class HostPhase { Idle, Connecting, Live, Reconnecting, Ending, Ended, Failed }

data class HostSessionUiState(
    val phase: HostPhase = HostPhase.Idle,
    val broadcastId: String? = null,
    val micEnabled: Boolean = true,
    val cameraEnabled: Boolean = true,
    val viewers: Int = 0,
    val tokensEarned: Long = 0,
    val adBreak: AdBreakState = AdBreakState.None,
    val privateShow: PrivateShowState = PrivateShowState.None,
    val tipsConfig: TipsConfig? = null,
    val error: HostError? = null,
)

sealed interface HostEvent {
    data class GoLiveRequested(val broadcastId: String) : HostEvent
    data object IngestConnected : HostEvent          // from AND-308 WebRTC layer
    data class IngestFailed(val reason: String) : HostEvent
    data object IngestDropped : HostEvent
    data object IngestRecovered : HostEvent
    data class ViewerCount(val n: Int) : HostEvent
    data class TipReceived(val tokens: Long) : HostEvent
    data class AdBreakStarted(val seconds: Int) : HostEvent
    data object AdBreakEnded : HostEvent
    data class PrivateShowRequested(val req: PrivateShowRequest) : HostEvent
    data object EndRequested : HostEvent
    data object Ended : HostEvent
    data class Failed(val error: HostError) : HostEvent
}

object HostSessionStateMachine {
    fun reduce(state: HostSessionUiState, event: HostEvent): HostSessionUiState
}
```

```kotlin
package com.testlogon.android.feature.broadcast.host.vm

@HiltViewModel
class HostSessionViewModel @Inject constructor(
    private val hostRepo: BroadcastHostRepository,   // go-live/end, ad, tips, private
    private val ingest: WebRtcIngestController,       // AND-308
    private val events: BroadcastEventSource,         // server/socket events -> Flow<HostEvent>
    @IoDispatcher private val io: CoroutineDispatcher,
) : ViewModel() {
    val uiState: StateFlow<HostSessionUiState>
    fun goLive(broadcastId: String)
    fun endShow()
    fun toggleMic()
    fun toggleCamera()
    fun startAdBreak(seconds: Int)
    fun stopAdBreak()
    fun applyTipsConfig(config: TipsConfig)
    fun respondPrivateShow(requestId: String, accept: Boolean)
    fun endPrivateShow()
}
```

### 4.2 Transition table (the test oracle)

| From         | Event                  | To            | Side effect asserted                         |
|--------------|------------------------|---------------|----------------------------------------------|
| Idle         | GoLiveRequested        | Connecting    | `ingest.connect(broadcastId)` called once    |
| Connecting   | IngestConnected        | Live          | none                                          |
| Connecting   | IngestFailed           | Failed        | `error != null`                              |
| Live         | IngestDropped          | Reconnecting  | `ingest.reconnect()` called                  |
| Reconnecting | IngestRecovered        | Live          | counters preserved                           |
| Reconnecting | IngestFailed           | Failed        | terminal                                     |
| Live         | ViewerCount(n)         | Live          | `viewers == n`                               |
| Live         | TipReceived(t)         | Live          | `tokensEarned += t`                          |
| Live         | AdBreakStarted(s)      | Live          | `adBreak == Active(s)`                        |
| Live         | EndRequested           | Ending        | `hostRepo.endBroadcast` called               |
| Ending       | Ended                  | Ended         | `ingest.disconnect()` called                 |
| Ended/Failed | any                    | (unchanged)   | no-op                                         |

### 4.3 Test design

- **Pure reducer tests** (`HostSessionStateMachineTest`): table-driven via JUnit
  parameterized cases over `(start, event, expectedPhase)`. No coroutines.
- **ViewModel tests** (`HostSessionViewModelTest`): construct with fakes; collect
  `uiState` through Turbine; drive a `MutableSharedFlow<HostEvent>` injected as
  `BroadcastEventSource`. Use `StandardTestDispatcher` set as Main via a
  `MainDispatcherRule` (`:core-testing`), and `advanceUntilIdle()` to flush.
- **Fakes** (contributed to `:core-testing`): `FakeBroadcastHostRepository`
  records calls and returns scripted `ApiResult<T>`; `FakeWebRtcIngestController`
  records connect/reconnect/disconnect and lets the test push connection
  callbacks; `FakeBroadcastEventSource` wraps the injectable event flow.

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}
```

## 5. API Contract

This ticket defines **no new HTTP endpoints**; network DTOs are owned by the
feature tickets (AND-282/AND-308/AND-314/AND-315/AND-316). The suite asserts
against the request shapes those tickets produce through the faked repository.
The relevant calls and their fixture JSON (loaded from
`src/test/resources/fixtures/`) are:

- `POST /api/broadcasts/{id}/golive` → `{ "ingest_url": "...", "session_id": "..." }`
- `POST /api/broadcasts/{id}/end` → `204`
- `POST /api/broadcasts/{id}/ad-break` body `{ "duration_seconds": 30 }` → `{ "ad_break_id": "...", "ends_at": "..." }` (AND-316)
- `PUT  /api/broadcasts/{id}/tips-config` (AND-315)
- `POST /api/broadcasts/{id}/private-show/{requestId}/respond` body `{ "accept": true }` (AND-315)

Error fixtures cover the three FastAPI `detail` variants and a transport
timeout, each mapped to a `HostError`:

```json
// detail-string.json
{ "detail": "broadcast already ended" }
// detail-array.json
{ "detail": [ { "msg": "duration_seconds must be > 0", "loc": ["body","duration_seconds"] } ] }
// detail-object.json
{ "detail": { "code": "STREAM_LIMIT", "message": "concurrent stream limit reached" } }
```

The contract verified here: `BroadcastHostRepository` returns
`ApiResult.Error(HostError.*)` for each; the ViewModel never throws on these.

## 6. Data & State Management

- **Single source of truth:** every assertion targets `HostSessionUiState`
  emitted on `uiState`. Tests assert full-state equality where practical
  (`assertThat(state).isEqualTo(expected)`) to catch unintended field drift.
- **Counter folding:** assert `tokensEarned` and `viewers` accumulate correctly
  across a scripted event sequence including a `Reconnecting` round-trip;
  counters must survive reconnect (regression guard for AND-317).
- **No persistence in scope:** host session is ephemeral (in-memory). Room
  (`:core-data`) and DataStore are **not** exercised here. If AND-317 persists
  a "resume last broadcast" flag, that DataStore key is faked via an in-memory
  `FakeBroadcastPrefs`; otherwise N/A.
- **Determinism:** all time-based logic (ad-break countdown) is driven through
  the `TestScope` virtual clock via `advanceTimeBy()`; no `Thread.sleep`, no
  wall-clock reads in tests.

## 7. Error Handling & Resilience

Tested error/resilience behaviors (all at the ViewModel boundary, no real I/O):

1. **Go-live failure:** `hostRepo.goLive` returns `ApiResult.Error` →
   `phase == Failed`, `error` set, `ingest.connect` not called.
2. **Ingest drop/recover:** `IngestDropped` → `Reconnecting`;
   `IngestRecovered` → `Live` with counters intact; bounded retry exhaustion
   (`IngestFailed`) → `Failed`.
3. **Idempotent guards:** second `goLive()` while `Connecting`/`Live` is a
   no-op (verify `ingest.connect` invoked exactly once via MockK `verify(exactly = 1)`).
4. **End during ad break / private show:** `endShow()` cleans up child state
   (`adBreak == None`, `privateShow == None`) before `Ended`.
5. **Timeout mapping:** a faked `SocketTimeoutException`-backed `ApiResult.Error`
   (the ~20s dev-host timeout class) maps to a recoverable `HostError.Timeout`,
   not a crash. Note: tests assert mapping only; the real timeout/backoff policy
   for idempotent GETs lives in `:core-network` and is not re-tested here.

## 8. Security & Privacy

No production security surface is added. Test-specific requirements:

- **No real credentials or cookies.** Cookie-based auth, `ui_csrf`/`X-CSRF-Token`
  handling, and `/ui/session/*` flows are owned by core-auth tickets and are
  fully mocked; no fixture contains a real session cookie or token.
- **No secrets in fixtures.** `src/test/resources/fixtures/*` contain only
  synthetic ids (`bcast_test_*`). A repo CI check (existing) rejects
  hard-coded tokens.
- **No PII in logs.** Tests that assert telemetry (§10) verify that emitted
  events carry only `broadcastId` and aggregate counts, never viewer identities
  or message contents.

## 9. Accessibility & i18n

Not applicable as production behavior — this is a JVM unit suite with no UI.
Compose semantics, TalkBack, and string externalization for the host screen are
covered by the host UI ticket (the AND-317 sibling screen ticket) and the
broadcast-host Compose UI tests, not here. The one related assertion in scope:
`HostError` exposes a stable `messageResId: Int` (not a hard-coded English
string), and tests assert the **resource id**, keeping all user-facing copy
localizable.

## 10. Telemetry & Logging

AND-317 emits analytics through an injected `BroadcastAnalytics` interface. This
suite injects a `FakeBroadcastAnalytics` recorder and asserts:

- `broadcast_go_live` logged exactly once on `Idle -> Connecting`.
- `broadcast_ended` logged once on `Ending -> Ended` with `{durationMs, peakViewers, tokensEarned}`.
- `ad_break_started` / `ad_break_ended` (AND-316) logged with `duration_seconds`.
- No analytics emitted on no-op/guarded calls (idempotency check extends to
  telemetry — no duplicate `broadcast_go_live`).
- Logging uses the project `Timber`-style logger tag `BroadcastHost`; tests do
  not assert log lines but verify no `error`-level log fires on the happy path
  via a fake logger tree.

## 11. Testing Strategy

This ticket **is** the testing work. Structure:

- **Location:** `:feature-broadcast-host/src/test/java/com/testlogon/android/feature/broadcast/host/`.
- **Files:**
  - `state/HostSessionStateMachineTest.kt` — parameterized reducer table (§4.2),
    illegal-event no-op cases.
  - `vm/HostSessionViewModelTest.kt` — lifecycle, controls, counters, guards,
    error mapping, telemetry.
  - `vm/HostControlsTest.kt` — focused per-control tests (mic, camera, ad break,
    tips, private show).
- **Fakes (in `:core-testing`):** `FakeBroadcastHostRepository`,
  `FakeWebRtcIngestController`, `FakeBroadcastEventSource`,
  `FakeBroadcastAnalytics`.
- **Patterns:** `runTest { }`, `MainDispatcherRule`, Turbine
  `uiState.test { ... }`, Truth assertions, MockK `verify`. No Robolectric, no
  emulator — pure JVM for sub-second runs.
- **Representative case:**

```kotlin
@Test
fun `go live then end emits full happy-path sequence`() = runTest {
    val vm = HostSessionViewModel(fakeRepo, fakeIngest, fakeEvents, testDispatcher)
    vm.uiState.test {
        assertThat(awaitItem().phase).isEqualTo(HostPhase.Idle)
        vm.goLive("bcast_test_1"); advanceUntilIdle()
        assertThat(awaitItem().phase).isEqualTo(HostPhase.Connecting)
        fakeEvents.emit(HostEvent.IngestConnected); advanceUntilIdle()
        assertThat(awaitItem().phase).isEqualTo(HostPhase.Live)
        fakeEvents.emit(HostEvent.TipReceived(50)); advanceUntilIdle()
        assertThat(awaitItem().tokensEarned).isEqualTo(50)
        vm.endShow(); advanceUntilIdle()
        assertThat(awaitItem().phase).isEqualTo(HostPhase.Ending)
        fakeEvents.emit(HostEvent.Ended); advanceUntilIdle()
        assertThat(awaitItem().phase).isEqualTo(HostPhase.Ended)
        cancelAndIgnoreRemainingEvents()
    }
    verify(exactly = 1) { fakeIngest.connect("bcast_test_1") }
    verify(exactly = 1) { fakeIngest.disconnect() }
}
```

- **CI:** `./gradlew :feature-broadcast-host:testDebugUnitTest` plus JaCoCo
  verification `:feature-broadcast-host:jacocoTestCoverageVerification` with the
  85% line/branch rule scoped to `...host.state` and `...host.vm`.

## 12. Dependencies & Sequencing

- **Depends on:** AND-317 (Broadcast host ViewModels) — the SUT must exist and
  expose the contracts in §4. Transitively builds on AND-308 (ingest controller
  interface), AND-314/315/316 (control surfaces being tested).
- **Provides to `:core-testing`:** the four host fakes, reusable by any later
  broadcast-host UI/integration ticket.
- **Sequencing:** land immediately after AND-317 merges; runs in the same CI
  gate. No downstream ticket is blocked by AND-318 (`blocks: []`), but it acts
  as the regression guard for all subsequent edits to `:feature-broadcast-host`.

## 13. Risks & Open Questions

1. **Contract drift:** if AND-317's final field/method names differ from §4,
   tests must track the actual code. Mitigation: write tests against AND-317's
   merged API, treat §4 as the agreed interface and reconcile in review.
2. **Event-source shape:** whether broadcast events arrive via WebSocket vs.
   polling affects how `BroadcastEventSource` is faked. Open question for
   AND-317 — the suite only requires a `Flow<HostEvent>` boundary regardless.
3. **Ad-break timing model:** if the countdown is server-driven (event) vs.
   client-timer, the virtual-clock test changes. Confirm with AND-316.
4. **Coverage scope:** WebRTC ingest internals (AND-308) are out of scope and
   excluded from the 85% gate to avoid measuring native/JNI-bound code that
   cannot run on the JVM.
5. **Flakiness:** any reliance on emission ordering of `uiState` distinct values;
   mitigated by `StandardTestDispatcher` + `advanceUntilIdle` and Turbine.

## 14. Acceptance Criteria

1. `./gradlew :feature-broadcast-host:testDebugUnitTest` passes locally and in
   CI (source acceptance: **"Pass."**).
2. Every transition in the §4.2 table has a passing test; every illegal event
   from a terminal state (`Ended`, `Failed`) is asserted as a no-op.
3. Each host control (`goLive`, `endShow`, `toggleMic`, `toggleCamera`,
   `startAdBreak`, `stopAdBreak`, `applyTipsConfig`, `respondPrivateShow`,
   `endPrivateShow`) has at least one test asserting both the state delta and
   the faked side effect.
4. Idempotency guards proven for `goLive`, `endShow`, and `startAdBreak`
   (`verify(exactly = 1)`).
5. All three FastAPI `detail` variants plus a timeout map to defined
   `HostError`s with no thrown exception.
6. Counters (`viewers`, `tokensEarned`) proven to survive a `Reconnecting`
   round-trip.
7. JaCoCo line + branch coverage ≥ 85% for `...host.state` and `...host.vm`;
   `jacocoTestCoverageVerification` is green.
8. Tests are JVM-only (no emulator/Robolectric), deterministic, and complete in
   under ~10s in CI.

## 15. Definition of Done

- All §14 criteria met; CI green on branch `android-port`.
- Test files added under `:feature-broadcast-host/src/test/...`; reusable fakes
  added to `:core-testing` with KDoc.
- Fixture JSON for the three `detail` variants committed under
  `src/test/resources/fixtures/`.
- JaCoCo verification task wired into the module's `check` and the CI workflow;
  the 85% rule scoped to the host packages.
- No `Thread.sleep`, no real network, no real credentials/PII in fixtures.
- Code review approved; any defect surfaced in AND-317 filed/fixed against
  AND-317 (not patched silently here), with the corresponding regression test
  retained in this suite.
- `depends_on: [AND-317]` satisfied (SUT merged); ticket marked done with the
  test run linked in the PR.
