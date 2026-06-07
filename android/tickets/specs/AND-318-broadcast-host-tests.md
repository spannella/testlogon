---
id: AND-318
title: Broadcast host tests
milestone: M7
epic: E41
priority: P2
size: M
depends_on: [AND-317]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
  faked. Endpoint shapes mirror `/openapi.json` (see corrected contract in §5) and
  the web reference under `src/api/` (e.g. `src/api/client.ts`); there is no
  `frontend/` prefix in the reference checkout.
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

> **Corrected against `openapi.index.txt` / `openapi.pretty.json` (2026-06-06).** The
> paths/methods/shapes originally drafted here did not exist in the backend. The
> real backend contract is below; all are under `/broadcast/sessions/{session_id}/...`
> (there is no `/api/broadcasts/...` namespace). The faked repository must mirror
> these so the fixtures stay contract-accurate.

- **Go live:** `POST /broadcast/sessions/{session_id}/start` → `202: BroadcastSessionOut`
  (req `BroadcastSessionActionIn`; supports `x-idempotency-key` / `x-correlation-id`
  headers). *(Was wrongly drafted as `POST /api/broadcasts/{id}/golive` returning
  `{ingest_url, session_id}`; ingest URL comes from the inputs/webrtc-offer flow,
  AND-308, not from start.)*
- **End show:** `POST /broadcast/sessions/{session_id}/stop` → `202: BroadcastSessionOut`
  (req `BroadcastSessionActionIn`). *(Was wrongly drafted as `POST .../end` → `204`;
  the real response is `202` with a `BroadcastSessionOut` body, not an empty `204`.)*
- **Start ad break:** `POST /broadcast/sessions/{session_id}/ad-break` → `200: AdBreakOut`
  with body `{ duration_seconds, started_at, skip_after_seconds, ok }`. The trigger
  takes **no request body** (duration is server/ad-config-driven). *(Was wrongly
  drafted with a `{duration_seconds:30}` request body and an `{ad_break_id, ends_at}`
  response — neither field exists.)* (AND-316)
- **Stop ad break:** `POST /broadcast/sessions/{session_id}/ad-break/end` → `200`
  (no body). *(This is a distinct endpoint; `stopAdBreak()` maps here, not to a
  parameter on the trigger call.)* (AND-316)
- **Tips config:** `PATCH /broadcast/sessions/{session_id}/tips/config` → `200: BroadcastSessionOut`
  (req `BroadcastTipConfigIn` = `{ tip_enabled?, tip_min_cents?, tip_max_cents? }`).
  *(Was wrongly drafted as `PUT .../tips-config`; method is `PATCH` and the path
  segment is `tips/config`.)* (AND-315)
- **Respond to private-show request:** there is **no single `/respond` endpoint**.
  Accept and decline are separate: `POST /broadcast/sessions/{session_id}/private/{request_id}/accept`
  (req `PrivateRequestAcceptIn` = `{ behavior: "pause"|"end"|"continue" }`) → `200: PrivateAcceptOut`,
  and `POST /broadcast/sessions/{session_id}/private/{request_id}/decline` → `200`
  (no body). End an active private session: `POST /broadcast/sessions/{session_id}/private/{private_id}/end`
  → `200: PrivateSessionEndOut`. *(Was wrongly drafted as one `.../private-show/{requestId}/respond`
  with a `{accept:true}` body. `respondPrivateShow(requestId, accept)` therefore
  dispatches to the accept or decline endpoint based on the flag.)* (AND-315)

Auth/transport (verified in `src/api/client.ts`): the web client sends `Authorization:
Bearer <accessToken>`, `X-CSRF-Token` (read from the `ui_csrf` cookie), `credentials:
"include"`, and optional `X-IMPERSONATION-TOKEN`; the OpenAPI also documents
`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` header params on these routes. This suite
mocks all of it (see §8) and asserts none of it directly.

Error fixtures cover the three FastAPI `detail` variants and a transport
timeout, each mapped to a `HostError`:

```json
// detail-string.json  (app-level FastAPI HTTPException)
{ "detail": "broadcast already ended" }
// detail-array.json  (the documented 422 = HTTPValidationError schema; each item is
//                     a ValidationError requiring loc, msg, AND type)
{ "detail": [ { "type": "greater_than", "msg": "Input should be greater than 0", "loc": ["body","duration_seconds"] } ] }
// detail-object.json  (app-level structured error)
{ "detail": { "code": "STREAM_LIMIT", "message": "concurrent stream limit reached" } }
```

> **Correction (verified against `components.schemas.HTTPValidationError` /
> `ValidationError`):** the array variant is the only one defined by the OpenAPI
> 422 schema, and each `ValidationError` requires `loc`, `msg`, **and `type`** — the
> original fixture omitted the required `type` field, so it has been added. The
> string and object `detail` variants are app-level `HTTPException` payloads (not in
> the 422 schema) but are realistic backend responses on `start`/`stop`/`ad-break`;
> the repository's `detail` parser must tolerate all three shapes.

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

- **No real credentials or cookies.** The web transport (verified in
  `src/api/client.ts`) uses `Authorization: Bearer`, an `X-CSRF-Token` header
  sourced from the `ui_csrf` cookie, `credentials: "include"`, and an optional
  `X-IMPERSONATION-TOKEN`; backend routes also accept `X-SESSION-ID`. All of this
  is owned by core-auth tickets and is **fully mocked** here; no fixture contains a
  real session cookie, bearer token, or CSRF value.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec
(`reference/openapi.pretty.json`, `components.schemas.*`), and frontend reference
(`reference/src/...`). "framework ref" = Android/library docs.

1. **Go-live endpoint.** Claim (orig): `POST /api/broadcasts/{id}/golive` →
   `{ingest_url, session_id}`. **VERDICT: Corrected.** Real: `POST
   /broadcast/sessions/{session_id}/start` → `202: BroadcastSessionOut`, req
   `BroadcastSessionActionIn`. Source: OpenAPI `POST /broadcast/sessions/{session_id}/start`.
2. **End-show endpoint.** Claim (orig): `POST /api/broadcasts/{id}/end` → `204`.
   **VERDICT: Corrected.** Real: `POST /broadcast/sessions/{session_id}/stop` →
   `202: BroadcastSessionOut`. Source: OpenAPI `POST /broadcast/sessions/{session_id}/stop`.
3. **Start ad-break endpoint + shape.** Claim (orig): `POST .../ad-break` body
   `{duration_seconds:30}` → `{ad_break_id, ends_at}`. **VERDICT: Corrected.**
   Real: `POST /broadcast/sessions/{session_id}/ad-break` (no request body) →
   `200: AdBreakOut` = `{duration_seconds, started_at, skip_after_seconds, ok}`.
   Source: OpenAPI `POST /broadcast/sessions/{session_id}/ad-break`; schema
   `components.schemas.AdBreakOut`.
4. **Stop ad-break endpoint.** Claim (orig): not present (modeled as a param).
   **VERDICT: Corrected.** Real: distinct endpoint `POST
   /broadcast/sessions/{session_id}/ad-break/end` → `200` (no body). Source:
   OpenAPI `POST /broadcast/sessions/{session_id}/ad-break/end`.
5. **Tips-config endpoint + method + shape.** Claim (orig): `PUT
   .../tips-config`. **VERDICT: Corrected.** Real: `PATCH
   /broadcast/sessions/{session_id}/tips/config` → `200: BroadcastSessionOut`, req
   `BroadcastTipConfigIn` = `{tip_enabled?, tip_min_cents?, tip_max_cents?}`
   (cents 100–100000). Source: OpenAPI `PATCH .../tips/config`; schema
   `components.schemas.BroadcastTipConfigIn`.
6. **Private-show respond endpoint.** Claim (orig): single `POST
   .../private-show/{requestId}/respond` body `{accept:true}`. **VERDICT:
   Corrected.** Real: separate `POST /broadcast/sessions/{session_id}/private/{request_id}/accept`
   (req `PrivateRequestAcceptIn` = `{behavior: "pause"|"end"|"continue"}` →
   `200: PrivateAcceptOut`) and `POST .../private/{request_id}/decline` → `200`.
   End active session: `POST .../private/{private_id}/end` → `PrivateSessionEndOut`.
   Source: OpenAPI those three paths; schemas `PrivateRequestAcceptIn`,
   `PrivateAcceptOut`.
7. **FastAPI 422 / `detail` shapes.** Claim (orig): three `detail` variants
   (string | array-of-`{msg,loc}` | object-`{code,message}`). **VERDICT:
   Corrected (array variant).** The documented `422` body is
   `HTTPValidationError` = `{detail: ValidationError[]}` where each
   `ValidationError` **requires `loc`, `msg`, and `type`** (orig fixture omitted
   `type`). String/object `detail` variants are valid app-level `HTTPException`
   payloads but are not the 422 schema. Source: `components.schemas.HTTPValidationError`,
   `components.schemas.ValidationError`.
8. **Auth/CSRF transport.** Claim (orig, §8): "Cookie-based auth,
   `ui_csrf`/`X-CSRF-Token`". **VERDICT: Verified (and clarified).** Web client
   sends `Authorization: Bearer`, `X-CSRF-Token` from the `ui_csrf` cookie,
   `credentials:"include"`, optional `X-IMPERSONATION-TOKEN`; routes also accept
   `X-SESSION-ID`. Source: `src/api/client.ts` (lines ~157–171, 183); OpenAPI
   route `params` columns list `X-SESSION-ID,X-IMPERSONATION-TOKEN`.
9. **WebRTC ingest path (AND-308).** Claim: ingest via `inputs` + `webrtc-offer`.
   **VERDICT: Verified.** Real: `POST /broadcast/sessions/{session_id}/inputs`
   (req `BroadcastInputCreateIn` → `BroadcastInputCreateOut`) and `POST
   .../inputs/{input_id}/webrtc-offer` (req `BroadcastWebRTCOfferIn` →
   `BroadcastWebRTCOfferOut`). Source: OpenAPI those two paths.
10. **Server event stream (`BroadcastEventSource`).** Claim: events arrive as a
    `Flow<HostEvent>`; transport open (WS vs poll). **VERDICT:
    Unverified-assumption (Kotlin boundary) / Verified (backend exists).** Backend
    exposes `GET /broadcast/sessions/{session_id}/stream` (an SSE/long-poll event
    stream) and `GET .../chat/stream`. The Kotlin `Flow<HostEvent>` abstraction is
    an AND-317 design choice not visible in these sources. Source: OpenAPI `GET
    .../stream`; AND-317 (not in repo).
11. **Viewer count source.** Claim: `ViewerCount(n)` event folds into state.
    **VERDICT: Verified (backend has a source).** `GET
    /broadcast/sessions/{session_id}/viewers/count` → `ViewerCountOut`; also
    likely surfaced via the event stream. Source: OpenAPI `GET .../viewers/count`,
    schema `ViewerCountOut`.
12. **Idempotency keys.** Claim (§5 amend): start/stop accept idempotency keys.
    **VERDICT: Verified.** `start` and `stop` declare `x-idempotency-key` and
    `x-correlation-id` header params. Source: OpenAPI `params=` on `POST
    .../start` and `POST .../stop`. Note: the ViewModel-level `goLive()`/`endShow()`
    idempotency guard (§7.3) is a client concern, separate from these headers.
13. **SUT Kotlin contracts (§4 types/methods).** Claim: `HostPhase`,
    `HostSessionUiState`, `HostEvent`, `HostSessionStateMachine.reduce`,
    `HostSessionViewModel` API. **VERDICT: Unverified-assumption.** Defined by
    AND-317, which is not present in the reference checkout (frontend is a React
    web app; no Android module here). Treat §4 as the agreed interface per §13.1.
14. **Testing libraries / JVM-only approach.** Claim: JUnit4, kotlinx-coroutines-test
    (`StandardTestDispatcher`, `runTest`), Turbine, Truth, MockK; `MainDispatcherRule`.
    **VERDICT: Verified (framework ref).** Standard, current Android testing
    stack. framework ref: developer.android.com/kotlin/coroutines/test and
    developer.android.com/training/testing. The `:core-testing` wiring itself is an
    AND-005 assumption (not in repo).
15. **JaCoCo 85% gate.** Claim: line+branch ≥85% via
    `jacocoTestCoverageVerification`. **VERDICT: Verified (framework ref) /
    Unverified (project wiring).** JaCoCo supports the rule; whether the module
    Gradle wiring exists is an AND-317/infra assumption. framework ref:
    docs.gradle.org JaCoCo plugin.

### Corrections made

- §5 go-live: `POST /api/broadcasts/{id}/golive` → `POST
  /broadcast/sessions/{session_id}/start` (`202: BroadcastSessionOut`).
- §5 end-show: `POST .../end`→`204` → `POST .../stop`→`202: BroadcastSessionOut`.
- §5 ad-break start: removed the bogus `{duration_seconds}` request body and
  `{ad_break_id, ends_at}` response; corrected to no-body request and `AdBreakOut`
  response.
- §5 ad-break stop: added the distinct `POST .../ad-break/end` endpoint.
- §5 tips: `PUT .../tips-config` → `PATCH .../tips/config` with `BroadcastTipConfigIn`.
- §5 private show: replaced the single `/respond` endpoint with the real
  `accept` (+`PrivateRequestAcceptIn` behavior) / `decline` / `private/{id}/end`
  endpoints; clarified `respondPrivateShow(requestId, accept)` dispatch.
- §5 error fixtures: added the required `type` field to the array `ValidationError`
  fixture; labeled string/object variants as app-level `HTTPException`.
- §2: corrected the reference path (`src/api/`, not `frontend/src/api/endpoints/`).
- §8: clarified the real transport (Bearer + `X-CSRF-Token` from `ui_csrf` +
  `credentials:include` + impersonation/session headers).
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **AND-317 Kotlin surface (§4).** Unverifiable: the Android module/SUT is not in
  the reference checkout (only the React web client + backend OpenAPI). All
  `HostPhase`/`HostEvent`/ViewModel signatures are taken on faith from the ticket;
  reconcile against the merged AND-317 code in review (§13.1).
- **Event transport (WS vs SSE vs poll).** Backend `GET .../stream` exists, but
  how AND-317 maps it to `Flow<HostEvent>` (and how `BroadcastEventSource` is
  shaped) is not in the sources (§13.2). Tests only require a `Flow` boundary.
- **Ad-break timing model (client timer vs server event).** Not determinable from
  sources; `AdBreakOut` carries `started_at`/`duration_seconds`/`skip_after_seconds`,
  which suggests server-authoritative timing, but the client countdown design is
  AND-316/AND-317's call (§13.3).
- **`:core-testing` / JaCoCo Gradle wiring.** Assumed to exist per AND-005-class
  infra; not present in this checkout.

## 17. Test Plan

All cases are **JVM-only** (no device) consistent with §14.8 — this ticket is a
pure unit/ViewModel suite. Target **JVM unit/Robolectric: local, no device** for
every case below; none require the emulator (`test35`) or the physical Galaxy
A15. (A note on hardware appears in TC-AND-318-13 for completeness: any real
WebRTC ingest/broadcast behavior belongs to AND-308/AND-317 instrumented suites
on the **physical device**, explicitly out of scope here.) Acceptance-criteria
references ("AC-#") point to the numbered list in §14.

- **TC-AND-318-01 — Happy-path go-live → live → end.**
  Type: unit (ViewModel). Target: JVM. Preconditions: `FakeBroadcastHostRepository`
  scripted to return `ApiResult.Success` for start/stop; `FakeWebRtcIngestController`;
  `FakeBroadcastEventSource`. Steps: collect `uiState` via Turbine; `goLive("bcast_test_1")`,
  emit `IngestConnected`, `TipReceived(50)`, `endShow()`, emit `Ended`. Expected:
  phases `Idle→Connecting→Live→Ending→Ended`; `tokensEarned==50`;
  `ingest.connect("bcast_test_1")` and `ingest.disconnect()` each called once.
  Traces: AC-1, AC-2, AC-3.

- **TC-AND-318-02 — Reducer transition table (parameterized).**
  Type: unit (pure reducer). Target: JVM. Preconditions: none (pure
  `HostSessionStateMachine.reduce`). Steps: parameterize over every `(from, event,
  to, side-effect)` row of §4.2. Expected: each produces the documented target
  phase and asserted field delta. Traces: AC-2.

- **TC-AND-318-03 — Illegal events from terminal states are no-ops.**
  Type: unit (pure reducer). Target: JVM. Preconditions: states `Ended` and
  `Failed`. Steps: feed each non-terminal `HostEvent` (e.g. `ViewerCount`,
  `TipReceived`, `GoLiveRequested`, `IngestConnected`). Expected: returned state is
  `equalTo` the input (no mutation, no throw). Traces: AC-2.

- **TC-AND-318-04 — Per-control state delta + side effect.**
  Type: unit (ViewModel). Target: JVM. Preconditions: phase `Live`; fakes record
  calls. Steps: invoke `toggleMic`, `toggleCamera`, `startAdBreak(30)`,
  `stopAdBreak`, `applyTipsConfig(cfg)`, `respondPrivateShow(id, accept=true)`,
  `respondPrivateShow(id, accept=false)`, `endPrivateShow`. Expected: each flips the
  matching `HostSessionUiState` field and records the corrected repo call —
  `startAdBreak`→`ad-break` (no body), `stopAdBreak`→`ad-break/end`,
  `applyTipsConfig`→`PATCH tips/config` with `BroadcastTipConfigIn`,
  accept→`private/{id}/accept` with `PrivateRequestAcceptIn`, decline→`private/{id}/decline`,
  `endPrivateShow`→`private/{id}/end`. Traces: AC-3.

- **TC-AND-318-05 — Go-live failure maps to Failed without connecting.**
  Type: contract/MockWebServer-style (faked repo returning a backend-shaped
  error). Target: JVM. Preconditions: `hostRepo.start` returns
  `ApiResult.Error` (from `detail-string.json`). Steps: `goLive(...)`; advance.
  Expected: `phase==Failed`, `error != null`, `ingest.connect` **not** called; no
  exception thrown. Traces: AC-3, AC-5.

- **TC-AND-318-06 — All three `detail` variants + the `type`-bearing 422 map to HostError.**
  Type: contract. Target: JVM. Preconditions: fixtures `detail-string.json`,
  `detail-array.json` (now with required `loc`/`msg`/`type`), `detail-object.json`.
  Steps: drive a failing control (e.g. `startAdBreak`) once per fixture through the
  repository's `detail` parser. Expected: each yields a defined `HostError`
  (string→message, array→first `ValidationError.msg`, object→`code`/`message`);
  ViewModel never throws. Traces: AC-5.

- **TC-AND-318-07 — Timeout / flaky-dev-host path maps to recoverable HostError.Timeout.**
  Type: contract. Target: JVM. Preconditions: faked `ApiResult.Error` backed by a
  `SocketTimeoutException` (the ~20s dev-host `18.222.237.167:8000` timeout class).
  Steps: `goLive(...)` with the timeout-scripted repo. Expected:
  `error == HostError.Timeout` (recoverable, not terminal `Failed`-only), no crash;
  asserts mapping only (backoff policy lives in `:core-network`). Traces: AC-5.

- **TC-AND-318-08 — Idempotency guards (`verify(exactly = 1)`).**
  Type: unit (ViewModel). Target: JVM. Preconditions: fakes with MockK
  verification. Steps: call `goLive()` twice while `Connecting`/`Live`; `endShow()`
  while already `Ended`; `startAdBreak()` during an active ad break. Expected:
  `ingest.connect`, `hostRepo.stop`, and the `ad-break` trigger each invoked
  exactly once; state stable. Traces: AC-4.

- **TC-AND-318-09 — Counters survive a Reconnecting round-trip.**
  Type: unit (ViewModel). Target: JVM. Preconditions: phase `Live` with
  `viewers=10`, `tokensEarned=200`. Steps: emit `IngestDropped` (→`Reconnecting`),
  more `TipReceived`/`ViewerCount` while reconnecting, then `IngestRecovered`
  (→`Live`). Expected: counters accumulate monotonically and are intact after
  recovery; `ingest.reconnect()` called. Traces: AC-2, AC-6.

- **TC-AND-318-10 — Reconnect exhaustion → Failed (terminal).**
  Type: unit (ViewModel). Target: JVM. Preconditions: phase `Reconnecting`.
  Steps: emit `IngestFailed`. Expected: `phase==Failed`, terminal; subsequent
  events are no-ops (cross-check with TC-03). Traces: AC-2, AC-5.

- **TC-AND-318-11 — End during ad break / private show cleans child state.**
  Type: unit (ViewModel). Target: JVM. Preconditions: phase `Live` with
  `adBreak=Active`, `privateShow=Active`. Steps: `endShow()`; emit `Ended`.
  Expected: before/at `Ended`, `adBreak==None` and `privateShow==None`;
  `ingest.disconnect()` called. Traces: AC-2, AC-3.

- **TC-AND-318-12 — Telemetry + no-secrets/no-PII assertions.**
  Type: unit (ViewModel). Target: JVM. Preconditions: `FakeBroadcastAnalytics`,
  fake logger tree. Steps: run the happy path (TC-01) and a guarded double
  `goLive()`. Expected: `broadcast_go_live` logged exactly once (not on the
  guarded call); `broadcast_ended` once with `{durationMs, peakViewers,
  tokensEarned}`; `ad_break_started`/`ad_break_ended` carry `duration_seconds`;
  emitted events carry only `broadcastId` + aggregate counts (no viewer identity);
  no `error`-level log on happy path; fixtures contain only synthetic
  `bcast_test_*` ids. Traces: AC-3, AC-4 (security/PII per §8/§10).

- **TC-AND-318-13 — `HostError` exposes a stable `messageResId` (localizable).**
  Type: unit. Target: JVM. Preconditions: each `HostError` constructed.
  Steps: assert `messageResId: Int` is set (resource id, not a hard-coded English
  string). Expected: every error has a non-zero `messageResId`. (Full TalkBack /
  Compose-semantics a11y checks are out of scope — they belong to the host UI
  ticket's Compose-UI suite on emulator `test35`, and any real WebRTC
  ingest/broadcast verification belongs to AND-308/AND-317 instrumented/e2e suites
  on the **physical Galaxy A15 (SM-A156U)** for real mic/camera + TURN; both are
  explicitly out of scope for AND-318.) Traces: AC-3 (relates to §9 a11y).

- **TC-AND-318-14 — JVM-only, deterministic, fast; coverage gate green.**
  Type: integration (CI/Gradle). Target: JVM. Preconditions: module test +
  JaCoCo tasks wired. Steps: run `./gradlew :feature-broadcast-host:testDebugUnitTest`
  then `:feature-broadcast-host:jacocoTestCoverageVerification`. Expected: all tests
  pass, no Robolectric/emulator needed, suite completes in <~10s, and JaCoCo
  line+branch ≥85% for `...host.state` and `...host.vm`. Traces: AC-1, AC-7, AC-8.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
|--------------------------|------------|
| AC-1 (suite passes locally + CI) | TC-01, TC-14 |
| AC-2 (every §4.2 transition; illegal events no-op) | TC-01, TC-02, TC-03, TC-09, TC-10, TC-11 |
| AC-3 (each control: state delta + side effect) | TC-01, TC-04, TC-05, TC-11, TC-12, TC-13 |
| AC-4 (idempotency guards `exactly=1`) | TC-08, TC-12 |
| AC-5 (3 `detail` variants + timeout → HostError, no throw) | TC-05, TC-06, TC-07, TC-10 |
| AC-6 (counters survive Reconnecting) | TC-09 |
| AC-7 (JaCoCo ≥85% line+branch) | TC-14 |
| AC-8 (JVM-only, deterministic, <~10s) | TC-14 (all cases are JVM/deterministic) |
