---
id: AND-389
title: Trust & safety tests
milestone: M8
epic: E50
priority: P1
size: M
status: draft
depends_on: [AND-388]
blocks: []
---

# AND-389 — Trust & safety tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks down the trust & safety
surface of the TestLogon Android app: blocking/unblocking, reporting, and muting
of users, together with the irreversible-action confirmation gating introduced by
`AND-382` (block/unblock data layer) and `AND-388` (trust & safety ViewModels).
It is a **Test** ticket (Type: Test, Priority: P1) and produces no shipping
feature code; its deliverable is repository-layer (JVM unit) tests plus Compose UI
tests that prove the confirmation gates cannot be bypassed and that block actions
actually hide content and prevent contact.

The goal is twofold:

1. **Behavioural correctness** — prove that block, unblock, report, and mute call
   the correct endpoints with the correct payloads, map `ApiResult` outcomes into
   the right `UiState`, and that a successful block removes the blocked user's
   content from the relevant feeds/threads and disables the send path.
2. **Confirmation gating** — prove that every irreversible or hard-to-undo action
   (block, report, leave/delete-thread) is fronted by a confirmation dialog, that
   the underlying repository call is **never** invoked until the user explicitly
   confirms, and that dismissing/cancelling is a true no-op.

"Acceptance: Pass" from the backlog is interpreted as: the new test source sets
compile and pass green in CI, run deterministically (no network, no flakiness),
and provide meaningful coverage of the AND-388 ViewModel state machine and the
AND-382 repository contract.

## 2. Context & References

- **Source ticket:** AND-389 — Trust & safety tests · Type: Test · Priority: P1 ·
  Deps: AND-388 · Scope: "Repo + UI tests (confirmation gating)" · Acceptance: "Pass".
- **Upstream under test:**
  - `AND-382` — Block / unblock. Web reference `frontend/src/api/endpoints/blocking.ts`;
    block/unblock embedded in profile and messages. Acceptance: "Block hides content
    + prevents contact (tested)."
  - `AND-388` — Trust & safety ViewModels (state + irreversible-action guards),
    unit-tested.
- **Module placement (layering app -> feature-* -> core-*):**
  - Repository tests live in `core-data` alongside the SUT:
    `core-data/src/test/java/com/testlogon/android/core/data/trust/`.
  - ViewModel unit tests live in the owning feature module, e.g.
    `feature-profile/src/test/java/com/testlogon/android/feature/profile/trust/`
    and `feature-messages/src/test/java/com/testlogon/android/feature/messages/trust/`.
  - Compose UI / confirmation-gating tests live in `androidTest` of the same
    feature modules:
    `feature-profile/src/androidTest/java/com/testlogon/android/feature/profile/trust/`.
- **Shared test infra:** `core-testing` (MainDispatcherRule, fakes, `MockWebServer`
  helpers, `ApiResult` assertion helpers). This ticket may add reusable fakes to
  `core-testing` but must not introduce production dependencies on it.
- **Backend / API:** FastAPI + DynamoDB; OpenAPI at `/openapi.json`; dev host
  `http://18.222.237.167:8000` (plaintext, unreliable — **not** contacted by these
  tests; all HTTP is stubbed with `MockWebServer`). Cookie + `ui_csrf`/`X-CSRF-Token`
  auth model is exercised only insofar as the trust endpoints are CSRF-protected.

## 3. Functional Requirements

The test suite MUST verify the following observable behaviours of the SUT
(production code from AND-382/AND-388):

- **FR-1 Block calls correct endpoint.** Confirming a block on user `targetId`
  issues `POST /ui/users/{targetId}/block` with the CSRF header and maps a `2xx`
  to `BlockState.Blocked`.
- **FR-2 Unblock calls correct endpoint.** Unblock issues `DELETE
  /ui/users/{targetId}/block` and maps `2xx` to `BlockState.NotBlocked`.
- **FR-3 Report calls correct endpoint.** Confirming a report issues
  `POST /ui/users/{targetId}/report` with body `{reason, details?}` and maps `2xx`
  to a `Reported` success state.
- **FR-4 Mute calls correct endpoint.** Mute/unmute toggles via
  `POST` / `DELETE /ui/users/{targetId}/mute`.
- **FR-5 Confirmation gating (core).** For each irreversible action (block, report,
  leave/delete thread) the ViewModel transitions to a `Confirming(action)` state
  on the request intent and performs **no** repository call until `confirm()` is
  called. `cancel()`/dismiss returns to `Idle` with zero repository interactions.
- **FR-6 Idempotency of intent.** Re-issuing the same request intent while already
  in `Confirming` does not stack dialogs or duplicate the pending action.
- **FR-7 Block hides content + prevents contact.** After a successful block:
  (a) the blocked user's items are filtered out of the feed/thread list rendered
  by the UI, and (b) the message composer / "Message" CTA is disabled or replaced
  with a "You blocked this user" affordance, so the send path is unreachable.
- **FR-8 Error mapping.** `4xx`/`5xx`/timeout responses map to the appropriate
  `UiState.Error(message)` (via FastAPI `detail` mapping) and leave the
  block/report state unchanged (no optimistic stickiness on failure).
- **FR-9 401 refresh-once.** A single `401` on a trust call triggers exactly one
  `POST /ui/session/refresh` then a retry; a second `401` surfaces an auth error.
  (Verified at repo level against `MockWebServer`.)
- **FR-10 Determinism.** All tests are hermetic: virtual time via
  `kotlinx-coroutines-test`, no real sockets except loopback `MockWebServer`,
  no `Thread.sleep`, fixed clocks where time matters.

## 4. Technical Design

### 4.1 Test stack

- `org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.x` — `runTest`,
  `StandardTestDispatcher`, `advanceUntilIdle`.
- JUnit4 (`junit:junit:4.13.2`) as the runner across unit + instrumented tiers.
- `com.google.truth:truth:1.4.x` for assertions; `app.cash.turbine:turbine:1.1.x`
  for `StateFlow`/`Flow` emission assertions.
- `io.mockk:mockk:1.13.x` (and `mockk-android` for instrumented) for fakes/spies of
  repository and API interfaces — verifying "never called until confirm".
- `okhttp3:mockwebserver:4.12.0` for repository HTTP contract tests (real Retrofit +
  Moshi + OkHttp stack against loopback).
- Compose: `androidx.compose.ui:ui-test-junit4` + `ui-test-manifest`,
  `createAndroidComposeRule` / `createComposeRule`, with Hilt test runner where DI
  injection is needed (`@HiltAndroidTest`, `HiltTestApplication`,
  `com.testlogon.android.core.testing.HiltTestRunner`).

### 4.2 `core-testing` additions

```kotlin
package com.testlogon.android.core.testing

class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}

/** In-memory fake of the AND-382 trust repository. */
class FakeTrustSafetyRepository : TrustSafetyRepository {
    val blockCalls = mutableListOf<String>()
    val unblockCalls = mutableListOf<String>()
    val reportCalls = mutableListOf<ReportRequest>()
    var blockResult: ApiResult<Unit> = ApiResult.Success(Unit)

    override suspend fun block(targetId: String): ApiResult<Unit> {
        blockCalls += targetId; return blockResult
    }
    // unblock / report / mute analogous …
}
```

### 4.3 SUT contracts assumed (owned by AND-382 / AND-388)

```kotlin
// core-data (AND-382)
interface TrustSafetyRepository {
    suspend fun block(targetId: String): ApiResult<Unit>
    suspend fun unblock(targetId: String): ApiResult<Unit>
    suspend fun report(req: ReportRequest): ApiResult<Unit>
    suspend fun mute(targetId: String): ApiResult<Unit>
    suspend fun unmute(targetId: String): ApiResult<Unit>
    fun blockState(targetId: String): Flow<BlockState>
}

// feature ViewModel (AND-388)
sealed interface TrustUiState {
    data object Idle : TrustUiState
    data class Confirming(val action: PendingAction) : TrustUiState
    data object Working : TrustUiState
    data class Error(val message: String) : TrustUiState
    data class Done(val action: PendingAction) : TrustUiState
}
sealed interface PendingAction { data class Block(val id: String) : PendingAction
    data class Report(val id: String, val reason: String) : PendingAction }
```

If any signature differs from the merged AND-388 code, the tests are updated to the
real signatures (the SUT is authoritative); discrepancies are logged as open
questions (§13) rather than changing production code in this ticket.

### 4.4 Representative tests

```kotlin
class TrustSafetyViewModelTest {
    @get:Rule val main = MainDispatcherRule()
    private val repo = FakeTrustSafetyRepository()
    private val vm = TrustSafetyViewModel(repo)

    @Test fun requestBlock_entersConfirming_withoutCallingRepo() = runTest {
        vm.requestBlock("u42")
        assertThat(vm.state.value).isInstanceOf(Confirming::class.java)
        assertThat(repo.blockCalls).isEmpty()        // FR-5: gated
    }

    @Test fun confirm_invokesRepo_andReachesDone() = runTest {
        vm.requestBlock("u42"); vm.confirm()
        advanceUntilIdle()
        assertThat(repo.blockCalls).containsExactly("u42")
        assertThat(vm.state.value).isEqualTo(Done(PendingAction.Block("u42")))
    }

    @Test fun cancel_isNoOp() = runTest {
        vm.requestBlock("u42"); vm.cancel()
        assertThat(repo.blockCalls).isEmpty()
        assertThat(vm.state.value).isEqualTo(TrustUiState.Idle)
    }
}
```

## 5. API Contract

These tests assert against the contract; they do not define it (owned by AND-382).
Repository-tier tests pin the exact HTTP wire shapes via `MockWebServer`:

- **Block:** `POST /ui/users/{userId}/block` — empty body; headers include
  `X-CSRF-Token`. Success `204`/`200`. Response asserted as `ApiResult.Success`.
- **Unblock:** `DELETE /ui/users/{userId}/block` — `204`.
- **Report:**
  `POST /ui/users/{userId}/report`
  ```json
  { "reason": "harassment", "details": "optional free text" }
  ```
  Success `201` `{ "report_id": "rep_abc123", "status": "received" }`.
- **Mute / unmute:** `POST` / `DELETE /ui/users/{userId}/mute` — `204`.
- **Error envelope (FastAPI `detail`):** tests cover all three shapes the client
  must handle:
  ```json
  { "detail": "User not found" }
  { "detail": [ { "loc": ["body","reason"], "msg": "field required" } ] }
  { "detail": { "code": "already_blocked", "message": "Already blocked" } }
  ```
- **Auth/CSRF:** one test stubs a `401` on the first block request, expects exactly
  one `POST /ui/session/refresh`, then a replayed block returning `204`
  (FR-9). `RecordedRequest` assertions confirm the `X-CSRF-Token` header is present
  and equals the `ui_csrf` cookie value.

`MockWebServer` `Dispatcher` example:

```kotlin
server.dispatcher = object : Dispatcher() {
    override fun dispatch(req: RecordedRequest) = when {
        req.path == "/ui/users/u42/block" && req.method == "POST" ->
            MockResponse().setResponseCode(204)
        else -> MockResponse().setResponseCode(404)
    }
}
```

## 6. Data & State Management

The tests assert the `StateFlow<TrustUiState>` transition graph of the AND-388
ViewModel using Turbine:

```kotlin
vm.state.test {
    assertThat(awaitItem()).isEqualTo(TrustUiState.Idle)     // initial
    vm.requestBlock("u42");  awaitItem() // Confirming
    vm.confirm();            awaitItem() // Working
    advanceUntilIdle();      awaitItem() // Done
    cancelAndIgnoreRemainingEvents()
}
```

Coverage matrix of transitions: `Idle→Confirming` (request),
`Confirming→Idle` (cancel), `Confirming→Working→Done` (confirm+success),
`Confirming→Working→Error` (confirm+failure), and `Error→Confirming` (retry).
For block-state propagation (FR-7), tests drive `repo.blockState(id)` to emit
`Blocked` and assert the feed/thread mapper filters that author out, and that the
composer-enabled derived flag flips to `false`. Persistence (Room/DataStore) is not
re-tested here — those layers are owned by AND-027/AND-382 and stubbed via fakes.
No production state is added by this ticket.

## 7. Error Handling & Resilience

The suite proves the resilience requirements rather than implementing them:

- **Timeout:** a `MockWebServer` response with `setBodyDelay` beyond the configured
  ~20s read timeout (compressed via virtual time / a shortened test OkHttp client)
  maps to `ApiResult.Error` of a timeout/IO category and `TrustUiState.Error`.
- **Retry policy boundary:** assert that the bounded backoff retry applies to
  **idempotent GETs only** — i.e. a failed block (`POST`) is **not** auto-retried;
  exactly one block request is recorded after a `500`.
- **Failure leaves state clean:** on any error the block/report state reverts and
  no content is hidden (no optimistic side effects survive failure) — FR-8.
- **Cancel-during-working:** if `cancel()` arrives while `Working`, the in-flight
  coroutine is cancelled and the terminal state is `Idle` (no late `Done`).
- **Determinism:** all delays use the test scheduler; no wall-clock waits.

## 8. Security & Privacy

- **CSRF enforcement test:** a block request stubbed to require `X-CSRF-Token`
  returns `403` when the header is absent; the suite asserts the production client
  always attaches it, preventing a regression that would expose CSRF.
- **Gating as a safety control:** confirmation gating (FR-5) is itself a safety
  requirement — these tests are the regression guard ensuring an irreversible
  block/report can never fire from a stray click or recomposition.
- **No real credentials / hosts:** tests never contact the plaintext dev backend;
  no real cookies, tokens, usernames, or passwords appear in fixtures (use
  synthetic ids like `u42`, `rep_abc123`).
- **Log hygiene assertion (light):** a test asserts that report `details` free-text
  is not echoed into any analytics event payload captured by the fake telemetry
  sink (§10) — privacy of user-entered report content.

## 9. Accessibility & i18n

UI confirmation-gating tests double as a11y guard:

- Confirmation dialogs are located by **semantics**, not pixels:
  `composeRule.onNodeWithText(R.string.block_confirm_title)` and confirm/cancel
  buttons by their content description / role, asserting both have non-empty
  accessible labels and `Role.Button`.
- A test asserts the destructive "Block" / "Report" confirm buttons carry a
  state/description distinguishing them as destructive (e.g. content description
  suffix), so screen-reader users are warned before an irreversible action.
- i18n: all asserted strings are referenced by `R.string.*` resource ids (no
  hard-coded literals in the test where a resource exists), so localization does
  not break the tests and untranslated keys are detectable.

## 10. Telemetry & Logging

A `FakeTrustTelemetry` sink is injected to assert analytics contracts without a
real backend:

```kotlin
class FakeTrustTelemetry : TrustTelemetry {
    val events = mutableListOf<TrustEvent>()
    override fun log(e: TrustEvent) { events += e }
}
```

- Assert that a successful block logs exactly one `TrustEvent.Blocked(targetId)`
  and that a **cancelled** confirmation logs `TrustEvent.ConfirmDismissed` (or
  nothing) but **never** `Blocked` — proving telemetry mirrors real intent.
- Assert report telemetry includes `reason` (an enum/category) but **not** the
  free-text `details` (privacy, §8).
- Assert no PII (username/password/cookie) is present in any captured event.

## 11. Testing Strategy

Three tiers:

1. **Repository contract (JVM, `core-data/src/test`)** — Retrofit+Moshi+OkHttp over
   `MockWebServer`: endpoint paths, methods, payloads, CSRF header, error-envelope
   mapping (all three `detail` shapes), `401→refresh→retry`, POST-not-retried.
2. **ViewModel unit (JVM, feature `src/test`)** — `runTest` + Turbine + MockK:
   full `TrustUiState` transition matrix, confirmation gating (repo never called
   pre-confirm), cancel no-op, error reversion, telemetry assertions.
3. **Compose UI / gating (instrumented, feature `src/androidTest`)** — Hilt-injected
   screens with fake repo: clicking "Block" shows a dialog and does **not** mutate
   state; tapping "Cancel" dismisses with no call; tapping "Confirm" hides content
   and disables the composer (FR-7); semantics/a11y assertions (§9).

Quality bars: each FR (FR-1..FR-10) maps to ≥1 named test. Tier 1+2 run on every
PR (`./gradlew testDebugUnitTest`); Tier 3 on `connectedDebugAndroidTest` /
Gradle Managed Device. No test exceeds a few hundred ms (virtual time). Target:
line coverage of AND-388 ViewModel ≥ 90%, every public repo method exercised on
both success and error paths. Tests must be re-run 3× locally to confirm zero
flake before merge.

## 12. Dependencies & Sequencing

- **Hard dependency:** `AND-388` (Trust & safety ViewModels) — provides the
  `TrustUiState`/`PendingAction` state machine and gating logic under test.
- **Transitive:** `AND-382` (Block/unblock repository + `blocking.ts` parity) and
  `AND-027` (its upstream).
- **Infra:** `core-testing` rules/fakes; the repo's test convention plugin must
  already wire coroutines-test, Truth, Turbine, MockK, MockWebServer, and Compose
  test artifacts.
- **Sequencing:** must merge **after** AND-388 lands. This ticket **blocks** the M8
  trust & safety epic (E50) sign-off / release gate since "Acceptance: Pass" is the
  exit criterion for the feature work it covers.

## 13. Risks & Open Questions

- **Signature drift:** AND-388's actual `TrustUiState`/method names may differ from
  the assumed contract (§4.3). Mitigation: tests track the merged code; pin via a
  thin SUT adapter if names churn. *Open:* confirm final state enum naming.
- **Where gating lives:** confirmation could be a Compose-only dialog or a
  ViewModel `Confirming` state. The backlog ("irreversible-action guards" in the
  ViewModel) implies ViewModel-level — tests assume this. *Open:* if gating is
  UI-only, FR-5 moves entirely to Tier 3 and the ViewModel "never called" assertion
  is dropped.
- **Endpoint shapes unverified against live OpenAPI** (dev host unreliable).
  *Open:* reconcile block/report/mute paths and report body with `/openapi.json`
  and `frontend/src/api/endpoints/blocking.ts` before pinning Tier 1 fixtures.
- **Instrumented flake** on emulator for dialog timing. Mitigation: idling via
  Compose test clock + semantics waits, no `Thread.sleep`.
- **Mute endpoint existence** is inferred; if mute is out of M8 scope, drop FR-4.

## 14. Acceptance Criteria

- **AC-1** All new unit (Tier 1+2) and instrumented (Tier 3) tests compile and pass
  green in CI (`testDebugUnitTest` + `connectedDebugAndroidTest`). (Backlog: "Pass".)
- **AC-2** A test proves the block repository call hits
  `POST /ui/users/{id}/block` with the CSRF header and maps `2xx→Success`,
  and unblock hits `DELETE /ui/users/{id}/block`. (FR-1/FR-2)
- **AC-3** A test proves report (`POST /ui/users/{id}/report` with `{reason}`) and
  mute/unmute endpoints are called with correct method+payload. (FR-3/FR-4)
- **AC-4** For block and report, a test proves the repository is **not** invoked
  until `confirm()`, and `cancel()`/dismiss results in zero repository calls and a
  return to `Idle`. (FR-5/FR-6)
- **AC-5** A UI test proves a successful block hides the blocked user's content and
  disables/replaces the message-send path. (FR-7 / AND-382 acceptance)
- **AC-6** Tests cover all three FastAPI `detail` error shapes and prove failures
  surface `UiState.Error` without leaving stale optimistic state. (FR-8)
- **AC-7** A repo test proves a single `401` triggers exactly one
  `/ui/session/refresh` then retry, and that a failed `POST` is **not** auto-retried.
  (FR-9 + retry boundary)
- **AC-8** Confirmation dialogs and their buttons are addressable by semantics with
  non-empty accessible labels and destructive role/description. (§9)
- **AC-9** Telemetry tests prove a cancelled confirmation never logs a `Blocked`
  event and report `details` free-text is never present in events. (§10/§8)
- **AC-10** Suite is hermetic and non-flaky: no real network beyond loopback
  `MockWebServer`, virtual time only, passes 3 consecutive local runs.

## 15. Definition of Done

- All three test tiers implemented under the module paths in §2, every FR
  (FR-1..FR-10) and AC (AC-1..AC-10) mapped to at least one named, passing test.
- `core-testing` fakes (`FakeTrustSafetyRepository`, `FakeTrustTelemetry`,
  `MainDispatcherRule`) added and reused; no production code in `core-data`/feature
  modules modified except trivial visibility/`@VisibleForTesting` if strictly
  required and reviewed.
- Green on CI for `:core-data:testDebugUnitTest`, the feature modules'
  `testDebugUnitTest`, and `connectedDebugAndroidTest` (or Gradle Managed Device).
- No new lint/Detekt/ktlint violations; new test code follows repo conventions
  (package `com.testlogon.android.*`, JDK 17, Kotlin 2.0.21).
- Coverage thresholds met (AND-388 ViewModel ≥ 90% line; every public repo method
  exercised on success+error).
- Open questions in §13 either resolved or filed as follow-up issues referencing
  AND-388/AND-382; PR description links AND-389 and notes any contract reconciliation
  against `/openapi.json` and `frontend/src/api/endpoints/blocking.ts`.
- Reviewed and merged to `android-port`; trust & safety (E50/M8) feature gate marked
  test-complete.
