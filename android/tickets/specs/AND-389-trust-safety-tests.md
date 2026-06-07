---
id: AND-389
title: Trust & safety tests
milestone: M8
epic: E50
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  issues `POST /ui/social/block` with JSON body `{ target_user_id, reason? }` and
  the CSRF header, and maps a `200` (`BlockActionResponse`) to `BlockState.Blocked`.
  **[Corrected — was `POST /ui/users/{targetId}/block` with empty body.]**
  Source: OpenAPI `POST /ui/social/block` (req=`BlockRequest`, resp=`200:BlockActionResponse`);
  frontend `src/api/endpoints/blocking.ts: blockUser`.
- **FR-2 Unblock calls correct endpoint.** Unblock issues `POST /ui/social/unblock`
  with JSON body `{ target_user_id }` and maps `200` (`BlockActionResponse`) to
  `BlockState.NotBlocked`. **[Corrected — was `DELETE /ui/users/{targetId}/block`;
  the real contract is a POST, not a DELETE.]** Source: OpenAPI
  `POST /ui/social/unblock` (req=`UnblockRequest`); `src/api/endpoints/blocking.ts: unblockUser`.
  Block status is read via `GET /ui/social/block-status/{targetId}` (`BlockStatusResponse`
  with `is_blocked_by_me` / `is_blocking_me`).
- **FR-3 Report calls correct endpoint.** There is **no** per-user report endpoint.
  Content reporting goes to `POST /moderation/reports` with body
  `CreateModerationReportIn { content_type, content_id, topics[], reason_text, ... }`
  (resp `CreateModerationReportOut { ok, report_id, status, ticket_id, created_at }`);
  message-scoped reports use `POST /messaging/conversations/{conversation_id}/messages/{message_id}/report`
  (`ReportMessageReq`). **[Corrected — was `POST /ui/users/{targetId}/report` with
  `{reason, details?}`, which does not exist. `reason`/`details` are not the wire
  field names; the moderation report uses `topics[]` + `reason_text`.]** Source:
  OpenAPI `POST /moderation/reports` and `POST .../messages/{message_id}/report`;
  frontend `src/api/endpoints/moderation.ts: createModerationReport`,
  `src/api/endpoints/messaging.ts: reportMessage`.
- **FR-4 Mute calls correct endpoint.** **[Unverified-assumption / likely
  out-of-scope.]** No per-user mute endpoint (`/ui/users/{id}/mute` or
  `/ui/social/.../mute`) exists in the OpenAPI. The only mute endpoints are
  conversation-scoped (`POST /messaging/conversations/{conversation_id}/mute`,
  req=`MuteIn`) and broadcast/chat-scoped. If a per-user mute is required it must
  be added upstream; otherwise FR-4 and the mute test cases should be dropped (see
  §13). Source: OpenAPI index — no per-user mute path found.
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

> **Contract correction (this review):** the original draft's `/ui/users/{id}/...`
> paths, the `DELETE`-based unblock, the `{reason, details}` report body, and the
> `204`/`201` success codes were all wrong. The verified wire shapes below come from
> the OpenAPI spec and the web `blocking.ts`/`moderation.ts`/`messaging.ts` clients.

- **Block:** `POST /ui/social/block` — JSON body
  `{ "target_user_id": "u42", "reason": "harassment" }` (`reason` optional,
  `maxLength: 500`; `target_user_id` required, `minLength: 1`). Headers include
  `X-CSRF-Token`. Success **`200`** with `BlockActionResponse`
  `{ "ok": true, "status": "blocked", "target_user_id": "u42" }`. Asserted as
  `ApiResult.Success`. **[Corrected from `POST /ui/users/{id}/block`, empty body, `204`.]**
- **Unblock:** `POST /ui/social/unblock` — JSON body `{ "target_user_id": "u42" }`.
  Success `200` `BlockActionResponse`. **[Corrected from `DELETE /ui/users/{id}/block`.]**
- **Block status (for FR-7 propagation):** `GET /ui/social/block-status/{targetUserId}`
  → `200` `BlockStatusResponse { "is_blocked_by_me": true, "is_blocking_me": false }`.
- **Report:** `POST /moderation/reports` — JSON body `CreateModerationReportIn`:
  ```json
  { "content_type": "profile_photo", "content_id": "u42",
    "topics": ["harassment"], "reason_text": "free text >=5 chars" }
  ```
  (`content_type` enum: feed_post|feed_comment|feed_media|message|message_media|profile_photo;
  `topics` 1..5 items; `reason_text` `minLength: 5`, `maxLength: 2000`). Success
  `200` `CreateModerationReportOut { "ok": true, "report_id": "...",
  "status": "submitted"|"deduplicated", "ticket_id": "...", "created_at": <int> }`.
  Message-scoped variant: `POST /messaging/conversations/{conversation_id}/messages/{message_id}/report`
  (`ReportMessageReq`). **[Corrected from `POST /ui/users/{id}/report` `{reason, details}` → `201`.]**
- **Mute / unmute:** no per-user mute endpoint exists; only
  `POST /messaging/conversations/{conversation_id}/mute` (`MuteIn`) and
  broadcast-scoped mutes. **[Corrected: `POST`/`DELETE /ui/users/{id}/mute` does not exist.]**
- **Error envelope (FastAPI):** the social/moderation endpoints document only
  `422 HTTPValidationError`. The client (`src/api/client.ts: normalizeErrorDetail`)
  must still handle three observed `detail` shapes — string, validation-array, and
  object-with-`code` (used by 403 authorization errors elsewhere):
  ```json
  { "detail": "User not found" }
  { "detail": [ { "loc": ["body","target_user_id"], "msg": "field required", "type": "value_error.missing" } ] }
  { "detail": { "code": "role_required", "message": "..." } }
  ```
  Note: `{ "code": "already_blocked" }` was an **invented** example in the original
  draft — no such code exists in the sources; the object-with-`code` shape is real
  but the `code` values come from authorization/geo (`role_required`, `geo_blocked`,
  etc.). Use a generic synthetic code in fixtures or one of the real codes.
- **Auth/CSRF:** verified against `src/api/client.ts`. Every request attaches
  `X-CSRF-Token` set from the `ui_csrf` cookie value. A single `401` (when
  authenticated) triggers exactly one `POST /ui/session/refresh` then **one** retry
  of the original request with the same headers; a second `401` logs the user out
  (`session_expired`) and surfaces an auth error (FR-9). A transport/network failure
  surfaces as `ApiError(0, "Network error")`. `RecordedRequest` assertions confirm
  the `X-CSRF-Token` header is present and equals the `ui_csrf` cookie value.

`MockWebServer` `Dispatcher` example:

```kotlin
server.dispatcher = object : Dispatcher() {
    override fun dispatch(req: RecordedRequest) = when {
        req.path == "/ui/social/block" && req.method == "POST" ->
            MockResponse().setResponseCode(200)
                .setBody("""{"ok":true,"status":"blocked","target_user_id":"u42"}""")
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
- **Endpoint shapes — RESOLVED this review** against the OpenAPI spec and the web
  `blocking.ts`/`moderation.ts`/`messaging.ts` clients. Block=`POST /ui/social/block`,
  unblock=`POST /ui/social/unblock`, report=`POST /moderation/reports`; all `200`
  on success. The original `/ui/users/{id}/...` paths were wrong and are corrected
  in §3/§5/§14. Tier 1 fixtures must be pinned to these verified shapes (see §16).
- **Instrumented flake** on emulator for dialog timing. Mitigation: idling via
  Compose test clock + semantics waits, no `Thread.sleep`.
- **Mute endpoint existence — RESOLVED (negative):** no per-user mute endpoint
  exists in the OpenAPI (only conversation/broadcast mute). FR-4 as written is not
  implementable against the current backend; either descope FR-4 and its test cases
  or retarget them at `POST /messaging/conversations/{id}/mute`. *Open:* product
  decision on whether per-user mute ships in M8.

## 14. Acceptance Criteria

- **AC-1** All new unit (Tier 1+2) and instrumented (Tier 3) tests compile and pass
  green in CI (`testDebugUnitTest` + `connectedDebugAndroidTest`). (Backlog: "Pass".)
- **AC-2** A test proves the block repository call hits
  `POST /ui/social/block` with body `{target_user_id, reason?}` and the CSRF header
  and maps `200→Success`, and unblock hits `POST /ui/social/unblock` with
  `{target_user_id}`. (FR-1/FR-2) **[Corrected endpoints/method this review.]**
- **AC-3** A test proves report (`POST /moderation/reports` with
  `{content_type, content_id, topics[], reason_text}`) is called with correct
  method+payload and maps `200→Success`. (FR-3) Mute coverage applies only if a
  per-user mute endpoint exists (FR-4 is unverified — see §13/§16); the conversation
  mute (`POST /messaging/conversations/{id}/mute`) is the closest real endpoint.
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

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and an exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`) and full spec
(`reference/openapi.pretty.json`, `components.schemas.<Name>`); frontend
(`reference/src/...`); Android docs (labelled "framework ref").

1. **Block endpoint is `POST /ui/social/block` with body `{target_user_id, reason?}`
   → `200 BlockActionResponse`.** VERDICT: Corrected (was `POST /ui/users/{id}/block`,
   empty body, `204`). SOURCE: OpenAPI `POST /ui/social/block` (req=`BlockRequest`,
   resp=`200:BlockActionResponse`); schema `BlockRequest` (`target_user_id` required
   minLength 1; `reason` optional maxLength 500); `src/api/endpoints/blocking.ts: blockUser`.
2. **Unblock endpoint is `POST /ui/social/unblock` with body `{target_user_id}` →
   `200 BlockActionResponse`.** VERDICT: Corrected (was `DELETE /ui/users/{id}/block`).
   SOURCE: OpenAPI `POST /ui/social/unblock` (req=`UnblockRequest`); schema
   `UnblockRequest`; `src/api/endpoints/blocking.ts: unblockUser`.
3. **`BlockActionResponse` shape `{ ok: bool(=true), status: str, target_user_id: str }`
   (required: status, target_user_id).** VERDICT: Verified. SOURCE:
   `openapi.pretty.json: components.schemas.BlockActionResponse`.
4. **Block status read via `GET /ui/social/block-status/{target_user_id}` →
   `BlockStatusResponse { is_blocked_by_me, is_blocking_me }`.** VERDICT: Verified
   (newly cited; supports FR-7). SOURCE: OpenAPI `GET /ui/social/block-status/{target_user_id}`;
   schema `BlockStatusResponse`; `src/api/endpoints/blocking.ts: getBlockStatus`.
5. **Blocked-users list: `GET /ui/social/blocked` → `BlockedUsersListResponse`
   (`blocked_users[]`, `next_cursor`).** VERDICT: Verified. SOURCE: OpenAPI
   `GET /ui/social/blocked`; schema `BlockedUsersListResponse`/`BlockedUserItem`;
   `src/api/endpoints/blocking.ts: getBlockedUsers`; `src/pages/settings/BlockedUsersPage.tsx`.
6. **No per-user report endpoint; reporting is `POST /moderation/reports`
   (`CreateModerationReportIn`) or message-scoped
   `POST /messaging/conversations/{cid}/messages/{mid}/report` (`ReportMessageReq`).**
   VERDICT: Corrected (was `POST /ui/users/{id}/report` with `{reason, details}`).
   SOURCE: OpenAPI `POST /moderation/reports` (resp=`CreateModerationReportOut`) and
   `POST .../messages/{message_id}/report`; `src/api/endpoints/moderation.ts: createModerationReport`,
   `src/api/endpoints/messaging.ts: reportMessage`.
7. **Report body fields are `content_type` (enum), `content_id`, `topics[]` (1..5),
   `reason_text` (5..2000) — NOT `reason`/`details`.** VERDICT: Corrected.
   SOURCE: `openapi.pretty.json: components.schemas.CreateModerationReportIn`;
   `src/api/endpoints/moderation.ts: CreateModerationReportReq`.
8. **Report response `CreateModerationReportOut { ok, report_id, status:
   submitted|deduplicated, ticket_id, created_at }`.** VERDICT: Corrected (draft
   claimed `201 {report_id, status:"received"}`; real code is `200` and
   `status` enum is submitted/deduplicated). SOURCE:
   `components.schemas.CreateModerationReportOut`.
9. **No per-user mute endpoint exists.** VERDICT: Corrected / Unverified-assumption
   (FR-4 not implementable as drafted). SOURCE: OpenAPI index — only
   `POST /messaging/conversations/{conversation_id}/mute` (`MuteIn`) and
   broadcast/chat mutes (`/broadcast/sessions/{id}/chat/mute`, etc.); no
   `/ui/users/{id}/mute` or `/ui/social/.../mute` path.
10. **CSRF: client sends header `X-CSRF-Token` set to the `ui_csrf` cookie value on
    every request.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")`
    → `headers.set("X-CSRF-Token", csrf)`).
11. **401 handling: one `POST /ui/session/refresh` then exactly one retry; second
    `401` logs out (`session_expired`). Refresh is de-duplicated via a shared
    promise.** VERDICT: Verified (FR-9 path/behavior correct). SOURCE:
    `src/api/client.ts` (`refreshSession`, `refreshPromise`, retry block); OpenAPI
    `POST /ui/session/refresh` (req empty, resp 200).
12. **Network/transport failure surfaces a distinct error (web: `ApiError(0,
    "Network error")`).** VERDICT: Verified (informs the offline/flaky-host case).
    SOURCE: `src/api/client.ts` catch block around `fetch`.
13. **Error `detail` shapes the client handles: string, validation-array
    (`{loc,msg,type}`), and object-with-`code`.** VERDICT: Verified (shapes), but
    the draft's `code:"already_blocked"` example is Corrected — that code is invented.
    Real object-`code` values are authorization/geo (`role_required`,
    `role_required_scope`, `geo_blocked`, helpdesk_*). SOURCE:
    `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`; social/
    moderation endpoints in OpenAPI document only `422 HTTPValidationError`.
14. **Web unblock has NO confirmation dialog (direct mutate); block/report on
    message surface DO use a confirm/report modal (`ConfirmDialog`,
    `ReportContentModal`).** VERDICT: Verified — note this nuance: FR-5's "gate every
    irreversible action incl. unblock" is an Android-side product choice, not mirrored
    by the web app for unblock. SOURCE: `src/pages/settings/BlockedUsersPage.tsx`
    (direct `unblockMut.mutate`); `src/pages/messages/MessageBubble.tsx`
    (imports `ConfirmDialog`, `ReportContentModal`, `reportMessage`).
15. **ViewModel/Repository Kotlin contracts (`TrustSafetyRepository`, `TrustUiState`,
    `PendingAction`) and the `ApiResult` type.** VERDICT: Unverified-assumption —
    these are AND-382/AND-388 SUT types not present in this reference snapshot
    (frontend is TypeScript; no Android module source provided). Tests must bind to
    the merged Kotlin signatures. SOURCE: none available here; see §4.3 / §13.
16. **Android test framework choices (coroutines-test, Turbine, MockK,
    MockWebServer, Compose `createAndroidComposeRule`, Hilt test runner).** VERDICT:
    Unverified-assumption for this repo's exact versions (no Gradle catalog in the
    snapshot), but standard. SOURCE: framework ref —
    https://developer.android.com/jetpack/compose/testing and
    https://developer.android.com/training/dependency-injection/hilt-testing.
17. **Compose semantics-based a11y assertions (role=Button, non-empty labels,
    destructive description).** VERDICT: Unverified-assumption (depends on AND-388
    UI), backed by framework ref. SOURCE:
    https://developer.android.com/jetpack/compose/semantics.

### Corrections made

- §3 FR-1/FR-2: block/unblock paths fixed to `POST /ui/social/block` /
  `POST /ui/social/unblock`; bodies and success code (`200`) corrected; DELETE→POST.
- §3 FR-3: report retargeted from the non-existent `POST /ui/users/{id}/report`
  `{reason, details}` to `POST /moderation/reports` with `topics[]`+`reason_text`
  (and the message-scoped variant).
- §3 FR-4: flagged that no per-user mute endpoint exists; descope or retarget.
- §5 API Contract: all paths/methods/bodies/status codes corrected; the invented
  `already_blocked` error code removed; CSRF/401-refresh behavior cited to `client.ts`.
- §13: endpoint-shape and mute-existence open questions resolved with sources.
- §14 AC-2/AC-3: endpoints/bodies corrected to match the verified contract.
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **Kotlin SUT signatures (AND-382/AND-388)** — not present in this snapshot; tests
  must track the merged Android code. Why unverifiable: only the TS reference app and
  OpenAPI are provided, not the Android module source.
- **Per-user mute (FR-4)** — no backend endpoint; pending product/scope decision.
- **Android dependency versions / convention plugin** — no Gradle files in the
  snapshot; versions in §4.1 are assumed-current, not verified.
- **Confirmation-gating location (ViewModel vs Compose)** — AND-388 design choice;
  web mixes both (unblock ungated, message report/block gated). Assumed ViewModel
  `Confirming` per backlog "irreversible-action guards."

## 17. Test Plan

IDs `TC-AND-389-NN`. "Traces" link to §14 Acceptance Criteria. Test targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the physical
Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Unit + contract tiers are
device-independent (JVM). UI/instrumented tiers run on the emulator unless a case
requires real-hardware behavior, in which case the physical device is noted.

- **TC-AND-389-01 — Block happy path (contract).** Type: contract/MockWebServer
  (JVM). Target: JVM unit. Preconditions: `MockWebServer` enqueues `200`
  `{"ok":true,"status":"blocked","target_user_id":"u42"}`; authenticated session,
  `ui_csrf` cookie set. Steps: call `repo.block("u42")`; capture `RecordedRequest`.
  Expected: request is `POST /ui/social/block`, JSON body contains
  `target_user_id="u42"`, header `X-CSRF-Token` equals the `ui_csrf` value; result is
  `ApiResult.Success`. Traces: AC-2.

- **TC-AND-389-02 — Unblock happy path (contract).** Type: contract/MockWebServer
  (JVM). Target: JVM unit. Preconditions: enqueue `200` `BlockActionResponse`. Steps:
  call `repo.unblock("u42")`; inspect `RecordedRequest`. Expected: `POST
  /ui/social/unblock` with body `{target_user_id:"u42"}`, CSRF header present,
  `ApiResult.Success`. Traces: AC-2.

- **TC-AND-389-03 — Report happy path (contract).** Type: contract/MockWebServer
  (JVM). Target: JVM unit. Preconditions: enqueue `200`
  `{"ok":true,"report_id":"rep_1","status":"submitted","ticket_id":"t1","created_at":1}`.
  Steps: call report with `content_type="profile_photo"`, `content_id="u42"`,
  `topics=["harassment"]`, `reason_text="abusive dms"`. Expected: `POST
  /moderation/reports`; body matches `CreateModerationReportIn`; `ApiResult.Success`
  carrying `report_id`. Traces: AC-3.

- **TC-AND-389-04 — Confirmation gating: request does not call repo (unit).** Type:
  unit. Target: JVM unit (Robolectric not needed). Preconditions: `FakeTrustSafetyRepository`,
  fresh ViewModel in `Idle`. Steps: `vm.requestBlock("u42")`. Expected: state
  `Confirming(Block("u42"))`; `repo.blockCalls` is empty. Traces: AC-4.

- **TC-AND-389-05 — Confirm invokes repo, reaches Done; cancel is a no-op (unit).**
  Type: unit. Target: JVM unit. Preconditions: as above; `blockResult=Success`.
  Steps: (a) `requestBlock("u42")`→`confirm()`→`advanceUntilIdle()`; (b) separate
  run `requestBlock("u42")`→`cancel()`. Expected: (a) `blockCalls==["u42"]`, terminal
  `Done`; (b) `blockCalls` empty, state back to `Idle`. Traces: AC-4.

- **TC-AND-389-06 — Idempotent intent: duplicate request does not stack/duplicate
  (unit).** Type: unit. Target: JVM unit. Preconditions: ViewModel in `Confirming`.
  Steps: call `requestBlock("u42")` twice without confirming, then `confirm()`,
  `advanceUntilIdle()`. Expected: still one logical pending action; `blockCalls`
  contains exactly one `"u42"`. Traces: AC-4 (FR-6).

- **TC-AND-389-07 — Validation (422) error mapping (contract).** Type:
  contract/MockWebServer (JVM). Target: JVM unit. Preconditions: enqueue `422`
  `{"detail":[{"loc":["body","target_user_id"],"msg":"field required","type":"value_error.missing"}]}`.
  Steps: call `repo.block("")`. Expected: `ApiResult.Error` with message derived from
  `detail[].msg` ("field required"); block state unchanged (no optimistic stickiness).
  Traces: AC-6.

- **TC-AND-389-08 — String + object `detail` error shapes (contract).** Type:
  contract/MockWebServer (JVM). Target: JVM unit. Preconditions: two enqueued
  responses: `404 {"detail":"User not found"}` and `403
  {"detail":{"code":"role_required","message":"..."}}`. Steps: call block twice.
  Expected: each maps to `ApiResult.Error` with the human-readable message
  (string passthrough; mapped authorization message for the object form); state
  reverts on both. Traces: AC-6.

- **TC-AND-389-09 — 401 → single refresh → retry; POST not auto-retried on 500
  (contract).** Type: contract/MockWebServer (JVM). Target: JVM unit. Preconditions:
  Dispatcher: first `/ui/social/block` → `401`; `/ui/session/refresh` → `200`;
  replayed block → `200`. Second scenario: block → `500`. Steps: run both. Expected:
  scenario A records exactly one `POST /ui/session/refresh` then one replayed block
  (total 2 block requests) ending `Success`; scenario B records exactly one block
  request (no auto-retry of the POST) ending `Error`. A second consecutive `401`
  surfaces an auth error. Traces: AC-7.

- **TC-AND-389-10 — Offline / flaky dev-host transport error (contract).** Type:
  contract/MockWebServer (JVM). Target: JVM unit. Preconditions: enqueue a response
  with `socketPolicy = DISCONNECT_AFTER_REQUEST` (or stop the server) to simulate the
  unreliable plaintext dev host. Steps: call `repo.block("u42")`. Expected:
  `ApiResult.Error` of IO/network category (parity with web `ApiError(0,"Network
  error")`); ViewModel maps to `TrustUiState.Error`; no state mutation. Traces: AC-6, AC-10.

- **TC-AND-389-11 — Block hides content + disables send path (Compose-UI).** Type:
  Compose-UI / instrumented. Target: emulator `test35` (no real hardware needed).
  Preconditions: Hilt-injected screen with fake repo; `blockState("u42")` emits
  `Blocked`. Steps: render feed/thread containing an item authored by `u42` and the
  composer; trigger a confirmed block. Expected: `u42`'s items are absent from the
  list (assert by semantics), and the composer/"Message" CTA is disabled or replaced
  by a "You blocked this user" affordance (send node not enabled). Traces: AC-5.

- **TC-AND-389-12 — Confirmation dialog gating in UI: cancel = no call, confirm =
  action (Compose-UI).** Type: Compose-UI / instrumented. Target: emulator `test35`.
  Preconditions: screen with fake repo, action menu visible. Steps: tap "Block";
  assert dialog shown and `repo.blockCalls` empty; tap "Cancel" → dialog gone, still
  empty; reopen, tap "Confirm" → exactly one call. Expected: as described. Traces:
  AC-4, AC-5.

- **TC-AND-389-13 — Accessibility of destructive confirm dialog (Compose-UI).**
  Type: Compose-UI / instrumented (a11y). Target: emulator `test35`. Preconditions:
  block confirm dialog shown. Steps: locate title and confirm/cancel by
  `onNodeWithText(R.string.block_confirm_title)` and by role; assert each button has
  a non-empty accessible label, `Role.Button`, and the destructive confirm carries a
  distinguishing description. Expected: all assertions pass; no hard-coded literals
  where a string resource exists. Traces: AC-8.

- **TC-AND-389-14 — Telemetry/privacy: cancel never logs Blocked; report `details`
  free-text never emitted (unit).** Type: unit. Target: JVM unit. Preconditions:
  `FakeTrustTelemetry` injected. Steps: (a) `requestBlock`→`cancel()`; (b) confirmed
  report with `reason_text="secret free text"`. Expected: (a) no `TrustEvent.Blocked`
  (at most `ConfirmDismissed`); (b) emitted events contain the topic/category but not
  the raw `reason_text`; no PII (username/cookie) in any event. Traces: AC-9.

- **TC-AND-389-15 — CSRF regression: missing header rejected (contract).** Type:
  contract/MockWebServer (JVM, security). Target: JVM unit. Preconditions: Dispatcher
  returns `403` when `X-CSRF-Token` is absent, `200` when present. Steps: issue a
  block via the production client. Expected: client always attaches `X-CSRF-Token`
  (so the call succeeds); a negative control omitting the cookie produces the `403`
  path → `ApiResult.Error`. Traces: AC-7 (security), §8.

- **TC-AND-389-16 — ABI/API parity smoke for the gating UI (instrumented).** Type:
  instrumented/e2e. Target: PHYSICAL DEVICE (Galaxy A15, arm64-v8a, API 34) — MUST
  run on the physical device to catch arm64-vs-x86 / API-34-vs-35 differences not
  seen on the x86_64 API-35 emulator. Preconditions: debug build installed via adb.
  Steps: run the block confirm→hide-content flow (TC-11/TC-12 abbreviated) on-device.
  Expected: identical gating/hide behavior as on the emulator; no ABI/API-level
  regressions. Traces: AC-1, AC-5.

### Coverage matrix (AC → TC)

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (all tiers compile & pass) | TC-01..TC-16 (suite); TC-16 device parity |
| AC-2 (block/unblock endpoints+CSRF) | TC-01, TC-02 |
| AC-3 (report endpoint+payload) | TC-03 |
| AC-4 (gating: no call until confirm; cancel no-op; idempotent) | TC-04, TC-05, TC-06, TC-12 |
| AC-5 (block hides content + disables send) | TC-11, TC-12, TC-16 |
| AC-6 (all error `detail` shapes; no stale state) | TC-07, TC-08, TC-10 |
| AC-7 (401→one refresh→retry; POST not retried; CSRF) | TC-09, TC-15 |
| AC-8 (a11y semantics on dialog) | TC-13 |
| AC-9 (telemetry: no Blocked on cancel; no `reason_text` leak) | TC-14 |
| AC-10 (hermetic, non-flaky) | TC-09, TC-10 (and suite-wide virtual-time discipline) |
