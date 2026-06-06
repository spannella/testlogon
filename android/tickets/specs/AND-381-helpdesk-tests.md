---
id: AND-381
title: Helpdesk tests
milestone: M8
epic: E49
priority: P2
size: M
status: draft
depends_on: [AND-380, AND-379, AND-378, AND-377]
blocks: []
---

# AND-381 — Helpdesk tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the **Helpdesk** feature area of the TestLogon native Android app (`com.testlogon.android`). It is a pure **Test** ticket (Type: Test, Priority: P2) — it ships no production behaviour. It adds repository-level (JVM) tests and Compose UI tests that exercise the code produced by the upstream Helpdesk feature tickets in epic E49: the agent dashboard (AND-377), claim/assignment management (AND-378), agent availability / online state (AND-379), and the Helpdesk ViewModel state layer (AND-380). The single backlog acceptance criterion is **"Pass."**, which this spec operationalises into concrete, measurable, deterministic test obligations.

The goal is to lock down the behaviour of the `feature-helpdesk` module so that the helpdesk surface — metrics dashboard, queue preview, ownership mutations (claim/assign/transfer), and the availability toggle that gates claim eligibility — is verified end-to-end at the unit and screen level against faked transport. Concretely, the suite must prove that: (a) helpdesk DTOs map correctly from FastAPI JSON into `core-model` domain types; (b) `HelpdeskMetricsRepository` and the assignment/availability repository surfaces translate transport outcomes into the typed `ApiResult<T>` envelope, including all three FastAPI `detail` error shapes, 401-refresh-then-retry, `409` conflict handling, and 20s-timeout behaviour; (c) the Helpdesk ViewModel(s) emit the correct `StateFlow<UiState>` transitions for loading/content/stale/empty/access-denied/error, optimistic-update-then-reconcile, and the availability toggle gating claim eligibility; and (d) the Compose dashboard, queue-preview, assignment bottom sheet, and availability toggle render each `UiState` and route correctly on interaction.

Out of scope: writing or modifying production source for helpdesk (owned by AND-377/378/379/380), backend changes, end-to-end tests against the live dev backend, and screenshot/visual-regression tooling. Network is always faked at the OkHttp boundary (`MockWebServer`); no test in this ticket contacts `http://18.222.237.167:8000`.

## 2. Context & References

- **Module layering:** `app -> feature-helpdesk -> core-* (core-network, core-model, core-data, core-ui, core-testing)`. Test code added here lives in `feature-helpdesk/src/test` (JVM unit) and `feature-helpdesk/src/androidTest` (instrumented Compose), with shared fixtures contributed to `core-testing`.
- **Upstream under test (epic E49):**
  - **AND-377** — Helpdesk agent dashboard: `HelpdeskDashboardScreen`, `HelpdeskDashboardViewModel`, `HelpdeskDashboardUiState`, `HelpdeskMetricsRepository`, `HelpdeskApi.getMetrics()`, `HelpdeskMetricsDto`, `HelpdeskMetricsEntity`/`HelpdeskMetricsDao` (Room), role gating from cached `Me`.
  - **AND-378** — Claim / assignment management: `AssignmentAction` (`CLAIM`/`ASSIGN`/`TRANSFER`), `Assignment`, `TransferTarget` models, optimistic-update + reconcile, `409` conflict handling, assign/transfer bottom sheet.
  - **AND-379** — Agent availability / online state: online/available toggle that gates claim eligibility.
  - **AND-380** — Helpdesk ViewModel: the state layer (`StateFlow<UiState>`) coordinating metrics, queue, ownership actions, and availability. **Primary subject under test; this ticket's direct dependency.**
- **Web reference (parity oracle for JSON shapes):** `frontend/src/api/endpoints/helpdesk.ts` and assignment/availability endpoints, shared types `frontend/src/api/types.ts`; backend `OpenAPI` at `/openapi.json`. Fixture JSON MUST be reconciled against these at implementation time.
- **Stack:** Kotlin 2.0.21, JUnit4, kotlinx-coroutines-test 1.8+, Turbine (Flow assertions), MockWebServer (OkHttp 4.12), Moshi 1.15 (codegen), Truth/AssertJ assertions, Compose UI Test (`createAndroidComposeRule`), Hilt testing (`HiltAndroidRule`, `@HiltAndroidTest`, `@TestInstallIn`), Robolectric for JVM-side Room/Android shims, Paging 3 `AsyncPagingDataDiffer`/`asSnapshot`. AGP 8.7.3, JDK 17, minSdk 24 / target 35, Gradle 8.9.
- **Conventions:** typed `ApiResult<T>`; FastAPI `detail` mapping (`string | [{msg}] | {code,...}`) via the shared `DetailErrorMapper` in `core-network`; ViewModels expose `StateFlow<UiState>`; cookie-based session with `ui_csrf` → `X-CSRF-Token` header.

## 3. Functional Requirements

FR-1. **Repository/DTO tests (JVM)** for metrics, assignment, and availability covering: success mapping, empty/all-zero payloads, malformed/partial JSON, HTTP 4xx/5xx with each `detail` variant, `409` conflict, `403` non-agent, 401 refresh-then-retry, bounded backoff for idempotent GETs, and 20s timeout handling.

FR-2. **DTO mapping tests (JVM)** for `HelpdeskMetricsDto`, the queue item DTO (consumed from AND-161/reused), and the assignment/availability DTOs — golden-JSON round-trip versus domain-object builders, including null time-metrics and unknown `deltas` keys.

FR-3. **ViewModel tests (JVM)** for the Helpdesk ViewModel(s) (AND-380) asserting exact `UiState` sequences via Turbine: initial `Loading`, `AccessDenied` (non-agent, no network call), `Content(isStale=false)` on success, `Content(isStale=true)` on network-fail-with-cache, `Empty`, `Error(retryable)`, `refresh()` toggling `isRefreshing` + queue invalidation, optimistic claim/assign/transfer then reconcile, `409`-rollback, and **availability toggle gating claim eligibility**.

FR-4. **Compose UI tests (instrumented)** for the dashboard (metric grid + queue preview), the assignment bottom sheet (agent/queue picker + note), the claim action (snackbar + undo), and the availability toggle: each `UiState` renders the correct nodes; tapping a queue row emits the navigation callback; "View full queue" emits its callback; retry re-invokes load; error banner shows mapped `detail` text; claim controls are disabled/enabled by availability state.

FR-5. **Shared fixtures** (`core-testing`) provide canonical helpdesk JSON sample payloads and domain-object builders (`HelpdeskFixtures`) plus the reused `NetworkTestHarness`/`MainDispatcherRule`/`FakeSessionRepository`, so tests do not duplicate literals.

FR-6. **CI gate:** `:feature-helpdesk:testDebugUnitTest` and `:feature-helpdesk:connectedDebugAndroidTest` (or the managed-device equivalent) both pass; coverage thresholds (Section 11) are met or the build fails.

## 4. Technical Design

### 4.1 JVM unit tests (`src/test`)

Repository tests use `MockWebServer` wired to a real Retrofit/Moshi/OkHttp stack so JSON deserialization, the CSRF header interceptor, the 401 refresh interceptor, and the persistent cookie jar are exercised together (integration-style at the repo boundary, no production code mocked). Room-backed metrics caching is tested with an in-memory Robolectric Room database.

```kotlin
class HelpdeskMetricsRepositoryTest {
    private val server = MockWebServer()
    private lateinit var repo: HelpdeskMetricsRepository

    @Before fun setUp() {
        server.start()
        val api = NetworkTestHarness(server.url("/")).create(HelpdeskApi::class.java)
        val dao = inMemoryRoom().helpdeskMetricsDao()
        repo = DefaultHelpdeskMetricsRepository(api, dao, errorMapper = DetailErrorMapper())
    }
    @After fun tearDown() = server.shutdown()

    @Test fun `refreshMetrics maps dto then caches`() = runTest {
        server.enqueue(jsonResponse(HelpdeskFixtures.METRICS_JSON))
        val result = repo.refreshMetrics()
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
        val m = (result as ApiResult.Success).data
        assertThat(m.openCount).isEqualTo(42)
        assertThat(m.avgFirstResponseSeconds).isEqualTo(540L)
        assertThat(server.takeRequest().getHeader("X-CSRF-Token")).isNotEmpty()
        assertThat(repo.observeMetrics().first()?.openCount).isEqualTo(42) // cached
    }
}
```

`NetworkTestHarness` (in `core-testing`, reused from AND-376) reuses the production `OkHttpClient`/`Moshi` builders from `core-network` with the base URL swapped to the `MockWebServer` URL and timeouts shortened (read/connect = 2s) so timeout assertions run fast via `SocketPolicy.NO_RESPONSE`.

ViewModel tests run on `StandardTestDispatcher` injected through a `MainDispatcherRule`. The repositories and `SessionRepository` are replaced by hand-written fakes (`FakeHelpdeskMetricsRepository`, `FakeHelpdeskAssignmentRepository`, `FakeSessionRepository`) implementing the interfaces with scriptable `ApiResult` responses and a settable `currentRole()` — this isolates state logic from transport.

```kotlin
@get:Rule val mainRule = MainDispatcherRule()

@Test fun `non-agent role yields AccessDenied and no network`() = runTest {
    val metrics = FakeHelpdeskMetricsRepository()
    val session = FakeSessionRepository(role = HelpdeskAgentRole.NONE)
    val vm = HelpdeskDashboardViewModel(metrics, session, FakeQueuePagerFactory())
    vm.uiState.test {
        assertThat(awaitItem()).isEqualTo(HelpdeskDashboardUiState.Loading)
        assertThat(awaitItem()).isEqualTo(HelpdeskDashboardUiState.AccessDenied)
        cancelAndConsumeRemainingEvents()
    }
    assertThat(metrics.refreshCallCount).isEqualTo(0)
}

@Test fun `availability off disables claim eligibility`() = runTest {
    val assign = FakeHelpdeskAssignmentRepository()
    val session = FakeSessionRepository(role = HelpdeskAgentRole.AGENT, available = false)
    val vm = helpdeskViewModel(assign, session)
    vm.uiState.test {
        skipItems(1) // Loading
        val content = awaitItem() as HelpdeskUiState.Content
        assertThat(content.canClaim).isFalse()   // gated by availability (AND-379)
        cancelAndConsumeRemainingEvents()
    }
    vm.claim("cnv_1")            // attempt while unavailable
    assertThat(assign.claimCallCount).isEqualTo(0) // gated client-side; server authoritative
}
```

Optimistic-update tests assert the row reflects the new assignee immediately, then either confirms (success) or rolls back (`409`/error) with the reconciled server payload applied:

```kotlin
@Test fun `claim conflict rolls back and reconciles`() = runTest {
    val assign = FakeHelpdeskAssignmentRepository().apply {
        enqueueClaim(ApiResult.Error(ApiError(code = "conflict",
            message = "Already claimed by B. Agent", httpStatus = 409)))
    }
    val vm = helpdeskViewModel(assign, FakeSessionRepository(available = true))
    vm.uiState.test {
        skipItems(2)
        vm.claim("cnv_1")
        val optimistic = awaitItem() as HelpdeskUiState.Content
        assertThat(optimistic.conversation("cnv_1").assigneeId).isEqualTo(SELF_ID)
        val reconciled = awaitItem() as HelpdeskUiState.Content
        assertThat(reconciled.conversation("cnv_1").assigneeId).isNotEqualTo(SELF_ID)
        assertThat(reconciled.snackbar?.message).contains("Already claimed")
        cancelAndConsumeRemainingEvents()
    }
}
```

### 4.2 Instrumented Compose tests (`src/androidTest`)

Screen-level tests drive stateless composables directly with hoisted state, plus a small set of ViewModel-backed `@HiltAndroidTest` flows using fake repository bindings via `@TestInstallIn` replacing the production `RepositoryModule`. Interaction uses `onNodeWithTag`/`onNodeWithText`; semantics test tags (`testTag("metricCard_open")`, `"queueRow_$id"`, `"viewFullQueue"`, `"helpdeskRetry"`, `"errorBanner"`, `"availabilityToggle"`, `"assignSheet"`) are added to production composables only if missing — permitted under this ticket as non-behavioural instrumentation (subject to Q3).

```kotlin
@Test fun dashboard_viewFullQueue_emitsCallback() {
    var opened = false
    composeRule.setContent {
        TestLogonTheme {
            HelpdeskDashboardContent(
                state = HelpdeskDashboardUiState.Content(
                    metrics = HelpdeskFixtures.metrics(), isStale = false, cachedAt = null),
                queue = HelpdeskFixtures.queuePreview(),
                onOpenFullQueue = { opened = true },
                onOpenConversation = {}, onRefresh = {}, onRetry = {})
        }
    }
    composeRule.onNodeWithTag("viewFullQueue").performClick()
    assertThat(opened).isTrue()
}

@Test fun availabilityOff_disablesClaimButton() {
    composeRule.setContent {
        TestLogonTheme {
            ConversationActionsBar(canClaim = false, onClaim = {}, onAssign = {}, onTransfer = {})
        }
    }
    composeRule.onNodeWithTag("claimAction").assertIsNotEnabled()
}
```

A managed Gradle device (Pixel 6 / API 34, ATD image) is configured so `connected` tests run headless in CI.

## 5. API Contract

This ticket defines **no new API**; it asserts the contracts owned by AND-377 (metrics), AND-378 (assignment), and AND-379 (availability). Canonical payload shapes that fixtures must mirror (verified against `/openapi.json` and `frontend/src/api/endpoints/helpdesk.ts`):

**`GET /messaging/helpdesk/metrics`** → dashboard metrics (AND-377):
```json
{
  "open": 42, "unassigned": 11, "assigned_to_me": 6, "sla_at_risk": 3,
  "avg_first_response_seconds": 540, "avg_resolution_seconds": 7200,
  "resolved_by_me_today": 9,
  "deltas": { "open": -4, "resolved_by_me_today": 2 },
  "generated_at": "2026-06-05T14:30:00Z"
}
```

**`GET /messaging/helpdesk/queue?page={n}`** → paged queue (reused from AND-161): `{ "items": [{"id":"cnv_1","subject":"...","assignee":null,"status":"open","requester":{...}}], "page":1, "has_more": true }`.

**Claim / assign / transfer** (AND-378) — request/response asserted for each `AssignmentAction`:
```json
// POST .../conversations/{id}/claim   -> 200
{"conversation_id":"cnv_1","assignee_id":"usr_self","assignee_name":"Me",
 "status":"assigned","queue_id":null,"updated_at":"2026-06-05T14:31:00Z"}
// POST .../conversations/{id}/transfer  body {"agent_id":"usr_2","note":"ctx"}
// 409 conflict -> {"detail":{"code":"conflict","message":"Already claimed by B. Agent"}}
```

**Availability toggle** (AND-379): `POST .../agents/me/availability` body `{"available": true}` → `200 {"available": true, "updated_at": "..."}`; the availability value gates claim eligibility in the ViewModel.

**Error envelope** (asserted in all three `detail` variants):
```json
{"detail": "Conversation not found"}
{"detail": [{"msg": "field required", "loc": ["body","agent_id"]}]}
{"detail": {"code": "forbidden", "message": "Not an agent"}}
```
The `DetailErrorMapper` reduces each to a stable `ApiError` (`message`, optional `code`, optional field list, `httpStatus`); tests assert the human-readable message and `retryable` classification chosen for each shape (`403`/`409`/`422` non-retryable; `5xx`/timeout retryable).

## 6. Data & State Management

Tests assert the `UiState` models defined in AND-377/378/380; this ticket introduces no new state types. The sealed hierarchies under test (asserted exactly):

```kotlin
sealed interface HelpdeskDashboardUiState {
    data object Loading : HelpdeskDashboardUiState
    data object AccessDenied : HelpdeskDashboardUiState
    data class Content(val metrics: HelpdeskMetrics, val isStale: Boolean,
                       val cachedAt: Instant?) : HelpdeskDashboardUiState
    data object Empty : HelpdeskDashboardUiState
    data class Error(val message: String, val retryable: Boolean) : HelpdeskDashboardUiState
}
```

State assertions cover: cold-start `Loading` (initial `StateFlow` value); `AccessDenied` for non-agent roles **with zero metrics requests issued**; `Content(isStale=false)` after a successful fetch; `Content(isStale=true)` + `cachedAt` when the network fails but Room holds a prior row; `Empty` for all-zero payload with no cache history; `Error(retryable)` on failure-without-cache. Room caching is in scope (AND-377 owns a single-row `helpdesk_metrics` table): a DAO round-trip test (`upsert`/`observe`/`clear`) and a stale-then-fresh emission test (cache emits first, network success replaces) are required. A logout test asserts `HelpdeskMetricsDao.clear()` is invoked so a second agent never sees the prior agent's `assigned_to_me`/`resolved_by_me_today`. Queue paging is asserted with `queuePreview.asSnapshot { scrollTo(24) }` to confirm a second page is requested and appended, and that `refresh()` invalidates the paging source (`server.requestCount` increments).

## 7. Error Handling & Resilience

Tests are the resilience contract here. Required cases:

- **Timeout:** `MockWebServer` `NO_RESPONSE` → repo returns `ApiResult.Error` with a timeout-classified error within the configured bound; ViewModel surfaces `Error(retryable=true)` (or `Content(isStale=true)` if a cache exists).
- **Bounded backoff (idempotent GET only):** transient `503` then `200` on `GET /metrics` → success after retry; `server.requestCount` confirms ≤ max-retries+1 attempts. Non-idempotent claim/assign/transfer POSTs are asserted **not** to retry on failure.
- **401 refresh:** enqueue `401`, then `200` for `POST /ui/session/refresh`, then `200` for the retried request; assert exactly one refresh occurs and the original call succeeds; a second consecutive 401 yields a terminal auth error (no infinite loop).
- **409 conflict:** claim against an already-claimed conversation rolls back the optimistic update and surfaces "Already claimed by {name}", reconciling the row from the server payload.
- **403 non-agent:** mapped to a non-retryable error / `AccessDenied`, no further requests.
- **Malformed JSON:** mapped parse error, not an uncaught exception/crash.
- **Refresh race:** an in-flight `load()` is cancelled by a subsequent `refresh()` so no stale emission overwrites fresh state (asserted via Turbine ordering).

## 8. Security & Privacy

No production security surface changes. Test-specific obligations: `NetworkTestHarness` must reproduce the CSRF header echo (`ui_csrf` cookie → `X-CSRF-Token`) and persistent cookie jar so the 401-refresh test is realistic; a regression test asserts `X-CSRF-Token` is present on both GET metrics and POST claim/assign/transfer/availability requests. A test asserts metrics cache is cleared on logout (privacy: per-agent counts must not leak across sessions). Fixtures contain only synthetic data — no real credentials, tokens, or PII; the spec mandates no logging of cookie/CSRF values or full response bodies in test output. Cleartext dev-host usage is irrelevant here since all traffic is local-loopback `MockWebServer`. Role gating is verified as UX-only with the server (`403`) treated as authoritative.

## 9. Accessibility & i18n

Compose UI tests double as a basic a11y gate: assertions use `onNodeWithText`/content-description selectors (not only test tags) for primary actions (claim, assign, transfer, retry, view full queue, availability toggle), forcing those nodes to carry semantics. A test asserts each metric card exposes a single merged readable node (e.g., "Open conversations: 42, down 4 since yesterday"), that the availability toggle exposes an on/off state description, and that interactive elements have non-empty content descriptions or text and ≥48dp targets. i18n: error and label strings are asserted via string resources (e.g., `R.string.helpdesk_error_generic`, `helpdesk_dashboard_*`) resolved through `context.getString(...)` rather than hard-coded literals, proving externalised strings; durations/relative times use platform formatters. RTL/locale matrix is deferred to a dedicated a11y sweep.

## 10. Telemetry & Logging

No production telemetry is added. If AND-377/378/380 emit analytics events (e.g., `helpdesk_dashboard_viewed`, `helpdesk_dashboard_refreshed`, `helpdesk_dashboard_error`, `helpdesk_dashboard_full_queue_opened`, and claim/assign/transfer/availability events), a ViewModel test injects a `FakeAnalytics` facade and asserts the event name + properties (role, trigger, code, retryable, action) fire on the corresponding action; absence of an event on a no-op (e.g., gated claim while unavailable) is also asserted. Otherwise this is N/A and noted in the test file. Test infrastructure logging is limited to JUnit/Compose failure dumps; `MockWebServer` request logs are captured only on failure. No PII or payload bodies are logged.

## 11. Testing Strategy

This ticket *is* the testing strategy. Test inventory and gates:

- **Repository (JVM):** `HelpdeskMetricsRepositoryTest`, `HelpdeskAssignmentRepositoryTest`, `HelpdeskAvailabilityRepositoryTest` — success, empty/all-zero, malformed, 404/422/403/409 `detail` variants, 503→200 GET retry, timeout, 401-refresh, cache upsert/observe round-trip (Robolectric Room), no-retry on POST. ~22 cases.
- **DTO mapping (JVM):** `HelpdeskMetricsDtoMappingTest`, `AssignmentDtoMappingTest`, `QueueItemDtoMappingTest` — golden-JSON round-trip vs builder, null time-metrics, unknown `deltas` keys. ~10 cases.
- **ViewModel (JVM):** `HelpdeskDashboardViewModelTest` (+ assignment/availability VM tests per AND-380's surface) — Turbine state sequences: Loading→Content/Empty/AccessDenied/Error, stale fallback, refresh + isRefreshing, optimistic claim/assign/transfer + reconcile, 409 rollback, **availability-gates-claim**, queue paging snapshot, refresh race. ~20 cases.
- **DAO (JVM/Robolectric):** `HelpdeskMetricsDaoTest` — in-memory upsert/observe/clear. ~4 cases.
- **Compose (androidTest):** `HelpdeskDashboardScreenTest`, `AssignmentSheetTest`, `AvailabilityToggleTest`, `ConversationActionsBarTest` — render per state, queue-row + view-full-queue callbacks, retry re-invoke, error-banner text, claim disabled when unavailable, assign/transfer picker selection + note. ~18 cases.
- **Coverage gate (JaCoCo via Gradle):** `feature-helpdesk` line coverage ≥ 80%, branch ≥ 70% over ViewModels + repositories + mappers (UI composables excluded from the line gate but covered by androidTest). Build fails below threshold.
- **Determinism:** all suspending tests use `runTest` + injected `TestDispatcher`; no `Thread.sleep`, no real network, virtual time only. Compose tests disable animations and use `waitForIdle()`.
- **Execution:** `./gradlew :feature-helpdesk:testDebugUnitTest :feature-helpdesk:pixel6Api34DebugAndroidTest` green locally and in CI.

## 12. Dependencies & Sequencing

- **Depends on AND-380** (Helpdesk ViewModel) — the primary subject under test; its `StateFlow<UiState>` and action coordination must be merged first.
- **Transitively depends on AND-377** (dashboard, metrics repository/DTO/Room), **AND-378** (claim/assign/transfer models + optimistic/conflict logic), and **AND-379** (availability toggle that gates claims) — all exercised by repository, mapping, ViewModel, and UI tests.
- **Reuses** shared test infrastructure from AND-376/AND-047/AND-048 (`NetworkTestHarness`, `MainDispatcherRule`, JSON fixture helpers) in `core-testing`, and contributes `HelpdeskFixtures`, `FakeHelpdeskMetricsRepository`, `FakeHelpdeskAssignmentRepository`, `FakeSessionRepository`, `FakeQueuePagerFactory` for reuse by future helpdesk tickets.
- No backend dependency; runs fully offline against `MockWebServer`.
- **Blocks:** none recorded in backlog. Should land at the close of the helpdesk feature work (M8/E49) as the verification gate.

## 13. Risks & Open Questions

- **R1 — Upstream API drift:** if AND-377/378/379 final DTO field names differ from the shapes in Section 5, fixtures break. Mitigation: derive fixture JSON from `/openapi.json` and `frontend/src/api/types.ts` at implementation time; mapping tests are the source of truth.
- **R2 — Metrics endpoint may not exist server-side (AND-377 Q1):** if AND-377 ships the client-side count-derivation fallback, the metrics-repository tests must target the fallback path instead of `GET /metrics`. Determine the implemented path before writing fixtures.
- **R3 — Availability gating semantics (AND-379):** confirm whether claim is gated purely client-side (UX) or also enforced by a server response; tests must assert the implemented contract (this spec assumes client-side gate + server-authoritative `403`/`409`).
- **R4 — Paging assertion flakiness:** `asSnapshot` ordering can be sensitive; mitigate with deterministic `PagingConfig` (no placeholders, fixed `pageSize`).
- **R5 — Managed-device availability in CI:** if the ATD image is unavailable, fall back to Robolectric for a subset of Compose tests and gate the rest behind a `connectedCheck` job.
- **Q1:** Do the helpdesk ViewModels emit analytics events? Determines whether Section 10 telemetry tests are required or N/A.
- **Q2:** Exact `Me.roles` taxonomy for agent/supervisor/admin (from AND-377) — the gating constant must be the single source of truth in tests.
- **Q3:** Final test-tag naming convention — confirm with the AND-377/378/380 authors to minimise touching production composables.

## 14. Acceptance Criteria

AC-1. `:feature-helpdesk:testDebugUnitTest` passes with all repository, DTO-mapping, DAO, and ViewModel suites listed in Section 11 present and green.
AC-2. `:feature-helpdesk` instrumented suite passes on the configured managed device, covering render-per-`UiState` (Loading/Content/Empty/AccessDenied/Error/stale), queue-row + view-full-queue navigation callbacks, retry re-invocation, and mapped error-banner text.
AC-3. All three FastAPI `detail` variants (string, `[{msg}]`, `{code,...}`) have explicit mapping assertions producing stable `ApiError` messages with correct `retryable` classification.
AC-4. 401→refresh→retry is asserted to refresh exactly once and then succeed, and a double-401 produces a terminal auth error with no retry loop.
AC-5. Timeout and transient-5xx-then-success behaviours are asserted for the idempotent metrics GET, and claim/assign/transfer/availability POSTs are asserted **not** to retry.
AC-6. Optimistic claim/assign/transfer is asserted to update the row immediately and reconcile on success; a `409` conflict is asserted to roll back and surface "Already claimed by {name}".
AC-7. The **availability toggle gating claim eligibility** is asserted: with availability off, claim controls are disabled and no claim request is issued; with availability on, claim proceeds (covers AND-379's backlog acceptance).
AC-8. Non-agent role yields `AccessDenied` with zero metrics requests; metrics cache is cleared on logout (asserted).
AC-9. Queue second-page append is asserted via `asSnapshot`, and `refresh()` is asserted to invalidate the paging source and toggle `isRefreshing`.
AC-10. JaCoCo coverage gate (≥80% line / ≥70% branch over VMs+repos+mappers) is enforced and met; the build fails if it regresses.
AC-11. Shared fixtures/harness are contributed to `core-testing` and consumed by the helpdesk suites (no duplicated JSON literals).
AC-12. No test contacts a real network host; all transport is `MockWebServer`.

## 15. Definition of Done

- All Section 14 acceptance criteria verified green in CI on branch `android-port`.
- Test sources reside under `feature-helpdesk/src/test` and `feature-helpdesk/src/androidTest`; shared helpers under `core-testing`; package roots `com.testlogon.android.feature.helpdesk.*` / `com.testlogon.android.core.testing.*`.
- Coverage gate wired into the Gradle build and passing; lint/detekt/ktlint clean.
- No production behaviour changed except additive, non-functional test tags/content descriptions agreed per Q3.
- Code reviewed and merged; the helpdesk fixtures confirmed reusable by downstream helpdesk tickets.
- Open questions Q1–Q3 and risk R2/R3 (fallback path, availability semantics) resolved or explicitly deferred with the owner noted in the PR description.
