---
id: AND-381
title: Helpdesk tests
milestone: M8
epic: E49
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-380, AND-379, AND-378, AND-377]
blocks: []
---

# AND-381 — Helpdesk tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the **Helpdesk** feature area of the TestLogon native Android app (`com.testlogon.android`). It is a pure **Test** ticket (Type: Test, Priority: P2) — it ships no production behaviour. It adds repository-level (JVM) tests and Compose UI tests that exercise the code produced by the upstream Helpdesk feature tickets in epic E49: the agent dashboard (AND-377), claim/assignment management (AND-378), agent availability / online state (AND-379), and the Helpdesk ViewModel state layer (AND-380). The single backlog acceptance criterion is **"Pass."**, which this spec operationalises into concrete, measurable, deterministic test obligations.

The goal is to lock down the behaviour of the `feature-helpdesk` module so that the helpdesk surface — metrics dashboard, queue preview, ownership mutations (claim/assign/transfer), and the availability toggle that gates claim eligibility — is verified end-to-end at the unit and screen level against faked transport. Concretely, the suite must prove that: (a) helpdesk DTOs map correctly from FastAPI JSON into `core-model` domain types; (b) `HelpdeskMetricsRepository` and the assignment/availability repository surfaces translate transport outcomes into the typed `ApiResult<T>` envelope, including all three FastAPI `detail` error shapes, 401-refresh-then-retry, `409` conflict handling, and 20s-timeout behaviour; (c) the Helpdesk ViewModel(s) emit the correct `StateFlow<UiState>` transitions for loading/content/stale/empty/access-denied/error, optimistic-update-then-reconcile, and the availability toggle gating claim eligibility; and (d) the Compose dashboard, queue-preview, assignment bottom sheet, and availability toggle render each `UiState` and route correctly on interaction.

Out of scope: writing or modifying production source for helpdesk (owned by AND-377/378/379/380), backend changes, end-to-end tests against the live dev backend, and screenshot/visual-regression tooling. Network is always faked at the OkHttp boundary (`MockWebServer`); no test in this ticket contacts `http://18.222.237.167:8000`.

> **REVIEWER NOTE (AND-381, 2026-06-06): scope corrected against authoritative sources.** The backend OpenAPI exposes **only two** helpdesk endpoints: `POST /messaging/helpdesk/conversations/{conversation_id}/claim` (→ `HelpdeskClaimOut`) and `GET /messaging/helpdesk/queue` (→ `ConversationOut[]`). There is **no metrics endpoint, no transfer endpoint, and no helpdesk availability endpoint** in the backend or the web reference. Consequently the metrics dashboard, the `assign`/`transfer` actions, the availability toggle, Room metrics caching, and queue *pagination* described below are **unverified / fabricated assumptions** and the corresponding test obligations are downgraded to "only if the upstream feature ticket actually ships them." The verified, in-contract behaviour this suite must lock down is: (1) the agent **queue** fetch (`getHelpdeskQueue`, flat array, `silent403` for non-agents); (2) the **claim** action (idempotent, returns new routing `state` + `assigned_agent_user_id` + `assignment_version`); (3) the shared transport contract — CSRF echo, 401→refresh→retry, and the three FastAPI `detail` error shapes. See §16 for the full audit.

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

Repository tests use `MockWebServer` wired to a real Retrofit/Moshi/OkHttp stack so JSON deserialization, the CSRF header interceptor, the 401 refresh interceptor, and the persistent cookie jar are exercised together (integration-style at the repo boundary, no production code mocked). The verified repository surfaces are the **queue** (`getHelpdeskQueue` → `List<Conversation>`) and **claim** (`claim` → `HelpdeskClaimOut`) calls.

> **CORRECTED:** The `HelpdeskMetricsRepositoryTest` snippet below references `/metrics`, `openCount`, and `avgFirstResponseSeconds`, **none of which exist** in the backend contract. It is retained only as an *illustrative harness pattern*; if AND-377 does not ship a real metrics source, delete this class and apply the same MockWebServer pattern to `HelpdeskQueueRepositoryTest` / `HelpdeskClaimRepositoryTest` instead (asserting `HelpdeskClaimOut` fields `ok`/`state`/`assigned_agent_user_id`/`assignment_version`/`idempotent`). Room metrics caching is likewise conditional on AND-377 actually persisting metrics.

```kotlin
class HelpdeskMetricsRepositoryTest { // ILLUSTRATIVE ONLY — no /metrics endpoint exists; see §16
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

This ticket defines **no new API**; it asserts the contracts owned by AND-377/378/379. The canonical payload shapes below are **corrected against the authoritative `openapi.pretty.json` and `frontend/src/api/endpoints/messaging.ts`** (note: there is no `endpoints/helpdesk.ts` — the helpdesk calls live in `messaging.ts`). Fixtures MUST mirror these exact shapes.

> The frontend has **no `helpdesk.ts`**; helpdesk calls (`claimHelpdeskConversation`, `getHelpdeskQueue`, `startHelpdeskConversation`) are defined in `src/api/endpoints/messaging.ts`. There is **no `types.ts` helpdesk metrics/assignment/availability DTO**.

**~~`GET /messaging/helpdesk/metrics`~~ — DOES NOT EXIST.** *(Corrected.)* No metrics endpoint is present in OpenAPI; `HelpdeskMetricsDto`/`HelpdeskMetricsRepository`/Room metrics caching have no backend contract. Any metrics-derivation must be a client-side count fallback if AND-377 ships one (see R2); fixtures for a `/metrics` JSON body are removed. Do not author `GET /metrics` MockWebServer fixtures.

**`GET /messaging/helpdesk/queue`** *(Corrected)* → **flat array** `ConversationOut[]` (NOT a paged envelope). Verified params: `group_id` (**required**, maxLength 128), `state` (optional string), `limit` (optional int, default **50**, max **200**). There is **no `page` param and no `has_more`/`items` envelope** — pagination and `asSnapshot` second-page assertions do not apply. The web client (`getHelpdeskQueue`) passes `group_id` (+ optional `state`) and uses `silent403: true` so non-agents silently get `403` and render no queue. Each element is a `ConversationOut`; helpdesk rows are keyed by `conversation_id` and carry `routing_mode: "helpdesk_bridge"`, `routing_state` (`awaiting_agent` | `assigned` | `paused_no_agents_online`), and `active_agent_user_id`.

**Claim** *(Corrected)* — `POST /messaging/helpdesk/conversations/{conversation_id}/claim` with an **empty JSON body `{}`** → `200 HelpdeskClaimOut`:
```json
{"ok": true, "conversation_id": "cnv_1", "state": "assigned",
 "assigned_agent_user_id": "usr_self", "assignment_version": 3, "idempotent": false}
```
Required fields: `ok`, `conversation_id`, `state`, `assigned_agent_user_id`, `assignment_version` (integer); `idempotent` defaults `false`. **There are NO `assignee_id`/`assignee_name`/`queue_id`/`updated_at` fields** — those were fabricated. Documented responses are **`200` and `422` only**; **no `409` is documented** and the operation is **idempotent** (re-claiming returns `idempotent: true`), so the "409 conflict / Already claimed by {name}" rollback narrative is unverified (see §16). On success the web client calls `onClaimSuccess(data.state, data.assigned_agent_user_id)` and invalidates the `conversations` + `helpdesk-queue` query caches.

**~~Assign / transfer~~ — DO NOT EXIST.** *(Corrected.)* There is no `POST .../conversations/{id}/transfer` and no generic assign endpoint; `AssignmentAction.{ASSIGN,TRANSFER}` and the assign/transfer bottom sheet have no backend contract. Only **claim** exists.

**~~Availability toggle `POST .../agents/me/availability`~~ — DOES NOT EXIST for helpdesk.** *(Corrected.)* The only availability endpoints in OpenAPI are KYC (`GET`/`PATCH /v1/kyc/assignment/availability`, schema `KycAdminAvailabilityOut`/`KycAdminAvailabilityIn`) and find-datetime poll availability — neither is the helpdesk agent toggle. The "availability gates claim eligibility" contract is **unverified** against backend/web; if AND-379 ships it, the gate is presumed client/presence-side (web uses `useHeartbeat`/`usePresence` for online state, not an availability POST). Treat AC-7 as conditional (see §16/§17).

**Error envelope** (asserted in all three `detail` variants):
```json
{"detail": "Conversation not found"}
{"detail": [{"msg": "field required", "loc": ["body","agent_id"]}]}
{"detail": {"code": "forbidden", "message": "Not an agent"}}
```
The three `detail` shapes are **Verified** against the web client's `normalizeErrorDetail` (`src/api/client.ts`): a `string` is returned verbatim; an **array** is mapped item-by-item to each `.msg` and joined with ", "; an **object** with `{code,...}` is run through `mapAuthorizationError` and otherwise falls back to its `.msg`. The `DetailErrorMapper` (Android) reduces each to a stable `ApiError` (`message`, optional `code`, optional field list, `httpStatus`); tests assert the human-readable message and `retryable` classification chosen for each shape (`403`/`422` non-retryable; `5xx`/timeout retryable). **`409` is NOT a documented helpdesk response** (claim returns only 200/422), so a 409-non-retryable assertion against `claim` is testing a hypothetical shape — keep it only as a generic mapper unit test, not as a claim-endpoint contract test.

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

State assertions cover: cold-start `Loading` (initial `StateFlow` value); `AccessDenied` for non-agent roles **with zero metrics requests issued**; `Content(isStale=false)` after a successful fetch; `Content(isStale=true)` + `cachedAt` when the network fails but Room holds a prior row; `Empty` for all-zero payload with no cache history; `Error(retryable)` on failure-without-cache. Room caching is in scope (AND-377 owns a single-row `helpdesk_metrics` table): a DAO round-trip test (`upsert`/`observe`/`clear`) and a stale-then-fresh emission test (cache emits first, network success replaces) are required. A logout test asserts `HelpdeskMetricsDao.clear()` is invoked so a second agent never sees the prior agent's `assigned_to_me`/`resolved_by_me_today`. ~~Queue paging is asserted with `queuePreview.asSnapshot { scrollTo(24) }`~~ — **CORRECTED:** `GET /messaging/helpdesk/queue` returns a **flat `ConversationOut[]`** with a `limit` cap (default 50, max 200) and **no cursor/page param**, so there is no Paging 3 source to invalidate or second page to append. Replace the paging assertions with: (a) a `limit`-respecting fetch test, (b) a `refresh()` re-fetch test asserting `server.requestCount` increments, and (c) a `silent403`/empty-list rendering test. (Metrics Room caching above is conditional on AND-377 — see §16.)

## 7. Error Handling & Resilience

Tests are the resilience contract here. Required cases:

- **Timeout:** `MockWebServer` `NO_RESPONSE` → repo returns `ApiResult.Error` with a timeout-classified error within the configured bound; ViewModel surfaces `Error(retryable=true)` (or `Content(isStale=true)` if a cache exists).
- **Bounded backoff (idempotent GET only):** transient `503` then `200` on `GET /metrics` → success after retry; `server.requestCount` confirms ≤ max-retries+1 attempts. Non-idempotent claim/assign/transfer POSTs are asserted **not** to retry on failure.
- **401 refresh:** enqueue `401`, then `200` for `POST /ui/session/refresh`, then `200` for the retried request; assert exactly one refresh occurs and the original call succeeds; a second consecutive 401 yields a terminal auth error (no infinite loop).
- **~~409 conflict~~ (CORRECTED → not in contract):** the claim endpoint documents only `200`/`422` and is **idempotent** (`HelpdeskClaimOut.idempotent`). There is no documented `409` and no "Already claimed by {name}" payload. Replace this with: a **re-claim idempotency** test (second claim returns `idempotent: true`, `state`/`assigned_agent_user_id` unchanged) and a generic `DetailErrorMapper` unit test for an arbitrary `{code,...}` object shape. Keep optimistic-update/rollback testing **only if** AND-378 implements a client-side conflict path against a real server error; otherwise drop it (no transfer/assign endpoints exist either).
- **403 non-agent:** mapped to a non-retryable error / `AccessDenied`, no further requests.
- **Malformed JSON:** mapped parse error, not an uncaught exception/crash.
- **Refresh race:** an in-flight `load()` is cancelled by a subsequent `refresh()` so no stale emission overwrites fresh state (asserted via Turbine ordering).

## 8. Security & Privacy

No production security surface changes. Test-specific obligations: `NetworkTestHarness` must reproduce the CSRF header echo (`ui_csrf` cookie → `X-CSRF-Token`) and persistent cookie jar so the 401-refresh test is realistic — **both Verified** against `src/api/client.ts` (CSRF read from `ui_csrf` cookie and set as `X-CSRF-Token`; 401 triggers a single `POST /ui/session/refresh` then one retry with `credentials: "include"`). A regression test asserts `X-CSRF-Token` is present on the **GET queue** and **POST claim** requests (the only two helpdesk calls; ~~GET metrics / POST assign/transfer/availability~~ do not exist — CORRECTED). A test asserts metrics cache is cleared on logout (privacy: per-agent counts must not leak across sessions). Fixtures contain only synthetic data — no real credentials, tokens, or PII; the spec mandates no logging of cookie/CSRF values or full response bodies in test output. Cleartext dev-host usage is irrelevant here since all traffic is local-loopback `MockWebServer`. Role gating is verified as UX-only with the server (`403`) treated as authoritative.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: **OAPI** = `reference/openapi.pretty.json` / `reference/openapi.index.txt`; **FE** = `reference/src/...`.

1. **Helpdesk exposes a metrics endpoint `GET /messaging/helpdesk/metrics`.** — **Corrected (false).** No such path exists. OAPI index has only two helpdesk routes (index lines 393–394). Source: `openapi.index.txt:393-394`; grep of `openapi.pretty.json` for `helpdesk` returns only `claim` + `queue`.
2. **`GET /messaging/helpdesk/queue` is paged with `?page=` and `{items,page,has_more}`.** — **Corrected (false).** Returns a flat `array of ConversationOut`; params are `group_id` (required, maxLen 128), `state` (optional), `limit` (default 50, max 200). Source: OAPI `GET /messaging/helpdesk/queue` (`openapi.pretty.json:120907-120996`); FE `src/api/endpoints/messaging.ts: getHelpdeskQueue` (lines 1002–1012).
3. **Claim path `POST /messaging/helpdesk/conversations/{conversation_id}/claim`.** — **Verified.** Source: OAPI `POST .../claim` (`openapi.index.txt:393`); FE `src/api/endpoints/messaging.ts: claimHelpdeskConversation` (line 998), body is `{}`.
4. **Claim response fields `{conversation_id, assignee_id, assignee_name, status, queue_id, updated_at}`.** — **Corrected (false).** Real schema `HelpdeskClaimOut` = `{ok:bool, conversation_id:str, state:str, assigned_agent_user_id:str, assignment_version:int, idempotent:bool=false}`; required: `ok, conversation_id, state, assigned_agent_user_id, assignment_version`. Source: OAPI `components.schemas.HelpdeskClaimOut` (`openapi.pretty.json:37249-37286`); FE consumes `data.state` + `data.assigned_agent_user_id` (`src/pages/messages/ConversationView.tsx:643-647`).
5. **Claim returns `409 conflict` / "Already claimed by {name}".** — **Corrected (false / unverified).** Claim documents only `200` + `422`; the op is idempotent (`HelpdeskClaimOut.idempotent`). No 409 and no such message anywhere in OAPI or FE. Source: OAPI `POST .../claim` responses (`openapi.pretty.json:120879-120900`).
6. **`POST .../conversations/{id}/transfer` and a generic assign endpoint exist (AND-378).** — **Corrected (false).** No transfer/assign helpdesk routes in OAPI. Source: full `helpdesk` grep of `openapi.index.txt` (only lines 393–394).
7. **`POST /messaging/helpdesk/agents/me/availability` toggles agent availability (AND-379).** — **Corrected (false).** No helpdesk availability route. Availability endpoints that DO exist are KYC (`GET`/`PATCH /v1/kyc/assignment/availability`, schemas `KycAdminAvailabilityOut`/`In`) and find-datetime polls. Source: `openapi.index.txt:2284-2285, 409, 491`.
8. **Availability gates claim eligibility.** — **Unverified-assumption.** No backend contract; FE drives agent online-state via presence/heartbeat (`useHeartbeat`/`usePresence` in `src/pages/helpdesk/HelpdeskPage.tsx:11-12,81`), not an availability POST. Cannot be confirmed from sources.
9. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** — **Verified.** Source: FE `src/api/client.ts:167-171` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
10. **401 → single refresh via `POST /ui/session/refresh` → retry once; double-401 → terminal logout.** — **Verified.** Source: FE `src/api/client.ts:119-237` (`refreshSession()` posts `/ui/session/refresh`; single in-flight `refreshPromise`; retry; `retryRes.status===401` → `logout("session_expired")`).
11. **Three FastAPI `detail` shapes (`string` | `[{msg}]` | `{code,...}`) map to stable messages.** — **Verified.** Source: FE `src/api/client.ts: normalizeErrorDetail` (lines 66-102); tests `src/api/client.errorMapping.test.ts`.
12. **Non-agents get `403` on the queue and the UI silently shows no queue.** — **Verified.** Source: FE `getHelpdeskQueue` uses `silent403: true` (`messaging.ts:1005-1010`); `HelpdeskPage` sets `isAgent = !queueError` (`HelpdeskPage.tsx:83-90,133`).
13. **Queue rows carry `routing_mode:"helpdesk_bridge"`, `routing_state` ∈ {awaiting_agent, assigned, paused_no_agents_online}, `active_agent_user_id`.** — **Verified.** Source: FE `HelpdeskPage.tsx:23-33,100-103` and `ConversationView.tsx:1476-1490`.
14. **Helpdesk endpoint calls live in `frontend/src/api/endpoints/helpdesk.ts`.** — **Corrected (false).** No `helpdesk.ts`; the calls are in `src/api/endpoints/messaging.ts` (lines 987-1012). DTOs are not in a helpdesk-specific `types.ts` section.
15. **Framework choices (Compose UI Test `createAndroidComposeRule`, Turbine, MockWebServer, Robolectric, Paging 3, Hilt `@TestInstallIn`).** — **Unverified-assumption (framework refs).** These are reasonable Android test stack choices but are project conventions, not derivable from the backend/FE sources. Paging 3 is **not applicable** to the queue (claim #2). Framework refs: developer.android.com/jetpack/compose/testing, developer.android.com/training/dependency-injection/hilt-testing.

### Corrections made

- Frontmatter: `status: draft → reviewed`; added `reviewed_on: 2026-06-06`.
- §1, §5: flagged that **`/metrics`, `/transfer`, assign, and `/agents/me/availability` do not exist**; corrected the queue to a flat `ConversationOut[]` (no `page`/`has_more`); corrected `HelpdeskClaimOut` field names; corrected claim responses to `200`/`422` only (no `409`, idempotent); corrected the endpoint-file location (`messaging.ts`, not `helpdesk.ts`).
- §5 (errors): annotated the three `detail` shapes as Verified; noted `409` is out-of-contract for claim.
- §4.1: marked the `HelpdeskMetricsRepositoryTest` snippet as illustrative-only (no metrics endpoint).
- §6: removed the `asSnapshot` paging assertion (no cursor/pagination); replaced with `limit`/refresh/empty-list assertions.
- §7: replaced the `409` conflict case with a re-claim **idempotency** test + generic mapper unit test.
- §8: cited CSRF + 401-refresh as Verified; corrected the CSRF-presence regression to the two real calls (GET queue, POST claim).

### Open assumptions

- **AvailabilitySerial gating (AC-7, §1/§5/§6 FR-3):** no backend/FE contract for a helpdesk availability toggle; if AND-379 ships one it is presumed presence/client-side. Tests for it are conditional and must be re-pointed once AND-379 lands. *Why unverifiable:* not in OAPI or FE.
- **Metrics dashboard (AND-377, FR-1/FR-2, §6 Room caching):** no `/metrics` endpoint; depends entirely on whether AND-377 ships a client-side count-derivation fallback (R2). *Why unverifiable:* not in OAPI or FE.
- **Assign/transfer optimistic-update + conflict (AND-378):** no endpoints exist; only **claim** does, and it is idempotent. *Why unverifiable:* not in OAPI or FE.
- **Analytics events (Q1, §10):** cannot confirm AND-377/378/380 emit any events. *Why unverifiable:* upstream production source not present in this reference set.
- **Exact `Me.roles` agent taxonomy (Q2):** not derivable from helpdesk OAPI/FE; FE infers agent-ness purely from a non-403 queue response. *Why unverifiable:* no role schema referenced by helpdesk.

## 17. Test Plan

Test targets: **JVM** = JVM unit / Robolectric (local, no device); **emu35** = headless AVD `test35` (x86_64, API 35) for fast Compose/instrumented CI; **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) for hardware-dependent behaviour. This ticket is almost entirely faked-transport + Compose, so the default target is JVM/emu35; A15 is only required where ABI/API-34-vs-35 behaviour is in question (TC-13). No case contacts a real host.

- **TC-AND-381-01 — Queue happy path maps flat array.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: `MockWebServer` up; valid `ui_csrf` cookie. Steps: enqueue `200` with a 3-element `ConversationOut[]` fixture; call `repo.getQueue(groupId, state=null)`. Expected: `ApiResult.Success` with 3 items, `conversation_id`/`routing_state`/`active_agent_user_id` mapped; request line is `GET /messaging/helpdesk/queue?group_id=...&limit=50` (no `page`); `X-CSRF-Token` header present. Traces: AC-1, AC-12.
- **TC-AND-381-02 — Queue respects `limit` and omits unset `state`.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: server up. Steps: call queue with `limit=200`, no `state`; inspect recorded request. Expected: query has `limit=200`, **no `state` param**, `group_id` present; `limit>200` is clamped/rejected per repo. Traces: AC-1.
- **TC-AND-381-03 — Non-agent queue 403 is silent / empty.** Type: contract/MockWebServer + ViewModel (JVM). Target: JVM. Preconditions: server up. Steps: enqueue `403 {"detail":{"code":"forbidden","message":"Not an agent"}}`; call queue via VM. Expected: repo returns non-retryable `ApiResult.Error` (httpStatus 403); VM emits `AccessDenied` (or empty/non-error per spec) with **no error toast/banner** (mirrors `silent403`); no further requests. Traces: AC-2, AC-8.
- **TC-AND-381-04 — Claim happy path returns `HelpdeskClaimOut`.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: server up; agent role. Steps: enqueue `200 {"ok":true,"conversation_id":"cnv_1","state":"assigned","assigned_agent_user_id":"usr_self","assignment_version":3,"idempotent":false}`; call `repo.claim("cnv_1")`. Expected: `ApiResult.Success`; fields `ok/state/assigned_agent_user_id/assignment_version/idempotent` mapped; request is `POST .../cnv_1/claim` with body `{}` and `X-CSRF-Token` set; **no** `assignee_id/queue_id/updated_at` expected. Traces: AC-6 (claim portion), AC-12.
- **TC-AND-381-05 — Claim idempotency (re-claim).** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: server up. Steps: enqueue a second claim `200` with `idempotent:true` and unchanged `state`/`assigned_agent_user_id`; call claim twice. Expected: second result `idempotent==true`, `assignment_version` non-decreasing, `state` stable; **no 409 handling path exercised**. Traces: AC-6.
- **TC-AND-381-06 — Claim validation error (422) maps the `[{msg}]` detail shape.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: server up. Steps: enqueue `422 {"detail":[{"msg":"field required","loc":["body","conversation_id"]}]}`; call claim. Expected: `ApiResult.Error` with message "field required", `retryable=false`, httpStatus 422. Traces: AC-3.
- **TC-AND-381-07 — `DetailErrorMapper` covers all three detail shapes.** Type: unit (JVM). Target: JVM. Preconditions: none. Steps: feed mapper a `string`, an array `[{msg}]`, and an object `{code,message}` (incl. a `{code:"forbidden"}` 403). Expected: string→verbatim; array→joined `.msg`; object→`message`/mapped code; `retryable` = `5xx`/timeout true, `403`/`422` false. (Object-with-`409` is exercised here as a generic mapper case only, NOT as a claim contract.) Traces: AC-3.
- **TC-AND-381-08 — 401 → single refresh → retry succeeds.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: authenticated session; `ui_csrf` cookie. Steps: enqueue `401`, then `200` for `POST /ui/session/refresh`, then `200` for the retried GET queue. Expected: exactly one refresh; original call succeeds; assert request order via `server.takeRequest()`. Traces: AC-4.
- **TC-AND-381-09 — Double-401 → terminal auth error, no loop.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: authenticated. Steps: enqueue `401`, refresh `200`, retry `401`. Expected: terminal auth error surfaced, session logout("session_expired") triggered, exactly one refresh attempt, no infinite retry. Traces: AC-4.
- **TC-AND-381-10 — Timeout on GET queue → retryable error; transient 503→200 retried; claim POST NOT retried.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: harness read/connect timeout shortened (~2s) via `SocketPolicy.NO_RESPONSE`. Steps: (a) NO_RESPONSE on GET → timeout-classified `ApiResult.Error(retryable=true)` within bound; (b) `503` then `200` on GET → success, `requestCount ≤ maxRetries+1`; (c) `500` on `POST claim` → single attempt, `requestCount==1`, no retry. Traces: AC-5.
- **TC-AND-381-11 — VM state sequence: Loading → Content / Empty / Error(retryable).** Type: ViewModel unit + Turbine (JVM). Target: JVM. Preconditions: fakes. Steps: with agent role, script success (non-empty queue), empty list, and a retryable failure; collect `uiState`. Expected: initial `Loading`; then `Content` (queue rendered), `Empty` (no items, no cache), `Error(retryable=true)` respectively; `refresh()` toggles `isRefreshing` and re-invokes the fetch (`server.requestCount`/fake call-count increments). Traces: AC-1, AC-2, AC-9 (refresh portion).
- **TC-AND-381-12 — Compose: queue render + row/empty/error/retry + a11y.** Type: Compose-UI / instrumented. Target: emu35. Preconditions: stateless `HelpdeskDashboardContent`/queue composable with hoisted state. Steps: render `Content` with 2 rows, then `Empty`, then `Error`; tap a queue row and "View full queue"; tap retry in `Error`. Expected: correct nodes per state; row tap and "view full queue" emit their callbacks; retry re-invokes `onRetry`; **a11y:** primary actions selectable via `onNodeWithText`/content-description (not only tags), interactive nodes have non-empty descriptions and ≥48dp targets; error banner shows mapped `detail` text from `R.string` (not a literal). Traces: AC-2, AC-9 (callbacks), AC-11.
- **TC-AND-381-13 — ABI/API parity for the helpdesk suite on real hardware.** Type: instrumented/e2e. **Target: A15 (physical, MUST).** Preconditions: app installed on SM-A156U via adb; fake repository bindings via `@TestInstallIn`. Steps: run the Hilt-backed helpdesk Compose flow (queue render + claim) on arm64/API 34 and compare to the emu35 (x86_64/API 35) run. Expected: identical pass/results; no Moshi-codegen/Compose behaviour divergence across ABI or API level. *Why physical:* this is the only case where arm64-vs-x86 / API-34-vs-35 differences could surface; the rest are deterministic on emu35/JVM. Traces: AC-2, AC-12.
- **TC-AND-381-14 — CSRF present on both real helpdesk calls; no PII/cookie logging.** Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: `ui_csrf` cookie seeded in the cookie jar. Steps: perform GET queue and POST claim; inspect recorded headers; capture test log output. Expected: `X-CSRF-Token` present on both; cookie/CSRF values and full response bodies are **not** emitted to test logs; fixtures contain only synthetic data. Traces: AC-12.
- **TC-AND-381-15 — (CONDITIONAL) availability-gates-claim, only if AND-379 ships a gate.** Type: ViewModel unit + Compose-UI. Target: JVM + emu35. Preconditions: AND-379 merged with a real availability/presence gate; fakes expose `available`. Steps: with `available=false`, assert `canClaim=false`, claim control disabled, and `claim()` issues **no** request; flip `available=true` and assert claim proceeds. Expected: gate behaves per the implemented contract. **If AND-379 does not ship a gate, mark this case N/A and document in the PR** (see §16 open assumptions). Traces: AC-7.

### Coverage matrix

| AC | Covered by |
|----|-----------|
| AC-1 | TC-01, TC-02, TC-11 |
| AC-2 | TC-03, TC-11, TC-12, TC-13 |
| AC-3 | TC-06, TC-07 |
| AC-4 | TC-08, TC-09 |
| AC-5 | TC-10 |
| AC-6 | TC-04, TC-05 (claim/idempotency; assign/transfer/409 rollback removed — no contract, see §16) |
| AC-7 | TC-15 (conditional on AND-379) |
| AC-8 | TC-03 (non-agent → AccessDenied; metrics-cache-clear is conditional on AND-377 metrics existing) |
| AC-9 | TC-11 (refresh re-fetch + isRefreshing; second-page append removed — queue is not paged, see §16) |
| AC-10 | JaCoCo Gradle gate (build config; no single TC — enforced over VMs+repos+mappers per §11) |
| AC-11 | TC-12, plus shared `HelpdeskFixtures` consumed by TC-01/04 |
| AC-12 | TC-01, TC-04, TC-13, TC-14 |
