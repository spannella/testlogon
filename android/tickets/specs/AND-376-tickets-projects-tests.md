---
id: AND-376
title: Tickets/projects tests
milestone: M8
epic: E48
priority: P2
size: M
status: draft
depends_on: [AND-375, AND-374, AND-371]
blocks: [AND-377]
---

# AND-376 — Tickets/projects tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the Tickets and Projects feature area of the TestLogon native Android app (`com.testlogon.android`). It is a pure **Test** ticket (P2): it adds no production behaviour and ships repository-level (JVM) tests plus Compose UI tests that exercise code produced by upstream tickets — the Tickets API/DTOs (AND-371), the Projects API (AND-374), and the Tickets/Projects ViewModels (AND-375). The single backlog acceptance criterion is **"Pass."**, which this spec operationalises into concrete, measurable test obligations.

The goal is to lock down the behaviour of the `feature-tickets` module (and the projects surface that lives alongside it) so that subsequent work — notably the helpdesk agent dashboard (AND-377) that consumes the same repositories and ticket-space DTOs — builds on a verified foundation. Concretely, the suite must prove that: (a) ticket and project DTOs map correctly from FastAPI JSON into `core-model` domain types; (b) repositories translate transport outcomes into the typed `ApiResult<T>` envelope including the FastAPI `detail` error shapes; (c) ViewModels emit the correct `StateFlow<UiState>` transitions for loading/content/error/empty and for paging; and (d) the Compose list and detail screens render each `UiState` and route correctly on interaction.

Out of scope: writing or modifying production source for tickets/projects (owned by AND-371/374/375), backend changes, end-to-end tests against the live dev backend, and screenshot/visual-regression tooling. Network is always faked at the OkHttp boundary (`MockWebServer`); no test in this ticket touches `http://18.222.237.167:8000`.

## 2. Context & References

- **Module layering:** `app -> feature-tickets -> core-* (core-network, core-model, core-data, core-ui, core-testing)`. Test code added here lives in `feature-tickets/src/test` (JVM unit) and `feature-tickets/src/androidTest` (instrumented Compose), with shared fixtures contributed to `core-testing`.
- **Upstream under test:**
  - AND-371 — Tickets API: `TicketsApi` Retrofit service, ticket/ticket-space/member/message DTOs in `core-model`.
  - AND-374 — Projects: `projects.ts`-equivalent list/detail service incl. Google Drive provider start/callback.
  - AND-375 — Tickets/projects ViewModels: `TicketsViewModel`, `TicketDetailViewModel`, `ProjectsViewModel`, `ProjectDetailViewModel` exposing `StateFlow<UiState>`.
- **Web reference (parity oracle for JSON shapes):** `frontend/src/api/endpoints/tickets.ts`, `frontend/src/api/endpoints/projects.ts`, shared types `frontend/src/api/types.ts`; backend `OpenAPI` at `/openapi.json`.
- **Stack:** Kotlin 2.0.21, JUnit4, kotlinx-coroutines-test 1.8+, Turbine (Flow assertions), MockWebServer (OkHttp 4.12), Moshi 1.15 (codegen), Truth/AssertJ assertions, Compose UI Test (`createAndroidComposeRule`), Hilt testing (`HiltAndroidRule`, `@HiltAndroidTest`), Robolectric for JVM-side Android shims where needed, Paging 3 `AsyncPagingDataDiffer`/`asSnapshot`. AGP 8.7.3, JDK 17, minSdk 24 / target 35.
- **Conventions:** typed `ApiResult<T>`; FastAPI `detail` mapping (`string | [{msg}] | {code,...}`); ViewModels expose `StateFlow<UiState>`.

## 3. Functional Requirements

FR-1. **Repository/DTO tests (JVM)** for tickets and projects covering: success mapping, empty collections, malformed/partial JSON, HTTP 4xx/5xx with each `detail` variant, 401 refresh-then-retry, and 20s timeout handling.

FR-2. **ViewModel tests (JVM)** for all four ViewModels asserting exact `UiState` sequences via Turbine, including initial Loading, Content, Empty, Error, retry, and pull-to-refresh transitions. Paging streams asserted with `asSnapshot {}`.

FR-3. **Compose UI tests (instrumented)** for the tickets list, ticket detail (with members/messages), projects list, and project detail screens: each `UiState` renders the correct nodes; tapping a row emits the correct navigation callback; retry button re-invokes the load action; error banner shows mapped `detail` text.

FR-4. **Shared fixtures** (`core-testing`) provide canonical JSON sample payloads and domain-object builders so tests do not duplicate literals, and so AND-377 can reuse them.

FR-5. **CI gate:** `:feature-tickets:testDebugUnitTest` and `:feature-tickets:connectedDebugAndroidTest` (or the managed-device equivalent) both pass; coverage thresholds (Section 11) are met or the build fails.

## 4. Technical Design

### 4.1 JVM unit tests (`src/test`)

Repository tests use `MockWebServer` wired to a real Retrofit/Moshi/OkHttp stack so JSON deserialization, the CSRF header interceptor, the 401 refresh interceptor, and the cookie jar are all exercised together (integration-style at the repo boundary, no production code mocked).

```kotlin
class TicketsRepositoryTest {
    private val server = MockWebServer()
    private lateinit var repo: TicketsRepository

    @Before fun setUp() {
        server.start()
        val api = NetworkTestHarness(server.url("/")).create(TicketsApi::class.java)
        repo = DefaultTicketsRepository(api, errorMapper = DetailErrorMapper())
    }
    @After fun tearDown() = server.shutdown()

    @Test fun `list maps page of tickets`() = runTest {
        server.enqueue(jsonResponse(TicketFixtures.LIST_PAGE_JSON))
        val result = repo.getTickets(page = 1)
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
        val tickets = (result as ApiResult.Success).data.items
        assertThat(tickets).hasSize(3)
        assertThat(tickets[0].id).isEqualTo("tkt_001")
        assertThat(server.takeRequest().getHeader("X-CSRF-Token")).isNotEmpty()
    }
}
```

`NetworkTestHarness` (added to `core-testing`) reuses the production `OkHttpClient`/`Moshi` builders from `core-network` with the base URL swapped to the `MockWebServer` URL and timeouts shortened (read/connect = 2s) so timeout assertions run fast via `MockWebServer` `SocketPolicy.NO_RESPONSE` + `VirtualTimeScheduler`.

ViewModel tests run on `StandardTestDispatcher` injected through a `MainDispatcherRule`. Repositories are replaced by hand-written fakes (`FakeTicketsRepository`) implementing the repository interface with scriptable `ApiResult` responses — this isolates state logic from transport.

```kotlin
@get:Rule val mainRule = MainDispatcherRule()

@Test fun `tickets vm emits Loading then Content`() = runTest {
    val fake = FakeTicketsRepository().apply { enqueue(ApiResult.Success(TicketFixtures.page())) }
    val vm = TicketsViewModel(fake, SavedStateHandle())
    vm.uiState.test {
        assertThat(awaitItem()).isEqualTo(TicketsUiState.Loading)
        val content = awaitItem() as TicketsUiState.Content
        assertThat(content.tickets).hasSize(3)
        cancelAndConsumeRemainingEvents()
    }
}
```

### 4.2 Instrumented Compose tests (`src/androidTest`)

Screen-level tests drive the stateless composables directly with hoisted state plus a small set of ViewModel-backed `@HiltAndroidTest` flows using fake repository bindings via `@TestInstallIn` replacing the production `RepositoryModule`. Interaction is via `onNodeWithTag`/`onNodeWithText`; semantics test tags (`testTag("ticketRow_$id")`, `"ticketsRetry"`, `"errorBanner"`) are added to production composables only if missing — and adding such tags is permitted under this ticket as it is non-behavioural instrumentation.

```kotlin
@Test fun ticketsList_rowClick_emitsNavigation() {
    var clicked: String? = null
    composeRule.setContent {
        TestLogonTheme {
            TicketsListScreen(
                state = TicketsUiState.Content(TicketFixtures.uiTickets()),
                onTicketClick = { clicked = it }, onRetry = {})
        }
    }
    composeRule.onNodeWithTag("ticketRow_tkt_001").performClick()
    assertThat(clicked).isEqualTo("tkt_001")
}
```

A managed Gradle device (`com.android.tools.build:gradle` managed device, Pixel 6 / API 34, ATD image) is configured so `connected` tests can run headless in CI.

## 5. API Contract

This ticket defines **no new API**; it asserts the contracts owned by AND-371 (tickets) and AND-374 (projects). The canonical payload shapes that fixtures must mirror (verified against `/openapi.json` and the web reference) are:

**`GET /tickets?page={n}&page_size={m}`** → paged list:
```json
{
  "items": [
    {"id": "tkt_001", "subject": "Cannot log in", "status": "open",
     "priority": "high", "space_id": "spc_1", "created_at": "2026-05-30T12:00:00Z",
     "updated_at": "2026-06-01T09:15:00Z", "requester": {"id": "usr_9", "name": "A. User"}}
  ],
  "page": 1, "page_size": 20, "total": 3, "has_more": false
}
```

**`GET /tickets/{id}`** → ticket detail with `space`, `members[]`, `messages[]`:
```json
{"id": "tkt_001", "subject": "Cannot log in", "status": "open",
 "space": {"id": "spc_1", "name": "Auth issues"},
 "members": [{"id": "usr_9", "name": "A. User", "role": "requester"}],
 "messages": [{"id": "msg_1", "author_id": "usr_9", "body": "Help", "created_at": "2026-05-30T12:00:00Z"}]}
```

**`GET /projects`** / **`GET /projects/{id}`** → project list/detail mirroring `projects.ts`, including the Google Drive provider linkage fields (`provider`, `provider_status`) exercised by the start/callback flow from AND-374.

**Error envelope** (asserted in all three `detail` variants):
```json
{"detail": "Ticket not found"}
{"detail": [{"msg": "field required", "loc": ["body","subject"]}]}
{"detail": {"code": "forbidden", "message": "Not a member"}}
```
The `DetailErrorMapper` must reduce each to a stable `ApiError` (`message`, optional `code`, optional field list); tests assert the human-readable message chosen for each shape.

## 6. Data & State Management

Tests assert the `UiState` models defined in AND-375; this ticket does not introduce new state types. The sealed hierarchies under test (asserted exactly):

```kotlin
sealed interface TicketsUiState {
    data object Loading : TicketsUiState
    data class Content(val tickets: List<TicketUi>, val refreshing: Boolean = false) : TicketsUiState
    data object Empty : TicketsUiState
    data class Error(val message: String, val retryable: Boolean) : TicketsUiState
}
```

State assertions cover: cold-start `Loading` (initial value of the `StateFlow`), `Content` after success, `Empty` when `items` is empty, `Error` on failure with `retryable` derived from HTTP class (5xx/timeout retryable, 4xx not), and `refreshing=true` during pull-to-refresh while prior `Content` is retained. Paging (Paging 3) for the tickets list is asserted with `flow.asSnapshot { scrollTo(20) }` to confirm a second page is requested and appended. DataStore/Room caching is not in scope for these screens (tickets/projects are network-live per AND-374/375); if a Room cache exists, a stale-then-fresh emission test is included, otherwise this is N/A and noted in the test file.

## 7. Error Handling & Resilience

Tests are the resilience contract here. Required cases:

- **Timeout:** `MockWebServer` `NO_RESPONSE` → repo returns `ApiResult.Error` with a timeout-classified error within the configured bound; ViewModel surfaces `Error(retryable=true)`. Idempotent GET retry/backoff (bounded) is asserted by counting `server.requestCount` after a transient 503 then 200.
- **401 refresh:** enqueue `401`, then `200` for `POST /ui/session/refresh`, then `200` for the retried GET; assert exactly one refresh occurs and the original call succeeds; a second consecutive 401 yields a terminal auth error (no infinite loop).
- **Malformed JSON:** assert a mapped parse error, not an uncaught exception/crash.
- **Non-idempotent calls** (e.g., posting a message) are asserted **not** to retry on failure.

## 8. Security & Privacy

No production security surface changes. Test-specific obligations: the `NetworkTestHarness` must reproduce the CSRF header echo (`ui_csrf` cookie → `X-CSRF-Token`) and persistent cookie jar so the 401-refresh test is realistic; a regression test asserts the `X-CSRF-Token` header is present on requests. Fixtures contain only synthetic data — no real credentials, tokens, or PII; the spec mandates no logging of cookie/CSRF values in test output. Cleartext dev-host usage is irrelevant to these tests since all traffic is local-loopback `MockWebServer`.

## 9. Accessibility & i18n

Compose UI tests double as a basic a11y gate: assertions use `onNodeWithText`/content-description selectors (not only test tags) for primary actions (retry, row open), which forces those nodes to carry semantics. A test asserts the ticket-row merged semantics expose subject + status as a single readable node and that interactive elements have a non-empty content description or text. i18n: error strings asserted via string resources (e.g., `R.string.tickets_error_generic`) resolved through `context.getString(...)` rather than hard-coded literals, proving externalised strings. RTL/locale matrix is not exercised at this ticket level (deferred to a dedicated a11y sweep).

## 10. Telemetry & Logging

No production telemetry is added. If AND-375 emits analytics events (e.g., `ticket_opened`), a ViewModel test injects a `FakeAnalytics` and asserts the event + properties fire on the corresponding action; otherwise this is N/A. Test infrastructure logging is limited to JUnit/Compose failure dumps; `MockWebServer` request logs are captured only on failure to aid debugging. No PII is logged.

## 11. Testing Strategy

This ticket *is* the testing strategy. Test inventory and gates:

- **Repository (JVM):** `TicketsRepositoryTest`, `ProjectsRepositoryTest` — success, empty, malformed, 404/422/403 `detail` variants, 503→200 retry, timeout, 401-refresh. ~18 cases.
- **DTO mapping (JVM):** `TicketDtoMappingTest`, `ProjectDtoMappingTest`, `TicketSpaceDtoMappingTest` (members/messages) — golden-JSON round-trip vs builder. ~10 cases.
- **ViewModel (JVM):** four `*ViewModelTest` classes, Turbine state sequences + paging snapshot. ~16 cases.
- **Compose (androidTest):** `TicketsListScreenTest`, `TicketDetailScreenTest`, `ProjectsListScreenTest`, `ProjectDetailScreenTest` — render per state, click→nav callback, retry re-invoke, error-banner text. ~16 cases.
- **Coverage gate (JaCoCo via Gradle):** `feature-tickets` line coverage ≥ 80%, branch ≥ 70% over ViewModels + repositories + mappers (UI composables excluded from the line gate but covered by androidTest). Build fails below threshold.
- **Determinism:** all suspending tests use `runTest` + injected `TestDispatcher`; no `Thread.sleep`, no real network, no flaky timeouts (virtual time only). Compose tests disable animations and use `waitForIdle()`.
- **Execution:** `./gradlew :feature-tickets:testDebugUnitTest :feature-tickets:pixel6Api34DebugAndroidTest` green locally and in CI.

## 12. Dependencies & Sequencing

- **Depends on AND-375** (Tickets/projects ViewModels) — the primary subject under test; must be merged first.
- **Transitively depends on AND-371** (Tickets API/DTOs) and **AND-374** (Projects) — their DTOs/services are exercised by repository and mapping tests.
- **Provides shared fixtures** (`TicketFixtures`, `ProjectFixtures`, `NetworkTestHarness`, `MainDispatcherRule`) in `core-testing`, reused by **AND-377** (Helpdesk agent dashboard), which consumes the same repositories/ticket-space DTOs — so this ticket **blocks** AND-377's own test work in practice and should land before it.
- No backend dependency; runs fully offline.

## 13. Risks & Open Questions

- **R1 — Upstream API drift:** if AND-371/374 final DTO field names differ from the shapes in Section 5, fixtures break. Mitigation: derive fixture JSON from `/openapi.json` and `frontend/src/api/types.ts` at implementation time; treat mapping tests as the source of truth.
- **R2 — Paging assertion flakiness:** `asSnapshot` ordering can be sensitive; mitigate with deterministic `PagingConfig` (no placeholders, fixed `pageSize`).
- **R3 — Managed-device availability in CI:** if the ATD image is unavailable, fall back to Robolectric for a subset of Compose tests (Robolectric Compose support) and gate the rest behind a `connectedCheck` job.
- **Q1:** Does AND-375 expose analytics events? Determines whether Section 10 telemetry tests are required or N/A.
- **Q2:** Is there a Room cache layer for tickets/projects? Determines whether the stale-then-fresh test in Section 6 applies.
- **Q3:** Final test-tag naming convention — confirm with the AND-375 author to avoid touching production composables unnecessarily.

## 14. Acceptance Criteria

AC-1. `:feature-tickets:testDebugUnitTest` passes with all repository, DTO-mapping, and ViewModel suites listed in Section 11 present and green.
AC-2. `:feature-tickets` instrumented suite passes on the configured managed device, covering render-per-`UiState`, row-click navigation callback, retry re-invocation, and mapped error-banner text for both tickets and projects screens.
AC-3. All three FastAPI `detail` variants (string, `[{msg}]`, `{code,...}`) have explicit mapping assertions producing stable `ApiError` messages.
AC-4. 401→refresh→retry is asserted to refresh exactly once and then succeed, and a double-401 produces a terminal auth error with no retry loop.
AC-5. Timeout and transient-5xx-then-success behaviours are asserted, including that non-idempotent calls do not retry.
AC-6. Paging second-page append is asserted via `asSnapshot`.
AC-7. JaCoCo coverage gate (≥80% line / ≥70% branch over VMs+repos+mappers) is enforced and met; the build fails if it regresses.
AC-8. Shared fixtures/harness are contributed to `core-testing` and consumed by at least the tickets and projects suites (no duplicated JSON literals).
AC-9. No test contacts a real network host; all transport is `MockWebServer`.

## 15. Definition of Done

- All Section 14 acceptance criteria verified green in CI on branch `android-port`.
- Test sources reside under `feature-tickets/src/test` and `feature-tickets/src/androidTest`; shared helpers under `core-testing`; package root `com.testlogon.android.feature.tickets.*` / `com.testlogon.android.core.testing.*`.
- Coverage gate wired into the Gradle build and passing.
- No production behaviour changed except additive, non-functional test tags/content descriptions agreed per Q3.
- Code reviewed and merged; AND-377 confirmed able to reuse the shared fixtures.
- This spec's open questions (Q1–Q3) resolved or explicitly deferred with owner noted in the PR description.
