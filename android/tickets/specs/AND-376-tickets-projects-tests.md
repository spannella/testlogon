---
id: AND-376
title: Tickets/projects tests
milestone: M8
epic: E48
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  - AND-374 — Projects: `projects.ts`-equivalent list/detail service under `/v1/projects*` incl. Google Drive provider OAuth start/callback (`POST /v1/projects/providers/google_drive/oauth/{start,callback}`).
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
        // Cursor pagination — no page/page_size; response is TicketListEnvelope {items, next_cursor}.
        server.enqueue(jsonResponse(TicketFixtures.LIST_PAGE_JSON))
        val result = repo.getTickets(cursor = null, limit = 20)
        assertThat(result).isInstanceOf(ApiResult.Success::class.java)
        val tickets = (result as ApiResult.Success).data.items
        assertThat(tickets).hasSize(3)
        assertThat(tickets[0].ticketId).isEqualTo("tkt_001") // maps from JSON "ticket_id"
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

This ticket defines **no new API**; it asserts the contracts owned by AND-371 (tickets) and AND-374 (projects). The canonical payload shapes below were **re-verified during review** against the backend OpenAPI spec (`reference/openapi.index.txt`, `reference/openapi.pretty.json`) and the web reference (`src/api/endpoints/tickets.ts`, `src/api/endpoints/projects.ts`, `src/api/client.ts`). **Several shapes in the original draft were wrong and have been corrected** — see §16 for the audit.

> CORRECTION NOTE: the original draft used `GET /tickets?page=&page_size=` with a `{page,page_size,total,has_more}` page object and ticket fields `id/priority/requester` and ISO-string timestamps. None of that matches the backend. Tickets use **cursor pagination**, the id field is `ticket_id`, there is no `priority` or `requester`, and timestamps are **epoch numbers**. Projects live under `/v1/...`, not `/projects`.

**`GET /tickets`** (`op=list_tickets_tickets_get`) — query params `status, source, workspace_id, assignee_admin_sub, owner_sub, cursor, limit, …` (NO `page`/`page_size`). Response `TicketListEnvelope`:
```json
{
  "items": [
    {"ticket_id": "tkt_001", "subject": "Cannot log in", "owner_sub": "usr_9",
     "status": "open", "assigned_admin_sub": null, "assigned_to_sub": null,
     "space_id": null, "version": 1,
     "created_at": 1748606400, "updated_at": 1748678100,
     "messages": [], "activity": []}
  ],
  "next_cursor": null
}
```
`status` enum = `open | in_progress | waiting_on_user | done` (writable also allows `reopened`). Timestamps are **Unix epoch integers** (`number`), not ISO-8601 strings. There is no `priority` field and no `requester` object.

**`GET /tickets/{ticket_id}`** (`op=get_ticket_tickets__ticket_id__get`) → `TicketEnvelope`, a **wrapper object** `{ "ticket": Ticket }` (the ticket is NOT at the top level). The `Ticket` carries `messages: TicketMessage[]` and `activity: TicketActivity[]` inline — there is **no `members` array and no `space` object on the ticket**:
```json
{"ticket": {
  "ticket_id": "tkt_001", "subject": "Cannot log in", "owner_sub": "usr_9",
  "status": "open", "version": 2, "space_id": "spc_1",
  "created_at": 1748606400, "updated_at": 1748678100,
  "messages": [{"message_id": "msg_1", "sender_sub": "usr_9", "sender_role": "user",
                "body": "Help", "created_at": 1748606400, "email_alert_queued_for": []}],
  "activity": [{"type": "status_change", "actor_sub": "adm_1", "status": "open", "created_at": 1748606500}]
}}
```
Message fields are `message_id` (not `id`), `sender_sub`/`sender_role` (not `author_id`), `body`, `created_at` (epoch number), `email_alert_queued_for[]`.

**Spaces are a separate resource.** Members/space metadata live on `/ticket-spaces*` endpoints, NOT on the ticket. `GET /ticket-spaces/{space_id}` → `TicketSpaceEnvelope = {space: TicketSpace}` where `TicketSpace` has `space_id, owner_sub, name, visibility ("private"|"shared"), created_at, updated_at, members: TicketSpaceMember[]`; member = `{space_id, member_sub, role ("owner"|"editor"|"viewer"), created_at, updated_at}`. If the ticket-detail screen renders members, the ViewModel/repository must compose a ticket call with a space call; this combination is an **assumption** about AND-375 (see §16 Open assumptions).

**`GET /v1/projects`** (`op=list_projects_route_v1_projects_get`) — params `limit, cursor, tag, name_query`. Response `ProjectListOut`:
```json
{"items": [{"id": "prj_1", "owner": "usr_9", "name": "Demo", "description": null,
            "tags": [], "settings": {}, "created_at": "2026-05-30T12:00:00Z",
            "updated_at": "2026-06-01T09:15:00Z"}],
 "cursor": null}
```
Note the list cursor field is `cursor` (NOT `next_cursor`), and project timestamps **are ISO-8601 strings** (unlike tickets). `ProjectOut` has no `priority`.

**`GET /v1/projects/{project_id}`** → `ProjectOut` (bare, no envelope). **`GET /v1/projects/{project_id}/detail`** → `ProjectDetailOut = {project: ProjectOut, files: TrackedFileOut[], cursor?}`.

**Google Drive provider linkage** is NOT a `provider`/`provider_status` pair on `ProjectOut` (those fields do not exist). It is exercised via: `POST /v1/projects/providers/google_drive/oauth/start` → `ProviderOAuthStartOut`, `POST /v1/projects/providers/google_drive/oauth/callback` → `ProviderCredentialOut`, and per-resource `provider`/`provider_ref` fields that appear on `ProjectEventOut` and tracked files. Tests must mirror those shapes, not invented project-level provider fields.

**Error shapes.** Two distinct envelopes coexist in the backend:
- **`ErrorEnvelope = {"error": {"code": str, "message": str, "details"?: obj}}`** — declared for tickets/ticket-spaces 400/403/404/409/429/500/502 responses.
- **`HTTPValidationError = {"detail": [{"loc": [...], "msg": str, "type": str}]}`** — FastAPI 422 validation errors (the `[{msg}]` variant).

The web client (`src/api/client.ts: normalizeErrorDetail`) ONLY reads `body.detail` and accepts three forms: a plain **string**, an **array of `{msg}`** objects, or an **object with a `code`** (authorization codes such as `role_required`, `helpdesk_claim_required`, mapped to friendly text; `geo_blocked` handled in the 403 branch). The three `detail` variants tests assert are therefore the *frontend-observed* shapes:
```json
{"detail": "Ticket not found"}
{"detail": [{"msg": "field required", "loc": ["body","subject"], "type": "missing"}]}
{"detail": {"code": "role_required", "message": "Not a member"}}
```
The Android `DetailErrorMapper` must reduce each to a stable `ApiError` (`message`, optional `code`, optional field list). Because the backend ALSO emits the `{error:{code,message}}` envelope for non-422 ticket errors, the mapper (and its tests) should additionally handle the `error` wrapper; whether AND-371/375 normalize this server-side is an **open assumption** (see §16).

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

State assertions cover: cold-start `Loading` (initial value of the `StateFlow`), `Content` after success, `Empty` when `items` is empty, `Error` on failure with `retryable` derived from HTTP class (5xx/timeout retryable, 4xx not), and `refreshing=true` during pull-to-refresh while prior `Content` is retained. Paging (Paging 3) for the tickets list is asserted with `flow.asSnapshot { scrollTo(20) }` to confirm a second page is requested and appended. Note the backend uses **cursor pagination** (`next_cursor` on `TicketListEnvelope`, `cursor` on `ProjectListOut`), so the `PagingSource` keys on the returned cursor, not a numeric page; the snapshot test must enqueue a first page with a non-null `next_cursor` and a second page with `next_cursor: null`, and assert the second request carried the cursor query param. DataStore/Room caching is not in scope for these screens (tickets/projects are network-live per AND-374/375); if a Room cache exists, a stale-then-fresh emission test is included, otherwise this is N/A and noted in the test file.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: OpenAPI index/spec under `reference/`, frontend under `src/` (the parity oracle), or framework docs.

1. **Tickets list endpoint is `GET /tickets` with cursor pagination (`status, source, assignee_admin_sub, owner_sub, cursor, limit`), NOT `?page=&page_size=`.** VERDICT: Corrected. SOURCE: OpenAPI `GET /tickets` (`op=list_tickets_tickets_get`, line 579 of `reference/openapi.index.txt`); `src/api/endpoints/tickets.ts: listTickets`.
2. **Tickets list response is `TicketListEnvelope = {items: Ticket[], next_cursor?: string|null}` — no `page/page_size/total/has_more`.** VERDICT: Corrected. SOURCE: `src/api/endpoints/tickets.ts: TicketListEnvelope`; OpenAPI `resp=200:TicketListEnvelope`.
3. **Ticket id field is `ticket_id` (not `id`); core fields `subject, owner_sub, status, version, space_id?, assigned_admin_sub?, assigned_to_sub?, created_at, updated_at, messages[], activity[]`.** VERDICT: Corrected. SOURCE: `src/api/endpoints/tickets.ts: interface Ticket`.
4. **Ticket has NO `priority` and NO `requester` object.** VERDICT: Corrected (both were invented in the draft). SOURCE: `src/api/endpoints/tickets.ts: interface Ticket` (neither field present).
5. **Ticket timestamps (`created_at`, `updated_at`, message/activity `created_at`) are Unix epoch integers (`number`), not ISO-8601 strings.** VERDICT: Corrected. SOURCE: `src/api/endpoints/tickets.ts` (`created_at: number`).
6. **`TicketStatus` enum = `open | in_progress | waiting_on_user | done`; writable adds `reopened`.** VERDICT: Verified (draft used `open` only as example; values now pinned). SOURCE: `src/api/endpoints/tickets.ts: TicketStatus / TicketStatusWritable`.
7. **`GET /tickets/{ticket_id}` returns `TicketEnvelope = {ticket: Ticket}` (wrapper), not a top-level ticket object.** VERDICT: Corrected. SOURCE: OpenAPI `GET /tickets/{ticket_id}` (`op=get_ticket_tickets__ticket_id__get`, line 587); `src/api/endpoints/tickets.ts: getTicket / TicketEnvelope`.
8. **Ticket detail has NO `members` array and NO `space` object; messages/activity are inline on `Ticket`.** VERDICT: Corrected. SOURCE: `src/api/endpoints/tickets.ts: interface Ticket` (has `messages`, `activity`; no `members`/`space`).
9. **Message fields are `message_id, sender_sub, sender_role, body, created_at(number), email_alert_queued_for[]` — not `id`/`author_id`.** VERDICT: Corrected. SOURCE: `src/api/endpoints/tickets.ts: interface TicketMessage`.
10. **Spaces/members are a separate resource under `/ticket-spaces*`; `GET /ticket-spaces/{space_id}` → `TicketSpaceEnvelope = {space: TicketSpace}` with `members: TicketSpaceMember[]`, member role `owner|editor|viewer`.** VERDICT: Verified. SOURCE: OpenAPI `GET /ticket-spaces/{space_id}` (line 570); `src/api/endpoints/tickets.ts: TicketSpace / TicketSpaceMember`.
11. **Projects live under `/v1/projects`, NOT `/projects`.** VERDICT: Corrected. SOURCE: OpenAPI `GET /v1/projects` (`op=list_projects_route_v1_projects_get`, line 2398); `src/api/endpoints/projects.ts: listProjects`.
12. **`ProjectListOut = {items: ProjectOut[], cursor?: string|null}` (list cursor field is `cursor`, not `next_cursor`).** VERDICT: Corrected. SOURCE: `components.schemas.ProjectListOut` (`reference/openapi.pretty.json` line 59083).
13. **`ProjectOut` fields: `id, owner, name, description?, tags[], settings{}, created_at(string), updated_at(string)`; project timestamps ARE ISO-8601 strings.** VERDICT: Verified/Corrected. SOURCE: `components.schemas.ProjectOut` (line 59107, required `id,owner,name,created_at,updated_at`).
14. **`GET /v1/projects/{project_id}` → bare `ProjectOut`; `GET /v1/projects/{project_id}/detail` → `ProjectDetailOut = {project, files[], cursor?}`.** VERDICT: Verified. SOURCE: OpenAPI lines 2406/2408; `components.schemas.ProjectDetailOut` (line 58947); `src/api/endpoints/projects.ts: getProject / getProjectDetail`.
15. **Google Drive linkage is NOT `provider`/`provider_status` fields on the project; it is the OAuth start/callback endpoints plus `provider`/`provider_ref` on events/tracked files.** VERDICT: Corrected. SOURCE: OpenAPI `POST /v1/projects/providers/google_drive/oauth/start` (line 2401) and `/callback` (line 2400); `components.schemas.ProjectEventOut` (`provider`, `provider_ref`, line 59001); `ProjectOut` has neither field.
16. **FastAPI 422 validation error = `HTTPValidationError = {detail: ValidationError[]}`, `ValidationError = {loc, msg, type}` — the `[{msg}]` variant.** VERDICT: Verified. SOURCE: `components.schemas.HTTPValidationError` (line 37133) and `ValidationError` (line 80337).
17. **Backend ALSO emits `ErrorEnvelope = {error: {code, message, details?}}` for non-422 ticket errors (400/403/404/409/429/500/502).** VERDICT: Verified (and a discrepancy the draft missed). SOURCE: OpenAPI `resp=...;403:ErrorEnvelope;404:ErrorEnvelope...` on `/tickets*` (lines 579–595); `components.schemas.ErrorEnvelope` (line 31777) and `ErrorDetail` (line 31747).
18. **Web client normalizes only `body.detail` into three forms: string, array-of-`{msg}`, or object-with-`code` (e.g. `role_required`, `helpdesk_claim_required`); `geo_blocked` handled in the 403 branch.** VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` and `mapAuthorizationError`.
19. **CSRF: `ui_csrf` cookie value is echoed in the `X-CSRF-Token` request header.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
20. **401 handling: a single refresh via `POST /ui/session/refresh` (credentials included), then retry the original request once; a retry that again returns 401 triggers logout (no loop). A 401 while unauthenticated propagates without refresh.** VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` and the 401 branch of `api()`.
21. **Auth also sends `Authorization: Bearer <accessToken>` from the auth store (in addition to the cookie/CSRF).** VERDICT: Verified (not previously noted in the spec). SOURCE: `src/api/client.ts` (`headers.set("Authorization", \`Bearer ${accessToken}\`)`).
22. **Network/offline error in the web client surfaces as `ApiError(0, "Network error")` (fetch throw), distinct from HTTP errors.** VERDICT: Verified — relevant to the offline test path. SOURCE: `src/api/client.ts` catch block around `fetch`.
23. **Non-idempotent mutations (e.g. `POST /tickets/{ticket_id}/messages`, `/status`, `/assign`) exist and are POSTs; tests asserting "no retry on POST failure" target these.** VERDICT: Verified. SOURCE: OpenAPI lines 588/593/594; `src/api/endpoints/tickets.ts: addTicketMessage / setTicketStatus / assignTicket`.
24. **Test stack choices (MockWebServer, Turbine, Paging3 `asSnapshot`/`AsyncPagingDataDiffer`, Compose UI Test, Hilt testing, Robolectric, JaCoCo) and `SocketPolicy.NO_RESPONSE` for timeouts.** VERDICT: Unverified-assumption (tooling/versions; framework refs). SOURCE: framework ref — OkHttp MockWebServer docs, `cashapp/turbine`, Android `androidx.paging.testing`, `androidx.compose.ui.test`, `dagger.hilt.android.testing`; no project source confirms exact versions.

### Corrections made
- §5 tickets list: replaced `GET /tickets?page=&page_size=` + `{page,page_size,total,has_more}` with `GET /tickets` cursor pagination + `TicketListEnvelope {items, next_cursor}` (claims 1–2).
- §5 ticket fields: `id`→`ticket_id`; removed invented `priority` and `requester`; timestamps changed from ISO strings to epoch numbers; pinned the status enum (claims 3–6).
- §5 ticket detail: now `{ticket: Ticket}` envelope; removed `members`/`space` from the ticket and documented spaces as a separate `/ticket-spaces` resource; corrected message field names (claims 7–10).
- §5 projects: paths corrected to `/v1/projects*`; list cursor field `next_cursor`→`cursor`; documented real `ProjectOut`/`ProjectDetailOut` shapes; removed invented `provider`/`provider_status` project fields and pointed Drive linkage at the OAuth start/callback endpoints (claims 11–15).
- §5 errors: documented both the `ErrorEnvelope {error:{code,message}}` (non-422) and `HTTPValidationError {detail:[{loc,msg,type}]}` (422) envelopes, and clarified the three `detail` variants are the frontend-observed shapes (claims 16–18).
- §4.1 example: `getTickets(page=1)`→`getTickets(cursor, limit)` and `tickets[0].id`→`tickets[0].ticketId`.
- §2: annotated AND-374 with the real `/v1/projects` paths.
- §6: clarified paging keys on the returned cursor, not a numeric page.

### Open assumptions
- **AND-375 UiState/ViewModel names** (`TicketsUiState`, `TicketsViewModel`, `TicketDetailViewModel`, `ProjectsViewModel`, `ProjectDetailViewModel`) and the `ApiResult<T>` / `DetailErrorMapper` types: assumed from the draft; not present in the reviewed sources (those are upstream Android tickets, not in `reference/`). Confirm against AND-371/374/375 before coding.
- **Ticket-detail "members" rendering:** the backend ticket has no members; if the detail screen shows members it must compose a `/ticket-spaces/{space_id}` call. Whether AND-375 does this (and exposes a combined UiState) is unverifiable here.
- **Whether AND-371/375 normalize the `{error:{code,message}}` envelope server-/repo-side** so the Android mapper only sees a `detail`-style body: unverifiable from `reference/`; the mapper tests cover both shapes defensively.
- **Q1 (analytics events) and Q2 (Room cache):** unresolved in the spec and not determinable from `reference/`; §10/§6 tests remain conditional.
- **Test tooling versions** (Kotlin/AGP/Turbine/Paging/etc.): framework assumptions, not verifiable against any project file in scope.

## 17. Test Plan

Test targets: **JVM** = local JVM unit/Robolectric (no device); **emu35** = headless AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Traces link to §14 acceptance criteria.

- **TC-AND-376-01 — Tickets list happy path (contract/MockWebServer).** Target: JVM. Preconditions: `MockWebServer` started; `TicketFixtures.LIST_PAGE_JSON` mirrors the corrected `TicketListEnvelope` (epoch timestamps, `ticket_id`). Steps: enqueue 200 with a 3-item page; call `repo.getTickets(cursor=null, limit=20)`. Expected: `ApiResult.Success`; `data.items` size 3; `items[0].ticketId == "tkt_001"`; status parses to `open`; request had `X-CSRF-Token` header. Traces: AC-1, AC-9.
- **TC-AND-376-02 — Ticket-detail envelope mapping (unit/contract).** Target: JVM. Preconditions: fixture for `TicketEnvelope = {ticket:{…messages[],activity[]}}`. Steps: enqueue 200; call `repo.getTicket("tkt_001")`. Expected: ticket unwrapped from `ticket` key; `messages[0].messageId == "msg_1"`, `senderSub`/`senderRole` populated, `createdAt` is a numeric epoch; no `members` expected on the ticket. Traces: AC-1.
- **TC-AND-376-03 — Projects list happy path (contract/MockWebServer).** Target: JVM. Preconditions: fixture mirrors `ProjectListOut {items, cursor}` with ISO-string timestamps. Steps: enqueue 200; call `repo.listProjects(limit=20)` against base path `/v1/projects`. Expected: `Success`; items mapped; pagination key read from `cursor` (not `next_cursor`); recorded request path is `/v1/projects`. Traces: AC-1, AC-9.
- **TC-AND-376-04 — All three `detail` error variants map to stable `ApiError` (unit).** Target: JVM. Preconditions: `DetailErrorMapper`. Steps: feed (a) `{"detail":"Ticket not found"}`, (b) `{"detail":[{"msg":"field required","loc":["body","subject"],"type":"missing"}]}`, (c) `{"detail":{"code":"role_required","message":"Not a member"}}`. Expected: (a) message = the string; (b) message contains "field required" + field path; (c) message mapped from code with `code=role_required`. Traces: AC-3.
- **TC-AND-376-05 — `ErrorEnvelope` (`{error:{code,message}}`) also maps (unit).** Target: JVM. Preconditions: mapper handles the non-422 backend envelope. Steps: feed `{"error":{"code":"forbidden","message":"Not a member","details":null}}` (a real ticket 403 shape). Expected: `ApiError(message="Not a member", code="forbidden")`; no crash/unmapped fallback. Traces: AC-3.
- **TC-AND-376-06 — 404 / 422 / 403 status classification (contract/MockWebServer).** Target: JVM. Steps: enqueue 404 `{"detail":"..."}`, then 422 `HTTPValidationError`, then 403 `ErrorEnvelope`; call the repo each time. Expected: each returns `ApiResult.Error` with mapped message and `retryable=false` (4xx not retryable). Traces: AC-2, AC-3, AC-5.
- **TC-AND-376-07 — Timeout path (contract/MockWebServer).** Target: JVM. Preconditions: harness read/connect timeout shortened; `SocketPolicy.NO_RESPONSE`. Steps: enqueue NO_RESPONSE; call the repo under `runTest`/virtual time. Expected: `ApiResult.Error` classified as timeout within bound; ViewModel surfaces `Error(retryable=true)`. Traces: AC-5.
- **TC-AND-376-08 — Transient 503→200 idempotent GET retry (contract/MockWebServer).** Target: JVM. Steps: enqueue 503 then 200; call `getTickets`. Expected: success; `server.requestCount == 2` (one bounded retry). Then assert a `POST /tickets/{id}/messages` that fails is NOT retried (`requestCount == 1`). Traces: AC-5.
- **TC-AND-376-09 — 401→refresh→retry once; double-401 terminal (contract/MockWebServer).** Target: JVM. Preconditions: cookie jar + CSRF echo wired in `NetworkTestHarness`; user marked authenticated. Steps (success): enqueue 401, then 200 for `POST /ui/session/refresh`, then 200 for the retried GET; assert exactly one refresh and original call succeeds. Steps (terminal): enqueue 401, refresh 200, then 401 again; assert a terminal auth error and no further refresh/loop. Traces: AC-4.
- **TC-AND-376-10 — Malformed JSON is a mapped parse error, not a crash (unit/contract).** Target: JVM. Steps: enqueue 200 with truncated/invalid JSON. Expected: `ApiResult.Error` (parse-classified); no uncaught exception. Traces: AC-1.
- **TC-AND-376-11 — ViewModel emits Loading→Content / Loading→Empty / Loading→Error via Turbine (unit).** Target: JVM. Preconditions: `MainDispatcherRule` + `FakeTicketsRepository`. Steps: script Success(3 items) → assert `Loading` then `Content(size=3)`; script Success(empty) → `Empty`; script Error(4xx) → `Error(retryable=false)`; invoke retry → re-load. Expected: exact state sequences; `refreshing=true` retains prior `Content` during pull-to-refresh. Traces: AC-1, AC-2.
- **TC-AND-376-12 — Paging second-page append via cursor (unit, Paging 3).** Target: JVM. Preconditions: deterministic `PagingConfig` (no placeholders, fixed pageSize). Steps: enqueue page 1 with non-null `next_cursor`, page 2 with `next_cursor:null`; `pagingData.asSnapshot { scrollTo(20) }`. Expected: 2nd request carries the cursor query param; snapshot contains both pages appended in order. Traces: AC-6.
- **TC-AND-376-13 — Tickets list Compose: render-per-state + row click nav callback + a11y (Compose-UI).** Target: emu35 (CI), also runnable on A15. Steps: set `TicketsListScreen` with `Content`, `Empty`, `Error`; click `ticketRow_tkt_001`; assert error banner shows mapped `detail` text; assert each ticket row exposes subject+status as one merged, readable semantics node and the retry control has non-empty text/content-description (selected via `onNodeWithText`). Expected: correct nodes per state; click emits `onTicketClick("tkt_001")`; retry re-invokes load; a11y selectors resolve. Traces: AC-2.
- **TC-AND-376-14 — Project detail Compose + Hilt fake-repo flow, incl. Drive-provider rows (Compose-UI/instrumented).** Target: emu35. Preconditions: `@TestInstallIn` fake `RepositoryModule`; fixtures for `ProjectDetailOut` with tracked files carrying `provider="google_drive"`/`provider_ref`. Steps: launch `ProjectDetailScreen`; assert project header + file rows render; tap a file row → nav callback; force an error state → mapped banner. Expected: correct rendering and callbacks; provider fields read from files/events, not from project-level fields. Traces: AC-2, AC-8.
- **TC-AND-376-15 — Offline/flaky-host behavior on real hardware (instrumented/e2e).** Target: **A15 (must run on physical device)** — exercises the real OkHttp stack against `MockWebServer` over loopback while toggling device connectivity, and validates arm64/API-34 behavior distinct from the x86_64/API-35 emulator. Steps: with the repo pointed at a local `MockWebServer`, simulate a connection drop (server `shutdown()` mid-flight) and assert a network-classified `ApiResult.Error` (mirrors the web client's `ApiError(0,"Network error")`) with no crash; restore and assert recovery on retry. Note: no test contacts `18.222.237.167`. Expected: graceful offline error then recovery. Traces: AC-5, AC-9.
- **TC-AND-376-16 — CI gate & coverage (manual/integration).** Target: JVM + emu35. Steps: run `:feature-tickets:testDebugUnitTest` and the managed/connected `:feature-tickets` androidTest; run the JaCoCo gate. Expected: both suites green; line ≥80% / branch ≥70% over VMs+repos+mappers, build fails below threshold; shared fixtures resolved from `core-testing` with no duplicated JSON literals. Traces: AC-1, AC-2, AC-7, AC-8.

### Coverage matrix
- AC-1 (unit suites green): TC-01, TC-02, TC-03, TC-10, TC-11, TC-16
- AC-2 (instrumented render/click/retry/error): TC-06, TC-11, TC-13, TC-14, TC-16
- AC-3 (three `detail` variants + ErrorEnvelope): TC-04, TC-05, TC-06
- AC-4 (401 refresh once / double-401 terminal): TC-09
- AC-5 (timeout, 5xx-then-success, no POST retry): TC-06, TC-07, TC-08, TC-15
- AC-6 (paging second-page append): TC-12
- AC-7 (JaCoCo coverage gate): TC-16
- AC-8 (shared fixtures consumed, no dup literals): TC-14, TC-16
- AC-9 (no real network host): TC-01, TC-03, TC-15, TC-16
