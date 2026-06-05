---
id: AND-156
title: Search/contacts tests
milestone: M3
epic: E21
priority: P2
size: M
status: draft
depends_on: [AND-155, AND-153, AND-152]
blocks: []
---

# AND-156 — Search/contacts tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the message-search and contacts
features implemented in the E21 epic. It is a pure **Test** ticket (Type: Test,
Priority: P2): it adds no production behavior and ships only test code, fixtures,
and CI wiring. The unit of work is to lock down the behavior of the search and
contacts repositories (`MessageSearchRepository`, `ContactsRepository`), their
`PagingSource`/`RemoteMediator` implementations, the debounced query
`ViewModel`s (`MessageSearchViewModel`, `ContactsViewModel` from AND-155), and the
Compose screens (`MessageSearchScreen` from AND-152, `ContactsScreen` from
AND-153) against a regression suite.

The goal is twofold: (1) prove the debounce/paging/empty-state logic from AND-155
behaves as specified under fast typing, cancellation, error, and empty-result
conditions; and (2) prove the two Compose screens render loading, content, empty,
and error states and drive the correct query/navigation callbacks. The single
acceptance bar from the backlog is **"Tests pass"** — i.e., the new modules
(`feature-search`, `feature-contacts`, plus repo tests in `core-data`) have green
JVM unit tests and instrumented/Robolectric UI tests in CI, with meaningful
assertions (not trivially-passing stubs) covering the scenarios enumerated in
§3 and §11.

The scope is explicitly **Repo + UI tests**: repository-level unit tests
(including `PagingSource` paging assertions) and Compose UI tests for the two
screens. ViewModel unit tests are owned primarily by AND-155 ("Unit-tested"); this
ticket extends them where coverage of debounce/paging interaction with the repo
layer is required and consolidates the suite.

## 2. Context & References

- **Depends on:** AND-155 (Search/contacts ViewModels + paging — debounced query
  state, paging, empty states), which in turn depends on AND-152 (Global message
  search, `/messaging/messages/search`) and AND-153 (Contacts list + search,
  `/messaging/contacts/search`). All three production tickets must be merged
  before this suite can compile and run.
- **Modules under test:** `feature-search`, `feature-contacts`, and the
  search/contacts code paths in `core-data` and `core-network`. Test utilities
  live in `core-testing`.
- **Backend:** FastAPI + DynamoDB; OpenAPI at `/openapi.json` on the dev host
  `http://18.222.237.167:8000` (plaintext HTTP, unreliable). Tests must **not**
  hit the live host; all network is faked via `MockWebServer` (OkHttp) or
  test-double Retrofit services. Endpoint shapes are taken from the web reference
  app: `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`.
- **Namespace:** all test packages live under `com.testlogon.android.*`
  (e.g., `com.testlogon.android.feature.search`,
  `com.testlogon.android.feature.contacts`,
  `com.testlogon.android.core.data.search`).
- **Stack relevant to tests:** Kotlin 2.0.21, Coroutines/Flow, Paging 3,
  Compose + Material 3, Hilt (KSP), Retrofit 2.11/OkHttp 4.12/Moshi 1.15, Room
  2.6. JDK 17, AGP 8.7.3, Gradle 8.9. minSdk 24 / target 35.

## 3. Functional Requirements

The suite must assert the following observable behaviors of the code delivered by
AND-152/153/155:

1. **Debounce:** rapid `onQueryChanged()` calls within the debounce window
   (300 ms) collapse to a single repository search invocation for the final
   value. A `query` shorter than the minimum (2 chars) issues no network call and
   resets results to `Idle`.
2. **Distinct-until-changed:** typing the same value twice (e.g., "ab" → "ab")
   does not re-trigger a search.
3. **Cancellation:** when a new query arrives while a previous search is in
   flight, the in-flight request is cancelled (no stale results overwrite newer
   ones — last-write-wins by query token).
4. **Paging:** the message-search `PagingSource` loads page 1, then appends
   page 2 on the next key (cursor), exposes `prevKey`/`nextKey` correctly, and
   surfaces `LoadResult.Error` on transport failure.
5. **Empty state:** a 200 response with `items: []` yields the `Empty` UI state
   (distinct from `Idle` and `Error`).
6. **Error state:** non-2xx / timeout / parse failures map to a typed
   `ApiResult.Error` and the `Error` UI state with a user-facing message derived
   from the FastAPI `detail` shape.
7. **Contacts tokenization:** the contacts repo forwards the raw query to
   `/messaging/contacts/search?q=` and returns the parsed contact list; name/
   fragment matches return results (server-side tokenization is not re-tested
   client-side, only that the query reaches the endpoint and results parse).
8. **UI rendering:** each screen renders loading skeleton, content list, empty
   placeholder, and error+retry, and fires `onQueryChange`, `onResultClick`,
   and `onRetry` callbacks with correct arguments.

## 4. Technical Design

### Test source sets & layout

```
feature-search/src/test/java/com/testlogon/android/feature/search/
  MessageSearchViewModelTest.kt        // JVM, Robolectric not required
feature-search/src/test/java/com/testlogon/android/feature/search/
  MessageSearchScreenTest.kt           // Robolectric (RobolectricTestRunner)
feature-contacts/src/test/java/com/testlogon/android/feature/contacts/
  ContactsViewModelTest.kt
  ContactsScreenTest.kt
core-data/src/test/java/com/testlogon/android/core/data/search/
  MessageSearchRepositoryTest.kt
  MessageSearchPagingSourceTest.kt
  ContactsRepositoryTest.kt
core-testing/src/main/java/com/testlogon/android/core/testing/
  MainDispatcherRule.kt
  MockWebServerExtensions.kt
  PagingTestExtensions.kt
  FakeSearchApi.kt
```

Compose UI tests run under **Robolectric** (`robolectric` + `createComposeRule`)
so they execute on the JVM in CI without an emulator; a parallel
`androidTest` smoke variant is allowed but not required for "Tests pass".

### Coroutine/time control

A reusable JUnit rule swaps the main dispatcher for a `TestDispatcher` and gives
tests virtual-time control over debounce:

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}
```

Debounce is verified by advancing virtual time:

```kotlin
@Test
fun debounce_collapses_rapid_input_to_single_search() = runTest {
    val vm = MessageSearchViewModel(repo, savedState)
    vm.onQueryChanged("h"); vm.onQueryChanged("he"); vm.onQueryChanged("hello")
    advanceTimeBy(299); runCurrent()
    coVerify(exactly = 0) { repo.searchMessages(any(), any(), any()) }
    advanceTimeBy(1)
    coVerify(exactly = 1) { repo.searchMessages("hello", null, null) }
}
```

### Repository test doubles

`MockWebServer` backs Retrofit for end-to-end JSON parsing tests; MockK fakes the
repo where only ViewModel logic is under test. JSON fixtures live in
`core-testing/src/main/resources/fixtures/` and are enqueued via a helper:

```kotlin
fun MockWebServer.enqueueJson(@Language("JSON") body: String, code: Int = 200) =
    enqueue(MockResponse().setResponseCode(code)
        .setHeader("Content-Type", "application/json").setBody(body))
```

### Paging assertions

`PagingSource` is exercised directly with `PagingSource.LoadParams.Refresh` /
`.Append` and via Paging's `AsyncPagingDataDiffer` for `Flow<PagingData<T>>`
collection. A `collectDataForTest()` helper snapshots `PagingData` into a `List`.

## 5. API Contract

This ticket defines no new endpoints; it asserts conformance to the contracts
from AND-152/153. Tests pin the exact request/response shapes so a backend or
parser drift fails the build.

**Message search** — `GET /messaging/messages/search`:

```
GET /messaging/messages/search?q=hello&sender=u_42&after=2026-01-01T00:00:00Z&limit=20&cursor=eyJ...
Cookies: session=...; ui_csrf=...
X-CSRF-Token: <ui_csrf value>
```

Expected 200 response (fixture `search_messages_page1.json`):

```json
{
  "items": [
    {"message_id":"m_1","conversation_id":"c_9","sender_id":"u_42",
     "sender_name":"Ada","snippet":"...hello there...","sent_at":"2026-06-01T12:00:00Z"}
  ],
  "next_cursor": "eyJwIjoyfQ==",
  "total": 37
}
```

**Contacts search** — `GET /messaging/contacts/search?q=ada`:

```json
{ "items": [ {"user_id":"u_42","display_name":"Ada Lovelace","handle":"@ada","avatar_url":null} ] }
```

**Error fixtures** assert FastAPI `detail` mapping in all three forms:

```json
{"detail":"Search temporarily unavailable"}
{"detail":[{"loc":["query","q"],"msg":"ensure this value has at least 2 characters","type":"value_error"}]}
{"detail":{"code":"rate_limited","retry_after":5}}
```

The 401-refresh path (`POST /ui/session/refresh` then single retry) is asserted
via an enqueued `401` followed by `200`, verifying exactly one refresh and one
replay of the original idempotent GET.

## 6. Data & State Management

Tests assert the `UiState` contract produced by the ViewModels (defined in
AND-155). The canonical shape under test:

```kotlin
sealed interface SearchUiState {
    data object Idle : SearchUiState                     // query < minLen
    data object Loading : SearchUiState
    data class Content(val results: Flow<PagingData<MessageHit>>) : SearchUiState
    data object Empty : SearchUiState                    // 200 + items == []
    data class Error(val message: String, val retryable: Boolean) : SearchUiState
}
```

State transitions verified: `Idle → Loading → Content`, `Idle → Loading → Empty`,
`Idle → Loading → Error`, and `Error → Loading` on retry. The `query` string is
held in `SavedStateHandle`; a test asserts it survives process-death simulation
by constructing a new ViewModel from the same handle and confirming the query and
resulting search are restored. Contacts uses an analogous `ContactsUiState` with
a non-paged `List<Contact>` (or paged if AND-155 paged contacts — the test
mirrors whichever the production type exposes). No Room/DataStore writes are
asserted here beyond confirming the repo's cache read path returns stale data
when offline (one test enqueues a network failure and asserts a cached page is
emitted with a `stale = true` flag if AND-155 exposes one).

## 7. Error Handling & Resilience

Tests cover the resilience requirements baked into the stack:

- **Timeout:** `MockWebServer` with `setBodyDelay(25, SECONDS)` against the
  configured ~20 s client timeout yields `ApiResult.Error` of `kind = Timeout`,
  mapped to a retryable `Error` UI state.
- **Bounded retry (idempotent GET only):** a test enqueues two `503` then `200`
  and asserts the search GET is retried within the bounded backoff and ultimately
  succeeds; a separate test asserts non-idempotent calls are **not** retried.
- **401 refresh-once:** verified per §5 — exactly one `POST /ui/session/refresh`
  and one retry; a second consecutive 401 surfaces an auth `Error` and does not
  loop.
- **Cancellation safety:** superseded queries cancel cleanly without emitting
  their results (asserted by collecting emissions and confirming only the latest
  query's results appear).
- **Parse failure:** malformed JSON yields a typed error, never a crash.

## 8. Security & Privacy

No production security surface changes. Test-specific requirements: fixtures must
contain only synthetic data (no real users/credentials/cookies). Tests assert
that the `X-CSRF-Token` header is populated from the `ui_csrf` cookie on every
search request (read from `RecordedRequest.getHeader("X-CSRF-Token")`), ensuring
the CSRF contract is not silently dropped. Tests must not log cookie values; the
persistent cookie jar used in tests is an in-memory test double, never written to
disk. No plaintext production host is contacted from any test.

## 9. Accessibility & i18n

UI tests assert accessibility affordances on the search/contacts screens:

- Each result row, the search field, and the retry button expose a non-empty
  content description / semantics label, asserted via
  `onNodeWithContentDescription` / `assertHasClickAction`.
- The empty and error placeholders expose readable text nodes (asserted by
  resource id, not hardcoded English literals, so localization is honored).
- All user-facing strings are resolved from `stringResource` (test asserts the
  rendered node text equals `context.getString(R.string.…)`), guaranteeing no
  hardcoded copy slipped into the production screens.

## 10. Telemetry & Logging

This ticket adds no telemetry. If AND-152/153/155 emit analytics events
(e.g., `search_performed`, `contact_opened`), a test injects a fake analytics
sink and asserts the event is logged once per committed (post-debounce) search
with the query length bucket but **not** the raw query string (privacy). If no
analytics interface exists in the production code, this section is N/A and owned
by the future analytics ticket; the test suite simply does not assert it.

## 11. Testing Strategy

This is the testing deliverable itself. Required test cases:

**Repository (`core-data`, JVM + MockWebServer):**
- `searchMessages` parses page 1, sends `q/sender/after/limit/cursor`, sets CSRF
  header.
- `searchMessages` empty `items` → repo returns empty page.
- `searchMessages` 503×2 then 200 → bounded retry succeeds.
- `searchMessages` 401 then 200 → one refresh, one retry.
- `searchContacts` parses list; sends `q`.
- Timeout → `ApiResult.Error(Timeout)`.
- All three `detail` shapes map to expected messages.

**PagingSource (`core-data`):**
- `load(Refresh)` returns page with correct `nextKey`, null `prevKey`.
- `load(Append)` with cursor returns page 2; null `next_cursor` → `nextKey == null`.
- Transport error → `LoadResult.Error`.
- `AsyncPagingDataDiffer` snapshot of `Flow<PagingData>` equals expected list.

**ViewModel (`feature-*`, virtual time):**
- Debounce collapse; min-length gate; distinct-until-changed; cancellation
  (last-write-wins); SavedStateHandle restore; retry transitions.

**Compose UI (Robolectric, `createComposeRule`):**
- `MessageSearchScreen`: loading skeleton shown; content list shows N rows;
  empty placeholder; error + retry click fires `onRetry`; typing fires
  `onQueryChange`; row click fires `onResultClick(messageId)`; a11y labels present.
- `ContactsScreen`: analogous content/empty/error + `onContactClick(userId)`.

**Coverage target:** ≥ 80% line coverage on the search/contacts production
packages (advisory, enforced via Jacoco report; build does not fail on coverage
but the report is published). Flakiness budget: zero — virtual time and
`MockWebServer` eliminate real delays. Run command:
`./gradlew :feature-search:testDebugUnitTest :feature-contacts:testDebugUnitTest
:core-data:testDebugUnitTest`.

## 12. Dependencies & Sequencing

- **Hard deps:** AND-155 (ViewModels + paging) must be merged; transitively
  AND-152 and AND-153. This ticket cannot compile before those land.
- **Test libs (add to version catalog / `core-testing`):** `junit:4.13.2`,
  `org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.x`, `io.mockk:mockk:1.13.x`,
  `com.squareup.okhttp3:mockwebserver:4.12.0`, `app.cash.turbine:turbine:1.x`
  (Flow assertions), `androidx.paging:paging-testing:3.3.x`,
  `org.robolectric:robolectric:4.13`, `androidx.compose.ui:ui-test-junit4`,
  `androidx.compose.ui:ui-test-manifest`, `androidx.arch.core:core-testing`.
- **Sequencing:** lands after AND-155; **blocks** nothing functional but is a
  gate for the M3 release sign-off (search/contacts cannot be marked Done without
  a green suite). CI must add the three `testDebugUnitTest` tasks to the PR check.

## 13. Risks & Open Questions

- **Production type drift:** exact `UiState`/`PagingData` types are owned by
  AND-155; if their shapes differ from §6, tests mirror the production types (the
  signatures here are the expected contract, to be reconciled at integration).
- **Contacts paging:** unclear whether AND-155 paged contacts or returns a flat
  list. Open question for AND-155 owner; the suite adapts to whichever is shipped.
- **Robolectric vs. instrumented:** Compose UI tests run on Robolectric for CI
  speed; if a Compose+Robolectric incompatibility appears on AGP 8.7.3, fall back
  to `androidTest` on an emulator runner (slower CI but unblocks "Tests pass").
- **Stale/offline flag:** the `stale` cache flag (§6) is only testable if AND-155
  exposes it; otherwise that single test is dropped.
- **Debounce window value:** assumed 300 ms / min-length 2; confirm against
  AND-155 constants and reference them rather than hardcoding.

## 14. Acceptance Criteria

1. `./gradlew :feature-search:testDebugUnitTest :feature-contacts:testDebugUnitTest
   :core-data:testDebugUnitTest` passes locally and in CI with zero failures and
   zero flakes across 3 consecutive runs.
2. All test cases enumerated in §11 exist and assert real behavior (no
   `@Ignore`, no assertion-free tests; reviewed for meaningful assertions).
3. Debounce, min-length gate, distinct-until-changed, cancellation/last-write-wins,
   empty-state, error-state, and SavedStateHandle-restore are each covered by at
   least one passing ViewModel test.
4. PagingSource refresh/append/error and a `Flow<PagingData>` snapshot are covered
   and pass.
5. Repository tests verify request params, `X-CSRF-Token` header, all three
   FastAPI `detail` mappings, timeout, bounded GET retry, and 401-refresh-once.
6. Compose UI tests for both screens cover loading/content/empty/error+retry and
   the `onQueryChange`/`onResultClick`/`onContactClick`/`onRetry` callbacks, plus
   a11y label presence, and pass.
7. No test contacts the live dev host `18.222.237.167`; all network is mocked.
8. Jacoco coverage report is produced for the search/contacts packages (≥ 80%
   advisory).

## 15. Definition of Done

- All §14 criteria met; suite green on the `android-port` branch CI.
- New test dependencies added to the Gradle version catalog; `core-testing`
  exposes the shared rules/helpers (`MainDispatcherRule`,
  `enqueueJson`, paging/turbine extensions, `FakeSearchApi`).
- CI PR check updated to run the three unit-test tasks; build fails on test
  failure.
- Fixtures committed under `core-testing/src/main/resources/fixtures/` with
  synthetic-only data.
- No production code changed (or, if a minimal testability hook was unavoidable —
  e.g., exposing a constructor-injected dispatcher — it is documented in the PR
  and approved by the AND-155 owner).
- Code reviewed and merged; M3 search/contacts features can be signed off as
  regression-protected.
