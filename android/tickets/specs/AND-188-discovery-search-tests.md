---
id: AND-188
title: Discovery/search tests
milestone: M4
epic: E25
priority: P2
size: M
status: draft
depends_on: [AND-187, AND-186, AND-185, AND-182]
blocks: []
---

# AND-188 — Discovery/search tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the Discovery and Search
surfaces of the TestLogon Android app (epic E25, milestone M4). The feature code
is implemented across AND-182 (Discover screen, `discovery.ts` parity),
AND-185 (global multi-entity search, `search.ts` parity), AND-186 (filters,
tabs, recent searches, empty/no-results states), and AND-187 (search/discovery
ViewModels with debounce, paging, and state). AND-188 adds no production
behavior; it adds repository-layer unit tests and Compose UI tests that lock in
the contracts those tickets established.

The goal is a fast, deterministic, network-free test suite that proves: (a) the
`DiscoveryRepository` and `SearchRepository` correctly map FastAPI responses
(including the polymorphic `detail` error shape) into `ApiResult<T>` and Paging
sources; (b) the `DiscoverViewModel` and `SearchViewModel` produce the right
`StateFlow<UiState>` transitions for query debounce, tab/filter changes, paging
append, refresh, empty results, and error/retry; and (c) the Compose screens
render loading, content, empty, no-results, and error states and emit the
expected navigation and interaction callbacks. "Tests pass" (the source
acceptance line) is operationalized below into specific, enumerated assertions
run in CI on every `android-port` PR.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Package base `com.testlogon.android`.
- Feature module under test: `feature-discovery`
  (`com.testlogon.android.feature.discovery`) and the search sub-package
  `com.testlogon.android.feature.discovery.search`.
- Core modules exercised: `core-model` (DTOs/domain), `core-network`
  (`ApiResult`, error mapping), `core-data` (repositories, Paging sources),
  `core-testing` (shared fakes, `MainDispatcherRule`, fixtures).
- Web reference for parity: `frontend/src/api/endpoints/discovery.ts`,
  `frontend/src/api/endpoints/search.ts`, `frontend/src/api/types.ts`.
- Backend OpenAPI: `http://18.222.237.167:8000/openapi.json` (dev host is
  PLAINTEXT and unreliable; tests MUST NOT touch it — see §7).
- Upstream tickets owning the code under test: AND-182, AND-185, AND-186,
  AND-187. AND-188 depends directly on AND-187 (ViewModels) per the backlog and
  transitively on the others.

Test stack: JUnit4, kotlinx-coroutines-test 1.8 (`runTest`,
`StandardTestDispatcher`, `TestDispatcher`), Turbine 1.1 for `Flow` assertions,
Truth 1.4 (or Kotlin `assertEquals`) for assertions, MockWebServer 4.12 for the
Retrofit/Moshi mapping layer, `androidx.paging:paging-testing:3.3` for
`PagingData` snapshots, Robolectric 4.13 for JVM-side ViewModel/Compose where
possible, and `androidx.compose.ui:ui-test-junit4` + `createComposeRule()` for
instrumented/Robolectric Compose tests. Hilt is bypassed in tests via direct
constructor injection of fakes; no `HiltAndroidTest` is required for these
units.

## 3. Functional Requirements

FR-1. Provide JVM unit tests for `SearchRepository` covering: success mapping of
the multi-entity payload into categorized domain results; per-tab paging source
behavior; empty-result payloads; and the three FastAPI `detail` error variants
mapped to `ApiResult.Error`.

FR-2. Provide JVM unit tests for `DiscoveryRepository` covering success mapping
of the curated/discover sections, empty sections, cache-then-network behavior
(Room-backed stale read), and error mapping.

FR-3. Provide ViewModel tests for `SearchViewModel` covering: query debounce
(rapid keystrokes collapse to a single fetch), minimum-query-length gating, tab
switching, filter application (AND-186), paging append, pull-to-refresh,
recent-searches persistence, empty/no-results state selection, and error→retry.

FR-4. Provide ViewModel tests for `DiscoverViewModel` covering initial load,
refresh, section rendering, stale/offline state surfacing, and error→retry.

FR-5. Provide Compose UI tests for `DiscoverScreen` and `SearchScreen` covering
each visual state (loading, content, empty, no-results, error) and interaction
callbacks (item tap → navigation, query input, tab select, filter toggle,
recent-search tap, retry).

FR-6. All tests are deterministic and hermetic: virtual time for debounce/delay,
injected `TestDispatcher`, no real sockets except MockWebServer on loopback, no
sleeps, no flakiness. The suite runs under `./gradlew :feature-discovery:test`
and `:feature-discovery:connectedDebugAndroidTest` (or the Robolectric
equivalent `testDebugUnitTest` for Compose-on-JVM).

FR-7. Code coverage for the discovery/search ViewModels and repositories is
reported (JaCoCo) with a floor of 80% line coverage on the
`feature.discovery` package; the suite fails CI below the floor.

## 4. Technical Design

Tests live alongside the modules they exercise:

```
feature-discovery/src/test/java/com/testlogon/android/feature/discovery/
    SearchViewModelTest.kt
    DiscoverViewModelTest.kt
    search/SearchUiStateReducerTest.kt           // if reducer is extracted
feature-discovery/src/androidTest/java/com/testlogon/android/feature/discovery/
    DiscoverScreenTest.kt
    search/SearchScreenTest.kt
core-data/src/test/java/com/testlogon/android/core/data/
    SearchRepositoryTest.kt
    DiscoveryRepositoryTest.kt
core-testing/src/main/java/com/testlogon/android/core/testing/
    MainDispatcherRule.kt
    fixtures/SearchFixtures.kt
    fixtures/DiscoveryFixtures.kt
    fakes/FakeSearchRepository.kt
    fakes/FakeDiscoveryRepository.kt
```

Shared infrastructure in `core-testing` (created or extended here):

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}

object SearchFixtures {
    fun multiEntityResponseJson(): String      // raw OpenAPI-shaped body
    fun emptyResponseJson(): String
    fun detailStringErrorJson(): String        // {"detail":"…"}
    fun detailListErrorJson(): String          // {"detail":[{"msg":"…"}]}
    fun detailObjectErrorJson(): String        // {"detail":{"code":"…"}}
    fun usersPage(n: Int): List<UserSummary>
    fun contentPage(n: Int): List<ContentSummary>
}
```

Repository tests use MockWebServer to validate the real Retrofit + Moshi +
`ApiResult` pipeline:

```kotlin
@get:Rule val main = MainDispatcherRule()
private lateinit var server: MockWebServer
private lateinit var repo: SearchRepository

@Before fun setUp() {
    server = MockWebServer().apply { start() }
    val api = retrofit(server.url("/")).create(SearchApi::class.java)
    repo = DefaultSearchRepository(api, /* csrf */ FakeCsrfStore(), ioDispatcher = main.dispatcher)
}
@After fun tearDown() = server.shutdown()
```

ViewModel tests inject the fake repository and the rule's `TestDispatcher`,
then drive virtual time with `advanceTimeBy`/`advanceUntilIdle` and assert
`StateFlow` emissions through Turbine:

```kotlin
@Test fun debounce_collapses_rapid_keystrokes() = runTest(main.dispatcher) {
    val repo = FakeSearchRepository().apply { totalCalls = 0 }
    val vm = SearchViewModel(repo, savedState(), main.dispatcher)
    vm.onQueryChanged("a"); vm.onQueryChanged("ab"); vm.onQueryChanged("abc")
    advanceTimeBy(299); assertThat(repo.totalCalls).isEqualTo(0)
    advanceTimeBy(1);   advanceUntilIdle()
    assertThat(repo.totalCalls).isEqualTo(1)
    assertThat(repo.lastQuery).isEqualTo("abc")
}
```

Paging assertions use `paging-testing` to snapshot the differ:

```kotlin
@Test fun search_users_tab_pages() = runTest(main.dispatcher) {
    val flow = repo.searchPaged(query = "kotlin", tab = SearchTab.USERS)
    val snapshot = flow.asSnapshot { scrollTo(index = 40) }
    assertThat(snapshot).hasSize(60)   // two pages of 30
}
```

Compose UI tests use `createComposeRule()` against the stateless screen
composables, feeding hand-built `UiState` values so rendering is decoupled from
the ViewModel:

```kotlin
@get:Rule val compose = createComposeRule()

@Test fun searchScreen_noResults_showsEmptyCopy() {
    compose.setContent {
        SearchScreen(state = SearchUiState.NoResults(query = "zzz"), onEvent = {})
    }
    compose.onNodeWithTag("search_no_results").assertIsDisplayed()
    compose.onNodeWithText("No results for \"zzz\"").assertExists()
}
```

The screens must expose stable `Modifier.testTag(...)` anchors (added in
AND-182/185/186 if missing; otherwise added here as a minimal, non-behavioral
change): `discover_grid`, `discover_loading`, `discover_error`,
`search_field`, `search_tabs`, `search_results`, `search_loading`,
`search_empty`, `search_no_results`, `search_error`, `recent_searches`,
`filter_chip_<id>`.

## 5. API Contract

This is a test ticket; it defines no new endpoints. It asserts against the
contracts owned by AND-185 (`/ui/search`) and AND-182 (`/ui/discovery`), which
the tests reproduce as MockWebServer fixtures. The canonical shapes the
repository tests assert on:

Search (multi-entity), `GET /ui/search?q={q}&type={users|content|...}&cursor={c}`:

```json
{
  "query": "kotlin",
  "results": {
    "users":   { "items": [ {"id":"u1","handle":"…","display_name":"…"} ], "next_cursor": "c2" },
    "content": { "items": [ {"id":"c1","title":"…","thumb_url":"…"} ],     "next_cursor": null }
  },
  "total": 42
}
```

Discovery, `GET /ui/discovery`:

```json
{
  "sections": [
    { "id": "trending", "title": "Trending", "items": [ {"id":"c1","title":"…","thumb_url":"…"} ] },
    { "id": "for_you",  "title": "For You",  "items": [] }
  ]
}
```

Polymorphic error body asserted in all three forms (string, list-of-`{msg}`,
object-with-`code`):

```json
{"detail": "rate limited"}
{"detail": [{"loc":["query","q"],"msg":"too short","type":"value_error"}]}
{"detail": {"code":"SEARCH_UNAVAILABLE","message":"backend down"}}
```

Tests assert each maps to `ApiResult.Error` with the human-facing message
extracted per the `core-network` error mapper, and that a 401 triggers exactly
one `POST /ui/session/refresh` + retry (verified via MockWebServer
`takeRequest()` ordering) — the refresh-once behavior owned by core-network is
re-asserted here at the repository boundary.

## 6. Data & State Management

The tests pin the `UiState` contracts emitted by AND-187's ViewModels:

```kotlin
sealed interface SearchUiState {
    data object Idle : SearchUiState                                   // empty query, show recents
    data class Loading(val query: String) : SearchUiState
    data class Content(
        val query: String, val tab: SearchTab,
        val results: Map<SearchTab, Flow<PagingData<SearchItem>>>,
        val activeFilters: Set<SearchFilter>,
    ) : SearchUiState
    data class NoResults(val query: String) : SearchUiState
    data class Error(val message: String, val retryable: Boolean) : SearchUiState
}

sealed interface DiscoverUiState {
    data object Loading : DiscoverUiState
    data class Content(val sections: List<DiscoverSection>, val isStale: Boolean) : DiscoverUiState
    data object Empty : DiscoverUiState
    data class Error(val message: String) : DiscoverUiState
}
```

Asserted transitions:
- Search: `Idle → Loading → Content` (results present); `Idle → Loading →
  NoResults` (empty payload, non-blank query); `Loading → Error` (mapped
  failure); `Error → Loading → Content` on retry; tab switch preserves query and
  swaps the active `PagingData` stream without re-issuing the network call when
  cached.
- Discover: `Loading → Content(isStale=false)` on fresh network;
  `Content(isStale=true)` when only the Room cache resolves (offline);
  `Loading → Error` on cold failure with empty cache; `Loading → Empty` when all
  sections are empty.
- Recent searches persisted via DataStore: tests inject a fake `RecentSearches`
  store and assert add-on-submit, dedupe, and bounded size (e.g., last 10).
- `SavedStateHandle` round-trip: query and active tab survive process death
  (tests reconstruct the ViewModel from a populated `SavedStateHandle`).

## 7. Error Handling & Resilience

The dev backend is plaintext and unreliable, so the suite is fully hermetic:
all HTTP is served by MockWebServer on `127.0.0.1`; no test references
`18.222.237.167`. A CI guard (a small JUnit assertion or lint rule) fails if any
fixture URL points off-loopback.

Resilience behaviors asserted:
- Timeout: MockWebServer dispatcher delays past the configured ~20s read
  timeout (simulated via `setBodyDelay` + `advanceTimeBy` virtual clock, not
  wall-clock) → repository returns `ApiResult.Error(retryable=true)` and the
  ViewModel surfaces `Error(retryable=true)`.
- Bounded retry: idempotent GET search/discovery retries up to the configured
  bound on 5xx; a non-idempotent path would not — asserted via request count in
  MockWebServer.
- 401 refresh-once: a 401 then 200 sequence yields a single
  `/ui/session/refresh` and a successful final result; a 401 → refresh → 401
  yields a terminal auth error with no infinite loop.
- Offline/stale: with the network fake throwing `IOException` and a primed Room
  cache, Discover emits `Content(isStale=true)`; with no cache it emits `Error`.
- Empty vs no-results disambiguation: blank-query Idle is distinct from
  non-blank query returning zero items (`NoResults`).

## 8. Security & Privacy

No new attack surface. Test-specific requirements: fixtures use synthetic
usernames/handles and dummy content only — no real user PII and no production
credentials. The CSRF/cookie behavior is exercised with a `FakeCsrfStore`
returning a fixed token; tests assert the repository attaches the
`X-CSRF-Token` header on state-changing calls (none expected for read-only
search/discovery, so the assertion is that GETs carry cookies but require no
CSRF header, matching the cookie-based auth model). No secrets are committed;
MockWebServer issues ephemeral loopback ports. Logs emitted during tests must
not contain raw query strings beyond what telemetry (§10) sanitizes.

## 9. Accessibility & i18n

Compose UI tests assert accessibility semantics on the surfaces:
- Search field has a content description / label resolvable via
  `onNodeWithContentDescription`, and the clear-query control is reachable.
- Tabs expose `Role.Tab` semantics and a selected state
  (`assertIsSelected()` on the active tab).
- Filter chips expose toggle (`Role` + on/off) state asserted via
  `assertIsOn()/assertIsOff()`.
- Empty/no-results/error states present readable text nodes (not icon-only) so
  TalkBack can announce them.
- i18n: all asserted user-facing strings are read from `stringResource`
  (the test resolves them through the test context / `composeRule.activity
  .getString(R.string.…)` rather than hard-coding English), so a future locale
  does not break the suite. A test confirms no hard-coded literal is rendered
  for the no-results headline by comparing against the resource id.

## 10. Telemetry & Logging

A `FakeAnalytics` (test double implementing the `core-data` analytics interface)
is injected to assert the discovery/search ViewModels log the expected events
without coupling to a real sink:
- `search_performed { query_len, tab, filter_count, result_count }` — note
  `query_len` not the raw query (privacy); tests assert the raw query is never
  passed to analytics.
- `search_result_tapped { tab, position, entity_type }`.
- `discover_section_viewed { section_id }` and `discover_item_tapped {
  section_id, position }`.
- `search_error { code, retryable }`.
Tests assert event ordering (e.g., `search_performed` fires once per debounced
fetch, not per keystroke) and that the failure path emits `search_error`.

## 11. Testing Strategy

Layers and representative cases (each a discrete `@Test`):

Repository (JVM, MockWebServer) — `SearchRepositoryTest`,
`DiscoveryRepositoryTest`:
1. success → categorized results parsed, cursors honored.
2. empty payload → empty domain result (drives NoResults upstream).
3. `detail` string / list / object → `ApiResult.Error` with extracted message.
4. 500 → bounded retry then error; request count asserted.
5. 401 → single refresh + retry success; and 401→401 terminal.
6. timeout (delayed body, virtual time) → retryable error.
7. paging source: `load()` returns `Page` with correct `nextKey`/`prevKey`;
   end of pagination when `next_cursor == null`.
8. Discovery cache-then-network: stale cache emitted, then fresh overwrites.

ViewModel (JVM/Robolectric) — `SearchViewModelTest`, `DiscoverViewModelTest`:
9. debounce collapses keystrokes (≤1 fetch within window).
10. min-length gating (query shorter than threshold issues no fetch).
11. tab switch swaps stream, preserves query.
12. filter apply refines query params (AND-186) and triggers refetch.
13. paging append updates differ snapshot.
14. refresh re-issues fetch and resets to Loading.
15. recent searches add/dedupe/bound; clear-all.
16. error → retry → content recovery.
17. SavedStateHandle restoration after process death.
18. NoResults vs Idle disambiguation.

Compose UI — `DiscoverScreenTest`, `SearchScreenTest`:
19. each state renders its tagged node (loading/content/empty/no-results/error).
20. item tap invokes `onEvent(NavigateTo…)`.
21. query input invokes `onEvent(QueryChanged)`.
22. tab select / filter toggle / recent tap / retry callbacks.
23. accessibility semantics (Role.Tab, selected, toggle on/off).

Determinism: every test uses `MainDispatcherRule` + virtual time; no
`Thread.sleep`; Turbine `awaitItem()/expectNoEvents()` for flow ordering;
`@Config(sdk=[34])` for Robolectric Compose. Coverage gate per FR-7.

Commands:
`./gradlew :core-data:testDebugUnitTest :feature-discovery:testDebugUnitTest`
and `:feature-discovery:connectedDebugAndroidTest`
(or `:feature-discovery:testDebugUnitTest` with Robolectric for Compose).

## 12. Dependencies & Sequencing

Depends on AND-187 (ViewModels + state contracts) directly per the backlog, and
transitively on AND-182 (Discover screen + `discovery.ts` parity), AND-185
(global search + `search.ts` parity), and AND-186 (filters/tabs/recent/empty
states). Those tickets must merge first; this ticket's tests encode their
finalized `UiState`, repository, and Paging signatures. `core-testing` must
already provide `MainDispatcherRule` and the Retrofit test factory (extended
here with search/discovery fixtures and fakes). No ticket is blocked by
AND-188 (it `blocks: []`); however, CI gating means a regression in
AND-182/185/186/187 surfaces here. Any minimal `testTag` additions to the
screens (if not present) are a prerequisite touch on the feature module and
should be coordinated with AND-186 to avoid merge conflicts.

## 13. Risks & Open Questions

- R1: ViewModel signatures or `UiState` shapes from AND-187 may differ from
  those assumed here; tests must track the merged code. Mitigation: write tests
  against the actual public API after AND-187 lands; treat §6 shapes as
  expected-not-guaranteed.
- R2: Compose UI tests can be slow/flaky on emulators. Mitigation: prefer
  Robolectric for screen tests where feasible; reserve `connectedAndroidTest`
  for a smoke subset.
- R3: Paging 3 test ergonomics (`asSnapshot`) require `paging-testing`
  artifact; ensure it is added to `feature-discovery` and `core-data`
  test configurations.
- Q1: Is `search_performed` debounce window 300ms (assumed) or another value?
  Confirm against AND-187 implementation before asserting timing.
- Q2: Recent-searches max size and dedupe rule — confirm bound (assumed 10) and
  storage (DataStore) with AND-186.
- Q3: Does Discover use Paging or a single sectioned fetch? Affects which
  paging assertions apply to Discover vs Search only.

## 14. Acceptance Criteria

AC-1. `./gradlew :core-data:testDebugUnitTest
:feature-discovery:testDebugUnitTest` passes with all repository and ViewModel
tests green (cases 1–18 above).
AC-2. Compose UI tests (cases 19–23) pass under the chosen runner
(Robolectric and/or connected).
AC-3. Debounce test proves rapid keystrokes produce exactly one repository call;
min-length gating produces zero calls below threshold.
AC-4. All three FastAPI `detail` error variants are asserted to map to
`ApiResult.Error` with a non-empty user-facing message.
AC-5. 401→refresh→retry asserts exactly one `/ui/session/refresh`; 401→401
asserts a terminal auth error with no retry loop.
AC-6. Paging tests assert correct page sizes, `nextKey`/`prevKey`, and
end-of-pagination on null cursor.
AC-7. NoResults, Empty, Idle, stale/offline, and Error states are each asserted
distinctly for both screens.
AC-8. No test references the dev host `18.222.237.167`; all HTTP is loopback
MockWebServer; suite is hermetic and free of `Thread.sleep`.
AC-9. JaCoCo line coverage on `com.testlogon.android.feature.discovery` ≥ 80%;
build fails below the floor.
AC-10. Tests run green in CI on the `android-port` branch with no flake across
3 consecutive runs.

## 15. Definition of Done

- All test files in §4 implemented under `com.testlogon.android` packages and
  green locally and in CI.
- `core-testing` fixtures/fakes (`SearchFixtures`, `DiscoveryFixtures`,
  `FakeSearchRepository`, `FakeDiscoveryRepository`, `MainDispatcherRule`)
  added and reused (no duplicated test scaffolding in the feature module).
- Any required `testTag` anchors present on the Discover/Search composables.
- Coverage gate (FR-7/AC-9) wired into the Gradle verification task and the CI
  workflow.
- No reference to the unreliable dev backend; MockWebServer only.
- PR on `android-port` reviewed and merged; CI 3× flake-free; ticket links the
  upstream AND-182/185/186/187 PRs it validates.
