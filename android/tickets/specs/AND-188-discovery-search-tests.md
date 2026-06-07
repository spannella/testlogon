---
id: AND-188
title: Discovery/search tests
milestone: M4
epic: E25
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
// Cursor paging applies to the DISCOVER endpoints (DiscoverySearchResponse),
// not to /ui/search. Page size follows the discover `limit` param (web default
// 20 for trending/search, 12 for suggested); fixtures set next_cursor to drive
// a second page and null to end pagination.
@Test fun discover_search_pages() = runTest(main.dispatcher) {
    val flow = repo.discoverSearchPaged(query = "kotlin", limit = 20)
    val snapshot = flow.asSnapshot { scrollTo(index = 25) }
    assertThat(snapshot).hasSize(40)   // two pages of 20 (next_cursor then null)
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
contracts owned by AND-185 (`/ui/search`) and AND-182 (the `/ui/discover/*`
family), which the tests reproduce as MockWebServer fixtures. The canonical
shapes below were VERIFIED against the backend OpenAPI index and the web
client's `src/api/endpoints/{search,discovery}.ts`; the original draft shapes
were inaccurate and have been corrected (see §16).

Search (multi-entity), `GET /ui/search?q={q}&types={csv}&limit={n}`
(op `global_search_ui_search_get`). NOTE: the real query params are
`q`, `types` (comma-separated string, optional) and `limit` (default 5 in the
web client, which uses 10 on the Search page); there is **no** `type` (singular)
param and **no** `cursor` on `/ui/search` — search is a single bounded fetch, not
cursor-paged. The response is `GlobalSearchResponse`: a fixed map of named
sections, each a `SearchResultSection { items, total_estimate, has_more }`.
Tabs in the UI are client-side filters over these sections, not per-tab network
calls:

```json
{
  "query": "kotlin",
  "results": {
    "users":   { "items": [ {"type":"user","id":"u1","title":"…","snippet":"…","thumbnail_url":"…","url":"…","meta":{}} ], "total_estimate": 12, "has_more": true },
    "posts":   { "items": [ {"type":"post","id":"p1","title":"…","snippet":"…","url":"…"} ], "total_estimate": 3, "has_more": false },
    "catalog": { "items": [], "total_estimate": 0, "has_more": false },
    "files":   { "items": [], "total_estimate": 0, "has_more": false }
  },
  "partial": false
}
```

Each `SearchResultItem` carries `type` (one of `user|post|catalog|file|message|
ticket|contact|video|calendar`), `id`, `title`, `snippet`, `url`, optional
`thumbnail_url`, and optional `meta`. Section keys `users|posts|catalog|files`
are always present; `messages|tickets|contacts|videos|calendar` are optional.
There is no top-level `total` field (use per-section `total_estimate`); there are
no `handle`/`display_name`/`content`/`thumb_url`/`next_cursor` fields on search
items — those were errors in the original draft.

Discovery does NOT have a single `GET /ui/discovery` returning `sections[]`
(that endpoint does not exist). It is a family of cursor-paged user/creator
endpoints (op prefix `discover_*`):
- `GET /ui/discover/search?q&limit&cursor` → `DiscoverySearchResponse`
- `GET /ui/discover/suggested?limit` → `DiscoverySearchResponse`
- `GET /ui/discover/trending?limit` → `DiscoverySearchResponse`
- `GET /ui/discover/creators?limit` → `CreatorSuggestionsResponse`
- `GET /ui/discover/trending-tags?limit` → `TrendingTagsResponse`
- `GET /ui/discover/tags/{tag}?limit&cursor` → `TagDiscoverResponse`
- `GET /ui/discover/profile/{user_id}` → `DiscoveryProfile`
- `POST /ui/discover/reindex`

`DiscoverySearchResponse` (used by search/suggested/trending) is the cursor-paged
shape — cursor pagination lives on **discovery**, not on `/ui/search`:

```json
{
  "items": [ {"user_id":"u1","display_name":"…","profile_photo_url":"…","follower_count":120,"is_following":false,"is_followed_by":false,"is_mutual":false} ],
  "next_cursor": "c2",
  "total_estimate": 42
}
```

End-of-pagination is `next_cursor` absent/null (the field is optional).
`CreatorSuggestionsResponse` is `{ creators: CreatorSuggestionItem[], source }`
(not paged); `TrendingTagsResponse` is `{ tags: [{tag,count,last_used_at}] }`.

Polymorphic error body asserted in all three forms (string, list-of-`{msg}`,
object-with-`code`). VERIFIED: the OpenAPI `422` schema `HTTPValidationError`
is strictly `{"detail": [ValidationError]}` where `ValidationError = {loc, msg,
type}` — i.e. the list-of-`{msg}` form. The bare-string and object-with-`code`
forms are produced by FastAPI `HTTPException`/custom handlers (not the 422
schema) and are handled by the web client's `normalizeErrorDetail`
(`src/api/client.ts`), which the Android `core-network` mapper mirrors. The
object form's `code` keys observed in the web client are authorization codes
(`role_required`, `geo_blocked`, etc.), not `SEARCH_UNAVAILABLE`; the fixture
value is illustrative only:

```json
{"detail": "rate limited"}
{"detail": [{"loc":["query","q"],"msg":"too short","type":"value_error"}]}
{"detail": {"code":"role_required","message":"…"}}
```

Tests assert each maps to `ApiResult.Error` with the human-facing message
extracted per the `core-network` error mapper (mirroring `normalizeErrorDetail`),
and that a 401 triggers exactly one `POST /ui/session/refresh` (op
`ui_session_refresh_ui_session_refresh_post`, VERIFIED) + retry of the original
request (verified via MockWebServer `takeRequest()` ordering) — the refresh-once
behavior owned by core-network, mirroring `src/api/client.ts:refreshSession`, is
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
  swaps the displayed section without re-issuing the network call (per the web
  reference, `/ui/search` returns all sections in one call and tabs filter
  client-side — see §5/§16; if the Android port instead paginates per tab,
  re-confirm before asserting a cached-stream swap).
- Discover: `Loading → Content(isStale=false)` on fresh network;
  `Content(isStale=true)` when only the Room cache resolves (offline);
  `Loading → Error` on cold failure with empty cache; `Loading → Empty` when all
  sections are empty.
- Recent searches: CORRECTION — the web reference persists search history
  **server-side** via `GET/POST/DELETE /ui/search/history`
  (`src/api/endpoints/search.ts`: `getSearchHistory`, `recordSearchHistory`,
  `deleteSearchHistoryItem`, `clearSearchHistory`), recording on submit when the
  query length ≥ 2 (`SearchPage.tsx`). Whether the Android port mirrors this
  server-backed model or adds a local DataStore cache is an AND-186 decision
  (see §16 Open assumptions). Tests should assert against whichever store
  AND-186 ships: add-on-submit, dedupe, bounded size, and clear-all, using a
  fake that stands in for the chosen backing (server repo and/or DataStore).
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
returning a fixed token. CORRECTION: the web client (`src/api/client.ts`)
attaches `X-CSRF-Token` (read from the `ui_csrf` cookie) on **every** request
when the cookie is present — including GETs — not only on state-changing calls,
and also sends a `Bearer` Authorization header from the auth store plus
`credentials: include` cookies. The earlier assumption that read-only GETs carry
no CSRF header was wrong; tests should assert that GET search/discovery requests
carry the `X-CSRF-Token` header and cookies when a token is present (and behave
correctly when it is absent). State-changing search-history calls
(`POST/DELETE /ui/search/history`) likewise carry the header. No secrets are committed;
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
7. paging source (DISCOVER endpoints only — `/ui/search` is single-fetch):
   `load()` returns `Page` with correct `nextKey`/`prevKey` from
   `DiscoverySearchResponse.next_cursor`; end of pagination when `next_cursor`
   is absent/null. Plus a `/ui/search` one-shot test asserting all sections and
   per-section `has_more`/`total_estimate` are parsed.
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
- Q1: Debounce window — RESOLVED for the web reference: `SearchPage.tsx` uses
  `useDebounce(inputValue, 300)`, i.e. **300ms**, and fetches when query length
  ≥ 1 (history recorded at length ≥ 2). Android timing should match unless
  AND-187 deliberately diverges; confirm the AND-187 constant equals 300ms.
- Q2: Recent-searches max size and dedupe rule — the web reference stores history
  **server-side** via `/ui/search/history` (no client max enforced there;
  `getSearchHistory` defaults to limit 20). Confirm any client-side bound/dedupe
  and whether the Android port adds a DataStore cache with AND-186.
- Q3: RESOLVED — discovery is the cursor-paged surface
  (`DiscoverySearchResponse.next_cursor`); `/ui/search` is a single bounded
  multi-section fetch (no cursor). So Paging-3 cursor assertions apply to the
  **discover** endpoints (search/suggested/trending/tags), while `/ui/search`
  is asserted as a one-shot fetch with per-section `has_more`/`total_estimate`.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **`GET /ui/search` exists with params `q`, `types`, `limit`.** VERIFIED.
   OpenAPI `GET /ui/search` (op `global_search_ui_search_get`, `params=q,types,
   limit,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`); frontend
   `src/api/endpoints/search.ts: globalSearch` (`api.get("/ui/search", {q,
   limit, types?})`).
2. **Original draft used a `type` (singular) param and a `cursor` on
   `/ui/search`.** CORRECTED → no such params; the real params are `q`, `types`
   (CSV string), `limit`. Source: same as (1). `/ui/search` is not cursor-paged.
3. **Search response shape `GlobalSearchResponse` = `{query, results:{users,
   posts,catalog,files,...}, partial?}`, each section
   `SearchResultSection {items, total_estimate, has_more}`.** VERIFIED via
   `src/api/endpoints/search.ts: GlobalSearchResponse / SearchResultSection /
   SearchResultItem`.
4. **Original draft search items had `handle`/`display_name`/`thumb_url`,
   sections had `next_cursor`, top-level `total`, and a `content` section.**
   CORRECTED → items are `SearchResultItem {type,id,title,snippet,url,
   thumbnail_url?,meta?}`; sections use `total_estimate`/`has_more` (no
   `next_cursor`); no top-level `total`; the section is `catalog`/`posts`/
   `files`, not `content`. Source: `src/api/endpoints/search.ts`.
5. **A single `GET /ui/discovery` returning `sections[]` exists.** CORRECTED →
   does NOT exist. Discovery is the `/ui/discover/*` family. Source: OpenAPI
   index lines for `/ui/discover/search|suggested|trending|creators|trending-
   tags|tags/{tag}|profile/{user_id}|reindex`; `src/api/endpoints/discovery.ts`.
6. **`DiscoverySearchResponse = {items: DiscoveryUser[], next_cursor?,
   total_estimate}` with cursor paging.** VERIFIED.
   `src/api/endpoints/discovery.ts: DiscoverySearchResponse / DiscoveryUser`;
   OpenAPI `GET /ui/discover/search` (`params=q,limit,cursor`),
   `/ui/discover/tags/{tag}` (`params=tag,limit,cursor`).
7. **`GET /ui/discover/creators` returns `CreatorSuggestionsResponse {creators,
   source}`.** VERIFIED. OpenAPI `GET /ui/discover/creators`
   (`resp=200:CreatorSuggestionsResponse`); schema
   `components.schemas.CreatorSuggestionsResponse` in openapi.pretty.json.
8. **Debounce window is 300ms.** VERIFIED (was an open question Q1).
   `src/pages/search/SearchPage.tsx: useDebounce(inputValue, 300)`.
9. **Search fetch min-query-length threshold.** VERIFIED = 1 char in the web
   reference (`SearchPage.tsx: enabled: debouncedQuery.length >= 1`); history is
   recorded only when length ≥ 2. The Android threshold is an AND-187 choice
   (treat a stricter threshold as an assumption until confirmed).
10. **Recent searches persisted via DataStore.** CORRECTED → the web reference
    persists **server-side** via `GET/POST/DELETE /ui/search/history`. OpenAPI
    `GET/POST /ui/search/history`, `DELETE /ui/search/history`,
    `DELETE /ui/search/history/{item_id}`; `src/api/endpoints/search.ts:
    getSearchHistory/recordSearchHistory/clearSearchHistory/
    deleteSearchHistoryItem`. Any DataStore cache on Android is an AND-186
    assumption.
11. **Tabs are per-tab network calls / per-tab `PagingData` streams for
    search.** CORRECTED → tabs are client-side filters over the one
    multi-section `/ui/search` response. `SearchPage.tsx`
    (`sectionCount(tab.value)`, single `globalSearch(...)` query).
12. **401 → exactly one `POST /ui/session/refresh` → retry original request;
    401-after-refresh is terminal (no loop).** VERIFIED. OpenAPI
    `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`);
    `src/api/client.ts: refreshSession` + single-flight `refreshPromise` guard
    and one retry, then `logout("session_expired")` on a second 401.
13. **CSRF: `X-CSRF-Token` attached only on state-changing calls.** CORRECTED →
    attached on **every** request when the `ui_csrf` cookie is present (incl.
    GETs), alongside a `Bearer` token and `credentials: include` cookies.
    `src/api/client.ts` (header set unconditionally from `getCookie("ui_csrf")`).
14. **422 error body schema.** VERIFIED. `components.schemas.HTTPValidationError
    = {detail: ValidationError[]}`, `ValidationError = {loc, msg, type}`
    (openapi.pretty.json). The bare-string and `{code,...}` object `detail`
    forms come from `HTTPException`/custom handlers and are normalized by
    `src/api/client.ts: normalizeErrorDetail`; all three forms are real and must
    map to `ApiResult.Error` with a non-empty message.
15. **Dev host `18.222.237.167` is plaintext/unreliable; tests must be
    hermetic.** Per spec §2/§7 (project convention, not independently verifiable
    from OpenAPI/frontend); retained as a project constraint.
16. **Android test stack (JUnit4, coroutines-test, Turbine, MockWebServer,
    paging-testing, Robolectric, compose ui-test).** framework ref — standard
    AndroidX testing libraries: Paging testing
    https://developer.android.com/topic/libraries/architecture/paging/test ;
    Compose testing
    https://developer.android.com/develop/ui/compose/testing ;
    coroutines test
    https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/ .
    Versions/choices are an implementation assumption, not contract-bound.

### Corrections made

- §5: replaced the inaccurate `/ui/search` URL/params (removed `type`, `cursor`)
  and corrected the response to `GlobalSearchResponse` with
  `SearchResultSection {items,total_estimate,has_more}` and proper
  `SearchResultItem` fields; removed `total`/`next_cursor`/`content`.
- §5: replaced the nonexistent `GET /ui/discovery` `sections[]` model with the
  real `/ui/discover/*` family and `DiscoverySearchResponse` cursor shape;
  clarified cursor paging belongs to discovery, not search.
- §5: corrected the error-body note (422 is list-only per schema; string/object
  forms are HTTPException-derived; example `code` made realistic).
- §6/§11/§13: corrected search "per-tab paging stream" to client-side section
  filtering; moved cursor-paging assertions to the discover endpoints; corrected
  the paging snapshot example.
- §6/§13: corrected recent-searches storage from "DataStore" to the
  server-backed `/ui/search/history` model (with DataStore noted as an
  unconfirmed Android-side addition).
- §8: corrected CSRF behavior — `X-CSRF-Token` is sent on all requests when the
  cookie is present, not only state-changing ones.
- §13: resolved Q1 (300ms) and Q3 (discovery is the paged surface).
- Frontmatter: `status: reviewed`, added `reviewed_on: 2026-06-06`.

### Open assumptions

- **Android `UiState`/ViewModel signatures (§6)** are expected-not-guaranteed
  until AND-187 merges; the audited contracts are the *backend/web* contracts,
  which the Android code must mirror. Why unverifiable: the Android source does
  not yet exist in the provided references.
- **Android-side recent-search storage (DataStore vs server-backed vs both)**
  and any client max/dedupe bound — AND-186 decision; web uses server history
  with no client max. Why: not in provided sources.
- **Android debounce constant and min-query threshold** — assumed to match the
  web's 300ms / length≥1; AND-187 may diverge. Why: Android constants not in
  references.
- **`X-CSRF-Token` on Android** — the web sends it from a cookie on all calls;
  whether the Android port also sends CSRF on read-only GETs is an AND-185/187
  transport decision (recommended to mirror the web). Why: Android transport not
  in references.
- **Read-timeout (~20s) and bounded-retry counts** — quoted in §7 as configured
  values; the exact numbers are core-network config, not in the provided
  sources. Why: Android config not in references.
- **JaCoCo 80% floor (FR-7/AC-9)** — a project policy assumption, not contract.

## 17. Test Plan

IDs `TC-AND-188-NN`. "AC-#" trace to §14 Acceptance Criteria. Unless a case is
marked PHYSICAL DEVICE, JVM/Robolectric cases run locally with no device and
instrumented Compose cases run on the headless emulator AVD `test35`
(API 35). MockWebServer binds loopback only.

**TC-AND-188-01 — Search success maps multi-section payload**
- Type: contract/MockWebServer (JVM)
- Target: `SearchRepositoryTest` (`DefaultSearchRepository` + Retrofit/Moshi).
- Preconditions: MockWebServer enqueues 200 with a `GlobalSearchResponse`
  fixture (`users`/`posts`/`catalog`/`files` populated; `has_more`/
  `total_estimate` set; `partial:false`).
- Steps: call `repo.search(q="kotlin", types=null, limit=10)`; inspect result
  and `server.takeRequest()`.
- Expected: `ApiResult.Success`; sections parsed into domain results with each
  item's `type,id,title,snippet,url,thumbnail_url,meta`; per-section `has_more`/
  `total_estimate` preserved; request path is `/ui/search?q=kotlin&limit=10`
  with NO `cursor`/`type` params; no top-level `total` expected.
- Traces: AC-1.

**TC-AND-188-02 — Empty search payload → empty domain (drives NoResults)**
- Type: contract/MockWebServer (JVM)
- Target: `SearchRepositoryTest`.
- Preconditions: 200 with all sections `items:[] , has_more:false,
  total_estimate:0`, non-blank query.
- Steps: call `repo.search("zzzzz")`.
- Expected: `ApiResult.Success` with zero items across all sections (consumed
  upstream as `NoResults`, distinct from `Idle`).
- Traces: AC-1, AC-7.

**TC-AND-188-03 — Three `detail` error forms → `ApiResult.Error`**
- Type: contract/MockWebServer (JVM)
- Target: `SearchRepositoryTest` + core-network mapper.
- Preconditions: three enqueued responses: `400 {"detail":"rate limited"}`,
  `422 {"detail":[{"loc":["query","q"],"msg":"too short","type":"value_error"}]}`,
  `403 {"detail":{"code":"role_required","message":"…"}}`.
- Steps: issue a search per response; capture each `ApiResult`.
- Expected: each → `ApiResult.Error` with a non-empty user-facing message
  matching `normalizeErrorDetail` semantics (string passthrough; list → joined
  `msg`s; object → mapped/`message`).
- Traces: AC-4.

**TC-AND-188-04 — 401 → single refresh → retry success**
- Type: contract/MockWebServer (JVM)
- Target: `SearchRepositoryTest` (core-network refresh-once at repo boundary).
- Preconditions: queue `401`, then expect `POST /ui/session/refresh` `200`,
  then `200` for the retried search.
- Steps: call `repo.search("kotlin")`; assert via `takeRequest()` ordering.
- Expected: exactly one `POST /ui/session/refresh`; original request retried
  once; final `ApiResult.Success`. No duplicate refreshes.
- Traces: AC-5.

**TC-AND-188-05 — 401 → refresh → 401 is terminal (no loop)**
- Type: contract/MockWebServer (JVM)
- Target: `SearchRepositoryTest`.
- Preconditions: queue `401`, refresh `200`, retried request `401`.
- Steps: call `repo.search(...)`; count requests.
- Expected: terminal `ApiResult.Error` (auth); exactly one refresh; no infinite
  retry; session-expired/logout signal emitted once.
- Traces: AC-5.

**TC-AND-188-06 — Read timeout (virtual clock) → retryable error**
- Type: contract/MockWebServer (JVM)
- Target: `SearchRepositoryTest`.
- Preconditions: MockWebServer `setBodyDelay` beyond the configured read
  timeout; virtual time advanced via the test dispatcher (no wall-clock sleep).
- Steps: call `repo.search(...)`; advance time past timeout.
- Expected: `ApiResult.Error(retryable=true)`; no `Thread.sleep` used.
- Traces: AC-1, AC-8.

**TC-AND-188-07 — Discover cursor paging + end-of-pagination**
- Type: contract/MockWebServer + paging-testing (JVM)
- Target: `DiscoveryRepositoryTest` (`/ui/discover/search|trending|suggested`
  PagingSource over `DiscoverySearchResponse`).
- Preconditions: page 1 → `{items:[20], next_cursor:"c2", total_estimate:40}`;
  page 2 → `{items:[20], next_cursor:null}`.
- Steps: `flow.asSnapshot { scrollTo(index=25) }`; verify the two requests'
  `cursor` params (`absent`, then `c2`).
- Expected: snapshot size 40; `nextKey` from `next_cursor`; end-of-pagination
  when `next_cursor` null; `/ui/search` is NOT used for paging.
- Traces: AC-6.

**TC-AND-188-08 — Discover offline → stale cache; cold failure → error**
- Type: integration (JVM/Robolectric, Room in-memory)
- Target: `DiscoveryRepositoryTest` + `DiscoverViewModelTest`.
- Preconditions: (a) network fake throws `IOException` with a primed Room cache;
  (b) same but empty cache.
- Steps: trigger discover load in each case.
- Expected: (a) `Content(isStale=true)` from cache; (b) `Error`. Idle/Empty not
  conflated with stale.
- Traces: AC-7.

**TC-AND-188-09 — Debounce collapses keystrokes; min-length gating**
- Type: unit (JVM, coroutines virtual time + Turbine)
- Target: `SearchViewModelTest`.
- Preconditions: `FakeSearchRepository` counting calls; debounce window per
  AND-187 (web reference = 300ms).
- Steps: emit "a","ab","abc" rapidly; `advanceTimeBy(299)` then `+1` &
  `advanceUntilIdle`; separately emit a sub-threshold/empty query.
- Expected: exactly one repository call for the debounced burst with
  `lastQuery=="abc"`; zero calls for the gated (empty/below-threshold) query.
- Traces: AC-3.

**TC-AND-188-10 — Tab switch filters client-side, preserves query, no refetch**
- Type: unit (JVM + Turbine)
- Target: `SearchViewModelTest`.
- Preconditions: `FakeSearchRepository` returns a populated multi-section
  result; call count tracked.
- Steps: perform a search (1 call), then switch tabs users→posts→all.
- Expected: query preserved; displayed section changes; no additional repository
  calls on tab switch (matches web client-side filtering).
- Traces: AC-1, AC-7.

**TC-AND-188-11 — Error → retry → content recovery; `search_error` emitted once**
- Type: unit (JVM + Turbine, `FakeAnalytics`)
- Target: `SearchViewModelTest`.
- Preconditions: fake returns Error then Success; `FakeAnalytics` injected.
- Steps: drive `Loading→Error`; invoke retry; observe `Error→Loading→Content`.
- Expected: state recovers to `Content`; `search_error{code,retryable}` emitted
  on the failure; `search_performed` carries `query_len` (never raw query).
- Traces: AC-1.

**TC-AND-188-12 — SavedStateHandle restore (query + tab survive process death)**
- Type: unit (JVM/Robolectric)
- Target: `SearchViewModelTest`.
- Preconditions: reconstruct ViewModel from a populated `SavedStateHandle`.
- Steps: set query/tab, simulate recreate from saved state.
- Expected: restored query and active tab; restores to `Content`/`Idle`
  appropriately without an extra network call when results are cached.
- Traces: AC-1, AC-7.

**TC-AND-188-13 — Recent searches add/dedupe/bound/clear against chosen store**
- Type: unit (JVM)
- Target: `SearchViewModelTest` with a fake recent-search store standing in for
  the AND-186 backing (server `/ui/search/history` and/or DataStore).
- Preconditions: store seeded empty; record threshold per web reference
  (length ≥ 2).
- Steps: submit several queries incl. duplicates and a sub-threshold one;
  invoke clear-all and single-delete.
- Expected: add-on-submit (only at/above threshold), dedupe, bounded size,
  clear-all and delete-one behave as configured. (If server-backed, assert the
  `POST/DELETE /ui/search/history` calls via the fake repo.)
- Traces: AC-1.

**TC-AND-188-14 — Compose: each search state renders its tagged node + a11y**
- Type: Compose-UI (Robolectric `@Config(sdk=[34])` or emulator `test35`)
- Target: `SearchScreenTest` (stateless `SearchScreen` fed hand-built
  `SearchUiState`).
- Preconditions: `createComposeRule()`; feed Idle/Loading/Content/NoResults/
  Error states in turn.
- Steps: assert tagged nodes (`search_loading`,`search_results`,`search_empty`,
  `search_no_results`,`search_error`,`recent_searches`); for NoResults assert
  copy via `stringResource` (not a hard-coded literal); assert tabs expose
  `Role.Tab` + `assertIsSelected()`, filter chips `assertIsOn()/assertIsOff()`,
  and the search field has a content description; error/empty present readable
  text (TalkBack).
- Expected: each state shows its node; a11y semantics present; no icon-only
  empty/error.
- Traces: AC-2, AC-7.

**TC-AND-188-15 — Compose: search interaction callbacks**
- Type: Compose-UI (Robolectric or emulator `test35`)
- Target: `SearchScreenTest`.
- Preconditions: capture `onEvent` via a recording lambda.
- Steps: type into field; tap a result; select a tab; toggle a filter chip; tap
  a recent search; tap retry on the Error state.
- Expected: `QueryChanged`, `NavigateTo…`, tab-select, filter-toggle,
  recent-tap, and retry events emitted with correct payloads.
- Traces: AC-2.

**TC-AND-188-16 — Compose: Discover states + section a11y**
- Type: Compose-UI (Robolectric or emulator `test35`)
- Target: `DiscoverScreenTest`.
- Preconditions: feed `Loading`,`Content(isStale=false/true)`,`Empty`,`Error`.
- Steps: assert `discover_loading`/`discover_grid`/`discover_error` nodes;
  stale banner visible when `isStale=true`; item tap emits
  `onEvent(NavigateTo…)`; section header text resolvable; readable empty/error.
- Expected: distinct rendering per state incl. stale; navigation + retry
  callbacks fire; a11y text present.
- Traces: AC-2, AC-7.

**TC-AND-188-17 — Hermeticity guard (no dev host, no sleeps)**
- Type: unit (JVM, static/lint assertion)
- Target: a `HermeticityGuardTest` (or Gradle/lint rule) scanning test fixtures.
- Preconditions: scans test sources/fixtures for `18.222.237.167`,
  non-loopback URLs, and `Thread.sleep`.
- Steps: run the guard over the discovery/search test source set.
- Expected: zero matches; all `MockWebServer` URLs are `127.0.0.1`/loopback.
- Traces: AC-8.

**TC-AND-188-18 — Coverage floor enforced**
- Type: unit/integration (JaCoCo verification task)
- Target: Gradle `jacoco` verification on `com.testlogon.android.feature.
  discovery`.
- Preconditions: full discovery/search suite run with coverage.
- Steps: execute the coverage verification task in CI.
- Expected: line coverage ≥ 80%; build fails below the floor.
- Traces: AC-9.

**TC-AND-188-19 — Real-network smoke on physical device (negative/offline)**
- Type: instrumented/e2e — PHYSICAL DEVICE REQUIRED (Samsung Galaxy A15 5G,
  SM-A156U, API 34, arm64-v8a, serial R5CX821TA9R)
- Target: `SearchScreenTest`/`DiscoverScreenTest` instrumented smoke that
  exercises the airplane-mode/offline path and arm64 API-34 behavior the
  emulator (x86_64 API 35) cannot represent.
- Preconditions: app installed on device; MockWebServer or a local stub still
  used for HTTP (the dev host stays untouched); device toggled offline for the
  offline leg.
- Steps: launch Discover offline with a primed cache → expect stale content;
  go online → expect refresh to fresh content; run the same on the emulator and
  compare for ABI/API-level regressions.
- Expected: stale→fresh transition works on real arm64/API-34 hardware;
  no crash/ANR; behavior matches emulator. MUST run on the physical device
  because it validates arm64-v8a + API-34 vs the emulator's x86_64 + API-35.
- Traces: AC-2, AC-7, AC-10.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-01, TC-02, TC-06, TC-10, TC-11, TC-12, TC-13 |
| AC-2 | TC-14, TC-15, TC-16, TC-19 |
| AC-3 | TC-09 |
| AC-4 | TC-03 |
| AC-5 | TC-04, TC-05 |
| AC-6 | TC-07 |
| AC-7 | TC-02, TC-08, TC-10, TC-12, TC-14, TC-16, TC-19 |
| AC-8 | TC-06, TC-17 |
| AC-9 | TC-18 |
| AC-10 | TC-19 (+ all cases run 3× flake-free in CI) |
