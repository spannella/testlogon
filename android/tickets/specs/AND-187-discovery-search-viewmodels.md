---
id: AND-187
title: Discovery/search ViewModels
milestone: M4
epic: E25
priority: P1
size: M
status: draft
depends_on: [AND-182, AND-185]
blocks: []
---

# AND-187 — Discovery/search ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state machines for the Discover and
Global Search experiences of the TestLogon native Android app: `DiscoverViewModel`
and `SearchViewModel`. The screens themselves (Compose UI for the curated/discover
grid in AND-182 and the multi-entity, tabbed search surface in AND-185) and the
network endpoint wrappers (`discovery.ts`/`search.ts` equivalents) are owned by the
dependency tickets. AND-187 is responsible for the logic that sits between them:
input debouncing, Paging 3 pipelines, query-state orchestration, and the
`StateFlow<UiState>` contracts the UI binds to.

The goal is a fully unit-tested pair of ViewModels (and their shared support types)
that:

- Debounce free-text search input so the dev backend (an unreliable plaintext HTTP
  host at `http://18.222.237.167:8000`) is not hammered per keystroke.
- Drive paged result lists via Paging 3 (`PagingData<T>`) for both discover rails
  and per-entity search tabs.
- Expose deterministic, exhaustive UI state (idle, loading, content, empty, error,
  offline/stale) so AND-182/AND-185 are pure rendering layers.

Out of scope: Compose UI, navigation, network DTO definitions, and Room cache
schema (referenced where they cross the boundary, but implemented elsewhere).

## 2. Context & References

- **App:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Module placement:** ViewModels live in feature modules. `DiscoverViewModel`
  belongs to `feature-discover` (`com.testlogon.android.feature.discover`);
  `SearchViewModel` belongs to `feature-search`
  (`com.testlogon.android.feature.search`). Shared paging/query helpers that are not
  feature-specific go to `core-ui`
  (`com.testlogon.android.core.ui.paging`) or `core-data`
  (`com.testlogon.android.core.data.search`).
- **Dependencies:**
  - **AND-182 — Discover screen** (P1): owns the `discovery` API wrapper and the
    curated/discover grid composables. AND-187 consumes its repository.
  - **AND-185 — Global search (multi-entity)** (P0): owns the `search` API wrapper
    across users/content/etc. and the tabbed UI. AND-187 consumes its repository and
    must mirror its entity taxonomy.
  - Transitively both depend on **AND-027** (core-network / Retrofit + cookie jar +
    CSRF + refresh interceptor) and AND-182 additionally on **AND-103**.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Paging 3, minSdk 24.
- **Web reference:** `frontend/src/api/endpoints/discovery.ts`,
  `frontend/src/api/endpoints/search.ts`, and shared types in
  `frontend/src/api/types.ts`. Canonical wire shapes also at `/openapi.json`.

## 3. Functional Requirements

FR-1. **Search debounce.** Free-text input from the search field is published to the
ViewModel as it changes. The ViewModel debounces by **300 ms** and ignores updates
that do not change the trimmed query. Queries shorter than **2 characters** (after
trim) reset to the idle state and issue no network call.

FR-2. **Distinct + cancel-previous.** Consecutive identical trimmed queries do not
re-trigger a fetch (`distinctUntilChanged`). When a new query arrives, the in-flight
paging stream for the previous query is cancelled (`flatMapLatest`).

FR-3. **Multi-entity results.** `SearchViewModel` exposes results categorized by
entity type matching AND-185's taxonomy: `USERS`, `CONTENT`, `PLAYLISTS`, `TAGS`
(enumerated in `SearchEntity`). The currently selected tab is part of UI state and
selecting a tab does not re-issue the query; each entity's `PagingData` is produced
lazily and cached.

FR-4. **Paging.** Both ViewModels expose `Flow<PagingData<T>>` backed by Paging 3
`PagingSource`s with a page size of **20** and `prefetchDistance = 5`. Discover
exposes one stream per rail/section; Search exposes one stream per `SearchEntity`.

FR-5. **Discover load + refresh.** `DiscoverViewModel` loads curated/discover
sections on init and exposes `refresh()` (pull-to-refresh) which re-requests the
section list and invalidates paging sources.

FR-6. **State exhaustiveness.** Each ViewModel exposes a single
`StateFlow<UiState>`; UI never derives state ad hoc. Paging load states
(`refresh`/`append`/`prepend`) are surfaced through `CombinedLoadStates` consumed by
the UI, while the screen-level scaffold state (selected tab, query echo,
offline/stale banner) lives in `UiState`.

FR-7. **Empty vs. error distinction.** A successful query that returns zero items is
`Empty` (not `Error`). Network/timeout failures are `Error` with a typed message;
served-from-cache results carry a `stale = true` flag.

FR-8. **Survives configuration change.** Query text and selected tab survive
rotation via `SavedStateHandle`.

## 4. Technical Design

ViewModels are Hilt `@HiltViewModel` classes injecting the repositories owned by
AND-182/AND-185 plus `SavedStateHandle`. They depend only on repository interfaces
(defined here as the contract AND-182/AND-185 implement) so they are testable with
fakes.

```kotlin
package com.testlogon.android.core.data.search

interface SearchRepository {
    // Returns a Paging stream for one entity bucket of a query.
    fun search(query: String, entity: SearchEntity): Flow<PagingData<SearchResult>>
}

interface DiscoverRepository {
    suspend fun sections(): ApiResult<List<DiscoverSection>>
    fun rail(sectionId: String): Flow<PagingData<DiscoverItem>>
}

enum class SearchEntity { USERS, CONTENT, PLAYLISTS, TAGS }
```

`ApiResult<T>` is the project-standard sealed type from `core-network`
(`Success`/`Error`/`Loading`) with FastAPI `detail` mapping (string |
`[{msg}]` | `{code,...}`).

### 4.1 SearchViewModel

```kotlin
package com.testlogon.android.feature.search

@HiltViewModel
class SearchViewModel @Inject constructor(
    private val repository: SearchRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val queryInput = MutableStateFlow(savedState.get<String>(KEY_QUERY).orEmpty())
    val uiState: StateFlow<SearchUiState>

    // One cached PagingData flow per entity for the active query.
    val results: Map<SearchEntity, Flow<PagingData<SearchResult>>>

    fun onQueryChange(raw: String)
    fun onSubmit()                 // bypass debounce, force fetch immediately
    fun onTabSelected(entity: SearchEntity)
    fun onClear()

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LEN = 2
        const val PAGE_SIZE = 20
        const val KEY_QUERY = "search.query"
        const val KEY_TAB = "search.tab"
    }
}
```

The debounced query pipeline:

```kotlin
private val activeQuery: StateFlow<String> = queryInput
    .map { it.trim() }
    .debounce(DEBOUNCE_MS)
    .distinctUntilChanged()
    .map { if (it.length >= MIN_QUERY_LEN) it else "" }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "")

private fun pagerFor(entity: SearchEntity): Flow<PagingData<SearchResult>> =
    activeQuery
        .flatMapLatest { q ->
            if (q.isEmpty()) flowOf(PagingData.empty())
            else repository.search(q, entity)
        }
        .cachedIn(viewModelScope)
```

`results` is built once as `SearchEntity.entries.associateWith { pagerFor(it) }`;
each value is `cachedIn(viewModelScope)` so tab switches do not refetch.

### 4.2 DiscoverViewModel

```kotlin
package com.testlogon.android.feature.discover

@HiltViewModel
class DiscoverViewModel @Inject constructor(
    private val repository: DiscoverRepository,
) : ViewModel() {

    val uiState: StateFlow<DiscoverUiState>
    fun rail(sectionId: String): Flow<PagingData<DiscoverItem>>  // memoized
    fun refresh()

    init { load() }
    private fun load()
}
```

`load()` calls `repository.sections()`, maps `ApiResult` into `DiscoverUiState`, and
exposes one memoized `cachedIn` paging flow per section id. `refresh()` re-runs
`load()` and emits `isRefreshing = true` while in flight.

### 4.3 Threading & cancellation

All work runs on `viewModelScope` (Dispatchers.Main.immediate by default; repository
suspends move to IO). `flatMapLatest` guarantees previous query streams are cancelled.
No manual thread management.

## 5. API Contract

AND-187 issues **no new endpoints**; it consumes repository interfaces. Wire calls
are owned by AND-182 (`discovery`) and AND-185 (`search`). Documented here for the
contract the ViewModels assume; final shapes are authoritative in `/openapi.json`.

**Search (per AND-185):**

```
GET /search?q={query}&type={users|content|playlists|tags}&cursor={c}&limit=20
```
Response (categorized; ViewModel reads one `type` bucket per `PagingSource` page):
```json
{
  "type": "users",
  "items": [
    { "id": "u_123", "kind": "user", "title": "jdoe", "subtitle": "@jdoe", "imageUrl": "..." }
  ],
  "next_cursor": "eyJvIjoyMH0=",
  "total": 137
}
```

**Discover (per AND-182):**

```
GET /discovery/sections
GET /discovery/sections/{sectionId}/items?cursor={c}&limit=20
```
```json
{ "sections": [ { "id": "trending", "title": "Trending", "layout": "grid" } ] }
```

Auth rides on cookies + `X-CSRF-Token` (from `ui_csrf`); on 401 the OkHttp layer
(AND-027) performs one `POST /ui/session/refresh` then retries. These GETs are
**idempotent**, so the bounded backoff-retry policy (~20s timeout) applies. The
ViewModel does not implement HTTP concerns; it observes the resulting `LoadState`.

## 6. Data & State Management

```kotlin
data class SearchUiState(
    val query: String = "",
    val selectedTab: SearchEntity = SearchEntity.USERS,
    val phase: SearchPhase = SearchPhase.Idle,
    val stale: Boolean = false,
)

sealed interface SearchPhase {
    data object Idle : SearchPhase          // query < MIN_QUERY_LEN
    data object Searching : SearchPhase     // debounce fired, refresh loading
    data object Results : SearchPhase
    data object Empty : SearchPhase
    data class Error(val message: String, val retryable: Boolean) : SearchPhase
}

data class DiscoverUiState(
    val sections: List<DiscoverSection> = emptyList(),
    val isRefreshing: Boolean = false,
    val phase: DiscoverPhase = DiscoverPhase.Loading,
    val stale: Boolean = false,
)

sealed interface DiscoverPhase {
    data object Loading : DiscoverPhase
    data object Content : DiscoverPhase
    data object Empty : DiscoverPhase
    data class Error(val message: String, val retryable: Boolean) : DiscoverPhase
}
```

- **Source of truth:** `StateFlow` for scaffold state; `PagingData` flows for lists.
  `phase` for list-level loading/empty/error is derived in the UI from
  `CombinedLoadStates` (the canonical Paging source) and reconciled into `UiState`
  only when needed for scaffolding (e.g., showing the global error banner). Item-level
  load/append spinners come straight from `LoadState`.
- **Persistence:** `SavedStateHandle` for `query` and `selectedTab`. No Room writes
  here; the `stale` flag is propagated from repository results (Room-backed cache
  owned by AND-182/AND-185/core-data).
- **Lifecycle:** `stateIn`/`cachedIn` with `SharingStarted.WhileSubscribed(5_000)`
  to keep streams alive across short config changes without leaking.

## 7. Error Handling & Resilience

- **Timeouts/host flakiness:** The dev host is plaintext and unreliable. Repository
  `PagingSource.load` returns `LoadResult.Error` on timeout; the ViewModel maps the
  `refresh` `LoadState.Error` into `SearchPhase.Error`/`DiscoverPhase.Error` with
  `retryable = true`. `append` errors keep existing items and expose a footer retry
  (UI uses `lazyPagingItems.retry()`).
- **Retry policy:** Bounded backoff retry for idempotent GETs is handled in the OkHttp
  layer (AND-027); the ViewModel adds no extra retry loop, only user-driven `retry()`.
- **Offline/stale:** When the repository serves cached data, `stale = true` is
  surfaced so the UI shows a non-blocking banner. Content is still rendered.
- **Empty vs. error:** Zero items with a successful `refresh` (`LoadState.NotLoading`,
  `endOfPaginationReached`) maps to `Empty`, never `Error`.
- **Error text:** FastAPI `detail` is normalized by `core-network` into a single
  user-safe string; the ViewModel never displays raw exceptions.
- **Debounce cancellation:** A query change mid-flight cancels the prior stream via
  `flatMapLatest`; no stale results from an abandoned query can reach the UI.

## 8. Security & Privacy

- No credentials handled here. Session cookies and `X-CSRF-Token` are managed by the
  persistent cookie jar / interceptors in AND-027.
- Search queries may contain PII; they are **not** logged at info level (see §10) and
  not persisted beyond `SavedStateHandle` (process-scoped, not on disk).
- The dev backend is plaintext HTTP; production must use TLS. This ViewModel layer is
  transport-agnostic and adds no plaintext exposure of its own.
- No new permissions. No data leaves the device except the query string sent to the
  search/discovery endpoints via the repositories.

## 9. Accessibility & i18n

- ViewModels hold no UI; a11y rendering (content descriptions, focus, talkback) is
  owned by AND-182/AND-185. AND-187 supports a11y by exposing distinct, announceable
  states (Loading/Empty/Error/Results) so the UI can surface them via live regions.
- All user-facing strings (error banners, empty-state copy) are exposed as
  string-resource ids or already-resolved strings produced by `core-network`'s
  localized error mapper, never hardcoded English in the ViewModel. Recommend the
  ViewModel emit a `@StringRes`/typed error and let the UI resolve, to keep i18n in
  the resource layer.
- Debounce timing (300 ms) is interaction-rate, not animation; no reduced-motion
  concern.

## 10. Telemetry & Logging

- Emit a debounced `search_query_executed` analytics event **only after** the
  debounce fires and a fetch begins, with `query_length` and `entity` — **never the
  raw query text** (PII). One event per executed query, not per keystroke.
- Emit `search_result_loaded` with `entity`, `result_count_bucket`
  (0 / 1-10 / 11-50 / 50+), and `stale` flag on first successful page.
- Emit `discover_loaded` / `discover_refreshed` with section count and `stale`.
- Emit `search_error` / `discover_error` with a coded error category (timeout,
  http_4xx, http_5xx, network) — no raw messages, no query.
- Logging via the project logger at DEBUG for state transitions in debug builds only;
  release builds suppress query content entirely.

## 11. Testing Strategy

Acceptance is **unit-tested**; this is the core deliverable. Use `core-testing`
(`MainDispatcherRule`, Turbine, fakes), JUnit, and `kotlinx-coroutines-test`
(`runTest`, `StandardTestDispatcher`, `advanceTimeBy`). Paging assertions use
`PagingData` snapshot via `AsyncPagingDataDiffer` or `cachedIn` + `.asSnapshot {}`.

Required tests:

- **Debounce:** typing "a","ab","abc" within the window triggers exactly one fetch
  after 300 ms with `"abc"` (`advanceTimeBy(299)` → no fetch; `+1` → fetch).
- **Min length:** query of length 1 yields `SearchPhase.Idle` and no repository call.
- **Distinct:** submitting the same trimmed query twice does not re-invoke the
  repository.
- **Cancellation:** a new query before the first resolves cancels the first
  (`flatMapLatest`); fake repository records only the latest active query.
- **Multi-entity:** four entity streams are produced; switching tabs does not
  re-invoke `repository.search` (cached).
- **Empty vs error:** repository returns empty page → `Empty`; returns error → `Error`
  with `retryable=true`; existing items retained on append error.
- **Stale flag:** cached repository result sets `stale=true` in `UiState`.
- **SavedState:** query + tab restored from `SavedStateHandle`.
- **Discover:** `init` loads sections; `refresh()` toggles `isRefreshing` and
  invalidates; error maps to `DiscoverPhase.Error`.
- **Paging:** `PagingSource` page size 20, cursor advances, `endOfPaginationReached`
  on null `next_cursor`.

Target ≥ 90% line coverage on both ViewModels and the debounce/paging helpers. No
instrumented tests required for this ticket (UI tests belong to AND-182/AND-185).

## 12. Dependencies & Sequencing

- **Hard deps:** AND-182 (DiscoverRepository + DTOs), AND-185 (SearchRepository +
  entity taxonomy + DTOs). Both transitively require AND-027 (core-network: cookie
  jar, CSRF, refresh, ApiResult, error mapping).
- **Sequencing:** The repository **interfaces** in §4 can be authored in `core-data`
  first to unblock parallel work; AND-182/AND-185 implement them. AND-187 ViewModels
  can be developed and unit-tested against fakes before the real repositories land,
  then wired up.
- **Blocks:** AND-182 and AND-185 screen wiring consume these ViewModels; final
  screen acceptance for those tickets depends on AND-187 being merged.

## 13. Risks & Open Questions

- **R1 — Entity taxonomy drift.** `SearchEntity` must match AND-185's `search.ts`
  buckets exactly. Mitigation: define the enum in `core-data` as the single source and
  have AND-185 import it. *Open: confirm exact set (users/content/playlists/tags) vs.
  `/openapi.json`.*
- **R2 — Cursor vs. offset paging.** Spec assumes opaque `next_cursor`. If the backend
  uses page/offset, the `PagingSource` key type changes. *Open: confirm with AND-185.*
- **R3 — Per-entity vs. combined search call.** Assumed one call per entity tab. If the
  backend returns all entities in one payload, `pagerFor` must split a shared response;
  prefer a single `RemoteMediator`. *Open: confirm endpoint shape.*
- **R4 — Debounce value.** 300 ms is a default; flaky host may warrant 400-500 ms.
  Make it a `const` for easy tuning; revisit after field testing.
- **R5 — Stale propagation.** Requires repositories to expose a stale signal through
  `PagingData`/`ApiResult`. *Open: confirm core-data contract surfaces this.*

## 14. Acceptance Criteria

AC-1. `SearchViewModel` and `DiscoverViewModel` exist in `feature-search` /
`feature-discover` under `com.testlogon.android.*`, Hilt-injected, exposing
`StateFlow<UiState>` and `Flow<PagingData<T>>`.

AC-2. Search input is debounced at 300 ms, ignores queries < 2 chars, and is
`distinctUntilChanged`; a burst of keystrokes produces exactly one fetch.

AC-3. A new query cancels the previous in-flight paging stream (verified via fake
repository call recording).

AC-4. Search results are categorized per `SearchEntity` (USERS/CONTENT/PLAYLISTS/TAGS)
with one cached `PagingData` stream each; tab switches do not refetch.

AC-5. Paging uses page size 20 with cursor advancement and correct
`endOfPaginationReached`.

AC-6. States are exhaustive and correct: Idle, Searching/Loading, Results/Content,
Empty (zero results on success), Error (retryable), and `stale` flag on cached data.

AC-7. `DiscoverViewModel` loads sections on init and supports `refresh()` with an
`isRefreshing` signal and source invalidation.

AC-8. Query text and selected tab survive configuration change via `SavedStateHandle`.

AC-9. Telemetry emits debounced, PII-free events; no raw query text is logged.

AC-10. Unit tests cover AC-2 through AC-8 with ≥ 90% coverage on the ViewModels and
helpers, all green in CI.

## 15. Definition of Done

- Both ViewModels and shared paging/query helpers implemented per §4, compiling on
  Kotlin 2.0.21 / AGP 8.7.3 / JDK 17.
- Repository interfaces (`SearchRepository`, `DiscoverRepository`, `SearchEntity`)
  placed in `core-data` and referenced by AND-182/AND-185.
- Full unit-test suite (§11) passing in CI; coverage gate met.
- Lint/detekt/ktlint clean; no new lint baseline entries.
- No raw query text in logs or analytics (verified by test or review).
- Code reviewed and merged to `android-port`; AND-182 and AND-185 unblocked for screen
  wiring.
- Open questions R1-R5 either resolved or filed as follow-up issues with owners.
