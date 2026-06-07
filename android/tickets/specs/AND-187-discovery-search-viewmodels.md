---
id: AND-187
title: Discovery/search ViewModels
milestone: M4
epic: E25
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** `src/api/endpoints/discovery.ts`,
  `src/api/endpoints/search.ts` (these files define the DTOs inline — there is no
  shared `types.ts` for these), and the screen behavior in
  `src/pages/search/SearchPage.tsx` and `src/pages/discover/DiscoverPage.tsx`.
  Canonical wire shapes are in the backend OpenAPI (`openapi.pretty.json`); note
  that `/ui/search` and the `/ui/discover/*` GETs have **untyped 200 responses** in
  the OpenAPI spec, so the **frontend TS interfaces are the authoritative contract**.
  (Corrected: earlier draft cited `frontend/src/...` and a shared `types.ts`; the
  real reference app roots at `src/` and the search/discover DTOs live in the
  endpoint files.)

## 3. Functional Requirements

FR-1. **Search debounce.** Free-text input from the search field is published to the
ViewModel as it changes. The ViewModel debounces by **300 ms** and ignores updates
that do not change the trimmed query. (300 ms is verified against both web search
surfaces, which use a 300 ms debounce — `SearchPage.tsx: useDebounce(inputValue, 300)`
and `DiscoverPage.tsx`.) Queries shorter than **2 characters** (after trim) reset to
the idle state and issue no network call. **Note (deviation from web):** the web
client actually fires the query at length **>= 1** (`enabled: debouncedQuery.length
>= 1` in both pages) and only records *search history* at length >= 2. The native
MIN_QUERY_LEN = 2 is a deliberate, mobile-friendly tightening (fewer round trips to
the flaky dev host), NOT a contract requirement; if parity is required, set
MIN_QUERY_LEN = 1.

FR-2. **Distinct + cancel-previous.** Consecutive identical trimmed queries do not
re-trigger a fetch (`distinctUntilChanged`). When a new query arrives, the in-flight
paging stream for the previous query is cancelled (`flatMapLatest`).

FR-3. **Multi-entity results.** `SearchViewModel` exposes results categorized by
entity type matching the web `/ui/search` taxonomy. **Corrected:** the earlier draft
listed `USERS/CONTENT/PLAYLISTS/TAGS`, which does not exist anywhere in the sources.
The real taxonomy (verified against `src/api/endpoints/search.ts:
GlobalSearchResponse.results` and `SearchPage.tsx: SEARCH_TABS`) is **nine buckets**:
`USERS`, `POSTS`, `CATALOG`, `FILES`, `MESSAGES`, `TICKETS`, `CONTACTS`, `VIDEOS`,
`CALENDAR` — plus an aggregate **"All"** tab. `users`, `posts`, `catalog`, `files`
are always present; `messages`, `tickets`, `contacts`, `videos`, `calendar` are
optional sections. `SearchEntity` must enumerate these nine. The currently selected
tab is part of UI state and selecting a tab does **not** re-issue the query — verified:
the web client makes a **single** `/ui/search` call and the tabs slice the one
response (`SearchPage.tsx` renders all tabs from `data.results.*`).

FR-4. **Paging — corrected to match the real wire shape.** The earlier draft assumed
cursor-paged, per-entity search streams; this is **wrong** for global search.
`/ui/search` is **not paged**: it returns ALL entity buckets in one response, each as
`SearchResultSection { items[], total_estimate, has_more }` with **no cursor** (verified
`src/api/endpoints/search.ts`). Therefore:
- **Global search (`SearchViewModel`):** a single repository call yields all buckets;
  the ViewModel exposes a `StateFlow` of the categorized result (sliced per
  `SearchEntity` for the tabs), NOT `Flow<PagingData<T>>`. `has_more` per section is
  surfaced as a "show more / refine" hint, since the endpoint exposes no continuation
  token. (If true Paging is later required it must go through a different endpoint;
  filed as R3.)
- **Discover user search (`/ui/discover/search`) and tag-post lists
  (`/ui/discover/tags/{tag}`)** ARE cursor-paged (`DiscoverySearchResponse.next_cursor`
  / `TagDiscoverResponse.next_cursor`, verified `src/api/endpoints/discovery.ts`). These
  legitimately use Paging 3 `PagingSource`s keyed by the opaque `next_cursor`.
- **Page size / prefetch:** `limit = 20` is verified for `/ui/discover/search`
  (`searchDiscoverUsers(q, limit = 20, cursor?)`). `prefetchDistance = 5` is an
  unverified ViewModel-layer default (no source dictates it). For global search the web
  default `limit` is **5–10** (`globalSearch(q, types, limit = 5)`, page calls 10), not
  20; a native `limit` of 20 is acceptable but is a deviation, not a verified value.

FR-5. **Discover load + refresh — corrected.** The earlier draft assumed a dynamic
section list from `GET /discovery/sections`. **No such endpoint exists.** Discover is
composed of **fixed, hard-coded rails** (verified `src/pages/discover/DiscoverPage.tsx`
+ `src/api/endpoints/discovery.ts`):
- `GET /ui/discover/suggested?limit=12` → `DiscoverySearchResponse` (Suggested For You)
- `GET /ui/discover/trending?limit=20` → `DiscoverySearchResponse` (Trending Creators)
- `GET /ui/discover/trending-tags?limit=20` → `TrendingTagsResponse` (Trending Tags)
- inline user search `GET /ui/discover/search?q=&limit=20&cursor=` → `DiscoverySearchResponse`

`DiscoverViewModel` loads the fixed rails on init and exposes `refresh()`
(pull-to-refresh) which re-requests the rails and invalidates the search/tag
`PagingSource`s. The "section list" is a static enum of rails, not a server response.
The rails (`suggested`/`trending`/`trending-tags`) are limit-only (NOT cursor-paged);
only the user-search and tag-post lists page.

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
    // CORRECTED: /ui/search is a single, non-paged call returning all buckets.
    // Returns the full categorized payload; the ViewModel slices per SearchEntity.
    suspend fun search(query: String, limit: Int = 20): ApiResult<GlobalSearchResult>
}

// CORRECTED taxonomy — matches src/api/endpoints/search.ts: GlobalSearchResponse.results
// and SearchPage.tsx: SEARCH_TABS (minus the synthetic "All" aggregate tab).
enum class SearchEntity { USERS, POSTS, CATALOG, FILES, MESSAGES, TICKETS, CONTACTS, VIDEOS, CALENDAR }

// GlobalSearchResult mirrors GlobalSearchResponse: query + per-entity sections
// (items, totalEstimate, hasMore) + partial flag.

interface DiscoverRepository {
    // CORRECTED: no server-driven section list. Rails are fixed; each returns users.
    suspend fun suggested(limit: Int = 12): ApiResult<List<DiscoveryUser>>
    suspend fun trending(limit: Int = 20): ApiResult<List<DiscoveryUser>>
    suspend fun trendingTags(limit: Int = 20): ApiResult<List<TrendingTag>>
    // Cursor-paged surfaces (next_cursor):
    fun searchUsers(query: String): Flow<PagingData<DiscoveryUser>>
    fun postsByTag(tag: String): Flow<PagingData<FeedPost>>
}
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

**Correction (paging model):** the `pagerFor`/`PagingData`-per-entity pattern shown
above reflected the original (incorrect) assumption that `/ui/search` is cursor-paged
per entity. Per §5/FR-4 the real `/ui/search` is a **single, non-paged** call. The
corrected pipeline is:

```kotlin
private val results: StateFlow<ApiResult<GlobalSearchResult>> = activeQuery
    .flatMapLatest { q ->
        if (q.isEmpty()) flowOf(ApiResult.Success(GlobalSearchResult.empty()))
        else flow { emit(ApiResult.Loading); emit(repository.search(q)) }
    }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ApiResult.Loading)

// Per-tab item lists are pure slices of the one response; switching tabs never
// re-issues the query (matches SearchPage.tsx). has_more per bucket is surfaced as a
// "refine" hint, not a continuation token.
fun itemsFor(entity: SearchEntity): List<SearchResultItem> =
    (results.value as? ApiResult.Success)?.data?.section(entity)?.items.orEmpty()
```

`flatMapLatest` still gives cancel-previous semantics on the single call. The
`Flow<PagingData<T>>` contract is retained ONLY for the genuinely cursor-paged
**discover** surfaces (`searchUsers`, `postsByTag`), not for global search.

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

**Correction:** there is no `repository.sections()` endpoint (see FR-5/§5). `load()`
instead fans out to the three **fixed rails** — `repository.suggested()`,
`repository.trending()`, `repository.trendingTags()` — (e.g. via
`coroutineScope { awaitAll }`), maps each `ApiResult` into `DiscoverUiState`, and
exposes `cachedIn` paging flows only for the cursor-paged `searchUsers(query)` and
`postsByTag(tag)` surfaces. `refresh()` re-runs `load()` (re-requesting the rails) and
emits `isRefreshing = true` while in flight, invalidating the paged sources. The
pseudocode signatures `rail(sectionId)` / `sections()` above are superseded by the
corrected `DiscoverRepository` in §4.

### 4.3 Threading & cancellation

All work runs on `viewModelScope` (Dispatchers.Main.immediate by default; repository
suspends move to IO). `flatMapLatest` guarantees previous query streams are cancelled.
No manual thread management.

## 5. API Contract

AND-187 issues **no new endpoints**; it consumes repository interfaces. Wire calls
are owned by AND-182 (`discovery`) and AND-185 (`search`). Documented here for the
contract the ViewModels assume. **The endpoints/shapes below have been corrected
against the OpenAPI index and the frontend reference app** (the earlier draft cited
non-existent `/search` and `/discovery/sections` paths). The `/ui/search` and
`/ui/discover/*` 200 bodies are **untyped in OpenAPI**, so the frontend TS interfaces
are authoritative for field shapes.

**Global search — verified `GET /ui/search` (`op=global_search_ui_search_get`):**

```
GET /ui/search?q={query}&types={csv}&limit={n}
```
Query params: `q`, `types` (optional CSV filter), `limit` (web default 5–10).
**There is no `cursor`/`type`-per-call and no pagination.** Response (single payload
with all buckets; `src/api/endpoints/search.ts: GlobalSearchResponse`):
```json
{
  "query": "jdoe",
  "results": {
    "users":   { "items": [ { "type": "user", "id": "u_123", "title": "jdoe", "snippet": "...", "url": "/u/u_123", "thumbnail_url": "...", "meta": {} } ], "total_estimate": 12, "has_more": true },
    "posts":   { "items": [], "total_estimate": 0, "has_more": false },
    "catalog": { "items": [], "total_estimate": 0, "has_more": false },
    "files":   { "items": [], "total_estimate": 0, "has_more": false },
    "messages": { "items": [], "total_estimate": 0, "has_more": false },
    "tickets":  { "items": [], "total_estimate": 0, "has_more": false },
    "contacts": { "items": [], "total_estimate": 0, "has_more": false },
    "videos":   { "items": [], "total_estimate": 0, "has_more": false },
    "calendar": { "items": [], "total_estimate": 0, "has_more": false }
  },
  "partial": false
}
```
`SearchResultItem` fields: `type, id, title, snippet, url` (required), `thumbnail_url?`,
`meta?`. (Not `kind/subtitle/imageUrl` as the earlier draft claimed.)

**Discover — verified `/ui/discover/*` (`src/api/endpoints/discovery.ts`):**

```
GET /ui/discover/suggested?limit=12        -> DiscoverySearchResponse
GET /ui/discover/trending?limit=20         -> DiscoverySearchResponse
GET /ui/discover/trending-tags?limit=20    -> TrendingTagsResponse
GET /ui/discover/search?q=&limit=20&cursor= -> DiscoverySearchResponse   (cursor-paged)
GET /ui/discover/tags/{tag}?limit=20&cursor= -> TagDiscoverResponse       (cursor-paged)
```
```json
// DiscoverySearchResponse
{
  "items": [ { "user_id": "u_1", "display_name": "Jane", "profile_photo_url": "...", "description": "...", "follower_count": 42, "is_following": false, "is_followed_by": false, "is_mutual": false } ],
  "next_cursor": "eyJvIjoyMH0=",
  "total_estimate": 137
}
```
Discover "items" are **users** (`DiscoveryUser`), not generic cards. Only
`/ui/discover/search` and `/ui/discover/tags/{tag}` carry `next_cursor`; the rails are
limit-only.

Auth rides on cookies + `X-CSRF-Token` taken from the `ui_csrf` cookie — **verified**
in `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
On a 401 for an authenticated user, the client performs **exactly one**
`POST /ui/session/refresh` (`credentials: include`, deduped via a shared
`refreshPromise`) then retries the original request once; a second 401 logs the user
out (`client.ts: refreshSession` / 401 branch — verified). Endpoint exists in the
index: `POST /ui/session/refresh` (`op=ui_session_refresh_ui_session_refresh_post`).
These GETs are idempotent. **Unverified:** the "bounded backoff-retry policy (~20s
timeout)" attributed to AND-027 is NOT present in the web client (it does one refresh+
retry, no backoff loop); treat it as an assumed Android OkHttp-layer behavior owned by
AND-027, not a web-contract fact. The ViewModel does not implement HTTP concerns; it
observes the resulting load state.

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

- **R1 — Entity taxonomy drift.** *RESOLVED by review.* The verified `/ui/search`
  taxonomy is the nine buckets `users/posts/catalog/files/messages/tickets/contacts/
  videos/calendar` (+ aggregate "All"), per `src/api/endpoints/search.ts:
  GlobalSearchResponse` and `SearchPage.tsx: SEARCH_TABS`. Define `SearchEntity` in
  `core-data` as the single source and have AND-185 import it. The earlier
  `users/content/playlists/tags` set was incorrect and has been removed.
- **R2 — Cursor vs. offset paging.** *RESOLVED by review.* Global search is **not paged
  at all** (single response, only `has_more`). The discover user-search and tag-post
  endpoints use an opaque `next_cursor` (verified `DiscoverySearchResponse.next_cursor`
  / `TagDiscoverResponse.next_cursor`), so those `PagingSource`s key on `String?` cursor.
- **R3 — Per-entity vs. combined search call.** *RESOLVED by review.* Verified: a
  **single** `/ui/search` call returns all entities in one payload (`SearchPage.tsx`
  makes one `globalSearch` call and slices `data.results.*`). Do NOT model global search
  as per-entity Paging streams or a `RemoteMediator`. *Remaining open:* if a future
  "view all results for one type" surface needs pagination, no current endpoint supports
  it — would need a backend addition.
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

AC-4. Search results are categorized per `SearchEntity`
(USERS/POSTS/CATALOG/FILES/MESSAGES/TICKETS/CONTACTS/VIDEOS/CALENDAR, + aggregate
"All"); a single `/ui/search` response is sliced per tab and tab switches do **not**
re-issue the query. (Corrected from the prior USERS/CONTENT/PLAYLISTS/TAGS +
per-entity-Paging wording.)

AC-5. The cursor-paged **discover** surfaces (`/ui/discover/search`,
`/ui/discover/tags/{tag}`) use Paging 3 with `limit=20`, opaque `next_cursor`
advancement, and `endOfPaginationReached` when `next_cursor` is null. (Global search is
non-paged and exempt from this AC.)

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI spec
(`reference/openapi.pretty.json`), and the frontend reference app under
`reference/src/`.

1. **Search debounce is 300 ms.** VERIFIED. `src/pages/search/SearchPage.tsx:
   const debouncedQuery = useDebounce(inputValue, 300)`; `src/pages/discover/
   DiscoverPage.tsx: setTimeout(() => setDebouncedQuery(...), 300)`.
2. **Global search endpoint is `GET /ui/search` with params `q, types, limit`.**
   VERIFIED (was CORRECTED from `GET /search?...&type=&cursor=&limit=20`). OpenAPI
   `GET /ui/search | op=global_search_ui_search_get | params=q,types,limit,...`;
   `src/api/endpoints/search.ts: globalSearch -> api.get("/ui/search", {q, limit, types?})`.
3. **`/ui/search` returns a single payload with all entity buckets; it is NOT paged
   and has no cursor.** VERIFIED (CORRECTED). `src/api/endpoints/search.ts:
   GlobalSearchResponse` = `{query, results:{users,posts,catalog,files,messages?,
   tickets?,contacts?,videos?,calendar?}, partial?}`; each bucket is
   `SearchResultSection {items, total_estimate, has_more}` (no cursor). `SearchPage.tsx`
   issues one `globalSearch` call and slices all tabs from `data.results.*`.
4. **Search entity taxonomy = users/posts/catalog/files/messages/tickets/contacts/
   videos/calendar (+ "All").** VERIFIED (CORRECTED from users/content/playlists/tags).
   `src/api/endpoints/search.ts: SearchResultType` + `GlobalSearchResponse.results`;
   `SearchPage.tsx: SEARCH_TABS`.
5. **`SearchResultItem` fields = `type,id,title,snippet,url` (req) + `thumbnail_url?,
   meta?`.** VERIFIED (CORRECTED from `kind/subtitle/imageUrl/total/next_cursor`).
   `src/api/endpoints/search.ts: interface SearchResultItem`.
6. **Tab selection does not re-issue the query.** VERIFIED. `SearchPage.tsx`
   `handleTabChange` only sets local `activeTab`; no new `useQuery` keyed on tab.
7. **No `GET /discovery/sections` or `/discovery/sections/{id}/items` endpoint;
   Discover is fixed rails.** VERIFIED (CORRECTED). Absent from `openapi.index.txt`
   (grep for `discover` lists only `/ui/discover/{creators,profile,reindex,search,
   suggested,tags,trending,trending-tags}`). `src/pages/discover/DiscoverPage.tsx`
   composes `getSuggestedUsers`, `getTrendingCreators`, `getTrendingTags`, +
   `searchDiscoverUsers`.
8. **Discover endpoints + params.** VERIFIED. OpenAPI/index +
   `src/api/endpoints/discovery.ts`: `GET /ui/discover/suggested (limit)`,
   `GET /ui/discover/trending (limit)`, `GET /ui/discover/trending-tags (limit)`,
   `GET /ui/discover/search (q,limit,cursor)`, `GET /ui/discover/tags/{tag}
   (limit,cursor)`.
9. **Discover items are users (`DiscoveryUser`), not generic cards.** VERIFIED
   (CORRECTED). `src/api/endpoints/discovery.ts: interface DiscoveryUser` (user_id,
   display_name, profile_photo_url?, description?, follower_count, is_following, ...).
10. **Only discover user-search & tag-posts are cursor-paged (`next_cursor`); the
    rails are limit-only.** VERIFIED. `DiscoverySearchResponse.next_cursor` +
    `TagDiscoverResponse.next_cursor` present; `suggested/trending/trending-tags`
    take only `limit`. (`src/api/endpoints/discovery.ts`.)
11. **Page size `limit=20` for `/ui/discover/search`.** VERIFIED. `src/api/endpoints/
    discovery.ts: searchDiscoverUsers = (q, limit = 20, cursor?)`.
12. **Auth uses cookies + `X-CSRF-Token` read from the `ui_csrf` cookie.** VERIFIED.
    `src/api/client.ts: const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token",
    csrf)`.
13. **On 401 (authenticated), client does exactly one `POST /ui/session/refresh`
    then retries once; second 401 logs out.** VERIFIED. `src/api/client.ts:
    refreshSession()` + the 401 branch (deduped `refreshPromise`, single retry,
    `logout("session_expired")`). OpenAPI: `POST /ui/session/refresh |
    op=ui_session_refresh_ui_session_refresh_post`.
14. **FastAPI validation errors are `{detail: [{loc, msg, type}]}` (422).** VERIFIED.
    OpenAPI `components.schemas.HTTPValidationError` -> `ValidationError {loc, msg,
    type}` (`openapi.pretty.json` lines ~37133 and ~80337). `detail` may also be a
    plain string or an object with `code`/`msg` — `src/api/client.ts:
    normalizeErrorDetail` handles string | array-of-{msg} | object-with-msg/code.
15. **Network failure surfaces as a distinct error (`ApiError(0, "Network error")`).**
    VERIFIED. `src/api/client.ts` catch around `fetch` throws `ApiError(0, ...)`;
    supports the offline/flaky-host path.
16. **MIN_QUERY_LEN = 2 (native).** UNVERIFIED-ASSUMPTION / deviation. Web fires at
    `length >= 1` (`SearchPage.tsx`/`DiscoverPage.tsx: enabled: ...length >= 1`); 2 is a
    native choice, not a contract value.
17. **PAGE_SIZE 20 for global search & `prefetchDistance = 5`.** UNVERIFIED-ASSUMPTION.
    Global search has no pagination; web `globalSearch` default `limit` is 5–10, not 20.
    `prefetchDistance = 5` has no source.
18. **Bounded backoff-retry (~20s timeout) for idempotent GETs at the OkHttp layer.**
    UNVERIFIED-ASSUMPTION (attributed to AND-027). Web client does a single refresh+
    retry, no backoff loop — not a web-contract fact.
19. **`stale = true` flag from a Room-backed cache surfaced through the repository.**
    UNVERIFIED-ASSUMPTION. No cache/stale concept exists in the web client (it uses
    react-query in-memory `staleTime`); this is an Android-side design owned by
    AND-182/AND-185/core-data (see R5).
20. **`ApiResult` sealed type + localized FastAPI `detail` mapping in core-network.**
    UNVERIFIED-ASSUMPTION (Android `core-network`/AND-027 internal; the *shape* of
    `detail` it must map is verified — see claim 14).
21. **Hilt/`@HiltViewModel`, `SavedStateHandle`, Paging 3 `cachedIn`, `flatMapLatest`
    cancel-previous, `distinctUntilChanged`, `StateFlow`/`stateIn`.** Framework refs
    (no app-source verification needed): AndroidX ViewModel/Paging/Hilt + kotlinx
    coroutines Flow operators — `developer.android.com/topic/libraries/architecture/
    viewmodel`, `developer.android.com/topic/libraries/architecture/paging/v3-overview`,
    `developer.android.com/training/dependency-injection/hilt-jetpack`.

### Corrections made

- §2: web reference path `frontend/src/...` + shared `types.ts` -> `src/api/...`
  with DTOs defined inline in the endpoint files; noted untyped OpenAPI 200 bodies.
- §5 / FR-3 / FR-4 / FR-5 / §4: search endpoint `GET /search?type=&cursor=` ->
  `GET /ui/search?q=&types=&limit=` (single, non-paged, all-buckets response).
- Entity taxonomy `USERS/CONTENT/PLAYLISTS/TAGS` -> nine-bucket taxonomy
  (`USERS/POSTS/CATALOG/FILES/MESSAGES/TICKETS/CONTACTS/VIDEOS/CALENDAR`).
- `SearchResultItem` field names `kind/subtitle/imageUrl/total/next_cursor` ->
  `type/title/snippet/url/thumbnail_url/meta` with `SearchResultSection.total_estimate
  /has_more`.
- Discover `GET /discovery/sections(+/{id}/items)` -> fixed rails
  `/ui/discover/{suggested,trending,trending-tags,search,tags/{tag}}`; discover items
  are `DiscoveryUser`.
- `DiscoverRepository.sections()/rail()` and `SearchRepository.search(...):
  Flow<PagingData>` interfaces rewritten to match the real shapes.
- §13: R1/R2/R3 marked resolved with verified facts.
- §5: "bounded backoff-retry (~20s)" relabeled as an AND-027 assumption (not a web
  fact); CSRF/refresh behavior cited to `client.ts`.

### Open assumptions

- **MIN_QUERY_LEN = 2 / global PAGE_SIZE 20 / prefetchDistance = 5** — native tuning
  values with no source; web uses len>=1 and limit 5–10. Confirm desired parity.
- **`stale`/offline cache flag** — depends on a core-data/Room cache contract
  (AND-182/AND-185) that does not exist in the web reference; cannot be verified here.
- **AND-027 internals** — `ApiResult`, error-mapper localization, cookie jar, and any
  backoff/timeout policy are owned by AND-027 and not observable in the reference app
  (only the *wire* behavior — CSRF header, single refresh+retry, error shapes — is
  verified).
- **AND-182/AND-185 repository implementations** — this ticket defines the interfaces;
  whether the dependency tickets adopt the corrected nine-bucket taxonomy / non-paged
  global search must be confirmed when they land.

## 17. Test Plan

All cases are JVM/Robolectric unit tests on the local runner unless noted; this ticket
is unit-test-only by acceptance (§11). Two cases that exercise real-network flakiness
and one a11y-state case are noted with their CI target. "Repo fake" = an in-memory
fake implementing the corrected `SearchRepository`/`DiscoverRepository`.

- **TC-AND-187-01** — Debounce coalesces a keystroke burst.
  - Type: unit (Robolectric/JVM, `runTest` + `StandardTestDispatcher`).
  - Target: JVM unit runner.
  - Preconditions: `SearchViewModel` with repo fake; `advanceTimeBy` control.
  - Steps: emit "a","ab","abc" within 300 ms; `advanceTimeBy(299)` assert no call;
    `advanceTimeBy(1)`.
  - Expected: exactly one `repository.search("abc", ...)`; intermediate queries never hit
    the repo.
  - Traces: AC-2.

- **TC-AND-187-02** — Min-length gate + distinctUntilChanged.
  - Type: unit. Target: JVM unit runner.
  - Preconditions: repo fake.
  - Steps: set query "a" (len 1) and advance; then set "ab" twice (same trimmed value)
    and advance.
  - Expected: len-1 query yields `SearchPhase.Idle` and **no** repo call; "ab" triggers
    exactly one call; the duplicate does not re-invoke the repo.
  - Traces: AC-2.

- **TC-AND-187-03** — New query cancels the in-flight one (flatMapLatest).
  - Type: unit. Target: JVM unit runner.
  - Preconditions: repo fake whose `search` suspends until released; records latest
    active query.
  - Steps: submit "abc" (suspends), then submit "abcd" before "abc" resolves; release
    both.
  - Expected: only the "abcd" result reaches `uiState`; the abandoned "abc" emission is
    dropped; fake records "abcd" as the latest/winning query.
  - Traces: AC-3.

- **TC-AND-187-04** — Single call populates all nine buckets; tab switch does not refetch.
  - Type: unit. Target: JVM unit runner.
  - Preconditions: repo fake returns a `GlobalSearchResult` with items in several
    buckets; call counter.
  - Steps: run query "jdoe"; read `itemsFor(USERS)`, then `onTabSelected(POSTS)` and read
    `itemsFor(POSTS)`, then `CONTACTS`.
  - Expected: `repository.search` invoked **once**; each tab reads the correct slice;
    "All" aggregates counts across buckets; no extra calls on tab switches.
  - Traces: AC-4.

- **TC-AND-187-05** — Empty vs error distinction for global search.
  - Type: unit. Target: JVM unit runner.
  - Preconditions: repo fake.
  - Steps: (a) return all-empty buckets on success; (b) return `ApiResult.Error`
    (timeout-category).
  - Expected: (a) `SearchPhase.Empty`, never Error; (b) `SearchPhase.Error(retryable=
    true)` with a normalized message; no raw exception text.
  - Traces: AC-6.

- **TC-AND-187-06** — 422 validation error is normalized (real error shape).
  - Type: contract / unit with MockWebServer. Target: JVM unit runner (Robolectric +
    `okhttp3.mockwebserver`).
  - Preconditions: a real repository wired to OkHttp/Retrofit against MockWebServer (or
    the core-network error mapper under test).
  - Steps: enqueue HTTP 422 body `{"detail":[{"loc":["query","q"],"msg":"field
    required","type":"value_error"}]}` for `/ui/search`.
  - Expected: mapped to a single user-safe string ("field required"), surfaced as
    `SearchPhase.Error`; matches the `HTTPValidationError`/`ValidationError` schema and
    `client.ts: normalizeErrorDetail`.
  - Traces: AC-6, AC-9.

- **TC-AND-187-07** — Flaky-host / offline path surfaces retryable error then recovers.
  - Type: contract / MockWebServer (and one real-network smoke variant). Target: JVM
    unit runner for the deterministic case; the **physical device (Samsung Galaxy A15,
    SM-A156U, API 34)** for the real plaintext-host smoke against
    `http://18.222.237.167:8000` (real network + cleartext traffic behavior). Emulator
    `test35` acceptable as fallback but the physical device is preferred for true
    cellular/cleartext timeout behavior.
  - Preconditions: MockWebServer that first drops/times out, then 200s.
  - Steps: trigger query; first attempt times out; user invokes `retry()`/re-query;
    second attempt succeeds.
  - Expected: first -> `Error(retryable=true)`; on retry -> `Results`; existing items
    retained on an `append`-style failure for the paged discover surfaces.
  - Traces: AC-6.

- **TC-AND-187-08** — Discover loads fixed rails on init; refresh toggles isRefreshing.
  - Type: unit. Target: JVM unit runner.
  - Preconditions: `DiscoverViewModel` + repo fake returning suggested/trending/
    trending-tags.
  - Steps: construct VM (init load); then call `refresh()`.
  - Expected: init populates the three rails -> `DiscoverPhase.Content`; `refresh()` sets
    `isRefreshing=true` while in flight then false; rails re-requested and paged sources
    invalidated. No call to any (non-existent) `sections()`.
  - Traces: AC-7.

- **TC-AND-187-09** — Discover error mapping.
  - Type: unit. Target: JVM unit runner.
  - Preconditions: repo fake returns `ApiResult.Error` for a rail.
  - Steps: construct VM with failing `suggested()`.
  - Expected: `DiscoverPhase.Error(retryable=true)`, normalized message; partial-rail
    failure handling deterministic (documented policy: any required-rail failure ->
    Error).
  - Traces: AC-6, AC-7.

- **TC-AND-187-10** — Cursor paging for `/ui/discover/search`.
  - Type: unit (Paging) with `PagingData.asSnapshot {}` / `AsyncPagingDataDiffer`.
    Target: JVM unit runner.
  - Preconditions: fake `PagingSource` returning `next_cursor` then null.
  - Steps: collect first page (limit 20), trigger append using returned cursor, then a
    page with `next_cursor=null`.
  - Expected: page size 20; cursor advances; `endOfPaginationReached=true` when
    `next_cursor` is null; items accumulate in order.
  - Traces: AC-5.

- **TC-AND-187-11** — SavedStateHandle restores query + selected tab across config change.
  - Type: unit. Target: JVM unit runner.
  - Preconditions: pre-seed `SavedStateHandle` with `search.query="abc"`,
    `search.tab="POSTS"`.
  - Steps: construct `SearchViewModel`; read initial `uiState`.
  - Expected: `query="abc"`, `selectedTab=POSTS`; on later edits the handle is updated so
    a re-creation restores the latest values.
  - Traces: AC-8.

- **TC-AND-187-12** — Telemetry is debounced and PII-free; no raw query logged.
  - Type: unit (with a fake analytics/logger sink). Target: JVM unit runner.
  - Preconditions: fake analytics recorder + log capture; debug build flags.
  - Steps: type a burst then settle; inspect emitted events and logs.
  - Expected: one `search_query_executed` per executed query (not per keystroke) with
    `query_length` + `entity` only; no event/log field contains the raw query string;
    error events carry a coded category, no raw message.
  - Traces: AC-9.

- **TC-AND-187-13** — Distinct/announceable states for accessibility (live regions).
  - Type: unit (state-contract) + optional Compose-UI smoke. Target: JVM unit runner for
    the state assertions; emulator `test35` (API 35) for the optional Compose
    `onNodeWithContentDescription`/live-region smoke if a harness screen is available
    (UI ownership is AND-182/AND-185, so this stays light here).
  - Preconditions: VM with repo fake driving each phase.
  - Steps: drive Idle -> Searching -> Results -> Empty -> Error transitions; assert each
    is a distinct, exhaustive `SearchPhase`/`DiscoverPhase` value.
  - Expected: every transition produces a single distinct state the UI can map to a
    TalkBack live-region announcement; no ambiguous/overlapping states.
  - Traces: AC-6, AC-1.

- **TC-AND-187-14** — Coverage gate on ViewModels + helpers.
  - Type: unit (coverage). Target: JVM unit runner in CI.
  - Preconditions: full suite (TC-01..13) green.
  - Steps: run Jacoco/Kover over `feature-search`, `feature-discover`, and the
    debounce/paging helpers.
  - Expected: >= 90% line coverage on both ViewModels and helpers; CI gate passes.
  - Traces: AC-10.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (VMs exist, Hilt, StateFlow/Paging contracts) | TC-13 (state contract); compile/wiring asserted across TC-04, TC-08 |
| AC-2 (debounce 300 ms, <2 chars, distinct) | TC-01, TC-02 |
| AC-3 (new query cancels previous) | TC-03 |
| AC-4 (nine-bucket taxonomy, single call, no refetch on tab) | TC-04 |
| AC-5 (cursor paging, size 20, endOfPaginationReached) | TC-10 |
| AC-6 (exhaustive states: Empty/Error/stale) | TC-05, TC-06, TC-07, TC-09, TC-13 |
| AC-7 (discover init load + refresh/isRefreshing) | TC-08, TC-09 |
| AC-8 (query + tab survive config change) | TC-11 |
| AC-9 (debounced, PII-free telemetry; no raw query) | TC-06, TC-12 |
| AC-10 (>= 90% coverage, green CI) | TC-14 (depends on all above) |
