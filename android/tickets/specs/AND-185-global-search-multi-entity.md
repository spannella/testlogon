---
id: AND-185
title: Global search (multi-entity)
milestone: M4
epic: E25
priority: P0
size: L
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-185 — Global search (multi-entity)

## 1. Overview & Goal

This ticket delivers a single, app-wide global search experience that queries the
TestLogon backend across multiple entity domains (users, content, and other
indexed types) from one query box and presents results grouped into per-entity
tabs. The web reference implements this in `frontend/src/api/endpoints/search.ts`;
this ticket ports that capability natively to the Android app under the canonical
namespace `com.testlogon.android`.

The goal is a `feature-search` module that owns a search route reachable from the
top-level app scaffold (search icon in the global app bar). A user types a query,
the app debounces input, issues a single multi-entity search request, and renders
categorized results: an "All" overview tab plus one tab per entity category
(Users, Content, …). Each result row deep-links to the relevant detail screen.
The screen must remain responsive and correct against the unreliable plaintext dev
backend, surfacing loading, empty, error, and offline/stale states distinctly.

Success means: a non-empty query returns categorized results that are correctly
bucketed by entity type; per-tab counts match rendered rows; the feature is fully
unit- and instrumentation-tested; and the search request shape matches the OpenAPI
contract verified against `/openapi.json`.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/search.ts` (request/response
  shape, query params, entity categories), shared types in
  `frontend/src/api/types.ts`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (PLAINTEXT HTTP, unreliable). Contract of record is `/openapi.json` — confirm
  the exact search path and category enum before implementation; this spec assumes
  `GET /ui/search` returning a categorized payload (see §5).
- **Dependency AND-027 (AuthApi / session endpoints):** establishes the
  cookie-based session, persistent cookie jar, `ui_csrf` → `X-CSRF-Token`
  handling, and the single-shot `POST /ui/session/refresh`-then-retry-on-401
  behavior in `core-network`. Global search is an authenticated call and reuses
  that OkHttp stack and `ApiResult<T>` mapping. AND-185 must not re-implement auth.
- **Module layering:** `app -> feature-search -> core-network, core-model,
  core-ui, core-data, core-testing`. ViewModels expose `StateFlow<UiState>`.
- **Detail destinations** (user profile, content detail) are owned by their
  respective feature tickets; AND-185 consumes their Navigation-Compose routes via
  a small navigation contract (see §4) and does not define their screens.

## 3. Functional Requirements

FR-1. A search entry point (search icon) in the global app bar navigates to the
`search` route. The route accepts an optional `q` argument so deep links and
process-death restoration can pre-fill the query.

FR-2. The search screen shows a focused text field at top with a leading search
icon, a clear (×) affordance when non-empty, and the soft keyboard auto-shown on
first composition.

FR-3. Input is debounced (300 ms) and trimmed. Queries shorter than 2 characters
do not trigger a network call; the screen shows a neutral "Type to search" prompt.

FR-4. A query of length ≥ 2 issues exactly one multi-entity search request. While
in flight, a loading indicator is shown; superseded requests are cancelled (latest
query wins).

FR-5. Results are presented as tabs: a leading "All" tab aggregating top results
across categories, followed by one tab per entity category returned by the backend
(e.g., Users, Content). Each non-"All" tab header shows its result count.

FR-6. The "All" tab renders sectioned results (a small capped slice per category,
default 3, with a "See all N" affordance that switches to that category's tab).
Per-category tabs render the full result list for that category, paged if the
backend returns pagination (Paging 3) — see §6.

FR-7. Each result row renders an entity-appropriate cell: avatar/title/subtitle for
users; thumbnail/title/snippet for content. Tapping a row navigates to that
entity's detail route.

FR-8. Empty query state, zero-results state ("No results for \"<q>\""), error
state (with Retry), and offline/stale state are visually distinct.

FR-9. Recent queries: the last 8 successful non-empty queries are persisted in
DataStore and shown as tappable chips when the field is empty. A "Clear" action
removes them.

FR-10. Rotation, navigating away and back, and process death preserve the current
query and selected tab.

## 4. Technical Design

New module `feature-search` (Kotlin 2.0.21, Compose + Material 3, Hilt/KSP).

Navigation contract (consumed, not defined here):

```kotlin
// core-ui or app navigation graph
const val SEARCH_ROUTE = "search?q={q}"
fun NavController.navigateToSearch(query: String? = null)

// Destinations AND-185 routes into (provided by other feature modules):
interface SearchNavigator {
    fun openUser(navController: NavController, userId: String)
    fun openContent(navController: NavController, contentId: String)
}
```

ViewModel:

```kotlin
@HiltViewModel
class SearchViewModel @Inject constructor(
    private val repository: SearchRepository,
    private val recentQueries: RecentQueriesStore,
    savedState: SavedStateHandle,
) : ViewModel() {
    val query: StateFlow<String>              // restored from SavedStateHandle["q"]
    val selectedTab: StateFlow<SearchTab>     // restored from SavedStateHandle
    val uiState: StateFlow<SearchUiState>
    val recents: StateFlow<List<String>>

    fun onQueryChange(text: String)
    fun onTabSelected(tab: SearchTab)
    fun onResultClick(result: SearchResult)
    fun onRetry()
    fun clearQuery()
    fun clearRecents()
}
```

State and models (in `core-model` where shared, `feature-search` for UI-only):

```kotlin
sealed interface SearchUiState {
    data object Idle : SearchUiState                 // empty/short query
    data object Loading : SearchUiState
    data class Success(
        val query: String,
        val categories: List<SearchCategory>,        // ordered; drives tabs
        val totalCount: Int,
        val stale: Boolean = false,                  // served from cache
    ) : SearchUiState
    data class Empty(val query: String) : SearchUiState
    data class Error(val message: String, val retryable: Boolean) : SearchUiState
}

enum class SearchEntityType { USER, CONTENT, OTHER }

data class SearchCategory(
    val type: SearchEntityType,
    val label: String,
    val count: Int,
    val items: List<SearchResult>,
)

sealed interface SearchResult {
    val id: String
    data class User(override val id: String, val displayName: String,
                    val username: String, val avatarUrl: String?) : SearchResult
    data class Content(override val id: String, val title: String,
                       val snippet: String?, val thumbnailUrl: String?) : SearchResult
}

sealed interface SearchTab {
    data object All : SearchTab
    data class Category(val type: SearchEntityType) : SearchTab
}
```

Debounce/cancellation is implemented in the ViewModel:

```kotlin
val uiState: StateFlow<SearchUiState> = query
    .map { it.trim() }
    .distinctUntilChanged()
    .debounce(300)
    .flatMapLatest { q ->
        if (q.length < 2) flowOf(SearchUiState.Idle)
        else flow {
            emit(SearchUiState.Loading)
            emit(repository.search(q).toUiState(q))
        }
    }
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), SearchUiState.Idle)
```

`flatMapLatest` guarantees the latest query wins and cancels in-flight work (FR-4).

Repository (`core-data` interface, `feature-search`/`core-data` impl):

```kotlin
interface SearchRepository {
    suspend fun search(query: String, limit: Int = 20): ApiResult<SearchResponse>
}
```

Compose surface: `SearchScreen` (route binding) → `SearchContent` (stateless,
takes `SearchUiState` + callbacks) → `SearchBar`, `SearchTabRow` (Material 3
`PrimaryScrollableTabRow`), `AllResultsList`, `CategoryResultsList`, result-cell
composables. Images via Coil `AsyncImage`. Stateless composables enable Compose UI
tests and previews per state.

## 5. API Contract

Authoritative source is `/openapi.json`; confirm the path and category enum before
coding. Expected contract (mirrors `search.ts`):

```kotlin
interface SearchApi {
    @GET("ui/search")
    suspend fun search(
        @Query("q") query: String,
        @Query("types") types: String? = null,   // CSV, e.g. "user,content"; null = all
        @Query("limit") limit: Int = 20,
    ): Response<SearchResponseDto>
}
```

Request: `GET /ui/search?q=jane&limit=20` with session cookies and
`X-CSRF-Token` header injected by the shared OkHttp interceptor from AND-027.

Response `200` (Moshi DTO):

```json
{
  "query": "jane",
  "total": 12,
  "categories": [
    {
      "type": "user",
      "label": "Users",
      "count": 8,
      "items": [
        { "id": "u_123", "display_name": "Jane Doe",
          "username": "jdoe", "avatar_url": "https://…/a.jpg" }
      ]
    },
    {
      "type": "content",
      "label": "Content",
      "count": 4,
      "items": [
        { "id": "c_987", "title": "Jane's stream",
          "snippet": "…", "thumbnail_url": "https://…/t.jpg" }
      ]
    }
  ]
}
```

DTOs use `@Json(name = "...")` for snake_case mapping and a `SearchItemDto`
discriminated by `type`; unknown `type` values map to `SearchEntityType.OTHER` and
render a generic cell (forward-compatibility). DTO→domain mapping lives in a pure
`SearchMapper` for unit testing.

Errors follow the FastAPI `detail` convention handled centrally in `core-network`
(`detail` may be `string | [{msg}] | {code,...}`); the repository surfaces them as
`ApiResult.Error` with a user-facing message. This endpoint is an authenticated
idempotent GET and is therefore eligible for the bounded backoff retry policy and
the single `POST /ui/session/refresh`-on-401 retry defined by AND-027.

## 6. Data & State Management

- **Single source of truth:** `SearchViewModel.uiState: StateFlow<SearchUiState>`,
  derived reactively from `query`. UI never calls the repository directly.
- **Restoration:** `query` and `selectedTab` are persisted in `SavedStateHandle`
  so rotation and process death restore the screen (FR-10). The `q` nav argument
  seeds the initial value.
- **Pagination:** when a category's `count` exceeds the returned `items.size`, the
  per-category tab uses Paging 3 (`Pager` + `PagingSource<Int, SearchResult>`
  keyed by `(query, type, offset)`) to load further pages via `limit`/`offset`
  params. The "All" tab is non-paged (capped slice only).
- **Caching (stale state):** the most recent successful `SearchResponse` per query
  is held in an in-memory LRU (size 16) in the repository so back-navigation is
  instant. Optional Room persistence is out of scope for AND-185 (results are
  volatile); if the network fails but an LRU entry exists for the query, emit
  `Success(stale = true)` so the UI can show a "showing cached results" banner.
- **Recent queries:** `RecentQueriesStore` backed by DataStore Preferences (key
  `recent_search_queries`, JSON-encoded ordered list, max 8, de-duplicated,
  most-recent-first). Persisted on a successful non-empty search.

## 7. Error Handling & Resilience

The dev backend is unreliable and plaintext; design accordingly.

- **Timeouts:** rely on the shared OkHttp client's ~20s call timeout (AND-027).
  On timeout, map to `SearchUiState.Error(retryable = true)`.
- **Retry policy:** because search is an idempotent GET, the shared bounded
  backoff retry for idempotent GETs applies. The UI also offers an explicit Retry
  button which re-emits the current query through the same flow.
- **401:** handled transparently by the AND-027 interceptor (one
  `POST /ui/session/refresh`, then retry). If refresh fails, the call returns an
  auth error and the screen routes to re-authentication per app-level policy.
- **Offline:** when the request fails due to no connectivity and an LRU cache hit
  exists, show stale results with a banner; otherwise show
  `Error("You're offline", retryable = true)`.
- **Empty vs error:** a successful `200` with `total == 0` maps to
  `Empty(query)`, never `Error`.
- **Race safety:** `flatMapLatest` cancels superseded requests so a slow earlier
  response can never overwrite a newer query's results.

## 8. Security & Privacy

- All requests ride the existing authenticated, cookie-based session and the
  persistent cookie jar from AND-027; no credentials are handled in this module.
- `X-CSRF-Token` (from the `ui_csrf` cookie) is attached by the shared
  interceptor — not by `feature-search`.
- The dev host is plaintext HTTP; this is a known dev-only condition. Production
  base URL must be HTTPS, and the app's network security config must not permit
  cleartext for non-dev build variants. Search query text must not be written to
  persistent logs in release builds (see §10).
- Recent queries are stored unencrypted in DataStore. Because queries may be
  sensitive, the "Clear recents" action fully removes them, and recents are not
  backed up (exclude the key via `dataExtractionRules`/`fullBackupContent`).

## 9. Accessibility & i18n

- Search field has a `contentDescription`/label "Search"; the clear button is
  labelled "Clear search". Tab headers expose count via `semantics` (e.g., "Users,
  8 results").
- Result rows are single focusable touch targets ≥ 48dp with merged semantics
  ("<name>, user" / "<title>, content") and a click action label "Open".
- Loading state announces "Searching"; results announce count via a
  `liveRegion` so screen-reader users hear "12 results".
- All user-facing strings live in `res/values/strings.xml` with placeholders
  (`No results for \"%1$s\"`, `%1$d results`); no concatenation. Entity labels come
  from the backend `label` but fall back to localized strings keyed by `type`.
- Layout respects dynamic font scaling and RTL (tab row and rows use
  start/end, not left/right).

## 10. Telemetry & Logging

- **Events** (via the app's analytics abstraction): `search_performed`
  `{query_length, types, total_results, latency_ms, source: network|cache}`,
  `search_result_clicked` `{entity_type, position, tab}`,
  `search_tab_selected {tab}`, `search_retry`, `search_recent_used`. Log
  `query_length`, never the raw query, to avoid logging PII.
- **Logging:** structured Timber logs at DEBUG for request lifecycle and error
  mapping; raw query strings are logged only in debug builds. Release builds redact
  query text. Network-level logging uses the OkHttp logging interceptor at
  `NONE`/`BASIC` in release.
- **Metrics:** record `latency_ms` from request start to first `Success` emission
  to monitor the unreliable backend.

## 11. Testing Strategy

Unit (JVM, `core-testing` helpers):
- `SearchMapper`: DTO→domain for users, content, unknown `type`→OTHER, and a
  multi-category payload; per-category counts preserved.
- `SearchViewModel` (Turbine + coroutine test dispatcher): debounce coalesces
  rapid input into one request; query < 2 chars stays `Idle`; `flatMapLatest`
  cancels superseded queries (latest wins); `200`/empty→`Empty`; error→`Error`;
  cache-fallback→`Success(stale = true)`; recents persisted on success;
  `selectedTab` restoration from `SavedStateHandle`.
- `RecentQueriesStore`: max-8 cap, de-dup, most-recent-first ordering, clear.

Network (MockWebServer, mirrors AND-027 style):
- Asserts `GET /ui/search` path, `q`/`limit`/`types` query params, and
  `X-CSRF-Token` header presence; parses the sample JSON in §5; maps FastAPI
  `detail` error shapes to `ApiResult.Error`; verifies 401→refresh→retry path.

Compose UI / instrumentation (`createAndroidComposeRule`):
- Each `SearchUiState` renders its expected surface (Idle/Loading/Success/Empty/
  Error); typing triggers results; tab switch shows the right list and counts;
  row click invokes the navigation callback with the correct id; "See all" jumps
  to the category tab; rotation preserves query + tab.

Acceptance test (the ticket's stated criterion): a seeded multi-entity query
returns categorized results and the test asserts each result is bucketed under the
correct entity tab with matching counts.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints): provides the authenticated
  OkHttp stack, persistent cookie jar, CSRF header injection, 401-refresh-retry,
  and `ApiResult<T>` infrastructure that search reuses. AND-185 cannot ship before
  AND-027.
- **Soft dependency:** the global app-bar scaffold / Navigation-Compose host must
  exist to host the search route and the search icon entry point; if not yet
  available, ship `feature-search` with its own nav graph and wire the entry point
  when the scaffold lands.
- **Consumes** the user-detail and content-detail routes from their owning feature
  modules via the `SearchNavigator` contract (§4); those are wired at the `app`
  layer and can be stubbed for tests.
- **Blocks:** none recorded in the source backlog.

## 13. Risks & Open Questions

- **Contract uncertainty:** exact search path (`/ui/search` assumed), the category
  `type` enum, and whether pagination is `limit`/`offset` vs cursor must be
  confirmed against `/openapi.json` and `search.ts`. Resolve before implementation;
  the `OTHER` fallback and pluggable param mapping limit blast radius.
- **Backend reliability:** slow/failed responses are expected; mitigated by
  debounce, `flatMapLatest`, timeouts, retry, and stale-cache fallback.
- **Entity-set growth:** new entity types should not require app changes — the
  scrollable tab row and generic-cell fallback are driven by the response.
- **"All" tab semantics:** whether the backend returns a dedicated "all/top" set or
  the client aggregates per-category slices. Default: client aggregates a capped
  slice per category.
- **Result freshness vs privacy:** persisting recents in DataStore vs not — decided
  to persist with explicit clear and backup exclusion (§8).

## 14. Acceptance Criteria

AC-1. A non-empty query (≥ 2 chars) returns categorized results, grouped into an
"All" tab plus one tab per entity category from the response, with each
non-"All" tab header showing a count equal to its rendered/declared item count.
(Directly satisfies the source acceptance bullet.)

AC-2. Results are correctly bucketed: a user result appears only under Users (and
"All"); a content result only under Content (and "All"); unknown types render
under a generic cell and do not crash.

AC-3. Input is debounced; rapid typing of a final query issues exactly one request
and the latest query's results are shown (no stale overwrite).

AC-4. Queries < 2 chars and the empty field show non-network states (Idle/recents),
and a `200`-with-zero-results shows the Empty state, not an error.

AC-5. Tapping a result navigates to the correct detail route with the correct id.

AC-6. Loading, Empty, Error (with working Retry), and offline/stale states are
each rendered and visually distinct.

AC-7. Query and selected tab survive rotation and process death.

AC-8. The request path, verb, and params match `/openapi.json`, verified by a
MockWebServer test; the `X-CSRF-Token` header is present.

AC-9. The categorization behavior is covered by automated tests (the "tested"
requirement in the source acceptance bullet).

## 15. Definition of Done

- `feature-search` module created and wired into `app` per the layering rules,
  using only `com.testlogon.android`-namespaced packages.
- `SearchApi`, DTOs/mapper, `SearchRepository`, `SearchViewModel`,
  `RecentQueriesStore`, and Compose surface implemented with Hilt (KSP) bindings.
- All §11 unit, MockWebServer, and Compose UI tests pass in CI; the categorized-
  results acceptance test (AC-1/AC-2/AC-9) is green.
- All §14 acceptance criteria demonstrably met on the dev backend, including graceful
  behavior under induced timeouts/offline.
- No raw query text logged in release; recents excluded from backup; cleartext
  permitted only for the dev variant.
- Strings externalized and localizable; accessibility semantics verified with
  TalkBack on the search field, tabs, and result rows.
- Code reviewed and merged to the `android-port` branch; ktlint/detekt clean; no new
  Compose stability/recomposition warnings on the result lists.
