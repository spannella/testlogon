---
id: AND-185
title: Global search (multi-entity)
milestone: M4
epic: E25
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
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
  (PLAINTEXT HTTP, unreliable). Contract of record is `/openapi.json`. VERIFIED:
  the endpoint is `GET /ui/search` (op `global_search_ui_search_get`) with query
  params `q` (required, 1–500 chars), `types` (CSV, optional), `limit` (default 5,
  max 20), plus `user_sub` query and `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` headers.
  NOTE: the OpenAPI `200` response schema is empty (`{}`), so the authoritative
  response shape comes from the web client `search.ts` (see §5, corrected). The
  category set is NOT an open enum — it is a fixed keyed object of nine sections
  (users, posts, catalog, files, messages, tickets, contacts, videos, calendar).
- **Dependency AND-027 (AuthApi / session endpoints):** establishes the
  transport that AND-185 reuses. VERIFIED against `src/api/client.ts`: the web
  client sends `Authorization: Bearer <accessToken>` (from the auth store) as the
  PRIMARY credential, AND includes cookies (`credentials: "include"`), AND attaches
  `X-CSRF-Token` from the `ui_csrf` cookie, plus an optional `X-IMPERSONATION-TOKEN`
  when impersonating. The OpenAPI additionally documents an `X-SESSION-ID` header
  and a `user_sub` query param on this route. On `401` (only when already
  authenticated) it performs a single `POST /ui/session/refresh` and retries once;
  on refresh failure it logs out. AND-185 reuses that OkHttp stack and `ApiResult<T>`
  mapping and must not re-implement auth. (Correction: the prior draft described
  this as a purely "cookie-based session" — the bearer token is the main credential.)
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
(Divergence note: the web enables the query at `length >= 1` but only records
history at `>= 2`; the backend accepts `q` of min length 1. The 2-char threshold
here is an intentional Android choice to cut chatter against the unreliable dev
backend — verified-divergence, see §16.)

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

FR-7. Each result row renders a cell from the uniform item fields (`title`,
`snippet`, optional `thumbnail_url`) with a leading type icon chosen by `type`
(the web maps each of the nine types to a distinct icon; see `resultIcon` in
SearchPage.tsx). Tapping a row navigates using the server-provided `url` (§4).
(Correction: there are no per-type fields such as `username`/`avatar_url`.)

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

// Destinations AND-185 routes into (provided by other feature modules).
// CORRECTION (verified vs SearchPage.tsx handleItemClick → navigate(item.url)):
// the web client does NOT construct routes from (type, id); it navigates to the
// server-provided `item.url`. The Android navigator must therefore resolve
// `SearchResult.url` to an in-app destination (parse the path and map to the
// owning feature route), falling back to type+id only if a url is absent.
interface SearchNavigator {
    // Resolve a server-provided deep-link URL to an in-app destination.
    fun open(navController: NavController, result: SearchResult)
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

// CORRECTION (verified vs search.ts: SearchResultType + GlobalSearchResponse):
// the backend exposes a FIXED set of nine sections, not USER/CONTENT. OTHER is
// retained only as a forward-compat fallback for an unrecognized `type` string.
enum class SearchEntityType {
    USER, POST, CATALOG, FILE, MESSAGE, TICKET, CONTACT, VIDEO, CALENDAR, OTHER
}

data class SearchCategory(
    val type: SearchEntityType,
    val label: String,
    val count: Int,
    val items: List<SearchResult>,
)

// CORRECTION (verified vs src/api/endpoints/search.ts: SearchResultItem): the
// backend returns a UNIFORM item shape for every entity type — there is no
// per-type field set. Every item is {type, id, title, snippet, thumbnail_url?,
// url, meta?}. The domain model must mirror this; type-specific rendering is a
// presentation concern keyed off `type`, not separate DTO classes.
data class SearchResult(
    val id: String,
    val type: SearchEntityType,
    val title: String,
    val snippet: String?,        // web suppresses snippet when it equals title
    val thumbnailUrl: String?,   // JSON: thumbnail_url
    val url: String,             // server-provided deep link target (see §4 nav note)
    val meta: Map<String, Any?> = emptyMap(),
)

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

Authoritative sources: OpenAPI `global_search_ui_search_get` for the request, and
`src/api/endpoints/search.ts` for the response shape (the OpenAPI `200` schema is
empty `{}`, so the web DTO is the contract of record for the body).

VERIFIED contract (mirrors `search.ts`):

```kotlin
interface SearchApi {
    @GET("ui/search")
    suspend fun search(
        @Query("q") query: String,                // required, 1..500 chars
        @Query("types") types: String? = null,    // CSV, e.g. "users,posts"; null = all
        @Query("limit") limit: Int = 5,           // backend default 5, MAX 20 (web sends 10)
    ): Response<SearchResponseDto>
}
```

Request: `GET /ui/search?q=jane&limit=10` carrying `Authorization: Bearer …`
(primary credential), session cookies, `X-CSRF-Token` (from `ui_csrf`), and an
optional `X-IMPERSONATION-TOKEN` — all injected by the shared OkHttp interceptor
from AND-027. (Correction: prior draft sent `limit=20` and described auth as
cookie-only; the documented default is 5/max 20 and the bearer token is primary.)

Response `200` — CORRECTED to the real shape. The body is `{query, results, partial?}`
where `results` is a KEYED OBJECT of nine optional sections (not a `categories`
array, and there is NO top-level `total`). Each section is
`{items, total_estimate, has_more}`, and every item shares ONE uniform shape:

```json
{
  "query": "jane",
  "partial": false,
  "results": {
    "users": {
      "total_estimate": 8,
      "has_more": true,
      "items": [
        { "type": "user", "id": "u_123", "title": "Jane Doe",
          "snippet": "@jdoe", "thumbnail_url": "https://…/a.jpg",
          "url": "/users/u_123", "meta": { } }
      ]
    },
    "posts": {
      "total_estimate": 4,
      "has_more": false,
      "items": [
        { "type": "post", "id": "c_987", "title": "Jane's stream",
          "snippet": "…", "thumbnail_url": "https://…/t.jpg",
          "url": "/posts/c_987" }
      ]
    }
    // ...catalog, files, messages?, tickets?, contacts?, videos?, calendar?
  }
}
```

Notes on the corrected shape:
- Per-tab "count" comes from each section's `items.size` (what the web renders) and
  `total_estimate` is the backend's estimate of the full count; `has_more` signals
  truncation. The web `total` for the "All" tab is the SUM of `items.length` across
  sections (see `SearchPage.tsx`), computed client-side — there is no server `total`.
- Items are uniform: `{type, id, title, snippet, thumbnail_url?, url, meta?}`. There
  are NO `display_name`/`username`/`avatar_url` fields. The web suppresses `snippet`
  when it equals `title`.

DTOs use `@Json(name = "...")` for snake_case mapping. Model `results` as a DTO with
nine nullable section fields (or a `Map<String, SectionDto>` to tolerate added keys),
each `SectionDto {items, total_estimate, has_more}`. A single `SearchItemDto`
(uniform fields) maps to domain; an unrecognized `type` string maps to
`SearchEntityType.OTHER` and renders a generic cell (forward-compatibility).
DTO→domain mapping lives in a pure `SearchMapper` for unit testing.

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
- **Pagination:** CORRECTION — `GET /ui/search` exposes NO `offset`/`cursor`/`page`
  param (verified: its only query params are `q`, `types`, `limit`, `user_sub`).
  `limit` is capped at 20. Therefore per-section results cannot be paged through this
  endpoint; the previously-planned Paging 3 `(query, type, offset)` source is
  unsupported by the contract. Each section instead returns up to `limit` items plus
  `has_more`/`total_estimate`; when `has_more` is true, the per-category tab shows a
  truncation hint (e.g. "Showing first N of ~M") and, where a richer per-entity
  search endpoint exists (e.g. `GET /ui/catalog/items/search` with `next_token`,
  `GET /ui/alerts/search` with `cursor`), deep-dive paging is delegated to that
  entity's own feature/route — out of scope for AND-185. The "All" tab remains a
  capped slice. (Open question moved to §13.)
- **Caching (stale state):** the most recent successful `SearchResponse` per query
  is held in an in-memory LRU (size 16) in the repository so back-navigation is
  instant. Optional Room persistence is out of scope for AND-185 (results are
  volatile); if the network fails but an LRU entry exists for the query, emit
  `Success(stale = true)` so the UI can show a "showing cached results" banner.
- **Recent queries:** `RecentQueriesStore` backed by DataStore Preferences (key
  `recent_search_queries`, JSON-encoded ordered list, max 8, de-duplicated,
  most-recent-first). Persisted on a successful non-empty search.
  DIVERGENCE NOTE (verified vs `SearchPage.tsx` + `search.ts`): the WEB client stores
  recents SERVER-SIDE via `POST /ui/search/history` (record), `GET /ui/search/history`
  (list, items `{id, query, ts, result_count}`), `DELETE /ui/search/history/{item_id}`,
  and `DELETE /ui/search/history` (clear all). AND-185 deliberately chooses local
  DataStore instead (privacy + offline + no server round-trip). This is an intentional
  product divergence, not a bug; if cross-device parity is later required, wire the
  four `/ui/search/history` endpoints. Tracked in §13/§16 Open assumptions.

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

AC-2. Results are correctly bucketed: each item appears only under its own section
tab (e.g. a `user` under Users, a `post` under Posts) and in "All"; an unrecognized
`type` maps to OTHER, renders a generic cell, and does not crash.

AC-3. Input is debounced; rapid typing of a final query issues exactly one request
and the latest query's results are shown (no stale overwrite).

AC-4. Queries < 2 chars and the empty field show non-network states (Idle/recents),
and a `200`-with-zero-results shows the Empty state, not an error.

AC-5. Tapping a result navigates to the destination resolved from the item's
server-provided `url` (mapped to the owning feature route).

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

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and an exact source pointer.

1. **Endpoint is `GET /ui/search`.** VERIFIED.
   Source: OpenAPI `GET /ui/search` (op `global_search_ui_search_get`); frontend
   `src/api/endpoints/search.ts: globalSearch` (`api.get("/ui/search", ...)`).
2. **Query params are `q` (required), `types` (CSV, optional), `limit`.** VERIFIED.
   Source: OpenAPI `GET /ui/search` params; `src/api/endpoints/search.ts: globalSearch`.
3. **`q` length bounds 1–500; `limit` default 5, max 20.** CORRECTED (draft said
   default 20). Source: OpenAPI `global_search_ui_search_get` parameter schemas
   (`q` minLength 1/maxLength 500; `limit` default 5/min 1/max 20). Web sends
   `limit=10` (`SearchPage.tsx: globalSearch(debouncedQuery, undefined, 10)`).
4. **`types` default value.** VERIFIED. OpenAPI default
   `"calendar,catalog,contacts,files,messages,posts,tickets,users,videos"`.
   Source: OpenAPI `GET /ui/search` `types` schema default.
5. **Response is `{query, results, partial?}` with a KEYED `results` object of nine
   sections, each `{items, total_estimate, has_more}`; NO top-level `total`; NO
   `categories` array.** CORRECTED (draft had `{query,total,categories:[...]}`).
   Source: `src/api/endpoints/search.ts: GlobalSearchResponse` + `SearchResultSection`.
   (OpenAPI `200` schema is empty `{}`, so the frontend type is authoritative.)
6. **Item shape is uniform `{type, id, title, snippet, thumbnail_url?, url, meta?}`
   for all types.** CORRECTED (draft used per-type `display_name`/`username`/
   `avatar_url`). Source: `src/api/endpoints/search.ts: SearchResultItem`.
7. **Entity `type` set = user, post, catalog, file, message, ticket, contact, video,
   calendar (9), not USER/CONTENT.** CORRECTED. Source:
   `src/api/endpoints/search.ts: SearchResultType` and `SEARCH_TABS` in
   `src/pages/search/SearchPage.tsx`.
8. **"All"/per-tab counts are client-computed from `items.length` (sum across
   sections for All).** VERIFIED. Source: `src/pages/search/SearchPage.tsx`
   (`totalItems`, `sectionCount`).
9. **Navigation uses the server-provided `item.url`, not client-built (type,id)
   routes.** CORRECTED. Source: `src/pages/search/SearchPage.tsx: handleItemClick`
   (`navigate(item.url)`).
10. **Auth: primary credential is `Authorization: Bearer <accessToken>`, plus cookies
    (`credentials: "include"`), plus `X-CSRF-Token` from the `ui_csrf` cookie, plus
    optional `X-IMPERSONATION-TOKEN`.** CORRECTED (draft described cookie-only).
    Source: `src/api/client.ts` (lines ~157–171 for Authorization/impersonation/CSRF;
    `credentials: "include"` ~183). OpenAPI also lists `X-SESSION-ID` header and
    `user_sub` query param on the route.
11. **`X-CSRF-Token` is derived from the `ui_csrf` cookie.** VERIFIED.
    Source: `src/api/client.ts: getCookie("ui_csrf") → headers.set("X-CSRF-Token", …)`.
12. **401 handling = single `POST /ui/session/refresh` then one retry; logout on
    refresh failure.** VERIFIED. Source: `src/api/client.ts: refreshSession` +
    the 401 branch (single-flight `refreshPromise`, one retry, `logout`).
13. **FastAPI error `detail` may be `string | [{msg}] | {code,...}`.** VERIFIED.
    Source: `src/api/client.ts: normalizeErrorDetail` + `mapAuthorizationError`;
    OpenAPI `422 → HTTPValidationError`.
14. **Network/offline error path.** VERIFIED. Source: `src/api/client.ts` fetch
    catch block → `ApiError(0, "Network error")`.
15. **Debounce is 300 ms.** VERIFIED. Source: `src/pages/search/SearchPage.tsx`
    (`useDebounce(inputValue, 300)`).
16. **Server-side search history endpoints exist (`/ui/search/history` GET/POST,
    `/ui/search/history/{item_id}` DELETE, `/ui/search/history` DELETE).** VERIFIED;
    AND-185 intentionally uses local DataStore instead (DIVERGENCE). Source: OpenAPI
    `GET/POST /ui/search/history`, `DELETE /ui/search/history`, `DELETE
    /ui/search/history/{item_id}`; `src/api/endpoints/search.ts`
    (`recordSearchHistory`, `getSearchHistory`, `deleteSearchHistoryItem`,
    `clearSearchHistory`).
17. **No pagination param on `/ui/search` (no offset/cursor/page); `has_more`/
    `total_estimate` only.** CORRECTED (draft planned Paging 3 by `offset`). Source:
    OpenAPI `GET /ui/search` params (only `q,types,limit,user_sub` + headers);
    `SearchResultSection.has_more/total_estimate` in `search.ts`.
18. **Min-query threshold of 2 chars is an Android divergence.** VERIFIED-DIVERGENCE
    (web enables at `>=1`, records history at `>=2`; backend min length 1). Source:
    `src/pages/search/SearchPage.tsx` (`enabled: debouncedQuery.length >= 1`;
    history effect guards `length >= 2`).
19. **Compose Material 3 `PrimaryScrollableTabRow`, Coil `AsyncImage`, Paging 3,
    DataStore, Hilt/KSP, `StateFlow`/`flatMapLatest`/`debounce` choices.** Framework
    refs (Android), not backend-verifiable:
    - Material 3 tabs: https://developer.android.com/develop/ui/compose/components/tabs (framework ref)
    - Coil AsyncImage: https://coil-kt.github.io/coil/compose/ (framework ref)
    - Kotlin Flow operators (debounce/flatMapLatest): https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/ (framework ref)
    - DataStore: https://developer.android.com/topic/libraries/architecture/datastore (framework ref)
    - SavedStateHandle/process death: https://developer.android.com/topic/libraries/architecture/saved-state (framework ref)
    - App backup exclusion (`dataExtractionRules`): https://developer.android.com/guide/topics/data/autobackup (framework ref)
    Note: `limit`/`offset` Paging 3 design is NOT applicable (claim 17).

### Corrections made

- C1. `limit` default fixed 20 → 5 (max 20); §2, §5 (claim 3).
- C2. Response shape rewritten: keyed `results` object of nine `{items,
  total_estimate, has_more}` sections; removed top-level `total` and `categories`
  array; §2, §5 (claim 5).
- C3. Item model unified to `{type, id, title, snippet, thumbnail_url?, url, meta?}`;
  removed per-type `display_name`/`username`/`avatar_url`; §4, §5, §3 FR-7 (claim 6).
- C4. `SearchEntityType` expanded to the nine real types + OTHER fallback (was
  USER/CONTENT/OTHER); §4 (claim 7).
- C5. Navigation changed to resolve `item.url` instead of `openUser(id)`/
  `openContent(id)`; §4 `SearchNavigator`, FR-7, AC-5 (claim 9).
- C6. Auth description corrected from "cookie-only" to bearer-token-primary + cookies
  + CSRF + optional impersonation (+ documented `X-SESSION-ID`/`user_sub`); §2, §5
  (claim 10).
- C7. Pagination claim corrected: endpoint has no offset/cursor param; Paging 3
  removed for `/ui/search`; §6, §13 (claim 17).
- C8. AC-2 reworded away from a "Content" tab to the real per-section bucketing.

### Open assumptions

- OA1. **Response body shape relies on the web type, not OpenAPI.** The OpenAPI `200`
  schema for `global_search_ui_search_get` is empty (`{}`), so the exact wire JSON
  (field nullability, presence of `partial`, `meta` contents) is taken from
  `search.ts`. Unverifiable from OpenAPI; confirm against a live dev response before
  freezing the Moshi DTOs. (Why: schema is untyped on the server side.)
- OA2. **Local DataStore recents vs server `/ui/search/history`.** Intentional
  product divergence (claim 16); needs product sign-off if cross-device parity is
  desired. (Why: a deliberate design choice, not derivable from sources.)
- OA3. **2-char min-query threshold** (claim 18) differs from the web's 1-char enable;
  needs product confirmation. (Why: product/UX decision.)
- OA4. **In-app resolution of `item.url`.** The web treats `url` as a router path; the
  mapping of each server path prefix (e.g. `/users/…`, `/posts/…`) to an Android
  feature route is not in the sources and must be defined with the owning feature
  teams. (Why: cross-feature contract not documented in backend/frontend refs.)
- OA5. **`has_more` deep-dive delegation.** Whether truncated sections route to a
  per-entity search route (catalog/alerts have their own paged endpoints) is an
  app-level decision out of scope here. (Why: no global "page section" mechanism.)
- OA6. **Stale/offline cache + bounded-GET retry** are AND-027/app-policy behaviors
  not observable in the web client (which has no offline cache); assumed to exist per
  AND-027. (Why: defined in a dependency, not re-verifiable from these sources.)

## 17. Test Plan

Test targets: **JVM** (local JVM/Robolectric, no device); **emu35** (headless AVD
`test35`, x86_64, API 35, CI); **deviceA15** (physical Samsung Galaxy A15 5G,
SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Most cases run on JVM or emu35;
physical-device-only cases are flagged explicitly.

- **TC-AND-185-01 — Happy path: multi-entity query returns categorized results.**
  Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: MockWebServer
  enqueues the §5 corrected JSON (users + posts + files sections). Steps: call
  `SearchApi.search("jane", null, 10)` through the real OkHttp/Moshi stack; map via
  `SearchMapper`. Expected: request path `/ui/search`, method GET, query `q=jane` &
  `limit=10`; parsed domain has one `SearchCategory` per non-empty section with
  `count == items.size`; uniform item fields populated; `url` preserved.
  Traces: AC-1, AC-8, AC-9.

- **TC-AND-185-02 — Mapper: uniform items, nine types, OTHER fallback.** Type: unit.
  Target: JVM. Preconditions: fixture JSON containing each of the nine `type` values
  plus one unknown type (`"widget"`). Steps: run `SearchMapper` on the payload.
  Expected: each known type maps to its `SearchEntityType`; unknown maps to `OTHER`;
  no crash; per-section counts preserved; "All" total == sum of section item counts.
  Traces: AC-2, AC-9.

- **TC-AND-185-03 — Debounce coalescing + latest-wins cancellation.** Type: unit
  (Turbine + TestDispatcher). Target: JVM. Preconditions: fake repository recording
  invocations, controllable virtual time. Steps: emit `j`,`ja`,`jan`,`jane` within
  the 300 ms window, advance time. Expected: exactly ONE repository call, for
  `"jane"`; `uiState` transitions Idle→Loading→Success; superseded queries cancelled
  (`flatMapLatest`). Traces: AC-3.

- **TC-AND-185-04 — Sub-threshold and empty stay non-network.** Type: unit. Target:
  JVM. Preconditions: spy repository. Steps: set query to `""` then `"j"`. Expected:
  no network call; `uiState == Idle`; recents surface when field empty. Traces: AC-4.

- **TC-AND-185-05 — 200 with all-empty sections → Empty, not Error.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue `{query, results:{}}`
  (or all sections empty). Steps: search `"zzzz"`. Expected: `ApiResult` success
  maps to `SearchUiState.Empty("zzzz")`; never `Error`. Traces: AC-4, AC-6.

- **TC-AND-185-06 — FastAPI 422 validation error mapping.** Type: contract/
  MockWebServer. Target: JVM. Preconditions: enqueue 422 with HTTPValidationError
  body `{"detail":[{"loc":["query","q"],"msg":"field required","type":"value_error"}]}`.
  Steps: search. Expected: `ApiResult.Error` carrying the `msg` text via the shared
  `detail` normalizer; `uiState = Error(retryable=…)`. Traces: AC-6, AC-8.

- **TC-AND-185-07 — 401 → single refresh → retry succeeds.** Type: contract/
  MockWebServer. Target: JVM. Preconditions: enqueue 401, then expect a
  `POST /ui/session/refresh` (200), then the original GET retried (200 with results).
  Steps: search while "authenticated". Expected: exactly one refresh POST; original
  request retried once; final state Success; if refresh returns non-2xx, state is an
  auth Error and re-auth is signaled. Traces: AC-8, AC-6.

- **TC-AND-185-08 — Request carries auth + CSRF + limit cap.** Type: contract/
  MockWebServer. Target: JVM. Preconditions: interceptor stack from AND-027 with a
  bearer token and `ui_csrf` cookie present. Steps: search `"jane"` with limit 25.
  Expected: recorded request has `Authorization: Bearer …` and `X-CSRF-Token`
  headers; `limit` clamped to ≤ 20 before send; `q` URL-encoded. Traces: AC-8.

- **TC-AND-185-09 — Offline → stale cache banner; offline with no cache → Error.**
  Type: unit/integration. Target: JVM. Preconditions: repository LRU pre-seeded for
  `"jane"`; network layer throws connectivity failure (`ApiError(0)`). Steps:
  (a) search `"jane"` offline; (b) search `"kate"` offline (no cache). Expected:
  (a) `Success(stale=true)` + banner; (b) `Error("You're offline", retryable=true)`.
  Traces: AC-6.

- **TC-AND-185-10 — Compose: each UiState renders its distinct surface + counts.**
  Type: Compose-UI. Target: emu35. Preconditions: stateless `SearchContent` driven
  by injected state. Steps: render Idle, Loading, Success(3 sections), Empty, Error.
  Expected: Idle shows recents/prompt; Loading shows indicator; Success shows All +
  one tab per section with header counts == rendered rows; Empty shows
  `No results for "<q>"`; Error shows message + enabled Retry. Traces: AC-1, AC-6.

- **TC-AND-185-11 — Compose: row tap resolves `url` to navigation callback.** Type:
  Compose-UI. Target: emu35. Preconditions: fake `SearchNavigator` capturing calls;
  Success state with a `user` item whose `url == "/users/u_123"`. Steps: tap the row.
  Expected: navigator invoked once with that `SearchResult` (url `/users/u_123`);
  "See all" on a section switches to that section's tab. Traces: AC-5, AC-1.

- **TC-AND-185-12 — Rotation & process-death restoration.** Type: instrumented.
  Target: emu35. Preconditions: query `"jane"`, Posts tab selected. Steps: rotate;
  then simulate process death via `SavedStateHandle`/`StateRestorationTester`.
  Expected: query text and selected tab restored; the `q` nav arg seeds initial
  value on a fresh deep link. Traces: AC-7.

- **TC-AND-185-13 — Accessibility semantics (TalkBack).** Type: Compose-UI/
  instrumented. Target: emu35. Preconditions: Success state. Steps: assert semantics
  for search field label "Search", clear button "Clear search", tab headers exposing
  count (e.g. "Users, 8 results"), rows as single ≥48dp targets with merged label +
  "Open" action, and the results `liveRegion` announcing count. Expected: all present;
  touch targets ≥ 48dp; dynamic font scale and RTL respected. Traces: AC-6 (and
  cross-cutting on AC-1/AC-5).

- **TC-AND-185-14 — Security: no cleartext in release; query not logged; recents
  excluded from backup.** Type: unit + manual. Target: JVM (config asserts) +
  deviceA15 (backup behavior). Preconditions: release build variant config. Steps:
  (a) assert network-security-config forbids cleartext for non-dev variants;
  (b) assert release Timber tree redacts raw query (logs `query_length` only);
  (c) on deviceA15 run `adb backup`/auto-backup and confirm the
  `recent_search_queries` key is excluded via `dataExtractionRules`. Expected: all
  hold. MUST run the backup-exclusion check on a physical device (deviceA15) for real
  Auto Backup/D2D behavior. Traces: AC-6 (security), DoD.

- **TC-AND-185-15 — ABI/API parity smoke (arm64 API 34 vs x86_64 API 35).** Type:
  e2e. Target: deviceA15 AND emu35. Preconditions: seeded dev backend reachable.
  Steps: run the happy-path search e2e on both targets. Expected: identical
  categorized results and rendering; no arm64-specific Coil/image or Moshi codegen
  regressions. MUST include the physical device (deviceA15) to catch arm64-vs-x86 and
  API-34-vs-35 differences. Traces: AC-1, AC-2, AC-9.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-10, TC-11, TC-15 |
| AC-2 | TC-02, TC-15 |
| AC-3 | TC-03 |
| AC-4 | TC-04, TC-05 |
| AC-5 | TC-11, TC-13 |
| AC-6 | TC-05, TC-06, TC-07, TC-09, TC-10, TC-13, TC-14 |
| AC-7 | TC-12 |
| AC-8 | TC-01, TC-06, TC-07, TC-08 |
| AC-9 | TC-01, TC-02, TC-15 |
