---
id: AND-186
title: Search filters/tabs
milestone: M4
epic: E25
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-185]
blocks: [AND-187]
---

# AND-186 — Search filters/tabs

## 1. Overview & Goal

This ticket layers the **filtering and entity-tab UX** on top of the global, multi-entity
search delivered by AND-185. AND-185 ports `frontend/src/api/endpoints/search.ts` to a
Kotlin `SearchApi` and returns categorized results across entity types (users, content,
and others the backend exposes). What AND-185 does *not* own is the interactive surface
that lets a user **narrow** those results: the per-entity tabs that scope the visible
result set, the in-screen filter controls that refine a query (entity type, sort, and any
backend-supported facets), the **recent searches** affordance, and the distinct
**empty** (no query yet) versus **no-results** (query ran, returned nothing) states.

The goal is a search surface where **filters and tabs measurably refine the rendered
results**: selecting a tab restricts results to that entity type, applying a filter
re-issues (or re-scopes) the query and changes what is shown, recent searches let a user
re-run a prior query with one tap, and the two distinct "nothing to show" states render
correctly. This is a UI + interaction-state slice in `feature-search`; the heavy
debounce/paging/state-machine plumbing it depends on is owned by AND-187 (which depends on
this ticket and AND-185 for the filter/tab model and the search binding respectively). To
keep this ticket independently testable, it ships a thin `SearchFilterController` over the
AND-185 search call and a deterministic recent-searches store; AND-187 later subsumes the
orchestration into the production `SearchViewModel`.

Namespace `com.testlogon.android` is used everywhere a package appears.

## 2. Context & References

- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000` (PLAINTEXT HTTP,
  unreliable). OpenAPI at `/openapi.json`. **[VERIFIED]** The global search endpoint is
  `GET /ui/search` (op `global_search_ui_search_get`) with query params **`q`** (required,
  1–500 chars), **`types`** (a single comma-separated string; default
  `calendar,catalog,contacts,files,messages,posts,tickets,users,videos`), and **`limit`**
  (1–20, default 5). **[CORRECTED]** There is **no `sort` parameter** and **no `cursor`
  parameter** on this endpoint — the entity-type filter is the only real server-side
  refinement. Verify any new filter against `/openapi.json` before binding it to a control.
- **Web reference:** `frontend/src/api/endpoints/search.ts` (the search surface AND-185
  ports; `globalSearch(q, types?, limit)` plus the server-backed search-history calls
  `recordSearchHistory`/`getSearchHistory`/`deleteSearchHistoryItem`/`clearSearchHistory`).
  The categorized result + item DTO shapes live in that same `search.ts`
  (`GlobalSearchResponse`, `SearchResultSection`, `SearchResultItem`), **not** in
  `frontend/src/api/types.ts`. **[VERIFIED]** The web client filters tabs **client-side**:
  `SearchPage.tsx` calls `globalSearch(query, undefined, 10)` (never passing `types`) and
  scopes per-tab over the already-fetched sectioned response.
- **Upstream tickets:**
  - **AND-185** — Global search (multi-entity). Owns `SearchApi`, the result DTOs, the
    `SearchMapper`, and the categorized `SearchResults` model. This ticket consumes that
    model and the entity categories it defines; the tab set is derived from those
    categories, not invented here.
- **Downstream:**
  - **AND-187** — Discovery/search ViewModels (debounce, paging, state). Depends on this
    ticket. The `SearchFilterState`, `SearchTab`, and `SearchFilters` types defined here
    are the stable contract AND-187's `SearchViewModel` consumes; the interim
    `SearchFilterController` is replaced by that ViewModel.
- **Sibling reference:** AND-182 (Discover screen) for state-composable reuse and nav-event
  patterns; AND-098 (Paging 3) for the paged-result hook AND-187 will attach to filters.
- **Reused infra:** AND-018 (`ApiResult`), AND-015 (FastAPI `detail` mapping), AND-021
  (Loading/Empty/Error/Offline composables), AND-016 (idempotent-GET retry), AND-017
  (connectivity), AND-027 (authenticated request plumbing: cookie jar + CSRF + refresh).

## 3. Functional Requirements

FR-1. The search screen presents a **tab row** of entity categories. Tabs are derived from
the entity categories AND-185 returns (e.g. "All", "Users", "Content"/"Posts", plus any
others the backend exposes). The first tab is always **All** (un-scoped). Tabs render as a
Material 3 `ScrollableTabRow`.

FR-2. Selecting a tab scopes the visible result set to that entity type. "All" shows the
full categorized result set (sectioned by category); a specific tab shows only that
category's results as a flat list. Tab selection re-issues the search with the
corresponding `type` filter **when the backend supports server-side type filtering**;
otherwise it filters the already-fetched categorized result set client-side. Which path is
used is determined at implementation time from `/openapi.json` (see §5).

FR-3. The screen exposes a **filter control** (a filter icon opening a Material 3
`ModalBottomSheet`) for refinements beyond the single-tab scope: entity-type selection
(mirroring tabs, and supporting explicit multi-select since `types` is a comma-joined list).
[CORRECTED] A **sort** option is NOT backed by any backend parameter (the search endpoint has
no `sort`) and the web client offers no sort control — if a sort affordance ships at all it
is **client-only**, clearly bounded and noted, and offered only for categories whose DTO
exposes a sortable field (see §4.1, §5, R5). Only refinements backed by a real backend query
parameter (`types`) re-issue the query; client-only refinements re-scope the held results.
Applying filters updates the rendered results.

FR-4. The active filter/tab selection is **visible**: the selected tab is highlighted, and
a non-default filter state shows a badge/indicator on the filter icon plus removable filter
chips (`FilterChip`) above the results. A "Clear" action resets filters to defaults.

FR-5. **Recent searches:** when the query field is empty (no active search), the screen
shows a list of the user's recent search terms (most-recent first, capped at a fixed N,
default 10). Tapping a recent search re-runs that query. Each row has a remove (×) action;
a "Clear all" action empties the list. A successful search commits its query string to the
recent list (de-duplicated, moved to top).

FR-6. **Two distinct empty states:**
  - **Empty / idle** — no query entered yet: show recent searches (FR-5) or, if none, a
    neutral prompt ("Search for users and content").
  - **No-results** — a query ran and returned zero results for the current tab/filters:
    show the AND-021 empty composable with the searched term echoed and an affordance to
    "Clear filters" (shown only when filters are non-default, since clearing may surface
    results) and/or "Search everything" (switch to the All tab).

FR-7. Filter and tab selection **survive configuration changes** and process-death within
lifetime (held in `SavedStateHandle`-friendly state). The query text and active selection
are restored on recomposition.

FR-8. Changing a tab or filter does not lose the current query; it re-applies the same
query under the new scope. Clearing the query resets to the idle/recent state but retains
the last-used filter defaults for the session.

## 4. Technical Design

Module `feature-search`, package `com.testlogon.android.feature.search` (the same module
AND-185 establishes). This ticket adds the filter/tab/recent layer.

### 4.1 Filter & tab model (stable contract for AND-187)

```kotlin
// com.testlogon.android.feature.search.model

/**
 * Entity scope; mirrors the categories AND-185 returns. ALL = un-scoped.
 * [CORRECTED] The backend exposes NINE result categories, not just users/content.
 * Per `search.ts: SearchResultType` and the `types` default in `GET /ui/search`, the
 * category set is: users, posts, catalog, files, messages, tickets, contacts, videos,
 * calendar. The `types` query param uses the PLURAL/section keys
 * (users, posts, catalog, files, messages, tickets, contacts, videos, calendar); the
 * per-item `type` field uses the SINGULAR form (user, post, file, message, ...).
 */
enum class SearchEntityType {
    ALL, USERS, POSTS, CATALOG, FILES, MESSAGES, TICKETS, CONTACTS, VIDEOS, CALENDAR
}

// [CORRECTED] No `sort` exists on the backend search endpoint and the web client offers
// no sort control. A SearchSort enum is therefore an UNVERIFIED, client-only refinement.
// If a sort UI ships, it MUST be implemented client-side over the fetched sections (and
// only for categories whose DTO exposes a sortable field) and labelled as client-only —
// it is NOT a server parameter. See §5 and §16. Default ordering is backend relevance.

data class SearchFilters(
    val entityType: SearchEntityType = SearchEntityType.ALL,
) {
    val isDefault: Boolean
        get() = this == SearchFilters()
}

/** One tab in the row; label is a string resource id resolved in UI. */
data class SearchTab(
    val type: SearchEntityType,
    val labelResId: Int,
)
```

```kotlin
sealed interface SearchUiState {
    /** No query yet: show recent searches or prompt. */
    data class Idle(val recent: List<String>) : SearchUiState
    data object Loading : SearchUiState
    data class Content(
        val query: String,
        val tabs: List<SearchTab>,
        val selected: SearchEntityType,
        val filters: SearchFilters,
        val results: SearchResults,   // categorized model from AND-185
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : SearchUiState
    /** Query ran, zero results for current tab+filters. */
    data class NoResults(
        val query: String,
        val filters: SearchFilters,
        val filtersActive: Boolean,
    ) : SearchUiState
    data class Error(val message: String, val retryable: Boolean = true) : SearchUiState
    data object Offline : SearchUiState
}
```

`SearchResults` is owned by AND-185 (a categorized container, e.g.
`Map<SearchEntityType, List<SearchEntity>>` or a list of category sections). This ticket
treats it as opaque and reads `results[selected]` (or all categories when `ALL`).

### 4.2 Interim controller (replaced by AND-187's ViewModel)

To stay independently shippable and testable without waiting on AND-187, this ticket
provides a focused controller that owns filter/tab/recent state and calls the AND-185
search binding. AND-187 folds this logic into the production `SearchViewModel`; the public
state/intent surface is identical so the swap is mechanical.

```kotlin
@HiltViewModel
class SearchFilterController @Inject constructor(
    private val repository: SearchRepository,   // AND-185
    private val recentSearches: RecentSearchesStore,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    val uiState: StateFlow<SearchUiState>

    fun onQueryChange(query: String)        // empty -> Idle(recent); non-empty defers to AND-187 debounce
    fun submitQuery()                        // commits query to recent, runs search
    fun onTabSelected(type: SearchEntityType)
    fun applyFilters(filters: SearchFilters)
    fun clearFilters()
    fun runRecent(query: String)
    fun removeRecent(query: String)
    fun clearRecent()
    fun retry()
    fun refresh()
}
```

Selection is persisted to `savedState` under keys `query`, `entity_type` ([CORRECTED] the
`sort` key is removed — there is no sort parameter; see §4.1/§5).
`onTabSelected`/`applyFilters` recompute the request and re-issue via the repository,
mapping `ApiResult` to `Content`/`NoResults`/`Error`/`Offline` exactly as §6/§7 specify.

> Note: AND-186 owns filter/tab/recent **state and UI**. Query **debounce** and **Paging 3**
> wiring are explicitly AND-187's responsibility; this controller submits on explicit
> `submitQuery()`/tab/filter changes (no debounce) so it is deterministic in tests. The
> debounce path attaches to `onQueryChange` in AND-187 without changing this surface.

### 4.3 Recent searches store

> **[CORRECTED — contract mismatch]** The backend already provides a **server-side**
> search-history API that the web client (`SearchPage.tsx`) uses as the source of truth:
> `GET /ui/search/history` (`{ items: [{ id, query, ts, result_count }] }`, param `limit`,
> default 20), `POST /ui/search/history` (body `RecordSearchHistoryReq {query, result_count}`),
> `DELETE /ui/search/history/{item_id}`, and `DELETE /ui/search/history` (clear all). The web
> app records history automatically after results arrive (`recordSearchHistory(query, count)`),
> lists it, deletes a single item by `id`, and clears all. The local DataStore design below is
> therefore a **deviation** from the web contract. **Recommended:** back `RecentSearchesStore`
> with these endpoints (it then becomes the offline cache, not the source of truth) so recent
> searches sync across devices like the web app, and so removal targets the server item `id`
> rather than a raw string. If the local-only store is kept deliberately (e.g. for offline-first
> on the unreliable dev host), record that decision in the PR. Either way, "remove" on the web
> deletes by item `id`, not by query text — the `remove(query)` signature below diverges from
> the backend `DELETE /ui/search/history/{item_id}` contract.

```kotlin
interface RecentSearchesStore {
    val recent: Flow<List<String>>          // most-recent first, max N (default 10)
    suspend fun add(query: String)          // trims, de-dups (case-insensitive), moves to top
    suspend fun remove(query: String)
    suspend fun clear()
}

@Singleton
class DataStoreRecentSearchesStore @Inject constructor(
    @Named("search_prefs") private val dataStore: DataStore<Preferences>,
) : RecentSearchesStore
```

Persisted via DataStore (a JSON-encoded ordered list under a single key) so recent searches
survive app restart. Blank/whitespace-only queries are never stored. Cleared on logout
(AND-032 wiring) to avoid leaking one user's queries to the next session.

### 4.4 Compose UI

```kotlin
@Composable
fun SearchRoute(
    onOpenUser: (String) -> Unit,
    onOpenContent: (String) -> Unit,
    viewModel: SearchFilterController = hiltViewModel(),
)

@Composable
fun SearchScreen(
    state: SearchUiState,
    onQueryChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onTabSelected: (SearchEntityType) -> Unit,
    onOpenFilters: () -> Unit,
    onApplyFilters: (SearchFilters) -> Unit,
    onClearFilters: () -> Unit,
    onRunRecent: (String) -> Unit,
    onRemoveRecent: (String) -> Unit,
    onClearRecent: () -> Unit,
    onResultClick: (SearchEntity) -> Unit,
    onRetry: () -> Unit,
)

@Composable private fun SearchTabRow(tabs: List<SearchTab>, selected: SearchEntityType, onSelect: (SearchEntityType) -> Unit)
@Composable private fun ActiveFilterChips(filters: SearchFilters, onClear: () -> Unit)
@Composable private fun FilterSheet(current: SearchFilters, onApply: (SearchFilters) -> Unit)   // ModalBottomSheet
@Composable private fun RecentSearches(items: List<String>, onRun: (String) -> Unit, onRemove: (String) -> Unit, onClearAll: () -> Unit)
@Composable private fun NoResults(query: String, filtersActive: Boolean, onClearFilters: () -> Unit, onSearchAll: () -> Unit)
```

`SearchScreen` composes a `SearchBar`/`TextField` (provided by AND-185 or the AND-020 input
composables), the `SearchTabRow`, the `ActiveFilterChips` row when `!filters.isDefault`, and
the body switching on `SearchUiState`. The filter icon shows a dot badge when filters are
non-default and opens `FilterSheet`. Tab row uses `ScrollableTabRow` with the All tab
pinned first. Tapping a result emits a nav event consumed by `SearchRoute` and routed to
`onOpenUser`/`onOpenContent` (target routes owned by AND-073 / AND-100).

## 5. API Contract

This ticket does **not** introduce a new endpoint. It binds **existing query parameters**
of the AND-185 search endpoint to the filter/tab UI. The endpoint, DTOs, and mapper are
owned by AND-185; the following is **[VERIFIED]** against `/openapi.json` and `search.ts`.

**[CORRECTED] Endpoint and parameters** — the search endpoint is `GET /ui/search` (NOT a
bare `search`), and the entity-type parameter is **`types`** (plural, a single
comma-separated string), NOT `type`. There is **no `sort` and no `cursor`** parameter.

```kotlin
interface SearchApi {              // owned by AND-185 — shown for the params this ticket drives
    @GET("ui/search")
    suspend fun search(
        @Query("q") query: String,                 // required, 1..500 chars
        @Query("types") types: String? = null,     // comma-joined section keys; omit = all 9
        @Query("limit") limit: Int? = null,        // 1..20, default 5 (10 in the web client)
    ): Response<GlobalSearchResponse>
}
```

Response shape (`search.ts: GlobalSearchResponse`): `{ query, results: { users, posts,
catalog, files, messages?, tickets?, contacts?, videos?, calendar? }, partial? }` where each
section is `SearchResultSection { items: SearchResultItem[], total_estimate, has_more }` and
`SearchResultItem { type, id, title, snippet, thumbnail_url?, url, meta? }`.

Filter-to-parameter mapping owned by this ticket:

| UI control            | Request parameter        | Values                                                              |
|-----------------------|--------------------------|--------------------------------------------------------------------|
| Tab / entity filter   | `types`                  | omit for ALL (= server default of all 9); else section key(s), e.g. `users`, `posts`, `catalog`, `files`, `messages`, `tickets`, `contacts`, `videos`, `calendar`, comma-joined |
| Sort                  | *(none — no server param)* | client-only if shipped (see §4.1); default = backend relevance ordering |

```kotlin
// com.testlogon.android.feature.search
fun SearchFilters.toQueryParams(): Map<String, String?> = mapOf(
    "types" to entityType.toWireOrNull(),  // ALL -> null (omit); else section key
    // [CORRECTED] no "sort" entry — backend exposes no sort parameter
)
```

**[CORRECTED] Decision rule.** The `types` parameter **does** exist, so a server-side path
is available. However, the **web reference filters tabs client-side**: `SearchPage.tsx`
fetches once with `globalSearch(query, undefined, 10)` and scopes each tab over the fetched
sections. To match the web contract (and avoid N requests on tab switches), the
**recommended default is client-side tab filtering** over the single all-categories
`GlobalSearchResponse`; use the `types` param only as an optimization (e.g. fetching a single
heavy category on demand). Either way the UI contract in §4 is unchanged. Any sort control,
if shipped, is **client-side only** (per category, over fields the DTO exposes) — there is no
server sort.

Error bodies use the FastAPI `HTTPValidationError` `detail` shape (`detail: [{loc, msg,
type}]`) decoded by the shared error mapper (AND-015) into `ApiResult.Failure`. The endpoint
documents only `200` and `422`. A `422` typically means `q` is missing/empty or out of the
1–500 length bound, or `types` contains an unknown key — treated as a client bug (caught in
tests), not a user-facing error.

## 6. Data & State Management

- Single source of truth: `SearchFilterController.uiState: StateFlow<SearchUiState>`
  (becomes `SearchViewModel.uiState` in AND-187 with the same shape).
- Filter/tab/query selection persisted in `SavedStateHandle` (keys `query`,
  `entity_type`; [CORRECTED] no `sort` key — no sort parameter exists) so it survives
  configuration change and process death (FR-7).
- Recent searches: [CORRECTED] the authoritative source is the **server-side** history API
  (`/ui/search/history`, see §4.3). If a local DataStore cache is kept, it is capped at
  N=10, de-duplicated case-insensitively, most-recent-first, and cleared on logout; it must
  be reconciled with the server list (the web app lists/records/deletes via the API).
- Navigation modeled as one-shot effects via a `Channel`/`receiveAsFlow` so result taps are
  not re-fired on config change (same pattern as AND-182).
- The categorized `SearchResults` is held only in the current `Content` state; switching
  tabs reads from it (client-side path) or replaces it (server-side path). No Room caching
  in this ticket; durable search-result caching is out of scope (deferred to the cache
  epic if ever needed — search is intentionally live).
- Last-used filter defaults are retained in memory for the session so clearing the query
  does not reset the user's preferred sort.

## 7. Error Handling & Resilience

- Dev host is plaintext and unreliable: OkHttp call timeout ~20s (AND-009); bounded
  exponential backoff on the idempotent search GET only (AND-016).
- `ApiResult.Failure` mapped per AND-015/AND-018:
  - Network/timeout with no connectivity and no prior results → `Offline` (AND-021 offline
    composable, Retry).
  - Network/timeout while `Content` is shown (e.g. a tab re-issue failed) → keep existing
    `Content`, mark `isStale = true`, show a transient snackbar; never blank a populated
    result list.
  - HTTP 4xx/5xx → `Error(message, retryable)` with `detail` mapped to a readable string;
    Retry calls `retry()` with the current query+filters.
  - 401 → transparent refresh via the authenticator (AND-013); a second 401 defers to
    global re-auth routing (AND-025), not a local error.
- **Zero results is not an error:** a successful response with no items for the current
  tab/filters yields `NoResults` (FR-6), with "Clear filters"/"Search everything"
  affordances when filters are non-default. This is the explicit distinction the backlog
  scope calls out.
- Empty/whitespace query never issues a request; it returns to `Idle(recent)`.
- Rapid tab/filter changes cancel the in-flight request (structured concurrency:
  `collectLatest` / job cancellation) so only the latest selection's result renders.

## 8. Security & Privacy

- All search requests are authenticated via the persistent cookie jar (AND-011) +
  `X-CSRF-Token` echo (AND-012); no credentials handled here. [VERIFIED] The web client
  (`client.ts`) reads the `ui_csrf` cookie and sends it as the `X-CSRF-Token` header on
  requests. The CSRF header is required for the **mutating** history calls (`POST`/`DELETE
  /ui/search/history`); the search `GET /ui/search` is a safe method but still rides the
  authenticated session cookie.
- **Recent searches are user content and potentially sensitive.** [CORRECTED] Note they are
  also persisted **server-side** by the backend history API (`POST /ui/search/history`); the
  web client records them automatically after results arrive. Any local cache is stored
  unencrypted in app-private DataStore (acceptable for non-credential data), **cleared on
  logout** to prevent cross-account leakage on a shared device, and **never** sent to
  telemetry — only aggregate counts/flags are logged, never the query text (see §10).
- Cleartext HTTP to the dev host is permitted only via the dev flavor's network-security
  config (AND-006/AND-009); release builds must not reach a cleartext host.
- No query strings or result identifiers containing PII are written to logs at any level.

## 9. Accessibility & i18n

- All labels (tab titles, filter options, "Clear", "Clear all", prompts, no-results copy)
  come from string resources; no hardcoded UI strings (i18n plumbing AND-111, catalogs
  AND-112). The searched term is interpolated via a parameterized resource.
- RTL-ready (AND-114): start/end paddings; `ScrollableTabRow` and chips mirror correctly.
- Tabs expose `selectableGroup()` semantics; the selected tab announces its selected state.
  Filter chips announce removable state; the filter icon's badge announces
  "Filters active". The no-results region uses `liveRegion = Assertive` so TalkBack
  announces it after a search; the stale banner uses `Polite`.
- Touch targets ≥ 48dp (tabs, chip close buttons, recent-search remove). Recent-search rows
  expose a remove action via custom accessibility action, not only the small × hit target.
- Large font scaling: tab labels and chips ellipsize at one line; layout does not clip.

## 10. Telemetry & Logging

- Events via the analytics facade (redacted per AND-052 — **never log query text**):
  - `search_tab_select` — `{ entity_type }`.
  - `search_filter_apply` — `{ entity_type, changed: [..] }` ([CORRECTED] no `sort` field —
    no sort parameter; include a `client_sort` flag only if a client-only sort ships).
  - `search_filter_clear` — `{}`.
  - `search_recent_run` — `{ position }` (index in the recent list; no text).
  - `search_recent_remove` / `search_recent_clear_all` — `{}`.
  - `search_no_results` — `{ entity_type, filters_active, query_len }` (length only, never
    the string).
- Debug logging via the shared logger logs query **length** and result **counts** only.
  OkHttp body-level logging is dev-flavor only (AND-009); query strings appear there only in
  dev builds, never release.

## 11. Testing Strategy

- **Unit (core-testing + MockWebServer, AND-046):**
  - `SearchFilters.toQueryParams`: ALL → null/omitted `types`; non-ALL → the correct section
    key (e.g. USERS → `users`, POSTS → `posts`); `isDefault` correct. [CORRECTED] No `sort`
    entry is emitted (no server param).
  - `DataStoreRecentSearchesStore`: add trims/de-dups (case-insensitive) and moves to top;
    cap at N evicts oldest; blank queries ignored; remove/clear; survives a store reopen;
    cleared on logout hook.
  - `SearchFilterController`:
    - `onTabSelected` re-issues the search with the right `type` (server path) or filters
      the held results (client path) and updates `selected`.
    - `applyFilters`/`clearFilters` recompute params, set/reset filter chips, and update
      results; `isDefault` drives the badge.
    - Successful non-empty response → `Content`; successful empty response →
      `NoResults(filtersActive=...)`; empty query → `Idle(recent)`.
    - `submitQuery` commits the term to recent (de-duped, top); `runRecent` re-runs it.
    - Failure mapping: offline, stale-on-content, error, transparent-401 (per §7).
    - Rapid tab switches cancel the prior request (only latest result applied).
    - Selection restored from `SavedStateHandle`.
- **Compose UI tests (AND-048 harness):**
  - Tab row renders derived tabs with All first; selecting a tab invokes `onTabSelected`
    and the rendered list scopes to that entity.
  - Filter sheet opens, applying a non-default sort shows the filter badge + a chip; "Clear"
    removes them; chip × invokes clear.
  - Empty query shows recent searches; tapping one invokes `onRunRecent`; remove and
    "Clear all" work.
  - No-results state renders the searched term and the "Clear filters"/"Search everything"
    affordances only when appropriate; idle vs. no-results are distinct.
  - State restoration: rotate with an active tab+filter+query and assert it persists.
- **Acceptance gate:** "Filters refine results" is verified by the tab-scoping and
  filter-apply UI tests (results visibly change) plus a `SearchFilterController` unit test
  asserting the request parameters and resulting state, and a manual run against the dev
  backend.

## 12. Dependencies & Sequencing

- **Hard dep (from backlog):**
  - **AND-185** — Global search (multi-entity). Provides `SearchApi`, result DTOs,
    `SearchMapper`, the categorized `SearchResults` model, and the `SearchRepository`/search
    binding this ticket drives. The tab set is derived from AND-185's entity categories;
    must land first.
- **Blocks:**
  - **AND-187** — Discovery/search ViewModels (debounce, paging, state). Consumes the
    `SearchFilters`/`SearchTab`/`SearchUiState` contract and replaces the interim
    `SearchFilterController` with the production `SearchViewModel`. This ticket must land (or
    at least freeze the contract) before AND-187.
- **Implicit infra deps (already in M0–M2):** AND-010 (Retrofit/Moshi), AND-015 (error
  mapping), AND-016 (GET retry), AND-018 (`ApiResult`), AND-021 (state composables), AND-020
  (input composables), AND-024 (authenticated nav graph), AND-017 (connectivity), AND-027
  (auth request plumbing), DataStore baseline (prefs).
- **Navigation targets (must exist or be stubbed):** AND-073 (public profile
  `profile/{userIdentifier}`) and AND-100 (post detail `post/{postId}`); wire to placeholder
  destinations if not yet merged.

## 13. Risks & Open Questions

- **R1 — Server-side vs. client-side filtering.** Whether the search endpoint supports
  `type`/`sort` parameters is unconfirmed. Mitigation: the §5 decision rule keeps the UI
  contract stable either way; verify `/openapi.json` first. *Open: which sort values does
  the backend accept, and is `type` multi-valued?*
- **R2 — Tab set source.** Tabs derive from AND-185's entity categories; if AND-185's
  category enum is still in flux, the tab list could churn. Mitigation: depend on the enum,
  not hardcoded tabs; "All" is the only guaranteed tab.
- **R3 — Overlap with AND-187.** Debounce/paging belong to AND-187; this ticket
  deliberately submits on explicit actions to stay deterministic. Risk of duplicated
  orchestration when AND-187 lands. Mitigation: identical public state/intent surface so the
  controller is swapped, not rewritten.
- **R4 — Recent-search privacy.** Queries may contain sensitive terms. Mitigation: app-
  private storage, logout-clear, never in telemetry. *Open: should recent searches be
  opt-out or auto-expiring?* Deferred to product.
- **R5 — Client-side sort fidelity.** If sort is client-side (R1 negative), the DTO may lack
  the field needed to sort a given category (e.g. recency). Mitigation: only offer sort
  options the data supports; hide unsupported options per category.
- **R6 — Unreliable dev host** makes empty-vs-error classification depend on connectivity
  signal fidelity (AND-017); 20s timeout + stale path mitigate.

## 14. Acceptance Criteria

AC-1. **Filters refine results** *(backlog acceptance)*: selecting a non-All tab scopes the
visible results to that entity type, and applying a sort/type filter changes the rendered
result set. Verified by the tab-scoping and filter-apply UI tests and a controller unit test
asserting the request parameters (or client-side filtering) and resulting state.

AC-2. The tab row renders categories derived from AND-185's result model with "All" pinned
first; the selected tab is visually indicated and survives rotation.

AC-3. The filter sheet opens, applies entity-type and sort refinements, shows an active-
filter badge and removable chips when non-default, and "Clear" resets to defaults.

AC-4. Recent searches show when the query is empty; tapping re-runs a query; remove and
"Clear all" work; a committed search is de-duplicated to the top; the list persists across
app restart and is cleared on logout.

AC-5. The **idle/empty** state (no query) and the **no-results** state (query ran, zero
results) are distinct; no-results echoes the searched term and offers "Clear filters" /
"Search everything" only when filters are non-default.

AC-6. Failure handling matches §7: offline, stale-on-content (never blanks a populated
list), error with working Retry, and transparent 401 refresh.

AC-7. No query text in telemetry or release logs; selection state restored from
`SavedStateHandle` after config change/process death.

AC-8. All §11 unit and Compose UI tests pass in CI (AND-050/AND-051).

## 15. Definition of Done

- `feature-search` extended under `com.testlogon.android.feature.search` with the filter/tab
  model (`SearchEntityType`, `SearchSort`, `SearchFilters`, `SearchTab`), `SearchUiState`,
  the interim `SearchFilterController`, `RecentSearchesStore` +
  `DataStoreRecentSearchesStore`, and the Compose surface (`SearchRoute`/`SearchScreen`,
  `SearchTabRow`, `FilterSheet`, `ActiveFilterChips`, `RecentSearches`, `NoResults`).
- Hilt bindings (KSP) wired (`RecentSearchesStore` binding, named `search_prefs` DataStore);
  screen registered in the authenticated nav graph with `onOpenUser`/`onOpenContent`
  callbacks connected to real or stubbed targets.
- Filter-to-query-parameter mapping verified against `/openapi.json` and `search.ts`; the
  server-side-vs-client-side §5 decision recorded in the PR.
- Recent searches cleared on logout (AND-032 wiring) and excluded from telemetry; selection
  persisted in `SavedStateHandle`.
- All §11 unit and Compose UI tests written and green in CI; lint/detekt/ktlint clean
  (AND-005).
- The `SearchFilters`/`SearchTab`/`SearchUiState` contract reviewed with the AND-187 owner so
  the `SearchViewModel` swap is mechanical.
- Manual verification against `http://18.222.237.167:8000`: selecting tabs and applying
  filters demonstrably refines results; recent searches and both empty states render
  correctly.
- Spec deviations (especially endpoint filter support) reconciled and documented in the PR;
  code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI
`reference/openapi.index.txt` / `reference/openapi.pretty.json` (cited as `METHOD /path` and
schema name), or frontend files under `reference/src/` (cited as `path: symbol`).

1. **The global search endpoint is `GET /ui/search`.** VERDICT: **Corrected** (spec §5 said
   `@GET("search")`). SOURCE: OpenAPI `GET /ui/search` (op `global_search_ui_search_get`);
   `src/api/endpoints/search.ts: globalSearch` calls `api.get("/ui/search", ...)`.
2. **The entity-type query parameter is `types` (plural, comma-separated string), not
   `type`.** VERDICT: **Corrected**. SOURCE: OpenAPI `GET /ui/search` param `types`
   (default `calendar,catalog,contacts,files,messages,posts,tickets,users,videos`);
   `src/api/endpoints/search.ts: globalSearch(q, types?, limit)` → `params.types = types`.
3. **The search endpoint has NO `sort` parameter.** VERDICT: **Corrected** (spec §5 bound a
   `sort` filter to a `@Query("sort")`). SOURCE: OpenAPI `GET /ui/search` params are exactly
   `q, types, limit, user_sub` (+ session/impersonation headers); no `sort`. No sort control
   appears in `src/pages/search/SearchPage.tsx`.
4. **The search endpoint has NO `cursor`/pagination parameter.** VERDICT: **Corrected** (spec
   §5 showed `@Query("cursor")`). SOURCE: OpenAPI `GET /ui/search` param list (above). It
   exposes `limit` (1–20, default 5) only. (The separate `GET /ui/discover/search` and
   `GET /ui/alerts/search` do have `cursor`, but those are different endpoints.)
5. **`q` is required, length 1–500; `limit` is 1–20 default 5.** VERDICT: **Verified**.
   SOURCE: OpenAPI `GET /ui/search` schema (`q` minLength 1 / maxLength 500; `limit` min 1 /
   max 20 / default 5). The web client passes `limit = 10` (`SearchPage.tsx: globalSearch(..., 10)`).
6. **Response is a sectioned multi-category object `GlobalSearchResponse`.** VERDICT:
   **Verified**. SOURCE: `src/api/endpoints/search.ts: GlobalSearchResponse` /
   `SearchResultSection` / `SearchResultItem`. (OpenAPI `200` schema is empty `{}` — untyped —
   so the frontend types are the authoritative shape.)
7. **There are NINE result categories, not just users/content.** VERDICT: **Corrected** (spec
   §4.1 enum was `ALL, USERS, CONTENT`). SOURCE: `src/api/endpoints/search.ts:
   SearchResultType` = user|post|catalog|file|message|ticket|contact|video|calendar;
   `SearchPage.tsx: SEARCH_TABS` = all, users, posts, catalog, files, messages, tickets,
   contacts, videos, calendar; OpenAPI `types` default lists the same nine section keys.
8. **Section keys (used in `types`) are plural; per-item `type` is singular.** VERDICT:
   **Verified**. SOURCE: `GlobalSearchResponse.results` keys (`users`, `posts`, `files`, ...)
   vs `SearchResultItem.type` values (`user`, `post`, `file`, ...) in `search.ts`.
9. **The web client filters tabs CLIENT-SIDE (does not pass `types`).** VERDICT: **Verified /
   Corrected** (spec §5 framed server-side as the primary/uncertain path). SOURCE:
   `src/pages/search/SearchPage.tsx`: `globalSearch(debouncedQuery, undefined, 10)` and
   per-tab scoping via `sectionCount`/`results[tab.value]`.
10. **Recent searches are backed by a SERVER-SIDE history API, not just local storage.**
    VERDICT: **Corrected** (spec §4.3/§6/§8 designed a local DataStore as source of truth).
    SOURCE: OpenAPI `GET /ui/search/history`, `POST /ui/search/history`
    (`req=RecordSearchHistoryReq`), `DELETE /ui/search/history/{item_id}`,
    `DELETE /ui/search/history`; `src/api/endpoints/search.ts:
    getSearchHistory/recordSearchHistory/deleteSearchHistoryItem/clearSearchHistory`;
    `SearchPage.tsx: SearchHistorySidebar` consumes all four.
11. **History record body is `{ query, result_count }` (query required, result_count default
    0).** VERDICT: **Verified**. SOURCE: OpenAPI schema `RecordSearchHistoryReq`;
    `search.ts: recordSearchHistory(query, result_count)`.
12. **History items carry a server `id` and removal is by item id.** VERDICT: **Verified /
    Corrected** (spec §4.3 `remove(query: String)` removes by text). SOURCE:
    `search.ts: SearchHistoryItem { id, query, ts, result_count }` and
    `deleteSearchHistoryItem(id)`; OpenAPI `DELETE /ui/search/history/{item_id}`.
13. **Web records history automatically after results arrive (length≥2), with total result
    count.** VERDICT: **Verified**. SOURCE: `SearchPage.tsx` effect on `data` →
    `recordMut.mutate({ query, count: totalResults })`. (Spec FR-5 commits on successful
    search — consistent.)
14. **Web debounces query input at 300ms.** VERDICT: **Verified** (informational; debounce is
    AND-187 scope per spec §4.2). SOURCE: `SearchPage.tsx: useDebounce(inputValue, 300)`.
15. **Search query is enabled only when query length ≥ 1.** VERDICT: **Verified** (supports
    FR-6 idle vs no-results). SOURCE: `SearchPage.tsx: useQuery({ enabled: debouncedQuery.length >= 1 })`.
16. **Auth uses session cookie + `X-CSRF-Token` echoed from the `ui_csrf` cookie.** VERDICT:
    **Verified**. SOURCE: `src/api/client.ts`: `getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)` with `credentials: "include"`. CSRF is required for
    the mutating history POST/DELETE; `GET /ui/search` is a safe method.
17. **Error bodies use the FastAPI `HTTPValidationError`/`detail` shape; endpoint declares
    only 200 and 422.** VERDICT: **Verified**. SOURCE: OpenAPI `GET /ui/search` responses
    `200` + `422:HTTPValidationError`; schema `HTTPValidationError { detail: [{loc,msg,type}] }`.
18. **Material 3 `ScrollableTabRow` / `ModalBottomSheet` / `FilterChip` are the chosen
    components; `selectableGroup()` and `liveRegion` for a11y.** VERDICT:
    **Unverified-assumption** (Android framework choices — not derivable from backend/web
    sources). SOURCE: framework ref —
    https://developer.android.com/develop/ui/compose/components/tabs ,
    https://developer.android.com/reference/kotlin/androidx/compose/material3/package-summary#ModalBottomSheet ,
    https://developer.android.com/develop/ui/compose/accessibility .
19. **`SavedStateHandle` survives configuration change and process death for the persisted
    selection.** VERDICT: **Unverified-assumption** (framework behavior, reasonable). SOURCE:
    framework ref — https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate .
20. **Backend is FastAPI + DynamoDB on `http://18.222.237.167:8000`.** VERDICT:
    **Unverified-assumption** (host/infra not confirmable from the provided sources; OpenAPI
    confirms FastAPI-style schemas but not DynamoDB or the host). SOURCE: spec §2 only.

### Corrections made

- §2/§5: endpoint corrected `search` → `GET /ui/search`; entity param `type` → `types`
  (plural, comma-joined); removed non-existent `sort` and `cursor` params; documented exact
  param bounds (`q` 1–500, `limit` 1–20 default 5) and the `GlobalSearchResponse` shape.
- §2: corrected DTO location — result/item types live in `search.ts`, not `types.ts`.
- §4.1: expanded `SearchEntityType` from `ALL/USERS/CONTENT` to the nine real categories;
  removed the `SearchSort` enum and the `sort` field from `SearchFilters` (no server backing);
  documented plural section keys vs singular item `type`.
- §4.2/§6: removed the `sort` `SavedStateHandle` key.
- §4.3/§6/§8: flagged the local-DataStore recent-searches design as a deviation from the
  server-side `/ui/search/history` API the web client uses; noted removal is by server item
  `id`, not by query text.
- §3 FR-3, §10, §11: removed/qualified `sort` as client-only/unbacked rather than a real
  filter or telemetry field.
- §5: corrected the decision rule — `types` exists, but the web reference filters tabs
  client-side; client-side is the recommended default, server `types` is an optimization.
- §8: noted CSRF (`ui_csrf` → `X-CSRF-Token`) applies to the mutating history calls.

### Open assumptions

- **Client-only sort fidelity (R5):** whether each category DTO exposes a field sufficient to
  sort (e.g. recency) is unverifiable — the `200` response is untyped in OpenAPI and
  `SearchResultItem.meta` is an opaque `Record<string, unknown>`. Offer sort only where the
  data supports it, or omit it.
- **Local vs server recent searches:** whether the Android port should make the server
  `/ui/search/history` the source of truth (matching web) or keep a local-only store for
  offline-first on the unreliable dev host is a product/architecture decision; not resolvable
  from sources. Recommended: server-backed with local cache.
- **Android UI/framework choices** (Material 3 components, `SavedStateHandle`, DataStore):
  reasonable but not derivable from backend/web sources; cited as framework refs above.
- **Backend infra/host** (DynamoDB, dev IP, cleartext policy): asserted by the spec, not
  confirmable from the provided OpenAPI/frontend sources.
- **`partial: true` semantics** (`GlobalSearchResponse.partial`): present in the DTO but its
  exact meaning (degraded/timed-out category) is not documented; treat a `partial` response
  as success-with-possibly-incomplete-sections and do not classify it as an error.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device); **MWS** =
contract test with MockWebServer; **EMU(test35)** = headless emulator AVD `test35`
(x86_64, Android 15 / API 35); **DEVICE** = physical Samsung Galaxy A15 5G (SM-A156U,
serial `R5CX821TA9R`, Android 14 / API 34, arm64-v8a). UI/instrumented cases run on
EMU(test35) by default; cases that must exercise real hardware or ABI/API-level differences
note DEVICE explicitly. This ticket has no camera/biometrics/WebRTC/FCM/Telecom surface, so
DEVICE is used only for ABI/API-34-vs-35 confidence and real-network/real-cleartext-host
behavior against the flaky dev host.

- **TC-AND-186-01 — `SearchFilters.toQueryParams` maps entity type to `types`, omits sort.**
  Type: unit. Target: JVM. Preconditions: none.
  Steps: (1) `SearchFilters()` (ALL) → params. (2) `SearchFilters(USERS)` → params.
  (3) `SearchFilters(POSTS)` → params.
  Expected: ALL yields `types` null/omitted; USERS yields `types="users"`; POSTS yields
  `types="posts"`; the map never contains a `sort` key; `SearchFilters().isDefault == true`,
  non-ALL `isDefault == false`.
  Traces: AC-1, AC-3.

- **TC-AND-186-02 — Search request hits `GET /ui/search` with correct params.**
  Type: contract/MockWebServer. Target: JVM + MWS. Preconditions: MWS enqueues a valid
  `GlobalSearchResponse`.
  Steps: trigger `submitQuery()` for query `"alice"` with ALL scope; then with USERS scope.
  Expected: recorded request path is `/ui/search`; query string has `q=alice`,
  `limit` within 1..20; ALL omits `types`; USERS sends `types=users`; no `sort`/`cursor`
  params present.
  Traces: AC-1.

- **TC-AND-186-03 — Successful multi-category response → `Content`; tab scoping is correct.**
  Type: unit. Target: JVM (+ MWS for the fetch). Preconditions: response has items in
  `users` and `posts`, empty elsewhere.
  Steps: submit query; assert `Content`; call `onTabSelected(ALL)` then `onTabSelected(USERS)`
  then `onTabSelected(POSTS)`.
  Expected: ALL exposes all non-empty sections (sectioned); USERS exposes only user items as a
  flat list; POSTS only post items; `selected` updates each time; no extra network call when
  filtering client-side (per §5 recommended path).
  Traces: AC-1, AC-2.

- **TC-AND-186-04 — Empty response for current tab → `NoResults` (not Error), with correct
  `filtersActive`.**
  Type: unit. Target: JVM + MWS. Preconditions: response with all sections empty.
  Steps: (1) submit query with default filters → assert `NoResults(filtersActive=false)`.
  (2) apply a non-default entity filter, submit → assert `NoResults(filtersActive=true)`.
  Expected: state is `NoResults` (zero results is not an error); `query` echoed;
  `filtersActive` reflects whether filters are non-default.
  Traces: AC-1, AC-5, AC-6.

- **TC-AND-186-05 — Empty / whitespace query never issues a request and returns to
  `Idle(recent)`.**
  Type: unit. Target: JVM + MWS. Preconditions: MWS running; recent list non-empty.
  Steps: `onQueryChange("")`; `onQueryChange("   ")`; `submitQuery()`.
  Expected: no request recorded by MWS; state is `Idle(recent)`; recent list surfaced.
  Traces: AC-5.

- **TC-AND-186-06 — Validation 422 from `q` bounds / unknown `types` is handled as a client
  bug, surfaced via the AND-015 detail mapper.**
  Type: contract/MockWebServer. Target: JVM + MWS. Preconditions: MWS enqueues `422` with an
  `HTTPValidationError` body `{ detail: [{loc, msg, type}] }`.
  Steps: issue a search that produces a 422 (e.g. simulate an out-of-bounds `q` or bad
  `types`).
  Expected: `ApiResult.Failure` carries the mapped `detail` message; the controller does NOT
  present it as a normal user-facing retryable error path for a malformed param (test asserts
  it is caught/logged as a client error). No crash.
  Traces: AC-1, AC-6.

- **TC-AND-186-07 — Recent searches via server history API: list, record-on-success, delete
  by id, clear all.**
  Type: contract/MockWebServer. Target: JVM + MWS. Preconditions: MWS stubs
  `GET/POST/DELETE /ui/search/history`.
  Steps: (1) load idle → assert `GET /ui/search/history?limit=...`. (2) submit a successful
  search → assert `POST /ui/search/history` with body `{query, result_count}`.
  (3) remove one item → assert `DELETE /ui/search/history/{id}` with the server item id.
  (4) clear all → assert `DELETE /ui/search/history`.
  Expected: each call uses the correct method/path/body; de-dup moves a re-run query to top
  on reload.
  Traces: AC-4.

- **TC-AND-186-08 — Mutating history calls carry `X-CSRF-Token`; search GET rides session
  cookie.**
  Type: contract/MockWebServer. Target: JVM + MWS. Preconditions: auth plumbing (AND-027)
  active with a CSRF token available.
  Steps: record a history item (POST) and delete one (DELETE); also perform a search (GET).
  Expected: POST and DELETE requests include the `X-CSRF-Token` header; all three include the
  session cookie; the search GET does not require CSRF.
  Traces: AC-4, AC-7 (security).

- **TC-AND-186-09 — Failure mapping: offline, stale-on-content, retryable error, transparent
  401.**
  Type: unit. Target: JVM + MWS. Preconditions: connectivity signal mockable (AND-017).
  Steps: (1) no connectivity + no prior results → `Offline`. (2) `Content` shown, a tab
  re-issue fails with timeout → keep `Content`, `isStale=true`, no blanking. (3) HTTP 500 →
  `Error(retryable=true)`; `retry()` re-issues with current query+filters. (4) first 401 →
  transparent refresh then success; second 401 → defers to global re-auth, not local error.
  Expected: each mapping matches §7.
  Traces: AC-6.

- **TC-AND-186-10 — Rapid tab/filter switches cancel the in-flight request (latest wins).**
  Type: unit. Target: JVM + MWS. Preconditions: MWS with a slow first response, fast second.
  Steps: trigger a search, then immediately switch tabs/filters before the first completes.
  Expected: only the latest selection's result is applied (`collectLatest`/job cancellation);
  no flicker of stale results; prior request cancelled.
  Traces: AC-1, AC-6.

- **TC-AND-186-11 — Tab row renders nine derived tabs with All pinned first; selection scopes
  the rendered list.**
  Type: Compose-UI. Target: EMU(test35). Preconditions: `Content` state with mixed sections.
  Steps: render `SearchScreen`; assert tab order (All, then categories); tap "Users".
  Expected: All is first and highlighted initially; tapping invokes `onTabSelected(USERS)` and
  the list scopes to user rows; selected tab visually indicated.
  Traces: AC-1, AC-2.

- **TC-AND-186-12 — Filter sheet + active-filter badge/chips + Clear.**
  Type: Compose-UI. Target: EMU(test35). Preconditions: `Content` state.
  Steps: open `FilterSheet`; select a non-default entity filter and apply; observe badge +
  `FilterChip`; tap chip ×; tap "Clear".
  Expected: applying shows the filter badge and a removable chip; chip × and "Clear" both
  reset to defaults (badge/chips disappear, `onClearFilters` invoked).
  Traces: AC-3.

- **TC-AND-186-13 — Idle vs No-results are distinct; recent searches interactions.**
  Type: Compose-UI. Target: EMU(test35). Preconditions: provide both `Idle(recent=[...])`
  and `NoResults` states.
  Steps: render `Idle` → assert recent list shown, tap a row (invokes `onRunRecent`), tap
  remove (×) and "Clear all". Render `NoResults` with `filtersActive=true` → assert searched
  term echoed and both "Clear filters" and "Search everything" affordances; render with
  `filtersActive=false` → assert "Clear filters" hidden.
  Expected: idle and no-results are visually/behaviorally distinct per FR-6; affordances gated
  on `filtersActive`.
  Traces: AC-4, AC-5.

- **TC-AND-186-14 — State restoration: rotate with active query+tab+filter.**
  Type: instrumented (Compose). Target: EMU(test35). Preconditions: active query, non-All
  tab, non-default filter.
  Steps: trigger config change (rotation) and process-death restore.
  Expected: query text, selected tab, and filter state restored from `SavedStateHandle`; no
  re-fire of nav effects.
  Traces: AC-2, AC-7.

- **TC-AND-186-15 — Accessibility: tab selection, removable chips, badge, no-results live
  region, touch targets.**
  Type: Compose-UI (a11y). Target: EMU(test35) (TalkBack assertions via semantics).
  Preconditions: `Content` with non-default filter and a `NoResults` render.
  Steps: assert selected tab exposes selected-state semantics within a `selectableGroup`;
  chips announce removable; filter badge announces "Filters active"; no-results region is an
  Assertive live region and the stale banner Polite; tap targets (tabs, chip ×, recent remove)
  ≥ 48dp; labels come from string resources.
  Traces: AC-7 (a11y), AC-3, AC-5.

- **TC-AND-186-16 — Real flaky dev host: cleartext, timeout/offline, and ABI/API-34 behavior
  on hardware.**
  Type: instrumented/e2e (manual-assisted). Target: **DEVICE** (must run on physical
  SM-A156U; arm64-v8a, API 34, real cellular/Wi-Fi). Preconditions: dev flavor pointed at
  `http://18.222.237.167:8000`.
  Steps: (1) run a search over real network; verify cleartext is permitted only in the dev
  flavor and results render. (2) toggle airplane mode mid-search → `Offline`/stale path per
  §7. (3) repeat a previously-passing JVM/MWS flow to confirm no arm64-vs-x86 or
  API-34-vs-35 regression.
  Expected: search works against the real host; offline/stale handled gracefully; behavior
  matches emulator results (no ABI/API-level divergence).
  Traces: AC-1, AC-6.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (filters refine results) | TC-01, TC-02, TC-03, TC-04, TC-06, TC-10, TC-11, TC-16 |
| AC-2 (tab row: All first, indicated, survives rotation) | TC-03, TC-11, TC-14 |
| AC-3 (filter sheet, badge/chips, Clear) | TC-01, TC-12, TC-15 |
| AC-4 (recent searches: list/run/remove/clear/dedup/persist/logout) | TC-07, TC-08, TC-13 |
| AC-5 (idle vs no-results distinct; gated affordances) | TC-04, TC-05, TC-13 |
| AC-6 (failure handling: offline/stale/error/401) | TC-04, TC-06, TC-09, TC-10, TC-16 |
| AC-7 (no query text in telemetry/logs; restoration; a11y/security) | TC-08, TC-14, TC-15 |
| AC-8 (all §11 unit + Compose UI tests green in CI) | TC-01…TC-15 (CI suite; TC-16 is on-device/manual) |
