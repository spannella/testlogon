---
id: AND-186
title: Search filters/tabs
milestone: M4
epic: E25
priority: P1
size: M
status: draft
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
  unreliable). OpenAPI at `/openapi.json`. The search endpoint's supported query
  parameters (entity-type filter, sort, pagination) are the authoritative source for which
  filters are real vs. client-side; confirm against `/openapi.json` and the web reference
  before finalizing the filter model.
- **Web reference:** `frontend/src/api/endpoints/search.ts` (the search surface AND-185
  ports; defines the `type`/`sort` query parameters this ticket binds to UI controls),
  `frontend/src/api/types.ts` (categorized result and entity DTO shapes).
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
`ModalBottomSheet`) for refinements beyond entity type: at minimum a **sort** option
(e.g. Relevance / Recent) and entity-type selection (mirroring tabs for explicit
multi-select where the backend allows). Only filters backed by a real backend query
parameter are functional; any client-only refinement is clearly bounded and noted. Applying
filters re-runs the query with the new parameters and updates results.

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

/** Entity scope; mirrors the categories AND-185 returns. ALL = un-scoped. */
enum class SearchEntityType { ALL, USERS, CONTENT /* + others from backend */ }

enum class SearchSort { RELEVANCE, RECENT }

data class SearchFilters(
    val entityType: SearchEntityType = SearchEntityType.ALL,
    val sort: SearchSort = SearchSort.RELEVANCE,
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

Selection is persisted to `savedState` under keys `query`, `entity_type`, `sort`.
`onTabSelected`/`applyFilters` recompute the request and re-issue via the repository,
mapping `ApiResult` to `Content`/`NoResults`/`Error`/`Offline` exactly as §6/§7 specify.

> Note: AND-186 owns filter/tab/recent **state and UI**. Query **debounce** and **Paging 3**
> wiring are explicitly AND-187's responsibility; this controller submits on explicit
> `submitQuery()`/tab/filter changes (no debounce) so it is deterministic in tests. The
> debounce path attaches to `onQueryChange` in AND-187 without changing this surface.

### 4.3 Recent searches store

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
owned by AND-185; confirm parameter names against `/openapi.json` and `search.ts`.

Representative search call as exercised by filters/tabs (final names per AND-185):

```kotlin
interface SearchApi {              // owned by AND-185 — shown for the params this ticket drives
    @GET("search")
    suspend fun search(
        @Query("q") query: String,
        @Query("type") type: String? = null,     // entity-type filter <- tabs / filter sheet
        @Query("sort") sort: String? = null,     // <- filter sheet
        @Query("cursor") cursor: String? = null, // <- AND-187 paging
    ): Response<SearchResultsDto>
}
```

Filter-to-parameter mapping owned by this ticket:

| UI control            | Request parameter        | Values                          |
|-----------------------|--------------------------|---------------------------------|
| Tab / entity filter   | `type`                   | omit for ALL; `users`,`content` |
| Sort filter           | `sort`                   | `relevance` (default), `recent` |

```kotlin
// com.testlogon.android.feature.search
fun SearchFilters.toQueryParams(): Map<String, String?> = mapOf(
    "type" to entityType.toWireOrNull(),   // ALL -> null
    "sort" to sort.toWire(),
)
```

**Decision rule (verify against `/openapi.json`):**
- If the search endpoint accepts `type`/`sort`, tabs and filters re-issue the GET with
  those params (server-side filtering) and rely on the AND-185 mapper.
- If it does **not**, the All-query result is fetched once and tabs/sort are applied
  **client-side** over the categorized `SearchResults` (sort applied per category by the
  fields the DTO exposes). Either way the UI contract in §4 is unchanged.

Error bodies use the FastAPI `detail` shape (string | `[{msg}]` | `{code,...}`) decoded by
the shared error mapper (AND-015) into `ApiResult.Failure`. A `422` on an unsupported
filter value is treated as a client bug (caught in tests), not a user-facing error.

## 6. Data & State Management

- Single source of truth: `SearchFilterController.uiState: StateFlow<SearchUiState>`
  (becomes `SearchViewModel.uiState` in AND-187 with the same shape).
- Filter/tab/query selection persisted in `SavedStateHandle` (keys `query`,
  `entity_type`, `sort`) so it survives configuration change and process death (FR-7).
- Recent searches persisted in DataStore via `RecentSearchesStore` (durable across app
  restart); capped at N=10, de-duplicated case-insensitively, most-recent-first, cleared on
  logout.
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
  `X-CSRF-Token` echo (AND-012); no credentials handled here.
- **Recent searches are user content and potentially sensitive.** They are stored
  unencrypted in app-private DataStore (acceptable for non-credential data), are **cleared
  on logout** to prevent cross-account leakage, and are **never** sent to telemetry — only
  aggregate counts/flags are logged, never the query text (see §10).
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
  - `search_filter_apply` — `{ entity_type, sort, changed: [..] }`.
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
  - `SearchFilters.toQueryParams`: ALL → null `type`; sort values map to wire strings;
    `isDefault` correct.
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
