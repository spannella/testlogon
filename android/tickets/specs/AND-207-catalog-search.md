---
id: AND-207
title: Catalog search
milestone: M5
epic: E28
priority: P1
size: M
status: draft
depends_on: [AND-204]
blocks: []
---

# AND-207 — Catalog search

## 1. Overview & Goal

Provide full-text search over the TestLogon catalog so users can locate shop
items by name, description, or SKU. This ticket delivers the **search feature
layer**: a `feature-catalog` search screen, a `SearchViewModel` with debounced
query handling, paged result rendering, and the resilience/empty/error states
needed for the unreliable dev backend. It builds directly on the catalog API,
DTOs, and result models delivered by **AND-204** (which owns the wire contract
and DTO→domain mapping). AND-207 does **not** add new networking primitives or
DTOs; it consumes them.

Goal, stated testably: from the catalog entry point, a user can open a search
field, type a term (≥2 chars), and within one debounce cycle see a paged,
scrollable list of matching catalog items, or a clearly labeled empty/error/
offline state. Tapping a result navigates to item detail (owned downstream).

Success is defined by the source acceptance bullet — **"Search returns items"** —
operationalized here as: a query that matches seeded catalog data renders ≥1
`CatalogItem` row, and a non-matching query renders the empty state, both
verified by instrumented tests against a fake API.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`. Feature package:
  `com.testlogon.android.feature.catalog.search`.
- **Module layering:** `app → feature-catalog → core-network, core-model,
  core-data, core-ui, core-testing`. This ticket adds code to `feature-catalog`
  only; it reuses the `CatalogApi`/`CatalogRepository`/DTOs created in AND-204.
- **Upstream (AND-204):** `CatalogApi.searchCatalog(...)`, `CatalogItem` domain
  model, `CatalogItemDto`, and the page envelope mapping live there. This spec
  references those signatures as fixed inputs.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Catalog/search
  endpoints documented there and mirrored in the web reference app
  (`frontend/src/api/endpoints/*.ts`, shared types `frontend/src/api/types.ts`).
- **Auth:** cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`;
  401 triggers a single `POST /ui/session/refresh` then retry. Handled by the
  shared OkHttp interceptors from core-network (AND-027/AND-204); search calls
  inherit this and add no auth logic.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6,
  DataStore, Coil, Paging 3. minSdk 24, compile/target 35, JDK 17, Gradle 8.9,
  AGP 8.7.3.

## 3. Functional Requirements

FR-1 **Search entry & field.** A `SearchScreen` exposes a Material 3
`SearchBar`/`OutlinedTextField` (top of the screen, focus-on-enter) bound to the
ViewModel query state. A clear ("×") affordance resets the query and results.

FR-2 **Debounced querying.** Input is debounced 300 ms. Queries shorter than the
**minimum length (2 chars)** do not hit the network; the screen shows the
neutral "type to search" prompt. Trimmed whitespace; consecutive identical
queries are de-duplicated (`distinctUntilChanged`).

FR-3 **Full-text scope.** The backend matches against name, description, and SKU
(server-side full-text per AND-204 contract). The client sends the raw trimmed
term; it does **not** implement client-side fielded parsing.

FR-4 **Paged results.** Results render via Paging 3 in a `LazyColumn`. Each row
shows item name, a short description snippet, SKU, price (if present), and a Coil
thumbnail. Scrolling loads subsequent pages (append). Page size 20.

FR-5 **Result selection.** Tapping a row invokes
`onItemClick(itemId: String)` (navigation to item detail owned downstream; this
ticket wires the callback and a nav route argument only).

FR-6 **States.** The screen renders exactly one of: Idle/prompt (empty query),
Loading (initial page in flight), Content (≥1 item), Empty ("No results for
\"<q>\"", matched-but-zero), Error (recoverable, with Retry), Offline/stale.

FR-7 **Lifecycle.** Query text and scroll position survive configuration change
(`SavedStateHandle` for the query string; Paging restores via its own state).
Re-entering the screen restores the last query and results.

FR-8 **Retry.** Error and Offline states expose a Retry action that re-runs the
current query. Idempotent GET retries also happen automatically (see §7).

## 4. Technical Design

New code lives under
`android/feature-catalog/src/main/kotlin/com/testlogon/android/feature/catalog/search/`.

### 4.1 UI state

```kotlin
sealed interface SearchUiState {
    data object Idle : SearchUiState                 // query blank / < min length
    data object Loading : SearchUiState              // first page in flight
    data class Content(val query: String) : SearchUiState   // items via PagingData flow
    data class Empty(val query: String) : SearchUiState
    data class Error(val message: String, val retryable: Boolean) : SearchUiState
    data object Offline : SearchUiState
}
```

Paged rows are exposed separately (PagingData cannot live in equatable state):

```kotlin
val results: Flow<PagingData<CatalogItem>>   // cachedIn(viewModelScope)
val uiState: StateFlow<SearchUiState>
```

### 4.2 ViewModel

```kotlin
@HiltViewModel
class SearchViewModel @Inject constructor(
    private val repository: CatalogRepository,   // from AND-204
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val query = MutableStateFlow(savedState.get<String>(KEY_Q).orEmpty())

    @OptIn(FlowPreview::class)
    private val activeQuery: StateFlow<String> = query
        .map { it.trim() }
        .debounce(DEBOUNCE_MS)
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, "")

    val results: Flow<PagingData<CatalogItem>> = activeQuery
        .filter { it.length >= MIN_QUERY_LEN }
        .flatMapLatest { q -> repository.searchPaged(q) }   // Pager(...).flow
        .cachedIn(viewModelScope)

    val uiState: StateFlow<SearchUiState> = /* derived from query + load states */

    fun onQueryChange(text: String) {
        query.value = text
        savedState[KEY_Q] = text
    }
    fun onClear() { onQueryChange("") }
    fun onRetry() { /* refresh trigger -> LazyPagingItems.retry() via channel */ }

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LEN = 2
        private const val KEY_Q = "catalog_search_query"
    }
}
```

`uiState` is derived in the Composable by combining `activeQuery` with
`LazyPagingItems.loadState` (Idle when query < min; Loading on
`refresh is LoadState.Loading`; Empty when `refresh is NotLoading` and
`itemCount == 0`; Error/Offline from `LoadState.Error`'s mapped exception).
This keeps PagingData out of the equatable StateFlow while still surfacing
load-driven states. A small `searchUiState(query, loadState, itemCount)` pure
function is exposed for unit testing.

### 4.3 Repository (consumed, defined in AND-204)

```kotlin
interface CatalogRepository {
    fun searchPaged(query: String): Flow<PagingData<CatalogItem>>   // AND-204
}
```

If AND-204 ships only a single-shot `searchCatalog(query, page, pageSize)`,
AND-207 supplies a thin `CatalogSearchPagingSource : PagingSource<Int,
CatalogItem>` in `feature-catalog` that calls it; otherwise it consumes the
repo's `Pager` directly. The PagingSource maps `ApiResult` failures to
`LoadResult.Error` so load-state mapping (§7) works uniformly.

### 4.4 Composables

```kotlin
@Composable fun SearchRoute(
    onItemClick: (String) -> Unit,
    onBack: () -> Unit,
    viewModel: SearchViewModel = hiltViewModel(),
)

@Composable fun SearchScreen(
    state: SearchUiState,
    query: String,
    items: LazyPagingItems<CatalogItem>,
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
    onRetry: () -> Unit,
    onItemClick: (String) -> Unit,
    onBack: () -> Unit,
)

@Composable private fun SearchResultRow(item: CatalogItem, onClick: () -> Unit)
```

### 4.5 Navigation

Add a `catalogSearch` destination to the catalog nav graph
(`com.testlogon.android.feature.catalog.navigation`):

```kotlin
const val CATALOG_SEARCH_ROUTE = "catalog/search"
fun NavController.navigateToCatalogSearch() = navigate(CATALOG_SEARCH_ROUTE)
fun NavGraphBuilder.catalogSearchScreen(
    onItemClick: (String) -> Unit, onBack: () -> Unit,
) = composable(CATALOG_SEARCH_ROUTE) { SearchRoute(onItemClick, onBack) }
```

## 5. API Contract

AND-207 calls the search endpoint defined and DTO-mapped by **AND-204**; this
section documents the contract it relies on (authoritative source: `/openapi.json`
and `frontend/src/api/endpoints/`). No new endpoint is added here.

**Request:** `GET /catalog/items` with query params.

```
GET /catalog/items?q=<term>&page=<n>&page_size=20
Cookie: <session cookies>
X-CSRF-Token: <ui_csrf value>     # echoed by core-network for non-GET; sent if present
Accept: application/json
```

Retrofit signature (owned by AND-204, referenced here):

```kotlin
@GET("catalog/items")
suspend fun searchCatalog(
    @Query("q") query: String,
    @Query("page") page: Int,
    @Query("page_size") pageSize: Int = 20,
): ApiResult<CatalogPageDto>
```

**Success 200 — page envelope:**

```json
{
  "items": [
    {
      "id": "itm_8f3",
      "name": "Aurora Hoodie",
      "description": "Midweight fleece pullover…",
      "sku": "AUR-HD-001",
      "price_cents": 5900,
      "currency": "USD",
      "image_url": "https://…/aurora.jpg",
      "category_id": "cat_apparel"
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 137,
  "has_more": true
}
```

`CatalogPageDto`/`CatalogItemDto` and the `→ CatalogItem` mapping are AND-204's.
AND-207 assumes `has_more`/`total` drive Paging's `nextKey` (next page when
`has_more == true`, else `null`).

**Error — FastAPI `detail`** (mapped by the shared error mapper from
core-network): `detail` may be a `string`, `[{ "msg": "...", "loc": [...] }]`,
or `{ "code": "...", ... }`. The mapper yields a user-facing message used by
`SearchUiState.Error`. A `422` on a malformed query is treated as
**non-retryable** (shows message, no auto-retry); `5x`/timeout is retryable.

## 6. Data & State Management

- **Source of truth:** server. Search is a live query; results are **not**
  persisted to Room in this ticket. (Catalog browse caching is AND-204/-205;
  search may layer a Room-backed `RemoteMediator` in a later ticket — out of
  scope here.)
- **Paging:** `Pager(PagingConfig(pageSize = 20, prefetchDistance = 10,
  initialLoadSize = 20, enablePlaceholders = false))`. `PagingData` is
  `cachedIn(viewModelScope)` so it survives config change and recomposition.
- **Query persistence:** the query string is held in `SavedStateHandle`
  (`KEY_Q`) to survive process death; debounce/dedup operators sit downstream of
  it. No DataStore writes for the query (transient UI concern), but the last
  query MAY be cached in DataStore in a follow-up for "recent searches" (open
  question §13).
- **Derived state:** `uiState` is pure-derived from `(activeQuery,
  loadState.refresh, itemCount)`; no independent mutable copy is stored, avoiding
  state divergence.
- **Threading:** all I/O on Dispatchers.IO inside the repository/PagingSource;
  ViewModel flows on `viewModelScope`. Composables collect via
  `collectAsLazyPagingItems()` and `collectAsStateWithLifecycle()`.

## 7. Error Handling & Resilience

- **Timeouts:** inherit core-network's ~20 s call timeout for the unreliable dev
  host. A timeout surfaces as `SearchUiState.Error(retryable = true)` (or
  `Offline` when no connectivity).
- **Bounded retry (idempotent GET only):** the search GET is safe to retry.
  OkHttp/core-network applies bounded exponential backoff (e.g., 2 attempts,
  250 ms→1 s, jitter) for `5xx`/timeout on GETs. The PagingSource does **not**
  add its own retry loop on top; it relies on the interceptor and exposes
  `LoadResult.Error` for the remainder, surfaced via `loadState`.
- **401 handling:** transparent — core-network performs a single
  `POST /ui/session/refresh` then retries; only a second 401 reaches the feature
  as an auth error (mapped to a non-retryable error prompting re-login,
  delegated to the auth flow).
- **Empty vs error:** zero results with `LoadState.NotLoading(endOfPagination)`
  → `Empty`; never shown as an error.
- **Append failures:** a failed page append shows an inline footer row with a
  Retry button (`items.retry()`), leaving already-loaded results intact.
- **Race safety:** `flatMapLatest` cancels the in-flight Pager when the query
  changes, preventing stale results from a previous term overwriting newer ones.
- **Exception mapping:** `IOException`/`SocketTimeout` → Offline/retryable;
  `HttpException`/`ApiResult.Error` → mapped FastAPI `detail` message;
  `422` → non-retryable.

## 8. Security & Privacy

- **Transport:** dev backend is plaintext HTTP; `usesCleartextTraffic`/network
  security config is owned by core-network (AND-027). No change here. Production
  must be HTTPS-only (tracked centrally, not this ticket).
- **Auth/CSRF:** search relies on the existing persistent cookie jar and
  `X-CSRF-Token` echo from core-network; AND-207 adds **no** credential handling
  and must never log cookies, CSRF tokens, or full URLs with session params.
- **Query data:** search terms are user content. They are not persisted to disk
  in this ticket (no recent-searches store), and must not be written to logs at
  WARN/ERROR. Telemetry sends only term **length** and result count, never the
  raw term (§10).
- **No injection surface:** the term is sent as a URL query parameter via
  Retrofit `@Query` (auto-encoded); no string concatenation into URLs or SQL.

## 9. Accessibility & i18n

- **Search field:** `contentDescription`/label "Search catalog"; clear button
  labeled "Clear search". IME action `Search`; supports voice input via the
  standard keyboard.
- **Touch targets:** result rows and the clear button ≥ 48 dp.
- **Result rows:** merged semantics announcing name, price, and SKU; thumbnail
  marked decorative with non-null alt where it conveys info (item name).
- **States:** Empty/Error/Offline messages use `liveRegion = Polite` so screen
  readers announce state changes after a query.
- **Dynamic type & contrast:** Material 3 typography scales; meets WCAG AA
  contrast in light/dark themes (core-ui).
- **i18n:** all strings in `feature-catalog` `strings.xml` with placeholders
  (`No results for \"%1$s\"`); no concatenation. RTL-safe layouts (start/end
  padding). Currency/price formatting via `NumberFormat`/locale (formatting
  helper from core-ui if present).

## 10. Telemetry & Logging

- **Events** (via the app analytics facade from core-* / AND-027, no PII):
  - `catalog_search_performed` { query_length: Int, debounced: true }
  - `catalog_search_results` { query_length: Int, result_count: Int,
    is_empty: Boolean, latency_ms: Long }
  - `catalog_search_error` { kind: "timeout|http|offline|parse",
    http_status: Int?, retryable: Boolean }
  - `catalog_search_result_click` { position: Int }
- **Raw query terms are never sent** — only length, to protect privacy (§8).
- **Logging:** debug-only `Timber` breadcrumbs (`d`) for query length and load
  state transitions; errors logged at `w` with mapped message and status, never
  the term or auth tokens. No logging in release except crash-reporter
  non-fatals for unexpected parse errors.

## 11. Testing Strategy

- **Unit (core-testing, JUnit + Turbine + coroutines-test):**
  - `searchUiState(query, loadState, itemCount)` pure function: Idle when
    `query.length < 2`; Loading on refresh-loading; Empty on
    NotLoading+0 items; Content on ≥1; Error/Offline from mapped exceptions.
  - Debounce: emit "a","ab","abc" within 300 ms → only the final term triggers
    a repository call (virtual time).
  - Min-length gate: "a" → no `searchPaged` call.
  - Dedup: same term twice → one downstream collection.
  - `flatMapLatest` cancellation: a new term cancels the prior Pager (assert
    prior fake source cancelled).
  - Error mapping: `422` → retryable=false; timeout → retryable=true/Offline.
- **Paging:** `CatalogSearchPagingSource` (if added here) with a fake
  `CatalogRepository`/`CatalogApi`: page 1 + `has_more=true` → `nextKey=2`;
  `has_more=false` → `nextKey=null`; API error → `LoadResult.Error`.
- **Compose UI (AndroidComposeTestRule + fake VM):**
  - Typing a matching term renders ≥1 `SearchResultRow` (covers the acceptance
    bullet "Search returns items").
  - Non-matching term renders the Empty node with the query echoed.
  - Error state shows Retry; clicking calls `onRetry`.
  - Clear button empties field and returns to Idle.
  - Row tap invokes `onItemClick(id)`.
- **Instrumented integration (optional, MockWebServer):** stubbed
  `/catalog/items` 200 page → results render; 500 then 200 → auto-retry then
  content; 422 → non-retryable error. No tests hit the live dev host.
- **Accessibility:** `onNodeWithContentDescription("Search catalog")` and
  merged-semantics assertions on a result row.

## 12. Dependencies & Sequencing

- **Depends on AND-204** (Catalog API + DTOs): provides `CatalogApi`,
  `CatalogPageDto`/`CatalogItemDto`, `CatalogItem`, and the search endpoint +
  DTO mapping. **Hard blocker** — AND-207 cannot complete until the search
  endpoint and item model are merged. Transitively depends on AND-027
  (core-network: cookie jar, CSRF, error mapper, retry/backoff, timeouts).
- **Blocks:** none listed in the backlog. Item-detail navigation is the
  natural consumer of `onItemClick`; AND-207 exposes the callback/route arg but
  the detail screen is owned by a downstream catalog ticket (E28). If that
  ticket is unmerged, wire `onItemClick` to a no-op/stub route.
- **Sequencing:** land AND-204 → add `searchPaged`/PagingSource glue → ViewModel
  + state derivation → Composables → nav wiring → tests.

## 13. Risks & Open Questions

- **R1 — Repo shape mismatch.** AND-204 may expose only a single-shot
  `searchCatalog(...)` rather than a `Pager`. Mitigation: ship
  `CatalogSearchPagingSource` in feature-catalog (§4.3). *Confirm with AND-204
  owner.*
- **R2 — Server pagination semantics.** Whether the endpoint uses
  `page`/`page_size` + `has_more` vs cursor tokens affects `nextKey`. Verify
  against `/openapi.json` and `frontend/src/api/types.ts`. *Open.*
- **R3 — Unreliable dev host** causes flaky manual QA. Mitigation: all tests use
  fakes/MockWebServer; rely on §7 timeouts + bounded retry.
- **R4 — Search field UI:** Material 3 `SearchBar` vs a plain field in a
  top app bar. Decision: plain `OutlinedTextField`/`TopAppBar` for layout
  control unless design specifies `SearchBar`. *Open — design sign-off.*
- **Q1 — Min query length:** is 2 acceptable, or should single-char SKU prefixes
  search? Default 2.
- **Q2 — Recent searches / suggestions:** out of scope; candidate follow-up
  (would introduce DataStore persistence — see §6/§8).
- **Q3 — Result ranking/highlighting:** server-ranked, no client highlight in
  this ticket.

## 14. Acceptance Criteria

AC-1 (**source bullet — "Search returns items"**): Given seeded catalog data and
a query matching ≥1 item, the screen renders ≥1 `SearchResultRow` with name,
SKU, and price. *Verified by Compose UI test against a fake API.*

AC-2: A query < 2 chars triggers **no** network call and shows the Idle prompt.
*(unit + UI)*

AC-3: Input is debounced 300 ms and de-duplicated; rapid typing yields exactly
one search for the final term. *(unit, virtual time)*

AC-4: A matched-but-zero-result query shows the Empty state with the query
echoed; never an error. *(unit + UI)*

AC-5: A `5xx`/timeout shows a retryable Error/Offline state with a working Retry
that re-runs the current query; bounded GET backoff applies and a 500→200
sequence ultimately renders content. *(integration)*

AC-6: A `422` shows a non-retryable error (no auto-retry). *(unit/integration)*

AC-7: Results are paged (page size 20); scrolling appends subsequent pages and a
failed append shows an inline retry without losing loaded rows. *(paging/UI)*

AC-8: Query text survives configuration change and process death (SavedState);
loaded results survive config change (cachedIn). *(UI)*

AC-9: Tapping a row invokes `onItemClick(itemId)` with the correct id. *(UI)*

AC-10: Telemetry emits length/count only — no raw query term in any event or log.
*(unit/inspection)*

AC-11: Search field and clear control are labeled, ≥48 dp, and state changes are
announced via a polite live region. *(a11y test)*

## 15. Definition of Done

- All §14 acceptance criteria pass in CI.
- `feature-catalog` search code under
  `com.testlogon.android.feature.catalog.search` with `SearchRoute`,
  `SearchScreen`, `SearchViewModel`, `SearchUiState`, nav wiring, and (if
  needed) `CatalogSearchPagingSource`.
- Unit + Compose tests added; coverage of the state-derivation function and
  debounce/min-length/dedup logic; instrumented MockWebServer path for
  200/500→200/422. No test depends on the live dev host.
- No new DTOs or endpoints introduced here (owned by AND-204); only consumption.
- Lint/Detekt/ktlint clean; no raw query terms or auth tokens in logs;
  Strings externalized and RTL-safe.
- Builds with Gradle 8.9 / AGP 8.7.3 / JDK 17; minSdk 24, target 35.
- Code reviewed and merged to `android-port`; ticket links the AND-204
  dependency and notes the downstream item-detail consumer for `onItemClick`.
- Open questions §13 (R1, R2, R4) resolved or explicitly deferred with owners.
