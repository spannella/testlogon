---
id: AND-207
title: Catalog search
milestone: M5
epic: E28
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-204]
blocks: []
---

# AND-207 — Catalog search

## 1. Overview & Goal

Provide full-text search over the TestLogon catalog so users can locate shop
items by free-text term (matched server-side against item fields such as name
and description). **Correction (see §16):** the source ticket says "name/desc/SKU",
but the catalog item model exposed by the backend has **no `sku` field**
(`CatalogItemOut` / frontend `CatalogItem` carry `item_id`, `name`,
`description`, `price_cents`, `currency`, `image_urls`, `category_id`,
`attributes`, stock fields — verified against OpenAPI and `src/api/types.ts`).
The web cart even reuses `item_id` as the "sku" when adding to a cart
(`src/pages/shop/ProductDetail.tsx`). The server `q` matching fields are not
documented in OpenAPI, so "matches SKU" is an unverified assumption; the client
sends the raw term and lets the server decide. This ticket delivers the **search feature
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
`CatalogItem` row (identified by `item_id`), and a non-matching query renders the empty state, both
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
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. The catalog search
  endpoint is **`GET /ui/catalog/items/search`** (op
  `search_items_ui_catalog_items_search_get`), mirrored in the web reference app
  by `searchCatalogItems` in `src/api/endpoints/cart.ts` (catalog calls live in
  `cart.ts`, not a `catalog.ts`), shared types in `src/api/types.ts`.
  **Correction (see §16):** an earlier draft assumed `GET /catalog/items`; the
  real path is `GET /ui/catalog/items/search`.
- **Auth/CSRF:** the web client (`src/api/client.ts`) sends, on **every** request
  including GETs: `Authorization: Bearer <accessToken>` (from the auth store),
  `X-CSRF-Token: <ui_csrf cookie value>`, and `credentials: include` (cookies).
  A `401` (when previously authenticated) triggers a single
  `POST /ui/session/refresh` then one retry of the original request; a second
  `401` logs out. (The OpenAPI also documents `X-SESSION-ID` / `X-API-Key` /
  `X-IMPERSONATION-TOKEN` as accepted params, but the reference web client's
  transport uses Bearer + `X-CSRF-Token` + cookies.) **Correction (see §16):**
  an earlier draft said CSRF is echoed only for non-GET — the web client sends
  `X-CSRF-Token` on GETs too. This is handled by the shared OkHttp interceptors
  from core-network (AND-027/AND-204); search calls inherit it and add no auth
  logic.
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
*Note (see §16): the web reference (`src/pages/shop/Catalog.tsx`) has no debounce
and fires search whenever `search.trim().length > 0` (effective min length 1) via
React Query. The 300 ms debounce and 2-char minimum are deliberate Android-side
mobile design choices (reduce flaky-dev-host load), not web behavior parity.*

FR-3 **Full-text scope.** The backend performs server-side matching of the `q`
term (against item fields such as name/description). The exact server-side
matching fields are **not documented in OpenAPI** and the catalog item has **no
`sku` field** (see §1/§16), so "matches SKU" is an unverified assumption. The
client sends the raw trimmed term as the `q` query param; it does **not**
implement client-side fielded parsing.

FR-4 **Paged results.** Results render via Paging 3 in a `LazyColumn`. Each row
shows item name, a short description snippet, price (`price_cents`+`currency`
formatted via `NumberFormat`), and a Coil thumbnail from `image_urls[0]` (or a
placeholder when `image_urls` is empty). **Correction (see §16):** there is no
`sku` field on the catalog item, so rows do not render an SKU. Paging uses the
server's **cursor** (`next_token`) for append — see §5/§6; the OpenAPI/web
contract has **no `page` offset param**. Page size requested via `page_size`.

FR-5 **Result selection.** Tapping a row invokes
`onItemClick(itemId: String)` (navigation to item detail owned downstream; this
ticket wires the callback and a nav route argument only). *Note (see §16): the
web detail route is keyed on **both** `category_id` and `item_id`
(`/shop/${category_id}/${item_id}` in `src/pages/shop/Catalog.tsx`). Since each
`CatalogItem` carries `category_id`, the downstream detail consumer may need
both; `onItemClick` should be free to pass `categoryId` too if the detail ticket
requires it.*

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

If AND-204 ships only a single-shot `searchCatalog(query, nextToken, pageSize)`,
AND-207 supplies a thin `CatalogSearchPagingSource : PagingSource<String,
CatalogItem>` in `feature-catalog` that calls it; otherwise it consumes the
repo's `Pager` directly. **Correction (see §16):** pagination is **cursor-based
via `next_token`** (the page key type is `String`, the opaque `next_token`), not
an `Int` page offset — the OpenAPI search params are `q,page_size,next_token`
with **no `page`**, and the response (`CatalogItemListOut`) returns only
`{ items, next_token }`. The PagingSource maps `ApiResult` failures to
`LoadResult.Error` so load-state mapping (§7) works uniformly, and sets
`nextKey = response.next_token` (null ⇒ end of pagination).

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
section documents the contract it relies on (authoritative sources: OpenAPI
`GET /ui/catalog/items/search` and `src/api/endpoints/cart.ts`/`src/api/types.ts`).
No new endpoint is added here. **All field/path/param shapes below were verified;
see §16 for per-claim citations and the corrections made versus the original draft.**

**Request:** `GET /ui/catalog/items/search` with query params `q`, `page_size`,
`next_token` (cursor). There is **no `page` offset param**.

```
GET /ui/catalog/items/search?q=<term>&page_size=20&next_token=<cursor?>
Authorization: Bearer <accessToken>     # primary auth (web client)
X-CSRF-Token: <ui_csrf cookie value>    # sent on every request incl. GET
Cookie: <session cookies>               # credentials: include
Accept: application/json
```

Documented OpenAPI params: `q, page_size, next_token, user_sub, X-SESSION-ID,
X-IMPERSONATION-TOKEN, X-API-Key`. Responses: `200:CatalogItemListOut;
422:HTTPValidationError; 400; 401; 403; 429`. The web client
(`searchCatalogItems`) sends only `q` and `page_size` (default 50 in web; this
ticket uses 20).

Retrofit signature (owned by AND-204, referenced here):

```kotlin
@GET("ui/catalog/items/search")
suspend fun searchCatalog(
    @Query("q") query: String,
    @Query("page_size") pageSize: Int = 20,
    @Query("next_token") nextToken: String? = null,
): ApiResult<CatalogItemListDto>   // maps CatalogItemListOut
```

**Success 200 — `CatalogItemListOut` (cursor envelope):** only `items` +
optional `next_token`. There is **no `page`/`page_size`/`total`/`has_more`** in
the response. Each item is a `CatalogItemOut`; required fields are `item_id`,
`name`, `category_id`, `price_cents`, `currency`, `image_urls`, `attributes`,
`created_at`, `updated_at` (note: `item_id` not `id`, `image_urls[]` not a single
`image_url`, **no `sku`**; `description`, `stock_count`, `position`,
`creator_id`, `stock_updated_at` are nullable).

```json
{
  "items": [
    {
      "item_id": "itm_8f3",
      "category_id": "cat_apparel",
      "name": "Aurora Hoodie",
      "description": "Midweight fleece pullover…",
      "price_cents": 5900,
      "currency": "USD",
      "image_urls": ["https://…/aurora.jpg"],
      "attributes": {},
      "stock_count": 12,
      "stock_status": "in_stock",
      "low_stock_threshold": 5,
      "created_at": "2026-01-02T00:00:00Z",
      "updated_at": "2026-01-02T00:00:00Z"
    }
  ],
  "next_token": "eyJwayI6..."
}
```

`CatalogItemListDto`/`CatalogItemDto` and the `→ CatalogItem` mapping are
AND-204's. Paging's `nextKey` is driven by `next_token` (next page = the returned
`next_token`; `null`/absent ⇒ end of pagination).

**Error — FastAPI `detail`** (mapped by the shared error mapper from
core-network): for `422` the verified shape is `HTTPValidationError =
{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }` (`ValidationError`).
The web `normalizeErrorDetail` (`src/api/client.ts`) also handles `detail` as a
plain `string` and as an object with a `code` (e.g. `role_required`,
`geo_blocked`) — so the Android mapper should accept string | array-of-issue |
object-with-code. The mapper yields a user-facing message used by
`SearchUiState.Error`. A `422` on a malformed query is treated as
**non-retryable** (shows message, no auto-retry); `5xx`/timeout is retryable.
`403` may carry `code:"geo_blocked"` (verified in `client.ts`) and is
non-retryable.

## 6. Data & State Management

- **Source of truth:** server. Search is a live query; results are **not**
  persisted to Room in this ticket. (Catalog browse caching is AND-204/-205;
  search may layer a Room-backed `RemoteMediator` in a later ticket — out of
  scope here.)
- **Paging:** `Pager(PagingConfig(pageSize = 20, prefetchDistance = 10,
  initialLoadSize = 20, enablePlaceholders = false))`. `PagingData` is
  `cachedIn(viewModelScope)` so it survives config change and recomposition.
  The `PagingSource` key is the opaque **`next_token` cursor (`String`)**, not an
  `Int` page index — `LoadResult.Page(nextKey = response.next_token)`, with
  `nextKey = null` ⇒ end of pagination (verified: `CatalogItemListOut` returns
  only `{items, next_token}`; no `has_more`/`total`). Because `initialLoadSize`
  may exceed `pageSize` in Paging 3 but the server has no offset param, the
  PagingSource should request `page_size = params.loadSize` per load rather than
  assuming a fixed 20.
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
- **Result rows:** merged semantics announcing name and price (no SKU — the
  catalog item has no `sku` field, see §16); thumbnail marked decorative with
  non-null alt where it conveys info (item name).
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
  `CatalogRepository`/`CatalogApi`: response with `next_token="t2"` →
  `nextKey="t2"`; response with `next_token=null` → `nextKey=null`
  (end of pagination); API error → `LoadResult.Error`. (Cursor-based; there is
  no `has_more`/numeric page — see §5/§16.)
- **Compose UI (AndroidComposeTestRule + fake VM):**
  - Typing a matching term renders ≥1 `SearchResultRow` (covers the acceptance
    bullet "Search returns items").
  - Non-matching term renders the Empty node with the query echoed.
  - Error state shows Retry; clicking calls `onRetry`.
  - Clear button empties field and returns to Idle.
  - Row tap invokes `onItemClick(id)`.
- **Instrumented integration (optional, MockWebServer):** stubbed
  `/ui/catalog/items/search` 200 `CatalogItemListOut` page → results render;
  500 then 200 → auto-retry then content; 422 `HTTPValidationError` →
  non-retryable error. No tests hit the live dev host.
- **Accessibility:** `onNodeWithContentDescription("Search catalog")` and
  merged-semantics assertions on a result row.

## 12. Dependencies & Sequencing

- **Depends on AND-204** (Catalog API + DTOs): provides `CatalogApi`,
  `CatalogItemListDto` (maps `CatalogItemListOut` = `{items, next_token}`) /
  `CatalogItemDto` (maps `CatalogItemOut`), `CatalogItem`, and the
  `GET /ui/catalog/items/search` endpoint + DTO mapping. **Hard blocker** — AND-207 cannot complete until the search
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
- **R2 — Server pagination semantics.** *Resolved (this review):* the endpoint is
  **cursor-based** — params `q,page_size,next_token` (no `page`), response
  `CatalogItemListOut = {items, next_token}` (no `has_more`/`total`). `nextKey =
  next_token`. Verified against OpenAPI `GET /ui/catalog/items/search` and
  `src/api/types.ts: PaginatedList`/`CatalogItem`.
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
a query matching ≥1 item, the screen renders ≥1 `SearchResultRow` with name and
price (no SKU — the catalog item has no `sku` field; see §16). *Verified by
Compose UI test against a fake API.*

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend =
`reference/src/...`.

1. **Search endpoint is `GET /ui/catalog/items/search`.** VERDICT: Corrected
   (draft said `GET /catalog/items`). SOURCE: OpenAPI `GET /ui/catalog/items/search`
   (op `search_items_ui_catalog_items_search_get`); frontend
   `src/api/endpoints/cart.ts: searchCatalogItems`.
2. **Method is GET.** VERDICT: Verified. SOURCE: same as #1.
3. **Query params are `q`, `page_size`, `next_token` (no `page` offset).**
   VERDICT: Corrected (draft used `page`/`page_size` offset). SOURCE: OpenAPI
   index line `params=q,page_size,next_token,...`; frontend
   `src/api/endpoints/cart.ts: searchCatalogItems` sends `q` + `page_size`.
4. **Success response is `CatalogItemListOut = { items[], next_token? }` (cursor),
   with no `total`/`has_more`/`page`.** VERDICT: Corrected (draft had a
   `{page,page_size,total,has_more}` envelope). SOURCE:
   `openapi.pretty.json` `components.schemas.CatalogItemListOut`; frontend
   `src/api/types.ts: PaginatedList<T>` (`{ items, next_token? }`).
5. **`nextKey` is the opaque `next_token` cursor; null ⇒ end.** VERDICT:
   Corrected (draft drove `nextKey` from `has_more`/numeric page). SOURCE: #4.
6. **Item shape `CatalogItemOut`: required `item_id, name, category_id,
   price_cents, currency, image_urls[], attributes, created_at, updated_at`;
   nullable `description, stock_count, position, creator_id, stock_updated_at`;
   `stock_status` default, `low_stock_threshold` default 5.** VERDICT: Verified.
   SOURCE: `openapi.pretty.json` `components.schemas.CatalogItemOut`; frontend
   `src/api/types.ts: CatalogItem`.
7. **Item id field is `item_id`, not `id`.** VERDICT: Corrected (draft used `id`).
   SOURCE: #6; frontend `src/pages/shop/Catalog.tsx` uses `item.item_id`.
8. **Images are `image_urls: string[]`, not a single `image_url`.** VERDICT:
   Corrected (draft used `image_url`). SOURCE: #6; `src/pages/shop/Catalog.tsx`
   renders `item.image_urls[0]`.
9. **Catalog item has no `sku` field; "search by SKU" is unsupported by the
   model.** VERDICT: Corrected / Unverified-assumption. SOURCE: `CatalogItemOut`
   and `src/api/types.ts: CatalogItem` contain no `sku`; the web cart sends
   `sku: item.item_id` (`src/pages/shop/ProductDetail.tsx`), i.e. it reuses
   `item_id`. Server-side `q` match fields are not in OpenAPI, so SKU matching
   cannot be confirmed.
10. **422 error shape is `HTTPValidationError = { detail: [{ loc, msg, type }] }`.**
    VERDICT: Verified. SOURCE: `openapi.pretty.json`
    `components.schemas.HTTPValidationError` + `ValidationError`; endpoint lists
    `422:HTTPValidationError`.
11. **`detail` may also be a string or an object with `code` (e.g.
    `role_required`, `geo_blocked`); client normalizes all three.** VERDICT:
    Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail` and
    `mapAuthorizationError`; geo-block branch checks `detail.code === "geo_blocked"`.
12. **Documented responses include `400, 401, 403, 429` besides 200/422.**
    VERDICT: Verified. SOURCE: OpenAPI index line for `GET /ui/catalog/items/search`.
13. **Auth: `Authorization: Bearer <accessToken>` is the primary auth (not
    cookie-session only).** VERDICT: Corrected (draft framed auth as cookie
    session + CSRF). SOURCE: `src/api/client.ts` sets `Authorization: Bearer` from
    the auth store on each request.
14. **CSRF: `X-CSRF-Token` from the `ui_csrf` cookie is sent on every request
    incl. GET.** VERDICT: Corrected (draft said non-GET only). SOURCE:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`
    unconditionally; `credentials: "include"`).
15. **401 → single `POST /ui/session/refresh` then one retry; second 401 logs
    out.** VERDICT: Verified. SOURCE: `src/api/client.ts: refreshSession` +
    the 401 handling block (`refreshPromise`, single retry, `logout`).
16. **Web has no debounce and searches when `trim().length > 0` (min length 1).**
    VERDICT: Verified (Android's 300 ms debounce + 2-char min are deliberate
    mobile design choices, not web parity). SOURCE: `src/pages/shop/Catalog.tsx`
    (`enabled: search.trim().length > 0`, React Query keyed on `search`).
17. **Web detail nav uses both `category_id` and `item_id`
    (`/shop/${category_id}/${item_id}`).** VERDICT: Verified. SOURCE:
    `src/pages/shop/Catalog.tsx` `navigate(...)`.
18. **Price rendering: `price_cents`/`currency` formatted via locale number
    format.** VERDICT: Verified. SOURCE: `src/pages/shop/Catalog.tsx: formatPrice`
    (`Intl.NumberFormat`, `cents / 100`).
19. **Stock UI states `low_stock` / `out_of_stock` exist on items.** VERDICT:
    Verified. SOURCE: `src/pages/shop/Catalog.tsx` badge logic; `stock_status` in
    `CatalogItemOut`.
20. **Network error path: fetch throwing surfaces a connection error.** VERDICT:
    Verified (maps to Android Offline). SOURCE: `src/api/client.ts` catch →
    `ApiError(0, "Network error")`.
21. **Paging 3 cursor-keyed PagingSource / Pager (Android framework).** VERDICT:
    Unverified-assumption (framework choice). SOURCE: framework ref —
    https://developer.android.com/topic/libraries/architecture/paging/v3-overview
22. **`SavedStateHandle` persists the query across process death (Android
    framework).** VERDICT: Unverified-assumption (framework choice). SOURCE:
    framework ref — https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate

### Corrections made

- Endpoint path `GET /catalog/items` → `GET /ui/catalog/items/search` (§2, §5,
  §11, §12).
- Pagination model offset (`page`/`page_size`/`has_more`/`total`) → **cursor**
  (`page_size` + `next_token`, response `{items, next_token}`); PagingSource key
  type `Int` → `String` (§4.3, §5, §6, §11).
- Item DTO fields: `id` → `item_id`; `image_url` → `image_urls[]`; removed the
  non-existent `sku` (§4.4, §5, §9, §11, §14).
- "Search matches name/description/SKU" softened to server-decided `q` match with
  no `sku` field; SKU matching flagged unverifiable (§1, §3 FR-3, §14 AC-1).
- Auth/CSRF: primary auth is `Authorization: Bearer`; `X-CSRF-Token` sent on all
  requests incl. GET (draft said cookie-session + non-GET CSRF) (§2, §5, §8).
- §13 R2 marked Resolved with the verified cursor semantics.
- Noted web has no debounce / min length 1, and web detail nav needs
  `category_id`+`item_id` (§3 FR-2, FR-5).

### Open assumptions

- **Server-side `q` match fields** (does it cover description? any code/identifier
  like `item_id`?) are not documented in OpenAPI — cannot be verified; the client
  only sends `q`. (Claim #9.)
- **AND-204 repository surface** (`searchPaged` Pager vs single-shot
  `searchCatalog(q, nextToken, pageSize)`) is owned upstream and not present in
  these reference sources — assumed; mitigated by shipping
  `CatalogSearchPagingSource` (§4.3, R1).
- **core-network behaviors** (≈20 s timeout, bounded GET backoff 2 attempts,
  cookie jar, single-refresh-on-401 interceptor) are attributed to AND-027 and
  not in the reference web client (which is browser fetch) — assumed from the
  Android stack, not verifiable here. The web client's single-refresh-on-401 is
  the contract being mirrored (Claim #15).
- **Paging 3 / SavedStateHandle / Compose** are Android framework choices (Claims
  #21–22), verified only against Android docs, not the backend/web sources.

## 17. Test Plan

IDs `TC-AND-207-NN`. "Traces" links to §14 acceptance criteria. Test targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the physical
**Samsung Galaxy A15 5G** (SM-A156U, serial `R5CX821TA9R`, API 34 arm64-v8a).
Search has no camera/biometric/WebRTC/push dependency, so most cases run on the
emulator; the physical device is reserved for real-network flaky-host behavior
and an arm64/API-34 ABI smoke.

**TC-AND-207-01 — Happy path: matching query returns items.**
Type: Compose-UI. Target: emulator `test35` (or Robolectric). Preconditions: fake
`CatalogRepository` returns a `CatalogItemListOut` page with ≥1 `CatalogItem`
(valid `item_id`, `name`, `price_cents`, `currency`, `image_urls`). Steps: launch
`SearchRoute` with fake VM; type "hood" (≥2 chars); advance past debounce.
Expected: ≥1 `SearchResultRow` rendered showing name + locale-formatted price;
no SKU text present; `uiState == Content`. Traces: AC-1.

**TC-AND-207-02 — Min-length gate: <2 chars makes no network call.**
Type: unit (Turbine + coroutines-test). Target: JVM. Preconditions: fake repo
records `searchPaged` invocations. Steps: `onQueryChange("a")`; advance virtual
time past 300 ms. Expected: repo `searchPaged` never called; `uiState == Idle`.
Traces: AC-2.

**TC-AND-207-03 — Debounce + dedup: rapid typing yields one search.**
Type: unit (virtual time). Target: JVM. Preconditions: fake repo counts calls.
Steps: emit "a","ab","abc" within 300 ms, then "abc" again; advance time.
Expected: exactly one downstream `searchPaged("abc")`; intermediate terms and the
duplicate are dropped (`debounce` + `distinctUntilChanged`). Traces: AC-3.

**TC-AND-207-04 — Empty state: matched-but-zero results.**
Type: Compose-UI. Target: emulator `test35`. Preconditions: fake repo returns
`{ items: [], next_token: null }`. Steps: type "zzqq"; advance debounce.
Expected: Empty node visible with the query echoed (`No results for "zzqq"`);
`uiState == Empty`; no Error shown; `liveRegion` announces. Traces: AC-4.

**TC-AND-207-05 — 5xx then 200: auto-retry then content (MockWebServer).**
Type: contract/MockWebServer (instrumented). Target: emulator `test35`.
Preconditions: MockWebServer enqueues `500` then `200 CatalogItemListOut` for
`GET /ui/catalog/items/search?q=...`. Steps: perform search; let core-network's
bounded GET backoff retry. Expected: after retry, content renders; transient
error not surfaced as terminal. Traces: AC-5.

**TC-AND-207-06 — 5xx terminal: retryable Error with working Retry.**
Type: contract/MockWebServer (instrumented). Target: emulator `test35`.
Preconditions: MockWebServer returns `500` for all attempts, then a `200` only
after Retry. Steps: search → observe `Error(retryable=true)`; tap Retry (now 200
queued). Expected: Retry re-runs the current query and renders content. Traces:
AC-5.

**TC-AND-207-07 — 422 validation: non-retryable error.**
Type: contract/MockWebServer (instrumented) + unit for the mapper. Target:
emulator `test35` (mapper unit on JVM). Preconditions: MockWebServer returns
`422 { detail: [{ loc, msg, type }] }`. Steps: search a malformed term. Expected:
`SearchUiState.Error(retryable=false)`; the mapped `msg` is shown; no auto-retry
fires. Traces: AC-6.

**TC-AND-207-08 — Cursor paging append + failed-append inline retry.**
Type: contract/MockWebServer (instrumented). Target: emulator `test35`.
Preconditions: page 1 returns `next_token="t2"`; page 2 (request carries
`next_token=t2`) first returns `500`, then `200 next_token=null`. Steps: scroll
to trigger append; observe inline footer error; tap footer Retry. Expected:
request 2 includes `next_token=t2` (no `page` param); failed append shows inline
retry without losing page-1 rows; after retry, page 2 appends and pagination
ends. Traces: AC-7.

**TC-AND-207-09 — Config-change + process-death state restoration.**
Type: instrumented (Compose). Target: emulator `test35`. Preconditions: query
"hood" with loaded results. Steps: rotate (config change) and simulate process
death/recreation (`SavedStateHandle`). Expected: query text restored from
`SavedStateHandle`; results survive config change via `cachedIn`. Traces: AC-8.

**TC-AND-207-10 — Row tap invokes onItemClick with correct id.**
Type: Compose-UI. Target: emulator `test35`. Preconditions: fake VM with a known
`item_id`. Steps: tap the first `SearchResultRow`. Expected:
`onItemClick("itm_8f3")` called once with the row's `item_id`. Traces: AC-9.

**TC-AND-207-11 — Telemetry & logging carry no raw query term.**
Type: unit/inspection. Target: JVM. Preconditions: fake analytics + log capture.
Steps: perform a search "secret-term", an empty result, and an error. Expected:
emitted events contain only `query_length`/`result_count`/`kind`/`http_status`;
the raw term appears in no event payload and no WARN/ERROR log; auth tokens/cookies
never logged. Traces: AC-10.

**TC-AND-207-12 — Accessibility: labels, touch targets, live region.**
Type: Compose-UI (a11y). Target: emulator `test35`. Preconditions: search screen
rendered. Steps: assert `onNodeWithContentDescription("Search catalog")` and the
"Clear search" control exist; assert row + clear ≥48 dp; trigger an Empty/Error
transition. Expected: merged row semantics announce name + price; state change is
announced via `liveRegion = Polite`. Traces: AC-11.

**TC-AND-207-13 — Offline path on flaky/real network.**
Type: integration; for real-network behavior **must run on the physical device**
(SM-A156U). Target: physical device. Preconditions: device search screen with a
seeded matching term; toggle airplane mode (or block the dev host). Steps: search
while offline; then restore connectivity and tap Retry. Expected: `Offline`
state (retryable) while offline (`IOException`/timeout → Offline, not a generic
error); Retry succeeds once connectivity returns. Traces: AC-5.

**TC-AND-207-14 — ABI / API-level smoke (arm64 + API 34).**
Type: instrumented/e2e; **must run on the physical device** (arm64-v8a, API 34)
to cover the arm64-vs-x86 and API-34-vs-35 gap not exercised by the emulator.
Target: physical device. Preconditions: release-candidate build installed.
Steps: run the happy-path + empty + error flows end-to-end against MockWebServer
(or a stable stub). Expected: no ABI/API-34-specific crashes (Coil decode,
Paging, Compose); behavior matches emulator results. Traces: AC-1, AC-4, AC-5.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (search returns items) | TC-01, TC-14 |
| AC-2 (min-length, no call) | TC-02 |
| AC-3 (debounce + dedup) | TC-03 |
| AC-4 (empty state) | TC-04, TC-14 |
| AC-5 (5xx/timeout retryable, retry, 500→200) | TC-05, TC-06, TC-13, TC-14 |
| AC-6 (422 non-retryable) | TC-07 |
| AC-7 (cursor paging + inline append retry) | TC-08 |
| AC-8 (config-change + process-death restore) | TC-09 |
| AC-9 (row tap → onItemClick id) | TC-10 |
| AC-10 (telemetry length/count only) | TC-11 |
| AC-11 (a11y labels/targets/live region) | TC-12 |
