---
id: AND-205
title: Catalog / category browse
milestone: M5
epic: E28
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-204, AND-103]
blocks: [AND-206]
---

# AND-205 — Catalog / category browse

## 1. Overview & Goal

Build the customer-facing catalog browse experience for the TestLogon native
Android app: a scrollable list of shop **categories** and, on selection, a
**paginated grid of items** within the chosen category. This is the entry point
into the shopping flow and the primary surface from which users navigate to the
product detail screen (AND-206).

The goal is a `feature-catalog` module that renders categories and item grids
backed by the Retrofit catalog API and DTOs delivered in AND-204, reuses the
media-thumbnail loading primitives from AND-103 for item imagery, and supports
forward/append pagination via Paging 3. The screen must behave correctly against
the unreliable plaintext dev backend: it must show loading, empty, error, and
stale/offline states, and recover gracefully when the network returns.

Success is measured by the acceptance criterion in the source ticket: **browse
renders and paginates.** Concretely, the category list and item grid render from
live data, scrolling to the end of a category transparently fetches and appends
the next page, and all non-happy-path states are represented in the UI without
crashes.

Out of scope (owned elsewhere): catalog endpoints/DTOs themselves (AND-204),
search UI, product detail / add-to-cart (AND-206), and cart/checkout.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace/applicationId base **`com.testlogon.android`**.
- Module layering: `app -> feature-catalog -> core-* (core-network,
  core-model, core-ui, core-data, core-testing)`. This ticket creates
  `feature-catalog` (Compose + ViewModel + Paging glue) and consumes the
  catalog API surface produced by AND-204.
- **AND-204 (depends_on)** — provides `CatalogApi` Retrofit interface,
  Moshi DTOs (`CategoryDto`, `CatalogItemDto`, paged envelopes), and the
  domain models in `core-model`. This ticket does **not** redefine those; it
  consumes them via a repository.
- **AND-103 (depends_on)** — feed media thumbnails: provides the Coil-based
  thumbnail composable / `ImageRequest` configuration and OkHttp image loader
  wiring reused here for item images.
- **AND-206 (blocks)** — product detail at route `shop/{categoryId}/{itemId}`;
  navigation argument contract is defined here and consumed there.
- Web reference: `frontend/src/api/endpoints/*.ts` (catalog/shop endpoints),
  shared types `frontend/src/api/types.ts`. Backend OpenAPI at
  `http://18.222.237.167:8000/openapi.json`.
- Auth is cookie-based (session + `ui_csrf` echoed as `X-CSRF-Token`); the
  catalog endpoints are authenticated GETs that ride the persistent cookie jar
  and the shared 401→`POST /ui/session/refresh`→retry-once interceptor
  (core-network). **Verified** against `src/api/client.ts`: `X-CSRF-Token` is
  read from the `ui_csrf` cookie and attached to *every* request (GETs included),
  `credentials: "include"` sends cookies, and a single `POST /ui/session/refresh`
  is attempted on 401 before one retry.
- **Endpoint correction (verified):** the real catalog paths are under
  `/ui/catalog/...`, **not** `/ui/shop/...`. The `/ui/shop/*` namespace in the
  backend is order-tracking/admin only. See §5 for corrected paths/shapes.

## 3. Functional Requirements

FR-1. **Category list.** On entering the catalog tab, fetch and display all shop
categories as a vertical list (or horizontally scrollable chip row at the top of
the browse screen). Each row shows category name. **Note (verified):**
`CatalogCategoryOut` provides only `category_id`, `name`, `description?`,
`creator_id?`, `created_at` — there is **no category image or item-count field**,
so the "optional thumbnail / item count" originally proposed here are not backed
by the API and are dropped pending design input (§13).

FR-2. **Default selection.** On first load with no explicit selection, the first
returned category is selected and its item grid is loaded automatically.

FR-3. **Item grid.** For the selected category, display items in a
`LazyVerticalGrid` (2 columns in portrait, 3 in landscape / `WindowSizeClass`
expanded). Each cell shows item thumbnail — the first entry of `image_urls`
(verified field), via the AND-103 primitive — name, and formatted price (from
`price_cents` + `currency`).

FR-4. **Pagination.** The grid pages forward using Paging 3. Scrolling near the
end of the loaded items triggers a fetch of the next page; new items append
without resetting scroll position. An append spinner shows while the next page
loads; an append-error footer with a Retry action shows on failure.

FR-5. **Category switch.** Selecting a different category resets the grid to page
1 for that category, scrolls to top, and shows the grid loading state.

FR-6. **Pull-to-refresh.** A pull-to-refresh gesture on the grid invalidates the
PagingSource and reloads from page 1 for the current category. Categories also
re-fetch.

FR-7. **Navigation to detail.** Tapping an item navigates to
`shop/{categoryId}/{itemId}` (AND-206), passing both ids as nav arguments.

FR-8. **Empty states.** Distinct empty UI for (a) no categories returned and
(b) selected category has zero items.

FR-9. **State preservation.** Selected category id and grid scroll position
survive configuration changes (rotation) and process death where feasible
(selected category id persisted to `SavedStateHandle`).

## 4. Technical Design

New Gradle module `:feature-catalog` (`com.android.library`, Hilt, Compose,
Paging). Package root `com.testlogon.android.feature.catalog`.

### Layers

```
ui/        CatalogScreen, CategoryRow, CatalogItemCell, CatalogStateScaffold
ui/state   CatalogUiState, CategoryUiModel, CatalogItemUiModel
vm/        CatalogViewModel
data/      CatalogRepository (interface) + CatalogRepositoryImpl
data/      CatalogItemsPagingSource
di/        CatalogModule (binds repository)
nav/       CatalogNavGraph, CatalogRoutes
```

### Repository

The repository wraps the AND-204 `CatalogApi`, maps DTOs → `core-model` domain
types, and exposes a `Pager`-backed `Flow<PagingData<CatalogItem>>`.

```kotlin
interface CatalogRepository {
    /** Idempotent GET; bounded-backoff retried by core-network. */
    suspend fun getCategories(): ApiResult<List<Category>>

    /** Paged item stream for a category, cached in PagingData. */
    fun itemsPager(categoryId: String): Flow<PagingData<CatalogItem>>
}
```

```kotlin
class CatalogRepositoryImpl @Inject constructor(
    private val api: CatalogApi,                 // from AND-204
    @IoDispatcher private val io: CoroutineDispatcher,
) : CatalogRepository {

    override suspend fun getCategories(): ApiResult<List<Category>> =
        withContext(io) {
            // CORRECTED: response envelope field is `items`, not `categories`.
            api.getCategories().toApiResult { dto -> dto.items.map(CatalogCategoryDto::toDomain) }
        }

    override fun itemsPager(categoryId: String): Flow<PagingData<CatalogItem>> =
        Pager(
            config = PagingConfig(
                pageSize = PAGE_SIZE,            // page_size sent to the API
                prefetchDistance = 6,
                initialLoadSize = PAGE_SIZE,
                enablePlaceholders = false,
            ),
            pagingSourceFactory = { CatalogItemsPagingSource(api, categoryId, io) },
        ).flow

    // The web client defaults page_size=50 for catalog (src/api/endpoints/cart.ts:
    // getCategoryItems). We use 50 to match the reference contract; tune for grid UX.
    companion object { const val PAGE_SIZE = 50 }
}
```

### PagingSource

> **CORRECTED — paging is cursor-based, not integer pages.** Verified against
> OpenAPI (`GET /ui/catalog/categories/{category_id}/items`, params
> `page_size,next_token`) and the frontend (`src/api/endpoints/cart.ts:
> getCategoryItems`, `src/api/types.ts: PaginatedList<T> { items, next_token }`).
> The request carries `page_size` + an optional `next_token`; the response is
> `CatalogItemListOut { items, next_token? }`. There is **no** `page`,
> `page_size`, `total`, or `has_more` in the response. The Paging key type is
> therefore `String` (the opaque cursor), and "has more" is derived from the
> presence/absence of `next_token`. The integer-page variant described in earlier
> drafts does not exist on this backend.

```kotlin
class CatalogItemsPagingSource(
    private val api: CatalogApi,
    private val categoryId: String,
    private val io: CoroutineDispatcher,
) : PagingSource<String, CatalogItem>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, CatalogItem> =
        withContext(io) {
            val cursor = params.key            // null on initial load
            when (val r = api.getCategoryItems(categoryId, params.loadSize, cursor)) {
                is ApiResult.Success -> {
                    val items = r.data.items.map(CatalogItemDto::toDomain)
                    LoadResult.Page(
                        data = items,
                        prevKey = null,                 // forward-only cursor paging
                        nextKey = r.data.nextToken,     // null ⇒ last page
                    )
                }
                is ApiResult.Failure -> LoadResult.Error(r.toThrowable())
            }
        }

    // Opaque cursors are not reversible; restart from the first page on refresh.
    override fun getRefreshKey(state: PagingState<String, CatalogItem>): String? = null
}
```

### ViewModel

```kotlin
@HiltViewModel
class CatalogViewModel @Inject constructor(
    private val repository: CatalogRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val selectedCategoryId =
        savedState.getStateFlow<String?>(KEY_SELECTED, null)

    private val _uiState = MutableStateFlow(CatalogUiState.Loading)
    val uiState: StateFlow<CatalogUiState> = _uiState.asStateFlow()

    /** PagingData stream that switches when the selected category changes. */
    @OptIn(ExperimentalCoroutinesApi::class)
    val items: Flow<PagingData<CatalogItemUiModel>> =
        selectedCategoryId
            .filterNotNull()
            .distinctUntilChanged()
            .flatMapLatest { id -> repository.itemsPager(id).map { it.map(CatalogItem::toUiModel) } }
            .cachedIn(viewModelScope)

    fun loadCategories() { /* fetch, set Ready/Empty/Error, default-select first */ }
    fun selectCategory(id: String) { savedState[KEY_SELECTED] = id }
    fun retryCategories() = loadCategories()

    companion object { const val KEY_SELECTED = "selected_category_id" }
}
```

### Compose

`CatalogScreen(state, items: LazyPagingItems<CatalogItemUiModel>, onSelect,
onItemClick, onRefresh)` renders the category strip plus a `LazyVerticalGrid`
fed by `items`. Append/refresh/empty states are derived from
`items.loadState`. A `PullToRefreshBox` (Material 3) wraps the grid. Item cells
use the AND-103 thumbnail composable for image loading.

`columns = GridCells.Fixed(if (widthSizeClass == Expanded) 3 else 2)`.

## 5. API Contract

Endpoints and DTOs are **owned by AND-204**; this section pins the contract this
ticket consumes. **All paths/fields below were verified against the backend
OpenAPI (`reference/openapi.pretty.json`) and the web client
(`reference/src/api/endpoints/cart.ts`, `reference/src/api/types.ts`) during this
review.** Multiple prior-draft claims were wrong and are corrected here.

**List categories** — `GET /ui/catalog/categories?page_size=50&next_token=…`
(prior draft said `GET /ui/shop/categories` — **wrong path, corrected**)

Response = `CatalogCategoryListOut`:

```json
{
  "items": [
    {
      "category_id": "cat_books",
      "name": "Books",
      "description": "Optional text or null",
      "creator_id": "usr_123",
      "created_at": "2026-01-02T03:04:05Z"
    }
  ],
  "next_token": "opaque-cursor-or-absent"
}
```

> Corrections vs prior draft: envelope key is **`items`**, not `categories`; each
> category exposes **`category_id`** (not `id`); there is **no `image_url`** and
> **no `item_count`** field on a category (FR-1's thumbnail/count are not backed
> by this DTO — see §13 Open Questions). Required fields: `category_id`, `name`,
> `created_at`. Optional/nullable: `description`, `creator_id`.

**List items in a category** —
`GET /ui/catalog/categories/{category_id}/items?page_size=50&next_token=…`
(prior draft said `/ui/shop/categories/{categoryId}/items?page=1&page_size=20` —
**wrong path and wrong paging params, corrected**)

Response = `CatalogItemListOut`:

```json
{
  "items": [
    {
      "category_id": "cat_books",
      "item_id": "itm_001",
      "name": "Example Item",
      "description": "Optional or null",
      "price_cents": 1999,
      "currency": "USD",
      "image_urls": ["https://…/a.jpg", "https://…/b.jpg"],
      "attributes": {},
      "stock_count": 12,
      "stock_status": "in_stock",
      "low_stock_threshold": 5,
      "position": 0,
      "created_at": "2026-01-02T03:04:05Z",
      "updated_at": "2026-01-02T03:04:05Z"
    }
  ],
  "next_token": "opaque-cursor-or-absent"
}
```

> Corrections vs prior draft: item id is **`item_id`** (not `id`); price is a
> **flat `price_cents` (int) + `currency` (string)** pair, **not** a nested
> `price: {amount_cents, currency}` object; the image field is **`image_urls`
> (string array)**, **not** a single `thumbnail_url` — the thumbnail composable
> should consume `image_urls.firstOrNull()`. The response has **no `page`,
> `page_size`, `total`, or `has_more`** — pagination is the opaque `next_token`
> only. Required item fields: `category_id`, `item_id`, `name`, `price_cents`,
> `currency`, `image_urls`, `attributes`, `created_at`, `updated_at`.

Retrofit interface (in `core-network`/AND-204), corrected to the real contract:

```kotlin
interface CatalogApi {
    @GET("ui/catalog/categories")
    suspend fun getCategories(
        @Query("page_size") pageSize: Int = 50,
        @Query("next_token") nextToken: String? = null,
    ): ApiResult<CatalogCategoryListDto>      // { items, next_token }

    @GET("ui/catalog/categories/{categoryId}/items")
    suspend fun getCategoryItems(
        @Path("categoryId") categoryId: String,
        @Query("page_size") pageSize: Int,
        @Query("next_token") nextToken: String? = null,
    ): ApiResult<CatalogItemListDto>          // { items, next_token }
}
```

> Note: categories are themselves paginated (`page_size`/`next_token`). For browse
> we request a large first page (web uses `page_size=50`) and may follow
> `next_token` if a creator has >50 categories; FR-1 ("display all categories")
> should loop the cursor or document the cap. Flagged in §13.

A related **search** endpoint exists — `GET /ui/catalog/items/search?q=&page_size=`
(`CatalogItemListOut`, `src/api/endpoints/cart.ts: searchCatalogItems`). It is
**out of scope** for this ticket (resolves the §13 search open question: search is
a separate endpoint, not part of browse).

All requests are authenticated GETs: cookies + `X-CSRF-Token` (from the `ui_csrf`
cookie) are attached by the shared OkHttp interceptors — **verified** in
`src/api/client.ts`, which attaches CSRF to every request and sends cookies via
`credentials: "include"`. On `401` the client performs one
`POST /ui/session/refresh` then retries once (verified, `client.ts`
`refreshSession`). These endpoints also document `400/401/403/429` plus
`422 HTTPValidationError`. FastAPI errors are surfaced via the shared `detail`
mapper; `client.ts: normalizeErrorDetail` accepts `string`, a validation array
of `{msg}`, or an object with a message — consistent with the spec's
`string | [{msg}] | {code,...}` description.

## 6. Data & State Management

`CatalogUiState` (categories layer) is a sealed hierarchy; the item grid uses
Paging's own `LoadState` rather than duplicating it in `CatalogUiState`.

```kotlin
sealed interface CatalogUiState {
    data object Loading : CatalogUiState
    data class Ready(
        val categories: List<CategoryUiModel>,
        val selectedId: String,
        val stale: Boolean = false,        // served from cache, network failed
    ) : CatalogUiState
    data object Empty : CatalogUiState     // no categories at all
    data class Error(val message: String, val retryable: Boolean) : CatalogUiState
}
```

**Caching (core-data / Room 2.6).** Categories and the first page of items per
category are written to Room on successful fetch and read back when the network
fails, surfacing `Ready(stale = true)`. Item pages beyond page 1 are not
persisted (Paging in-memory only) to bound cache size. DataStore holds the
last-selected category id as a UX convenience across cold starts.

**State retention.** Selected category id lives in `SavedStateHandle`
(survives process death). Grid scroll position is retained by `rememberLazyGridState`
within the navigation back stack entry; `cachedIn(viewModelScope)` keeps loaded
pages across config changes.

Domain → UI mapping (`CatalogItem.toUiModel()`) formats price via
`NumberFormat.getCurrencyInstance` whose currency is set to the DTO `currency`
field, applied to `price_cents / 100.0` (verified: price is `price_cents:int` +
`currency:string`, not a nested money object), producing a locale-formatted
`priceLabel: String`. The thumbnail uses `image_urls.firstOrNull()`.

## 7. Error Handling & Resilience

- **Timeouts.** Catalog GETs use the core-network ~20s call timeout suited to
  the unreliable dev host.
- **Idempotent retry.** Both endpoints are GETs; the OkHttp bounded-backoff
  retry policy (for idempotent GETs only) applies. No retries on non-GET (none
  here).
- **Category load failure.** First load with no cache → `Error(retryable=true)`
  with a full-screen retry. With cache present → `Ready(stale=true)` plus a
  non-blocking "Showing saved data" banner and a refresh affordance.
- **Item page failure.** Surfaced through `items.loadState`:
  - `refresh is LoadState.Error` with empty grid → full-screen error + Retry
    (`items.retry()`).
  - `refresh is LoadState.Error` with cached page 1 → keep showing items, show
    snackbar.
  - `append is LoadState.Error` → footer row with message + Retry.
- **401.** Transparent to this layer; handled by the refresh-once interceptor.
  If refresh fails, the error maps to a non-retryable auth error and routing to
  re-auth is delegated to the app shell.
- **Empty vs. error** are never conflated: HTTP success with `items: []` →
  `Empty`; transport/HTTP error → `Error`.

## 8. Security & Privacy

- No new credentials or secrets. Session rides the existing persistent cookie
  jar; `X-CSRF-Token` is attached by core-network. This module never reads or
  logs cookie or CSRF values.
- Dev backend is **plaintext HTTP**; cleartext is permitted only for the dev
  flavor via the existing network-security-config (no change here). Release
  builds target HTTPS hosts.
- Catalog data is non-PII product content; cached Room rows contain no user
  data. No analytics on item identifiers beyond aggregate counts (Section 10).
- Image loads (AND-103/Coil) go through the shared OkHttp client so they inherit
  the same TLS/cleartext policy; no third-party image CDN credentials.

## 9. Accessibility & i18n

- All text from string resources in `feature-catalog/src/main/res/values/strings.xml`;
  no hardcoded user-facing strings. Pseudolocale-tested.
- Item cells: thumbnail `contentDescription` = item name; price exposed as text,
  not image. Category rows are a single focusable node announcing name + item
  count.
- Touch targets ≥ 48dp; grid cells meet minimum tap size at 2- and 3-column
  layouts.
- TalkBack: append spinner announced as "Loading more items"; retry buttons have
  descriptive labels. Pull-to-refresh has an accessible refresh action.
- Prices formatted with `NumberFormat`/locale currency; layouts use start/end
  (RTL-safe). Dynamic type respected (no fixed `sp` overrides that clip).
- Color contrast for price/name text meets WCAG AA against card surfaces in both
  light and dark themes (core-ui Material 3 tokens).

## 10. Telemetry & Logging

Via the shared analytics facade in core-ui/core-data (no PII):

- `catalog_browse_open` — { source }
- `catalog_category_select` — { category_id, position }
- `catalog_page_loaded` — { category_id, page, item_count, latency_ms }
- `catalog_load_error` — { scope: categories|items_refresh|items_append, code,
  http_status }
- `catalog_item_open` — { category_id, item_id, grid_position }

Logging uses the project `Timber`/`Logger` wrapper at `DEBUG` for load-state
transitions and `WARN`/`ERROR` for failures. Never log cookies, CSRF tokens, or
full URLs with auth context. Latency measured around each PagingSource `load`.

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + MockWebServer):**
- `CatalogItemsPagingSource.load` returns `Page` with `nextKey = next_token`
  when `next_token` is present, and `nextKey=null` on the last page (when
  `next_token` is absent/null).
- PagingSource maps `ApiResult.Failure` → `LoadResult.Error`.
- `CatalogRepositoryImpl.getCategories` maps DTOs → domain and surfaces cache on
  network failure (`stale=true`).
- `CatalogViewModel`: first load default-selects first category; `selectCategory`
  switches the paging stream (`flatMapLatest`) and resets to page 1;
  `Empty`/`Error` state derivation.
- Price formatting for multiple currencies/locales.

**Paging tests:** use `AsyncPagingDataDiffer` / `PagingData` snapshot to assert
append behavior across two pages and append-error retry.

**Compose UI (`createAndroidComposeRule`):**
- Category list renders; selecting a chip loads its grid.
- Grid renders ≥ page-size items; scrolling to end appends (assert via test tag
  on append spinner then more items).
- Empty, error+retry, and stale-banner states render with correct semantics.
- Item tap invokes `onItemClick(categoryId, itemId)`.

**Instrumented integration (MockWebServer):** end-to-end categories→items→append
against canned JSON matching Section 5 shapes, including a 500 on page 2 to
exercise append-error retry, and a 401-then-refresh-then-200 sequence.

Acceptance gate: automated test proving **render + paginate** (page 1 renders,
scroll triggers page 2 append).

## 12. Dependencies & Sequencing

- **Hard deps:** AND-204 (CatalogApi + DTOs + domain models) must merge first;
  AND-103 (thumbnail primitive) for item imagery.
- **Transitive:** AND-027 (via AND-204) for the typed `ApiResult`/network base;
  core-network cookie jar + CSRF + 401-refresh interceptors must be in place.
- **Blocks:** AND-206 (product detail) consumes the
  `shop/{categoryId}/{itemId}` route and nav-arg contract defined here.
- **Sequencing:** (1) scaffold `:feature-catalog` + DI; (2) repository + cache;
  (3) PagingSource + ViewModel; (4) Compose UI + states; (5) nav wiring + tests.
  If AND-204 paging is cursor-based, adapt only `CatalogItemsPagingSource`.

## 13. Risks & Open Questions

- **Paging style.** ~~Unknown.~~ **RESOLVED (verified):** cursor-based
  (`page_size` + opaque `next_token`); no integer pages. PagingSource keys are
  `String` cursors. See §5.
- **Category-as-chip vs. dedicated list screen.** Source scope says "category
  list, item grid" — assumed single screen with a category strip + grid.
  **Open: confirm IA with design** (not resolvable from API/frontend sources).
- **Price shape.** ~~Assumed `{amount_cents, currency}`.~~ **RESOLVED
  (verified):** flat `price_cents: int` + `currency: string` on `CatalogItemOut`.
  Map `price_cents/100` into `NumberFormat.getCurrencyInstance(Locale)` set to the
  item `currency`.
- **Category thumbnail / item count.** **RESOLVED (verified) — NOT AVAILABLE:**
  `CatalogCategoryOut` has no `image_url` and no `item_count`. FR-1's optional
  thumbnail + count must be dropped or sourced elsewhere. **Open: confirm with
  design whether category rows show name-only.**
- **Category pagination.** Categories endpoint is itself cursor-paginated; FR-1
  "display all categories" implies following `next_token` or capping at one large
  page. **Open: confirm expected category volume / cap.**
- **`next_token` semantics.** "Has more" is derived purely from `next_token`
  presence; there is no `total`/`has_more`. (Was: derive from `total/page`.)
- **Dev host flakiness** may make append tests nondeterministic against live
  backend; tests must use MockWebServer, not the dev host.
- **Search.** **RESOLVED (verified):** search is a separate endpoint
  (`GET /ui/catalog/items/search?q=`), not part of the browse screen. Out of
  scope here.

## 14. Acceptance Criteria

AC-1. Entering the catalog renders the category list from
`GET /ui/catalog/categories`; the first category is auto-selected and its items
load.
AC-2. The item grid renders the first page (page_size items) for the selected
category with thumbnail (`image_urls.first`), name, and locale-formatted price
(from `price_cents`/`currency`).
AC-3. Scrolling to the end of the grid fetches and **appends** the next page
without resetting scroll; an append spinner shows during the fetch
(**render + paginate** — primary ticket acceptance).
AC-4. Selecting a different category resets the grid to page 1 and scrolls to top.
AC-5. Pull-to-refresh reloads categories and page 1 of the current category.
AC-6. Empty categories and empty-item-category render distinct empty states; no
crash.
AC-7. Network failure with cache shows items/categories with a stale banner;
without cache shows a retryable error; retry recovers.
AC-8. Append failure shows a footer error with a working Retry.
AC-9. Tapping an item navigates to `shop/{categoryId}/{itemId}` with both ids.
AC-10. Selected category and loaded pages survive rotation; selected id survives
process death.
AC-11. Automated tests in Section 11 pass in CI, including the render+paginate
gate and the append-error/401-refresh sequences.

## 15. Definition of Done

- `:feature-catalog` module created, wired into `:app` navigation, builds with
  Gradle 8.9 / AGP 8.7.3, JDK 17, compileSdk/targetSdk 35, minSdk 24.
- All FRs and ACs implemented and verified; no hardcoded user-facing strings.
- Unit, Paging, Compose, and instrumented tests merged and green in CI; coverage
  for PagingSource, repository mapping/caching, and ViewModel selection logic.
- Lint/detekt/ktlint clean; no new cleartext exceptions beyond the existing dev
  flavor config.
- Telemetry events (Section 10) emitted and verified; no secrets logged.
- Accessibility pass (TalkBack + pseudolocale + RTL) completed.
- Nav-arg contract for `shop/{categoryId}/{itemId}` documented for AND-206.
- Code reviewed and merged to `android-port`; open questions in Section 13
  resolved or explicitly deferred with owners.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT (Verified / Corrected / Unverified-assumption)
and an exact SOURCE pointer. OpenAPI references are by `METHOD /path` and/or schema
name in `reference/openapi.pretty.json` / `reference/openapi.index.txt`; frontend
references are file + symbol.

1. **Categories endpoint path.** Claim (prior draft): `GET /ui/shop/categories`.
   VERDICT: **Corrected** → `GET /ui/catalog/categories`. SOURCE: OpenAPI
   `GET /ui/catalog/categories` (op `list_categories_..._get`, resp
   `CatalogCategoryListOut`); frontend `src/api/endpoints/cart.ts: getCategories`.
2. **Items endpoint path.** Claim: `GET /ui/shop/categories/{categoryId}/items`.
   VERDICT: **Corrected** → `GET /ui/catalog/categories/{category_id}/items`.
   SOURCE: OpenAPI `GET /ui/catalog/categories/{category_id}/items` (resp
   `CatalogItemListOut`); frontend `src/api/endpoints/cart.ts: getCategoryItems`.
3. **Pagination model.** Claim: integer `page` + `page_size`, response with
   `page/page_size/total/has_more`. VERDICT: **Corrected** → cursor-based:
   request `page_size` + optional `next_token`; response `{ items, next_token? }`
   only. SOURCE: OpenAPI params `page_size,next_token` on both list ops; schemas
   `CatalogCategoryListOut`/`CatalogItemListOut` (only `items` + nullable
   `next_token`); frontend `src/api/types.ts: PaginatedList<T> { items; next_token? }`.
4. **Category DTO fields.** Claim: `{ id, name, image_url, item_count }`. VERDICT:
   **Corrected** → `CatalogCategoryOut { category_id, name, description?,
   creator_id?, created_at }`; **no `image_url`, no `item_count`**, id is
   `category_id`. SOURCE: OpenAPI schema `CatalogCategoryOut`; frontend
   `src/api/types.ts: CatalogCategory`.
5. **Categories envelope key.** Claim: `{ "categories": [...] }`. VERDICT:
   **Corrected** → `{ "items": [...], "next_token"? }`. SOURCE: schema
   `CatalogCategoryListOut`.
6. **Item DTO id field.** Claim: `id`. VERDICT: **Corrected** → `item_id`.
   SOURCE: schema `CatalogItemOut` (required `item_id`); `src/api/types.ts:
   CatalogItem`.
7. **Item price shape.** Claim: nested `price: { amount_cents, currency }`.
   VERDICT: **Corrected** → flat `price_cents: int` + `currency: string`. SOURCE:
   schema `CatalogItemOut` (`price_cents`, `currency` both required);
   `src/api/types.ts: CatalogItem`.
8. **Item image field.** Claim: single `thumbnail_url`. VERDICT: **Corrected** →
   `image_urls: string[]` (required array); use `firstOrNull()` for the
   thumbnail. SOURCE: schema `CatalogItemOut`; `src/api/types.ts: CatalogItem`.
9. **Auth: CSRF on GETs.** Claim: cookies + `X-CSRF-Token` attached to catalog
   GETs. VERDICT: **Verified.** SOURCE: `src/api/client.ts` (reads `ui_csrf`
   cookie → `X-CSRF-Token` header on every request; `credentials: "include"`).
10. **401 handling.** Claim: one `POST /ui/session/refresh` then retry. VERDICT:
    **Verified.** SOURCE: `src/api/client.ts: refreshSession` + single-retry block
    on `res.status === 401`.
11. **Error `detail` mapper shape.** Claim: `string | [{msg}] | {code,...}`.
    VERDICT: **Verified** (consistent). SOURCE: `src/api/client.ts:
    normalizeErrorDetail`; OpenAPI `422 HTTPValidationError` (array of
    `{loc,msg,type}`). List ops also declare `400/401/403/429`
    (`reference/openapi.index.txt` lines for both list ops).
12. **Search is separate / out of scope.** Claim: search not part of browse.
    VERDICT: **Verified.** SOURCE: OpenAPI `GET /ui/catalog/items/search` (param
    `q`); frontend `src/api/endpoints/cart.ts: searchCatalogItems`.
13. **Web client default page_size = 50.** VERDICT: **Verified.** SOURCE:
    `src/api/endpoints/cart.ts` (`getCategories(pageSize = 50)`,
    `getCategoryItems(..., pageSize = 50)`).
14. **Nav route `shop/{categoryId}/{itemId}`.** VERDICT: **Unverified-assumption**
    (Android-internal navigation route, not an API path; owned by this ticket for
    AND-206). Not derivable from backend/frontend sources — frontend is a separate
    web router. Kept as the in-app contract.
15. **Paging 3 / Compose / Hilt / Room / DataStore choices.** VERDICT:
    **Unverified-assumption** (Android framework choices, not backed by the API
    contract). framework ref:
    https://developer.android.com/topic/libraries/architecture/paging/v3-overview ,
    https://developer.android.com/develop/ui/compose/lists ,
    https://developer.android.com/training/data-storage/room .
16. **Stock/attributes fields available on items.** VERDICT: **Verified** present
    (`stock_count?`, `stock_status`, `low_stock_threshold`, `attributes`,
    `position`, timestamps) though unused by browse. SOURCE: schema
    `CatalogItemOut`. Browse may optionally show stock badges (not required).

### Corrections made

- §2, §5, §14 AC-1: catalog paths changed from `/ui/shop/...` to `/ui/catalog/...`.
- §4 (Repository): `dto.categories` → `dto.items`; `CategoryDto` → `CatalogCategoryDto`.
- §4 (PagingSource): rewritten from integer-page (`PagingSource<Int,…>`,
  `page`/`hasMore`) to cursor-based (`PagingSource<String,…>`, `next_token`);
  `getRefreshKey` returns null (opaque cursors); `PAGE_SIZE` 20 → 50.
- §4/§5 (CatalogApi): query params `page`/`page_size` → `page_size`/`next_token`;
  response types → `CatalogCategoryListDto`/`CatalogItemListDto` (`{items,next_token}`).
- §5: category DTO (no `image_url`/`item_count`; `category_id`), item DTO
  (`item_id`, flat `price_cents`+`currency`, `image_urls[]`), removed
  `page/page_size/total/has_more`; added `400/401/403/429/422` note and search note.
- §6: price mapping clarified to `price_cents/100` + currency; thumbnail =
  `image_urls.firstOrNull()`.
- FR-1: dropped unbacked category thumbnail/item-count; FR-3: thumbnail =
  `image_urls.first`, price from `price_cents`/`currency`.
- §11: `has_more=true` test rephrased to `next_token` presence.
- §13: resolved paging-style, price-shape, search, and `has_more` open questions;
  added category-thumbnail/count and category-pagination as new open items.
- §14 AC-1/AC-2: path + field corrections.

### Open assumptions

- **Category IA (chip strip vs dedicated screen).** Not derivable from API/frontend
  (frontend is a different web layout); needs design confirmation.
- **Category rows have no image/count.** Confirmed absent in the DTO; whether the
  row is name-only or pulls counts from elsewhere is a design decision.
- **Category-list pagination cap.** "Show all categories" vs following `next_token`
  / capping at one large page is unspecified by the contract.
- **Nav route `shop/{categoryId}/{itemId}`.** App-internal; cannot be verified
  against backend/frontend. Defined by this ticket for AND-206.
- **Android library/version choices** (Paging 3, Compose, Hilt, Room, DataStore,
  Coil, AGP/Gradle/JDK pins): framework decisions, not API-verifiable.
- **Caching to Room for stale/offline** (§6/§7): a client design choice; no backend
  contract governs it.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, Android 15 / API 35); **A15** = physical
Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34,
arm64-v8a). Network is always faked with **MockWebServer** (never the flaky dev
host) per §13.

- **TC-AND-205-01** — Type: contract/MockWebServer. Target: JVM. Precondition:
  MockWebServer serves `CatalogCategoryListOut` with 3 items, `next_token` absent.
  Steps: call `CatalogApi.getCategories()`; map via repository. Expected: 3 domain
  `Category` items parsed from envelope key **`items`**; each has `category_id`,
  `name`; no crash on missing `image_url`/`item_count`. Traces: AC-1.

- **TC-AND-205-02** — Type: contract/MockWebServer. Target: JVM. Precondition:
  MockWebServer serves `CatalogItemListOut` page 1 with `next_token:"c2"`, items
  carrying `item_id`, `price_cents`, `currency`, `image_urls[]`. Steps: invoke
  `CatalogItemsPagingSource.load(refresh)`. Expected: `LoadResult.Page` with
  `nextKey == "c2"`, `prevKey == null`, items mapped (`item_id`, price from
  `price_cents`, thumbnail = `image_urls.first`). Traces: AC-2, AC-3.

- **TC-AND-205-03** — Type: unit. Target: JVM. Precondition: MockWebServer serves
  a last page with `next_token` absent/null. Steps: `load(append)` with key `"c2"`.
  Expected: `LoadResult.Page` with `nextKey == null` (end of pagination). Traces:
  AC-3.

- **TC-AND-205-04** — Type: contract/MockWebServer. Target: JVM. Precondition:
  endpoint returns HTTP 500 (or transport failure). Steps: `load()`. Expected:
  `ApiResult.Failure` → `LoadResult.Error(throwable)`; no crash; error not
  conflated with empty. Traces: AC-7, AC-8.

- **TC-AND-205-05** — Type: unit (Turbine). Target: JVM. Precondition: repository
  fake returns categories then a network failure with a Room-cached copy. Steps:
  call `getCategories()` twice (success, then failure). Expected: first emits
  `Ready`; on failure surfaces cached categories with `stale=true`; HTTP-200 +
  empty `items` → `Empty` (distinct from error). Traces: AC-6, AC-7.

- **TC-AND-205-06** — Type: unit (Turbine). Target: JVM. Precondition:
  `CatalogViewModel` with a repository fake exposing 2 categories. Steps: call
  `loadCategories()`; then `selectCategory(secondId)`. Expected: first category
  auto-selected on load; `selectCategory` updates `SavedStateHandle[KEY_SELECTED]`
  and `flatMapLatest` switches the paging stream to the new category (resets to
  first page). Traces: AC-1, AC-4, AC-10.

- **TC-AND-205-07** — Type: unit. Target: JVM. Precondition: items with
  currencies USD and EUR under locales en-US and de-DE. Steps: map
  `CatalogItem.toUiModel()`. Expected: `priceLabel` = locale-currency formatting
  of `price_cents/100` using the item `currency` (e.g. `$19.99`, `19,99 €`).
  Traces: AC-2.

- **TC-AND-205-08** — Type: unit (Paging, `AsyncPagingDataDiffer`). Target: JVM.
  Precondition: MockWebServer serves page 1 (`next_token:"c2"`) then page 2
  (`next_token` absent). Steps: collect snapshot, trigger append. Expected: page-1
  items present, then page-2 items appended (no reset); after page 2,
  `append.endOfPaginationReached == true`. Traces: AC-3 (render+paginate gate).

- **TC-AND-205-09** — Type: unit (Paging). Target: JVM. Precondition: page 1 OK,
  page 2 returns HTTP 500, then a retry of page 2 returns 200. Steps: append →
  observe `append is LoadState.Error` → `retry()` → success. Expected: append
  error surfaced via `loadState`; retry appends page 2. Traces: AC-8, AC-11.

- **TC-AND-205-10** — Type: Compose-UI. Target: emu35 (fast CI UI). Precondition:
  MockWebServer canned categories + item pages. Steps: launch `CatalogScreen`;
  assert category strip renders; tap a category; scroll grid to end; assert append
  spinner (test tag) then additional cells; tap an item. Expected: grid renders ≥
  first-page items; append spinner shows during fetch; more items appear;
  `onItemClick(categoryId, itemId)` invoked with both ids. Traces: AC-1, AC-2,
  AC-3, AC-4, AC-9.

- **TC-AND-205-11** — Type: Compose-UI. Target: emu35. Precondition: variants —
  (a) `items: []`, (b) zero categories, (c) refresh error with no cache,
  (d) stale-cache banner. Steps: render each. Expected: distinct empty UI for no
  categories vs empty-item-category; full-screen retryable error when no cache;
  "Showing saved data" stale banner when cache present; Retry recovers. Traces:
  AC-6, AC-7, AC-8.

- **TC-AND-205-12** — Type: Compose-UI accessibility. Target: emu35. Precondition:
  TalkBack/semantics assertions enabled; pseudolocale + RTL configs. Steps: assert
  semantics on item cells, append spinner, retry buttons; verify tap targets ≥
  48dp; run pseudolocale (no clipping) and RTL layout. Expected: thumbnail
  `contentDescription` = item name; price is text; append spinner announces
  "Loading more items"; retry/refresh have accessible actions; no hardcoded
  strings. Traces: AC-2, AC-6, AC-8.

- **TC-AND-205-13** — Type: instrumented/e2e (MockWebServer). Target: emu35.
  Precondition: scripted sequence categories→items page1→**401 on page 2**→
  `POST /ui/session/refresh` 200→page 2 retry 200. Steps: drive browse end to end.
  Expected: 401 triggers exactly one refresh then a successful retry transparent to
  the UI; append completes; `X-CSRF-Token` present on requests. Traces: AC-3,
  AC-7, AC-11.

- **TC-AND-205-14** — Type: instrumented (config-change / process-death). Target:
  A15 (real OS state-saving behavior on API 34 / arm64 differs from emulator;
  prefer physical device). Precondition: category selected, grid scrolled, pages
  loaded. Steps: rotate device; then simulate process death
  (`adb shell am kill` / "Don't keep activities") and restore. Expected: selected
  category id and scroll/loaded pages survive rotation; selected id restored from
  `SavedStateHandle` after process death. Traces: AC-10. **Must run on the
  physical device** (A15) for authentic process-death/restore and API-34 behavior.

- **TC-AND-205-15** — Type: manual. Target: A15. Precondition: dev build with
  cleartext flavor; toggle airplane mode. Steps: load browse online; enable
  airplane mode; pull-to-refresh; re-enable network and refresh. Expected: offline
  shows stale banner (if cached) or retryable error (if not); recovery on
  reconnect; no cleartext leak beyond dev flavor; no cookie/CSRF in logs. Traces:
  AC-5, AC-7. (Real-radio offline/recovery — physical device.)

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1  | TC-01, TC-06, TC-10 |
| AC-2  | TC-02, TC-07, TC-10, TC-12 |
| AC-3  | TC-02, TC-03, TC-08, TC-10, TC-13 |
| AC-4  | TC-06, TC-10 |
| AC-5  | TC-15 |
| AC-6  | TC-05, TC-11, TC-12 |
| AC-7  | TC-04, TC-05, TC-11, TC-13, TC-15 |
| AC-8  | TC-04, TC-09, TC-11, TC-12 |
| AC-9  | TC-10 |
| AC-10 | TC-06, TC-14 |
| AC-11 | TC-09, TC-13 |
