---
id: AND-205
title: Catalog / category browse
milestone: M5
epic: E28
priority: P0
size: L
status: draft
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
  and the shared 401→`/ui/session/refresh`→retry interceptor (core-network).

## 3. Functional Requirements

FR-1. **Category list.** On entering the catalog tab, fetch and display all shop
categories as a vertical list (or horizontally scrollable chip row at the top of
the browse screen). Each row shows category name, optional thumbnail, and item
count if provided by the DTO.

FR-2. **Default selection.** On first load with no explicit selection, the first
returned category is selected and its item grid is loaded automatically.

FR-3. **Item grid.** For the selected category, display items in a
`LazyVerticalGrid` (2 columns in portrait, 3 in landscape / `WindowSizeClass`
expanded). Each cell shows item thumbnail (via AND-103 primitive), name, and
formatted price.

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
            api.getCategories().toApiResult { dto -> dto.categories.map(CategoryDto::toDomain) }
        }

    override fun itemsPager(categoryId: String): Flow<PagingData<CatalogItem>> =
        Pager(
            config = PagingConfig(
                pageSize = PAGE_SIZE,            // 20
                prefetchDistance = 6,
                initialLoadSize = PAGE_SIZE,
                enablePlaceholders = false,
            ),
            pagingSourceFactory = { CatalogItemsPagingSource(api, categoryId, io) },
        ).flow

    companion object { const val PAGE_SIZE = 20 }
}
```

### PagingSource

```kotlin
class CatalogItemsPagingSource(
    private val api: CatalogApi,
    private val categoryId: String,
    private val io: CoroutineDispatcher,
) : PagingSource<Int, CatalogItem>() {

    override suspend fun load(params: LoadParams<Int>): LoadResult<Int, CatalogItem> =
        withContext(io) {
            val page = params.key ?: 1
            when (val r = api.getCategoryItems(categoryId, page, params.loadSize)) {
                is ApiResult.Success -> {
                    val items = r.data.items.map(CatalogItemDto::toDomain)
                    LoadResult.Page(
                        data = items,
                        prevKey = if (page == 1) null else page - 1,
                        nextKey = if (r.data.hasMore) page + 1 else null,
                    )
                }
                is ApiResult.Failure -> LoadResult.Error(r.toThrowable())
            }
        }

    override fun getRefreshKey(state: PagingState<Int, CatalogItem>): Int? =
        state.anchorPosition?.let { anchor ->
            state.closestPageToPosition(anchor)?.let { it.prevKey?.plus(1) ?: it.nextKey?.minus(1) }
        }
}
```

> If AND-204 exposes cursor-based paging instead of integer pages, the keys
> become `String?` cursors echoed from `next_cursor`; the structure is
> otherwise identical. The PagingSource is the single point of adaptation.

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
ticket consumes. Confirm exact paths/field names against
`/openapi.json` and `frontend/src/api/endpoints/*.ts` during implementation.

**List categories** — `GET /ui/shop/categories`

```json
{
  "categories": [
    { "id": "cat_books", "name": "Books", "image_url": "https://…/c.jpg", "item_count": 128 }
  ]
}
```

**List items in a category** — `GET /ui/shop/categories/{categoryId}/items?page=1&page_size=20`

```json
{
  "items": [
    {
      "id": "itm_001",
      "category_id": "cat_books",
      "name": "Example Item",
      "price": { "amount_cents": 1999, "currency": "USD" },
      "thumbnail_url": "https://…/t.jpg"
    }
  ],
  "page": 1,
  "page_size": 20,
  "total": 128,
  "has_more": true
}
```

Retrofit interface (in `core-network`/AND-204):

```kotlin
interface CatalogApi {
    @GET("ui/shop/categories")
    suspend fun getCategories(): ApiResult<CategoriesResponseDto>

    @GET("ui/shop/categories/{categoryId}/items")
    suspend fun getCategoryItems(
        @Path("categoryId") categoryId: String,
        @Query("page") page: Int,
        @Query("page_size") pageSize: Int,
    ): ApiResult<CategoryItemsResponseDto>
}
```

All requests are authenticated GETs: cookies + `X-CSRF-Token` are attached by
the shared OkHttp interceptors; on `401` the client performs one
`POST /ui/session/refresh` then retries (core-network). FastAPI errors are
surfaced via the shared `detail` mapper (`string | [{msg}] | {code,...}`).

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
`NumberFormat.getCurrencyInstance` using the DTO currency, producing a
locale-formatted `priceLabel: String`.

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
- `CatalogItemsPagingSource.load` returns `Page` with correct `nextKey` when
  `has_more=true`, and `nextKey=null` on the last page.
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

- **Paging style unknown.** Integer page vs. cursor is not yet confirmed from
  AND-204/OpenAPI. *Mitigation:* isolate in PagingSource. **Open: confirm.**
- **Category-as-chip vs. dedicated list screen.** Source scope says "category
  list, item grid" — assumed single screen with a category strip + grid.
  **Open: confirm IA with design.**
- **Price shape.** Assumed `{amount_cents, currency}`. If backend returns a
  pre-formatted string or float dollars, mapping changes. **Open: verify DTO.**
- **`has_more` field presence.** If absent, derive from `total`/`page`/`page_size`.
- **Dev host flakiness** may make append tests nondeterministic against live
  backend; tests must use MockWebServer, not the dev host.
- **Search** is referenced in AND-204 scope but not part of this ticket — confirm
  it is not expected on the browse screen here.

## 14. Acceptance Criteria

AC-1. Entering the catalog renders the category list from `GET /ui/shop/categories`;
the first category is auto-selected and its items load.
AC-2. The item grid renders page 1 (≤ 20 items) for the selected category with
thumbnail, name, and locale-formatted price.
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
