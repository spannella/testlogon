---
id: AND-208
title: Catalog ViewModels
milestone: M5
epic: E28
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-204]
blocks: [AND-205, AND-206, AND-207, AND-209]
---

# AND-208 — Catalog ViewModels

## 1. Overview & Goal

This ticket delivers the presentation-layer state holders for the catalog/shop
area of the TestLogon native Android app: the **browse** ViewModel (categories +
paged item grid), the **detail** ViewModel (single product), and the **search**
ViewModel (full-text query over the catalog). Each is a `@HiltViewModel` that
exposes an immutable `StateFlow<…UiState>`, accepts intent-style entry points
from its Compose screen, drives a `CatalogRepository` call, and maps the typed
`ApiResult<T>` (and Paging `LoadState`) into screen-ready state and one-shot
navigation effects.

The scope is **the ViewModels and their state contracts only** — state shape,
intent handlers, the result→state/effect mapping, the paging-stream wiring, and
exhaustive unit-test coverage of the state machines. The Compose screens
(AND-205 browse, AND-206 detail, AND-207 search), the `CatalogApi`/DTOs/domain
models (AND-204), and the integration/UI test suite (AND-209) are consumed or
owned elsewhere — not implemented here. The single acceptance bar from the
backlog is **unit-tested**: every state transition in §11 is covered by passing
JVM unit tests.

Module: `:feature-catalog`. Package root
`com.testlogon.android.feature.catalog`. The ViewModels depend on `core-data`
(`CatalogRepository`), `core-model` (domain types + `ApiResult`), and `core-ui`
(`UiText`).

> Sequencing note: AND-205/206/207 each name their own screen-scoped ViewModel
> in their drafts. To avoid divergence, **this ticket is the canonical owner of
> the three ViewModel classes, their `UiState`/`Effect` contracts, and the
> `CatalogRepository` interface shape**; the screen tickets consume them. Where
> earlier drafts sketched a `CatalogViewModel`, that name maps to
> `CatalogBrowseViewModel` here.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace / applicationId base **`com.testlogon.android`**.
- Module layering: `app -> feature-catalog -> core-* (core-network, core-model,
  core-ui, core-data, core-testing)`. ViewModels expose `StateFlow<UiState>`;
  typed `ApiResult<T>`; FastAPI `detail` mapping (`string | [{msg}] |
  {code,...}`) is performed in core-network and surfaced as `ApiError`.
- **AND-204 (depends_on)** — provides `CatalogApi` (Retrofit), Moshi DTOs
  (`CategoryDto`, `CatalogItemDto`, paged envelopes), and `core-model` domain
  types (`Category`, `CatalogItem`, `CatalogItemDetail`, `Price`). This ticket
  consumes those via a `CatalogRepository`; it does **not** redefine them.
- **AND-205 (blocks)** — browse screen renders `CatalogBrowseUiState` +
  `LazyPagingItems` and forwards category/refresh/item-click intents.
- **AND-206 (blocks)** — detail screen at route `shop/{categoryId}/{itemId}`
  renders `ProductDetailUiState` and forwards add-to-cart / retry intents.
- **AND-207 (blocks)** — search screen renders `CatalogSearchUiState`, forwards
  query edits, consumes the debounced paged results.
- **AND-209 (blocks)** — repo + UI test ticket; this ticket ships the *unit*
  tests, AND-209 adds Compose/instrumented coverage.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext,
  unreliable: ~20s timeouts, bounded-backoff retry for idempotent GETs only,
  offline/stale states). Catalog endpoints are authenticated GETs riding the
  persistent cookie jar + `ui_csrf`/`X-CSRF-Token`; `401`→one
  `POST /ui/session/refresh`→retry is handled inside core-network.
- Web reference: catalog endpoint helpers live in `src/api/endpoints/cart.ts`
  (`getCategories`, `getCategoryItems`, `searchCatalogItems` — there is **no**
  `catalog.ts`/`shop.ts` file), shared DTOs in `src/api/types.ts`
  (`CatalogCategory`, `CatalogItem`, `PaginatedList<T>`). OpenAPI at
  `/openapi.json`. CORRECTED: the web app uses the `/ui/catalog/*` route family,
  not `/ui/shop/*` (see §5 corrections).

## 3. Functional Requirements

FR-1. **Browse state.** `CatalogBrowseViewModel` exposes
`val uiState: StateFlow<CatalogBrowseUiState>` (categories layer) and
`val items: Flow<PagingData<CatalogItemUi>>` for the selected category's grid.

FR-2. **Category load + default selection.** On init, fetch categories via
`repository.getCategories()`; map to `Ready(categories, selectedId)` selecting
the first category (or the `SavedStateHandle`-restored id) and emit the item
pager for that id. Empty list → `Empty`; failure with no cache → `Error`.

FR-3. **Category switch.** `selectCategory(id)` writes the id to
`SavedStateHandle`; the `items` stream switches via `flatMapLatest`, resetting to
page 1 for the new category. Re-selecting the current id is a no-op.

FR-4. **Browse refresh.** `refresh()` re-fetches categories and invalidates the
paging stream (the screen also calls `items.refresh()` for the grid).

FR-5. **Detail state.** `ProductDetailViewModel` reads `categoryId`/`itemId`
from `SavedStateHandle` (nav args), loads the product on init via
`repository.getItem(categoryId, itemId)`, and exposes
`StateFlow<ProductDetailUiState>` with `Loading | Ready | Error`.

FR-6. **Detail add-to-cart.** `onAddToCart()` is exposed but **delegates** to the
cart flow (E29 / AND-21x); in this ticket it sets a transient
`addToCartStatus` and emits a `ProductDetailEffect.AddToCart(item)` one-shot
effect. Idempotent while a cart op is in flight (double-tap guard).

FR-7. **Search state.** `CatalogSearchViewModel` exposes
`val uiState: StateFlow<CatalogSearchUiState>` (query + status) and
`val results: Flow<PagingData<CatalogItemUi>>`. `onQueryChange(String)` updates
the query immediately; the query is **debounced 300ms** and trimmed before a
search is issued.

FR-8. **Search empty / min-length.** Queries shorter than 2 non-blank chars
produce `Idle` (no request, empty results). A debounced query that yields zero
items maps to `NoResults`; a non-empty result set maps to `HasResults`.

FR-9. **One-shot navigation/effects.** Item taps from browse/search and the
add-to-cart confirmation are delivered as effects via a `SharedFlow`, never as
state, so rotation/recomposition cannot replay a navigation.

FR-10. **In-flight guards.** Every submit-style intent
(`refresh`, `retry`, `onAddToCart`) is a no-op while its own operation is in
flight, to prevent duplicate calls against the flaky dev host.

FR-11. **State retention.** Selected category id and current search query survive
configuration changes and process death via `SavedStateHandle`; loaded paging
pages survive config changes via `cachedIn(viewModelScope)`.

## 4. Technical Design

Package layout added by this ticket (within `:feature-catalog`):

```
vm/    CatalogBrowseViewModel, ProductDetailViewModel, CatalogSearchViewModel
ui/state  CatalogBrowseUiState, ProductDetailUiState, CatalogSearchUiState,
          CatalogItemUi, CategoryUi, AddToCartStatus
vm/effect CatalogBrowseEffect, ProductDetailEffect, CatalogSearchEffect
data/  CatalogRepository (interface, shape defined here; impl + PagingSource land
       with AND-205) and CatalogItem(Detail)?.toUi() mappers
```

The repository contract this ticket depends on (impl owned by AND-205):

```kotlin
interface CatalogRepository {
    /** Idempotent GET GET /ui/catalog/categories; bounded-backoff retried by core-network. */
    suspend fun getCategories(): ApiResult<List<Category>>
    /**
     * CORRECTED: there is NO item-detail endpoint in the backend. The web client
     * (src/pages/shop/ProductDetail.tsx) fetches GET /ui/catalog/categories/{id}/items
     * and then selects the item client-side by item_id. AND-204/205 must implement
     * getItem() the same way (list-then-find), so this stays a single suspend call
     * the ViewModel can fake. Repository owns the list-fetch + find; the VM is
     * unchanged. */
    suspend fun getItem(categoryId: String, itemId: String): ApiResult<CatalogItemDetail>
    fun itemsPager(categoryId: String): Flow<PagingData<CatalogItem>>
    fun searchPager(query: String): Flow<PagingData<CatalogItem>>
}
```

### Browse ViewModel

```kotlin
package com.testlogon.android.feature.catalog.vm

@HiltViewModel
class CatalogBrowseViewModel @Inject constructor(
    private val repository: CatalogRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow<CatalogBrowseUiState>(CatalogBrowseUiState.Loading)
    val uiState: StateFlow<CatalogBrowseUiState> = _uiState.asStateFlow()

    private val _effects = MutableSharedFlow<CatalogBrowseEffect>(
        replay = 0, extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val effects: SharedFlow<CatalogBrowseEffect> = _effects.asSharedFlow()

    private val selectedId = savedState.getStateFlow<String?>(KEY_SELECTED, null)

    @OptIn(ExperimentalCoroutinesApi::class)
    val items: Flow<PagingData<CatalogItemUi>> =
        selectedId.filterNotNull().distinctUntilChanged()
            .flatMapLatest { id -> repository.itemsPager(id).map { p -> p.map(CatalogItem::toUi) } }
            .cachedIn(viewModelScope)

    init { loadCategories() }

    fun loadCategories()                        // → Loading; getCategories(); map Empty/Ready/Error,
                                                //   default-select first or restored KEY_SELECTED
    fun selectCategory(id: String)              // no-op if == current; else write KEY_SELECTED, copy Ready
    fun onItemClick(item: CatalogItemUi) =
        _effects.tryEmit(CatalogBrowseEffect.NavigateToDetail(item.categoryId, item.id))
    fun refresh() = loadCategories()
    fun retryCategories() = loadCategories()

    companion object { const val KEY_SELECTED = "selected_category_id" }
}
```

`loadCategories()` sets `Loading`, calls `repository.getCategories()`, and on
`Success` maps `List<Category>`→`Empty` (no rows) or
`Ready(categories, selectedId)` — preferring a restored `KEY_SELECTED` that still
exists, else the first category; on `Failure` it sets `Error(toUiText, retryable=true)`.
`selectCategory(id)` returns early if `id` equals the current selection,
otherwise writes `KEY_SELECTED` (driving the `flatMapLatest` switch) and copies
the `Ready` state's `selectedId`.

### Detail ViewModel

```kotlin
@HiltViewModel
class ProductDetailViewModel @Inject constructor(
    private val repository: CatalogRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val categoryId: String = checkNotNull(savedState["categoryId"])
    private val itemId: String = checkNotNull(savedState["itemId"])

    private val _uiState = MutableStateFlow<ProductDetailUiState>(ProductDetailUiState.Loading)
    val uiState: StateFlow<ProductDetailUiState> = _uiState.asStateFlow()
    val effects: SharedFlow<ProductDetailEffect>            // replay=0, buffer=1, DROP_OLDEST

    init { load() }

    fun load()                  // → Loading; getItem(c,i); Success→Ready(toUi), Failure→Error(retryable)
    fun retry() = load()
    fun onAddToCart()           // from Ready & not InProgress: set InProgress, emit AddToCart(item)
    fun onAddToCartResult(success: Boolean)  // Ready.copy(status = if(success) Added else Idle)
}
```

`onAddToCart()` returns early unless the state is `Ready` with
`addToCartStatus != InProgress`; otherwise it sets `InProgress` and emits the
one-shot `ProductDetailEffect.AddToCart(item)` (the cart mutation is owned by
E29 / AND-21x). The screen calls `onAddToCartResult(success)` when the cart op
settles, resolving to `Added` or back to `Idle`.

### Search ViewModel

```kotlin
@HiltViewModel
class CatalogSearchViewModel @Inject constructor(
    private val repository: CatalogRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val queryFlow = savedState.getStateFlow(KEY_QUERY, "")
    val uiState: StateFlow<CatalogSearchUiState>           // query mirrored from queryFlow

    @OptIn(FlowPreview::class, ExperimentalCoroutinesApi::class)
    val results: Flow<PagingData<CatalogItemUi>> =
        queryFlow.map { it.trim() }
            .debounce(DEBOUNCE_MS)              // 300L
            .distinctUntilChanged()
            .flatMapLatest { q ->
                if (q.length < MIN_QUERY_LEN) flowOf(PagingData.empty())   // MIN_QUERY_LEN = 2
                else repository.searchPager(q).map { p -> p.map(CatalogItem::toUi) }
            }
            .cachedIn(viewModelScope)

    fun onQueryChange(value: String) { savedState[KEY_QUERY] = value }
    fun onClear() { savedState[KEY_QUERY] = "" }
    fun onItemClick(item: CatalogItemUi)       // emit CatalogSearchEffect.NavigateToDetail
}
```

Design notes:
- **State via `update {}` only**, never raw assignment, to avoid lost-update
  races between intents and the load coroutine.
- **Effects over state for navigation** (replay=0, buffer=1, `DROP_OLDEST`);
  collected by the screen in `repeatOnLifecycle(STARTED)`.
- **No threading in the ViewModel**; repository suspends switch to
  `Dispatchers.IO` (core-data convention). ViewModels stay on `viewModelScope`
  (Main). For deterministic tests, the test dispatcher is injected via
  `Dispatchers.setMain`.
- **Item-grid `LoadState`** (refresh/append/error) is owned by Paging and read
  by the screen from `LazyPagingItems.loadState`; it is **not** duplicated into
  the categories-layer `UiState` to keep a single source of truth.

## 5. API Contract

No new endpoint is defined or called directly by this ticket. The ViewModels
invoke `CatalogRepository` (impl + Retrofit `CatalogApi` owned by AND-204/205).
The contract below is **verified against `openapi.pretty.json` and
`src/api/endpoints/cart.ts` + `src/api/types.ts`** (2026-06-06). The original
draft used a fictional `/ui/shop/*` route family and `price`/`media`/`thumbnail`
field names that do not exist; those are corrected here and audited in §16.

> CORRECTIONS (paths, paging, fields) — all `/ui/shop/*` → `/ui/catalog/*`;
> integer `page`/`total`/`has_more` paging → cursor `page_size`/`next_token`;
> nested `price{amount_cents,currency}` → flat `price_cents` + `currency`;
> `thumbnail_url`/`media` → `image_urls: string[]`; category has no
> `image_url`/`item_count`; no item-detail GET exists.

**Categories** — `GET /ui/catalog/categories?page_size=50[&next_token=…]`
→ `CatalogCategoryListOut`
```json
{ "items": [ { "category_id": "cat_books", "name": "Books",
  "description": null, "creator_id": "usr_1", "created_at": "2026-01-02T…" } ],
  "next_token": null }
```
Note: no `image_url`, no `item_count` — CategoryUi must treat those as
unavailable (see §6 correction). `category_id`+`name`+`created_at` are required.

**Items in category (paged)** —
`GET /ui/catalog/categories/{category_id}/items?page_size=50[&next_token=…]`
→ `CatalogItemListOut`
```json
{ "items": [ { "category_id": "cat_books", "item_id": "itm_001",
  "name": "Example Item", "description": "…", "price_cents": 1999,
  "currency": "USD", "image_urls": ["https://…/1.jpg"], "attributes": {},
  "stock_count": 7, "stock_status": "in_stock", "low_stock_threshold": 5,
  "created_at": "…", "updated_at": "…", "position": 0 } ],
  "next_token": "eyJ…" }
```
Required fields: `category_id, item_id, name, price_cents, currency,
image_urls, attributes, created_at, updated_at`. Cursor paging only — the
response carries **no** `page`/`page_size`/`total`/`has_more`; "next page"
availability == `next_token != null`. Stock is `stock_count` (nullable) +
`stock_status` (string, e.g. `unlimited`), **not** a boolean `in_stock`.

**Item detail** — **NO endpoint.** There is no
`GET /ui/catalog/categories/{id}/items/{itemId}`; the OpenAPI index lists only
`PATCH`/`DELETE` on that path. The web client
(`src/pages/shop/ProductDetail.tsx`) loads the category-items list via
`getCategoryItems(categoryId)` and resolves the product with
`items.find(i => i.item_id === itemId)`. `getItem()` must do the same
(list-then-find) and surface `ApiError.NotFound` when the id is absent.
`CatalogItemDetail`/`CatalogItemDetailUi` are derived from the same
`CatalogItem` shape (no `sku`; SKU at cart-add time is the `item_id` —
see `ProductDetail.tsx` `addCartItem({ sku: item.item_id, … })`).

**Search (paged)** — `GET /ui/catalog/items/search?q={query}&page_size=50`
→ `CatalogItemListOut` (same envelope as category items). CORRECTED from the
draft's `/ui/shop/search`. Distinct from the global `GET /ui/search`
(`src/api/endpoints/search.ts`), which is a multi-type search returning grouped
sections, not the catalog item list — do **not** wire the catalog search VM to
`/ui/search`.

All are authenticated GETs: the persistent cookie jar + `X-CSRF-Token` (from the
`ui_csrf` cookie) are attached by core-network — VERIFIED against
`src/api/client.ts`. `401`→one `POST /ui/session/refresh`→retry is handled
inside core-network (VERIFIED: `refreshSession()` in `client.ts`). FastAPI errors
arrive pre-mapped as `ApiError`; the `detail` field is `string | [{msg}] |
{code,…}` (VERIFIED: `normalizeErrorDetail` in `client.ts`; 422 =
`HTTPValidationError`). The ViewModels are transport-agnostic and depend only on
`core-model` domain types and `ApiResult`.

## 6. Data & State Management

```kotlin
// Browse
sealed interface CatalogBrowseUiState {
    data object Loading : CatalogBrowseUiState
    data class Ready(val categories: List<CategoryUi>, val selectedId: String,
                     val stale: Boolean = false) : CatalogBrowseUiState
    data object Empty : CatalogBrowseUiState
    data class Error(val message: UiText, val retryable: Boolean) : CatalogBrowseUiState
}
sealed interface CatalogBrowseEffect {
    data class NavigateToDetail(val categoryId: String, val itemId: String) : CatalogBrowseEffect
}

// Detail
sealed interface ProductDetailUiState {
    data object Loading : ProductDetailUiState
    data class Ready(val item: CatalogItemDetailUi,
                     val addToCartStatus: AddToCartStatus = AddToCartStatus.Idle) : ProductDetailUiState
    data class Error(val message: UiText, val retryable: Boolean) : ProductDetailUiState
}
enum class AddToCartStatus { Idle, InProgress, Added }
sealed interface ProductDetailEffect { data class AddToCart(val item: CatalogItemDetailUi) : ProductDetailEffect }

// Search
data class CatalogSearchUiState(
    val query: String = "",
    val phase: SearchPhase = SearchPhase.Idle,   // derived by screen from query + results.loadState
)
enum class SearchPhase { Idle, Searching, HasResults, NoResults, Error }
sealed interface CatalogSearchEffect { data class NavigateToDetail(val categoryId: String, val itemId: String) : CatalogSearchEffect }

// Shared UI models
// CORRECTED to match the real DTOs (CatalogCategory / CatalogItem in
// src/api/types.ts + CatalogItemOut/CatalogCategoryOut in OpenAPI):
//  - Category has NO image_url and NO item_count → those UI fields stay nullable
//    and default null until/unless AND-204 synthesizes them. They are NOT in the
//    wire payload; do not assume the repository can populate them.
//  - Item has image_urls: List<String> (not a single thumbnail_url) →
//    thumbnailUrl = image_urls.firstOrNull().
//  - Item has NO boolean in_stock and NO sku → inStock is DERIVED from
//    stock_status/stock_count (see toUi mapper note); sku is dropped (cart-add
//    uses item_id as the sku).
data class CategoryUi(val id: String, val name: String,
                      val description: String? = null,
                      val imageUrl: String? = null,   // not in API; reserved
                      val itemCount: Int? = null)     // not in API; reserved
data class CatalogItemUi(val id: String, val categoryId: String, val name: String,
                         val priceLabel: String, val thumbnailUrl: String?)
data class CatalogItemDetailUi(val id: String, val categoryId: String, val name: String,
                               val description: String, val priceLabel: String,
                               val imageUrls: List<String>, val inStock: Boolean,
                               val stockCount: Int?)
```

State rules:
- Selected category id (`KEY_SELECTED`) and search query (`KEY_QUERY`) live in
  `SavedStateHandle` → survive process death. Detail nav args
  (`categoryId`/`itemId`) come from the back-stack entry's `SavedStateHandle`.
- `cachedIn(viewModelScope)` retains loaded paging pages across config changes;
  re-collection does not re-fetch.
- Domain→UI mapping (`CatalogItem.toUi()`, `CatalogItemDetail.toUi()`) formats
  `priceLabel` from `price_cents`/`currency` via
  `NumberFormat.getCurrencyInstance(...)` keyed on the DTO `currency`, so the
  JVM-pure mappers are unit-testable. (Note: the web client hardcodes
  `Intl.NumberFormat("en-US", …)` in `Catalog.tsx`/`ProductDetail.tsx`; the
  Android port deliberately upgrades this to device-locale-aware formatting —
  flagged as an intentional behavior divergence, see §16.)
  `thumbnailUrl = image_urls.firstOrNull()`; `imageUrls = image_urls`.
  `inStock` is DERIVED, not a wire field: `stock_status != "out_of_stock"`
  (treat `unlimited` and any positive `stock_count` as in stock); preserve the
  raw `stock_count` for the detail screen. The exact `stock_status` string set is
  an unverified assumption (only `unlimited` is visible as a default in OpenAPI)
  — see §16 open assumptions.
- `stale = true` on `Ready` indicates categories served from cache after a
  network failure (cache read owned by AND-205's repository impl; the ViewModel
  only relays the flag the repository signals).

## 7. Error Handling & Resilience

- **`ApiError`→`UiText` mapping** (shared extension in `core-ui`/feature):
```kotlin
private fun ApiError.toUiText(): UiText = when (this) {
    is ApiError.Network, is ApiError.Timeout -> UiText.Res(R.string.catalog_error_network)
    is ApiError.Server                        -> UiText.Res(R.string.catalog_error_server)
    is ApiError.NotFound                      -> UiText.Res(R.string.catalog_error_not_found)
    is ApiError.Validation                    -> UiText.Dynamic(firstMessage)
    is ApiError.Unauthorized                  -> UiText.Res(R.string.catalog_error_auth)
    else                                      -> UiText.Res(R.string.catalog_error_generic)
}
```
- **Timeouts.** Catalog GETs use core-network's ~20s call timeout for the
  unreliable plaintext dev host; timeout → `ApiError.Timeout` → network message.
- **Idempotent retry.** All catalog endpoints are GETs, so core-network's
  bounded-backoff retry applies transparently. ViewModels add **no** retry loops;
  `retry()`/`retryCategories()` re-issue exactly one fresh call.
- **Item-grid / search paging errors** surface through `LoadState`:
  `refresh` error with empty data → screen shows full-screen error + `retry()`;
  `append` error → footer + `items.retry()`. The ViewModel does not intercept
  these; it owns only the categories/detail/query layers.
- **401** is transparent (refresh-once interceptor). If refresh ultimately fails,
  the error maps to `ApiError.Unauthorized` and re-auth routing is delegated to
  the app shell — these ViewModels do not own session recovery.
- **Empty vs. error never conflated.** HTTP 200 with empty list → `Empty` /
  `NoResults`; transport/HTTP error → `Error`.
- **Double-submit guards** (FR-10) keep one in-flight op per intent.
- **Cancellation.** In-flight loads cancel automatically when `viewModelScope`
  clears or `flatMapLatest` switches; no manual `Job` tracking.

## 8. Security & Privacy

- No credentials or secrets handled here. The session rides the existing
  persistent cookie jar; `X-CSRF-Token` is attached by core-network. These
  ViewModels never read, store, or log cookie or CSRF values.
- Catalog/search payloads are non-PII product content; nothing user-identifying
  is persisted by these state holders (only category id and a product search
  query in `SavedStateHandle`).
- Search queries are user input but not secrets; they are not logged at
  non-debug levels and never sent to analytics verbatim (only `query_len`).
- Dev backend is **plaintext HTTP**; cleartext is permitted only for the dev
  flavor via the existing network-security-config — no change in this ticket.
- `UiState`/`UiText` carry no transport details, so accidental state logging
  cannot leak endpoints, tokens, or stack traces.

## 9. Accessibility & i18n

- All user-facing strings are emitted as `UiText` (string-resource or
  validated dynamic), never hardcoded English: `catalog_error_network`,
  `catalog_error_server`, `catalog_error_not_found`, `catalog_error_auth`,
  `catalog_error_generic`. Screens (AND-205/206/207) resolve them per locale.
- `priceLabel` is produced with locale-aware `NumberFormat` currency formatting
  so the rendered price respects the device locale and is announced as text.
- The ViewModels guarantee mutually-consistent flags (`addToCartStatus`,
  `phase`) so TalkBack reads the correct busy/added/empty state; errors are
  surfaced as state (not transient toasts) so screen readers can announce them
  via `liveRegion`.
- `SearchPhase.Searching/NoResults` give the search screen distinct,
  announceable states rather than an ambiguous blank list.
- No locale-specific parsing of input beyond `query.trim()`; layout direction /
  RTL concerns are the screens' responsibility.

## 10. Telemetry & Logging

Emitted via the shared analytics facade in core-data (no PII):

| Event | When | Properties |
|-------|------|-----------|
| `catalog_browse_open` | browse VM init | — |
| `catalog_category_select` | `selectCategory` accepted | `category_id` |
| `catalog_categories_error` | categories load failure | `error_type`, `http_status?` |
| `catalog_item_open` | item-click effect emitted | `category_id`, `item_id`, `source` (browse\|search) |
| `catalog_detail_view` | detail VM `Ready` | `category_id`, `item_id`, `in_stock` |
| `catalog_detail_error` | detail load failure | `error_type`, `http_status?` |
| `catalog_add_to_cart_tap` | `onAddToCart` accepted | `item_id` |
| `catalog_search` | debounced query issued | `query_len`, `min_len_met` |

- `Timber`/`Logger` wrapper: `DEBUG` for state-machine transitions and the
  debounce fire, `WARN`/`ERROR` for failures. Never log cookies, CSRF, full
  authed URLs, or the raw search string at non-debug levels (`query_len` only).

## 11. Testing Strategy

Pure-JVM unit tests (no Robolectric) under
`feature-catalog/src/test/.../vm/`, using `kotlinx-coroutines-test`
(`StandardTestDispatcher` + `Dispatchers.setMain`), `Turbine` for flows, and a
fake `CatalogRepository` from `core-testing`. Paging behavior is asserted with
`AsyncPagingDataDiffer` / `PagingData` snapshots and a fake `PagingSource`.

```kotlin
class FakeCatalogRepository(
    var categories: ApiResult<List<Category>>,
    var item: ApiResult<CatalogItemDetail>,
    var itemsPages: List<List<CatalogItem>> = emptyList(),
    var searchPages: List<List<CatalogItem>> = emptyList(),
) : CatalogRepository {
    val itemsPagerCategories = mutableListOf<String>()
    val searchQueries = mutableListOf<String>()
    override suspend fun getCategories() = categories
    override suspend fun getItem(c: String, i: String) = item
    override fun itemsPager(categoryId: String) =
        flowOf(PagingData.from(itemsPages.flatten())).also { itemsPagerCategories += categoryId }
    override fun searchPager(query: String) =
        flowOf(PagingData.from(searchPages.flatten())).also { searchQueries += query }
}
```

Required cases:

**Browse** — (1) init success → `Ready` with first category default-selected and
`items` collecting page 1; (2) empty categories → `Empty`; (3) failure → `Error(retryable=true)`;
(4) `selectCategory(new)` updates `selectedId` and switches the pager
(`itemsPagerCategories` last == new id); (5) `selectCategory(current)` is a no-op
(no extra pager call); (6) restored `KEY_SELECTED` reused on init when still
present, else falls back to first; (7) `onItemClick` emits
`NavigateToDetail(categoryId,itemId)`; (8) `retryCategories` re-issues `getCategories`.

**Detail** — (9) init success → `Ready(item)`; (10) failure → `Error(retryable=true)`;
(11) `retry()` re-loads; (12) `onAddToCart` from `Ready` sets `InProgress` and
emits `AddToCart`; (13) second `onAddToCart` while `InProgress` is a no-op (one
effect emitted); (14) `onAddToCartResult(true)` → `Added`, `(false)` → `Idle`;
(15) `onAddToCart` ignored when state not `Ready`.

**Search** — (16) `onQueryChange` updates `uiState.query` immediately; (17) query
< `MIN_QUERY_LEN` yields empty results, **no** `searchPager` call; (18) debounce:
rapid edits within 300ms issue exactly one search for the final value (advance
virtual time, assert `searchQueries.size == 1`); (19) query is trimmed before
search; (20) `onClear` resets query to "" and results to empty; (21) results map
DTOs→`CatalogItemUi` with formatted price.

**Mappers** — (22) `CatalogItem.toUi`/`CatalogItemDetail.toUi` price formatting
for multiple currencies/locales; null thumbnail/description handled.

Coverage gate: 100% branches of the three ViewModels, the `toUiText` mapper, and
the `toUi` mappers.

## 12. Dependencies & Sequencing

- **Hard dep (must merge first):** AND-204 — `CatalogApi`, DTOs, and `core-model`
  domain types (`Category`, `CatalogItem`, `CatalogItemDetail`, `Price`).
- **Transitive (via AND-204):** AND-027 (auth/session base), core-network cookie
  jar + CSRF + 401-refresh + idempotent-GET retry; `ApiResult`/`ApiError`
  (AND-018/AND-015).
- **Blocks / enables:** AND-205 (browse screen + repository impl + PagingSource),
  AND-206 (detail screen + add-to-cart), AND-207 (search screen), AND-209
  (repo/UI tests). This ticket defines the `UiState`/`Effect`/`CatalogRepository`
  contracts those tickets consume.
- **Cross-epic:** add-to-cart fulfillment belongs to cart epic E29 (AND-21x); the
  detail VM only emits the `AddToCart` effect and accepts the result callback.
- **Build sequencing:** (1) lock `CatalogRepository` + UI-model + state/effect
  contracts; (2) implement the three ViewModels + mappers; (3) unit tests; the
  repository impl + PagingSources land in AND-205 against the same interface.

## 13. Risks & Open Questions

- **R1 — Repository impl boundary.** AND-205's draft sketches the repository +
  PagingSource. This ticket *defines* the `CatalogRepository` interface so the VM
  can be unit-tested with a fake; AND-205 supplies the impl. **Open: confirm the
  interface lives in `core-data` and AND-205 implements, rather than duplicating.**
- **R2 — Paging key style.** RESOLVED (2026-06-06): the backend is **cursor-based**
  — `page_size` + opaque `next_token` (response `{items, next_token?}`), no
  integer page/offset and no `total`/`has_more`. AND-205's PagingSource must use a
  `String?` next-key derived from `next_token` (null token ⇒ end of list).
  ViewModels remain key-agnostic.
- **R3 — Search endpoint shape.** RESOLVED (2026-06-06): the catalog search is
  `GET /ui/catalog/items/search?q=&page_size=` → `CatalogItemListOut` (same
  envelope as category items), per `src/api/endpoints/cart.ts: searchCatalogItems`.
  The draft's `/ui/shop/search` was wrong and would have collided with the global
  multi-type `GET /ui/search` (`src/api/endpoints/search.ts`).
- **R4 — Add-to-cart ownership.** The detail VM stops at emitting `AddToCart` +
  accepting a result; the actual cart mutation is E29. **Open: confirm the
  effect→cart handoff signature with the cart epic.**
- **R5 — Stale/offline for catalog reads.** `Ready(stale=true)` depends on the
  repository's cache (AND-205). If caching slips to a later ticket, `stale` is
  always false initially — acceptable; the flag is forward-compatible.
- **R6 — `CatalogViewModel` naming in earlier drafts.** AND-205/206 reference a
  `CatalogViewModel`; reconcile to `CatalogBrowseViewModel`/`ProductDetailViewModel`
  here to avoid two competing classes.

## 14. Acceptance Criteria

- AC-1. `CatalogBrowseViewModel`, `ProductDetailViewModel`, and
  `CatalogSearchViewModel` each expose a `StateFlow<…UiState>` and deliver all
  navigation via one-shot `SharedFlow` effects (never state). *(unit-tested)*
- AC-2. Browse init maps categories → `Ready` with the first (or restored)
  category selected; empty → `Empty`; failure → `Error(retryable)`; the `items`
  stream emits page 1 for the selected category. *(unit-tested)*
- AC-3. `selectCategory` switches the paging stream and updates `selectedId`;
  re-selecting the current id is a no-op. *(unit-tested)*
- AC-4. Detail init maps success → `Ready(item)` and failure → `Error(retryable)`;
  `retry()` re-loads. *(unit-tested)*
- AC-5. `onAddToCart` from `Ready` sets `InProgress`, emits `AddToCart`, and is a
  no-op while in flight; `onAddToCartResult` resolves to `Added`/`Idle`.
  *(unit-tested)*
- AC-6. Search debounces 300ms, trims, enforces a 2-char minimum (no request
  below it), issues exactly one search per settled query, and maps results to
  `CatalogItemUi`. *(unit-tested)*
- AC-7. Selected category id and search query survive process death
  (`SavedStateHandle`); loaded pages survive config change (`cachedIn`).
- AC-8. Every `ApiError` variant maps to the correct `UiText`; empty results are
  never conflated with errors. *(unit-tested)*
- AC-9. All §11 cases pass in CI with 100% branch coverage of the three
  ViewModels and the `toUiText`/`toUi` mappers (the **unit-tested** backlog bar).

## 15. Definition of Done

- Code merged to `android-port` under
  `feature-catalog/src/main/java/com/testlogon/android/feature/catalog/vm/`
  (+ `ui/state`, `vm/effect`) with the three ViewModels, their `UiState`/`Effect`
  contracts, the `CatalogRepository` interface, and the `toUi`/`toUiText` mappers.
- `@HiltViewModel` wiring compiles with KSP; each VM is resolvable via
  `hiltViewModel()` in its screen (AND-205/206/207) and reads its
  `SavedStateHandle` keys/nav args correctly.
- `CatalogBrowseViewModelTest`, `ProductDetailViewModelTest`,
  `CatalogSearchViewModelTest`, and mapper tests (cases 1–22) green in CI; branch
  coverage gate met. Debounce test uses virtual time and is deterministic.
- No secrets in any log, `toString`, or analytics payload; search string never
  logged verbatim at non-debug level (verified by a redaction assertion).
- Builds with Gradle 8.9 / AGP 8.7.3 / JDK 17 / compileSdk 35 / minSdk 24;
  ktlint/detekt clean; no new public API leaked into `core-*` beyond the agreed
  `CatalogRepository` contract.
- Open questions R1/R2/R4 resolved or explicitly deferred with named owners;
  naming reconciled with AND-205/206 (R6).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index/spec at `reference/openapi.index.txt` /
`reference/openapi.pretty.json`; frontend at `reference/src/…`.

1. **Categories endpoint is `GET /ui/catalog/categories`** (draft said
   `/ui/shop/categories`). VERDICT: **Corrected.** SOURCE: OpenAPI
   `GET /ui/catalog/categories` (op `list_categories_…`, resp
   `200:CatalogCategoryListOut`); `src/api/endpoints/cart.ts: getCategories`.
2. **Category-items endpoint is
   `GET /ui/catalog/categories/{category_id}/items`** (draft said
   `/ui/shop/...`). VERDICT: **Corrected.** SOURCE: OpenAPI
   `GET /ui/catalog/categories/{category_id}/items` (resp
   `200:CatalogItemListOut`); `src/api/endpoints/cart.ts: getCategoryItems`.
3. **Catalog search endpoint is `GET /ui/catalog/items/search?q=`** (draft said
   `/ui/shop/search`). VERDICT: **Corrected.** SOURCE: OpenAPI
   `GET /ui/catalog/items/search` (params `q,page_size,next_token`, resp
   `200:CatalogItemListOut`); `src/api/endpoints/cart.ts: searchCatalogItems`.
   Distinct from global `GET /ui/search` (`src/api/endpoints/search.ts:
   globalSearch`), which returns grouped multi-type sections, not the catalog
   list.
4. **No item-detail GET endpoint exists; detail is list-then-find by
   `item_id`** (draft asserted `GET /ui/shop/categories/{c}/items/{i}`).
   VERDICT: **Corrected.** SOURCE: OpenAPI shows only `PATCH`/`DELETE` on
   `/ui/catalog/categories/{category_id}/items/{item_id}` (no GET);
   `src/pages/shop/ProductDetail.tsx` calls `getCategoryItems(categoryId)` then
   `items.find(i => i.item_id === itemId)`.
5. **Paging is cursor-based: request `page_size` + optional `next_token`;
   response `{items, next_token?}` — no `page`/`total`/`has_more`** (draft showed
   `page/page_size/total/has_more`). VERDICT: **Corrected.** SOURCE: OpenAPI
   schemas `CatalogItemListOut` / `CatalogCategoryListOut` (`items`, nullable
   `next_token`); `src/api/types.ts: PaginatedList<T> = { items; next_token? }`;
   params `page_size,next_token` on both list ops.
6. **Item price is flat `price_cents` + `currency`** (draft used nested
   `price: {amount_cents, currency}`). VERDICT: **Corrected.** SOURCE: OpenAPI
   `CatalogItemOut.price_cents` (integer, required) + `currency` (string,
   required); `src/api/types.ts: CatalogItem.price_cents/currency`.
7. **Item images are `image_urls: string[]`** (draft used `thumbnail_url` and a
   `media: [{type,url}]` array). VERDICT: **Corrected.** SOURCE: OpenAPI
   `CatalogItemOut.image_urls` (required array of string);
   `src/api/types.ts: CatalogItem.image_urls`.
8. **No boolean `in_stock` and no `sku` on the item** (draft used both).
   VERDICT: **Corrected.** SOURCE: OpenAPI `CatalogItemOut` exposes
   `stock_count` (nullable int) + `stock_status` (string, default `unlimited`) +
   `low_stock_threshold`, no `in_stock`, no `sku`. Cart-add uses `item_id` as the
   sku — `src/pages/shop/ProductDetail.tsx` `addCartItem({ sku: item.item_id })`.
9. **Category has no `image_url` and no `item_count`** (draft put both on the
   category JSON). VERDICT: **Corrected.** SOURCE: OpenAPI `CatalogCategoryOut`
   = `category_id, name, created_at` (req) + optional `description, creator_id`;
   `src/api/types.ts: CatalogCategory`.
10. **Auth: persistent cookie jar + `X-CSRF-Token` header sourced from the
    `ui_csrf` cookie.** VERDICT: **Verified.** SOURCE: `src/api/client.ts`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`,
    `credentials: "include"`).
11. **401 → one `POST /ui/session/refresh` → retry, inside the transport.**
    VERDICT: **Verified.** SOURCE: OpenAPI `POST /ui/session/refresh`
    (op `ui_session_refresh_…`, resp `200`); `src/api/client.ts: refreshSession()`
    + single-retry on `res.status === 401`.
12. **FastAPI error `detail` shape is `string | [{msg}] | {code,…}`; 422 =
    `HTTPValidationError`.** VERDICT: **Verified.** SOURCE:
    `src/api/client.ts: normalizeErrorDetail` (string / array-of-`{msg}` /
    object-with-`code` branches); OpenAPI list ops declare
    `422:HTTPValidationError` (also `400/401/403/429`).
13. **All catalog reads are idempotent GETs (eligible for bounded-backoff
    retry).** VERDICT: **Verified.** SOURCE: OpenAPI method column = `GET` for
    categories, items, and items/search.
14. **Endpoints also accept `X-API-Key` and `X-SESSION-ID` / `user_sub`
    params.** VERDICT: **Verified (informational).** SOURCE: OpenAPI `params=…
    X-SESSION-ID,X-IMPERSONATION-TOKEN,X-API-Key` on the three list ops. The
    Android client relies on the cookie session (as the web client does); API-key
    auth is not used by this ticket.
15. **Web price formatting is `Intl.NumberFormat("en-US", …)` (hardcoded
    locale); Android intentionally uses device-locale `NumberFormat`.**
    VERDICT: **Verified (intentional divergence).** SOURCE:
    `src/pages/shop/Catalog.tsx` + `src/pages/shop/ProductDetail.tsx`
    `formatPrice`.
16. **`@HiltViewModel` + `SavedStateHandle` + `viewModelScope` + Paging 3
    `cachedIn`/`flatMapLatest` are the correct AndroidX APIs for the described
    state holders.** VERDICT: **Verified (framework ref).** SOURCE:
    https://developer.android.com/topic/libraries/architecture/viewmodel and
    https://developer.android.com/topic/libraries/architecture/paging/v3-paging-data
    (cachedIn / Flow<PagingData>).

### Corrections made

- §2: rewrote the web-reference pointer — catalog helpers live in
  `src/api/endpoints/cart.ts` (no `catalog.ts`/`shop.ts`); route family is
  `/ui/catalog/*` not `/ui/shop/*`.
- §4 repository contract: annotated `getItem()` as list-then-find (no
  item-detail endpoint).
- §5 API Contract: corrected all four endpoints (`/ui/shop/*`→`/ui/catalog/*`,
  search path), replaced integer paging with cursor (`page_size`/`next_token`,
  response `{items,next_token?}`), corrected item fields
  (`price_cents`+`currency`, `image_urls`, `stock_count`/`stock_status`, no
  `in_stock`/`sku`/`media`/`thumbnail_url`), corrected category fields (no
  `image_url`/`item_count`), and noted the global-search vs catalog-search
  distinction. Confirmed auth/CSRF/refresh/error-shape as Verified.
- §6 UI models: `CatalogItemDetailUi` now carries `imageUrls`/`inStock`(derived)/
  `stockCount` instead of `mediaUrls`/`inStock`(wire)/`sku`; `CategoryUi`
  `imageUrl`/`itemCount` marked reserved/not-in-API; added the `toUi` mapping
  rules and the intentional locale-formatting divergence note.
- §13: R2 (paging key) and R3 (search endpoint) marked RESOLVED with sources.

### Open assumptions

- **`stock_status` value set.** Only `unlimited` (the schema default) is visible
  in OpenAPI; the `inStock` derivation assumes other values like
  `in_stock`/`out_of_stock`/`low_stock` exist. UNVERIFIED — confirm the enum with
  AND-204; the mapper isolates this in one place.
- **`ApiResult`/`ApiError` variant names** (`Network`, `Timeout`, `Server`,
  `NotFound`, `Validation`, `Unauthorized`). UNVERIFIED here — defined by
  AND-015/AND-018 (out of this repo's reference); names used as-drafted.
- **`getItem()` → `ApiError.NotFound` when the id is absent in the list.** This
  is a chosen mapping (no 404 from a real endpoint, since detail is list-then-
  find). UNVERIFIED contract; owned by AND-204/205's repository impl.
- **Dev host flakiness / ~20s timeout / bounded-backoff retry for GETs.** Stated
  in the draft; not observable from OpenAPI or the web client. UNVERIFIED —
  treated as a core-network behavioral assumption.
- **Category `image_url`/`item_count` synthesis.** Not in the wire payload;
  whether AND-204 can compute `item_count` is UNVERIFIED. UI fields stay nullable.

## 17. Test Plan

All cases target the three ViewModels and the pure mappers and so are **JVM
unit / Robolectric-free** unless noted. They use `kotlinx-coroutines-test`
(`StandardTestDispatcher` + `Dispatchers.setMain`), `Turbine`, a fake
`CatalogRepository`, and `AsyncPagingDataDiffer`/`PagingData` snapshots (per
§11). A small contract suite uses MockWebServer to pin the corrected wire shapes;
those run on the **headless emulator AVD `test35`** in CI. No case in this
ticket needs the physical device (no camera/biometrics/FCM/WebRTC/Telecom);
that is called out explicitly per case.

- **TC-AND-208-01** — Browse init happy path. Type: unit (JVM).
  Target: `CatalogBrowseViewModel`. Preconditions: fake repo
  `getCategories = Success([Books, Music])`, `itemsPages` non-empty.
  Steps: construct VM (empty `SavedStateHandle`); collect `uiState` + `items`
  via Turbine; advance dispatcher. Expected: `uiState` ends `Ready(categories=[2],
  selectedId="cat_books")`; `items` emits page 1; `itemsPagerCategories.last ==
  "cat_books"`. Traces: AC-1, AC-2.
- **TC-AND-208-02** — Empty categories. Type: unit (JVM).
  Target: `CatalogBrowseViewModel`. Preconditions: `getCategories =
  Success(emptyList())`. Steps: construct VM; advance. Expected: `uiState ==
  Empty`; `items` never collects a real page (no `itemsPager` call). Traces:
  AC-2, AC-8.
- **TC-AND-208-03** — Categories load failure → retryable error, then
  successful retry. Type: unit (JVM). Target: `CatalogBrowseViewModel`.
  Preconditions: `getCategories = Failure(ApiError.Timeout)` first, then swap to
  `Success([...])`. Steps: construct VM; assert `Error`; call `retryCategories()`;
  advance. Expected: first `Error(message=catalog_error_network, retryable=true)`;
  after retry `Ready`; exactly two `getCategories` calls. Traces: AC-2, AC-8.
- **TC-AND-208-04** — `selectCategory(new)` switches the pager. Type: unit (JVM).
  Target: `CatalogBrowseViewModel`. Preconditions: VM in `Ready` with
  `cat_books`. Steps: collect `items`; call `selectCategory("cat_music")`;
  advance. Expected: `Ready.selectedId == "cat_music"`; `SavedStateHandle[KEY_
  SELECTED] == "cat_music"`; `itemsPagerCategories.last == "cat_music"`; `items`
  re-emits page 1 for the new id. Traces: AC-3.
- **TC-AND-208-05** — `selectCategory(current)` is a no-op. Type: unit (JVM).
  Target: `CatalogBrowseViewModel`. Preconditions: `Ready(selectedId="cat_books")`.
  Steps: record `itemsPagerCategories.size`; call `selectCategory("cat_books")`;
  advance. Expected: state unchanged; no additional `itemsPager` invocation.
  Traces: AC-3.
- **TC-AND-208-06** — Restored `KEY_SELECTED` survives process death; falls back
  to first if stale. Type: unit (JVM). Target: `CatalogBrowseViewModel` +
  `SavedStateHandle`. Preconditions: pre-seed `SavedStateHandle(KEY_SELECTED =
  "cat_music")`. Steps: construct VM; advance. Expected: `Ready.selectedId ==
  "cat_music"`. Variant: seed `"cat_gone"` not in the list → falls back to first
  (`cat_books`). Traces: AC-2, AC-7.
- **TC-AND-208-07** — `onItemClick` emits one-shot NavigateToDetail (browse).
  Type: unit (JVM). Target: `CatalogBrowseViewModel.effects`. Preconditions:
  `Ready`. Steps: subscribe to `effects` (Turbine); call
  `onItemClick(itemUi(categoryId="cat_books", id="itm_1"))`. Expected: exactly
  one `CatalogBrowseEffect.NavigateToDetail("cat_books","itm_1")`; nothing leaks
  into `uiState`. Traces: AC-1.
- **TC-AND-208-08** — Detail init happy path (list-then-find). Type: unit (JVM).
  Target: `ProductDetailViewModel`. Preconditions: `SavedStateHandle{categoryId=
  cat_books,itemId=itm_1}`; `getItem = Success(detail(itm_1))`. Steps: construct
  VM; advance. Expected: `uiState == Ready(item.id="itm_1",
  addToCartStatus=Idle)`; `priceLabel` formatted from `price_cents`/`currency`.
  Traces: AC-4.
- **TC-AND-208-09** — Detail not-found / failure → retryable error + retry.
  Type: unit (JVM). Target: `ProductDetailViewModel`. Preconditions: `getItem =
  Failure(ApiError.NotFound)` (id absent from list-then-find), then `Success`.
  Steps: construct VM → assert `Error`; call `retry()`; advance. Expected:
  `Error(message=catalog_error_not_found, retryable=true)` then `Ready`; two
  `getItem` calls. Traces: AC-4, AC-8.
- **TC-AND-208-10** — Add-to-cart in-flight guard + effect. Type: unit (JVM).
  Target: `ProductDetailViewModel`. Preconditions: `Ready(Idle)`. Steps:
  subscribe `effects`; call `onAddToCart()` twice without resolving. Expected:
  state → `Ready(InProgress)`; exactly **one** `ProductDetailEffect.AddToCart`
  emitted (second call no-op); `onAddToCart` ignored when state is not `Ready`
  (Loading/Error). Traces: AC-5, AC-1.
- **TC-AND-208-11** — Add-to-cart result resolution. Type: unit (JVM).
  Target: `ProductDetailViewModel`. Preconditions: `Ready(InProgress)`. Steps:
  call `onAddToCartResult(true)` → assert; reset; `onAddToCartResult(false)`.
  Expected: `true → Ready(Added)`; `false → Ready(Idle)`. Traces: AC-5.
- **TC-AND-208-12** — Search debounce + trim + min-length, exactly one search
  per settled query. Type: unit (JVM, virtual time). Target:
  `CatalogSearchViewModel`. Preconditions: fresh VM. Steps: `onQueryChange("a")`
  (len<2) then rapid `onQueryChange("ph")`,`"pho")`,`"  phone  "` within 300ms;
  advance virtual time past `DEBOUNCE_MS`. Expected: `uiState.query` updates
  immediately on each edit; `searchPager` called **once** with the trimmed final
  value `"phone"`; the len-1 "a" never triggers a request. Traces: AC-6.
- **TC-AND-208-13** — Search results mapping + NoResults vs HasResults; `onClear`.
  Type: unit (JVM). Target: `CatalogSearchViewModel` + mappers. Preconditions:
  `searchPages` with two items. Steps: query `"book"`, snapshot `results`; assert
  mapped `CatalogItemUi` (thumbnail = first `image_urls`, formatted price); set
  `searchPages = empty`, query `"zzzz"` → NoResults; call `onClear()`. Expected:
  non-empty maps to `CatalogItemUi`; empty page ⇒ no items (NoResults derivable);
  `onClear` resets query to "" and results to empty; empty never surfaced as
  `Error`. Traces: AC-6, AC-8.
- **TC-AND-208-14** — Mapper unit tests (currency/locale, nullables, derived
  inStock). Type: unit (JVM). Target: `CatalogItem.toUi`/`CatalogItemDetail.toUi`
  + `ApiError.toUiText`. Preconditions: items with `currency` USD/EUR/JPY,
  null `description`, empty `image_urls`, `stock_status` ∈
  {`unlimited`,`out_of_stock`}, `stock_count` null/0/5. Steps: map under two
  device locales (en-US, de-DE). Expected: `priceLabel` is locale-aware and
  currency-correct; `thumbnailUrl == image_urls.firstOrNull()`; `inStock` false
  only for `out_of_stock` (and zero `stock_count` when status implies it); every
  `ApiError` variant → the documented `UiText` (Network/Timeout→network,
  Server→server, NotFound→not_found, Unauthorized→auth, Validation→Dynamic,
  else→generic). Traces: AC-8, AC-6.
- **TC-AND-208-15** — Contract test: corrected wire shapes deserialize and the
  cursor pager advances. Type: contract/MockWebServer (runs on emulator
  `test35`). Target: AND-204/205 `CatalogApi`/PagingSource against the fake
  server (consumed by these VMs). Preconditions: MockWebServer returns
  `CatalogItemListOut` JSON with flat `price_cents`/`currency`/`image_urls` and a
  non-null `next_token`, then a second page with `next_token: null`.
  Steps: request `GET /ui/catalog/categories/{id}/items?page_size=50`, then the
  follow-up with `next_token`. Expected: items deserialize (no `price`/`media`/
  `thumbnail_url` fields expected); pager treats null `next_token` as end-of-list;
  request path/query match the corrected contract. Traces: AC-2, AC-6.
- **TC-AND-208-16** — Flaky-host / offline + 401-refresh transparency.
  Type: contract/MockWebServer (emulator `test35`). Target: core-network
  transport behind `CatalogRepository`. Preconditions: server scripted to (a)
  delay > call-timeout once, (b) return `401` once then `200` after a
  `POST /ui/session/refresh`. Steps: trigger `getCategories()` through the
  repository. Expected: timeout surfaces as `ApiError.Timeout` →
  `catalog_error_network` (VM shows `Error(retryable=true)`); the 401 path issues
  exactly one refresh then retries and succeeds (VM reaches `Ready`); offline
  read with no cache ⇒ `Error`, never `Empty`. Traces: AC-2, AC-8.
- **TC-AND-208-17** — Security/redaction + no-secret-logging. Type: unit (JVM).
  Target: VMs + analytics/log facade. Preconditions: capture log + analytics
  sinks. Steps: drive a search for `"secret query"`, a category select, and an
  errored load. Expected: no cookie or `ui_csrf`/`X-CSRF-Token` value ever
  appears in logs/`toString`/analytics; the raw search string is **not** logged
  at non-debug level (only `query_len`/`min_len_met` in `catalog_search`); no
  authed URL with query string is logged. Traces: AC-1 (state-only nav), §8/§10.
- **TC-AND-208-18** — Accessibility state consistency (Compose-UI smoke).
  Type: Compose-UI (emulator `test35`). Target: a thin harness composing the
  three `UiState`s (screens are AND-205/206/207; this is a state-contract
  a11y check). Preconditions: feed `Ready`, `Empty`/`NoResults`, `Error`,
  `addToCartStatus ∈ {Idle,InProgress,Added}`. Steps: render each; query the
  semantics tree. Expected: error/empty/busy/added are distinct, announceable
  states (no ambiguous blank list); `Error` is rendered as content (liveRegion-
  eligible), not a transient toast; price text is non-empty and readable.
  Traces: AC-1, AC-8, §9. (Emulator is sufficient; no physical-device a11y
  hardware needed.)

### Coverage matrix

| AC (section 14) | Covered by |
|---|---|
| AC-1 (StateFlow + one-shot effects, nav never state) | TC-01, TC-07, TC-10, TC-17, TC-18 |
| AC-2 (browse init Ready/Empty/Error, items page 1) | TC-01, TC-02, TC-03, TC-06, TC-15, TC-16 |
| AC-3 (selectCategory switch + no-op) | TC-04, TC-05 |
| AC-4 (detail Ready/Error + retry) | TC-08, TC-09 |
| AC-5 (add-to-cart InProgress/effect/no-op + result) | TC-10, TC-11 |
| AC-6 (search debounce/trim/min-len/one-search/map) | TC-12, TC-13, TC-14, TC-15 |
| AC-7 (SavedStateHandle survives process death; cachedIn) | TC-06 (state retention); cachedIn relayed via TC-01/TC-04 collection |
| AC-8 (every ApiError→UiText; empty≠error) | TC-02, TC-03, TC-09, TC-13, TC-14, TC-16, TC-18 |
| AC-9 (all §11 cases pass, 100% branch coverage of VMs + mappers) | TC-01–TC-14 (the JVM unit set; coverage gate in CI) |
