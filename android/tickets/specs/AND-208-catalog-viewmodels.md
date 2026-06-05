---
id: AND-208
title: Catalog ViewModels
milestone: M5
epic: E28
priority: P1
size: M
status: draft
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
- Web reference: `frontend/src/api/endpoints/*.ts` (catalog/shop + search),
  shared types `frontend/src/api/types.ts`. OpenAPI at `/openapi.json`.

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
    /** Idempotent GET; bounded-backoff retried by core-network. */
    suspend fun getCategories(): ApiResult<List<Category>>
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
For reference, the consumed contract (confirm field names against `/openapi.json`
and `frontend/src/api/endpoints/*.ts`):

**Categories** — `GET /ui/shop/categories`
```json
{ "categories": [ { "id": "cat_books", "name": "Books", "image_url": "https://…/c.jpg", "item_count": 128 } ] }
```

**Items in category (paged)** — `GET /ui/shop/categories/{categoryId}/items?page=1&page_size=20`
```json
{ "items": [ { "id": "itm_001", "category_id": "cat_books", "name": "Example Item",
  "price": { "amount_cents": 1999, "currency": "USD" }, "thumbnail_url": "https://…/t.jpg" } ],
  "page": 1, "page_size": 20, "total": 128, "has_more": true }
```

**Item detail** — `GET /ui/shop/categories/{categoryId}/items/{itemId}`
```json
{ "id": "itm_001", "category_id": "cat_books", "name": "Example Item",
  "description": "…", "price": { "amount_cents": 1999, "currency": "USD" },
  "media": [ { "type": "image", "url": "https://…/1.jpg" } ], "in_stock": true, "sku": "BK-001" }
```

**Search (paged)** — `GET /ui/shop/search?q={query}&page=1&page_size=20`
matches name/description/SKU; same paged envelope as category items.

All are authenticated GETs: cookies + `X-CSRF-Token` attached by core-network;
`401`→one `POST /ui/session/refresh`→retry inside core-network. FastAPI errors
arrive pre-mapped as `ApiError` (`string | [{msg}] | {code,...}`). The
ViewModels are transport-agnostic and depend only on `core-model` domain types
and `ApiResult`.

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
data class CategoryUi(val id: String, val name: String, val imageUrl: String?, val itemCount: Int?)
data class CatalogItemUi(val id: String, val categoryId: String, val name: String,
                         val priceLabel: String, val thumbnailUrl: String?)
data class CatalogItemDetailUi(val id: String, val categoryId: String, val name: String,
                               val description: String, val priceLabel: String,
                               val mediaUrls: List<String>, val inStock: Boolean, val sku: String?)
```

State rules:
- Selected category id (`KEY_SELECTED`) and search query (`KEY_QUERY`) live in
  `SavedStateHandle` → survive process death. Detail nav args
  (`categoryId`/`itemId`) come from the back-stack entry's `SavedStateHandle`.
- `cachedIn(viewModelScope)` retains loaded paging pages across config changes;
  re-collection does not re-fetch.
- Domain→UI mapping (`CatalogItem.toUi()`, `CatalogItemDetail.toUi()`) formats
  `priceLabel` via `NumberFormat.getCurrencyInstance(...)` keyed on the DTO
  currency, so the JVM-pure mappers are unit-testable.
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
- **R2 — Paging key style.** Integer page vs. cursor is unconfirmed from AND-204/
  OpenAPI. ViewModels are key-agnostic (they consume `Flow<PagingData>`); only the
  PagingSource (AND-205) is affected. **Open: confirm.**
- **R3 — Search endpoint shape.** `GET /ui/shop/search?q=` assumed; verify path
  and paging envelope against OpenAPI / `frontend/src/api/endpoints`.
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
