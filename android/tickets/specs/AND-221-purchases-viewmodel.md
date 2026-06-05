---
id: AND-221
title: Purchases ViewModel
milestone: M5
epic: E30
priority: P1
size: M
status: draft
depends_on: [AND-218]
blocks: [AND-219, AND-220, AND-222]
---

# AND-221 — Purchases ViewModel

## 1. Overview & Goal

This ticket delivers the presentation-layer state holder for the TestLogon
**purchases / order-history** surface: a Hilt-injected `PurchasesViewModel` plus
the `core-data` repository it consumes, wiring the `PurchasesApi` (AND-218) into a
Paging 3 stream for history/search and an `ApiResult`-wrapped one-shot call for
order detail. It produces **no Compose UI** — the history list/search screen is
AND-219 and the order-detail screen is AND-220. This ticket owns the
`StateFlow<PurchasesUiState>` contract, the `Flow<PagingData<PurchaseListItem>>`
those screens collect, the search-query debounce/state machine, pull-to-refresh
and retry intents, and the domain mapping (DTO → UI model) that turns AND-218's
raw wire types into render-ready, locale-formattable list/detail models.

Scope, verbatim from the backlog: *State + paging.* The single acceptance
criterion is: *Unit-tested.* This ticket therefore owns (a) a `PurchasesRepository`
in `core-data` exposing a `PagingSource`-backed history/search stream and an
`ApiResult<PurchaseDetail>` detail call; (b) immutable domain models
(`PurchaseListItem`, `PurchaseDetail`, `Money`, `OrderStatus`) in `core-model`
mapped from AND-218 DTOs; (c) a `PurchasesViewModel` exposing `StateFlow<UiState>`
+ a `PagingData` flow + intent functions (`onSearchQueryChanged`, `refresh`,
`retry`, `loadDetail`); and (d) a JVM unit-test suite (`runTest` + Turbine +
fakes) proving every state transition, the debounce, paging mapping, and
error/retry paths.

The deliverable: a compiling `core-data` repository + `core-model` domain models +
a `feature-purchases` ViewModel, all behind interfaces, with a green unit-test
suite. The screens that bind to it (AND-219/AND-220) and the broader repo + UI
test pass (AND-222) build directly on this contract.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. The repository + Paging source land in module
  **`core-data`** under `com.testlogon.android.core.data.purchases`. Domain models
  land in **`core-model`** under `com.testlogon.android.core.model.purchases`
  (alongside AND-218's DTOs, but as distinct domain types). The ViewModel +
  `UiState` land in **`feature-purchases`** under
  `com.testlogon.android.feature.purchases`.
- **Canonical package:** `com.testlogon.android` everywhere a package appears.
- **Stack pins relevant here:** Kotlin 2.0.21, Coroutines/Flow, **Paging 3**
  (`androidx.paging:paging-runtime` + `paging-compose`, with `paging-common` for
  JVM tests), Hilt (KSP), `androidx.lifecycle:lifecycle-viewmodel` +
  `viewModelScope`, JDK 17, minSdk 24 / compileSdk 35, AGP 8.7.3 / Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. `PurchasesViewModel`
  (`feature-purchases`) depends on `PurchasesRepository` (`core-data`), which
  depends on `PurchasesApi` (`core-network`, AND-218) and domain models
  (`core-model`). No `feature-*`/`app` symbols leak into `core-*`.
- **Upstream dependency — AND-218 (Purchases API):** pinned by the backlog. Supplies
  `PurchasesApi` (`listPurchases`, `getPurchase`, `searchPurchases`) and the wire
  DTOs (`PurchaseSummaryDto`, `PurchaseDetailDto`, `PurchasePageDto`,
  `PurchaseSearchResultDto`, `MoneyDto`, `PurchaseItemDto`, `TrackingDto`). This
  ticket maps those DTOs to domain models; it does not redefine wire types.
- **Transitive upstream:** AND-018 (`sealed ApiResult<T>` =
  `Success`/`Failure(ApiError)`/`NetworkError` in `core-model`), AND-015 (FastAPI
  `detail` → `ApiError` mapping), AND-016 (bounded backoff for idempotent GETs on
  the shared client), AND-027/AND-013 (cookie session + 401-refresh-once),
  AND-003/AND-004 (module + Hilt baseline). The ViewModel never touches cookies,
  CSRF, or retry — those are owned by the shared client and `ApiResult` layer.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` is
  plaintext and unreliable (~20s timeouts). All purchase reads are idempotent GETs;
  the UI must surface offline/stale/loading states (handled here via `UiState` +
  Paging `LoadState`).
- **Web reference (authoritative for behavior parity):**
  `frontend/src/api/endpoints/purchases.ts` and the web history/search screen
  (search debounce, empty-state copy, pagination behavior). Match its search
  semantics (query length threshold, debounce) where defined.

## 3. Functional Requirements

FR-1. **History stream.** Expose `pagingFlow: Flow<PagingData<PurchaseListItem>>`
that, with an empty/blank search query, pages the full purchase history via
`PurchasesApi.listPurchases(page, limit)`; with a non-blank query it pages search
results via `PurchasesApi.searchPurchases(q, page, limit)`. The stream is
`cachedIn(viewModelScope)` so it survives configuration changes and Compose
recomposition.

FR-2. **Search state machine.** `onSearchQueryChanged(query: String)` updates
`UiState.query` immediately (for the text field) and **debounces** (300 ms, default
`SEARCH_DEBOUNCE_MS`) before switching the paging stream to the search endpoint.
Blanking the query (or trimming to `< MIN_QUERY_LEN = 1` non-whitespace chars)
reverts to the history endpoint. The debounced query drives a new `PagingData`
generation (the prior generation is cancelled).

FR-3. **Screen-level UiState.** Expose `state: StateFlow<PurchasesUiState>` carrying
the current `query`, an `isSearching` flag, and a derived high-level status used by
AND-219 for empty/error/loading scaffolding when the `PagingData`'s `LoadState`
isn't sufficient on its own (e.g. initial empty history vs empty search result must
be distinguishable for copy).

FR-4. **Detail load.** `loadDetail(purchaseId: String)` fetches
`PurchasesApi.getPurchase(id)` through the repository, returning
`ApiResult<PurchaseDetail>`, and publishes it into `detailState:
StateFlow<DetailUiState>` (`Loading`/`Content(PurchaseDetail)`/`Error(message,
retryable)`). Re-invoking with the same id while `Loading` is a no-op
(de-duplication); a new id cancels the in-flight detail load.

FR-5. **Refresh / retry intents.** `refresh()` triggers a Paging `refresh()` of the
active stream (history or search) for pull-to-refresh. `retry()` retries the failed
load (Paging `retry()` for the list; re-invokes `loadDetail` for the detail
screen). Both are idempotent and safe to call repeatedly.

FR-6. **Domain mapping.** Map AND-218 DTOs to render-ready domain models:
`PurchaseSummaryDto → PurchaseListItem`, `PurchaseDetailDto → PurchaseDetail`,
`MoneyDto → Money` (preserving `amountMinor`/`currency`), and the raw `status`
string → `OrderStatus` enum with an `OrderStatus.Unknown(raw)` fallback (never
throws). Mapping is in a pure, separately-tested mapper (no Android types).

FR-7. **Pagination contract.** The `PagingSource` translates AND-218's
page/limit + `has_more`/`next_cursor` envelope into Paging 3 `LoadResult.Page`
(`prevKey`/`nextKey`). `PagingConfig(pageSize = 20, prefetchDistance = 5,
enablePlaceholders = false, initialLoadSize = 20)`. `nextKey` is `null` when
`has_more == false`.

FR-8. **No persistence in this ticket.** History is fetched live via a
`PagingSource` (network-only). A Room-backed `RemoteMediator` for offline history
is explicitly out of scope (future ticket); the ViewModel surfaces offline via
`LoadState.Error` only.

FR-9. **Lifecycle correctness.** All flows run in `viewModelScope`; the search
debounce uses `@OptIn(FlowPreview)` `debounce` + `distinctUntilChanged` +
`flatMapLatest`. No work leaks past `onCleared()`. `StateFlow`s use
`SharingStarted.WhileSubscribed(5_000)` where derived via `stateIn`.

FR-10. **Testability.** The repository is an interface (`PurchasesRepository`) with
a real impl and a `core-testing` fake; the mapper is pure; the ViewModel takes the
repository + a `CoroutineDispatcher` (or `SavedStateHandle` for `query` survival)
via constructor injection so every requirement above is unit-testable on the JVM
with `runTest`.

## 4. Technical Design

### 4.1 Domain models (`core-model.purchases`)

Distinct from AND-218 wire DTOs; immutable, UI-render-ready, `@Immutable` for
stable Compose params (consumed by AND-219/AND-220).

```kotlin
package com.testlogon.android.core.model.purchases

import androidx.compose.runtime.Immutable

@Immutable
data class Money(val amountMinor: Long, val currency: String, val display: String?)

@Immutable
sealed interface OrderStatus {
    data object Paid : OrderStatus
    data object Shipped : OrderStatus
    data object Delivered : OrderStatus
    data object Refunded : OrderStatus
    data object Cancelled : OrderStatus
    data class Unknown(val raw: String) : OrderStatus
}

@Immutable
data class PurchaseListItem(
    val id: String,
    val orderNumber: String?,
    val status: OrderStatus,
    val total: Money,
    val itemCount: Int,
    val purchasedAtIso: String,      // raw ISO-8601; formatted in UI (AND-219)
    val thumbnailUrl: String?,
)

@Immutable
data class PurchaseDetail(
    val id: String,
    val orderNumber: String?,
    val status: OrderStatus,
    val items: List<PurchaseLine>,
    val subtotal: Money?,
    val tax: Money?,
    val shipping: Money?,
    val total: Money,
    val paymentMethod: String?,
    val shippingAddress: String?,
    val tracking: Tracking?,
    val purchasedAtIso: String,
)

@Immutable
data class PurchaseLine(
    val id: String, val name: String, val sku: String?,
    val quantity: Int, val unitPrice: Money, val lineTotal: Money?, val imageUrl: String?,
)

@Immutable
data class Tracking(
    val carrier: String?, val trackingNumber: String?,
    val trackingUrl: String?, val status: String?, val estimatedDeliveryIso: String?,
)
```

### 4.2 Mapper (`core-data.purchases`)

Pure functions; no Android imports; separately unit-tested.

```kotlin
internal fun MoneyDto.toDomain() = Money(amountMinor, currency, display)

internal fun String.toOrderStatus(): OrderStatus = when (lowercase()) {
    "paid" -> OrderStatus.Paid
    "shipped" -> OrderStatus.Shipped
    "delivered" -> OrderStatus.Delivered
    "refunded" -> OrderStatus.Refunded
    "cancelled", "canceled" -> OrderStatus.Cancelled
    else -> OrderStatus.Unknown(this)        // never throws
}

internal fun PurchaseSummaryDto.toListItem() = PurchaseListItem(
    id = id, orderNumber = orderNumber, status = status.toOrderStatus(),
    total = total.toDomain(), itemCount = itemCount ?: 0,
    purchasedAtIso = purchasedAt, thumbnailUrl = thumbnailUrl,
)

internal fun PurchaseDetailDto.toDomain() = PurchaseDetail(/* field-by-field map */)
```

### 4.3 Repository (`core-data.purchases`)

```kotlin
package com.testlogon.android.core.data.purchases

import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.purchases.PurchaseDetail
import com.testlogon.android.core.model.purchases.PurchaseListItem
import kotlinx.coroutines.flow.Flow

interface PurchasesRepository {
    /** History (query null/blank) or search (query non-blank), paged. */
    fun purchasesPaging(query: String?): Flow<PagingData<PurchaseListItem>>

    /** One-shot order detail, wrapped per AND-018. */
    suspend fun getPurchaseDetail(id: String): ApiResult<PurchaseDetail>
}
```

Impl constructs a `Pager` per query:

```kotlin
@Singleton
class DefaultPurchasesRepository @Inject constructor(
    private val api: PurchasesApi,
) : PurchasesRepository {

    override fun purchasesPaging(query: String?): Flow<PagingData<PurchaseListItem>> =
        Pager(
            config = PagingConfig(pageSize = PAGE_SIZE, prefetchDistance = 5,
                enablePlaceholders = false, initialLoadSize = PAGE_SIZE),
            pagingSourceFactory = { PurchasesPagingSource(api, query?.trim()?.ifBlank { null }) },
        ).flow

    override suspend fun getPurchaseDetail(id: String): ApiResult<PurchaseDetail> =
        runCatchingApi { api.getPurchase(id).toDomain() }   // AND-018/AND-015 helper

    companion object { const val PAGE_SIZE = 20 }
}
```

`runCatchingApi { }` is AND-018's helper mapping success → `ApiResult.Success`,
`HttpException` → `ApiResult.Failure(ApiError)` (via AND-015), and
`IOException`/`SocketTimeoutException` → `ApiResult.NetworkError`.

### 4.4 PagingSource

```kotlin
internal class PurchasesPagingSource(
    private val api: PurchasesApi,
    private val query: String?,            // null => history endpoint
) : PagingSource<Int, PurchaseListItem>() {

    override suspend fun load(params: LoadParams<Int>): LoadResult<Int, PurchaseListItem> {
        val page = params.key ?: 1
        return try {
            val (items, hasMore) = if (query == null) {
                val r = api.listPurchases(page = page, limit = params.loadSize)
                r.items.map { it.toListItem() } to r.hasMore
            } else {
                val r = api.searchPurchases(q = query, page = page, limit = params.loadSize)
                r.items.map { it.toListItem() } to r.hasMore
            }
            LoadResult.Page(
                data = items,
                prevKey = if (page == 1) null else page - 1,
                nextKey = if (hasMore) page + 1 else null,
            )
        } catch (e: IOException) { LoadResult.Error(e) }
          catch (e: HttpException) { LoadResult.Error(e) }
    }

    override fun getRefreshKey(state: PagingState<Int, PurchaseListItem>): Int? =
        state.anchorPosition?.let { state.closestPageToPosition(it)?.prevKey?.plus(1)
            ?: state.closestPageToPosition(it)?.nextKey?.minus(1) }
}
```

### 4.5 ViewModel (`feature-purchases`)

```kotlin
package com.testlogon.android.feature.purchases

@HiltViewModel
class PurchasesViewModel @Inject constructor(
    private val repository: PurchasesRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val queryFlow = savedState.getStateFlow(KEY_QUERY, "")

    val state: StateFlow<PurchasesUiState> =
        queryFlow.map { q -> PurchasesUiState(query = q, isSearching = q.isNotBlank()) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000),
                PurchasesUiState())

    @OptIn(FlowPreview::class, ExperimentalCoroutinesApi::class)
    val pagingFlow: Flow<PagingData<PurchaseListItem>> =
        queryFlow
            .debounce { if (it.isBlank()) 0 else SEARCH_DEBOUNCE_MS }
            .distinctUntilChanged()
            .flatMapLatest { q -> repository.purchasesPaging(q.ifBlank { null }) }
            .cachedIn(viewModelScope)

    private val _detailState = MutableStateFlow<DetailUiState>(DetailUiState.Idle)
    val detailState: StateFlow<DetailUiState> = _detailState.asStateFlow()
    private var detailJob: Job? = null

    fun onSearchQueryChanged(query: String) { savedState[KEY_QUERY] = query }

    fun loadDetail(id: String) {
        if (_detailState.value is DetailUiState.Loading) return
        detailJob?.cancel()
        detailJob = viewModelScope.launch {
            _detailState.value = DetailUiState.Loading
            _detailState.value = when (val r = repository.getPurchaseDetail(id)) {
                is ApiResult.Success -> DetailUiState.Content(r.data)
                is ApiResult.Failure -> DetailUiState.Error(r.error.message, retryable = true)
                is ApiResult.NetworkError -> DetailUiState.Error(OFFLINE, retryable = true)
            }
        }
    }

    fun retryDetail(id: String) { _detailState.value = DetailUiState.Idle; loadDetail(id) }

    companion object {
        const val KEY_QUERY = "purchases_query"
        const val SEARCH_DEBOUNCE_MS = 300L
        const val OFFLINE = "You appear to be offline."
    }
}
```

The list `refresh()`/`retry()` are driven from the Compose layer (AND-219) on the
collected `LazyPagingItems` (`items.refresh()` / `items.retry()`); the ViewModel
exposes the stream and search/state intents. Pull-to-refresh in AND-219 calls
`LazyPagingItems.refresh()`.

### 4.6 Gradle wiring

`feature-purchases` adds `paging-runtime`, `paging-compose`, `lifecycle-viewmodel`,
`hilt`. `core-data` adds `paging-common` (+ `paging-common` for tests). `core-data`
declares `implementation(project(":core-network"))` + `:core-model`. No new
network deps (transport is AND-218/AND-009).

## 5. API Contract

This ticket defines **no new HTTP endpoints**; it consumes AND-218's contract.
Endpoints used (relative to `http://18.222.237.167:8000/`):

- `GET purchases?page={n}&limit=20` → `PurchasePageDto` (history stream).
- `GET purchases/search?q={query}&page={n}&limit=20` → `PurchaseSearchResultDto`
  (search stream).
- `GET purchases/{purchaseId}` → `PurchaseDetailDto` (detail load).

Paging keys map from the envelope: `has_more == true` ⇒ `nextKey = page + 1`,
else `null`. The ViewModel/repository assert no new request/response shapes; if
AND-218 resolves to cursor-based paging (its Q-2/R-2), `PurchasesPagingSource`
switches `Int` keys to `String` cursor keys and reads `next_cursor` — a localized
change behind the repository interface. Error bodies (FastAPI `detail` union) are
already mapped to `ApiError` by AND-015 inside `runCatchingApi`; the detail call
surfaces `ApiResult`, the list surfaces Paging `LoadState.Error(throwable)`.

## 6. Data & State Management

- **`PurchasesUiState`** (`feature-purchases`): `data class PurchasesUiState(val
  query: String = "", val isSearching: Boolean = false)`. The list contents
  themselves live in `PagingData`, not in `UiState` (Paging owns list state); this
  state holds only the search/scaffold concerns.
- **`DetailUiState`**: `sealed interface { Idle; Loading; data class
  Content(val detail: PurchaseDetail); data class Error(val message: String, val
  retryable: Boolean) }`.
- **Paging state** (current page, accumulation, refresh/append/prepend
  `LoadState`s) is owned by Paging 3 and surfaced to AND-219 via `LazyPagingItems`.
  `cachedIn(viewModelScope)` keeps the stream alive across config changes.
- **Search query survival:** stored in `SavedStateHandle` (`KEY_QUERY`) so it
  survives process death and config change; both `state` and `pagingFlow` derive
  from `savedState.getStateFlow`. A single source of truth — `onSearchQueryChanged`
  only writes `savedState`.
- **No Room / DataStore** in this ticket (FR-8). DTOs never enter composition;
  only `@Immutable` domain models do.
- **Threading:** all flows in `viewModelScope`; suspend repository calls run on the
  IO dispatcher established by the network layer. `flatMapLatest` cancels the prior
  paging generation when the debounced query changes.
- **Detail de-dup / cancellation:** `detailJob` is cancelled on a new `loadDetail`;
  a same-id call while `Loading` is a no-op.

## 7. Error Handling & Resilience

- **List load errors** become Paging `LoadState.Error(throwable)`; AND-219 renders
  a full-screen error (initial) or an append-error footer with a retry affordance
  calling `LazyPagingItems.retry()`. `IOException`/`SocketTimeoutException`
  (offline / ~20s dev timeout) and `HttpException` are both caught in the
  `PagingSource` and returned as `LoadResult.Error` (never crash the stream).
- **Detail errors** map to `DetailUiState.Error`: `ApiResult.Failure` carries the
  AND-015 `ApiError.message`; `ApiResult.NetworkError` shows the offline copy. Both
  are `retryable = true`; `retryDetail(id)` re-runs the call.
- **401 expired session:** handled below this layer — the AND-013 `Authenticator`
  refreshes once and retries; a hard second 401 surfaces as `HttpException(401)` →
  `LoadState.Error` / `ApiResult.Failure`, which AND-219/AND-220 route to login
  (AND-025). The ViewModel adds no auth handling.
- **Bounded backoff** for the idempotent GETs is owned by AND-016 on the shared
  client; the `PagingSource` does not retry internally (Paging `retry()` is the
  user-driven retry).
- **Empty vs error distinction:** an empty history page (`items: []`,
  `LoadState.NotLoading` + `endOfPaginationReached`) is an *empty state*, not an
  error; an empty *search* result is distinguished via `state.isSearching` so
  AND-219 can show "No results for '<q>'" vs "No purchases yet".
- **Debounce safety:** rapid typing collapses to a single search via
  `debounce + distinctUntilChanged + flatMapLatest`; in-flight searches for stale
  queries are cancelled, preventing out-of-order results.

## 8. Security & Privacy

- **Auth:** all reads ride the cookie-based session attached by the shared client
  (AND-011/AND-012/AND-013). The ViewModel/repository send no `user_id`, no manual
  cookie/CSRF headers; endpoints are server-side user-scoped (no IDOR surface).
- **Sensitive data in state:** `PurchaseDetail` holds semi-sensitive PII/financial
  hints (`shippingAddress`, masked `paymentMethod`, `tracking`). These live only in
  `viewModelScope` state, are cleared with the ViewModel, and must never be logged
  in full (see §10). `paymentMethod` arrives backend-masked (AND-218); the client
  never holds a full PAN, CVV, or token.
- **SavedStateHandle:** only the **search query** string is persisted there — no
  PII, no detail payloads (which would be written to the saved-state bundle / disk
  on process death). Detail content is re-fetched, not persisted.
- **External tracking link:** `Tracking.trackingUrl` is opaque carrier data; the
  ViewModel only carries it. AND-220 validates the `https` scheme before opening a
  Custom Tab.
- **Transport:** dev is plaintext HTTP (AND-006 scoped cleartext, dev-only); the
  data here is acknowledged sensitive, so cleartext must not reach staging/prod.

## 9. Accessibility & i18n

No Compose UI in this ticket, but the domain models are explicitly shaped for
accessible, localizable downstream rendering (AND-219/AND-220):
- `Money` exposes `amountMinor` + `currency` (not just `display`) so AND-219 can
  format with `NumberFormat.getCurrencyInstance(locale)`; `display` is a fallback.
- `purchasedAtIso`/`estimatedDeliveryIso` are raw ISO-8601 so the UI formats per
  device locale/time zone (`DateUtils`/`DateTimeFormatter`).
- `OrderStatus` is a typed value (not a server label) so AND-219 maps each case to
  a localized `strings.xml` label + status-chip `contentDescription`;
  `OrderStatus.Unknown(raw)` lets the UI fall back gracefully without crashing.
- User-facing strings produced *here* (offline message, error copy) are placeholder
  constants; AND-219/AND-220 must source final copy from `strings.xml` rather than
  the constants in §4.5 (those are test-stable defaults, flagged in Q-3). No
  hardcoded user-visible string ships in `feature-purchases` release UI.

## 10. Telemetry & Logging

- **Analytics events** (emitted from the ViewModel via the AND-### analytics
  facade, if present at M5; otherwise stubbed behind an interface): `purchases_history_viewed`,
  `purchases_search_performed { query_len }` (length only, never the raw query
  text — see §8), `purchase_detail_viewed { purchase_id }`, `purchases_load_failed
  { surface, error_type }`. Events fire on debounced search commit and on
  `LoadState`/`ApiResult` transitions, not per keystroke.
- **Logging:** no `Log.*` of `PurchaseDetail` bodies (PII/financial). Errors are
  logged at most as `error_type` + endpoint, never payloads. HTTP logging is the
  AND-009 debug-only interceptor; this ticket adds none.
- If no analytics facade exists yet at M5, this ticket defines a no-op
  `PurchasesAnalytics` interface (injected, default no-op binding) so events are
  testable now and wired later — flagged in Q-2.

## 11. Testing Strategy

The backlog acceptance is *Unit-tested*. All tests are JVM (`paging-common`,
`kotlinx-coroutines-test` `runTest`, Turbine, MockK/fakes, `core-testing`). No
instrumented tests here (UI tests are AND-219/AND-222).

### 11.1 Mapper tests (`core-data`, pure)
`PurchasesMapperTest`: `MoneyDto.toDomain()` preserves `amountMinor`/`currency`;
each known `status` string → correct `OrderStatus`; `"partially_refunded"` →
`OrderStatus.Unknown("partially_refunded")` (no throw); `itemCount == null` → `0`;
full `PurchaseDetailDto` → `PurchaseDetail` field-by-field incl. items/tracking.

### 11.2 PagingSource tests (`core-data`)
`PurchasesPagingSourceTest` with a fake `PurchasesApi`:
- `load(refresh, key=null)` → `LoadResult.Page(prevKey=null, nextKey=2)` when
  `has_more=true`; `nextKey=null` when `has_more=false`.
- Query `null` calls `listPurchases`; non-null calls `searchPurchases(q=…)` with
  the exact trimmed query (verify args).
- `IOException` / `HttpException(404/401)` from the api → `LoadResult.Error(e)`
  (stream not crashed).
- Empty page (`items=[]`, `has_more=false`) → `LoadResult.Page(data=[], nextKey=null)`.

### 11.3 Repository tests (`core-data`)
`DefaultPurchasesRepositoryTest`: `getPurchaseDetail` maps api success →
`ApiResult.Success(PurchaseDetail)`; `HttpException` → `ApiResult.Failure`;
`IOException` → `ApiResult.NetworkError`. `purchasesPaging(query)` builds a
`Pager` whose first page (collected via Paging test util `asSnapshot {}`) contains
mapped `PurchaseListItem`s in order.

### 11.4 ViewModel tests (`feature-purchases`)
`PurchasesViewModelTest` (`runTest`, `StandardTestDispatcher`, `Dispatchers.Main`
set via `MainDispatcherRule`, Turbine on `StateFlow`s; fake repository):
- **Initial state** — `state.value == PurchasesUiState(query="", isSearching=false)`.
- **Query update** — `onSearchQueryChanged("tee")` immediately sets
  `state.query == "tee"`, `isSearching == true`; persisted in `SavedStateHandle`.
- **Debounce** — typing `t`,`te`,`tee` within 300 ms advances virtual time;
  `repository.purchasesPaging` is invoked with `"tee"` exactly **once** for the
  search (not per keystroke); blanking reverts to history (`query=null`) with `0 ms`
  debounce.
- **flatMapLatest cancellation** — a second query before the first paging emission
  cancels the first generation (verify only the latest query reaches the repo).
- **Paging mapping** — collect `pagingFlow` via `asSnapshot {}`; assert mapped
  items match the fake's page and order; search query routes to the search fake.
- **SavedState survival** — recreate the ViewModel with a `SavedStateHandle`
  preloaded with `KEY_QUERY="tee"`; `state.query == "tee"` and `pagingFlow` uses the
  search endpoint on first collection.
- **Detail success/failure/offline** — `loadDetail("pur_001")` transitions
  `Idle → Loading → Content`; `Failure` → `Error(message, retryable=true)`;
  `NetworkError` → `Error(OFFLINE, true)`.
- **Detail de-dup** — second `loadDetail` while `Loading` is a no-op (repo called
  once); a different id cancels the prior `detailJob`.
- **retryDetail** — resets to `Idle` then re-invokes and reaches `Content`.

Coverage target: ≥90% line coverage on `feature-purchases` ViewModel +
`core-data.purchases` (mapper, repository, paging source). Every state transition,
the debounce, and each error path has an assertion.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-218** (Purchases API) — supplies `PurchasesApi` + DTOs this ticket maps
  and pages. Pinned by the backlog.

**Transitive upstream (already required):** AND-018 (`ApiResult` +
`runCatchingApi`), AND-015 (`ApiError` mapping), AND-016 (GET backoff), AND-027/
AND-013 (session + refresh), AND-003/AND-004 (modules + Hilt). Paging 3 must be on
the version catalog (added here if absent).

**Downstream (this ticket blocks / unblocks):**
- **AND-219** (Purchase history + search) — collects `pagingFlow` +
  `state`, binds the search field to `onSearchQueryChanged`, renders empty/loading/
  error via `LoadState`. *Listed by the backlog as depending on AND-218; this
  ViewModel is the state contract it binds to, so AND-221 should land before or with
  AND-219.*
- **AND-220** (Order detail + tracking) — collects `detailState`, calls
  `loadDetail`/`retryDetail`, opens `tracking.trackingUrl`.
- **AND-222** (Purchases tests) — repo + UI tests building on this ViewModel/repo.

**Sequencing within the ticket:** (1) domain models in `core-model`; (2) pure
mapper + `PurchasesMapperTest`; (3) `PurchasesPagingSource` + test; (4)
`PurchasesRepository` interface + impl + test + `core-testing` fake; (5)
`PurchasesViewModel` + `UiState`/`DetailUiState` + tests; (6) Hilt bindings
(`@HiltViewModel`, repository `@Binds`).

## 13. Risks & Open Questions

- **R-1 Paging key type.** If AND-218 resolves to cursor-based paging (`next_cursor`)
  rather than `page`/`limit`, `PurchasesPagingSource` switches `Int` keys to
  `String` cursor keys. Mitigation: the repository interface hides this; only the
  source + its test change. Guarded by §11.2.
- **R-2 Analytics facade availability at M5.** The shared analytics facade may not
  exist yet. Mitigation: inject a no-op `PurchasesAnalytics` interface now, wire the
  real impl when available.
- **R-3 Search debounce / min-length parity.** The web reference may use a different
  debounce (e.g. 250/400 ms) or a min query length > 1. Mitigation: match
  `frontend` behavior; `SEARCH_DEBOUNCE_MS`/`MIN_QUERY_LEN` are single constants.
- **R-4 Empty-state ambiguity.** Distinguishing "no purchases" from "no results"
  relies on `state.isSearching` + `LoadState`; confirm AND-219's copy needs match
  this signal set.
- **R-5 SavedState + Paging interaction.** Restoring `query` from `SavedStateHandle`
  must re-trigger the correct (search vs history) stream on first collection;
  covered by the SavedState-survival test, but verify `flatMapLatest` emits the
  restored query's stream (not the default history stream) on cold collect.
- **Q-1** Cursor vs page/limit paging (inherited from AND-218 Q-2)? *Proposed:*
  `page`/`limit` `Int` keys; switch if OpenAPI says cursor.
- **Q-2** Does an analytics facade exist at M5, and what is its interface?
  *Proposed:* no-op `PurchasesAnalytics` until then.
- **Q-3** Final user-facing error/empty/offline copy — owned here or in AND-219's
  `strings.xml`? *Proposed:* placeholder constants here; canonical copy in AND-219.

## 14. Acceptance Criteria

- **AC-1 (backlog — State).** `PurchasesViewModel` exposes
  `state: StateFlow<PurchasesUiState>` (query + `isSearching`),
  `detailState: StateFlow<DetailUiState>`, and intent functions
  `onSearchQueryChanged`, `loadDetail`, `retryDetail`; `PurchasesRepository`
  interface + `DefaultPurchasesRepository` exist in `core-data` and the domain
  models exist in `com.testlogon.android.core.model.purchases`.
- **AC-2 (backlog — Paging).** `pagingFlow: Flow<PagingData<PurchaseListItem>>` is
  `cachedIn(viewModelScope)`, pages history via `listPurchases` for a blank query
  and search via `searchPurchases` for a non-blank query, with
  `PagingConfig(pageSize=20, prefetchDistance=5, enablePlaceholders=false)`;
  `has_more=false` ⇒ `nextKey=null`.
- **AC-3 (backlog — Unit-tested).** Mapper, `PagingSource`, repository, and
  ViewModel unit tests (§11) pass; ≥90% coverage on the new surface; debounce
  collapses keystrokes to one search; `flatMapLatest` cancels stale generations.
- **AC-4.** DTO→domain mapping is lossless for money (`Long` minor units) and
  total for `OrderStatus` (unknown statuses → `Unknown(raw)`, never throws).
- **AC-5.** Detail load transitions `Idle → Loading → Content/Error`; `Failure` →
  `Error(ApiError.message, retryable)`; `NetworkError` → offline `Error`; same-id
  re-entry while `Loading` is a no-op; new id cancels the prior load.
- **AC-6.** Search query survives config change + process death via
  `SavedStateHandle`; restored query drives the search stream on first collection.
- **AC-7.** List/detail errors (`IOException`, `HttpException`, hard `401`) never
  crash the stream/app — list → `LoadState.Error` (retryable), detail →
  `DetailUiState.Error`; no auth/cookie/CSRF/retry logic added in this layer.
- **AC-8.** No PII/financial payload is written to `SavedStateHandle` or logged;
  only `query_len` (not raw query) is recorded in telemetry.
- **AC-9.** Hilt: `@HiltViewModel` `PurchasesViewModel` and a `@Binds`
  `PurchasesRepository` resolve; modules build clean under AGP 8.7.3 / Gradle 8.9 /
  JDK 17; all tests green in CI; no new lint/detekt regressions.

## 15. Definition of Done

- Domain models (`com.testlogon.android.core.model.purchases`), mapper +
  `PurchasesRepository`/`DefaultPurchasesRepository` + `PurchasesPagingSource`
  (`com.testlogon.android.core.data.purchases`), and `PurchasesViewModel` +
  `PurchasesUiState`/`DetailUiState` (`com.testlogon.android.feature.purchases`)
  are implemented under the canonical `com.testlogon.android` base; nothing
  redefined elsewhere.
- The repository wraps detail in `ApiResult` (AND-018) via `runCatchingApi`
  (AND-015 error mapping); the `PagingSource` returns `LoadResult.Error` for
  `IOException`/`HttpException`; no second `OkHttpClient`/`Retrofit` and no manual
  cookie/CSRF/auth headers are introduced.
- Open questions Q-1/Q-2/Q-3 (and risks R-1/R-3/R-5) are resolved against
  `/openapi.json`, `frontend/src/api/endpoints/purchases.ts`, and the web history/
  search screen; paging key type, debounce/min-length, and analytics facade reflect
  the confirmed contract.
- Unit tests (`PurchasesMapperTest`, `PurchasesPagingSourceTest`,
  `DefaultPurchasesRepositoryTest`, `PurchasesViewModelTest`) are implemented and
  green in CI; ≥90% line coverage on the new surface; every state transition, the
  debounce, paging mapping, and each error path is asserted (Turbine + `runTest` +
  `asSnapshot`).
- `./gradlew :core-model:testDebugUnitTest :core-data:testDebugUnitTest
  :feature-purchases:testDebugUnitTest :feature-purchases:assemble` passes locally
  and in CI with no new lint/detekt violations (AND-005 config).
- A `core-testing` `FakePurchasesRepository` is provided for AND-219/AND-220/AND-222
  to bind in their UI/repo tests.
- Code reviewed and merged to `android-port`; AND-219 (history/search screen),
  AND-220 (detail/tracking screen), and AND-222 (tests) can compile and bind
  against `PurchasesViewModel`, `PurchasesRepository`, and the domain models.
- A one-line note in the `feature-purchases` / `core-data` README records the
  ViewModel state contract (`state`/`pagingFlow`/`detailState` + intents) and the
  delegation of transport/auth/retry to AND-218/AND-009/AND-013/AND-016.
