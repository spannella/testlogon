---
id: AND-221
title: Purchases ViewModel
milestone: M5
epic: E30
priority: P1
size: M
depends_on: [AND-218]
blocks: [AND-219, AND-220, AND-222]
status: reviewed
reviewed_on: 2026-06-06
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
  `PurchasesApi` and the wire DTOs. **[CORRECTED 2026-06-06]** Verified against the
  OpenAPI spec and `src/api/endpoints/purchases.ts`, the real surface is
  `listTransactions(limit, status)` → `PurchaseTransactionSummary[]`,
  `searchTransactions(q, limit)` → `PurchaseTransactionSummary[]`, and
  `getTransaction(txnId)` → `PurchaseTransactionInfo`. The wire DTOs are
  **`PurchaseTransactionSummary`**, **`PurchaseTransactionInfo`** (extends summary),
  and **`PurchaseShipping`** (+ `CarrierEvent`). The DTO names in the original draft
  (`PurchaseSummaryDto`, `PurchaseDetailDto`, `PurchasePageDto`,
  `PurchaseSearchResultDto`, `MoneyDto`, `PurchaseItemDto`, `TrackingDto`) **do not
  exist**. This ticket maps the real DTOs to domain models; it does not redefine
  wire types.
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

FR-6. **Domain mapping.** **[CORRECTED 2026-06-06]** Map AND-218 DTOs to
render-ready domain models: `PurchaseTransactionSummary → PurchaseListItem`,
`PurchaseTransactionInfo → PurchaseDetail`, `(amount, currency) → Money`
(preserving the decimal `amount` losslessly + `currency`), epoch-second
timestamps passed through as `Long`, and the raw uppercase `status` string →
`OrderStatus` with an `OrderStatus.Unknown(raw)` fallback (never throws). Mapping
is in a pure, separately-tested mapper (no Android types).

FR-7. **Pagination contract.** **[CORRECTED 2026-06-06]** The backend exposes
**no pagination** — `GET /ui/purchase-history/transactions` and `.../search`
return a bare `PurchaseTransactionSummary[]` bounded only by a `limit` query param
(no `page`, no cursor, no `has_more`/`next_cursor`; verified in the OpenAPI spec
and `src/api/endpoints/purchases.ts`). The `PagingSource` is therefore
*single-page*: it loads one `limit`-bounded array and returns
`LoadResult.Page(prevKey = null, nextKey = null)`. `PagingConfig(pageSize = 50,
prefetchDistance = 0, enablePlaceholders = false, initialLoadSize = 50)` — page
size equals a server-accepted `limit` (web uses 50; list max 100, search max 200).
Paging 3 is kept only for its `LoadState`/stream ergonomics, not incremental load.

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

> **[CORRECTED 2026-06-06]** The original models were modelled on a richer
> "order" shape (minor-unit money, order numbers, item counts, line items, a
> price breakdown, masked payment method) that **does not exist** in the real
> `PurchaseTransactionSummary` / `PurchaseTransactionInfo` DTOs. Verified against
> `src/api/types.ts` and `components.schemas.PurchaseTransactionSummary/Info`.
> The wire shape is a *transaction*, not a multi-line order. Corrections:
> - `amount` is a **decimal major-unit `number`** + `currency` (e.g. 19.99 USD),
>   **not** integer minor units. The web formats it directly with
>   `Intl.NumberFormat({style:'currency', currency})`. `Money.amountMinor: Long`
>   is wrong; use a decimal/`String` amount.
> - Timestamps `created_at`/`updated_at`/`completed_at`/`shipped_at`/`delivered_at`
>   are **epoch seconds (`integer`)**, not ISO-8601 strings. The web does
>   `new Date(ts * 1000)`.
> - Real status values are **UPPERCASE**: `PENDING`, `COMPLETED`, `CANCELLED`,
>   `REVERTED`, `CANCEL_REQUESTED`, `CANCEL_DENIED` — not `paid/shipped/delivered/
>   refunded`. The `OrderStatus` cases are corrected accordingly.
> - Line items are **not on the transaction**. The web sources them from a
>   *separate* cart endpoint via `metadata.cart_id` (`getCartItems`); out of scope
>   here (FR-8/§13). `PurchaseDetail.items` is removed/optional.
> - There is **no** `orderNumber`, `itemCount`, `thumbnailUrl`, `subtotal`, `tax`,
>   shipping-cost `Money`, or `paymentMethod` on the wire. Tracking lives under
>   `shipping` (`PurchaseShipping`).

```kotlin
package com.testlogon.android.core.model.purchases

import androidx.compose.runtime.Immutable

// [CORRECTED] amount is a decimal major-unit value; carry it losslessly (String
// or BigDecimal) — the wire field is a JSON number, formatted by NumberFormat in
// the UI. No minor-unit Long, no `display` from the server.
@Immutable
data class Money(val amount: String, val currency: String)

// [CORRECTED] cases match the real server status set (uppercase on the wire).
@Immutable
sealed interface OrderStatus {
    data object Pending : OrderStatus
    data object Completed : OrderStatus
    data object Cancelled : OrderStatus
    data object Reverted : OrderStatus
    data object CancelRequested : OrderStatus
    data object CancelDenied : OrderStatus
    data class Unknown(val raw: String) : OrderStatus
}

// [CORRECTED] mirrors PurchaseTransactionSummary (txn_id, created_at epoch,
// status, amount/currency, merchant_id?, external_ref?, description?).
@Immutable
data class PurchaseListItem(
    val id: String,                  // txn_id
    val status: OrderStatus,
    val amount: Money,
    val createdAtEpochSec: Long,     // epoch seconds; formatted in UI (AND-219)
    val merchantId: String?,
    val externalRef: String?,
    val description: String?,
)

// [CORRECTED] mirrors PurchaseTransactionInfo (extends summary + buyer/shipping/
// cancel/completed_at/reverted_at/version/metadata/receipt fields). No line-item
// list, no price breakdown, no paymentMethod on the wire.
@Immutable
data class PurchaseDetail(
    val id: String,                  // txn_id
    val status: OrderStatus,
    val amount: Money,
    val createdAtEpochSec: Long,
    val updatedAtEpochSec: Long,
    val merchantId: String?,
    val externalRef: String?,
    val description: String?,
    val buyerId: String,
    val completedAtEpochSec: Long?,
    val revertedAtEpochSec: Long?,
    val shipping: Shipping?,
    val cancel: Map<String, Any?>?,  // server returns an open object
    val cartId: String?,             // from metadata.cart_id; line items fetched separately (out of scope)
)

// [CORRECTED] mirrors PurchaseShipping (carrier/tracking_number/tracking_url/
// status/status_description/shipped_at/delivered_at/estimated_delivery + carrier_events).
@Immutable
data class Shipping(
    val carrier: String?,
    val trackingNumber: String?,
    val trackingUrl: String?,
    val status: String?,
    val statusDescription: String?,
    val shippedAtEpochSec: Long?,
    val deliveredAtEpochSec: Long?,
    val estimatedDelivery: String?,
)
```

### 4.2 Mapper (`core-data.purchases`)

Pure functions; no Android imports; separately unit-tested.

> **[CORRECTED 2026-06-06]** Rewritten to map the real `PurchaseTransactionSummary`
> / `PurchaseTransactionInfo` DTOs (AND-218). Status normalization keys off the
> **uppercase** server values; `amount`+`currency` build `Money` directly (no
> minor-unit math); epoch-second timestamps pass through as `Long`.

```kotlin
// amount is a JSON number; carry it losslessly to a String for the UI to format.
internal fun PurchaseTransactionSummary.toMoney() =
    Money(amount = amount.toPlainStringLossless(), currency = currency)

internal fun String.toOrderStatus(): OrderStatus = when (uppercase()) {
    "PENDING" -> OrderStatus.Pending
    "COMPLETED" -> OrderStatus.Completed
    "CANCELLED", "CANCELED" -> OrderStatus.Cancelled
    "REVERTED" -> OrderStatus.Reverted
    "CANCEL_REQUESTED" -> OrderStatus.CancelRequested
    "CANCEL_DENIED" -> OrderStatus.CancelDenied
    else -> OrderStatus.Unknown(this)        // never throws
}

internal fun PurchaseTransactionSummary.toListItem() = PurchaseListItem(
    id = txnId, status = status.toOrderStatus(), amount = toMoney(),
    createdAtEpochSec = createdAt, merchantId = merchantId,
    externalRef = externalRef, description = description,
)

internal fun PurchaseTransactionInfo.toDomain() = PurchaseDetail(/* field-by-field
    map incl. buyerId, completedAt/revertedAt epochs, shipping.toDomain(),
    cartId = (metadata["cart_id"] as? String) */)
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

> **[CORRECTED 2026-06-06]** Method names align to AND-218's actual `PurchasesApi`
> surface backing the real endpoints: `listTransactions(limit, status)`,
> `searchTransactions(q, limit)`, `getTransaction(txnId)` (cf.
> `src/api/endpoints/purchases.ts`). **The backend has no pagination**, so the
> `PagingSource` is *single-page*: it loads one `limit`-bounded array and reports
> `nextKey = null` always (see §4.4). `PagingConfig.initialLoadSize` therefore
> must equal `pageSize` and `pageSize` should be set to a real `limit` the server
> accepts (≤ 100 list / ≤ 200 search; the web uses 50). Paging 3 is retained
> purely as the stream/`LoadState` plumbing AND-219 consumes — not for true
> incremental paging.

```kotlin
@Singleton
class DefaultPurchasesRepository @Inject constructor(
    private val api: PurchasesApi,
) : PurchasesRepository {

    override fun purchasesPaging(query: String?): Flow<PagingData<PurchaseListItem>> =
        Pager(
            // initialLoadSize == pageSize: a single bounded fetch (no real paging).
            config = PagingConfig(pageSize = PAGE_SIZE, prefetchDistance = 0,
                enablePlaceholders = false, initialLoadSize = PAGE_SIZE),
            pagingSourceFactory = { PurchasesPagingSource(api, query?.trim()?.ifBlank { null }) },
        ).flow

    override suspend fun getPurchaseDetail(id: String): ApiResult<PurchaseDetail> =
        runCatchingApi { api.getTransaction(id).toDomain() }   // AND-018/AND-015 helper

    companion object { const val PAGE_SIZE = 50 }   // [CORRECTED] server limit, was page-size 20
}
```

`runCatchingApi { }` is AND-018's helper mapping success → `ApiResult.Success`,
`HttpException` → `ApiResult.Failure(ApiError)` (via AND-015), and
`IOException`/`SocketTimeoutException` → `ApiResult.NetworkError`.

### 4.4 PagingSource

> **[CORRECTED 2026-06-06]** The original read a `page`/`limit` + `has_more`
> envelope that **does not exist** (both endpoints return a bare
> `PurchaseTransactionSummary[]`). Rewritten as a *single-page* source: load once,
> `nextKey = null` always. Calls the corrected method names.

```kotlin
internal class PurchasesPagingSource(
    private val api: PurchasesApi,
    private val query: String?,            // null => history endpoint
) : PagingSource<Int, PurchaseListItem>() {

    override suspend fun load(params: LoadParams<Int>): LoadResult<Int, PurchaseListItem> {
        return try {
            // Response is a bare array; size is bounded by `limit`, no envelope.
            val rows = if (query == null) {
                api.listTransactions(limit = params.loadSize, status = null)
            } else {
                api.searchTransactions(q = query, limit = params.loadSize)
            }
            LoadResult.Page(
                data = rows.map { it.toListItem() },
                prevKey = null,
                nextKey = null,            // [CORRECTED] no backend pagination
            )
        } catch (e: IOException) { LoadResult.Error(e) }
          catch (e: HttpException) { LoadResult.Error(e) }
    }

    // Single page => refresh always restarts from the top.
    override fun getRefreshKey(state: PagingState<Int, PurchaseListItem>): Int? = null
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

> **[CORRECTED 2026-06-06]** The original draft listed `GET purchases`,
> `GET purchases/search`, `GET purchases/{purchaseId}` returning
> `PurchasePageDto`/`PurchaseSearchResultDto`/`PurchaseDetailDto` with a
> `page`/`limit` + `has_more`/`next_cursor` envelope. **None of that matches the
> backend or the web reference.** The real contract (verified against the OpenAPI
> index and `src/api/endpoints/purchases.ts`) is below.

Endpoints actually used (relative to `http://18.222.237.167:8000/`):

- `GET /ui/purchase-history/transactions?limit={n}&status={s}` →
  **`PurchaseTransactionSummary[]`** (a bare JSON array — *not* an envelope). The
  history list. `limit` default 25, max 100, min 1; `status` is an optional filter
  string. **There is no `page` parameter.**
- `GET /ui/purchase-history/transactions/search?q={query}&limit={n}` →
  **`PurchaseTransactionSummary[]`** (bare array). Search. `q` is **required,
  `minLength=1`**; `limit` default 100, max 200. **No `page` parameter.**
- `GET /ui/purchase-history/transactions/{txnId}` → **`PurchaseTransactionInfo`**
  (detail load). Path param is `txn_id`.

**[CORRECTED] No backend pagination exists.** Both list and search return a single
bounded array sized by `limit`; there is no `page`, no cursor, no `has_more` /
`next_cursor` field anywhere in the schema. The web reference fetches one page of
`limit: 50` and does **client-side** status filtering — it does not paginate. The
spec's Paging-3 "page = page + 1 / nextKey" design (FR-7, §4.3–4.4) is therefore
**not supported by the backend**; see §13 R-1 for the resolution
(single-page `PagingSource` over a `limit`-bounded fetch, `nextKey` always `null`).

Error bodies follow the FastAPI `detail` union, verified in `src/api/client.ts`
(`normalizeErrorDetail`): `detail` may be a plain string, an array of
`{msg, loc, type}` objects (422 validation), or an object with `code`/`message`/
`reason` (authorization/geo errors, e.g. `400 api_key_dual_credential_conflict`).
These are mapped to `ApiError` by AND-015 inside `runCatchingApi`; the detail call
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

- **Auth:** all reads ride the session attached by the shared client
  (AND-011/AND-012/AND-013). The ViewModel/repository send no `user_id`, no manual
  cookie/CSRF headers; endpoints are server-side user-scoped (no IDOR surface).
  **[CORRECTED 2026-06-06]** Note the web reference (`src/api/client.ts`) is *not*
  purely cookie-based: it sends `Authorization: Bearer <accessToken>` **and**
  `credentials: "include"` (cookies) **and** an `X-CSRF-Token` header (read from
  the `ui_csrf` cookie) on **every** request, including GETs, plus an optional
  `X-IMPERSONATION-TOKEN`. 401 triggers a single `POST /ui/session/refresh` +
  retry. The Android transport (AND-011/012/013) owns exactly how this is mirrored;
  this ticket adds none of it, but the "cookie-only" framing was inaccurate.
- **Sensitive data in state:** **[CORRECTED 2026-06-06]** `PurchaseTransactionInfo`
  carries **no `paymentMethod` and no top-level `shippingAddress`** field (verified
  in `src/api/types.ts`). The PII/financial-adjacent fields it does expose are
  `buyer_id`/`buyer_profile`, the shipping block (`carrier`, `tracking_number`,
  `tracking_url`, an open `address` object under `PurchaseShipping`), `external_ref`,
  and an open `metadata` object. These live only in `viewModelScope` state, are
  cleared with the ViewModel, and must never be logged in full (see §10). The client
  never receives a PAN/CVV/payment token from these endpoints.
- **SavedStateHandle:** only the **search query** string is persisted there — no
  PII, no detail payloads (which would be written to the saved-state bundle / disk
  on process death). Detail content is re-fetched, not persisted.
- **External tracking link:** `shipping.tracking_url` is opaque carrier data; the
  ViewModel only carries it. **[CORRECTED 2026-06-06]** The web reference opens it
  directly with `target="_blank" rel="noopener noreferrer"` and does **not**
  validate the scheme; AND-220 *should* still validate the `https` scheme before
  opening a Custom Tab (recommended Android hardening, not web-verified behavior).
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
**[CORRECTED 2026-06-06]** `PurchasesMapperTest`: `(amount, currency) → Money`
preserves the decimal `amount` losslessly + `currency`; each known uppercase
`status` (`PENDING/COMPLETED/CANCELLED/REVERTED/CANCEL_REQUESTED/CANCEL_DENIED`) →
correct `OrderStatus`; an unrecognized status (e.g. `"DISPUTED"`) →
`OrderStatus.Unknown("DISPUTED")` (no throw); epoch-second timestamps pass through;
full `PurchaseTransactionInfo` → `PurchaseDetail` field-by-field incl.
`shipping`/`cancel`/`metadata.cart_id`.

### 11.2 PagingSource tests (`core-data`)
**[CORRECTED 2026-06-06]** `PurchasesPagingSourceTest` with a fake `PurchasesApi`
(no pagination — single bounded array):
- `load(refresh, key=null)` → `LoadResult.Page(prevKey=null, nextKey=null)` always
  (single page; there is no `has_more`/next page).
- Query `null` calls `listTransactions(limit, status=null)`; non-null calls
  `searchTransactions(q=…, limit)` with the exact trimmed query (verify args).
- `IOException` / `HttpException(404/401)` from the api → `LoadResult.Error(e)`
  (stream not crashed).
- Empty array (`[]`) → `LoadResult.Page(data=[], prevKey=null, nextKey=null)`.

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

- **R-1 No backend pagination (RESOLVED 2026-06-06).** Verified: the list/search
  endpoints return a bare `PurchaseTransactionSummary[]` bounded by `limit` only —
  no `page`, no cursor, no `has_more`/`next_cursor`. Resolution: single-page
  `PagingSource` (`nextKey = null` always); `limit` = 50 (web parity; list max 100,
  search max 200). If the backend later adds true paging, only the source + its
  test change behind the repository interface. Guarded by §11.2. **Residual risk:**
  large histories are truncated at `limit`; a future ticket may add real paging or a
  `RemoteMediator` (out of scope, FR-8).
- **R-2 Analytics facade availability at M5.** The shared analytics facade may not
  exist yet. Mitigation: inject a no-op `PurchasesAnalytics` interface now, wire the
  real impl when available.
- **R-3 Search debounce / min-length parity (RESOLVED 2026-06-06).** Verified the
  web reference (`src/pages/purchases/PurchaseHistory.tsx`) uses a **300 ms**
  debounce and enters search mode when `debouncedQuery.trim().length > 0`
  (min length 1; matches the backend `q` `minLength=1`). The spec's
  `SEARCH_DEBOUNCE_MS = 300` and `MIN_QUERY_LEN = 1` are correct as written.
- **R-4 Empty-state ambiguity.** Distinguishing "no purchases" from "no results"
  relies on `state.isSearching` + `LoadState`; confirm AND-219's copy needs match
  this signal set.
- **R-5 SavedState + Paging interaction.** Restoring `query` from `SavedStateHandle`
  must re-trigger the correct (search vs history) stream on first collection;
  covered by the SavedState-survival test, but verify `flatMapLatest` emits the
  restored query's stream (not the default history stream) on cold collect.
- **Q-1 (RESOLVED 2026-06-06)** Cursor vs page/limit paging? **Neither** — the
  OpenAPI spec and web reference confirm a `limit`-only bare-array contract with no
  pagination. Single-page `PagingSource`, `limit=50`. See R-1.
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
- **AC-2 (backlog — Paging).** **[CORRECTED 2026-06-06]** `pagingFlow:
  Flow<PagingData<PurchaseListItem>>` is `cachedIn(viewModelScope)`, loads history
  via `listTransactions(limit, status=null)` for a blank query and search via
  `searchTransactions(q, limit)` for a non-blank query, with
  `PagingConfig(pageSize=50, prefetchDistance=0, enablePlaceholders=false,
  initialLoadSize=50)`. Because the backend returns a bare array with no
  pagination, the `PagingSource` is single-page: `nextKey` is **always `null`**
  (no `has_more`/`page` exists). Paging 3 is used for `LoadState`/stream plumbing,
  not incremental fetch.
- **AC-3 (backlog — Unit-tested).** Mapper, `PagingSource`, repository, and
  ViewModel unit tests (§11) pass; ≥90% coverage on the new surface; debounce
  collapses keystrokes to one search; `flatMapLatest` cancels stale generations.
- **AC-4.** **[CORRECTED 2026-06-06]** DTO→domain mapping is lossless for money
  (the wire `amount` is a **decimal major-unit number** + `currency`, carried
  without precision loss — *not* `Long` minor units) and total for `OrderStatus`
  (server values `PENDING/COMPLETED/CANCELLED/REVERTED/CANCEL_REQUESTED/
  CANCEL_DENIED` map to typed cases; any other → `Unknown(raw)`, never throws).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "OpenAPI"
pointers are `METHOD /path` and/or `components.schemas.<Name>` in
`reference/openapi.pretty.json` / `reference/openapi.index.txt`. Frontend pointers
are paths under `reference/src/`.

1. **History endpoint is `GET /ui/purchase-history/transactions`** (not
   `GET purchases`). **VERDICT: Corrected.** Source: OpenAPI
   `GET /ui/purchase-history/transactions` (op `ui_list_transactions_…`);
   `src/api/endpoints/purchases.ts: listTransactions`.
2. **History list params are `limit` (default 25, max 100, min 1) + optional
   `status` — there is no `page`.** **VERDICT: Corrected.** Source: OpenAPI
   `GET /ui/purchase-history/transactions` parameters block;
   `src/api/endpoints/purchases.ts: listTransactions`.
3. **History list response is a bare `PurchaseTransactionSummary[]` array (no
   envelope, no `has_more`/`next_cursor`).** **VERDICT: Corrected.** Source:
   OpenAPI 200 response of `GET /ui/purchase-history/transactions` (`type: array`,
   `items: $ref PurchaseTransactionSummary`); `src/api/endpoints/purchases.ts`
   (`api.get<PurchaseTransactionSummary[]>`).
4. **Search endpoint is `GET /ui/purchase-history/transactions/search`, `q`
   required `minLength=1`, `limit` default 100 max 200, no `page`; returns bare
   `PurchaseTransactionSummary[]`.** **VERDICT: Corrected.** Source: OpenAPI
   `GET /ui/purchase-history/transactions/search` parameters + 200 response;
   `src/api/endpoints/purchases.ts: searchTransactions`.
5. **Detail endpoint is `GET /ui/purchase-history/transactions/{txn_id}` →
   `PurchaseTransactionInfo`.** **VERDICT: Corrected** (was `GET purchases/{id}` →
   `PurchaseDetailDto`). Source: OpenAPI
   `GET /ui/purchase-history/transactions/{txn_id}` (resp `200:
   PurchaseTransactionInfo`); `src/api/endpoints/purchases.ts: getTransaction`.
6. **The backend exposes no pagination of any kind** (no page, no cursor, no
   `has_more`). **VERDICT: Corrected.** Source: absence of paging params/fields in
   the two list endpoints above + `PurchaseTransactionSummary` schema; web fetches
   a single `limit: 50` page (`src/pages/purchases/PurchaseHistory.tsx`).
7. **DTO names `PurchaseTransactionSummary` / `PurchaseTransactionInfo` /
   `PurchaseShipping` (the draft's `PurchaseSummaryDto`/`PurchaseDetailDto`/
   `PurchasePageDto`/`PurchaseSearchResultDto`/`MoneyDto`/`PurchaseItemDto`/
   `TrackingDto` do not exist).** **VERDICT: Corrected.** Source:
   `components.schemas.PurchaseTransactionSummary`, `…PurchaseTransactionInfo`;
   `src/api/types.ts: PurchaseTransactionSummary / PurchaseTransactionInfo /
   PurchaseShipping`.
8. **`amount` is a decimal major-unit JSON number + `currency` string (not
   integer minor units; no server `display`).** **VERDICT: Corrected.** Source:
   `components.schemas.PurchaseTransactionSummary.amount` (`type: number`);
   `src/pages/purchases/PurchaseHistory.tsx: formatCurrency(txn.amount, …)` via
   `Intl.NumberFormat`.
9. **Timestamps `created_at`/`updated_at`/`completed_at`/`shipped_at`/
   `delivered_at` are epoch seconds (integer), not ISO-8601 strings.** **VERDICT:
   Corrected.** Source: `components.schemas.PurchaseTransactionSummary.created_at`
   (`type: integer`); `src/pages/purchases/…: new Date(ts * 1000)`.
10. **Real status values are uppercase `PENDING / COMPLETED / CANCELLED /
    REVERTED / CANCEL_REQUESTED / CANCEL_DENIED`** (not `paid/shipped/delivered/
    refunded`). **VERDICT: Corrected.** Source:
    `src/pages/purchases/TransactionDetail.tsx: statusVariant` and the `canComplete/
    canRevert/canRequestCancel/canRespondCancel` guards;
    `src/pages/purchases/PurchaseHistory.tsx: STATUS_FILTERS`.
11. **Detail (`PurchaseTransactionInfo`) carries no line-item list, no price
    breakdown (subtotal/tax/shipping), and no `paymentMethod`; line items come from
    a separate cart endpoint via `metadata.cart_id`.** **VERDICT: Corrected.**
    Source: `src/api/types.ts: PurchaseTransactionInfo`;
    `src/pages/purchases/TransactionDetail.tsx: CartItemsCard` using
    `metadata.cart_id` + `getCartItems`.
12. **Tracking lives under `shipping` (`PurchaseShipping`: carrier /
    tracking_number / tracking_url / status / shipped_at / delivered_at /
    estimated_delivery / carrier_events).** **VERDICT: Corrected.** Source:
    `src/api/types.ts: PurchaseShipping`;
    `src/pages/purchases/TransactionDetail.tsx` shipping block.
13. **Search debounce = 300 ms.** **VERDICT: Verified.** Source:
    `src/pages/purchases/PurchaseHistory.tsx` (`setTimeout(... , 300)`).
14. **Search min query length = 1 (enter search when trimmed length > 0).**
    **VERDICT: Verified.** Source:
    `src/pages/purchases/PurchaseHistory.tsx: isSearchMode`; backend `q`
    `minLength: 1`.
15. **Empty-state copy differs for "no orders" vs search "no matching orders".**
    **VERDICT: Verified** (supports FR-3/§7 empty-vs-search distinction). Source:
    `src/pages/purchases/PurchaseHistory.tsx: EmptyState` title/description.
16. **Error `detail` is a union: string | array of `{msg,…}` (422) | object with
    `code`/`message`/`reason` (e.g. `400 api_key_dual_credential_conflict`).**
    **VERDICT: Verified.** Source: `src/api/client.ts: normalizeErrorDetail`;
    OpenAPI `400`/`422` examples on the purchase-history endpoints; AND-015 maps
    this to `ApiError`.
17. **Web client sends `Authorization: Bearer` + cookies (`credentials:
    include`) + `X-CSRF-Token` (from `ui_csrf` cookie) + optional
    `X-IMPERSONATION-TOKEN` on every request; 401 → single `POST
    /ui/session/refresh` + retry; offline → `ApiError(0)`.** **VERDICT: Corrected**
    (draft framed reads as cookie-only). Source: `src/api/client.ts` (`api`,
    `refreshSession`).
18. **List/search return `200` plus documented `400/401/403/429/422` error
    codes.** **VERDICT: Verified.** Source: `reference/openapi.index.txt` lines for
    `ui_list_transactions` / `ui_search_transactions` (`resp=…;400;401;403;429`).
19. **Web does not validate the tracking URL scheme before opening it.**
    **VERDICT: Verified** (so Android https-scheme validation is a recommendation,
    not parity). Source: `src/pages/purchases/TransactionDetail.tsx`
    (`<a href={txn.shipping.tracking_url} target="_blank" rel="noopener
    noreferrer">`).
20. **Paging 3 / Hilt / coroutines stack choices (single-page `PagingSource`,
    `cachedIn`, `flatMapLatest`, `SavedStateHandle`, `WhileSubscribed(5_000)`).**
    **VERDICT: Unverified-assumption** (Android architecture choices, not derivable
    from backend/web). Framework refs:
    https://developer.android.com/topic/libraries/architecture/paging/v3-paged-data ,
    https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate .

### Corrections made

- §2, §4.1, §4.2, §4.3, §4.4, §5, §7-adjacent: endpoint paths corrected to
  `/ui/purchase-history/transactions[/search|/{txn_id}]`; method names to
  `listTransactions` / `searchTransactions` / `getTransaction`.
- Removed the fabricated `page`/`limit`/`has_more`/`next_cursor` paging envelope;
  reworked the `PagingSource`/`Pager` to a single-page (`nextKey = null`) design
  with `limit`-bounded fetch and `PAGE_SIZE = 50`. Updated FR-7, AC-2, R-1, Q-1,
  §11.2.
- Domain models realigned to the real transaction shape: `Money` now decimal
  `amount` + `currency` (was minor-unit `Long`); `OrderStatus` cases now the real
  uppercase set; `PurchaseListItem`/`PurchaseDetail`/`Shipping` rebuilt from
  `PurchaseTransactionSummary`/`PurchaseTransactionInfo`/`PurchaseShipping`;
  timestamps as epoch-second `Long`. Updated §4.1, §4.2, FR-6, AC-4, §11.1.
- Corrected DTO names in §2 (the `…Dto` names do not exist).
- §8: corrected the "cookie-only" auth framing (web also sends Bearer + CSRF
  header); removed nonexistent `paymentMethod`/`shippingAddress` field claims;
  flagged tracking-URL scheme validation as Android-side recommendation.
- Resolved R-3 and Q-1 against verified sources; annotated R-1.
- Frontmatter: `status: reviewed`, `reviewed_on: 2026-06-06`.

### Open assumptions

- **Status filter parity.** The web sends `status` to `listTransactions`
  (uppercased) for filtering; this ticket's `purchasesPaging(query)` does not yet
  thread a `status` filter param. Whether AND-219 needs server-side status
  filtering (vs client-side) is unconfirmed — left out of this state contract; flag
  for AND-219. *Why unverifiable:* it is a downstream-UI decision, not fixed by the
  backend.
- **Lossless decimal carrying of `amount`.** Modelled as `String`/`BigDecimal` to
  avoid float rounding; the exact Android representation (and whether AND-218's
  generated DTO deserializes `amount` as `Double`/`BigDecimal`) depends on AND-218's
  Retrofit/Moshi config, which is not in these sources. *Why unverifiable:* AND-218
  client code is not present in the reference.
- **Analytics facade existence at M5 (Q-2).** Not determinable from backend/web
  sources; remains a no-op-interface assumption.
- **Final user-facing copy / strings.xml ownership (Q-3).** UI concern owned by
  AND-219; not verifiable here.
- **Android framework choices (Paging 3 single-page, Hilt, SavedStateHandle,
  coroutine operators).** Reasonable architecture, not derivable from the contract;
  see citation 20 framework refs.

## 17. Test Plan

All cases trace to §14 Acceptance Criteria. The backlog acceptance is
*Unit-tested*; this ticket produces **no Compose UI**, so the core suite is JVM
unit / contract on the **JVM unit/Robolectric** target (local, no device).
Instrumented and physical-device cases are included only where they add real value
for downstream verification (they would normally land with AND-219/AND-222) and are
labelled with the required target.

- **TC-AND-221-01 — Mapper: summary → list item (happy path).**
  Type: unit. Target: JVM unit. Preconditions: a `PurchaseTransactionSummary`
  fixture (`txn_id`, `amount=19.99`, `currency="USD"`, `status="COMPLETED"`,
  `created_at=1_717_000_000`, `merchant_id`, `external_ref`, `description`).
  Steps: call `toListItem()`. Expected: `PurchaseListItem` with `id=txn_id`,
  `amount=Money("19.99","USD")` (lossless), `status=OrderStatus.Completed`,
  `createdAtEpochSec=1_717_000_000`, fields copied 1:1. Traces: AC-1, AC-4.

- **TC-AND-221-02 — Mapper: status normalization + Unknown fallback.**
  Type: unit. Target: JVM unit. Preconditions: status strings
  `PENDING/COMPLETED/CANCELLED/CANCELED/REVERTED/CANCEL_REQUESTED/CANCEL_DENIED`
  and an unrecognized `"DISPUTED"`; mixed case. Steps: call `toOrderStatus()` on
  each. Expected: each maps to its typed case (case-insensitive); `"DISPUTED"` →
  `OrderStatus.Unknown("DISPUTED")`; no exception thrown for any input. Traces:
  AC-4.

- **TC-AND-221-03 — Mapper: detail → PurchaseDetail incl. shipping & cart_id.**
  Type: unit. Target: JVM unit. Preconditions: a `PurchaseTransactionInfo` fixture
  with `shipping` (carrier/tracking_number/tracking_url/shipped_at/delivered_at),
  `completed_at`, `metadata={"cart_id":"cart_9"}`. Steps: call `toDomain()`.
  Expected: `PurchaseDetail` with `shipping` mapped field-by-field (epoch Longs),
  `completedAtEpochSec` set, `cartId="cart_9"`; no line-item list expected (sourced
  separately). Traces: AC-1, AC-4.

- **TC-AND-221-04 — PagingSource: single-page history load (contract).**
  Type: contract/MockWebServer. Target: JVM unit (MockWebServer; or fake
  `PurchasesApi`). Preconditions: MockWebServer returns a bare JSON array of N
  `PurchaseTransactionSummary` for `GET /ui/purchase-history/transactions?limit=50`.
  Steps: `load(LoadParams.Refresh(key=null, loadSize=50))` with `query=null`.
  Expected: `LoadResult.Page(data=mapped N items in order, prevKey=null,
  nextKey=null)`; request path/params exactly `…/transactions?limit=50` (no `page`).
  Traces: AC-2.

- **TC-AND-221-05 — PagingSource: search routes to search endpoint with trimmed q.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: fake/MockWebServer
  for `GET …/transactions/search`. Steps: construct source with `query="  tee "`
  (already trimmed by repo to `"tee"`); `load(refresh)`. Expected: calls
  `searchTransactions(q="tee", limit=…)` → path
  `…/transactions/search?q=tee&limit=50`; `null` query path calls
  `listTransactions` instead. Traces: AC-2.

- **TC-AND-221-06 — PagingSource: error & empty handling (no crash).**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: API throws
  `IOException` (offline/flaky dev host), then `HttpException(401)`, then returns
  `[]`. Steps: `load(refresh)` for each. Expected: first two →
  `LoadResult.Error(e)` (stream not crashed); empty → `LoadResult.Page(data=[],
  prevKey=null, nextKey=null)` (empty state, not error). Traces: AC-7, AC-2.

- **TC-AND-221-07 — Repository: detail success / failure / network mapping.**
  Type: unit. Target: JVM unit. Preconditions: fake `PurchasesApi`. Steps: (a)
  `getPurchaseDetail("txn_1")` with API success; (b) with `HttpException(404,
  body detail="not found")`; (c) with `SocketTimeoutException`. Expected: (a)
  `ApiResult.Success(PurchaseDetail)`; (b) `ApiResult.Failure(ApiError(message…))`
  via AND-015; (c) `ApiResult.NetworkError`. Traces: AC-1, AC-5, AC-7.

- **TC-AND-221-08 — Repository: paging stream emits mapped items via asSnapshot.**
  Type: unit. Target: JVM unit (`paging-common` `asSnapshot {}`). Preconditions:
  fake API returns a known list. Steps: collect first generation of
  `purchasesPaging(null)`. Expected: snapshot equals the mapped `PurchaseListItem`
  list in order; a non-null query yields the search fake's list. Traces: AC-2,
  AC-4.

- **TC-AND-221-09 — ViewModel: initial state + immediate query update + debounce.**
  Type: unit. Target: JVM unit (`runTest`, `StandardTestDispatcher`,
  `MainDispatcherRule`, Turbine). Preconditions: fake repo recording
  `purchasesPaging` calls. Steps: assert initial `state ==
  PurchasesUiState(query="", isSearching=false)`; call `onSearchQueryChanged("t")`,
  `("te")`, `("tee")` within 300 ms; advance virtual time past 300 ms; collect
  `pagingFlow`. Expected: `state.query` updates immediately to `"tee"`,
  `isSearching=true`, persisted in `SavedStateHandle`; repo's search path invoked
  with `"tee"` exactly **once** (debounce collapses keystrokes). Traces: AC-1,
  AC-3, AC-6.

- **TC-AND-221-10 — ViewModel: flatMapLatest cancels stale generation; blank
  reverts to history.** Type: unit. Target: JVM unit. Preconditions: fake repo.
  Steps: emit `"a"` then quickly `"ab"` before first paging emission; then blank
  the query. Expected: only the latest query (`"ab"`) reaches the repo before
  blanking; blanking switches to the history path (`query=null`) with ~0 ms
  debounce. Traces: AC-3.

- **TC-AND-221-11 — ViewModel: detail Idle→Loading→Content/Error + dedup +
  cancel.** Type: unit. Target: JVM unit (Turbine on `detailState`).
  Preconditions: fake repo with controllable suspension. Steps: `loadDetail("t1")`
  → assert `Idle→Loading→Content`; force `Failure` → `Error(message,
  retryable=true)`; force `NetworkError` → `Error(OFFLINE, true)`; call
  `loadDetail("t1")` again while `Loading` (no-op, repo called once); call
  `loadDetail("t2")` mid-flight (cancels prior job). Expected: transitions and
  de-dup/cancellation as specified. Traces: AC-5, AC-7.

- **TC-AND-221-12 — ViewModel: SavedState survival drives search stream on cold
  collect.** Type: unit. Target: JVM unit. Preconditions: construct ViewModel with
  a `SavedStateHandle` preloaded `KEY_QUERY="tee"`. Steps: read `state`; collect
  `pagingFlow` cold. Expected: `state.query=="tee"`, `isSearching=true`; the first
  paging generation uses the **search** endpoint (not history) for the restored
  query (covers R-5). Traces: AC-6.

- **TC-AND-221-13 — Security: no PII written to SavedState; only query_len logged.**
  Type: unit. Target: JVM unit (fake `PurchasesAnalytics` + spy on
  `SavedStateHandle`). Preconditions: load a detail with shipping/buyer fields;
  perform a search. Steps: inspect every key written to `SavedStateHandle`; capture
  emitted analytics events. Expected: only `KEY_QUERY` (the query string) is in
  saved state — no detail payload, no buyer/shipping/address; `purchases_search_
  performed` carries `query_len` only, never the raw query. Traces: AC-8.

- **TC-AND-221-14 — Flaky/offline dev-host end-to-end through the ViewModel.**
  Type: integration. Target: JVM unit (MockWebServer simulating ~20s timeout via
  throttled/`SocketPolicy.NO_RESPONSE`). Preconditions: list load times out, then a
  detail load times out. Steps: collect `pagingFlow` (assert `LoadState.Error`),
  call `retry()` after the server recovers (assert items load); `loadDetail` times
  out → `DetailUiState.Error(OFFLINE, retryable)`, then `retryDetail` succeeds.
  Expected: no crash; errors are retryable; recovery loads data. Traces: AC-7, AC-5.

- **TC-AND-221-15 — Compose smoke bind of the contract (downstream guard).**
  Type: Compose-UI. Target: headless emulator AVD `test35` (API 35) — fast CI UI
  run; **emulator is sufficient** (no hardware dependency). Preconditions: a minimal
  test composable collecting `pagingFlow` as `LazyPagingItems` + `state` +
  `detailState` from a ViewModel backed by `FakePurchasesRepository`. Steps: render
  list (items + empty state), trigger an error generation, render detail Content.
  Expected: the state contract binds and renders without runtime/type errors;
  empty-vs-search copy is selectable via `state.isSearching`; status chips expose a
  non-empty `contentDescription` (a11y check) for each `OrderStatus`, including
  `Unknown`. Traces: AC-1, AC-3. *(Belongs with AND-219; included as a contract
  smoke guard.)*

- **TC-AND-221-16 — Real-device API-34/arm64 contract sanity (optional, downstream).**
  Type: instrumented/e2e. Target: **PHYSICAL DEVICE Samsung Galaxy A15 5G (SM-A156U,
  serial R5CX821TA9R, Android 14 / API 34, arm64-v8a)** — must run here, not the
  emulator, to catch arm64-vs-x86 ABI / API-34-vs-35 deserialization or
  `NumberFormat`/timezone-formatting differences against the live dev backend.
  Preconditions: app built for arm64-v8a, dev host reachable via adb-forwarded
  network. Steps: launch, open purchases, fetch real history + one detail.
  Expected: list and detail deserialize and render; decimal `amount` formats
  correctly per device locale; epoch timestamps render in device timezone; no ABI
  crash. Traces: AC-1, AC-2, AC-4, AC-7. *(Optional; primarily an AND-219/AND-222
  concern — flagged because hardware/ABI parity needs the physical device.)*

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (state + repo + models exist) | TC-01, TC-03, TC-07, TC-09, TC-11, TC-15, TC-16 |
| AC-2 (paging: list vs search, nextKey=null) | TC-04, TC-05, TC-06, TC-08, TC-16 |
| AC-3 (unit-tested; debounce; flatMapLatest cancel) | TC-09, TC-10, TC-15 |
| AC-4 (lossless money; total OrderStatus mapping) | TC-01, TC-02, TC-03, TC-08, TC-16 |
| AC-5 (detail Idle→Loading→Content/Error; dedup; cancel) | TC-07, TC-11, TC-14 |
| AC-6 (query survives config/process death; restores search) | TC-09, TC-12 |
| AC-7 (errors never crash; LoadState/DetailUiState.Error) | TC-06, TC-07, TC-11, TC-14, TC-16 |
| AC-8 (no PII in SavedState/logs; only query_len) | TC-13 |
| AC-9 (Hilt resolves; builds clean; tests green) | Whole suite green in CI (TC-01…TC-14 on JVM; build/assemble gate) |
