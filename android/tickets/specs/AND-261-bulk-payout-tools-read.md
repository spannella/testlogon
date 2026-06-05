---
id: AND-261
title: Bulk payout tools (read)
milestone: M6
epic: E35
priority: P2
size: M
status: draft
depends_on: [AND-258]
blocks: []
---

# AND-261 — Bulk payout tools (read)

## 1. Overview & Goal

This ticket delivers the **read-only** Android UI surface for the "bulk payout
tools" — the operator/creator-facing views that the web reference implements in
`frontend/src/api/endpoints/bulkPayoutTools.ts`. On web these tools let a user
inspect payouts in aggregate: a batch list, a batch detail with its constituent
payout line items, and roll-up totals. This ticket ports **only the read views**:
the screens that render bulk/batch payout data. No batch creation, approval,
cancellation, retry, or any other mutating action is in scope.

The single hard acceptance signal from the backlog is **"Bulk views render."**
Concretely: a user can navigate to a Bulk Payouts list screen, see batches loaded
from the backend, tap a batch to open a detail screen that renders the batch's
roll-up totals and a paginated list of the payout line items inside it, and the
screens correctly present loading, empty, error, and offline/stale states. All
monetary values render locale-correctly from the `Money(amountMinor, currency)`
domain type established in AND-258.

Scope is feature UI: a `feature-payouts` (bulk sub-package) ViewModel +
`UiState` + Compose screens, plus the thin Retrofit/repository read methods for
the bulk endpoints that are not already covered by AND-258's `PayoutsApi`. The
data plumbing reuses AND-258 patterns exactly (Moshi DTOs, `*.toDomain()`
mappers, `ApiResult<T>`, the shared authenticated OkHttp/Retrofit stack). When
this ticket merges, the bulk payout read experience is navigable and tested; any
mutating "bulk action" is explicitly deferred to a future M6 write ticket.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace:** code lands under `com.testlogon.android` —
  `com.testlogon.android.feature.payouts.bulk` (ViewModel, UiState, Compose
  screens, navigation), with the read-only network/data additions under
  `com.testlogon.android.core.network.payouts` and
  `com.testlogon.android.core.data.payouts`, and domain types under
  `com.testlogon.android.core.model.payout`.
- **Module placement:** screens + ViewModel in `feature-payouts`; any new DTOs +
  Retrofit methods in `core-network`; new domain models in `core-model`; new
  repository methods in `core-data`. Layering rule
  `app -> feature-payouts -> core-data -> core-network -> core-model` is
  respected.
- **Web reference:** `frontend/src/api/endpoints/bulkPayoutTools.ts` (endpoint
  paths, query params, batch + line-item shapes) and `frontend/src/api/types.ts`
  (any `PayoutBatch` / bulk types). The backend OpenAPI at `/openapi.json` on the
  dev host is the tie-breaker; capture a live response if web types and the wire
  disagree.
- **Depends on AND-258 (Payouts API):** reuse its `PayoutsApi`,
  `PayoutsRepository`, the `Payout` / `Money` / `PayoutStatus` domain types, the
  `*.toDomain()` mapper conventions, the shared `apiCall { }` helper, and the
  shared idempotent-GET retry. The bulk read methods are added alongside the
  existing payouts read methods following the identical pattern. AND-258 in turn
  depends on AND-027 (authenticated Retrofit/OkHttp stack: persistent cookie jar,
  `ui_csrf` → `X-CSRF-Token`, single 401→refresh→retry interceptor, FastAPI
  `detail` error mapper) — this ticket adds **no** auth code.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable — design for ~20s timeouts, bounded backoff retry
  on idempotent GETs only, and offline/stale UI states).
- **Blocks:** nothing currently; a future bulk-payout *write/actions* ticket will
  build on these read views.

## 3. Functional Requirements

FR-1. **Bulk Payouts list screen.** Render a scrollable, paged list of payout
batches from `GET /ui/payouts/bulk`. Each row shows: a human label / batch id, a
`PayoutBatchStatus` chip, item count, total amount (locale-formatted), and
created date. Newest first as returned by the server.

FR-2. **Batch detail screen.** On tapping a batch, navigate to a detail screen
keyed by `batchId` that renders: the batch header (status, totals roll-up —
total amount, item count, and per-status counts if provided) plus a paginated
list of the constituent payout line items (`GET /ui/payouts/bulk/{batchId}/items`),
each shown with recipient label, amount, and per-item `PayoutStatus`.

FR-3. **Read-only.** No create/approve/cancel/retry/export buttons. The screens
contain no mutating affordances and issue only `GET` requests.

FR-4. **Pagination.** Both the batch list and the items list are cursor-paged via
Paging 3, driven by the `nextCursor` exposed by the page DTOs (same convention as
AND-258's `PayoutPage.nextCursor`). Append loads on scroll; show append spinner
and append-error retry footer.

FR-5. **State coverage.** Each screen exposes Loading, Content (with data),
Empty (no batches / no items — distinct copy), and Error states. Error state
shows a retryable message mapped from the FastAPI `detail` body.

FR-6. **Offline / stale.** When the unreliable dev host is unreachable, the
screen shows an offline/error state with retry; if cached content from a previous
successful load is available in memory for the current session, it is shown with
a non-blocking "couldn't refresh" indicator rather than being discarded.

FR-7. **Money formatting.** All amounts are formatted in the UI layer from
`Money(amountMinor, currency)` via locale-aware `NumberFormat.getCurrencyInstance`;
no formatting happens in the data layer and no floating-point money is introduced.

FR-8. **Navigation.** Add typed Navigation-Compose routes `bulkPayouts` (list)
and `bulkPayoutDetail/{batchId}` to the payouts nav graph, with an entry point
reachable from the Payouts area.

## 4. Technical Design

### Network additions (`core-network`)

Add bulk read methods to a `BulkPayoutsApi` (kept separate from AND-258's
`PayoutsApi` for cohesion; both are created from the same shared `Retrofit`):

```kotlin
package com.testlogon.android.core.network.payouts

interface BulkPayoutsApi {
    @GET("ui/payouts/bulk")
    suspend fun getBatches(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): PayoutBatchPageDto

    @GET("ui/payouts/bulk/{batchId}")
    suspend fun getBatch(@Path("batchId") batchId: String): PayoutBatchDto

    @GET("ui/payouts/bulk/{batchId}/items")
    suspend fun getBatchItems(
        @Path("batchId") batchId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): PayoutPageDto   // reuses AND-258 PayoutDto/PayoutPageDto for line items
}
```

DTOs (`core-network`; `PayoutDto`/`PayoutPageDto` reused from AND-258):

```kotlin
@JsonClass(generateAdapter = true)
data class PayoutBatchPageDto(
    @Json(name = "items") val items: List<PayoutBatchDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total") val total: Int? = null,
)

@JsonClass(generateAdapter = true)
data class PayoutBatchDto(
    @Json(name = "id") val id: String,
    @Json(name = "label") val label: String?,
    @Json(name = "status") val status: String?,
    @Json(name = "item_count") val itemCount: Int?,
    @Json(name = "total_amount") val totalAmountMinor: Long?,
    @Json(name = "currency") val currency: String?,
    @Json(name = "status_counts") val statusCounts: Map<String, Int>? = null,
    @Json(name = "created_at") val createdAt: String?,
)
```

Domain models (`core-model`):

```kotlin
package com.testlogon.android.core.model.payout

enum class PayoutBatchStatus {
    DRAFT, PENDING, PROCESSING, COMPLETED, PARTIALLY_FAILED, FAILED, CANCELED, UNKNOWN
}

data class PayoutBatch(
    val id: String,
    val label: String?,
    val status: PayoutBatchStatus,
    val itemCount: Int,
    val total: Money,                       // from AND-258
    val statusCounts: Map<PayoutStatus, Int>,
    val createdAt: Instant?,
)

data class PayoutBatchPage(
    val items: List<PayoutBatch>,
    val nextCursor: String?,
    val total: Int?,
)
```

Mappers (`core-network`, pure, package-internal — same style as AND-258):

```kotlin
internal fun PayoutBatchDto.toDomain(): PayoutBatch = PayoutBatch(
    id = id,
    label = label,
    status = status.toPayoutBatchStatus(),
    itemCount = itemCount ?: 0,
    total = Money(totalAmountMinor ?: 0L, currency ?: "USD"),
    statusCounts = (statusCounts ?: emptyMap())
        .mapKeys { it.key.toPayoutStatus() },     // reuse AND-258 String?.toPayoutStatus()
    createdAt = createdAt?.toInstantOrNull(),
)

internal fun String?.toPayoutBatchStatus(): PayoutBatchStatus = when (this?.lowercase()) {
    "draft" -> PayoutBatchStatus.DRAFT
    "pending" -> PayoutBatchStatus.PENDING
    "processing", "in_progress" -> PayoutBatchStatus.PROCESSING
    "completed", "succeeded", "paid" -> PayoutBatchStatus.COMPLETED
    "partially_failed", "partial" -> PayoutBatchStatus.PARTIALLY_FAILED
    "failed" -> PayoutBatchStatus.FAILED
    "canceled", "cancelled" -> PayoutBatchStatus.CANCELED
    else -> PayoutBatchStatus.UNKNOWN
}
```

### Repository (`core-data`)

Extend the payouts data layer with bulk read methods returning `ApiResult<T>`,
plus Paging 3 `PagingSource`s for the two paged surfaces:

```kotlin
package com.testlogon.android.core.data.payouts

interface BulkPayoutsRepository {
    suspend fun getBatch(batchId: String): ApiResult<PayoutBatch>
    fun batchesPager(): Flow<PagingData<PayoutBatch>>
    fun batchItemsPager(batchId: String): Flow<PagingData<Payout>>
}

class DefaultBulkPayoutsRepository @Inject constructor(
    private val api: BulkPayoutsApi,
) : BulkPayoutsRepository {

    override suspend fun getBatch(batchId: String): ApiResult<PayoutBatch> =
        apiCall { api.getBatch(batchId).toDomain() }

    override fun batchesPager(): Flow<PagingData<PayoutBatch>> = Pager(
        config = PagingConfig(pageSize = 20, enablePlaceholders = false),
    ) { BatchesPagingSource(api) }.flow

    override fun batchItemsPager(batchId: String): Flow<PagingData<Payout>> = Pager(
        config = PagingConfig(pageSize = 20, enablePlaceholders = false),
    ) { BatchItemsPagingSource(api, batchId) }.flow
}
```

`BatchesPagingSource` / `BatchItemsPagingSource` (`core-data`) implement
`PagingSource<String, PayoutBatch>` / `PagingSource<String, Payout>` using the
opaque `nextCursor` as the key, mapping DTOs via `toDomain()`, and returning
`LoadResult.Error` on `HttpException`/`IOException` so Paging surfaces append
errors with retry.

### ViewModel + UiState (`feature-payouts`)

```kotlin
package com.testlogon.android.feature.payouts.bulk

sealed interface BulkBatchDetailUiState {
    data object Loading : BulkBatchDetailUiState
    data class Content(val batch: PayoutBatch) : BulkBatchDetailUiState
    data class Error(val message: String, val canRetry: Boolean = true) : BulkBatchDetailUiState
}

@HiltViewModel
class BulkPayoutsViewModel @Inject constructor(
    private val repo: BulkPayoutsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    // List screen: Paging flow cached in the VM scope.
    val batches: Flow<PagingData<PayoutBatch>> =
        repo.batchesPager().cachedIn(viewModelScope)

    // Detail screen: header state + paged line items.
    private val batchId: String = checkNotNull(savedStateHandle["batchId"])

    private val _detail = MutableStateFlow<BulkBatchDetailUiState>(BulkBatchDetailUiState.Loading)
    val detail: StateFlow<BulkBatchDetailUiState> = _detail.asStateFlow()

    val items: Flow<PagingData<Payout>> =
        repo.batchItemsPager(batchId).cachedIn(viewModelScope)

    init { loadBatch() }

    fun loadBatch() = viewModelScope.launch {
        _detail.value = BulkBatchDetailUiState.Loading
        _detail.value = when (val r = repo.getBatch(batchId)) {
            is ApiResult.Success -> BulkBatchDetailUiState.Content(r.data)
            is ApiResult.Error -> BulkBatchDetailUiState.Error(r.message)
        }
    }
}
```

### Compose screens (`feature-payouts`)

- `BulkPayoutsListScreen(onBatchClick: (String) -> Unit, vm: BulkPayoutsViewModel)`
  collects `vm.batches.collectAsLazyPagingItems()`, renders a `LazyColumn` of
  `BatchRow` composables, and maps `loadState.refresh` to full-screen
  Loading/Empty/Error and `loadState.append` to a footer spinner/retry.
- `BulkPayoutDetailScreen(vm: BulkPayoutsViewModel)` renders the
  `BulkBatchDetailUiState` header (totals roll-up, status chip, per-status counts)
  followed by `vm.items.collectAsLazyPagingItems()` as a `LazyColumn` of
  `BatchItemRow`. Header and items load independently; a header error does not
  blank the items list and vice versa.
- Reuse `core-ui` chips, list-state scaffolding (the shared
  `EmptyState`/`ErrorState`/`LoadingState` composables), and Material 3 theming.

### Navigation

Add to the payouts nav graph:

```kotlin
const val BULK_PAYOUTS_ROUTE = "bulkPayouts"
const val BULK_PAYOUT_DETAIL_ROUTE = "bulkPayoutDetail/{batchId}"

fun NavController.navigateToBulkPayoutDetail(batchId: String) =
    navigate("bulkPayoutDetail/$batchId")
```

with `composable(BULK_PAYOUT_DETAIL_ROUTE, arguments = listOf(navArgument("batchId") { type = NavType.StringType }))`.

### Hilt

```kotlin
@Module @InstallIn(SingletonComponent::class)
object BulkPayoutsNetworkModule {
    @Provides @Singleton
    fun provideBulkPayoutsApi(retrofit: Retrofit): BulkPayoutsApi = retrofit.create()
}

@Module @InstallIn(SingletonComponent::class)
abstract class BulkPayoutsDataModule {
    @Binds abstract fun bindBulkPayoutsRepository(
        impl: DefaultBulkPayoutsRepository,
    ): BulkPayoutsRepository
}
```

## 5. API Contract

Base URL `http://18.222.237.167:8000/`. All calls authenticated via the shared
cookie jar + `X-CSRF-Token` (AND-027). Verify exact paths/params against
`/openapi.json` and `bulkPayoutTools.ts` at implementation time; the shapes below
are the contract this ticket maps to. **All endpoints are GET (read-only).**

`GET /ui/payouts/bulk?cursor=&limit=20` → 200:

```json
{
  "items": [
    {
      "id": "bat_77",
      "label": "May 2026 creator payouts",
      "status": "completed",
      "item_count": 128,
      "total_amount": 5764500,
      "currency": "USD",
      "status_counts": { "paid": 124, "failed": 2, "pending": 2 },
      "created_at": "2026-05-31T22:10:00Z"
    }
  ],
  "next_cursor": "eyJrIjoiYmF0Xzc2In0=",
  "total": 12
}
```

`GET /ui/payouts/bulk/{batchId}` → 200: a single object identical in shape to an
`items[]` element above.

`GET /ui/payouts/bulk/{batchId}/items?cursor=&limit=20` → 200: the AND-258
`PayoutPage` shape (array of `PayoutDto` line items + `next_cursor` + `total`):

```json
{
  "items": [
    {
      "id": "po_5501",
      "amount": 4500,
      "currency": "USD",
      "status": "paid",
      "method_id": "pm_01",
      "created_at": "2026-05-30T18:04:11Z",
      "arrival_at": "2026-06-02T00:00:00Z",
      "failure_reason": null
    }
  ],
  "next_cursor": null,
  "total": 128
}
```

Error responses (FastAPI): 401 handled by the AND-027 refresh-once interceptor
before reaching the repo; 404 `{"detail":"Batch not found"}` (e.g. bad
`batchId`); 422 `{"detail":[{"loc":[...],"msg":"...","type":"..."}]}` for bad
query params; 5xx / connection failure → mapped to `ApiResult.Error` /
`LoadResult.Error` via the shared mapper. **No POST/PUT/PATCH/DELETE is called by
this ticket.**

## 6. Data & State Management

- **No persistent state.** This ticket adds no Room table and no DataStore key.
  Bulk read data lives in memory only for the session; Paging streams are
  `cachedIn(viewModelScope)` so configuration changes and back-navigation within
  the screen do not re-fetch. (A Room-backed `RemoteMediator` cache for bulk
  history is a deliberate future enhancement, not in scope.)
- **List state** is owned by Paging 3 `LazyPagingItems.loadState` (refresh /
  append / prepend) — the screen derives Loading/Empty/Content/Error from it
  rather than a hand-rolled `UiState`.
- **Detail header state** is the explicit `BulkBatchDetailUiState` `StateFlow`
  (Loading/Content/Error), independent of the items Paging stream so the two can
  fail and retry independently.
- **Money** is carried as `Money(amountMinor, currency)` end-to-end; the UI is the
  only place a formatted string is produced, via
  `NumberFormat.getCurrencyInstance(locale)` seeded with the `Money.currency`.
- **Status counts** are kept as a `Map<PayoutStatus, Int>` so the detail roll-up
  can render a deterministic, locale-labeled breakdown.

## 7. Error Handling & Resilience

- All three calls are idempotent GETs and opt into the network core's **bounded
  backoff retry** (max ~2 retries, jittered) for transient
  `IOException`/timeout/5xx — appropriate for the unreliable dev host.
- Per-request timeout follows the global ~20s call timeout on the shared OkHttp
  client (AND-027); this ticket does not override it.
- 401 is resolved upstream by the single refresh-then-retry interceptor; the repo
  only sees auth failure if refresh itself fails, surfaced as `ApiResult.Error` /
  `LoadResult.Error` for the screen to show an error (and the app-level auth
  guard from AND-025 to route to login).
- **Paging append errors** are non-fatal: the already-loaded pages stay visible
  and a retry footer is shown (`lazyItems.retry()`); a **refresh error** with no
  prior data shows the full-screen `ErrorState` with retry.
- **Offline / stale (FR-6):** if a refresh fails but Paging already holds items
  from this session, the list is not cleared; a transient "Couldn't refresh"
  snackbar/banner is shown. The detail header, if previously `Content`, is
  retained and the error is surfaced non-destructively.
- Mapping is defensively null-safe: missing `total_amount` → `0` minor units,
  missing `currency` → `"USD"`, missing `item_count` → `0`, unknown
  `status`/per-item status → `UNKNOWN`, unparseable timestamps → `null`,
  missing/empty `status_counts` → empty map. A malformed-but-structured payload
  never throws from a mapper; only a Moshi structural failure yields an error.
- Empty results (`items: []`, `next_cursor: null`) are valid successes rendered as
  the distinct **Empty** state, not errors.

## 8. Security & Privacy

- Bulk payout data is financial PII (batch totals, per-recipient amounts, payout
  statuses). It must **never** be written to logs. The OkHttp
  `HttpLoggingInterceptor` for these routes is `Level.NONE` (or headers-only) in
  release; body logging is debug-only and even then amounts and recipient labels
  are redacted by the shared logging redactor.
- No tokens are handled here; auth is cookie-based and owned by AND-027. The
  persistent cookie jar stays in private/encrypted app storage as established
  there.
- Transport is plaintext HTTP **only because the dev host is HTTP**; production
  base URL must be HTTPS and the existing network-security-config scopes
  `cleartextTrafficPermitted` to the dev host only. This ticket adds **no** new
  cleartext exemption.
- No bulk payout data is serialized to disk (no Room/DataStore here), so no
  at-rest exposure is introduced. Screenshots of these screens should be treated
  as sensitive; do not set `FLAG_SECURE` here, but flag the consideration to the
  future write ticket.

## 9. Accessibility & i18n

- All interactive rows (batch rows) expose `Modifier.semantics`/`contentDescription`
  combining label, status, count, and amount so TalkBack reads a coherent summary;
  status chips have text equivalents, never color-only meaning.
- Touch targets ≥ 48dp; list supports large font scaling and does not truncate
  amounts in a way that loses precision (wrap/marquee labels, never the amount).
- **i18n:** every user-facing string (screen titles, Empty/Error copy, status
  labels, "items", "Total") is a `strings.xml` resource. `PayoutBatchStatus` and
  `PayoutStatus` enums are mapped to string resources in the UI layer, not
  hardcoded. Amounts use `NumberFormat.getCurrencyInstance(Locale.getDefault())`
  seeded by the `Money.currency`; dates use `DateTimeFormatter`/locale-aware
  medium format. No currency symbols or formatted numbers are produced in the
  data layer.
- Server-provided `label` / `failure_reason` strings are passed through verbatim
  and are not localizable.

## 10. Telemetry & Logging

- Network timing/outcome telemetry is captured by the shared OkHttp event
  listener; bulk calls inherit it with the route tag `payouts_bulk`. **No**
  request/response bodies are emitted.
- Screen-level analytics (non-PII): `screen_view` for `bulk_payouts_list` and
  `bulk_payout_detail` (detail carries only an opaque `batchId`, never amounts or
  recipient data), and an `error_shown` breadcrumb on full-screen error carrying
  endpoint name + HTTP status + mapped error category only.
- The repository may emit a structured, non-PII breadcrumb on error: endpoint
  name, HTTP status, mapped category — never amounts, recipient ids, or status
  counts.

## 11. Testing Strategy

Anchored to the acceptance signal **"Bulk views render."**

Unit — mapping (`core-network`, JVM):
1. `PayoutBatchDto.toDomain()` maps a fully populated fixture to `PayoutBatch`
   with correct `Money(totalAmountMinor, currency)`, parsed `createdAt`, status,
   and `statusCounts` mapped to `Map<PayoutStatus, Int>`.
2. Every `status` variant (`draft`, `pending`, `processing`/`in_progress`,
   `completed`/`succeeded`/`paid`, `partially_failed`/`partial`, `failed`,
   `canceled`/`cancelled`) → correct enum; unknown → `PayoutBatchStatus.UNKNOWN`.
3. Null/missing `total_amount`, `currency`, `item_count`, `created_at`,
   `status_counts` produce documented defaults without throwing.
4. `PayoutBatchPageDto.toDomain()` preserves order and `nextCursor`; empty items →
   empty list success.

Integration — MockWebServer (`core-testing`):
5. `getBatches` issues `GET /ui/payouts/bulk?cursor=...&limit=20` with exact path,
   verb, and query encoding (assert recorded request).
6. `getBatch("bat_1")` hits `GET /ui/payouts/bulk/bat_1`; `getBatchItems("bat_1")`
   hits `GET /ui/payouts/bulk/bat_1/items`.
7. 404 `{"detail":"Batch not found"}` → `ApiResult.Error` with mapped message;
   422 detail-array → mapped message.
8. 503-then-200 verifies idempotent-GET retry succeeds (request count asserted).
9. `BatchesPagingSource.load` returns `LoadResult.Page` with `nextKey =
   nextCursor`, and `LoadResult.Error` on `IOException`.

UI — Compose (`feature-payouts`, instrumented or Robolectric):
10. **List renders content:** given a fake `BulkPayoutsRepository` emitting a
    `PagingData` of batches, `BulkPayoutsListScreen` displays the rows with
    formatted amount and status chip (**"Bulk views render"**).
11. **List empty/error/offline:** empty `PagingData` → Empty state; refresh error
    → full-screen ErrorState with a working Retry; prior content + refresh error →
    content retained + "couldn't refresh" indicator.
12. **Detail renders:** header (`BulkBatchDetailUiState.Content`) shows totals +
    per-status counts; items Paging list renders line-item rows; header error and
    items error are independent.
13. **Navigation:** tapping a batch row invokes `onBatchClick(batchId)` with the
    correct id; detail VM reads `batchId` from `SavedStateHandle`.

Coverage target: 100% of new mapper functions and all `PagingSource`/`ApiResult`
branches; the four screen states for both screens exercised in Compose tests.

## 12. Dependencies & Sequencing

- **Depends on AND-258 (Payouts API):** reuses `PayoutDto`/`PayoutPageDto`,
  `Payout`/`Money`/`PayoutStatus`, `String?.toPayoutStatus()`,
  `toInstantOrNull()`, `apiCall { }`, and the shared idempotent-GET retry. Do not
  reimplement any of these.
- **Depends transitively on AND-027** (authenticated Retrofit/OkHttp stack,
  cookie jar, CSRF + 401-refresh interceptors, FastAPI error mapper) and on the
  M1 core-network bootstrap (`Retrofit` `@Provides`, base-URL config) and the
  shared `core-ui` list-state/chips and `core-testing` MockWebServer harness.
- **Blocks:** none today; a future **bulk payout write/actions** ticket (batch
  create/approve/cancel/retry) will build on these read views and own all
  mutating endpoints, DTOs, and confirmation UI.
- Sequencing within the ticket: confirm live shapes via `/openapi.json` +
  `bulkPayoutTools.ts` → DTOs + Moshi adapters → domain models + mappers + unit
  tests → `BulkPayoutsApi` + MockWebServer tests → repository +
  `PagingSource`s + tests → ViewModel + UiState → Compose screens + navigation +
  UI tests.

## 13. Risks & Open Questions

- **R1 — Endpoint paths/params unconfirmed.** `bulkPayoutTools.ts` may use a
  different prefix (`/ui/payouts/bulk` vs `/ui/payouts/batches` vs
  `/ui/bulk-payouts`) or page by token vs page-number. Mitigation: capture a real
  response and treat `/openapi.json` + the wire as authoritative; nullable DTOs
  absorb optional fields. **Open:** confirm the list, detail, and items paths and
  the items endpoint shape (dedicated array vs reuse of `PayoutPage`).
- **R2 — Batch status vocabulary.** The backend batch-status set is unconfirmed;
  `UNKNOWN` prevents crashes but the enum may need new members. **Open:**
  enumerate authoritative batch statuses.
- **R3 — Roll-up source.** Whether `status_counts` / `item_count` / `total_amount`
  come from the batch object or must be computed client-side from the items page.
  Current assumption: server provides them on the batch object; if not, the detail
  header degrades gracefully (counts hidden) and we file a follow-up.
- **R4 — "Bulk tools" surface ambiguity.** `bulkPayoutTools.ts` might expose more
  than batches (e.g., bulk export status, CSV templates). This ticket scopes to
  the *read* batch list + detail + items only; any other read view discovered in
  the web file is captured as a follow-up note, and all write/export *actions* are
  out of scope.
- **R5 — Dev host flakiness** may make MockWebServer the only reliable test
  surface — acceptable, since acceptance is "views render" against fake/mocked
  data, not live connectivity.

## 14. Acceptance Criteria

1. `BulkPayoutsApi`, the new DTOs, `PayoutBatch`/`PayoutBatchPage`/
   `PayoutBatchStatus` domain models, mappers, `BulkPayoutsRepository` (+ Paging
   sources), `BulkPayoutsViewModel`/`BulkBatchDetailUiState`, the two Compose
   screens, navigation routes, and Hilt modules exist under
   `com.testlogon.android.{feature.payouts.bulk, core.network/data/model.payout(s)}`
   on `android-port`, with correct module layering and **no mutating endpoints**.
2. **Bulk views render:** the list screen displays batches loaded from
   `GET /ui/payouts/bulk`; tapping a batch opens the detail screen rendering the
   roll-up header and the paged line items from
   `GET /ui/payouts/bulk/{batchId}/items` — proven by Compose tests against a fake
   repository.
3. Both lists are cursor-paged via Paging 3 using `nextCursor`, with working
   append spinner and append-error retry.
4. Loading, Empty, Error, and offline/stale states render correctly on both
   screens; full-screen errors are retryable and mapped through the shared FastAPI
   `detail` mapper.
5. Monetary values are `Money(amountMinor: Long, currency: String)` end-to-end and
   formatted only in the UI via locale-aware `NumberFormat`; no floating-point
   money anywhere.
6. `status` (batch + per-item) maps to enums with `UNKNOWN` fallbacks; no
   unrecognized server string throws.
7. All network calls are GETs, carry session cookies + `X-CSRF-Token` via the
   shared client, and use the shared idempotent-GET retry.
8. Unit + MockWebServer + Compose tests from §11 are present and green, including
   path/verb/query assertions, null-defaulting cases, and the four screen states.
9. No payout PII appears in logs in release configuration; analytics carry no
   amounts or recipient data.

## 15. Definition of Done

- All §14 acceptance criteria met; CI green (`assembleDebug`, `ktlint`/detekt,
  unit + MockWebServer + Compose test tasks for `core-network`/`core-data`/
  `feature-payouts`).
- No new cleartext-traffic exemption; release logging interceptor verified
  `NONE`/redacted for the `payouts_bulk` routes; no financial PII logged.
- KSP generates all new Moshi adapters; no reflection-based JSON fallback.
- All user-facing strings are in `strings.xml`; status enums mapped to resources;
  amounts/dates locale-formatted; rows have TalkBack-coherent semantics.
- Public surface (`BulkPayoutsApi`, `BulkPayoutsRepository`, new domain models,
  ViewModel/UiState) has KDoc; reuse of AND-258 types is documented.
- Navigation entry point to the Bulk Payouts list is reachable from the Payouts
  area and verified manually on a device/emulator against the dev host.
- Open questions R1–R4 either resolved against `/openapi.json` +
  `bulkPayoutTools.ts` or recorded as follow-up notes for the future bulk-write
  ticket.
- Code reviewed and merged to `android-port`.
