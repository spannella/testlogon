---
id: AND-261
title: Bulk payout tools (read)
milestone: M6
epic: E35
priority: P2
size: M
status: reviewed
depends_on: [AND-258]
blocks: []
reviewed_on: 2026-06-06
---

# AND-261 — Bulk payout tools (read)

## 1. Overview & Goal

This ticket delivers the **read-only** Android UI surface for the "bulk payout
tools" — the **admin**-facing views that the web reference implements in
`frontend/src/api/endpoints/bulkPayoutTools.ts` (consumed by
`src/pages/admin/BulkPayoutConsole.tsx`). On web these tools let an admin user
inspect payout/refund batches in aggregate: a batch history list and a batch
detail with its constituent line items and roll-up counts. This ticket ports
**only the read views**: the screens that render bulk/batch payout data. No batch
preview, execute, or any other mutating action is in scope.
**[CORRECTED]** These are admin routes under `/ui/admin/bulk-payouts`, not the
creator `/ui/payouts/...` namespace (verified: `bulkPayoutTools.ts` `BASE =
"/ui/admin/bulk-payouts"` and OpenAPI `GET /ui/admin/bulk-payouts/batches`).

The single hard acceptance signal from the backlog is **"Bulk views render."**
Concretely: a user can navigate to a Bulk Payouts list screen, see batches loaded
from the backend, tap a batch to open a detail screen that renders the batch's
roll-up counts and the line items inside it, and the screens correctly present
loading, empty, error, and offline/stale states.
**[CORRECTED]** The line items are **embedded in the batch object** (`BulkBatchOut.items`)
and are returned in full by the detail call; there is **no** separate items
endpoint and **no** cursor pagination on any bulk endpoint (verified against
OpenAPI + `BulkPayoutConsole.tsx`). All monetary values are integer minor units
(`*_cents`) rendered locale-correctly; the web client hard-codes USD (`fmtCents`
divides by 100 and prefixes `$`) and the batch object carries **no `currency`
field**, so amounts are formatted as USD unless a currency is later added
server-side (see §16 open assumptions).

Scope is feature UI: a `feature-payouts` (bulk sub-package) ViewModel +
`UiState` + Compose screens, plus the thin Retrofit/repository read methods for
the two bulk read endpoints (`listBatches`, `getBatch`) that are not already
covered by AND-258's `PayoutsApi`. The data plumbing reuses AND-258 patterns
(Moshi DTOs, `*.toDomain()` mappers, `ApiResult<T>`, the shared authenticated
OkHttp/Retrofit stack) **except for Paging 3**, which does not apply here because
neither bulk endpoint is paginated (both return whole collections in one call).
When this ticket merges, the bulk payout read experience is navigable and tested;
any mutating "bulk action" (preview/execute) is explicitly deferred to a future
M6 write ticket.

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
  paths/methods) and `frontend/src/pages/admin/BulkPayoutConsole.tsx` (screen
  behavior, field usage, `fmtCents` USD formatting). The bulk DTO types are
  `BulkBatchOut` / `BulkBatchItem` / `BulkEligibleItem` (OpenAPI
  `components.schemas`), **not** a `PayoutBatch` type. **[CORRECTED]** Verified
  field names: batch id is `batch_id` (not `id`), total is `total_cents` (not
  `total_amount`), there is no `label` and no batch-level `currency`, roll-up is
  `success_count`/`failure_count` (not a `status_counts` map), `created_at` is an
  **integer epoch** (not an ISO string), and the batch has `kind` + an embedded
  `items: BulkBatchItem[]`. The backend OpenAPI at `/openapi.json` on the dev host
  is the tie-breaker.
- **Depends on AND-258 (Payouts API):** reuse its `Money` / `PayoutStatus` domain
  types, the `*.toDomain()` mapper conventions, the shared `apiCall { }` helper,
  the `ApiResult<T>` type, and the shared idempotent-GET retry. **[CORRECTED]**
  AND-258's `PayoutDto`/`PayoutPageDto` and its cursor pagination are **not**
  reused for line items, because bulk line items are a distinct `BulkBatchItem`
  shape embedded in the batch (no `next_cursor`); only `Money`/`PayoutStatus` and
  the helper conventions carry over. The bulk read methods are added alongside the
  existing payouts read methods following the same `apiCall`/mapper pattern.
  AND-258 in turn
  depends on AND-027 (authenticated Retrofit/OkHttp stack: persistent cookie jar,
  `ui_csrf` → `X-CSRF-Token`, single 401→refresh→retry interceptor, FastAPI
  `detail` error mapper) — this ticket adds **no** auth code.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable — design for ~20s timeouts, bounded backoff retry
  on idempotent GETs only, and offline/stale UI states).
- **Blocks:** nothing currently; a future bulk-payout *write/actions* ticket will
  build on these read views.

## 3. Functional Requirements

FR-1. **Bulk Payouts list screen.** Render a scrollable list of payout/refund
batches from `GET /ui/admin/bulk-payouts/batches` **[CORRECTED path]**. Each row
shows: the `batch_id`, the `kind` (payout/refund), a `PayoutBatchStatus` chip,
item count (`item_count`), and total amount from `total_cents` (locale-formatted).
**[CORRECTED]** The batch has no `label` and no `created_at`-as-date for display
(`created_at` is an integer epoch; render it via epoch→`Instant` if shown). Order
is as returned by the server. **[CORRECTED]** The endpoint takes no query params
and returns a plain JSON array (not a page object), so this is a single full-list
load, not a paged list.

FR-2. **Batch detail screen.** On tapping a batch, navigate to a detail screen
keyed by `batchId` that renders from a single `GET /ui/admin/bulk-payouts/batches/{batchId}`
**[CORRECTED path]**: the batch header (`kind`, `status`, roll-up — `total_cents`,
`item_count`, `success_count`, `failure_count`) plus the constituent line items.
**[CORRECTED]** The line items come from `BulkBatchOut.items` (embedded in the
same detail response) — there is **no** `.../items` endpoint. Each item shows
`recipient`, amount (`amount_cents`), per-item `status` (mapped to `PayoutStatus`),
and `reason`.

FR-3. **Read-only.** No preview/execute/approve/cancel/retry/export buttons. The
screens contain no mutating affordances and issue only `GET` requests.

FR-4. **No pagination. [CORRECTED]** Neither the batch list nor the items list is
paginated: `listBatches` returns the full array and `getBatch` returns the full
`items` array inline. Render both with a plain `LazyColumn`. Paging 3 is **not**
used in this ticket. (If the batch list grows unbounded server-side, a future
ticket can add a paged variant; today the contract has no cursor.)

FR-5. **State coverage.** Each screen exposes Loading, Content (with data),
Empty (no batches / no items — distinct copy), and Error states. Error state
shows a retryable message mapped from the FastAPI `detail` body.

FR-6. **Offline / stale.** When the unreliable dev host is unreachable, the
screen shows an offline/error state with retry; if cached content from a previous
successful load is available in memory for the current session, it is shown with
a non-blocking "couldn't refresh" indicator rather than being discarded.

FR-7. **Money formatting.** All amounts are integer minor units (`total_cents` /
`amount_cents`) carried as `Money(amountMinor, currency)` and formatted only in
the UI layer via locale-aware `NumberFormat.getCurrencyInstance`; no formatting
happens in the data layer and no floating-point money is introduced.
**[CORRECTED]** Since the bulk batch object has no `currency` field, default the
`Money.currency` to `"USD"` (matching the web `fmtCents`, which hard-codes `$`).

FR-8. **Navigation.** Add typed Navigation-Compose routes `bulkPayouts` (list)
and `bulkPayoutDetail/{batchId}` to the payouts nav graph, with an entry point
reachable from the Payouts area.

## 4. Technical Design

### Network additions (`core-network`)

Add bulk read methods to a `BulkPayoutsApi` (kept separate from AND-258's
`PayoutsApi` for cohesion; both are created from the same shared `Retrofit`):

**[CORRECTED]** Paths are the admin `/ui/admin/bulk-payouts/...` routes; the list
returns a bare array (no page wrapper, no query params) and the detail returns the
batch with embedded items (no separate items endpoint):

```kotlin
package com.testlogon.android.core.network.payouts

interface BulkPayoutsApi {
    // Returns a bare JSON array of batches; no cursor/limit params.
    @GET("ui/admin/bulk-payouts/batches")
    suspend fun getBatches(): List<PayoutBatchDto>

    // Returns the full batch including its embedded line items.
    @GET("ui/admin/bulk-payouts/batches/{batchId}")
    suspend fun getBatch(@Path("batchId") batchId: String): PayoutBatchDto
}
```

DTOs (`core-network`) — mirror OpenAPI `BulkBatchOut` / `BulkBatchItem` exactly
(`PayoutDto`/`PayoutPageDto` from AND-258 are **not** used here):

```kotlin
// Mirrors components.schemas.BulkBatchOut
@JsonClass(generateAdapter = true)
data class PayoutBatchDto(
    @Json(name = "batch_id") val batchId: String,
    @Json(name = "kind") val kind: String,
    @Json(name = "status") val status: String,
    @Json(name = "item_count") val itemCount: Int = 0,
    @Json(name = "total_cents") val totalCents: Long = 0L,
    @Json(name = "success_count") val successCount: Int = 0,
    @Json(name = "failure_count") val failureCount: Int = 0,
    @Json(name = "created_at") val createdAtEpoch: Long? = null, // integer epoch
    @Json(name = "created_by") val createdBy: String? = null,
    @Json(name = "items") val items: List<PayoutBatchItemDto> = emptyList(),
)

// Mirrors components.schemas.BulkBatchItem
@JsonClass(generateAdapter = true)
data class PayoutBatchItemDto(
    @Json(name = "ref_id") val refId: String,
    @Json(name = "amount_cents") val amountCents: Long = 0L,
    @Json(name = "status") val status: String,
    @Json(name = "recipient") val recipient: String = "",
    @Json(name = "reason") val reason: String = "",
)
```

Domain models (`core-model`):

**[CORRECTED]** The domain model mirrors the real `BulkBatchOut`: id is `id`
(mapped from `batch_id`), it carries `kind`, success/failure counts (not a
`status_counts` map), the embedded line items, and an `Instant?` parsed from the
**integer epoch** `created_at`. There is no `PayoutBatchPage` (no pagination).

```kotlin
package com.testlogon.android.core.model.payout

enum class PayoutBatchStatus {
    DRAFT, PENDING, PROCESSING, COMPLETED, PARTIALLY_FAILED, FAILED, CANCELED, UNKNOWN
}

data class PayoutBatch(
    val id: String,                         // from batch_id
    val kind: String,                       // "payout" | "refund" (server string)
    val status: PayoutBatchStatus,
    val itemCount: Int,
    val total: Money,                       // Money(totalCents, "USD"); from AND-258
    val successCount: Int,
    val failureCount: Int,
    val createdAt: Instant?,                // parsed from integer epoch created_at
    val items: List<PayoutBatchItem>,       // embedded line items
)

data class PayoutBatchItem(
    val refId: String,
    val amount: Money,                      // Money(amountCents, "USD")
    val status: PayoutStatus,               // reuse AND-258 PayoutStatus
    val recipient: String,
    val reason: String,
)
```

Mappers (`core-network`, pure, package-internal — same style as AND-258):

**[CORRECTED]** Maps the real fields: `batch_id`→`id`, `total_cents`→`Money(_, "USD")`,
success/failure counts, embedded items, and `created_at` (integer epoch seconds)→
`Instant`. No `currency` field exists, so `"USD"` is the constant default.

```kotlin
internal fun PayoutBatchDto.toDomain(): PayoutBatch = PayoutBatch(
    id = batchId,
    kind = kind,
    status = status.toPayoutBatchStatus(),
    itemCount = itemCount,
    total = Money(totalCents, "USD"),
    successCount = successCount,
    failureCount = failureCount,
    createdAt = createdAtEpoch?.let { Instant.ofEpochSecond(it) }, // epoch-int, NOT ISO
    items = items.map { it.toDomain() },
)

internal fun PayoutBatchItemDto.toDomain(): PayoutBatchItem = PayoutBatchItem(
    refId = refId,
    amount = Money(amountCents, "USD"),
    status = status.toPayoutStatus(),       // reuse AND-258 String?.toPayoutStatus()
    recipient = recipient,
    reason = reason,
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

**[CORRECTED]** Both endpoints return whole collections, so the repository uses
two simple suspend `ApiResult<T>` methods — **no Paging 3, no `PagingSource`s**.
Line items are obtained from the batch detail (`getBatch`) result, not a separate
call:

```kotlin
package com.testlogon.android.core.data.payouts

interface BulkPayoutsRepository {
    suspend fun getBatches(): ApiResult<List<PayoutBatch>>
    suspend fun getBatch(batchId: String): ApiResult<PayoutBatch>
}

class DefaultBulkPayoutsRepository @Inject constructor(
    private val api: BulkPayoutsApi,
) : BulkPayoutsRepository {

    override suspend fun getBatches(): ApiResult<List<PayoutBatch>> =
        apiCall { api.getBatches().map { it.toDomain() } }

    override suspend fun getBatch(batchId: String): ApiResult<PayoutBatch> =
        apiCall { api.getBatch(batchId).toDomain() }
}
```

`apiCall { }` (from AND-258) wraps both calls, applies the shared idempotent-GET
retry/timeout, and maps `HttpException`/`IOException`/FastAPI `detail` into
`ApiResult.Error`. The detail screen's line-item list is simply
`PayoutBatch.items` from the `getBatch` success.

### ViewModel + UiState (`feature-payouts`)

**[CORRECTED]** Both screens use plain `StateFlow<UiState>` (no `LazyPagingItems`).
The detail `Content` carries the full batch including its embedded `items`, so the
detail screen needs no second data source. The list `Content` carries the whole
`List<PayoutBatch>`; Empty is `Content(emptyList())` or a dedicated Empty case.

```kotlin
package com.testlogon.android.feature.payouts.bulk

sealed interface BulkListUiState {
    data object Loading : BulkListUiState
    data object Empty : BulkListUiState
    data class Content(val batches: List<PayoutBatch>, val stale: Boolean = false) : BulkListUiState
    data class Error(val message: String, val canRetry: Boolean = true) : BulkListUiState
}

sealed interface BulkBatchDetailUiState {
    data object Loading : BulkBatchDetailUiState
    data class Content(val batch: PayoutBatch) : BulkBatchDetailUiState   // includes items
    data class Error(val message: String, val canRetry: Boolean = true) : BulkBatchDetailUiState
}

@HiltViewModel
class BulkPayoutsViewModel @Inject constructor(
    private val repo: BulkPayoutsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val _list = MutableStateFlow<BulkListUiState>(BulkListUiState.Loading)
    val list: StateFlow<BulkListUiState> = _list.asStateFlow()

    private val batchId: String = checkNotNull(savedStateHandle["batchId"])
    private val _detail = MutableStateFlow<BulkBatchDetailUiState>(BulkBatchDetailUiState.Loading)
    val detail: StateFlow<BulkBatchDetailUiState> = _detail.asStateFlow()

    init { loadBatches(); loadBatch() }

    fun loadBatches() = viewModelScope.launch {
        // Preserve prior content for the offline/stale path (FR-6).
        val prior = (_list.value as? BulkListUiState.Content)?.batches
        if (prior == null) _list.value = BulkListUiState.Loading
        _list.value = when (val r = repo.getBatches()) {
            is ApiResult.Success ->
                if (r.data.isEmpty()) BulkListUiState.Empty
                else BulkListUiState.Content(r.data)
            is ApiResult.Error ->
                if (prior != null) BulkListUiState.Content(prior, stale = true)
                else BulkListUiState.Error(r.message)
        }
    }

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
  collects `vm.list.collectAsStateWithLifecycle()` and renders Loading/Empty/Error
  full-screen, or a `LazyColumn` of `BatchRow` composables for `Content`. When
  `Content.stale` is true, a non-blocking "couldn't refresh" banner is shown over
  the retained rows (FR-6). **[CORRECTED]** No `LazyPagingItems`/append footer —
  the list is loaded whole.
- `BulkPayoutDetailScreen(vm: BulkPayoutsViewModel)` collects
  `vm.detail.collectAsStateWithLifecycle()` and, for `Content`, renders the header
  (roll-up: `total_cents`, `item_count`, `success_count`/`failure_count`, `kind`,
  status chip) followed by a `LazyColumn` of `BatchItemRow` over
  `batch.items`. **[CORRECTED]** Header and items come from one response, so there
  is a single Loading/Error state for the detail; there is no independent items
  failure path.
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
cookie jar + `X-CSRF-Token` (AND-027; verified `credentials: "include"` +
`ui_csrf`→`X-CSRF-Token` in `src/api/client.ts`). Paths/shapes below are verified
against `/openapi.json` and `bulkPayoutTools.ts`. **The two endpoints this ticket
calls are GET (read-only).** The web `bulkPayoutTools` object also exposes
`listEligible` (GET), `preview` (POST), and `execute` (POST); the POST mutators
and the `eligible` view are **out of scope** for this read ticket.

`GET /ui/admin/bulk-payouts/batches` → 200 (**bare array**, no query params):

```json
[
  {
    "batch_id": "bat_77",
    "kind": "payout",
    "status": "completed",
    "item_count": 128,
    "total_cents": 5764500,
    "success_count": 124,
    "failure_count": 4,
    "created_at": 1748729400,
    "created_by": "admin_42",
    "items": []
  }
]
```

`GET /ui/admin/bulk-payouts/batches/{batchId}` → 200: a single `BulkBatchOut`
identical in shape, **with its `items` array populated** (`BulkBatchItem[]`):

```json
{
  "batch_id": "bat_77",
  "kind": "payout",
  "status": "completed",
  "item_count": 128,
  "total_cents": 5764500,
  "success_count": 124,
  "failure_count": 4,
  "created_at": 1748729400,
  "created_by": "admin_42",
  "items": [
    {
      "ref_id": "po_5501",
      "amount_cents": 4500,
      "status": "paid",
      "recipient": "creator_88",
      "reason": ""
    }
  ]
}
```

Field notes (verified against `components.schemas.BulkBatchOut` / `BulkBatchItem`):
required batch fields are `batch_id`, `created_at`, `kind`, `status`, `item_count`,
`total_cents`; `created_at` is an **integer epoch** (not ISO); `success_count` /
`failure_count` default `0`; **no `currency`, no `label`, no `status_counts`, no
`next_cursor`/`total`**. Each item requires `ref_id`, `amount_cents`, `status`;
`recipient` / `reason` default `""`.

Error responses (FastAPI): 401 handled by the AND-027 refresh-once interceptor
before reaching the repo; **422** `{"detail":[{"loc":[...],"msg":"...","type":"..."}]}`
is the only declared error on `getBatch` (`HTTPValidationError`); a `404` for an
unknown `batch_id` is **not declared in the OpenAPI** and is an unverified runtime
assumption — handle a generic non-2xx defensively rather than assuming a fixed
`{"detail":"Batch not found"}` body; 5xx / connection failure → mapped to
`ApiResult.Error` via the shared mapper. **No POST/PUT/PATCH/DELETE is called by
this ticket.**

## 6. Data & State Management

- **No persistent state.** This ticket adds no Room table and no DataStore key.
  Bulk read data lives in memory only for the session; the VM holds the last
  successful `List<PayoutBatch>` / `PayoutBatch` in `StateFlow`s so configuration
  changes and back-navigation within the screen do not re-fetch. (A Room-backed
  cache for bulk history is a deliberate future enhancement, not in scope.)
- **[CORRECTED] List state** is an explicit `BulkListUiState` `StateFlow`
  (Loading/Empty/Content/Error, plus a `stale` flag on Content) — **not** Paging 3
  `LazyPagingItems.loadState`, because the endpoint is not paged.
- **Detail state** is the explicit `BulkBatchDetailUiState` `StateFlow`
  (Loading/Content/Error). **[CORRECTED]** Header and line items load together from
  a single `getBatch` response, so there is no separate items stream and no
  independent items failure.
- **Money** is carried as `Money(amountMinor, currency)` end-to-end with
  `currency = "USD"` (no server currency field); the UI is the only place a
  formatted string is produced, via `NumberFormat.getCurrencyInstance(locale)`.
- **[CORRECTED] Roll-up** is rendered from scalar `success_count` / `failure_count`
  / `item_count` on the batch, not a `Map<PayoutStatus, Int>` (no such map exists
  in the contract).

## 7. Error Handling & Resilience

- **[CORRECTED]** Both calls (`getBatches`, `getBatch`) are idempotent GETs and opt
  into the network core's **bounded backoff retry** (max ~2 retries, jittered) for
  transient `IOException`/timeout/5xx — appropriate for the unreliable dev host.
  (There is no third `/items` call.)
- Per-request timeout follows the global ~20s call timeout on the shared OkHttp
  client (AND-027); this ticket does not override it.
- 401 is resolved upstream by the single refresh-then-retry interceptor; the repo
  only sees auth failure if refresh itself fails, surfaced as `ApiResult.Error`
  for the screen to show an error (and the app-level auth guard from AND-025 to
  route to login).
- **[CORRECTED] No append errors** (no pagination). A **refresh error** with no
  prior data shows the full-screen `ErrorState` with retry; otherwise see the
  stale path below.
- **Offline / stale (FR-6):** if a list refresh fails but the VM still holds a
  prior successful `List<PayoutBatch>` from this session, the list is not cleared;
  `BulkListUiState.Content(prior, stale = true)` is emitted and a transient
  "Couldn't refresh" banner is shown. The detail screen, if previously `Content`,
  is retained on retry failure and the error surfaced non-destructively.
- **[CORRECTED]** Mapping is defensively null-safe per the real schema: missing
  `total_cents`/`amount_cents` → `0` minor units, currency is always `"USD"`
  (no field), missing `item_count`/`success_count`/`failure_count` → `0`, unknown
  batch/item `status` → `UNKNOWN`, missing integer `created_at` → `null` `Instant`.
  A malformed-but-structured payload never throws from a mapper; only a Moshi
  structural failure (e.g. missing required `batch_id`/`kind`/`status`) yields an
  error.
- **[CORRECTED]** An empty batch array `[]` is a valid success rendered as the
  distinct **Empty** state, not an error.

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
   with correct `Money(totalCents, "USD")`, `Instant` parsed from the integer
   epoch `created_at`, status, `successCount`/`failureCount`, and mapped embedded
   `items` (`PayoutBatchItemDto.toDomain()` → `PayoutBatchItem` with
   `Money(amountCents,"USD")` and `PayoutStatus`).
2. Every `status` variant (`draft`, `pending`, `processing`/`in_progress`,
   `completed`/`succeeded`/`paid`, `partially_failed`/`partial`, `failed`,
   `canceled`/`cancelled`) → correct enum; unknown → `PayoutBatchStatus.UNKNOWN`.
3. Null/missing `total_cents`, `item_count`, `success_count`, `failure_count`,
   `created_at`, `items` produce documented defaults (0 / null `Instant` / empty
   list) without throwing.
4. A bare-array response maps to `List<PayoutBatch>` preserving order; an empty
   array → empty list success.

Integration — MockWebServer (`core-testing`):
5. `getBatches` issues `GET /ui/admin/bulk-payouts/batches` with exact path and
   verb and **no query params** (assert recorded request).
6. `getBatch("bat_1")` hits `GET /ui/admin/bulk-payouts/batches/bat_1`; the parsed
   `PayoutBatch.items` reflects the embedded array (no second request is made).
7. 422 detail-array → `ApiResult.Error` with mapped message; a generic non-2xx
   (e.g. 404/500 body) → `ApiResult.Error` without assuming a fixed detail string.
8. 503-then-200 verifies idempotent-GET retry succeeds (request count asserted).
9. Connection failure / `IOException` → `ApiResult.Error` (offline path).

UI — Compose (`feature-payouts`, instrumented or Robolectric):
10. **List renders content:** given a fake `BulkPayoutsRepository` returning
    `ApiResult.Success(List<PayoutBatch>)`, `BulkPayoutsListScreen` displays rows
    with formatted USD amount, `kind`, and status chip (**"Bulk views render"**).
11. **List empty/error/offline:** empty list → Empty state; refresh error with no
    prior data → full-screen ErrorState with a working Retry; prior content +
    refresh error → content retained + "couldn't refresh" (`stale`) banner.
12. **Detail renders:** `BulkBatchDetailUiState.Content` shows the roll-up header
    (`total_cents`, `item_count`, `success_count`/`failure_count`, `kind`, status
    chip) and a list of `batch.items` line-item rows from the same response;
    detail error → ErrorState with retry.
13. **Navigation:** tapping a batch row invokes `onBatchClick(batchId)` with the
    correct id; detail VM reads `batchId` from `SavedStateHandle`.

Coverage target: 100% of new mapper functions and all `ApiResult` branches; all
four list states and the three detail states exercised in Compose tests.

## 12. Dependencies & Sequencing

- **Depends on AND-258 (Payouts API):** reuses `Money`/`PayoutStatus`,
  `String?.toPayoutStatus()`, `apiCall { }`, `ApiResult<T>`, and the shared
  idempotent-GET retry. Do not reimplement any of these. **[CORRECTED]** It does
  **not** reuse `PayoutDto`/`PayoutPageDto` or AND-258's cursor pagination (bulk
  uses the distinct embedded `BulkBatchItem` shape and is not paged).
- **Depends transitively on AND-027** (authenticated Retrofit/OkHttp stack,
  cookie jar, CSRF + 401-refresh interceptors, FastAPI error mapper) and on the
  M1 core-network bootstrap (`Retrofit` `@Provides`, base-URL config) and the
  shared `core-ui` list-state/chips and `core-testing` MockWebServer harness.
- **Blocks:** none today; a future **bulk payout write/actions** ticket (batch
  create/approve/cancel/retry) will build on these read views and own all
  mutating endpoints, DTOs, and confirmation UI.
- Sequencing within the ticket: confirm live shapes via `/openapi.json` +
  `bulkPayoutTools.ts` → DTOs + Moshi adapters → domain models + mappers + unit
  tests → `BulkPayoutsApi` + MockWebServer tests → repository
  (`ApiResult` methods, **no `PagingSource`s**) + tests → ViewModel + UiState →
  Compose screens + navigation + UI tests.

## 13. Risks & Open Questions

- **R1 — Endpoint paths/params. [RESOLVED]** Confirmed against `/openapi.json` and
  `bulkPayoutTools.ts`: list = `GET /ui/admin/bulk-payouts/batches` (bare array, no
  params), detail = `GET /ui/admin/bulk-payouts/batches/{batchId}` (full batch with
  embedded `items`). There is **no** items endpoint and **no** cursor pagination.
- **R2 — Batch status vocabulary. [PARTIALLY OPEN]** OpenAPI types `status` as a
  free-form `string` with no enum, so the authoritative value set is still
  unconfirmed; `UNKNOWN` prevents crashes. The mapper's `lowercase()` mapping is a
  best-effort guess; observed live values should be reconciled and the enum
  extended if needed. **Open:** enumerate real server status strings from live data.
- **R3 — Roll-up source. [RESOLVED]** The batch object carries `item_count`,
  `total_cents`, `success_count`, `failure_count` directly; line items are embedded
  in `items`. No client-side computation from a separate items page is needed.
- **R4 — "Bulk tools" surface. [RESOLVED]** `bulkPayoutTools.ts` exposes
  `listEligible` (GET, read), `preview`/`execute` (POST, write), `listBatches`
  (GET, read), `getBatch` (GET, read). This ticket scopes to the two read
  **batch** views (`listBatches` + `getBatch`); the `eligible` read view and all
  preview/execute writes are deferred to the future bulk-write ticket. **Open:**
  decide whether the read-only `eligible` list deserves its own follow-up read
  ticket.
- **R5 — Dev host flakiness** may make MockWebServer the only reliable test
  surface — acceptable, since acceptance is "views render" against fake/mocked
  data, not live connectivity.

## 14. Acceptance Criteria

1. `BulkPayoutsApi`, the new DTOs (`PayoutBatchDto`/`PayoutBatchItemDto`),
   `PayoutBatch`/`PayoutBatchItem`/`PayoutBatchStatus` domain models, mappers,
   `BulkPayoutsRepository` (two suspend `ApiResult` methods — **no** Paging
   sources), `BulkPayoutsViewModel`/`BulkListUiState`/`BulkBatchDetailUiState`, the
   two Compose screens, navigation routes, and Hilt modules exist under
   `com.testlogon.android.{feature.payouts.bulk, core.network/data/model.payout(s)}`
   on `android-port`, with correct module layering and **no mutating endpoints**.
2. **Bulk views render:** the list screen displays batches loaded from
   `GET /ui/admin/bulk-payouts/batches`; tapping a batch opens the detail screen
   rendering the roll-up header and the **embedded** line items returned by
   `GET /ui/admin/bulk-payouts/batches/{batchId}` — proven by Compose tests
   against a fake repository.
3. **[CORRECTED]** Neither view is paginated (the contract has no cursor); both
   render the full server collection in a plain `LazyColumn`.
4. Loading, Empty, Error, and offline/stale states render correctly on both
   screens; full-screen errors are retryable and mapped through the shared FastAPI
   `detail` mapper.
5. Monetary values are `Money(amountMinor: Long, currency: String)` end-to-end
   (`currency = "USD"`, no server field) and formatted only in the UI via
   locale-aware `NumberFormat`; no floating-point money anywhere.
6. `status` (batch + per-item) maps to enums with `UNKNOWN` fallbacks; no
   unrecognized server string throws.
7. Both network calls are GETs, carry session cookies + `X-CSRF-Token` via the
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend =
`reference/src/...`.

1. **Bulk endpoints live under `/ui/admin/bulk-payouts`, not `/ui/payouts/bulk`.**
   VERDICT: Corrected. SOURCE: `src/api/endpoints/bulkPayoutTools.ts` (`BASE =
   "/ui/admin/bulk-payouts"`); OpenAPI `GET /ui/admin/bulk-payouts/batches`
   (op `bulk_list_batches_...`).
2. **Batch list = `GET /ui/admin/bulk-payouts/batches`, returns a bare JSON array
   of `BulkBatchOut` with no query params (no cursor/limit).** VERDICT: Corrected.
   SOURCE: `bulkPayoutTools.ts: listBatches` (`api.get<BulkBatchOut[]>(\`${BASE}/batches\`)`,
   no args); OpenAPI `GET /ui/admin/bulk-payouts/batches` 200 schema = `type: array,
   items: $ref BulkBatchOut`, `params=` empty.
3. **Batch detail = `GET /ui/admin/bulk-payouts/batches/{batch_id}`, returns one
   `BulkBatchOut` with its line items embedded in `items`.** VERDICT: Corrected.
   SOURCE: `bulkPayoutTools.ts: getBatch`; OpenAPI `GET
   /ui/admin/bulk-payouts/batches/{batch_id}` 200 = `$ref BulkBatchOut`;
   `components.schemas.BulkBatchOut.items` = array of `BulkBatchItem`.
4. **No separate `/items` endpoint and no cursor pagination on any bulk endpoint.**
   VERDICT: Corrected (spec claimed `GET /ui/payouts/bulk/{batchId}/items` + Paging
   3 with `nextCursor`). SOURCE: OpenAPI index has no `bulk-payouts/.../items`
   route; neither `BulkBatchOut` nor the list response declares `next_cursor`/`total`;
   `BulkPayoutConsole.tsx: openDetail` renders `detail.items` from `getBatch`.
5. **Batch field names: `batch_id`, `kind`, `status`, `item_count`, `total_cents`,
   `success_count`, `failure_count`, `created_at` (integer epoch), `created_by`,
   `items`.** VERDICT: Corrected (spec used `id`, `label`, `total_amount`,
   `currency`, `status_counts`, ISO `created_at`). SOURCE:
   `components.schemas.BulkBatchOut` (required: `batch_id, created_at, kind, status,
   item_count, total_cents`; `created_at` `type: integer`).
6. **Batch object has no `currency` and no `label`.** VERDICT: Corrected. SOURCE:
   `components.schemas.BulkBatchOut` (no such properties); `BulkPayoutConsole.tsx:
   fmtCents` hard-codes `$` and `/100`.
7. **Roll-up is scalar `success_count`/`failure_count`, not a `status_counts`
   map.** VERDICT: Corrected. SOURCE: `components.schemas.BulkBatchOut`
   (`success_count`/`failure_count`, default 0); `BulkPayoutConsole.tsx` detail
   drawer renders `detail.success_count` / `detail.failure_count`.
8. **Line item shape `BulkBatchItem` = `ref_id`, `amount_cents`, `status`,
   `recipient` (default ""), `reason` (default "").** VERDICT: Corrected (spec
   reused AND-258 `PayoutDto`: `amount`, `method_id`, `arrival_at`,
   `failure_reason`). SOURCE: `components.schemas.BulkBatchItem` (required:
   `ref_id, amount_cents, status`).
9. **`getBatch` declares only 422 (`HTTPValidationError`); 404 with a fixed
   `{"detail":"Batch not found"}` body is NOT in the contract.** VERDICT: Corrected
   to unverified-assumption. SOURCE: OpenAPI `GET
   /ui/admin/bulk-payouts/batches/{batch_id}` responses = `200`, `422` only.
10. **Auth is cookie-based with `ui_csrf` cookie copied to `X-CSRF-Token`.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`credentials: "include"`;
    `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
11. **All this ticket's calls are GET (read-only); the web file also has POST
    `preview`/`execute` and GET `eligible`, which are out of scope.** VERDICT:
    Verified. SOURCE: `bulkPayoutTools.ts` (`api.post` for `preview`/`execute`);
    OpenAPI `POST /ui/admin/bulk-payouts/preview` / `.../execute`.
12. **AND-258's cursor pagination pattern is real for `/ui/payouts` but does not
    apply here.** VERDICT: Verified. SOURCE: `src/api/endpoints/payouts.ts:
    listPayouts` (`limit`/`cursor` params); contrast item 2.
13. **`Money(amountMinor: Long, currency)` modeling with UI-only formatting.**
    VERDICT: Verified (design choice, consistent with integer `*_cents` fields in
    the schema and AND-258). SOURCE: `components.schemas.BulkBatchOut.total_cents`
    / `BulkBatchItem.amount_cents` (`type: integer`).
14. **`PayoutBatchStatus` enum membership / status string vocabulary.** VERDICT:
    Unverified-assumption. SOURCE: `components.schemas.BulkBatchOut.status` is a
    free-form `type: string` with no enum constraint; the mapper's string set is a
    guess.
15. **Plain `LazyColumn` (no Paging 3 / `LazyPagingItems`) for both screens.**
    VERDICT: Corrected design consequence of items 2 & 4. SOURCE (framework ref):
    Compose lists — https://developer.android.com/develop/ui/compose/lists ;
    `collectAsStateWithLifecycle` — https://developer.android.com/topic/libraries/architecture/coroutines#statflow .

### Corrections made

- §1, §2, §3, §4, §5, §6, §7, §11, §12, §13, §14: endpoint paths changed from
  `/ui/payouts/bulk*` to `/ui/admin/bulk-payouts/batches[/{id}]`.
- Removed the non-existent `GET .../items` endpoint; line items now read from the
  embedded `BulkBatchOut.items`.
- Removed cursor pagination / Paging 3 / `PagingSource`s / `nextCursor` / page
  DTOs throughout; list and detail use plain `ApiResult` + `StateFlow` +
  `LazyColumn`. Added `BulkListUiState`.
- Renamed/retyped DTO + domain fields to the real schema: `id`→`batch_id`,
  `total_amount`+`currency`→`total_cents` (USD constant), `status_counts` map →
  scalar `success_count`/`failure_count`, added `kind`, `created_at` ISO→integer
  epoch, replaced reuse of `PayoutDto` with `BulkBatchItemDto`/`PayoutBatchItem`.
- Error contract: 404-with-fixed-body claim downgraded to a defensive non-2xx case;
  only 422 is declared.
- §13 R1/R3/R4 marked resolved; R2 narrowed to the unconstrained status string.

### Open assumptions

- **Status vocabulary (R2):** `status` is an unconstrained string in OpenAPI; the
  batch/item status→enum maps are best-effort. Why unverifiable: no enum in the
  schema and no fixtures in the reference sources. Reconcile against live data.
- **404 on unknown `batch_id`:** not in the OpenAPI for `getBatch`; FastAPI may
  return 404 at runtime but the body is unconfirmed. Handle generically.
- **Currency:** assumed USD because no `currency` field exists and the web hard-codes
  `$`. If multi-currency batches appear, the model needs a currency source.
- **Ordering of the batch list:** the array order is server-defined; "newest first"
  is not guaranteed by the contract (no sort field documented).
- **Admin authorization:** these are `admin-bulk-payouts`-tagged routes; whether the
  Android app's current session is authorized (vs. needing an admin role/gate) is
  not verifiable from the sources and must be confirmed before wiring a nav entry.

## 17. Test Plan

IDs `TC-AND-261-NN`. "AC-#" traces to §14 Acceptance Criteria. Default target is
JVM/Robolectric unless a case needs a device; UI cases run on the **headless
emulator AVD `test35`** (API 35) in CI. None of these cases require the physical
Samsung A15 (no camera/biometrics/FCM/WebRTC/Telecom/streaming/ABI-specific
behavior is involved); the device is noted only where ABI/API-level parity is
worth a spot-check.

- **TC-AND-261-01 — Batch DTO maps fully populated fixture.** Type: unit (JVM).
  Target: `PayoutBatchDto.toDomain()` (core-network). Preconditions: JSON fixture
  matching `BulkBatchOut` with non-empty `items`. Steps: parse via Moshi, call
  `toDomain()`. Expected: `id==batch_id`, `total==Money(total_cents,"USD")`,
  `createdAt==Instant.ofEpochSecond(created_at)`, `successCount`/`failureCount`/
  `itemCount` correct, `items` mapped to `PayoutBatchItem` with
  `Money(amount_cents,"USD")` + mapped `PayoutStatus`. Traces: AC-1, AC-5.

- **TC-AND-261-02 — Status string → enum table.** Type: unit (JVM). Target:
  `String?.toPayoutBatchStatus()`. Preconditions: none. Steps: feed each documented
  variant + an unknown value + null. Expected: each maps to the documented enum;
  unknown/null → `UNKNOWN`; no throw. Traces: AC-6.

- **TC-AND-261-03 — Null/missing fields default safely.** Type: unit (JVM). Target:
  `PayoutBatchDto.toDomain()` / `PayoutBatchItemDto.toDomain()`. Preconditions:
  fixture omitting `total_cents`, `item_count`, `success_count`, `failure_count`,
  `created_at`, `items`, item `recipient`/`reason`. Steps: parse + map. Expected:
  zeros, `null` `Instant`, empty `items`, empty strings; no exception. Traces: AC-6.

- **TC-AND-261-04 — List maps bare array; empty array preserved.** Type: unit
  (JVM). Target: repo mapping of `List<PayoutBatchDto>`. Preconditions: a 2-element
  array fixture and an empty `[]` fixture. Steps: map both. Expected: order
  preserved for the 2-element case; `[]` → empty list success (no error). Traces:
  AC-2, AC-3.

- **TC-AND-261-05 — `getBatches` hits exact path/verb with no query params.**
  Type: contract/MockWebServer. Target: `BulkPayoutsApi.getBatches`. Preconditions:
  MockWebServer enqueues a 200 array body. Steps: call `getBatches()`; inspect
  `RecordedRequest`. Expected: `GET /ui/admin/bulk-payouts/batches`, no `?` query
  string; body parses to `List<PayoutBatch>`. Traces: AC-2, AC-7.

- **TC-AND-261-06 — `getBatch` hits exact path; items come from one response.**
  Type: contract/MockWebServer. Target: `BulkPayoutsApi.getBatch`. Preconditions:
  200 `BulkBatchOut` with a populated `items` array. Steps: call `getBatch("bat_1")`;
  inspect requests. Expected: exactly one `GET
  /ui/admin/bulk-payouts/batches/bat_1`; resulting `PayoutBatch.items` reflects the
  embedded array; **no** second request to any `/items` path. Traces: AC-2.

- **TC-AND-261-07 — 422 validation error mapped to `ApiResult.Error`.** Type:
  contract/MockWebServer. Target: `DefaultBulkPayoutsRepository.getBatch`.
  Preconditions: enqueue 422 with `HTTPValidationError` `detail` array. Steps: call
  `getBatch`. Expected: `ApiResult.Error` with a message mapped from the shared
  FastAPI `detail` mapper; no crash. Traces: AC-4.

- **TC-AND-261-08 — Generic non-2xx (e.g. 404/500) mapped without assuming a fixed
  body.** Type: contract/MockWebServer. Target: repo `getBatch`. Preconditions:
  enqueue 404 (arbitrary/empty body) then a 500. Steps: call twice. Expected: both
  → `ApiResult.Error`; the code does not depend on a `{"detail":"Batch not found"}`
  literal. Traces: AC-4.

- **TC-AND-261-09 — Idempotent-GET retry: 503-then-200 succeeds.** Type:
  contract/MockWebServer. Target: shared retry + `getBatches`. Preconditions:
  enqueue 503 then 200 array. Steps: call `getBatches()`; assert request count ==
  2. Expected: `ApiResult.Success`; exactly one retry consumed. Traces: AC-7.

- **TC-AND-261-10 — Offline → Error / stale retention.** Type: unit (JVM,
  ViewModel + fake repo) plus Compose assertion. Target: `BulkPayoutsViewModel.
  loadBatches` + `BulkPayoutsListScreen`. Preconditions: fake repo returns
  `ApiResult.Error` (IOException) first with no prior data, then a Success, then an
  Error again. Steps: (a) initial load fails → assert `BulkListUiState.Error`; (b)
  reload succeeds → `Content`; (c) reload fails → `Content(prior, stale=true)`.
  Expected: full-screen Error when no prior data; retained rows + "couldn't
  refresh" banner when prior data exists. Traces: AC-4.

- **TC-AND-261-11 — List renders content ("Bulk views render").** Type: Compose-UI
  (emulator `test35` or Robolectric). Target: `BulkPayoutsListScreen`.
  Preconditions: fake repo → `Content` of 2 batches. Steps: set content; assert.
  Expected: 2 `BatchRow`s showing `kind`, status chip, item count, and USD-formatted
  `total_cents`; tapping a row triggers nav callback. Traces: AC-2.

- **TC-AND-261-12 — List Empty state.** Type: Compose-UI. Target:
  `BulkPayoutsListScreen`. Preconditions: fake repo → `Empty`. Steps: set content.
  Expected: distinct Empty copy (no rows, no error). Traces: AC-4.

- **TC-AND-261-13 — Detail renders header + embedded items; error retryable.**
  Type: Compose-UI. Target: `BulkPayoutDetailScreen`. Preconditions: fake VM emits
  `BulkBatchDetailUiState.Content` (batch with 3 items), then `Error`. Steps:
  assert header shows `total_cents` (USD), `item_count`, `success_count`/
  `failure_count`, `kind`, status chip, and 3 `BatchItemRow`s; switch to Error →
  ErrorState with working Retry that re-invokes `loadBatch`. Traces: AC-2, AC-4.

- **TC-AND-261-14 — Read-only: no mutating affordance, only GETs.** Type:
  integration (MockWebServer + screen interaction). Target: both screens + API.
  Preconditions: dispatcher recording all requests. Steps: open list, open detail,
  exercise retry. Expected: every recorded request is a `GET` under
  `/ui/admin/bulk-payouts/batches`; no `preview`/`execute`/POST and no
  create/cancel UI exists. Traces: AC-1, AC-7.

- **TC-AND-261-15 — Accessibility / semantics on rows.** Type: Compose-UI
  (accessibility). Target: `BatchRow` / `BatchItemRow`. Preconditions: `Content`
  fixture. Steps: assert merged `contentDescription` combines label/kind/status/
  count/amount; status chip has a text equivalent (not color-only); touch target
  ≥ 48dp; amount not truncated at large font scale. Expected: TalkBack reads a
  coherent summary; checks pass. Traces: AC-2 (and §9).

- **TC-AND-261-16 — No payout PII in release logs.** Type: instrumented (release
  config). Target: OkHttp logging for `payouts_bulk` route. Preconditions: release
  build variant. Steps: trigger `getBatch` with a fixture; capture logcat. Expected:
  no `total_cents`/`amount_cents`/`recipient`/`reason`/`batch_id` body content
  emitted; interceptor at `NONE`/redacted. Traces: AC-9. Note: run on the headless
  emulator; optionally spot-check on the physical A15 (arm64, API 34) to confirm no
  ABI/API-level logging difference.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (artifacts exist, layering, no mutating endpoints) | TC-01, TC-14 |
| AC-2 (bulk views render: list + detail from real paths) | TC-04, TC-05, TC-06, TC-11, TC-13, TC-15 |
| AC-3 (no pagination; full collection rendered) | TC-04, TC-11 |
| AC-4 (Loading/Empty/Error/offline-stale, retryable) | TC-07, TC-08, TC-10, TC-12, TC-13 |
| AC-5 (Money minor-units, UI-only formatting) | TC-01, TC-11, TC-13 |
| AC-6 (status→enum with UNKNOWN, no throw) | TC-02, TC-03 |
| AC-7 (GET + cookies/CSRF + idempotent retry) | TC-05, TC-09, TC-14 |
| AC-8 (unit + MockWebServer + Compose tests present) | TC-01…TC-13 |
| AC-9 (no PII in logs; analytics carry no amounts) | TC-16 |
