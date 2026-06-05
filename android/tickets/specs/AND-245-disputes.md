---
id: AND-245
title: Disputes
milestone: M5
epic: E33
priority: P2
size: M
status: draft
depends_on: [AND-223]
blocks: []
---

# AND-245 — Disputes

## 1. Overview & Goal

This ticket delivers the **Disputes** surface for the TestLogon native Android
port: a read-oriented feature that lets a signed-in user view the billing
disputes (chargebacks) raised against their account, browse them in a paged
list, and drill into a detail screen showing the dispute reason, amount, status,
evidence-submission deadline, and the related invoice/charge.

The scope, per the backlog, is the Android equivalent of the web reference layer
`frontend/src/api/endpoints/billingDisputes.ts` — **list and detail**. Concretely
this ticket produces, end to end within `feature-billing`:

1. A `DisputesApi` Retrofit service plus Moshi DTOs and `core-model` domain types
   for the `/ui/billing/disputes` list and `/ui/billing/disputes/{id}` detail
   endpoints, with total `toDomain()` mappers.
2. A `DisputesRepository` and a Paging 3 `PagingSource` over the cursor-paged
   list, exposed through `core-data`.
3. Two Compose Material 3 screens — `DisputesListScreen` and
   `DisputeDetailScreen` — each driven by a `StateFlow<UiState>` from a Hilt
   ViewModel, wired into the single-Activity Navigation-Compose graph.

The acceptance bar from the backlog is intentionally minimal — **"Disputes
render."** Success means: given a signed-in session, the list screen renders real
disputes returned by the backend (with loading / empty / error / offline states),
and tapping a row renders the corresponding detail screen. This ticket is
explicitly **read-only**: it does not implement evidence upload or dispute
response submission (called out as out of scope in section 3).

Disputes reuses the billing network/auth/error foundations frozen by AND-223 and
the cookie session from AND-027 (inherited transitively); it adds no new auth
surface.

## 2. Context & References

- **Package base:** `com.testlogon.android`. New code lives under
  `com.testlogon.android.feature.billing.disputes` (UI + ViewModels),
  `com.testlogon.android.core.network.billing.disputes` (API + DTOs),
  `com.testlogon.android.core.model.billing` (domain types, alongside AND-223's
  `Invoice`/`Money`), and `com.testlogon.android.core.data.billing` (repository +
  PagingSource).
- **Module layering:** `app -> feature-billing -> core-data -> core-network ->
  core-model`. `feature-billing` also depends on `core-ui` (theme, shared
  composables) and `core-testing`.
- **Web reference (authoritative for shapes):**
  - `frontend/src/api/endpoints/billingDisputes.ts` — endpoint paths, verbs,
    query params, and field names for the dispute list/detail.
  - `frontend/src/api/types.ts` — shared `Dispute`/`DisputeStatus` TypeScript
    types; Kotlin DTOs must be field-name-equivalent.
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json` — fetch the live dispute
  schema fragments to confirm field nullability and enum members before
  finalizing DTOs. Where OpenAPI and `types.ts` disagree, prefer OpenAPI and file
  an Open Question (section 13).
- **Dependency AND-223 (Billing API + DTOs):** provides the authenticated
  `Retrofit` singleton, the `Money` value type, `Instant` timestamp handling, the
  `toInstantOrNull()` helper, the `ApiResult<T>` type, the shared FastAPI error
  mapper, and the cursor-pagination conventions (`InvoicePageDto.nextCursor`).
  This ticket follows AND-223's DTO/mapper patterns verbatim and reuses its
  `Invoice` model for the linked-invoice reference.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP),
  Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Paging 3, Coil
  (status/brand icons only). minSdk 24 / compileSdk 35, JDK 17, AGP 8.7.3,
  Gradle 8.9, branch `android-port`.

## 3. Functional Requirements

FR-1. Expose a `DisputesApi` Retrofit interface with `suspend` functions for the
list (`GET /ui/billing/disputes`) and detail (`GET /ui/billing/disputes/{id}`)
endpoints (section 5), returning DTOs that the repository maps to domain models.

FR-2. Provide Moshi `@JsonClass(generateAdapter = true)` DTOs for the dispute
page, dispute summary, and dispute detail, plus total `toDomain()` mappers:
unknown status/reason strings → `UNKNOWN`, unparseable timestamps → `null`,
missing collections → empty list.

FR-3. The list screen presents disputes newest-first, paged with Paging 3 over
the backend cursor (`next_cursor`). Each row shows the disputed amount
(locale-formatted), counterparty/reason, status chip, and opened date.

FR-4. The list screen renders distinct states: initial **loading** (shimmer/
spinner), **content** (paged), **empty** ("No disputes" with explanatory copy),
**error** (with retry), and **offline/stale** (banner + cached content if any).

FR-5. Tapping a list row navigates to `DisputeDetailScreen` for that dispute id,
which renders: status, reason, amount + currency, opened/`evidence_due_by` dates,
the related invoice/charge reference (deep-linkable to AND-223 invoice detail if
present), and any free-text bank/network explanation.

FR-6. The detail screen renders its own loading / content / error / not-found
(`404` → "Dispute not found") states and supports pull-to-refresh / retry.

FR-7. Status is rendered as a typed, color-coded chip via a single
`DisputeStatus -> StatusChipStyle` mapping in `core-ui`, so list and detail are
visually consistent.

FR-8. **Out of scope (deferred):** submitting evidence, accepting/contesting a
dispute, file/document upload, and any mutating call. There are **no POST/PUT**
endpoints in this ticket. A follow-up ticket (not yet filed; see OQ-3) owns
dispute response. The UI may show a disabled "Respond" affordance with a
"coming soon"/external-portal note, but performs no write.

## 4. Technical Design

### 4.1 DTO layer (`core-network`)

```kotlin
package com.testlogon.android.core.network.billing.disputes

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class DisputePageDto(
    @Json(name = "items") val items: List<DisputeSummaryDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String?,
)

@JsonClass(generateAdapter = true)
data class DisputeSummaryDto(
    @Json(name = "dispute_id") val disputeId: String,
    @Json(name = "status") val status: String,        // needs_response|under_review|won|lost|...
    @Json(name = "reason") val reason: String?,        // fraudulent|product_not_received|...
    @Json(name = "amount_minor") val amountMinor: Long,
    @Json(name = "currency") val currency: String,     // ISO-4217
    @Json(name = "opened_at") val openedAt: String?,   // ISO-8601
    @Json(name = "evidence_due_by") val evidenceDueBy: String?,
    @Json(name = "invoice_id") val invoiceId: String?,
)

@JsonClass(generateAdapter = true)
data class DisputeDetailDto(
    @Json(name = "dispute_id") val disputeId: String,
    @Json(name = "status") val status: String,
    @Json(name = "reason") val reason: String?,
    @Json(name = "amount_minor") val amountMinor: Long,
    @Json(name = "currency") val currency: String,
    @Json(name = "opened_at") val openedAt: String?,
    @Json(name = "evidence_due_by") val evidenceDueBy: String?,
    @Json(name = "invoice_id") val invoiceId: String?,
    @Json(name = "charge_id") val chargeId: String?,
    @Json(name = "network_reason_code") val networkReasonCode: String?,
    @Json(name = "explanation") val explanation: String?,
)
```

### 4.2 Domain models (`core-model`)

```kotlin
package com.testlogon.android.core.model.billing

import java.time.Instant

enum class DisputeStatus {
    NEEDS_RESPONSE, UNDER_REVIEW, WON, LOST, WARNING_CLOSED, CANCELED, UNKNOWN
}

enum class DisputeReason {
    FRAUDULENT, PRODUCT_NOT_RECEIVED, PRODUCT_UNACCEPTABLE,
    DUPLICATE, SUBSCRIPTION_CANCELED, CREDIT_NOT_PROCESSED, GENERAL, UNKNOWN
}

data class DisputeSummary(
    val disputeId: String,
    val status: DisputeStatus,
    val reason: DisputeReason,
    val amount: Money,                 // reused from AND-223
    val openedAt: Instant?,
    val evidenceDueBy: Instant?,
    val invoiceId: String?,
)

data class DisputeDetail(
    val disputeId: String,
    val status: DisputeStatus,
    val reason: DisputeReason,
    val amount: Money,
    val openedAt: Instant?,
    val evidenceDueBy: Instant?,
    val invoiceId: String?,
    val chargeId: String?,
    val networkReasonCode: String?,
    val explanation: String?,
)

data class DisputePage(val items: List<DisputeSummary>, val nextCursor: String?)
```

### 4.3 Mappers (`core-network`)

```kotlin
internal fun DisputeSummaryDto.toDomain() = DisputeSummary(
    disputeId = disputeId,
    status = status.toDisputeStatus(),
    reason = reason.orEmpty().toDisputeReason(),
    amount = Money(amountMinor, currency),
    openedAt = openedAt?.toInstantOrNull(),
    evidenceDueBy = evidenceDueBy?.toInstantOrNull(),
    invoiceId = invoiceId,
)

internal fun String.toDisputeStatus() = when (lowercase()) {
    "needs_response", "warning_needs_response" -> DisputeStatus.NEEDS_RESPONSE
    "under_review" -> DisputeStatus.UNDER_REVIEW
    "won" -> DisputeStatus.WON
    "lost" -> DisputeStatus.LOST
    "warning_closed" -> DisputeStatus.WARNING_CLOSED
    "canceled", "cancelled" -> DisputeStatus.CANCELED
    else -> DisputeStatus.UNKNOWN
}
```

`toDisputeReason()` follows the same total pattern; `toInstantOrNull()` and
`Money` are inherited from AND-223 (no re-implementation).

### 4.4 API + Hilt module (`core-network`)

```kotlin
internal interface DisputesApi {
    @GET("ui/billing/disputes")
    suspend fun getDisputes(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): DisputePageDto

    @GET("ui/billing/disputes/{disputeId}")
    suspend fun getDispute(@Path("disputeId") disputeId: String): DisputeDetailDto
}

@Module
@InstallIn(SingletonComponent::class)
internal object DisputesNetworkModule {
    @Provides @Singleton
    fun provideDisputesApi(retrofit: Retrofit): DisputesApi =
        retrofit.create(DisputesApi::class.java)
}
```

The return-type convention (`: Dto` vs `: ApiResult<Dto>`) is inherited from
AND-223/AND-027, not re-decided here.

### 4.5 Repository + Paging (`core-data`)

```kotlin
package com.testlogon.android.core.data.billing

interface DisputesRepository {
    fun disputesPager(): Flow<PagingData<DisputeSummary>>
    suspend fun getDispute(id: String): ApiResult<DisputeDetail>
}

internal class DefaultDisputesRepository @Inject constructor(
    private val api: DisputesApi,
) : DisputesRepository {

    override fun disputesPager(): Flow<PagingData<DisputeSummary>> =
        Pager(PagingConfig(pageSize = 20, enablePlaceholders = false)) {
            DisputesPagingSource(api)
        }.flow

    override suspend fun getDispute(id: String): ApiResult<DisputeDetail> =
        apiCall { api.getDispute(id).toDomain() }   // apiCall = shared ApiResult wrapper
}

internal class DisputesPagingSource(
    private val api: DisputesApi,
) : PagingSource<String, DisputeSummary>() {
    override suspend fun load(params: LoadParams<String>): LoadResult<String, DisputeSummary> =
        try {
            val page = api.getDisputes(cursor = params.key, limit = params.loadSize)
            LoadResult.Page(
                data = page.items.map { it.toDomain() },
                prevKey = null,
                nextKey = page.nextCursor,
            )
        } catch (t: Throwable) {
            LoadResult.Error(t)
        }
    override fun getRefreshKey(state: PagingState<String, DisputeSummary>) = null
}
```

### 4.6 ViewModels (`feature-billing`)

```kotlin
@HiltViewModel
class DisputesListViewModel @Inject constructor(
    repo: DisputesRepository,
) : ViewModel() {
    val disputes: Flow<PagingData<DisputeSummary>> =
        repo.disputesPager().cachedIn(viewModelScope)
}

@HiltViewModel
class DisputeDetailViewModel @Inject constructor(
    private val repo: DisputesRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val disputeId: String = checkNotNull(savedState["disputeId"])
    private val _state = MutableStateFlow<DisputeDetailUiState>(DisputeDetailUiState.Loading)
    val state: StateFlow<DisputeDetailUiState> = _state.asStateFlow()

    init { load() }
    fun load() = viewModelScope.launch {
        _state.value = DisputeDetailUiState.Loading
        _state.value = when (val r = repo.getDispute(disputeId)) {
            is ApiResult.Success -> DisputeDetailUiState.Content(r.data)
            is ApiResult.Error ->
                if (r.error.status == 404) DisputeDetailUiState.NotFound
                else DisputeDetailUiState.Failure(r.error.toUiMessage())
        }
    }
}

sealed interface DisputeDetailUiState {
    data object Loading : DisputeDetailUiState
    data class Content(val dispute: DisputeDetail) : DisputeDetailUiState
    data object NotFound : DisputeDetailUiState
    data class Failure(val message: String) : DisputeDetailUiState
}
```

The list screen derives loading/empty/error from Paging's
`LazyPagingItems.loadState` (`refresh`, `append`) rather than a custom
`StateFlow<UiState>`, per Paging 3 conventions.

### 4.7 Compose screens + navigation (`feature-billing`)

```kotlin
@Composable fun DisputesListScreen(
    onOpenDispute: (String) -> Unit,
    vm: DisputesListViewModel = hiltViewModel(),
)

@Composable fun DisputeDetailScreen(
    onBack: () -> Unit,
    onOpenInvoice: (String) -> Unit,
    vm: DisputeDetailViewModel = hiltViewModel(),
)

// Navigation-Compose routes
const val DISPUTES_LIST_ROUTE = "billing/disputes"
const val DISPUTE_DETAIL_ROUTE = "billing/disputes/{disputeId}"

fun NavGraphBuilder.disputesGraph(nav: NavController) {
    composable(DISPUTES_LIST_ROUTE) {
        DisputesListScreen(onOpenDispute = { nav.navigate("billing/disputes/$it") })
    }
    composable(
        DISPUTE_DETAIL_ROUTE,
        arguments = listOf(navArgument("disputeId") { type = NavType.StringType }),
    ) {
        DisputeDetailScreen(
            onBack = { nav.popBackStack() },
            onOpenInvoice = { nav.navigate("billing/invoices/$it") }, // AND-223 surface
        )
    }
}
```

The list uses `LazyColumn` with `items(lazyPagingItems.itemCount)`; rows are a
`DisputeRow` composable. Status chips come from a shared
`core-ui` `StatusChip(style: StatusChipStyle)` driven by a
`DisputeStatus.toChipStyle()` map.

## 5. API Contract

All paths are relative to dev base `http://18.222.237.167:8000` (plaintext HTTP,
unreliable host). Auth is via the inherited cookie session; both calls are
idempotent GETs (no `X-CSRF-Token` required).

| Verb | Path | Query | Response DTO |
|------|------|-------|--------------|
| GET | `/ui/billing/disputes` | `cursor`, `limit` | `DisputePageDto` |
| GET | `/ui/billing/disputes/{disputeId}` | — | `DisputeDetailDto` |

Example `GET /ui/billing/disputes?limit=20` 200:

```json
{
  "items": [
    {
      "dispute_id": "dp_7c1",
      "status": "needs_response",
      "reason": "fraudulent",
      "amount_minor": 4900,
      "currency": "USD",
      "opened_at": "2026-05-20T14:03:00Z",
      "evidence_due_by": "2026-06-10T23:59:59Z",
      "invoice_id": "in_001"
    }
  ],
  "next_cursor": "dp_7c1"
}
```

Example `GET /ui/billing/disputes/dp_7c1` 200:

```json
{
  "dispute_id": "dp_7c1",
  "status": "under_review",
  "reason": "fraudulent",
  "amount_minor": 4900,
  "currency": "USD",
  "opened_at": "2026-05-20T14:03:00Z",
  "evidence_due_by": "2026-06-10T23:59:59Z",
  "invoice_id": "in_001",
  "charge_id": "ch_88a",
  "network_reason_code": "10.4",
  "explanation": "Cardholder reports unauthorized charge."
}
```

Error envelopes follow the FastAPI shape and are mapped by the shared error
mapper (AND-223 / AND-015):

```json
{ "detail": "Dispute not found" }
{ "detail": [{ "loc": ["query","limit"], "msg": "ensure value <= 100", "type": "value_error" }] }
```

Statuses to handle: `200`, `401` (handled by the inherited
refresh-and-retry interceptor), `404` (unknown dispute → not-found UI), `422`
(bad query → error UI), `5xx`/timeout (bounded retry, then error/offline UI).
Field names/nullability/enum members above are **provisional** and MUST be
reconciled against `/openapi.json` and `billingDisputes.ts` during implementation
(section 11 captures live fixtures).

## 6. Data & State Management

- **List state** is owned by Paging 3. `DisputesPagingSource` is keyed by the
  opaque `next_cursor` (`String`); `DisputesListViewModel` exposes
  `Flow<PagingData<DisputeSummary>>` `cachedIn(viewModelScope)` to survive config
  changes. The screen reads `loadState.refresh` / `loadState.append` to drive
  loading / empty / error sub-states.
- **Detail state** is a `StateFlow<DisputeDetailUiState>` (Loading/Content/
  NotFound/Failure). `disputeId` is read from `SavedStateHandle` so detail
  survives process death; on restore the screen re-fetches (no body is persisted).
- **Caching (optional, additive):** a Room `DisputeEntity` mirror in `core-data`
  may back an offline/stale list. If included, it is a thin
  `RemoteMediator`-style write-through behind the existing `PagingSource`; if
  deferred, the offline state simply shows the error/retry UI. The DTO field
  names are designed so a Room mirror can be added later without contract change.
  Default plan: **no Room** in this ticket unless OQ-2 resolves toward offline.
- **DataStore:** none. No user preferences are introduced.
- No mutable cross-screen state; navigation passes only the `disputeId` string.

## 7. Error Handling & Resilience

- Both endpoints are **idempotent GETs**, eligible for the shared bounded-backoff
  retry (AND-223/AND-027): retry on connect/read timeout and 5xx, capped (~3
  attempts, jittered), ~20 s per-attempt timeout for the unreliable dev host.
- **List errors:** a `refresh` failure surfaces a full-screen error with retry
  (`lazyPagingItems.retry()`); an `append` failure surfaces an inline footer
  "Couldn't load more — Retry". An empty successful page → empty state, not error.
- **Detail errors:** `404` → dedicated `NotFound` state ("Dispute not found");
  other failures → `Failure(message)` with retry; `message` comes from the shared
  `ApiError.toUiMessage()` (all three `detail` shapes).
- **401** is transparent to this feature — handled by the inherited single-shot
  `POST /ui/session/refresh`-then-retry interceptor.
- **Mapping resilience:** mappers never throw — unknown `status`/`reason` →
  `UNKNOWN` (rendered as a neutral chip / "Other"), bad timestamps → `null`
  (date row hidden), missing collections → empty list. A backend adding a new
  status never crashes the client.
- **Offline:** if Room caching is included, show last-cached list with a
  "Showing cached disputes" banner; otherwise show error/retry. The detail screen
  with no cache shows the failure state.

## 8. Security & Privacy

- **No new auth surface.** Disputes ride the existing cookie session; both calls
  are GETs needing no CSRF header. No tokens or credentials are stored.
- **Sensitive data:** dispute payloads contain account-billing info (amounts,
  reasons, network reason codes, free-text `explanation`). These are
  display-only and MUST NOT be written to logs (see section 10). No PAN/CVV is
  present (only references such as `charge_id`/`invoice_id`).
- **No capability-bearing URLs** are introduced by these endpoints; if a future
  `evidence_url` is added, treat it as a secret (out of scope here).
- **Transport:** dev backend is plaintext HTTP. Production must be HTTPS; the
  network-security config (separate infra ticket) restricts cleartext to the dev
  host. This ticket adds no cleartext exemptions.
- **Authorization:** the backend scopes disputes to the session's account; the
  client never passes an account id. A `403`/`401` is treated as a generic error
  / re-auth, never by widening the request.

## 9. Accessibility & i18n

- **Money** is formatted from minor units + ISO-4217 currency via
  `NumberFormat.getCurrencyInstance(locale)` — never a pre-formatted server
  string. **Timestamps** (`opened_at`, `evidence_due_by`) are `Instant` rendered
  in the device locale/zone with `DateTimeFormatter.ofLocalizedDate`.
- All user-facing strings (status labels, reason labels, empty/error/not-found
  copy, "Respond (coming soon)") live in `feature-billing` `strings.xml`; status
  and reason enums map to string resources, not raw backend tokens.
- **Status chips** convey state with both color and text (never color alone), and
  carry a `contentDescription` (e.g., "Status: needs response"). `evidence_due_by`
  rows announce urgency in text, not color alone.
- Screens support TalkBack: rows are a single focusable node with a combined
  semantics label ("Dispute, $49.00, fraudulent, needs response, opened May 20");
  dynamic type / font scaling and a minimum 48dp touch target are respected.
- RTL layouts supported via standard Compose start/end alignment.

## 10. Telemetry & Logging

- Reuse the shared OkHttp `HttpLoggingInterceptor` at `BASIC` (not `BODY`) for
  dispute paths so amounts, reason codes, and `explanation` text are not logged.
- Emit `feature-billing` analytics via the shared analytics interface (no PII):
  `disputes_list_viewed`, `dispute_detail_viewed { status }` (status enum name
  only, no amount/explanation), `disputes_list_load_error { http_status }`,
  `dispute_detail_load_error { http_status }`. No dispute ids in analytics.
- Mapper warnings (unknown enum, bad timestamp) log at `WARN` via the shared
  `Logger` with the field name only — never the raw token or `explanation`.
- A debug-only (`BuildConfig.DEBUG`) one-line count of unknown enum hits flags
  contract drift early.

## 11. Testing Strategy

Acceptance is "Disputes render." Testing spans data, repository, and UI.

1. **Moshi round-trip unit tests** (`core-network`, JVM): deserialize captured
   `disputes_page.json` and `dispute_detail.json` fixtures, assert every field,
   re-serialize, assert structural equality; include fixtures with `null`
   optionals and missing keys to prove defaults.
2. **Mapper tests:** assert `toDomain()` for summary/detail, including unknown
   `status`/`reason` → `UNKNOWN`, malformed `opened_at`/`evidence_due_by` →
   `null`, `Money(minor, currency)` construction, and `next_cursor` passthrough.
3. **`DisputesApi` MockWebServer tests:** enqueue fixtures; assert request path,
   verb, and `cursor`/`limit` query params for list, and path for detail.
4. **PagingSource tests:** assert first `load` returns a `Page` with
   `nextKey == next_cursor`; a subsequent `load(key = cursor)` advances; an
   error response yields `LoadResult.Error`.
5. **ViewModel tests** (`core-testing`, `runTest` + `MainDispatcherRule`):
   `DisputeDetailViewModel` emits `Loading -> Content` on success,
   `Loading -> NotFound` on `404`, `Loading -> Failure` on other errors, and
   `load()` retries.
6. **Compose UI tests** (`createAndroidComposeRule`): list renders rows from a
   fake paged source (content state), shows empty state for an empty page, shows
   error + retry on `refresh` error; tapping a row invokes `onOpenDispute(id)`.
   Detail renders content, not-found, and failure states.
7. **Live verification (non-CI, documented):** run once against
   `http://18.222.237.167:8000` + `/openapi.json` to capture real fixtures and
   confirm field names/nullability/enums; commit sanitized fixtures under
   `core-network/src/test/resources/billing/disputes/`.

Coverage target: 100% of DTOs/mappers/PagingSource and both ViewModels; the two
screens covered by the state-rendering UI tests above.

## 12. Dependencies & Sequencing

- **Depends on AND-223 (Billing API + DTOs):** provides the authenticated
  `Retrofit`, `Money`, `Instant`/`toInstantOrNull()`, `ApiResult`, the shared
  FastAPI error mapper, cursor-pagination conventions, and the MockWebServer test
  harness. Disputes cannot be wired without it. (AND-223 → AND-027 → AND-026
  transitively supply cookie session, CSRF, retry/timeout policy.)
- **Soft adjacency to AND-015** (API error model) for `ApiError.toUiMessage()`
  and detail-shape handling; consumed via AND-223, not re-implemented.
- **Optional linkage:** the "open related invoice" action navigates to the
  AND-223 invoice-detail route if/when that surface exists; if not yet present,
  the action is hidden (no hard build dependency).
- **Blocks:** nothing currently. A future dispute-response/evidence ticket (not
  filed; OQ-3) would depend on this read surface.
- **Sequencing:** land DTOs/mappers/API first (verifiable against fixtures), then
  repository + PagingSource, then ViewModels, then Compose screens + nav.

## 13. Risks & Open Questions

- **OQ-1 (path namespacing):** Backlog/scope names `billingDisputes.ts`; the
  assumed paths are `/ui/billing/disputes` (cookie/UI surface, consistent with
  AND-223's `ui/billing/*`). Confirm against `/openapi.json` — disputes may live
  under `/api/billing/disputes`. Reconcile before merging.
- **OQ-2 (offline caching):** Is a Room mirror required for disputes, or is
  error/retry-only acceptable for P2? Default is no Room; revisit if product
  requires offline viewing. DTO field names are stable either way.
- **OQ-3 (response scope):** Is dispute-evidence submission ever needed in-app,
  or is it handled by an external processor portal? This ticket is read-only;
  confirm the disabled "Respond" affordance copy (in-app-coming-soon vs.
  external-link) with product.
- **OQ-4 (enum members):** `DisputeStatus`/`DisputeReason` members are
  provisional (modeled on common chargeback lifecycles). Verify the exact backend
  enum set against `/openapi.json`; `UNKNOWN` fallback mitigates drift but the
  primary members should match for correct chip styling/labels.
- **Risk — contract drift / fixture staleness:** the dev backend is unreliable
  and may evolve; mitigated by `UNKNOWN` fallbacks, total mappers, the debug
  drift counter, and re-runnable live fixture capture (section 11.7).
- **Risk — empty-data ambiguity:** distinguishing "no disputes" (success, empty
  page) from a silently failed load; mitigated by driving empty state strictly
  off a successful `LoadResult.Page` with zero items.

## 14. Acceptance Criteria

1. `DisputesApi` exists in `com.testlogon.android.core.network.billing.disputes`
   with `suspend` list + detail functions matching section 5 paths/verbs/query
   params — verified by MockWebServer tests.
2. All dispute DTOs exist with Moshi codegen and deserialize the captured
   fixtures with every field asserted (including null/missing-key defaults).
3. `core-model.billing` `DisputeSummary`/`DisputeDetail`/`DisputePage` and total
   `toDomain()` mappers exist; unknown enums → `UNKNOWN`, bad timestamps →
   `null`, missing collections → empty — proven by mapper tests.
4. `DisputesRepository` + `DisputesPagingSource` page over `next_cursor`; first/
   next page and error cases proven by PagingSource tests.
5. `DisputesListScreen` renders paged disputes and shows loading, empty, error
   (with retry) states; tapping a row navigates to detail — proven by Compose
   tests. **Disputes render** against the live backend for a signed-in user.
6. `DisputeDetailScreen` renders content, `NotFound` (404), and failure states
   with retry — proven by ViewModel + Compose tests.
7. Status is rendered via the shared typed `StatusChip`; money is locale-currency
   formatted; dates are locale-formatted from `Instant`.
8. No POST/PUT, no evidence upload, no write of any kind is added by this ticket.
9. The full test suite (round-trip, mapper, MockWebServer, PagingSource,
   ViewModel, Compose) passes in CI.

## 15. Definition of Done

- All acceptance criteria in section 14 are met and CI is green.
- Code lives under the exact `com.testlogon.android.*` packages above with the
  module layering respected (no Retrofit/Moshi types leak into `core-model`; no
  Android UI imports in ViewModels' logic paths).
- Sanitized fixtures captured from the live dev backend / `/openapi.json` are
  committed under `core-network/src/test/resources/billing/disputes/`, and
  OQ-1/OQ-3/OQ-4 are resolved and reflected in final field names, paths, and enum
  members.
- `HttpLoggingInterceptor` confirmed not to log amounts, reason codes, or
  `explanation`; analytics carry no PII or dispute ids.
- Screens pass a TalkBack pass and font-scaling check; all strings are in
  `strings.xml` (no hardcoded user-facing text); RTL verified.
- Ktlint/Detekt pass; KSP generates Moshi adapters with no warnings.
- KDoc on `DisputesApi`, the domain models, and `DisputesRepository` is
  sufficient for future consumers (e.g., a dispute-response ticket).
- Reviewed and merged to branch `android-port`.

> Word count note: prose is within the 2,200–2,800 target; the elevated raw count
> reflects the embedded Kotlin/JSON contract blocks, which are load-bearing.
