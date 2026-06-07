---
id: AND-245
title: Disputes
milestone: M5
epic: E33
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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

// CORRECTED (review 2026-06-06): the backend returns a SINGLE `DisputeOut`
// shape for BOTH list rows and detail (frontend `src/api/types.ts: DisputeOut`,
// used by both `listMyDisputes` and `getDispute`). There is no separate
// summary/detail schema. The list response is `{ "items": DisputeOut[] }`
// with NO `next_cursor` — the endpoint is limit-bounded, not cursor-paged.
@JsonClass(generateAdapter = true)
data class DisputePageDto(
    @Json(name = "items") val items: List<DisputeDto> = emptyList(),
    // No `next_cursor`: backend does not paginate disputes (verified vs
    // OpenAPI `GET /ui/billing/disputes` resp + frontend billingDisputes.ts).
)

// CORRECTED: field names/types reconciled to the real `DisputeOut`.
// - `amount_cents` (not `amount_minor`)
// - timestamps are EPOCH SECONDS as numbers (not ISO-8601 strings):
//   `created_at` (not `opened_at`), `deadline_at` (not `evidence_due_by`),
//   `updated_at`.
// - `reason` is FREE TEXT (not an enum); `status` observed values: open |
//   under_review | resolved.
// - `invoice_id`/`charge_id`/`network_reason_code`/`explanation` do NOT exist.
//   Real linkage is `transaction_entry_id`; extra fields: provider,
//   provider_dispute_id, user_id, evidence_submitted, evidence_text,
//   resolution, admin_notes.
@JsonClass(generateAdapter = true)
data class DisputeDto(
    @Json(name = "dispute_id") val disputeId: String,
    @Json(name = "provider") val provider: String,
    @Json(name = "provider_dispute_id") val providerDisputeId: String?,
    @Json(name = "user_id") val userId: String?,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String,     // ISO-4217
    @Json(name = "reason") val reason: String,          // free text
    @Json(name = "status") val status: String,          // open|under_review|resolved
    @Json(name = "evidence_submitted") val evidenceSubmitted: Boolean = false,
    @Json(name = "evidence_text") val evidenceText: String?,
    @Json(name = "resolution") val resolution: String?,
    @Json(name = "admin_notes") val adminNotes: String?,
    @Json(name = "transaction_entry_id") val transactionEntryId: String?,
    @Json(name = "created_at") val createdAt: Long,     // epoch SECONDS
    @Json(name = "updated_at") val updatedAt: Long?,    // epoch SECONDS
    @Json(name = "deadline_at") val deadlineAt: Long?,  // epoch SECONDS
)
```

> Review note: the original spec invented separate `DisputeSummaryDto` /
> `DisputeDetailDto` schemas, ISO-8601 string timestamps, an `amount_minor`
> field, an invoice/charge/network-reason model, and a cursor-paged page DTO.
> None of these exist in the backend or web reference; they are corrected above.

### 4.2 Domain models (`core-model`)

```kotlin
package com.testlogon.android.core.model.billing

import java.time.Instant

// CORRECTED: observed status values are open|under_review|resolved (frontend
// DisputesPage.tsx statusVariant). UNKNOWN keeps the mapper total. There is NO
// reason enum — `reason` is free text in the contract, so it stays a String.
enum class DisputeStatus {
    OPEN, UNDER_REVIEW, RESOLVED, UNKNOWN
}

// CORRECTED: one domain type (`Dispute`) mirrors the single `DisputeOut`.
// `reason` is a free-text String (not an enum). Timestamps are `Instant`
// decoded from epoch seconds. `transactionEntryId` is the only real linkage.
data class Dispute(
    val disputeId: String,
    val provider: String,
    val providerDisputeId: String?,
    val status: DisputeStatus,
    val reason: String,                // free text
    val amount: Money,                 // reused from AND-223
    val evidenceSubmitted: Boolean,
    val evidenceText: String?,
    val resolution: String?,
    val transactionEntryId: String?,
    val createdAt: Instant?,
    val updatedAt: Instant?,
    val deadlineAt: Instant?,
)

// CORRECTED: page carries items only — no cursor (backend is not cursor-paged).
data class DisputePage(val items: List<Dispute>)
```

> Review note: `adminNotes`/`userId` are admin-facing/internal and are
> intentionally omitted from the user-facing domain model. The original
> `DisputeReason` enum and `WON/LOST/WARNING_CLOSED/CANCELED/NEEDS_RESPONSE`
> statuses were invented (chargeback-lifecycle guesses) and are removed.

### 4.3 Mappers (`core-network`)

```kotlin
// CORRECTED: single mapper; amount_cents; epoch-SECONDS timestamps; free-text
// reason (no enum mapping); transaction_entry_id linkage.
internal fun DisputeDto.toDomain() = Dispute(
    disputeId = disputeId,
    provider = provider,
    providerDisputeId = providerDisputeId,
    status = status.toDisputeStatus(),
    reason = reason,                                   // free text, passthrough
    amount = Money(amountCents, currency),
    evidenceSubmitted = evidenceSubmitted,
    evidenceText = evidenceText,
    resolution = resolution,
    transactionEntryId = transactionEntryId,
    createdAt = createdAt.epochSecondsToInstantOrNull(),
    updatedAt = updatedAt?.epochSecondsToInstantOrNull(),
    deadlineAt = deadlineAt?.epochSecondsToInstantOrNull(),
)

internal fun String.toDisputeStatus() = when (lowercase()) {
    "open" -> DisputeStatus.OPEN
    "under_review" -> DisputeStatus.UNDER_REVIEW
    "resolved" -> DisputeStatus.RESOLVED
    else -> DisputeStatus.UNKNOWN
}

// epoch-seconds helper (Instant.ofEpochSecond, guarding overflow) — a new
// total helper, since AND-223's `toInstantOrNull()` parses ISO-8601 STRINGS
// and is unusable here (dispute timestamps are numeric epoch seconds).
internal fun Long.epochSecondsToInstantOrNull(): Instant? =
    runCatching { Instant.ofEpochSecond(this) }.getOrNull()
```

> Review note: the original mappers parsed ISO-8601 strings via AND-223's
> `toInstantOrNull()`. Dispute timestamps are numeric epoch seconds, so a new
> `epochSecondsToInstantOrNull()` is required; string parsing would always
> fail. `Money` is inherited from AND-223. There is no `toDisputeReason()`.

### 4.4 API + Hilt module (`core-network`)

```kotlin
// CORRECTED: no `cursor` query param exists; only `limit` (default 50 per
// OpenAPI). Detail returns the same `DisputeDto`. Path param is `dispute_id`.
internal interface DisputesApi {
    @GET("ui/billing/disputes")
    suspend fun getDisputes(
        @Query("limit") limit: Int = 50,
    ): DisputePageDto

    @GET("ui/billing/disputes/{dispute_id}")
    suspend fun getDispute(@Path("dispute_id") disputeId: String): DisputeDto
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

### 4.5 Repository (`core-data`)

> CORRECTED (review 2026-06-06): the backend is **not cursor-paged** — the list
> endpoint returns a flat `{ items: [...] }` bounded by `limit` (no
> `next_cursor`). Paging 3 / `PagingSource` over a cursor is therefore
> **removed**; it cannot be implemented against this contract. The repository
> exposes a single bounded fetch returning the full list. (If the dataset ever
> grows large, server-side pagination would need to be added first — see OQ-2.)

```kotlin
package com.testlogon.android.core.data.billing

interface DisputesRepository {
    suspend fun getDisputes(limit: Int = 50): ApiResult<List<Dispute>>
    suspend fun getDispute(id: String): ApiResult<Dispute>
}

internal class DefaultDisputesRepository @Inject constructor(
    private val api: DisputesApi,
) : DisputesRepository {

    override suspend fun getDisputes(limit: Int): ApiResult<List<Dispute>> =
        apiCall { api.getDisputes(limit).items.map { it.toDomain() } }

    override suspend fun getDispute(id: String): ApiResult<Dispute> =
        apiCall { api.getDispute(id).toDomain() }   // apiCall = shared ApiResult wrapper
}
```

### 4.6 ViewModels (`feature-billing`)

```kotlin
// CORRECTED: with no server pagination, the list VM owns a plain
// StateFlow<UiState> (Loading/Content/Empty/Failure) instead of PagingData.
@HiltViewModel
class DisputesListViewModel @Inject constructor(
    private val repo: DisputesRepository,
) : ViewModel() {
    private val _state = MutableStateFlow<DisputesListUiState>(DisputesListUiState.Loading)
    val state: StateFlow<DisputesListUiState> = _state.asStateFlow()

    init { load() }
    fun load() = viewModelScope.launch {
        _state.value = DisputesListUiState.Loading
        _state.value = when (val r = repo.getDisputes()) {
            is ApiResult.Success ->
                if (r.data.isEmpty()) DisputesListUiState.Empty
                else DisputesListUiState.Content(r.data)
            is ApiResult.Error -> DisputesListUiState.Failure(r.error.toUiMessage())
        }
    }
}

sealed interface DisputesListUiState {
    data object Loading : DisputesListUiState
    data object Empty : DisputesListUiState
    data class Content(val disputes: List<Dispute>) : DisputesListUiState
    data class Failure(val message: String) : DisputesListUiState
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
            // NOTE: 404 mapping is an UNVERIFIED assumption — the OpenAPI for
            // GET /ui/billing/disputes/{dispute_id} declares only 200 + 422.
            // The NotFound branch defends against a runtime 404 if FastAPI
            // raises one; an unknown id may instead surface as 422/200.
            is ApiResult.Error ->
                if (r.error.status == 404) DisputeDetailUiState.NotFound
                else DisputeDetailUiState.Failure(r.error.toUiMessage())
        }
    }
}

sealed interface DisputeDetailUiState {
    data object Loading : DisputeDetailUiState
    data class Content(val dispute: Dispute) : DisputeDetailUiState
    data object NotFound : DisputeDetailUiState
    data class Failure(val message: String) : DisputeDetailUiState
}
```

> Review note: the list screen no longer uses Paging's `LazyPagingItems`/
> `loadState` (Paging 3 was removed; see 4.5). It renders directly off
> `DisputesListUiState`.

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

The list uses `LazyColumn` over `DisputesListUiState.Content.disputes`
(CORRECTED: not `LazyPagingItems`, since Paging 3 was removed in 4.5); rows are
a `DisputeRow` composable. Status chips come from a shared
`core-ui` `StatusChip(style: StatusChipStyle)` driven by a
`DisputeStatus.toChipStyle()` map. NOTE: a `billing/disputes/{disputeId}`
detail route is an Android-only addition — the web reference has only the flat
`billing/disputes` list route (no detail page); the `getDispute(id)` endpoint
nonetheless exists, so the Android detail screen is contract-valid.

## 5. API Contract

All paths are relative to dev base `http://18.222.237.167:8000` (plaintext HTTP,
unreliable host). CORRECTED auth note: the web client (`src/api/client.ts`)
sends BOTH `Authorization: Bearer <accessToken>` (from the auth store) AND
cookies (`credentials: include`), and it attaches `X-CSRF-Token` (from the
`ui_csrf` cookie) on **every** request including GETs. CSRF is harmless on
idempotent GETs but is not actually omitted by the reference client; the Android
client should follow whatever AND-223/AND-027 froze for the shared
authenticated `Retrofit`. The list/detail endpoints also accept optional
`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers and a `user_sub` query param
(impersonation/support — out of scope here; never set by the normal client).

| Verb | Path | Query | Response |
|------|------|-------|----------|
| GET | `/ui/billing/disputes` | `limit` (default 50) | `{ "items": DisputeDto[] }` (no cursor) |
| GET | `/ui/billing/disputes/{dispute_id}` | — | `DisputeDto` |

(There is also `POST /ui/billing/disputes` to *file* a dispute, and admin
respond/resolve endpoints — all **out of scope**; this ticket is read-only.)

Example `GET /ui/billing/disputes?limit=50` 200 (CORRECTED to the real
`DisputeOut` shape; timestamps are epoch SECONDS):

```json
{
  "items": [
    {
      "dispute_id": "dp_7c1",
      "provider": "stripe",
      "provider_dispute_id": "du_1Nx...",
      "user_id": "usr_42",
      "amount_cents": 4900,
      "currency": "USD",
      "reason": "Cardholder reports an unauthorized charge.",
      "status": "open",
      "evidence_submitted": false,
      "evidence_text": null,
      "resolution": null,
      "admin_notes": null,
      "transaction_entry_id": "le_88a",
      "created_at": 1747749780,
      "updated_at": null,
      "deadline_at": 1749599999
    }
  ]
}
```

Example `GET /ui/billing/disputes/dp_7c1` 200 returns the same `DisputeDto`
shape (resolved example):

```json
{
  "dispute_id": "dp_7c1",
  "provider": "stripe",
  "amount_cents": 4900,
  "currency": "USD",
  "reason": "Cardholder reports an unauthorized charge.",
  "status": "resolved",
  "evidence_submitted": true,
  "resolution": "won",
  "transaction_entry_id": "le_88a",
  "created_at": 1747749780,
  "updated_at": 1748200000,
  "deadline_at": 1749599999
}
```

Error envelopes follow the FastAPI shape and are mapped by the shared error
mapper (AND-223 / AND-015). The 422 shape is the standard
`HTTPValidationError` (verified in OpenAPI components):

```json
{ "detail": "Dispute not found" }
{ "detail": [{ "loc": ["query","limit"], "msg": "Input should be a valid integer", "type": "int_parsing" }] }
```

Statuses to handle: `200`, `401` (handled by the inherited refresh-and-retry
interceptor → `POST /ui/session/refresh`), `422` (bad query/path → error UI),
`5xx`/timeout (bounded retry, then error/offline UI). **`404` is an UNVERIFIED
assumption** — OpenAPI declares only `200` + `422` for both GETs; the NotFound
branch defends a possible runtime 404 but an unknown id may surface as 422/200.
Field names/nullability above are now reconciled to OpenAPI
(`GET /ui/billing/disputes`, `GET /ui/billing/disputes/{dispute_id}`) and
frontend `src/api/types.ts: DisputeOut`; remaining nullability edge cases are
confirmed via the live-fixture capture in section 11.

## 6. Data & State Management

- **List state** (CORRECTED — no Paging 3; backend is not cursor-paged) is a
  `StateFlow<DisputesListUiState>` (Loading/Empty/Content/Failure) exposed by
  `DisputesListViewModel`, surviving config changes via `viewModelScope`. A
  single bounded `getDisputes(limit = 50)` populates it; empty list → `Empty`.
- **Detail state** is a `StateFlow<DisputeDetailUiState>` (Loading/Content/
  NotFound/Failure). `disputeId` is read from `SavedStateHandle` so detail
  survives process death; on restore the screen re-fetches (no body is persisted).
- **Caching (optional, additive):** a Room `DisputeEntity` mirror in `core-data`
  may back an offline/stale list as a simple write-through cache behind
  `getDisputes()` (CORRECTED: no `RemoteMediator`, since there is no Paging
  source). If deferred, the offline state simply shows the error/retry UI. The
  DTO field names are designed so a Room mirror can be added later without
  contract change. Default plan: **no Room** in this ticket unless OQ-2
  resolves toward offline.
- **DataStore:** none. No user preferences are introduced.
- No mutable cross-screen state; navigation passes only the `disputeId` string.

## 7. Error Handling & Resilience

- Both endpoints are **idempotent GETs**, eligible for the shared bounded-backoff
  retry (AND-223/AND-027): retry on connect/read timeout and 5xx, capped (~3
  attempts, jittered), ~20 s per-attempt timeout for the unreliable dev host.
- **List errors** (CORRECTED — no paging append): a load failure surfaces a
  full-screen error with retry (`viewModel.load()`); a successful empty list →
  empty state, not error. (There is no incremental "load more" footer because
  the endpoint returns a single bounded list.)
- **Detail errors:** `404` → dedicated `NotFound` state ("Dispute not found");
  other failures → `Failure(message)` with retry; `message` comes from the shared
  `ApiError.toUiMessage()` (all three `detail` shapes).
- **401** is transparent to this feature — handled by the inherited single-shot
  `POST /ui/session/refresh`-then-retry interceptor.
- **Mapping resilience:** mappers never throw — unknown `status` → `UNKNOWN`
  (rendered as a neutral chip / "Other"); `reason` is free text shown verbatim
  (CORRECTED: it is not an enum, so there is no reason fallback); bad/overflow
  epoch timestamps → `null` (date row hidden); missing `items` → empty list. A
  backend adding a new status never crashes the client.
- **Offline:** if Room caching is included, show last-cached list with a
  "Showing cached disputes" banner; otherwise show error/retry. The detail screen
  with no cache shows the failure state.

## 8. Security & Privacy

- **No new auth surface.** Disputes ride the existing authenticated transport
  frozen by AND-223/AND-027 (Bearer token + session cookies; the web client also
  sends `X-CSRF-Token` on all requests — CORRECTED: GETs are not actually
  CSRF-exempt in the reference client, though CSRF is inert on idempotent GETs).
  This ticket stores no new tokens or credentials.
- **Sensitive data:** dispute payloads contain account-billing info (amounts,
  free-text `reason`, `evidence_text`, `resolution`, and internal `admin_notes`/
  `provider_dispute_id`). These are display-only and MUST NOT be written to logs
  (see section 10). No PAN/CVV is present (only references such as
  `transaction_entry_id` / `provider_dispute_id`). `admin_notes` is internal and
  is not surfaced in the user-facing UI.
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
  string. **Timestamps** (`created_at`, `deadline_at`, `updated_at` — CORRECTED
  names, decoded from epoch SECONDS) are `Instant` rendered in the device
  locale/zone with `DateTimeFormatter.ofLocalizedDate`.
- All user-facing strings (status labels, empty/error/not-found copy, "Respond
  (coming soon)") live in `feature-billing` `strings.xml`; the status enum maps
  to string resources, not raw backend tokens. `reason` is free text from the
  backend and is shown verbatim (not localized).
- **Status chips** convey state with both color and text (never color alone), and
  carry a `contentDescription` (e.g., "Status: under review"). `deadline_at`
  rows announce urgency in text, not color alone.
- Screens support TalkBack: rows are a single focusable node with a combined
  semantics label ("Dispute, $49.00, open, filed May 20");
  dynamic type / font scaling and a minimum 48dp touch target are respected.
- RTL layouts supported via standard Compose start/end alignment.

## 10. Telemetry & Logging

- Reuse the shared OkHttp `HttpLoggingInterceptor` at `BASIC` (not `BODY`) for
  dispute paths so amounts, free-text `reason`/`evidence_text`/`resolution`, and
  `admin_notes` are not logged.
- Emit `feature-billing` analytics via the shared analytics interface (no PII):
  `disputes_list_viewed`, `dispute_detail_viewed { status }` (status enum name
  only, no amount/explanation), `disputes_list_load_error { http_status }`,
  `dispute_detail_load_error { http_status }`. No dispute ids in analytics.
- Mapper warnings (unknown status, bad/overflow epoch timestamp) log at `WARN`
  via the shared `Logger` with the field name only — never the raw token, free
  text, or `evidence_text`.
- A debug-only (`BuildConfig.DEBUG`) one-line count of unknown enum hits flags
  contract drift early.

## 11. Testing Strategy

Acceptance is "Disputes render." Testing spans data, repository, and UI.

1. **Moshi round-trip unit tests** (`core-network`, JVM): deserialize captured
   `disputes_page.json` and `dispute_detail.json` fixtures, assert every field,
   re-serialize, assert structural equality; include fixtures with `null`
   optionals and missing keys to prove defaults.
2. **Mapper tests** (CORRECTED): assert `DisputeDto.toDomain()`, including
   unknown `status` → `UNKNOWN`, free-text `reason` passthrough, overflow/bad
   epoch `created_at`/`deadline_at`/`updated_at` → `null`,
   `Money(amountCents, currency)` construction, and null-optional handling.
3. **`DisputesApi` MockWebServer tests:** enqueue fixtures; assert request path,
   verb, and the `limit` query param for list (no `cursor` param exists), and
   `{dispute_id}` path for detail.
4. **Repository tests** (CORRECTED — Paging 3 removed): assert `getDisputes()`
   maps `{ items: [...] }` → `ApiResult.Success(List<Dispute>)`, an empty
   `items` → empty list, and an error response → `ApiResult.Error`.
5. **ViewModel tests** (`core-testing`, `runTest` + `MainDispatcherRule`):
   `DisputesListViewModel` emits `Loading -> Content`, `Loading -> Empty`,
   `Loading -> Failure`, and `load()` retries. `DisputeDetailViewModel` emits
   `Loading -> Content` on success, `Loading -> NotFound` on a (defensive)
   `404`, `Loading -> Failure` on other errors (incl. `422`), and `load()`
   retries.
6. **Compose UI tests** (`createAndroidComposeRule`): list renders rows from a
   fake `DisputesListUiState.Content`, shows empty state for `Empty`, shows
   error + retry for `Failure`; tapping a row invokes `onOpenDispute(id)`.
   Detail renders content, not-found, and failure states.
7. **Live verification (non-CI, documented):** run once against
   `http://18.222.237.167:8000` + `/openapi.json` to capture real fixtures and
   confirm field names/nullability/enums; commit sanitized fixtures under
   `core-network/src/test/resources/billing/disputes/`.

Coverage target: 100% of DTOs/mappers/repository and both ViewModels; the two
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
  the repository (single bounded fetch — no PagingSource), then ViewModels, then
  Compose screens + nav.

## 13. Risks & Open Questions

- **OQ-1 (path namespacing): RESOLVED (review 2026-06-06).** Paths are
  `/ui/billing/disputes` and `/ui/billing/disputes/{dispute_id}` — confirmed in
  OpenAPI (`list_my_disputes`, `get_my_dispute`) and frontend
  `billingDisputes.ts`. No `/api/billing/disputes` variant exists.
- **OQ-2 (offline caching / pagination): UPDATED.** The backend is **not
  paginated** — the list returns a flat `{ items: [...] }` bounded by `limit`
  (default 50; web app requests 100). Paging 3 is therefore out. If the dataset
  grows, server-side pagination must be added first. Room offline mirror stays
  optional; default is no Room. DTO field names are stable either way.
- **OQ-3 (response scope):** Is dispute-evidence submission ever needed in-app,
  or is it handled by an external processor portal? This ticket is read-only;
  confirm the disabled "Respond" affordance copy (in-app-coming-soon vs.
  external-link) with product.
- **OQ-4 (enum members): UPDATED.** `reason` is **free text**, not an enum (no
  `DisputeReason` enum). `status` is a plain string; observed values from the web
  app are `open | under_review | resolved` (frontend `DisputesPage.tsx`
  `statusVariant`). The backend does not declare a formal status enum in OpenAPI
  (the response schema is untyped `additionalProperties:true`), so the modeled
  `DisputeStatus` set + `UNKNOWN` fallback is the best-available mapping — verify
  the full status vocabulary against live data during fixture capture (11.7).
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
3. `core-model.billing` `Dispute` + `DisputePage` and a total `DisputeDto`
   `toDomain()` mapper exist; unknown `status` → `UNKNOWN`, free-text `reason`
   preserved, bad/overflow epoch timestamps → `null`, missing `items` → empty —
   proven by mapper tests.
4. `DisputesRepository` returns the bounded list (`{ items: [...] }`, no cursor)
   and the single dispute; success/empty/error cases proven by repository tests.
5. `DisputesListScreen` renders the disputes list and shows loading, empty, error
   (with retry) states; tapping a row navigates to detail — proven by Compose
   tests. **Disputes render** against the live backend for a signed-in user.
6. `DisputeDetailScreen` renders content, `NotFound` (404), and failure states
   with retry — proven by ViewModel + Compose tests.
7. Status is rendered via the shared typed `StatusChip`; money is locale-currency
   formatted; dates are locale-formatted from `Instant`.
8. No POST/PUT, no evidence upload, no write of any kind is added by this ticket.
9. The full test suite (round-trip, mapper, MockWebServer, repository,
   ViewModel, Compose) passes in CI.

## 15. Definition of Done

- All acceptance criteria in section 14 are met and CI is green.
- Code lives under the exact `com.testlogon.android.*` packages above with the
  module layering respected (no Retrofit/Moshi types leak into `core-model`; no
  Android UI imports in ViewModels' logic paths).
- Sanitized fixtures captured from the live dev backend / `/openapi.json` are
  committed under `core-network/src/test/resources/billing/disputes/`, and
  OQ-1/OQ-3/OQ-4 are resolved and reflected in final field names, paths, and the
  status mapping.
- `HttpLoggingInterceptor` confirmed not to log amounts, free-text
  `reason`/`evidence_text`/`resolution`, or `admin_notes`; analytics carry no PII
  or dispute ids.
- Screens pass a TalkBack pass and font-scaling check; all strings are in
  `strings.xml` (no hardcoded user-facing text); RTL verified.
- Ktlint/Detekt pass; KSP generates Moshi adapters with no warnings.
- KDoc on `DisputesApi`, the domain models, and `DisputesRepository` is
  sufficient for future consumers (e.g., a dispute-response ticket).
- Reviewed and merged to branch `android-port`.

> Word count note: prose is within the 2,200–2,800 target; the elevated raw count
> reflects the embedded Kotlin/JSON contract blocks, which are load-bearing.

## 16. Citations & Assumption Audit

Every concrete technical claim in this spec, with a verdict and an exact source
pointer. Sources: **OpenAPI** = `reference/openapi.pretty.json` /
`reference/openapi.index.txt`; **FE** = `reference/src/...`.

1. **List path/verb is `GET /ui/billing/disputes`.** VERDICT: Verified.
   SOURCE: OpenAPI `GET /ui/billing/disputes` (op `list_my_disputes`);
   FE `src/api/endpoints/billingDisputes.ts: listMyDisputes`.
2. **Detail path/verb is `GET /ui/billing/disputes/{dispute_id}`.** VERDICT:
   Verified. SOURCE: OpenAPI `GET /ui/billing/disputes/{dispute_id}` (op
   `get_my_dispute`); FE `billingDisputes.ts: getDispute`.
3. **List response is `{ items: [...] }` with NO `next_cursor`; not
   cursor-paged.** VERDICT: Corrected (spec had `DisputePageDto.next_cursor` +
   Paging 3). SOURCE: OpenAPI `GET /ui/billing/disputes` 200 schema
   (`additionalProperties:true`, no cursor); FE `billingDisputes.ts: listMyDisputes`
   returns `{ items: DisputeOut[] }`.
4. **Only `limit` query param (default 50); no `cursor` param.** VERDICT:
   Corrected (spec had `cursor` + `limit=20`). SOURCE: OpenAPI
   `GET /ui/billing/disputes` parameters (`limit` default 50, `user_sub`);
   FE `listMyDisputes(limit = 50)`.
5. **List and detail return the SAME single `DisputeOut` shape (no separate
   Summary/Detail).** VERDICT: Corrected. SOURCE: FE `src/api/types.ts: DisputeOut`
   used by both `listMyDisputes` and `getDispute`.
6. **Amount field is `amount_cents` (Long), not `amount_minor`.** VERDICT:
   Corrected. SOURCE: `src/api/types.ts: DisputeOut.amount_cents`;
   FE `DisputesPage.tsx: formatCents(cents/100)`.
7. **Timestamps are epoch SECONDS as numbers (`created_at`, `updated_at`,
   `deadline_at`), not ISO-8601 strings; field names corrected from
   `opened_at`/`evidence_due_by`.** VERDICT: Corrected. SOURCE:
   `src/api/types.ts: DisputeOut` (`created_at: number`, `deadline_at?: number`);
   FE `DisputesPage.tsx: formatDate(ts) -> new Date(ts * 1000)`.
8. **`reason` is free text, not an enum (`fraudulent|product_not_received|...`).**
   VERDICT: Corrected (removed `DisputeReason` enum). SOURCE:
   `src/api/types.ts: DisputeFileIn.reason: string`; FE `DisputesPage.tsx`
   renders raw `d.reason` and the file form requires "min 10 characters".
9. **`invoice_id` / `charge_id` / `network_reason_code` / `explanation` do not
   exist; real fields are `provider`, `provider_dispute_id`, `user_id`,
   `evidence_submitted`, `evidence_text`, `resolution`, `admin_notes`,
   `transaction_entry_id`.** VERDICT: Corrected. SOURCE:
   `src/api/types.ts: DisputeOut`.
10. **Observed `status` values: `open`, `under_review`, `resolved`.** VERDICT:
    Corrected (spec had `needs_response/won/lost/warning_closed/canceled`).
    SOURCE: FE `DisputesPage.tsx: statusVariant` switch. NOTE: backend OpenAPI
    response schema is untyped (`additionalProperties:true`), so the full status
    vocabulary is not formally declared — see Open assumptions.
11. **401 handled by single-shot refresh via `POST /ui/session/refresh` then
    retry.** VERDICT: Verified. SOURCE: FE `src/api/client.ts: refreshSession` +
    401 retry block; OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh`).
12. **Auth transport: Bearer token + session cookies + `X-CSRF-Token` on ALL
    requests (including GETs).** VERDICT: Corrected (spec claimed cookie-only and
    "GETs need no CSRF header"). SOURCE: FE `src/api/client.ts` — sets
    `Authorization: Bearer`, `credentials: "include"`, and `X-CSRF-Token` from
    the `ui_csrf` cookie unconditionally.
13. **422 error envelope is FastAPI `HTTPValidationError` (`detail: [{loc,msg,
    type}]`); string `detail` also possible.** VERDICT: Verified. SOURCE: OpenAPI
    components `HTTPValidationError`; both GETs declare `422` responses; FE
    `client.ts: normalizeErrorDetail` handles both string and array `detail`.
14. **404 → NotFound on detail.** VERDICT: Unverified-assumption. SOURCE: OpenAPI
    `GET /ui/billing/disputes/{dispute_id}` declares only `200` + `422` (no 404).
    The NotFound branch is a defensive guard; see Open assumptions.
15. **`POST /ui/billing/disputes` (file) and admin respond/resolve endpoints
    exist but are out of scope (read-only ticket).** VERDICT: Verified. SOURCE:
    OpenAPI `POST /ui/billing/disputes` (op `file_billing_dispute`, req
    `DisputeFileIn`), `POST /ui/admin/disputes/{id}/respond|resolve`;
    FE `billingDisputes.ts`.
16. **Web reference has no dispute *detail* route — only the flat
    `billing/disputes` list (with a file-dispute dialog).** VERDICT: Verified
    (Android detail screen is an additive, contract-valid design choice since
    `getDispute` exists). SOURCE: FE `src/App.tsx` route table (only
    `billing/disputes`); `DisputesPage.tsx` (no navigation to a detail page).
17. **`Money`, `ApiResult`, shared error mapper, retry/timeout, authenticated
    `Retrofit` are inherited from AND-223/AND-027.** VERDICT: Unverified-assumption
    (cross-ticket dependency; AND-223 source not in this repo snapshot). Treated
    as a stated dependency, not re-derived here.
18. **Framework choices (Compose Material 3, Hilt, Retrofit/Moshi, Navigation-
    Compose, `NumberFormat`/`DateTimeFormatter`).** VERDICT: Verified (framework
    ref). SOURCE (framework ref): developer.android.com — Jetpack Compose,
    Hilt, Navigation-Compose, and `java.time` formatting APIs.

### Corrections made

- **Removed cursor pagination entirely** (DTO `next_cursor`, `cursor` query
  param, Paging 3 `Pager`/`PagingSource`/`RemoteMediator`, `LazyPagingItems`).
  The endpoint is a flat `{ items: [...] }` bounded by `limit`. List state is now
  a plain `StateFlow<DisputesListUiState>` (§4.5, §4.6, §6, §7, §11).
- **Collapsed `DisputeSummaryDto`/`DisputeDetailDto` → one `DisputeDto`** and
  `DisputeSummary`/`DisputeDetail` → one domain `Dispute`, mirroring the single
  backend `DisputeOut` (§4.1, §4.2, §4.3).
- **Field renames/retypes:** `amount_minor`→`amount_cents`;
  `opened_at`→`created_at`, `evidence_due_by`→`deadline_at`, added `updated_at`;
  all timestamps are epoch **seconds** decoded via a new
  `epochSecondsToInstantOrNull()` (AND-223's ISO-8601 `toInstantOrNull()` is
  unusable here). Removed `invoice_id`/`charge_id`/`network_reason_code`/
  `explanation`; added the real provider/evidence/resolution fields (§4.1–§4.3,
  §5, §8, §9, §10).
- **`reason` is free text, not an enum;** removed `DisputeReason`. `DisputeStatus`
  members corrected to `OPEN/UNDER_REVIEW/RESOLVED/UNKNOWN` (§4.2, §4.3, §9).
- **Auth/CSRF note corrected:** Bearer + cookies + CSRF-on-all-requests, not
  "cookie-only, no CSRF on GETs" (§5, §8).
- **`limit` default corrected to 50** (was 20); path param is `dispute_id`
  (§4.4, §5).
- **OQ-1 resolved** (path confirmed); **OQ-2/OQ-4 updated** (no pagination; free-
  text reason; untyped status) (§13). Acceptance criteria 3/4/5/9 and the test
  strategy updated to the corrected shapes.

### Open assumptions

- **404 on unknown dispute id (claim 14):** OpenAPI declares only 200 + 422 for
  the detail GET; whether FastAPI raises a runtime 404 vs a 422/empty-200 for an
  unknown id is unverifiable from the static spec. The NotFound branch is
  retained as a defensive guard; confirm during live-fixture capture (§11.7).
- **Full `status` vocabulary (claim 10):** the backend response schema is untyped
  (`additionalProperties:true`); only `open/under_review/resolved` are observable
  in the web client. Other values may exist; `UNKNOWN` fallback covers drift.
- **AND-223/AND-027 inherited primitives (claim 17):** `Money`, `ApiResult`, the
  shared error mapper, retry/timeout policy, and the authenticated `Retrofit` are
  assumed from dependency tickets not present in this repo snapshot.
- **DTO nullability fine-points:** the live response schema is untyped, so
  required-vs-nullable for fields beyond what `types.ts` declares
  (`updated_at`, `deadline_at`, `evidence_text`, `resolution`, `admin_notes`,
  `provider_dispute_id`, `user_id`, `transaction_entry_id` are nullable there) is
  confirmed only against `types.ts`; reconcile via live fixtures (§11.7).

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device);
**emu35** = headless emulator AVD `test35` (x86_64, API 35) in CI; **A15** =
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). All cases are
software/UI/network only — none need device-specific hardware (camera,
biometrics, FCM, WebRTC, Telecom), so the emulator suffices for instrumented
cases. One case is flagged to also run on **A15** to cover the
arm64-v8a / API-34 vs x86_64 / API-35 ABI/version delta.

- **TC-AND-245-01** — Type: contract/MockWebServer (JVM). Target: `DisputesApi`
  list. Preconditions: MockWebServer enqueues `disputes_page.json`
  (`{ items: [...] }`). Steps: call `getDisputes(limit = 50)`; capture the
  request. Expected: method `GET`, path `/ui/billing/disputes?limit=50` (no
  `cursor` param); body deserializes into `DisputePageDto` with the expected
  item count. Traces: AC-1, AC-4.
- **TC-AND-245-02** — Type: unit (JVM). Target: `DisputeDto.toDomain()` +
  Moshi round-trip. Preconditions: fixture with all fields populated. Steps:
  deserialize, map to `Dispute`, assert every field; re-serialize and assert
  structural equality. Expected: `amount = Money(amount_cents, currency)`;
  `createdAt/updatedAt/deadlineAt` decoded from epoch seconds via
  `Instant.ofEpochSecond`; `reason` preserved verbatim; `status`→enum. Traces:
  AC-2, AC-3, AC-7.
- **TC-AND-245-03** — Type: unit (JVM). Target: mapper resilience. Preconditions:
  fixtures with unknown `status` ("charge_refunded"), null `updated_at`/
  `deadline_at`, overflow/garbage epoch (e.g. `Long.MAX_VALUE` edge), missing
  `items` key, and an empty `reason`. Steps: map each. Expected: unknown status →
  `DisputeStatus.UNKNOWN`; bad/overflow epoch → `null`; missing `items` → empty
  list; mapper never throws. Traces: AC-3.
- **TC-AND-245-04** — Type: contract/MockWebServer (JVM). Target: `DisputesApi`
  detail. Preconditions: enqueue `dispute_detail.json`. Steps: call
  `getDispute("dp_7c1")`. Expected: `GET /ui/billing/disputes/dp_7c1`; body →
  `DisputeDto`; same shape as list item. Traces: AC-1, AC-2.
- **TC-AND-245-05** — Type: unit (JVM). Target: `DefaultDisputesRepository`.
  Preconditions: fake `DisputesApi` returns `{ items: [a, b] }`, then `{ items:
  [] }`, then throws. Steps: call `getDisputes()` three times. Expected:
  `ApiResult.Success(List<Dispute>)` of size 2; then success with empty list;
  then `ApiResult.Error`. Traces: AC-4.
- **TC-AND-245-06** — Type: unit (JVM, `runTest` + `MainDispatcherRule`). Target:
  `DisputesListViewModel`. Preconditions: repo stubbed for success(non-empty),
  success(empty), and error. Steps: init VM per case; collect `state`. Expected:
  `Loading → Content(list)`; `Loading → Empty`; `Loading → Failure(msg)`;
  `load()` re-runs the fetch. Traces: AC-5.
- **TC-AND-245-07** — Type: unit (JVM, `runTest`). Target:
  `DisputeDetailViewModel`. Preconditions: repo stubbed for success, an
  `ApiResult.Error(status=404)`, an `ApiResult.Error(status=422)`. Steps: init
  per case; collect `state`. Expected: `Loading → Content`; `Loading → NotFound`
  (defensive 404); `Loading → Failure` (422 and other non-404). `disputeId` read
  from `SavedStateHandle`. Traces: AC-6.
- **TC-AND-245-08** — Type: Compose-UI / instrumented (emu35). Target:
  `DisputesListScreen`. Preconditions: VM seeded with
  `DisputesListUiState.Content(list)`, then `Empty`, then `Failure`. Steps:
  render each; for Failure, click Retry; click a row in Content. Expected: rows
  show locale-formatted amount, status chip, reason, date; Empty shows "No
  disputes" copy; Failure shows error + Retry (Retry invokes `load()`); row tap
  invokes `onOpenDispute(dispute_id)`. Traces: AC-5, AC-7.
- **TC-AND-245-09** — Type: Compose-UI / instrumented (emu35). Target:
  `DisputeDetailScreen`. Preconditions: VM seeded with Content, NotFound,
  Failure. Steps: render each; tap Retry on Failure; tap "open related"
  affordance if `transaction_entry_id` present. Expected: Content shows status,
  reason, amount+currency, created/`deadline_at` dates; NotFound shows "Dispute
  not found"; Failure shows retry. Traces: AC-6, AC-7.
- **TC-AND-245-10** — Type: Compose-UI / instrumented (emu35). Target: status
  chip + accessibility. Preconditions: render a row with status `open`. Steps:
  inspect semantics; enable large font scale (1.3x); verify chip is not
  color-only. Expected: chip exposes `contentDescription` (e.g. "Status: open");
  row is a single focusable node with a combined label ("Dispute, $49.00, open,
  filed …"); text reflows at large font; touch target ≥ 48dp. Traces: AC-5,
  AC-7.
- **TC-AND-245-11** — Type: integration/MockWebServer (JVM). Target: error-shape
  handling end-to-end. Preconditions: MockWebServer returns `422` with
  `{ detail: [{loc:["query","limit"], msg:"…", type:"int_parsing"}] }` for the
  list, and a plain `{ detail: "Dispute not found" }` for a detail id. Steps:
  drive repo→VM. Expected: both `detail` shapes map via the shared
  `toUiMessage()` to a non-empty user message → `Failure`; no crash. Traces:
  AC-6, AC-9.
- **TC-AND-245-12** — Type: integration/MockWebServer (JVM). Target: flaky-host /
  offline + 401 path. Preconditions: MockWebServer (a) drops the connection /
  times out on first attempt then 200 on retry, and (b) a separate case returns
  `401` once then 200 after a stubbed `POST /ui/session/refresh`. Steps: trigger
  list load. Expected: timeout/5xx → bounded retry then success (or `Failure`/
  offline UI after cap); 401 → single transparent refresh-and-retry, no logout on
  recovery. Traces: AC-5, AC-6, AC-9.
- **TC-AND-245-13** — Type: unit (JVM). Target: security/logging + no-write.
  Preconditions: OkHttp logging at `BASIC`; static scan of the feature module.
  Steps: capture logs for a list+detail call; assert no `@POST`/`@PUT`/`@PATCH`/
  `@DELETE` in `DisputesApi`. Expected: logs contain no amounts, `reason`,
  `evidence_text`, `resolution`, or `admin_notes`; analytics events carry no
  dispute ids/amounts; only GETs exist (read-only). Traces: AC-8, AC-9.
- **TC-AND-245-14** — Type: instrumented/e2e (A15, physical device REQUIRED).
  Target: full list→detail flow on real arm64-v8a / API-34. Preconditions:
  signed-in session against `http://18.222.237.167:8000`; device on network.
  Steps: open Disputes; observe list renders; tap a row; observe detail renders;
  background/foreground to exercise process-death restore of `disputeId`.
  Expected: "Disputes render" for a signed-in user on the physical device;
  detail re-fetches and renders after restore; behavior matches emu35 (validates
  ABI/API-version parity — must run on A15 specifically, not the emulator).
  Traces: AC-5, AC-6.

### Coverage matrix

| AC (section 14) | Covered by |
|-----------------|------------|
| AC-1 (DisputesApi paths/verbs/params) | TC-01, TC-04 |
| AC-2 (DTOs + Moshi deserialize, null/missing defaults) | TC-02, TC-03, TC-04 |
| AC-3 (domain models + total mappers) | TC-02, TC-03 |
| AC-4 (repository bounded list/detail, success/empty/error) | TC-01, TC-05 |
| AC-5 (list screen states + nav; renders live) | TC-06, TC-08, TC-10, TC-12, TC-14 |
| AC-6 (detail content/NotFound/failure + retry) | TC-07, TC-09, TC-11, TC-12, TC-14 |
| AC-7 (StatusChip, locale money/date) | TC-02, TC-08, TC-09, TC-10 |
| AC-8 (no writes / read-only) | TC-13 |
| AC-9 (full suite green; error shapes; resilience) | TC-11, TC-12, TC-13 |
