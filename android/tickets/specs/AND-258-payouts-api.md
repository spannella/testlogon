---
id: AND-258
title: Payouts API
milestone: M6
epic: E35
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: [AND-259]
---

# AND-258 — Payouts API

## 1. Overview & Goal

This ticket delivers the network access layer for the Payouts domain of the
TestLogon native Android app: a Retrofit service interface, its Moshi DTOs, the
DTO→domain mapping functions, and the repository contract that wraps them in the
app's typed `ApiResult<T>` envelope. It is the Android port of the web reference
layer in `frontend/src/api/endpoints/payouts.ts` plus the payout-related shapes
in `frontend/src/api/types.ts`.

Scope is strictly the API/data plumbing. There is **no UI, no ViewModel, and no
navigation** in this ticket — those belong to AND-259 (Payout setup + KYC gate),
which depends on this work. The deliverable is a fully tested, injectable
`PayoutsApi` + `PayoutsRepository` pair that AND-259 (and any future payout
history/detail screen) can consume without touching Retrofit again.

The single hard acceptance signal from the backlog is: **"Payout data maps
(tested)."** Concretely, every field returned by the backend payout endpoints
deserializes into a Moshi DTO and maps losslessly into a `core-model` domain type,
proven by unit tests running against canned JSON and against MockWebServer.

Goal restated for engineers: when this ticket merges, a caller can write
`payoutsRepository.getPayoutBalance()` and `payoutsRepository.getPayouts(cursor)`
and receive `ApiResult<PayoutBalance>` / `ApiResult<PayoutPage>` with correctly
mapped, null-safe, money-precise domain objects.

> **REVIEW NOTE (2026-06-06):** This spec was reviewed against the backend
> OpenAPI (`reference/openapi.index.txt` / `openapi.pretty.json`) and the web
> reference (`reference/src/api/endpoints/payouts.ts`, `types.ts`). Several
> endpoint paths, the response field names, and the timestamp type in the
> original draft were **wrong** and have been corrected in place. There is **no**
> `GET /ui/payouts/account` and **no** `GET /ui/payouts/{payoutId}` endpoint; the
> read surface is `GET /ui/payouts/balance` and `GET /ui/payouts`. See §16 for
> the full audit.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace:** all code lands under `com.testlogon.android` — specifically
  `com.testlogon.android.core.network.payouts`,
  `com.testlogon.android.core.model.payout`, and
  `com.testlogon.android.core.data.payouts`.
- **Module placement:** DTOs + Retrofit interface in `core-network`; domain
  models in `core-model`; repository in `core-data`. Layering rule
  `core-data -> core-network -> core-model` is respected; no feature module is
  touched.
- **Web reference:** `frontend/src/api/endpoints/payouts.ts` (endpoint shapes,
  query params, cursor pagination) and `frontend/src/api/types.ts` (`Payout`,
  `PayoutBalance`, `PayoutListResp`, `PayoutCreateResp`, `PayoutActionResp`
  types). The backend OpenAPI document at `/openapi.json` on the dev host is the
  tie-breaker if the web types and live responses disagree; capture a real
  response and follow the wire. **Verified 2026-06-06:** the web client exports
  `getPayoutBalance`, `requestPayout`, `cancelPayout`, `listPayouts` — there is
  **no** `getPayoutAccount` and **no** single-payout `get` call. (Note: the web
  `types.ts` has no `PayoutAccount`/`PayoutMethod`/`PayoutStatus` enum — those
  were inventions in the original draft and have been removed below.)
- **Dependencies:** AND-027 (`AuthApi` + the authenticated OkHttp/Retrofit stack:
  persistent cookie jar, `ui_csrf` → `X-CSRF-Token` header, single 401→refresh→retry
  interceptor) is the prerequisite. This ticket reuses that exact `OkHttpClient`
  and Retrofit `Moshi` converter; it does not build a new client.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). Error bodies use the FastAPI `detail` convention.
  **Verified:** the only declared error response for the payout endpoints is
  `422 HTTPValidationError` = `{"detail":[{"loc":[...],"msg":"...","type":"..."}]}`
  (`reference/openapi.pretty.json: HTTPValidationError`); plain-string `detail`
  (e.g. on 4xx) is also handled by the web `normalizeErrorDetail`
  (`reference/src/api/client.ts`). The `{code,...}` detail variant is an
  **unverified assumption** carried from AND-027's mapper and is not present in
  this OpenAPI; see §16.
- **Blocks:** AND-259 consumes `PayoutsRepository` for the payout-setup flow and
  the KYC gate.

## 3. Functional Requirements

FR-1. Expose a Retrofit `PayoutsApi` covering the **read** payout endpoints
present in `payouts.ts` (verified against `openapi.index.txt`):
- `GET /ui/payouts/balance` — the current user's payout balance/state
  (`resp=200:PayoutBalanceOut`). **This replaces the non-existent
  `/ui/payouts/account`.**
- `GET /ui/payouts` — paginated payout (transfer) history, cursor-based
  (`resp=200:PayoutListOut`).

  Note: there is **no** `GET /ui/payouts/{payoutId}` single-detail endpoint in the
  backend. The original draft's `getPayout(payoutId)` is removed; a single payout
  is obtained by filtering `getPayouts()` results client-side, or not at all in
  this read-only ticket. The only `{payout_id}`-scoped user endpoint is
  `POST /ui/payouts/{payout_id}/cancel` (a write, deferred to AND-259 per FR-8).

FR-2. Provide Moshi DTOs for every response above with `@Json(name=...)` for each
field that differs from idiomatic Kotlin camelCase, and nullable types for every
field not guaranteed by the backend contract.

FR-3. Provide pure mapping functions `*.toDomain()` from each DTO to a
`core-model` domain type. Monetary amounts must be parsed into a precise type
(minor units `Long` + ISO-4217 `currency` string), never `Float`/`Double`.
**Correction:** the backend amount field is `amount_cents` (integer), **not**
`amount`. `PayoutOut` carries **no per-payout `currency`** — currency is only
present on `PayoutBalanceOut.currency` (default `"USD"`). Per-payout `Money` must
therefore default its currency to the balance currency or `"USD"`.

FR-4. Map the enum-like `status` string into a domain `enum` with an explicit
`UNKNOWN` fallback so unrecognized server values never throw. **Correction:**
there is **no `method.type` / methods array** in the backend; `method` is a plain
free-text string on `PayoutOut`/`PayoutRequestIn` (default `"bank_transfer"`).
It is kept as a `String` in the domain (optionally normalized to a
`PayoutMethodType` enum with `UNKNOWN` fallback, but the raw string is retained).
The authoritative `status` vocabulary is **not enumerated** in the OpenAPI
(`status` is a free `string`); the `UNKNOWN` fallback is mandatory — see §16 open
assumptions.

FR-5. Cursor pagination: `getPayouts` accepts an optional opaque `cursor: String?`
and `limit: Int`, returns items plus `nextCursor: String?`. The mapper exposes
`nextCursor` so a downstream Paging 3 source (AND-259+) can drive itself.

FR-6. Expose a `PayoutsRepository` interface + Hilt-bound implementation returning
`ApiResult<T>`. GETs here are idempotent and therefore eligible for the bounded
backoff retry policy defined in the network core.

FR-7. All requests automatically carry session cookies and the `X-CSRF-Token`
header via the shared client from AND-027; this ticket adds **no** auth code.

FR-8. No write endpoints are in scope here. `payouts.ts` **does** expose writes —
`requestPayout` → `POST /ui/payouts/request` (`PayoutRequestIn` → `201
PayoutCreateOut`) and `cancelPayout` → `POST /ui/payouts/{payout_id}/cancel`
(→ `PayoutActionOut`). Their DTOs (`PayoutRequestDto`, `PayoutCreateRespDto`,
`PayoutActionRespDto`) **may be declared** in this ticket but are *owned and
exercised* by AND-259; this ticket only guarantees the read path
(`getPayoutBalance`, `getPayouts`) is mapped and tested.

## 4. Technical Design

Retrofit interface (suspend functions, `ApiResult` wrapping happens in the repo):

```kotlin
package com.testlogon.android.core.network.payouts

interface PayoutsApi {
    // Verified: GET /ui/payouts/balance -> PayoutBalanceOut
    @GET("ui/payouts/balance")
    suspend fun getPayoutBalance(): PayoutBalanceDto

    // Verified: GET /ui/payouts -> PayoutListOut; params=limit,cursor
    @GET("ui/payouts")
    suspend fun getPayouts(
        @Query("limit") limit: Int = 20,
        @Query("cursor") cursor: String? = null,
    ): PayoutListDto

    // NOTE: there is no GET /ui/payouts/{payoutId}; removed.
}
```

DTOs (`core-network`):

DTO shapes below are taken **verbatim** from the OpenAPI schemas `PayoutListOut`,
`PayoutOut`, and `PayoutBalanceOut` (`reference/openapi.pretty.json`) cross-checked
with the web `types.ts`.

```kotlin
// OpenAPI: PayoutListOut { items: PayoutOut[] (required), next_cursor: string|null }
// NOTE: there is NO `total` field on the backend response — removed.
@JsonClass(generateAdapter = true)
data class PayoutListDto(
    @Json(name = "items") val items: List<PayoutDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

// OpenAPI: PayoutOut. created_at/updated_at are INTEGER epoch seconds, not ISO
// strings. No `currency`, no `arrival_at`. Failure text is `reject_reason`.
@JsonClass(generateAdapter = true)
data class PayoutDto(
    @Json(name = "payout_id") val payoutId: String,
    @Json(name = "user_id") val userId: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "method") val method: String? = null,        // default "bank_transfer"
    @Json(name = "status") val status: String,
    @Json(name = "created_at") val createdAt: Long,           // epoch seconds
    @Json(name = "updated_at") val updatedAt: Long,           // epoch seconds
    @Json(name = "notes") val notes: String? = null,
    @Json(name = "reject_reason") val rejectReason: String? = null,
    @Json(name = "approved_by") val approvedBy: String? = null,
    @Json(name = "completed_at") val completedAt: Long? = null, // epoch seconds | null
)

// OpenAPI: PayoutBalanceOut (all integer cents; currency string; has minimum).
// This REPLACES the invented PayoutAccountDto/PayoutMethodDto. There is no
// methods[], account_id, default_method_id, kyc_tier, or payouts_enabled on the
// backend payout API.
@JsonClass(generateAdapter = true)
data class PayoutBalanceDto(
    @Json(name = "available_cents") val availableCents: Long = 0,
    @Json(name = "pending_cents") val pendingCents: Long = 0,
    @Json(name = "total_earned_cents") val totalEarnedCents: Long = 0,
    @Json(name = "hold_cents") val holdCents: Long = 0,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "minimum_payout_cents") val minimumPayoutCents: Long = 1000,
)

// Write DTOs — DECLARED here, OWNED/exercised by AND-259 (FR-8):
@JsonClass(generateAdapter = true)
data class PayoutRequestDto(           // OpenAPI: PayoutRequestIn
    @Json(name = "amount_cents") val amountCents: Long,  // minimum 100
    @Json(name = "method") val method: String = "bank_transfer",
    @Json(name = "notes") val notes: String = "",
)

@JsonClass(generateAdapter = true)
data class PayoutCreateRespDto(        // OpenAPI: PayoutCreateOut (201)
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "payout_id") val payoutId: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "status") val status: String,
)

@JsonClass(generateAdapter = true)
data class PayoutActionRespDto(        // OpenAPI: PayoutActionOut
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "payout_id") val payoutId: String,
    @Json(name = "status") val status: String,
)
```

Domain models (`core-model`):

```kotlin
package com.testlogon.android.core.model.payout

data class Money(val amountMinor: Long, val currency: String) // e.g. 1299, "USD"

// status vocabulary is NOT enumerated by the backend (free string); UNKNOWN is
// the mandatory fallback. Members below are a best-effort guess (see §16).
enum class PayoutStatus { PENDING, PROCESSING, APPROVED, PAID, REJECTED, CANCELED, UNKNOWN }

// `method` is a free string on the backend (default "bank_transfer"); we keep the
// raw string and ALSO expose a best-effort enum. UNKNOWN must not throw.
enum class PayoutMethodType { BANK_TRANSFER, PAYPAL, CARD, UNKNOWN }

data class Payout(
    val payoutId: String,
    val userId: String,
    val amount: Money,                 // amount_cents + balance/"USD" currency
    val status: PayoutStatus,
    val method: String?,               // raw server string (e.g. "bank_transfer")
    val createdAt: Instant,            // from epoch-seconds Long
    val updatedAt: Instant,            // from epoch-seconds Long
    val completedAt: Instant?,         // nullable epoch-seconds
    val notes: String?,
    val rejectReason: String?,
    val approvedBy: String?,
)

// no `total` — PayoutListOut has only items + next_cursor.
data class PayoutPage(val items: List<Payout>, val nextCursor: String?)

// Replaces the invented PayoutAccount/PayoutMethod. Mirrors PayoutBalanceOut.
data class PayoutBalance(
    val availableCents: Long,
    val pendingCents: Long,
    val totalEarnedCents: Long,
    val holdCents: Long,
    val currency: String,
    val minimumPayoutCents: Long,
)
```

Mappers (`core-network`, pure, package-visible functions):

```kotlin
// currency is taken from the caller's PayoutBalance (or "USD"); PayoutOut has none.
internal fun PayoutDto.toDomain(currency: String = "USD"): Payout = Payout(
    payoutId = payoutId,
    userId = userId,
    amount = Money(amountCents, currency),
    status = status.toPayoutStatus(),
    method = method,
    createdAt = Instant.ofEpochSecond(createdAt),
    updatedAt = Instant.ofEpochSecond(updatedAt),
    completedAt = completedAt?.let { Instant.ofEpochSecond(it) },
    notes = notes,
    rejectReason = rejectReason,
    approvedBy = approvedBy,
)

internal fun PayoutListDto.toDomain(currency: String = "USD"): PayoutPage = PayoutPage(
    items = items.map { it.toDomain(currency) },
    nextCursor = nextCursor,
)

internal fun PayoutBalanceDto.toDomain(): PayoutBalance = PayoutBalance(
    availableCents = availableCents,
    pendingCents = pendingCents,
    totalEarnedCents = totalEarnedCents,
    holdCents = holdCents,
    currency = currency,
    minimumPayoutCents = minimumPayoutCents,
)

internal fun String?.toPayoutStatus(): PayoutStatus = when (this?.lowercase()) {
    "pending" -> PayoutStatus.PENDING
    "processing" -> PayoutStatus.PROCESSING
    "approved" -> PayoutStatus.APPROVED
    "paid", "completed", "succeeded" -> PayoutStatus.PAID
    "rejected" -> PayoutStatus.REJECTED
    "canceled", "cancelled" -> PayoutStatus.CANCELED
    else -> PayoutStatus.UNKNOWN
}
```

**Correction:** `created_at`/`updated_at`/`completed_at` are **integer epoch
seconds** in `PayoutOut`, so the mapper uses `Instant.ofEpochSecond(...)`, **not**
an ISO-8601 string parser. (The original draft's `toInstantOrNull()` ISO parser is
wrong for this endpoint — the web `types.ts` types these as `number`.) The status
strings above (`processing`, `approved`, `rejected`, …) are a best-effort guess
derived from the admin action endpoints (`approve`/`reject`/`mark-paid`/`complete`)
since the OpenAPI does not enumerate `status`; `UNKNOWN` is the guaranteed
fallback — see §16 open assumptions.

Repository:

```kotlin
package com.testlogon.android.core.data.payouts

interface PayoutsRepository {
    suspend fun getPayoutBalance(): ApiResult<PayoutBalance>
    suspend fun getPayouts(cursor: String? = null, limit: Int = 20): ApiResult<PayoutPage>
    // no getPayout(payoutId) — backend has no single-payout GET endpoint.
}

class DefaultPayoutsRepository @Inject constructor(
    private val api: PayoutsApi,
) : PayoutsRepository {
    override suspend fun getPayoutBalance(): ApiResult<PayoutBalance> =
        apiCall { api.getPayoutBalance().toDomain() }

    override suspend fun getPayouts(cursor: String?, limit: Int): ApiResult<PayoutPage> =
        apiCall { api.getPayouts(limit, cursor).toDomain() }
}
```

`apiCall { }` is the shared inline helper from `core-network` that runs the block,
catches `HttpException`/`IOException`/timeouts, maps the FastAPI `detail` body, and
returns `ApiResult.Success`/`ApiResult.Error`. Hilt module:

```kotlin
@Module @InstallIn(SingletonComponent::class)
object PayoutsNetworkModule {
    @Provides @Singleton
    fun providePayoutsApi(retrofit: Retrofit): PayoutsApi = retrofit.create()
}

@Module @InstallIn(SingletonComponent::class)
abstract class PayoutsDataModule {
    @Binds abstract fun bindPayoutsRepository(impl: DefaultPayoutsRepository): PayoutsRepository
}
```

## 5. API Contract

Base URL: `http://18.222.237.167:8000/`. All calls authenticated via shared cookie
jar + `X-CSRF-Token` (AND-027). Verify exact paths against `/openapi.json` and
`payouts.ts` at implementation time; the shapes below are the contract this ticket
maps to.

All samples below are derived from the verified OpenAPI schemas
(`PayoutBalanceOut`, `PayoutListOut`, `PayoutOut`).

`GET /ui/payouts/balance` → 200 (`PayoutBalanceOut`):

```json
{
  "available_cents": 4500,
  "pending_cents": 1200,
  "total_earned_cents": 98000,
  "hold_cents": 0,
  "currency": "USD",
  "minimum_payout_cents": 1000
}
```

`GET /ui/payouts?limit=20&cursor=` → 200 (`PayoutListOut`, items are `PayoutOut`):

```json
{
  "items": [
    {
      "payout_id": "po_1029",
      "user_id": "usr_77",
      "amount_cents": 4500,
      "method": "bank_transfer",
      "status": "paid",
      "created_at": 1748628251,
      "updated_at": 1748800800,
      "notes": "",
      "reject_reason": "",
      "approved_by": "admin_3",
      "completed_at": 1748800800
    }
  ],
  "next_cursor": "eyJrIjoicG9fMTAyOSJ9"
}
```

Notes on the verified shape (corrections vs. the original draft):
- item key is `payout_id` (not `id`); amount is `amount_cents` (not `amount`);
  method is a free string `method` (not `method_id`); failure text is
  `reject_reason` (not `failure_reason`).
- `created_at`/`updated_at`/`completed_at` are **integer epoch seconds**, not ISO
  strings; `completed_at` may be `null`.
- there is **no per-item `currency`** and **no `arrival_at`**; `PayoutListOut` has
  **no `total`** field.
- additional `PayoutOut` fields not in the original draft: `user_id`, `updated_at`,
  `notes`, `approved_by`.

There is **no** `GET /ui/payouts/{payoutId}` endpoint. (Write endpoints, deferred
to AND-259: `POST /ui/payouts/request` → 201 `PayoutCreateOut`; `POST
/ui/payouts/{payout_id}/cancel` → 200 `PayoutActionOut`.)

Query/header params on the user payout endpoints (per `openapi.index.txt`):
`limit`, `cursor`, and `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`. The
Android client supplies session via the AND-027 cookie jar; `user_sub` is derived
server-side from the session and is not sent by this client.

Error responses (FastAPI): the **only declared error code** for these endpoints is
`422 HTTPValidationError` = `{"detail":[{"loc":[...],"msg":"...","type":"..."}]}`.
401 is handled by the AND-027 refresh-once interceptor before reaching the repo; a
plain-string `detail` (e.g. 4xx) is normalized by the shared mapper; 5xx /
connection failure → mapped to `ApiResult.Error`. (A 404
`{"detail":"Payout not found"}` is **not** a declared response here since there is
no single-payout GET; that error shape from the original draft was removed.)

## 6. Data & State Management

This ticket introduces **no persistent state**, no Room table, and no DataStore
key. It produces in-memory domain objects only. Caching of payout history (Room)
and Paging 3 mediation are explicitly deferred to AND-259 / a future history
screen; the `nextCursor` field and the `PayoutPage` shape are provided here so
that work can plug in without changing this layer.

State exposure to callers is via the suspend functions returning `ApiResult<T>`.
No `StateFlow`/`UiState` is created in this ticket (that is ViewModel territory in
AND-259). `Money` carries minor units + currency to keep all downstream
formatting (locale-aware `NumberFormat`) lossless and the responsibility of the
UI layer.

Note: the KYC gate that AND-259 builds is **not** driven by any payout field — the
backend payout API exposes no `kyc_tier`/`payouts_enabled`. AND-259 must source
KYC state from the dedicated KYC endpoints (e.g. `reference/src/api/endpoints/kyc.ts`),
not from this layer. `PayoutBalance.minimumPayoutCents` is the only gating value
this ticket surfaces (used by AND-259 to validate request amounts).

## 7. Error Handling & Resilience

- All three calls are idempotent GETs and therefore opt into the network core's
  **bounded backoff retry** (max ~2 retries, jittered) for transient
  `IOException`/timeout/5xx — appropriate given the unreliable dev host.
- Per-request timeout follows the global ~20s call timeout configured on the
  shared OkHttp client (AND-027); this ticket does not override it.
- 401 is resolved upstream by the single refresh-then-retry interceptor; the repo
  never sees a bare 401 unless refresh itself fails, in which case it surfaces as
  `ApiResult.Error` (auth) for AND-259 to route to login.
- Mapping is defensively null-safe where the contract allows nulls: `amount_cents`
  is a **required** integer (no default needed; a missing/non-int value is a Moshi
  structural failure → `ApiResult.Error`); per-item currency is sourced from the
  caller's `PayoutBalance` or defaults to `"USD"` (there is no per-item currency on
  the wire); unknown `status` → `PayoutStatus.UNKNOWN`; nullable `completed_at` →
  `null`; `notes`/`reject_reason`/`approved_by`/`method` default to empty/`null`.
  `created_at`/`updated_at` are required epoch-second integers parsed with
  `Instant.ofEpochSecond`. A malformed but type-valid payload never throws from a
  mapper; only a Moshi structural failure (e.g., `items` not an array, a missing
  required field, a non-integer timestamp) yields `ApiResult.Error`.
- Empty history (`items: []`, `next_cursor: null`) is a valid success, not an
  error.

## 8. Security & Privacy

- Payout data is financial PII (amounts/`amount_cents`, balances, `user_id`, free
  `notes`/`reject_reason`). It must **never** be written to logs. The OkHttp
  `HttpLoggingInterceptor` for payout endpoints must be `Level.NONE` (or
  headers-only) in release builds; body logging is permitted only in debug and even
  then amounts/`user_id`/`notes` should be redacted by the shared logging redactor.
  (Note: the original draft referenced `last4`/`label`/bank-account fields — those
  do **not** exist on this API; the sensitive fields are the cents amounts and the
  free-text `notes`/`reject_reason`.)
- No tokens are handled here; auth is cookie-based and owned by AND-027. The
  persistent cookie jar must remain in encrypted/private app storage as
  established there.
- Transport is plaintext HTTP **only because the dev host is HTTP**; the
  production base URL must be HTTPS and `cleartextTrafficPermitted` is scoped to
  the dev host via the existing network-security-config. This ticket adds no new
  cleartext exemption.
- DTOs are not serialized to disk in this ticket, so no at-rest exposure is
  introduced.

## 9. Accessibility & i18n

No UI is produced, so screen-level a11y is N/A and owned by AND-259. Two
i18n-relevant contracts are established here:

- `Money` keeps amount + ISO currency separate so AND-259 can format with
  locale-aware `NumberFormat.getCurrencyInstance(locale)`. No currency symbols or
  formatted strings are produced in this layer.
- Server-provided strings (`label`, `failure_reason`) are passed through
  verbatim; any user-facing copy for statuses (e.g., "In transit") is mapped from
  the `PayoutStatus` enum to string resources in AND-259, not hardcoded here.

## 10. Telemetry & Logging

- Network timing/outcome telemetry is captured by the shared OkHttp event
  listener from the core; payout calls inherit it automatically with the route
  tag `payouts`. No request/response bodies are emitted.
- The repository may emit a structured, **non-PII** breadcrumb on error only:
  endpoint name, HTTP status, and mapped error category — never amounts, ids of
  financial methods, or `last4`.
- No new analytics events are defined; user-facing payout events belong to
  AND-259.

## 11. Testing Strategy

This is the heart of the acceptance criterion ("Payout data maps (tested)").

Unit — mapping (`core-network`, JVM, no Android):
1. `PayoutDto.toDomain()` maps a fully populated `PayoutOut` fixture to `Payout`
   with correct `Money(amountCents, currency)`, `Instant.ofEpochSecond` for
   `createdAt`/`updatedAt`/`completedAt`, and status.
2. Each `status` string variant (`pending`, `processing`, `approved`,
   `paid`/`completed`/`succeeded`, `rejected`, `canceled`/`cancelled`) maps to the
   right enum; an unknown string → `PayoutStatus.UNKNOWN`.
3. Nullable `completed_at`, empty/missing `notes`/`reject_reason`/`approved_by`/
   `method` produce the documented defaults without throwing; per-item currency
   defaults to `"USD"` when not supplied by the caller.
4. `PayoutBalanceDto.toDomain()` maps all six cents/currency fields, including the
   schema defaults (`minimum_payout_cents` → 1000, `currency` → "USD").
5. `PayoutListDto.toDomain()` preserves item order and `nextCursor`; empty
   `items` → empty list, success; absent `next_cursor` → `null`.

Integration — MockWebServer (`core-testing`):
6. `getPayouts(20, cursor)` issues `GET /ui/payouts?limit=20&cursor=...` with the
   exact path, verb, and query encoding (assert recorded request).
7. `getPayoutBalance()` hits `GET /ui/payouts/balance` (assert path + verb).
8. A 422 detail-array `{"detail":[{"loc":[...],"msg":"...","type":"..."}]}` →
   `ApiResult.Error` with the mapped message; a plain-string `detail` → mapped
   message.
9. A 503 then 200 verifies the idempotent-GET retry succeeds (drives the shared
   retry policy); confirm request count.
10. Moshi adapters are confirmed generated (KSP) — a test deserializes the
    sample payloads from §5 verbatim.

Coverage target: 100% of the mapper functions and every `ApiResult` branch in
`DefaultPayoutsRepository`.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (authenticated Retrofit/OkHttp stack, cookie jar,
  CSRF interceptor, 401-refresh interceptor, shared Moshi, `ApiResult`/`apiCall`,
  FastAPI error mapper). This ticket must not reimplement any of those.
- **Depends transitively** on the core network module bootstrap from M1 (the
  `Retrofit` `@Provides` and base-URL config).
- **Blocks AND-259** (Payout setup + KYC gate), which consumes
  `PayoutsRepository`, `PayoutBalance.minimumPayoutCents`/`availableCents` for
  request validation, the write DTOs declared here, and `PayoutPage.nextCursor`
  for history paging. (The KYC gate is sourced from the KYC endpoints, not from
  this layer — see §6.)
- Sequencing within the ticket: confirm live shapes via `/openapi.json` →
  DTOs + Moshi adapters → domain models in `core-model` → mappers + unit tests →
  `PayoutsApi` + MockWebServer tests → repository + Hilt wiring + repo tests.

## 13. Risks & Open Questions

- **R1 — Wire shape drift.** **RESOLVED 2026-06-06:** confirmed against OpenAPI —
  `amount_cents` is an integer (minor units), pagination is `next_cursor`
  (string|null) with no `total`, and timestamps are integer epoch seconds. DTOs
  updated. Residual risk: if the live dev host diverges from the committed OpenAPI,
  capture a real response and re-confirm.
- **R2 — Endpoint paths.** **RESOLVED:** verified `GET /ui/payouts/balance` and
  `GET /ui/payouts` exist (`openapi.index.txt`); `/ui/payouts/account` and
  `GET /ui/payouts/{id}` do **not** exist. Paths corrected in §3–§5.
- **R3 — Status vocabulary.** The OpenAPI types `status` as a free `string` and
  does **not** enumerate the value set. The `UNKNOWN` fallback prevents crashes;
  the enum members (`PENDING`/`PROCESSING`/`APPROVED`/`PAID`/`REJECTED`/`CANCELED`)
  are a best-effort guess inferred from the admin action endpoints
  (`approve`/`reject`/`mark-paid`/`complete`). **Open (unverifiable from sources):**
  capture live payouts to confirm the authoritative status strings.
- **R4 — Write endpoint ownership.** **RESOLVED:** `payouts.ts` exposes two writes
  — `POST /ui/payouts/request` and `POST /ui/payouts/{payout_id}/cancel` (no
  create/update-*method* endpoint exists). Decision unchanged: read-only here;
  write DTOs (`PayoutRequestDto`/`PayoutCreateRespDto`/`PayoutActionRespDto`) may
  be declared here but are owned/tested by AND-259.
- **R5 — Dev host flakiness** could make MockWebServer the only reliable test
  surface; that is acceptable since acceptance is mapping correctness, not live
  connectivity.

## 14. Acceptance Criteria

1. `PayoutsApi`, the DTOs, domain models, mappers, `PayoutsRepository`, and Hilt
   modules exist under `com.testlogon.android.core.{network,model,data}.payout(s)`
   on branch `android-port`, with correct module layering.
2. Every field in the §5 response samples deserializes into its DTO via generated
   Moshi adapters and maps into the domain model with no data loss
   (**"Payout data maps"**).
3. Monetary values are represented as `Money(amountMinor: Long, currency: String)`
   — no floating-point money anywhere in the chain.
4. `status` maps to an enum with an `UNKNOWN` fallback; no unrecognized server
   string throws. (`method` is retained as a raw string per the verified contract;
   any `PayoutMethodType` normalization also has an `UNKNOWN` fallback.)
5. `getPayouts` supports `cursor` + `limit` and surfaces `nextCursor`.
6. Both read repository methods (`getPayoutBalance`, `getPayouts`) return
   `ApiResult<T>`, route errors through the shared FastAPI `detail` mapper, and use
   the shared idempotent-GET retry.
7. Unit + MockWebServer tests from §11 are present and green, including the
   path/verb/query assertions and the null-defaulting cases (**"(tested)"**).
8. No payout PII appears in logs in release configuration.

## 15. Definition of Done

- All §14 acceptance criteria met; CI green (`assembleDebug`, `ktlint`/detekt,
  unit + MockWebServer test tasks for `core-network`/`core-data`).
- No new cleartext-traffic exemption, no new logging of financial PII; release
  logging interceptor verified `NONE`/redacted for payout routes.
- KSP generates all Moshi adapters; no reflection-based JSON fallback.
- Public surface (`PayoutsApi`, `PayoutsRepository`, domain models) has KDoc; the
  `nextCursor`/`Money` contract is documented for AND-259.
- Code reviewed and merged to `android-port`; AND-259 can inject
  `PayoutsRepository` with no further network changes.
- Open questions R1–R4 either resolved against `/openapi.json` or recorded as
  follow-up notes on AND-259.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index (`reference/openapi.index.txt`), OpenAPI full spec
(`reference/openapi.pretty.json`, `components.schemas.<Name>`), and frontend
(`reference/src/api/...`).

1. **Read endpoint is `GET /ui/payouts/balance` returning `PayoutBalanceOut`.**
   VERIFIED. Source: OpenAPI `GET /ui/payouts/balance` (op
   `payout_balance_ui_payouts_balance_get`, `resp=200:PayoutBalanceOut`);
   `src/api/endpoints/payouts.ts: getPayoutBalance`.
2. **Original draft's `GET /ui/payouts/account` does not exist.** CORRECTED
   (removed). Source: no such path in `openapi.index.txt`; `payouts.ts` has no
   `getPayoutAccount`.
3. **Paginated history is `GET /ui/payouts` returning `PayoutListOut`; params
   `limit`, `cursor`.** VERIFIED. Source: OpenAPI `GET /ui/payouts` (op
   `list_payouts_ui_payouts_get`, `resp=200:PayoutListOut`,
   `params=limit,cursor,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`);
   `src/api/endpoints/payouts.ts: listPayouts`.
4. **`PayoutListOut` has only `items` + `next_cursor` (no `total`).** CORRECTED
   (draft's `total` removed). Source: `openapi.pretty.json: PayoutListOut`
   (properties = items, next_cursor; required = [items]);
   `src/api/types.ts: PayoutListResp` (`items`, `next_cursor`).
5. **No `GET /ui/payouts/{payoutId}` single-detail endpoint.** CORRECTED
   (`getPayout` removed). Source: `openapi.index.txt` has only
   `POST /ui/payouts/{payout_id}/cancel` for the `{payout_id}` path; no GET.
6. **Payout item key is `payout_id` (not `id`).** CORRECTED. Source:
   `openapi.pretty.json: PayoutOut` (`payout_id` required);
   `src/api/types.ts: Payout.payout_id`.
7. **Amount field is `amount_cents` integer (not `amount`).** CORRECTED. Source:
   `openapi.pretty.json: PayoutOut.amount_cents` (type integer, required);
   `src/api/types.ts: Payout.amount_cents: number`.
8. **`created_at`/`updated_at`/`completed_at` are integer epoch seconds, not ISO
   strings; `completed_at` nullable.** CORRECTED (mapper now uses
   `Instant.ofEpochSecond`, not an ISO parser). Source: `openapi.pretty.json:
   PayoutOut` (`created_at`/`updated_at` type integer; `completed_at` anyOf
   integer|null); `src/api/types.ts: Payout` (`created_at: number`,
   `completed_at: number | null`).
9. **No per-item `currency` and no `arrival_at` on `PayoutOut`; currency lives on
   `PayoutBalanceOut`.** CORRECTED. Source: `openapi.pretty.json: PayoutOut`
   (no currency/arrival_at properties); `PayoutBalanceOut.currency` (default
   "USD").
10. **Failure text is `reject_reason` (not `failure_reason`); `method` is a free
    string (not `method_id`).** CORRECTED. Source: `openapi.pretty.json: PayoutOut`
    (`reject_reason`, `method` default "bank_transfer");
    `src/api/types.ts: Payout` (`method`, `reject_reason`).
11. **Additional `PayoutOut` fields: `user_id`, `notes`, `approved_by`.** VERIFIED
    (added). Source: `openapi.pretty.json: PayoutOut`; `src/api/types.ts: Payout`.
12. **`PayoutBalanceOut` fields: `available_cents`, `pending_cents`,
    `total_earned_cents`, `hold_cents`, `currency`, `minimum_payout_cents`.**
    VERIFIED. Source: `openapi.pretty.json: PayoutBalanceOut`;
    `src/api/types.ts: PayoutBalance`.
13. **There is no `methods[]`/`PayoutMethod`/`kyc_tier`/`payouts_enabled`/
    `account_id` on the payout API.** CORRECTED (invented `PayoutAccount`/
    `PayoutMethod` types removed). Source: absence in `openapi.pretty.json`
    payout schemas and `src/api/types.ts` (no `PayoutAccount`/`PayoutMethod`).
14. **Write endpoints exist and are deferred to AND-259:
    `POST /ui/payouts/request` (`PayoutRequestIn`→201 `PayoutCreateOut`),
    `POST /ui/payouts/{payout_id}/cancel` (→`PayoutActionOut`).** VERIFIED. Source:
    OpenAPI `create_payout_request_...`, `cancel_payout_request_...`;
    `src/api/endpoints/payouts.ts: requestPayout, cancelPayout`. `PayoutRequestIn`
    requires `amount_cents` (minimum 100) — `openapi.pretty.json: PayoutRequestIn`.
15. **Auth/CSRF: session via cookies (`credentials: include`); `ui_csrf` cookie →
    `X-CSRF-Token` header; 401 → refresh-once → retry.** VERIFIED for the web
    contract. Source: `src/api/client.ts` (lines ~168–171 CSRF, ~183/220
    `credentials: "include"`, ~194–221 refresh-once-then-retry). The Android port
    reuses AND-027's cookie jar + CSRF interceptor per §2.
16. **Declared error shape is `422 HTTPValidationError`
    (`detail:[{loc,msg,type}]`).** VERIFIED. Source: every payout op in
    `openapi.index.txt` lists `422:HTTPValidationError`;
    `openapi.pretty.json: HTTPValidationError`. Plain-string `detail` handling:
    `src/api/client.ts: normalizeErrorDetail`.
17. **Money modeled as minor units `Long` + ISO-4217 currency string (no
    float).** VERIFIED as a design choice consistent with the integer-cents wire
    contract. Source: `amount_cents`/`*_cents` integers in OpenAPI schemas above.
18. **Framework choices (Retrofit `@GET`/`@Query`/`@Path`, Moshi `@JsonClass`/
    `@Json`, KSP codegen, Hilt `@Module`/`@Binds`, `java.time.Instant`).**
    Unverified against the in-repo Android stack (no Android sources in the
    reference set) but standard. framework ref: Retrofit
    https://square.github.io/retrofit/ ; Moshi codegen
    https://github.com/square/moshi#codegen ; Hilt
    https://developer.android.com/training/dependency-injection/hilt-android ;
    `Instant` https://developer.android.com/reference/java/time/Instant .

### Corrections made

- Removed non-existent endpoints `GET /ui/payouts/account` and
  `GET /ui/payouts/{payoutId}`; replaced read surface with
  `GET /ui/payouts/balance` + `GET /ui/payouts` (claims 2, 5).
- Replaced invented `PayoutAccountDto`/`PayoutMethodDto`/`PayoutAccount`/
  `PayoutMethod`/`PayoutStatus(IN_TRANSIT…)` and `is_default`/`payouts_enabled`/
  `kyc_tier` with the real `PayoutBalanceDto`/`PayoutBalance` (claims 4, 13).
- Renamed/retyped `PayoutDto` fields: `id`→`payout_id`, `amount`→`amount_cents`,
  `method_id`→`method` (string), `failure_reason`→`reject_reason`; added
  `user_id`, `updated_at`, `notes`, `approved_by`; timestamps integer epoch
  seconds via `Instant.ofEpochSecond` (claims 6–11).
- Removed `total` from `PayoutListOut`/`PayoutPage` (claim 4).
- Reworked the `status` enum (PROCESSING/APPROVED/REJECTED) and demoted `method`
  to a free string per the verified contract.
- Corrected §5 samples, §8 PII fields (amounts/`user_id`/`notes`, not
  `last4`/`label`), §11 tests, and the §13 risk resolutions.
- Removed the undeclared `404 {"detail":"Payout not found"}` error claim (no
  single-payout GET).

### Open assumptions

- **`status` value set.** The OpenAPI types `status` as a free `string` with no
  enum; the domain enum members are inferred from the admin action endpoints
  (`approve`/`reject`/`mark-paid`/`complete`) and are a guess. `UNKNOWN` fallback
  is mandatory. Cannot be verified from the supplied sources; needs a live
  capture. (R3.)
- **Per-payout currency.** No per-item currency on the wire; the mapper assumes
  the balance currency (or `"USD"`). Holds only if a user's payouts share the
  balance currency — unverifiable from the sources.
- **`{code,...}` error `detail` variant.** Carried from AND-027's mapper but not
  present in this OpenAPI; treat as unverified until AND-027's mapper is inspected.
- **`X-SESSION-ID`/`user_sub`/`X-IMPERSONATION-TOKEN` params.** Present in the
  OpenAPI param list; assumed satisfied by the AND-027 cookie-session stack rather
  than sent explicitly. Unverified against AND-027's actual interceptor code.
- **Android framework integration** (Retrofit/Moshi/Hilt/KSP wiring, shared
  `ApiResult`/`apiCall`, retry policy, OkHttp client). Defined by AND-027/M1; no
  Android sources in the reference set, so treated as assumptions (claim 18).

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric unit, no device; **emulator** =
headless AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15
5G (SM-A156U, API 34, arm64-v8a). This ticket is a pure data/network layer with
**no UI** — the bulk runs on JVM (mapping + MockWebServer). Compose-UI/a11y cases
are N/A here and owned by AND-259; one ABI-difference smoke is noted for the
device. AC-# references are to the §14 Acceptance Criteria.

- **TC-AND-258-01** — Type: unit (JVM). Target: `PayoutDto.toDomain()`.
  Preconditions: fully populated `PayoutOut` JSON fixture from §5. Steps: parse via
  generated Moshi adapter, call `toDomain("USD")`. Expected: `Payout` with
  `amount = Money(4500,"USD")`, `payoutId="po_1029"`, `userId`, `method`,
  `status=PAID`, `createdAt/updatedAt/completedAt` = `Instant.ofEpochSecond(...)`,
  `notes/rejectReason/approvedBy` mapped; no data loss. Traces: AC-2, AC-3.
- **TC-AND-258-02** — Type: unit (JVM). Target: `String?.toPayoutStatus()`.
  Preconditions: none. Steps: map `pending`, `processing`, `approved`, `paid`,
  `completed`, `succeeded`, `rejected`, `canceled`, `cancelled`, `"WeIrD"`, `null`.
  Expected: each maps to the documented enum; `"WeIrD"`/`null` → `UNKNOWN`; never
  throws. Traces: AC-4.
- **TC-AND-258-03** — Type: unit (JVM). Target: `PayoutDto.toDomain()` defaults.
  Preconditions: `PayoutOut` fixture with `completed_at=null`, omitted
  `notes`/`reject_reason`/`approved_by`/`method`, no caller currency. Steps: map.
  Expected: `completedAt=null`, empty/`null` text fields, `method=null`,
  `currency="USD"`; no throw. Traces: AC-2, AC-4.
- **TC-AND-258-04** — Type: unit (JVM). Target: money precision. Preconditions:
  `amount_cents` = `2147483648` (> Int.MAX) and `0`. Steps: map. Expected:
  `Money.amountMinor` is `Long`, exact, no float/precision loss. Traces: AC-3.
- **TC-AND-258-05** — Type: unit (JVM). Target: `PayoutBalanceDto.toDomain()` and
  schema defaults. Preconditions: (a) full balance JSON from §5; (b) `{}` empty
  object. Steps: parse + map both. Expected: (a) all six fields mapped; (b) Moshi
  defaults applied (`available/pending/total/hold=0`, `currency="USD"`,
  `minimumPayoutCents=1000`). Traces: AC-2.
- **TC-AND-258-06** — Type: unit (JVM). Target: `PayoutListDto.toDomain()`.
  Preconditions: list with 3 items + `next_cursor`; and empty `items:[]` with
  absent `next_cursor`. Steps: map both. Expected: item order preserved,
  `nextCursor` surfaced; empty → empty list + `nextCursor=null`; success (not an
  error); no `total` field referenced. Traces: AC-2, AC-5.
- **TC-AND-258-07** — Type: contract/MockWebServer (JVM). Target:
  `PayoutsApi.getPayouts` request. Preconditions: MockWebServer enqueues 200
  `PayoutListOut`. Steps: call `repo.getPayouts(cursor="C1", limit=20)`; inspect
  recorded request. Expected: `GET /ui/payouts?limit=20&cursor=C1`, correct verb
  and URL-encoded query; returns `ApiResult.Success<PayoutPage>`. Traces: AC-5,
  AC-6, AC-7.
- **TC-AND-258-08** — Type: contract/MockWebServer (JVM). Target:
  `PayoutsApi.getPayoutBalance` request. Preconditions: enqueue 200
  `PayoutBalanceOut`. Steps: call `repo.getPayoutBalance()`; inspect recorded
  request. Expected: `GET /ui/payouts/balance` (path + verb); maps to
  `ApiResult.Success<PayoutBalance>`. Traces: AC-6, AC-7.
- **TC-AND-258-09** — Type: contract/MockWebServer (JVM). Target: 422 error
  mapping. Preconditions: enqueue 422
  `{"detail":[{"loc":["query","limit"],"msg":"bad","type":"x"}]}`. Steps: call
  `repo.getPayouts()`. Expected: `ApiResult.Error` with the shared FastAPI-detail
  mapped message; no crash. Traces: AC-6, AC-7.
- **TC-AND-258-10** — Type: contract/MockWebServer (JVM). Target: structural Moshi
  failure. Preconditions: enqueue 200 with `items` as an object (not array), or a
  missing required `payout_id`/non-integer `created_at`. Steps: call
  `repo.getPayouts()`. Expected: `ApiResult.Error` (mapping failure surfaced, not a
  thrown uncaught exception). Traces: AC-2, AC-6.
- **TC-AND-258-11** — Type: integration/MockWebServer (JVM). Target: idempotent-GET
  retry + offline/flaky-host path. Preconditions: enqueue `503` then `200`; then a
  separate run enqueueing repeated `IOException`/`SocketTimeout`. Steps: call
  `repo.getPayouts()` for each. Expected: 503-then-200 yields `Success` after the
  bounded backoff retry (assert request count = 2); exhausted transient failures
  yield `ApiResult.Error` (no infinite retry). Traces: AC-6, AC-7.
- **TC-AND-258-12** — Type: unit (JVM). Target: PII-safe error breadcrumb.
  Preconditions: error path with a populated body (amounts/`user_id`/`notes`).
  Steps: trigger `ApiResult.Error`, capture the structured breadcrumb. Expected:
  breadcrumb contains endpoint name + HTTP status + error category only; contains
  **no** `amount_cents`, `user_id`, `notes`, or `reject_reason`. Traces: AC-8.
- **TC-AND-258-13** — Type: instrumented (emulator `test35`). Target: release
  logging config for payout routes. Preconditions: release-like build var on the
  emulator. Steps: issue a payout call through the real OkHttp stack; capture
  logcat. Expected: `HttpLoggingInterceptor` level is `NONE` (or
  headers-only/redacted); no payout body/amounts in logs. Traces: AC-8.
- **TC-AND-258-14** — Type: instrumented/e2e (PHYSICAL DEVICE, SM-A156U,
  arm64-v8a/API 34). Target: ABI + API-level smoke of the Moshi/KSP-generated
  adapters. Preconditions: app on the device; MockWebServer or recorded payout
  responses. Rationale: KSP adapter codegen and `java.time` behavior should be
  confirmed on the real arm64-v8a / API-34 target, not only the x86_64/API-35
  emulator. **Must run on the physical device.** Steps: drive `getPayouts` +
  `getPayoutBalance`. Expected: identical mapped domain objects to the JVM/emulator
  runs; no arm64-vs-x86 or API-34-vs-35 deserialization difference. Traces: AC-2,
  AC-7.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (modules/layering/namespaces exist) | Compile/CI (DoD §15); structurally exercised by all TCs via `PayoutsApi`/`PayoutsRepository`/domain types |
| AC-2 (every field deserializes + maps, no loss) | TC-01, TC-03, TC-05, TC-06, TC-10, TC-14 |
| AC-3 (Money minor-units Long, no float) | TC-01, TC-04 |
| AC-4 (status enum + UNKNOWN fallback, no throw) | TC-02, TC-03 |
| AC-5 (cursor + limit, surfaces nextCursor) | TC-06, TC-07 |
| AC-6 (ApiResult, shared detail mapper, idempotent retry) | TC-07, TC-08, TC-09, TC-10, TC-11 |
| AC-7 (unit + MockWebServer tests incl. path/verb/query + null-defaulting) | TC-07, TC-08, TC-09, TC-11, TC-14 |
| AC-8 (no payout PII in logs in release) | TC-12, TC-13 |
