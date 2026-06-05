---
id: AND-258
title: Payouts API
milestone: M6
epic: E35
priority: P0
size: M
status: draft
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
`payoutsRepository.getPayoutAccount()` and `payoutsRepository.getPayouts(cursor)`
and receive `ApiResult<PayoutAccount>` / `ApiResult<PayoutPage>` with correctly
mapped, null-safe, money-precise domain objects.

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
  `PayoutAccount`, `PayoutStatus`, `PayoutMethod` types). The backend OpenAPI
  document at `/openapi.json` on the dev host is the tie-breaker if the web types
  and live responses disagree; capture a real response and follow the wire.
- **Dependencies:** AND-027 (`AuthApi` + the authenticated OkHttp/Retrofit stack:
  persistent cookie jar, `ui_csrf` → `X-CSRF-Token` header, single 401→refresh→retry
  interceptor) is the prerequisite. This ticket reuses that exact `OkHttpClient`
  and Retrofit `Moshi` converter; it does not build a new client.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). Error bodies use the FastAPI `detail` convention
  (string | `[{msg,...}]` | `{code,...}`) already centralized in AND-027's error
  mapper.
- **Blocks:** AND-259 consumes `PayoutsRepository` for the payout-setup flow and
  the KYC gate.

## 3. Functional Requirements

FR-1. Expose a Retrofit `PayoutsApi` covering, at minimum, the payout endpoints
present in `payouts.ts`:
- `GET /ui/payouts/account` — the current user's payout account/method state.
- `GET /ui/payouts` — paginated payout (transfer) history, cursor-based.
- `GET /ui/payouts/{payoutId}` — a single payout detail.

FR-2. Provide Moshi DTOs for every response above with `@Json(name=...)` for each
field that differs from idiomatic Kotlin camelCase, and nullable types for every
field not guaranteed by the backend contract.

FR-3. Provide pure mapping functions `*.toDomain()` from each DTO to a
`core-model` domain type. Monetary amounts must be parsed into a precise type
(minor units `Long` + ISO-4217 `currency` string), never `Float`/`Double`.

FR-4. Map enum-like string fields (`status`, `method.type`) into sealed/`enum`
domain types with an explicit `UNKNOWN`/`Unknown` fallback so unrecognized
server values never throw.

FR-5. Cursor pagination: `getPayouts` accepts an optional opaque `cursor: String?`
and `limit: Int`, returns items plus `nextCursor: String?`. The mapper exposes
`nextCursor` so a downstream Paging 3 source (AND-259+) can drive itself.

FR-6. Expose a `PayoutsRepository` interface + Hilt-bound implementation returning
`ApiResult<T>`. GETs here are idempotent and therefore eligible for the bounded
backoff retry policy defined in the network core.

FR-7. All requests automatically carry session cookies and the `X-CSRF-Token`
header via the shared client from AND-027; this ticket adds **no** auth code.

FR-8. No write endpoints (account create/update) are in scope here. If
`payouts.ts` exposes a `POST/PUT` for setting a payout method, its DTO may be
declared but is *owned and exercised* by AND-259; this ticket only guarantees the
read path is mapped and tested.

## 4. Technical Design

Retrofit interface (suspend functions, `ApiResult` wrapping happens in the repo):

```kotlin
package com.testlogon.android.core.network.payouts

interface PayoutsApi {
    @GET("ui/payouts/account")
    suspend fun getPayoutAccount(): PayoutAccountDto

    @GET("ui/payouts")
    suspend fun getPayouts(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): PayoutPageDto

    @GET("ui/payouts/{payoutId}")
    suspend fun getPayout(@Path("payoutId") payoutId: String): PayoutDto
}
```

DTOs (`core-network`):

```kotlin
@JsonClass(generateAdapter = true)
data class PayoutPageDto(
    @Json(name = "items") val items: List<PayoutDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "total") val total: Int? = null,
)

@JsonClass(generateAdapter = true)
data class PayoutDto(
    @Json(name = "id") val id: String,
    @Json(name = "amount") val amountMinor: Long?,
    @Json(name = "currency") val currency: String?,
    @Json(name = "status") val status: String?,
    @Json(name = "method_id") val methodId: String?,
    @Json(name = "created_at") val createdAt: String?,
    @Json(name = "arrival_at") val arrivalAt: String?,
    @Json(name = "failure_reason") val failureReason: String?,
)

@JsonClass(generateAdapter = true)
data class PayoutAccountDto(
    @Json(name = "account_id") val accountId: String?,
    @Json(name = "status") val status: String?,
    @Json(name = "default_method_id") val defaultMethodId: String?,
    @Json(name = "kyc_tier") val kycTier: String?,
    @Json(name = "payouts_enabled") val payoutsEnabled: Boolean?,
    @Json(name = "methods") val methods: List<PayoutMethodDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class PayoutMethodDto(
    @Json(name = "id") val id: String,
    @Json(name = "type") val type: String?,
    @Json(name = "label") val label: String?,
    @Json(name = "last4") val last4: String?,
    @Json(name = "is_default") val isDefault: Boolean? = false,
)
```

Domain models (`core-model`):

```kotlin
package com.testlogon.android.core.model.payout

data class Money(val amountMinor: Long, val currency: String) // e.g. 1299, "USD"

enum class PayoutStatus { PENDING, IN_TRANSIT, PAID, FAILED, CANCELED, UNKNOWN }

enum class PayoutMethodType { BANK_ACCOUNT, CARD, PAYPAL, UNKNOWN }

data class Payout(
    val id: String,
    val amount: Money,
    val status: PayoutStatus,
    val methodId: String?,
    val createdAt: Instant?,
    val arrivalAt: Instant?,
    val failureReason: String?,
)

data class PayoutPage(val items: List<Payout>, val nextCursor: String?, val total: Int?)

data class PayoutMethod(
    val id: String,
    val type: PayoutMethodType,
    val label: String?,
    val last4: String?,
    val isDefault: Boolean,
)

data class PayoutAccount(
    val accountId: String?,
    val status: String?,
    val defaultMethodId: String?,
    val kycTier: String?,
    val payoutsEnabled: Boolean,
    val methods: List<PayoutMethod>,
)
```

Mappers (`core-network`, pure, package-visible functions):

```kotlin
internal fun PayoutDto.toDomain(): Payout = Payout(
    id = id,
    amount = Money(amountMinor ?: 0L, currency ?: "USD"),
    status = status.toPayoutStatus(),
    methodId = methodId,
    createdAt = createdAt?.toInstantOrNull(),
    arrivalAt = arrivalAt?.toInstantOrNull(),
    failureReason = failureReason,
)

internal fun String?.toPayoutStatus(): PayoutStatus = when (this?.lowercase()) {
    "pending" -> PayoutStatus.PENDING
    "in_transit", "intransit" -> PayoutStatus.IN_TRANSIT
    "paid", "completed", "succeeded" -> PayoutStatus.PAID
    "failed" -> PayoutStatus.FAILED
    "canceled", "cancelled" -> PayoutStatus.CANCELED
    else -> PayoutStatus.UNKNOWN
}
```

`toInstantOrNull()` reuses the shared ISO-8601 parser already provided by the
network core (the same one AND-027/earnings use) and returns `null` on parse
failure rather than throwing.

Repository:

```kotlin
package com.testlogon.android.core.data.payouts

interface PayoutsRepository {
    suspend fun getPayoutAccount(): ApiResult<PayoutAccount>
    suspend fun getPayouts(cursor: String? = null, limit: Int = 20): ApiResult<PayoutPage>
    suspend fun getPayout(payoutId: String): ApiResult<Payout>
}

class DefaultPayoutsRepository @Inject constructor(
    private val api: PayoutsApi,
) : PayoutsRepository {
    override suspend fun getPayouts(cursor: String?, limit: Int): ApiResult<PayoutPage> =
        apiCall { api.getPayouts(cursor, limit).toDomain() }
    // getPayoutAccount / getPayout follow the same apiCall { } pattern
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

`GET /ui/payouts/account` → 200:

```json
{
  "account_id": "acct_8f12",
  "status": "active",
  "default_method_id": "pm_01",
  "kyc_tier": "tier_1",
  "payouts_enabled": true,
  "methods": [
    { "id": "pm_01", "type": "bank_account", "label": "Chase ****", "last4": "4321", "is_default": true }
  ]
}
```

`GET /ui/payouts?cursor=&limit=20` → 200:

```json
{
  "items": [
    {
      "id": "po_1029",
      "amount": 4500,
      "currency": "USD",
      "status": "paid",
      "method_id": "pm_01",
      "created_at": "2026-05-30T18:04:11Z",
      "arrival_at": "2026-06-02T00:00:00Z",
      "failure_reason": null
    }
  ],
  "next_cursor": "eyJrIjoicG9fMTAyOSJ9",
  "total": 37
}
```

`GET /ui/payouts/{payoutId}` → 200: a single object identical in shape to an
`items[]` element above.

Error responses (FastAPI): 401 (handled by the AND-027 refresh-once interceptor
before reaching the repo), 404 `{"detail":"Payout not found"}`, 422
`{"detail":[{"loc":[...],"msg":"...","type":"..."}]}`, 5xx / connection
failure → mapped to `ApiResult.Error` via the shared mapper.

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

## 7. Error Handling & Resilience

- All three calls are idempotent GETs and therefore opt into the network core's
  **bounded backoff retry** (max ~2 retries, jittered) for transient
  `IOException`/timeout/5xx — appropriate given the unreliable dev host.
- Per-request timeout follows the global ~20s call timeout configured on the
  shared OkHttp client (AND-027); this ticket does not override it.
- 401 is resolved upstream by the single refresh-then-retry interceptor; the repo
  never sees a bare 401 unless refresh itself fails, in which case it surfaces as
  `ApiResult.Error` (auth) for AND-259 to route to login.
- Mapping is defensively null-safe: missing `amount` → `0` minor units, missing
  `currency` → `"USD"`, unknown `status`/`type` → `UNKNOWN`, unparseable
  timestamps → `null`. A malformed but non-empty payload never throws from a
  mapper; only a Moshi structural failure (e.g., `items` not an array) yields
  `ApiResult.Error`.
- Empty history (`items: []`, `next_cursor: null`) is a valid success, not an
  error.

## 8. Security & Privacy

- Payout data is financial PII (bank labels, `last4`, amounts). It must **never**
  be written to logs. The OkHttp `HttpLoggingInterceptor` for payout endpoints
  must be `Level.NONE` (or headers-only) in release builds; body logging is
  permitted only in debug and even then `last4`/`label` should be redacted by the
  shared logging redactor.
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
1. `PayoutDto.toDomain()` maps a fully populated JSON fixture to `Payout` with
   correct `Money(amountMinor, currency)`, parsed `Instant`s, and status.
2. Each `status` string variant (`pending`, `in_transit`, `paid`/`completed`/
   `succeeded`, `failed`, `canceled`/`cancelled`) maps to the right enum;
   an unknown string → `PayoutStatus.UNKNOWN`.
3. Null/missing `amount`, `currency`, timestamps, and `failure_reason` produce the
   documented defaults without throwing.
4. `PayoutMethodDto`/`PayoutAccountDto` map, including `is_default` defaulting to
   `false` and `payouts_enabled` null → `false`.
5. `PayoutPageDto.toDomain()` preserves item order and `nextCursor`; empty
   `items` → empty list, success.

Integration — MockWebServer (`core-testing`):
6. `getPayouts` issues `GET /ui/payouts?cursor=...&limit=20` with the exact path,
   verb, and query encoding (assert recorded request).
7. `getPayout("po_1")` hits `GET /ui/payouts/po_1`.
8. A 404 with `{"detail":"Payout not found"}` → `ApiResult.Error` with the mapped
   message; a 422 detail-array → mapped message.
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
  `PayoutsRepository`, the `PayoutAccount.kycTier`/`payoutsEnabled` fields for the
  KYC gate, and `PayoutPage.nextCursor` for history paging.
- Sequencing within the ticket: confirm live shapes via `/openapi.json` →
  DTOs + Moshi adapters → domain models in `core-model` → mappers + unit tests →
  `PayoutsApi` + MockWebServer tests → repository + Hilt wiring + repo tests.

## 13. Risks & Open Questions

- **R1 — Wire shape drift.** `payouts.ts` types may lag the live FastAPI schema
  (amount as decimal string vs minor-unit int; `next_cursor` vs `cursor` vs
  page-number). Mitigation: capture a real response from the dev host and treat
  `/openapi.json` + the wire as authoritative; the nullable DTOs absorb optional
  fields. **Open:** confirm `amount` is integer minor units, not a decimal.
- **R2 — Endpoint paths.** Exact path prefix (`/ui/payouts` vs `/ui/payments` vs
  `/ui/me/payouts`) must be verified against OpenAPI before merge.
- **R3 — Status vocabulary.** The backend status set is unconfirmed; the
  `UNKNOWN` fallback prevents crashes but the enum may need new members once the
  real vocabulary is known. **Open:** enumerate authoritative statuses.
- **R4 — Write endpoint ownership.** Whether `payouts.ts` exposes a
  create/update-method `POST` and whether it lives here or in AND-259. Current
  decision: read-only here; write DTOs (if any) owned/tested by AND-259.
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
4. `status` and `method.type` map to enums with `UNKNOWN` fallbacks; no
   unrecognized server string throws.
5. `getPayouts` supports `cursor` + `limit` and surfaces `nextCursor`.
6. All three repository methods return `ApiResult<T>`, route errors through the
   shared FastAPI `detail` mapper, and use the shared idempotent-GET retry.
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
