---
id: AND-363
title: Ads accounts API
milestone: M8
epic: E47
priority: P1
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-364]
---

# AND-363 — Ads accounts API

## 1. Overview & Goal

This ticket delivers the typed HTTP seam and Moshi-backed data-transfer objects
(DTOs) for the TestLogon **advertising / ads-accounts** surface: listing the
advertiser accounts a session user can manage, fetching a single ads account,
reading the account's billing/spend summary, and reading the account's campaigns
(read-only). It produces **no UI, no repositories, no ViewModels** — it is the
transport-and-serialization foundation that subsequent ads feature work
(ViewModels, screens, and tests under epic E47) builds on.

Scope, verbatim from the backlog: *`/ui/ads/accounts*` DTOs (accounts, billing,
campaigns read).* This ticket ports the `/ui/ads/accounts*` route family to a
native Retrofit `AdsAccountsApi` plus the immutable DTOs those endpoints
(de)serialize. The single backlog acceptance criterion is: *Ads account payloads
map (tested).* This ticket therefore owns (a) immutable Kotlin DTOs in
`core-model` modeling the documented ads-account JSON exactly (snake_case →
camelCase via Moshi codegen), (b) the Retrofit `AdsAccountsApi` interface in
`core-network` exposing the account list/detail, billing-read, and campaigns-read
operations with correct verbs/paths/query params, and (c) the Hilt provider plus
MockWebServer and round-trip test suites that prove every payload (de)serializes
and every endpoint is callable.

This ticket deliberately does **not** own: the cookie jar (AND-011), CSRF
injection (AND-012), the 401-refresh `Authenticator` (AND-013), `ApiResult<T>`
wrapping (AND-018), FastAPI `detail` error mapping (AND-015), bounded-backoff
retry for idempotent GETs (AND-016), Paging 3 `PagingSource`/`Pager` wiring, any
ads-campaign **mutation** (create/pause/budget — a separate future ticket), or
any Room cache / domain mapping (`core-data`). Those attach to the shared
`OkHttpClient`/`Retrofit` or live in higher layers and take effect for
`AdsAccountsApi` calls without changes here.

The deliverable: compiling DTOs + a compiling `AdsAccountsApi` + its Hilt
provider + a green test suite asserting (de)serialization fidelity and each
endpoint's verb/path/query/decoding.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. DTOs land in module **`core-model`** under package
  `com.testlogon.android.core.model.ads`. The `AdsAccountsApi` interface and its
  Hilt module land in **`core-network`** under
  `com.testlogon.android.core.network.ads`.
- **Canonical package:** `com.testlogon.android` everywhere a package appears;
  `applicationId` base identical.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines, JDK 17,
  minSdk 24 / compileSdk 35 / targetSdk 35, AGP 8.7.3 / Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. `AdsAccountsApi` lives in
  `core-network`, consumes DTOs from `core-model`, is consumed by `core-data`
  repositories and the ads `feature-*` module (downstream E47). No `feature-*`/
  `app` symbols leak into `core-network`/`core-model`.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** the backlog
  pins AND-363 to AND-027. Ads endpoints are served behind the cookie-based
  `/ui/*` session; this ticket reuses the same shared `OkHttpClient`/`Retrofit`
  (cookie jar, CSRF, 401-refresh) established by the auth-network stack, so
  AND-027's transport conventions (relative `/ui/...`-style paths, `suspend`
  methods, Hilt-provided service on the shared `Retrofit`) are the template
  followed here.
- **Transitive upstream (already required by AND-027):** AND-026 (Moshi
  adapter-set pattern), AND-010 (shared Retrofit/Moshi + KSP codegen), AND-009
  (shared `OkHttpClient`, ~20s timeouts, redacting logger), AND-006
  (`BuildConfig.API_BASE_URL`, dev → `http://18.222.237.167:8000/`),
  AND-003/AND-004 (module structure, Hilt baseline). AND-016 (bounded backoff for
  idempotent GETs) applies to these endpoints once present but is not a compile
  dependency.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` is
  **plaintext HTTP and unreliable** (~20s timeouts; bounded backoff for
  idempotent GETs owned by AND-009/AND-016). Every endpoint in this ticket is an
  **idempotent GET**. OpenAPI at `/openapi.json` is authoritative for shapes,
  paths, and `required` arrays.
- **Web reference (authoritative for field names / paths):** the ported web API
  module under `frontend/src/api/endpoints/` for the `/ui/ads/accounts*` family
  (e.g. `ads.ts`), and shared types in `frontend/src/api/types.ts` (`AdsAccount`,
  `AdsBilling`, `AdsCampaign`, money types). Mirror those wire names exactly; do
  **not** invent camelCase wire keys — the backend is snake_case.

## 3. Functional Requirements

FR-1. Define response **DTOs** in `core-model.ads` covering: an ads-account
summary (list row), a full ads-account detail, an ads billing/spend summary, an
ads campaign (read row), a money/spend value, a paged account-list envelope, and
a paged campaign-list envelope.

FR-2. Define a single Retrofit interface **`AdsAccountsApi`** in
`core-network.ads` exposing exactly the `/ui/ads/accounts*` read operations:
`listAdsAccounts` (paged), `getAdsAccount` (detail), `getAdsAccountBilling`
(billing read), and `listAdsAccountCampaigns` (campaigns read, paged).

FR-3. All `AdsAccountsApi` methods are `suspend` functions returning the typed
DTO body. All are HTTP **GET** (campaign mutation is out of scope — a future
ticket). Paths are relative with **no leading slash** (AND-010 convention) so
they append to the normalized base URL; the route family is `ui/ads/accounts`
(confirm exact prefix against `/openapi.json`, Q-1).

FR-4. Paging is offset/limit (or cursor) via `@Query` params: `listAdsAccounts`
and `listAdsAccountCampaigns` accept `page`/`limit` (or `cursor`/`limit`) and
return a paged envelope carrying `items`, `total`, and a next-page indicator. The
exact param names and envelope keys are confirmed against `/openapi.json` / web
reference before coding (Q-1) and modeled in per-type envelopes.

FR-5. Every DTO field maps to the backend's snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. Unknown/extra JSON keys are tolerated
(Moshi codegen default — additive backend evolution must not throw).

FR-6. Required vs optional fidelity: required fields are non-null and their
absence surfaces as a `JsonDataException` (fail fast); optional fields are
Kotlin-nullable with a `null`/empty default per `/openapi.json` `required`
arrays.

FR-7. Money/spend is modeled losslessly: the minor-unit integer amount plus the
ISO-4217 currency code are preserved exactly (no float rounding). Account
balance, lifetime spend, campaign budget/spend all use the same `MoneyDto`. A
backend-supplied formatted display string, if present, is kept verbatim as a
`String`.

FR-8. Timestamps (`created_at`, `updated_at`, billing `period_start`/
`period_end`, campaign `start_date`/`end_date`) are kept as ISO-8601 `String`s;
parsing to `Instant`/`LocalDate` is deferred to the domain-mapping layer
(downstream consumers), consistent with AND-026 §6. Enumerated tokens — account
`status` (e.g. `"active"`, `"suspended"`), billing `payment_status`, campaign
`status` (e.g. `"running"`, `"paused"`, `"ended"`), and campaign `objective` —
are kept as raw `String`s; mapping to typed enums is a downstream domain concern
(an unknown token must never throw at the DTO layer).

FR-9. All DTOs are immutable `data class`es; collections are exposed as read-only
`List<T>` with safe defaults (`emptyList()`).

FR-10. A Hilt `@Provides @Singleton fun provideAdsAccountsApi(retrofit:
Retrofit): AdsAccountsApi` constructs the service from the shared `Retrofit`
(AND-010). No new `Retrofit`/`OkHttpClient`/`Moshi` is created; no per-method
cookie/CSRF headers are declared.

FR-11. Captured JSON sample fixtures are committed under `core-model` test
resources for each payload and drive round-trip tests.

## 4. Technical Design

DTOs land in
`core-model/src/main/kotlin/com/testlogon/android/core/model/ads/`. The
`AdsAccountsApi` and `AdsAccountsApiModule` land in
`core-network/src/main/kotlin/com/testlogon/android/core/network/ads/`.

### 4.1 DTOs (`core-model.ads`)

All DTOs are `@JsonClass(generateAdapter = true)` so Moshi codegen (KSP) emits
adapters at build time (no reflection adapter added for these types).

```kotlin
package com.testlogon.android.core.model.ads

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/** Money/spend kept lossless: minor units + ISO-4217 code; display verbatim. */
@JsonClass(generateAdapter = true)
data class MoneyDto(
    @Json(name = "amount_minor") val amountMinor: Long,
    val currency: String,                                  // e.g. "USD"
    @Json(name = "display") val display: String? = null,   // e.g. "$1,250.00"
)

/** List-row shape for an ads account. */
@JsonClass(generateAdapter = true)
data class AdsAccountSummaryDto(
    val id: String,
    val name: String,
    val status: String,                                    // "active" | "suspended" | …
    val currency: String,                                  // account billing currency
    @Json(name = "balance") val balance: MoneyDto? = null,
    @Json(name = "campaign_count") val campaignCount: Int? = null,
    @Json(name = "created_at") val createdAt: String,      // ISO-8601
)

/** Full ads-account detail. */
@JsonClass(generateAdapter = true)
data class AdsAccountDetailDto(
    val id: String,
    val name: String,
    val status: String,
    val currency: String,
    @Json(name = "timezone") val timezone: String? = null,
    @Json(name = "owner_id") val ownerId: String? = null,
    @Json(name = "balance") val balance: MoneyDto? = null,
    @Json(name = "lifetime_spend") val lifetimeSpend: MoneyDto? = null,
    @Json(name = "campaign_count") val campaignCount: Int? = null,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "updated_at") val updatedAt: String? = null,
)

/** Billing / spend summary for an ads account (read). */
@JsonClass(generateAdapter = true)
data class AdsBillingDto(
    @Json(name = "account_id") val accountId: String,
    val currency: String,
    @Json(name = "balance") val balance: MoneyDto? = null,
    @Json(name = "current_spend") val currentSpend: MoneyDto? = null,
    @Json(name = "credit_limit") val creditLimit: MoneyDto? = null,
    @Json(name = "payment_status") val paymentStatus: String? = null, // "paid" | "past_due" | …
    @Json(name = "payment_method") val paymentMethod: String? = null, // backend-masked, e.g. "visa ****4242"
    @Json(name = "period_start") val periodStart: String? = null,     // ISO-8601
    @Json(name = "period_end") val periodEnd: String? = null,
    @Json(name = "invoices") val invoices: List<AdsInvoiceRefDto> = emptyList(),
)

/** Lightweight invoice reference embedded in billing read. */
@JsonClass(generateAdapter = true)
data class AdsInvoiceRefDto(
    val id: String,
    val amount: MoneyDto,
    val status: String? = null,
    @Json(name = "issued_at") val issuedAt: String? = null,
)

/** Read-only campaign row under an account. */
@JsonClass(generateAdapter = true)
data class AdsCampaignDto(
    val id: String,
    @Json(name = "account_id") val accountId: String? = null,
    val name: String,
    val status: String,                                    // "running" | "paused" | "ended" | …
    val objective: String? = null,                         // e.g. "traffic" | "conversions"
    val budget: MoneyDto? = null,
    val spend: MoneyDto? = null,
    val impressions: Long? = null,
    val clicks: Long? = null,
    @Json(name = "start_date") val startDate: String? = null,
    @Json(name = "end_date") val endDate: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
)

/** Paged envelope for the account list. */
@JsonClass(generateAdapter = true)
data class AdsAccountPageDto(
    val items: List<AdsAccountSummaryDto> = emptyList(),
    val total: Int = 0,
    val page: Int = 1,
    val limit: Int = DEFAULT_PAGE_LIMIT,
    @Json(name = "has_more") val hasMore: Boolean = false,
    @Json(name = "next_cursor") val nextCursor: String? = null,
) {
    companion object { const val DEFAULT_PAGE_LIMIT = 20 }
}

/** Paged envelope for an account's campaigns. */
@JsonClass(generateAdapter = true)
data class AdsCampaignPageDto(
    val items: List<AdsCampaignDto> = emptyList(),
    val total: Int = 0,
    val page: Int = 1,
    val limit: Int = 20,
    @Json(name = "has_more") val hasMore: Boolean = false,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
```

Design notes:
- The paged envelopes are kept as concrete classes (not a generic
  `Paged<T>`) because Moshi codegen on generic types requires a
  `Types.newParameterizedType(...)` adapter lookup; concrete envelopes keep
  codegen total and the test surface simple. If `/openapi.json` shows identical
  envelope shapes, the campaign envelope may reuse the account envelope's keys
  during implementation (Q-2).
- `status`, `payment_status`, `objective` are raw `String`s, not enums: the wire
  vocabulary is backend-owned and mapped to a sealed/`enum` type in the
  downstream domain layer; an unknown token must never throw at the DTO layer.
- `AdsInvoiceRefDto` is modeled here so `getAdsAccountBilling` decodes the
  complete billing payload in one round trip; the full invoices feature
  (AND-243) is unrelated and not coupled.
- `impressions`/`clicks` are `Long?` (metrics can exceed `Int` range and may be
  absent for new campaigns). All timestamps are `String` (ISO-8601); no
  `Date`/`Instant` adapter is added in this ticket.

### 4.2 `AdsAccountsApi` interface (`core-network.ads`)

```kotlin
package com.testlogon.android.core.network.ads

import com.testlogon.android.core.model.ads.AdsAccountDetailDto
import com.testlogon.android.core.model.ads.AdsAccountPageDto
import com.testlogon.android.core.model.ads.AdsBillingDto
import com.testlogon.android.core.model.ads.AdsCampaignPageDto
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

interface AdsAccountsApi {

    /** Paged ads accounts the current session user can manage. Idempotent GET. */
    @GET("ui/ads/accounts")
    suspend fun listAdsAccounts(
        @Query("page") page: Int = 1,
        @Query("limit") limit: Int = 20,
    ): AdsAccountPageDto

    /** Full ads-account detail by id. */
    @GET("ui/ads/accounts/{accountId}")
    suspend fun getAdsAccount(
        @Path("accountId") accountId: String,
    ): AdsAccountDetailDto

    /** Billing / spend summary for an account (read). */
    @GET("ui/ads/accounts/{accountId}/billing")
    suspend fun getAdsAccountBilling(
        @Path("accountId") accountId: String,
    ): AdsBillingDto

    /** Read-only campaigns for an account, paged. */
    @GET("ui/ads/accounts/{accountId}/campaigns")
    suspend fun listAdsAccountCampaigns(
        @Path("accountId") accountId: String,
        @Query("page") page: Int = 1,
        @Query("limit") limit: Int = 20,
    ): AdsCampaignPageDto
}
```

Path/verb conventions: relative paths, no leading slash, resolve against base
`http://18.222.237.167:8000/` → e.g. `…/ui/ads/accounts/{id}/billing`. The exact
prefix (`ui/ads/accounts`) and the sub-resource shapes (`/billing`,
`/campaigns`) are confirmed against `/openapi.json` and the web reference module
before coding (Q-1). Retrofit only constructs the request URL; server-side
routing decides the match, so no client-side annotation-ordering issue arises,
but the literal sub-paths must be confirmed to not be shadowed by the
`{accountId}` route.

### 4.3 Hilt provider

```kotlin
package com.testlogon.android.core.network.ads.di

import com.testlogon.android.core.network.ads.AdsAccountsApi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AdsAccountsApiModule {

    @Provides
    @Singleton
    fun provideAdsAccountsApi(retrofit: Retrofit): AdsAccountsApi =
        retrofit.create(AdsAccountsApi::class.java)
}
```

The injected `Retrofit` is the singleton from AND-010's `NetworkModule`, built on
AND-009's shared `OkHttpClient` (cookie jar, CSRF, 401-refresh, redacting logger
all attached there). No client/Retrofit/Moshi is constructed here.

### 4.4 Gradle wiring

No new dependencies. `core-model` already has Moshi codegen annotations + KSP;
`core-network` already has Retrofit, the Moshi converter, Hilt, and (test)
MockWebServer from AND-010/AND-027. `core-network` already declares
`implementation(project(":core-model"))`. This ticket adds source files + test
fixtures only.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All responses are JSON; all
endpoints are idempotent GETs requiring the session cookie (set by the auth flow)
and tolerating the AND-013 401-refresh-once behavior. Accounts are scoped to the
current session user server-side (no `user_id` query param).

### GET `ui/ads/accounts?page=1&limit=20`
Response `200`:
```json
{
  "items": [
    {
      "id": "ada_001",
      "name": "Acme Brand Studio",
      "status": "active",
      "currency": "USD",
      "balance": { "amount_minor": 125000, "currency": "USD", "display": "$1,250.00" },
      "campaign_count": 4,
      "created_at": "2026-01-12T08:00:00Z"
    }
  ],
  "total": 2, "page": 1, "limit": 20, "has_more": false, "next_cursor": null
}
```

### GET `ui/ads/accounts/{accountId}`
Response `200`:
```json
{
  "id": "ada_001",
  "name": "Acme Brand Studio",
  "status": "active",
  "currency": "USD",
  "timezone": "America/New_York",
  "owner_id": "usr_77",
  "balance": { "amount_minor": 125000, "currency": "USD", "display": "$1,250.00" },
  "lifetime_spend": { "amount_minor": 980000, "currency": "USD" },
  "campaign_count": 4,
  "created_at": "2026-01-12T08:00:00Z",
  "updated_at": "2026-06-01T11:30:00Z"
}
```
`404` if the account id is unknown or not owned/managed by the session user.

### GET `ui/ads/accounts/{accountId}/billing`
Response `200`:
```json
{
  "account_id": "ada_001",
  "currency": "USD",
  "balance": { "amount_minor": 125000, "currency": "USD" },
  "current_spend": { "amount_minor": 43250, "currency": "USD", "display": "$432.50" },
  "credit_limit": { "amount_minor": 500000, "currency": "USD" },
  "payment_status": "paid",
  "payment_method": "visa ****4242",
  "period_start": "2026-06-01",
  "period_end": "2026-06-30",
  "invoices": [
    { "id": "inv_9001", "amount": { "amount_minor": 43250, "currency": "USD" },
      "status": "open", "issued_at": "2026-06-01T00:00:00Z" }
  ]
}
```

### GET `ui/ads/accounts/{accountId}/campaigns?page=1&limit=20`
Response `200`:
```json
{
  "items": [
    {
      "id": "cmp_501",
      "account_id": "ada_001",
      "name": "Summer Launch",
      "status": "running",
      "objective": "conversions",
      "budget": { "amount_minor": 50000, "currency": "USD", "display": "$500.00" },
      "spend": { "amount_minor": 21340, "currency": "USD" },
      "impressions": 184220,
      "clicks": 3120,
      "start_date": "2026-05-20",
      "end_date": "2026-06-20",
      "created_at": "2026-05-18T10:00:00Z"
    }
  ],
  "total": 4, "page": 1, "limit": 20, "has_more": false, "next_cursor": null
}
```

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg,type,loc}] | {code,...}`). Mapping to a typed `ApiError` is
owned by **AND-015**; this ticket lets non-2xx surface as
`retrofit2.HttpException` so AND-015/AND-018 can map it. Exact path prefix,
pagination param names (`page`/`limit` vs `offset`/`cursor`), money
representation, and `required` arrays are confirmed against `/openapi.json` / the
web reference before coding (Q-1).

## 6. Data & State Management

- `AdsAccountsApi` is **stateless** — a singleton interface proxy with no fields.
  DTOs are transient wire types.
- **No Room / DataStore** in this ticket. Caching account/campaign pages, the
  Paging 3 `PagingSource`/`RemoteMediator`, and domain mapping are `core-data` /
  downstream-E47 concerns. DTOs must **not** be persisted directly nor enter
  Compose composition; they carry no `@Stable`/`@Immutable` annotations.
- **No `StateFlow`/`UiState`** here. A future ads ViewModel exposes
  `StateFlow<AdsUiState>` by consuming a repository that wraps these calls in
  `ApiResult<T>` (AND-018). This layer returns plain DTOs (happy path) and throws
  on failure.
- **Session state** rides entirely on cookies persisted by the AND-011 jar;
  `AdsAccountsApi` neither reads nor writes cookies. CSRF (`ui_csrf` →
  `X-CSRF-Token`) is irrelevant to these GETs (CSRF applies to mutating verbs)
  but is handled globally regardless.
- **Pagination state** (current page/cursor, accumulation) is owned by the Paging
  3 layer downstream; the DTOs only carry per-response page metadata (`page`,
  `limit`, `total`, `has_more`, `next_cursor`).
- **Serialization** uses the shared Moshi codegen adapters via the AND-010
  converter; unknown keys are ignored, absent optional fields fall back to Kotlin
  defaults. ISO-4217 currency and minor-unit amounts are preserved exactly
  (`Long`, never `Double`); metrics are `Long`. Timestamps remain `String`.
- **Threading:** suspend methods are invoked from an IO-dispatcher coroutine at
  the repository layer; this ticket imposes no dispatcher.

## 7. Error Handling & Resilience

Responsibilities here are narrow: declare endpoints and DTOs so failures
propagate cleanly and deserialization is robust.

- **Non-2xx** (`404` unknown/unmanaged account, `403` if the session user lacks
  ads access, `422` bad query) surfaces as `retrofit2.HttpException` carrying the
  raw error body for AND-015 to decode the FastAPI `detail`. Nothing is swallowed
  here.
- **`401`** on any ads call is intercepted by the AND-013 `Authenticator`, which
  calls `sessionRefresh()` once and retries; only a second `401` propagates,
  which the consumer routes to login (AND-025). Ads accounts are auth-only, so a
  hard `401` (expired session) is a common failure and must reach the consumer
  cleanly.
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged. The ~20s timeouts and **bounded backoff for
  idempotent GETs** are owned by AND-009/AND-016 on the shared client — all four
  methods are GETs and are therefore retry-eligible there.
- **Deserialization robustness (DTO layer):**
  - Missing **required** field (e.g. `id`, `name`, `status`, `currency`,
    `created_at`, or `amount_minor` inside a `MoneyDto`) → `JsonDataException`
    (desired fail-fast; asserted in tests).
  - Unknown/extra JSON keys → skipped silently (additive backend evolution safe).
  - `null` for a nullable field → tolerated; `null` for a non-null field →
    `JsonDataException`.
  - Empty arrays/objects → modeled via `emptyList()` defaults so an account with
    no campaigns or no invoices, and an empty account page, never produce nulls.
  - Unknown enum token (`status: "archived"`, `objective: "app_installs"`,
    `payment_status: "in_review"`) → tolerated as a raw `String`; never throws.
- **Money/metric safety:** every `amount_minor`, `impressions`, and `clicks` is
  `Long`; a non-integer/overflowing value surfaces as `JsonDataException` rather
  than silent float/`Int` truncation.
- This ticket maps **no** errors itself and applies **no** retry policy — those
  are AND-015 (`ApiError`), AND-018 (`ApiResult`), and AND-009/AND-016 (client
  retry).

## 8. Security & Privacy

- **Auth:** ads endpoints require the cookie-based `/ui/*` session; the shared
  client attaches cookies/CSRF transparently. `AdsAccountsApi` declares no manual
  `Cookie`/`Authorization`/`X-CSRF-Token` headers. Accounts are user-scoped
  server-side; the client never sends a `user_id`/`owner_id` (no IDOR surface
  from this layer — only an `accountId` path param the server authorizes).
- **Transport:** on `dev` these ride plaintext HTTP
  (`http://18.222.237.167:8000`) — a known dev-only risk permitted by the scoped
  cleartext config (AND-006); `staging`/`prod` are HTTPS-only. Billing payloads
  carry financial hints (`balance`, `current_spend`, masked `payment_method`), so
  the cleartext exposure is acknowledged as dev-only and must not reach prod.
- **Sensitive payloads / logging:** the billing DTO carries semi-sensitive data
  (`payment_method` mask, spend/credit figures). The AND-009 HTTP logger is
  **debug-build only**; because these bodies are not credentials, body logging in
  debug is acceptable, but `payment_method` must already be backend-masked (the
  client never receives a full PAN). No DTO here carries passwords, tokens, CVV,
  or full card numbers, so no custom `toString()` redaction is required; if the
  backend ever returns an unmasked field, AND-052's redaction policy applies and a
  redacting adapter is added (flagged in Q-3).
- **No token storage:** auth is cookie-based; this layer holds no bearer tokens.
- **Injection safety:** `accountId` is passed as a Retrofit `@Path`
  (path-segment encoded); paging values are `@Query` ints (URL-encoded by
  OkHttp). No manual string concatenation into the URL.

## 9. Accessibility & i18n

Not applicable as a UI surface — this is a headless transport + DTO layer with no
Compose UI and no `strings.xml` entries. Three pass-through constraints are
recorded for downstream consumers (the ads ViewModels/screens under E47):
- `MoneyDto` exposes `amountMinor` + `currency` (not just a pre-formatted
  `display`) so the UI/domain layer can apply locale-aware currency formatting
  (`NumberFormat.getCurrencyInstance(locale)`); the backend `display` string is a
  fallback, not the canonical render.
- `created_at`/`updated_at`/`period_start`/`period_end`/`start_date`/`end_date`
  are raw ISO-8601 strings so the UI can format dates/date-ranges per device
  locale and time zone (`DateTimeFormatter` / `android.text.format.DateUtils`),
  rather than rendering server-formatted text.
- `status`/`payment_status`/`objective` are raw tokens (not localized labels) so
  the downstream feature can map them to localized, accessible status strings and
  `contentDescription`s for status chips; large metric numbers
  (`impressions`/`clicks`) format with locale grouping downstream.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's `HttpLoggingInterceptor` (debug
  builds only). No new logging is added here.
- **No analytics events** emitted by this layer. Ads-accounts-viewed /
  account-detail-viewed / campaigns-viewed events are emitted by the downstream
  ads ViewModel from `ApiResult` outcomes, not from `AdsAccountsApi`.
- **Build-time signal:** KSP must generate Moshi adapters for every ads DTO
  referenced here; a missing adapter fails the build (no reflection fallback, per
  AND-010 policy). This is the only diagnostic surface the ticket adds.

## 11. Testing Strategy

Two test surfaces: **round-trip DTO tests** (JVM, in `core-model`) and
**MockWebServer endpoint tests** (JVM, in `core-network`), both using the
production Moshi/Retrofit configuration. This ticket's tests satisfy the AND-363
backlog acceptance (*Ads account payloads map (tested)*); broader repo + UI tests
belong to a downstream E47 test ticket.

### 11.1 DTO round-trip tests (`core-model`)
Captured samples live at
`core-model/src/test/resources/ads/<name>.json`. Test class:
`com.testlogon.android.core.model.ads.AdsDtoRoundTripTest`.

- **Round-trip fidelity.** For each DTO, `moshi.adapter(T::class.java).fromJson(sample)`
  is non-null and equals the expected object; re-serializing yields JSON whose
  parsed tree equals the original parsed tree (compare as Moshi `Map`/`JSONObject`
  to ignore key order/whitespace).
- **Snake_case mapping.** Serialized `AdsAccountSummaryDto` contains
  `"campaign_count"`/`"created_at"`, never their camelCase forms; `AdsBillingDto`
  contains `"account_id"`/`"current_spend"`/`"credit_limit"`/`"payment_status"`/
  `"payment_method"`/`"period_start"`; `AdsCampaignDto` contains `"start_date"`/
  `"end_date"`/`"account_id"`.
- **Required-field failure.** Removing `id`/`name`/`status`/`currency`/
  `created_at` from an `AdsAccountSummaryDto` sample (or `amount_minor` from
  `MoneyDto`, or `account_id`/`currency` from `AdsBillingDto`) causes `fromJson`
  to throw `JsonDataException`.
- **Unknown-key tolerance.** A sample with an extra `"server_time"` /
  `"experimental_flag"` key deserializes without error.
- **Unknown-token tolerance.** `status: "archived"`, `objective: "app_installs"`,
  and `payment_status: "in_review"` deserialize to the raw strings without
  throwing.
- **Money fidelity.** `amount_minor: 125000` deserializes to `Long` `125000` and
  survives round-trip with no float drift; nested `MoneyDto` (balance,
  lifetime_spend, current_spend, credit_limit, budget, spend, invoice amount) all
  preserved. `impressions: 184220` / `clicks: 3120` decode to `Long`.
- **Nested decoding.** `AdsBillingDto` decodes its `invoices` list; `AdsAccountPageDto`/
  `AdsCampaignPageDto` decode their `items` and page metadata.
- **Defaults.** A page with `"items": []` yields an empty list, not null; an
  account with no `campaigns`/`invoices` yields `emptyList()`; absent
  `next_cursor`/`updated_at`/`tracking-like` optionals yield `null`.

### 11.2 MockWebServer endpoint tests (`core-network`)
Harness mirrors the AND-027 pattern:
```kotlin
private fun api(server: MockWebServer): AdsAccountsApi {
    val moshi = Moshi.Builder().build() // mirrors provideMoshi(): codegen adapters
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(AdsAccountsApi::class.java)
}
```

- **T-1 `listAdsAccounts`** — asserts `GET /ui/ads/accounts?page=2&limit=10`
  (paging query present and correct), decodes `AdsAccountPageDto` including
  `total`/`has_more`.
  ```kotlin
  @Test fun listAdsAccounts_sendsPagingQueryAndDecodes() = runTest {
      val server = MockWebServer().apply {
          enqueue(MockResponse().setBody(loadFixture("ads/account_page.json"))); start()
      }
      val page = api(server).listAdsAccounts(page = 2, limit = 10)
      val req = server.takeRequest()
      assertEquals("GET", req.method)
      assertEquals("/ui/ads/accounts?page=2&limit=10", req.path)
      assertEquals(2, page.total)
      assertEquals("active", page.items.first().status)
      assertEquals(125000L, page.items.first().balance!!.amountMinor)
      server.shutdown()
  }
  ```
- **T-2 `getAdsAccount`** — asserts `GET /ui/ads/accounts/ada_001` (path param
  interpolated), decodes `AdsAccountDetailDto` including `lifetime_spend` money.
- **T-3 `getAdsAccountBilling`** — asserts
  `GET /ui/ads/accounts/ada_001/billing` (literal sub-path), decodes
  `AdsBillingDto` including nested `invoices` and money sub-fields.
- **T-4 `listAdsAccountCampaigns`** — asserts
  `GET /ui/ads/accounts/ada_001/campaigns?page=1&limit=20`, decodes
  `AdsCampaignPageDto` including `impressions`/`clicks` as `Long` and
  `budget`/`spend` money.
- **T-5 error propagation** — a `404` from `getAdsAccount` throws
  `retrofit2.HttpException` with `code() == 404` (confirms non-2xx not swallowed,
  leaving room for AND-015); a `403` from `getAdsAccountBilling` likewise
  surfaces as `HttpException(403)`.
- **T-6 `401` not swallowed** — a `401` from `listAdsAccounts` surfaces as
  `HttpException(401)` at this bare-Retrofit harness (the AND-013 refresh
  `Authenticator` is not installed in the unit harness; this documents that the
  DTO layer itself adds no auth handling).
- **T-7 Hilt provider** — `@HiltAndroidTest` (or minimal `core-testing`
  harness) injects `AdsAccountsApi`, asserts non-null `@Singleton` built on the
  shared Retrofit (same instance on repeated injection).

Coverage target: ≥90% on the new surface (DTOs + interface binding + provider);
each of the four endpoints has at least one verb/path/query assertion; every DTO
has at least one round-trip test and committed fixture.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-027** (AuthApi / session endpoints) — pinned by the backlog. Establishes
  the shared-`Retrofit`-on-shared-`OkHttpClient` transport pattern, cookie/CSRF/
  refresh stack, and the Hilt-provided-service convention this ticket reuses.

**Transitive upstream (already required by AND-027):** AND-026 (Moshi adapter-set
pattern), AND-010 (shared Retrofit/Moshi + KSP codegen), AND-009 (shared
`OkHttpClient`, timeouts, redacting logger), AND-006 (`BuildConfig` base URL),
AND-003/AND-004 (module structure, Hilt baseline). AND-016 (bounded-backoff for
GETs) applies to these endpoints once present but is not a compile dependency.

**Downstream (this ticket blocks):**
- **AND-364** (next E47 ticket) — consumes `AdsAccountsApi`/`core-model.ads` DTOs
  via a repository + Paging 3, rendering the ads-accounts list, account detail,
  billing summary, and campaigns read. (The exact downstream consumer ids are the
  E47 ads-feature tickets following this DTO/API ticket; confirm against the
  backlog ordering, Q-4.)

**Sequencing within the ticket:** (1) confirm path prefix (`ui/ads/accounts`),
sub-resource paths (`/billing`, `/campaigns`), pagination param names, money
representation, and `required` arrays against `/openapi.json` + the web reference
(Q-1..Q-3); (2) define DTOs in `core-model.ads` + commit fixtures; (3) write
`AdsDtoRoundTripTest`; (4) declare `AdsAccountsApi`; (5) add
`AdsAccountsApiModule`; (6) write MockWebServer tests T-1..T-7.

## 13. Risks & Open Questions

- **R-1 Path-prefix / sub-resource shape.** Billing/campaigns may be top-level
  (`ui/ads/billing?account_id=…`, `ui/ads/campaigns?account_id=…`) rather than
  nested under `accounts/{id}/…`. Mitigation: confirm via `/openapi.json` + web
  reference; update all annotation paths and test assertions consistently.
  Guarded by T-1..T-4.
- **R-2 Pagination contract.** `page`/`limit` vs `offset`/`limit` vs
  `cursor`/`limit`, and bare-array vs enveloped responses, are unconfirmed.
  Mitigation: match the live contract; if cursor-based, the list methods take
  `@Query("cursor") cursor: String?` and the envelope exposes `next_cursor`
  (already modeled). Guarded by T-1/T-4.
- **R-3 Summary vs detail divergence.** The account list-row shape may differ
  from the detail shape. Modeled as separate `AdsAccountSummaryDto`/
  `AdsAccountDetailDto`; reconfirm field membership against OpenAPI.
- **R-4 Money representation.** Backend may send a decimal string (`"1250.00"`)
  or float rather than `amount_minor`. Mitigation: confirm via OpenAPI; if
  decimal string, `MoneyDto` keeps `amount` as `String` and minor-unit parsing
  moves to the domain layer (no float). Guarded by the money-fidelity test.
- **R-5 Sub-route shadowing.** Server routing may match `accounts/{accountId}`
  against a literal sibling. Mitigation: confirm `/billing` and `/campaigns`
  exist distinctly in `/openapi.json`.
- **R-6 Billing embed vs separate.** `invoices` may not be embedded in the
  billing read (could be a separate paged endpoint, AND-243 territory).
  Mitigation: confirm; if separate, drop `invoices` from `AdsBillingDto` and keep
  billing as the scalar spend/balance summary only.
- **Q-1** Exact route prefix (`ui/ads/accounts`) + sub-resource paths
  (`/billing`, `/campaigns`) + pagination param names? *Proposed:* nested
  `ui/ads/accounts/{id}/…` with `page`/`limit`; confirm against `/openapi.json` /
  web reference before coding.
- **Q-2** Are the account-list and campaign-list envelopes identical? *Proposed:*
  keep both concrete; collapse if identical.
- **Q-3** Does any DTO field arrive unmasked/sensitive (e.g. full
  `payment_method`)? *Proposed:* assume backend-masked; if not, add an
  AND-052-style redacting adapter.
- **Q-4** Which exact E47 ticket(s) consume this API first (confirm `blocks`
  list)? *Proposed:* AND-364.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Ads DTOs (`MoneyDto`, `AdsAccountSummaryDto`,
  `AdsAccountDetailDto`, `AdsBillingDto`, `AdsInvoiceRefDto`, `AdsCampaignDto`,
  `AdsAccountPageDto`, `AdsCampaignPageDto`) exist in
  `com.testlogon.android.core.model.ads` as immutable
  `@JsonClass(generateAdapter=true)` data classes.
- **AC-2 (backlog).** Ads account payloads **map (tested)**: every documented
  payload in Sections 4–5 (de)serializes the documented JSON exactly, proven by
  `AdsDtoRoundTripTest` against committed fixtures (parsed-tree equality,
  snake_case keys verified, nested money/invoice decoding).
- **AC-3.** `AdsAccountsApi` declares all four operations (`listAdsAccounts`,
  `getAdsAccount`, `getAdsAccountBilling`, `listAdsAccountCampaigns`); the module
  compiles against the ads DTOs.
- **AC-4.** Each endpoint is callable and its **verb + resolved path + query
  params** match Section 5, asserted with MockWebServer (T-1..T-4), including the
  list paging query, path-param interpolation, and the literal `/billing` and
  `/campaigns` sub-paths.
- **AC-5.** Required-field absence (e.g. `id`, `name`, `status`, `currency`,
  `created_at`, `account_id`, `amount_minor`) throws `JsonDataException`; unknown
  JSON keys and unknown enum tokens are tolerated; empty collections default to
  `emptyList()` and absent optional objects (`balance`, `next_cursor`,
  `updated_at`) default to `null`.
- **AC-6.** Money is lossless: every `amount_minor` decodes to `Long` and
  survives round-trip with no float drift; `impressions`/`clicks` decode to
  `Long`.
- **AC-7.** Non-2xx (e.g. `404` from `getAdsAccount`, `403` from
  `getAdsAccountBilling`, `401` from `listAdsAccounts`) surfaces as
  `HttpException` and is not swallowed (T-5/T-6).
- **AC-8.** `AdsAccountsApi` is Hilt-provided as a `@Singleton` built on the
  shared `Retrofit`; repeated injection yields the same instance; no new
  `OkHttpClient`/`Retrofit`/`Moshi` is constructed and no per-method cookie/CSRF
  headers are declared (T-7).
- **AC-9.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle
  8.9 / JDK 17 with KSP-generated adapters present and no new lint/detekt
  regressions.

## 15. Definition of Done

- DTOs (`com.testlogon.android.core.model.ads`) and `AdsAccountsApi` +
  `AdsAccountsApiModule` (`com.testlogon.android.core.network.ads[.di]`) are
  implemented under `core-model`/`core-network`, package base
  `com.testlogon.android`; no DTOs redefined elsewhere.
- Open questions Q-1..Q-4 (and risks R-1/R-2/R-4/R-5/R-6) are resolved against
  `/openapi.json` and the web reference module, and the interface paths/query
  params and DTO shapes reflect the confirmed contract.
- `AdsDtoRoundTripTest` (with committed fixtures under
  `core-model/src/test/resources/ads/`) and the MockWebServer tests T-1..T-7 are
  implemented and green in CI; ≥90% line coverage on the new surface; every
  endpoint has a verb/path/query assertion and every DTO has a round-trip test.
- No second `OkHttpClient`/`Retrofit`/`Moshi`; no manual cookie/CSRF/auth headers
  in the interface; money modeled with integer minor units (no `Double`);
  metrics modeled as `Long`; timestamps kept as ISO-8601 `String`.
- `./gradlew :core-model:testDebugUnitTest :core-network:assemble
  :core-network:testDebugUnitTest` passes locally and in CI with no new
  lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; the downstream E47 ads feature
  ticket(s) (AND-364) are unblocked (the ads repository, accounts/billing/
  campaigns screens, ViewModel, and tests can compile against these types and
  endpoints).
- A one-line note in the `core-network` README (owned by AND-007) records the
  `AdsAccountsApi` path/verb/query map and the delegation of cookie/CSRF/refresh/
  retry to AND-011/AND-012/AND-013/AND-016.
