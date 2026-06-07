---
id: AND-363
title: Ads accounts API
milestone: M8
epic: E47
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

FR-1. Define response **DTOs** in `core-model.ads` covering: an ads account
(`AdAccountDto` — same shape for list rows and single-account detail), an ads
campaign read row (`AdCampaignDto`), and an ads billing-history ledger entry
(`AdBillingEntryDto`). **[CORRECTED]** There is no separate summary/detail split,
no `MoneyDto`, and no paged-envelope types — verified against `src/api/types.ts`
and OpenAPI (see §16).

FR-2. Define a single Retrofit interface **`AdsAccountsApi`** in
`core-network.ads` exposing exactly the `/ui/ads/accounts*` read operations:
`listAdsAccounts` (bare array), `getAdsAccount` (single), `getAdsAccountBilling`
(billing-history array), and `listAdsAccountCampaigns` (campaigns array).

FR-3. All `AdsAccountsApi` methods are `suspend` functions returning the typed
DTO body. All are HTTP **GET** (campaign mutation is out of scope — a future
ticket). Paths are relative with **no leading slash** (AND-010 convention) so
they append to the normalized base URL; the route family is **`ui/ads/accounts`
(verified** against OpenAPI lines 784/786/787/789).

FR-4. **[CORRECTED]** These endpoints are **not paginated** in the contract.
`listAdsAccounts` and `listAdsAccountCampaigns` take no query params and return
bare JSON arrays. Only `getAdsAccountBilling` accepts an optional **`limit`**
`@Query` (default 50, matching the web client) to cap the returned history; no
`page`/`offset`/`cursor` and no envelope keys (`total`/`has_more`/`next_cursor`)
exist. Verified against OpenAPI `params=` and `src/api/endpoints/ads.ts`.

FR-5. Every DTO field maps to the backend's snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. Unknown/extra JSON keys are tolerated
(Moshi codegen default — additive backend evolution must not throw).

FR-6. Required vs optional fidelity: required fields are non-null and their
absence surfaces as a `JsonDataException` (fail fast); optional fields are
Kotlin-nullable with a `null`/empty default per `/openapi.json` `required`
arrays.

FR-7. **[CORRECTED]** Money/spend is modeled losslessly as **flat `*_cents`
integers** (`Long`): `balance_cents`, `lifetime_spend_cents` (account);
`budget_cents`, `daily_budget_cents`, `spent_today_cents`,
`lifetime_spent_cents` (campaign); `amount_cents` (billing entry). There is **no
nested `MoneyDto`, no per-payload ISO-4217 currency field, and no backend
`display` string** on these payloads (verified against `src/api/types.ts` and
OpenAPI `AdminAdAccountOut`). Values are `Long` to avoid `Int` overflow; no float
is used.

FR-8. **[CORRECTED]** Timestamps (`created_at`, `updated_at`) are **epoch
integers** decoded to `Long`, not ISO-8601 strings (OpenAPI `type: integer`;
`src/api/types.ts` types them as `number`). There are no `period_start`/
`period_end`/`start_date`/`end_date` fields on these payloads. Conversion to
`Instant` is deferred to the domain-mapping layer (downstream), consistent with
AND-026 §6. Enumerated tokens — account `status` (e.g. `"pending_review"`,
`"active"`, `"suspended"`), campaign `status` (e.g. `"running"`, `"paused"`,
`"ended"`), campaign `objective`, and billing-entry `entry_type`/`state` — are
kept as raw `String`s; mapping to typed enums is a downstream domain concern (an
unknown token must never throw at the DTO layer).

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

> **CORRECTED (review AND-363, 2026-06-06):** The original draft modeled a
> nested `MoneyDto` (`amount_minor` + ISO-4217 `currency` + `display`), paged
> envelopes (`AdsAccountPageDto`/`AdsCampaignPageDto` with `items`/`total`/
> `page`/`limit`/`has_more`/`next_cursor`), an enveloped billing **summary**
> (`AdsBillingDto` with `payment_status`/`payment_method`/`period_*`/embedded
> `invoices`), and ISO-8601 string timestamps. **All of these are wrong against
> the live contract.** Verified against `src/api/types.ts` (`AdAccount`,
> `Campaign`, `AdBillingEntry`) and `src/api/endpoints/ads.ts` (`listMyAdAccounts`,
> `getAdAccount`, `listCampaigns`, `getAdBillingHistory`) plus OpenAPI schema
> `AdminAdAccountOut`: money is **flat `*_cents` integers** (no `MoneyDto`, no
> `currency`, no `display`); all list reads return **bare JSON arrays** (no paged
> envelope); billing read returns a **bare array of `AdBillingEntry` ledger
> rows** (not a summary with payment status/method/invoices); and timestamps are
> **epoch integers** (`created_at`/`updated_at` `type: integer`), not ISO strings.
> The DTOs below are rewritten to the verified shapes. See §16 for the full audit.

```kotlin
package com.testlogon.android.core.model.ads

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * Advertiser account. Wire shape per src/api/types.ts: AdAccount and OpenAPI
 * AdminAdAccountOut. Money is flat *_cents integers; timestamps are epoch ints.
 * GET /ui/ads/accounts returns List<AdAccountDto>; GET /ui/ads/accounts/{id}
 * returns a single AdAccountDto (same shape — no separate summary/detail).
 */
@JsonClass(generateAdapter = true)
data class AdAccountDto(
    @Json(name = "account_id") val accountId: String,
    @Json(name = "owner_sub") val ownerSub: String? = null,
    @Json(name = "company_name") val companyName: String? = null,
    @Json(name = "billing_email") val billingEmail: String? = null,
    val status: String? = null,                                   // e.g. "pending_review" | "active" | "suspended"
    @Json(name = "balance_cents") val balanceCents: Long = 0,
    @Json(name = "lifetime_spend_cents") val lifetimeSpendCents: Long = 0,
    @Json(name = "created_at") val createdAt: Long = 0,           // epoch seconds (integer)
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

/** Campaign read row. Wire shape per src/api/types.ts: Campaign. */
@JsonClass(generateAdapter = true)
data class AdCampaignDto(
    @Json(name = "campaign_id") val campaignId: String,
    @Json(name = "account_id") val accountId: String? = null,
    val name: String? = null,
    val objective: String? = null,                               // e.g. "traffic" | "conversions"
    @Json(name = "budget_cents") val budgetCents: Long = 0,
    @Json(name = "budget_type") val budgetType: String? = null,
    @Json(name = "daily_budget_cents") val dailyBudgetCents: Long = 0,
    @Json(name = "spent_today_cents") val spentTodayCents: Long = 0,
    @Json(name = "lifetime_spent_cents") val lifetimeSpentCents: Long = 0,
    val status: String? = null,                                  // "running" | "paused" | "ended" | …
    @Json(name = "created_at") val createdAt: Long = 0,          // epoch seconds (integer)
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

/**
 * One billing-ledger entry. GET /ui/ads/accounts/{id}/billing returns a bare
 * List<AdBillingEntryDto> (billing HISTORY, not a summary). Wire shape per
 * src/api/types.ts: AdBillingEntry.
 */
@JsonClass(generateAdapter = true)
data class AdBillingEntryDto(
    @Json(name = "entry_id") val entryId: String,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "entry_type") val entryType: String? = null,    // e.g. "deposit" | "charge"
    @Json(name = "amount_cents") val amountCents: Long = 0,
    val state: String? = null,
    val reason: String? = null,
    val meta: Map<String, Any?> = emptyMap(),                    // free-form; see note below
    @Json(name = "created_at") val createdAt: Long = 0,          // epoch seconds (integer)
)
```

Design notes:
- **No paged envelopes and no `MoneyDto`.** The list/campaign/billing reads
  return bare JSON arrays decoded as `List<AdAccountDto>` / `List<AdCampaignDto>`
  / `List<AdBillingEntryDto>` (Retrofit + Moshi list adapter). The original
  envelope types (`AdsAccountPageDto`, `AdsCampaignPageDto`) and `MoneyDto`/
  `AdsInvoiceRefDto`/`AdsBillingDto` are **removed** — they do not exist in the
  contract. (Corrected; see §16.)
- `status` and `objective` are raw `String`s, not enums: the wire vocabulary is
  backend-owned and mapped to a sealed/`enum` type downstream; an unknown token
  must never throw at the DTO layer.
- All money is **flat `*_cents` `Long`** (no nested currency object; backend has
  no per-account ISO-4217 field on these payloads). Modeled `Long` to avoid any
  `Int` overflow on lifetime spend.
- All timestamps (`created_at`/`updated_at`) are **epoch integers** decoded to
  `Long`; conversion to `Instant` is deferred to the domain layer (consistent
  with AND-026 §6). No `Date`/`Instant` adapter is added in this ticket.
- `AdBillingEntryDto.meta` is a free-form `Map<String, Any?>` (web type
  `Record<string, unknown>`). Decoding an arbitrary map with Moshi codegen
  requires the reflective `Map` adapter to be on the shared `Moshi`; if it is
  not, model `meta` as a raw `String`/omit it (flagged Q-5 in §13).

### 4.2 `AdsAccountsApi` interface (`core-network.ads`)

> **CORRECTED (review AND-363, 2026-06-06):** Return types were paged envelopes
> and a billing summary; the live contract returns **bare arrays** and a billing
> **history array**. `listAdsAccounts`/`listAdsAccountCampaigns` carry **no
> `page`/`limit` query params** (verified: OpenAPI `params=` is empty for both,
> and `src/api/endpoints/ads.ts` calls them with no query). `getAdsAccountBilling`
> takes an optional **`limit`** query (default 50 in the web client), not paging.
> All paths verified present in OpenAPI lines 784/786/787/789.

```kotlin
package com.testlogon.android.core.network.ads

import com.testlogon.android.core.model.ads.AdAccountDto
import com.testlogon.android.core.model.ads.AdBillingEntryDto
import com.testlogon.android.core.model.ads.AdCampaignDto
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

interface AdsAccountsApi {

    /** Ads accounts owned by the current session user. Idempotent GET; bare array. */
    @GET("ui/ads/accounts")
    suspend fun listAdsAccounts(): List<AdAccountDto>

    /** Single ads account by id (same shape as a list row). */
    @GET("ui/ads/accounts/{account_id}")
    suspend fun getAdsAccount(
        @Path("account_id") accountId: String,
    ): AdAccountDto

    /** Billing HISTORY (ledger entries) for an account; bare array, capped by `limit`. */
    @GET("ui/ads/accounts/{account_id}/billing")
    suspend fun getAdsAccountBilling(
        @Path("account_id") accountId: String,
        @Query("limit") limit: Int = 50,
    ): List<AdBillingEntryDto>

    /** Read-only campaigns for an account; bare array (no paging). */
    @GET("ui/ads/accounts/{account_id}/campaigns")
    suspend fun listAdsAccountCampaigns(
        @Path("account_id") accountId: String,
    ): List<AdCampaignDto>
}
```

Path/verb conventions: relative paths, no leading slash, resolve against base
`http://18.222.237.167:8000/` → e.g. `…/ui/ads/accounts/{id}/billing`. The route
prefix `ui/ads/accounts` and the sub-resources `/billing` and `/campaigns` are
**verified distinct routes** in OpenAPI (lines 784, 786, 787, 789), so the
literal sub-paths are not shadowed by the `{account_id}` route. The `@Path` name
is `account_id` to mirror the OpenAPI path template (any consistent name works;
this keeps it self-documenting). Note OpenAPI also lists `user_sub`,
`X-SESSION-ID`, and `X-IMPERSONATION-TOKEN` as parameters on every `/ui/ads/*`
route; these are supplied by the shared session/transport layer (cookie/header
injection owned upstream) and are **not** declared per-method here.

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
current session user server-side; the client sends no `user_id`/`owner_sub`
query param. (OpenAPI lists `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`
as route params, but those are injected by the shared transport/session layer,
not declared per-method here.)

> **CORRECTED (review AND-363, 2026-06-06):** All example payloads below are
> rewritten to the **verified** wire shapes (`src/api/types.ts`,
> `src/api/endpoints/ads.ts`, OpenAPI `AdminAdAccountOut`). List/campaign/billing
> reads are **bare arrays**; money is **flat `*_cents` integers**; timestamps are
> **epoch integers**. The earlier enveloped/`MoneyDto`/ISO-string examples were
> fictional.

### GET `ui/ads/accounts`  (no query params; bare array)
Response `200`:
```json
[
  {
    "account_id": "ada_001",
    "owner_sub": "usr_77",
    "company_name": "Acme Brand Studio",
    "billing_email": "ads@acme.example",
    "status": "active",
    "balance_cents": 125000,
    "lifetime_spend_cents": 980000,
    "created_at": 1736668800,
    "updated_at": 1748777400
  }
]
```

### GET `ui/ads/accounts/{account_id}`  (single object, same shape as a list row)
Response `200`:
```json
{
  "account_id": "ada_001",
  "owner_sub": "usr_77",
  "company_name": "Acme Brand Studio",
  "billing_email": "ads@acme.example",
  "status": "active",
  "balance_cents": 125000,
  "lifetime_spend_cents": 980000,
  "created_at": 1736668800,
  "updated_at": 1748777400
}
```
`404`/`422` if the account id is unknown or not owned/managed by the session user.

### GET `ui/ads/accounts/{account_id}/billing?limit=50`  (billing HISTORY; bare array of ledger entries)
Response `200`:
```json
[
  {
    "entry_id": "ble_9001",
    "account_id": "ada_001",
    "campaign_id": "cmp_501",
    "entry_type": "charge",
    "amount_cents": 43250,
    "state": "settled",
    "reason": "daily_charge",
    "meta": { "source": "auto" },
    "created_at": 1748736000
  }
]
```

### GET `ui/ads/accounts/{account_id}/campaigns`  (no query params; bare array)
Response `200`:
```json
[
  {
    "campaign_id": "cmp_501",
    "account_id": "ada_001",
    "name": "Summer Launch",
    "objective": "conversions",
    "budget_cents": 50000,
    "budget_type": "lifetime",
    "daily_budget_cents": 5000,
    "spent_today_cents": 2134,
    "lifetime_spent_cents": 21340,
    "status": "running",
    "created_at": 1747562400,
    "updated_at": 1748777400
  }
]
```

> Related sibling reads **out of scope** here but present in the family (for
> downstream tickets): `GET /ui/ads/accounts/{account_id}/billing/campaigns/{campaign_id}`
> (per-campaign spending, `limit` default 100) and
> `GET /ui/ads/accounts/{account_id}/invoices/{month}` (monthly `AdInvoice`).

**Error envelope (all endpoints):** every `/ui/ads/*` route declares only
`422:HTTPValidationError` (plus implicit `4xx`) in OpenAPI; the FastAPI `detail`
union (`string | [{msg,type,loc}] | {code,...}`) applies. Mapping to a typed
`ApiError` is owned by **AND-015**; this ticket lets non-2xx surface as
`retrofit2.HttpException` so AND-015/AND-018 can map it.

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
- **Deserialization robustness (DTO layer):** **[CORRECTED field names]**
  - Missing **required** field (only `account_id` on `AdAccountDto`,
    `campaign_id` on `AdCampaignDto`, `entry_id` on `AdBillingEntryDto` are
    non-null with no default) → `JsonDataException` (desired fail-fast; asserted
    in tests). All other fields have Kotlin defaults to tolerate the backend's
    `default`-heavy schema (e.g. `AdminAdAccountOut` marks only `account_id`
    `required`).
  - Unknown/extra JSON keys → skipped silently (additive backend evolution safe).
  - `null` for a nullable field → tolerated; `null` for a non-null required field
    (`account_id`/`campaign_id`/`entry_id`) → `JsonDataException`.
  - An **empty top-level array** (`[]`) for any list read decodes to an empty
    `List`, never null.
  - Unknown enum token (`status: "archived"`, `objective: "app_installs"`,
    `entry_type: "adjustment"`, `state: "in_review"`) → tolerated as a raw
    `String`; never throws.
- **Money/timestamp safety:** every `*_cents` amount and every `created_at`/
  `updated_at` is `Long`; a non-integer/overflowing value surfaces as
  `JsonDataException` rather than silent float/`Int` truncation.
- This ticket maps **no** errors itself and applies **no** retry policy — those
  are AND-015 (`ApiError`), AND-018 (`ApiResult`), and AND-009/AND-016 (client
  retry).

## 8. Security & Privacy

- **Auth:** ads endpoints require the cookie-based `/ui/*` session; the shared
  client attaches cookies/CSRF transparently. `AdsAccountsApi` declares no manual
  `Cookie`/`Authorization`/`X-CSRF-Token` headers. Accounts are user-scoped
  server-side; the client never sends a `user_id`/`owner_sub` (no IDOR surface
  from this layer — only an `account_id` path param the server authorizes).
- **Transport:** on `dev` these ride plaintext HTTP
  (`http://18.222.237.167:8000`) — a known dev-only risk permitted by the scoped
  cleartext config (AND-006); `staging`/`prod` are HTTPS-only. **[CORRECTED]** The
  payloads carry financial figures (`balance_cents`, `lifetime_spend_cents`,
  `*_spent_cents`, billing `amount_cents`) and the account `billing_email` (PII);
  there is **no `payment_method`/PAN field** in these DTOs (that error is removed).
  The cleartext exposure is acknowledged as dev-only and must not reach prod.
- **Sensitive payloads / logging:** the billing/account DTOs carry semi-sensitive
  data (spend figures, `billing_email`). The AND-009 HTTP logger is
  **debug-build only**; because these bodies are not credentials, body logging in
  debug is acceptable. No DTO here carries passwords, tokens, CVV, card numbers,
  or a `payment_method` string, so no custom `toString()` redaction is required;
  if the backend ever returns an unmasked sensitive field, AND-052's redaction
  policy applies and a redacting adapter is added (flagged in Q-3).
- **No token storage:** auth is cookie-based; this layer holds no bearer tokens.
- **Injection safety:** `accountId` is passed as a Retrofit `@Path`
  (path-segment encoded); paging values are `@Query` ints (URL-encoded by
  OkHttp). No manual string concatenation into the URL.

## 9. Accessibility & i18n

Not applicable as a UI surface — this is a headless transport + DTO layer with no
Compose UI and no `strings.xml` entries. Three pass-through constraints are
recorded for downstream consumers (the ads ViewModels/screens under E47):
- **[CORRECTED]** Money is exposed as raw integer `*_cents` (`Long`), not a
  pre-formatted display string, so the UI/domain layer applies locale-aware
  currency formatting (`NumberFormat.getCurrencyInstance(locale)` over
  cents/100). There is no backend `display` string and no per-payload currency
  code, so downstream must supply the currency (platform default) when formatting.
- **[CORRECTED]** `created_at`/`updated_at` are raw **epoch integers** so the UI
  can format dates per device locale/time zone (`Instant.ofEpochSecond(...)` →
  `DateTimeFormatter` / `android.text.format.DateUtils`), rather than rendering
  server-formatted text.
- `status`/`objective`/`entry_type`/`state` are raw tokens (not localized labels)
  so the downstream feature can map them to localized, accessible status strings
  and `contentDescription`s for status chips; large figures format with locale
  grouping downstream.

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
- **Snake_case mapping. [CORRECTED]** Serialized `AdAccountDto` contains
  `"account_id"`/`"owner_sub"`/`"company_name"`/`"billing_email"`/
  `"balance_cents"`/`"lifetime_spend_cents"`/`"created_at"`/`"updated_at"`, never
  their camelCase forms; `AdCampaignDto` contains `"campaign_id"`/`"account_id"`/
  `"budget_cents"`/`"budget_type"`/`"daily_budget_cents"`/`"spent_today_cents"`/
  `"lifetime_spent_cents"`; `AdBillingEntryDto` contains `"entry_id"`/
  `"account_id"`/`"campaign_id"`/`"entry_type"`/`"amount_cents"`.
- **Required-field failure. [CORRECTED]** Removing `account_id` from an
  `AdAccountDto` sample (or `campaign_id` from `AdCampaignDto`, or `entry_id` from
  `AdBillingEntryDto`) causes `fromJson` to throw `JsonDataException`. (These are
  the only non-defaulted fields; other fields tolerate absence.)
- **Unknown-key tolerance.** A sample with an extra `"server_time"` /
  `"experimental_flag"` key deserializes without error.
- **Unknown-token tolerance. [CORRECTED]** `status: "archived"`,
  `objective: "app_installs"`, and billing `state: "in_review"` deserialize to the
  raw strings without throwing.
- **Money fidelity. [CORRECTED]** `balance_cents: 125000` /
  `lifetime_spend_cents: 980000` / `budget_cents` / `daily_budget_cents` /
  `spent_today_cents` / `lifetime_spent_cents` / billing `amount_cents` each
  decode to `Long` and survive round-trip with no float drift.
- **Timestamp fidelity. [CORRECTED]** `created_at: 1736668800` /
  `updated_at: 1748777400` decode to `Long` epoch values (no ISO parsing at this
  layer).
- **Array decoding. [CORRECTED]** `loadFixture("ads/accounts.json")` (a bare JSON
  array) decodes to `List<AdAccountDto>`; likewise campaigns and billing-history
  fixtures decode to `List<AdCampaignDto>` / `List<AdBillingEntryDto>`. Decoding
  uses `Types.newParameterizedType(List::class.java, T::class.java)`.
- **Defaults. [CORRECTED]** An empty array (`[]`) yields an empty `List`, not
  null; absent optional scalars (`updated_at`, `owner_sub`, etc.) fall back to
  their Kotlin defaults (`0`/`null`).

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

- **T-1 `listAdsAccounts` [CORRECTED]** — asserts `GET /ui/ads/accounts` (no
  query string), decodes a bare array to `List<AdAccountDto>`.
  ```kotlin
  @Test fun listAdsAccounts_noQueryAndDecodesArray() = runTest {
      val server = MockWebServer().apply {
          enqueue(MockResponse().setBody(loadFixture("ads/accounts.json"))); start()
      }
      val accounts = api(server).listAdsAccounts()
      val req = server.takeRequest()
      assertEquals("GET", req.method)
      assertEquals("/ui/ads/accounts", req.path)
      assertEquals("ada_001", accounts.first().accountId)
      assertEquals("active", accounts.first().status)
      assertEquals(125000L, accounts.first().balanceCents)
      server.shutdown()
  }
  ```
- **T-2 `getAdsAccount`** — asserts `GET /ui/ads/accounts/ada_001` (path param
  interpolated), decodes a single `AdAccountDto` including `lifetime_spend_cents`.
- **T-3 `getAdsAccountBilling` [CORRECTED]** — asserts
  `GET /ui/ads/accounts/ada_001/billing?limit=50` (literal sub-path + `limit`
  query), decodes a bare array to `List<AdBillingEntryDto>` including
  `amount_cents` and `meta`.
- **T-4 `listAdsAccountCampaigns` [CORRECTED]** — asserts
  `GET /ui/ads/accounts/ada_001/campaigns` (no query), decodes a bare array to
  `List<AdCampaignDto>` including the `*_cents` figures as `Long`.
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
  via a repository, rendering the ads-accounts list, account detail, billing
  history, and campaigns read. **[CORRECTED]** No Paging 3 is needed for these
  reads (bare arrays, not paginated). (The exact downstream consumer ids are the
  E47 ads-feature tickets following this DTO/API ticket; confirm against the
  backlog ordering, Q-4.)

**Sequencing within the ticket:** Q-1..Q-3 are now resolved against OpenAPI + the
web reference during this review (see §16). (1) define DTOs `AdAccountDto`/
`AdCampaignDto`/`AdBillingEntryDto` in `core-model.ads` + commit fixtures;
(2) write `AdsDtoRoundTripTest`; (3) declare `AdsAccountsApi`; (4) add
`AdsAccountsApiModule`; (5) write MockWebServer tests T-1..T-7.

## 13. Risks & Open Questions

- **R-1 Path-prefix / sub-resource shape. [RESOLVED]** Confirmed nested under
  `ui/ads/accounts/{account_id}/…`: `/billing` and `/campaigns` are distinct
  routes (OpenAPI lines 787, 789). Not top-level. Guarded by T-1..T-4.
- **R-2 Pagination contract. [RESOLVED]** Confirmed **no pagination** on list/
  campaign reads (bare arrays, empty `params=` in OpenAPI; `src/api/endpoints/ads.ts`
  sends no query). Billing read takes a single `limit` cap (default 50). No
  `page`/`offset`/`cursor` and no envelope. Original `page`/`limit` envelope
  design was wrong.
- **R-3 Summary vs detail divergence. [RESOLVED]** Confirmed **no divergence**:
  `listMyAdAccounts` returns `AdAccount[]` and `getAdAccount` returns one
  `AdAccount` of the **same shape** (`src/api/endpoints/ads.ts`). Collapsed to a
  single `AdAccountDto`.
- **R-4 Money representation. [RESOLVED]** Confirmed **flat integer `*_cents`**
  (OpenAPI `type: integer`; `src/api/types.ts` `*_cents: number`). No decimal
  string, no float, no nested `MoneyDto`, no per-payload currency code. Modeled as
  `Long`.
- **R-5 Sub-route shadowing. [RESOLVED]** `/billing` and `/campaigns` are
  registered as their own OpenAPI paths (no shadow). Guarded by T-3/T-4.
- **R-6 Billing shape. [RESOLVED]** Billing read is **not** a summary with
  embedded invoices — it returns a bare `AdBillingEntry[]` ledger history
  (`getAdBillingHistory` → `AdBillingEntry[]`). Monthly invoices are a **separate**
  endpoint `GET /ui/ads/accounts/{id}/invoices/{month}` (out of scope here).
  `AdsBillingDto`/`AdsInvoiceRefDto` were removed.
- **Q-1 [RESOLVED]** Route prefix `ui/ads/accounts`; sub-resources `/billing`,
  `/campaigns`; no pagination params (billing `limit` only). See R-1/R-2.
- **Q-2 [RESOLVED — moot]** No envelopes exist; list reads are bare arrays.
- **Q-3 [RESOLVED]** No `payment_method`/PAN field exists on these payloads;
  semi-sensitive data is limited to spend figures and `billing_email` (PII). No
  redacting adapter required now (AND-052 applies if a sensitive field appears).
- **Q-4** Which exact E47 ticket(s) consume this API first (confirm `blocks`
  list)? *Proposed:* AND-364. **[Unverified — not resolvable from the provided
  sources; backlog ordering not in scope of the OpenAPI/frontend references.]**
- **Q-5 [NEW]** `AdBillingEntryDto.meta` is a free-form map. Confirm the shared
  `Moshi` includes a reflective `Map`/`Any` adapter, or model `meta` as a raw
  `String`/omit it. *Proposed:* model as `Map<String, Any?>` with `emptyMap()`
  default; fall back to omission if the shared adapter set rejects `Any`.

## 14. Acceptance Criteria

- **AC-1 (backlog). [CORRECTED]** Ads DTOs (`AdAccountDto`, `AdCampaignDto`,
  `AdBillingEntryDto`) exist in `com.testlogon.android.core.model.ads` as
  immutable `@JsonClass(generateAdapter=true)` data classes. (No `MoneyDto`, no
  summary/detail split, no paged-envelope or invoice-ref types — those were
  fictional; see §16.)
- **AC-2 (backlog).** Ads account payloads **map (tested)**: every documented
  payload in Sections 4–5 (de)serializes the documented JSON exactly, proven by
  `AdsDtoRoundTripTest` against committed fixtures (parsed-tree equality,
  snake_case keys verified, bare-array and `*_cents`/epoch decoding).
- **AC-3.** `AdsAccountsApi` declares all four operations (`listAdsAccounts`,
  `getAdsAccount`, `getAdsAccountBilling`, `listAdsAccountCampaigns`); the module
  compiles against the ads DTOs.
- **AC-4. [CORRECTED]** Each endpoint is callable and its **verb + resolved path +
  query params** match Section 5, asserted with MockWebServer (T-1..T-4): list and
  campaigns reads send **no** query string; billing sends `?limit=50`; path-param
  interpolation and the literal `/billing` and `/campaigns` sub-paths verified.
- **AC-5. [CORRECTED]** Required-field absence (`account_id` on `AdAccountDto`,
  `campaign_id` on `AdCampaignDto`, `entry_id` on `AdBillingEntryDto`) throws
  `JsonDataException`; unknown JSON keys and unknown enum tokens are tolerated; an
  empty top-level array decodes to an empty `List`; absent optional scalars
  default to `0`/`null`/`emptyMap()`.
- **AC-6. [CORRECTED]** Money is lossless: every `*_cents` field decodes to `Long`
  and survives round-trip with no float drift; `created_at`/`updated_at` epoch
  values decode to `Long`.
- **AC-7.** Non-2xx (e.g. `404`/`422` from `getAdsAccount`, `403` from
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
- Open questions Q-1..Q-3/Q-5 (and risks R-1..R-6) are resolved against
  `/openapi.json` and the web reference module (done in this review, §16), and the
  interface paths/query params and DTO shapes reflect the confirmed contract; Q-4
  (first downstream consumer) remains an unverified backlog-ordering assumption.
- `AdsDtoRoundTripTest` (with committed fixtures under
  `core-model/src/test/resources/ads/`) and the MockWebServer tests T-1..T-7 are
  implemented and green in CI; ≥90% line coverage on the new surface; every
  endpoint has a verb/path/query assertion and every DTO has a round-trip test.
- No second `OkHttpClient`/`Retrofit`/`Moshi`; no manual cookie/CSRF/auth headers
  in the interface; **[CORRECTED]** money modeled as flat integer `*_cents`
  (`Long`, no `Double`); timestamps kept as epoch integers (`Long`); list reads
  return bare `List<T>` (no envelope).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
**OpenAPI index** = `reference/openapi.index.txt`; **OpenAPI spec** =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); **frontend** =
`reference/src/...`.

1. **Route prefix is `ui/ads/accounts` (relative, no leading slash).** Verified.
   OpenAPI `GET /ui/ads/accounts` (index line 784, op
   `list_my_accounts_ui_ads_accounts_get`); frontend `src/api/endpoints/ads.ts:
   listMyAdAccounts` (`/ui/ads/accounts`).
2. **`GET /ui/ads/accounts` lists the session user's accounts.** Verified.
   OpenAPI line 784; `src/api/endpoints/ads.ts: listMyAdAccounts`.
3. **List response is a bare JSON array, NOT a paged envelope.** Corrected (was
   `AdsAccountPageDto` with `items/total/page/limit/has_more/next_cursor`).
   `src/api/endpoints/ads.ts: listMyAdAccounts` returns `AdAccount[]`; OpenAPI
   `params=` is empty (no `page`/`limit`).
4. **List takes no `page`/`limit` query params.** Corrected. OpenAPI line 784
   `params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN` (session/transport only);
   `src/api/endpoints/ads.ts: listMyAdAccounts` sends no query.
5. **`GET /ui/ads/accounts/{account_id}` returns a single account, same shape as
   a list row.** Verified/Corrected (was separate `AdsAccountDetailDto`).
   OpenAPI line 786; `src/api/endpoints/ads.ts: getAdAccount` returns `AdAccount`
   (identical to the list element type).
6. **`AdAccount` fields = `account_id, owner_sub, company_name, billing_email,
   status, balance_cents, lifetime_spend_cents, created_at, updated_at`.**
   Corrected (was `id/name/status/currency/balance(MoneyDto)/campaign_count/...`).
   `src/api/types.ts: AdAccount`; cross-checked OpenAPI spec
   `components.schemas.AdminAdAccountOut` (pretty.json ~line 2415).
7. **Money is flat `*_cents` integers; no `MoneyDto`, no `currency`, no
   `display`.** Corrected. `src/api/types.ts: AdAccount.balance_cents` /
   `lifetime_spend_cents` (`number`); OpenAPI `AdminAdAccountOut.balance_cents`
   `type: integer` (pretty.json line 2422), `lifetime_spend_cents` `type: integer`
   (line 2442).
8. **`created_at`/`updated_at` are epoch integers, not ISO-8601 strings.**
   Corrected. OpenAPI `AdminAdAccountOut.created_at`/`updated_at` `type: integer`
   (pretty.json lines 2437, 2457); `src/api/types.ts: AdAccount.created_at: number`.
9. **Only `account_id` is required on the account payload.** Verified. OpenAPI
   `AdminAdAccountOut.required: ["account_id"]` (pretty.json ~line 2463).
10. **`GET /ui/ads/accounts/{account_id}/billing` returns billing HISTORY as a
    bare `AdBillingEntry[]`, NOT a billing summary with payment status/method/
    embedded invoices.** Corrected (was `AdsBillingDto`+`AdsInvoiceRefDto`).
    OpenAPI line 787 (op `billing_history_endpoint...`); `src/api/endpoints/ads.ts:
    getAdBillingHistory` returns `AdBillingEntry[]`.
11. **Billing read takes a `limit` query (default 50 in web client), not
    pagination.** Verified/Corrected. OpenAPI line 787 `params=account_id,limit,...`;
    `src/api/endpoints/ads.ts: getAdBillingHistory(accountId, limit = 50)`.
12. **`AdBillingEntry` fields = `entry_id, account_id, campaign_id, entry_type,
    amount_cents, state, reason, meta, created_at`.** Corrected. `src/api/types.ts:
    AdBillingEntry`.
13. **No `payment_status`/`payment_method`/`period_start`/`period_end` fields
    exist on any ads-accounts payload.** Corrected (these were invented).
    Absent from `src/api/types.ts: AdAccount`/`AdBillingEntry` and from OpenAPI
    `AdminAdAccountOut`.
14. **`GET /ui/ads/accounts/{account_id}/campaigns` returns a bare `Campaign[]`,
    no pagination.** Corrected (was `AdsCampaignPageDto` with `page`/`limit`).
    OpenAPI line 789 (`params=account_id,user_sub,...` — no `page`/`limit`);
    `src/api/endpoints/ads.ts: listCampaigns` returns `Campaign[]`.
15. **`Campaign` fields = `campaign_id, account_id, name, objective, budget_cents,
    budget_type, daily_budget_cents, spent_today_cents, lifetime_spent_cents,
    status, created_at, updated_at`. No `impressions`/`clicks`/`start_date`/
    `end_date`/`budget(MoneyDto)`/`spend(MoneyDto)`.** Corrected. `src/api/types.ts:
    Campaign`.
16. **`/billing` and `/campaigns` are distinct routes (no sub-route shadowing).**
    Verified. OpenAPI lines 787 and 789 are separate registered paths.
17. **All four methods are idempotent GETs; campaign mutation is out of scope.**
    Verified. The mutating ads routes (`POST /ui/ads/accounts/{id}/campaigns`,
    `PATCH .../campaigns/{campaign_id}`, `.../submit`, `.../deposit`) exist in
    OpenAPI (lines 790, 792, 793, 794) but are excluded from this read-only ticket.
18. **`user_sub`/`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` are transport/session-
    injected, not per-method client params.** Verified (interpretation). OpenAPI
    lists them on every `/ui/ads/*` route (lines 784–880); web `src/api/client.ts`
    attaches session context globally (not in `ads.ts` call sites).
19. **Cookie jar / CSRF / 401-refresh / `ApiResult` / error mapping are owned by
    AND-011/012/013/018/015, not this ticket.** Unverified-assumption (cross-ticket
    ownership) — not checkable against OpenAPI/frontend; consistent with the
    stated AND-363 scope.
20. **Retrofit 2.11.0 / OkHttp 4.12.0 / Moshi 1.15.x / Hilt-via-KSP behaviors
    (codegen adapters, `@Path` segment encoding, `MoshiConverterFactory` list
    decoding, no per-method headers).** Framework ref:
    https://square.github.io/retrofit/ , https://github.com/square/moshi (codegen +
    `Types.newParameterizedType`), https://dagger.dev/hilt/ .
21. **Sensitive data in payloads is limited to spend figures + `billing_email`
    (PII); no PAN/card field.** Verified. `src/api/types.ts: AdAccount`/
    `AdBillingEntry` contain no card/payment-method field.
22. **First downstream consumer is AND-364.** Unverified-assumption — backlog
    ordering is not present in the OpenAPI/frontend sources (Q-4).
23. **`AdBillingEntry.meta` is a free-form `Record<string, unknown>`.** Verified
    (web type) / open on the Kotlin side. `src/api/types.ts: AdBillingEntry.meta`;
    Moshi `Any`/`Map` decoding depends on the shared adapter set (Q-5).
24. **Sibling reads exist (per-campaign spending; monthly invoice) but are out of
    scope.** Verified. OpenAPI lines 788
    (`.../billing/campaigns/{campaign_id}`) and 795 (`.../invoices/{month}`);
    `src/api/endpoints/ads.ts: getCampaignSpending`, `getAdInvoice`.

### Corrections made
- **Money model:** removed nested `MoneyDto` (`amount_minor`/`currency`/`display`)
  → flat `*_cents` `Long` fields (claims 7). Affected §4.1, §5, §3 FR-7, §6, §9,
  §11, §14 AC-6, §15.
- **Pagination:** removed `AdsAccountPageDto`/`AdsCampaignPageDto` envelopes and
  all `page`/`limit` list queries → bare `List<T>` returns; kept only billing
  `limit` (claims 3, 4, 14). Affected §3 FR-1/FR-2/FR-4, §4.1, §4.2, §5, §11
  (T-1/T-4), §14 AC-4, §13 R-2.
- **Account summary/detail:** collapsed `AdsAccountSummaryDto`+`AdsAccountDetailDto`
  → single `AdAccountDto` (claim 5). Affected §3 FR-1, §4.1, §4.2, §13 R-3.
- **Billing shape:** replaced `AdsBillingDto`+`AdsInvoiceRefDto` (summary with
  payment status/method/period/invoices) → bare `List<AdBillingEntryDto>` history
  (claims 10–13). Affected §4.1, §4.2, §5, §8, §13 R-6.
- **Timestamps:** ISO-8601 `String` → epoch `Long` (claim 8). Affected §3 FR-8,
  §4.1, §6, §9, §11, §14 AC-6, §15.
- **Field names:** corrected to wire names (`company_name`, `owner_sub`,
  `billing_email`, `budget_type`, `daily_budget_cents`, `spent_today_cents`,
  `lifetime_spent_cents`, `entry_type`, `state`, etc.) and `@Path("account_id")`
  (claims 6, 12, 15). Affected §4.1, §4.2, §7, §11, §14 AC-1/AC-5.
- **Security:** dropped the (nonexistent) masked `payment_method` discussion;
  noted `billing_email` PII (claims 13, 21). Affected §8.
- **Open questions:** Q-1/Q-2/Q-3 resolved, Q-5 added; risks R-1..R-6 marked
  resolved. Affected §13.

### Open assumptions
- **Q-4 / claim 22 — first downstream consumer (AND-364):** not derivable from the
  OpenAPI/frontend sources (those describe the API, not the Android backlog
  ordering); carried as an assumption.
- **Claim 19 — cross-ticket ownership of cookie jar / CSRF / 401-refresh /
  `ApiResult` / FastAPI `detail` mapping:** an architectural assumption about
  AND-011/012/013/018/015; cannot be confirmed from the API/web sources.
- **Q-5 / claim 23 — `meta` decoding:** whether the shared `Moshi` instance
  includes a reflective adapter able to decode `Map<String, Any?>` is not
  observable from these sources; resolved at implementation (fallback: model
  `meta` as a raw JSON `String` or omit it).
- **HTTP status set beyond `422`:** OpenAPI declares only `200`/`422` (plus the
  implicit FastAPI defaults) for these routes; the `401`/`403`/`404` behaviors
  asserted in tests are assumed from standard FastAPI session/authorization
  semantics, not explicitly enumerated per-route in the spec.

## 17. Test Plan

Test targets (per the CI/dev inventory): **JVM** = local JVM unit/Robolectric (no
device); **emu35** = headless emulator AVD `test35` (x86_64, API 35); **A15** =
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This ticket is a
headless transport + DTO layer with **no UI, no camera/biometrics/WebRTC/FCM**,
so almost everything runs on **JVM**; one ABI/API smoke case is noted for the
physical device. No Compose-UI or accessibility cases apply (no UI surface);
their absence is justified in TC-AND-363-12.

- **TC-AND-363-01** — Type: contract/MockWebServer. Target: emu35 or JVM
  (MockWebServer; JVM sufficient). Preconditions: MockWebServer serving
  `ads/accounts.json` (a bare array). Steps: call `listAdsAccounts()`; capture the
  request. Expected: method `GET`, path exactly `/ui/ads/accounts` (no query
  string); response decodes to `List<AdAccountDto>` with `accountId="ada_001"`,
  `status="active"`, `balanceCents=125000L`, `lifetimeSpendCents=980000L`,
  `createdAt=1736668800L`. Traces: AC-3, AC-4, AC-6.
- **TC-AND-363-02** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  MockWebServer serving a single-object `ads/account.json`. Steps: call
  `getAdsAccount("ada_001")`. Expected: `GET /ui/ads/accounts/ada_001` (path-param
  interpolated, account_id not URL-mangled); decodes one `AdAccountDto` equal to
  the fixture (same shape as a list row). Traces: AC-3, AC-4, AC-5.
- **TC-AND-363-03** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  MockWebServer serving `ads/billing_history.json` (bare array of entries). Steps:
  call `getAdsAccountBilling("ada_001")` (default limit). Expected:
  `GET /ui/ads/accounts/ada_001/billing?limit=50`; decodes to
  `List<AdBillingEntryDto>` with `entryId`, `amountCents=43250L`, `entryType`,
  `state`, and `meta` populated. Traces: AC-3, AC-4, AC-6.
- **TC-AND-363-04** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  MockWebServer serving `ads/campaigns.json` (bare array). Steps: call
  `listAdsAccountCampaigns("ada_001")`. Expected: `GET /ui/ads/accounts/ada_001/campaigns`
  (no query string); decodes to `List<AdCampaignDto>` with `campaignId="cmp_501"`,
  `budgetCents=50000L`, `dailyBudgetCents=5000L`, `spentTodayCents=2134L`,
  `lifetimeSpentCents=21340L`, all `Long`. Traces: AC-3, AC-4, AC-6.
- **TC-AND-363-05** — Type: unit (Moshi round-trip). Target: JVM (`core-model`).
  Preconditions: production Moshi (codegen adapters). Steps: for each of
  `AdAccountDto`, `AdCampaignDto`, `AdBillingEntryDto`, decode its fixture, then
  re-encode. Expected: decode is non-null and equals the expected object; the
  re-encoded JSON's parsed tree equals the original parsed tree; serialized keys
  are snake_case (`balance_cents`, `lifetime_spend_cents`, `company_name`,
  `owner_sub`, `daily_budget_cents`, `entry_type`, etc.). Traces: AC-1, AC-2.
- **TC-AND-363-06** — Type: unit. Target: JVM. Preconditions: account fixture with
  `created_at`/`updated_at` epoch ints and `*_cents` near `Int.MAX_VALUE` (e.g.
  `lifetime_spend_cents: 9000000000`). Steps: decode. Expected: `createdAt`/
  `updatedAt`/`*_cents` are `Long` and exact (no `Int` overflow, no float drift).
  Traces: AC-2, AC-6.
- **TC-AND-363-07** — Type: unit (validation/error shape). Target: JVM.
  Preconditions: fixtures with the sole required field removed —
  `account_id`-less account, `campaign_id`-less campaign, `entry_id`-less billing
  entry. Steps: decode each. Expected: each throws `JsonDataException` (fail-fast).
  Traces: AC-5.
- **TC-AND-363-08** — Type: unit (tolerance). Target: JVM. Preconditions: fixtures
  with (a) extra unknown keys (`server_time`, `experimental_flag`), (b) unknown
  enum tokens (`status:"archived"`, `objective:"app_installs"`,
  `state:"in_review"`), (c) absent optionals, (d) empty top-level array `[]`.
  Steps: decode. Expected: unknown keys ignored; unknown tokens kept as raw
  `String`; absent optionals default to `0`/`null`/`emptyMap()`; `[]` → empty
  `List` (never null). Traces: AC-5.
- **TC-AND-363-09** — Type: contract/MockWebServer (error propagation). Target:
  JVM. Preconditions: MockWebServer enqueuing `404` then `422` then `403`. Steps:
  call `getAdsAccount` (404), `getAdsAccount` (422), `getAdsAccountBilling` (403)
  using the real FastAPI `detail` body (`{"detail":"..."}` and the
  `[{"msg","type","loc"}]` validation form). Expected: each raises
  `retrofit2.HttpException` with the matching `code()`, body not swallowed (so
  AND-015 can map it). Traces: AC-7.
- **TC-AND-363-10** — Type: contract/MockWebServer (offline / flaky-dev-host).
  Target: JVM. Preconditions: MockWebServer scripted with
  `SocketPolicy.NO_RESPONSE` / `DISCONNECT_AT_START`, or pointed at a dead port to
  simulate the unreliable `18.222.237.167:8000` dev host. Steps: call
  `listAdsAccounts()`. Expected: a transport exception
  (`SocketTimeoutException`/`IOException`) propagates unchanged (this layer adds no
  retry/swallow; AND-009/AND-016 own backoff for these idempotent GETs). Traces:
  AC-7.
- **TC-AND-363-11** — Type: integration (Hilt). Target: emu35 (`@HiltAndroidTest`)
  or JVM via a minimal `core-testing` component. Preconditions: Hilt graph with
  AND-010's shared `Retrofit`. Steps: inject `AdsAccountsApi` twice. Expected:
  non-null, `@Singleton` (same instance on repeated injection), built on the shared
  `Retrofit`; no second `OkHttpClient`/`Retrofit`/`Moshi` created; no per-method
  cookie/CSRF headers declared on the interface. Traces: AC-8.
- **TC-AND-363-12** — Type: unit (security/no-leak + scope guard). Target: JVM.
  Preconditions: the `AdsAccountsApi` source/proxy and DTO set. Steps: assert (via
  reflection or compile-time review) that no method declares a `@Header`
  `Cookie`/`Authorization`/`X-CSRF-Token`/`user_sub` param and no DTO field is a
  PAN/card/`payment_method`; assert `billing_email` is the only PII field and is
  not logged by any custom `toString()`. Note: confirms no UI/accessibility surface
  exists (so no Compose-UI/a11y cases are owed), and that user scoping relies only
  on the server-authorized `account_id` path param (no IDOR query param). Traces:
  AC-1, AC-8.
- **TC-AND-363-13** — Type: instrumented/e2e smoke (ABI / API-level). Target:
  **A15 (physical device — MUST run here, not emu35)**. Preconditions:
  debug build installed on SM-A156U (arm64-v8a, API 34); a reachable stub or the
  dev backend returning a known `ads/accounts.json`. Steps: from an instrumented
  test, inject `AdsAccountsApi` and call `listAdsAccounts()`/`getAdsAccount()`.
  Expected: KSP-generated Moshi adapters load and decode correctly on **arm64-v8a
  / API 34** (catches arm64-vs-x86 and API-34-vs-35 codegen/R8 differences the
  emulator suite would miss); results equal the JVM-decoded objects. Traces: AC-2,
  AC-9.
- **TC-AND-363-14** — Type: manual. Target: A15 (or emu35) with the real dev
  backend `http://18.222.237.167:8000`. Preconditions: a valid session cookie
  (logged-in advertiser). Steps: trigger `listAdsAccounts` → `getAdsAccount` →
  `getAdsAccountBilling` → `listAdsAccountCampaigns` against live data; observe the
  redacting debug HTTP log. Expected: live payloads decode without
  `JsonDataException`; `*_cents`/epoch fields are plausible; confirms the live
  contract matches §5 (guards against undocumented backend drift). Traces: AC-2,
  AC-9.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (DTOs exist, correct shape) | TC-05, TC-12 |
| AC-2 (payloads map, tested) | TC-05, TC-06, TC-13, TC-14 |
| AC-3 (all four ops declared/compile) | TC-01, TC-02, TC-03, TC-04 |
| AC-4 (verb/path/query per §5) | TC-01, TC-02, TC-03, TC-04 |
| AC-5 (required-fail / tolerance / defaults) | TC-02, TC-07, TC-08 |
| AC-6 (money + epoch lossless `Long`) | TC-01, TC-03, TC-04, TC-06 |
| AC-7 (non-2xx + transport not swallowed) | TC-09, TC-10 |
| AC-8 (Hilt singleton, no extra client/headers) | TC-11, TC-12 |
| AC-9 (CI build/tests; ABI/API parity) | TC-13, TC-14 |
