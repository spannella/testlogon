---
id: AND-218
title: Purchases API
milestone: M5
epic: E30
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: [AND-219, AND-220, AND-221, AND-222]
---

# AND-218 — Purchases API

## 1. Overview & Goal

This ticket delivers the typed HTTP seam and Moshi-backed data-transfer objects
(DTOs) for the TestLogon **purchases / order-history** surface: listing a user's
past purchases (paged), fetching a single purchase/order detail, and full-text
search over purchase history. It produces no UI, no repositories, and no
ViewModels — it is the transport-and-serialization foundation that the purchase
history feature (AND-219), order detail + tracking (AND-220), the purchases
ViewModel (AND-221), and the purchases test suite (AND-222) build on.

Scope, verbatim from the backlog: *`purchases.ts` list/detail/search.* The
referenced `purchases.ts` is the **web reference** API module
(`reference/src/api/endpoints/purchases.ts`); this ticket ports its three
read operations — list, detail, search — to a native Retrofit `PurchasesApi`
plus the DTOs those endpoints (de)serialize. **[CORRECTED]** The real endpoint
family is `/ui/purchase-history/transactions` (NOT `purchases/…` or `orders/…`),
verified against the OpenAPI index and `purchases.ts`. The web module also
exposes mutating actions (shipping/complete/revert/cancel) and events/receipt
sub-resources; this ticket ports only the three **read** operations named in the
backlog (list/detail/search) and defers the mutating actions to AND-220's order
detail work. The single backlog acceptance criterion is:
*Purchases map (tested).* This ticket therefore owns (a) immutable Kotlin DTOs in
`core-model` modeling the documented purchase-transaction JSON exactly
(snake_case → camelCase via Moshi), (b) the Retrofit `PurchasesApi` interface in
`core-network` exposing list/detail/search with correct verbs/paths/query
params, and (c) the
Hilt provider plus the MockWebServer and round-trip test suites that prove every
payload (de)serializes and every endpoint is callable.

This ticket deliberately does **not** own: cookie jar (AND-011), CSRF injection
(AND-012), the 401-refresh `Authenticator` (AND-013), `ApiResult<T>` wrapping
(AND-018), FastAPI `detail` error mapping (AND-015), bounded-backoff retry for
idempotent GETs (AND-016), Paging 3 `PagingSource`/`Pager` wiring (AND-221/AND-219),
or any Room cache / domain mapping (`core-data`, AND-219 consumers). Those attach
to the shared `OkHttpClient`/`Retrofit` or live in higher layers and take effect
for `PurchasesApi` calls without changes here.

The deliverable: compiling DTOs + a compiling `PurchasesApi` + its Hilt provider +
a green test suite asserting (de)serialization fidelity and each endpoint's
verb/path/query/decoding.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. DTOs land in module **`core-model`** under package
  `com.testlogon.android.core.model.purchases`. The `PurchasesApi` interface and
  its Hilt module land in **`core-network`** under
  `com.testlogon.android.core.network.purchases`.
- **Canonical package:** `com.testlogon.android` everywhere a package appears.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines, JDK 17,
  minSdk 24 / compileSdk 35, AGP 8.7.3 / Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. `PurchasesApi` lives in
  `core-network`, consumes DTOs from `core-model`, is consumed by `core-data`
  repositories and `feature-purchases` (AND-219/AND-221). No `feature-*`/`app`
  symbols leak into `core-network`/`core-model`.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** the backlog
  pins AND-218 to AND-027. Purchase endpoints are served behind the cookie-based
  session; this ticket reuses the same shared `OkHttpClient`/`Retrofit` (cookie
  jar, CSRF, 401-refresh) established by the auth-network stack, so AND-027's
  transport conventions (relative paths, no leading slash, `suspend` methods,
  Hilt-provided service on the shared `Retrofit`) are the template followed here.
- **Transitive upstream:** AND-010 (Retrofit + Moshi + KSP codegen), AND-009
  (shared `OkHttpClient` + timeouts + redacting logger), AND-006
  (`BuildConfig.API_BASE_URL`, dev → `http://18.222.237.167:8000/`),
  AND-003/AND-004 (module structure, Hilt baseline). AND-016 (bounded backoff for
  idempotent GETs) applies to these endpoints once present but is not a compile
  dependency.
- **Backend:** FastAPI + DynamoDB; dev host is plaintext HTTP and unreliable
  (~20s timeouts; bounded backoff for idempotent GETs owned by AND-009/AND-016).
  All purchase endpoints in this ticket are **idempotent GETs**. OpenAPI at
  `/openapi.json` is authoritative for shapes, paths, and `required` arrays.
- **Web reference (authoritative for field names / paths):**
  `reference/src/api/endpoints/purchases.ts` (the ported module) and shared types
  in `reference/src/api/types.ts` — **[CORRECTED]** the relevant types are
  `PurchaseTransactionSummary` (list/search row), `PurchaseTransactionInfo`
  (detail, which `extends PurchaseTransactionSummary`), and `PurchaseShipping`
  (carrier/tracking sub-object). There is **no** `Purchase`/`Order`/line-item/
  `Money` type in `types.ts`; the prior draft invented those. Mirror the real
  wire names exactly; do **not** invent camelCase wire keys — the backend is
  snake_case.
- **[CORRECTED] Web client transport (`reference/src/api/client.ts`):** the web
  client sends `Authorization: Bearer <accessToken>` (from `authStore`) **and**
  `X-CSRF-Token` (from the `ui_csrf` cookie) on **every** request, with
  `credentials: "include"` (cookies). 401 triggers one `POST /ui/session/refresh`
  then a single retry. The Android transport convention is owned by AND-027 (the
  shared `OkHttpClient`/`Retrofit`); this ticket adds no manual auth headers.

## 3. Functional Requirements

FR-1. Define response **DTOs** in `core-model.purchases` covering: a purchase
**transaction summary** (list/search row → `PurchaseTransactionSummary`), a full
purchase **transaction detail** (`PurchaseTransactionInfo`, a superset of the
summary), and a carrier/shipping/tracking sub-object (`PurchaseShipping`, for
AND-220). **[CORRECTED]** There is **no** order line-item type, **no** nested
money/price object, and **no** paged envelope in the real contract — list and
search return **bare JSON arrays** of summaries, and money is a flat
`amount: number` + `currency: String` on each transaction. The prior draft's
`PurchaseItemDto`, `MoneyDto`, `PurchasePageDto`, and `PurchaseSearchResultDto`
do not correspond to the backend and are removed/replaced below.

FR-2. Define a single Retrofit interface **`PurchasesApi`** in
`core-network.purchases` exposing exactly three operations matching the web
`purchases.ts`: `listTransactions` (history list), `getTransaction` (detail), and
`searchTransactions` (full-text over history). **[CORRECTED]** Method names mirror
the web module exactly (`listTransactions`/`getTransaction`/`searchTransactions`),
not the prior draft's `listPurchases`/`getPurchase`/`searchPurchases`; list and
search return arrays, not paged envelopes.

FR-3. All `PurchasesApi` methods are `suspend` functions returning the typed DTO
body. All are HTTP **GET** (purchase history is read-only at this layer; cart /
checkout mutation is AND-210/AND-213). Paths are relative with **no leading
slash** (AND-010 convention) so they append to the normalized base URL.

FR-4. **[CORRECTED]** There is **no** page/offset/cursor paging. `listTransactions`
accepts optional `@Query("limit") limit: Int?` and optional `@Query("status")
status: String?`; `searchTransactions` accepts required `@Query("q") q: String`
and optional `@Query("limit") limit: Int?`. Each returns a **bare JSON array**
(`List<PurchaseTransactionSummary>`), with no `total`/`page`/`has_more`/
`next_cursor` envelope. Verified against OpenAPI
`GET /ui/purchase-history/transactions` (params=`limit,status`),
`GET /ui/purchase-history/transactions/search` (params=`q,limit`), and
`purchases.ts: listTransactions`/`searchTransactions`. Any client-side paging
(Paging 3) is an AND-219/AND-221 concern layered above this array return.

FR-5. Every DTO field maps to the backend's snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. Unknown/extra JSON keys are tolerated
(Moshi codegen default — additive backend evolution must not throw).

FR-6. Required vs optional fidelity: required fields are non-null and their
absence surfaces as a `JsonDataException` (fail fast); optional fields are
Kotlin-nullable with a `null`/empty default per `/openapi.json` `required` arrays.

FR-7. **[CORRECTED]** Money is **not** a nested minor-unit object. The backend
sends a flat top-level `amount` (JSON `number`) plus a top-level `currency`
(ISO-4217 `String`) on each transaction; there are **no** `amount_minor`,
`display`, `subtotal`, `tax`, `shipping`, or per-line price fields. The summary
and detail schemas are identical on money (`amount` + `currency`, both
`required`). To avoid float drift on a JSON `number`, `amount` is modeled as
`java.math.BigDecimal` (Moshi maps JSON numbers to `BigDecimal` losslessly) — not
`Double`. (If the domain layer later wants minor units, it derives them from
`amount` + `currency`; that is an AND-219 concern.)

FR-8. **[CORRECTED]** Timestamps (`created_at`, `updated_at`, and detail-only
`completed_at`/`reverted_at`/`receipt_generated_at`, plus shipping
`shipped_at`/`delivered_at`/`last_carrier_check`) are **integer epoch seconds**
(`Long`), not ISO-8601 strings; there is **no** `purchased_at` field. The one
string-typed time field is shipping `estimated_delivery` (a `String`). Parsing
epoch → `Instant` is deferred to the domain-mapping layer (AND-219 consumers),
consistent with AND-026 §6. Transaction `status` is kept as a raw `String` (e.g.
`"pending"`, `"completed"`, `"reverted"`, `"cancelled"`); mapping to a typed enum
is a domain-layer concern downstream.

FR-9. All DTOs are immutable `data class`es; collections are exposed as read-only
`List<T>` with safe defaults (`emptyList()`).

FR-10. A Hilt `@Provides @Singleton fun providePurchasesApi(retrofit: Retrofit):
PurchasesApi` constructs the service from the shared `Retrofit` (AND-010). No new
`Retrofit`/`OkHttpClient` is created; no per-method cookie/CSRF headers are
declared.

FR-11. Captured JSON sample fixtures are committed under `core-model` test
resources for each payload and drive round-trip tests.

## 4. Technical Design

DTOs land in
`core-model/src/main/kotlin/com/testlogon/android/core/model/purchases/`. The
`PurchasesApi` and `PurchasesApiModule` land in
`core-network/src/main/kotlin/com/testlogon/android/core/network/purchases/`.

### 4.1 DTOs (`core-model.purchases`)

All DTOs are `@JsonClass(generateAdapter = true)` so Moshi codegen (KSP) emits
adapters at build time (no reflection adapter added for these types).

**[CORRECTED]** The DTO model below replaces the prior draft's invented
`MoneyDto`/`PurchaseItemDto`/`TrackingDto`/`PurchaseSummaryDto`/
`PurchaseDetailDto`/`PurchasePageDto`/`PurchaseSearchResultDto`. The real wire
shapes are the OpenAPI `PurchaseTransactionSummary`, `PurchaseTransactionInfo`,
and `PurchaseShippingIn` schemas (verified field-by-field).

```kotlin
package com.testlogon.android.core.model.purchases

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import java.math.BigDecimal

/**
 * Carrier/shipping/tracking sub-object (OpenAPI PurchaseShippingIn; web
 * PurchaseShipping). All fields optional. Consumed by AND-220.
 * carrier_events is a free-form object list, kept as raw maps at the DTO layer.
 */
@JsonClass(generateAdapter = true)
data class PurchaseShippingDto(
    val carrier: String? = null,
    @Json(name = "tracking_number") val trackingNumber: String? = null,
    @Json(name = "tracking_url") val trackingUrl: String? = null,
    val status: String? = null,
    @Json(name = "status_description") val statusDescription: String? = null,
    @Json(name = "shipped_at") val shippedAt: Long? = null,        // epoch seconds
    @Json(name = "delivered_at") val deliveredAt: Long? = null,    // epoch seconds
    @Json(name = "estimated_delivery") val estimatedDelivery: String? = null, // String
    @Json(name = "carrier_events") val carrierEvents: List<Map<String, Any?>> = emptyList(),
    @Json(name = "last_carrier_check") val lastCarrierCheck: Long? = null,
    val address: Map<String, Any?>? = null,
)

/**
 * List/search row. OpenAPI PurchaseTransactionSummary.
 * required: txn_id, created_at, updated_at, status, amount, currency.
 */
@JsonClass(generateAdapter = true)
data class PurchaseTransactionSummaryDto(
    @Json(name = "txn_id") val txnId: String,
    @Json(name = "created_at") val createdAt: Long,        // epoch seconds
    @Json(name = "updated_at") val updatedAt: Long,        // epoch seconds
    val status: String,
    val amount: BigDecimal,                                // lossless, never Double
    val currency: String,                                  // ISO-4217, e.g. "USD"
    @Json(name = "merchant_id") val merchantId: String? = null,
    @Json(name = "external_ref") val externalRef: String? = null,
    val description: String? = null,
)

/**
 * Full transaction detail. OpenAPI PurchaseTransactionInfo (superset of summary).
 * required adds: buyer_id, version (txn_id/created_at/updated_at/status/amount/
 * currency carried from the summary).
 */
@JsonClass(generateAdapter = true)
data class PurchaseTransactionInfoDto(
    @Json(name = "txn_id") val txnId: String,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long,
    val status: String,
    val amount: BigDecimal,
    val currency: String,
    @Json(name = "merchant_id") val merchantId: String? = null,
    @Json(name = "external_ref") val externalRef: String? = null,
    val description: String? = null,
    @Json(name = "buyer_id") val buyerId: String,
    val version: Int,
    val shipping: PurchaseShippingDto? = null,
    val cancel: Map<String, Any?>? = null,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "reverted_at") val revertedAt: Long? = null,
    val metadata: Map<String, Any?>? = null,
    @Json(name = "receipt_path") val receiptPath: String? = null,
    @Json(name = "receipt_generated_at") val receiptGeneratedAt: Long? = null,
    // buyer_profile (ProfileBase) is omitted here; AND-219 may add it if needed.
)
```

Design notes:
- **[CORRECTED]** No paged-envelope DTOs exist: list and search return
  `List<PurchaseTransactionSummaryDto>` directly (a bare JSON array). The
  Retrofit method return type is the parameterized list; Moshi resolves the
  `List<T>` adapter at the Retrofit converter via `Types.newParameterizedType` —
  no envelope codegen needed.
- `status` is a raw `String` not an enum: the wire vocabulary is owned by the
  backend and mapped to a sealed/`enum` type in the AND-219/AND-221 domain layer;
  an unknown status string must never throw at the DTO layer.
- `PurchaseShippingDto` is modeled here (even though tracking UI is AND-220) so
  that `getTransaction` decodes the complete detail payload in one round trip and
  AND-220 needs no DTO additions. `carrier_events`/`cancel`/`metadata`/`address`
  are free-form objects in OpenAPI (`additionalProperties: true`) and are kept as
  `Map<String, Any?>` rather than typed.
- **[CORRECTED]** Timestamps are epoch-seconds `Long`, not ISO-8601 `String`. The
  lone string time field is shipping `estimated_delivery`. No `Date`/`Instant`
  adapter is added in this ticket.
- **[CORRECTED]** `amount` is `BigDecimal` (the wire type is a JSON `number`).
  Moshi parses JSON numbers to `BigDecimal` losslessly when the target field is
  `BigDecimal`; `Double` is forbidden (float drift). The summary and detail use
  the same `amount`/`currency` representation.

### 4.2 `PurchasesApi` interface (`core-network.purchases`)

**[CORRECTED]** Paths, method names, params, and return types below match the
OpenAPI index and `purchases.ts` exactly.

```kotlin
package com.testlogon.android.core.network.purchases

import com.testlogon.android.core.model.purchases.PurchaseTransactionInfoDto
import com.testlogon.android.core.model.purchases.PurchaseTransactionSummaryDto
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

interface PurchasesApi {

    /** Purchase history (transaction list) for the current session user. GET. */
    @GET("ui/purchase-history/transactions")
    suspend fun listTransactions(
        @Query("limit") limit: Int? = null,
        @Query("status") status: String? = null,
    ): List<PurchaseTransactionSummaryDto>

    /** Full transaction detail by id. */
    @GET("ui/purchase-history/transactions/{txnId}")
    suspend fun getTransaction(
        @Path("txnId") txnId: String,
    ): PurchaseTransactionInfoDto

    /** Full-text search over the user's purchase history (AND-219). */
    @GET("ui/purchase-history/transactions/search")
    suspend fun searchTransactions(
        @Query("q") q: String,
        @Query("limit") limit: Int? = null,
    ): List<PurchaseTransactionSummaryDto>
}
```

Path/verb conventions: relative paths, **no leading slash** (AND-010 convention)
so they append to the normalized base URL; e.g. resolves to
`…/ui/purchase-history/transactions/{txnId}`. **[CORRECTED]** The route family is
`ui/purchase-history/transactions`, verified against OpenAPI
(`GET /ui/purchase-history/transactions`,
`GET /ui/purchase-history/transactions/{txn_id}`,
`GET /ui/purchase-history/transactions/search`) and `purchases.ts`. The path
param is `txn_id` (web uses `${txnId}`); the Retrofit `@Path` name is `txnId`
bound to the `{txnId}` placeholder. Routing note: `…/transactions/search` is a
distinct literal route in OpenAPI declared alongside `…/transactions/{txn_id}`,
so server-side it is **not** shadowed by the id route (R-5 is resolved — the
literal route exists). Retrofit only builds the URL; ordering is irrelevant
client-side.

### 4.3 Hilt provider

```kotlin
package com.testlogon.android.core.network.purchases.di

import com.testlogon.android.core.network.purchases.PurchasesApi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object PurchasesApiModule {

    @Provides
    @Singleton
    fun providePurchasesApi(retrofit: Retrofit): PurchasesApi =
        retrofit.create(PurchasesApi::class.java)
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

Base path (`dev`): the `BuildConfig.API_BASE_URL` from AND-006 (the specific dev
host value is owned by AND-006 and not re-verified here — see Open assumptions).
All responses are JSON; all three endpoints are idempotent **GET**s requiring the
authenticated session and tolerating the AND-013 401-refresh-once behavior.
Endpoints are scoped to the current session user server-side (no `user_id` query
param; the web client passes identity via auth headers/cookies handled by AND-027).

**[CORRECTED]** All example payloads below were rebuilt from the OpenAPI schemas
`PurchaseTransactionSummary`, `PurchaseTransactionInfo`, and `PurchaseShippingIn`.

### GET `ui/purchase-history/transactions?limit=20&status=completed`
Response `200` — a **bare array** of summaries:
```json
[
  {
    "txn_id": "txn_001",
    "created_at": 1747836191,
    "updated_at": 1747922600,
    "status": "completed",
    "amount": 45.97,
    "currency": "USD",
    "merchant_id": "mer_001",
    "external_ref": "TL-100245",
    "description": "Logo Tee x2"
  }
]
```

### GET `ui/purchase-history/transactions/{txn_id}`
Response `200`:
```json
{
  "txn_id": "txn_001",
  "created_at": 1747836191,
  "updated_at": 1747922600,
  "status": "completed",
  "amount": 45.97,
  "currency": "USD",
  "merchant_id": "mer_001",
  "external_ref": "TL-100245",
  "description": "Logo Tee x2",
  "buyer_id": "usr_42",
  "version": 3,
  "shipping": {
    "carrier": "ups",
    "tracking_number": "1Z999AA10123456784",
    "tracking_url": "https://www.ups.com/track?tracknum=1Z999AA10123456784",
    "status": "in_transit",
    "status_description": "On the way",
    "shipped_at": 1747850000,
    "delivered_at": null,
    "estimated_delivery": "2026-05-25",
    "carrier_events": [
      { "timestamp": "2026-05-21T18:00:00Z", "description": "Shipped", "location": "Columbus OH" }
    ],
    "last_carrier_check": 1747900000,
    "address": { "line1": "123 Main St", "city": "Columbus", "state": "OH", "zip": "43215" }
  },
  "cancel": null,
  "completed_at": 1747922600,
  "reverted_at": null,
  "metadata": { "source": "web" },
  "receipt_path": "receipts/txn_001.pdf",
  "receipt_generated_at": 1747922700
}
```
`404` if the transaction id is unknown or not owned by the session user.

### GET `ui/purchase-history/transactions/search?q=tee&limit=20`
Response `200` — a **bare array** (same row shape as list, no envelope/`query` key):
```json
[
  {
    "txn_id": "txn_001",
    "created_at": 1747836191,
    "updated_at": 1747922600,
    "status": "completed",
    "amount": 45.97,
    "currency": "USD",
    "external_ref": "TL-100245",
    "description": "Logo Tee x2"
  }
]
```

**Error responses (all endpoints):** the OpenAPI index lists `400`, `401`, `403`,
`422` (`HTTPValidationError`), and `429` for these routes. The FastAPI `detail`
union is `string | [{msg,type,loc}] | {code,...}` (confirmed in
`reference/src/api/client.ts: normalizeErrorDetail`). Mapping to a typed
`ApiError` is owned by **AND-015**; this ticket lets non-2xx surface as
`retrofit2.HttpException` so AND-015/AND-018 can map it. Path family, param names,
and `required` arrays are now verified (Q-1 resolved).

## 6. Data & State Management

- `PurchasesApi` is **stateless** — a singleton interface proxy with no fields.
  DTOs are transient wire types.
- **No Room / DataStore** in this ticket. Caching history pages, the Paging 3
  `PagingSource`/`RemoteMediator`, and domain mapping are `core-data` / AND-219 /
  AND-221 concerns. DTOs must **not** be persisted directly nor enter Compose
  composition; they carry no `@Stable`/`@Immutable` annotations.
- **No `StateFlow`/`UiState`** here. The purchases ViewModel (AND-221) exposes
  `StateFlow<PurchasesUiState>` by consuming a repository that wraps these calls in
  `ApiResult<T>` (AND-018). This layer returns plain DTOs (happy path) and throws
  on failure.
- **Session state** rides on the AND-027 transport: cookies persisted by the
  AND-011 jar plus, per the web client (`client.ts`), an `Authorization: Bearer`
  token and an `X-CSRF-Token` (`ui_csrf` cookie) header. **[CORRECTED]**
  `PurchasesApi` itself neither reads nor writes any of these — they are attached
  globally by the shared client. CSRF is sent on every web request (not just
  mutating verbs) but for these read-only GETs it is harmless and handled globally.
- **Pagination state** — **[CORRECTED]** there is no server pagination metadata to
  carry: list/search return bare arrays with only an optional `limit` request cap
  (and `status` filter on list). Any client-side accumulation/Paging 3 is an
  AND-221 concern; the DTOs carry no `page`/`total`/`has_more`/`next_cursor`.
- **Serialization** uses the shared Moshi codegen adapters via the AND-010
  converter; unknown keys are ignored, absent optional fields fall back to Kotlin
  defaults. **[CORRECTED]** ISO-4217 `currency` is a `String` and `amount` is a
  `BigDecimal` (never `Double`) to avoid float drift; timestamps are epoch-seconds
  `Long` (except shipping `estimated_delivery`, a `String`).
- **Threading:** suspend methods are invoked from an IO-dispatcher coroutine at the
  repository layer; this ticket imposes no dispatcher.

## 7. Error Handling & Resilience

Responsibilities here are narrow: declare endpoints and DTOs so failures propagate
cleanly and deserialization is robust.

- **Non-2xx** (`404` unknown/unowned purchase, `422` bad query, `403` if not
  owned) surfaces as `retrofit2.HttpException` carrying the raw error body for
  AND-015 to decode the FastAPI `detail`. Nothing is swallowed here.
- **`401`** on any purchases call is intercepted by the AND-013 `Authenticator`,
  which calls `sessionRefresh()` once and retries; only a second `401` propagates,
  which the consumer routes to login (AND-025). Purchase history is auth-only, so a
  hard `401` (expired session) is the most common failure and must reach the
  consumer cleanly.
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged. The ~20s timeouts and **bounded backoff for
  idempotent GETs** are owned by AND-009/AND-016 on the shared client — all three
  purchases methods are GETs and are therefore retry-eligible there.
- **Deserialization robustness (DTO layer):** **[CORRECTED required set]**
  - Missing **required** field — summary/detail: `txn_id`, `created_at`,
    `updated_at`, `status`, `amount`, `currency`; detail additionally `buyer_id`,
    `version` — → `JsonDataException` (desired fail-fast; asserted in tests).
  - Unknown/extra JSON keys → skipped silently (additive backend evolution safe).
  - `null` for a nullable field → tolerated; `null` for a non-null field →
    `JsonDataException`.
  - Empty/absent arrays/objects → modeled via `emptyList()`/`null` defaults so an
    absent `shipping`, empty `carrier_events`, or an empty history array never
    produces unexpected nulls.
  - Unknown `status` string (e.g. `"partially_refunded"`) → tolerated as a raw
    `String`; never throws (mapped downstream).
- **Money safety:** **[CORRECTED]** `amount` is a JSON `number` decoded to
  `BigDecimal`; precision is preserved with no float truncation. (There is no
  `amount_minor`/`Long` field on the wire.)
- This ticket maps **no** errors itself and applies **no** retry policy — those are
  AND-015 (`ApiError`), AND-018 (`ApiResult`), and AND-009/AND-016 (client retry).

## 8. Security & Privacy

- **Auth:** **[CORRECTED]** these endpoints require the authenticated session, and
  per the web client (`client.ts`) that means an `Authorization: Bearer` token
  **plus** session cookies **plus** an `X-CSRF-Token` header — not cookie-only.
  The shared AND-027 client attaches all of these transparently; `PurchasesApi`
  declares no manual `Cookie`/`Authorization`/`X-CSRF-Token` headers. Endpoints are
  user-scoped server-side; the client never sends a `user_id` (no IDOR surface from
  this layer).
- **Transport:** on `dev` these ride plaintext HTTP — a known dev-only risk
  permitted by the scoped cleartext config (AND-006); `staging`/`prod` are
  HTTPS-only. Purchase payloads carry PII (`shipping.address`, `buyer_id`,
  `tracking_number`, transaction `amount`/`description`), so the cleartext exposure
  is acknowledged as dev-only and must not reach prod.
- **Sensitive payloads / logging:** **[CORRECTED]** purchase DTOs contain
  semi-sensitive data (`shipping.address`, `buyer_id`, `tracking_number`,
  `receipt_path`). There is **no** `payment_method`/PAN field in the contract, so
  there is no card-masking concern here. The AND-009 HTTP logger is **debug-build
  only**; because these bodies are not credentials, body logging in debug is
  acceptable. No DTO here carries passwords, tokens, CVV, or card numbers, so no
  custom `toString()` redaction is required; if the backend ever returns an
  unmasked sensitive field, AND-052's redaction policy applies and a redacting
  adapter is added (flagged in Q-3).
- **No token storage:** auth is cookie-based; this layer holds no bearer tokens.
- **Injection safety:** the `q` search term is passed as a Retrofit `@Query`
  (URL-encoded by OkHttp); `txnId` is passed as a `@Path` (path-segment encoded).
  No manual string concatenation into the URL.
- **External tracking link:** `shipping.tracking_url` is opaque, carrier-supplied
  data; this
  layer only deserializes it. The consumer (AND-220) is responsible for validating
  the scheme (https) before opening it in a browser/Custom Tab.

## 9. Accessibility & i18n

Not applicable as a UI surface — this is a headless transport + DTO layer with no
Compose UI and no `strings.xml` entries. Three pass-through constraints are
recorded for downstream consumers (AND-219/AND-220/AND-221):
- **[CORRECTED]** Each transaction exposes `amount` (`BigDecimal`) + `currency`
  (ISO-4217) so the UI/domain layer can apply locale-aware currency formatting
  (`NumberFormat.getCurrencyInstance(locale)`). There is no backend-formatted
  display string to fall back to.
- **[CORRECTED]** `createdAt`/`updatedAt` (and detail epoch fields) are epoch
  seconds (`Long`); `estimatedDelivery` is a raw `String`. The UI converts epochs
  to `Instant` and formats per device locale/time zone (`DateTimeFormatter` /
  `android.text.format.DateUtils`), rather than rendering server-formatted text.
- `status` is a raw token (not a localized label) so AND-219 can map it to a
  localized, accessible status string and a `contentDescription` for status chips.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's `HttpLoggingInterceptor` (debug
  builds only). No new logging is added here.
- **No analytics events** emitted by this layer. Purchase-history-viewed /
  purchase-detail-viewed / purchase-search-performed events are emitted by the
  purchases ViewModel (AND-221) from `ApiResult` outcomes, not from `PurchasesApi`.
- **Build-time signal:** KSP must generate Moshi adapters for every purchases DTO
  referenced here; a missing adapter fails the build (no reflection fallback, per
  AND-010 policy). This is the only diagnostic surface the ticket adds.

## 11. Testing Strategy

Two test surfaces: **round-trip DTO tests** (JVM, in `core-model`) and
**MockWebServer endpoint tests** (JVM, in `core-network`), both using the
production Moshi/Retrofit configuration. This ticket's tests satisfy the AND-218
backlog acceptance (*Purchases map (tested)*); the broader repo + UI tests are
AND-222.

### 11.1 DTO round-trip tests (`core-model`)
Captured samples live at
`core-model/src/test/resources/purchases/<name>.json`. Test class:
`com.testlogon.android.core.model.purchases.PurchasesDtoRoundTripTest`.

- **Round-trip fidelity.** For each DTO, `moshi.adapter(T::class.java).fromJson(sample)`
  is non-null and equals the expected object; re-serializing yields JSON whose
  parsed tree equals the original parsed tree (compare as Moshi `Map`/`JSONObject`
  to ignore key order/whitespace).
- **Snake_case mapping.** **[CORRECTED]** Serialized `PurchaseTransactionSummaryDto`
  contains `"txn_id"`, `"created_at"`, `"updated_at"`, `"merchant_id"`,
  `"external_ref"`, never their camelCase forms; `PurchaseTransactionInfoDto`
  additionally contains `"buyer_id"`, `"completed_at"`, `"receipt_path"`;
  `PurchaseShippingDto` contains `"tracking_number"`/`"tracking_url"`/
  `"estimated_delivery"`/`"carrier_events"`.
- **Required-field failure.** **[CORRECTED]** Removing `txn_id`/`status`/`amount`/
  `currency`/`created_at`/`updated_at` from a summary sample (or `buyer_id`/
  `version` from a detail sample) causes `fromJson` to throw `JsonDataException`.
- **Unknown-key tolerance.** A sample with an extra `"server_time"` /
  `"experimental_flag"` key deserializes without error.
- **Unknown-status tolerance.** `status: "partially_refunded"` deserializes to the
  raw string without throwing.
- **Money fidelity.** **[CORRECTED]** `amount: 45.97` deserializes to `BigDecimal`
  `45.97` (assert via `compareTo`/string value) and survives round-trip with no
  float drift; a high-precision value (e.g. `19.995`) is preserved exactly, proving
  no `Double` coercion.
- **Nested decoding.** **[CORRECTED]** `PurchaseTransactionInfoDto` decodes its
  `shipping` object (including `carrier_events` list) and the free-form
  `metadata`/`cancel`/`address` maps.
- **Defaults.** **[CORRECTED]** A list response of `[]` decodes to an empty
  `List`, not null; a detail with no `shipping` yields `null`; absent
  `carrier_events` yields `emptyList()`.

### 11.2 MockWebServer endpoint tests (`core-network`)
Harness mirrors the AND-027 pattern:
```kotlin
private fun api(server: MockWebServer): PurchasesApi {
    // Mirrors production provideMoshi(): codegen adapters + a BigDecimal adapter
    // (Moshi has no built-in BigDecimal mapping; needed so `amount` stays lossless).
    val moshi = Moshi.Builder().add(BigDecimalAdapter).build()
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(PurchasesApi::class.java)
}
```

- **T-1 `listTransactions`** — asserts `GET /ui/purchase-history/transactions?limit=10&status=completed`
  (query present and correct), decodes `List<PurchaseTransactionSummaryDto>`.
  ```kotlin
  @Test fun listTransactions_sendsQueryAndDecodes() = runTest {
      val server = MockWebServer().apply {
          enqueue(MockResponse().setBody(loadFixture("purchases/transaction_list.json"))); start()
      }
      val rows = api(server).listTransactions(limit = 10, status = "completed")
      val req = server.takeRequest()
      assertEquals("GET", req.method)
      assertEquals("/ui/purchase-history/transactions?limit=10&status=completed", req.path)
      assertEquals(1, rows.size)
      assertEquals("completed", rows.first().status)
      assertEquals(0, BigDecimal("45.97").compareTo(rows.first().amount))
      server.shutdown()
  }
  ```
- **T-2 `getTransaction`** — asserts `GET /ui/purchase-history/transactions/txn_001`
  (path param interpolated), decodes `PurchaseTransactionInfoDto` including nested
  `shipping` (with `carrier_events`), `buyer_id`, `version`, and epoch fields.
- **T-3 `searchTransactions`** — asserts
  `GET /ui/purchase-history/transactions/search?q=logo%20tee&limit=20`
  (`q` URL-encoded; a query with a space encodes to `logo%20tee`), decodes a bare
  `List<PurchaseTransactionSummaryDto>`.
- **T-4 error propagation** — a `404` from `getTransaction` throws
  `retrofit2.HttpException` with `code() == 404` (confirms non-2xx not swallowed,
  leaving room for AND-015).
- **T-5 `401` not swallowed** — a `401` from `listTransactions` surfaces as
  `HttpException(401)` at this bare-Retrofit harness (the AND-013 refresh
  `Authenticator` is not installed in the unit harness; this documents that the DTO
  layer itself adds no auth handling).
- **T-6 Hilt provider** — `@HiltAndroidTest` (or minimal `core-testing` harness)
  injects `PurchasesApi`, asserts non-null `@Singleton` built on the shared
  Retrofit (same instance on repeated injection).

Coverage target: ≥90% on the new surface (DTOs + interface binding + provider);
each of the three endpoints has at least one verb/path/query assertion; every DTO
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
- **AND-219** (Purchase history + search) — consumes `listTransactions`/`searchTransactions`
  via a repository + Paging 3, renders the history list and search.
- **AND-220** (Order detail + tracking) — consumes `getTransaction`; uses
  `PurchaseTransactionInfoDto.shipping` (carrier/tracking) and the transaction
  `amount`/`status`. (AND-220 also depends on AND-219.) The web module's mutating
  actions (shipping update, complete/revert, cancel request/respond) and the
  events/receipt sub-resources are AND-220 scope, not ported here.
- **AND-221** (Purchases ViewModel) — wraps the repository in `ApiResult`/`UiState`,
  owns paging state.
- **AND-222** (Purchases tests) — repo + UI tests over the above; transitively
  depends on this surface.

**Sequencing within the ticket:** (1) confirm path prefix, pagination param names,
money representation, and `required` arrays against `/openapi.json` +
`reference/src/api/endpoints/purchases.ts` (Q-1..Q-3 — now resolved, see §16);
(2) define DTOs in
`core-model.purchases` + commit fixtures; (3) write `PurchasesDtoRoundTripTest`;
(4) declare `PurchasesApi`; (5) add `PurchasesApiModule`; (6) write MockWebServer
tests T-1..T-6.

## 13. Risks & Open Questions

- **R-1 Path-prefix ambiguity. [RESOLVED]** The route family is
  `ui/purchase-history/transactions` — neither `purchases/…` nor `orders/…`.
  Verified against OpenAPI index + `purchases.ts`; all paths/tests updated.
- **R-2 Pagination contract. [RESOLVED]** There is **no** paging contract: list
  and search return bare arrays; the only request params are `limit` (+`status` on
  list, `q` on search). No `page`/`offset`/`cursor`/envelope. Verified against
  OpenAPI params and `purchases.ts`.
- **R-3 Summary vs detail divergence. [RESOLVED]** Confirmed distinct: detail
  (`PurchaseTransactionInfo`) is a superset of the list/search row
  (`PurchaseTransactionSummary`, which it `extends`). Search and list share the
  exact summary row shape (verified: both typed `PurchaseTransactionSummary[]`).
- **R-4 Money representation. [RESOLVED]** Backend sends a flat top-level
  `amount` (JSON `number`) + `currency` string — **not** `amount_minor`, not a
  nested object, not a decimal string. Modeled as `BigDecimal` to stay lossless.
  Guarded by the money-fidelity test.
- **R-5 Search route shadowing. [RESOLVED]** OpenAPI declares
  `GET /ui/purchase-history/transactions/search` as a distinct literal route
  alongside `…/transactions/{txn_id}`; no shadowing. `searchTransactions` is kept
  as a separate method (matches `purchases.ts`).
- **R-6 Tracking shape. [RESOLVED]** `shipping` is a single object
  (`PurchaseShippingIn`/`PurchaseShipping`), not a list; multi-package detail (if
  any) is carried inside `carrier_events`. Modeled as a single `PurchaseShippingDto`.
- **Q-1 [RESOLVED]** Path family + params: `ui/purchase-history/transactions`,
  `limit`/`status`/`q`, bare-array returns. Verified.
- **Q-2 [RESOLVED]** Search and list share the identical summary row shape; both
  return `List<PurchaseTransactionSummaryDto>` (no separate envelope type needed).
- **Q-3 [RESOLVED]** No `payment_method`/PAN field exists in the contract; semi-
  sensitive fields are `shipping.address`/`buyer_id`/`tracking_number`. No
  redacting adapter required now; AND-052 policy applies only if a future field
  arrives sensitive.

## 14. Acceptance Criteria

- **AC-1 (backlog).** **[CORRECTED]** Purchase DTOs
  (`PurchaseTransactionSummaryDto`, `PurchaseTransactionInfoDto`,
  `PurchaseShippingDto`) exist in `com.testlogon.android.core.model.purchases`
  as immutable `@JsonClass(generateAdapter=true)` data classes.
- **AC-2 (backlog).** Purchases **map (tested)**: every documented payload in
  Sections 4–5 (de)serializes the documented JSON exactly, proven by
  `PurchasesDtoRoundTripTest` against committed fixtures (parsed-tree equality,
  snake_case keys verified, nested `shipping`/`carrier_events` decoded).
- **AC-3.** **[CORRECTED]** `PurchasesApi` declares all three operations
  (`listTransactions`, `getTransaction`, `searchTransactions`); the module compiles
  against the purchases DTOs.
- **AC-4.** **[CORRECTED]** Each endpoint is callable and its **verb + resolved
  path + query params** match Section 5, asserted with MockWebServer (T-1..T-3),
  including the `listTransactions` `limit`/`status` query, `getTransaction`
  path-param interpolation (`{txnId}`), and URL-encoded `searchTransactions` `q`.
- **AC-5.** **[CORRECTED]** Required-field absence (`txn_id`, `status`, `amount`,
  `currency`, `created_at`, `updated_at`; detail also `buyer_id`, `version`) throws
  `JsonDataException`; unknown JSON keys and unknown `status` strings are tolerated;
  empty `carrier_events` defaults to `emptyList()` and absent `shipping` defaults
  to `null`.
- **AC-6.** **[CORRECTED]** Money is lossless: every `amount` decodes to
  `BigDecimal` and survives round-trip with no float drift (no `Double`).
- **AC-7.** Non-2xx (e.g. `404` from `getTransaction`, `401` from
  `listTransactions`) surfaces as `HttpException` and is not swallowed (T-4/T-5).
- **AC-8.** `PurchasesApi` is Hilt-provided as a `@Singleton` built on the shared
  `Retrofit`; repeated injection yields the same instance; no new
  `OkHttpClient`/`Retrofit`/`Moshi` is constructed and no per-method cookie/CSRF
  headers are declared (T-6).
- **AC-9.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no new lint/detekt regressions.

## 15. Definition of Done

- DTOs (`com.testlogon.android.core.model.purchases`) and `PurchasesApi` +
  `PurchasesApiModule` (`com.testlogon.android.core.network.purchases[.di]`) are
  implemented under `core-model`/`core-network`, package base
  `com.testlogon.android`; no DTOs redefined elsewhere.
- Open questions Q-1/Q-2/Q-3 (and risks R-1/R-2/R-4/R-5/R-6) are resolved against
  `/openapi.json` and `reference/src/api/endpoints/purchases.ts`, and the interface
  paths/query params and DTO shapes reflect the confirmed contract.
- `PurchasesDtoRoundTripTest` (with committed fixtures under
  `core-model/src/test/resources/purchases/`) and the MockWebServer tests T-1..T-6
  are implemented and green in CI; ≥90% line coverage on the new surface; every
  endpoint has a verb/path/query assertion and every DTO has a round-trip test.
- No second `OkHttpClient`/`Retrofit`/`Moshi`; no manual cookie/CSRF/auth headers
  in the interface; **[CORRECTED]** money modeled as `BigDecimal` (no `Double`);
  timestamps kept as epoch-seconds `Long` (shipping `estimated_delivery` a `String`).
- `./gradlew :core-model:testDebugUnitTest :core-network:assemble
  :core-network:testDebugUnitTest` passes locally and in CI with no new
  lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; AND-219/AND-220/AND-221/AND-222 are
  unblocked (the purchases repository, history/detail/search screens, ViewModel,
  and tests can compile against these types and endpoints).
- A one-line note in the `core-network` README (owned by AND-007) records the
  `PurchasesApi` path/verb/query map and the delegation of cookie/CSRF/refresh/retry
  to AND-011/AND-012/AND-013/AND-016.

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT, and an exact source pointer.

1. **Endpoint family is `ui/purchase-history/transactions`** (not `purchases/…`
   or `orders/…`). **Corrected.** OpenAPI `GET /ui/purchase-history/transactions`,
   `GET /ui/purchase-history/transactions/{txn_id}`,
   `GET /ui/purchase-history/transactions/search`; `src/api/endpoints/purchases.ts:
   listTransactions/getTransaction/searchTransactions`.
2. **All three operations are GET.** Verified. Same OpenAPI lines (method=GET);
   `purchases.ts` uses `api.get(...)` for list/search/detail.
3. **List params are `limit` (optional) + `status` (optional).** Verified/Corrected
   (was `page`/`limit`). OpenAPI `GET /ui/purchase-history/transactions
   | params=limit,status,…`; `purchases.ts: listTransactions({limit,status})`.
4. **Search params are `q` (required) + `limit` (optional).** Verified/Corrected
   (was `q`+`page`+`limit`). OpenAPI `…/transactions/search | params=q,limit,…`;
   `purchases.ts: searchTransactions(q, limit)`.
5. **Detail path param is `txn_id`.** Corrected (was `purchaseId`). OpenAPI
   `…/transactions/{txn_id}`; `purchases.ts: getTransaction(txnId)`.
6. **List and search return BARE ARRAYS of `PurchaseTransactionSummary`** (no
   `items`/`total`/`page`/`has_more`/`next_cursor` envelope). Corrected. OpenAPI
   index shows `resp=200:` with no schema for both routes; `purchases.ts` typed
   return is `PurchaseTransactionSummary[]` for both.
7. **Detail response schema is `PurchaseTransactionInfo`** (superset of the
   summary). Verified/Corrected (was `PurchaseDetailDto` with `items`/totals).
   OpenAPI `…/transactions/{txn_id} | resp=200:PurchaseTransactionInfo`;
   `components.schemas.PurchaseTransactionInfo`; `types.ts: PurchaseTransactionInfo
   extends PurchaseTransactionSummary`.
8. **Money is a flat top-level `amount` (JSON number) + `currency` (string); no
   `amount_minor`, no nested money object, no `subtotal`/`tax`/`shipping`/line
   prices.** Corrected. `components.schemas.PurchaseTransactionSummary` →
   `amount: number`, `currency: string` (both in `required`);
   `types.ts: PurchaseTransactionSummary { amount: number; currency: string }`.
9. **Modeling `amount` as `BigDecimal` (not `Double`) to stay lossless.**
   Unverified-assumption (design choice). Rationale: JSON `number` + the no-float
   requirement (FR-7). framework ref:
   https://github.com/square/moshi#custom-type-adapters (Moshi has no built-in
   `BigDecimal` adapter; a custom one is required).
10. **Timestamps are integer epoch seconds (`created_at`, `updated_at`,
    `completed_at`, `reverted_at`, `receipt_generated_at`, shipping
    `shipped_at`/`delivered_at`/`last_carrier_check`); `estimated_delivery` is a
    `String`; there is no `purchased_at`.** Corrected (was ISO-8601 strings +
    `purchased_at`). `components.schemas.PurchaseTransactionInfo` (those fields
    `type: integer`); `PurchaseShippingIn.estimated_delivery: string`;
    `types.ts: created_at:number, updated_at:number, estimated_delivery?:string`.
11. **No order line-items exist.** Corrected (prior `PurchaseItemDto` invented).
    `PurchaseTransactionInfo` has no `items` array (schema enumerated in full).
12. **Tracking is the `shipping` object (`PurchaseShippingIn`), a single object
    with a `carrier_events` list — not a `tracking` field or a list.** Corrected.
    `components.schemas.PurchaseShippingIn`;
    `PurchaseTransactionInfo.shipping → $ref PurchaseShippingIn`;
    `types.ts: PurchaseShipping`.
13. **Required fields — summary: `txn_id,created_at,updated_at,status,amount,
    currency`; detail adds `buyer_id,version`.** Verified/Corrected.
    `components.schemas.PurchaseTransactionSummary.required` and
    `PurchaseTransactionInfo.required`.
14. **Web client auth = `Authorization: Bearer <token>` + cookies
    (`credentials:"include"`) + `X-CSRF-Token` (from `ui_csrf` cookie) on every
    request.** Corrected (spec claimed cookie-only, no bearer token).
    `src/api/client.ts` (sets `Authorization` from `authStore`, `X-CSRF-Token`
    from `ui_csrf`, `credentials:"include"`).
15. **401 → one `POST /ui/session/refresh` then a single retry.** Verified.
    `src/api/client.ts: refreshSession()` + 401 branch.
16. **Error shapes: `400/401/403/422(HTTPValidationError)/429`; FastAPI `detail`
    union `string | [{msg,type,loc}] | {code,...}`.** Verified. OpenAPI index for
    the three routes lists those codes; `src/api/client.ts: normalizeErrorDetail`
    handles all three `detail` forms.
17. **No `payment_method`/PAN field in the contract.** Corrected (spec discussed
    masking a `payment_method`). Not present in `PurchaseTransactionInfo` schema.
18. **Hilt provides `PurchasesApi` from the shared `Retrofit` via
    `retrofit.create(...)`.** Unverified-assumption (depends on AND-010's
    `NetworkModule`, not in these sources). framework ref:
    https://square.github.io/retrofit/ (service creation);
    https://dagger.dev/hilt/modules (module/provider pattern).
19. **Relative paths with no leading slash append to the normalized base URL.**
    Unverified-assumption for Android (AND-010 convention); web client
    `withApiBase` does normalize a leading slash, so paths there start with `/`.
    framework ref: https://square.github.io/retrofit/2.x/retrofit/retrofit2/Retrofit.Builder.html#baseUrl-okhttp3.HttpUrl-
20. **Dev base URL `http://18.222.237.167:8000/`.** Unverified-assumption (owned by
    AND-006/`BuildConfig`; not present in the provided OpenAPI/frontend sources;
    the frontend reads `VITE_API_BASE_URL` from env).
21. **`searchTransactions` route not shadowed by `{txn_id}`.** Verified. The
    literal `…/transactions/search` route is declared distinctly in the OpenAPI
    index alongside `…/transactions/{txn_id}`.

### Corrections made
- Endpoint family `purchases/…`/`orders/…` → `ui/purchase-history/transactions`
  (paths, method names, tests). (#1, #5)
- Method names `listPurchases/getPurchase/searchPurchases` →
  `listTransactions/getTransaction/searchTransactions`. (#1)
- Pagination removed: bare-array returns; params reduced to `limit`(+`status`)/`q`;
  dropped `PurchasePageDto`/`PurchaseSearchResultDto` and all `page/total/has_more/
  next_cursor`. (#3, #4, #6)
- DTO model rebuilt: removed invented `MoneyDto`/`PurchaseItemDto`/`TrackingDto`/
  `PurchaseSummaryDto`/`PurchaseDetailDto`; added `PurchaseTransactionSummaryDto`,
  `PurchaseTransactionInfoDto`, `PurchaseShippingDto`. (#7, #8, #11, #12)
- Money: nested minor-unit `MoneyDto` → flat `amount: BigDecimal` + `currency`. (#8)
- Timestamps: ISO-8601 `String`/`purchased_at` → epoch-seconds `Long`
  (`created_at`/`updated_at`/…), with `estimated_delivery` a `String`. (#10)
- Required-field sets corrected across FR-6, §7, AC-5. (#13)
- Auth corrected to Bearer + cookies + CSRF (not cookie-only); §2/§6/§8. (#14)
- Removed the non-existent `payment_method`/PAN masking discussion. (#17)
- Example payloads in §5 fully rebuilt from the real schemas.

### Open assumptions
- `amount` modeled as `BigDecimal` — a deliberate design choice, not dictated by
  the sources (the wire type is only "number"). A custom Moshi adapter is required.
  (#9)
- Hilt provider wiring and the shared-`Retrofit` singleton are inherited from
  AND-010/AND-027, which are outside the provided sources. (#18)
- Leading-slash/relative-path convention for the Android Retrofit base URL is an
  AND-010 convention not provable from these sources. (#19)
- Dev base URL value is owned by AND-006/`BuildConfig`; not present in the OpenAPI
  or frontend sources (frontend uses an env var). (#20)
- `buyer_profile` (`ProfileBase`) on the detail schema is intentionally omitted
  from the DTO; whether AND-219 needs it is deferred. Source:
  `PurchaseTransactionInfo.buyer_profile`.

## 17. Test Plan

This is a headless transport + DTO layer: there is **no Compose UI**, so there are
no Compose-UI or accessibility test cases (a11y is recorded as N/A in §9). All
deserialization/contract logic runs on the **JVM unit/Robolectric** target; the
Hilt-provider case runs on the **headless emulator AVD `test35`**; the
flaky-dev-host / offline behavior is owned by AND-009/AND-016 but is smoke-checked
here against the real dev host from the **physical device (SM-A156U)** to exercise
true cellular/Wi-Fi loss (a behavior the emulator cannot faithfully reproduce).
Test targets are noted per case.

- **TC-AND-218-01** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Precondition: `MockWebServer` enqueues `200` with fixture
  `purchases/transaction_list.json` (bare array). Steps: call
  `listTransactions(limit=10, status="completed")`; capture the request. Expected:
  method `GET`, path `/ui/purchase-history/transactions?limit=10&status=completed`;
  response decodes to a `List<PurchaseTransactionSummaryDto>` of size 1 with
  `status="completed"` and `amount.compareTo(BigDecimal("45.97"))==0`. Traces: AC-3,
  AC-4.
- **TC-AND-218-02** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Precondition: `200` with fixture `purchases/transaction_detail.json`. Steps: call
  `getTransaction("txn_001")`. Expected: path
  `/ui/purchase-history/transactions/txn_001`; decodes `PurchaseTransactionInfoDto`
  with `buyerId`, `version`, nested `shipping.trackingNumber`,
  `shipping.carrierEvents` non-empty, and epoch `createdAt` as `Long`. Traces:
  AC-3, AC-4.
- **TC-AND-218-03** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Precondition: `200` with a bare-array search fixture. Steps: call
  `searchTransactions(q="logo tee", limit=20)`. Expected: path
  `/ui/purchase-history/transactions/search?q=logo%20tee&limit=20` (space
  URL-encoded); decodes a bare `List<PurchaseTransactionSummaryDto>`. Traces: AC-3,
  AC-4.
- **TC-AND-218-04** — Type: unit (JVM, Moshi round-trip). Target: JVM unit.
  Precondition: committed fixtures for each DTO. Steps: `fromJson` then `toJson`
  each DTO; parse both JSON trees to `Map`. Expected: trees equal (order/whitespace
  ignored); serialized keys are snake_case (`txn_id`, `created_at`, `buyer_id`,
  `tracking_number`, `carrier_events`), never camelCase. Traces: AC-1, AC-2.
- **TC-AND-218-05** — Type: unit (JVM). Target: JVM unit. Precondition: summary
  fixture variants each missing one required key, and a detail fixture missing
  `buyer_id`/`version`. Steps: `fromJson` each. Expected: each throws
  `JsonDataException` (missing `txn_id`/`status`/`amount`/`currency`/`created_at`/
  `updated_at`/`buyer_id`/`version`). Traces: AC-5.
- **TC-AND-218-06** — Type: unit (JVM). Target: JVM unit. Precondition: summary
  fixture with extra keys (`server_time`, `experimental_flag`) and
  `status:"partially_refunded"`. Steps: `fromJson`. Expected: decodes without error;
  `status` kept as the raw string. Traces: AC-5.
- **TC-AND-218-07** — Type: unit (JVM). Target: JVM unit. Precondition: fixtures
  with `amount: 45.97` and a high-precision `amount: 19.995`. Steps: `fromJson`,
  round-trip. Expected: `amount` is `BigDecimal` equal by `compareTo`/string value
  with no float drift; the value type is never `Double`. Traces: AC-6.
- **TC-AND-218-08** — Type: unit (JVM). Target: JVM unit. Precondition: a list
  response `[]`; a detail with no `shipping`; a shipping object with no
  `carrier_events`. Steps: `fromJson`. Expected: list → empty `List`; `shipping` →
  `null`; `carrierEvents` → `emptyList()`. Traces: AC-5.
- **TC-AND-218-09** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Precondition: `MockWebServer` enqueues `404` (FastAPI `detail` string body) for
  `getTransaction`. Steps: call `getTransaction("nope")`. Expected: throws
  `retrofit2.HttpException` with `code()==404`; body preserved for AND-015; nothing
  swallowed. Traces: AC-7.
- **TC-AND-218-10** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Precondition: enqueue `401` for `listTransactions` (bare-Retrofit harness, no
  AND-013 `Authenticator`). Steps: call `listTransactions()`. Expected:
  `HttpException(401)` surfaces (documents this layer adds no auth handling).
  Traces: AC-7.
- **TC-AND-218-11** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Precondition: enqueue `422` with an `HTTPValidationError` body
  (`detail:[{msg,type,loc}]`) for `searchTransactions` with empty `q`. Steps: call
  `searchTransactions(q="")`. Expected: `HttpException(422)`; raw validation body
  intact for AND-015 to map. Traces: AC-5, AC-7.
- **TC-AND-218-12** — Type: integration / instrumented (Hilt). Target: headless
  emulator AVD `test35` (`@HiltAndroidTest`). Precondition: app Hilt graph with
  AND-010 `NetworkModule` + `PurchasesApiModule`. Steps: inject `PurchasesApi`
  twice. Expected: non-null, `@Singleton` (same instance both times), built on the
  shared `Retrofit`; no second `OkHttpClient`/`Retrofit`/`Moshi`; no per-method
  cookie/CSRF headers declared. Traces: AC-8.
- **TC-AND-218-13** — Type: security/permission (instrumented). Target: headless
  emulator AVD `test35`. Precondition: a recording OkHttp interceptor on the shared
  client; an authenticated session established by AND-027. Steps: call all three
  endpoints; inspect outbound requests. Expected: each carries the globally
  attached auth (cookies / `Authorization` / `X-CSRF-Token`) from the shared
  client; `PurchasesApi` declares no manual `Cookie`/`Authorization`/`X-CSRF-Token`
  header and never sends a `user_id` query param (no IDOR surface). Traces: AC-8.
- **TC-AND-218-14** — Type: instrumented / e2e (real network). Target: **physical
  device SM-A156U (MUST run on device)** — exercises genuine cellular/Wi-Fi loss
  and the flaky dev host, which the emulator cannot faithfully reproduce.
  Precondition: app pointed at the dev host; authenticated session. Steps: (a) with
  connectivity, call `listTransactions()` and confirm a decoded list; (b) toggle
  airplane mode and repeat. Expected: (a) success; (b) the call surfaces a
  transport failure (`IOException`/`UnknownHostException`/timeout) propagated
  unchanged (AND-009/AND-016 bounded backoff applies for these idempotent GETs);
  nothing is swallowed or silently retried by this layer. Traces: AC-7.

### Coverage matrix
- **AC-1** (DTOs exist, immutable, codegen): TC-04
- **AC-2** (purchases map / round-trip tested): TC-04
- **AC-3** (three operations declared, compile): TC-01, TC-02, TC-03
- **AC-4** (verb/path/query correct): TC-01, TC-02, TC-03
- **AC-5** (required-field failure; unknown keys/status; defaults): TC-05, TC-06,
  TC-08, TC-11
- **AC-6** (money lossless `BigDecimal`): TC-07
- **AC-7** (non-2xx surfaces as `HttpException`, not swallowed): TC-09, TC-10,
  TC-11, TC-14
- **AC-8** (Hilt `@Singleton` on shared `Retrofit`; no new client; no manual
  headers): TC-12, TC-13
- **AC-9** (CI green / clean build): covered implicitly by all JVM/instrumented
  cases passing in CI (no dedicated case).
