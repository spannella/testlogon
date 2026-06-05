---
id: AND-218
title: Purchases API
milestone: M5
epic: E30
priority: P0
size: M
status: draft
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
(`frontend/src/api/endpoints/purchases.ts`); this ticket ports its three
operations — list, detail, search — to a native Retrofit `PurchasesApi` plus the
DTOs those endpoints (de)serialize. The single backlog acceptance criterion is:
*Purchases map (tested).* This ticket therefore owns (a) immutable Kotlin DTOs in
`core-model` modeling the documented purchase JSON exactly (snake_case →
camelCase via Moshi), (b) the Retrofit `PurchasesApi` interface in `core-network`
exposing list/detail/search with correct verbs/paths/query params, and (c) the
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
  `frontend/src/api/endpoints/purchases.ts` (the ported module) and shared types
  in `frontend/src/api/types.ts` (`Purchase`, `Order`, line-item, money types).
  Mirror those wire names exactly; do **not** invent camelCase wire keys — the
  backend is snake_case.

## 3. Functional Requirements

FR-1. Define response **DTOs** in `core-model.purchases` covering: a purchase
summary (history-list row), a full purchase/order detail, an order line-item, a
money/price value, a carrier/tracking reference (for AND-220), a paged history
envelope, and a paged search-result envelope.

FR-2. Define a single Retrofit interface **`PurchasesApi`** in
`core-network.purchases` exposing exactly three operations matching the web
`purchases.ts`: `listPurchases` (history, paged), `getPurchase` (detail), and
`searchPurchases` (full-text over history, paged).

FR-3. All `PurchasesApi` methods are `suspend` functions returning the typed DTO
body. All are HTTP **GET** (purchase history is read-only at this layer; cart /
checkout mutation is AND-210/AND-213). Paths are relative with **no leading
slash** (AND-010 convention) so they append to the normalized base URL.

FR-4. Paging is offset/limit (or cursor) via `@Query` params: `listPurchases` and
`searchPurchases` accept `page`/`limit` (or `cursor`/`limit`) and return a paged
envelope carrying `items`, `total`, and a next-page indicator. The exact param
names and envelope keys are confirmed against `/openapi.json` / web reference
before coding (Q-1) and modeled in per-type envelopes.

FR-5. Every DTO field maps to the backend's snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. Unknown/extra JSON keys are tolerated
(Moshi codegen default — additive backend evolution must not throw).

FR-6. Required vs optional fidelity: required fields are non-null and their
absence surfaces as a `JsonDataException` (fail fast); optional fields are
Kotlin-nullable with a `null`/empty default per `/openapi.json` `required` arrays.

FR-7. Money is modeled losslessly: the minor-unit integer amount plus the
ISO-4217 currency code are preserved exactly (no float rounding). Order totals,
per-item prices, tax, and shipping all use the same `MoneyDto`. A backend-supplied
formatted display string, if present, is kept verbatim as a `String`.

FR-8. Timestamps (`purchased_at`, `updated_at`) are kept as ISO-8601 `String`s;
parsing to `Instant`/`LocalDateTime` is deferred to the domain-mapping layer
(AND-219 consumers), consistent with AND-026 §6. Order `status` is kept as a raw
`String` (e.g. `"paid"`, `"shipped"`, `"refunded"`); mapping to a typed enum is a
domain-layer concern downstream.

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

```kotlin
package com.testlogon.android.core.model.purchases

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/** Money kept lossless: minor units + ISO-4217 code; display string verbatim. */
@JsonClass(generateAdapter = true)
data class MoneyDto(
    @Json(name = "amount_minor") val amountMinor: Long,
    val currency: String,                          // e.g. "USD"
    @Json(name = "display") val display: String? = null, // e.g. "$19.99"
)

/** One line on an order/purchase. */
@JsonClass(generateAdapter = true)
data class PurchaseItemDto(
    val id: String,
    @Json(name = "product_id") val productId: String? = null,
    val name: String,
    val sku: String? = null,
    val quantity: Int = 1,
    @Json(name = "unit_price") val unitPrice: MoneyDto,
    @Json(name = "line_total") val lineTotal: MoneyDto? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
)

/** Carrier/tracking reference (consumed by AND-220 order detail + tracking). */
@JsonClass(generateAdapter = true)
data class TrackingDto(
    val carrier: String? = null,                   // e.g. "ups"
    @Json(name = "tracking_number") val trackingNumber: String? = null,
    @Json(name = "tracking_url") val trackingUrl: String? = null,
    val status: String? = null,                    // e.g. "in_transit"
    @Json(name = "estimated_delivery") val estimatedDelivery: String? = null,
)

/** History-row / list-card shape (also used in search results). */
@JsonClass(generateAdapter = true)
data class PurchaseSummaryDto(
    val id: String,
    @Json(name = "order_number") val orderNumber: String? = null,
    val status: String,                            // "paid" | "shipped" | …
    val total: MoneyDto,
    @Json(name = "item_count") val itemCount: Int? = null,
    @Json(name = "purchased_at") val purchasedAt: String,   // ISO-8601
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
)

/** Full purchase/order detail (AND-220 consumer). */
@JsonClass(generateAdapter = true)
data class PurchaseDetailDto(
    val id: String,
    @Json(name = "order_number") val orderNumber: String? = null,
    val status: String,
    val items: List<PurchaseItemDto> = emptyList(),
    val subtotal: MoneyDto? = null,
    val tax: MoneyDto? = null,
    val shipping: MoneyDto? = null,
    val total: MoneyDto,
    @Json(name = "payment_method") val paymentMethod: String? = null,
    @Json(name = "shipping_address") val shippingAddress: String? = null,
    val tracking: TrackingDto? = null,
    @Json(name = "purchased_at") val purchasedAt: String,
    @Json(name = "updated_at") val updatedAt: String? = null,
)

/** Paged envelope for history list. */
@JsonClass(generateAdapter = true)
data class PurchasePageDto(
    val items: List<PurchaseSummaryDto> = emptyList(),
    val total: Int = 0,
    val page: Int = 1,
    val limit: Int = DEFAULT_PAGE_LIMIT,
    @Json(name = "has_more") val hasMore: Boolean = false,
    @Json(name = "next_cursor") val nextCursor: String? = null,
) {
    companion object { const val DEFAULT_PAGE_LIMIT = 20 }
}

/** Paged envelope for history search. */
@JsonClass(generateAdapter = true)
data class PurchaseSearchResultDto(
    val query: String? = null,
    val items: List<PurchaseSummaryDto> = emptyList(),
    val total: Int = 0,
    val page: Int = 1,
    val limit: Int = 20,
    @Json(name = "has_more") val hasMore: Boolean = false,
)
```

Design notes:
- `PurchasePageDto` and `PurchaseSearchResultDto` are kept as concrete envelopes
  (rather than a generic `Paged<PurchaseSummaryDto>`) because Moshi codegen on
  generic types requires a parameterized `Types.newParameterizedType(...)` adapter
  lookup; concrete envelopes keep codegen total and the test surface simple. If
  `/openapi.json` shows identical envelopes for both, `PurchaseSearchResultDto` may
  be collapsed into `PurchasePageDto` during implementation (Q-2).
- `status` is a raw `String` not an enum: the wire vocabulary is owned by the
  backend and mapped to a sealed/`enum` type in the AND-219/AND-221 domain layer;
  an unknown status string must never throw at the DTO layer.
- `TrackingDto` is modeled here (even though tracking UI is AND-220) so that
  `getPurchase` decodes the complete detail payload in one round trip and AND-220
  needs no DTO additions.
- All timestamps are `String` (ISO-8601). No `Date`/`Instant` adapter is added in
  this ticket.

### 4.2 `PurchasesApi` interface (`core-network.purchases`)

```kotlin
package com.testlogon.android.core.network.purchases

import com.testlogon.android.core.model.purchases.PurchaseDetailDto
import com.testlogon.android.core.model.purchases.PurchasePageDto
import com.testlogon.android.core.model.purchases.PurchaseSearchResultDto
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

interface PurchasesApi {

    /** Paged purchase history for the current session user. Idempotent GET. */
    @GET("purchases")
    suspend fun listPurchases(
        @Query("page") page: Int = 1,
        @Query("limit") limit: Int = 20,
    ): PurchasePageDto

    /** Full purchase/order detail by id. */
    @GET("purchases/{purchaseId}")
    suspend fun getPurchase(@Path("purchaseId") purchaseId: String): PurchaseDetailDto

    /** Full-text search over the user's purchase history (AND-219). */
    @GET("purchases/search")
    suspend fun searchPurchases(
        @Query("q") query: String,
        @Query("page") page: Int = 1,
        @Query("limit") limit: Int = 20,
    ): PurchaseSearchResultDto
}
```

Path/verb conventions: relative paths, no leading slash, resolve against base
`http://18.222.237.167:8000/` → e.g. `…/purchases/{id}`. The concrete `purchases/…`
prefix is confirmed against `/openapi.json` and `frontend/src/api/endpoints/purchases.ts`
before coding (Q-1) — the live route family may be `orders/…` (purchase ≈ order);
if so, every annotation path and test assertion is updated consistently. Routing
order: `purchases/search` is a literal path declared alongside `purchases/{purchaseId}`;
since Retrofit only constructs the request URL (server-side routing decides the
match), no annotation ordering issue arises client-side, but the literal `search`
path must be confirmed to not be shadowed server-side by the `{purchaseId}` route.

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

Base path (`dev`): `http://18.222.237.167:8000/`. All responses are JSON; all
endpoints are idempotent GETs requiring the session cookie (set by the auth flow)
and tolerating the AND-013 401-refresh-once behavior. Endpoints are scoped to the
current session user server-side (no `user_id` query param).

### GET `purchases?page=1&limit=20`
Response `200`:
```json
{
  "items": [
    {
      "id": "pur_001",
      "order_number": "TL-100245",
      "status": "shipped",
      "total": { "amount_minor": 4597, "currency": "USD", "display": "$45.97" },
      "item_count": 3,
      "purchased_at": "2026-05-21T14:03:11Z",
      "thumbnail_url": "http://.../order_001.png"
    }
  ],
  "total": 17, "page": 1, "limit": 20, "has_more": false, "next_cursor": null
}
```

### GET `purchases/{purchaseId}`
Response `200`:
```json
{
  "id": "pur_001",
  "order_number": "TL-100245",
  "status": "shipped",
  "items": [
    {
      "id": "li_1", "product_id": "itm_001", "name": "Logo Tee", "sku": "TEE-001",
      "quantity": 2,
      "unit_price": { "amount_minor": 1999, "currency": "USD", "display": "$19.99" },
      "line_total": { "amount_minor": 3998, "currency": "USD" },
      "image_url": "http://.../tee.png"
    }
  ],
  "subtotal": { "amount_minor": 3998, "currency": "USD" },
  "tax": { "amount_minor": 300, "currency": "USD" },
  "shipping": { "amount_minor": 299, "currency": "USD" },
  "total": { "amount_minor": 4597, "currency": "USD", "display": "$45.97" },
  "payment_method": "visa ****4242",
  "shipping_address": "123 Main St, Columbus OH 43215",
  "tracking": {
    "carrier": "ups", "tracking_number": "1Z999AA10123456784",
    "tracking_url": "https://www.ups.com/track?tracknum=1Z999AA10123456784",
    "status": "in_transit", "estimated_delivery": "2026-05-25"
  },
  "purchased_at": "2026-05-21T14:03:11Z",
  "updated_at": "2026-05-22T09:10:00Z"
}
```
`404` if the purchase id is unknown or not owned by the session user.

### GET `purchases/search?q=tee&page=1&limit=20`
Response `200`:
```json
{
  "query": "tee", "total": 1, "page": 1, "limit": 20, "has_more": false,
  "items": [
    {
      "id": "pur_001", "order_number": "TL-100245", "status": "shipped",
      "total": { "amount_minor": 4597, "currency": "USD" },
      "item_count": 3, "purchased_at": "2026-05-21T14:03:11Z"
    }
  ]
}
```

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg,type,loc}] | {code,...}`). Mapping to a typed `ApiError` is owned
by **AND-015**; this ticket lets non-2xx surface as `retrofit2.HttpException` so
AND-015/AND-018 can map it. Exact path prefix (`purchases` vs `orders`),
pagination param names (`page`/`limit` vs `offset`/`cursor`), and `required`
arrays are confirmed against `/openapi.json` / `purchases.ts` before coding (Q-1).

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
- **Session state** rides entirely on cookies persisted by the AND-011 jar;
  `PurchasesApi` neither reads nor writes cookies. CSRF (`ui_csrf` →
  `X-CSRF-Token`) is irrelevant to these GETs (CSRF applies to mutating verbs) but
  is handled globally regardless.
- **Pagination state** (current page/cursor, accumulation) is owned by the Paging 3
  layer downstream (AND-221); the DTOs only carry per-response page metadata
  (`page`, `limit`, `total`, `has_more`, `next_cursor`).
- **Serialization** uses the shared Moshi codegen adapters via the AND-010
  converter; unknown keys are ignored, absent optional fields fall back to Kotlin
  defaults. ISO-4217 currency and minor-unit amounts are preserved exactly (`Long`,
  never `Double`). Timestamps remain `String`.
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
- **Deserialization robustness (DTO layer):**
  - Missing **required** field (e.g. `id`, `status`, `total`, `purchased_at`,
    `unit_price`) → `JsonDataException` (desired fail-fast; asserted in tests).
  - Unknown/extra JSON keys → skipped silently (additive backend evolution safe).
  - `null` for a nullable field → tolerated; `null` for a non-null field →
    `JsonDataException`.
  - Empty arrays/objects → modeled via `emptyList()` defaults so a purchase with no
    line items (edge case) or an empty history page never produces nulls.
  - Unknown `status` string (e.g. `"partially_refunded"`) → tolerated as a raw
    `String`; never throws (mapped downstream).
- **Money safety:** every `amount_minor` is `Long`; a non-integer/overflowing value
  surfaces as `JsonDataException` rather than silent float truncation.
- This ticket maps **no** errors itself and applies **no** retry policy — those are
  AND-015 (`ApiError`), AND-018 (`ApiResult`), and AND-009/AND-016 (client retry).

## 8. Security & Privacy

- **Auth:** purchase endpoints require the cookie-based session; the shared client
  attaches cookies/CSRF transparently. `PurchasesApi` declares no manual
  `Cookie`/`Authorization`/`X-CSRF-Token` headers. Endpoints are user-scoped
  server-side; the client never sends a `user_id` (no IDOR surface from this
  layer).
- **Transport:** on `dev` these ride plaintext HTTP (`http://18.222.237.167:8000`)
  — a known dev-only risk permitted by the scoped cleartext config (AND-006);
  `staging`/`prod` are HTTPS-only. Note that purchase payloads carry PII/financial
  hints (`shipping_address`, masked `payment_method`, order totals), so the
  cleartext exposure is acknowledged as dev-only and must not reach prod.
- **Sensitive payloads / logging:** purchase DTOs contain semi-sensitive data
  (`shipping_address`, `payment_method` mask, `tracking_number`). The AND-009
  HTTP logger is **debug-build only**; nonetheless, because these bodies are not
  credentials, body logging in debug is acceptable, but `payment_method` must
  already be backend-masked (the client never receives a full PAN). No DTO here
  carries passwords, tokens, CVV, or full card numbers, so no custom `toString()`
  redaction is required; if the backend ever returns an unmasked field, AND-052's
  redaction policy applies and a redacting adapter is added (flagged in Q-3).
- **No token storage:** auth is cookie-based; this layer holds no bearer tokens.
- **Injection safety:** the `q` search term is passed as a Retrofit `@Query`
  (URL-encoded by OkHttp); `purchaseId` is passed as a `@Path` (path-segment
  encoded). No manual string concatenation into the URL.
- **External tracking link:** `tracking_url` is opaque, carrier-supplied data; this
  layer only deserializes it. The consumer (AND-220) is responsible for validating
  the scheme (https) before opening it in a browser/Custom Tab.

## 9. Accessibility & i18n

Not applicable as a UI surface — this is a headless transport + DTO layer with no
Compose UI and no `strings.xml` entries. Three pass-through constraints are
recorded for downstream consumers (AND-219/AND-220/AND-221):
- `MoneyDto` exposes `amountMinor` + `currency` (not just a pre-formatted
  `display`) so the UI/domain layer can apply locale-aware currency formatting
  (`NumberFormat.getCurrencyInstance(locale)`); the backend `display` string is a
  fallback, not the canonical render.
- `purchasedAt`/`updatedAt`/`estimatedDelivery` are raw ISO-8601 strings so the UI
  can format dates per device locale and time zone (`DateTimeFormatter` /
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
- **Snake_case mapping.** Serialized `PurchaseSummaryDto` contains `"order_number"`,
  `"purchased_at"`, `"item_count"`, never their camelCase forms; `PurchaseItemDto`
  contains `"unit_price"`/`"line_total"`/`"product_id"`.
- **Required-field failure.** Removing `id`/`status`/`total`/`purchased_at` from a
  `PurchaseSummaryDto` sample (or `amount_minor` from `MoneyDto`) causes `fromJson`
  to throw `JsonDataException`.
- **Unknown-key tolerance.** A sample with an extra `"server_time"` /
  `"experimental_flag"` key deserializes without error.
- **Unknown-status tolerance.** `status: "partially_refunded"` deserializes to the
  raw string without throwing.
- **Money fidelity.** `amount_minor: 4597` deserializes to `Long` `4597` and
  survives round-trip with no float drift; nested `MoneyDto` (unit_price,
  line_total, tax, shipping, total) all preserved.
- **Nested decoding.** `PurchaseDetailDto` decodes its `items` list, `tracking`
  object, and all money sub-fields.
- **Defaults.** A history page with `"items": []` yields an empty list, not null;
  an order with no `tracking` yields `null`; absent `next_cursor` yields `null`.

### 11.2 MockWebServer endpoint tests (`core-network`)
Harness mirrors the AND-027 pattern:
```kotlin
private fun api(server: MockWebServer): PurchasesApi {
    val moshi = Moshi.Builder().build() // mirrors provideMoshi(): codegen adapters
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(PurchasesApi::class.java)
}
```

- **T-1 `listPurchases`** — asserts `GET /purchases?page=2&limit=10` (paging query
  present and correct), decodes `PurchasePageDto` including `total`/`has_more`.
  ```kotlin
  @Test fun listPurchases_sendsPagingQueryAndDecodes() = runTest {
      val server = MockWebServer().apply {
          enqueue(MockResponse().setBody(loadFixture("purchases/purchase_page.json"))); start()
      }
      val page = api(server).listPurchases(page = 2, limit = 10)
      val req = server.takeRequest()
      assertEquals("GET", req.method)
      assertEquals("/purchases?page=2&limit=10", req.path)
      assertEquals(17, page.total)
      assertEquals("shipped", page.items.first().status)
      assertEquals(4597L, page.items.first().total.amountMinor)
      server.shutdown()
  }
  ```
- **T-2 `getPurchase`** — asserts `GET /purchases/pur_001` (path param
  interpolated), decodes `PurchaseDetailDto` including nested `items`, money
  sub-fields, and `tracking`.
- **T-3 `searchPurchases`** — asserts `GET /purchases/search?q=tee&page=1&limit=20`
  (`q` URL-encoded; a query with a space, e.g. `"logo tee"`, encodes to `logo%20tee`),
  decodes `PurchaseSearchResultDto`.
- **T-4 error propagation** — a `404` from `getPurchase` throws
  `retrofit2.HttpException` with `code() == 404` (confirms non-2xx not swallowed,
  leaving room for AND-015).
- **T-5 `401` not swallowed** — a `401` from `listPurchases` surfaces as
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
- **AND-219** (Purchase history + search) — consumes `listPurchases`/`searchPurchases`
  via a repository + Paging 3, renders the history list and search.
- **AND-220** (Order detail + tracking) — consumes `getPurchase`; uses
  `PurchaseDetailDto.tracking`/`items`/totals. (AND-220 also depends on AND-219.)
- **AND-221** (Purchases ViewModel) — wraps the repository in `ApiResult`/`UiState`,
  owns paging state.
- **AND-222** (Purchases tests) — repo + UI tests over the above; transitively
  depends on this surface.

**Sequencing within the ticket:** (1) confirm path prefix, pagination param names,
money representation, and `required` arrays against `/openapi.json` +
`frontend/src/api/endpoints/purchases.ts` (Q-1..Q-3); (2) define DTOs in
`core-model.purchases` + commit fixtures; (3) write `PurchasesDtoRoundTripTest`;
(4) declare `PurchasesApi`; (5) add `PurchasesApiModule`; (6) write MockWebServer
tests T-1..T-6.

## 13. Risks & Open Questions

- **R-1 Path-prefix ambiguity.** Endpoints may be under `orders/…` rather than
  `purchases/…` (purchase ≈ order in the domain). Mitigation: confirm via
  `/openapi.json` + `purchases.ts`; update all annotation paths and test assertions
  consistently. Guarded by T-1..T-3.
- **R-2 Pagination contract.** `page`/`limit` vs `offset`/`limit` vs
  `cursor`/`limit`, and bare-array vs enveloped responses, are unconfirmed.
  Mitigation: match the live contract; if cursor-based, `listPurchases`/`searchPurchases`
  take `@Query("cursor") cursor: String?` and the envelope exposes `next_cursor`
  (already modeled). Guarded by T-1/T-3.
- **R-3 Summary vs detail divergence.** The history-row shape may differ from the
  detail shape. Modeled as separate `PurchaseSummaryDto`/`PurchaseDetailDto`; if
  the search/list rows differ from the history rows, the search envelope's item type
  is reconfirmed (assumed identical here).
- **R-4 Money representation.** Backend may send a decimal string (`"45.97"`) or
  float rather than `amount_minor`. Mitigation: confirm via OpenAPI; if decimal
  string, `MoneyDto` keeps `amount` as `String` and minor-unit parsing moves to the
  domain layer (no float). Guarded by the money-fidelity test.
- **R-5 Search route shadowing.** Server-side routing may match `purchases/search`
  against the `purchases/{purchaseId}` route. Mitigation: confirm the literal
  `search` endpoint exists distinctly in `/openapi.json`; if the contract instead
  uses `purchases?q=…`, fold search into `listPurchases` with an optional
  `@Query("q")` and drop `searchPurchases` (update T-3).
- **R-6 Tracking shape.** `tracking` may be a list (multi-package shipments) rather
  than a single object. Mitigation: confirm; switch to `List<TrackingDto>` if so
  (AND-220 consumer adjusts).
- **Q-1** Exact path prefix (`purchases` vs `orders`) + pagination param names?
  *Proposed:* `purchases/…` with `page`/`limit`; confirm against `/openapi.json` /
  `purchases.ts` before coding.
- **Q-2** Is search's envelope identical to history-list's? *Proposed:* keep both;
  collapse `PurchaseSearchResultDto` into `PurchasePageDto` if identical.
- **Q-3** Does any DTO field arrive unmasked/sensitive (e.g. full `payment_method`)?
  *Proposed:* assume backend-masked; if not, add an AND-052-style redacting adapter.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Purchase DTOs (`MoneyDto`, `PurchaseItemDto`, `TrackingDto`,
  `PurchaseSummaryDto`, `PurchaseDetailDto`, `PurchasePageDto`,
  `PurchaseSearchResultDto`) exist in `com.testlogon.android.core.model.purchases`
  as immutable `@JsonClass(generateAdapter=true)` data classes.
- **AC-2 (backlog).** Purchases **map (tested)**: every documented payload in
  Sections 4–5 (de)serializes the documented JSON exactly, proven by
  `PurchasesDtoRoundTripTest` against committed fixtures (parsed-tree equality,
  snake_case keys verified, nested money/tracking decoded).
- **AC-3.** `PurchasesApi` declares all three operations (`listPurchases`,
  `getPurchase`, `searchPurchases`); the module compiles against the purchases DTOs.
- **AC-4.** Each endpoint is callable and its **verb + resolved path + query
  params** match Section 5, asserted with MockWebServer (T-1..T-3), including the
  `listPurchases` paging query, `getPurchase` path-param interpolation, and
  URL-encoded `searchPurchases` `q`.
- **AC-5.** Required-field absence (e.g. `id`, `status`, `total`, `purchased_at`,
  `amount_minor`) throws `JsonDataException`; unknown JSON keys and unknown `status`
  strings are tolerated; empty collections default to `emptyList()` and absent
  optional objects (`tracking`, `next_cursor`) default to `null`.
- **AC-6.** Money is lossless: every `amount_minor` decodes to `Long` and survives
  round-trip with no float drift.
- **AC-7.** Non-2xx (e.g. `404` from `getPurchase`, `401` from `listPurchases`)
  surfaces as `HttpException` and is not swallowed (T-4/T-5).
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
  `/openapi.json` and `frontend/src/api/endpoints/purchases.ts`, and the interface
  paths/query params and DTO shapes reflect the confirmed contract.
- `PurchasesDtoRoundTripTest` (with committed fixtures under
  `core-model/src/test/resources/purchases/`) and the MockWebServer tests T-1..T-6
  are implemented and green in CI; ≥90% line coverage on the new surface; every
  endpoint has a verb/path/query assertion and every DTO has a round-trip test.
- No second `OkHttpClient`/`Retrofit`/`Moshi`; no manual cookie/CSRF/auth headers
  in the interface; money modeled with integer minor units (no `Double`);
  timestamps kept as ISO-8601 `String`.
- `./gradlew :core-model:testDebugUnitTest :core-network:assemble
  :core-network:testDebugUnitTest` passes locally and in CI with no new
  lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; AND-219/AND-220/AND-221/AND-222 are
  unblocked (the purchases repository, history/detail/search screens, ViewModel,
  and tests can compile against these types and endpoints).
- A one-line note in the `core-network` README (owned by AND-007) records the
  `PurchasesApi` path/verb/query map and the delegation of cookie/CSRF/refresh/retry
  to AND-011/AND-012/AND-013/AND-016.
