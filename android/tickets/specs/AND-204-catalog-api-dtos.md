---
id: AND-204
title: Catalog API + DTOs
milestone: M5
epic: E28
priority: P0
size: M
depends_on: [AND-027]
blocks: [AND-205, AND-206, AND-207, AND-208]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-204 — Catalog API + DTOs

## 1. Overview & Goal

This ticket delivers the typed HTTP seam and Moshi-backed data-transfer objects
(DTOs) for the TestLogon **catalog / shop** surface: browsing categories, listing
and paging items within a category, fetching a single item (product) detail, and
full-text catalog search. It produces no UI, no repositories, no ViewModels — it
is the transport-and-serialization foundation that the catalog feature
(`feature-catalog`, AND-205/206/207) and the catalog ViewModels (AND-208) build
on.

Scope, verbatim from the backlog: *Catalog/shop endpoints + DTOs (categories,
items, search).* The single acceptance criterion is: *Catalog + item payloads map
(tested).* This ticket owns (a) the immutable Kotlin DTOs in `core-model` that
model the documented catalog JSON exactly (snake_case → camelCase via Moshi), (b)
the Retrofit `CatalogApi` interface in `core-network` that exposes the catalog
endpoints with the correct verbs/paths/query params, and (c) the Hilt provider and
MockWebServer/round-trip test suites that prove every payload (de)serializes and
every endpoint is callable.

This ticket deliberately does **not** own: cookie jar (AND-011), CSRF injection
(AND-012), the 401-refresh `Authenticator` (AND-013), `ApiResult<T>` wrapping
(AND-018), FastAPI `detail` error mapping (AND-015), bounded-backoff retry
(AND-016), Paging 3 `PagingSource`/`Pager` wiring (owned by AND-205/AND-208), or
any Room cache / domain mapping (owned by `core-data` in the catalog feature).
Those attach to the shared `OkHttpClient`/`Retrofit` or live in higher layers and
take effect for `CatalogApi` calls without changes here.

The deliverable: compiling DTOs + a compiling `CatalogApi` + its Hilt provider + a
green test suite asserting (de)serialization fidelity and each endpoint's
verb/path/query/decoding.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. DTOs land in module **`core-model`** under package
  `com.testlogon.android.core.model.catalog`. The `CatalogApi` interface and its
  Hilt module land in **`core-network`** under
  `com.testlogon.android.core.network.catalog`.
- **Canonical package:** `com.testlogon.android` everywhere a package appears.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines, JDK 17,
  minSdk 24 / compileSdk 35, AGP 8.7.3 / Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. `CatalogApi` lives in
  `core-network`, consumes DTOs from `core-model`, is consumed by `core-data`
  repositories and `feature-catalog`. No `feature-*`/`app` symbols leak into
  `core-network`/`core-model`.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** the backlog
  pins AND-204 to AND-027. Catalog endpoints are served behind the cookie-based
  session; this ticket reuses the same shared `OkHttpClient`/`Retrofit` (cookie
  jar, CSRF, 401-refresh) established by the auth-network stack, so AND-027's
  transport conventions (relative paths, no leading slash, suspend methods,
  Hilt-provided service on the shared `Retrofit`) are the template followed here.
- **Transitive upstream:** AND-010 (Retrofit + Moshi), AND-009 (shared
  `OkHttpClient` + timeouts/redacting logger), AND-006 (`BuildConfig.API_BASE_URL`,
  dev → `http://18.222.237.167:8000/`), AND-003/AND-004 (module structure, Hilt
  baseline).
- **Backend:** FastAPI + DynamoDB; dev host is plaintext HTTP and unreliable
  (~20s timeouts; bounded backoff for idempotent GETs owned by AND-009/AND-016).
  All catalog endpoints in this ticket are **idempotent GETs**. OpenAPI at
  `/openapi.json` is authoritative for shapes and `required` arrays.
- **Web reference (authoritative for field names / paths):** the catalog endpoint
  layer is in `frontend/src/api/endpoints/cart.ts` (NOT a `catalog.ts`/`shop.ts`
  file — catalog calls live alongside cart calls), and shared types in
  `frontend/src/api/types.ts`. **CORRECTED:** the web React *route* `shop/...` is a
  client-side route, not the API path. The actual REST prefix is **`ui/catalog/`**
  for every endpoint (verified: `cart.ts: getCategories/getCategoryItems/
  searchCatalogItems` call `/ui/catalog/categories`, `/ui/catalog/categories/
  {id}/items`, `/ui/catalog/items/search`; OpenAPI index lines 1308/1311/1321).
  Mirror the snake_case wire keys from `types.ts`/OpenAPI — do **not** invent
  camelCase wire keys; the backend is snake_case.

## 3. Functional Requirements

FR-1. Define response **DTOs** in `core-model.catalog` covering: a category
(`CatalogCategoryDto`), a paged category list (`CatalogCategoryListDto`), a catalog
item (`CatalogItemDto` — **one shape serves both list and detail**, verified), and
a paged item list / search envelope (`CatalogItemListDto`). **CORRECTED:** there is
no separate item-summary vs item-detail shape (both are `CatalogItemOut`), no
nested `MediaAssetDto` (media is a flat `image_urls: List<String>`), and no nested
money/`PriceDto` value object (price is two flat sibling fields `price_cents` +
`currency` on the item).

FR-2. Define a single Retrofit interface **`CatalogApi`** in `core-network.catalog`
exposing exactly: `listCategories`, `listItems` (by category, paged), and
`searchCatalog` (full-text, paged). **CORRECTED:** the originally-proposed
`getCategory` (single category) and `getItem` (single item detail) endpoints **do
not exist** in the backend — there is no `GET /ui/catalog/categories/{id}` and no
`GET /ui/catalog/items/{id}`. The web client obtains a single item by *filtering
the category-items list* client-side (`ProductDetail.tsx`:
`items.find((i) => i.item_id === itemId)`), and the list payload carries the full
item shape (`CatalogItemOut` is used for both list and detail). Product detail
(AND-206) and category metadata (AND-205/206) must therefore be derived from
`listItems`/`listCategories` results downstream, not from dedicated detail GETs.

FR-3. All `CatalogApi` methods are `suspend` functions returning the typed DTO
body. All are HTTP **GET** (catalog is read-only at this layer; cart mutation is
AND-210). Paths are relative with **no leading slash** (AND-010 convention) so
they append to the normalized base URL — i.e. `ui/catalog/categories`, not
`/ui/catalog/categories`.

FR-4. **CORRECTED — paging is token/cursor-based, not offset/limit.** Verified
against OpenAPI and `cart.ts`: `listCategories`, `listItems`, and `searchCatalog`
accept `@Query("page_size") pageSize` and `@Query("next_token") nextToken`
(nullable). The paged envelope carries exactly `{ items, next_token }` — there is
**no** `total`, `page`, `limit`, or `has_more` field. Both `CatalogCategoryListOut`
and `CatalogItemListOut` have this identical 2-field shape (only `items` is
`required`; `next_token` is nullable). The web client's `searchCatalogItems` does
not even send `next_token`. End-of-pages is signalled by `next_token == null`.

FR-5. Every DTO field maps to the backend's snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. Unknown/extra JSON keys are tolerated
(Moshi codegen default — additive backend evolution must not throw).

FR-6. Required vs optional fidelity: required fields are non-null and their
absence surfaces as a `JsonDataException` (fail fast); optional fields are
Kotlin-nullable with a `null`/empty default per `/openapi.json` `required` arrays.

FR-7. Prices/money are modeled losslessly: **CORRECTED** — the wire fields are flat
on the item, `price_cents` (integer minor units) and `currency` (ISO-4217 string,
default `"USD"`), preserved exactly (no float rounding). There is **no** backend
`display` string and **no** nested price object, so no `display` field is modeled.
`price_cents` is `Long` to avoid any float drift; locale formatting is downstream
(`NumberFormat.getCurrencyInstance`).

FR-8. All DTOs are immutable `data class`es; collections are exposed as read-only
`List<T>` with safe defaults (`emptyList()`).

FR-9. A Hilt `@Provides @Singleton fun provideCatalogApi(retrofit: Retrofit):
CatalogApi` constructs the service from the shared `Retrofit` (AND-010). No new
`Retrofit`/`OkHttpClient` is created; no per-method cookie/CSRF headers are
declared.

FR-10. Captured JSON sample fixtures are committed under `core-model` test
resources for each payload and drive round-trip tests.

## 4. Technical Design

DTOs land in
`core-model/src/main/kotlin/com/testlogon/android/core/model/catalog/`. The
`CatalogApi` and `CatalogApiModule` land in
`core-network/src/main/kotlin/com/testlogon/android/core/network/catalog/`.

### 4.1 DTOs (`core-model.catalog`)

All DTOs are `@JsonClass(generateAdapter = true)` so Moshi codegen (KSP) emits
adapters at build time (no reflection adapter added for these types).

**CORRECTED — the block below now mirrors the verified `CatalogCategoryOut`,
`CatalogItemOut`, `CatalogCategoryListOut`, and `CatalogItemListOut` schemas
(OpenAPI components.schemas) and `frontend/src/api/types.ts` (`CatalogCategory`,
`CatalogItem`, `PaginatedList<T>`).**

```kotlin
package com.testlogon.android.core.model.catalog

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * A storefront category (schema CatalogCategoryOut).
 * required: category_id, name, created_at.
 * NOTE: no slug / image_url / item_count / parent_id on the wire.
 */
@JsonClass(generateAdapter = true)
data class CatalogCategoryDto(
    @Json(name = "category_id") val categoryId: String,
    val name: String,
    @Json(name = "created_at") val createdAt: String,        // ISO-8601, kept as String
    val description: String? = null,
    @Json(name = "creator_id") val creatorId: String? = null,
)

/** Paged category list (schema CatalogCategoryListOut): { items, next_token }. */
@JsonClass(generateAdapter = true)
data class CatalogCategoryListDto(
    val items: List<CatalogCategoryDto> = emptyList(),
    @Json(name = "next_token") val nextToken: String? = null,
)

/**
 * A catalog item — ONE shape for both list and detail (schema CatalogItemOut).
 * required: category_id, item_id, name, price_cents, currency, image_urls,
 *           attributes, created_at, updated_at.
 * Money is flat: price_cents (Long minor units) + currency. Media is image_urls.
 * No sku / in_stock-bool / nested price / nested media / display string.
 */
@JsonClass(generateAdapter = true)
data class CatalogItemDto(
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "item_id") val itemId: String,
    val name: String,
    @Json(name = "price_cents") val priceCents: Long,       // minor units, lossless
    val currency: String,                                   // ISO-4217, e.g. "USD"
    @Json(name = "image_urls") val imageUrls: List<String> = emptyList(),
    val attributes: Map<String, Any?> = emptyMap(),         // additionalProperties:true
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "updated_at") val updatedAt: String,
    val description: String? = null,
    @Json(name = "creator_id") val creatorId: String? = null,
    val position: Int? = null,
    @Json(name = "stock_count") val stockCount: Int? = null,
    @Json(name = "stock_status") val stockStatus: String = "unlimited",  // default
    @Json(name = "low_stock_threshold") val lowStockThreshold: Int = 5,  // default
    @Json(name = "stock_updated_at") val stockUpdatedAt: String? = null,
)

/**
 * Paged item list AND search envelope (schema CatalogItemListOut):
 * { items, next_token }. Search returns this same shape — there is no distinct
 * SearchResultDto, no query/total/page/limit/has_more fields.
 */
@JsonClass(generateAdapter = true)
data class CatalogItemListDto(
    val items: List<CatalogItemDto> = emptyList(),
    @Json(name = "next_token") val nextToken: String? = null,
)
```

Design notes:
- **CORRECTED:** `CatalogCategoryListDto` and `CatalogItemListDto` are intentionally
  the only two envelopes; search reuses `CatalogItemListDto`. They are structurally
  identical to a hypothetical `Paged<T>` but are kept concrete so Moshi codegen
  stays total (no `Types.newParameterizedType` lookup). A generic
  `PagedDto<T>(items, nextToken)` is an acceptable equivalent if codegen for the
  parameterized adapter is wired; either passes the round-trip tests.
- **CORRECTED:** `attributes` is `Map<String, Any?>` because the OpenAPI schema is
  `additionalProperties: true` (arbitrary JSON values, not guaranteed `String`).
  `Map<String,String>` would throw `JsonDataException` on a non-string value; if
  the domain layer only needs strings it coerces downstream.
- ISO-8601 timestamps (`created_at`, `updated_at`, `stock_updated_at`) are required
  on items per the schema and kept as `String` (parsing deferred to domain mapping,
  consistent with AND-026 §6).
- `image_urls` and `attributes` are `required` on `CatalogItemOut` but defaulted to
  `emptyList()`/`emptyMap()` here for resilience; a conformant server always sends
  them (possibly empty).

### 4.2 `CatalogApi` interface (`core-network.catalog`)

**CORRECTED** — paths are `ui/catalog/...`, paging is `page_size`/`next_token`,
search returns `CatalogItemListDto`, and the non-existent `getCategory`/`getItem`
methods are removed.

```kotlin
package com.testlogon.android.core.network.catalog

import com.testlogon.android.core.model.catalog.CatalogCategoryListDto
import com.testlogon.android.core.model.catalog.CatalogItemListDto
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

interface CatalogApi {

    /** All categories, token-paged. Idempotent GET (AND-016 retry-eligible). */
    @GET("ui/catalog/categories")
    suspend fun listCategories(
        @Query("page_size") pageSize: Int = 50,
        @Query("next_token") nextToken: String? = null,
    ): CatalogCategoryListDto

    /** Token-paged items within a category. */
    @GET("ui/catalog/categories/{categoryId}/items")
    suspend fun listItems(
        @Path("categoryId") categoryId: String,
        @Query("page_size") pageSize: Int = 50,
        @Query("next_token") nextToken: String? = null,
    ): CatalogItemListDto

    /** Full-text catalog search (AND-207). Returns the same list envelope. */
    @GET("ui/catalog/items/search")
    suspend fun searchCatalog(
        @Query("q") query: String,
        @Query("page_size") pageSize: Int = 50,
        @Query("next_token") nextToken: String? = null,
    ): CatalogItemListDto
}
```

Path/verb conventions: relative paths, no leading slash, resolve against base
`http://18.222.237.167:8000/` → e.g. `…/ui/catalog/categories/{id}/items`. The
`ui/catalog/…` prefix is **verified** (OpenAPI index lines 1308/1311/1321;
`frontend/src/api/endpoints/cart.ts`). `page_size` defaults to 50 to match the web
client; a nullable `next_token` is omitted from the query string by Retrofit when
`null` (matching the web `searchCatalogItems`, which never sends `next_token`).

### 4.3 Hilt provider

```kotlin
package com.testlogon.android.core.network.catalog.di

import com.testlogon.android.core.network.catalog.CatalogApi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object CatalogApiModule {

    @Provides
    @Singleton
    fun provideCatalogApi(retrofit: Retrofit): CatalogApi =
        retrofit.create(CatalogApi::class.java)
}
```

The injected `Retrofit` is the singleton from AND-010's `NetworkModule`, built on
AND-009's shared `OkHttpClient` (cookie jar, CSRF, 401-refresh, redacting logger
all attached there). No client/Retrofit/Moshi is constructed here.

### 4.4 Gradle wiring

No new dependencies. `core-model` already has Moshi codegen annotations + KSP;
`core-network` already has Retrofit, Moshi converter, Hilt, and (test)
MockWebServer from AND-010/AND-027. `core-network` already declares
`implementation(project(":core-model"))`. This ticket adds source files + test
fixtures only.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All responses are JSON; all three
endpoints are idempotent GETs. **CORRECTED auth note:** the web client authenticates
with `Authorization: Bearer <accessToken>` (from the auth store) **plus** cookies
(`credentials: "include"`) **plus** an `X-CSRF-Token` header sourced from the
`ui_csrf` cookie on mutating verbs (`client.ts`). The OpenAPI also documents
`X-SESSION-ID`, `X-IMPERSONATION-TOKEN`, and `X-API-Key` params on these routes.
The transport stack (AND-027/AND-009..AND-013) attaches whatever is required; this
layer declares no manual headers. CSRF is irrelevant to these GETs.

### GET `ui/catalog/categories?page_size=50&next_token=...`
Response `200` (schema `CatalogCategoryListOut`):
```json
{
  "items": [
    { "category_id": "cat_apparel", "name": "Apparel",
      "description": "Shirts, hats, more", "creator_id": "usr_1",
      "created_at": "2026-01-02T10:00:00Z" }
  ],
  "next_token": "eyJwayI6..."
}
```

### GET `ui/catalog/categories/{categoryId}/items?page_size=50&next_token=...`
Response `200` (schema `CatalogItemListOut`):
```json
{
  "items": [
    { "category_id": "cat_apparel", "item_id": "itm_001", "name": "Logo Tee",
      "description": "100% cotton logo tee.",
      "price_cents": 1999, "currency": "USD",
      "image_urls": ["http://.../tee_1.png", "http://.../tee_2.png"],
      "attributes": { "color": "black", "size": "M" },
      "creator_id": "usr_1", "position": 0,
      "stock_count": 120, "stock_status": "in_stock", "low_stock_threshold": 5,
      "stock_updated_at": "2026-05-01T00:00:00Z",
      "created_at": "2026-01-02T10:00:00Z", "updated_at": "2026-05-01T00:00:00Z" }
  ],
  "next_token": null
}
```

### GET `ui/catalog/items/search?q=tee&page_size=50`
Response `200` (schema `CatalogItemListOut` — same envelope as item list; **no**
`query`/`total`/`page`/`limit`/`has_more` fields):
```json
{
  "items": [
    { "category_id": "cat_apparel", "item_id": "itm_001", "name": "Logo Tee",
      "price_cents": 1999, "currency": "USD",
      "image_urls": ["http://.../tee_1.png"], "attributes": {},
      "created_at": "2026-01-02T10:00:00Z", "updated_at": "2026-05-01T00:00:00Z" }
  ],
  "next_token": null
}
```

**Error envelope (all endpoints) — CORRECTED.** The documented error responses are
`422` (`HTTPValidationError`) on all three reads, plus `400/401/403/429` on the
read routes (OpenAPI). There is **no `404`** documented for any catalog read (no
single-resource GET exists). `HTTPValidationError` is `{ "detail":
[{ "loc": [...], "msg": "...", "type": "..." }] }` (`ValidationError`; `loc/msg/type`
all required). The web `client.ts` additionally tolerates a `detail` object
carrying a `code` for authorization errors, so the practical `detail` union is
`[{loc,msg,type}] | {code,...} | string`. Mapping to a typed `ApiError` is owned by
**AND-015**; this ticket lets non-2xx surface as `retrofit2.HttpException` so
AND-015/AND-018 can map it.

## 6. Data & State Management

- `CatalogApi` is **stateless** — a singleton interface proxy with no fields. DTOs
  are transient wire types.
- **No Room / DataStore** in this ticket. Caching item/category pages, the Paging 3
  `RemoteMediator`/`PagingSource`, and domain mapping are `core-data` /
  AND-205/AND-208 concerns. DTOs must **not** be persisted directly nor enter
  Compose composition; they carry no `@Stable`/`@Immutable` annotations.
- **No `StateFlow`/`UiState`** here. ViewModels (AND-208) expose state by consuming
  a catalog repository that wraps these calls in `ApiResult<T>` (AND-018). This
  layer returns plain DTOs (happy path) and throws on failure.
- **Session state** rides entirely on cookies persisted by the AND-011 jar;
  `CatalogApi` neither reads nor writes cookies. CSRF (`ui_csrf` → `X-CSRF-Token`)
  is irrelevant to these GETs (CSRF applies to mutating verbs) but is handled
  globally regardless.
- **Pagination state** (cursor accumulation) is owned by the Paging 3 layer
  downstream; the DTOs only carry the single page-metadata field that exists on the
  wire — **`next_token`** (nullable; CORRECTED — there is no `page`/`limit`/`total`/
  `has_more`/`next_cursor`). End-of-pages is `next_token == null`.
- **Serialization** uses the shared Moshi codegen adapters via the AND-010
  converter; unknown keys are ignored, absent optional fields fall back to Kotlin
  defaults. ISO-4217 `currency` and `price_cents` minor-unit amounts are preserved
  exactly (`Long`, never `Double`).
- **Threading:** suspend methods are invoked from an IO-dispatcher coroutine at the
  repository layer; this ticket imposes no dispatcher.

## 7. Error Handling & Resilience

Responsibilities here are narrow: declare endpoints and DTOs so failures propagate
cleanly and deserialization is robust.

- **Non-2xx** (`422` validation, plus documented `400/401/403/429`) surfaces as
  `retrofit2.HttpException` carrying the raw error body for AND-015 to decode the
  FastAPI `detail`. Nothing is swallowed here. **CORRECTED:** no `404` is documented
  for catalog reads (no single-resource GET exists); an unknown `categoryId` returns
  `422`/empty per the backend, not `404`.
- **`401`** on any catalog call is intercepted by the AND-013 `Authenticator`,
  which calls `sessionRefresh()` once and retries; only a second `401` propagates,
  which the consumer routes to login (AND-025).
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged. The ~20s timeouts and **bounded backoff for
  idempotent GETs** are owned by AND-009/AND-016 on the shared client — all **three**
  catalog methods are GETs and are therefore retry-eligible there.
- **Deserialization robustness (DTO layer):**
  - Missing **required** field (e.g. `item_id`, `name`, `price_cents`, `currency`,
    `created_at`) → `JsonDataException` (desired fail-fast; asserted in tests).
  - Unknown/extra JSON keys → skipped silently (additive backend evolution safe).
  - `null` for a nullable field → tolerated; `null` for a non-null field →
    `JsonDataException`.
  - Empty arrays/objects → modeled via `emptyList()`/`emptyMap()` defaults so a
    sparse category/search response never produces nulls.
- **Money safety:** `price_cents` is `Long`; a non-integer/overflowing value
  surfaces as `JsonDataException` rather than silent float truncation.
- This ticket maps **no** errors itself and applies **no** retry policy — those are
  AND-015 (`ApiError`), AND-018 (`ApiResult`), and AND-009/AND-016 (client retry).

## 8. Security & Privacy

- **Auth:** catalog endpoints require the authenticated session. **CORRECTED:** the
  web client sends both a `Bearer` access token (`Authorization`) and cookies
  (`credentials: "include"`), not cookies alone; the OpenAPI also lists
  `X-SESSION-ID`/`X-IMPERSONATION-TOKEN`/`X-API-Key` params. The shared client
  (AND-027) attaches whatever the transport requires transparently. `CatalogApi`
  declares no manual `Cookie`/`Authorization`/`X-CSRF-Token`/`X-SESSION-ID` headers.
- **Transport:** on `dev` these ride plaintext HTTP (`http://18.222.237.167:8000`)
  — a known dev-only risk permitted by the scoped cleartext config (AND-006);
  `staging`/`prod` are HTTPS-only.
- **No sensitive payloads:** catalog data is non-credential, non-PII product
  content. No DTO here carries passwords, tokens, or MFA codes, so no `toString()`
  redaction is required (unlike AND-026). Standard HTTP logging from AND-009 (debug
  builds, with auth bodies already redacted) is acceptable for catalog bodies.
- **No token storage:** auth is cookie-based; this layer holds no bearer tokens.
- **Injection safety:** the `q` search term is passed as a Retrofit `@Query`
  (URL-encoded by OkHttp); no manual string concatenation into the URL.

## 9. Accessibility & i18n

Not applicable as a UI surface — this is a headless transport + DTO layer with no
Compose UI and no `strings.xml` entries. Two pass-through constraints are recorded
for downstream consumers (AND-205/AND-206):
- **CORRECTED:** there is no `MediaAssetDto`/`alt` on the wire — media is a flat
  `image_urls: List<String>` with no per-image alt text. The product/gallery UI
  (AND-206) must synthesize Compose `contentDescription` from the item `name`/index,
  since the backend supplies no alt text.
- `CatalogItemDto` exposes `priceCents` + `currency` (no pre-formatted display
  string exists on the wire) so the UI/domain layer applies locale-aware currency
  formatting (`NumberFormat.getCurrencyInstance(locale)`). Localization of catalog
  UI text is owned by the catalog feature tickets.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's `HttpLoggingInterceptor` (debug
  builds only). No new logging is added here.
- **No analytics events** emitted by this layer. Catalog-view / search-performed /
  item-viewed events are emitted by the catalog ViewModels (AND-208) from
  `ApiResult` outcomes, not from `CatalogApi`.
- **Build-time signal:** KSP must generate Moshi adapters for every catalog DTO
  referenced here; a missing adapter fails the build (no reflection fallback, per
  AND-010 policy). This is the only diagnostic surface the ticket adds.

## 11. Testing Strategy

Two test surfaces: **round-trip DTO tests** (JVM, in `core-model`) and
**MockWebServer endpoint tests** (JVM, in `core-network`), both using the
production Moshi/Retrofit configuration.

### 11.1 DTO round-trip tests (`core-model`)
Captured samples live at
`core-model/src/test/resources/catalog/<name>.json`. Test class:
`com.testlogon.android.core.model.catalog.CatalogDtoRoundTripTest`.

- **Round-trip fidelity.** For each DTO, `moshi.adapter(T::class.java).fromJson(sample)`
  is non-null and equals the expected object; re-serializing yields JSON whose
  parsed tree equals the original parsed tree (compare as Moshi `Map`/`JSONObject`
  to ignore key order/whitespace).
- **Snake_case mapping.** Serialized `CatalogItemDto` contains `"category_id"`,
  `"item_id"`, `"price_cents"`, and `"image_urls"`, never the camelCase forms.
- **Required-field failure.** Removing `item_id` from a `CatalogItemDto` sample (or
  `price_cents`, `currency`, `created_at`) causes `fromJson` to throw
  `JsonDataException`.
- **Unknown-key tolerance.** A sample with an extra `"server_time"` /
  `"experimental_flag"` key deserializes without error.
- **Money fidelity.** `price_cents: 1999` deserializes to `Long` `1999`, preserved
  through round-trip (no float drift).
- **Defaults.** A list response with `"items": []` yields an empty list, not null;
  an item with empty `image_urls`/`attributes` yields `emptyList()`/`emptyMap()`;
  a `null`/absent `next_token` yields `null`.

### 11.2 MockWebServer endpoint tests (`core-network`)
Harness mirrors the AND-027 pattern:
```kotlin
private fun api(server: MockWebServer): CatalogApi {
    val moshi = Moshi.Builder().build() // mirrors provideMoshi(): codegen adapters
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(CatalogApi::class.java)
}
```

**CORRECTED** — three endpoints (not five); no `getCategory`/`getItem`; paths are
`ui/catalog/...`; paging is `page_size`/`next_token`; error code is `422` not `404`.

- **T-1 `listCategories`** — asserts `GET /ui/catalog/categories?page_size=50`,
  decodes `CatalogCategoryListDto` with N categories and `next_token`.
- **T-2 `listItems`** — asserts
  `GET /ui/catalog/categories/cat_apparel/items?page_size=10&next_token=abc`
  (path + query params present and correct), decodes `CatalogItemListDto`.
  ```kotlin
  @Test fun listItems_sendsPagingQueryAndDecodes() = runTest {
      val server = MockWebServer().apply {
          enqueue(MockResponse().setBody(loadFixture("catalog/item_list.json"))); start()
      }
      val page = api(server).listItems("cat_apparel", pageSize = 10, nextToken = "abc")
      val req = server.takeRequest()
      assertEquals("GET", req.method)
      assertEquals(
          "/ui/catalog/categories/cat_apparel/items?page_size=10&next_token=abc",
          req.path,
      )
      assertEquals(1999L, page.items.first().priceCents)
      assertEquals("USD", page.items.first().currency)
      assertNull(page.nextToken)   // fixture has next_token: null → end of pages
      server.shutdown()
  }
  ```
- **T-3 `searchCatalog`** — asserts `GET /ui/catalog/items/search?q=tee&page_size=50`
  (`q` URL-encoded), decodes `CatalogItemListDto` (same envelope as item list).
- **T-4 nullable `next_token` omission** — `listCategories(nextToken = null)` sends
  a path with **no** `next_token` query param (Retrofit drops null `@Query`).
- **T-5 error propagation** — a `422` (`{"detail":[{"loc":["query","q"],"msg":...,
  "type":...}]}`) from `searchCatalog` throws `retrofit2.HttpException` with
  `code() == 422`, body intact (non-2xx not swallowed, leaving room for AND-015).
- **T-6 Hilt provider** — `@HiltAndroidTest` (or minimal `core-testing` harness)
  injects `CatalogApi`, asserts non-null `@Singleton` built on the shared Retrofit
  (same instance on repeated injection).

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
- **AND-205** (Catalog / category browse) — consumes `listCategories`/`listItems`
  via a repository + Paging 3 (token/`next_token` cursor).
- **AND-206** (Product detail) — **CORRECTED:** since no single-item/single-category
  GET exists, AND-206 must derive item detail by locating the item in a
  `listItems(categoryId)` result (mirroring web `ProductDetail.tsx`), or via a
  repository cache keyed on `item_id`. It does NOT consume a `getItem`/`getCategory`.
- **AND-207** (Catalog search) — consumes `searchCatalog`.
- **AND-208** (Catalog ViewModels) — wraps the repository in `ApiResult`/`UiState`.
- (AND-209 catalog tests transitively depend on this surface.)

**Sequencing within the ticket:** (1) confirm path prefix, pagination params, and
`required` arrays against `/openapi.json` + web reference (Q-1..Q-3); (2) define
DTOs in `core-model.catalog` + commit fixtures; (3) write
`CatalogDtoRoundTripTest`; (4) declare `CatalogApi`; (5) add `CatalogApiModule`;
(6) write MockWebServer tests T-1..T-6.

## 13. Risks & Open Questions

All of the prior open risks/questions were **RESOLVED during this review** against
OpenAPI + `cart.ts`/`types.ts`; recorded here with their resolution.

- **R-1 Path-prefix ambiguity — RESOLVED.** Prefix is `ui/catalog/` (not `catalog/`
  nor `shop/`; `shop/...` is only a client-side React route). Guarded by T-1..T-3.
- **R-2 Pagination contract — RESOLVED.** Token-based: `page_size` + `next_token`;
  enveloped `{ items, next_token }` only. No `page`/`limit`/`offset`/`total`/
  `has_more`. Guarded by T-2/T-3/T-4.
- **R-3 Item summary vs detail divergence — RESOLVED.** One shape (`CatalogItemOut`)
  serves both list and (client-derived) detail; a single `CatalogItemDto` is used.
- **R-4 Money representation — RESOLVED.** Flat `price_cents` (integer) + `currency`
  (string), not a decimal string and not a nested object. `Long` `price_cents`.
  Guarded by the money-fidelity test.
- **R-5 Attributes shape — RESOLVED.** `attributes` is `additionalProperties: true`
  (arbitrary JSON values), modeled as `Map<String, Any?>` (not `Map<String,String>`,
  which would throw on non-string values).
- **R-6 No single-resource GET — NEW (RESOLVED).** There is no
  `GET /ui/catalog/categories/{id}` or `GET /ui/catalog/items/{id}`; `getCategory`/
  `getItem` were removed and downstream detail is derived from list results.
- **Q-1** Path prefix + pagination params? → **Answered:** `ui/catalog/…`,
  `page_size`/`next_token`.
- **Q-2** Is search's envelope identical to item-list's? → **Answered:** yes,
  identical (`CatalogItemListOut`); a single `CatalogItemListDto` is reused.
- **Q-3** Are item `attributes` flat key/value or structured? → **Answered:**
  free-form (`additionalProperties: true`) → `Map<String, Any?>`.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Catalog DTOs (`CatalogCategoryDto`, `CatalogCategoryListDto`,
  `CatalogItemDto`, `CatalogItemListDto`) exist in
  `com.testlogon.android.core.model.catalog` as immutable
  `@JsonClass(generateAdapter=true)` data classes mirroring `CatalogCategoryOut`,
  `CatalogItemOut`, `CatalogCategoryListOut`, `CatalogItemListOut`.
- **AC-2 (backlog).** Catalog + item payloads **map (tested)**: every documented
  payload in Sections 4–5 (de)serializes the documented JSON exactly, proven by
  `CatalogDtoRoundTripTest` against committed fixtures (parsed-tree equality,
  snake_case keys verified).
- **AC-3.** `CatalogApi` declares the three operations (`listCategories`,
  `listItems`, `searchCatalog`) — and **no** `getCategory`/`getItem` (no such
  endpoint exists); the module compiles against the catalog DTOs.
- **AC-4.** Each endpoint is callable and its **verb + resolved path + query
  params** match Section 5 (`ui/catalog/...`, `page_size`/`next_token`), asserted
  with MockWebServer (T-1..T-4), including `listItems` paging query, null-token
  omission, and URL-encoded `searchCatalog` `q`.
- **AC-5.** Required-field absence (e.g. `item_id`, `price_cents`, `currency`,
  `created_at`) throws `JsonDataException`; unknown JSON keys are tolerated; empty
  collections default to `emptyList()`/`emptyMap()`; absent `next_token` is `null`.
- **AC-6.** Money is lossless: `price_cents` decodes to `Long` and survives
  round-trip with no float drift.
- **AC-7.** Non-2xx (e.g. `422` from `searchCatalog`) surfaces as `HttpException`
  with the body intact and is not swallowed (T-5).
- **AC-8.** `CatalogApi` is Hilt-provided as a `@Singleton` built on the shared
  `Retrofit`; repeated injection yields the same instance; no new
  `OkHttpClient`/`Retrofit`/`Moshi` is constructed and no per-method cookie/CSRF
  headers are declared (T-6).
- **AC-9.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no new lint/detekt regressions.

## 15. Definition of Done

- DTOs (`com.testlogon.android.core.model.catalog`) and `CatalogApi` +
  `CatalogApiModule` (`com.testlogon.android.core.network.catalog[.di]`) are
  implemented under `core-model`/`core-network`, package base
  `com.testlogon.android`; no DTOs redefined elsewhere.
- Open questions Q-1/Q-2/Q-3 and risks R-1..R-6 are **resolved** (see §13 and §16)
  against `/openapi.json` and the web reference, and the interface paths/query
  params and DTO shapes reflect the confirmed contract (`ui/catalog/...`,
  `page_size`/`next_token`, flat `price_cents`/`currency`, `image_urls`).
- `CatalogDtoRoundTripTest` (with committed fixtures under
  `core-model/src/test/resources/catalog/`) and the MockWebServer tests T-1..T-6
  are implemented and green in CI; ≥90% line coverage on the new surface; every
  endpoint has a verb/path/query assertion and every DTO has a round-trip test.
- No second `OkHttpClient`/`Retrofit`/`Moshi`; no manual cookie/CSRF/auth headers
  in the interface; money modeled with integer minor units (no `Double`).
- `./gradlew :core-model:testDebugUnitTest :core-network:assemble
  :core-network:testDebugUnitTest` passes locally and in CI with no new
  lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; AND-205/AND-206/AND-207/AND-208 are
  unblocked (the catalog repository, browse/detail/search screens, and ViewModels
  can compile against these types and endpoints).
- A one-line note in the `core-network` README (owned by AND-007) records the
  `CatalogApi` path/verb/query map and the delegation of cookie/CSRF/refresh/retry
  to AND-011/AND-012/AND-013/AND-016.

## 16. Citations & Assumption Audit

Every concrete API/transport claim, with verdict and an exact source pointer.
Sources: **OpenAPI index** = `reference/openapi.index.txt`; **OpenAPI spec** =
`reference/openapi.pretty.json` (components.schemas); **FE** = `reference/src/...`.

1. **Path prefix is `ui/catalog/` (not `catalog/`, not `shop/`).**
   VERDICT: **Corrected** (spec originally guessed `catalog/`/`shop/`).
   SOURCE: OpenAPI `GET /ui/catalog/categories` (index L1308),
   `GET /ui/catalog/categories/{category_id}/items` (L1311),
   `GET /ui/catalog/items/search` (L1321); FE `src/api/endpoints/cart.ts:
   getCategories/getCategoryItems/searchCatalogItems`.
2. **`listCategories` = `GET /ui/catalog/categories` → `CatalogCategoryListOut`.**
   VERDICT: **Verified.** SOURCE: OpenAPI index L1308; spec `CatalogCategoryListOut`.
3. **`listItems` = `GET /ui/catalog/categories/{category_id}/items` →
   `CatalogItemListOut`.** VERDICT: **Verified.** SOURCE: index L1311.
4. **`searchCatalog` = `GET /ui/catalog/items/search?q=...` → `CatalogItemListOut`.**
   VERDICT: **Verified.** SOURCE: index L1321; FE `cart.ts: searchCatalogItems`.
5. **No single-category GET and no single-item-detail GET exist.**
   VERDICT: **Corrected** (spec defined `getCategory`/`getItem`). SOURCE: OpenAPI
   index — `/ui/catalog/categories/{category_id}` only has DELETE (L1310);
   `/ui/catalog/items/{item_id}/...` only exposes `/reviews` (L1322) and `/stock`
   (L1325), no bare-item GET; FE `src/pages/shop/ProductDetail.tsx` derives the item
   via `items.find((i) => i.item_id === itemId)`, not a detail call.
6. **All catalog reads are HTTP GET / idempotent.** VERDICT: **Verified.**
   SOURCE: OpenAPI index L1308/L1311/L1321 (METHOD = GET).
7. **Pagination params are `page_size` + `next_token` (token/cursor), not
   `page`/`limit`.** VERDICT: **Corrected.** SOURCE: OpenAPI index params on
   L1308/L1311/L1321 (`page_size,next_token`); FE `cart.ts` (`page_size`,
   `next_token`); spec `PaginatedList<T>` in `src/api/types.ts`.
8. **List envelope shape is exactly `{ items, next_token }` — no `total`, `page`,
   `limit`, `has_more`, `next_cursor`.** VERDICT: **Corrected.** SOURCE: spec
   `CatalogCategoryListOut` (openapi.pretty.json L14782) and `CatalogItemListOut`
   (L14939); FE `types.ts: PaginatedList<T> { items; next_token? }`.
9. **`CatalogCategoryOut` fields: required `category_id, name, created_at`; optional
   `description, creator_id`. No `slug`/`image_url`/`item_count`/`parent_id`/`id`.**
   VERDICT: **Corrected** (spec invented `id`/`slug`/`image_url`/`item_count`/
   `parent_id`). SOURCE: openapi.pretty.json `CatalogCategoryOut` L14809–14853;
   FE `types.ts: CatalogCategory`.
10. **`CatalogItemOut` required: `category_id, item_id, name, price_cents, currency,
    image_urls, attributes, created_at, updated_at`; optional `description,
    creator_id, position, stock_count, stock_status(=unlimited), low_stock_threshold
    (=5), stock_updated_at`.** VERDICT: **Corrected.** SOURCE: openapi.pretty.json
    `CatalogItemOut` L14966–15087; FE `types.ts: CatalogItem`.
11. **Money is flat `price_cents` (integer) + `currency` (string), NOT a nested
    `price{amount_minor,currency,display}` object.** VERDICT: **Corrected.** SOURCE:
    `CatalogItemOut.price_cents`/`currency` (L15038/L14992); FE
    `src/pages/shop/Catalog.tsx`: `formatPrice(item.price_cents, item.currency)`.
12. **Media is a flat `image_urls: string[]`, NOT a `media: MediaAssetDto[]` list,
    and there is no per-image `alt`.** VERDICT: **Corrected.** SOURCE:
    `CatalogItemOut.image_urls` (L15007); FE `ProductDetail.tsx`
    `item.image_urls[activeImageIndex]`.
13. **No item `sku` and no `in_stock` boolean (stock is `stock_count`/
    `stock_status`).** VERDICT: **Corrected** (spec invented `sku`/`in_stock`).
    SOURCE: `CatalogItemOut` property set (L14966–15087) — no `sku`/`in_stock`.
14. **`attributes` is free-form (`additionalProperties: true`) → modeled as
    `Map<String, Any?>`, not `Map<String,String>`.** VERDICT: **Corrected.**
    SOURCE: `CatalogItemOut.attributes` L14968 (`additionalProperties: true`).
15. **Search envelope is identical to item-list (`CatalogItemListOut`); no separate
    `SearchResultDto`/`query`/`total`.** VERDICT: **Corrected.** SOURCE: OpenAPI
    L1321 (`resp=200:CatalogItemListOut`); FE `searchCatalogItems` returns
    `PaginatedList<CatalogItem>`.
16. **Error responses: `422` (`HTTPValidationError`) on all reads, plus
    `400/401/403/429` on the read routes; no `404`.** VERDICT: **Corrected** (spec
    asserted `404` from `getItem`/unknown ids). SOURCE: OpenAPI index L1308/L1311/
    L1321 (`resp=...;422:HTTPValidationError;400;401;403;429`).
17. **`HTTPValidationError` = `{ "detail": [ { loc, msg, type } ] }`
    (`ValidationError`, all three required).** VERDICT: **Verified.** SOURCE:
    openapi.pretty.json `HTTPValidationError` L37133, `ValidationError` L80337.
18. **Auth: web client sends `Authorization: Bearer <token>` + cookies
    (`credentials:"include"`) + `X-CSRF-Token` (from `ui_csrf` cookie); routes also
    list `X-SESSION-ID`/`X-IMPERSONATION-TOKEN`/`X-API-Key`.** VERDICT: **Corrected**
    (spec called it "cookie-based session" only). SOURCE: FE `src/api/client.ts`
    (`Authorization` Bearer, `getCookie("ui_csrf")` → `X-CSRF-Token`,
    `credentials:"include"`); OpenAPI index params on L1308/L1311/L1321.
19. **CSRF (`ui_csrf` → `X-CSRF-Token`) applies to mutating verbs and is irrelevant
    to these GETs.** VERDICT: **Verified.** SOURCE: FE `client.ts` sets
    `X-CSRF-Token` from `ui_csrf`; GETs are read-only.
20. **`@Query` URL-encoding for the `q` search term (no manual concatenation).**
    VERDICT: **Verified (framework ref).** SOURCE: Retrofit `@Query` encodes by
    default — https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/Query.html
21. **Retrofit drops a `null` `@Query` parameter from the URL.** VERDICT:
    **Verified (framework ref).** SOURCE: Retrofit `@Query` Javadoc (null values
    omitted) — https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/Query.html
22. **Moshi codegen ignores unknown JSON keys and throws `JsonDataException` on a
    missing non-null required field.** VERDICT: **Verified (framework ref).**
    SOURCE: Moshi codegen behavior — https://github.com/square/moshi#codegen
23. **Hilt `@Provides @Singleton` on the shared `Retrofit` yields one instance.**
    VERDICT: **Verified (framework ref).** SOURCE: Dagger Hilt scoping —
    https://developer.android.com/training/dependency-injection/hilt-android#scoping

### Corrections made
- **C-1** Path prefix `catalog/`/`shop/` → **`ui/catalog/`** (items 1, FR-3, §2,
  §4.2, §5, T-1..T-3).
- **C-2** Removed non-existent `getCategory`/`getItem` endpoints and their DTO
  consumers; downstream detail now derived from list results (items 5, FR-2, §4.2,
  §12 AND-206).
- **C-3** Pagination `page`/`limit`/`has_more`/`next_cursor` → **`page_size`/
  `next_token`**; envelope reduced to `{ items, next_token }` (items 7–8, FR-4, §6).
- **C-4** Money: nested `PriceDto{amount_minor,currency,display}` → flat
  `price_cents: Long` + `currency: String`; no `display` (items 11, FR-1/FR-7).
- **C-5** Media: `media: List<MediaAssetDto>` (+`alt`) → `image_urls: List<String>`;
  removed `MediaAssetDto` (items 12, FR-1, §9).
- **C-6** Removed invented item fields `sku`/`in_stock`; added real
  `stock_count`/`stock_status`/`low_stock_threshold`/`position`/timestamps
  (items 10, 13).
- **C-7** `attributes` `Map<String,String>` → `Map<String, Any?>` (item 14).
- **C-8** Search: removed separate `SearchResultDto`/`query`/`total`; reuse
  `CatalogItemListDto` (item 15).
- **C-9** DTO renames: `CategoryDto`→`CatalogCategoryDto`, `CategoryListDto`→
  `CatalogCategoryListDto`, `ItemSummaryDto`/`ItemDetailDto`→`CatalogItemDto`,
  `ItemPageDto`→`CatalogItemListDto`; category field `id`→`category_id` etc.
- **C-10** Error model: `404` claim → **`422`** (+`400/401/403/429`); documented the
  real `HTTPValidationError`/`ValidationError` shape (items 16–17, §5, §7, AC-7).
- **C-11** Auth description: "cookie-based session" → Bearer token + cookies +
  CSRF + session/impersonation/api-key headers (item 18, §5, §8).
- **C-12** Test plan reduced from five endpoints (T-1..T-7 incl. getCategory/getItem)
  to three (T-1..T-6), with corrected paths/queries/error code.

### Open assumptions
- **OA-1** Base URL `http://18.222.237.167:8000/` and the dev host's
  ~20s-timeout/unreliability are taken from the spec/AND-006 and were **not** present
  in the supplied reference sources — *unverified assumption* (no env/config file in
  `reference/`).
- **OA-2** The shared transport's exact auth mechanism for Android (cookie jar vs
  Bearer vs `X-SESSION-ID`) is owned by **AND-027** and not re-derived here; the web
  client uses all three, so the Android side is assumed to attach whatever the
  backend requires — *unverified for Android* (depends on AND-027 implementation).
- **OA-3** `stock_status` enum values (e.g. `"unlimited"`/`"in_stock"`/`"out"`) are
  free-form `String` on the wire (schema gives only the default `"unlimited"`); exact
  value set is *unverified* — modeled as `String`, not an enum.
- **OA-4** Whether an unknown `categoryId` returns `422`, an empty list, or another
  code is *unverified* (no example in sources); only the documented response set is
  cited. Tests assert behavior for documented codes only.
- **OA-5** `next_token` opacity/format (e.g. base64 DynamoDB key) is *unverified*;
  treated as an opaque `String` round-tripped verbatim.

## 17. Test Plan

IDs `TC-AND-204-NN`. Targets: **JVM** (local Robolectric/unit, no device);
**emulator** = AVD `test35` (x86_64, API 35); **device** = Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). This ticket is a headless transport + DTO layer:
the substantive logic (Moshi (de)serialization, Retrofit path/query building,
`HttpException` propagation, Hilt provision) is pure-JVM and runs as **unit /
contract (MockWebServer)** tests — no device is required for any functional case.
Device/emulator cases below exist only to satisfy the review's hardware/ABI and
"instrumented build" coverage requirements.

- **TC-AND-204-01** — Type: **contract/MockWebServer** (JVM).
  Target: JVM. Precond: MockWebServer enqueues `catalog/category_list.json`
  (`{items:[...], next_token:"..."}`). Steps: call `listCategories(pageSize=50)`;
  read `takeRequest()`. Expected: method `GET`, path
  `/ui/catalog/categories?page_size=50`; decodes `CatalogCategoryListDto` with N
  `CatalogCategoryDto` (correct `categoryId`/`name`/`createdAt`) and `nextToken`.
  Traces: AC-3, AC-4.
- **TC-AND-204-02** — Type: **contract/MockWebServer** (JVM).
  Target: JVM. Precond: enqueue `catalog/item_list.json` with `next_token:null`.
  Steps: `listItems("cat_apparel", pageSize=10, nextToken="abc")`. Expected: path
  `/ui/catalog/categories/cat_apparel/items?page_size=10&next_token=abc`; decodes
  `CatalogItemListDto`; `items[0].priceCents == 1999L`, `currency=="USD"`,
  `imageUrls` non-empty, `nextToken == null`. Traces: AC-4, AC-6.
- **TC-AND-204-03** — Type: **contract/MockWebServer** (JVM).
  Target: JVM. Precond: enqueue `catalog/item_list.json`. Steps:
  `searchCatalog(query="tee & hats", pageSize=50)`. Expected: path
  `/ui/catalog/items/search?q=tee%20%26%20hats&page_size=50` (`q` URL-encoded);
  decodes `CatalogItemListDto`. Traces: AC-4 (security: injection-safe `@Query`).
- **TC-AND-204-04** — Type: **contract/MockWebServer** (JVM).
  Target: JVM. Precond: enqueue any 200 body. Steps: `listCategories(nextToken=null)`.
  Expected: request path is `/ui/catalog/categories?page_size=50` with **no**
  `next_token` query param (Retrofit drops null `@Query`). Traces: AC-4.
- **TC-AND-204-05** — Type: **unit (round-trip)** (JVM).
  Target: JVM (`CatalogDtoRoundTripTest`). Precond: fixtures
  `catalog/category.json`, `catalog/item.json`. Steps: `fromJson` then `toJson` each
  DTO; compare parsed trees. Expected: equal trees; serialized item carries
  `category_id`/`item_id`/`price_cents`/`image_urls` (snake_case), never camelCase.
  Traces: AC-1, AC-2.
- **TC-AND-204-06** — Type: **unit (round-trip)** (JVM).
  Target: JVM. Precond: an item fixture with `price_cents: 9007199254740993`
  (> 2^53) and a normal `1999`. Steps: deserialize. Expected: decodes to `Long`
  exactly (no float drift / precision loss); round-trips identically. Traces: AC-6.
- **TC-AND-204-07** — Type: **unit (round-trip / validation)** (JVM).
  Target: JVM. Precond: item fixture with `item_id` (or `price_cents`/`currency`/
  `created_at`) removed. Steps: `adapter.fromJson(body)`. Expected: throws
  `JsonDataException` (fail-fast on missing required field). Traces: AC-5.
- **TC-AND-204-08** — Type: **unit (round-trip)** (JVM).
  Target: JVM. Precond: item fixture with extra `"server_time"`/`"experimental_flag"`
  keys, empty `image_urls`/`attributes`, and absent `next_token` at the envelope.
  Steps: deserialize. Expected: no error; unknown keys ignored; `imageUrls`/
  `attributes` are empty (not null); `nextToken == null`. Traces: AC-5.
- **TC-AND-204-09** — Type: **unit (round-trip)** (JVM).
  Target: JVM. Precond: item fixture with mixed-type `attributes`
  (`{"color":"black","featured":true,"rank":3}`). Steps: deserialize into
  `Map<String,Any?>`. Expected: succeeds (free-form values preserved); a
  `Map<String,String>` model would have thrown — guards the C-7 correction.
  Traces: AC-1, AC-5.
- **TC-AND-204-10** — Type: **contract/MockWebServer (error)** (JVM).
  Target: JVM. Precond: enqueue `422` with body
  `{"detail":[{"loc":["query","q"],"msg":"field required","type":"missing"}]}`.
  Steps: `searchCatalog("")` and catch. Expected: throws `retrofit2.HttpException`
  with `code()==422` and `response().errorBody()` intact (not swallowed), so AND-015
  can decode the `detail` list. Traces: AC-7.
- **TC-AND-204-11** — Type: **integration / offline-resilience (MockWebServer)** (JVM).
  Target: JVM. Precond: MockWebServer with
  `SocketPolicy.NO_RESPONSE`/`DISCONNECT_AT_START` simulating the flaky dev host.
  Steps: call `listCategories()`. Expected: a transport exception
  (`SocketTimeoutException`/`IOException`) propagates unchanged (this layer adds no
  retry/swallow; backoff is AND-009/AND-016). Traces: AC-7 (resilience boundary).
- **TC-AND-204-12** — Type: **instrumented (Hilt)** — emulator.
  Target: **emulator `test35`** (API 35). Precond: `@HiltAndroidTest` app with the
  shared `NetworkModule` + `CatalogApiModule`. Steps: inject `CatalogApi` twice.
  Expected: non-null; both injections are the same `@Singleton` instance; no second
  `Retrofit`/`OkHttpClient`/`Moshi` constructed. MUST run on emulator/device (needs
  Android runtime + Hilt). Traces: AC-8.
- **TC-AND-204-13** — Type: **instrumented / ABI build** — physical device.
  Target: **physical device A15 (arm64-v8a, API 34)**. Precond: assembled
  `androidTest` APK installed via adb on serial `R5CX821TA9R`. Steps: run the Hilt
  injection + one MockWebServer decode on-device. Expected: KSP-generated Moshi
  adapters load and decode identically on **arm64-v8a / API 34** as on emulator
  x86_64 / API 35 (guards the ABI/API-level difference; codegen is the only
  build-time surface this ticket adds). MUST run on the physical device (this is the
  only arm64 + API-34 target). Traces: AC-9.
- **TC-AND-204-14** — Type: **manual / CI gate** (JVM build).
  Target: JVM/CI. Precond: clean checkout. Steps: run
  `./gradlew :core-model:testDebugUnitTest :core-network:assemble
  :core-network:testDebugUnitTest`. Expected: builds clean under AGP 8.7.3 / Gradle
  8.9 / JDK 17, KSP adapters generated for all four DTOs, ≥90% coverage on the new
  surface, no new lint/detekt violations. Traces: AC-9.

Note on accessibility & permissions: this ticket exposes **no Compose UI** and
declares **no runtime permissions or manual headers**, so dedicated Compose-UI a11y
and permission cases are **N/A**; the two downstream a11y constraints (synthesizing
`contentDescription` from `image_urls`, locale price formatting from
`priceCents`/`currency` — §9) are owned by AND-205/AND-206 and tested there.

### Coverage matrix
| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (DTOs exist, immutable, codegen) | TC-05, TC-09 |
| AC-2 (payloads map / round-trip) | TC-05, TC-06 |
| AC-3 (three ops declared; no getItem/getCategory) | TC-01 |
| AC-4 (verb + path + query per §5) | TC-01, TC-02, TC-03, TC-04 |
| AC-5 (required-fail / unknown-tolerant / defaults) | TC-07, TC-08, TC-09 |
| AC-6 (money lossless `Long`) | TC-02, TC-06 |
| AC-7 (non-2xx → `HttpException`, not swallowed) | TC-10, TC-11 |
| AC-8 (Hilt `@Singleton` on shared Retrofit) | TC-12 |
| AC-9 (CI build clean / KSP / coverage / ABI) | TC-13, TC-14 |
