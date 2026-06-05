---
id: AND-204
title: Catalog API + DTOs
milestone: M5
epic: E28
priority: P0
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-205, AND-206, AND-207, AND-208]
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
  layer in `frontend/src/api/endpoints/` (expected `catalog.ts` / `shop.ts`) and
  shared types in `frontend/src/api/types.ts`. The web client uses routes of the
  form `shop/:categoryId/:itemId` (cf. AND-206), confirming a `shop`/`catalog`
  path family. Mirror those names; do **not** invent camelCase wire keys — the
  backend is snake_case.

## 3. Functional Requirements

FR-1. Define request/response **DTOs** in `core-model.catalog` covering: a
category, a paged category list, a catalog item summary (list/grid card), a full
item detail (product page), a paged item list, an item media asset, a money/price
value, and a paged search-result envelope.

FR-2. Define a single Retrofit interface **`CatalogApi`** in `core-network.catalog`
exposing exactly: `listCategories`, `getCategory`, `listItems` (by category,
paged), `getItem` (detail), and `searchCatalog` (full-text, paged).

FR-3. All `CatalogApi` methods are `suspend` functions returning the typed DTO
body. All are HTTP **GET** (catalog is read-only at this layer; cart mutation is
AND-210). Paths are relative with **no leading slash** (AND-010 convention) so
they append to the normalized base URL.

FR-4. Paging is offset/limit (or cursor) via `@Query` params: `listItems` and
`searchCatalog` accept `page`/`limit` (or `cursor`/`limit`) and return a paged
envelope carrying `items`, `total`, and a next-page indicator. The exact param
names and envelope keys are confirmed against `/openapi.json`/web reference before
coding (Q-1) and modeled in a reusable `Paged<T>` generic where Moshi permits, or
per-type envelopes otherwise.

FR-5. Every DTO field maps to the backend's snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. Unknown/extra JSON keys are tolerated
(Moshi codegen default — additive backend evolution must not throw).

FR-6. Required vs optional fidelity: required fields are non-null and their
absence surfaces as a `JsonDataException` (fail fast); optional fields are
Kotlin-nullable with a `null`/empty default per `/openapi.json` `required` arrays.

FR-7. Prices/money are modeled losslessly: the minor-unit integer amount plus the
ISO-4217 currency code are preserved exactly (no float rounding). A formatted
display string, if the backend supplies one, is kept verbatim as a `String`.

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

```kotlin
package com.testlogon.android.core.model.catalog

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/** A storefront category. Children optional (flat catalogs omit them). */
@JsonClass(generateAdapter = true)
data class CategoryDto(
    val id: String,
    val name: String,
    val slug: String? = null,
    val description: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "item_count") val itemCount: Int? = null,
    @Json(name = "parent_id") val parentId: String? = null,
)

@JsonClass(generateAdapter = true)
data class CategoryListDto(
    val categories: List<CategoryDto> = emptyList(),
)

/** Money kept lossless: minor units + ISO-4217 code; display string verbatim. */
@JsonClass(generateAdapter = true)
data class PriceDto(
    @Json(name = "amount_minor") val amountMinor: Long,
    val currency: String,                       // e.g. "USD"
    @Json(name = "display") val display: String? = null, // e.g. "$19.99"
)

@JsonClass(generateAdapter = true)
data class MediaAssetDto(
    val url: String,
    val type: String? = null,                   // "image" | "video"
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    val alt: String? = null,
)

/** Card/summary shape used in grids and search results. */
@JsonClass(generateAdapter = true)
data class ItemSummaryDto(
    val id: String,
    val name: String,
    val sku: String? = null,
    @Json(name = "category_id") val categoryId: String? = null,
    val price: PriceDto,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "in_stock") val inStock: Boolean = true,
)

/** Full product-detail shape (AND-206 consumer). */
@JsonClass(generateAdapter = true)
data class ItemDetailDto(
    val id: String,
    val name: String,
    val sku: String? = null,
    @Json(name = "category_id") val categoryId: String? = null,
    val description: String? = null,
    val price: PriceDto,
    val media: List<MediaAssetDto> = emptyList(),
    @Json(name = "in_stock") val inStock: Boolean = true,
    @Json(name = "stock_qty") val stockQty: Int? = null,
    val attributes: Map<String, String> = emptyMap(),
)

/** Paged envelope for item lists and search. */
@JsonClass(generateAdapter = true)
data class ItemPageDto(
    val items: List<ItemSummaryDto> = emptyList(),
    val total: Int = 0,
    val page: Int = 1,
    val limit: Int = DEFAULT_PAGE_LIMIT,
    @Json(name = "has_more") val hasMore: Boolean = false,
    @Json(name = "next_cursor") val nextCursor: String? = null,
) {
    companion object { const val DEFAULT_PAGE_LIMIT = 20 }
}

@JsonClass(generateAdapter = true)
data class SearchResultDto(
    val query: String? = null,
    val items: List<ItemSummaryDto> = emptyList(),
    val total: Int = 0,
    val page: Int = 1,
    val limit: Int = 20,
    @Json(name = "has_more") val hasMore: Boolean = false,
)
```

Design notes:
- `ItemPageDto` and `SearchResultDto` are kept as concrete envelopes (rather than a
  generic `Paged<ItemSummaryDto>`) because Moshi codegen on generic types requires
  a parameterized `Types.newParameterizedType(...)` adapter lookup; concrete
  envelopes keep codegen total and the test surface simple. If `/openapi.json`
  shows identical envelopes for both, `SearchResultDto` may be collapsed into
  `ItemPageDto` during implementation (Q-2).
- `attributes` is `Map<String,String>`; if the backend returns typed/structured
  attributes, this becomes `List<AttributeDto>` (resolved against OpenAPI, Q-3).
- ISO-8601 timestamps, if present, are kept as `String` (parsing deferred to the
  domain-mapping layer, consistent with AND-026 §6). No catalog timestamps are
  modeled here unless `/openapi.json` requires them.

### 4.2 `CatalogApi` interface (`core-network.catalog`)

```kotlin
package com.testlogon.android.core.network.catalog

import com.testlogon.android.core.model.catalog.CategoryDto
import com.testlogon.android.core.model.catalog.CategoryListDto
import com.testlogon.android.core.model.catalog.ItemDetailDto
import com.testlogon.android.core.model.catalog.ItemPageDto
import com.testlogon.android.core.model.catalog.SearchResultDto
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

interface CatalogApi {

    /** All top-level categories. Idempotent GET (AND-016 retry-eligible). */
    @GET("catalog/categories")
    suspend fun listCategories(): CategoryListDto

    /** A single category by id. */
    @GET("catalog/categories/{categoryId}")
    suspend fun getCategory(@Path("categoryId") categoryId: String): CategoryDto

    /** Paged items within a category. */
    @GET("catalog/categories/{categoryId}/items")
    suspend fun listItems(
        @Path("categoryId") categoryId: String,
        @Query("page") page: Int = 1,
        @Query("limit") limit: Int = 20,
    ): ItemPageDto

    /** Full item/product detail. */
    @GET("catalog/items/{itemId}")
    suspend fun getItem(@Path("itemId") itemId: String): ItemDetailDto

    /** Full-text catalog search over name/description/SKU (AND-207). */
    @GET("catalog/search")
    suspend fun searchCatalog(
        @Query("q") query: String,
        @Query("page") page: Int = 1,
        @Query("limit") limit: Int = 20,
    ): SearchResultDto
}
```

Path/verb conventions: relative paths, no leading slash, resolve against base
`http://18.222.237.167:8000/` → e.g. `…/catalog/categories/{id}/items`. The
concrete `catalog/…` prefix is confirmed against `/openapi.json` and the web
reference before coding (Q-1) — the web route family is `shop/:categoryId/:itemId`,
so the prefix may be `shop` rather than `catalog`; if so, every annotation path is
updated consistently and the tests track the confirmed paths.

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

Base path (`dev`): `http://18.222.237.167:8000/`. All responses are JSON; all
endpoints are idempotent GETs requiring the session cookie (set by the auth flow)
and tolerating the AND-013 401-refresh-once behavior.

### GET `catalog/categories`
Response `200`:
```json
{
  "categories": [
    { "id": "cat_apparel", "name": "Apparel", "slug": "apparel",
      "image_url": "http://.../apparel.png", "item_count": 42, "parent_id": null }
  ]
}
```

### GET `catalog/categories/{categoryId}`
Response `200`: a single `CategoryDto`. `404` if unknown.
```json
{ "id": "cat_apparel", "name": "Apparel", "slug": "apparel",
  "description": "Shirts, hats, more", "item_count": 42 }
```

### GET `catalog/categories/{categoryId}/items?page=1&limit=20`
Response `200`:
```json
{
  "items": [
    { "id": "itm_001", "name": "Logo Tee", "sku": "TEE-001",
      "category_id": "cat_apparel",
      "price": { "amount_minor": 1999, "currency": "USD", "display": "$19.99" },
      "image_url": "http://.../tee.png", "in_stock": true }
  ],
  "total": 42, "page": 1, "limit": 20, "has_more": true, "next_cursor": null
}
```

### GET `catalog/items/{itemId}`
Response `200`:
```json
{
  "id": "itm_001", "name": "Logo Tee", "sku": "TEE-001",
  "category_id": "cat_apparel", "description": "100% cotton logo tee.",
  "price": { "amount_minor": 1999, "currency": "USD", "display": "$19.99" },
  "media": [
    { "url": "http://.../tee_1.png", "type": "image",
      "thumbnail_url": "http://.../tee_1_thumb.png", "alt": "Front" }
  ],
  "in_stock": true, "stock_qty": 120,
  "attributes": { "color": "black", "size": "M" }
}
```
`404` if the item id is unknown.

### GET `catalog/search?q=tee&page=1&limit=20`
Response `200`:
```json
{
  "query": "tee", "total": 3, "page": 1, "limit": 20, "has_more": false,
  "items": [
    { "id": "itm_001", "name": "Logo Tee", "sku": "TEE-001",
      "category_id": "cat_apparel",
      "price": { "amount_minor": 1999, "currency": "USD" }, "in_stock": true }
  ]
}
```

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg,type,loc}] | {code,...}`). Mapping to a typed `ApiError` is owned
by **AND-015**; this ticket lets non-2xx surface as `retrofit2.HttpException` so
AND-015/AND-018 can map it. Exact path prefix (`catalog` vs `shop`), pagination
param names (`page`/`limit` vs `offset`/`cursor`), and `required` arrays are
confirmed against `/openapi.json` before coding (Q-1).

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
- **Pagination state** (current page/cursor, accumulation) is owned by the Paging 3
  layer downstream; the DTOs only carry the per-response page metadata (`page`,
  `limit`, `total`, `has_more`, `next_cursor`).
- **Serialization** uses the shared Moshi codegen adapters via the AND-010
  converter; unknown keys are ignored, absent optional fields fall back to Kotlin
  defaults. ISO-4217 currency and minor-unit amounts are preserved exactly (`Long`,
  never `Double`).
- **Threading:** suspend methods are invoked from an IO-dispatcher coroutine at the
  repository layer; this ticket imposes no dispatcher.

## 7. Error Handling & Resilience

Responsibilities here are narrow: declare endpoints and DTOs so failures propagate
cleanly and deserialization is robust.

- **Non-2xx** (`404` unknown category/item, `422` bad query) surfaces as
  `retrofit2.HttpException` carrying the raw error body for AND-015 to decode the
  FastAPI `detail`. Nothing is swallowed here.
- **`401`** on any catalog call is intercepted by the AND-013 `Authenticator`,
  which calls `sessionRefresh()` once and retries; only a second `401` propagates,
  which the consumer routes to login (AND-025).
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged. The ~20s timeouts and **bounded backoff for
  idempotent GETs** are owned by AND-009/AND-016 on the shared client — all five
  catalog methods are GETs and are therefore retry-eligible there.
- **Deserialization robustness (DTO layer):**
  - Missing **required** field (e.g. `id`, `name`, `price`) → `JsonDataException`
    (desired fail-fast; asserted in tests).
  - Unknown/extra JSON keys → skipped silently (additive backend evolution safe).
  - `null` for a nullable field → tolerated; `null` for a non-null field →
    `JsonDataException`.
  - Empty arrays/objects → modeled via `emptyList()`/`emptyMap()` defaults so a
    sparse category/search response never produces nulls.
- **Money safety:** `amount_minor` is `Long`; a non-integer/overflowing value
  surfaces as `JsonDataException` rather than silent float truncation.
- This ticket maps **no** errors itself and applies **no** retry policy — those are
  AND-015 (`ApiError`), AND-018 (`ApiResult`), and AND-009/AND-016 (client retry).

## 8. Security & Privacy

- **Auth:** catalog endpoints require the cookie-based session; the shared client
  attaches cookies/CSRF transparently. `CatalogApi` declares no manual
  `Cookie`/`Authorization`/`X-CSRF-Token` headers.
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
- `MediaAssetDto.alt` is preserved verbatim so the product/gallery UI can supply
  Compose `contentDescription` for images.
- `PriceDto` exposes `amountMinor` + `currency` (not just a pre-formatted
  `display`) so the UI/domain layer can apply locale-aware currency formatting
  (`NumberFormat.getCurrencyInstance(locale)`); the backend `display` string is a
  fallback, not the canonical render. Localization of catalog UI text is owned by
  the catalog feature tickets.

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
- **Snake_case mapping.** Serialized `ItemSummaryDto` contains `"category_id"` and
  `"in_stock"`, never `"categoryId"`/`"inStock"`.
- **Required-field failure.** Removing `id` from an `ItemDetailDto` sample (or
  `amount_minor` from `PriceDto`) causes `fromJson` to throw `JsonDataException`.
- **Unknown-key tolerance.** A sample with an extra `"server_time"` /
  `"experimental_flag"` key deserializes without error.
- **Money fidelity.** `amount_minor: 1999` deserializes to `Long` `1999`; a value
  with cents preserved through round-trip (no float drift).
- **Defaults.** A category response with `"categories": []` yields an empty list,
  not null; an item with no `media` yields `emptyList()`.

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

- **T-1 `listCategories`** — asserts `GET /catalog/categories`, decodes
  `CategoryListDto` with N categories.
- **T-2 `getCategory`** — asserts `GET /catalog/categories/cat_apparel` (path param
  interpolated), decodes `CategoryDto`.
- **T-3 `listItems`** — asserts `GET /catalog/categories/cat_apparel/items?page=2&limit=10`
  (path + query params present and correct), decodes `ItemPageDto` including
  `total`/`has_more`.
  ```kotlin
  @Test fun listItems_sendsPagingQueryAndDecodes() = runTest {
      val server = MockWebServer().apply {
          enqueue(MockResponse().setBody(loadFixture("catalog/item_page.json"))); start()
      }
      val page = api(server).listItems("cat_apparel", page = 2, limit = 10)
      val req = server.takeRequest()
      assertEquals("GET", req.method)
      assertEquals("/catalog/categories/cat_apparel/items?page=2&limit=10", req.path)
      assertEquals(42, page.total)
      assertTrue(page.hasMore)
      assertEquals(1999L, page.items.first().price.amountMinor)
      server.shutdown()
  }
  ```
- **T-4 `getItem`** — asserts `GET /catalog/items/itm_001`, decodes `ItemDetailDto`
  including nested `media` and `attributes`.
- **T-5 `searchCatalog`** — asserts `GET /catalog/search?q=tee&page=1&limit=20`
  (`q` URL-encoded), decodes `SearchResultDto`.
- **T-6 error propagation** — a `404` from `getItem` throws `retrofit2.HttpException`
  with `code() == 404` (confirms non-2xx not swallowed, leaving room for AND-015).
- **T-7 Hilt provider** — `@HiltAndroidTest` (or minimal `core-testing` harness)
  injects `CatalogApi`, asserts non-null `@Singleton` built on the shared Retrofit
  (same instance on repeated injection).

Coverage target: ≥90% on the new surface (DTOs + interface binding + provider);
each of the five endpoints has at least one verb/path/query assertion; every DTO
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
  via a repository + Paging 3.
- **AND-206** (Product detail) — consumes `getItem`/`getCategory`.
- **AND-207** (Catalog search) — consumes `searchCatalog`.
- **AND-208** (Catalog ViewModels) — wraps the repository in `ApiResult`/`UiState`.
- (AND-209 catalog tests transitively depend on this surface.)

**Sequencing within the ticket:** (1) confirm path prefix, pagination params, and
`required` arrays against `/openapi.json` + web reference (Q-1..Q-3); (2) define
DTOs in `core-model.catalog` + commit fixtures; (3) write
`CatalogDtoRoundTripTest`; (4) declare `CatalogApi`; (5) add `CatalogApiModule`;
(6) write MockWebServer tests T-1..T-7.

## 13. Risks & Open Questions

- **R-1 Path-prefix ambiguity.** Endpoints may be under `shop/…` (web route family
  `shop/:categoryId/:itemId`) rather than `catalog/…`. Mitigation: confirm via
  `/openapi.json` + `frontend/src/api/endpoints/`; update all annotation paths and
  test assertions consistently. Guarded by T-1..T-5.
- **R-2 Pagination contract.** `page`/`limit` vs `offset`/`limit` vs
  `cursor`/`limit`, and bare-array vs enveloped responses, are unconfirmed.
  Mitigation: match the live contract; if cursor-based, `listItems`/`searchCatalog`
  take `@Query("cursor") cursor: String?` and the envelope exposes `next_cursor`
  (already modeled). Guarded by T-3/T-5.
- **R-3 Item summary vs detail divergence.** The list/grid item shape may differ
  from the detail shape (e.g. detail-only fields). Modeled as separate
  `ItemSummaryDto`/`ItemDetailDto`; if identical, collapse during implementation.
- **R-4 Money representation.** Backend may send a decimal string (`"19.99"`) or
  float rather than `amount_minor`. Mitigation: confirm via OpenAPI; if decimal
  string, `PriceDto` keeps `amount` as `String` and parsing to minor units moves to
  the domain layer (no float). Guarded by the money-fidelity test.
- **R-5 Attributes shape.** `attributes` may be structured rather than
  `Map<String,String>`. Mitigation: confirm; switch to `List<AttributeDto>` if so.
- **Q-1** Exact path prefix + pagination param names? *Proposed:* `catalog/…` with
  `page`/`limit`; confirm against `/openapi.json`/web reference before coding.
- **Q-2** Is search's envelope identical to item-list's? *Proposed:* keep both;
  collapse `SearchResultDto` into `ItemPageDto` if identical.
- **Q-3** Are `ItemDetailDto.attributes` flat key/value or structured? *Proposed:*
  flat `Map<String,String>`; revisit per OpenAPI.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Catalog DTOs (`CategoryDto`, `CategoryListDto`, `PriceDto`,
  `MediaAssetDto`, `ItemSummaryDto`, `ItemDetailDto`, `ItemPageDto`,
  `SearchResultDto`) exist in `com.testlogon.android.core.model.catalog` as
  immutable `@JsonClass(generateAdapter=true)` data classes.
- **AC-2 (backlog).** Catalog + item payloads **map (tested)**: every documented
  payload in Sections 4–5 (de)serializes the documented JSON exactly, proven by
  `CatalogDtoRoundTripTest` against committed fixtures (parsed-tree equality,
  snake_case keys verified).
- **AC-3.** `CatalogApi` declares all five operations (`listCategories`,
  `getCategory`, `listItems`, `getItem`, `searchCatalog`); the module compiles
  against the catalog DTOs.
- **AC-4.** Each endpoint is callable and its **verb + resolved path + query
  params** match Section 5, asserted with MockWebServer (T-1..T-5), including
  `listItems` paging query and URL-encoded `searchCatalog` `q`.
- **AC-5.** Required-field absence (e.g. `id`, `amount_minor`) throws
  `JsonDataException`; unknown JSON keys are tolerated; empty collections default to
  `emptyList()`/`emptyMap()`.
- **AC-6.** Money is lossless: `amount_minor` decodes to `Long` and survives
  round-trip with no float drift.
- **AC-7.** Non-2xx (e.g. `404` from `getItem`) surfaces as `HttpException` and is
  not swallowed (T-6).
- **AC-8.** `CatalogApi` is Hilt-provided as a `@Singleton` built on the shared
  `Retrofit`; repeated injection yields the same instance; no new
  `OkHttpClient`/`Retrofit`/`Moshi` is constructed and no per-method cookie/CSRF
  headers are declared (T-7).
- **AC-9.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no new lint/detekt regressions.

## 15. Definition of Done

- DTOs (`com.testlogon.android.core.model.catalog`) and `CatalogApi` +
  `CatalogApiModule` (`com.testlogon.android.core.network.catalog[.di]`) are
  implemented under `core-model`/`core-network`, package base
  `com.testlogon.android`; no DTOs redefined elsewhere.
- Open questions Q-1/Q-2/Q-3 (and risks R-1/R-2/R-4/R-5) are resolved against
  `/openapi.json` and the web reference, and the interface paths/query params and
  DTO shapes reflect the confirmed contract.
- `CatalogDtoRoundTripTest` (with committed fixtures under
  `core-model/src/test/resources/catalog/`) and the MockWebServer tests T-1..T-7
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
