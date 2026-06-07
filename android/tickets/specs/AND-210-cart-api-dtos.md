---
id: AND-210
title: Cart API + DTOs
milestone: M5
epic: E29
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: []
---

# AND-210 — Cart API + DTOs

## 1. Overview & Goal

This ticket delivers the network contract for the shopping cart: a Retrofit
`CartApi` service interface, the Moshi-backed DTOs that model the FastAPI cart
payloads, and the mapping layer that converts those DTOs into `core-model`
domain types. The scope mirrors the web reference layer `frontend/src/api/endpoints/cart.ts`
plus the cart-related shapes in `frontend/src/api/types.ts`, ported to Kotlin.

The deliverable is a *data-access* slice only. It owns the endpoint definitions,
the wire DTOs, the DTO→domain mappers, and their unit tests. It does **not**
include the cart repository, ViewModel, Compose UI, or Room caching — those are
owned by downstream tickets in milestone M5 / epic E29 (cart repository and
cart screen tickets). The goal is that, on completion, any consumer can inject
`CartApi`, call a cart endpoint, receive a typed `ApiResult<T>`, and map the
wire DTOs into domain objects with field-for-field fidelity proven by tests.

**Contract correction (verified 2026-06-06).** The original draft assumed a single
"current cart" endpoint at `/ui/cart` returning a self-contained envelope with
nested `Money` objects (`subtotal`/`tax`/`shipping`/`total`) and item-level
`unit_price`/`line_total` money objects. The authoritative backend
(OpenAPI + `frontend/src/api/endpoints/cart.ts`) is materially different and the
spec is corrected throughout:
- Cart endpoints live under `/ui/shoppingcart/carts` (not `/ui/cart`).
- Carts are an explicit, multi-cart resource: there is **no** "get current cart".
  `POST /ui/shoppingcart/carts` creates a cart (returns `ShoppingCartSummary`);
  `GET /ui/shoppingcart/carts` lists summaries; items are fetched separately via
  `GET /ui/shoppingcart/carts/{cart_id}/items` (`ShoppingCartItemsOut`).
- Items are keyed by **`sku`**, not an opaque `itemId`/line-item `id`.
- **There is no `Money` object and no `tax`/`shipping`/`subtotal` fields.** All
  monetary values are flat integer cents: `unit_price_cents`, `line_total_cents`,
  `total_cents`, `purchased_total_cents`. The cart total is its own endpoint
  (`GET .../{cart_id}/total` → `ShoppingCartTotalOut`).
- `addItem` returns the single added item (`ShoppingCartItemOut`), not the whole
  cart; `removeItem` and `deleteCart` return `{ "ok": true }` (`OkResp`), not a
  cart.

Success is measured by: every cart endpoint above is callable with the correct
verb/path/body; every wire field round-trips through Moshi without loss; and the
DTO→domain mappers are exhaustively unit-tested, including the FastAPI `detail`
error union and empty/partial payloads.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. New code lands in `core-network` (API + DTOs) and `core-model`
  (domain types), following the `app -> feature-* -> core-*` layering.
- **Namespace:** `com.testlogon.android`. Cart networking lives in
  `com.testlogon.android.core.network.cart`; DTOs in
  `com.testlogon.android.core.network.cart.dto`; domain models in
  `com.testlogon.android.core.model.cart`.
- **Web reference:** `frontend/src/api/endpoints/cart.ts` (endpoint surface) and
  `frontend/src/api/types.ts` (`CartSummary`, `CartItem`, `CartItemIn`,
  `CartItemsResp`, `CartTotal`, `OkResp`). These are authoritative for field names
  and nullability. (Note: there is no `Cart` envelope type and no `Money` type in
  the reference; prices are flat `*_cents` integers — see §1 contract correction.)
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json`. Confirm exact paths,
  request bodies, and response schemas against the live spec before finalizing
  DTO field names; the JSON shapes in §5 are the working contract and must be
  reconciled with `/openapi.json` (see §13).
- **Upstream dependency — AND-027 (AuthApi):** establishes the Retrofit/OkHttp/
  Moshi stack, the persistent cookie jar, the `X-CSRF-Token` header interceptor,
  the 401→`/ui/session/refresh`→retry behavior, and the shared `ApiResult<T>`
  type. AND-210 reuses that `Retrofit` instance and `Moshi` instance verbatim;
  it must not construct its own OkHttp client. Cart calls are authenticated and
  ride the same cookie session.
- **Backend traits:** FastAPI + DynamoDB at a plaintext, unreliable dev host.
  Design for ~20s timeouts and bounded retry on idempotent GETs only (mutations
  are not retried). See §7.

## 3. Functional Requirements

FR-1. Provide a Retrofit interface `CartApi` exposing the cart endpoints
(verified against `cart.ts` / OpenAPI): create cart, list carts, get cart items,
get cart total, add item, update item quantity, remove item, and delete cart.
(There is no "get current cart" single envelope endpoint; the caller creates or
selects a `cart_id` and fetches items/total separately.) The working set is in §5.

FR-2. Every endpoint returns a typed result usable as `ApiResult<T>`. The
service declares `suspend` functions returning Retrofit `Response<...>` (or the
project's `ApiResult` adapter from AND-027); the resilience layer maps HTTP/IO
outcomes to `ApiResult.Success | ApiResult.Error`.

FR-3. Define Moshi DTOs covering the cart payloads: cart summary, line items
(with flat `*_cents` integer prices — no nested money object), the items response
wrapper, and the cart total. All wire field names are bound with
`@Json(name = ...)` to the backend's snake_case names; Kotlin properties use
camelCase.

FR-4. Provide pure mapper functions `CartItemDto.toDomain(): CartItem`,
`CartSummaryDto.toDomain(): CartSummary`, `CartItemsRespDto.toDomain(): Cart`
(combining a summary's id with items), and `CartTotalDto.toDomain(): CartTotal`,
producing `core-model` types. Mapping is total: nullable/absent wire fields map to
documented defaults (empty list, zero cents, etc.) rather than throwing.

FR-5. Mutations send the `X-CSRF-Token` header (inherited from the AND-027
interceptor) and a typed request body DTO where applicable (`AddCartItemRequest`
for add, `UpdateCartItemQtyRequest` for quantity update). Note the web client
attaches `X-CSRF-Token` to *all* requests (from the `ui_csrf` cookie), not only
mutations — see `src/api/client.ts`.

FR-6. The DTO/mapper layer compiles in `core-network`/`core-model` with no
dependency on Compose, Hilt UI scopes, or Android framework classes (pure
Kotlin/Moshi/Retrofit), so it is unit-testable on the JVM.

## 4. Technical Design

**Module placement.** `CartApi` and DTOs go in `core-network`; domain types in
`core-model`; mappers in `core-network` (they depend on both). A Hilt provider
in `core-network`'s networking module exposes `CartApi`:

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object CartNetworkModule {
    @Provides @Singleton
    fun provideCartApi(retrofit: Retrofit): CartApi =
        retrofit.create(CartApi::class.java)
}
```

The injected `Retrofit` is the singleton built in AND-026/AND-027 (cookie jar,
CSRF interceptor, Moshi converter, 20s timeouts). AND-210 adds no client config.

**Service interface.**

```kotlin
package com.testlogon.android.core.network.cart

interface CartApi {
    @POST("ui/shoppingcart/carts")
    suspend fun createCart(): ApiResult<CartSummaryDto>

    @GET("ui/shoppingcart/carts")
    suspend fun getCarts(): ApiResult<List<CartSummaryDto>>

    @GET("ui/shoppingcart/carts/{cartId}/items")
    suspend fun getCartItems(@Path("cartId") cartId: String): ApiResult<CartItemsRespDto>

    @GET("ui/shoppingcart/carts/{cartId}/total")
    suspend fun getCartTotal(@Path("cartId") cartId: String): ApiResult<CartTotalDto>

    @POST("ui/shoppingcart/carts/{cartId}/items")
    suspend fun addItem(
        @Path("cartId") cartId: String,
        @Body body: AddCartItemRequest,
    ): ApiResult<CartItemDto>

    @PATCH("ui/shoppingcart/carts/{cartId}/items/{sku}")
    suspend fun updateItemQty(
        @Path("cartId") cartId: String,
        @Path("sku") sku: String,
        @Body body: UpdateCartItemQtyRequest,
    ): ApiResult<CartItemDto>

    @DELETE("ui/shoppingcart/carts/{cartId}/items/{sku}")
    suspend fun removeItem(
        @Path("cartId") cartId: String,
        @Path("sku") sku: String,
        @Query("decrement") decrement: Boolean? = null,
    ): ApiResult<OkRespDto>

    @DELETE("ui/shoppingcart/carts/{cartId}")
    suspend fun deleteCart(@Path("cartId") cartId: String): ApiResult<OkRespDto>
}
```

`ApiResult<T>` is the call adapter / sealed result from AND-027. If the project
adapter is not yet wired for cart, the interface may instead return
`Response<T>` and the repository (downstream) wraps it; the chosen form must
match whatever AND-027 standardized. Note: unlike the original draft's assumption,
mutations do **not** return the full updated cart — `addItem`/`updateItemQty`
return the affected `CartItemDto`, and `removeItem`/`deleteCart` return
`OkRespDto`. Callers needing authoritative cart state after a mutation must
re-fetch via `getCartItems` / `getCartTotal`.

**DTOs (Moshi, `@JsonClass(generateAdapter = true)`).**

```kotlin
package com.testlogon.android.core.network.cart.dto

// ShoppingCartSummary
@JsonClass(generateAdapter = true)
data class CartSummaryDto(
    @Json(name = "cart_id") val cartId: String?,
    @Json(name = "status") val status: String?,
    @Json(name = "created_at") val createdAt: String?,
    @Json(name = "currency") val currency: String?,
    @Json(name = "purchased_at") val purchasedAt: String?,
    @Json(name = "purchased_total_cents") val purchasedTotalCents: Long?,
    // SHOP-003 abandonment tracking (epoch seconds)
    @Json(name = "last_activity_at") val lastActivityAt: Long?,
    @Json(name = "abandoned_at") val abandonedAt: Long?,
    @Json(name = "reminder_count") val reminderCount: Int?,
)

// ShoppingCartItemOut — note flat *_cents integers, no nested money object
@JsonClass(generateAdapter = true)
data class CartItemDto(
    @Json(name = "sku") val sku: String?,
    @Json(name = "name") val name: String?,
    @Json(name = "quantity") val quantity: Int?,
    @Json(name = "unit_price_cents") val unitPriceCents: Long?,
    @Json(name = "line_total_cents") val lineTotalCents: Long?,
    @Json(name = "updated_at") val updatedAt: String?,
    @Json(name = "image_url") val imageUrl: String?,
    @Json(name = "category_id") val categoryId: String?,
    @Json(name = "item_id") val itemId: String?,
)

// ShoppingCartItemsOut
@JsonClass(generateAdapter = true)
data class CartItemsRespDto(
    @Json(name = "cart_id") val cartId: String?,
    @Json(name = "items") val items: List<CartItemDto>?,
)

// ShoppingCartTotalOut
@JsonClass(generateAdapter = true)
data class CartTotalDto(
    @Json(name = "cart_id") val cartId: String?,
    @Json(name = "total_cents") val totalCents: Long?,
    @Json(name = "currency") val currency: String?,
)

@JsonClass(generateAdapter = true)
data class OkRespDto(
    @Json(name = "ok") val ok: Boolean?,
)

// ShoppingCartItemIn — required: sku, name, unit_price_cents. quantity defaults
// to 1 server-side (min 1, max 1000). Optional product fields omitted for brevity.
@JsonClass(generateAdapter = true)
data class AddCartItemRequest(
    @Json(name = "sku") val sku: String,
    @Json(name = "name") val name: String,
    @Json(name = "unit_price_cents") val unitPriceCents: Long,
    @Json(name = "quantity") val quantity: Int? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "category_id") val categoryId: String? = null,
    @Json(name = "item_id") val itemId: String? = null,
)

// ShoppingCartUpdateQtyIn — quantity min 0 (0 is valid, max 1000)
@JsonClass(generateAdapter = true)
data class UpdateCartItemQtyRequest(
    @Json(name = "quantity") val quantity: Int,
)
```

All *response* fields are nullable because the dev backend is unreliable and may
return partial payloads; the mapper enforces invariants, not the parser. Request
DTOs make server-required fields (`sku`, `name`, `unit_price_cents`, `quantity`
for update) non-nullable.

**Domain models (`core-model`).**

```kotlin
package com.testlogon.android.core.model.cart

// The backend has no cart "envelope"; Cart is an Android-side aggregate composed
// from a cart id + its items. Totals come from the separate CartTotal endpoint
// (the backend exposes only a single total_cents — no tax/shipping/subtotal).
data class Cart(
    val id: String,
    val items: List<CartItem>,
    val currency: String,
) {
    val itemCount: Int get() = items.sumOf { it.quantity }
    val subtotalCents: Long get() = items.sumOf { it.lineTotalCents }
    companion object { val EMPTY = Cart("", emptyList(), "USD") }
}

data class CartItem(
    val sku: String,
    val name: String,
    val quantity: Int,
    val unitPriceCents: Long,
    val lineTotalCents: Long,
    val imageUrl: String?,
    val categoryId: String?,
    val itemId: String?,
)

// Authoritative server-computed total (GET .../{cart_id}/total).
data class CartTotal(
    val cartId: String,
    val totalCents: Long,
    val currency: String,
)

// Cart status/lifecycle metadata (POST/GET .../carts).
data class CartSummary(
    val cartId: String,
    val status: String,
    val createdAt: String,
    val currency: String,
)
```

**Mappers (pure functions, `core-network`).**

```kotlin
fun CartItemsRespDto.toDomain(currency: String = "USD"): Cart = Cart(
    id = cartId.orEmpty(),
    items = items.orEmpty().map { it.toDomain() },
    currency = currency,
)

fun CartItemDto.toDomain(): CartItem = CartItem(
    sku = sku.orEmpty(),
    name = name.orEmpty(),
    quantity = quantity ?: 0,
    unitPriceCents = unitPriceCents ?: 0L,
    lineTotalCents = lineTotalCents ?: (unitPriceCents ?: 0L) * (quantity ?: 0),
    imageUrl = imageUrl?.takeIf { it.isNotBlank() },
    categoryId = categoryId?.takeIf { it.isNotBlank() },
    itemId = itemId?.takeIf { it.isNotBlank() },
)

fun CartTotalDto.toDomain(): CartTotal = CartTotal(
    cartId = cartId.orEmpty(),
    totalCents = totalCents ?: 0L,
    currency = currency ?: "USD",
)

fun CartSummaryDto.toDomain(): CartSummary = CartSummary(
    cartId = cartId.orEmpty(),
    status = status.orEmpty(),
    createdAt = createdAt.orEmpty(),
    currency = currency ?: "USD",
)
```

The mapper is the single source of truth for default values and is the primary
test target (§11).

## 5. API Contract

Base URL: `http://18.222.237.167:8000/`. All cart endpoints are authenticated;
the web client sends a Bearer `Authorization` token from the auth store **and**
the `X-CSRF-Token` header (from the `ui_csrf` cookie) plus session cookies
(`credentials: include`) on every request. The shared AND-027 client config owns
these. Paths and shapes below are verified against the OpenAPI index/spec and
`frontend/src/api/endpoints/cart.ts`.

**POST `/ui/shoppingcart/carts`** (`ui_start_cart`) → 200 `ShoppingCartSummary`:

```json
{ "cart_id": "cart_8f1c", "status": "open", "created_at": "2026-06-05T12:00:00Z", "currency": "USD" }
```

**GET `/ui/shoppingcart/carts`** (`ui_list_carts`) → 200 array of
`ShoppingCartSummary` (the response schema is unannotated in the index but the
frontend types it `CartSummary[]`).

**GET `/ui/shoppingcart/carts/{cart_id}/items`** (`ui_list_items`) → 200
`ShoppingCartItemsOut`. Item prices are flat integer cents — no nested money:

```json
{
  "cart_id": "cart_8f1c",
  "items": [
    {
      "sku": "sku_42",
      "name": "Demo Widget",
      "quantity": 2,
      "unit_price_cents": 1999,
      "line_total_cents": 3998,
      "updated_at": "2026-06-05T12:00:00Z",
      "image_url": "https://.../widget.png",
      "category_id": "cat_1",
      "item_id": "prod_42"
    }
  ]
}
```

**GET `/ui/shoppingcart/carts/{cart_id}/total`** (`ui_cart_total`) → 200
`ShoppingCartTotalOut`: `{ "cart_id": "cart_8f1c", "total_cents": 4318, "currency": "USD" }`.
This is the only server-provided total; there are no separate tax/shipping/subtotal
fields anywhere in the API.

**POST `/ui/shoppingcart/carts/{cart_id}/items`** (`ui_add_item`, req
`ShoppingCartItemIn`) — body must include `sku`, `name`, `unit_price_cents`
(required); `quantity` optional (default 1, min 1, max 1000). → 200 the added
`ShoppingCartItemOut` (the single item, **not** the whole cart):

```json
{ "sku": "sku_42", "name": "Demo Widget", "quantity": 1, "unit_price_cents": 1999, "line_total_cents": 1999, "updated_at": "2026-06-05T12:00:00Z" }
```

**PATCH `/ui/shoppingcart/carts/{cart_id}/items/{sku}`** (`ui_update_item_quantity`,
req `ShoppingCartUpdateQtyIn`) — body `{"quantity":3}` → 200. The OpenAPI declares
`quantity` **minimum 0** (max 1000), so `quantity: 0` is schema-valid (the backend
treats 0 as a remove/zero-out; see §13). The frontend `updateCartItemQty` types
the response as `CartItem`, but the index response schema is unannotated — treat
as `CartItemOut` and re-fetch items if the full cart is needed.

**DELETE `/ui/shoppingcart/carts/{cart_id}/items/{sku}`** (`ui_remove_item`) —
optional query param `decrement` (when true, decrements quantity by one instead of
removing the line). → 200 `{ "ok": true }` (`OkResp`).

**DELETE `/ui/shoppingcart/carts/{cart_id}`** (`ui_delete_cart`) → 200
`{ "ok": true }` (`OkResp`). This deletes the cart resource; it does not return an
emptied cart envelope.

**Error union (FastAPI `detail`).** Errors decode via the shared error parser
from AND-027. The web client's `normalizeErrorDetail` (`src/api/client.ts`)
handles three `detail` forms:

```json
{ "detail": "Item not found" }
{ "detail": [ { "loc": ["body","quantity"], "msg": "ensure this value is >= 1", "type": "value_error" } ] }
{ "detail": { "code": "OUT_OF_STOCK", "message": "Only 1 left" } }
```

Common statuses on cart endpoints (per OpenAPI index): 422 (validation,
`HTTPValidationError`), 400, 401 (triggers single refresh+retry), 403
(permission/geo-block; note `detail.code == "geo_blocked"` and the
`role_required*` codes mapped by `mapAuthorizationError` in `client.ts`), and 429
(rate limit). The index does **not** declare a 409 on cart endpoints; the
"stock conflict" 409 in the original draft is unverified — treat any
domain-specific conflict as the object-form `detail` (e.g. `{"code":...}`) if it
occurs. AND-210 does not re-implement this parser; it relies on AND-027's
`ApiResult.Error` carrying the mapped message/code.

## 6. Data & State Management

This ticket produces **wire DTOs and domain models only**. It introduces no
StateFlow, no ViewModel, and no `UiState`. The DTO→domain boundary is the
contribution to state management: consumers downstream hold domain types
(`Cart`/`CartItem`/`CartTotal`/`CartSummary`), never the wire `*Dto` types.

Persistence is explicitly out of scope. Room caching of the cart and DataStore
prefs are owned by the downstream cart-repository ticket in M5/E29. The domain
`Cart`/`CartItem`/`Money` types defined here are designed to be Room-entity-
mappable later (flat primitives, no platform types), but no `@Entity`, DAO, or
DataStore key is added in AND-210.

Monetary values use integer `*Cents: Long` fields (the backend's native
representation) to avoid floating-point currency error; all arithmetic downstream
operates on cents. `Cart.EMPTY` provides deterministic empty state for
offline/initial rendering downstream.

## 7. Error Handling & Resilience

- **Timeouts:** inherited 20s connect/read/write from the shared OkHttp client
  (AND-026). AND-210 sets none of its own.
- **Retry policy:** the GET reads (`getCarts`, `getCartItems`, `getCartTotal`) are
  idempotent and eligible for the shared bounded backoff retry (max ~2 retries,
  jittered) configured for GETs. All mutations (`createCart`, `addItem`,
  `updateItemQty`, `removeItem`, `deleteCart`) are **never retried** automatically
  to avoid duplicate cart operations; failures surface as `ApiResult.Error` for
  the caller to retry explicitly. (Note: `removeItem` with `decrement=true` is
  especially non-idempotent.)
- **401 handling:** the AND-027 authenticator performs one `POST /ui/session/refresh`
  then replays the original cart request once; AND-210 inherits this and adds
  nothing.
- **Mapping robustness:** because all response DTO fields are nullable,
  malformed/partial JSON never throws in the parser. `toDomain()` substitutes
  documented defaults (zero cents, empty list, derived `lineTotalCents` from
  `unitPriceCents * quantity` when absent). A null/blank `image_url` maps to
  `null`, not an empty string, so Coil downstream shows a placeholder.
- **IO/parse failures:** mapped by the shared call adapter to
  `ApiResult.Error(IoFailure | ParseFailure | Http(status, detail))`.

## 8. Security & Privacy

- Auth combines a Bearer `Authorization` token (from the auth store) with
  session cookies and a `ui_csrf`→`X-CSRF-Token` echo, all provided by
  AND-027/AND-026 (`src/api/client.ts`). The web client attaches `X-CSRF-Token`
  to **every** request (not just mutations); AND-210 must verify (via MockWebServer
  in §11) that cart requests carry `X-CSRF-Token` (and that mutations in
  particular do). The 403 path also carries permission/geo-block codes
  (`role_required*`, `geo_blocked`) that the shared parser maps to user messages.
- **Plaintext transport:** the dev host is HTTP. The cart contains no card/PAN
  data (this is a demo backend), but cart contents and product IDs are user
  data. The HTTP cleartext permit is a dev-only manifest concession owned by the
  networking ticket; AND-210 adds no new cleartext exception.
- No secrets or tokens are logged. DTOs are not logged at body level in release
  builds (see §10).
- No PII beyond session cookie is stored by this slice (no persistence here).

## 9. Accessibility & i18n

No UI in this ticket, so screen-reader/contrast/touch-target requirements are
N/A and owned by the downstream cart-screen ticket (M5/E29).

i18n-relevant contribution: `Money` retains a `currency` code and integer cents,
enabling correct locale-aware formatting downstream (e.g. `NumberFormat
.getCurrencyInstance`). The mapper preserves the server `currency` and only
falls back to `"USD"` when absent. No user-facing strings are introduced; server
error messages pass through `ApiResult.Error` for downstream presentation.

## 10. Telemetry & Logging

- Use the project's OkHttp `HttpLoggingInterceptor` at `BODY` level in debug and
  `NONE`/`BASIC` in release (configured by the networking ticket; AND-210 relies
  on it). Cart payloads are not separately logged.
- Mapper failures or unexpected nulls in critical fields (e.g. missing `id` on a
  non-empty cart) may emit a single `Timber.w` tag `CartMapper` to aid dev
  debugging; no values that constitute user data are included beyond counts.
- No analytics events are emitted from this layer; cart analytics (add-to-cart,
  remove) are owned downstream where user intent is known.

## 11. Testing Strategy

All tests are JVM unit tests in `core-network`'s test source set (no
instrumentation). Two suites:

**A. `CartApiTest` (MockWebServer).** Validates the wire contract.
- `createCart` issues `POST /ui/shoppingcart/carts`; asserts method/path.
- `getCarts` issues `GET /ui/shoppingcart/carts`; parses a `List<CartSummaryDto>`.
- `getCartItems` issues `GET /ui/shoppingcart/carts/cart_8f1c/items`.
- `getCartTotal` issues `GET /ui/shoppingcart/carts/cart_8f1c/total`.
- `addItem` issues `POST /ui/shoppingcart/carts/cart_8f1c/items` with body
  `{"sku":"sku_42","name":"Demo Widget","unit_price_cents":1999,"quantity":1}`;
  assert JSON body and that `X-CSRF-Token` header is present (shared client config).
- `updateItemQty` issues `PATCH /ui/shoppingcart/carts/cart_8f1c/items/sku_42`
  with `{"quantity":3}` (and a separate case with `{"quantity":0}`).
- `removeItem` issues `DELETE /ui/shoppingcart/carts/cart_8f1c/items/sku_42`; a
  variant with `decrement=true` asserts the `?decrement=true` query.
- `deleteCart` issues `DELETE /ui/shoppingcart/carts/cart_8f1c`.
- Enqueue the §5 sample 200 bodies; assert they parse into the right DTOs and that
  the mappers yield the expected domain objects.
- Enqueue 422/404/403 with each `detail` shape; assert `ApiResult.Error` carries
  the expected message/code via the shared error parser.

**B. `CartMapperTest` (pure).** Validates the `toDomain()` mappers exhaustively —
this is the ticket's "Cart payload maps (tested)" acceptance.
- Full `ShoppingCartItemsOut` payload → `Cart` with all item fields equal expected
  (the load-bearing round-trip test).
- `items: null` and `items: []` → `Cart.items == emptyList()` and derived
  `itemCount == 0`, `subtotalCents == 0`.
- Missing `line_total_cents` on an item → derived as `unit_price_cents * quantity`.
- Null `unit_price_cents`/`quantity` → default to `0`.
- Blank/null `image_url`/`category_id`/`item_id` → mapped to `null`.
- `CartTotalDto` with null `total_cents`/`currency` → `0L` / `"USD"`.
- `CartSummaryDto` round-trip including null `currency` → `"USD"` fallback.

Test fixtures: JSON strings in `src/test/resources` mirroring §5. Use the shared
`core-testing` Moshi instance to guarantee adapter parity with production.
Target: 100% of mapper branches covered.

## 12. Dependencies & Sequencing

- **Depends on AND-027 (AuthApi, P0):** provides the Retrofit/Moshi/OkHttp
  singletons, cookie jar, CSRF interceptor, 401-refresh authenticator,
  `ApiResult<T>`, and the FastAPI `detail` error parser. AND-210 cannot be
  built or tested without these. Transitively depends on AND-026 (network core).
- **Blocks (downstream, M5/E29):** the cart **repository** ticket (consumes
  `CartApi` + mappers, adds Room cache + StateFlow), the cart **screen/UI**
  ticket (Compose, a11y, i18n formatting), and any checkout ticket that reads
  `Cart`. These own the sections marked N/A above. Keep the AND-### references in
  those downstream specs pointing back to AND-210 for the contract.
- **Sequencing:** land after AND-027 is merged on `android-port`; merge before
  the cart repository ticket starts.

## 13. Risks & Open Questions

- **Contract drift (RESOLVED 2026-06-06):** the original §5 paths (`/ui/cart`) and
  shapes (nested `Money`, `subtotal`/`tax`/`shipping`/`total`, `item_count`) were
  wrong. Verified against the OpenAPI index and `cart.ts`: paths are under
  `/ui/shoppingcart/carts`, items are keyed by `sku`, and prices are flat
  `*_cents` integers. The spec has been corrected throughout (see §1, §4, §5, §16).
- **Money representation (RESOLVED):** the backend uses integer cents fields
  (`unit_price_cents`, `line_total_cents`, `total_cents`) — no decimal strings or
  float conversion is needed. Mappers carry cents through as `Long`.
- **PATCH quantity = 0 semantics (PARTIALLY RESOLVED):** `ShoppingCartUpdateQtyIn`
  declares `quantity` minimum 0 (not 1), so `quantity: 0` is schema-valid and is
  **not** a 422. The backend presumably zeroes/removes the line; the exact
  remove-vs-keep-at-0 behavior is not specified in the OpenAPI and remains an
  observable-behavior open question to confirm against the live host (§16 open
  assumptions). A dedicated `DELETE .../items/{sku}` (optionally `decrement=true`)
  exists for explicit removal.
- **Verb support:** `PATCH` is the documented verb for quantity updates
  (`ui_update_item_quantity`); confirm the plaintext dev proxy honors `PATCH`
  end-to-end (some proxies strip it). No `POST` fallback exists in the API — if
  `PATCH` is blocked in the dev environment it must be raised with backend.
- **`ApiResult` vs `Response` return type:** must match exactly what AND-027
  standardized; if AND-027 returns `Response<T>`, mirror it here.

## 14. Acceptance Criteria

AC-1. `CartApi` exposes `createCart`, `getCarts`, `getCartItems`, `getCartTotal`,
`addItem`, `updateItemQty`, `removeItem`, `deleteCart` with paths/verbs/bodies
matching the contract (§5), verified by `CartApiTest` against MockWebServer
(`RecordedRequest` assertions).

AC-2. The §5 `ShoppingCartItemsOut`, `ShoppingCartTotalOut`, and
`ShoppingCartSummary` payloads deserialize into their DTOs with no Moshi errors
and no field loss.

AC-3. **Cart payload maps (tested):** `CartItemsRespDto.toDomain()` produces a
`Cart` equal to the expected fixture for the full items payload, and
`CartMapperTest` covers null/empty/partial cases (and `CartTotal`/`CartSummary`
mappers) per §11-B.

AC-4. Cart requests include the `X-CSRF-Token` header, and mutation requests in
particular (asserted in test).

AC-5. The three FastAPI `detail` error shapes (string / array / object) map to
`ApiResult.Error` via the shared parser (asserted in test).

AC-6. The code resides in `com.testlogon.android.core.network.cart(.dto)` and
`com.testlogon.android.core.model.cart`, has no Compose/Android-framework deps,
and compiles under Kotlin 2.0.21 / KSP-generated Moshi adapters.

## 15. Definition of Done

- `CartApi`, all DTOs, domain models, and mappers implemented in the specified
  packages; Hilt `CartNetworkModule` provides `CartApi` from the shared Retrofit.
- `CartApiTest` and `CartMapperTest` written and green; mapper branch coverage
  ~100%.
- DTO field names and endpoint paths reconciled against `/openapi.json` and
  `frontend/src/api/types.ts`; any deltas from §5 applied and noted in the PR.
- No new OkHttp client, timeout, interceptor, or cleartext exception introduced
  (reuses AND-026/AND-027).
- `./gradlew :core-network:test :core-model:test` passes; ktlint/detekt clean.
- PR on `android-port` reviewed and merged; downstream cart-repository ticket
  unblocked, with its spec referencing AND-210 as the contract owner.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.
OpenAPI pointers reference `reference/openapi.index.txt` (line entries) and
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend pointers
reference `reference/src/...`.

1. **Cart endpoints are under `/ui/shoppingcart/carts`, not `/ui/cart`.**
   VERDICT: Corrected. SOURCE: OpenAPI `POST /ui/shoppingcart/carts`
   (`ui_start_cart`), `GET /ui/shoppingcart/carts` (`ui_list_carts`);
   `src/api/endpoints/cart.ts: createCart, getCarts`.
2. **There is no "get current cart" single-envelope endpoint; carts are listed and
   items fetched separately.** VERDICT: Corrected. SOURCE: OpenAPI
   `GET /ui/shoppingcart/carts/{cart_id}/items` (`ui_list_items`, resp
   `ShoppingCartItemsOut`); `src/api/endpoints/cart.ts: getCarts, getCartItems`
   (no "current cart" call exists).
3. **`POST /ui/shoppingcart/carts/{cart_id}/items` adds an item; req
   `ShoppingCartItemIn`; resp `ShoppingCartItemOut` (single item).** VERDICT:
   Corrected (was `POST /ui/cart/items` returning the whole cart). SOURCE: OpenAPI
   `POST /ui/shoppingcart/carts/{cart_id}/items` (`ui_add_item`);
   `src/api/endpoints/cart.ts: addCartItem` returns `CartItem`.
4. **`ShoppingCartItemIn` required fields are `sku`, `name`, `unit_price_cents`
   (not `product_id`/`quantity`); `quantity` defaults to 1 (min 1, max 1000).**
   VERDICT: Corrected. SOURCE: `components.schemas.ShoppingCartItemIn` (`required:
   [sku, name, unit_price_cents]`, `quantity` default 1); `src/api/types.ts:
   CartItemIn`.
5. **Quantity update is `PATCH /ui/shoppingcart/carts/{cart_id}/items/{sku}`, req
   `ShoppingCartUpdateQtyIn` `{quantity}`.** VERDICT: Corrected (was
   `PATCH /ui/cart/items/{itemId}`; key is `sku`, not `itemId`). SOURCE: OpenAPI
   `PATCH .../items/{sku}` (`ui_update_item_quantity`);
   `src/api/endpoints/cart.ts: updateCartItemQty(cartId, sku, quantity)`.
6. **`ShoppingCartUpdateQtyIn.quantity` minimum is 0 (so `quantity: 0` is
   schema-valid, not 422).** VERDICT: Corrected (draft listed quantity-0 as an
   open "remove vs reject"). SOURCE: `components.schemas.ShoppingCartUpdateQtyIn`
   (`minimum: 0`, `maximum: 1000`).
7. **Item removal is `DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}` with an
   optional `decrement` query param; resp `OkResp` (`{ok}`).** VERDICT: Corrected
   (was `DELETE /ui/cart/items/{itemId}` returning a cart). SOURCE: OpenAPI
   `DELETE .../items/{sku}` (`ui_remove_item`, params include `decrement`);
   `src/api/endpoints/cart.ts: removeCartItem` returns `OkResp`;
   `src/api/types.ts: OkResp = {ok: boolean}`.
8. **Cart deletion ("clear") is `DELETE /ui/shoppingcart/carts/{cart_id}`; resp
   `OkResp`.** VERDICT: Corrected (was `DELETE /ui/cart` returning an emptied
   cart). SOURCE: OpenAPI `DELETE /ui/shoppingcart/carts/{cart_id}`
   (`ui_delete_cart`); `src/api/endpoints/cart.ts: deleteCart`.
9. **All monetary values are flat integer cents (`unit_price_cents`,
   `line_total_cents`, `total_cents`, `purchased_total_cents`); there is NO `Money`
   object and NO `tax`/`shipping`/`subtotal` fields.** VERDICT: Corrected (draft
   modeled nested `MoneyDto` and tax/shipping/subtotal/total money objects).
   SOURCE: `components.schemas.ShoppingCartItemOut` (`unit_price_cents`,
   `line_total_cents` as `integer`), `ShoppingCartTotalOut` (`total_cents`);
   `src/api/types.ts: CartItem, CartTotal` (no money type defined anywhere).
10. **`ShoppingCartItemOut` required fields: `sku, name, quantity,
    unit_price_cents, line_total_cents, updated_at`; `image_url`, `category_id`,
    `item_id` optional.** VERDICT: Verified. SOURCE:
    `components.schemas.ShoppingCartItemOut.required`; `src/api/types.ts: CartItem`.
11. **The cart total is a dedicated endpoint
    `GET /ui/shoppingcart/carts/{cart_id}/total` → `ShoppingCartTotalOut`
    `{cart_id, total_cents, currency}`.** VERDICT: Verified (added; the draft had
    no total endpoint). SOURCE: OpenAPI `GET .../total` (`ui_cart_total`);
    `components.schemas.ShoppingCartTotalOut`; `src/api/endpoints/cart.ts:
    getCartTotal`.
12. **`ShoppingCartSummary` shape: `cart_id, status, created_at, currency
    (default USD)` plus optional `purchased_*` and abandonment fields.** VERDICT:
    Verified. SOURCE: `components.schemas.ShoppingCartSummary`; `src/api/types.ts:
    CartSummary`.
13. **Auth is Bearer token + session cookies + `X-CSRF-Token` from the `ui_csrf`
    cookie, sent on ALL requests (not only mutations).** VERDICT: Corrected (draft
    said cookie-only and CSRF on mutations only). SOURCE: `src/api/client.ts`
    (sets `Authorization: Bearer`, `X-CSRF-Token` from `getCookie("ui_csrf")`,
    `credentials: "include"` unconditionally).
14. **401 handling: one `POST /ui/session/refresh` then a single retry of the
    original request.** VERDICT: Verified. SOURCE: `src/api/client.ts`
    (`refreshSession()` → retry once).
15. **FastAPI `detail` has three forms (string / validation array / object) mapped
    by the shared parser.** VERDICT: Verified. SOURCE: `src/api/client.ts:
    normalizeErrorDetail` (string, array-of-`{msg}`, object via
    `mapAuthorizationError`); `components.schemas.HTTPValidationError`.
16. **Documented cart error statuses are 400/401/403/422/429 (no 409 declared).**
    VERDICT: Corrected (draft asserted a 409 stock-conflict). SOURCE: OpenAPI cart
    rows `resp=...;422:HTTPValidationError;400;401;403;429` (no 409 listed).
17. **403 may carry `geo_blocked` and `role_required*` permission codes.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (403 branch + `mapAuthorizationError`).
18. **Module placement / namespace (`core.network.cart(.dto)`,
    `core.model.cart`), Hilt `CartNetworkModule`, Kotlin 2.0.21 + KSP Moshi.**
    VERDICT: Unverified-assumption (project-internal convention; no source in the
    provided references). Framework ref for Moshi codegen:
    https://github.com/square/moshi#codegen.
19. **Retrofit `@PATCH`/`@DELETE`/`@Query`/`@Path`/`@Body` usage.** VERDICT:
    Verified (framework ref): https://square.github.io/retrofit/.
20. **The reused Retrofit/OkHttp/cookie-jar/CSRF-interceptor/`ApiResult<T>` come
    from AND-027/AND-026.** VERDICT: Unverified-assumption (cross-ticket
    dependency; AND-027 spec not in the provided sources). Consistent with the
    web client's transport behavior in `src/api/client.ts`.

### Corrections made

- Endpoint base path `/ui/cart*` → `/ui/shoppingcart/carts*` throughout (§1, §4, §5, §11, §14).
- Removed the fictional single "get current cart" envelope; added `createCart`,
  `getCarts`, `getCartItems`, `getCartTotal` and reframed `Cart` as an
  Android-side aggregate (§1, §3, §4).
- Item key `id`/`itemId` → `sku` (path params, DTOs, mappers, tests).
- Removed nested `MoneyDto` and `subtotal`/`tax`/`shipping`/`total` money objects;
  replaced with flat `*_cents: Long` fields and a separate `CartTotal` (§4, §5, §6, §11).
- `AddCartItemRequest` corrected to `{sku, name, unit_price_cents, quantity?, ...}`
  (was `{product_id, quantity}`); `UpdateCartItemQtyRequest` documented as
  `quantity` min 0.
- Mutation responses corrected: add/update return a single item, remove/delete
  return `OkResp` (not the whole cart); §4 notes the re-fetch requirement.
- CSRF: clarified `X-CSRF-Token` is sent on all requests, plus Bearer auth (§5, §8).
- Removed the unverified 409 stock-conflict claim; aligned error statuses to the
  documented 400/401/403/422/429 (§5).
- Resolved §13 open questions for money representation and quantity-0 schema validity.

### Open assumptions

- **Quantity-0 runtime behavior:** the schema allows `quantity: 0`, but whether the
  backend removes the line or keeps a zero-quantity line is not specified in the
  OpenAPI and must be confirmed against the live host (not derivable from the
  provided sources).
- **`PATCH` reachability through the plaintext dev proxy:** the verb is documented,
  but proxy support is environmental and cannot be verified from the references.
- **Module/package layout, Hilt wiring, Kotlin/KSP versions:** Android-project
  conventions not present in the provided reference material.
- **AND-027/AND-026 internals** (`ApiResult<T>`, cookie jar, interceptors, refresh
  authenticator, timeouts): assumed from the dependency; those ticket specs are not
  in the provided sources. The web client (`src/api/client.ts`) corroborates the
  intended transport behavior only.
- **`GET /ui/shoppingcart/carts` response schema:** the index leaves `resp=200:`
  unannotated; typed as `CartSummary[]` from `src/api/endpoints/cart.ts: getCarts`.

## 17. Test Plan

All cases are JVM-only by nature (this is a pure data-access slice with no UI,
hardware, or permissions). They run on the **JVM unit/Robolectric** target; none
require the emulator `test35` or the physical Samsung Galaxy A15 (SM-A156U), since
there is no camera, biometric, FCM, WebRTC, Telecom, streaming, or ABI-sensitive
code in scope. The emulator/device note is recorded per case for completeness.

| ID | Type | Target |
|----|------|--------|
| TC-AND-210-01 | contract/MockWebServer | JVM unit |
| TC-AND-210-02 | contract/MockWebServer | JVM unit |
| TC-AND-210-03 | contract/MockWebServer | JVM unit |
| TC-AND-210-04 | contract/MockWebServer | JVM unit |
| TC-AND-210-05 | contract/MockWebServer | JVM unit |
| TC-AND-210-06 | contract/MockWebServer | JVM unit |
| TC-AND-210-07 | contract/MockWebServer | JVM unit |
| TC-AND-210-08 | unit (mapper) | JVM unit |
| TC-AND-210-09 | unit (mapper) | JVM unit |
| TC-AND-210-10 | unit (mapper) | JVM unit |
| TC-AND-210-11 | contract/MockWebServer | JVM unit |
| TC-AND-210-12 | contract/MockWebServer | JVM unit |

**TC-AND-210-01 — Read endpoints issue correct verb/path.**
Type: contract/MockWebServer. Target: JVM unit (no device).
Preconditions: `CartApi` built on the shared Retrofit pointed at MockWebServer;
queue 200 bodies. Steps: call `createCart()`, `getCarts()`,
`getCartItems("cart_8f1c")`, `getCartTotal("cart_8f1c")`; capture each
`RecordedRequest`. Expected: requests are `POST /ui/shoppingcart/carts`,
`GET /ui/shoppingcart/carts`, `GET /ui/shoppingcart/carts/cart_8f1c/items`,
`GET /ui/shoppingcart/carts/cart_8f1c/total` respectively. Traces: AC-1.

**TC-AND-210-02 — `addItem` sends correct path and JSON body.**
Type: contract/MockWebServer. Target: JVM unit. Preconditions: queue a 200
`ShoppingCartItemOut`. Steps: call
`addItem("cart_8f1c", AddCartItemRequest(sku="sku_42", name="Demo Widget", unitPriceCents=1999, quantity=1))`.
Expected: `POST /ui/shoppingcart/carts/cart_8f1c/items` with JSON body containing
`sku`, `name`, `unit_price_cents`, `quantity` (snake_case) and no `product_id`;
response parses to `CartItemDto` with `unitPriceCents == 1999`. Traces: AC-1, AC-2.

**TC-AND-210-03 — `updateItemQty` PATCHes the sku with `{quantity}`.**
Type: contract/MockWebServer. Target: JVM unit. Preconditions: queue 200. Steps:
call `updateItemQty("cart_8f1c", "sku_42", UpdateCartItemQtyRequest(3))`. Expected:
`PATCH /ui/shoppingcart/carts/cart_8f1c/items/sku_42`, body `{"quantity":3}`.
Traces: AC-1.

**TC-AND-210-04 — quantity 0 is sent as a valid PATCH (not rejected client-side).**
Type: contract/MockWebServer. Target: JVM unit. Preconditions: queue 200. Steps:
call `updateItemQty("cart_8f1c", "sku_42", UpdateCartItemQtyRequest(0))`. Expected:
`PATCH .../items/sku_42` with body `{"quantity":0}`; the client serializes 0
without throwing (schema min is 0). Traces: AC-1.
Note: runtime remove-vs-keep behavior is a live-host assumption (§16), not asserted here.

**TC-AND-210-05 — `removeItem` DELETEs the sku; `decrement` query honored.**
Type: contract/MockWebServer. Target: JVM unit. Preconditions: queue two 200
`{"ok":true}` bodies. Steps: call `removeItem("cart_8f1c", "sku_42")` and
`removeItem("cart_8f1c", "sku_42", decrement=true)`. Expected: first request
`DELETE /ui/shoppingcart/carts/cart_8f1c/items/sku_42` with no query; second adds
`?decrement=true`; both parse to `OkRespDto(ok=true)`. Traces: AC-1, AC-2.

**TC-AND-210-06 — `deleteCart` DELETEs the cart and parses `OkResp`.**
Type: contract/MockWebServer. Target: JVM unit. Preconditions: queue 200
`{"ok":true}`. Steps: call `deleteCart("cart_8f1c")`. Expected:
`DELETE /ui/shoppingcart/carts/cart_8f1c`; response parses to `OkRespDto(ok=true)`.
Traces: AC-1, AC-2.

**TC-AND-210-07 — Full items payload deserializes with no field loss.**
Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue the §5
`ShoppingCartItemsOut` fixture. Steps: call `getCartItems("cart_8f1c")`. Expected:
`CartItemsRespDto.cartId == "cart_8f1c"`; one `CartItemDto` with `sku=="sku_42"`,
`quantity==2`, `unitPriceCents==1999`, `lineTotalCents==3998`,
`imageUrl`/`categoryId`/`itemId` populated; no Moshi error. Traces: AC-2.

**TC-AND-210-08 — Items mapper round-trip (load-bearing).**
Type: unit (mapper). Target: JVM unit. Preconditions: a fully-populated
`CartItemsRespDto`. Steps: call `.toDomain(currency="USD")`. Expected: a `Cart`
with `id=="cart_8f1c"`, mapped items, `itemCount==2` (derived sum),
`subtotalCents==3998` (derived). Traces: AC-3.

**TC-AND-210-09 — Mapper defaults for null/empty/partial fields.**
Type: unit (mapper). Target: JVM unit. Preconditions: DTOs with `items=null`,
`items=[]`, an item missing `line_total_cents`, an item with null
`unit_price_cents`/`quantity`, and blank `image_url`/`category_id`/`item_id`.
Steps: map each. Expected: null/empty items → `Cart.items==emptyList()`,
`itemCount==0`, `subtotalCents==0`; missing `line_total_cents` →
`unitPriceCents*quantity`; null price/qty → 0; blank strings → `null`. Traces: AC-3.

**TC-AND-210-10 — `CartTotal` and `CartSummary` mappers + currency fallback.**
Type: unit (mapper). Target: JVM unit. Preconditions: `CartTotalDto` with null
`total_cents`/`currency`, and `CartSummaryDto` with null `currency`. Steps: map
both. Expected: `CartTotal.totalCents==0`, `currency=="USD"`;
`CartSummary.currency=="USD"`; other fields preserved. Traces: AC-2, AC-3.

**TC-AND-210-11 — `X-CSRF-Token` present on cart requests (security).**
Type: contract/MockWebServer. Target: JVM unit (uses the shared client config with
a seeded `ui_csrf` cookie). Preconditions: cookie jar seeded with `ui_csrf=abc123`;
queue 200s. Steps: issue a GET (`getCartItems`) and a mutation (`addItem`); inspect
`RecordedRequest` headers. Expected: both carry `X-CSRF-Token: abc123` (the web
client sends it on all requests); the mutation in particular includes it.
Traces: AC-4.

**TC-AND-210-12 — Error `detail` shapes map to `ApiResult.Error`; offline path.**
Type: contract/MockWebServer. Target: JVM unit. Preconditions: enqueue, across
sub-cases: 422 with array `detail` (`HTTPValidationError`), 404 with string
`detail`, 403 with object `detail` (`{"code":"role_required",...}`), and (offline
sub-case) a MockWebServer `SocketPolicy.DISCONNECT_AT_START` / no-response to
simulate the flaky plaintext dev host. Steps: call a cart endpoint per sub-case.
Expected: each non-2xx maps to `ApiResult.Error` with the parser-derived message
(joined `msg`s for the array form, the string for the string form, the mapped
permission message for the object form); the disconnect maps to an IO/network
error variant, never a crash or thrown parse exception. Traces: AC-5, and
resilience behavior in §7.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|----------------------------|-----------|
| AC-1 (endpoint verbs/paths/bodies) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-06 |
| AC-2 (DTO deserialization, no loss) | TC-02, TC-05, TC-06, TC-07, TC-10 |
| AC-3 (cart payload maps, tested) | TC-08, TC-09, TC-10 |
| AC-4 (`X-CSRF-Token` on requests) | TC-11 |
| AC-5 (three `detail` error shapes) | TC-12 |
| AC-6 (package placement / no Android deps / compiles) | Enforced by the fact all tests run on the JVM unit target with no Android/Compose imports (compile-time); no dedicated runtime TC. |
