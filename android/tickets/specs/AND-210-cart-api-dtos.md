---
id: AND-210
title: Cart API + DTOs
milestone: M5
epic: E29
priority: P0
size: M
status: draft
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
`CartApi`, call a cart endpoint, receive a typed `ApiResult<CartDto>`, and map it
to a `Cart` domain object with field-for-field fidelity proven by tests.

Success is measured by: every cart endpoint in the OpenAPI spec is callable with
the correct verb/path/body; every field in the cart payload round-trips through
Moshi without loss; and the DTO→domain mapper is exhaustively unit-tested,
including the FastAPI `detail` error union and empty/partial payloads.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. New code lands in `core-network` (API + DTOs) and `core-model`
  (domain types), following the `app -> feature-* -> core-*` layering.
- **Namespace:** `com.testlogon.android`. Cart networking lives in
  `com.testlogon.android.core.network.cart`; DTOs in
  `com.testlogon.android.core.network.cart.dto`; domain models in
  `com.testlogon.android.core.model.cart`.
- **Web reference:** `frontend/src/api/endpoints/cart.ts` (endpoint surface) and
  `frontend/src/api/types.ts` (shared `Cart`, `CartItem`, `Money` types). These
  are authoritative for field names and nullability.
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

FR-1. Provide a Retrofit interface `CartApi` exposing the cart endpoints:
get current cart, add item, update item quantity, remove item, and clear cart.
The exact surface is reconciled against `cart.ts` / `/openapi.json`; the working
set is in §5.

FR-2. Every endpoint returns a typed result usable as `ApiResult<T>`. The
service declares `suspend` functions returning Retrofit `Response<...>` (or the
project's `ApiResult` adapter from AND-027); the resilience layer maps HTTP/IO
outcomes to `ApiResult.Success | ApiResult.Error`.

FR-3. Define Moshi DTOs covering the full cart payload: cart envelope, line
items, money/price fields, and totals. All wire field names are bound with
`@Json(name = ...)` to the backend's snake_case names; Kotlin properties use
camelCase.

FR-4. Provide pure mapper functions `CartDto.toDomain(): Cart` (and nested
`CartItemDto.toDomain()`, `MoneyDto.toDomain()`) producing `core-model` types.
Mapping is total: nullable/absent wire fields map to documented defaults
(empty list, zero money, etc.) rather than throwing.

FR-5. Mutations send the `X-CSRF-Token` header (inherited from the AND-027
interceptor) and a typed request body DTO where applicable (e.g. add/update).

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
    @GET("ui/cart")
    suspend fun getCart(): ApiResult<CartDto>

    @POST("ui/cart/items")
    suspend fun addItem(@Body body: AddCartItemRequest): ApiResult<CartDto>

    @PATCH("ui/cart/items/{itemId}")
    suspend fun updateItem(
        @Path("itemId") itemId: String,
        @Body body: UpdateCartItemRequest,
    ): ApiResult<CartDto>

    @DELETE("ui/cart/items/{itemId}")
    suspend fun removeItem(@Path("itemId") itemId: String): ApiResult<CartDto>

    @DELETE("ui/cart")
    suspend fun clearCart(): ApiResult<CartDto>
}
```

`ApiResult<T>` is the call adapter / sealed result from AND-027. If the project
adapter is not yet wired for cart, the interface may instead return
`Response<CartDto>` and the repository (downstream) wraps it; the chosen form
must match whatever AND-027 standardized. Mutations return the updated `CartDto`
so callers always have authoritative server state.

**DTOs (Moshi, `@JsonClass(generateAdapter = true)`).**

```kotlin
package com.testlogon.android.core.network.cart.dto

@JsonClass(generateAdapter = true)
data class CartDto(
    @Json(name = "id") val id: String?,
    @Json(name = "items") val items: List<CartItemDto>?,
    @Json(name = "subtotal") val subtotal: MoneyDto?,
    @Json(name = "tax") val tax: MoneyDto?,
    @Json(name = "shipping") val shipping: MoneyDto?,
    @Json(name = "total") val total: MoneyDto?,
    @Json(name = "currency") val currency: String?,
    @Json(name = "item_count") val itemCount: Int?,
    @Json(name = "updated_at") val updatedAt: String?,
)

@JsonClass(generateAdapter = true)
data class CartItemDto(
    @Json(name = "id") val id: String?,
    @Json(name = "product_id") val productId: String?,
    @Json(name = "name") val name: String?,
    @Json(name = "image_url") val imageUrl: String?,
    @Json(name = "unit_price") val unitPrice: MoneyDto?,
    @Json(name = "quantity") val quantity: Int?,
    @Json(name = "line_total") val lineTotal: MoneyDto?,
)

@JsonClass(generateAdapter = true)
data class MoneyDto(
    @Json(name = "amount_cents") val amountCents: Long?,
    @Json(name = "currency") val currency: String?,
)

@JsonClass(generateAdapter = true)
data class AddCartItemRequest(
    @Json(name = "product_id") val productId: String,
    @Json(name = "quantity") val quantity: Int,
)

@JsonClass(generateAdapter = true)
data class UpdateCartItemRequest(
    @Json(name = "quantity") val quantity: Int,
)
```

All response fields are nullable because the dev backend is unreliable and may
return partial payloads; the mapper enforces invariants, not the parser.

**Domain models (`core-model`).**

```kotlin
package com.testlogon.android.core.model.cart

data class Cart(
    val id: String,
    val items: List<CartItem>,
    val subtotal: Money,
    val tax: Money,
    val shipping: Money,
    val total: Money,
    val itemCount: Int,
) {
    companion object { val EMPTY = Cart("", emptyList(), Money.ZERO, Money.ZERO, Money.ZERO, Money.ZERO, 0) }
}

data class CartItem(
    val id: String,
    val productId: String,
    val name: String,
    val imageUrl: String?,
    val unitPrice: Money,
    val quantity: Int,
    val lineTotal: Money,
)

data class Money(val amountCents: Long, val currency: String) {
    companion object { val ZERO = Money(0L, "USD") }
}
```

**Mappers (pure functions, `core-network`).**

```kotlin
fun CartDto.toDomain(): Cart = Cart(
    id = id.orEmpty(),
    items = items.orEmpty().map { it.toDomain() },
    subtotal = subtotal.toDomainMoney(currency),
    tax = tax.toDomainMoney(currency),
    shipping = shipping.toDomainMoney(currency),
    total = total.toDomainMoney(currency),
    itemCount = itemCount ?: items.orEmpty().sumOf { it.quantity ?: 0 },
)

fun CartItemDto.toDomain(): CartItem = CartItem(
    id = id.orEmpty(),
    productId = productId.orEmpty(),
    name = name.orEmpty(),
    imageUrl = imageUrl?.takeIf { it.isNotBlank() },
    unitPrice = unitPrice.toDomainMoney(null),
    quantity = quantity ?: 0,
    lineTotal = lineTotal.toDomainMoney(null),
)

private fun MoneyDto?.toDomainMoney(fallbackCurrency: String?): Money =
    Money(this?.amountCents ?: 0L, this?.currency ?: fallbackCurrency ?: "USD")
```

The mapper is the single source of truth for default values and is the primary
test target (§11).

## 5. API Contract

Base URL: `http://18.222.237.167:8000/`. All cart endpoints are
cookie-authenticated; mutations require the `X-CSRF-Token` header (added by the
shared interceptor). Reconcile names/paths with `/openapi.json` before merge.

**GET `/ui/cart`** → 200, the current session's cart:

```json
{
  "id": "cart_8f1c",
  "currency": "USD",
  "item_count": 3,
  "items": [
    {
      "id": "li_01",
      "product_id": "prod_42",
      "name": "Demo Widget",
      "image_url": "https://.../widget.png",
      "unit_price": { "amount_cents": 1999, "currency": "USD" },
      "quantity": 2,
      "line_total": { "amount_cents": 3998, "currency": "USD" }
    }
  ],
  "subtotal": { "amount_cents": 3998, "currency": "USD" },
  "tax":      { "amount_cents": 320,  "currency": "USD" },
  "shipping": { "amount_cents": 0,    "currency": "USD" },
  "total":    { "amount_cents": 4318, "currency": "USD" },
  "updated_at": "2026-06-05T12:00:00Z"
}
```

**POST `/ui/cart/items`** — body `{"product_id":"prod_42","quantity":1}` → 200
with the updated cart (same shape as GET).

**PATCH `/ui/cart/items/{itemId}`** — body `{"quantity":3}` → 200 updated cart.
Quantity 0 behavior (remove vs reject) is an open question (§13).

**DELETE `/ui/cart/items/{itemId}`** → 200 updated cart.

**DELETE `/ui/cart`** → 200 empty cart (`items: []`, zeroed totals).

**Error union (FastAPI `detail`).** Errors decode via the shared error parser
from AND-027, which handles the three `detail` forms:

```json
{ "detail": "Item not found" }
{ "detail": [ { "loc": ["body","quantity"], "msg": "ensure this value is >= 1", "type": "value_error" } ] }
{ "detail": { "code": "OUT_OF_STOCK", "message": "Only 1 left" } }
```

Common statuses: 401 (triggers single refresh+retry), 404 (unknown item),
422 (validation), 409 (stock conflict). AND-210 does not re-implement this
parser; it relies on AND-027's `ApiResult.Error` carrying the mapped message/code.

## 6. Data & State Management

This ticket produces **wire DTOs and domain models only**. It introduces no
StateFlow, no ViewModel, and no `UiState`. The DTO→domain boundary is the
contribution to state management: consumers downstream hold `Cart` (never
`CartDto`) in their state.

Persistence is explicitly out of scope. Room caching of the cart and DataStore
prefs are owned by the downstream cart-repository ticket in M5/E29. The domain
`Cart`/`CartItem`/`Money` types defined here are designed to be Room-entity-
mappable later (flat primitives, no platform types), but no `@Entity`, DAO, or
DataStore key is added in AND-210.

`Money` uses integer `amountCents: Long` to avoid floating-point currency error;
all arithmetic downstream operates on cents. `Cart.EMPTY` and `Money.ZERO`
provide deterministic empty state for offline/initial rendering downstream.

## 7. Error Handling & Resilience

- **Timeouts:** inherited 20s connect/read/write from the shared OkHttp client
  (AND-026). AND-210 sets none of its own.
- **Retry policy:** `getCart()` is idempotent and eligible for the shared bounded
  backoff retry (max ~2 retries, jittered) configured for GETs. All mutations
  (`addItem`, `updateItem`, `removeItem`, `clearCart`) are **never retried**
  automatically to avoid duplicate cart operations; failures surface as
  `ApiResult.Error` for the caller to retry explicitly.
- **401 handling:** the AND-027 authenticator performs one `POST /ui/session/refresh`
  then replays the original cart request once; AND-210 inherits this and adds
  nothing.
- **Mapping robustness:** because all DTO fields are nullable, malformed/partial
  JSON never throws in the parser. `toDomain()` substitutes documented defaults
  (`Money.ZERO`, empty list, derived `itemCount`). A null/blank `image_url` maps
  to `null`, not an empty string, so Coil downstream shows a placeholder.
- **IO/parse failures:** mapped by the shared call adapter to
  `ApiResult.Error(IoFailure | ParseFailure | Http(status, detail))`.

## 8. Security & Privacy

- Auth is cookie-based; the persistent cookie jar and `ui_csrf`→`X-CSRF-Token`
  echo are provided by AND-027/AND-026. Cart mutations carry the CSRF header
  automatically. AND-210 must verify (via MockWebServer in §11) that mutation
  requests include `X-CSRF-Token`.
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
- `getCart` issues `GET /ui/cart`; asserts method and path via `RecordedRequest`.
- `addItem` issues `POST /ui/cart/items` with body
  `{"product_id":"prod_42","quantity":1}`; assert JSON body and that
  `X-CSRF-Token` header is present (using the shared client config).
- `updateItem` issues `PATCH /ui/cart/items/li_01` with `{"quantity":3}`.
- `removeItem` issues `DELETE /ui/cart/items/li_01`.
- `clearCart` issues `DELETE /ui/cart`.
- Enqueue the §5 sample 200 body; assert it parses into `CartDto` and that
  `toDomain()` yields the expected `Cart`.
- Enqueue 404/422/409 with each `detail` shape; assert `ApiResult.Error` carries
  the expected message/code via the shared error parser.

**B. `CartMapperTest` (pure).** Validates `toDomain()` exhaustively — this is the
ticket's "Cart payload maps (tested)" acceptance.
- Full payload → all fields equal expected (the load-bearing round-trip test).
- `items: null` and `items: []` → `Cart.items == emptyList()`.
- Missing `item_count` → derived from summed item quantities.
- Null `MoneyDto` fields → `Money.ZERO` with correct currency fallback chain
  (item currency → cart currency → `"USD"`).
- Blank/null `image_url` → `CartItem.imageUrl == null`.
- Empty-cart payload (DELETE `/ui/cart` response) → equals `Cart.EMPTY` semantics
  (empty items, zeroed totals).

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

- **Contract drift vs `/openapi.json`:** the §5 field names (`amount_cents`,
  `unit_price`, `line_total`, `item_count`) are inferred from the web reference;
  the live OpenAPI may differ (e.g. money as a flat decimal string instead of a
  cents object, or paths under `/ui/cart` vs `/cart`). **Action:** verify against
  `/openapi.json` and `frontend/src/api/types.ts` before merge and adjust DTOs.
- **Money representation:** if the backend returns decimal strings/floats rather
  than integer cents, `MoneyDto.amountCents` and the mapper must convert (parse
  decimal → cents) carefully to avoid rounding error. Resolve during verification.
- **PATCH quantity = 0 semantics:** does the backend treat quantity 0 as remove,
  or 422? Affects whether the UI uses PATCH-to-0 or DELETE. Document the answer.
- **Verb support:** confirm the dev backend honors `PATCH` (some proxies don't);
  fallback may be `POST /ui/cart/items/{itemId}`.
- **`ApiResult` vs `Response` return type:** must match exactly what AND-027
  standardized; if AND-027 returns `Response<T>`, mirror it here.

## 14. Acceptance Criteria

AC-1. `CartApi` exposes `getCart`, `addItem`, `updateItem`, `removeItem`,
`clearCart` with paths/verbs/bodies matching the contract (§5), verified by
`CartApiTest` against MockWebServer (`RecordedRequest` assertions).

AC-2. The §5 GET payload deserializes into `CartDto` with no Moshi errors and no
field loss.

AC-3. **Cart payload maps (tested):** `CartDto.toDomain()` produces a `Cart`
equal to the expected fixture for the full payload, and `CartMapperTest` covers
null/empty/partial/empty-cart cases per §11-B.

AC-4. Mutation requests include the `X-CSRF-Token` header (asserted in test).

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
