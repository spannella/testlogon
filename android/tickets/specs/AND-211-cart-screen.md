---
id: AND-211
title: Cart screen
milestone: M5
epic: E29
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-210, AND-206, AND-022, AND-024, AND-018, AND-021, AND-116]
blocks: [AND-212]
---

# AND-211 — Cart screen

## 1. Overview & Goal

Build the customer-facing **shopping cart** screen for the TestLogon native
Android app. The screen reads the current cart for the authenticated session,
renders each line item (image, name, unit price, quantity, line subtotal), and
exposes the three mutating cart operations from the source scope: **add** (qty
increment), **update quantity**, and **remove**. It displays the cart
**total** (the backend exposes a single `total_cents` + `currency` via a
separate total endpoint — there is **no** server-side subtotal/tax/shipping/
discount breakdown; see Section 5 and §16) and renders a distinct **empty
state** when the cart has no items, with a call-to-action back to the catalog.

The deliverable lives in a new `:feature-cart` library module (epic E29). It
consumes the `CartApi`, Moshi DTOs, and `core-model` domain types delivered by
**AND-210**, the Coil image primitive from AND-103 (already used by AND-206 for
product imagery), and the shared `ApiResult<T>`, cookie/CSRF/401-refresh
networking stack from the core-network tickets. Add-to-cart is normally
initiated from product detail (AND-206); this screen owns quantity editing,
removal, totals, and the empty state, and is the surface that downstream cart
search (AND-212) filters.

Because mutations change server-side cart state, edits use an **optimistic
update with rollback** model so the UI feels immediate while remaining correct
against the unreliable plaintext dev backend. All non-happy states (loading,
empty, error/retry, offline-stale, per-row mutation in-flight, mutation failure)
are explicitly represented.

Success is the source-ticket acceptance: **cart edits persist and totals
update.** Concretely — changing a quantity or removing an item issues an
authenticated mutation (keyed by **`sku`**, not a `line_id`), the row and the
total reflect the new state after the mandatory items+total re-fetch, and the
change survives a screen reload (it persisted server-side); removing the last
item yields the empty state.

> **Reviewer note (2026-06-06):** This spec was drafted against an assumed
> single-cart `GET /ui/shop/cart` contract that does **not** exist. The real
> backend is a **multi-cart** model under `/ui/shoppingcart/carts`, items are
> keyed by **`sku`**, and there is **no combined cart object** — items, total,
> and the cart list are three separate reads. Mutations return an untyped `200`
> (not the full cart), so the client **must re-fetch** items+total after every
> mutation. All affected sections below have been corrected inline; see §16 for
> the full audit.

Out of scope (owned elsewhere): cart endpoints/DTOs and payload mapping
(AND-210), the add-to-cart mutation entry point and product media (AND-206),
within-cart item/SKU search (AND-212), and checkout/payment (a later M5/E29
ticket — this screen ends at "proceed to checkout" navigation only).

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace / applicationId base **`com.testlogon.android`**.
- Module layering: `app -> feature-cart -> core-* (core-network, core-model,
  core-ui, core-data, core-testing)`. This ticket adds a new `:feature-cart`
  Gradle library module wired into `:app` and the authenticated nav graph.
- **AND-210 (depends_on)** — provides `CartApi`, Moshi DTOs and `core-model`
  domain types. **Corrected:** the backend has no combined `CartDto`/`MoneyDto`/
  `CartTotalsDto`. The real schemas are `ShoppingCartSummary` (cart list/create),
  `ShoppingCartItemsOut` (`{cart_id, items[]}`), `ShoppingCartItemOut`
  (per-item line: `sku, name, quantity, unit_price_cents, line_total_cents,
  updated_at, image_url?, item_id?, category_id?`), `ShoppingCartTotalOut`
  (`{cart_id, total_cents, currency}`), and request `ShoppingCartUpdateQtyIn`
  (`{quantity: int, min 0, max 1000}`). Prices are flat integer `*_cents`
  fields, **not** a nested `{amount_cents, currency}` money object. This ticket
  consumes AND-210's DTOs/mappers and adds mutation methods to `CartApi` only if
  AND-210 did not already expose them (see Section 5).
- **AND-206 (depends_on)** — defines the add-to-cart contract and surfaces a
  `CartSummary`/cart-count for the app shell; this screen reads/updates the same
  cart and reuses AND-206's Coil image usage pattern (AND-103 primitive).
- **AND-022 / AND-024 (depends_on)** — Navigation-Compose host and the
  authenticated nav graph + bottom-nav skeleton this destination registers into.
- **AND-018 (depends_on)** — typed `ApiResult<T>` and the FastAPI `detail` error
  mapper (`string | [{msg}] | {code,...}`).
- **AND-021 (depends_on)** — shared Loading/Empty/Error/Offline state composables.
- **AND-116 (depends_on)** — cache/SWR repository pattern (Room 2.6) used to back
  the offline-stale cart read.
- Web reference: `src/api/endpoints/cart.ts` (AND-210's source — verified) and
  shared types `src/api/types.ts`; screen behavior in `src/pages/shop/Cart.tsx`.
  Backend OpenAPI verified against `reference/openapi.pretty.json`.
- Auth is cookie-based: session cookies + `ui_csrf` echoed as the
  `X-CSRF-Token` header; on `401` the shared authenticator does one
  `POST /ui/session/refresh` then retries. **Verified** in `src/api/client.ts`
  (`getCookie("ui_csrf")` → `X-CSRF-Token`, `credentials: "include"`, single
  `refreshSession()` on 401). The cart reads (cart list, items, total) are
  idempotent GETs and bounded-backoff retried; cart mutations (`PATCH`/`DELETE`)
  are **not** auto-retried.

## 3. Functional Requirements

FR-1. **Resolve & load cart.** On entry, resolve the active cart, then fetch
its items and total. **Corrected:** there is no single `GET /ui/shop/cart`. The
flow is: `GET /ui/shoppingcart/carts` → pick the first cart with
`status == "OPEN"` (web behavior in `Cart.tsx`); if none exists, create one via
`POST /ui/shoppingcart/carts` (returns `ShoppingCartSummary` with `cart_id`).
Then load items via `GET /ui/shoppingcart/carts/{cart_id}/items`
(`ShoppingCartItemsOut`) and the total via
`GET /ui/shoppingcart/carts/{cart_id}/total` (`ShoppingCartTotalOut`). Show a
loading state until items+total resolve. (Multi-cart selection UI is out of
scope here — pick the first OPEN cart; see §16 Open assumptions.)

FR-2. **Render lines.** For each `items[]` entry display: thumbnail (AND-103
Coil primitive, from `image_url`), item `name`, unit price
(`unit_price_cents`, locale currency), a quantity control, and the per-line
total (`line_total_cents`, locale currency). Items render in the order returned
by the backend. **Corrected:** field is `image_url` (not `thumbnail_url`) and
the per-line amount is `line_total_cents` (not a `line_subtotal` money object).

FR-3. **Update quantity.** Each line has a quantity stepper (− / value / +).
Changing quantity issues
`PATCH /ui/shoppingcart/carts/{cart_id}/items/{sku}` with `{quantity}`
(`ShoppingCartUpdateQtyIn`, server bounds `0..1000`). The change is applied
optimistically; the mutation returns an untyped `200` (**not** the full cart),
so on success the client re-fetches items+total to reconcile. On failure it
rolls back to the prior quantity and shows a typed error with Retry.
**Corrected:** path is keyed by `{sku}` under `/ui/shoppingcart/carts/{cart_id}`,
not `/ui/shop/cart/items/{lineId}`. There is **no per-line `max_quantity`** in
the contract; client-side clamp upper bound is the server max (1000) unless a
stock cap is surfaced elsewhere (see §16 Open assumptions).

FR-4. **Increment to add.** Tapping `+` on an existing line is the in-cart "add"
operation (increases quantity by one via the same PATCH). **Corrected (matches
web):** the `−` control clamps at quantity 1 (`max(1, qty-1)`) and does **not**
auto-remove; removal is a separate explicit affordance (FR-5). Decrementing
below 1 is therefore not possible via `−`.

FR-5. **Remove line.** Each line has a remove affordance (and swipe-to-dismiss)
that issues `DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}`. The endpoint
accepts an optional `decrement` query param (decrement-by-one vs. full remove);
this screen omits it for full removal. The DELETE returns `{ "ok": true }`
(`OkResp` per web; OpenAPI declares an untyped `200`), so success triggers an
items+total re-fetch. Removal is confirmed (or shown as an undoable snackbar)
and applied optimistically; on failure the line is restored and a typed error
shown.

FR-6. **Total.** A pinned total section displays the cart **total**
(`total_cents` + `currency` from the total endpoint), locale currency-formatted.
**Corrected:** the backend exposes only a single grand total — there is no
subtotal/tax/shipping/discount breakdown. The total updates by re-fetching
`/total` after every successful mutation (optimistic preview may be shown
in-flight, then reconciled to the server `total_cents`).

FR-7. **Empty state.** When the cart has zero lines (initial or after removing
the last item), render a distinct empty state (illustration/text + "Browse
catalog" action navigating to the catalog) instead of the line list/totals.

FR-8. **Checkout entry.** A primary "Proceed to checkout" button is present and
enabled only when the cart is non-empty and no mutation is in flight; tapping it
navigates to the checkout route (owned by a later ticket; this screen only
performs the navigation).

FR-9. **Per-row in-flight.** Each line shows a per-row in-flight indicator while
its mutation is pending; the row's controls are disabled during its own
mutation. Other rows remain interactive.

FR-10. **Distinct non-happy states.** Loading, empty, generic error with retry,
and offline-stale (cached cart shown with a "Showing saved cart" banner; edits
disabled while offline) are each visually distinct and never conflated.

FR-11. **State preservation.** Scroll position and any pending confirmation
survive configuration changes; the screen re-reads the authoritative cart from
the back-stack entry / repository on resume.

## 4. Technical Design

New code in a new `:feature-cart` library module under
`com.testlogon.android.feature.cart`.

### Layers

```
cart/ui/        CartScreen, CartLineRow, QuantityStepper, CartTotals,
                CartEmptyState, CartStateScaffold
cart/ui/state   CartUiState, CartUiModel, CartLineUiModel, RowMutationState
cart/vm/        CartViewModel
cart/data/      CartRepository (interface) + CartRepositoryImpl
cart/di/        CartModule (binds repository), CartNavGraph entry
```

The route is registered into AND-024's authenticated graph
(`composable(CartRoutes.CART)`, route string `"shop/cart"`).

### Repository

```kotlin
interface CartRepository {
    /** Resolve active OPEN cart (list → first OPEN, else create). */
    suspend fun resolveActiveCartId(): ApiResult<String>

    /** Idempotent GETs; bounded-backoff retried by core-network. SWR-backed.
     *  A `Cart` here is the client-composed aggregate of items + total. */
    fun observeCart(): Flow<ApiResult<Cart>>          // cache-first then network
    suspend fun refresh(): ApiResult<Cart>            // GET items + GET total, compose

    /** Non-idempotent mutations; never auto-retried. Keyed by SKU.
     *  Corrected: the mutation responses are NOT the full cart (PATCH=200 untyped,
     *  DELETE={ok:true}); the impl re-fetches items+total and returns the
     *  recomposed Cart so callers still get an authoritative aggregate. */
    suspend fun setQuantity(sku: String, quantity: Int): ApiResult<Cart>
    suspend fun removeLine(sku: String): ApiResult<Cart>
}
```

> The `Cart` aggregate is **client-composed** (items from
> `ShoppingCartItemsOut` + `total_cents`/`currency` from `ShoppingCartTotalOut`),
> because the backend has no combined cart object. AND-210 owns the mapping; if
> AND-210 only exposes raw item/total DTOs, this repository performs the
> composition.

```kotlin
class CartRepositoryImpl @Inject constructor(
    private val api: CartApi,                 // from AND-210
    private val cache: CartCacheDao,          // core-data / Room 2.6 (AND-116)
    @IoDispatcher private val io: CoroutineDispatcher,
) : CartRepository {

    // Composes items + total into a Cart aggregate; cartId resolved once and cached.
    override suspend fun refresh(): ApiResult<Cart> = withContext(io) {
        when (val id = resolveActiveCartId()) {
            is ApiResult.Failure -> cache.load()?.toDomain()
                ?.let { ApiResult.Success(it) } ?: id
            is ApiResult.Success -> {
                val cartId = id.data
                val items = api.getCartItems(cartId)
                val total = api.getCartTotal(cartId)
                when {
                    items is ApiResult.Success && total is ApiResult.Success ->
                        Cart.compose(items.data, total.data)
                            .also { cache.replace(it.toEntity()) }
                            .let { ApiResult.Success(it) }
                    else -> cache.load()?.toDomain()
                        ?.let { ApiResult.Success(it) }
                        ?: (items as? ApiResult.Failure ?: total as ApiResult.Failure)
                }
            }
        }
    }

    // PATCH returns an untyped 200 (not the cart) -> re-fetch to reconcile.
    override suspend fun setQuantity(sku: String, quantity: Int): ApiResult<Cart> =
        withContext(io) {
            val cartId = cachedCartId() ?: return@withContext resolveThenFail()
            when (api.updateLine(cartId, sku, UpdateCartLineDto(quantity))) {
                is ApiResult.Success -> refresh()      // re-read items + total
                is ApiResult.Failure -> (it as ApiResult.Failure)
            }
        }

    // DELETE returns {ok:true} (not the cart) -> re-fetch to reconcile.
    override suspend fun removeLine(sku: String): ApiResult<Cart> =
        withContext(io) {
            val cartId = cachedCartId() ?: return@withContext resolveThenFail()
            when (api.deleteLine(cartId, sku)) {
                is ApiResult.Success -> refresh()
                is ApiResult.Failure -> (it as ApiResult.Failure)
            }
        }
}
```

### ViewModel

```kotlin
@HiltViewModel
class CartViewModel @Inject constructor(
    private val repository: CartRepository,
    private val analytics: Analytics,
) : ViewModel() {

    private val _uiState = MutableStateFlow<CartUiState>(CartUiState.Loading)
    val uiState: StateFlow<CartUiState> = _uiState.asStateFlow()

    private val _events = Channel<CartEvent>(Channel.BUFFERED)
    val events: Flow<CartEvent> = _events.receiveAsFlow()

    init { load() }

    fun load() {
        viewModelScope.launch {
            _uiState.value = CartUiState.Loading
            _uiState.value = repository.refresh().toUiState()
        }
    }

    // Lines are keyed by SKU (corrected: no server line_id).
    fun onQuantityChange(sku: String, newQuantity: Int) {
        // Web clamps `−` at 1 and removes via a separate control; we mirror that.
        val current = (_uiState.value as? CartUiState.Content) ?: return
        if (newQuantity < 1) return                      // `−` floors at 1; use onRemove
        if (current.rowState(sku) is RowMutationState.InFlight) return
        val rolledBack = current
        _uiState.value = current.optimisticSetQuantity(sku, newQuantity)  // + InFlight
        viewModelScope.launch {
            when (val r = repository.setQuantity(sku, newQuantity)) {     // re-fetches inside
                is ApiResult.Success -> {
                    _uiState.value = CartUiState.Content(r.data.toUiModel())
                    analytics.log("cart_update_qty_success", "sku" to sku, "qty" to newQuantity)
                }
                is ApiResult.Failure -> {
                    _uiState.value = rolledBack.clearRow(sku)
                    analytics.log("cart_update_qty_error", "sku" to sku, "code" to r.code)
                    _events.send(CartEvent.MutationFailed(r.message) { onQuantityChange(sku, newQuantity) })
                }
            }
        }
    }

    fun onRemove(sku: String) {
        val current = (_uiState.value as? CartUiState.Content) ?: return
        val rolledBack = current
        _uiState.value = current.optimisticRemove(sku)
        viewModelScope.launch {
            when (val r = repository.removeLine(sku)) {                  // re-fetches inside
                is ApiResult.Success -> {
                    _uiState.value = r.data.toUiState()                 // may become Empty
                    analytics.log("cart_remove_success", "sku" to sku)
                }
                is ApiResult.Failure -> {
                    _uiState.value = rolledBack.clearRow(sku)
                    _events.send(CartEvent.MutationFailed(r.message) { onRemove(sku) })
                }
            }
        }
    }

    fun retry() = load()
}

sealed interface CartEvent {
    data class MutationFailed(val message: String, val retry: () -> Unit) : CartEvent
}
```

### Compose

```kotlin
@Composable
fun CartScreen(
    state: CartUiState,
    onQuantityChange: (sku: String, qty: Int) -> Unit,
    onRemove: (sku: String) -> Unit,
    onCheckout: () -> Unit,
    onBrowseCatalog: () -> Unit,
    onRetry: () -> Unit,
)
```

`CartScreen` uses a `Scaffold` with a `TopAppBar` (title "Cart") and a `bottomBar`
containing `CartTotals` + the checkout button. The body is a `LazyColumn` of
`CartLineRow`s (each with a `QuantityStepper`, line subtotal, and remove/swipe
affordance). `CartUiState.Empty` swaps the body/bottom bar for `CartEmptyState`.
`CartUiState.Loading/Error/Offline` route through the AND-021 state composables.
One-shot `CartEvent`s are collected via `LaunchedEffect` into a
`SnackbarHostState` (error + Retry; remove undo).

## 5. API Contract

DTOs are defined in **AND-210**; this ticket consumes them and adds the methods
below to `CartApi` if AND-210 did not already expose them. **All paths/fields
in this section were corrected against `reference/openapi.pretty.json` and
`src/api/endpoints/cart.ts` (see §16).** The original draft assumed a single
`GET /ui/shop/cart` returning a combined cart — that endpoint does not exist.

**Contract overview (verified):** the backend is **multi-cart** under
`/ui/shoppingcart/carts`; items are keyed by **`sku`**; reads are split into
three GETs; mutations return untyped/`ok` payloads (re-fetch required).

**List carts** — `GET /ui/shoppingcart/carts` → `200: ShoppingCartSummary[]`.
Web (`Cart.tsx`) selects the first with `status == "OPEN"`.

**Create cart** — `POST /ui/shoppingcart/carts` → `200: ShoppingCartSummary`
(`{ cart_id, status, created_at, currency, ... }`). Called when no OPEN cart.

**Get cart items** — `GET /ui/shoppingcart/carts/{cart_id}/items` →
`200: ShoppingCartItemsOut`:

```json
{
  "cart_id": "cart_abc",
  "items": [
    {
      "sku": "SKU-001",
      "name": "Example Item",
      "quantity": 2,
      "unit_price_cents": 1999,
      "line_total_cents": 3998,
      "updated_at": "2026-06-05T12:00:00Z",
      "image_url": "https://…/a.jpg",
      "item_id": "itm_001",
      "category_id": "cat_001"
    }
  ]
}
```

(Other optional `ShoppingCartItemOut` fields exist — `product_type`,
`access_mode`, `scope`, `rental_metadata`, `entitlement_template_metadata` — not
needed by this screen. There is **no** `line_id` and **no** `max_quantity`.)

**Get cart total** — `GET /ui/shoppingcart/carts/{cart_id}/total` →
`200: ShoppingCartTotalOut`:

```json
{ "cart_id": "cart_abc", "total_cents": 3998, "currency": "USD" }
```

(Single grand total only — no subtotal/tax/shipping/discount breakdown.)

**Update item quantity** — `PATCH /ui/shoppingcart/carts/{cart_id}/items/{sku}`
Request: `ShoppingCartUpdateQtyIn` = `{ "quantity": 3 }` (server bounds
`0 ≤ quantity ≤ 1000`). Response: **`200` with an untyped JSON body** (OpenAPI
`schema: {}`; web types it `CartItem` but does not consume the body — it
invalidates and re-fetches items+total). **Client must re-fetch** to reconcile.

**Remove item** — `DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}`
Optional query `decrement` (decrement-by-one vs. full removal; omit for full
removal). Response: `200` (`OkResp` `{ "ok": true }` per web). **Client must
re-fetch** items+total.

> Not used by this screen but part of the same router (do not call):
> `POST .../items` (add by free-form `CartItemIn`, owned by AND-206),
> `POST .../items/catalog` (add by `CatalogCartItemIn`),
> `POST .../{cart_id}/purchase` (checkout, later ticket),
> `DELETE /ui/shoppingcart/carts/{cart_id}` (delete entire cart),
> `GET .../carts/items/search` (within-cart search, AND-212).

Retrofit (in `:feature-cart` / AND-210's `core-network` `CartApi`):

```kotlin
interface CartApi {
    @GET("ui/shoppingcart/carts")
    suspend fun listCarts(): ApiResult<List<CartSummaryDto>>

    @POST("ui/shoppingcart/carts")
    suspend fun createCart(): ApiResult<CartSummaryDto>

    @GET("ui/shoppingcart/carts/{cartId}/items")
    suspend fun getCartItems(@Path("cartId") cartId: String): ApiResult<CartItemsDto>

    @GET("ui/shoppingcart/carts/{cartId}/total")
    suspend fun getCartTotal(@Path("cartId") cartId: String): ApiResult<CartTotalDto>

    @PATCH("ui/shoppingcart/carts/{cartId}/items/{sku}")
    suspend fun updateLine(
        @Path("cartId") cartId: String,
        @Path("sku") sku: String,
        @Body body: UpdateCartLineDto,
    ): ApiResult<Unit>          // untyped 200; body ignored, re-fetch after

    @DELETE("ui/shoppingcart/carts/{cartId}/items/{sku}")
    suspend fun deleteLine(
        @Path("cartId") cartId: String,
        @Path("sku") sku: String,
        @Query("decrement") decrement: Boolean? = null,
    ): ApiResult<Unit>          // {ok:true}; re-fetch after
}

@JsonClass(generateAdapter = true)
data class UpdateCartLineDto(val quantity: Int)   // 0..1000
```

All requests are authenticated (cookies + `X-CSRF-Token`). The `PATCH`/`DELETE`
mutations **require** the CSRF header (attached by the shared CSRF interceptor)
and are excluded from the idempotent-GET retry policy. On `401`, core-network
performs one `POST /ui/session/refresh` then retries (verified in
`src/api/client.ts`). FastAPI errors surface via the shared `detail` mapper; the
shoppingcart endpoints also return structured `detail` objects with
`{code, reason, ...}` for `400/401/403/429` (e.g. `api_key_scope_denied`,
`api_limit_exceeded`) and `HTTPValidationError` for `422`. A `404`/`400` on a
mutation (item/cart already gone) is reconciled by re-reading the cart; a `422`
(quantity out of `0..1000`) maps to a non-retryable typed message. Because
mutations return no cart body, **totals reconciliation is done by re-fetching
`/items` + `/total`**, not from the mutation response.

## 6. Data & State Management

```kotlin
sealed interface CartUiState {
    data object Loading : CartUiState
    data object Empty : CartUiState
    data class Content(
        val lines: List<CartLineUiModel>,
        val totals: TotalsUiModel,
        val mutating: Boolean = false,        // any row in flight
        val stale: Boolean = false,           // offline cached cart
    ) : CartUiState
    data class Error(val message: String, val retryable: Boolean) : CartUiState
}

data class CartLineUiModel(
    val sku: String,                          // line key (corrected: no line_id)
    val itemId: String?,                      // optional; for deep-link to product
    val name: String,
    val imageUrl: String?,                    // corrected: image_url, not thumbnail_url
    val unitPriceLabel: String,               // from unit_price_cents, locale-formatted
    val quantity: Int,
    val maxQuantity: Int? = null,             // not in contract; server cap is 1000
    val lineTotalLabel: String,               // from line_total_cents
    val row: RowMutationState = RowMutationState.Idle,
)

// Corrected: backend exposes only a single total_cents + currency.
data class TotalsUiModel(
    val grandTotalLabel: String,              // from total_cents + currency
)

sealed interface RowMutationState {
    data object Idle : RowMutationState
    data object InFlight : RowMutationState
}
```

- **SWR caching (core-data / Room 2.6, AND-116).** The whole cart is persisted as
  a single replace-on-write row set keyed by `cart_id`. `refresh()` writes through
  on success; on network failure the cached cart is returned as
  `Content(stale = true)` behind a "Showing saved cart" banner with edits
  disabled.
- **Optimistic edits.** `optimisticSetQuantity`/`optimisticRemove` mutate the
  in-memory `Content` immediately (recomputing affected line subtotal and totals
  for preview) and mark the row `InFlight`; the prior `Content` is captured for
  rollback. On success the server's authoritative cart replaces the optimistic
  state; on failure the captured state is restored. Totals shown after success
  always come from the server `totals`.
- **State retention.** No nav args. Scroll position via `rememberSaveable` within
  the back-stack entry; on process death the ViewModel re-fetches the
  authoritative cart. One-shot results (mutation failed, remove undo) go through a
  `Channel` to avoid re-emitting snackbars on recomposition/rotation.
- Currency formatting via `NumberFormat.getCurrencyInstance` using the cart-level
  `currency` (from `ShoppingCartTotalOut`/`ShoppingCartSummary`); per-item amounts
  are integer `*_cents` divided by 100 (matches web `formatCents`). **Corrected:**
  there is no nested per-amount `Money.currency` and no `item_count` field —
  the app-shell cart badge derives its count from `items.size` (sum of
  quantities if a unit count is desired).

## 7. Error Handling & Resilience

- **Timeouts.** Cart GET and all mutations use the core-network ~20s call timeout
  for the unreliable dev host.
- **Idempotent retry.** The cart GET is eligible for bounded-backoff retry.
  `PATCH`/`DELETE` are **never** auto-retried (avoids duplicate/lost edits); retry
  is user-initiated via the snackbar action only.
- **Optimistic rollback.** Every failed mutation restores the captured `Content`
  exactly (quantity and totals) and surfaces a typed error + Retry; the rest of
  the cart stays interactive.
- **Load failure.** No cache → `Error(retryable=true)` full-screen retry. With
  cache → `Content(stale=true)` + banner; edit controls disabled while stale.
- **Concurrency guard.** A row ignores re-entry while its own mutation is
  `InFlight`; the stepper/remove for that row are disabled. Distinct rows may
  mutate concurrently.
- **Stale item/cart (`404`/`400` on mutation).** Treated as "cart changed
  underneath": re-read via `refresh()` and surface a brief "Cart updated" notice
  rather than a hard error.
- **Invalid quantity (`422`).** `ShoppingCartUpdateQtyIn` bounds quantity to
  `0..1000`; out-of-range maps to `HTTPValidationError`. Rolled back, shown as a
  terminal non-retryable message. **Corrected:** there is no `409` and no
  per-line `max_quantity` in the contract; the stepper clamps to the server
  bound (1000) and floors at 1 client-side. (A true out-of-stock cap, if it
  exists, is not exposed on the cart item — see §16 Open assumptions.)
- **401.** Transparent (refresh-once interceptor). If refresh fails, maps to a
  non-retryable auth error; re-auth routing is delegated to the app shell.
- **Image failure.** Thumbnail falls back to the Coil error placeholder; never
  fails the row or screen.

## 8. Security & Privacy

- No new credentials or secrets. Session rides the existing persistent cookie
  jar; cookies and `ui_csrf`/`X-CSRF-Token` are attached by core-network and are
  never read or logged by this module.
- The cart `PATCH`/`DELETE` are state-changing and **must** carry the CSRF header;
  enforced by the shared CSRF interceptor, not re-implemented here.
- Dev backend is **plaintext HTTP**; cleartext is permitted only for the dev
  flavor via the existing network-security-config (no change here). Release builds
  target HTTPS; thumbnail loads share the same OkHttp/TLS policy.
- **Cached cart is user-scoped PII-adjacent data** (purchase intent). The Room
  cache stores line/item ids, names, quantities, and prices only — no payment
  data. The cached cart must be cleared on logout (hook into the AND-032/AND-109
  logout/de-register flow); cache lives in app-private storage.
- Logs and analytics carry only line/item ids, quantities, and aggregate counts —
  never prices tied to a user, payment data, or auth material.

## 9. Accessibility & i18n

- All user-facing strings from `feature-cart` `strings.xml` (no hardcoded text);
  pseudolocale-tested. Prices via `NumberFormat`/locale currency. Quantities and
  counts use plural-aware resources.
- The quantity stepper exposes `−`/`+` as labeled buttons with state-describing
  semantics ("Increase quantity of {name}", "Decrease quantity of {name}", value
  announced); the value control announces the current quantity. Disabled controls
  expose disabled semantics.
- Remove affordance has a clear label ("Remove {name} from cart"); swipe-to-remove
  has an accessible equivalent (the explicit remove button). Removal/undo and
  mutation errors are announced via the snackbar live region.
- Each line's content (image + name + quantity + line subtotal) is grouped with a
  merged `contentDescription`. The totals block reads as labeled key/value pairs.
- Touch targets ≥ 48dp; layouts use start/end (RTL-safe) and respect dynamic type
  without clipping (long names truncate, prices never clip). Color contrast meets
  WCAG AA in light and dark via core-ui Material 3 tokens.

## 10. Telemetry & Logging

Via the shared analytics facade (no PII / no user-tied prices):

(Keys corrected to `sku`; no `item_count`/`has_discount` fields exist in the
contract — counts are derived client-side, and there is no discount breakdown.)

- `cart_view` — { line_count, total_cents, stale, latency_ms }
- `cart_update_qty_tap` — { sku, from_qty, to_qty }
- `cart_update_qty_success` — { sku, qty }
- `cart_update_qty_error` — { sku, code, http_status }
- `cart_remove_tap` — { sku }
- `cart_remove_success` — { sku, remaining_lines }
- `cart_remove_error` — { sku, code, http_status }
- `cart_checkout_tap` — { line_count }
- `cart_load_error` — { scope: list | items | total, code, http_status, had_cache }
- `cart_empty_view` — { reason: initial | last_removed }

`Timber`/`Logger` wrapper at `DEBUG` for state transitions and optimistic
apply/rollback, `WARN`/`ERROR` for failures. Never log cookies, CSRF tokens,
request bodies with auth context, or full authenticated URLs. Latency measured
around `refresh`.

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + MockWebServer):**
- `CartRepositoryImpl.refresh` maps `CartDto`→`Cart`, replaces cache on success,
  returns the cached cart on network failure, surfaces failure when no cache.
- `setQuantity`/`removeLine` map success→updated `Cart` and failure→typed
  message; verify the mutation is issued exactly once (no retry) on a 500.
- `CartViewModel` optimistic logic: `onQuantityChange` applies the new quantity +
  recomputed line subtotal/totals immediately with the row `InFlight`, then
  reconciles to the server cart on success, and **rolls back exactly** on failure
  (Turbine sequence asserted); re-entry while `InFlight` issues one request.
- `onRemove` removes the line optimistically, transitions to `Empty` when the last
  line is removed on success, and restores the line on failure.
- `Loading→Content` on success, `→Empty` for zero lines, `→Error(retryable)` on
  transport error; offline `→Content(stale=true)` from cache.
- Currency/plural formatting across currencies and locales.

**Compose UI (`createAndroidComposeRule`):**
- Cart renders line rows (name, unit price, quantity, line subtotal) and a totals
  block matching canned JSON; `+`/`−` update the displayed quantity, line
  subtotal, and totals optimistically (assert via test tags).
- Removing the last line shows the empty state with a working "Browse catalog"
  action; checkout button disabled when empty and during mutation.
- Mutation failure rolls the row back to the prior quantity and shows the error
  snackbar with a working Retry.
- `Loading`, retryable `Error` + working Retry, and stale banner (edits disabled)
  each render with correct semantics; per-row in-flight indicator shown only on
  the mutating row.

**Instrumented integration (MockWebServer):** resolve cart via `GET .../carts`
(first OPEN), load a multi-line cart via `GET .../items` + `GET .../total`,
PATCH a quantity (untyped 200) then assert the follow-up items+total re-fetch
updates the line total and grand total, DELETE the last item (`{ok:true}`) then
re-fetch returns empty items (assert empty state), a 500-on-PATCH rollback +
Retry, a 422-on-PATCH (quantity out of `0..1000`) terminal message, a
404-on-DELETE that triggers a re-read, and a 401-then-refresh-then-200 sequence
for `GET .../items`.

Acceptance gate: automated tests proving **cart edits persist** (mutation → server
returns updated cart → reloading the screen shows the new state) and **totals
update** (quantity/remove changes the rendered totals to match the server
response).

## 12. Dependencies & Sequencing

- **Hard deps:** AND-210 (`CartApi` + DTOs + domain) must merge first; AND-206
  (cart contract / `CartSummary` cart-count surface and Coil image pattern);
  AND-022/AND-024 (nav host + authenticated graph) to host the route; AND-018
  (typed `ApiResult` + error mapper); AND-021 (state composables); AND-116
  (SWR/Room cache pattern) for offline-stale.
- **Transitive:** core-network (cookie jar, CSRF interceptor, 401-refresh
  authenticator, idempotent-GET retry from AND-009..AND-016/AND-027).
- **Blocks:** AND-212 (within-cart item/SKU search) filters the line list this
  screen renders and reuses `CartUiModel`/`CartLineUiModel`.
- **Sequencing:** (1) create `:feature-cart` module + DI + nav entry; (2) add
  `getCart`/`updateLine`/`deleteLine` to `CartApi` + `UpdateCartLineDto` if absent;
  (3) `CartRepository` + SWR cache + logout-clear hook; (4) `CartViewModel`
  optimistic/rollback state machine; (5) Compose screen, line row, stepper,
  totals, empty state; (6) tests. Checkout navigation is a stub target until the
  checkout ticket lands.

## 13. Risks & Open Questions

- **Cart endpoint shape.** ~~Unconfirmed.~~ **RESOLVED (corrected):** keyed by
  `{sku}` under `PATCH/DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}` (not
  `line_id` / `item_id`). Verified in OpenAPI + `cart.ts`.
- **Mutation response.** ~~Assumed full updated cart.~~ **RESOLVED (corrected):**
  PATCH returns an untyped `200` and DELETE returns `{ok:true}`; **neither
  returns the cart**, so the repository **must** follow every mutation with a
  `GET .../items` + `GET .../total` re-fetch (mirrors web `invalidateQueries`).
- **Totals fields.** ~~Assumed subtotal/tax/shipping/discount/grand_total.~~
  **RESOLVED (corrected):** the backend exposes only `total_cents` + `currency`
  (`ShoppingCartTotalOut`). There is no breakdown; render the single total.
- **Money shape.** ~~Assumed `{amount_cents, currency}`.~~ **RESOLVED
  (corrected):** flat integer `*_cents` fields with a cart-level `currency`; no
  nested money object.
- **Add semantics.** Source scope lists "add"; modeled as in-cart quantity
  increment via PATCH, since first-add (`POST .../items`) is owned by AND-206.
  Confirmed against `cart.ts` (`addCartItem` is a distinct endpoint). If the cart
  screen must support adding new items directly, that overlaps AND-212 (search) —
  **Open: confirm with design.**
- **Remove UX.** Web uses an explicit Trash button + a `ConfirmDialog` only for
  full-cart delete; per-item remove is immediate with a toast. This spec defaults
  to optimistic remove with an undo snackbar (richer than web). **Open: confirm
  with design** (web has no swipe-to-remove or undo).
- **Multi-cart.** **NEW (from correction):** the backend supports multiple carts
  per user; web auto-selects the first `status == "OPEN"` cart and auto-creates
  one if none exist. This screen mirrors that (no multi-cart picker). **Open:
  confirm single-active-cart UX is acceptable for v1.**
- **Concurrent stale edits.** Two rapid edits to the same line are serialized by
  the per-row in-flight guard; cross-line concurrency relies on each mutation
  returning the full cart. If the backend is not last-write-authoritative, a
  trailing `refresh` is required.
- **Dev host flakiness** makes live cart edits nondeterministic; all assertions
  use MockWebServer, not the dev host.

## 14. Acceptance Criteria

AC-1. Entering the cart resolves the active OPEN cart
(`GET /ui/shoppingcart/carts`, creating one if none), then issues
`GET /ui/shoppingcart/carts/{cart_id}/items` and
`GET /ui/shoppingcart/carts/{cart_id}/total`, and renders each item's image,
name, locale-formatted unit price (`unit_price_cents`), quantity, and line total
(`line_total_cents`), plus the single grand total (`total_cents`/`currency`).
AC-2. Changing an item quantity via the stepper issues exactly one
`PATCH /ui/shoppingcart/carts/{cart_id}/items/{sku}` with `{quantity}`, followed
by an items+total re-fetch that updates the line total and grand total, and the
change persists across a reload (**cart edits persist** + **totals update** —
primary).
AC-3. Tapping `+` increments and tapping `−` decrements; `−` floors at quantity
1 (does not auto-remove); quantity is bounded to the server max (1000). Removal
is a separate explicit affordance (AC-4).
AC-4. Removing an item issues exactly one
`DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}`, then re-fetches to remove
the row and update the total; removing the last item shows the empty state with
a working "Browse catalog" action.
AC-5. A failed mutation rolls the affected row back to its prior quantity/presence
and totals, and shows a typed error with a working Retry; mutations are never
auto-retried.
AC-6. The empty state is distinct from loading/error; the checkout button is
disabled when the cart is empty and while any mutation is in flight.
AC-7. Transport errors render a retryable error whose Retry recovers; network
failure with cache shows the cart with a "Showing saved cart" stale banner and
edits disabled.
AC-8. Per-row in-flight indicators show only on the mutating row; other rows stay
interactive; re-entry on a row already mutating issues no extra request.
AC-9. The cached cart is cleared on logout; scroll position survives rotation and
the authoritative cart is re-read on process-death restore.
AC-10. All automated tests in Section 11 pass in CI, including the persist + totals
gates and the rollback / empty / 422 / 404-re-read / 401-refresh sequences.

## 15. Definition of Done

- Cart screen implemented in a new `:feature-cart` module with nav destination
  registered in AND-024's authenticated graph; builds with Gradle 8.9 / AGP
  8.7.3, JDK 17, compileSdk/targetSdk 35, minSdk 24.
- All FRs and ACs implemented and verified; no hardcoded user-facing strings;
  plural/currency resources in place.
- Unit, Compose, and instrumented tests merged and green in CI; coverage for
  repository mapping/caching, the optimistic-update/rollback state machine,
  per-row in-flight guard, empty/stale states, and totals reconciliation.
- Lint/detekt/ktlint clean; no new cleartext exceptions beyond the existing dev
  flavor config; cached cart cleared on logout.
- Telemetry events (Section 10) emitted and verified; no secrets/PII/user-tied
  prices logged.
- Accessibility pass (TalkBack + pseudolocale + RTL) completed, including stepper
  and remove semantics.
- `CartUiModel`/`CartLineUiModel` and the cart-count surface documented for
  AND-212 (search) and the checkout ticket; any `CartApi` additions documented
  for AND-210 consumers.
- Code reviewed and merged to `android-port`; Section 13 open questions resolved
  or explicitly deferred with owners.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI = `reference/openapi.pretty.json` (+ `openapi.index.txt`); frontend =
`reference/src/...`.

1. **Cart base path is `/ui/shoppingcart/carts/...` (not `/ui/shop/cart`).**
   VERDICT: Corrected. SOURCE: OpenAPI `GET /ui/shoppingcart/carts`,
   `GET /ui/shoppingcart/carts/{cart_id}/items`; `src/api/endpoints/cart.ts:
   getCarts / getCartItems`.
2. **There is no single combined "get cart" endpoint; reads are split into
   carts-list + items + total.** VERDICT: Corrected. SOURCE: OpenAPI
   `GET /ui/shoppingcart/carts`, `GET /ui/shoppingcart/carts/{cart_id}/items`
   (`ShoppingCartItemsOut`), `GET /ui/shoppingcart/carts/{cart_id}/total`
   (`ShoppingCartTotalOut`); `src/pages/shop/Cart.tsx` (three `useQuery` calls).
3. **Backend is multi-cart; client selects first `status == "OPEN"`, else
   creates via `POST /ui/shoppingcart/carts`.** VERDICT: Corrected. SOURCE:
   `src/pages/shop/Cart.tsx` (`activeCarts = carts.filter(c => c.status ===
   "OPEN")`, auto-create effect); OpenAPI `POST /ui/shoppingcart/carts` →
   `ShoppingCartSummary`.
4. **Items are keyed by `sku` (not `line_id`/`item_id`) in mutation paths.**
   VERDICT: Corrected. SOURCE: OpenAPI
   `PATCH /ui/shoppingcart/carts/{cart_id}/items/{sku}`,
   `DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}`;
   `src/api/endpoints/cart.ts: updateCartItemQty / removeCartItem`.
5. **Update quantity uses `PATCH .../items/{sku}` with body
   `ShoppingCartUpdateQtyIn = {quantity}` bounded `0..1000`.** VERDICT:
   Corrected (path/method/body). SOURCE: OpenAPI schema `ShoppingCartUpdateQtyIn`
   (`quantity` integer, `minimum:0`, `maximum:1000`); `cart.ts: updateCartItemQty`
   (`api.patch(..., { quantity })`).
6. **PATCH returns an untyped `200` (not the full cart); the client must
   re-fetch items+total.** VERDICT: Corrected. SOURCE: OpenAPI
   `PATCH .../items/{sku}` `responses.200.content.application/json.schema = {}`;
   `src/pages/shop/Cart.tsx` (`updateQtyMutation.onSuccess` →
   `invalidateQueries(["cart-items"]/["cart-total"])`).
7. **DELETE returns `{ ok: true }` (`OkResp`), not the cart; re-fetch required.**
   VERDICT: Corrected. SOURCE: `src/api/endpoints/cart.ts: removeCartItem`
   (`api.del<OkResp>`); `src/api/types.ts: OkResp` (`{ ok: boolean }`); OpenAPI
   `DELETE .../items/{sku}` `200` untyped + `removeMutation.onSuccess` invalidates.
8. **DELETE accepts optional `decrement` query param.** VERDICT: Verified.
   SOURCE: OpenAPI `DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}`
   `params=...,decrement,...` (`openapi.index.txt` line for `ui_remove_item`).
9. **Per-item fields are `sku, name, quantity, unit_price_cents,
   line_total_cents, updated_at, image_url?, item_id?, category_id?`.** VERDICT:
   Corrected. SOURCE: OpenAPI schema `ShoppingCartItemOut` (required: `sku, name,
   quantity, unit_price_cents, line_total_cents, updated_at`);
   `src/api/types.ts: CartItem`.
10. **Image field is `image_url` (not `thumbnail_url`).** VERDICT: Corrected.
    SOURCE: `ShoppingCartItemOut.image_url`; `src/api/types.ts: CartItem.image_url`;
    `src/pages/shop/Cart.tsx` (`item.image_url`).
11. **Per-line amount is `line_total_cents` (flat int), not a `line_subtotal`
    money object.** VERDICT: Corrected. SOURCE: `ShoppingCartItemOut.line_total_cents`;
    `Cart.tsx` (`formatCents(item.line_total_cents)`).
12. **Prices are flat integer `*_cents` + a single cart-level `currency`; there
    is no `{amount_cents, currency}` money object.** VERDICT: Corrected. SOURCE:
    `ShoppingCartItemOut.unit_price_cents`, `ShoppingCartTotalOut.{total_cents,
    currency}`; `Cart.tsx: formatCents(cents, currency)`.
13. **Cart total is a single `total_cents` + `currency`; no
    subtotal/tax/shipping/discount breakdown.** VERDICT: Corrected. SOURCE:
    OpenAPI schema `ShoppingCartTotalOut` (`{cart_id, total_cents, currency}`);
    `src/api/types.ts: CartTotal`; `Cart.tsx` renders one "Total".
14. **There is no per-item `max_quantity` in the contract.** VERDICT: Corrected
    (claim removed). SOURCE: `ShoppingCartItemOut` properties (no such field);
    only server bound is `ShoppingCartUpdateQtyIn.maximum = 1000`.
15. **There is no `item_count` field on the cart.** VERDICT: Corrected. SOURCE:
    `ShoppingCartItemsOut` = `{cart_id, items[]}` only; count derived client-side.
16. **`−` clamps at quantity 1 and does NOT auto-remove; remove is a separate
    control.** VERDICT: Corrected (to match web). SOURCE: `src/pages/shop/Cart.tsx`
    (`quantity: Math.max(1, item.quantity - 1)` on `−`; separate Trash2 →
    `removeMutation`).
17. **Auth: `ui_csrf` cookie echoed as `X-CSRF-Token`; cookie-based session
    (`credentials: include`).** VERDICT: Verified. SOURCE: `src/api/client.ts`
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`,
    `credentials: "include"`).
18. **On `401`, one `POST /ui/session/refresh` then retry.** VERDICT: Verified.
    SOURCE: `src/api/client.ts: refreshSession()` (`fetch("/ui/session/refresh",
    { method: "POST" })`) + single-flight retry on 401.
19. **Error shape: FastAPI `detail` — `HTTPValidationError` for `422`, structured
    `{code, reason, ...}` for `400/401/403/429`.** VERDICT: Verified. SOURCE:
    OpenAPI schema `HTTPValidationError`; `DELETE .../items/{sku}` response
    examples (`api_key_dual_credential_conflict`, `api_key_scope_denied`,
    `api_limit_exceeded`).
20. **Checkout endpoint is `POST /ui/shoppingcart/carts/{cart_id}/purchase`
    (out of scope here; navigation only).** VERDICT: Verified. SOURCE: OpenAPI
    `POST .../{cart_id}/purchase` → `ShoppingCartPurchaseOut`; `cart.ts:
    purchaseCart`; `Cart.tsx` navigates to `/cart/checkout?cartId=...`.
21. **Optimistic-update-with-rollback model.** VERDICT: Unverified-assumption
    (Android design choice; web does NOT do optimism — it disables buttons during
    `isPending` and refetches). Acceptable as an enhancement. SOURCE: framework
    ref — Android UI guide, unidirectional data flow / `StateFlow`
    (https://developer.android.com/topic/architecture/ui-layer).
22. **Swipe-to-dismiss + undo snackbar for remove.** VERDICT:
    Unverified-assumption (web uses an immediate Trash button + toast, no swipe/
    undo). SOURCE: `src/pages/shop/Cart.tsx` (`removeMutation`, `toast.success`).
    Framework ref — Material 3 `SwipeToDismissBox`
    (https://developer.android.com/jetpack/compose/components).
23. **SWR/offline cache of the cart (Room).** VERDICT: Unverified-assumption
    (no web equivalent; relies on AND-116). SOURCE: AND-116 dependency; no
    backend/web contract involved.

### Corrections made

- §1 Overview / §3 FR-1, FR-2, FR-3, FR-5, FR-6 / §5 entire API contract / §6
  data models & currency note / §7 error cases / §10 telemetry keys / §11
  integration test / §13 risks / §14 AC-1..AC-4, AC-10: rewrote the assumed
  single-cart `GET /ui/shop/cart` contract to the real **multi-cart**
  `/ui/shoppingcart/carts` model.
- Endpoint paths/methods: `PATCH|DELETE /ui/shop/cart/items/{lineId}` →
  `PATCH|DELETE /ui/shoppingcart/carts/{cart_id}/items/{sku}`.
- Item key `line_id` → `sku` throughout (FRs, ViewModel, UI model, telemetry).
- Reads split into `GET .../carts`, `GET .../items`, `GET .../total`; added
  cart-resolution (first OPEN, else `POST .../carts`).
- Mutation responses are NOT the cart → repository now re-fetches items+total
  after every PATCH/DELETE (corrected repo/VM code and AC-2/AC-4).
- Field names: `thumbnail_url` → `image_url`; `line_subtotal` (money) →
  `line_total_cents` (int); removed `{amount_cents, currency}` money object;
  removed `max_quantity` and `item_count` (not in contract).
- Totals: removed subtotal/tax/shipping/discount/grand_total breakdown → single
  `total_cents` + `currency`.
- Error mapping: removed nonexistent `409`; quantity validation is `422`
  (`ShoppingCartUpdateQtyIn` bound `0..1000`).
- `−` behavior corrected to clamp at 1 (no auto-remove), matching web.

### Open assumptions

- **Optimistic UI + undo snackbar + swipe-to-dismiss** (audit #21, #22): not how
  the web client behaves (web is refetch-on-success, immediate remove + toast,
  no swipe/undo). Kept as deliberate native enhancements; cannot be "verified"
  against the contract — flag for design sign-off.
- **Single active cart, no multi-cart picker UI** (§13): backend supports
  multiple carts; v1 mirrors web's first-OPEN-or-create. Verifiable behavior, but
  the *product decision* to hide multi-cart is unconfirmed with design.
- **Stock cap beyond `quantity ≤ 1000`** (audit #14): the cart item carries no
  `max_quantity`/stock field; any true per-SKU stock clamp would require a
  catalog/stock read (`/ui/catalog/items/{itemId}/stock` exists but is not part
  of this screen). Unverifiable from the cart contract.
- **SWR/Room offline-stale cache** (audit #23): no web/backend contract;
  depends entirely on AND-116. Assumed available.
- **`POST /ui/session/refresh` returning before retry / cookie semantics on
  native OkHttp**: verified for the web `fetch` client; the Android core-network
  authenticator behavior is owned by AND-009..AND-027 and assumed equivalent.

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric unit; **MWS** = MockWebServer
contract; **EMU** = headless emulator AVD `test35` (x86_64, API 35); **DEV** =
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Compose-UI and
instrumented suites run on EMU unless a case needs real hardware or ABI/API-level
coverage (then DEV).

- **TC-AND-211-01** — Type: contract/MWS (JVM). Target: MWS.
  Precondition: MWS queues `GET /ui/shoppingcart/carts` → `[{cart_id:"c1",
  status:"OPEN",currency:"USD"}]`, `GET .../c1/items` → 2 items,
  `GET .../c1/total` → `{total_cents:5997,currency:"USD"}`.
  Steps: call `CartRepository.refresh()`.
  Expected: resolves cart `c1`, composes `Cart` with 2 lines + grand total
  `$59.97`; cache written; requests hit the corrected paths.
  Traces: AC-1.
- **TC-AND-211-02** — Type: contract/MWS (JVM). Target: MWS.
  Precondition: `GET .../carts` → `[]` (no OPEN cart).
  Steps: `refresh()`.
  Expected: issues `POST /ui/shoppingcart/carts`, uses returned `cart_id`, then
  loads items+total (empty). Verifies create-on-missing flow.
  Traces: AC-1.
- **TC-AND-211-03** — Type: unit (JVM, Turbine). Target: JVM.
  Precondition: `Content` with line `sku=SKU-1` qty 2; MWS PATCH → untyped `200`,
  then `GET .../items` qty 3 + `GET .../total` updated.
  Steps: `onQuantityChange("SKU-1", 3)`.
  Expected: optimistic `Content` (qty 3, row `InFlight`) emitted immediately;
  exactly one `PATCH .../items/SKU-1 {quantity:3}`; then reconciled `Content`
  from the re-fetch (line total + grand total updated); no retry.
  Traces: AC-2, AC-8.
- **TC-AND-211-04** — Type: contract/MWS (JVM). Target: MWS.
  Precondition: PATCH `200`; assert no cart body is consumed.
  Steps: `setQuantity("SKU-1", 3)`.
  Expected: after PATCH, repository issues `GET .../items` **and**
  `GET .../total` (re-fetch), returning the recomposed `Cart`. Confirms
  "mutation response is not the cart".
  Traces: AC-2.
- **TC-AND-211-05** — Type: unit (JVM, Turbine). Target: JVM.
  Precondition: `Content` 1 line; MWS DELETE → `{ok:true}`, then `GET .../items`
  → empty, `GET .../total` → `0`.
  Steps: `onRemove("SKU-1")`.
  Expected: optimistic remove → `Empty`; exactly one
  `DELETE .../items/SKU-1`; reconciled to `Empty` after re-fetch.
  Traces: AC-4.
- **TC-AND-211-06** — Type: unit (JVM, Turbine). Target: JVM.
  Precondition: `Content` qty 2; MWS PATCH → `500`.
  Steps: `onQuantityChange("SKU-1", 3)`.
  Expected: optimistic qty 3 then **exact rollback** to qty 2 + prior total;
  `CartEvent.MutationFailed` with working retry; the PATCH is issued **once**
  (no auto-retry).
  Traces: AC-5.
- **TC-AND-211-07** — Type: contract/MWS (JVM). Target: MWS.
  Precondition: MWS PATCH → `422` with `HTTPValidationError` (quantity > 1000).
  Steps: `setQuantity("SKU-1", 5000)`.
  Expected: `ApiResult.Failure` mapped to a terminal non-retryable typed message
  via the shared `detail` mapper; no re-fetch loop; stepper bound respected.
  Traces: AC-5.
- **TC-AND-211-08** — Type: contract/MWS (JVM). Target: MWS.
  Precondition: MWS DELETE → `404`/`400` (item gone), then `GET .../items`
  succeeds without that item.
  Steps: `removeLine("SKU-1")`.
  Expected: treated as "cart changed underneath" → triggers `refresh()`,
  surfaces a soft "Cart updated" notice (not a hard error); state reconciles.
  Traces: AC-4, AC-5.
- **TC-AND-211-09** — Type: contract/MWS (JVM). Target: MWS.
  Precondition: `GET .../c1/items` → `401`, queued `POST /ui/session/refresh` →
  `200`, retried `GET .../c1/items` → `200`.
  Steps: `refresh()`.
  Expected: one transparent refresh then retry succeeds; `Content` rendered;
  `X-CSRF-Token` present on the request.
  Traces: AC-1, AC-7.
- **TC-AND-211-10** — Type: Compose-UI (EMU). Target: EMU.
  Precondition: canned multi-line `Content`.
  Steps: render `CartScreen`; assert rows (name, unit price, qty, line total) +
  grand total; tap `+`/`−` (assert optimistic qty/line-total/total via test
  tags); assert checkout enabled.
  Expected: rows and total match canned data; stepper updates optimistically;
  `−` floors at 1.
  Traces: AC-1, AC-2, AC-3.
- **TC-AND-211-11** — Type: Compose-UI (EMU). Target: EMU.
  Precondition: single-line `Content`; mutation wired to fail.
  Steps: remove the last line (success path) → assert empty state + working
  "Browse catalog"; separately, a failed PATCH → assert row rolls back + error
  snackbar with working Retry; checkout disabled while mutating and when empty.
  Expected: empty state distinct from loading/error; rollback + retry work.
  Traces: AC-4, AC-5, AC-6.
- **TC-AND-211-12** — Type: Compose-UI (EMU). Target: EMU.
  Precondition: states `Loading`, retryable `Error`, `Content(stale=true)`,
  and a per-row `InFlight`.
  Steps: render each; assert distinct semantics; Retry on `Error` recovers; stale
  banner "Showing saved cart" shown with edit controls disabled; in-flight
  indicator only on the mutating row, other rows interactive.
  Expected: all four states visually/semantically distinct; guards hold.
  Traces: AC-7, AC-8.
- **TC-AND-211-13** — Type: instrumented/e2e (EMU). Target: EMU.
  Precondition: MWS-backed full flow on device-under-test; rotate mid-flow;
  simulate process death.
  Steps: load cart, edit a qty, rotate (assert scroll/qty preserved), kill+restore
  process (assert authoritative re-fetch), then log out.
  Expected: scroll/pending state survive rotation; authoritative cart re-read on
  restart; cached cart cleared on logout (no stale cart after re-login).
  Traces: AC-9.
- **TC-AND-211-14** — Type: instrumented/e2e accessibility (DEV — physical
  device). Target: DEV (SM-A156U, API 34, arm64-v8a).
  Precondition: real TalkBack enabled on the physical device; pseudolocale +
  RTL configs.
  Steps: traverse cart with TalkBack — stepper announces "Increase/Decrease
  quantity of {name}" and current value; remove announces "Remove {name} from
  cart"; snackbar errors/undo announced via live region; verify ≥48dp targets,
  no clipping under largest dynamic type, RTL mirroring. Run on the physical
  device to validate real AT behavior and arm64/API-34 rendering (vs. emulator).
  Expected: all semantics announced; targets/contrast meet WCAG AA; layout holds
  in RTL + large type.
  Traces: AC-1, AC-3, AC-4 (a11y), and DoD accessibility gate.
- **TC-AND-211-15** — Type: contract/MWS security (JVM). Target: MWS.
  Precondition: MWS records request headers; logout flow exercised.
  Steps: issue a PATCH and a DELETE; inspect captured requests; then assert logs.
  Expected: every mutation carries the `X-CSRF-Token` header (CSRF enforced) and
  session cookie; idempotent GETs may retry, PATCH/DELETE never auto-retry; no
  cookie/CSRF/price-with-user logged (telemetry uses `sku`/aggregate only).
  Traces: AC-5 (no auto-retry), §8 security, §10 telemetry.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-01, TC-02, TC-09, TC-10, TC-14 |
| AC-2 | TC-03, TC-04, TC-10 |
| AC-3 | TC-10, TC-14 |
| AC-4 | TC-05, TC-08, TC-11, TC-14 |
| AC-5 | TC-06, TC-07, TC-08, TC-11, TC-15 |
| AC-6 | TC-11 |
| AC-7 | TC-09, TC-12 |
| AC-8 | TC-03, TC-12 |
| AC-9 | TC-13 |
| AC-10 | TC-01..TC-15 (the full suite is the CI gate) |
