---
id: AND-211
title: Cart screen
milestone: M5
epic: E29
priority: P0
size: L
status: draft
depends_on: [AND-210, AND-206, AND-022, AND-024, AND-018, AND-021, AND-116]
blocks: [AND-212]
---

# AND-211 — Cart screen

## 1. Overview & Goal

Build the customer-facing **shopping cart** screen for the TestLogon native
Android app. The screen reads the current cart for the authenticated session,
renders each line item (image, name, unit price, quantity, line subtotal), and
exposes the three mutating cart operations from the source scope: **add** (qty
increment), **update quantity**, and **remove**. It computes and displays cart
**totals** (subtotal, and any tax/shipping/discount/grand total fields the
backend returns) and renders a distinct **empty state** when the cart has no
items, with a call-to-action back to the catalog.

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
update.** Concretely — changing a quantity or removing a line issues an
authenticated mutation, the row and the totals reflect the new state, and the
change survives a screen reload (it persisted server-side); removing the last
item yields the empty state.

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
- **AND-210 (depends_on)** — provides `CartApi`, Moshi DTOs (`CartDto`,
  `CartLineDto`, `MoneyDto`, `CartTotalsDto`) and `core-model` domain types
  (`Cart`, `CartLine`, `Money`, `CartTotals`). This ticket consumes them and
  adds mutation methods to `CartApi` only if AND-210 did not already expose them
  (see Section 5).
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
- Web reference: `frontend/src/api/endpoints/cart.ts` (AND-210's source) and
  shared types `frontend/src/api/types.ts`. Backend OpenAPI at
  `http://18.222.237.167:8000/openapi.json` (verify exact paths/fields).
- Auth is cookie-based: session cookies + `ui_csrf` echoed as the
  `X-CSRF-Token` header; on `401` the shared authenticator does one
  `POST /ui/session/refresh` then retries. The cart GET is idempotent and
  bounded-backoff retried; cart mutations are **not** auto-retried.

## 3. Functional Requirements

FR-1. **Load cart.** On entry, fetch the current cart via
`GET /ui/shop/cart`. Show a loading state until the first result resolves.

FR-2. **Render lines.** For each `lines[]` entry display: thumbnail (AND-103
Coil primitive), item name, unit price (locale currency), a quantity control,
and the per-line subtotal (locale currency). Lines render in the order returned
by the backend.

FR-3. **Update quantity.** Each line has a quantity stepper (− / value / +) and
respects a `maxQuantity` when known. Changing quantity issues
`PATCH /ui/shop/cart/items/{lineId}` with `{quantity}`. The change is applied
optimistically; on failure it rolls back to the prior quantity and shows a typed
error with Retry.

FR-4. **Increment to add.** Tapping `+` on an existing line is the in-cart "add"
operation (increases quantity by one via the same PATCH). Decrementing below 1
is disallowed; the `−` control at quantity 1 is replaced by / behaves as remove
(with confirmation, FR-5).

FR-5. **Remove line.** Each line has a remove affordance (and swipe-to-dismiss)
that issues `DELETE /ui/shop/cart/items/{lineId}`. Removal is confirmed (or shown
as an undoable snackbar) and applied optimistically; on failure the line is
restored and a typed error shown.

FR-6. **Totals.** A pinned totals section displays subtotal and any
tax/shipping/discount and grand total the backend returns, each locale
currency-formatted. Totals update whenever a mutation succeeds (and optimistically
during in-flight edits, then reconcile to the server response).

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
    /** Idempotent GET; bounded-backoff retried by core-network. SWR-backed. */
    fun observeCart(): Flow<ApiResult<Cart>>          // cache-first then network
    suspend fun refresh(): ApiResult<Cart>

    /** Non-idempotent mutations; never auto-retried. Return the updated cart. */
    suspend fun setQuantity(lineId: String, quantity: Int): ApiResult<Cart>
    suspend fun removeLine(lineId: String): ApiResult<Cart>
}
```

```kotlin
class CartRepositoryImpl @Inject constructor(
    private val api: CartApi,                 // from AND-210
    private val cache: CartCacheDao,          // core-data / Room 2.6 (AND-116)
    @IoDispatcher private val io: CoroutineDispatcher,
) : CartRepository {

    override suspend fun refresh(): ApiResult<Cart> = withContext(io) {
        when (val r = api.getCart()) {
            is ApiResult.Success -> r.data.toDomain()
                .also { cache.replace(it.toEntity()) }
                .let { ApiResult.Success(it) }
            is ApiResult.Failure -> cache.load()?.toDomain()
                ?.let { ApiResult.Success(it) } ?: r   // stale fallback
        }
    }

    override suspend fun setQuantity(lineId: String, quantity: Int): ApiResult<Cart> =
        withContext(io) {
            api.updateLine(lineId, UpdateCartLineDto(quantity = quantity))
                .map { it.toDomain().also { c -> cache.replace(c.toEntity()) } }
        }

    override suspend fun removeLine(lineId: String): ApiResult<Cart> =
        withContext(io) {
            api.deleteLine(lineId)
                .map { it.toDomain().also { c -> cache.replace(c.toEntity()) } }
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

    fun onQuantityChange(lineId: String, newQuantity: Int) {
        if (newQuantity < 1) { onRemove(lineId); return }
        val current = (_uiState.value as? CartUiState.Content) ?: return
        if (current.rowState(lineId) is RowMutationState.InFlight) return
        val rolledBack = current
        _uiState.value = current.optimisticSetQuantity(lineId, newQuantity)  // + InFlight
        viewModelScope.launch {
            when (val r = repository.setQuantity(lineId, newQuantity)) {
                is ApiResult.Success -> {
                    _uiState.value = CartUiState.Content(r.data.toUiModel())
                    analytics.log("cart_update_qty_success", "line_id" to lineId, "qty" to newQuantity)
                }
                is ApiResult.Failure -> {
                    _uiState.value = rolledBack.clearRow(lineId)
                    analytics.log("cart_update_qty_error", "line_id" to lineId, "code" to r.code)
                    _events.send(CartEvent.MutationFailed(r.message) { onQuantityChange(lineId, newQuantity) })
                }
            }
        }
    }

    fun onRemove(lineId: String) {
        val current = (_uiState.value as? CartUiState.Content) ?: return
        val rolledBack = current
        _uiState.value = current.optimisticRemove(lineId)
        viewModelScope.launch {
            when (val r = repository.removeLine(lineId)) {
                is ApiResult.Success -> {
                    _uiState.value = r.data.toUiState()                 // may become Empty
                    analytics.log("cart_remove_success", "line_id" to lineId)
                }
                is ApiResult.Failure -> {
                    _uiState.value = rolledBack.clearRow(lineId)
                    _events.send(CartEvent.MutationFailed(r.message) { onRemove(lineId) })
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
    onQuantityChange: (lineId: String, qty: Int) -> Unit,
    onRemove: (lineId: String) -> Unit,
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

DTOs are defined in **AND-210**; this ticket consumes them and adds the two
mutation methods below to `CartApi` if AND-210 did not already expose them.
Confirm exact paths/field names against `/openapi.json` and
`frontend/src/api/endpoints/cart.ts`.

**Get cart** — `GET /ui/shop/cart`

```json
{
  "cart_id": "cart_abc",
  "lines": [
    {
      "line_id": "ln_001",
      "item_id": "itm_001",
      "name": "Example Item",
      "thumbnail_url": "https://…/a_t.jpg",
      "unit_price": { "amount_cents": 1999, "currency": "USD" },
      "quantity": 2,
      "max_quantity": 10,
      "line_subtotal": { "amount_cents": 3998, "currency": "USD" }
    }
  ],
  "item_count": 2,
  "totals": {
    "subtotal":   { "amount_cents": 3998, "currency": "USD" },
    "tax":        { "amount_cents": 320,  "currency": "USD" },
    "shipping":   { "amount_cents": 0,    "currency": "USD" },
    "discount":   { "amount_cents": 0,    "currency": "USD" },
    "grand_total":{ "amount_cents": 4318, "currency": "USD" }
  }
}
```

**Update line quantity** — `PATCH /ui/shop/cart/items/{lineId}`

Request: `{ "quantity": 3 }` · Response (200): the full updated cart (same shape
as the GET).

**Remove line** — `DELETE /ui/shop/cart/items/{lineId}` · Response (200): the
full updated cart (same shape as the GET; `lines` may be empty).

Retrofit (in `:feature-cart` / AND-210's `core-network` `CartApi`):

```kotlin
interface CartApi {
    @GET("ui/shop/cart")
    suspend fun getCart(): ApiResult<CartDto>

    @PATCH("ui/shop/cart/items/{lineId}")
    suspend fun updateLine(
        @Path("lineId") lineId: String,
        @Body body: UpdateCartLineDto,
    ): ApiResult<CartDto>

    @DELETE("ui/shop/cart/items/{lineId}")
    suspend fun deleteLine(@Path("lineId") lineId: String): ApiResult<CartDto>
}

@JsonClass(generateAdapter = true)
data class UpdateCartLineDto(val quantity: Int)
```

All requests are authenticated (cookies + `X-CSRF-Token`). The `PATCH`/`DELETE`
mutations **require** the CSRF header (attached by the shared CSRF interceptor)
and are excluded from the idempotent-GET retry policy. On `401`, core-network
performs one `POST /ui/session/refresh` then retries. FastAPI errors surface via
the shared `detail` mapper; `404` on a line mutation (line already gone) is
reconciled by re-reading the cart; `409`/`422` (e.g. quantity exceeds stock) maps
to a non-retryable typed message. Each mutation returning the full cart makes
totals reconciliation authoritative server-side (no client-side total
re-derivation needed beyond the optimistic preview).

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
    val lineId: String,
    val itemId: String,
    val name: String,
    val thumbnailUrl: String?,
    val unitPriceLabel: String,               // locale currency-formatted
    val quantity: Int,
    val maxQuantity: Int?,
    val lineSubtotalLabel: String,
    val row: RowMutationState = RowMutationState.Idle,
)

data class TotalsUiModel(
    val subtotalLabel: String,
    val taxLabel: String?,
    val shippingLabel: String?,
    val discountLabel: String?,
    val grandTotalLabel: String,
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
- Currency formatting via `NumberFormat.getCurrencyInstance` using each
  `Money.currency`. The cart `item_count` is surfaced to the app-shell cart badge.

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
- **Stale line (`404` on mutation).** Treated as "cart changed underneath":
  re-read the cart via `refresh()` and surface a brief "Cart updated" notice
  rather than a hard error.
- **Out-of-stock / invalid quantity (`409`/`422`).** Rolled back, shown as a
  terminal non-retryable message; the stepper clamps to the returned/known
  `max_quantity`.
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

- `cart_view` — { item_count, line_count, has_discount, stale, latency_ms }
- `cart_update_qty_tap` — { line_id, from_qty, to_qty }
- `cart_update_qty_success` — { line_id, qty }
- `cart_update_qty_error` — { line_id, code, http_status }
- `cart_remove_tap` — { line_id }
- `cart_remove_success` — { line_id, remaining_lines }
- `cart_remove_error` — { line_id, code, http_status }
- `cart_checkout_tap` — { item_count }
- `cart_load_error` — { scope: get, code, http_status, had_cache }
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

**Instrumented integration (MockWebServer):** load a multi-line cart, PATCH a
quantity returning an updated cart with new totals, DELETE the last line returning
an empty cart (assert empty state), a 500-on-PATCH rollback + Retry, a
409-on-PATCH (over stock) terminal message + clamp, a 404-on-DELETE that triggers
a re-read, and a 401-then-refresh-then-200 sequence for the GET.

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

- **Cart endpoint shape.** Paths `PATCH /ui/shop/cart/items/{lineId}` and
  `DELETE /ui/shop/cart/items/{lineId}` vs. id-by-`item_id` (no separate
  `line_id`) are unconfirmed. *Mitigation:* isolate in `CartApi`/repository.
  **Open: verify in OpenAPI / `cart.ts` (shared with AND-210).**
- **Mutation response.** Assumes each mutation returns the full updated cart
  (enables authoritative totals reconciliation). If it returns only the changed
  line or a 204, the ViewModel must follow with a `getCart` refresh. **Open:
  confirm.**
- **Totals fields.** Assumed `subtotal/tax/shipping/discount/grand_total`; if the
  backend omits tax/shipping until checkout, the totals block renders subtotal +
  grand_total only. **Open: confirm DTO.**
- **Money shape.** Assumes `{amount_cents, currency}` (shared with AND-204/AND-206);
  pre-formatted strings or float dollars would change mapping. **Open: confirm.**
- **Add semantics.** Source scope lists "add"; modeled as in-cart quantity
  increment via PATCH, since first-add is owned by AND-206. If the cart screen must
  support adding new items directly, that overlaps AND-212 (search) — **Open:
  confirm with design.**
- **Remove UX.** Confirmation dialog vs. undoable snackbar not specified; default
  to optimistic remove with undo snackbar. **Open: confirm.**
- **Concurrent stale edits.** Two rapid edits to the same line are serialized by
  the per-row in-flight guard; cross-line concurrency relies on each mutation
  returning the full cart. If the backend is not last-write-authoritative, a
  trailing `refresh` is required.
- **Dev host flakiness** makes live cart edits nondeterministic; all assertions
  use MockWebServer, not the dev host.

## 14. Acceptance Criteria

AC-1. Entering the cart issues `GET /ui/shop/cart` and renders each line's
thumbnail, name, locale-formatted unit price, quantity, and line subtotal, plus a
totals block (subtotal … grand total).
AC-2. Changing a line quantity via the stepper issues exactly one
`PATCH /ui/shop/cart/items/{lineId}` with `{quantity}`, updates the line subtotal
and totals, and the change persists across a reload (**cart edits persist** +
**totals update** — primary).
AC-3. Tapping `+` increments and tapping `−` decrements; `−` at quantity 1
triggers remove; quantity is clamped to `max_quantity` when known.
AC-4. Removing a line issues exactly one `DELETE /ui/shop/cart/items/{lineId}`,
removes the row, and updates totals; removing the last line shows the empty state
with a working "Browse catalog" action.
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
gates and the rollback / empty / 409 / 404-re-read / 401-refresh sequences.

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
