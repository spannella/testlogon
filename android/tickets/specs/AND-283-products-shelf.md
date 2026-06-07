---
id: AND-283
title: Products shelf
milestone: M6
epic: E38
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-280, AND-206]
blocks: []
---

# AND-283 — Products shelf

## 1. Overview & Goal

Add an in-stream **products shelf** to the live viewer experience: while an
authorized viewer watches a broadcast (AND-280), the app fetches the products
associated with that live session via the broadcast **shelf** endpoint
`GET /broadcast/sessions/{session_id}/products` (the source-ticket
"`chat/product`" label is a misnomer — corrected in §2/§5), renders them
as a compact, dismissible horizontal shelf overlaid on the player, and lets the
viewer **buy from the stream** without leaving playback. Tapping a product's
Buy action routes the viewer into the existing checkout/commerce flow seeded by
the product-detail screen (AND-206), passing the selected item id so the cart /
checkout path can complete the purchase.

The deliverable is a self-contained `shelf/` package inside the existing
`:feature-viewer` module created by AND-280. It reuses AND-280's viewer screen
host (the shelf is composed over the player surface) and reuses AND-206's
product-detail / add-to-cart destination and `CatalogItem` domain model as the
buy target — this ticket does **not** re-implement checkout, the cart, or the
product-detail screen. It owns only: the session→products fetch, the shelf UI
and its state machine, and the navigation hand-off to the buy flow.

Success is the source-ticket acceptance, made concrete: **the shelf renders**
(products for the active broadcast load and display over the player with
loading/empty/error/offline states), and **buy routes to checkout** (tapping
Buy on a shelf product navigates to the AND-206 product-detail/add-to-cart
destination for that item id, from which checkout proceeds).

Out of scope (owned elsewhere): the player core and playback-authorization
handshake (AND-280 / AND-167), product detail rendering and the add-to-cart
mutation (AND-206), the cart screen and checkout-session creation (later M5
cart/checkout tickets), and broadcaster-side product management.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace / applicationId base **`com.testlogon.android`**.
  New package: `com.testlogon.android.feature.viewer.shelf.*`.
- Module layering: `app -> feature-viewer -> core-* (core-network, core-model,
  core-ui, core-data, core-testing)`. This ticket extends `:feature-viewer`
  with a `shelf/` subpackage; it adds no new Gradle module. It may add a
  `chat/product` method to a `core-network` API interface (see §5).
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single
  Activity), Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 +
  Moshi 1.15, Room 2.6, DataStore, Coil (product thumbnails). minSdk 24,
  compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **AND-280 (depends_on)** — provides the viewer playback screen and its
  `sessionId` nav arg / back-stack entry. The shelf is hosted by AND-280's
  `ViewerPlaybackScreen` as an overlay; this ticket consumes the same
  `sessionId` and is mounted in AND-280's `feature-viewer` nav destination.
- **AND-206 (depends_on)** — provides the product-detail / add-to-cart
  destination at route `shop/{categoryId}/{itemId}`, the `CatalogItem` /
  `ProductUiModel` domain types, and the `CartSummary` surface. The shelf's Buy
  action navigates to this route; checkout proceeds from there.
- Web reference (verified): the shelf list call lives in
  `frontend/src/api/endpoints/broadcast-shelf.ts` (`getShelfProducts`), and the
  viewer UI in `frontend/src/pages/broadcast/ProductShelf.tsx`. The endpoint is
  **`GET /broadcast/sessions/{session_id}/products`** (NOT a `chat/product` GET —
  `chat/product` is only `POST /broadcast/sessions/{session_id}/chat/product`,
  a broadcaster-side action that posts a product *link message* into chat). The
  session→product linkage is the path segment `{session_id}`; the payload is
  `BroadcastShelfListOut` (see §5). The original "`chat/product` surface" framing
  in the source ticket scope was inaccurate and is corrected here.
- Auth is cookie-based: session cookies + `ui_csrf` echoed as `X-CSRF-Token`;
  on `401` the shared authenticator does one `POST /ui/session/refresh` then
  retries. The products fetch is an idempotent GET (bounded-backoff retried);
  the buy hand-off performs no mutation itself.

## 3. Functional Requirements

FR-1. **Fetch on entry.** When the viewer screen is active for `sessionId`,
fetch the session's products via the `chat/product` GET (§5). Fetch lazily —
only when the shelf is first requested/visible — so it never blocks first frame
of video.

FR-2. **Shelf render.** Render products as a horizontally scrollable
`LazyRow` of compact cards overlaid on the bottom of the player surface. Each
card shows the product thumbnail (Coil), name, locale-formatted price, and a
Buy affordance. The shelf has a header/toggle and a dismiss (close) control.

FR-3. **Toggle visibility.** A shelf entry-point control (e.g., a "Shop" /
cart-style icon on the player chrome) toggles the shelf open/closed. The shelf
is hidden by default so it does not obscure playback; opening it does not pause
the stream. Closing returns to plain playback.

FR-4. **Buy routes to checkout.** Tapping Buy on a card navigates to the
AND-206 destination `shop/{categoryId}/{itemId}` for that product, from which
add-to-cart / checkout proceeds. The shelf itself performs no purchase mutation;
it only routes. If the product carries no `category_id`, route with the
fallback category segment defined by AND-206's nav contract.

FR-5. **Empty state.** When the session has zero products, the shelf either
hides its entry-point or, when opened, shows a compact "No products" empty
state — it never shows a broken/blank shelf.

FR-6. **Loading state.** While the first fetch is in flight, opening the shelf
shows a compact loading row (shimmer/placeholder cards), distinct from empty.

FR-7. **Error / retry.** On fetch failure with no cached data, the open shelf
shows an inline error with a Retry action; failure never crashes or disrupts
playback.

FR-8. **Offline / stale.** If a cached product list exists for the session, a
fetch failure shows the cached products behind a non-blocking "saved data"
marker rather than an error.

FR-9. **Non-intrusive lifecycle.** The shelf overlay is paused/cleared (cards
released, Coil requests cancellable) when the viewer screen is backgrounded;
shelf open/closed and scroll position survive configuration changes.

FR-10. **No playback regression.** Shelf presence/animation must not pause,
stutter, or release the AND-280 player; it composes above the player surface
without taking video focus.

## 4. Technical Design

New code under `com.testlogon.android.feature.viewer.shelf` inside the existing
`:feature-viewer` library module.

### Layers

```
shelf/ui/        ProductsShelf, ProductShelfCard, ShelfStateRow,
                 ShelfToggleButton
shelf/ui/state   ProductsShelfUiState, ShelfProductUiModel
shelf/vm/        ProductsShelfViewModel
shelf/data/      ProductsShelfRepository (interface) + Impl
shelf/di/        ProductsShelfModule (binds repository)
```

The shelf is composed by AND-280's `ViewerPlaybackScreen` as an overlay sibling
of the player; AND-280 owns the `sessionId` nav arg and the screen scaffold.
This ticket provides a `ProductsShelf(...)` entry composable and a hoisted
`ProductsShelfViewModel` scoped to the same nav back-stack entry.

### Repository

```kotlin
interface ProductsShelfRepository {
    /** Idempotent GET; bounded-backoff retried by core-network. */
    suspend fun getSessionProducts(sessionId: String): ApiResult<List<CatalogItem>>
}

class ProductsShelfRepositoryImpl @Inject constructor(
    private val api: BroadcastShelfApi,              // §5; may be added here or core-network
    private val cache: ShelfProductCacheDao,         // core-data / Room, keyed by sessionId
    @IoDispatcher private val io: CoroutineDispatcher,
) : ProductsShelfRepository {

    override suspend fun getSessionProducts(sessionId: String): ApiResult<List<CatalogItem>> =
        withContext(io) {
            when (val r = api.getSessionProducts(sessionId)) {
                // r.data is BroadcastShelfListOut; unwrap .items then map.
                is ApiResult.Success -> r.data.items.map { it.toDomain() }
                    .also { cache.replace(sessionId, it.map { p -> p.toEntity(sessionId) }) }
                    .let { ApiResult.Success(it) }
                is ApiResult.Failure -> cache.findBySession(sessionId)
                    .takeIf { it.isNotEmpty() }
                    ?.map { it.toDomain() }
                    ?.let { ApiResult.Success(it) }   // stale fallback
                    ?: r
            }
        }
}
```

### ViewModel

```kotlin
@HiltViewModel
class ProductsShelfViewModel @Inject constructor(
    private val repository: ProductsShelfRepository,
    private val analytics: Analytics,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val sessionId: String = checkNotNull(savedState[ViewerRoutes.ARG_SESSION_ID])

    private val _uiState = MutableStateFlow<ProductsShelfUiState>(ProductsShelfUiState.Idle)
    val uiState: StateFlow<ProductsShelfUiState> = _uiState.asStateFlow()

    /** Open/closed survives rotation via SavedStateHandle. */
    val expanded: StateFlow<Boolean> =
        savedState.getStateFlow(KEY_EXPANDED, false)

    fun setExpanded(open: Boolean) {
        savedState[KEY_EXPANDED] = open
        if (open && _uiState.value is ProductsShelfUiState.Idle) load()
        analytics.log("viewer_shelf_toggle", "session_id" to sessionId, "open" to open)
    }

    fun load() {
        viewModelScope.launch {
            _uiState.value = ProductsShelfUiState.Loading
            _uiState.value = when (val r = repository.getSessionProducts(sessionId)) {
                is ApiResult.Success ->
                    if (r.data.isEmpty()) ProductsShelfUiState.Empty
                    else ProductsShelfUiState.Ready(r.data.map { it.toShelfUiModel() })
                is ApiResult.Failure ->
                    ProductsShelfUiState.Error(r.message, retryable = r.retryable)
            }
        }
    }

    fun onBuy(item: ShelfProductUiModel) {
        analytics.log("viewer_shelf_buy_tap",
            "session_id" to sessionId, "item_id" to item.id)
        // Navigation is performed by the host via the onBuy lambda (see Compose).
    }

    fun retry() = load()

    companion object { const val KEY_EXPANDED = "shelf_expanded" }
}
```

### Compose

```kotlin
@Composable
fun ProductsShelf(
    state: ProductsShelfUiState,
    expanded: Boolean,
    onToggle: (Boolean) -> Unit,
    onBuy: (ShelfProductUiModel) -> Unit,   // host maps to nav -> shop/{categoryId}/{itemId}
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
)
```

`ProductsShelf` renders a `ShelfToggleButton` on the player chrome and, when
`expanded`, an `AnimatedVisibility` panel anchored to the bottom of the player
holding a `LazyRow` of `ProductShelfCard`s (or a `ShelfStateRow` for
loading/empty/error). The host (AND-280 `ViewerPlaybackScreen`) wires `onBuy`
to `navController.navigate("shop/${item.categoryId ?: DEFAULT_CATEGORY}/${item.id}")`,
which lands on the AND-206 destination. The overlay uses
`Modifier.semantics { }` and `WindowInsets` so it does not collide with player
controls.

## 5. API Contract

The shelf reads products linked to a broadcast session via the broadcast
**shelf** surface. **VERIFIED** against OpenAPI and the web client — see §16.

**Get session products** — `GET /broadcast/sessions/{session_id}/products`
(VERIFIED: OpenAPI index line 219, `op=list_shelf_products_route_...`;
web client `broadcast-shelf.ts: getShelfProducts`). The session linkage is the
`{session_id}` path segment (NOT a `?session_id=` query param). Response (200)
is schema **`BroadcastShelfListOut`**, NOT a `{ products: [...] }` wrapper:

```json
{
  "session_id": "sess_123",
  "count": 1,
  "items": [
    {
      "session_id": "sess_123",
      "item_id": "itm_001",
      "category_id": "cat_live",
      "name": "Tour Hoodie",
      "description": "Limited tour merch",
      "price_cents": 4500,
      "currency": "USD",
      "image_url": "https://…/h.jpg",
      "display_order": 0,
      "added_by": "usr_abc",
      "added_at": 1717600000,
      "broadcast_price_cents": 3900,
      "effective_price_cents": 3900,
      "is_broadcast_price": true,
      "discount_pct": 13,
      "original_price_cents": 4500,
      "broadcast_price_expires_at": null,
      "broadcast_price_set_at": 1717600000
    }
  ]
}
```

CORRECTIONS vs. the original draft (all verified against schema
`BroadcastShelfItemOut`):
- The list lives under **`items`**, not `products`; the envelope also carries
  `session_id` and `count`.
- Each item is a **flat** `BroadcastShelfItemOut`, NOT a nested AND-206
  `CatalogItemDto`. Fields are `item_id` (not `id`), flat `price_cents` +
  `currency` (NOT a nested `price: { amount_cents, currency }`), a single
  `image_url` (NOT a `media: [{ url, thumbnail_url }]` array).
- **`category_id` is a REQUIRED field** (schema `required` list), so the §13
  "fallback category" concern is resolved: the Buy route always has a real
  `category_id` and `DEFAULT_CATEGORY` is dead/defensive only.
- There is **no `availability`/`in_stock`** object in the payload. The draft's
  `inStock` UI field is therefore an *unverified assumption*; the contract does
  carry live-pricing fields instead: `broadcast_price_cents`,
  `effective_price_cents`, `is_broadcast_price`, `discount_pct`,
  `original_price_cents`, `broadcast_price_expires_at` (LCOM-004 pricing). The
  shelf SHOULD prefer `effective_price_cents` for the displayed price and MAY
  show a strikethrough `original_price_cents` when `is_broadcast_price` is true.

Retrofit:

```kotlin
interface BroadcastShelfApi {
    @GET("broadcast/sessions/{sessionId}/products")
    suspend fun getSessionProducts(
        @Path("sessionId") sessionId: String,
    ): ApiResult<BroadcastShelfListOut>   // { session_id, count, items: List<BroadcastShelfItemOut> }
}
```

The request is authenticated. **VERIFIED** in `frontend/src/api/client.ts`: the
web client sends cookies (`credentials: "include"`), echoes the `ui_csrf`
cookie as the `X-CSRF-Token` header on **every** request (GET included), and
also attaches `Authorization: Bearer <accessToken>` from its auth store plus an
optional `X-IMPERSONATION-TOKEN`. On `401`, the client refreshes **exactly
once** via `POST /ui/session/refresh` (VERIFIED: OpenAPI index line 1847) and
retries the original request; a second `401` is terminal (logout). core-network
on Android mirrors this (cookie jar + CSRF interceptor + single-refresh
authenticator). NOTE: the OpenAPI op also lists header params
`X-SESSION-ID`/`X-IMPERSONATION-TOKEN` and a `user_sub` — core-network owns
these; the shelf module passes only `sessionId`. This GET is idempotent and
eligible for bounded-backoff retry. FastAPI errors surface via the shared
`detail` mapper (`string | [{msg}] | {code,...}` — VERIFIED:
`client.ts: normalizeErrorDetail`); the only documented error is `422
HTTPValidationError` (malformed `session_id`). The shelf treats any failure as
a retryable/stale error (no special `404` semantics — a missing list is
`Empty`).

**Buy hand-off:** no new endpoint. Navigation targets the AND-206 route
`shop/{categoryId}/{itemId}` (VERIFIED present in web routing,
`frontend/src/App.tsx: <Route path="shop/:categoryId/:itemId">`). NOTE /
deviation: the *web* `ProductShelf.tsx` does NOT route to the detail screen on
buy — it performs an inline add-to-cart (`getCarts`/`createCart`/`addCartItem`
with `sku = item_id`). This ticket deliberately interprets "buy from stream" as
*routing to the AND-206 detail/add-to-cart destination* instead (see §13 open
question). Either way, the add-to-cart mutation and checkout-session creation
are owned downstream, not by this ticket.

## 6. Data & State Management

```kotlin
sealed interface ProductsShelfUiState {
    data object Idle : ProductsShelfUiState         // not yet loaded (shelf closed)
    data object Loading : ProductsShelfUiState
    data class Ready(
        val products: List<ShelfProductUiModel>,
        val stale: Boolean = false,
    ) : ProductsShelfUiState
    data object Empty : ProductsShelfUiState
    data class Error(val message: String, val retryable: Boolean) : ProductsShelfUiState
}

data class ShelfProductUiModel(
    val id: String,                 // <- BroadcastShelfItemOut.item_id
    val categoryId: String,         // REQUIRED in the contract (never null); DEFAULT_CATEGORY is defensive only
    val name: String,
    val priceLabel: String,         // currency-formatted from effective_price_cents (fallback price_cents)
    val originalPriceLabel: String?,// non-null only when is_broadcast_price == true (strikethrough)
    val thumbnailUrl: String?,      // <- image_url (single URL; contract has no media[] array)
)
```

> CORRECTION: the contract's `BroadcastShelfItemOut` carries **no `availability`
> / `in_stock`** field, so the original `inStock: Boolean` field is dropped (it
> was an unverified assumption). Out-of-stock handling is owned by the AND-206
> detail screen after the Buy hand-off. The contract does expose LCOM-004
> live-pricing fields (`broadcast_price_cents`, `effective_price_cents`,
> `is_broadcast_price`, `discount_pct`, `original_price_cents`); the shelf
> displays `effective_price_cents` (or `price_cents` when null) and may show a
> strikethrough `original_price_cents`.

- **Caching (core-data / Room 2.6).** Successful fetches `replace` the cached
  product rows for `sessionId` in a `shelf_products` table; on network failure
  the cached rows are returned as `Ready(stale = true)`. Cache rows hold product
  content only (no user/cart/account data), keyed by `sessionId`.
- **State retention.** `sessionId` and the `expanded` flag live in
  `SavedStateHandle` (survive process death). `LazyRow` scroll position is held
  via `rememberSaveable` within the back-stack entry. The product list is not
  re-fetched on rotation (held in `uiState`).
- **Lazy load.** `uiState` starts `Idle`; the first `setExpanded(true)`
  triggers `load()`. This keeps the network request off the playback hot path.
- Price formatting uses `NumberFormat.getCurrencyInstance` over
  `effective_price_cents / 100` (fallback `price_cents / 100`) with the DTO
  `currency`. NOTE: the web shelf (`ProductShelf.tsx: formatPrice`) hardcodes the
  `en-US` locale via `Intl.NumberFormat("en-US", { style: "currency", currency })`;
  the Android port intentionally uses the **device locale** (i18n requirement
  §9) rather than copying the web's fixed `en-US`, so a non-US device formats the
  same currency per its locale conventions. Parity is on the amount, not the
  locale grouping.

## 7. Error Handling & Resilience

- **Timeouts.** The products GET uses the core-network ~20s call timeout for
  the unreliable plaintext dev host.
- **Idempotent retry.** The GET is eligible for bounded-backoff retry; there is
  no mutation in this ticket, so no auto-retry concerns for writes.
- **Fetch failure, no cache.** Open shelf shows inline `Error(retryable=true)`
  with a Retry action; playback is unaffected.
- **Fetch failure, with cache.** `Ready(stale=true)` + a non-blocking "saved
  data" marker; products remain buyable from cache (the Buy route re-fetches
  fresh data on the detail screen).
- **Empty.** Distinct `Empty` state (or hidden entry-point); never conflated
  with loading or error.
- **401.** Transparent to this layer (refresh-once interceptor). A terminal
  auth failure maps to a non-retryable error; re-auth routing is delegated to
  the app shell, and playback teardown is owned by AND-280.
- **Buy with broken/stale product.** Routing always succeeds (it only navigates
  by id); AND-206's detail screen re-fetches and owns not-found / out-of-stock
  handling, so a stale shelf entry degrades gracefully on the detail screen.
- **Playback isolation.** All shelf errors are confined to the overlay; the
  player is never paused or released by shelf failures.

## 8. Security & Privacy

- No new credentials or secrets. The session rides the existing persistent
  cookie jar; cookies and `ui_csrf`/`X-CSRF-Token` are attached by core-network
  and are never read or logged by this module.
- The products GET is a read; the Buy path performs no mutation here, so no
  CSRF-protected write originates in this ticket (the downstream add-to-cart
  POST carries CSRF via the shared interceptor in AND-206).
- Dev backend is **plaintext HTTP**; cleartext is permitted only for the dev
  flavor via the existing network-security-config (no change here). Product
  thumbnails load through the shared OkHttp/Coil TLS policy.
- Cached Room rows contain product content only — no PII, no cart/account data;
  rows are scoped per `sessionId` and subject to the existing cache TTL/eviction.
- Logs and analytics carry only session/item ids and aggregate counts; no
  prices tied to users, no auth material.

## 9. Accessibility & i18n

- All user-facing strings from `feature-viewer` `strings.xml` (no hardcoded
  text); pseudolocale-tested. Price via `NumberFormat`/locale currency.
- Each `ProductShelfCard` exposes a `contentDescription` (name + price + stock)
  and a labeled Buy action ("Buy {name}"); the toggle button is labeled
  ("Show products" / "Hide products") and announces state to TalkBack.
- The shelf overlay does not trap focus over player controls; opening/closing
  is announced via a live region; empty/error/stale states are readable by
  screen readers.
- Touch targets ≥ 48dp; `LazyRow` uses start/end (RTL-safe) padding and
  respects dynamic type without clipping card text. Color contrast for
  name/price over the (potentially busy) video meets WCAG AA via a scrim behind
  the shelf (core-ui Material 3 tokens).

## 10. Telemetry & Logging

Via the shared analytics facade (no PII):

- `viewer_shelf_toggle` — { session_id, open }
- `viewer_shelf_load` — { session_id, product_count, latency_ms, stale }
- `viewer_shelf_load_error` — { session_id, code, http_status }
- `viewer_shelf_buy_tap` — { session_id, item_id, category_id }
- `viewer_shelf_impression` — { session_id, item_id, position } (per visible card)

`Timber`/`Logger` wrapper at `DEBUG` for state transitions, `WARN`/`ERROR` for
fetch failures. Never log cookies, CSRF tokens, or full authenticated URLs.
Latency measured around `getSessionProducts`.

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + MockWebServer):**
- `ProductsShelfRepositoryImpl.getSessionProducts` maps DTO→domain, replaces
  cache on success, returns `stale` cached rows on network failure, and
  surfaces failure when no cache exists.
- `ProductsShelfViewModel`: `Idle→Loading→Ready` on a non-empty list,
  `→Empty` on an empty list, `→Error(retryable)` on transport error;
  `setExpanded(true)` triggers exactly one load from `Idle` and does not
  re-load when already loaded; `retry()` re-loads; `expanded` flips and persists
  via `SavedStateHandle`.
- Price formatting across currencies/locales (parity with AND-206).

**Compose UI (`createAndroidComposeRule`):**
- Toggle opens/closes the shelf; an open shelf renders a `LazyRow` of cards with
  name/price/thumbnail; scrolling reveals further cards.
- Loading, Empty, and retryable Error (with a working Retry) each render with
  distinct, correct semantics; stale marker renders on cache fallback.
- Tapping Buy invokes `onBuy` with the correct `item_id`/`category_id` (assert
  via a fake nav lambda / test tag).
- Shelf overlay does not cover the player's primary controls (layout assertion).

**Instrumented integration (MockWebServer):** mount the shelf inside the
AND-280 viewer destination, return canned `BroadcastShelfListOut` JSON from
`GET /broadcast/sessions/{session_id}/products`, open the shelf,
assert cards render, tap Buy and assert navigation to
`shop/{categoryId}/{itemId}` with the tapped id; include an empty-list case, a
500-then-Retry-then-200 case, and a 401-then-refresh-then-200 sequence.

Acceptance gate: automated tests proving **shelf renders** (products GET →
populated `LazyRow`) and **buy routes to checkout** (Buy tap → navigation to the
AND-206 destination for the tapped item).

## 12. Dependencies & Sequencing

- **Hard deps:** AND-280 (viewer screen host + `sessionId` nav arg; the shelf
  is composed over its player) and AND-206 (the `shop/{categoryId}/{itemId}`
  buy destination + `CatalogItem` domain model the shelf routes to and reuses).
- **Transitive:** core-network (typed `ApiResult`, cookie jar, CSRF
  interceptor, 401-refresh authenticator, idempotent-GET retry), core-data
  (Room cache), Coil image primitive (AND-103) for thumbnails.
- **Blocks:** none in the backlog. The buy hand-off relies on the downstream
  cart/checkout tickets (reached via AND-206) to complete a purchase, but those
  are not gated by this ticket.
- **Sequencing:** (1) add `BroadcastShelfApi.getSessionProducts` + DTOs if absent;
  (2) `ProductsShelfRepository` + per-session cache; (3) `ProductsShelfViewModel`
  + state/expand logic; (4) `ProductsShelf` Compose + cards + states; (5) mount
  in AND-280's viewer screen and wire the Buy nav lambda; (6) tests.

## 13. Risks & Open Questions

- **~~`chat/product` endpoint shape.~~ RESOLVED (verified).** The path is
  `GET /broadcast/sessions/{session_id}/products` (session via path segment),
  returning `BroadcastShelfListOut` (`items[]` + `count`). The source ticket's
  "`chat/product`" label was a misnomer (`chat/product` is a *POST* that drops a
  product-link chat message). See §5/§16.
- **~~Product payload parity.~~ RESOLVED (verified).** Items are flat
  `BroadcastShelfItemOut`, NOT the AND-206 `CatalogItemDto`. `category_id` **is
  required** in the contract, so no fallback/lookup is needed in practice
  (DEFAULT_CATEGORY remains as defensive code only). The shape carries no
  `availability`; it carries LCOM-004 live-pricing fields instead. A thin
  DTO→domain map is required (item_id→id, price_cents/effective_price_cents→
  priceLabel, image_url→thumbnailUrl). See §5/§16.
- **Buy destination semantics.** "Buy from stream" is interpreted as routing to
  the AND-206 product-detail/add-to-cart destination (which leads to checkout).
  NOTE: the *web* shelf does inline add-to-cart instead of navigating
  (`ProductShelf.tsx: handleAddToCart`). If product owners want web parity
  (one-tap add-to-cart) or a one-tap "instant buy" straight to checkout, an
  additional path is needed. **Open: confirm with design/product whether
  Android Buy = route-to-detail (current plan), inline add-to-cart (web parity),
  or direct checkout.**
- **Live updates.** The *web* shelf DOES update live: it consumes
  `shelf:add` / `shelf:remove` / `shelf:reorder` window events (sourced from
  SSE) in `ProductShelf.tsx`. This Android ticket fetches once on open with
  manual retry and does **not** subscribe to live shelf deltas. **Open: confirm
  whether live shelf updates (SSE deltas) are required for M6 parity, or are
  deferred to a follow-up.** *(Note: matching the web also implies the shelf can
  be reordered by `display_order`, which the Android list should respect when
  rendering — sort by `display_order`.)**
- **Overlay vs. PiP / fullscreen.** Behavior of the shelf in fullscreen or
  (future) picture-in-picture is undefined; default is shelf hidden in PiP.
- **Dev host flakiness** makes a live shelf nondeterministic; all assertions use
  MockWebServer, not the dev host.

## 14. Acceptance Criteria

AC-1. With the viewer playing a broadcast for `sessionId`, opening the shelf
fetches `GET /broadcast/sessions/{sessionId}/products` for that session and
renders the `items[]` products as a
horizontally scrollable shelf of cards (thumbnail, name, locale-formatted
price, Buy) over the player (**shelf renders** — primary).
AC-2. Tapping Buy on a card navigates to the AND-206 destination
`shop/{categoryId}/{itemId}` for the tapped item id, from which checkout
proceeds (**buy routes to checkout** — primary).
AC-3. The shelf is hidden by default and toggled via a player-chrome control;
opening/closing does not pause, stutter, or release the AND-280 player.
AC-4. A session with zero products shows a distinct Empty state (or hidden
entry-point); the first fetch shows a distinct Loading state.
AC-5. Fetch failure with no cache shows an inline Error with a working Retry;
failure with cache shows the cached products behind a "saved data" marker. No
failure disrupts playback.
AC-6. Shelf open/closed state and `LazyRow` scroll position survive rotation;
`sessionId` and `expanded` survive process death.
AC-7. The products GET is issued lazily (only on first open), is auto-retried
only as an idempotent GET, and recovers transparently across a
401-refresh-retry sequence.
AC-8. All automated tests in §11 pass in CI, including the renders + buy-route
gates and the empty / 500-retry / 401-refresh sequences.

## 15. Definition of Done

- Products shelf implemented in `:feature-viewer` (`shelf/` package), mounted in
  AND-280's viewer screen, with the Buy nav lambda wired to AND-206's route.
  Builds with Gradle 8.9 / AGP 8.7.3, JDK 17, compile/target 35, minSdk 24.
- All FRs and ACs implemented and verified; no hardcoded user-facing strings.
- Unit, Compose, and instrumented tests merged and green in CI; coverage for
  repository mapping/caching, ViewModel state/expand logic, lazy-load guard, and
  the Buy navigation hand-off.
- Lint/detekt/ktlint clean; no new cleartext exceptions beyond the existing dev
  flavor config; no playback regression (player not paused/released by the
  shelf), verified.
- Telemetry events (§10) emitted and verified; no secrets/PII logged.
- Accessibility pass (TalkBack + pseudolocale + RTL) completed; shelf does not
  obstruct player controls.
- `BroadcastShelfApi` additions documented for core-network consumers; §13 open
  questions resolved or explicitly deferred with owners.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT, and an exact source pointer.

1. **List endpoint is `GET /broadcast/sessions/{session_id}/products`.**
   VERDICT: **Corrected** (draft said `GET /ui/chat/product?session_id=`).
   SOURCE: OpenAPI `GET /broadcast/sessions/{session_id}/products`
   (op `list_shelf_products_route_...`, openapi.index.txt line 219); frontend
   `src/api/endpoints/broadcast-shelf.ts: getShelfProducts`.
2. **Session linkage is the `{session_id}` path segment, not a query param.**
   VERDICT: **Corrected.** SOURCE: same endpoint params=`session_id` (path);
   `broadcast-shelf.ts: getShelfProducts` builds `/broadcast/sessions/${sessionId}/products`.
3. **Response envelope is `BroadcastShelfListOut` = `{ session_id, count, items[] }`,
   not `{ products: [...] }`.** VERDICT: **Corrected.** SOURCE: schema
   `BroadcastShelfListOut` (openapi.pretty.json ~line 12617); frontend
   `src/api/endpoints/broadcast-shelf.ts: ShelfListResponse`.
4. **Item is flat `BroadcastShelfItemOut` with `item_id`, `price_cents`,
   `currency`, `image_url` — NOT a nested `CatalogItemDto` with
   `price:{amount_cents,currency}` and `media[]`.** VERDICT: **Corrected.**
   SOURCE: schema `BroadcastShelfItemOut` (openapi.pretty.json line 12476);
   frontend `ShelfItem` (`broadcast-shelf.ts`).
5. **`category_id` is a REQUIRED item field (always present).** VERDICT:
   **Corrected** (draft treated it as possibly absent, needing a fallback).
   SOURCE: `BroadcastShelfItemOut.required` includes `category_id`
   (openapi.pretty.json ~line 12605); `ShelfItem.category_id: string` (non-null).
6. **No `availability`/`in_stock` field exists; the draft's `inStock` UI field
   is dropped.** VERDICT: **Corrected** (was an unverified assumption). SOURCE:
   `BroadcastShelfItemOut` properties (no availability key); `ShelfItem` has no
   stock field.
7. **Contract carries LCOM-004 live-pricing fields (`broadcast_price_cents`,
   `effective_price_cents`, `is_broadcast_price`, `discount_pct`,
   `original_price_cents`, `broadcast_price_expires_at`).** VERDICT: **Verified**
   (new, added to spec). SOURCE: `BroadcastShelfItemOut` properties
   (openapi.pretty.json lines 12487-12595).
8. **Auth: `ui_csrf` cookie echoed as `X-CSRF-Token` on every request; cookies
   sent (`credentials:"include"`).** VERDICT: **Verified.** SOURCE:
   `src/api/client.ts` lines 167-171, 183.
9. **401 -> single `POST /ui/session/refresh` then one retry; 2nd 401 terminal.**
   VERDICT: **Verified.** SOURCE: `src/api/client.ts` lines 119-128, 194-229;
   OpenAPI `POST /ui/session/refresh` (openapi.index.txt line 1847).
10. **Error `detail` mapper accepts `string | [{msg}] | {code,...}`.** VERDICT:
    **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail` lines 66-102.
11. **Only documented error on the GET is `422 HTTPValidationError`.** VERDICT:
    **Verified.** SOURCE: endpoint resp=`200:BroadcastShelfListOut;422:HTTPValidationError`
    (openapi.index.txt line 219); schema `HTTPValidationError`→`ValidationError`
    (`{loc, msg, type}`, openapi.pretty.json lines 37133, 80337).
12. **Buy destination route `shop/{categoryId}/{itemId}` exists.** VERDICT:
    **Verified.** SOURCE: `src/App.tsx` line 331
    `<Route path="shop/:categoryId/:itemId" element={<ProductDetail/>} />`.
13. **Web buy behavior is inline add-to-cart, not navigate-to-detail.** VERDICT:
    **Verified** (documented as a deliberate Android deviation). SOURCE:
    `src/pages/broadcast/ProductShelf.tsx: handleAddToCart`
    (`getCarts`/`createCart`/`addCartItem`, sku=`item_id`).
14. **Web shelf receives live SSE deltas (`shelf:add/remove/reorder`).** VERDICT:
    **Verified** (Android defers this; §13 open question). SOURCE:
    `src/pages/broadcast/ProductShelf.tsx` lines 131-161.
15. **Web price format is fixed `en-US` `Intl.NumberFormat`.** VERDICT:
    **Verified** (Android intentionally uses device locale instead). SOURCE:
    `src/pages/broadcast/ProductShelf.tsx: formatPrice` lines 17-22.
16. **`chat/product` is a broadcaster POST (chat product-link message), not a
    viewer GET.** VERDICT: **Verified** (explains the source-ticket misnomer).
    SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/chat/product`
    (req `BroadcastChatProductLinkIn`, openapi.index.txt line 164).
17. **Compose/Material 3, Navigation-Compose, Hilt+KSP, Retrofit/OkHttp/Moshi,
    Room, Coil, SavedStateHandle process-death survival, minSdk 24/target 35.**
    VERDICT: **Unverified-assumption** for this repo (no Android sources in the
    reference set) but consistent with standard Android guidance. SOURCE:
    framework ref — developer.android.com/jetpack/compose,
    developer.android.com/guide/navigation,
    developer.android.com/topic/libraries/architecture/saving-states.
18. **Android transport is purely cookie-based.** VERDICT:
    **Unverified-assumption.** The *web* client additionally sends
    `Authorization: Bearer <accessToken>` and may send `X-IMPERSONATION-TOKEN`
    (`src/api/client.ts` lines 157-165). Whether the Android core-network mirrors
    cookie-only or also carries a bearer token is an AND-280/core-network
    decision not visible here.

### Corrections made

- Endpoint path/linkage rewritten to `GET /broadcast/sessions/{session_id}/products`
  (path segment), replacing the fictional `GET /ui/chat/product?session_id=`
  (§1, §2, §5, §11, §14 AC-1).
- Response model corrected to `BroadcastShelfListOut` (`items[]`+`count`),
  replacing `{ products: [...] }`; repository unwrap changed to `r.data.items`
  (§4, §5, §6).
- Item DTO corrected to flat `BroadcastShelfItemOut` (`item_id`, `price_cents`,
  `currency`, `image_url`); removed nested `price{}`/`media[]`/`availability{}`
  assumptions; dropped `inStock` UI field; added live-pricing fields and
  `effective/original_price` display rule (§5, §6).
- `category_id` documented as required; DEFAULT_CATEGORY demoted to defensive
  only (§5, §6, §13).
- Retrofit interface renamed `ChatProductApi`→`BroadcastShelfApi` with `@Path`
  (was `@Query`) (§4, §5, §12, §15).
- §13 risks 1 & 2 marked RESOLVED with citations; risks 3 (buy semantics) and 4
  (live updates) updated with the verified web behavior they were uncertain about.
- Price-format note: web hardcodes `en-US`; Android uses device locale (§6).

### Open assumptions

- **A1 (Buy semantics).** Routing to the AND-206 detail screen vs. web-parity
  inline add-to-cart vs. direct checkout is a product decision; only the route's
  *existence* is verified. Why unresolved: design/product sign-off needed.
- **A2 (Live SSE shelf deltas).** Web has them; this ticket fetches once.
  Whether M6 requires parity is unconfirmed. Why: scope/PM decision.
- **A3 (Android stack & framework choices).** No Android sources in the
  reference set; all module/library/lifecycle choices are best-practice
  assumptions (citation 17), inherited from AND-280/AND-206 conventions.
- **A4 (Bearer vs. cookie-only transport).** core-network's exact auth header
  policy is owned by AND-280; the web uses cookie + bearer (citation 18).
- **A5 (Android Room cache TTL/eviction, analytics facade, `ApiResult` type).**
  Inherited from core-data/core-network/core-testing (AND-280 deps), not
  independently verifiable from the provided sources.

## 17. Test Plan

Test targets: **JVM** (Robolectric/JUnit, local), **emulator** (AVD `test35`,
x86_64, API 35), **device** (Samsung Galaxy A15 5G, SM-A156U, API 34, arm64-v8a).
This ticket is pure UI/networking with no camera/biometric/WebRTC/FCM/Telecom
behavior, so almost everything runs on JVM or the headless emulator; the device
is used only to confirm arm64/API-34 parity for the real player overlay
(AND-280 hardware video decode) and offline/airplane-mode behavior.

- **TC-AND-283-01** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `BroadcastShelfApi` + MockWebServer enqueuing a 200
  `BroadcastShelfListOut` with 2 `items`. Steps: call
  `getSessionProducts("sess_1")`; inspect the recorded request and parsed result.
  Expected: request is `GET /broadcast/sessions/sess_1/products`; Moshi parses
  `items[]` (flat fields `item_id`, `price_cents`, `currency`, `image_url`,
  `category_id`), DTO→domain maps `item_id`→id and `effective_price_cents`
  (fallback `price_cents`)→priceLabel; cache `replace(sess_1, …)` invoked.
  Traces: AC-1.
- **TC-AND-283-02** — Type: unit (JVM). Target: JVM. Preconditions: repository
  with fake api+cache; api returns empty `items`. Steps: `getSessionProducts`.
  Expected: `ApiResult.Success(emptyList())`; ViewModel maps it to
  `ProductsShelfUiState.Empty`. Traces: AC-4.
- **TC-AND-283-03** — Type: unit (JVM). Target: JVM. Preconditions: ViewModel
  in `Idle`. Steps: `setExpanded(true)` once, then again. Expected: exactly ONE
  `load()` from `Idle`→`Loading`→`Ready`; second toggle does not re-fetch;
  `expanded` flips and is written to `SavedStateHandle` (process-death survival).
  Traces: AC-6, AC-7.
- **TC-AND-283-04** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer returns 422 with body
  `{"detail":[{"loc":["query","session_id"],"msg":"field required","type":"value_error"}]}`
  and the cache is empty. Steps: `getSessionProducts`; map to UI. Expected:
  failure surfaces; `detail` mapper yields the `msg` string; ViewModel →
  `Error(message, retryable=true)`; playback untouched. Traces: AC-5.
- **TC-AND-283-05** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: cache has 1 stale row for `sess_1`; MockWebServer returns 500
  (or a socket failure). Steps: `getSessionProducts`. Expected: repository
  returns `ApiResult.Success(stale)`; ViewModel → `Ready(stale=true)` and the
  "saved data" marker is set; no `Error`. Traces: AC-5, AC-8.
- **TC-AND-283-06** — Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer scripted 500 then 200. Steps: open shelf (500 →
  `Error(retryable=true)`), invoke `retry()`. Expected: second request issued,
  `Ready` rendered; matches the 500-then-Retry-then-200 acceptance sequence.
  Traces: AC-5, AC-7, AC-8.
- **TC-AND-283-07** — Type: contract/MockWebServer (JVM, OkHttp authenticator).
  Target: JVM. Preconditions: MockWebServer returns 401, then 200 on
  `/broadcast/sessions/{id}/products`, with `POST /ui/session/refresh`→200 in
  between. Steps: open shelf. Expected: exactly one refresh POST, original GET
  retried once, `Ready` rendered; a second 401 would be terminal/non-retryable.
  Traces: AC-7, AC-8.
- **TC-AND-283-08** — Type: Compose-UI (emulator `test35`). Target: emulator.
  Preconditions: `ProductsShelf` hosted with a `Ready` state of 5 cards. Steps:
  tap `ShelfToggleButton`; scroll the `LazyRow`. Expected: panel animates open,
  cards show name + locale price + Coil thumbnail; scrolling reveals later cards;
  toggle again closes. Distinct Loading (shimmer), Empty ("No products"), and
  Error+Retry states each render with correct semantics. Traces: AC-1, AC-3,
  AC-4, AC-5.
- **TC-AND-283-09** — Type: Compose-UI (emulator `test35`). Target: emulator.
  Preconditions: `Ready` card for `item_id=itm_9`, `category_id=cat_live`.
  Steps: tap the card's Buy action; capture the `onBuy` lambda arg. Expected:
  `onBuy(ShelfProductUiModel(id="itm_9", categoryId="cat_live", …))` fires once;
  host maps to nav `shop/cat_live/itm_9`. Traces: AC-2.
- **TC-AND-283-10** — Type: instrumented/e2e (emulator `test35`, MockWebServer).
  Target: emulator. Preconditions: shelf mounted inside the AND-280 viewer
  destination with a NavController under test; canned `BroadcastShelfListOut`.
  Steps: open shelf, tap Buy on the first card. Expected: NavController current
  destination becomes `shop/{categoryId}/{itemId}` with the tapped id args
  (renders + buy-route acceptance gate). Traces: AC-1, AC-2, AC-8.
- **TC-AND-283-11** — Type: instrumented (emulator `test35`). Target: emulator.
  Preconditions: shelf open and `Ready`. Steps: rotate device; trigger process
  death (`savedStateHandle` restore) via the testing API. Expected: `expanded`
  stays true, `LazyRow` scroll position restored, product list NOT re-fetched
  (held in `uiState`), `sessionId`+`expanded` survive process death. Traces:
  AC-6.
- **TC-AND-283-12** — Type: instrumented/accessibility (emulator `test35`,
  TalkBack/pseudolocale/RTL). Target: emulator. Preconditions: `Ready` shelf.
  Steps: enable pseudolocale + RTL; traverse with accessibility checks. Expected:
  each card has a `contentDescription` (name+price), Buy labeled "Buy {name}",
  toggle labeled "Show/Hide products" announcing state; open/close announced via
  live region; touch targets ≥48dp; no hardcoded strings; no focus trap over
  player controls. Traces: AC-3.
- **TC-AND-283-13** — Type: instrumented/e2e (**physical device**, SM-A156U,
  API 34, arm64-v8a). Target: **device (required)**. Preconditions: AND-280
  player playing a stream on the real device; MockWebServer (or recorded
  response) for the shelf. Steps: open the shelf over live hardware-decoded
  video, scroll, then close. Expected: the player is never paused, stuttered, or
  released by shelf presence/animation (no-playback-regression); overlay
  composes above the SurfaceView without taking video focus. MUST run on the
  device because hardware video decode + Surface compositing differ from the
  emulator. Traces: AC-3.
- **TC-AND-283-14** — Type: manual/instrumented offline (**physical device**).
  Target: **device (required)**. Preconditions: a cached shelf list for the
  session exists; then enable airplane mode (real radio off). Steps: open the
  shelf with no connectivity; tap Retry; restore connectivity and Retry again.
  Expected: offline open shows cached products with the "saved data" marker (no
  crash, no playback disruption); after reconnect, Retry fetches fresh `items`.
  Device preferred because the flaky-dev-host/real-offline radio behavior is not
  reproducible on the headless emulator. Traces: AC-5, AC-7.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (shelf renders) | TC-01, TC-08, TC-10 |
| AC-2 (buy routes to checkout) | TC-09, TC-10 |
| AC-3 (hidden by default / no playback regression / a11y) | TC-08, TC-12, TC-13 |
| AC-4 (Empty + Loading states) | TC-02, TC-08 |
| AC-5 (error+retry / cache stale marker) | TC-04, TC-05, TC-06, TC-08, TC-14 |
| AC-6 (rotation + process-death survival) | TC-03, TC-11 |
| AC-7 (lazy GET / idempotent retry / 401-refresh) | TC-03, TC-06, TC-07, TC-14 |
| AC-8 (CI gates: renders + buy + empty/500/401) | TC-05, TC-06, TC-07, TC-10 |
