---
id: AND-283
title: Products shelf
milestone: M6
epic: E38
priority: P2
size: M
status: draft
depends_on: [AND-280, AND-206]
blocks: []
---

# AND-283 — Products shelf

## 1. Overview & Goal

Add an in-stream **products shelf** to the live viewer experience: while an
authorized viewer watches a broadcast (AND-280), the app fetches the products
associated with that live session via the `chat/product` surface, renders them
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
- Web reference: `frontend/src/api/endpoints/*.ts` (the `chat/product`
  endpoints), shared types `frontend/src/api/types.ts`. Backend OpenAPI at
  `http://18.222.237.167:8000/openapi.json` — verify exact `chat/product`
  path, the session→product linkage, and the product payload shape.
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
    private val api: ChatProductApi,                 // §5; may be added here or core-network
    private val cache: ShelfProductCacheDao,         // core-data / Room, keyed by sessionId
    @IoDispatcher private val io: CoroutineDispatcher,
) : ProductsShelfRepository {

    override suspend fun getSessionProducts(sessionId: String): ApiResult<List<CatalogItem>> =
        withContext(io) {
            when (val r = api.getSessionProducts(sessionId)) {
                is ApiResult.Success -> r.data.map { it.toDomain() }
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

The shelf reads products linked to a broadcast/chat session via the
`chat/product` surface. **Verify the exact path and linkage against
`/openapi.json` and `frontend/src/api/endpoints/*.ts`** — see §13.

**Get session products** — `GET /ui/chat/product` (session-scoped)

Likely shape: `GET /ui/chat/product?session_id={sessionId}` or
`GET /ui/chat/sessions/{sessionId}/products`. Response (200):

```json
{
  "products": [
    {
      "id": "itm_001",
      "category_id": "cat_live",
      "name": "Tour Hoodie",
      "price": { "amount_cents": 4500, "currency": "USD" },
      "media": [
        { "type": "image", "url": "https://…/h.jpg", "thumbnail_url": "https://…/h_t.jpg" }
      ],
      "availability": { "in_stock": true, "quantity": 30 }
    }
  ]
}
```

The product object reuses the AND-206 `CatalogItemDto` shape (id, category_id,
name, price, media, availability), so the Buy hand-off to
`shop/{categoryId}/{itemId}` requires no field translation.

Retrofit:

```kotlin
interface ChatProductApi {
    @GET("ui/chat/product")
    suspend fun getSessionProducts(
        @Query("session_id") sessionId: String,
    ): ApiResult<SessionProductsDto>   // { products: List<CatalogItemDto> }
}
```

The request is authenticated: cookies + `X-CSRF-Token` attached by
core-network; on `401`, core-network does one `POST /ui/session/refresh` then
retries. This GET is idempotent and **is** eligible for bounded-backoff retry.
FastAPI errors surface via the shared `detail` mapper
(`string | [{msg}] | {code,...}`); the shelf treats any failure as a
retryable/stale error (no special `404` semantics — a missing list is `Empty`).

**Buy hand-off:** no new endpoint. Navigation targets the AND-206 route
`shop/{categoryId}/{itemId}`; the add-to-cart `POST /ui/shop/cart/items` and
any checkout-session creation are owned downstream (AND-206 and the cart/
checkout tickets), not by this ticket.

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
    val id: String,
    val categoryId: String?,        // null -> host uses DEFAULT_CATEGORY for the route
    val name: String,
    val priceLabel: String,         // locale currency-formatted
    val thumbnailUrl: String?,
    val inStock: Boolean,
)
```

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
- Price formatting uses `NumberFormat.getCurrencyInstance` with the DTO
  `currency`, matching AND-206 so identical products read identically across the
  shelf and the detail screen.

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
AND-280 viewer destination, return canned `chat/product` JSON, open the shelf,
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
- **Sequencing:** (1) add `ChatProductApi.getSessionProducts` + DTOs if absent;
  (2) `ProductsShelfRepository` + per-session cache; (3) `ProductsShelfViewModel`
  + state/expand logic; (4) `ProductsShelf` Compose + cards + states; (5) mount
  in AND-280's viewer screen and wire the Buy nav lambda; (6) tests.

## 13. Risks & Open Questions

- **`chat/product` endpoint shape.** Path and session linkage
  (`GET /ui/chat/product?session_id=` vs.
  `GET /ui/chat/sessions/{sessionId}/products`) are unconfirmed. *Mitigation:*
  isolate in `ChatProductApi`/repository. **Open: verify in OpenAPI /
  `frontend/src/api/endpoints/*.ts`.**
- **Product payload parity.** Assumes products use the AND-206 `CatalogItemDto`
  shape (id, category_id, price, media, availability). If `chat/product`
  returns a leaner/different shape (e.g., no `category_id`), the Buy route needs
  a fallback category and possibly a lookup. **Open: confirm payload + whether
  `category_id` is always present.**
- **Buy destination semantics.** "Buy from stream" is interpreted as routing to
  the AND-206 product-detail/add-to-cart destination (which leads to checkout).
  If product owners expect a one-tap "instant buy" straight to a checkout
  session, an additional path is needed. **Open: confirm with design/product
  whether Buy = detail+cart or direct checkout.**
- **Live updates.** Whether the product list changes mid-stream (broadcaster
  pins/unpins products) and should update in real time (SSE) is unspecified;
  this ticket fetches once on open with manual retry. **Open: confirm if live
  shelf updates are required for M6.**
- **Overlay vs. PiP / fullscreen.** Behavior of the shelf in fullscreen or
  (future) picture-in-picture is undefined; default is shelf hidden in PiP.
- **Dev host flakiness** makes a live shelf nondeterministic; all assertions use
  MockWebServer, not the dev host.

## 14. Acceptance Criteria

AC-1. With the viewer playing a broadcast for `sessionId`, opening the shelf
fetches `chat/product` for that session and renders the products as a
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
- `ChatProductApi` additions documented for core-network consumers; §13 open
  questions resolved or explicitly deferred with owners.
- Code reviewed and merged to `android-port`.
