---
id: AND-206
title: Product detail
milestone: M5
epic: E28
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-205, AND-204, AND-103, AND-166]
blocks: [AND-207]
---

# AND-206 — Product detail

## 1. Overview & Goal

Build the customer-facing **product detail** screen for the TestLogon native
Android app, reached from the catalog item grid (AND-205) at the navigation route
`shop/{categoryId}/{itemId}`. The screen resolves a single catalog item by id
(see correction below — there is **no** single-item GET endpoint; the item is
obtained from the category-items list / passed nav state and cache), renders its
image set (carousel), name, description, formatted price, stock status, and
attributes, and exposes a primary **add-to-cart** action that adds the item to a
shopping cart and reflects the result in the UI.

> **CORRECTION (review 2026-06-06).** Two foundational API claims in the original
> draft were fabricated and have been corrected throughout this spec. (1) There is
> **no** `GET /ui/shop/items/{itemId}` endpoint; no single-item GET exists at all.
> Items come from `GET /ui/catalog/categories/{category_id}/items`
> (`CatalogItemListOut`) or `GET /ui/catalog/items/search`. (2) Add-to-cart is
> **not** `POST /ui/shop/cart/items`; the real flow is create-cart
> (`POST /ui/shoppingcart/carts`) then `POST /ui/shoppingcart/carts/{cart_id}/items`
> with a `ShoppingCartItemIn` body (`sku`, `name`, `unit_price_cents` required).
> The catalog item DTO is `CatalogItemOut` with flat `price_cents`/`currency`,
> `image_urls: string[]` (no video/HLS media, no thumbnails), `attributes` as an
> object map, and `stock_count`/`stock_status` (no `availability` object). See §5
> and §16 for exact pointers.

The deliverable lives in the existing `:feature-catalog` module created by
AND-205 (a `detail/` subpackage), reusing the catalog `CatalogApi`/DTOs from
AND-204, the Coil thumbnail/image primitives from AND-103 for stills, and the
Media3/ExoPlayer player from AND-166 *if and only if* an item ever exposes video
media. **NOTE (corrected):** the verified `CatalogItemOut` DTO has only
`image_urls: string[]` — there is **no** video/HLS media field and no
`type`/`thumbnail_url` discriminator. The Media3/ExoPlayer path is therefore an
unverified, speculative capability with no backing in the current contract; it
must be treated as dead code unless/until the backend adds video media. It must behave
correctly against the unreliable plaintext dev backend: loading, error/retry,
offline-stale, and add-to-cart in-flight/failure states must all be represented.

Success is the source-ticket acceptance: **detail renders; add-to-cart works.**
Concretely — navigating from a grid cell loads and renders the item from live
data including media/price; tapping Add to cart issues an authenticated POST,
shows progress, and surfaces success (cart count / confirmation) or a typed
error with retry.

Out of scope (owned elsewhere): catalog endpoints/DTOs (AND-204), category browse
and the nav-arg contract source (AND-205), catalog search (AND-207), and the full
cart/checkout surface (cart screen, quantity editing, checkout — a later M5
ticket; this screen only performs the add mutation and reads cart count).

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace / applicationId base **`com.testlogon.android`**.
- Module layering: `app -> feature-catalog -> core-* (core-network, core-model,
  core-ui, core-data, core-testing)`. This ticket extends `:feature-catalog`
  with a `detail/` package; it adds no new Gradle module.
- **AND-205 (depends_on)** — defines the route `shop/{categoryId}/{itemId}` and
  the `categoryId`/`itemId` nav-argument contract this screen consumes; it is the
  caller that navigates here.
- **AND-204 (depends_on)** — provides `CatalogApi`, Moshi DTOs and `core-model`
  domain types. The verified server DTO is `CatalogItemOut` (flat `price_cents` +
  `currency`, `image_urls: string[]`, `attributes` object map,
  `stock_count`/`stock_status`); there is **no** `MediaDto`/`PriceDto` in the
  contract (those were assumed). This ticket adds the **category-items list** read
  (used to resolve the item by id) and **add-to-cart** methods to `CatalogApi`/a
  new `CartApi` if AND-204 did not already expose them (see Section 5).
- **AND-103 (depends_on)** — Coil image primitive / `ImageRequest` config for
  stills in the media carousel.
- **AND-166 (depends_on)** — Media3/ExoPlayer integration. **Verified: no video
  media exists in `CatalogItemOut`**, so for this ticket this dependency is a
  no-op; keep it listed only for forward-compatibility if video media is added.
- Web reference: `src/api/endpoints/cart.ts` (cart + catalog endpoints), shared
  types `src/api/types.ts`, transport `src/api/client.ts`. Backend OpenAPI index
  at `reference/openapi.index.txt`, full spec `reference/openapi.pretty.json`.
- Auth is cookie-based: session cookies + `ui_csrf` echoed as the
  `X-CSRF-Token` header (verified in `src/api/client.ts`, attached on **every**
  request, not just mutations); on `401` (only when already authenticated) the
  client does one `POST /ui/session/refresh` then retries once. The catalog list
  GET is idempotent and bounded-backoff retried; the add-to-cart POST is **not**
  auto-retried.

## 3. Functional Requirements

FR-1. **Load by id.** On entry, read `categoryId` and `itemId` from nav args and
resolve the item. **CORRECTED:** there is no single-item GET; resolve by fetching
`GET /ui/catalog/categories/{categoryId}/items` (`CatalogItemListOut`, paginated
via `page_size`/`next_token`) and selecting the entry whose `item_id == itemId`,
falling back to a cached row when offline. (An optimization is to seed the screen
from list data already held by AND-205 and only re-fetch for freshness.) Render a
loading state until the first result resolves.

FR-2. **Detail render.** Display item name, formatted price from `price_cents` +
`currency` (locale currency), stock status derived from `stock_status` /
`stock_count`, description (plain text / simple markup), and an attribute list
rendered from the `attributes` **object map** (`Record<String, Any>`) when present.

FR-3. **Media carousel.** Render `image_urls[]` in a horizontally pageable
carousel (`HorizontalPager`) with a page indicator. Image entries use the AND-103
Coil primitive. **CORRECTED:** the contract has no video media field, no
`type` discriminator, and no `thumbnail_url`; there are no HLS/video entries, so
no AND-166 player is instantiated for any current item. (Forward-compat: if a
video media array is added later, the carousel can branch on it then.)

FR-4. **Add to cart.** A primary, full-width button performs the **two-step**
verified cart flow: (1) ensure a cart exists — reuse a known `cart_id` or create
one via `POST /ui/shoppingcart/carts` (returns `ShoppingCartSummary`); (2)
`POST /ui/shoppingcart/carts/{cart_id}/items` with a `ShoppingCartItemIn` body.
Required fields are `sku`, `name`, `unit_price_cents`; `quantity` defaults to 1
(server bounds 1..1000); pass `item_id`/`category_id`/`image_url` from the item.
(`sku` is required by the server but is not present on `CatalogItemOut` — see §16
open assumption AS-1 on sku derivation.) The button shows an in-progress spinner
and is disabled while in flight and when the item is out of stock.

FR-5. **Add-to-cart result.** The add response is `ShoppingCartItemOut` — a
**single line item**, NOT a cart summary; it has **no** `item_count` and **no**
`subtotal`. On success, show confirmation (snackbar "Added to cart"); to update a
cart-count badge the client must separately read
`GET /ui/shoppingcart/carts/{cart_id}/items` (`ShoppingCartItemsOut`) or
`GET /ui/shoppingcart/carts/{cart_id}/total` (`ShoppingCartTotalOut`). On
failure, keep the item rendered, re-enable the button, and show a typed error
(snackbar with Retry) mapped from the FastAPI `detail`.

FR-6. **Out-of-stock.** When `stock_status` indicates unavailable (or
`stock_count == 0`), the Add to cart button is disabled with an explanatory
label ("Out of stock") and the quantity stepper is hidden. Note `stock_status`
defaults to `"unlimited"` server-side, in which case stock is unbounded.

FR-7. **Back navigation.** A top app bar with title (item name once loaded) and
an Up affordance returns to the catalog browse screen preserving its state.

FR-8. **State preservation.** Carousel page index and selected quantity survive
configuration changes; `itemId`/`categoryId` come from nav args and survive
process death via `SavedStateHandle`.

FR-9. **Distinct non-happy states.** Loading, not-found (item id absent from the
category list — **there is no item `404`**; "not found" is a client-side
condition after the list resolves with no matching `item_id`), generic error
with retry, and offline-stale (cached item shown with a banner) are each
visually distinct and never conflated with one another.

## 4. Technical Design

New code under `com.testlogon.android.feature.catalog.detail` inside the existing
`:feature-catalog` library module.

### Layers

```
detail/ui/        ProductDetailScreen, MediaCarousel, AttributeList,
                  AddToCartBar, ProductDetailStateScaffold
detail/ui/state   ProductDetailUiState, ProductUiModel, MediaUiModel,
                  AddToCartUiState
detail/vm/        ProductDetailViewModel
detail/data/      CatalogDetailRepository (interface) + Impl
detail/di/        CatalogDetailModule (binds repository)
```

The route, nav-args, and graph entry are defined in AND-205's `CatalogNavGraph`;
this ticket registers the `composable(CatalogRoutes.PRODUCT_DETAIL)` destination
and reads typed args.

### Repository

> **CORRECTED contract note.** `getItem` is implemented over the category-items
> *list* endpoint (no single-item GET exists) and `addToCart` performs the
> two-step create-cart-then-add flow. The return type of the add is the created
> line item (`CartItem`), not a cart summary with a count; a count, if needed for
> the badge, is read separately (see §5).

```kotlin
interface CatalogDetailRepository {
    /** Resolves item by id from GET /ui/catalog/categories/{categoryId}/items.
     *  Idempotent; bounded-backoff retried by core-network. */
    suspend fun getItem(categoryId: String, itemId: String): ApiResult<CatalogItem>

    /** Two-step: ensure cart (POST /ui/shoppingcart/carts) then
     *  POST /ui/shoppingcart/carts/{cartId}/items. Non-idempotent; never auto-retried. */
    suspend fun addToCart(item: CatalogItem, quantity: Int): ApiResult<CartItem>
}
```

```kotlin
class CatalogDetailRepositoryImpl @Inject constructor(
    private val api: CatalogApi,                 // from AND-204
    private val cache: CatalogItemCacheDao,      // core-data / Room (optional read-through)
    @IoDispatcher private val io: CoroutineDispatcher,
) : CatalogDetailRepository {

    override suspend fun getItem(categoryId: String, itemId: String): ApiResult<CatalogItem> =
        withContext(io) {
            // No single-item GET — fetch the category list and select by id.
            when (val r = api.listCategoryItems(categoryId)) {  // GET /ui/catalog/categories/{categoryId}/items
                is ApiResult.Success -> r.data.items.firstOrNull { it.itemId == itemId }
                    ?.toDomain()
                    ?.also { cache.upsert(it.toEntity()) }
                    ?.let { ApiResult.Success(it) }
                    ?: ApiResult.Failure.NotFound       // id absent from list (client-side not-found)
                is ApiResult.Failure -> cache.find(itemId)?.toDomain()
                    ?.let { ApiResult.Success(it) }      // stale fallback
                    ?: r
            }
        }

    override suspend fun addToCart(item: CatalogItem, quantity: Int): ApiResult<CartItem> =
        withContext(io) {
            // Step 1: ensure a cart (reuse stored cart_id or create one).
            val cartId = cartStore.currentCartId()
                ?: when (val c = api.createCart()) {     // POST /ui/shoppingcart/carts -> ShoppingCartSummary
                    is ApiResult.Success -> c.data.cartId.also { cartStore.setCurrentCartId(it) }
                    is ApiResult.Failure -> return@withContext c
                }
            // Step 2: add the line item (sku/name/unit_price_cents required).
            api.addCartItem(
                cartId,
                ShoppingCartItemInDto(
                    sku = item.sku,                      // see §16 AS-1: sku derivation
                    name = item.name,
                    unitPriceCents = item.priceCents,
                    quantity = quantity,
                    itemId = item.itemId,
                    categoryId = item.categoryId,
                    imageUrl = item.imageUrls.firstOrNull(),
                ),
            ).toApiResult { it.toDomain() }              // ShoppingCartItemOut -> CartItem
        }
}
```

### ViewModel

```kotlin
@HiltViewModel
class ProductDetailViewModel @Inject constructor(
    private val repository: CatalogDetailRepository,
    private val analytics: Analytics,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val itemId: String = checkNotNull(savedState[CatalogRoutes.ARG_ITEM_ID])
    val categoryId: String = checkNotNull(savedState[CatalogRoutes.ARG_CATEGORY_ID])

    private val _uiState = MutableStateFlow<ProductDetailUiState>(ProductDetailUiState.Loading)
    val uiState: StateFlow<ProductDetailUiState> = _uiState.asStateFlow()

    private val _addState = MutableStateFlow<AddToCartUiState>(AddToCartUiState.Idle)
    val addState: StateFlow<AddToCartUiState> = _addState.asStateFlow()

    private val _events = Channel<DetailEvent>(Channel.BUFFERED)
    val events: Flow<DetailEvent> = _events.receiveAsFlow()

    init { load() }

    fun load() {
        viewModelScope.launch {
            _uiState.value = ProductDetailUiState.Loading
            _uiState.value = when (val r = repository.getItem(categoryId, itemId)) {
                is ApiResult.Success -> ProductDetailUiState.Ready(r.data.toUiModel())
                is ApiResult.Failure ->
                    if (r.isNotFound) ProductDetailUiState.NotFound   // id absent from category list
                    else ProductDetailUiState.Error(r.message, retryable = r.retryable)
            }
        }
    }

    fun addToCart(quantity: Int = 1) {
        if (_addState.value is AddToCartUiState.InFlight) return
        viewModelScope.launch {
            _addState.value = AddToCartUiState.InFlight
            when (val r = repository.addToCart(item, quantity)) {
                is ApiResult.Success -> {
                    _addState.value = AddToCartUiState.Idle
                    analytics.log("catalog_add_to_cart_success", "item_id" to itemId, "qty" to quantity)
                    // ShoppingCartItemOut has no cart count; emit added line + refresh badge separately.
                    _events.send(DetailEvent.AddedToCart(r.data))
                }
                is ApiResult.Failure -> {
                    _addState.value = AddToCartUiState.Idle
                    analytics.log("catalog_add_to_cart_error", "item_id" to itemId, "code" to r.code)
                    _events.send(DetailEvent.AddToCartFailed(r.message))
                }
            }
        }
    }

    fun retry() = load()
}

sealed interface DetailEvent {
    // Corrected: add response is a single line item, not a count.
    data class AddedToCart(val addedItem: CartItem) : DetailEvent
    data class AddToCartFailed(val message: String) : DetailEvent
}
```

### Compose

```kotlin
@Composable
fun ProductDetailScreen(
    state: ProductDetailUiState,
    addState: AddToCartUiState,
    onAddToCart: (quantity: Int) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
)
```

`ProductDetailScreen` uses a `Scaffold` with a `TopAppBar` (Up + dynamic title)
and a pinned `AddToCartBar` as the `bottomBar`. The body is a vertical scroll:
`MediaCarousel` (`HorizontalPager` + `Modifier.aspectRatio(1f)`), name + price
header, availability chip, description, and `AttributeList`. One-shot
`DetailEvent`s are collected with `LaunchedEffect` and routed to a
`SnackbarHostState` and cart-badge update. Video pages bind a single Media3
`ExoPlayer` (AND-166) created in a lifecycle-aware `remember`/`DisposableEffect`
and released on `onDispose`.

## 5. API Contract

> **This section was substantially corrected during review.** The original draft's
> `GET /ui/shop/items/{itemId}` and `POST /ui/shop/cart/items` endpoints **do not
> exist** in the backend. All shapes below are verified against
> `reference/openapi.index.txt`, `reference/openapi.pretty.json`
> (`components.schemas.*`), and `src/api/endpoints/cart.ts` + `src/api/types.ts`.

**Resolve item by id** — there is **no single-item GET**. Use the category list:
`GET /ui/catalog/categories/{categoryId}/items` →
`200: CatalogItemListOut` (`{ items: CatalogItemOut[], next_token?: string }`),
query params `page_size`, `next_token`. Select the entry with the matching
`item_id`. (Alt: `GET /ui/catalog/items/search?q=…`.) `CatalogItemOut` (verified
fields):

```json
{
  "category_id": "cat_books",
  "item_id": "itm_001",
  "name": "Example Item",
  "description": "Full long-form description…",
  "price_cents": 1999,
  "currency": "USD",
  "image_urls": ["https://…/a.jpg", "https://…/b.jpg"],
  "attributes": { "SKU": "EX-001", "Weight": "1.2 kg" },
  "creator_id": "usr_…",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-02T00:00:00Z",
  "stock_count": 12,
  "stock_status": "in_stock",
  "low_stock_threshold": 5,
  "position": 0
}
```
Required: `category_id, item_id, name, price_cents, currency, image_urls,
attributes, created_at, updated_at`. `stock_status` defaults to `"unlimited"`.
There is **no** `price` object, **no** `availability` object, and **no** `media`
array / video / thumbnails.

**Add to cart** — two steps (verified in `src/api/endpoints/cart.ts`):

1. Create/ensure cart: `POST /ui/shoppingcart/carts` →
   `200: ShoppingCartSummary` = `{ cart_id, status, created_at, currency, … }`
   (**no** `item_count`, **no** `subtotal`).
2. Add line item: `POST /ui/shoppingcart/carts/{cart_id}/items`, body
   `ShoppingCartItemIn`, → `200: ShoppingCartItemOut` (a single line item).

`ShoppingCartItemIn` (required `sku`, `name`, `unit_price_cents`):

```json
{
  "sku": "EX-001",
  "name": "Example Item",
  "unit_price_cents": 1999,
  "quantity": 1,
  "item_id": "itm_001",
  "category_id": "cat_books",
  "image_url": "https://…/a.jpg"
}
```
Server constraints: `quantity` integer 1..1000 (default 1); `unit_price_cents`
0..100000000; `sku` 1..128 chars; `name` 1..256 chars. (A catalog-specific
variant `POST /ui/shoppingcart/carts/{cart_id}/items/catalog` with
`CatalogCartItemIn` also exists; the generic items endpoint matches the web
client and is what this ticket uses.)

Add response `ShoppingCartItemOut` (≈ web `CartItem`):

```json
{ "sku": "EX-001", "name": "Example Item", "quantity": 1,
  "unit_price_cents": 1999, "line_total_cents": 1999, "updated_at": "…" }
```

**Cart count for the badge** is NOT in any of the above. Read it via
`GET /ui/shoppingcart/carts/{cart_id}/items` (`ShoppingCartItemsOut`) or
`GET /ui/shoppingcart/carts/{cart_id}/total` (`ShoppingCartTotalOut`).

Retrofit (verified paths):

```kotlin
interface CatalogApi {
    @GET("ui/catalog/categories/{categoryId}/items")
    suspend fun listCategoryItems(
        @Path("categoryId") categoryId: String,
        @Query("page_size") pageSize: Int = 50,
        @Query("next_token") nextToken: String? = null,
    ): ApiResult<CatalogItemListOutDto>
}

interface CartApi {
    @POST("ui/shoppingcart/carts")
    suspend fun createCart(): ApiResult<ShoppingCartSummaryDto>

    @POST("ui/shoppingcart/carts/{cartId}/items")
    suspend fun addCartItem(
        @Path("cartId") cartId: String,
        @Body body: ShoppingCartItemInDto,
    ): ApiResult<ShoppingCartItemOutDto>

    @GET("ui/shoppingcart/carts/{cartId}/items")
    suspend fun getCartItems(@Path("cartId") cartId: String): ApiResult<ShoppingCartItemsOutDto>
}
```

All requests are authenticated. Per `src/api/client.ts`, the `X-CSRF-Token`
header (from the `ui_csrf` cookie) is attached to **every** request (GET and
POST alike), plus cookies via `credentials: "include"`. On `401` — only when the
user is already authenticated — the client performs one `POST /ui/session/refresh`
then retries the request once; a second `401` logs out. The cart POSTs are
mutating and excluded from idempotent-GET retry. FastAPI errors surface via the
shared `detail` mapper. Documented error responses for these endpoints are
`400, 401, 403, 422, 429` (validation failures → `422: HTTPValidationError`,
shape `{ detail: [{ loc, msg, type }] }`). **No `404` and no `409`** are
documented for the item-resolution or cart-add paths; "not found" is a
client-side outcome (id absent from list) and over-quantity is a `422`.

## 6. Data & State Management

```kotlin
sealed interface ProductDetailUiState {
    data object Loading : ProductDetailUiState
    data class Ready(val product: ProductUiModel, val stale: Boolean = false) : ProductDetailUiState
    data object NotFound : ProductDetailUiState
    data class Error(val message: String, val retryable: Boolean) : ProductDetailUiState
}

sealed interface AddToCartUiState { data object Idle; data object InFlight }

data class ProductUiModel(
    val id: String,
    val categoryId: String,
    val name: String,
    val priceLabel: String,          // locale currency-formatted
    val description: String,
    val inStock: Boolean,
    val maxQuantity: Int?,           // null when unknown
    val attributes: List<Pair<String, String>>,
    val media: List<MediaUiModel>,
)

// Corrected: contract exposes only image_urls (no video/thumbnail). isVideo is
// retained for forward-compat but is always false for current items.
data class MediaUiModel(val isVideo: Boolean = false, val url: String)
```

- **Caching (core-data / Room 2.6).** On a successful item GET the item is
  upserted to a `catalog_items` table; on network failure the cached row is
  returned as `Ready(stale = true)` behind a "Showing saved data" banner. Cache
  rows hold product content only (no user/cart data).
- **State retention.** `itemId`/`categoryId` live in `SavedStateHandle` (process
  death). Carousel page index and selected quantity are held via
  `rememberSaveable` within the back-stack entry. `addState` is transient and not
  persisted; one-shot results are delivered via a `Channel` to avoid re-emitting
  snackbars on recomposition/rotation.
- Domain→UI mapping formats price from `price_cents`/100 with
  `NumberFormat.getCurrencyInstance` using the DTO `currency`. **Corrected:** the
  add response carries no cart count, so the badge is refreshed by reading
  `GET /ui/shoppingcart/carts/{cart_id}/items` (or `/total`) after a successful
  add; the `AddedToCart` event carries the added line item and triggers that
  refresh into a shared cart `StateFlow`.

## 7. Error Handling & Resilience

- **Timeouts.** Item GET and cart POST use the core-network ~20s call timeout
  for the unreliable dev host.
- **Idempotent retry.** The item GET is eligible for bounded-backoff retry. The
  cart POST is **never** auto-retried (avoids duplicate cart additions); retry is
  user-initiated via the snackbar action only.
- **Item load failure.** No cache → `Error(retryable=true)` full-screen retry;
  item id absent from the category list → `NotFound` (distinct copy, Up
  affordance, no retry — **corrected: this is client-side, not an HTTP `404`**).
  With cache → `Ready(stale=true)` + non-blocking banner.
- **Add-to-cart failure.** Item stays rendered; button re-enabled; snackbar with
  mapped message + Retry. Invalid-quantity / validation errors are returned as
  **`422: HTTPValidationError`** (`{detail:[{loc,msg,type}]}`) — shown as terminal,
  non-retryable messages (**corrected: no `409` is documented for these
  endpoints**). Either create-cart or add-item step can fail; surface the failing
  step's message and do not leave a half-created cart blocking retry.
- **Double-tap guard.** `addToCart` ignores re-entry while `InFlight`; the button
  is also disabled in that state.
- **401.** Transparent to this layer (refresh-once interceptor). If refresh
  fails, the error maps to a non-retryable auth error and re-auth routing is
  delegated to the app shell.
- **Media failure.** A broken still falls back to the Coil error placeholder; an
  HLS load error shows an inline player error without failing the whole screen.

## 8. Security & Privacy

- No new credentials or secrets. Session rides the existing persistent cookie
  jar; cookies and `ui_csrf`/`X-CSRF-Token` are attached by core-network and are
  never read or logged by this module.
- The cart POST is a state-changing request and **must** carry the CSRF header;
  this is enforced by the shared CSRF interceptor, not re-implemented here.
- Dev backend is **plaintext HTTP**; cleartext is permitted only for the dev
  flavor via the existing network-security-config (no change here). Release
  builds target HTTPS hosts; HLS/image loads share the same OkHttp/TLS policy.
- Cached Room rows contain product content only — no PII, no cart/account data.
- Logs and analytics carry only item/category ids and aggregate cart counts; no
  prices tied to users, no auth material.

## 9. Accessibility & i18n

- All user-facing strings from `feature-catalog` `strings.xml` (no hardcoded
  text); pseudolocale-tested. Price via `NumberFormat`/locale currency.
- Media carousel: each page has a `contentDescription` (item name + "image N of
  M"); the page indicator is `Modifier.clearAndSetSemantics {}` decorative; video
  controls (AND-166) expose accessible play/pause labels.
- Add to cart button has a descriptive label that reflects state ("Add to cart",
  "Adding…", "Out of stock"); state changes announced via the snackbar live
  region. The quantity stepper exposes increment/decrement actions.
- Touch targets ≥ 48dp; layouts use start/end (RTL-safe) and respect dynamic
  type without clipping. Color contrast for price/name/availability meets WCAG AA
  in light and dark (core-ui Material 3 tokens).
- Snackbar results (added / failed) are announced to TalkBack.

## 10. Telemetry & Logging

Via the shared analytics facade (no PII):

- `catalog_item_view` — { category_id, item_id, has_video, media_count, latency_ms }
- `catalog_media_swipe` — { item_id, page_index, is_video }
- `catalog_add_to_cart_tap` — { item_id, quantity }
- `catalog_add_to_cart_success` — { item_id, quantity, cart_count }
- `catalog_add_to_cart_error` — { item_id, code, http_status }
- `catalog_item_load_error` — { item_id, scope: get|not_found, code, http_status }

`Timber`/`Logger` wrapper at `DEBUG` for state transitions, `WARN`/`ERROR` for
failures. Never log cookies, CSRF tokens, request bodies with auth context, or
full authenticated URLs. Latency measured around `getItem`.

## 11. Testing Strategy

**Unit (core-testing, JUnit + Turbine + MockWebServer):**
- `CatalogDetailRepositoryImpl.getItem` fetches the category list, selects the
  matching `item_id`, maps DTO→domain, upserts cache on success, returns
  `NotFound` when the id is absent, and returns `stale` cached item on network
  failure; surfaces failure when no cache.
- `addToCart` performs create-cart-then-add, maps success→`CartItem` and
  failure→typed message; verifies neither POST is auto-retried (issued once each)
  for a 500, and that a create-cart failure short-circuits before the add.
- `ProductDetailViewModel`: `Loading→Ready` on success, `→NotFound` when the id
  is absent from the list, `→Error(retryable)` on transport error; `addToCart`
  emits `InFlight` then
  `AddedToCart`/`AddToCartFailed`; re-entry guard while `InFlight` issues one
  request; `retry()` re-loads.
- Price formatting across currencies/locales.

**Compose UI (`createAndroidComposeRule`):**
- Detail renders name/price/description/attributes and media carousel; swiping
  advances the page indicator.
- Add to cart shows progress, disables during in-flight, and shows the success
  snackbar + re-enables on completion (assert via test tags).
- Out-of-stock disables the button with the correct label.
- `NotFound`, retryable `Error` + working Retry, and stale banner each render
  with correct semantics.

**Instrumented integration (MockWebServer):** navigate from a grid cell into
detail, render canned `CatalogItemListOut` JSON matching Section 5, perform
add-to-cart exercising both the `POST /ui/shoppingcart/carts` and
`POST /ui/shoppingcart/carts/{cart_id}/items` calls and a follow-up cart-items
read for the badge; include an item-not-found case (id absent from list), a
500-on-add failure with Retry, a `422` validation case, and a
401-then-refresh-then-200 sequence for the list GET.

Acceptance gate: automated tests proving **detail renders** (item GET → fully
populated screen) and **add-to-cart works** (POST → success snackbar + updated
cart count).

## 12. Dependencies & Sequencing

- **Hard deps:** AND-205 (route + nav-arg contract + caller) and AND-204
  (`CatalogApi` + DTOs + domain) must merge first; AND-103 (image primitive) for
  stills; AND-166 (Media3 player) for video media.
- **Transitive:** AND-027/core-network (typed `ApiResult`, cookie jar, CSRF
  interceptor, 401-refresh authenticator, idempotent-GET retry) must be in place.
- **Blocks:** AND-207 (catalog search) reuses this detail destination as its
  result tap target; the full cart screen (later M5) consumes the cart count /
  `CartSummary` surfaced here.
- **Sequencing:** (1) add `getItem`/`addToCart` to `CatalogApi` + DTOs if absent;
  (2) `CatalogDetailRepository` + cache read-through; (3) `ProductDetailViewModel`
  + state/events; (4) Compose screen, carousel, add-to-cart bar; (5) register nav
  destination + tests. If item media omits video, AND-166 wiring is a no-op path.

## 13. Risks & Open Questions

- **Item-by-id endpoint shape.** RESOLVED (review): no single-item GET exists.
  Item is resolved from `GET /ui/catalog/categories/{categoryId}/items`
  (`CatalogItemListOut`); isolate in repository. *Risk:* large categories require
  pagination to find the id — prefer seeding from AND-205 list state.
- **Cart endpoint contract.** RESOLVED (review): two-step
  `POST /ui/shoppingcart/carts` then
  `POST /ui/shoppingcart/carts/{cart_id}/items` (`ShoppingCartItemIn`); a cart
  **must** exist first. Verified in `src/api/endpoints/cart.ts`.
- **Availability/quantity fields.** RESOLVED (review): DTO uses
  `stock_count` (nullable int) + `stock_status` (string, default `"unlimited"`),
  not an `availability` object. Stepper max derives from `stock_count` when set.
- **Price shape.** RESOLVED (review): flat `price_cents` (int) + `currency`
  (string) on `CatalogItemOut`; no nested `{amount_cents}` object.
- **Media typing.** RESOLVED (review): no media/video field exists — only
  `image_urls: string[]`. AND-166/HLS is dead-code for current items.
- **`sku` for add-to-cart.** OPEN: `ShoppingCartItemIn.sku` is required but
  `CatalogItemOut` has no `sku` field (only `item_id`). Web stores carry `sku` on
  cart items but the source of truth for a catalog item's sku is unconfirmed; see
  §16 AS-1. *Mitigation:* confirm with backend whether `item_id` doubles as sku
  or whether sku lives in `attributes`.
- **Quantity stepper inclusion.** Source scope says "add-to-cart" without
  quantity; default to qty=1 with an optional stepper. **Open: confirm with
  design whether the stepper ships in M5.**
- **Dev host flakiness** makes live add-to-cart nondeterministic; all assertions
  use MockWebServer, not the dev host.

## 14. Acceptance Criteria

AC-1. Navigating from a catalog grid cell to `shop/{categoryId}/{itemId}`
resolves the item via `GET /ui/catalog/categories/{categoryId}/items`
(`CatalogItemListOut`, select by `item_id`) and renders name, locale-formatted
price (from `price_cents`/`currency`), description, attributes, and stock status
(**detail renders** — primary).
AC-2. The media carousel renders all `image_urls[]` entries via the AND-103
primitive; swiping updates the page indicator. (No video media exists in the
contract; the AND-166 player path is not exercised by current items.)
AC-3. Tapping Add to cart performs the two-step flow — at most one
`POST /ui/shoppingcart/carts` (only if no cart yet) and exactly one
`POST /ui/shoppingcart/carts/{cart_id}/items` — shows an in-flight spinner, and
on 200 shows an "Added to cart" snackbar and refreshes the cart-count badge via a
subsequent cart-items/total read (**add-to-cart works** — primary).
AC-4. Add-to-cart failure (either step) keeps the item rendered, re-enables the
button, and shows a typed error with a working Retry; neither POST is
auto-retried.
AC-5. Out-of-stock items (`stock_status`/`stock_count == 0`) disable Add to cart
with an explanatory label and hide the quantity stepper.
AC-6. An item id absent from the category list renders a distinct Not Found state
(client-side, no HTTP `404`); transport errors render a retryable error whose
Retry recovers; network failure with cache shows the item with a stale banner.
AC-7. Carousel page index and selected quantity survive rotation; `itemId`/
`categoryId` survive process death; Up returns to the catalog preserving its
state.
AC-8. ExoPlayer instances are released when the screen is backgrounded or
disposed (no leaked players; verified).
AC-9. All automated tests in Section 11 pass in CI, including the renders +
add-to-cart gates and the not-found / add-failure / `422` / 401-refresh sequences.

## 15. Definition of Done

- Product detail implemented in `:feature-catalog` (`detail/` package), nav
  destination registered in AND-205's graph, builds with Gradle 8.9 / AGP 8.7.3,
  JDK 17, compileSdk/targetSdk 35, minSdk 24.
- All FRs and ACs implemented and verified; no hardcoded user-facing strings.
- Unit, Compose, and instrumented tests merged and green in CI; coverage for
  repository mapping/caching, ViewModel state/event logic, add-to-cart single-
  shot guard, and media lifecycle.
- Lint/detekt/ktlint clean; no new cleartext exceptions beyond the existing dev
  flavor config; ExoPlayer release verified (no leaks).
- Telemetry events (Section 10) emitted and verified; no secrets/PII logged.
- Accessibility pass (TalkBack + pseudolocale + RTL) completed.
- Cart-count / `CartSummary` surface documented for the downstream cart screen;
  any `CatalogApi` additions documented for AND-204 consumers.
- Code reviewed and merged to `android-port`; Section 13 open questions resolved
  or explicitly deferred with owners.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
`openapi.index.txt` (OpenAPI index), `openapi.pretty.json`
(`components.schemas.*`), and frontend files under `src/`.

1. **"Item is fetched via `GET /ui/shop/items/{itemId}`."** VERDICT: **Corrected.**
   No such endpoint exists; no single-item GET exists at all. Items come from the
   list endpoint. SOURCE: `openapi.index.txt` (no `/ui/shop/items/...` line; the
   catalog read is `GET /ui/catalog/categories/{category_id}/items`); confirmed
   absent in `src/api/endpoints/cart.ts` (no `getItem`).
2. **"Item resolved from category list."** VERDICT: **Verified (corrected target).**
   SOURCE: OpenAPI `GET /ui/catalog/categories/{category_id}/items` →
   `resp=200:CatalogItemListOut`; `src/api/endpoints/cart.ts: getCategoryItems`.
3. **`CatalogItemListOut` shape `{items[], next_token?}`.** VERDICT: **Verified.**
   SOURCE: `openapi.pretty.json` schema `CatalogItemListOut`;
   `src/api/types.ts: PaginatedList<CatalogItem>`.
4. **Item DTO uses nested `price:{amount_cents,currency}`.** VERDICT: **Corrected.**
   Actual: flat `price_cents` (int) + `currency` (string). SOURCE:
   `openapi.pretty.json` schema `CatalogItemOut` (props `price_cents`, `currency`);
   `src/api/types.ts: CatalogItem`.
5. **Item DTO has `availability:{in_stock,quantity}`.** VERDICT: **Corrected.**
   Actual: `stock_count` (nullable int) + `stock_status` (string, default
   `"unlimited"`) + `low_stock_threshold`. SOURCE: `openapi.pretty.json` schema
   `CatalogItemOut`; `src/api/types.ts: CatalogItem`.
6. **Item DTO has `attributes` as a `[{key,value}]` array.** VERDICT: **Corrected.**
   Actual: `attributes` is an object map (`Record<string, unknown>` /
   `additionalProperties:true`). SOURCE: `openapi.pretty.json` schema
   `CatalogItemOut.attributes`; `src/api/types.ts: CatalogItem.attributes`.
7. **Item DTO has `media[]` with `type`/`url`/`thumbnail_url`, incl. HLS video.**
   VERDICT: **Corrected.** Actual: only `image_urls: string[]`; no media array, no
   video, no thumbnails, no `type` discriminator. SOURCE: `openapi.pretty.json`
   schema `CatalogItemOut.image_urls`; `src/api/types.ts: CatalogItem.image_urls`.
8. **Add-to-cart is `POST /ui/shop/cart/items` with `{item_id,quantity}`.**
   VERDICT: **Corrected.** No such endpoint. Real path:
   `POST /ui/shoppingcart/carts/{cart_id}/items`, and a cart must be created first.
   SOURCE: `openapi.index.txt` lines for `/ui/shoppingcart/carts` and
   `/ui/shoppingcart/carts/{cart_id}/items`; `src/api/endpoints/cart.ts:
   createCart`, `addCartItem`.
9. **A cart must be created before adding (`POST /ui/shoppingcart/carts`).**
   VERDICT: **Verified.** SOURCE: OpenAPI `POST /ui/shoppingcart/carts`
   `resp=200:ShoppingCartSummary`; `src/api/endpoints/cart.ts: createCart`.
10. **Add body is `ShoppingCartItemIn` (required `sku`,`name`,`unit_price_cents`).**
    VERDICT: **Verified.** SOURCE: `openapi.pretty.json` schema
    `ShoppingCartItemIn` (`required:[sku,name,unit_price_cents]`, `quantity` default
    1 / 1..1000); `src/api/types.ts: CartItemIn`.
11. **Add response returns `{cart_id, item_count, subtotal}`.** VERDICT:
    **Corrected.** Actual response is `ShoppingCartItemOut` — a single line item
    (`sku,name,quantity,unit_price_cents,line_total_cents,updated_at`); it has no
    `item_count` and no `subtotal`. SOURCE: OpenAPI
    `POST /ui/shoppingcart/carts/{cart_id}/items` `resp=200:ShoppingCartItemOut`;
    `src/api/types.ts: CartItem`.
12. **`ShoppingCartSummary` carries a cart count.** VERDICT: **Corrected.** It does
    not (`cart_id,status,created_at,currency,…` only). Count must be read via
    `GET /ui/shoppingcart/carts/{cart_id}/items` (`ShoppingCartItemsOut`) or
    `/total` (`ShoppingCartTotalOut`). SOURCE: `openapi.pretty.json` schema
    `ShoppingCartSummary`; OpenAPI index lines for `.../items` and `.../total`.
13. **Auth: `ui_csrf` cookie echoed as `X-CSRF-Token`.** VERDICT: **Verified.**
    SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
14. **CSRF header attached only to mutating POSTs.** VERDICT: **Corrected.** It is
    attached to **every** request (the header-build block runs for all methods).
    SOURCE: `src/api/client.ts` (CSRF set before method-specific logic).
15. **401 → one `POST /ui/session/refresh` then retry once.** VERDICT: **Verified
    (with nuance).** Only when the user is already authenticated; a second 401 logs
    out; unauthenticated 401s propagate. SOURCE: `src/api/client.ts`
    (`refreshSession` posts `/ui/session/refresh`; single-flight `refreshPromise`,
    one retry) and OpenAPI `POST /ui/session/refresh`.
16. **Cart-add mutation is not auto-retried.** VERDICT: **Unverified-assumption
    (Android-side policy).** The web client does not retry POSTs beyond the single
    401-refresh retry; the "never auto-retry mutations" rule is an Android
    core-network (AND-027) policy,
    not in the OpenAPI/frontend sources. SOURCE:
    framework ref — design decision; no contradicting evidence in `src/api/client.ts`.
17. **Error responses for cart/catalog reads/adds.** VERDICT: **Verified.**
    Documented codes are `400,401,403,422,429`; validation → `422:HTTPValidationError`.
    No `404` (item-resolution) and no `409` (add) are documented. SOURCE:
    `openapi.index.txt` (resp lists for the cart/catalog lines);
    `openapi.pretty.json` schema `HTTPValidationError`.
18. **"Item `404` → NotFound state."** VERDICT: **Corrected.** Not-found is a
    client-side condition (id absent from the category list); there is no item GET
    to return 404. SOURCE: see citations 1, 2, 17.
19. **Media3/ExoPlayer (AND-166) used for HLS previews.** VERDICT:
    **Unverified-assumption / not applicable.** No video media in the contract
    (citation 7), so this path is dead for current items. SOURCE: framework ref
    (Media3) — capability unused; no backing field in `CatalogItemOut`.
20. **Price formatting via `NumberFormat.getCurrencyInstance`.** VERDICT:
    **Unverified-assumption (Android framework choice).** Reasonable given
    `price_cents`+`currency`; not derivable from sources. SOURCE: framework ref —
    `https://developer.android.com/reference/java/text/NumberFormat`.
21. **Compose `HorizontalPager` for the carousel; `SavedStateHandle` for nav args;
    Room for offline cache.** VERDICT: **Unverified-assumption (Android framework
    choices).** SOURCE: framework refs —
    `https://developer.android.com/develop/ui/compose/layouts/pager`,
    `https://developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate`,
    `https://developer.android.com/training/data-storage/room`.

### Corrections made

- §1/§Overview, §5, §14 AC-1: item retrieval changed from the non-existent
  `GET /ui/shop/items/{itemId}` to `GET /ui/catalog/categories/{categoryId}/items`
  with client-side selection by `item_id` (citations 1, 2).
- §5, §6, §FR-2: price corrected to flat `price_cents`+`currency`; stock corrected
  to `stock_count`/`stock_status`; attributes corrected to an object map (4, 5, 6).
- §Overview, §2, §FR-3, §6, §14 AC-2: removed video/HLS/`media[]`/thumbnail
  assumptions; carousel now over `image_urls[]`; AND-166 marked no-op (7, 19).
- §5, §FR-4, §Technical Design, §14 AC-3: add-to-cart corrected to the two-step
  create-cart + `POST /ui/shoppingcart/carts/{cart_id}/items` flow with
  `ShoppingCartItemIn` (8, 9, 10).
- §FR-5, §6, §14 AC-3, ViewModel/`DetailEvent`: add response corrected to a single
  `ShoppingCartItemOut` line item (no count); badge now refreshed via a separate
  cart-items/total read (11, 12).
- §2, §5: CSRF clarified to apply to all requests, not just mutations (14).
- §FR-9, §7, §13, §14 AC-6: item "404" reframed as client-side not-found; "409"
  removed in favor of `422` validation errors (17, 18).

### Open assumptions

- **AS-1 (`sku` source).** `ShoppingCartItemIn.sku` is required (citation 10) but
  `CatalogItemOut` exposes no `sku` (citation 4). Whether `item_id` is reused as
  `sku`, or `sku` lives under `attributes`, is unconfirmed by any source — must be
  confirmed with backend before implementing add-to-cart.
- **AS-2 (cart reuse/identity).** How an existing `cart_id` is discovered/reused
  on Android (persisted locally? `GET /ui/shoppingcart/carts` returns a list) is a
  design choice; the web client does not centralize this. Affects whether each add
  may create a new cart.
- **AS-3 (Android framework choices).** Compose pager, `SavedStateHandle`, Room
  cache, Coil, Media3, `NumberFormat`, and the core-network no-retry-on-mutation
  policy are implementation decisions (citations 16, 19, 20, 21) not verifiable
  against backend/frontend sources.
- **AS-4 (analytics/telemetry).** §10 event names/fields are app-internal; no
  external source to verify.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (no device); **emu35** = headless
emulator AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). MockWebServer is used for all
network cases so the flaky dev host never gates CI.

- **TC-AND-206-01** — Type: contract/MockWebServer (JVM). Target:
  `CatalogDetailRepositoryImpl.getItem`. Preconditions: MockWebServer queues a
  `CatalogItemListOut` containing `item_id="itm_001"`. Steps: call
  `getItem("cat_books","itm_001")`. Expected: request hits
  `GET /ui/catalog/categories/cat_books/items`; result `Success` with mapped domain
  (price from `price_cents`/`currency`, attributes from object map, media from
  `image_urls`); cache upserted. Traces: AC-1.
- **TC-AND-206-02** — Type: unit (JVM). Target: price/stock/attribute mapping.
  Preconditions: DTOs with `price_cents=1999,currency="USD"`,
  `stock_status="in_stock",stock_count=12`, `attributes={SKU,Weight}`,
  multi-locale. Steps: map and format. Expected: "$19.99" (en-US) / locale
  variants; attributes preserved as ordered pairs; in-stock true. Traces: AC-1.
- **TC-AND-206-03** — Type: contract/MockWebServer (JVM). Target: `getItem`
  not-found. Preconditions: list response omits the requested id. Steps: call
  `getItem` for an absent id. Expected: `Failure.NotFound` (client-side; no HTTP
  404 issued). Traces: AC-6.
- **TC-AND-206-04** — Type: contract/MockWebServer (JVM). Target: `getItem`
  offline-stale. Preconditions: cache holds the item; MockWebServer returns a
  network error / 500. Steps: call `getItem`. Expected: `Success` with cached item
  flagged `stale=true`. With empty cache → `Failure(retryable)`. Traces: AC-6.
- **TC-AND-206-05** — Type: contract/MockWebServer (JVM). Target:
  `addToCart` happy path (two-step). Preconditions: no stored `cart_id`; queue
  `ShoppingCartSummary` then `ShoppingCartItemOut`. Steps: call
  `addToCart(item, qty=1)`. Expected: exactly one `POST /ui/shoppingcart/carts`
  then one `POST /ui/shoppingcart/carts/{cart_id}/items` with body
  `{sku,name,unit_price_cents,quantity=1,item_id,category_id,image_url}`; returns
  mapped `CartItem`. Traces: AC-3.
- **TC-AND-206-06** — Type: contract/MockWebServer (JVM). Target: `addToCart`
  reuse + no-retry + step failures. Preconditions: (a) stored `cart_id` present →
  create-cart is skipped; (b) add returns 500. Steps: invoke both scenarios.
  Expected: (a) only the items POST is issued; (b) failure mapped to typed message
  and the add POST is issued exactly once (no auto-retry); a create-cart 500
  short-circuits before any items POST. Traces: AC-3, AC-4.
- **TC-AND-206-07** — Type: contract/MockWebServer (JVM). Target: `addToCart`
  `422` validation. Preconditions: items POST returns
  `422 {detail:[{loc,msg,type}]}` (e.g., quantity over 1000). Steps: call
  `addToCart`. Expected: non-retryable typed message parsed from `detail[].msg`;
  item stays loaded. Traces: AC-4, AC-5.
- **TC-AND-206-08** — Type: contract/MockWebServer (JVM). Target: 401-refresh on
  the list GET. Preconditions: first GET → 401, then `POST /ui/session/refresh`
  → 200, retried GET → 200 `CatalogItemListOut`. Steps: call `getItem`. Expected:
  exactly one refresh, one retry, final `Success`; a second 401 surfaces a
  non-retryable auth error. Traces: AC-6, AC-9.
- **TC-AND-206-09** — Type: unit (JVM, Turbine). Target: `ProductDetailViewModel`.
  Preconditions: fake repo. Steps: drive success / not-found / transport-error /
  add-in-flight-guard (double tap) / retry. Expected: `Loading→Ready`,
  `→NotFound`, `→Error(retryable)`; `addToCart` emits `InFlight` then
  `AddedToCart`/`AddToCartFailed`; re-entry while `InFlight` issues one request;
  `retry()` re-loads. Traces: AC-3, AC-4, AC-6, AC-7.
- **TC-AND-206-10** — Type: Compose-UI (emu35). Target: `ProductDetailScreen`
  render + carousel. Preconditions: `Ready` state with multiple `image_urls`.
  Steps: assert name/price/description/attributes/stock; swipe the
  `HorizontalPager`. Expected: all fields render; page indicator advances; no
  ExoPlayer instantiated (no video). Traces: AC-1, AC-2.
- **TC-AND-206-11** — Type: Compose-UI (emu35). Target: add-to-cart button states
  + out-of-stock. Preconditions: `Ready`; toggle `stock_status` out-of-stock.
  Steps: tap Add (in-stock) → assert spinner + disabled during in-flight, success
  snackbar + re-enable on completion; render out-of-stock variant. Expected:
  in-flight disable/spinner via test tags; "Added to cart" snackbar; out-of-stock
  disables button with "Out of stock" and hides the stepper. Traces: AC-3, AC-5.
- **TC-AND-206-12** — Type: Compose-UI (emu35). Target: distinct non-happy states.
  Preconditions: drive `NotFound`, retryable `Error`, stale banner. Steps: render
  each; tap Retry on `Error`. Expected: three visually distinct states; Retry
  recovers to `Ready`; stale banner shows "Showing saved data". Traces: AC-6.
- **TC-AND-206-13** — Type: Compose-UI accessibility (emu35). Target: a11y
  semantics. Preconditions: `Ready` with TalkBack assertions + pseudolocale + RTL.
  Steps: assert each carousel page `contentDescription` ("<name> image N of M"),
  decorative indicator cleared from semantics, add-button state labels
  ("Add to cart"/"Adding…"/"Out of stock"), touch targets ≥48dp, snackbar
  announced. Expected: all semantics present; no clipping under largest font/RTL.
  Traces: AC-1, AC-3, AC-5.
- **TC-AND-206-14** — Type: instrumented/e2e (emu35). Target: grid→detail→add full
  flow over MockWebServer. Preconditions: canned `CatalogItemListOut`,
  `ShoppingCartSummary`, `ShoppingCartItemOut`, and a follow-up
  `ShoppingCartItemsOut` for the badge. Steps: navigate from a grid cell, render
  detail, tap Add, observe snackbar + badge refresh; also exercise not-found,
  500-on-add+Retry, and 401-refresh-then-200 on the GET. Expected: detail renders;
  add succeeds and badge updates from the cart-items read; error paths behave per
  AC-4/AC-6. Traces: AC-1, AC-3, AC-4, AC-6, AC-9.
- **TC-AND-206-15** — Type: instrumented (A15 — **must run on physical device**).
  Target: ExoPlayer/media-lifecycle guard + ABI/API-34 parity. Preconditions:
  build with a synthetic item carrying a (future) video URL to force the AND-166
  path; LeakCanary/idling assertions. Steps: open detail, background/rotate/dispose
  the screen on arm64-v8a/API 34. Expected: any ExoPlayer instance is released on
  background/dispose (no leak); image carousel + add-to-cart behave identically to
  emu35 (no arm64-vs-x86 / API-34-vs-35 regressions). Rationale for device:
  real arm64 media/codec + ABI parity; not reliably reproducible on the x86_64
  emulator. Traces: AC-8, AC-2.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (detail renders) | TC-01, TC-02, TC-10, TC-13, TC-14 |
| AC-2 (image carousel; no video path) | TC-10, TC-15 |
| AC-3 (add-to-cart two-step works) | TC-05, TC-06, TC-09, TC-11, TC-13, TC-14 |
| AC-4 (add failure, no auto-retry, Retry) | TC-06, TC-07, TC-09, TC-14 |
| AC-5 (out-of-stock disables/hides stepper) | TC-07, TC-11, TC-13 |
| AC-6 (not-found / error+retry / stale) | TC-03, TC-04, TC-08, TC-09, TC-12, TC-14 |
| AC-7 (state retention / re-entry guard) | TC-09 |
| AC-8 (ExoPlayer released, no leak) | TC-15 |
| AC-9 (CI suite incl. error/refresh seqs) | TC-08, TC-14 |
