---
id: AND-206
title: Product detail
milestone: M5
epic: E28
priority: P0
size: L
status: draft
depends_on: [AND-205, AND-204, AND-103, AND-166]
blocks: [AND-207]
---

# AND-206 — Product detail

## 1. Overview & Goal

Build the customer-facing **product detail** screen for the TestLogon native
Android app, reached from the catalog item grid (AND-205) at the navigation route
`shop/{categoryId}/{itemId}`. The screen fetches a single shop item by id,
renders its full media set (image carousel and, where present, an HLS video
preview), name, description, formatted price, availability, and attributes, and
exposes a primary **add-to-cart** action that posts to the cart endpoint and
reflects the result in the UI.

The deliverable lives in the existing `:feature-catalog` module created by
AND-205 (a `detail/` subpackage), reusing the catalog `CatalogApi`/DTOs from
AND-204, the Coil thumbnail/image primitives from AND-103 for stills, and the
Media3/ExoPlayer player from AND-166 for any video media. It must behave
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
- **AND-204 (depends_on)** — provides `CatalogApi`, Moshi DTOs
  (`CatalogItemDto`, `MediaDto`, `PriceDto`) and `core-model` domain types. This
  ticket adds the **item-by-id** and **add-to-cart** methods to `CatalogApi` if
  AND-204 did not already expose them (see Section 5), and reuses existing DTOs.
- **AND-103 (depends_on)** — Coil image primitive / `ImageRequest` config for
  stills in the media carousel.
- **AND-166 (depends_on)** — Media3/ExoPlayer integration + reusable player UI
  for HLS video previews when an item has video media; if the item has only
  stills, ExoPlayer is not instantiated.
- Web reference: `frontend/src/api/endpoints/*.ts` (shop/cart endpoints), shared
  types `frontend/src/api/types.ts`. Backend OpenAPI at
  `http://18.222.237.167:8000/openapi.json` (verify exact paths/fields).
- Auth is cookie-based: session cookies + `ui_csrf` echoed as the
  `X-CSRF-Token` header; on `401` the shared authenticator does one
  `POST /ui/session/refresh` then retries. The item GET is idempotent and
  bounded-backoff retried; the add-to-cart POST is **not** auto-retried.

## 3. Functional Requirements

FR-1. **Load by id.** On entry, read `categoryId` and `itemId` from nav args and
fetch the full item via `GET /ui/shop/items/{itemId}`. Render a loading state
until the first result resolves.

FR-2. **Detail render.** Display item name, formatted price (locale currency),
availability/stock status, description (rendered as plain text / simple markup),
and a key/value attribute list when the DTO provides `attributes`.

FR-3. **Media carousel.** Render `media[]` in a horizontally pageable carousel
(`HorizontalPager`) with a page indicator. Image entries use the AND-103 Coil
primitive; video entries (`type == "video"`, HLS `url`) render the AND-166
reusable player with play/pause and are paused/released when scrolled off-screen
or the screen is backgrounded.

FR-4. **Add to cart.** A primary, full-width button issues
`POST /ui/shop/cart/items` with `{item_id, quantity}` (quantity defaults to 1;
an optional stepper may set 1..maxQty when stock is known). The button shows an
in-progress spinner and is disabled while the request is in flight and when the
item is out of stock.

FR-5. **Add-to-cart result.** On success, show confirmation (snackbar
"Added to cart" + updated cart badge count from the response) and re-enable the
button. On failure, keep the item rendered, re-enable the button, and show a
typed error (snackbar with Retry) mapped from the FastAPI `detail`.

FR-6. **Out-of-stock.** When availability indicates unavailable / zero stock,
the Add to cart button is disabled with an explanatory label ("Out of stock")
and the quantity stepper is hidden.

FR-7. **Back navigation.** A top app bar with title (item name once loaded) and
an Up affordance returns to the catalog browse screen preserving its state.

FR-8. **State preservation.** Carousel page index and selected quantity survive
configuration changes; `itemId`/`categoryId` come from nav args and survive
process death via `SavedStateHandle`.

FR-9. **Distinct non-happy states.** Loading, not-found (`404`), generic error
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

```kotlin
interface CatalogDetailRepository {
    /** Idempotent GET; bounded-backoff retried by core-network. */
    suspend fun getItem(itemId: String): ApiResult<CatalogItem>

    /** Non-idempotent mutation; never auto-retried. */
    suspend fun addToCart(itemId: String, quantity: Int): ApiResult<CartSummary>
}
```

```kotlin
class CatalogDetailRepositoryImpl @Inject constructor(
    private val api: CatalogApi,                 // from AND-204
    private val cache: CatalogItemCacheDao,      // core-data / Room (optional read-through)
    @IoDispatcher private val io: CoroutineDispatcher,
) : CatalogDetailRepository {

    override suspend fun getItem(itemId: String): ApiResult<CatalogItem> =
        withContext(io) {
            when (val r = api.getItem(itemId)) {
                is ApiResult.Success -> r.data.toDomain()
                    .also { cache.upsert(it.toEntity()) }
                    .let { ApiResult.Success(it) }
                is ApiResult.Failure -> cache.find(itemId)?.toDomain()
                    ?.let { ApiResult.Success(it) }      // stale fallback
                    ?: r
            }
        }

    override suspend fun addToCart(itemId: String, quantity: Int): ApiResult<CartSummary> =
        withContext(io) {
            api.addToCart(AddToCartRequestDto(itemId = itemId, quantity = quantity))
                .toApiResult { it.toDomain() }
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
            _uiState.value = when (val r = repository.getItem(itemId)) {
                is ApiResult.Success -> ProductDetailUiState.Ready(r.data.toUiModel())
                is ApiResult.Failure ->
                    if (r.isNotFound) ProductDetailUiState.NotFound
                    else ProductDetailUiState.Error(r.message, retryable = r.retryable)
            }
        }
    }

    fun addToCart(quantity: Int = 1) {
        if (_addState.value is AddToCartUiState.InFlight) return
        viewModelScope.launch {
            _addState.value = AddToCartUiState.InFlight
            when (val r = repository.addToCart(itemId, quantity)) {
                is ApiResult.Success -> {
                    _addState.value = AddToCartUiState.Idle
                    analytics.log("catalog_add_to_cart_success", "item_id" to itemId, "qty" to quantity)
                    _events.send(DetailEvent.AddedToCart(r.data.itemCount))
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
    data class AddedToCart(val cartCount: Int) : DetailEvent
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

DTOs are defined in AND-204; this ticket adds the two `CatalogApi` methods below
if not already present. Confirm exact paths/field names against `/openapi.json`
and `frontend/src/api/endpoints/*.ts`.

**Get item by id** — `GET /ui/shop/items/{itemId}`

```json
{
  "id": "itm_001",
  "category_id": "cat_books",
  "name": "Example Item",
  "description": "Full long-form description…",
  "price": { "amount_cents": 1999, "currency": "USD" },
  "availability": { "in_stock": true, "quantity": 12 },
  "attributes": [
    { "key": "SKU", "value": "EX-001" },
    { "key": "Weight", "value": "1.2 kg" }
  ],
  "media": [
    { "type": "image", "url": "https://…/a.jpg", "thumbnail_url": "https://…/a_t.jpg" },
    { "type": "video", "url": "https://…/v.m3u8", "thumbnail_url": "https://…/v_t.jpg" }
  ]
}
```

**Add to cart** — `POST /ui/shop/cart/items`

Request:

```json
{ "item_id": "itm_001", "quantity": 1 }
```

Response (200):

```json
{ "cart_id": "cart_abc", "item_count": 3, "subtotal": { "amount_cents": 5997, "currency": "USD" } }
```

Retrofit (in `core-network`/AND-204):

```kotlin
interface CatalogApi {
    @GET("ui/shop/items/{itemId}")
    suspend fun getItem(@Path("itemId") itemId: String): ApiResult<CatalogItemDto>

    @POST("ui/shop/cart/items")
    suspend fun addToCart(@Body body: AddToCartRequestDto): ApiResult<CartSummaryDto>
}
```

All requests are authenticated. The GET attaches cookies + `X-CSRF-Token`; the
POST additionally **requires** the `X-CSRF-Token` header (attached by the shared
CSRF interceptor). On `401`, core-network performs one `POST /ui/session/refresh`
then retries. The POST is mutating and is excluded from the idempotent-GET retry
policy. FastAPI errors surface via the shared `detail` mapper
(`string | [{msg}] | {code,...}`); `404` from the item GET maps to `NotFound`,
`409`/`422` (e.g., out of stock, invalid quantity) on the POST maps to a
non-retryable typed message.

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

data class MediaUiModel(val isVideo: Boolean, val url: String, val thumbnailUrl: String?)
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
- Domain→UI mapping formats price with `NumberFormat.getCurrencyInstance` using
  the DTO `currency`. The cart-count badge is surfaced via the `AddedToCart`
  event for the app shell / a shared cart `StateFlow` to consume.

## 7. Error Handling & Resilience

- **Timeouts.** Item GET and cart POST use the core-network ~20s call timeout
  for the unreliable dev host.
- **Idempotent retry.** The item GET is eligible for bounded-backoff retry. The
  cart POST is **never** auto-retried (avoids duplicate cart additions); retry is
  user-initiated via the snackbar action only.
- **Item load failure.** No cache → `Error(retryable=true)` full-screen retry;
  `404` → `NotFound` (distinct copy, Up affordance, no retry). With cache →
  `Ready(stale=true)` + non-blocking banner.
- **Add-to-cart failure.** Item stays rendered; button re-enabled; snackbar with
  mapped message + Retry. Out-of-stock / invalid-quantity (`409`/`422`) are shown
  as terminal, non-retryable messages and the button reflects stock state.
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
- `CatalogDetailRepositoryImpl.getItem` maps DTO→domain, upserts cache on
  success, and returns `stale` cached item on network failure; surfaces failure
  when no cache.
- `addToCart` maps success→`CartSummary` and failure→typed message; verifies the
  POST is issued exactly once (no retry) for a 500.
- `ProductDetailViewModel`: `Loading→Ready` on success, `→NotFound` on 404,
  `→Error(retryable)` on transport error; `addToCart` emits `InFlight` then
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
detail, render canned JSON matching Section 5, perform add-to-cart returning an
updated `item_count`; include a 404 item case, a 500-on-POST add failure with
Retry, and a 401-then-refresh-then-200 sequence for the GET.

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

- **Item-by-id endpoint shape.** Path `GET /ui/shop/items/{itemId}` vs.
  `GET /ui/shop/categories/{categoryId}/items/{itemId}` not confirmed.
  *Mitigation:* isolate in `CatalogApi`/repository. **Open: verify in OpenAPI.**
- **Cart endpoint contract.** Path/body/response for add-to-cart and whether a
  cart must be created first (`POST /ui/shop/cart` then add) is unconfirmed.
  **Open: verify against `frontend/src/api/endpoints/*.ts`.**
- **Availability/quantity fields.** Assumed `availability:{in_stock,quantity}`;
  if backend returns a status enum or omits quantity, the stepper/max logic
  changes. **Open: verify DTO.**
- **Price shape.** Assumed `{amount_cents, currency}`; pre-formatted string or
  float dollars would change mapping. **Open: confirm (shared with AND-205).**
- **Media typing.** Relies on a `type` discriminator and HLS `.m3u8` for video;
  if videos are MP4 progressive, AND-166 still handles it but data-saver/HLS
  logic differs.
- **Quantity stepper inclusion.** Source scope says "add-to-cart" without
  quantity; default to qty=1 with an optional stepper. **Open: confirm with
  design whether the stepper ships in M5.**
- **Dev host flakiness** makes live add-to-cart nondeterministic; all assertions
  use MockWebServer, not the dev host.

## 14. Acceptance Criteria

AC-1. Navigating from a catalog grid cell to `shop/{categoryId}/{itemId}` loads
the item via `GET /ui/shop/items/{itemId}` and renders name, locale-formatted
price, description, attributes, and availability (**detail renders** — primary).
AC-2. The media carousel renders all `media[]` entries; images load via the
AND-103 primitive and video entries play via the AND-166 player; swiping updates
the page indicator.
AC-3. Tapping Add to cart issues exactly one `POST /ui/shop/cart/items`, shows an
in-flight spinner, and on 200 shows an "Added to cart" snackbar and updates the
cart count from `item_count` (**add-to-cart works** — primary).
AC-4. Add-to-cart failure keeps the item rendered, re-enables the button, and
shows a typed error with a working Retry; the POST is never auto-retried.
AC-5. Out-of-stock items disable Add to cart with an explanatory label and hide
the quantity stepper.
AC-6. Item `404` renders a distinct Not Found state; transport errors render a
retryable error whose Retry recovers; network failure with cache shows the item
with a stale banner.
AC-7. Carousel page index and selected quantity survive rotation; `itemId`/
`categoryId` survive process death; Up returns to the catalog preserving its
state.
AC-8. ExoPlayer instances are released when the screen is backgrounded or
disposed (no leaked players; verified).
AC-9. All automated tests in Section 11 pass in CI, including the renders +
add-to-cart gates and the 404 / add-failure / 401-refresh sequences.

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
