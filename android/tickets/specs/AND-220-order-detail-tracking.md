---
id: AND-220
title: Order detail + tracking
milestone: M5
epic: E30
priority: P1
size: M
depends_on: [AND-219, AND-215]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-220 — Order detail + tracking

## 1. Overview & Goal

Provide a full-screen **Order Detail** view for a single purchased order in the
TestLogon native Android app. The screen is reached from the Purchase History
list (AND-219) by tapping an order row. It must render the order header
(number, status, dates, totals), the line items that compose the order, and a
**tracking section** that surfaces the carrier tracking status (provided by the
shared carrier-tracking module from AND-215) with an actionable **tracking
link** that opens the carrier's tracking page in the browser / Custom Tab.

Goal: a user can open any order from their history and see, in one scrollable
screen, *what* they bought, *how much* it cost, and *where the shipment is*,
including a tappable link to the carrier's live tracking page. The screen must
behave correctly against the unreliable plaintext dev backend (slow responses,
transient 5xx, offline) by showing loading, error, and stale states, and must
not crash when tracking is absent (digital goods, not-yet-shipped orders).

This ticket owns the `feature-orders` order-detail screen, its ViewModel, the
detail repository call, and the wiring of the AND-215 carrier-tracking display
into that screen. It does **not** own the history list (AND-219) nor the
carrier-tracking data/parsing layer itself (AND-215); it consumes both.

## 2. Context & References

- **Repo / module**: `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Code lands in module `feature-orders`
  (package `com.testlogon.android.feature.orders.detail`) consuming
  `core-network`, `core-model`, `core-data`, `core-ui`.
- **Stack**: Kotlin 2.0.21, Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12
  / Moshi 1.15, Room 2.6, DataStore, Coil. minSdk 24, compile/target 35,
  JDK 17, Gradle 8.9, AGP 8.7.3.
- **Dependencies**:
  - **AND-219 — Purchase history + search**: owns the history list and the
    navigation source. Supplies the `orderId` argument that opens this screen
    and the cached `OrderSummary` used for instant header pre-render.
  - **AND-215 — Carrier tracking**: owns `carrierTracking.ts` (web ref) and the
    Android `CarrierTrackingRepository` / `TrackingStatus` model + status
    display composable. This screen embeds that composable and calls that
    repository; it does not re-implement carrier parsing.
- **Backend**: FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000`
  (PLAINTEXT, unreliable). OpenAPI at `/openapi.json`. Auth: the web client
  rides the persistent cookie jar AND attaches `Authorization: Bearer
  <accessToken>` (from its auth store) plus echoes the `ui_csrf` cookie as the
  `X-CSRF-Token` header (verified `src/api/client.ts`). On 401, the client calls
  `POST /ui/session/refresh` once then retries the original request; a second
  401 logs the user out / routes to re-auth. The Android port mirrors this via
  an OkHttp `Authenticator` + cookie jar + CSRF interceptor. **Correction:**
  earlier draft said "cookie-based" only — a Bearer token is also sent.
- **Web reference**: `src/api/endpoints/purchases.ts` (`getTransaction` — order
  detail fetch), `src/api/endpoints/carrierTracking.ts` (`getCarrierTracking`,
  `pollCarrierTracking`), `src/api/types.ts`
  (`PurchaseTransactionInfo`, `PurchaseShipping`, `CarrierTrackingView`,
  `CarrierEvent`; line items come from `CartItem`), screen
  `src/pages/purchases/TransactionDetail.tsx`. **Correction:** there is no
  `orders.ts` and no `Order`/`OrderItem`/`TrackingInfo` types — the domain is
  *purchase transactions*, not "orders".

## 3. Functional Requirements

1. **Navigation entry**: route `orders/{orderId}` registered in the orders nav
   graph. `orderId` is a non-empty `String` path argument. Deep-link compatible
   pattern `testlogon://orders/{orderId}` is registered but not user-facing.
2. **Header**: render the transaction label (`description`, else
   "Order " + `txnId.take(8)`), localized human status (mapped from the
   uppercase backend strings `PENDING`/`COMPLETED`/`CANCELLED`/`REVERTED`/
   `CANCEL_REQUESTED`/`CANCEL_DENIED`/unknown), created-at date (from epoch
   seconds), and the transaction `amount` formatted with the order currency.
   *(Corrected: there is no `order_number` or `placed_at`; the status taxonomy
   and money/date shapes differ from the original draft — see §5.)*
3. **Items list**: render each line item (name, optional thumbnail via Coil,
   quantity, unit price, line subtotal) **only when** the transaction
   `metadata.cart_id` is present and the separate cart fetch
   (`getCartItems(cartId)`) returns items; otherwise omit the items card (the
   transaction payload itself carries no items). Cart-item money is integer
   cents (`unit_price_cents`/`line_total_cents`). The list is part of the single
   vertical scroll (not an independently scrolling nested list).
4. **Summary block**: amount, status, created, and (when present) merchant,
   external reference, completed-at, reverted-at. *(Corrected: the backend
   does NOT return a subtotal/shipping/tax/discount/grand-total breakdown — only
   a single `amount`. The original "Totals block" is dropped.)*
5. **Tracking section**:
   - If the transaction has a `shipping` object with a tracking number, render
     the AND-215 `TrackingStatusCard`: carrier name, tracking number, current
     status, last-update timestamp, and a **"Track package"** button.
     *(Corrected: a single optional `shipping` object, not a `shipments[]`
     array — at most one tracking card.)*
   - The button opens the carrier `tracking_url` via Chrome Custom Tabs,
     falling back to an `ACTION_VIEW` browser intent.
   - If shipping exists but has no tracking number yet, show
     "Tracking not available yet".
   - If the transaction has no `shipping` (digital goods / not shipped), omit
     the tracking section entirely (do not show an empty card).
6. **States**: Loading (skeleton), Content, Error (with Retry), and Offline /
   Stale (cached content + a non-blocking banner). Pull-to-refresh re-fetches.
7. **Pre-render**: when navigated from AND-219, use the passed cached
   `OrderSummary` to paint the header immediately while the full detail loads.

## 4. Technical Design

Single Compose screen backed by a Hilt `ViewModel` exposing a
`StateFlow<OrderDetailUiState>`, fed by `OrderRepository`. Carrier tracking is
delegated to AND-215's `CarrierTrackingRepository`; this screen merges order +
tracking into one UI state.

> **NOTE (corrected model).** The model below was rewritten to match the
> verified `PurchaseTransactionInfo` shape: `amount` is a `Double` in major
> units (no cents totals breakdown), timestamps are epoch seconds, there is a
> single optional `shipping` (not `shipments[]`), the id is `txnId` (no
> `orderNumber`), and line items come from a separate cart fetch.

```kotlin
// core-model
data class Order(                  // maps PurchaseTransactionInfo
    val txnId: String,
    val description: String?,      // header label; fall back to "Order " + txnId.take(8)
    val status: OrderStatus,       // free-form uppercase string -> enum
    val createdAt: Instant,        // from epoch SECONDS
    val updatedAt: Instant,
    val completedAt: Instant?,
    val revertedAt: Instant?,
    val currency: String,          // ISO-4217, e.g. "USD"
    val amount: Double,            // major units (e.g. 49.57), NOT cents
    val merchantId: String?,
    val externalRef: String?,
    val cartId: String?,           // from metadata.cart_id; drives items fetch
    val items: List<OrderItem>,    // resolved via getCartItems(cartId); may be empty
    val shipping: Shipment?,       // single optional shipping object
)

data class OrderItem(              // maps CartItem (cents ARE integers here)
    val sku: String,
    val itemId: String?,
    val name: String,
    val imageUrl: String?,
    val quantity: Int,
    val unitPriceCents: Long,
    val lineTotalCents: Long,
)

data class Shipment(               // maps PurchaseShipping (a single object)
    val carrier: String?,          // e.g. "ups"
    val trackingNumber: String?,
    val trackingUrl: String?,
    val status: String?,
    val shippedAt: Instant?,       // epoch seconds
    val deliveredAt: Instant?,
    val estimatedDelivery: String?,// free-form string, not epoch
)

// Free-form backend strings: PENDING, COMPLETED, CANCELLED, REVERTED,
// CANCEL_REQUESTED, CANCEL_DENIED, ... -> map unknowns to UNKNOWN.
enum class OrderStatus { PENDING, COMPLETED, CANCELLED, REVERTED, CANCEL_REQUESTED, CANCEL_DENIED, UNKNOWN }
```

```kotlin
// feature-orders/detail
sealed interface OrderDetailUiState {
    data object Loading : OrderDetailUiState
    data class Content(
        val order: Order,
        val tracking: TrackingStatus?, // single per-transaction AND-215 status (was a per-shipment Map; backend has one shipping object)
        val isStale: Boolean,
        val isRefreshing: Boolean,
    ) : OrderDetailUiState
    data class Error(val message: String, val canRetry: Boolean) : OrderDetailUiState
}

@HiltViewModel
class OrderDetailViewModel @Inject constructor(
    private val orderRepository: OrderRepository,
    private val trackingRepository: CarrierTrackingRepository, // AND-215
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val txnId: String = checkNotNull(savedStateHandle["orderId"]) // nav arg name kept; value is a txn_id
    val uiState: StateFlow<OrderDetailUiState>
    fun refresh()
    fun retry()
    fun onTrackClicked()   // emits OpenUrl effect (single shipping per txn; no shipmentId)
}
```

```kotlin
// repository
interface OrderRepository {
    // Combines GET .../transactions/{txnId} with the cart-items fetch
    // (metadata.cart_id -> getCartItems) into a single Order.
    fun observeOrder(txnId: String): Flow<ApiResult<Order>>  // cache-first, then network
    suspend fun refreshOrder(txnId: String): ApiResult<Order>
}
```

Composables:

```kotlin
@Composable fun OrderDetailScreen(onBack: () -> Unit, viewModel: OrderDetailViewModel = hiltViewModel())
@Composable private fun OrderHeader(order: Order)
@Composable private fun OrderItemsList(items: List<OrderItem>, currency: String)
@Composable private fun OrderTotals(order: Order)
@Composable private fun TrackingSection(
    shipping: Shipment?,
    tracking: TrackingStatus?,
    onTrack: () -> Unit,
) // delegates to AND-215 TrackingStatusCard (single shipping per txn)
```

The screen is a `Scaffold` + `TopAppBar` (back nav) wrapping a
`LazyColumn` with stable keys (`order.txnId`, `item.sku`). The
ViewModel combines `observeOrder` with the single per-transaction tracking flow
via `flatMapLatest` + `combine`; tracking failures are isolated so a tracking
error never fails the whole screen. Currency formatting via a shared
`core-ui` helper `formatMoney(amount: Double, currency: String): String`
using `NumberFormat.getCurrencyInstance` — note the source `amount` is in
**major units** (the transaction), whereas cart line items expose integer
cents (`unit_price_cents`/100) and need a separate `formatMoneyCents` overload.

## 5. API Contract

> **CORRECTED — verified against OpenAPI + web reference.** The earlier draft's
> `GET /ui/orders/{order_id}` endpoint and `Order`/`items[]`/`shipments[]`
> payload **do not exist**. The real domain is a *purchase transaction*. See
> §16 for the full audit.

**Order (transaction) detail** — `GET /ui/purchase-history/transactions/{txn_id}`
(op `ui_get_transaction`; idempotent; eligible for bounded backoff retry).
Cookies + `Authorization: Bearer` + `X-CSRF-Token` per §2. Documented responses
(OpenAPI index): `200:PurchaseTransactionInfo; 422:HTTPValidationError; 400;
401; 403; 429`. **No 404 is documented for this op** — see error handling note
below.

Response 200 (`PurchaseTransactionInfo`, verified
`components.schemas.PurchaseTransactionInfo` and `src/api/types.ts`):
```json
{
  "txn_id": "txn_8f2c",
  "created_at": 1748451851,
  "updated_at": 1748455000,
  "status": "PENDING",
  "amount": 49.57,
  "currency": "USD",
  "buyer_id": "usr_1",
  "version": 3,
  "description": "Widget Pro x2",
  "merchant_id": "mch_9",
  "external_ref": "ext-123",
  "completed_at": null,
  "reverted_at": null,
  "receipt_path": null,
  "metadata": { "cart_id": "cart_77" },
  "shipping": {
    "carrier": "ups",
    "tracking_number": "1Z999...",
    "tracking_url": "https://www.ups.com/track?tracknum=1Z999...",
    "status": "in_transit",
    "shipped_at": 1748460000,
    "delivered_at": null,
    "estimated_delivery": "2026-06-02",
    "carrier_events": [ { "timestamp": "...", "description": "...", "location": "..." } ]
  }
}
```

Key shape facts (each a correction vs. the original draft):
- **`amount` is a JSON `number` in major currency units** (e.g. `49.57`), NOT
  integer cents, and there is **no per-line totals breakdown**
  (`subtotal_cents`/`shipping_cents`/`tax_cents`/`discount_cents`/`total_cents`
  do not exist). Format with `NumberFormat.getCurrencyInstance` over the
  `Double` amount + `currency` (web does `Intl.NumberFormat({style:"currency"})`
  on `txn.amount`).
- **Timestamps are integer epoch *seconds*** (`created_at`, `updated_at`,
  `completed_at`, `reverted_at`, `shipping.shipped_at`, `shipping.delivered_at`,
  `shipping.last_carrier_check`). `estimated_delivery` is a free `String`.
  Multiply by 1000 for `Instant.ofEpochMilli`. There is **no** `placed_at`
  ISO-8601 field.
- **There is no `order_number`.** The header identifier is `txn_id`; the web UI
  shows `description ?? "Order " + txn_id[:8]`.
- **`status` is a free-form uppercase string.** Observed values in the web ref:
  `PENDING`, `COMPLETED`, `CANCELLED`, `REVERTED`, `CANCEL_REQUESTED`,
  `CANCEL_DENIED`. The draft's `placed/paid/shipped/delivered` lowercase values
  are wrong. Map unknowns to `OrderStatus.UNKNOWN`.
- **Shipping is a single optional `shipping` object, NOT a `shipments[]`
  array** (`PurchaseShipping`/`PurchaseShippingIn`): one carrier /
  tracking_number / tracking_url / status / timestamps / `carrier_events[]`.
  The "multiple shipments / partial fulfilment" design is unsupported by the
  backend; collapse the design to a single shipment.
- **Line items are NOT in this payload.** The web client renders items from a
  *separate* cart fetch: if `metadata.cart_id` is a string it calls
  `getCartItems(cartId)` → `CartItem[]` with `name`, `image_url`, `quantity`,
  `unit_price_cents`, `line_total_cents` (these ARE integer cents). The Android
  port must do the same (or omit the items card when there is no `cart_id`).

**Tracking** — `GET /ui/purchase-history/transactions/{txn_id}/tracking`
(op `ui_get_tracking`) → `CarrierTrackingView` (`txn_id`, `carrier`,
`tracking_number`, `tracking_url`, `status`, `status_description`,
`estimated_delivery`, `delivered_at`, `carrier_events[]`, `last_carrier_check`).
This is **per-transaction, not per-shipment**, and is owned by AND-215. A manual
refresh polls the carrier via `POST /ui/shop/tracking/transactions/{txn_id}/poll`
(op `ui_poll_transaction`) → `CarrierPollTransactionOut` (`{ poll, tracking }`).
This screen calls `CarrierTrackingRepository.observeTracking(txnId)` (single
arg — there is no `shipmentId`) and does not bind these endpoints directly. The
"Track package" `tracking_url` comes from `shipping.tracking_url`; if null, fall
back to `CarrierTrackingView.tracking_url`.

**Moshi DTOs** mirror the JSON with `@Json(name = "...")` snake_case mapping
and map to `core-model` via a `toDomain()` extension. Unknown `status` strings
map to `OrderStatus.UNKNOWN`. Errors: FastAPI `detail` decoded by the shared
`core-network` error mapper (string | `[{msg}]` | `{code,...}`, verified
`normalizeErrorDetail` in `src/api/client.ts`). 404 is **not** documented for
this op; treat any 404 defensively as a terminal "Order not found"
(non-retryable) but do not assume the backend emits it — a missing/garbage
`txn_id` more likely yields 422 (validation) or 403.

## 6. Data & State Management

- **Cache (Room 2.6)**: reuse the orders cache established by AND-218/AND-219.
  Detail extends it with an `OrderItemEntity` table (cart line items, keyed by
  `txnId` FK, `onDelete = CASCADE`) and embeds the single shipping object on the
  transaction row (a one-to-one `@Embedded` shipping group, not a separate
  `shipments` table — the backend returns at most one `shipping`).
  `OrderDao.observeOrderWithItems(txnId): Flow<OrderWithRelations?>` powers
  cache-first rendering. *(Corrected: keyed by `txnId`, single embedded
  shipping; items are the cart line items, cached after the cart fetch.)*
- **Cache-first**: `observeOrder` emits cached data immediately (marked
  `isStale = true` if older than 5 minutes or fetched while offline), then
  triggers a network refresh that upserts and clears the stale flag.
- **Tracking** is **not** persisted by this ticket (it is volatile/live);
  AND-215 owns its own caching policy. We hold tracking in memory in the UI
  state map only.
- **Pre-render**: the `OrderSummary` passed via `SavedStateHandle` from AND-219
  seeds the header before the DAO/network emits.
- **No DataStore writes**; prefs untouched. Process-death safe via
  `SavedStateHandle` (`orderId` + last scroll position retained by Compose).

## 7. Error Handling & Resilience

- **Timeouts**: OkHttp call timeout ~20s (global `core-network` client). Order
  detail GET is idempotent → eligible for bounded exponential backoff
  (max 3 attempts, jitter) on connect/timeout/5xx. Mutations: none here.
- **401**: handled by the global authenticator (`POST /ui/session/refresh` once,
  then retry); a second 401 surfaces an auth error and routes to re-auth.
  *(Verified against `src/api/client.ts`.)*
- **403 / 429**: documented responses for this op. 403 → permission/geo error
  (the web mapper special-cases `code == "geo_blocked"`); 429 → rate-limited,
  retry-after backoff. Surface as non-retryable (403) / retryable-with-delay
  (429) errors.
- **404 / 422**: 404 is **NOT documented** for `ui_get_transaction` (the index
  lists `200;422;400;401;403;429`). A bad/unknown `txn_id` most likely returns
  422 (`HTTPValidationError`) or 403, not 404. Map 422/`detail` to a terminal
  "Order not found / invalid" (`canRetry = false`); still handle a stray 404 the
  same way defensively. *(Corrected from the draft's confident 404 claim.)*
- **Offline / network failure with cache**: show cached `Content` with
  `isStale = true` and a dismissible banner "Showing saved copy — couldn't
  refresh." Retry/pull-to-refresh re-attempts.
- **Offline / no cache**: `Error("You're offline", canRetry = true)`.
- **Tracking failure**: isolated — the order renders; the affected
  `TrackingStatusCard` shows AND-215's own inline error/"unavailable" state and
  does not propagate to `OrderDetailUiState.Error`.
- **Malformed JSON**: caught by the error mapper → non-retryable generic error,
  logged with the failing field (no PII).

## 8. Security & Privacy

- All requests use the shared persistent cookie jar; session + `ui_csrf` cookie
  echoed as `X-CSRF-Token`. No tokens or order data written to logs.
- Dev backend is plaintext HTTP: a `usesCleartextTraffic`-scoped network
  security config restricts cleartext to the dev host only; production builds
  enforce HTTPS. No order/tracking data persisted outside the app sandbox; Room
  DB lives in app-private storage (no external storage, no backup of the cache —
  excluded via `dataExtractionRules` / `fullBackupContent`).
- The "Track package" link opens an **external** carrier URL. Validate the URL
  scheme is `https` (or `http` only for the dev allowlist) before launching;
  reject `javascript:`/`intent:`/`file:` schemes to prevent intent redirection.
  Use Chrome Custom Tabs (no cookies shared from app session) so the user's
  TestLogon session is never exposed to the carrier site.
- Tracking numbers are treated as semi-sensitive: shown in UI but never logged.

## 9. Accessibility & i18n

- All strings in `feature-orders` `strings.xml`; no hardcoded literals. Plurals
  for quantity (`quant, quantity`). Status labels localized via a
  `OrderStatus -> @StringRes` mapper.
- Money and dates formatted locale-aware (`NumberFormat`, `DateTimeFormatter`
  with the device locale/zone); never string-concatenated currency symbols.
- Content descriptions: item thumbnails get `contentDescription` = item name;
  decorative icons `null`. "Track package" button has a descriptive label
  including carrier + tracking number for TalkBack
  ("Track package, UPS, ending 9 9 9").
- Touch targets ≥ 48dp; dynamic type / font scaling respected; meets WCAG AA
  contrast under Material 3 theming. RTL-safe via `start/end` paddings.

## 10. Telemetry & Logging

- Analytics events via the shared `core-data` analytics interface:
  - `order_detail_viewed { order_id_hash, status, item_count, has_tracking }`
  - `order_detail_refresh { source: pull|retry|auto, result: ok|error|stale }`
  - `order_tracking_link_opened { carrier, order_id_hash }`
  - `order_detail_error { code, retryable }`
  Order ids are hashed; no tracking numbers, names, or prices in analytics.
- Logging: Timber, debug-only network breadcrumbs (path, status, latency) with
  bodies redacted. No PII at any level; tracking numbers and emails never
  logged.

## 11. Testing Strategy

- **Unit (ViewModel)** with `core-testing` (MainDispatcherRule, Turbine):
  Loading→Content; cache-first emits stale then fresh; 404→non-retryable Error;
  offline-with-cache→stale Content + banner; offline-no-cache→retryable Error;
  tracking failure isolated (order Content still emitted); `onTrackClicked`
  emits `OpenUrl` effect with the validated URL.
- **Repository**: MockWebServer (OkHttp) — JSON mapping incl. snake_case,
  `amount` as float major units, epoch-seconds timestamps, unknown `status`
  →UNKNOWN, missing/null `shipping`→omitted tracking section, the secondary
  cart-items fetch driven by `metadata.cart_id`, retry on 503 then 200,
  terminal mapping on 422. DAO upsert/observe via Room in-memory.
- **Compose UI** (`createAndroidComposeRule`): header/items/summary render;
  items card omitted when no `cart_id`/no items; tracking section omitted when
  no `shipping`; "Tracking not available yet" when shipping without a number;
  Retry click calls ViewModel; semantics/contentDescription assertions for
  accessibility.
- **URL safety**: parameterized test rejecting `javascript:`, `file:`,
  `intent:` and accepting `https`.
- Coverage target ≥ 80% on ViewModel + repository mappers. Screenshot test
  (optional) for the three primary states.

## 12. Dependencies & Sequencing

- **Blocked by AND-219** (Purchase history + search): provides the nav source,
  the `orderId` argument, the seed `OrderSummary`, and the base orders Room
  cache. Detail tables extend that schema.
- **Blocked by AND-215** (Carrier tracking): provides
  `CarrierTrackingRepository`, `TrackingStatus`, and `TrackingStatusCard`. If
  AND-215 lands after the screen scaffold, integrate behind a feature check and
  render a placeholder tracking row until available.
- Transitively depends on AND-218 (orders API/cache foundation) via both deps.
- **Blocks**: none in the provided backlog.
- Sequencing: implement DTOs/repository/DAO extension → ViewModel + tests →
  Compose screen → AND-215 tracking integration → nav wiring from AND-219.

## 13. Risks & Open Questions

- **Backend shape — RESOLVED (this review).** Verified against the OpenAPI index
  and `src/api/endpoints/purchases.ts`: the endpoint is
  `GET /ui/purchase-history/transactions/{txn_id}` returning
  `PurchaseTransactionInfo` (not `GET /ui/orders/{order_id}`). Field names,
  `amount` as a float, epoch-seconds timestamps, and the single `shipping`
  object are corrected throughout (§5, §4).
- **Tracking endpoint ownership — RESOLVED.** Tracking is a *separate* call
  (`GET .../transactions/{txn_id}/tracking` → `CarrierTrackingView`; poll via
  `POST /ui/shop/tracking/transactions/{txn_id}/poll`), owned by AND-215. The
  `shipping` object inside the transaction also carries `tracking_url`, used as
  the primary "Track package" source. Combine logic stays per-transaction.
- **Multiple shipments — RESOLVED (does not apply).** The backend models a
  single `shipping` object per transaction; there is no `shipments[]`. The
  design is collapsed to one shipment. Partial-fulfilment / multi-parcel is out
  of scope unless the backend adds it.
- **Currency/precision — partially open.** Confirmed the transaction `amount`
  is a JSON `number` in major units (not cents); cart line items use integer
  cents. `NumberFormat.getCurrencyInstance` handles zero-decimal currencies
  (e.g. JPY) from the currency code, but the dev backend's actual rounding /
  zero-decimal behavior for `amount` is *unverified* — see §16 open assumptions.
- **Line-item source — open dependency.** Items are not in the transaction
  payload; the web client fetches them via `getCartItems(metadata.cart_id)`.
  Whether AND-219/AND-218 already expose a cart-items repository, or this ticket
  must bind `GET /ui/cart/{cart_id}/items` itself, needs confirming with those
  owners. *Owner: confirm before repository merge.*
- **Custom Tabs availability** on minSdk 24 devices without Chrome — fallback
  `ACTION_VIEW` must be verified on a real device/clean emulator.

## 14. Acceptance Criteria

1. Tapping an order in Purchase History (AND-219) opens `orders/{orderId}` and
   the **detail renders with tracking** (primary acceptance from the backlog).
2. Header shows the transaction label (`description` or `txnId` prefix),
   localized status, created date, and the transaction `amount` in the order
   currency. *(No `order_number`/`placed_at`/grand-total — see §5.)*
3. When line items resolve (via `metadata.cart_id` → cart fetch), each renders
   with name, quantity, unit price, and line subtotal; thumbnails load via Coil
   with a name `contentDescription`. When there is no `cart_id`/no items, the
   items card is omitted (no crash, no empty card).
4. When the transaction `shipping` has a tracking number, the AND-215
   `TrackingStatusCard` shows carrier + status, and "Track package" opens the
   carrier `tracking_url` in a Custom Tab / browser.
5. Transactions with no `shipping` show **no** tracking section; `shipping`
   without a number shows "Tracking not available yet".
6. Loading shows a skeleton; a transient backend failure with cached data shows
   stale content + banner; offline-with-no-cache shows a retryable error; a
   terminal 422/404 shows non-retryable "Order not found".
7. Pull-to-refresh and Retry re-fetch and update state.
8. A non-`http(s)` tracking URL is rejected and never launched.
9. No PII (tracking numbers, names, prices, raw order ids) appears in logs or
   analytics.

## 15. Definition of Done

- Code merged to `android-port` under `feature-orders`
  (`com.testlogon.android.feature.orders.detail`); CI green (build, lint,
  detekt, unit + instrumented tests) on JDK 17 / AGP 8.7.3 / Gradle 8.9.
- ViewModel + repository unit tests and Compose UI tests added and passing;
  coverage ≥ 80% on new ViewModel/mapper code.
- All user-facing strings externalized and localized; accessibility checks
  (TalkBack labels, 48dp targets, contrast) verified on an emulator.
- Network security config restricts cleartext to the dev host only; URL-scheme
  validation enforced for the tracking link.
- Analytics events emit with hashed/redacted fields; no PII in Timber logs.
- API contract reconciled against `/openapi.json` and the web reference, or
  open questions in §13 explicitly resolved/ticketed.
- Screen reachable from AND-219 and integrates the live AND-215 tracking
  component (or a documented placeholder if AND-215 is not yet merged).
- Spec reviewed; PR description links AND-220, AND-219, AND-215.

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and exact source pointer.

1. **Order-detail endpoint is `GET /ui/purchase-history/transactions/{txn_id}`**
   (op `ui_get_transaction`), returning `PurchaseTransactionInfo`.
   **VERDICT: Corrected** (draft said `GET /ui/orders/{order_id}` which does not
   exist). SOURCE: OpenAPI `GET /ui/purchase-history/transactions/{txn_id}` (op
   `ui_get_transaction`, `resp=200:PurchaseTransactionInfo`); `src/api/endpoints/
   purchases.ts: getTransaction`.
2. **No `GET /ui/orders/...` endpoint exists at all.** **VERDICT: Corrected.**
   SOURCE: OpenAPI index — no `/ui/orders` path; the only order-detail surface is
   under `/ui/purchase-history/transactions`.
3. **Response is a *transaction*, not an "order".** **VERDICT: Corrected.**
   SOURCE: `components.schemas.PurchaseTransactionInfo`; `src/api/types.ts:
   PurchaseTransactionInfo` (extends `PurchaseTransactionSummary`).
4. **`amount` is a JSON `number` in major units (not integer cents); no
   subtotal/shipping/tax/discount/total cents breakdown.** **VERDICT: Corrected.**
   SOURCE: `components.schemas.PurchaseTransactionInfo.amount` (`type: number`);
   `src/pages/purchases/TransactionDetail.tsx: formatCurrency(txn.amount, …)`.
5. **Timestamps are integer epoch seconds (`created_at`, `updated_at`,
   `completed_at`, `reverted_at`, `shipping.shipped_at`,
   `shipping.delivered_at`); `estimated_delivery` is a string.** **VERDICT:
   Corrected** (draft used ISO-8601 `placed_at`). SOURCE:
   `components.schemas.PurchaseTransactionInfo` (`created_at: integer`, etc.);
   `TransactionDetail.tsx: formatDate(ts) => new Date(ts * 1000)`.
6. **There is no `order_number`; the header id is `txn_id`, label is
   `description`.** **VERDICT: Corrected.** SOURCE: schema (`txn_id`,
   `description`); `TransactionDetail.tsx` header `txn.description ?? "Order " +
   txn.txn_id.slice(0,8)`.
7. **`status` is a free-form uppercase string; observed values
   `PENDING`/`COMPLETED`/`CANCELLED`/`REVERTED`/`CANCEL_REQUESTED`/
   `CANCEL_DENIED`.** **VERDICT: Corrected** (draft used
   placed/paid/shipped/delivered/refunded). SOURCE: schema (`status: string`);
   `TransactionDetail.tsx: statusVariant()` switch on those literals.
8. **Shipping is a single optional `shipping` object (not `shipments[]`),
   carrying carrier/tracking_number/tracking_url/status/shipped_at/
   delivered_at/estimated_delivery/carrier_events.** **VERDICT: Corrected.**
   SOURCE: `components.schemas.PurchaseShippingIn`; `src/api/types.ts:
   PurchaseShipping`; `TransactionDetail.tsx: txn.shipping?.…` (no array).
9. **Line items are NOT in the transaction; the web client fetches them via
   `getCartItems(metadata.cart_id)` → `CartItem[]` (which DO use integer
   `unit_price_cents`/`line_total_cents`).** **VERDICT: Corrected.** SOURCE:
   `TransactionDetail.tsx: CartItemsCard` gated on `txn.metadata.cart_id`, calls
   `getCartItems`; `src/api/endpoints/cart.ts`.
10. **Tracking is a separate per-transaction call
    `GET /ui/purchase-history/transactions/{txn_id}/tracking` →
    `CarrierTrackingView`; manual refresh is
    `POST /ui/shop/tracking/transactions/{txn_id}/poll`.** **VERDICT: Verified**
    (corrects the draft's per-shipment / `{order_id}/tracking` phrasing).
    SOURCE: OpenAPI `GET /ui/purchase-history/transactions/{txn_id}/tracking`
    (op `ui_get_tracking`), `POST /ui/shop/tracking/transactions/{txn_id}/poll`
    (op `ui_poll_transaction`); `src/api/endpoints/carrierTracking.ts:
    getCarrierTracking, pollCarrierTracking`.
11. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** **VERDICT:
    Verified.** SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
12. **Auth also sends `Authorization: Bearer <accessToken>` (not cookie-only).**
    **VERDICT: Corrected** (draft said "cookie-based" only). SOURCE:
    `src/api/client.ts` (`headers.set("Authorization", \`Bearer ${accessToken}\`)`).
13. **On 401, refresh once via `POST /ui/session/refresh` then retry; second 401
    logs out / re-auth.** **VERDICT: Verified.** SOURCE: `src/api/client.ts:
    refreshSession()` + the 401 retry block.
14. **Error `detail` shapes: string | `[{msg}]` | `{code,…}`.** **VERDICT:
    Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail` /
    `mapAuthorizationError`.
15. **Documented responses for `ui_get_transaction`:
    `200; 422; 400; 401; 403; 429` — no 404.** **VERDICT: Corrected** (draft
    asserted a 404 "Order not found"). SOURCE: OpenAPI index line for
    `GET /ui/purchase-history/transactions/{txn_id}`
    (`resp=200:PurchaseTransactionInfo;422:HTTPValidationError;400;401;403;429`).
16. **`tracking_url` is the per-shipping carrier URL opened externally.**
    **VERDICT: Verified.** SOURCE: `PurchaseShipping.tracking_url`;
    `TransactionDetail.tsx` anchor `href={txn.shipping.tracking_url}`
    (`target="_blank" rel="noopener noreferrer"`).
17. **Chrome Custom Tabs for the external link with `ACTION_VIEW` fallback.**
    **VERDICT: Unverified-assumption** (Android implementation choice; the web
    ref just opens a new tab). framework ref:
    https://developer.chrome.com/docs/android/custom-tabs/ and
    https://developer.android.com/reference/android/content/Intent#ACTION_VIEW
18. **Money/date locale formatting via `NumberFormat.getCurrencyInstance` /
    `DateTimeFormatter`.** **VERDICT: Verified-equivalent** (web uses
    `Intl.NumberFormat({style:"currency"})` and `toLocaleDateString`). SOURCE:
    `TransactionDetail.tsx: formatCurrency`, `formatDate`. framework ref:
    https://developer.android.com/reference/java/text/NumberFormat

### Corrections made
- Endpoint path/method fixed everywhere: `GET /ui/orders/{order_id}` →
  `GET /ui/purchase-history/transactions/{txn_id}` (§2, §4, §5, §7, §13, §14).
- Payload model rewritten (§4, §5): transaction, not order; `amount: Double`
  (major units) with no cents-totals breakdown; epoch-seconds timestamps;
  `txn_id`/`description` instead of `order_number`/`placed_at`; uppercase
  free-form `status` taxonomy; single `shipping` object instead of
  `shipments[]`.
- Line items sourced from a separate `getCartItems(metadata.cart_id)` fetch, not
  from the transaction payload (§3, §4, §5, §6).
- Tracking corrected to per-transaction (single arg) with the real tracking +
  poll endpoints (§5, §13).
- Auth note corrected: Bearer token + CSRF cookie, not cookie-only (§2).
- 404 claim softened to the documented `422/400/401/403/429` set (§5, §7, §14).
- Frontend reference paths corrected: `purchases.ts` / `carrierTracking.ts` /
  `TransactionDetail.tsx` (no `orders.ts`/`Order`/`OrderItem`/`TrackingInfo`)
  (§2).

### Open assumptions
- **Custom Tabs vs. `ACTION_VIEW`** is an Android-side choice not present in the
  web ref (claim 17) — unverifiable from backend/frontend sources; validate on
  device (TC-AND-220-09/12).
- **`amount` rounding / zero-decimal currency behavior** from the dev backend is
  unverified — schema only says `number`; no JPY sample observed. Assume
  `NumberFormat` from the currency code is correct; verify with a real payload.
- **Cart-items endpoint ownership** (`GET /ui/cart/{cart_id}/items` vs. an
  existing AND-218/AND-219 repository) is unconfirmed — depends on those tickets.
- **Deep link `testlogon://orders/{orderId}`** is an app-internal decision with
  no backend/web counterpart — unverifiable here (carried as a design choice).
- **Pre-render `OrderSummary` seed from AND-219** is an inter-ticket contract,
  not verifiable from the provided sources — depends on AND-219's API.

## 17. Test Plan

Acceptance-criteria references point to §14 (AC-1..AC-9). Test targets: JVM =
JVM/Robolectric unit; MWS = contract via MockWebServer; emulator = headless AVD
`test35` (x86_64, API 35); device = physical Samsung Galaxy A15 5G (SM-A156U,
API 34, arm64-v8a).

- **TC-AND-220-01 — Happy path: detail renders with tracking.**
  Type: unit (ViewModel) + Compose-UI. Target: JVM (VM) + emulator (UI).
  Preconditions: MWS returns a `PurchaseTransactionInfo` with `status:"PENDING"`,
  `amount:49.57`, `currency:"USD"`, `metadata.cart_id`, and a `shipping` with a
  `tracking_number` + `tracking_url`; cart fetch returns 2 `CartItem`s.
  Steps: open `orders/{txnId}`; let load complete. Expected: state →
  `Content`; header shows label/status/created/`$49.57`; both items render;
  one `TrackingStatusCard` shows carrier + status with a "Track package" button.
  Traces: AC-1, AC-2, AC-3, AC-4.

- **TC-AND-220-02 — Money & timestamp mapping.** Type: contract/MWS + unit.
  Target: JVM. Preconditions: payload with `amount:49.5`, `currency:"USD"`,
  `created_at:1748451851` (epoch seconds), `shipping.shipped_at` set.
  Steps: deserialize + `toDomain()`; format. Expected: `amount` → `$49.50`
  (major units, NOT `$0.50`); `createdAt == Instant.ofEpochSecond(1748451851)`;
  no cents-breakdown fields referenced. Traces: AC-2.

- **TC-AND-220-03 — Unknown status maps to UNKNOWN; known uppercase statuses
  map correctly.** Type: unit. Target: JVM. Preconditions: payloads with
  `status` in {`PENDING`,`COMPLETED`,`CANCELLED`,`REVERTED`,`CANCEL_REQUESTED`,
  `CANCEL_DENIED`,`WAT`}. Steps: map each. Expected: first six map to the
  matching enum; `WAT` → `OrderStatus.UNKNOWN` (no crash). Traces: AC-2.

- **TC-AND-220-04 — Items resolved from cart_id; omitted when absent.**
  Type: contract/MWS + Compose-UI. Target: JVM + emulator. Preconditions:
  (a) txn with `metadata.cart_id` + cart returns items; (b) txn with no
  `cart_id`. Steps: load each. Expected: (a) items card with name/qty/unit
  price/line subtotal, thumbnails via Coil with name `contentDescription`;
  (b) no items card, no crash, no empty placeholder. Traces: AC-3.

- **TC-AND-220-05 — No shipping → no tracking section; shipping w/o number →
  "Tracking not available yet".** Type: Compose-UI. Target: emulator.
  Preconditions: (a) `shipping == null`; (b) `shipping` present,
  `tracking_number == null`. Steps: render. Expected: (a) tracking section
  absent; (b) section shows "Tracking not available yet" and no "Track package"
  button. Traces: AC-5.

- **TC-AND-220-06 — Loading skeleton then content.** Type: Compose-UI.
  Target: emulator. Preconditions: MWS delayed response. Steps: open screen.
  Expected: skeleton shown while `Loading`, replaced by `Content` on success.
  Traces: AC-6.

- **TC-AND-220-07 — Offline with cache → stale content + banner; offline no
  cache → retryable error; pull-to-refresh/Retry re-fetch.** Type: unit
  (ViewModel, Turbine) + integration. Target: JVM (+ emulator with airplane
  mode for the integration leg). Preconditions: (a) Room has a cached txn,
  network fails; (b) empty cache, network fails. Steps: trigger load; then
  restore network and pull-to-refresh. Expected: (a) `Content(isStale=true)` +
  "Showing saved copy" banner; (b) `Error(canRetry=true, "You're offline")`;
  refresh/Retry transitions to fresh `Content`. Traces: AC-6, AC-7.

- **TC-AND-220-08 — Flaky dev host: retry on 503 then 200; terminal on 422.**
  Type: contract/MWS. Target: JVM. Preconditions: MWS scripted 503,503,200 for
  the GET, and separately a single 422 `HTTPValidationError`. Steps: load each.
  Expected: 503 sequence → bounded backoff (≤3 attempts) → `Content`; 422 →
  terminal `Error(canRetry=false)` "Order not found / invalid" (no retry storm).
  Traces: AC-6, AC-7.

- **TC-AND-220-09 — "Track package" opens validated https URL (happy + scheme
  rejection).** Type: unit (URL validator) + instrumented. Target: JVM
  (validator) + device (real Custom Tab launch / `ACTION_VIEW` fallback).
  Preconditions: shipping `tracking_url` = a real `https://www.ups.com/...`;
  plus injected `javascript:`, `file:`, `intent:`, `http:` (non-allowlisted)
  values. Steps: tap "Track package" / call validator. Expected: only
  `https` (and dev-allowlisted `http`) launches a Custom Tab (fallback
  `ACTION_VIEW` if no browser); all other schemes rejected and never launched;
  app session/cookies not shared to the carrier site. MUST run on the physical
  device for the real Custom Tabs / browser-availability path. Traces: AC-4,
  AC-8.

- **TC-AND-220-10 — 401 triggers a single session refresh then retry.**
  Type: contract/MWS. Target: JVM. Preconditions: MWS returns 401 once, then
  200 after `POST /ui/session/refresh`. Steps: load. Expected: exactly one
  refresh call, original GET retried once, `Content` rendered; a second 401
  surfaces an auth error / re-auth route. Traces: AC-6.

- **TC-AND-220-11 — Security: CSRF + auth headers, cleartext scoping, no PII in
  logs/analytics.** Type: contract/MWS + unit. Target: JVM. Preconditions:
  MWS recording; Timber test tree; analytics fake. Steps: perform a load + a
  track-link tap. Expected: requests carry `X-CSRF-Token` (from `ui_csrf`) and
  `Authorization: Bearer`; cleartext permitted only for the dev host;
  `order_detail_viewed`/`order_tracking_link_opened` emit hashed `txn_id` and
  carry no tracking number / item name / price; logs contain no tracking
  numbers, names, prices, or raw `txn_id`. Traces: AC-9.

- **TC-AND-220-12 — Accessibility checks.** Type: Compose-UI + instrumented
  (TalkBack). Target: emulator (semantics) + device (real TalkBack pass).
  Preconditions: content state with shipping + items. Steps: run semantics
  assertions; enable TalkBack on device and traverse. Expected: thumbnails have
  name `contentDescription`; decorative icons have `null`; "Track package"
  exposes a descriptive label incl. carrier + tracking suffix; touch targets
  ≥ 48dp; font-scaling honored; AA contrast. Device leg confirms the real
  TalkBack reading order. Traces: AC-3, AC-4.

- **TC-AND-220-13 — ABI / API-level parity (arm64 API 34 vs x86_64 API 35).**
  Type: instrumented/e2e. Target: device (arm64-v8a, API 34) AND emulator
  (x86_64, API 35). Preconditions: TC-01 happy-path setup. Steps: run the
  happy-path e2e on both. Expected: identical rendering, money/date formatting,
  and Custom Tab launch behavior; no ABI/API-specific crash. The device leg is
  required to catch arm64 / API-34 differences. Traces: AC-1, AC-2, AC-4.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (open detail, renders w/ tracking) | TC-01, TC-13 |
| AC-2 (header: label/status/date/amount) | TC-01, TC-02, TC-03, TC-13 |
| AC-3 (line items + thumbnails / omit) | TC-01, TC-04, TC-12 |
| AC-4 (tracking card + Track package opens URL) | TC-01, TC-09, TC-12, TC-13 |
| AC-5 (no shipping → no section; no number → pending) | TC-05 |
| AC-6 (loading/stale/offline/terminal error states) | TC-06, TC-07, TC-08, TC-10 |
| AC-7 (pull-to-refresh & Retry re-fetch) | TC-07, TC-08 |
| AC-8 (non-http(s) URL rejected) | TC-09 |
| AC-9 (no PII in logs/analytics) | TC-11 |
