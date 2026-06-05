---
id: AND-220
title: Order detail + tracking
milestone: M5
epic: E30
priority: P1
size: M
status: draft
depends_on: [AND-219, AND-215]
blocks: []
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
  (PLAINTEXT, unreliable). OpenAPI at `/openapi.json`. Auth is cookie-based;
  all calls ride the persistent cookie jar and echo `ui_csrf` as
  `X-CSRF-Token`. On 401, OkHttp authenticator calls
  `POST /ui/session/refresh` once then retries.
- **Web reference**: `frontend/src/api/endpoints/orders.ts` (order detail
  fetch), `frontend/src/api/endpoints/carrierTracking.ts`,
  `frontend/src/api/types.ts` (`Order`, `OrderItem`, `TrackingInfo`).

## 3. Functional Requirements

1. **Navigation entry**: route `orders/{orderId}` registered in the orders nav
   graph. `orderId` is a non-empty `String` path argument. Deep-link compatible
   pattern `testlogon://orders/{orderId}` is registered but not user-facing.
2. **Header**: render order number, human status (Placed / Paid / Shipped /
   Delivered / Cancelled / Refunded), placed-at date, and grand total formatted
   with the order currency.
3. **Items list**: render each line item with name, optional thumbnail (Coil),
   quantity, unit price, and line subtotal. The list is part of the single
   vertical scroll (not an independently scrolling nested list).
4. **Totals block**: subtotal, shipping, tax, discount (if present), and grand
   total. Hide a row when its value is null/zero except grand total.
5. **Tracking section**:
   - If the order has one or more shipments with tracking, render the AND-215
     `TrackingStatusCard` per shipment: carrier name, tracking number, current
     status, last-update timestamp, and a **"Track package"** button.
   - The button opens the carrier `tracking_url` via Chrome Custom Tabs,
     falling back to an `ACTION_VIEW` browser intent.
   - If tracking is pending (shipment exists, no number yet), show
     "Tracking not available yet".
   - If the order is digital / has no shipments, omit the tracking section
     entirely (do not show an empty card).
6. **States**: Loading (skeleton), Content, Error (with Retry), and Offline /
   Stale (cached content + a non-blocking banner). Pull-to-refresh re-fetches.
7. **Pre-render**: when navigated from AND-219, use the passed cached
   `OrderSummary` to paint the header immediately while the full detail loads.

## 4. Technical Design

Single Compose screen backed by a Hilt `ViewModel` exposing a
`StateFlow<OrderDetailUiState>`, fed by `OrderRepository`. Carrier tracking is
delegated to AND-215's `CarrierTrackingRepository`; this screen merges order +
tracking into one UI state.

```kotlin
// core-model
data class Order(
    val id: String,
    val orderNumber: String,
    val status: OrderStatus,
    val placedAt: Instant,
    val currency: String,          // ISO-4217, e.g. "USD"
    val items: List<OrderItem>,
    val subtotalCents: Long,
    val shippingCents: Long,
    val taxCents: Long,
    val discountCents: Long,
    val totalCents: Long,
    val shipments: List<Shipment>,
)

data class OrderItem(
    val id: String,
    val name: String,
    val imageUrl: String?,
    val quantity: Int,
    val unitPriceCents: Long,
    val lineTotalCents: Long,
)

data class Shipment(
    val id: String,
    val carrier: String?,          // e.g. "ups"
    val trackingNumber: String?,
    val trackingUrl: String?,
)

enum class OrderStatus { PLACED, PAID, SHIPPED, DELIVERED, CANCELLED, REFUNDED, UNKNOWN }
```

```kotlin
// feature-orders/detail
sealed interface OrderDetailUiState {
    data object Loading : OrderDetailUiState
    data class Content(
        val order: Order,
        val tracking: Map<String, TrackingStatus>, // shipmentId -> AND-215 status
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
    private val orderId: String = checkNotNull(savedStateHandle["orderId"])
    val uiState: StateFlow<OrderDetailUiState>
    fun refresh()
    fun retry()
    fun onTrackClicked(shipmentId: String)   // emits OpenUrl effect
}
```

```kotlin
// repository
interface OrderRepository {
    fun observeOrder(orderId: String): Flow<ApiResult<Order>>  // cache-first, then network
    suspend fun refreshOrder(orderId: String): ApiResult<Order>
}
```

Composables:

```kotlin
@Composable fun OrderDetailScreen(onBack: () -> Unit, viewModel: OrderDetailViewModel = hiltViewModel())
@Composable private fun OrderHeader(order: Order)
@Composable private fun OrderItemsList(items: List<OrderItem>, currency: String)
@Composable private fun OrderTotals(order: Order)
@Composable private fun TrackingSection(
    shipments: List<Shipment>,
    tracking: Map<String, TrackingStatus>,
    onTrack: (String) -> Unit,
) // delegates each row to AND-215 TrackingStatusCard
```

The screen is a `Scaffold` + `TopAppBar` (back nav) wrapping a
`LazyColumn` with stable keys (`order.id`, `item.id`, `shipment.id`). The
ViewModel combines `observeOrder` with per-shipment tracking flows via
`flatMapLatest` + `combine`; tracking failures are isolated so a tracking error
never fails the whole screen. Currency formatting via a shared
`core-ui` helper `formatMoney(cents: Long, currency: String): String`
using `NumberFormat.getCurrencyInstance`.

## 5. API Contract

**Order detail** — `GET /ui/orders/{order_id}` (idempotent; eligible for bounded
backoff retry). Cookies + `X-CSRF-Token` required.

Response 200:
```json
{
  "id": "ord_8f2c",
  "order_number": "TL-100245",
  "status": "shipped",
  "placed_at": "2026-05-28T17:04:11Z",
  "currency": "USD",
  "items": [
    { "id": "li_1", "name": "Widget Pro", "image_url": "https://.../w.png",
      "quantity": 2, "unit_price_cents": 1999, "line_total_cents": 3998 }
  ],
  "subtotal_cents": 3998,
  "shipping_cents": 599,
  "tax_cents": 360,
  "discount_cents": 0,
  "total_cents": 4957,
  "shipments": [
    { "id": "shp_1", "carrier": "ups", "tracking_number": "1Z999...",
      "tracking_url": "https://www.ups.com/track?tracknum=1Z999..." }
  ]
}
```

**Tracking status** — owned by AND-215 (e.g.
`GET /ui/orders/{order_id}/tracking` returning `TrackingInfo`). This ticket
calls `CarrierTrackingRepository.observeTracking(orderId, shipmentId)` and does
not bind that endpoint directly. The `tracking_url` for the "Track package"
link comes from the order `shipments[].tracking_url`; if null, fall back to the
URL supplied by AND-215's `TrackingStatus`.

**Moshi DTOs** mirror the JSON with `@Json(name = "...")` snake_case mapping
and map to `core-model` via a `toDomain()` extension. Unknown `status` strings
map to `OrderStatus.UNKNOWN`. Errors: FastAPI `detail` decoded by the shared
`core-network` error mapper (string | `[{msg}]` | `{code,...}`); 404 →
"Order not found" non-retryable.

## 6. Data & State Management

- **Cache (Room 2.6)**: reuse the orders cache established by AND-218/AND-219.
  Detail extends it with `OrderItemEntity` and `ShipmentEntity` tables keyed by
  `orderId` (FK, `onDelete = CASCADE`). `OrderDao.observeOrderWithItems(orderId):
  Flow<OrderWithRelations?>` powers cache-first rendering.
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
- **404**: terminal "Order not found", `canRetry = false`.
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
  unknown `status`→UNKNOWN, missing/null shipments→empty tracking section,
  retry on 503 then 200, no-retry on 404. DAO upsert/observe via Room
  in-memory.
- **Compose UI** (`createAndroidComposeRule`): header/items/totals render;
  totals rows hidden when zero; tracking section omitted when no shipments;
  "Tracking not available yet" when shipment without number; Retry click calls
  ViewModel; semantics/contentDescription assertions for accessibility.
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

- **Backend shape unverified**: `GET /ui/orders/{order_id}` field names and the
  `shipments[]` structure must be confirmed against `/openapi.json` and
  `frontend/src/api/endpoints/orders.ts`; the contract above is the working
  assumption. *Owner: confirm before repository merge.*
- **Tracking endpoint ownership**: whether tracking ships inline in the order
  payload or via a separate AND-215 call affects the combine logic. Assume
  separate; adapt if inline.
- **Multiple shipments / partial fulfilment**: design supports N shipments;
  confirm backend can return more than one and that each carries its own
  `tracking_url`.
- **Currency/precision**: assumes integer cents minor units; verify backend
  doesn't send floats or zero-decimal currencies (e.g. JPY) needing special
  formatting.
- **Custom Tabs availability** on minSdk 24 devices without Chrome — fallback
  `ACTION_VIEW` must be verified on a clean emulator.

## 14. Acceptance Criteria

1. Tapping an order in Purchase History (AND-219) opens `orders/{orderId}` and
   the **detail renders with tracking** (primary acceptance from the backlog).
2. Header shows order number, localized status, placed date, and grand total in
   the order currency.
3. All line items render with name, quantity, unit price, and line subtotal;
   thumbnails load via Coil with a name `contentDescription`.
4. When the order has a shipment with a tracking number, the AND-215
   `TrackingStatusCard` shows carrier + status, and "Track package" opens the
   carrier `tracking_url` in a Custom Tab / browser.
5. Orders with no shipments show **no** tracking section; shipments without a
   number show "Tracking not available yet".
6. Loading shows a skeleton; a transient backend failure with cached data shows
   stale content + banner; offline-with-no-cache shows a retryable error; 404
   shows non-retryable "Order not found".
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
