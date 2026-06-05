---
id: AND-215
title: Carrier tracking
milestone: M5
epic: E29
priority: P2
size: M
status: draft
depends_on: [AND-218]
blocks: []
---

# AND-215 — Carrier tracking

## 1. Overview & Goal

Surface shipment/carrier tracking information for an order in the TestLogon
Android app. When a purchase has one or more shipments with a carrier and
tracking number, the order detail experience must render a tracking section
showing the current shipment status (e.g. `LABEL_CREATED`, `IN_TRANSIT`,
`OUT_FOR_DELIVERY`, `DELIVERED`), the carrier name, the tracking number, an
estimated/actual delivery date when available, and a chronological list of
tracking events. The user must be able to open the carrier's public tracking
page in an external browser.

This ticket owns the Android equivalent of the web reference module
`carrierTracking.ts` (under `frontend/src/api/endpoints/`) plus the Compose
UI that displays tracking status within order detail. It depends on
**AND-218 (Purchases API)** for the order/purchase domain models and the
detail screen into which the tracking section is embedded; this ticket adds
the tracking endpoint binding, mappers, repository, ViewModel state, and the
`TrackingSection` composable. The single load-bearing acceptance criterion
from the backlog is: **tracking shows for an order.**

Goal: a user viewing an order that has shipped sees accurate, resilient,
accessible tracking status sourced from the FastAPI backend, with graceful
handling of orders that have no tracking, the unreliable dev host, and
offline/stale conditions.

## 2. Context & References

- **Repo / branch:** `spannella/testlogon`, Android app in `android/`, branch
  `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`. Feature module
  package: `com.testlogon.android.feature.purchases.tracking`.
- **Module layering:** `app -> feature-purchases -> core-network, core-model,
  core-data, core-ui, core-testing`. Tracking lives inside the existing
  `feature-purchases` module created by AND-218, not a new module.
- **Web reference:**
  - `frontend/src/api/endpoints/carrierTracking.ts` — endpoint signatures and
    response shapes to mirror.
  - `frontend/src/api/endpoints/purchases.ts` — order detail (AND-218 source).
  - `frontend/src/api/types.ts` — shared `Shipment`, `TrackingEvent`,
    `CarrierTracking` types.
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json` — authoritative
  field names; confirm `GET /ui/purchases/{order_id}/tracking` shape against
  the live schema before freezing mappers.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). Cookie-based session + `X-CSRF-Token`; tracking
  is a GET behind the authenticated session established in AND-027/AND-218.
- **Upstream deps:** AND-218 (Purchases API) provides `PurchaseDetail`,
  `OrderId`, `PurchasesRepository`, and `PurchaseDetailScreen`. AND-027 (the
  shared API client / cookie jar / `ApiResult`, transitively required) provides
  the configured Retrofit/OkHttp stack.

## 3. Functional Requirements

FR-1. Given an order id, the app fetches carrier tracking via
`GET /ui/purchases/{order_id}/tracking` and maps it to a domain model.

FR-2. An order may have **zero, one, or many** shipments. The UI renders one
tracking card per shipment. Orders with no shipments render no tracking
section (collapsed, no empty card) — but a digital-only or not-yet-shipped
order shows a single informational row: "Not yet shipped."

FR-3. Each shipment card displays: carrier display name, tracking number
(monospace, copyable via long-press), a status chip mapped from the backend
status enum to a localized label, estimated or actual delivery date, and an
expandable timeline of tracking events (most recent first).

FR-4. A "Track on carrier site" affordance opens `tracking_url` (when present)
in an external browser via an `ACTION_VIEW` intent. If `tracking_url` is null
but carrier + tracking number are present, the affordance is hidden (no
client-side URL templating in this ticket).

FR-5. Tracking is **read-only**. No mutations, no push subscriptions in this
ticket (push/notify-on-delivery is explicitly out of scope; named below).

FR-6. Pull-to-refresh on the order detail screen re-fetches tracking. Tracking
also refreshes on screen re-entry if the cached entry is older than the TTL
(see §6).

FR-7. Loading, error, empty, and stale states are all visually distinct (§7).

## 4. Technical Design

### 4.1 Domain models (`core-model`)

```kotlin
package com.testlogon.android.core.model.purchases

data class CarrierTracking(
    val orderId: String,
    val shipments: List<Shipment>,
)

data class Shipment(
    val shipmentId: String,
    val carrier: Carrier,
    val trackingNumber: String?,
    val trackingUrl: String?,
    val status: ShipmentStatus,
    val estimatedDelivery: Instant?,   // null if unknown
    val deliveredAt: Instant?,         // set only when DELIVERED
    val events: List<TrackingEvent>,   // newest-first after mapping
)

data class TrackingEvent(
    val timestamp: Instant,
    val status: ShipmentStatus,
    val description: String,
    val location: String?,             // "Columbus, OH, US" or null
)

data class Carrier(
    val code: String,                  // raw backend code, e.g. "ups"
    val displayName: String,           // "UPS"
)

enum class ShipmentStatus {
    PRE_TRANSIT, LABEL_CREATED, IN_TRANSIT, OUT_FOR_DELIVERY,
    DELIVERED, EXCEPTION, RETURNED, UNKNOWN;
}
```

`ShipmentStatus.from(raw: String?)` performs case-insensitive lookup and
returns `UNKNOWN` for unrecognized values so an unexpected enum from the
backend never crashes the screen.

### 4.2 Network layer (`core-network`)

Mirror of `carrierTracking.ts`. Retrofit service plus Moshi DTOs:

```kotlin
interface CarrierTrackingApi {
    @GET("ui/purchases/{orderId}/tracking")
    suspend fun getTracking(
        @Path("orderId") orderId: String,
    ): TrackingResponseDto
}

@JsonClass(generateAdapter = true)
data class TrackingResponseDto(
    @Json(name = "order_id") val orderId: String,
    val shipments: List<ShipmentDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class ShipmentDto(
    @Json(name = "shipment_id") val shipmentId: String,
    @Json(name = "carrier_code") val carrierCode: String?,
    @Json(name = "carrier_name") val carrierName: String?,
    @Json(name = "tracking_number") val trackingNumber: String?,
    @Json(name = "tracking_url") val trackingUrl: String?,
    val status: String?,
    @Json(name = "estimated_delivery") val estimatedDelivery: String?,
    @Json(name = "delivered_at") val deliveredAt: String?,
    val events: List<TrackingEventDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class TrackingEventDto(
    val timestamp: String,
    val status: String?,
    val description: String?,
    val location: String?,
)
```

The service shares the OkHttp client, persistent cookie jar, CSRF interceptor,
401-refresh authenticator, and 20s timeouts configured in AND-027. No new
client config here.

### 4.3 Mappers (`core-data`)

```kotlin
fun TrackingResponseDto.toDomain(): CarrierTracking
fun ShipmentDto.toDomain(): Shipment   // sorts events desc by timestamp
```

Date strings are ISO-8601; parse defensively with
`runCatching { Instant.parse(it) }.getOrNull()`. Carrier display name falls
back to `carrierName ?: carrierCode?.uppercase() ?: "Carrier"`.

### 4.4 Repository (`core-data`)

```kotlin
interface CarrierTrackingRepository {
    fun tracking(orderId: String): Flow<ApiResult<CarrierTracking>>
    suspend fun refresh(orderId: String)
}
```

Implementation uses the offline-first pattern: emit cached Room data first
(stale-flagged), then network. `refresh()` forces a fetch. Single bounded
backoff retry is permitted for this idempotent GET (per project policy).

### 4.5 ViewModel & UI state (`feature-purchases`)

Tracking is exposed as a slice consumed by `PurchaseDetailViewModel`
(AND-218). To keep concerns isolated, this ticket adds a dedicated state:

```kotlin
sealed interface TrackingUiState {
    data object Loading : TrackingUiState
    data class Ready(
        val shipments: List<Shipment>,
        val isStale: Boolean,
    ) : TrackingUiState
    data object NotShipped : TrackingUiState        // 200 with no shipments
    data class Error(val message: String, val retryable: Boolean) : TrackingUiState
}
```

`PurchaseDetailViewModel` exposes `val tracking: StateFlow<TrackingUiState>`
backed by `CarrierTrackingRepository.tracking(orderId)` mapped to the state
above, with `WhileSubscribed(5_000)`.

### 4.6 Composables (`core-ui` / `feature-purchases`)

```kotlin
@Composable fun TrackingSection(state: TrackingUiState, onRetry: () -> Unit,
    onOpenCarrier: (url: String) -> Unit, onCopy: (String) -> Unit)

@Composable fun ShipmentCard(shipment: Shipment, ...)
@Composable fun StatusChip(status: ShipmentStatus)
@Composable fun TrackingTimeline(events: List<TrackingEvent>)  // collapsible
```

`TrackingSection` is inserted into `PurchaseDetailScreen`'s scroll content
below the line-items block.

## 5. API Contract

**Request:** `GET /ui/purchases/{order_id}/tracking`
Auth: session cookies + `X-CSRF-Token` header (from `ui_csrf` cookie).
No query params. Idempotent.

**200 response:**

```json
{
  "order_id": "ord_8Kd92",
  "shipments": [
    {
      "shipment_id": "shp_01",
      "carrier_code": "ups",
      "carrier_name": "UPS",
      "tracking_number": "1Z999AA10123456784",
      "tracking_url": "https://www.ups.com/track?tracknum=1Z999AA10123456784",
      "status": "in_transit",
      "estimated_delivery": "2026-06-09T00:00:00Z",
      "delivered_at": null,
      "events": [
        {
          "timestamp": "2026-06-06T14:22:00Z",
          "status": "in_transit",
          "description": "Departed facility",
          "location": "Columbus, OH, US"
        }
      ]
    }
  ]
}
```

An order with no shipments returns `{"order_id":"...","shipments":[]}`
(HTTP 200) → mapped to `TrackingUiState.NotShipped`.

**Error responses** follow the project FastAPI `detail` mapping
(string | `[{msg}]` | `{code,...}`):

- `401` → authenticator triggers `POST /ui/session/refresh` once, then retry;
  if still 401 → `Error(retryable=false)` and the host screen routes to login.
- `404` → order not found → `Error("Order not found", retryable=false)`.
- `5xx` / timeout / `IOException` → `Error(retryable=true)` with the generic
  network message; one bounded backoff retry already attempted internally.

The `detail` parsing helper and `ApiResult<T>` wrapper are reused from
AND-027; this ticket does not redefine them.

## 6. Data & State Management

- **Room cache (`core-data`):** add `TrackingEntity` keyed by `orderId`
  (one row per order, shipments serialized as a Moshi JSON column or a child
  `ShipmentEntity` table with FK; child-table approach preferred for queryable
  status). Columns include `fetchedAt: Long`. Migration appended to the
  Purchases Room database introduced by AND-218 (bump version, additive).
- **TTL / staleness:** `fetchedAt` older than **15 minutes** marks the cached
  result `isStale = true`; the UI shows the cached data immediately with a
  subtle "Updated Xm ago" caption and triggers a background refresh.
- **DataStore:** not used for tracking content; only the existing session/prefs
  store is read transitively.
- **Single source of truth:** Room. Network writes into Room; UI observes Room.
  On a successful fetch, replace the order's tracking rows transactionally.
- **Threading:** all I/O on `Dispatchers.IO` via repository; ViewModel maps on
  the default dispatcher; Compose collects with `collectAsStateWithLifecycle`.

## 7. Error Handling & Resilience

- **Timeouts:** 20s call timeout (inherited). Tracking GET is idempotent, so a
  single bounded exponential backoff retry (e.g. 500ms → 1.5s, jittered) is
  applied for `IOException`/`5xx` only — never for 4xx.
- **Offline / stale:** cached tracking renders with a stale badge; a refresh
  failure while cache exists keeps the stale data and surfaces a non-blocking
  snackbar ("Couldn't refresh tracking"). A failure with no cache shows the
  full-section `Error` state with a Retry button.
- **Empty vs. error:** HTTP 200 + empty shipments is **NotShipped**, never an
  error. Distinguish clearly so not-yet-shipped orders don't show error UI.
- **Unknown enums / null dates:** mapped to `UNKNOWN` / null and rendered
  defensively; no crashes on schema drift from the dev backend.
- **401 storm protection:** rely on the AND-027 authenticator's single-refresh
  guard; tracking does not implement its own refresh logic.

## 8. Security & Privacy

- Tracking data rides the authenticated cookie session; the persistent cookie
  jar and `X-CSRF-Token` echo are reused from AND-027. No tokens are logged.
- Tracking numbers and carrier URLs are mildly sensitive (PII-adjacent). Do not
  log full tracking numbers; if logging is needed, redact to last 4 chars.
- External carrier links open via `Intent.ACTION_VIEW`. Validate `tracking_url`
  is `https://` before launching; reject non-http(s) schemes to prevent intent
  redirection to arbitrary apps. Use a Chrome Custom Tab if available, else the
  default browser.
- Dev host is plaintext HTTP; the app already permits cleartext for the dev
  domain only via the network security config (AND-027). Carrier URLs from the
  backend are expected to be https and must not be downgraded.
- No tracking data is written to external storage or shared via logs/analytics
  payloads.

## 9. Accessibility & i18n

- Status chip exposes a `contentDescription` of the full localized status
  ("Status: Out for delivery"), not just the visual short label.
- Timeline entries use semantic merge so TalkBack reads each event as a single
  unit: "{description}, {location}, {relative time}".
- Tracking number is announced digit-by-digit-safe; long-press-to-copy exposes
  a custom accessibility action "Copy tracking number".
- All strings (status labels, "Not yet shipped", "Track on carrier site",
  "Updated Xm ago", error messages) live in `strings.xml`; status enum →
  string map is centralized in `feature-purchases`. No hardcoded UI text.
- Dates/times formatted with the device locale and zone via
  `java.time` + Android `DateUtils.getRelativeTimeSpanString` for event times.
- Touch targets ≥ 48dp; chip/timeline contrast meets WCAG AA against Material 3
  surfaces in light and dark themes.

## 10. Telemetry & Logging

- Emit analytics events (via the shared analytics façade, if present from
  AND-027; otherwise debug-log only): `tracking_viewed {order_id_hash,
  shipment_count, has_tracking}`, `tracking_carrier_opened {carrier_code}`,
  `tracking_refresh {result: success|error, stale: bool}`.
- `order_id` is hashed/truncated in analytics; tracking numbers never logged.
- Debug builds: `Timber` tags `CarrierTracking` for fetch lifecycle and mapper
  fallbacks (unknown status, unparseable date) to catch dev-host schema drift.
- Release builds: no verbose tracking logs; errors counted, not detailed.

## 11. Testing Strategy

- **Mapper unit tests (`core-data`, JVM):** `ShipmentDto.toDomain` covers each
  status string (including unknown → `UNKNOWN`), null dates, missing
  carrier_name fallback, and events sorted newest-first.
- **Repository tests (`core-testing` fakes + MockWebServer):**
  - 200 with shipments → `Ready`.
  - 200 empty shipments → `NotShipped`.
  - 404 → `Error(retryable=false)`.
  - 500 then 200 → retry succeeds → `Ready`.
  - Offline with cache → `Ready(isStale=true)`.
  - Stale cache + failed refresh → keeps stale, no crash.
- **ViewModel tests:** `StateFlow<TrackingUiState>` transitions
  Loading → Ready/Error using `runTest` and a fake repository.
- **Room migration test:** additive migration on the Purchases DB succeeds
  from the AND-218 version.
- **Compose UI tests (`androidTest`):** `TrackingSection` renders status chip,
  timeline expand/collapse, Retry callback, NotShipped row, and verifies the
  carrier-link affordance is hidden when `trackingUrl == null`.
- **Acceptance test (maps to backlog):** with a fixture order that has a
  shipment, `PurchaseDetailScreen` displays the tracking status — "Tracking
  shows for an order."

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-218 (Purchases API, P0)** — supplies
  `PurchaseDetail`, `OrderId`, `PurchasesRepository`, the Purchases Room DB,
  and `PurchaseDetailScreen` host. Tracking cannot integrate until the detail
  screen exists. Transitively requires **AND-027** (shared API client, cookie
  jar, CSRF/refresh interceptors, `ApiResult`, network security config).
- **Sequencing:** implement mappers + network DTOs (no UI) first against
  MockWebServer; then repository + Room migration; then wire
  `TrackingUiState` into `PurchaseDetailViewModel`; finally the
  `TrackingSection` composable and instrumentation tests.
- **Blocks:** nothing in the current backlog. A future "notify on delivery"
  push feature would depend on this ticket but is not yet scoped.

## 13. Risks & Open Questions

- **R1 (schema):** exact field names of `GET /ui/purchases/{order_id}/tracking`
  must be confirmed against `/openapi.json`; the dev host may differ from
  `carrierTracking.ts`. Mitigation: defensive mappers + `UNKNOWN` fallback.
  **OPEN:** is the path `/ui/purchases/{id}/tracking` or
  `/ui/orders/{id}/tracking`? Confirm in OpenAPI before merge.
- **R2 (multi-shipment):** unclear whether the backend splits an order into
  multiple shipments or returns one aggregate. Design supports a list either
  way. **OPEN:** confirm cardinality.
- **R3 (tracking_url presence):** if the backend often omits `tracking_url`,
  the "Track on carrier site" CTA disappears often. **OPEN:** should the client
  template carrier URLs by carrier_code? Deferred — out of scope here.
- **R4 (dev host flakiness):** intermittent 5xx/timeouts may make tracking look
  perpetually erroring in QA. Mitigation: stale cache + retry + clear messaging.
- **R5 (TTL value):** 15-minute TTL is an assumption; tune after backend
  guidance on tracking-event update frequency.

## 14. Acceptance Criteria

AC-1. For an order with at least one shipment, the order detail screen renders
a tracking section showing carrier name, status chip, tracking number, and at
least the latest tracking event — **"tracking shows for an order"** (backlog).
AC-2. `GET /ui/purchases/{order_id}/tracking` returning empty `shipments`
renders the "Not yet shipped" row, not an error.
AC-3. Status strings from the backend map correctly to `ShipmentStatus`, with
unrecognized values shown as a neutral "Unknown" chip and no crash.
AC-4. Tapping "Track on carrier site" opens `tracking_url` in an external
browser; the CTA is hidden when `tracking_url` is null.
AC-5. Cached tracking older than the TTL shows immediately with a stale
indicator and triggers a background refresh; a failed refresh retains the
cached data.
AC-6. 401 triggers exactly one session refresh+retry (via AND-027) before
surfacing a non-retryable error.
AC-7. All mapper, repository, ViewModel, migration, and Compose tests in §11
pass in CI.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android.feature.purchases.
  tracking`, `...core.model.purchases`, `...core.data.purchases`, and
  `...core.network` per the module layering.
- `CarrierTrackingApi`, DTOs, mappers, `CarrierTrackingRepository` + impl,
  Room `TrackingEntity` + additive migration, `TrackingUiState`,
  `PurchaseDetailViewModel` integration, and `TrackingSection` composable
  implemented and wired into `PurchaseDetailScreen`.
- All §11 tests written and green in CI; mapper/repository coverage for the
  enumerated cases.
- All user-facing strings externalized; light/dark + TalkBack verified.
- No tracking numbers or session tokens in logs; https-only carrier link
  launch enforced.
- Lint/detekt/ktlint clean; builds with Kotlin 2.0.21, AGP 8.7.3, JDK 17,
  Gradle 8.9, compileSdk/targetSdk 35, minSdk 24.
- OpenAPI path/field assumptions (R1, R2) confirmed or recorded as follow-ups;
  spec open questions resolved or ticketed.
- PR reviewed and approved; demo on a fixture/dev order shows tracking
  rendering end-to-end against `http://18.222.237.167:8000`.
