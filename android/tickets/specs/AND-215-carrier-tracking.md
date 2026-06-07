---
id: AND-215
title: Carrier tracking
milestone: M5
epic: E29
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  field names. **CORRECTED:** the tracking endpoint is
  `GET /ui/purchase-history/transactions/{txn_id}/tracking`
  (op `ui_get_tracking_...`), NOT `/ui/purchases/{order_id}/tracking`. Note
  the OpenAPI 200 response body for this op is declared as an empty schema
  (`{}`, untyped), so the **authoritative response shape is the frontend
  `CarrierTrackingView` type** in `src/api/types.ts`, not OpenAPI. Verify any
  mapper field against that type and `CarrierEvent`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). Cookie-based session + `X-CSRF-Token`; tracking
  is a GET behind the authenticated session established in AND-027/AND-218.
- **Upstream deps:** AND-218 (Purchases API) provides `PurchaseDetail`,
  `OrderId`, `PurchasesRepository`, and `PurchaseDetailScreen`. AND-027 (the
  shared API client / cookie jar / `ApiResult`, transitively required) provides
  the configured Retrofit/OkHttp stack.

## 3. Functional Requirements

FR-1. Given a transaction (order) id, the app fetches carrier tracking via
`GET /ui/purchase-history/transactions/{txn_id}/tracking` (CORRECTED path; the
path param is `txn_id`) and maps the `CarrierTrackingView` body to a domain
model.

FR-2. **CORRECTED — single shipment, not a list.** The authoritative
`CarrierTrackingView` is a **flat, per-transaction** shape with at most ONE
carrier/tracking set (`carrier`, `tracking_number`, `tracking_url`, `status`,
`carrier_events[]`); there is no `shipments` array in the contract. The UI
therefore renders at most one tracking card per order. A transaction with no
carrier/tracking data (all of `carrier`/`tracking_number` null/absent) renders
no tracking card — instead a single informational row: "Not yet shipped."
(The original multi-shipment design is retained only as a forward-looking note;
implement against the flat shape that the backend and web client actually use.)

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

FR-6. Pull-to-refresh on the order detail screen re-fetches tracking via the
GET above. **Note (web parity):** the web client's explicit "Refresh tracking"
button does NOT re-GET — it issues `POST /ui/shop/tracking/transactions/{txn_id}/poll`
(`pollCarrierTracking`), which asks the backend to re-poll the carrier and
returns `CarrierPollTransactionOut { poll, tracking }`. For this read-only
ticket the Android refresh path is a plain GET (poll-on-demand is OUT of scope,
see FR-5); a future enhancement may add the POST poll. Tracking also refreshes
on screen re-entry if the cached entry is older than the TTL (see §6).

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

> **CORRECTED — model vs. contract.** The domain types above keep a
> `List<Shipment>` for forward-flexibility, but the backend contract is
> **flat / single-shipment** (one `CarrierTrackingView` per `txn_id`, no
> `shipments` array). Map the single view into a 0-or-1-element list. Also:
> the backend's status vocabulary (per the mock-tracking seed schema and web
> usage) is lowercase `label_created, in_transit, out_for_delivery, delivered,
> exception`; `PRE_TRANSIT`/`RETURNED` are NOT emitted by the backend and exist
> only as defensive extras (they will simply never be produced). Carrier is a
> **single string code** (e.g. `"ups"`, `"fedex"`, `"usps"`, `"dhl"`) — there is
> no separate `carrier_code`/`carrier_name` pair on the wire (see §4.2). And
> `TrackingEvent` has **no per-event `status`** field in the contract
> (`CarrierEvent` = `{timestamp?, description?, location?}`); derive a status
> for display from the shipment-level `status` or drop the per-event chip.

### 4.2 Network layer (`core-network`)

Mirror of `carrierTracking.ts` (`getCarrierTracking`). Retrofit service plus
Moshi DTOs. **CORRECTED** to match `CarrierTrackingView` / `CarrierEvent` in
`src/api/types.ts` (flat, single-shipment; no `shipments` wrapper). Note the
path is `ui/purchase-history/transactions/{txnId}/tracking`, the body returns
`txn_id` (not `order_id`), `delivered_at` and `last_carrier_check` are **epoch
seconds (numbers)** not ISO strings, and events come under `carrier_events`:

```kotlin
interface CarrierTrackingApi {
    @GET("ui/purchase-history/transactions/{txnId}/tracking")
    suspend fun getTracking(
        @Path("txnId") txnId: String,
        // Optional auth params the backend accepts (normally supplied by the
        // cookie session / shared client, included here for completeness):
        // @Query("user_sub") userSub: String? = null,
    ): CarrierTrackingViewDto
}

@JsonClass(generateAdapter = true)
data class CarrierTrackingViewDto(
    @Json(name = "txn_id") val txnId: String,
    val carrier: String?,                                  // single code, e.g. "ups"
    @Json(name = "tracking_number") val trackingNumber: String?,
    @Json(name = "tracking_url") val trackingUrl: String?,
    val status: String?,
    @Json(name = "status_description") val statusDescription: String?,
    @Json(name = "estimated_delivery") val estimatedDelivery: String?,   // ISO string
    @Json(name = "delivered_at") val deliveredAt: Long?,                 // epoch SECONDS
    @Json(name = "carrier_events") val carrierEvents: List<CarrierEventDto>? = null,
    @Json(name = "last_carrier_check") val lastCarrierCheck: Long?,      // epoch seconds
)

@JsonClass(generateAdapter = true)
data class CarrierEventDto(
    val timestamp: String?,          // ISO string; nullable per contract
    val description: String?,
    val location: String?,
    // NOTE: no per-event `status` field exists in the CarrierEvent contract.
)
```

`delivered_at` / `last_carrier_check` are seconds; convert with
`Instant.ofEpochSecond(it)`. `estimated_delivery` is an ISO string.
`status_description` is a backend-provided human label that should be preferred
over the client enum→string map when present.

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
    data object NotShipped : TrackingUiState        // 200 with no carrier/tracking data
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

**Request:** `GET /ui/purchase-history/transactions/{txn_id}/tracking`
(CORRECTED path + param name). Auth: session cookies; the shared web client
also sets `X-CSRF-Token` (from the `ui_csrf` cookie) on every request including
GETs, plus an `Authorization: Bearer <accessToken>` header from the auth store
(verified in `src/api/client.ts`). The OpenAPI op additionally documents
optional `user_sub` (query), `X-SESSION-ID` and `X-IMPERSONATION-TOKEN`
(headers). No required query params. Idempotent.

**200 response — `CarrierTrackingView` (CORRECTED: flat, single-shipment):**

```json
{
  "txn_id": "txn_8Kd92",
  "carrier": "ups",
  "tracking_number": "1Z999AA10123456784",
  "tracking_url": "https://www.ups.com/track?tracknum=1Z999AA10123456784",
  "status": "in_transit",
  "status_description": "Departed facility, in transit",
  "estimated_delivery": "2026-06-09T00:00:00Z",
  "delivered_at": null,
  "carrier_events": [
    {
      "timestamp": "2026-06-06T14:22:00Z",
      "description": "Departed facility",
      "location": "Columbus, OH, US"
    }
  ],
  "last_carrier_check": 1749218400
}
```

Notes vs. the old example: top-level `txn_id` (not `order_id`); there is **no
`shipments` array**; `carrier` is a single string; events are `carrier_events`
and carry **no per-event `status`**; `delivered_at`/`last_carrier_check` are
**epoch seconds** (or null). A transaction that has not shipped returns a view
with `carrier`/`tracking_number`/`status` null (or absent) → mapped to
`TrackingUiState.NotShipped`. (The OpenAPI 200 schema for this op is empty/
untyped; the field shape above is from `CarrierTrackingView`.)

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
- **Empty vs. error:** HTTP 200 with null/absent carrier+tracking fields is
  **NotShipped**, never an error. Distinguish clearly so not-yet-shipped orders
  don't show error UI.
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

- **R1 (schema): RESOLVED in this review.** The path is
  `GET /ui/purchase-history/transactions/{txn_id}/tracking` and the field shape
  is `CarrierTrackingView` (see §5/§16). The OpenAPI 200 body is untyped, so the
  frontend type is authoritative; defensive mappers + `UNKNOWN` fallback are
  retained for dev-host drift. Residual risk: backend may add fields not in the
  TS type.
- **R2 (multi-shipment): RESOLVED — single shipment.** The contract is flat
  (one carrier/tracking set per transaction); there is no multi-shipment array.
  The domain model keeps a 0-or-1-element list only for forward flexibility.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Tracking endpoint path/method.** Claim (orig.): `GET /ui/purchases/{order_id}/tracking`.
   **VERDICT: Corrected** → `GET /ui/purchase-history/transactions/{txn_id}/tracking`.
   Source: OpenAPI `GET /ui/purchase-history/transactions/{txn_id}/tracking`
   (op `ui_get_tracking_ui_purchase_history_transactions__txn_id__tracking_get`);
   `src/api/endpoints/carrierTracking.ts: getCarrierTracking`. No `/ui/purchases/*`
   route exists in the OpenAPI index.
2. **Path parameter name.** Claim: `order_id`. **VERDICT: Corrected** → `txn_id`.
   Source: OpenAPI op `parameters[].name=txn_id` (path);
   `src/api/endpoints/carrierTracking.ts` (`/transactions/${txnId}/tracking`).
3. **Response is `{order_id, shipments:[...]}` (multi-shipment).**
   **VERDICT: Corrected** → flat, single-shipment `CarrierTrackingView`
   (`txn_id, carrier?, tracking_number?, tracking_url?, status?, status_description?,
   estimated_delivery?, delivered_at?, carrier_events?, last_carrier_check?`); no
   `shipments` array. Source: `src/api/types.ts: CarrierTrackingView`.
4. **Per-shipment fields `carrier_code` + `carrier_name`.** **VERDICT: Corrected**
   → a single `carrier` string code (e.g. `"ups"`). Source: `src/api/types.ts:
   CarrierTrackingView.carrier`; web display uses `txn.shipping.carrier` directly
   (`src/pages/purchases/TransactionDetail.tsx`).
5. **Events field named `events`, with per-event `status`.** **VERDICT: Corrected**
   → field is `carrier_events`; each `CarrierEvent` is `{timestamp?, description?,
   location?}` with **no `status`**. Source: `src/api/types.ts: CarrierEvent`.
6. **`delivered_at` is an ISO-8601 string.** **VERDICT: Corrected** → epoch
   **seconds** (number); same for `last_carrier_check`. Source:
   `src/api/types.ts` (`delivered_at?: number`, `last_carrier_check?: number`);
   web formats via `new Date(ts * 1000)` (`TransactionDetail.tsx: formatDate`).
   (`estimated_delivery` remains an ISO string — Verified.)
7. **`status_description` field exists.** **VERDICT: Corrected/added** — the spec
   originally omitted it; backend supplies a human label. Source: `src/api/types.ts:
   CarrierTrackingView.status_description`; mock-seed schema documents
   `status_description (optional, human-readable)`.
8. **Status enum vocabulary.** Claim: `LABEL_CREATED, IN_TRANSIT, OUT_FOR_DELIVERY,
   DELIVERED, EXCEPTION` plus `PRE_TRANSIT, RETURNED`. **VERDICT: Partially
   verified** — backend documents lowercase `label_created, in_transit,
   out_for_delivery, delivered, exception`. Source: OpenAPI
   `POST /mock/carrier-tracking/seed` description. `PRE_TRANSIT`/`RETURNED` are
   **Unverified-assumption** (defensive extras; not emitted by the backend).
9. **Carrier codes.** Codes are `ups, fedex, usps, dhl`. **VERDICT: Verified.**
   Source: OpenAPI `POST /mock/carrier-tracking/seed` description.
10. **Auth: cookie session + `X-CSRF-Token` from `ui_csrf` cookie.**
    **VERDICT: Verified** (the web client sets `X-CSRF-Token` on every request,
    GET included) **+ corrected/expanded**: it also sends `Authorization: Bearer
    <accessToken>`, and the op documents optional `user_sub`/`X-SESSION-ID`/
    `X-IMPERSONATION-TOKEN`. Source: `src/api/client.ts` (lines ~157–171);
    OpenAPI op `parameters`.
11. **401 → single `POST /ui/session/refresh` then one retry.** **VERDICT:
    Verified.** Source: `src/api/client.ts: refreshSession` + single in-flight
    `refreshPromise` guard; OpenAPI `POST /ui/session/refresh`.
12. **FastAPI `detail` error shape (string | `[{msg}]` | `{code,...}`).**
    **VERDICT: Verified.** Source: `src/api/client.ts: normalizeErrorDetail`,
    `mapAuthorizationError`; OpenAPI `422: HTTPValidationError`.
13. **Network error mapping.** Web maps fetch failure to `ApiError(0, "Network
    error")`. **VERDICT: Verified** (informs the Android offline/IOException path).
    Source: `src/api/client.ts` catch block (~line 185).
14. **"Refresh tracking" re-fetches via GET.** **VERDICT: Corrected (web parity).**
    The web "Refresh tracking" button issues `POST /ui/shop/tracking/transactions/
    {txn_id}/poll` (`pollCarrierTracking`) returning `CarrierPollTransactionOut`,
    not a GET. Android keeps a GET-only refresh for this read-only ticket (poll is
    out of scope). Source: `src/api/endpoints/carrierTracking.ts: pollCarrierTracking`;
    `src/pages/purchases/TransactionDetail.tsx: pollTrackingMutation`; OpenAPI
    `POST /ui/shop/tracking/transactions/{txn_id}/poll`.
15. **Tracking link opens via external browser/anchor.** **VERDICT: Verified**
    (web uses `<a target="_blank" rel="noopener noreferrer">`). The Android
    https-scheme validation before `ACTION_VIEW` is an **Unverified-assumption**
    (sensible hardening, not present in web). Source: `TransactionDetail.tsx`
    tracking-link `<a>`; framework ref:
    https://developer.android.com/training/basics/intents/sending
16. **404 → "Order not found".** **VERDICT: Unverified-assumption** — the OpenAPI
    op only declares 200 and 422; a 404 mapping is plausible but not documented.
    Source: OpenAPI op responses (`200`, `422` only).
17. **Android framework/version targets** (Kotlin 2.0.21, AGP 8.7.3, Compose,
    Room, Moshi/Retrofit, minSdk 24/targetSdk 35). **VERDICT: Unverified-assumption**
    (project toolchain choices, not in the reference sources). Framework refs:
    https://developer.android.com/jetpack/compose ,
    https://developer.android.com/training/data-storage/room ,
    https://square.github.io/retrofit/ .
18. **15-minute cache TTL.** **VERDICT: Unverified-assumption** (R5) — no backend
    guidance on carrier-event update cadence. `last_carrier_check` (from the view)
    could later drive a smarter TTL. Source: `src/api/types.ts:
    CarrierTrackingView.last_carrier_check`.

### Corrections made

- Endpoint path corrected to `GET /ui/purchase-history/transactions/{txn_id}/tracking`
  and path param to `txn_id` (was `/ui/purchases/{order_id}/tracking`) — §2, §4.2,
  §5, FR-1, R1.
- Response shape corrected from nested `{order_id, shipments:[]}` to the flat
  single-shipment `CarrierTrackingView`; domain model now maps to a 0/1-element
  list — §4.1, §4.2, §5, FR-2, R2.
- DTO field names corrected: `txn_id` (not `order_id`); single `carrier` (not
  `carrier_code`/`carrier_name`); `carrier_events` (not `events`); added
  `status_description` and `last_carrier_check`; removed the invented per-event
  `status` — §4.2, §5.
- `delivered_at` / `last_carrier_check` corrected to epoch **seconds** (numbers),
  not ISO strings — §4.2, §5.
- NotShipped trigger corrected from "empty shipments array" to "null/absent
  carrier+tracking fields" — §4.5, §5, §7.
- Refresh semantics clarified: web "Refresh tracking" is a POST poll, not a GET;
  Android refresh stays GET-only (poll out of scope) — FR-6.
- Auth note expanded: `X-CSRF-Token` confirmed and `Authorization: Bearer`
  documented — §5.
- R1/R2 marked RESOLVED — §13.

### Open assumptions

- `PRE_TRANSIT` / `RETURNED` statuses: not emitted by the backend; kept as
  defensive enum values only (will never appear). Unverifiable beyond the seed
  schema's documented set.
- 404 → "Order not found" mapping: OpenAPI declares only 200/422 for this op;
  the not-found behavior is assumed, not documented.
- 15-minute TTL: no backend guidance; placeholder pending tracking-update cadence.
- Android https-only validation before launching `tracking_url`: a hardening
  decision with no web counterpart; assumed safe and desirable.
- All Android toolchain/library/version choices: project conventions, not present
  in the OpenAPI/frontend sources.

## 17. Test Plan

Test cases for AND-215. IDs `TC-AND-215-NN`. "AC-#" trace to §14.
Default target is the **headless emulator AVD `test35`** (API 35) for
instrumented/Compose suites and **JVM/Robolectric** for unit/contract; only the
external-browser-launch case benefits from the **physical Samsung A15 (SM-A156U,
API 34, serial R5CX821TA9R)** to exercise the real Chrome/browser chooser and
arm64/API-34 behavior — noted per case. (No camera/biometric/WebRTC/FCM/Telecom
behavior is in scope for this read-only feature.)

- **TC-AND-215-01 — Mapper: happy-path CarrierTrackingView → domain.**
  Type: unit (JVM). Target: `core-data` mapper (`CarrierTrackingViewDto.toDomain`).
  Preconditions: a `CarrierTrackingView` JSON fixture with `carrier="ups"`,
  `status="in_transit"`, two `carrier_events`, `estimated_delivery` ISO,
  `delivered_at=null`. Steps: deserialize with Moshi, call mapper. Expected:
  domain `Shipment` with carrier code `ups`, `ShipmentStatus.IN_TRANSIT`, events
  sorted newest-first, `estimatedDelivery` parsed, `deliveredAt=null`. Traces: AC-1, AC-3.

- **TC-AND-215-02 — Mapper: epoch-seconds and unknown-status handling.**
  Type: unit (JVM). Target: `core-data` mapper + `ShipmentStatus.from`.
  Preconditions: fixture with `status="warp_speed"` (unrecognized),
  `delivered_at=1749218400` (epoch seconds), malformed `estimated_delivery`.
  Steps: map. Expected: `ShipmentStatus.UNKNOWN`; `deliveredAt ==
  Instant.ofEpochSecond(1749218400)`; unparseable date → null; no exception.
  Traces: AC-3.

- **TC-AND-215-03 — Mapper: not-shipped (null carrier/tracking) → NotShipped.**
  Type: unit (JVM). Target: mapper + state reducer. Preconditions: view with
  `carrier=null, tracking_number=null, status=null, carrier_events=null`.
  Steps: map and reduce to `TrackingUiState`. Expected: `TrackingUiState.NotShipped`
  (not Ready, not Error). Traces: AC-2.

- **TC-AND-215-04 — Mapper: carrier display fallback + status_description preference.**
  Type: unit (JVM). Target: mapper. Preconditions: (a) `carrier="fedex"`,
  `status_description="Out for delivery"`; (b) `carrier=null`. Steps: map both.
  Expected: (a) display name uses `status_description` over enum label, carrier
  shown as `FEDEX`; (b) carrier display falls back to "Carrier". Traces: AC-1, AC-3.

- **TC-AND-215-05 — Contract: 200 with shipment → Ready.**
  Type: contract/MockWebServer. Target: `CarrierTrackingApi` + repository.
  Preconditions: MockWebServer enqueues 200 with a full `CarrierTrackingView`
  body for `GET /ui/purchase-history/transactions/{txn_id}/tracking`. Steps:
  call `repository.tracking(txnId)`. Expected: request path/method match exactly;
  emits `Ready` with one shipment; latest event present. Traces: AC-1.

- **TC-AND-215-06 — Contract: 200 not-shipped body → NotShipped.**
  Type: contract/MockWebServer. Target: repository. Preconditions: 200 with
  `{"txn_id":"...","carrier":null,"tracking_number":null}`. Steps: collect flow.
  Expected: emits `NotShipped`; no error UI. Traces: AC-2.

- **TC-AND-215-07 — Contract: 404 → non-retryable Error.**
  Type: contract/MockWebServer. Target: repository. Preconditions: MockWebServer
  returns 404 with `{"detail":"Order not found"}`. Steps: collect flow. Expected:
  `Error(retryable=false)` with the parsed detail; no internal retry on 4xx.
  Traces: AC-1 (negative). (Note: 404 mapping is an assumption — see §16 #16.)

- **TC-AND-215-08 — Contract: 500-then-200 single backoff retry → Ready.**
  Type: contract/MockWebServer. Target: repository. Preconditions: enqueue 500
  then 200(valid). Steps: collect flow. Expected: exactly one bounded retry;
  final `Ready`; verify two recorded requests. Traces: AC-1, AC-7.

- **TC-AND-215-09 — Contract: 401 → one session refresh + retry, then non-retryable.**
  Type: contract/MockWebServer. Target: OkHttp authenticator + repository.
  Preconditions: enqueue 401, then `POST /ui/session/refresh` 200, then 401 again.
  Steps: call. Expected: exactly one `POST /ui/session/refresh` issued, original
  GET retried once; persistent 401 → `Error(retryable=false)` and host routes to
  login (no refresh storm). Traces: AC-6.

- **TC-AND-215-10 — Integration: offline with cache → Ready(isStale=true).**
  Type: integration (Robolectric + in-memory Room + MockWebServer). Target:
  offline-first repository. Preconditions: seed Room with a tracking row
  `fetchedAt` > 15 min old; MockWebServer set to fail (IOException/timeout).
  Steps: collect flow, trigger refresh. Expected: emits cached `Ready(isStale=true)`
  immediately; refresh failure retains stale data (no crash, no Error replacing
  cache); non-blocking "Couldn't refresh tracking" surfaced. Traces: AC-5.

- **TC-AND-215-11 — Integration: Room additive migration from AND-218 version.**
  Type: integration (instrumented, AVD `test35`). Target: Purchases Room DB
  migration adding the tracking entity. Preconditions: DB created at the AND-218
  schema version. Steps: open with the new version + migration, run
  `MigrationTestHelper`. Expected: migration succeeds; existing rows intact;
  tracking table/columns present. Traces: AC-7.

- **TC-AND-215-12 — ViewModel: Loading → Ready/Error transitions.**
  Type: unit (JVM, `runTest`). Target: `PurchaseDetailViewModel.tracking` StateFlow.
  Preconditions: fake repository emitting Loading→Ready, and Loading→Error.
  Steps: collect with a test dispatcher. Expected: ordered emissions match;
  `WhileSubscribed` does not drop the terminal state for an active collector.
  Traces: AC-1, AC-7.

- **TC-AND-215-13 — Compose-UI: tracking renders; timeline expand/collapse; copy.**
  Type: Compose-UI (AVD `test35`). Target: `TrackingSection`/`ShipmentCard`/
  `TrackingTimeline`. Preconditions: `Ready` state with one shipment + 3 events.
  Steps: assert carrier name, status chip, tracking number, and latest event are
  displayed; tap to expand timeline → all events shown; long-press tracking
  number → "Copy tracking number" action fires `onCopy`. Expected: all assertions
  pass; expand toggles event count. Traces: AC-1, AC-7.

- **TC-AND-215-14 — Compose-UI: NotShipped row and hidden CTA when tracking_url null.**
  Type: Compose-UI (AVD `test35`). Target: `TrackingSection`. Preconditions:
  (a) `NotShipped` state; (b) `Ready` with `trackingUrl=null` but carrier+number
  present. Steps: render both. Expected: (a) "Not yet shipped" row, no error/card;
  (b) "Track on carrier site" affordance is absent (not merely disabled).
  Traces: AC-2, AC-4.

- **TC-AND-215-15 — Instrumented: external carrier link launch + https-only guard
  (PHYSICAL DEVICE).** Type: instrumented/e2e. Target: `onOpenCarrier` →
  `ACTION_VIEW`. **Must run on the physical Samsung A15 (SM-A156U, API 34)** to
  exercise the real browser/Custom-Tab chooser and arm64/API-34 intent behavior.
  Preconditions: `Ready` with `trackingUrl="https://www.ups.com/track?..."`; a
  second fixture with a non-https scheme (e.g. `intent://`/`http://`). Steps:
  tap "Track on carrier site" (use Espresso-Intents `intended()` to capture);
  then attempt the non-https fixture. Expected: https URL fires a single
  `ACTION_VIEW` with the exact URL; non-https URL is rejected (no intent fired).
  Traces: AC-4.

- **TC-AND-215-16 — Compose-UI: accessibility (TalkBack semantics, touch targets,
  contrast).** Type: Compose-UI (AVD `test35`). Target: `StatusChip`, timeline,
  tracking-number row. Preconditions: `Ready` fixture, light + dark themes.
  Steps: assert status chip `contentDescription` reads the full localized status
  ("Status: Out for delivery"); each timeline entry is one merged semantics node;
  the copy action is exposed as a custom a11y action; assert touch targets ≥ 48dp.
  Expected: all semantics/size assertions pass in both themes. Traces: AC-1, AC-7.

- **TC-AND-215-17 — Manual: dev-host flakiness end-to-end against real backend.**
  Type: manual. Target: full screen against `http://18.222.237.167:8000` (seed via
  `POST /mock/carrier-tracking/seed`). Preconditions: a seeded shipped order;
  toggle airplane mode mid-session. Steps: open order detail; observe tracking;
  go offline and pull-to-refresh; come back online and refresh. Expected: stale
  badge + retained data offline; successful refresh online; no token/tracking
  number in logcat. Traces: AC-5, AC-7.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (tracking shows for an order) | TC-01, TC-04, TC-05, TC-12, TC-13, TC-16 |
| AC-2 (no tracking → "Not yet shipped", not error) | TC-03, TC-06, TC-14 |
| AC-3 (status mapping incl. unknown → no crash) | TC-01, TC-02, TC-04 |
| AC-4 (open tracking_url; CTA hidden when null) | TC-14, TC-15 |
| AC-5 (stale cache shown + background refresh; failed refresh retains) | TC-10, TC-17 |
| AC-6 (401 → exactly one refresh+retry, then non-retryable) | TC-09 |
| AC-7 (all §11 test suites green in CI) | TC-08, TC-11, TC-12, TC-13, TC-16, TC-17 |
