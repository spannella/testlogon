---
id: AND-404
title: Admin email/SMS dashboards (read)
milestone: M8
epic: E53
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-403]
blocks: []
---

# AND-404 — Admin email/SMS dashboards (read)

## 1. Overview & Goal

Deliver two read-only administrative dashboards in the TestLogon native Android app that
surface email-delivery and SMS-delivery health for operators. The screens consume the
backend's `/ui/admin/email/dashboard/*` and `/ui/admin/sms/dashboard/*` endpoints and
present provider metrics (send volume, delivery/bounce/failure rates, recent message
activity) in a Compose Material 3 UI. The feature is strictly observational: no message
re-sends, no template edits, no suppression-list mutations. All write affordances are
explicitly out of scope and deferred to a future M8+ admin-actions ticket.

This ticket builds directly on AND-403, which introduced the role-gated admin shell
(read-only alerts/metrics), the admin navigation entry point, and the `AdminGate`
composable that enforces the operator role before any admin destination renders. AND-404
adds the email and SMS dashboard destinations inside that shell and reuses its gating,
error, and offline scaffolding.

Goal: an operator with the admin role can open Admin → Email Dashboard and Admin → SMS
Dashboard, see current delivery metrics and a recent-activity list for each channel, pull
to refresh, and observe clear loading / empty / error / offline states — with zero
mutating capabilities exposed.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- New feature module: `feature-admin-dashboards` (or a sub-package of the existing
  `feature-admin` module created in AND-403 — see §12). Layering:
  `app -> feature-admin* -> core-network, core-model, core-data, core-ui, core-testing`.
- Dev backend: `http://18.222.237.167:8000` (plaintext HTTP, unreliable dev host). OpenAPI
  at `/openapi.json`. Web reference under `frontend/` — admin email/SMS API calls live in
  `frontend/src/api/endpoints/adminMessagingDashboards.ts` (NOT `admin.ts` — corrected on
  review; mirror its query params and response field names), shared types in
  `frontend/src/api/types.ts`. Web dashboard panels: `src/pages/admin/EmailDashboardPanel.tsx`
  and `SmsDashboardPanel.tsx` (composed by `EmailSmsDashboardPage.tsx`).
- Auth is cookie-based with a `ui_csrf` cookie echoed as `X-CSRF-Token`; the shared OkHttp
  client (from `core-network`, established in AND-027 and used by AND-403) owns the
  persistent cookie jar and the single-shot `POST /ui/session/refresh` retry on 401
  (verified: `POST /ui/session/refresh` exists; `src/api/client.ts` does exactly this).
  Note (verified on review): the web client ALSO attaches a Bearer `Authorization` header
  from its auth store in addition to cookies + CSRF; the Android `core-network` client must
  carry whatever token AND-027/AND-403 established, not cookies alone. This ticket performs
  only idempotent GETs and inherits that transport behavior unchanged.
- Stack: Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single Activity), Hilt
  (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore,
  Paging 3. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR1. Provide two navigable destinations: `admin/email-dashboard` and `admin/sms-dashboard`,
reachable from the AND-403 admin landing screen via list rows ("Email delivery",
"SMS delivery"). Both sit behind the AND-403 `AdminGate`.

FR2. Each dashboard renders a **metrics summary** region (a grid/row of metric cards:
total sent, delivered, bounced/failed, pending, and delivery-rate %) followed by a
**recent activity** list (most-recent messages with recipient-masked address, status,
provider, timestamp).

FR3. Both dashboards support **pull-to-refresh** (Material 3 `PullToRefreshBox`) and an
explicit retry action in the error state. Refresh re-issues the dashboard GET(s).

FR4. Distinct, testable UI states per screen: `Loading`, `Content` (metrics + activity),
`Empty` (request succeeded but no data), `Error` (with mapped message + Retry), and a
`stale` content variant when showing cached data while offline.

FR5. **Read-only enforcement.** No buttons, menus, swipe actions, or long-press affordances
that mutate state. Activity rows are non-actionable (or open a read-only detail in a later
ticket); for AND-404 they are inert display rows.

FR6. **Role gating.** A non-admin reaching the route (e.g., via deep link) sees the AND-403
"not authorized" state and never triggers the dashboard network calls.

FR7. Time-range selector is **out of scope** for this ticket. The stats endpoints accept an
optional integer `days` param (verified: default 7, min 1, max 365 per `EmailDashboardStatsOut`/
`SmsDashboardStatsOut.period_days`); AND-404 sends `days=7` (the backend/web default) and does
not expose a user-selectable range. (Original draft referred to a `range`/`window` string param;
that is incorrect — the param is the integer `days`.)

## 4. Technical Design

Package root: `com.testlogon.android.feature.admin.dashboards`.

Navigation (extends AND-403's admin nav graph):

```kotlin
object AdminDashboardRoutes {
    const val EMAIL = "admin/email-dashboard"
    const val SMS = "admin/sms-dashboard"
}

fun NavGraphBuilder.adminDashboardScreens(navController: NavController) {
    composable(AdminDashboardRoutes.EMAIL) {
        AdminGate { EmailDashboardScreen(onBack = navController::popBackStack) }
    }
    composable(AdminDashboardRoutes.SMS) {
        AdminGate { SmsDashboardScreen(onBack = navController::popBackStack) }
    }
}
```

Both channels share a generic ViewModel/state to avoid duplication; the channel is a
constructor/assisted parameter.

```kotlin
enum class DashboardChannel { EMAIL, SMS }

data class MetricCard(val label: String, val value: String, val emphasis: Boolean = false)

data class ActivityRow(
    // NOTE: backend delivery items have no `id` field; derive a stable key from
    // (maskedRecipient + timestamp) or the list index.
    val key: String,
    val maskedRecipient: String,   // masked to_email or phone
    val status: DeliveryStatus,    // mapped from lowercase string: delivered/bounced/failed/sent/pending/unknown
    // NOTE: delivery items expose no `provider` field. Use subject (email) or
    // bounce_type/error (failure detail) as the secondary line instead.
    val detail: String?,
    val timestamp: Instant,        // built via Instant.ofEpochSecond(created_at) — created_at is epoch seconds
)

data class DashboardUiData(
    val metrics: List<MetricCard>,
    val deliveryRatePct: Double?,
    val activity: List<ActivityRow>,
)

sealed interface DashboardUiState {
    data object Loading : DashboardUiState
    data class Content(val data: DashboardUiData, val stale: Boolean = false) : DashboardUiState
    data object Empty : DashboardUiState
    data class Error(val message: String, val canRetry: Boolean) : DashboardUiState
}
```

```kotlin
@HiltViewModel(assistedFactory = DashboardViewModel.Factory::class)
class DashboardViewModel @AssistedInject constructor(
    @Assisted val channel: DashboardChannel,
    private val repository: AdminDashboardRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<DashboardUiState>(DashboardUiState.Loading)
    val state: StateFlow<DashboardUiState> = _state.asStateFlow()

    private val _refreshing = MutableStateFlow(false)
    val refreshing: StateFlow<Boolean> = _refreshing.asStateFlow()

    init { load(forceRefresh = false) }

    fun refresh() = load(forceRefresh = true)

    private fun load(forceRefresh: Boolean) {
        viewModelScope.launch {
            if (forceRefresh) _refreshing.value = true else _state.value = DashboardUiState.Loading
            _state.value = repository.dashboard(channel, forceRefresh).toUiState()
            _refreshing.value = false
        }
    }

    @AssistedFactory interface Factory { fun create(channel: DashboardChannel): DashboardViewModel }
}
```

Repository in `core-data` (or feature-local data layer), backed by Retrofit + a Room cache:

```kotlin
interface AdminDashboardRepository {
    suspend fun dashboard(channel: DashboardChannel, forceRefresh: Boolean): ApiResult<DashboardUiData>
}
```

`ApiResult<T>` is the shared typed result (`Success`, `Error(detail)`, `NetworkError`,
`Unauthorized`) from `core-network`. `toUiState()` maps `Success(empty)` to `Empty`,
`Success(data)` to `Content`, and errors to `Error`/stale-`Content` per §7.

Compose layer: a single `DashboardScreenScaffold(title, state, refreshing, onRefresh,
onRetry, onBack)` shared by both screens. Metric cards render in a `FlowRow`/2-column grid;
activity uses `LazyColumn`. Paging 3 is **not** required for AND-404 (recent activity is a
bounded recent slice, `limit=50`); the `/deliveries` response's `next_cursor` field
(verified name — not `next`) is ignored and a "showing recent N" footer is shown. Promote to
Paging 3 in a follow-up if needed.

## 5. API Contract

All endpoints are idempotent GETs under the admin namespace. **The paths and field names
below were corrected on review against `/openapi.json` (OpenAPI index lines 662-768) and
`frontend/src/api/endpoints/adminMessagingDashboards.ts`.** The originally-drafted
`/dashboard/summary` and `/dashboard/activity` endpoints **do not exist** — they were
fabricated. The real contract:

```
GET /ui/admin/email/dashboard/stats?days=7          -> EmailDashboardStatsOut
GET /ui/admin/sms/dashboard/stats?days=7            -> SmsDashboardStatsOut
GET /ui/admin/email/deliveries?limit=50[&cursor&status]  -> MessagingDeliveryList   (activity)
GET /ui/admin/sms/deliveries?limit=50[&cursor&status]    -> MessagingDeliveryList   (activity)
```

The metrics summary comes from `/dashboard/stats` (param `days`, default 7 — NOT a string
`window`/`range`). The "recent activity" list maps to the `/deliveries` endpoint (param
`limit`, optional `cursor`, optional `status`). There is **no** combined dashboard document;
the repository fans out stats + deliveries concurrently with `async`/`awaitAll` and merges.
Optional companion endpoints used by the web panels but **out of scope** for AND-404's
minimal read view (may be added in a follow-up): `GET /ui/admin/email/dashboard/timeseries`,
`GET /ui/admin/email/dashboard/bounce-domains`, `GET /ui/admin/email/bounces`,
`GET /ui/admin/email/complaints`, `GET /ui/admin/sms/dashboard/timeseries`,
`GET /ui/admin/sms/dashboard/failure-types`, `GET /ui/admin/sms/failures` (all return
`DashboardTimeseriesOut` / `DashboardBreakdownOut` / `MessagingDeliveryList`). Headers:
cookies + `X-CSRF-Token` + Bearer `Authorization` (all injected by the shared OkHttp
interceptor; not set per-call here).

Representative responses (corrected to the real schemas — Moshi DTOs):

```jsonc
// EmailDashboardStatsOut  (rates are PERCENTAGES 0-100, not 0..1 fractions)
{
  "sent": 12840, "delivered": 12111, "bounced": 412, "complained": 7,
  "failed": 96, "suppressed": 33, "total": 12840,
  "delivery_rate": 94.3, "bounce_rate": 3.2, "complaint_rate": 0.05,
  "period_days": 7
}
```

```jsonc
// SmsDashboardStatsOut  (no `bounced`; has segments/cost/failure_rate; rates are 0-100)
{
  "sent": 4210, "delivered": 4001, "failed": 209, "total": 4210,
  "total_segments": 5120, "estimated_cost_usd": 38.40, "suppressed_numbers": 12,
  "delivery_rate": 95.0, "failure_rate": 5.0, "period_days": 7
}
```

```jsonc
// MessagingDeliveryList (deliveries = activity). created_at is EPOCH SECONDS (number),
// recipient is to_email (email) or phone (sms); there is NO id / provider field.
{
  "items": [
    { "to_email": "jane@example.com", "subject": "Welcome", "status": "delivered",
      "created_at": 1749132131, "bounce_type": null }
  ],
  "next_cursor": null
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class EmailStatsDto(
    val sent: Int = 0, val delivered: Int = 0, val bounced: Int = 0,
    val complained: Int = 0, val failed: Int = 0, val suppressed: Int = 0,
    val total: Int = 0,
    @Json(name = "delivery_rate") val deliveryRate: Double = 0.0,   // 0..100
    @Json(name = "bounce_rate") val bounceRate: Double = 0.0,       // 0..100
    @Json(name = "complaint_rate") val complaintRate: Double = 0.0, // 0..100
    @Json(name = "period_days") val periodDays: Int = 7,
)
@JsonClass(generateAdapter = true)
data class SmsStatsDto(
    val sent: Int = 0, val delivered: Int = 0, val failed: Int = 0, val total: Int = 0,
    @Json(name = "total_segments") val totalSegments: Int = 0,
    @Json(name = "estimated_cost_usd") val estimatedCostUsd: Double = 0.0,
    @Json(name = "suppressed_numbers") val suppressedNumbers: Int = 0,
    @Json(name = "delivery_rate") val deliveryRate: Double = 0.0,   // 0..100
    @Json(name = "failure_rate") val failureRate: Double = 0.0,     // 0..100
    @Json(name = "period_days") val periodDays: Int = 7,
)
@JsonClass(generateAdapter = true)
data class DeliveryItemDto(
    @Json(name = "to_email") val toEmail: String? = null,  // email channel
    val phone: String? = null,                             // sms channel
    val subject: String? = null,
    val status: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null, // EPOCH SECONDS, not ISO string
    @Json(name = "bounce_type") val bounceType: String? = null,
    @Json(name = "diagnostic_code") val diagnosticCode: String? = null,
    val error: String? = null,
    val segments: Int? = null,
)
@JsonClass(generateAdapter = true)
data class DeliveryListDto(
    val items: List<DeliveryItemDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,  // NOT `next`
)
```

Note the field-name corrections vs the original draft: `total_sent`→`sent`/`total`,
removed nonexistent `pending`/`provider`/`window` from stats; rates are percentages 0-100;
activity recipient is `to_email`/`phone` (not `recipient`), `created_at` is an epoch-seconds
number (the mapper does `Instant.ofEpochSecond(createdAt)` — not ISO parse), there is no
`id` field (use list index or `to_email+created_at` as a stable key), and the page cursor
field is `next_cursor` (not `next`). All these endpoints declare `422:HTTPValidationError`
for bad params.

Error body follows the FastAPI `detail` convention and is decoded by the shared mapper:
`detail` may be a string, `[{msg}]`, or `{code,...}`. Verified in `src/api/client.ts`
(`normalizeErrorDetail`): a `403` with `detail.code` of `role_required` /
`role_required_admin_profile_type` / `role_required_scope` is a permission failure → surface
AND-403's not-authorized state, not a generic error. Bad query params yield `422` with a
`detail: [{msg,...}]` array.

## 6. Data & State Management

- ViewModels expose `StateFlow<DashboardUiState>` + `StateFlow<Boolean>` for refresh; UI
  collects with `collectAsStateWithLifecycle()`.
- **Cache:** Room tables `admin_email_dashboard` and `admin_sms_dashboard` (one summary row
  + activity rows keyed by channel) with a `fetched_at` epoch column. Repository policy:
  on `load` serve cache immediately if fresh (TTL ~60s) else fetch; on `forceRefresh`
  always fetch. On network failure with a cached row present, emit
  `Content(stale = true)`; with no cache, emit `Error`.
- Activity timestamps: the backend `created_at` is **epoch seconds (a number)**, not an ISO
  string (verified: `MessagingDeliveryItem.created_at: number`; the web does
  `new Date(ts * 1000)`). Map with `Instant.ofEpochSecond(createdAt)`; render via a shared
  relative-time formatter in `core-ui` (e.g. "3 min ago"), locale-aware.
- Recipient masking is computed in the mapper (not stored unmasked in Room beyond what the
  backend already returns — see §8). Masking helper: `String.maskEmail()` / `String.maskPhone()`
  in `core-ui` (or `core-model`).
- No DataStore writes for this ticket; admin role/session state is owned by AND-403/AND-027.

## 7. Error Handling & Resilience

- All calls are idempotent GETs → eligible for `core-network` bounded backoff retry
  (≤2 retries, jittered, ~20s overall budget) for transient `IOException`/5xx. No retry on
  4xx.
- Timeouts: rely on the shared OkHttp ~20s call timeout configured for the unreliable dev
  host.
- `401`: handled by the shared interceptor (single `POST /ui/session/refresh` then one
  retry); if still 401, emit `Error("Session expired", canRetry = true)`.
- `403`: emit the AND-403 not-authorized terminal state (no Retry that re-hammers).
- Network/offline with cache → `Content(stale = true)` plus a top banner "Showing cached
  data · last updated {relativeTime}". Without cache → `Error` with Retry.
- Partial fan-out failure (summary OK, activity fails or vice-versa): show the part that
  succeeded and a non-blocking inline notice for the failed part; do not blank the whole
  screen.
- Empty deterministic mapping: summary present but all-zero AND activity empty → `Empty`
  with a "No delivery activity in this window" message.

## 8. Security & Privacy

- Read-only by construction: the feature module exposes no mutating endpoints; reviewers
  verify no `POST/PUT/PATCH/DELETE` calls exist in `feature-admin-dashboards`.
- Role gating via AND-403 `AdminGate`; network calls are not issued for non-admins.
- **PII minimization:** recipient email/phone are masked before display and not logged.
  **Verified on review:** the backend returns FULL unmasked PII — `to_email` / `phone` in
  `MessagingDeliveryItem` (and the web app renders them unmasked). Therefore the Android app
  MUST mask in the mapper and SHOULD persist only the masked form in Room (do not cache full
  addresses) to minimize PII at rest. No PII in telemetry, crash reports, or logcat.
- All traffic is plaintext HTTP **only** because the dev host requires it; production must
  use HTTPS. Network security config keeps cleartext permitted solely for the dev host
  domain/IP (inherited from AND-027), not app-wide.
- CSRF token handled by the shared client; never rendered or logged.

## 9. Accessibility & i18n

- All strings in `strings.xml` (e.g. `admin_email_dashboard_title`,
  `admin_dashboard_metric_delivered`, `admin_dashboard_stale_banner`); no hardcoded copy.
- Metric cards: each card has a combined `contentDescription` ("Delivered: 12,111, 94.3
  percent") so TalkBack reads label+value together; decorative icons marked
  `contentDescription = null`.
- Touch targets ≥ 48dp; pull-to-refresh has an accessible refresh action alternative (the
  Retry/refresh affordance is focusable).
- Numbers and percentages formatted with `NumberFormat`/locale; timestamps localized.
- Dynamic type and dark theme via Material 3 theme from `core-ui`; metric grid reflows at
  large font scales (FlowRow, no fixed-height clipping).
- Status colors (delivered/bounced/failed) paired with a text label and shape/icon — never
  color alone — to satisfy color-contrast and color-blind requirements.

## 10. Telemetry & Logging

- Screen-view events: `admin_email_dashboard_view`, `admin_sms_dashboard_view`.
- Action events: `admin_dashboard_refresh` (props: `channel`, `trigger=pull|retry`),
  `admin_dashboard_load_result` (props: `channel`, `outcome=content|empty|error|stale`,
  `latency_ms`, `http_status` for errors, `error_code`).
- Events route through the shared analytics abstraction in `core-data`/`core-ui`; **no PII**
  (no recipients, no message ids) in any property.
- Logging via the shared `Timber`-style logger at DEBUG for request lifecycle; bodies are
  not logged. Production builds strip verbose network logging (OkHttp logging interceptor
  level gated by `BuildConfig.DEBUG`).

## 11. Testing Strategy

Unit (JUnit + Turbine + `core-testing`):
- `DashboardViewModelTest`: emits `Loading → Content` on success; `Loading → Empty` on
  empty; `Loading → Error` on failure with no cache; `Content(stale=true)` when offline
  with cache; `refresh()` toggles `refreshing` and re-fetches; channel parameter selects
  email vs SMS endpoints.
- Mapper tests: DTO→`DashboardUiData` including null-field handling, delivery-rate
  formatting, and masking (`maskEmail`, `maskPhone`) edge cases.
- `FastAPI detail` mapping reuse test for 403 vs generic error.

Repository (MockWebServer in `core-testing`):
- Summary+activity fan-out merge; partial-failure path; retry on 5xx for GET; no retry on
  4xx; cache TTL serve-then-refresh; 401→refresh→retry handled by shared client (asserted
  via enqueued sequence).

Compose UI (`createAndroidComposeRule`):
- Each state renders its testTag (`dashboard_loading`, `dashboard_content`,
  `dashboard_empty`, `dashboard_error`, `dashboard_stale_banner`).
- Pull-to-refresh triggers `refresh()`; Retry triggers reload.
- **Read-only assertion:** no node with mutating semantics/onClick performs a write; assert
  activity rows have no actionable click handler.
- Non-admin route shows not-authorized and issues no network call (verify MockWebServer
  received zero requests).

Accessibility test: metric cards expose merged contentDescription; targets ≥48dp.

## 12. Dependencies & Sequencing

- **Depends on AND-403** (read-only admin shell, `AdminGate`, admin nav landing, role
  state) — hard dependency. AND-403 in turn depends on AND-027 (core-network session/cookie
  jar + admin role plumbing), which this ticket consumes transitively.
- Sequencing: implement after AND-403 merges. Add the two list rows to the AND-403 admin
  landing screen and the two `composable` destinations to its nav graph.
- Module decision (resolve at kickoff): either add a `dashboards` package inside the
  existing `feature-admin` module from AND-403, or create `feature-admin-dashboards`. Prefer
  reusing `feature-admin` to share `AdminGate` and theming unless that module grows too
  large.
- Blocks: a future admin email/SMS **actions** ticket (re-send, suppression management) and
  an activity **detail** screen — both out of scope here.

## 13. Risks & Open Questions

- ~~Exact endpoint paths/shape unconfirmed.~~ **RESOLVED on review** (see §5/§16): real
  endpoints are `/ui/admin/{email,sms}/dashboard/stats?days=` (stats) and
  `/ui/admin/{email,sms}/deliveries?limit=` (activity). There is no combined document; fan
  out the two calls. The drafted `/dashboard/summary` and `/dashboard/activity` paths were
  wrong and have been corrected.
- ~~Does the backend return full recipient PII?~~ **RESOLVED:** it returns FULL unmasked
  `to_email`/`phone`; mask in the mapper and persist only masked form in Room (§8).
- ~~Time-window semantics.~~ **RESOLVED:** the param is integer `days` (default 7, max 365),
  not a `window`/`range` string. AND-404 sends `days=7` and does not expose a selector;
  user-selectable ranges remain a follow-up.
- Activity volume: if recent activity can be large, Paging 3 may be required; current
  assumption is a bounded recent slice (≤50).
- Dev host unreliability may cause frequent stale states in QA — ensure stale UX is clearly
  distinguishable from fresh.

## 14. Acceptance Criteria

AC1. An admin opening Admin → Email Dashboard and Admin → SMS Dashboard sees, on success,
metric cards (sent/delivered/bounced/failed/pending + delivery-rate %) and a recent-activity
list — satisfying the backlog "Dashboards render (read)."
AC2. Both screens are read-only: no mutating control exists; automated test asserts zero
write calls and inert activity rows.
AC3. Loading, Content, Empty, Error (with Retry), and offline stale-content states each
render correctly and are covered by tests.
AC4. Pull-to-refresh and Retry re-fetch the dashboard data.
AC5. A non-admin navigating to either route sees the AND-403 not-authorized state and no
dashboard network request is made.
AC6. Recipient PII is masked in the UI and never logged or sent to telemetry.
AC7. All GETs use the shared cookie/CSRF client with ~20s timeout and GET-only bounded
retry; 401 triggers a single refresh-and-retry; 403 maps to not-authorized.
AC8. All user-facing strings are in `strings.xml`; metric cards expose merged TalkBack
descriptions.

## 15. Definition of Done

- Both destinations implemented under `com.testlogon.android.feature.admin.dashboards`,
  wired into the AND-403 admin nav graph and landing screen, behind `AdminGate`.
- Endpoint paths/shapes confirmed against `/openapi.json` and the web reference; DTOs +
  mapper + repository + Room cache implemented.
- Unit, repository (MockWebServer), and Compose UI tests pass in CI; read-only and
  no-network-for-non-admin assertions included; meaningful coverage of all five UI states.
- Lint/detekt/ktlint clean; no hardcoded strings; no PII in logs/telemetry (verified).
- `./gradlew :feature-admin*:test :app:assembleDebug` green on JDK 17 / AGP 8.7.3.
- Telemetry events emit with documented props and no PII.
- Manual QA on the dev backend: success, empty, error/offline (stale), and non-admin paths
  verified; screenshots attached to the PR.
- PR reviewed and merged to `android-port`; spec status moved from draft.

## 16. Citations & Assumption Audit

Each key technical claim, its VERDICT, and an exact source pointer. "OpenAPI index" =
`reference/openapi.index.txt`; "OpenAPI spec" = `reference/openapi.pretty.json`
(`components.schemas.<Name>`); frontend paths are under `reference/src/`.

1. **Email stats endpoint is `GET /ui/admin/email/dashboard/stats` with `days` param** —
   Corrected (draft said `/dashboard/summary`). Source: OpenAPI index line 665
   `GET /ui/admin/email/dashboard/stats | ... | resp=200:EmailDashboardStatsOut | params=days`;
   `src/api/endpoints/adminMessagingDashboards.ts: getEmailDashboardStats`.
2. **SMS stats endpoint is `GET /ui/admin/sms/dashboard/stats` with `days` param** —
   Corrected (draft said `/dashboard/summary`). Source: OpenAPI index line 754
   `... resp=200:SmsDashboardStatsOut | params=days`;
   `src/api/endpoints/adminMessagingDashboards.ts: getSmsDashboardStats`.
3. **`/dashboard/summary` and `/dashboard/activity` do NOT exist** — Corrected
   (fabricated in draft). Source: grep of OpenAPI index for `dashboard` (lines 662-768) shows
   no such paths; the only email/sms `/dashboard/*` ops are `stats`, `timeseries`,
   `bounce-domains` (email), `failure-types` (sms).
4. **"Activity" maps to `GET /ui/admin/{email,sms}/deliveries?limit=&cursor=&status=`** —
   Corrected (draft used `/dashboard/activity`). Source: OpenAPI index lines 667 & 756
   `GET /ui/admin/email/deliveries | ... | params=limit,cursor,status`;
   `src/api/endpoints/adminMessagingDashboards.ts: getEmailDeliveries / getSmsDeliveries`.
5. **EmailDashboardStatsOut fields = sent, delivered, bounced, complained, failed,
   suppressed, total, delivery_rate, bounce_rate, complaint_rate, period_days** — Corrected
   (draft had `total_sent`, `pending`, `provider`, `window`). Source: OpenAPI spec
   `EmailDashboardStatsOut` (lines 31186-31254); `src/api/types.ts: EmailDashboardStats`.
6. **SmsDashboardStatsOut fields = sent, delivered, failed, total, total_segments,
   estimated_cost_usd, suppressed_numbers, delivery_rate, failure_rate, period_days (no
   `bounced`)** — Corrected. Source: OpenAPI spec `SmsDashboardStatsOut` (lines 67981-68042);
   `src/api/types.ts: SmsDashboardStats`.
7. **Rate fields are percentages 0-100, not 0..1 fractions** — Corrected (draft used
   `"delivery_rate": 0.943`). Source: OpenAPI spec `delivery_rate`/`bounce_rate` carry
   `minimum:0, maximum:100`; web renders `${s.delivery_rate}%` in
   `src/pages/admin/EmailDashboardPanel.tsx` (KpiCard `Delivery Rate`).
8. **Delivery item recipient field is `to_email` (email) / `phone` (sms), not `recipient`** —
   Corrected. Source: `src/api/types.ts: MessagingDeliveryItem`;
   `src/pages/admin/EmailDashboardPanel.tsx` renders `b.to_email`.
9. **Delivery item `created_at` is epoch SECONDS (number), not an ISO-8601 string** —
   Corrected. Source: `src/api/types.ts: MessagingDeliveryItem.created_at?: number`;
   `EmailDashboardPanel.tsx: fmtTs` does `new Date(ts * 1000)`.
10. **Delivery items have NO `id` and NO `provider` field** — Corrected (draft had both).
    Source: `src/api/types.ts: MessagingDeliveryItem` (fields: to_email, phone, subject,
    status, created_at, bounce_type, diagnostic_code, complaint_feedback_type, error,
    segments).
11. **Delivery list wrapper field is `next_cursor`, not `next`** — Corrected. Source:
    `src/api/types.ts: MessagingDeliveryList { items, next_cursor }`.
12. **Auth = cookie-based, `ui_csrf` cookie echoed as `X-CSRF-Token`** — Verified. Source:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
13. **401 → single `POST /ui/session/refresh` then one retry** — Verified. Source:
    `src/api/client.ts: refreshSession` + the 401 branch (refreshes once via shared
    `refreshPromise`, retries the original request once); OpenAPI index line 1847
    `POST /ui/session/refresh`.
14. **Web client also sends a Bearer `Authorization` header (not cookies alone)** — Verified
    (draft implied cookies+CSRF only). Source: `src/api/client.ts` (`Authorization: Bearer
    ${accessToken}` from auth store).
15. **403 with `detail.code` of `role_required*` is a permission failure → not-authorized
    state** — Verified. Source: `src/api/client.ts: mapAuthorizationError` (`role_required`,
    `role_required_admin_profile_type`, `role_required_scope`).
16. **FastAPI `detail` may be string | `[{msg}]` | `{code,...}`; 422 for bad params** —
    Verified. Source: `src/api/client.ts: normalizeErrorDetail`; OpenAPI index shows
    `422:HTTPValidationError` on every dashboard/deliveries op (lines 664-667, 753-756).
17. **`days` param: default 7, min 1, max 365** — Verified. Source: OpenAPI spec
    `EmailDashboardStatsOut.period_days` / `SmsDashboardStatsOut.period_days`
    (`default:7, minimum:1, maximum:365`); `adminMessagingDashboards.ts` defaults `days = 7`.
18. **Backend returns FULL unmasked recipient PII** — Verified. Source: `MessagingDeliveryItem`
    exposes raw `to_email`/`phone`, and `EmailDashboardPanel.tsx` renders them unmasked → the
    Android client must mask client-side.
19. **Frontend endpoint module is `adminMessagingDashboards.ts`, not `admin.ts`** —
    Corrected. Source: file `src/api/endpoints/adminMessagingDashboards.ts` exists; no
    `admin.ts` for these calls.
20. **Read-only is an Android-side scoping decision, not mirrored by the web app** —
    Verified context. The web `EmailDashboardPanel.tsx`/`SmsDashboardPanel.tsx` DO expose
    mutations (add/remove suppression, send-test SMS via `POST /ui/admin/sms/send-test`,
    `POST/DELETE /ui/admin/{email,sms}/suppressed`). AND-404 deliberately omits all of these
    (FR5/AC2). Source: `adminMessagingDashboards.ts` (`addEmailSuppression`,
    `removeEmailSuppression`, `sendTestSms`); OpenAPI index lines 672-673, 759, 762-765.
21. **Material 3 `PullToRefreshBox` for pull-to-refresh** — Unverified-assumption (framework
    ref): a reasonable Compose Material 3 choice; not verifiable from backend/frontend
    sources. framework ref: developer.android.com/jetpack/androidx/releases/compose-material3.
22. **Bounded GET retry / ~20s OkHttp timeout / cookie jar live in `core-network` (AND-027)**
    — Unverified-assumption: established by AND-027/AND-403, which are not in these reference
    sources. Confirm against the AND-027 spec / `core-network` implementation at build time.

### Corrections made

- §2: frontend endpoint file `admin.ts` → `adminMessagingDashboards.ts`; added auth nuance
  that a Bearer header accompanies cookies+CSRF.
- §5: replaced the fabricated `/dashboard/summary` + `/dashboard/activity` contract with the
  real `/dashboard/stats` (param `days`) + `/deliveries` (param `limit`) endpoints; rewrote
  all DTOs to the real schemas — stats fields (`sent`/`total`, no `pending`/`provider`/
  `window`), rates as percentages 0-100, SMS-specific fields, delivery item `to_email`/`phone`
  + epoch-seconds `created_at`, no `id`/`provider`, and `next_cursor` (not `next`).
- §3 FR7: param corrected from `range`/`window` string to integer `days`.
- §4: `ActivityRow` corrected — no `id` (use derived key), no `provider` (use subject/error
  detail), `created_at` is epoch seconds; cursor field is `next_cursor`.
- §6: timestamp mapping corrected to `Instant.ofEpochSecond(created_at)` (was ISO parse).
- §8 & §13: PII question resolved — backend returns full unmasked PII; mask in mapper and
  persist masked-only in Room. Endpoint/time-window open questions resolved.

### Open assumptions

- Pull-to-refresh via Material 3 `PullToRefreshBox`, Hilt assisted-inject ViewModel, Room
  cache + 60s TTL, and the relative-time/masking helpers in `core-ui` are framework/design
  choices not derivable from the reference sources (claim 21). Validate against the actual
  `core-ui`/`core-network` modules.
- AND-027/AND-403 behavior (shared OkHttp client, cookie jar, ~20s timeout, bounded GET
  retry, `AdminGate`, admin role state) is consumed transitively and is NOT verifiable from
  the OpenAPI/frontend sources here (claim 22). Confirm at integration time.
- The `Empty` mapping (stats all-zero AND deliveries empty → Empty) is a client design
  decision; the backend returns 200 with zeroed fields regardless, so the client must derive
  emptiness — no backend "empty" signal exists.
- `status` enum values from `/deliveries` are free-form lowercase strings in the sources
  (e.g. "delivered"); the exact closed set is not enumerated in the schemas (delivery item is
  an open `[key: string]: unknown` map), so `DeliveryStatus.UNKNOWN` fallback is required.

## 17. Test Plan

Test targets: **JVM** = local JUnit/Robolectric (no device); **emu35** = headless emulator
AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial
R5CX821TA9R, API 34, arm64-v8a). This ticket is networked-Compose UI with no
camera/biometric/WebRTC/Telecom/push hardware dependency, so most cases run on JVM or emu35;
A15 is used only for the arm64/API-34 ABI smoke and a real-flaky-network behavior pass.

- **TC-AND-404-01** — Type: unit (JVM). Target: `DashboardViewModelTest`. Preconditions:
  repository fake returns `Success(non-empty DashboardUiData)` for EMAIL. Steps: construct VM
  with `channel=EMAIL`; collect `state` via Turbine. Expected: emits `Loading` → `Content`
  with metric cards (sent/delivered/bounced/failed/delivery-rate) and a non-empty activity
  list; `refreshing` stays false. Traces: AC1, AC3.
- **TC-AND-404-02** — Type: unit (JVM). Target: `DashboardViewModelTest`. Preconditions:
  repository returns `Success` with all-zero stats AND empty deliveries. Steps: load EMAIL.
  Expected: `Loading` → `Empty`. Traces: AC3.
- **TC-AND-404-03** — Type: unit (JVM). Target: `DashboardViewModelTest`. Preconditions:
  repository returns `Error(detail)` with no cache. Steps: load SMS. Expected: `Loading` →
  `Error(message, canRetry=true)`. Traces: AC3.
- **TC-AND-404-04** — Type: unit (JVM). Target: `DashboardViewModelTest`. Preconditions:
  cache present; network throws `IOException` (offline). Steps: load EMAIL. Expected:
  `Content(stale=true)` emitted; stale banner data present. Traces: AC3, AC7.
- **TC-AND-404-05** — Type: unit (JVM). Target: `DashboardViewModelTest`. Steps: call
  `refresh()`. Expected: `refreshing` toggles true→false; repository called with
  `forceRefresh=true`; data re-emitted. Traces: AC4.
- **TC-AND-404-06** — Type: unit (JVM). Target: `DashboardMapperTest`. Preconditions: raw
  `EmailStatsDto` with `delivery_rate=94.3` and `SmsStatsDto` with `failure_rate=5.0`. Steps:
  map to `DashboardUiData`. Expected: rates treated as percentages (rendered "94.3%", not
  "9430%"); SMS shows failed/failure-rate/segments and NO bounced card; null/absent numeric
  fields default to 0. Traces: AC1.
- **TC-AND-404-07** — Type: unit (JVM). Target: `DashboardMapperTest` (masking +
  timestamp). Preconditions: delivery item `to_email="jane@example.com"`,
  `created_at=1749132131`; an SMS item `phone="+15551234821"`. Steps: map. Expected:
  `maskEmail`→`j***@e***.com`, `maskPhone`→masked tail; timestamp built via
  `Instant.ofEpochSecond(1749132131)` (NOT ISO parse, NOT ms); no `id`/`provider` referenced.
  Edge cases: null recipient → safe placeholder; malformed status → `UNKNOWN`. Traces: AC6.
- **TC-AND-404-08** — Type: contract/MockWebServer (JVM). Target: `AdminDashboardRepository`
  fan-out. Preconditions: MockWebServer enqueues 200 `EmailDashboardStatsOut` JSON for
  `/ui/admin/email/dashboard/stats?days=7` and 200 `MessagingDeliveryList` for
  `/ui/admin/email/deliveries?limit=50`. Steps: call `dashboard(EMAIL, force=false)`. Expected:
  exactly two GET requests to those paths with those query params; merged `Success`
  `DashboardUiData`; assert request paths/methods match the corrected §5 contract. Traces: AC1.
- **TC-AND-404-09** — Type: contract/MockWebServer (JVM). Target: repository partial-failure.
  Preconditions: stats returns 200, deliveries returns 500. Steps: load. Expected: the
  succeeded part (metrics) is shown with a non-blocking inline notice for the failed activity
  part; whole screen is not blanked; GET 5xx is retried per the bounded policy then surfaces
  the partial result. Traces: AC3, AC7.
- **TC-AND-404-10** — Type: contract/MockWebServer (JVM). Target: repository error mapping.
  Preconditions: enqueue 403 with body `{"detail":{"code":"role_required"}}`. Steps: load.
  Expected: result maps to the not-authorized terminal state (not a generic Error/Retry that
  re-hammers); also enqueue a 422 `HTTPValidationError` `{"detail":[{"msg":...}]}` and assert
  it maps to a readable Error message. No retry on 4xx. Traces: AC7.
- **TC-AND-404-11** — Type: Compose-UI (emu35). Target: `DashboardScreenScaffold` /
  `EmailDashboardScreen`. Preconditions: VM driven through each state. Steps: assert testTags
  `dashboard_loading`, `dashboard_content`, `dashboard_empty`, `dashboard_error`,
  `dashboard_stale_banner` render for their respective states. Expected: each state's node is
  displayed. Traces: AC3.
- **TC-AND-404-12** — Type: Compose-UI (emu35). Target: refresh/retry interactions.
  Steps: pull-to-refresh gesture on `PullToRefreshBox`; tap Retry in error state. Expected:
  each invokes the VM (`refresh()` / reload); MockWebServer-backed repo sees re-fetch. Traces:
  AC4.
- **TC-AND-404-13** — Type: Compose-UI (emu35). Target: read-only enforcement. Steps: render
  `Content` with activity rows; query the semantics tree. Expected: no node exposes an
  `OnClick`/mutating action on activity rows; no POST/PUT/PATCH/DELETE-bound control exists;
  static check/assert that `feature-admin-dashboards` issues no mutating call. Traces: AC2.
- **TC-AND-404-14** — Type: instrumented (emu35). Target: non-admin gating. Preconditions:
  role state = non-admin; MockWebServer recording. Steps: navigate to `admin/email-dashboard`
  and `admin/sms-dashboard`. Expected: AND-403 not-authorized state renders; MockWebServer
  received **zero** requests to stats/deliveries. Traces: AC5.
- **TC-AND-404-15** — Type: Compose-UI accessibility (emu35). Target: metric cards + targets.
  Steps: inspect semantics. Expected: each metric card exposes one merged `contentDescription`
  combining label+value (e.g. "Delivered: 12,111, 94.3 percent"); decorative icons have null
  contentDescription; touch targets ≥48dp; status conveyed by text/shape not color alone.
  Traces: AC8.
- **TC-AND-404-16** — Type: instrumented/e2e (emu35). Target: PII-not-logged. Preconditions:
  capture logcat + a stub analytics sink during a full load. Steps: load a dashboard with PII
  deliveries; refresh. Expected: no raw `to_email`/`phone` and no message identifiers appear in
  logcat, crash metadata, or any telemetry property; only masked values reach the UI. Traces:
  AC6.
- **TC-AND-404-17** — Type: integration / flaky-network (A15 — physical device REQUIRED).
  Target: real dev-host (`http://18.222.237.167:8000`) behavior over real cellular/Wi-Fi with
  the unreliable host. Steps: load both dashboards; toggle airplane mode mid-refresh; restore.
  Expected: offline → `Content(stale=true)` with "Showing cached data" banner when cache
  exists, else `Error` + Retry; on reconnect, Retry/pull yields fresh `Content`; ~20s timeout
  honored without ANR. MUST run on A15 to exercise true network loss/latency (emulator network
  is too synthetic for the flaky-host path). Traces: AC3, AC4, AC7.
- **TC-AND-404-18** — Type: instrumented smoke (A15 — physical device REQUIRED for ABI).
  Target: arm64-v8a / API 34 vs emulator x86_64 / API 35. Steps: install debug build on A15;
  open both dashboards against MockWebServer or dev host; verify happy path + masking +
  timestamp formatting. Expected: parity with emu35 results; no arm64/API-34-specific crash
  (e.g. `java.time` formatting/locale). Traces: AC1, AC6. MUST run on A15.

### Coverage matrix

| AC  | Covered by |
|-----|------------|
| AC1 | TC-01, TC-06, TC-08, TC-18 |
| AC2 | TC-13 |
| AC3 | TC-01, TC-02, TC-03, TC-04, TC-09, TC-11, TC-17 |
| AC4 | TC-05, TC-12, TC-17 |
| AC5 | TC-14 |
| AC6 | TC-07, TC-16, TC-18 |
| AC7 | TC-04, TC-09, TC-10, TC-17 |
| AC8 | TC-15 |
