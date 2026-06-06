---
id: AND-404
title: Admin email/SMS dashboards (read)
milestone: M8
epic: E53
priority: P2
size: M
status: draft
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
  `frontend/src/api/endpoints/admin.ts` (mirror its query params and response field names),
  shared types in `frontend/src/api/types.ts`.
- Auth is cookie-based with a `ui_csrf` cookie echoed as `X-CSRF-Token`; the shared OkHttp
  client (from `core-network`, established in AND-027 and used by AND-403) owns the
  persistent cookie jar and the single-shot `POST /ui/session/refresh` retry on 401. This
  ticket performs only idempotent GETs and inherits that behavior unchanged.
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

FR7. Time-range selector is **out of scope** unless the backend defaults provide a single
window; if the endpoint accepts an optional `range`/`window` param it defaults to the
backend default and is not user-selectable in this ticket.

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
    val id: String,
    val maskedRecipient: String,   // e.g. "j***@e***.com" / "+1 *** *** 4821"
    val status: DeliveryStatus,    // DELIVERED, BOUNCED, FAILED, PENDING, SENT, UNKNOWN
    val provider: String?,         // "ses", "twilio", etc.
    val timestamp: Instant,
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
bounded recent slice, typically ≤ 50); if the endpoint returns a `next` cursor it is
ignored and a "showing recent N" footer is shown. Promote to Paging 3 in a follow-up if
needed.

## 5. API Contract

All endpoints are idempotent GETs under the admin namespace; exact paths and field names
must be confirmed against `/openapi.json` and `frontend/src/api/endpoints/admin.ts` during
implementation. Expected shape based on the web reference:

```
GET /ui/admin/email/dashboard/summary
GET /ui/admin/email/dashboard/activity?limit=50
GET /ui/admin/sms/dashboard/summary
GET /ui/admin/sms/dashboard/activity?limit=50
```

If the backend exposes a single combined `/ui/admin/{email|sms}/dashboard` document, the
repository issues one call and splits it client-side; otherwise it fans out summary +
activity concurrently with `async`/`awaitAll` and merges. Headers: cookies + `X-CSRF-Token`
(injected by the shared OkHttp interceptor; not set per-call here).

Representative responses (Moshi DTOs):

```jsonc
// summary
{
  "total_sent": 12840,
  "delivered": 12111,
  "bounced": 412,
  "failed": 96,
  "pending": 221,
  "delivery_rate": 0.943,
  "provider": "ses",
  "window": "24h"
}
```

```jsonc
// activity
{
  "items": [
    { "id": "msg_01H...", "recipient": "jane@example.com", "status": "delivered",
      "provider": "ses", "created_at": "2026-06-05T14:02:11Z" }
  ],
  "next": null
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class EmailSummaryDto(
    @Json(name = "total_sent") val totalSent: Int?,
    val delivered: Int?, val bounced: Int?, val failed: Int?, val pending: Int?,
    @Json(name = "delivery_rate") val deliveryRate: Double?,
    val provider: String?, val window: String?,
)
@JsonClass(generateAdapter = true)
data class ActivityItemDto(
    val id: String, val recipient: String?, val status: String?,
    val provider: String?, @Json(name = "created_at") val createdAt: String?,
)
@JsonClass(generateAdapter = true)
data class ActivityPageDto(val items: List<ActivityItemDto> = emptyList(), val next: String? = null)
```

Error body follows the FastAPI `detail` convention and is decoded by the shared mapper:
`detail` may be a string, `[{msg}]`, or `{code,...}`. A `403` here means lost/insufficient
admin role → surface AND-403's not-authorized state, not a generic error.

## 6. Data & State Management

- ViewModels expose `StateFlow<DashboardUiState>` + `StateFlow<Boolean>` for refresh; UI
  collects with `collectAsStateWithLifecycle()`.
- **Cache:** Room tables `admin_email_dashboard` and `admin_sms_dashboard` (one summary row
  + activity rows keyed by channel) with a `fetched_at` epoch column. Repository policy:
  on `load` serve cache immediately if fresh (TTL ~60s) else fetch; on `forceRefresh`
  always fetch. On network failure with a cached row present, emit
  `Content(stale = true)`; with no cache, emit `Error`.
- Activity timestamps parsed to `java.time.Instant`; rendered via a shared relative-time
  formatter in `core-ui` (e.g. "3 min ago"), locale-aware.
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
  Cached recipient values stay only in app-private Room storage; consider storing only the
  masked form if the backend already returns full PII (decide during implementation — see
  §13). No PII in telemetry, crash reports, or logcat.
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

- Exact endpoint paths/shape unconfirmed: backlog says `/ui/admin/email|sms/dashboard/*`.
  Verify against `/openapi.json` and `frontend/src/api/endpoints/admin.ts`; combined-vs-split
  (summary/activity) layout affects §5 fan-out. **Action: confirm before coding.**
- Does the backend return full recipient PII or already-masked values? Affects whether Room
  may persist full addresses (§8). **Open question for backend owner.**
- Time-window semantics: is there a fixed default window or a required `window`/`range`
  param? If user-selectable ranges are needed, that is a follow-up ticket.
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
