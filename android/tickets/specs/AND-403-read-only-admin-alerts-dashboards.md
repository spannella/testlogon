---
id: AND-403
title: Read-only admin alerts/dashboards
milestone: M8
epic: E53
priority: P2
size: M
status: draft
depends_on: [AND-027]
blocks: []
---

# AND-403 — Read-only admin alerts/dashboards

## 1. Overview & Goal

Provide an authenticated **admin** user with a strictly **read-only** view of
operational alerts and summary metrics for the TestLogon backend, surfaced inside
the Android app as a role-gated screen. The screen renders server-provided alerts
(active/recent notifications about backend health, auth anomalies, rate-limit
events, etc.) and a small set of dashboard metric tiles. It performs **no
mutations** — there is no acknowledge, dismiss, resolve, or configuration action
in this ticket. Every interaction is a `GET` read.

Scope is deliberately narrow: this ticket delivers (a) role gating so only users
whose `GET /ui/me` profile carries an admin role can reach or render the screen,
(b) a `feature-admin` screen that lists alerts and metric tiles fetched over the
existing authenticated cookie/CSRF network stack, and (c) graceful
loading/empty/error/offline/forbidden states. Non-admin users must never see the
data and must not be able to navigate to the route.

Success means: an admin sees current read-only alerts and metric tiles loaded
from the admin read endpoints; a non-admin (or unauthenticated) user is denied at
both the navigation and data layers; no write/mutation affordance exists; and all
gating and rendering behaviors are covered by deterministic tests (MockWebServer +
ViewModel unit + Compose UI).

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- New feature module: **`feature-admin`** → consumes `core-network`,
  `core-model`, `core-data`, `core-ui`, `core-testing`. Layering: `app →
  feature-admin → core-*`.
- **AND-027** owns `AuthApi` (session/finalize/refresh/logout, `me`,
  `sessions(+revoke)`) and the wired cookie jar + CSRF interceptor + 401-refresh
  authenticator chain. This ticket introduces a **separate** `AdminApi` for the
  admin read endpoints and **reuses** AND-027's `OkHttpClient`/`Retrofit`
  configuration; it does not redefine auth/session methods.
- Auth is cookie-based: requests carry session cookies + `X-CSRF-Token` echoed
  from the `ui_csrf` cookie. On `401` the OkHttp authenticator performs
  `POST /ui/session/refresh` once and retries (transparent to this ticket). Admin
  reads are idempotent `GET`s and are therefore eligible for the bounded-backoff
  retry policy for idempotent GETs (from the E04 network tickets).
- Role information comes from the current user profile (`GET /ui/me`). The admin
  role flag (e.g. `is_admin` / `roles[]` containing `"admin"`) MUST be confirmed
  against `/openapi.json`; see §13 Q1.
- Dev backend `http://18.222.237.167:8000` is plaintext HTTP and unreliable:
  ~20s timeouts, offline/stale UI states, bounded retry for GETs only.
- Web reference: `frontend/src/api/endpoints/*.ts` and `frontend/src/api/types.ts`
  for the admin alerts/metrics shapes; verify exact field names and the exact
  admin paths against `/openapi.json` at build time. The shapes below are the
  contract this ticket implements.

## 3. Functional Requirements

FR-1. The Admin entry point (route + any nav affordance) is visible **only** when
the current authenticated user has the admin role, derived from the auth state
store / `GET /ui/me`. Non-admins never see the entry.

FR-2. On entering the screen the app fetches alerts and metrics, showing a loading
state, then a combined dashboard: a metrics section (tiles) followed by an alerts
list.

FR-3. Each alert row shows: severity (info/warning/critical), title/message,
source/category, and a relative timestamp (e.g. "5 minutes ago"). Severity is
visually encoded (icon + Material 3 color) and exposed to accessibility.

FR-4. Metric tiles each show a label and a value (and optional unit/trend text if
present); tiles render in a wrap/grid that adapts to width.

FR-5. The screen is **read-only**: no acknowledge/dismiss/resolve/edit/delete
controls render anywhere. The only actions are Refresh (re-read) and Back.

FR-6. Pull-to-refresh (and an explicit Retry on error) re-fetch both alerts and
metrics. Refresh replaces the in-memory data; server is source of truth.

FR-7. Empty state: zero alerts shows an explicit "No active alerts" message; the
metrics section still renders if metrics are present.

FR-8. If the backend returns `403` (caller is not authorized for admin reads,
e.g. role changed server-side), the screen shows a non-destructive "You don't
have access to admin alerts" state and offers Back — it does not crash or loop.

FR-9. Errors (network/offline, 401-after-refresh-failure, 5xx, timeout) surface a
retryable message; the last successfully loaded data, if any, is retained and
marked stale rather than blanked.

FR-10. Alerts are sorted severity-desc then time-desc by the mapper (critical and
most-recent first); ordering is deterministic and unit-tested.

## 4. Technical Design

Module: `feature-admin`. MVVM with Hilt, `StateFlow<UiState>`.

Domain models (`core-model`):

```kotlin
enum class AlertSeverity { CRITICAL, WARNING, INFO, UNKNOWN }

data class AdminAlert(
    val id: String,
    val severity: AlertSeverity,
    val title: String,
    val message: String?,
    val source: String?,        // category/component, e.g. "auth", "rate_limit"
    val createdAt: Instant,
)

data class AdminMetric(
    val key: String,            // stable id, e.g. "active_sessions"
    val label: String,          // display label
    val value: String,          // pre-formatted display value
    val unit: String? = null,
    val trend: String? = null,  // optional, e.g. "+3% 24h"
)

data class AdminDashboard(
    val alerts: List<AdminAlert>,
    val metrics: List<AdminMetric>,
)
```

Network (`core-network`) — a new read-only interface, distinct from `AuthApi`:

```kotlin
interface AdminApi {
    @GET("ui/admin/alerts")
    suspend fun getAlerts(): Response<AdminAlertListDto>

    @GET("ui/admin/metrics")
    suspend fun getMetrics(): Response<AdminMetricsDto>
}
```

`AdminApi` is provided via Hilt using the **same** `Retrofit` instance configured
in the E04/AND-027 chain (shared `OkHttpClient` with cookie jar, CSRF
interceptor, 401 authenticator, idempotent-GET backoff, ~20s timeouts):

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object AdminNetworkModule {
    @Provides @Singleton
    fun provideAdminApi(retrofit: Retrofit): AdminApi = retrofit.create(AdminApi::class.java)
}
```

Repository (`core-data`) maps DTO → domain + `ApiResult<T>` (AND-018) and applies
ordering:

```kotlin
class AdminRepository @Inject constructor(
    private val adminApi: AdminApi,
    private val authStateStore: AuthStateStore, // role/profile source (AND-029 chain)
    private val dispatchers: AppDispatchers,
) {
    /** Loads alerts + metrics concurrently; either sub-call failing fails the result. */
    suspend fun loadDashboard(): ApiResult<AdminDashboard>

    /** Convenience role check read from cached profile. */
    fun isAdmin(): Boolean
}
```

ViewModel:

```kotlin
@HiltViewModel
class AdminDashboardViewModel @Inject constructor(
    private val repo: AdminRepository,
) : ViewModel() {

    sealed interface UiState {
        data object Loading : UiState
        data class Content(
            val dashboard: AdminDashboard,
            val isRefreshing: Boolean = false,
            val isStale: Boolean = false,
            val error: UiError? = null, // transient error overlaid on existing content
        ) : UiState
        data object Empty : UiState              // loaded, no alerts and no metrics
        data object Forbidden : UiState          // 403 / not admin
        data class Error(val error: UiError) : UiState // first load failed, no data
    }

    private val _state = MutableStateFlow<UiState>(UiState.Loading)
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun load()      // initial + retry
    fun refresh()   // pull-to-refresh
    fun dismissTransientError()
}
```

Composables (Material 3, `core-ui` state composables from AND-021):

```kotlin
@Composable
fun AdminDashboardRoute(
    viewModel: AdminDashboardViewModel = hiltViewModel(),
    onBack: () -> Unit,
)

@Composable
fun AdminDashboardScreen(
    state: AdminDashboardViewModel.UiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onDismissError: () -> Unit,
    onBack: () -> Unit,
)
```

**Role gating (two layers):**

1. *Navigation layer.* The `adminDashboard` route is registered in the
   authenticated nav graph (AND-024), but the entry affordance and the route's
   composable are guarded by `authStateStore.isAdmin()`. A non-admin who somehow
   reaches the route (deep link) is redirected back / shown `Forbidden` rather
   than issuing admin requests.
2. *Data layer.* The ViewModel checks `repo.isAdmin()` before fetching; if false
   it emits `Forbidden` without a network call. The backend `403` is the final
   authority and also maps to `Forbidden` (defense in depth).

Alerts and metrics are fetched **concurrently** in the repository via
`coroutineScope { async { getAlerts() }; async { getMetrics() } }`. Both must
succeed for `Content`; a 403 on either maps to `Forbidden`. Mapper applies
severity-desc then `createdAt`-desc ordering and resolves unknown severity
strings to `AlertSeverity.UNKNOWN`.

## 5. API Contract

`GET /ui/admin/alerts` → 200:

```json
{
  "alerts": [
    {
      "id": "alrt_01HX...",
      "severity": "critical",
      "title": "Elevated auth failure rate",
      "message": "Failed logins exceeded threshold (120/min) for region us-east.",
      "source": "auth",
      "created_at": "2026-06-05T09:31:44Z"
    }
  ]
}
```

`GET /ui/admin/metrics` → 200:

```json
{
  "metrics": [
    { "key": "active_sessions", "label": "Active sessions", "value": "1,284", "unit": null, "trend": "+3% 24h" },
    { "key": "mfa_challenges_1h", "label": "MFA challenges (1h)", "value": "57" }
  ]
}
```

Error envelope (FastAPI `detail`, mapped per project convention — string |
`[{msg}]` | `{code,...}`, via AND-015):

```json
{ "detail": "Admin access required" }
{ "detail": [{ "msg": "Forbidden" }] }
{ "detail": { "code": "forbidden", "message": "..." } }
```

Status handling: `200` success; `401` → authenticator refresh-once-then-retry
(transparent), persistent 401 → `UiError(type=auth)` "Session expired", delegate
re-auth to the auth flow; `403` → `UiState.Forbidden`; `404` on an admin path →
treat as misconfigured endpoint → `UiError(type=server)` (and §13 Q2); `5xx` /
timeout → retryable `UiError(type=network|server)`, retain prior data if any.
All admin paths and field names (`severity` enum string set, role flag) MUST be
verified against `/openapi.json`; Moshi DTOs use `@Json(name=...)` for snake_case.
The exact admin paths are **placeholders pending `/openapi.json` confirmation**
(§13 Q2).

This ticket adds **no** write/mutation endpoints by design.

## 6. Data & State Management

- **No Room persistence.** Admin alerts/metrics are operational, time-sensitive,
  and authorization-scoped; they are fetched on demand and held only in
  `StateFlow` memory. No disk cache, no Paging (the read sets are small,
  bounded summaries; pagination is out of scope — see §13 Q3).
- Role flag is read from the existing auth state store (`AuthStateStore`,
  DataStore-backed, populated by the `getMe` chain). This ticket only **reads**
  the role; it does not write auth state.
- `loadDashboard()` returns a single `AdminDashboard` aggregating two concurrent
  GETs. Refresh fully replaces the in-memory dashboard (server is source of
  truth). On refresh failure, the previous `Content` is retained with
  `isStale = true` and a transient `error`.
- Sorting/derivation lives in the mapper, not the UI: alerts arrive pre-sorted
  (severity desc, then time desc); metrics preserve server order.
- State transitions: `Loading → Content | Empty | Forbidden | Error`. From
  `Content`, refresh sets `isRefreshing = true`; success → fresh `Content`;
  failure → same `Content` with `isStale`, `error` set.

## 7. Error Handling & Resilience

- Timeouts ~20s (OkHttp config from core-network). Admin reads are idempotent
  `GET`s and use the existing bounded-backoff retry for GETs (AND-016).
- `401`: handled by the OkHttp authenticator (single `POST /ui/session/refresh`
  then retry). Persistent 401 → "Session expired" and hand off to auth flow; not
  re-implemented here.
- `403`: deterministic `Forbidden` state with a clear message and Back; no retry
  loop, no data fetched. This also covers a server-side role revocation occurring
  after the client-side gate passed.
- Concurrent fetch: if one of alerts/metrics fails while the other succeeds, the
  first load fails as `Error` (atomic dashboard) to avoid showing a misleadingly
  partial admin view; a subsequent Retry re-attempts both. (Open to relaxation —
  §13 Q4.)
- Network offline: offline banner + Retry; retain last-rendered dashboard if
  present (marked stale) rather than blanking.
- All retries are bounded; no busy-loop against the unreliable dev host.

## 8. Security & Privacy

- **Role gating is the core security property.** Enforced at the navigation
  layer, the ViewModel layer (no fetch when non-admin), and validated by the
  backend `403` (defense in depth). Tests assert a non-admin never triggers an
  admin network call.
- Read-only by construction: no mutation endpoints in `AdminApi`, no
  write/acknowledge controls in the UI. There is nothing this screen can change
  server-side.
- All calls ride the existing authenticated cookie jar with `X-CSRF-Token`; no
  cookies, CSRF token, or session ids are logged or persisted by this feature.
- Alert contents may include operational/PII-adjacent detail (IPs, regions,
  usernames). Do not write alert message bodies to logcat in release, do not
  include them in analytics payloads, and do not put them in crash breadcrumbs.
- Admin data is held in memory only and cleared on logout (process state reset via
  the auth flow); not exported, not cached to disk.
- Dev backend is plaintext HTTP; production must be HTTPS. This screen adds no new
  cleartext exemptions beyond the existing dev `network_security_config`.

## 9. Accessibility & i18n

- All strings in `feature-admin` `strings.xml`; no hardcoded text. Relative times
  via a locale-aware formatter (`DateUtils.getRelativeTimeSpanString`).
- Severity is never color-only: each alert pairs a Material 3 color with a
  severity icon and a text label, and exposes severity in `contentDescription`
  (e.g. "Critical alert: Elevated auth failure rate, source auth, 5 minutes ago").
- Metric tiles expose a merged `contentDescription` of label + value + unit/trend.
- Touch targets (Refresh, Back) ≥ 48dp. Supports dynamic font scaling, dark theme,
  and RTL-safe layouts (start/end paddings; the metrics grid reflows). No content
  truncation that hides severity or value from TalkBack.
- Forbidden and error states are announced to TalkBack and are keyboard/Dpad
  reachable.

## 10. Telemetry & Logging

- Events (no PII; no alert bodies; ids omitted or hashed):
  `admin_dashboard_viewed`, `admin_dashboard_refresh`,
  `admin_dashboard_load_error` (`{type}`), `admin_dashboard_forbidden`.
- Logging via the project Timber wrapper; debug-only request/response metadata
  (status, path, latency) — never cookies, `X-CSRF-Token`, or alert message text.
- Error mapping records the normalized `UiError.type`
  (network/auth/forbidden/server) for triage, not raw `detail` strings that may
  carry identifiers.

## 11. Testing Strategy

- **MockWebServer (core-testing, AND-046 harness)**: enqueue
  `GET /ui/admin/alerts` and `GET /ui/admin/metrics` fixtures (populated, empty,
  unknown-severity), and error responses (`403`, `404`, `500`, timeout). Assert
  verbs/paths and that requests carry the session cookie context. Assert **no**
  admin request is issued in the non-admin path.
- **ViewModel unit tests** (Turbine + coroutine test rule):
  - admin user → `Loading → Content`; alerts sorted severity-desc then time-desc.
  - non-admin user → emits `Forbidden`, **zero** API calls (verify mock).
  - empty alerts + empty metrics → `Empty`; empty alerts + present metrics →
    `Content` with empty alert list.
  - `403` from backend → `Forbidden`; `5xx`/timeout on first load → `Error`.
  - refresh failure from `Content` → retains data, `isStale = true`, `error` set.
  - unknown severity string maps to `AlertSeverity.UNKNOWN`.
- **Repository tests**: DTO→domain mapping; concurrent fetch aggregation; error
  envelope mapping (string/array/object forms); ordering correctness.
- **Compose UI tests**: admin sees alerts list + metric tiles and **no**
  acknowledge/dismiss/mutation control exists anywhere on screen (assert absence);
  non-admin/forbidden path renders the Forbidden state and no alert rows;
  severity is conveyed by icon+label (not color alone). These satisfy the AC
  "Admin sees read-only alerts (role-gated)".
- All tests deterministic; no real network.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (`AuthApi` + the wired network stack: cookie jar, CSRF
  interceptor, 401-refresh authenticator, configured `Retrofit`). `AdminApi`
  reuses that `Retrofit`; hard blocker.
- Transitively relies on: AND-015 (error/`detail` mapping), AND-016
  (idempotent-GET backoff), AND-018 (`ApiResult`), AND-021 (state composables),
  AND-024 (authenticated nav graph for route registration), and the `getMe`/auth
  state store chain (AND-029) for the role flag. Assumed present via the M1 E04/E06
  chain.
- Blocks: none currently tracked.
- Sequencing: confirm admin paths + role flag against `/openapi.json` → DTOs +
  mapper + repository (unit + MockWebServer) → ViewModel + role gating → Compose
  screen + nav wiring + Forbidden gate → UI tests.

## 13. Risks & Open Questions

- Q1: What is the exact admin role representation in `GET /ui/me` — a boolean
  `is_admin`, a `roles[]` array containing `"admin"`, or a scope claim? The gate
  in §4 must bind to the confirmed field. Verify against `/openapi.json` and
  `frontend/src/api/types.ts`.
- Q2: Do `GET /ui/admin/alerts` and `GET /ui/admin/metrics` exist, and are the
  paths as written? Paths are placeholders pending `/openapi.json`. If a single
  combined dashboard endpoint exists instead, collapse to one GET in the
  repository (the ViewModel/UI contract is unaffected).
- Q3: Is pagination needed for alerts? Assumed bounded summary set (no Paging) for
  this ticket; a follow-up ticket owns pagination if the backend returns large
  pages.
- Q4: Atomic vs. partial dashboard — should a metrics-only or alerts-only success
  render partially? §7 chooses atomic (both-or-error) for a trustworthy admin
  view; revisit if product wants partial rendering.
- Q5: Severity enum value set (`critical|warning|info|...`) — confirm the exact
  strings so the mapper and color/icon mapping are exhaustive; unknowns fall back
  to `UNKNOWN`.
- Risk: unreliable dev host makes manual QA flaky; mitigated by MockWebServer
  coverage being the correctness source of truth.

## 14. Acceptance Criteria

AC-1. An admin user navigating to the Admin dashboard issues `GET
/ui/admin/alerts` and `GET /ui/admin/metrics` and renders the alerts list and
metric tiles. (MockWebServer + Compose UI test — satisfies "Admin sees read-only
alerts".)

AC-2. The feature is **role-gated**: a non-admin (or unauthenticated) user cannot
reach the route/entry, the ViewModel emits `Forbidden` without any admin network
call, and a backend `403` also maps to `Forbidden`. (Unit + UI test — satisfies
"role-gated".)

AC-3. The screen is **read-only**: no acknowledge/dismiss/resolve/edit/delete
control exists; the only actions are Refresh and Back. (Compose UI test asserts
absence of mutation controls — satisfies "no mutations".)

AC-4. Alerts render with severity (icon + label + color), title/message, source,
and a relative timestamp, sorted severity-desc then time-desc; unknown severity
strings map to `UNKNOWN`. (Unit + UI test.)

AC-5. Empty alerts show "No active alerts"; metrics still render if present.
(Unit + UI test.)

AC-6. Network/server errors on first load show a retryable Error state; a refresh
failure retains the last data marked stale with a transient error. (MockWebServer
+ ViewModel test.)

AC-7. `401` is handled transparently by the existing refresh-then-retry
authenticator; persistent 401 surfaces "Session expired" and hands off to the
auth flow. (MockWebServer test.)

## 15. Definition of Done

- `feature-admin` Admin dashboard screen, ViewModel, `AdminRepository`,
  DTOs/mapper, `AdminApi`, Hilt wiring, and nav registration implemented under
  `com.testlogon.android`, reusing the AND-027 network stack (no duplicate
  auth/session endpoints, no `Retrofit` reconfiguration).
- Role gating enforced at navigation + ViewModel layers and validated by backend
  `403`; non-admin path issues zero admin requests.
- No mutation endpoints or write controls anywhere in the feature.
- All AC-1…AC-7 tests green: MockWebServer, ViewModel/repository unit, and at
  least one Compose UI test, passing in CI.
- No cookie/CSRF/alert-body leakage in logs or telemetry; strings externalized;
  severity conveyed non-color-only; TalkBack and dynamic-type verified.
- Lint/detekt/ktlint clean; builds on `compileSdk 35` / `targetSdk 35` / AGP
  8.7.3 / Kotlin 2.0.21 / JDK 17 with the Gradle 8.9 wrapper.
- Admin paths and role flag confirmed against `/openapi.json` (Q1, Q2 resolved)
  before merge.
- PR on `android-port` references AND-403 and links AND-027.
