---
id: AND-403
title: Read-only admin alerts/dashboards
milestone: M8
epic: E53
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- Role information does **NOT** come from `GET /ui/me`. **[CORRECTED]** Verified
  against the frontend (`src/api/types.ts: MeResp = { user_sub, session_id, ip }`)
  and OpenAPI (`GET /ui/me` 200 response schema is empty/untyped `{}`): the `me`
  payload carries **no** role/`is_admin`/`roles[]` field. The web client derives
  the admin role from the **JWT access-token `role` claim** decoded client-side
  (`src/lib/adminCapabilities.ts: getRoleFromAccessToken` →
  `claims.role`), where `role ∈ {"admin","root"}`, plus an optional
  `admin_profile` (`type: "general" | "scoped"`, `scopes[]`). General admin or
  root is required for full admin reads. The Android role gate MUST bind to the
  decoded access-token `role` claim (and `admin_profile.type`), not to `/ui/me`.
  See §13 Q1.
- Dev backend `http://18.222.237.167:8000` is plaintext HTTP and unreliable:
  ~20s timeouts, offline/stale UI states, bounded retry for GETs only.
- Web reference: `src/api/endpoints/*.ts` and `src/api/types.ts`. **[CORRECTED]**
  There is **no** `admin alerts` or `admin metrics` endpoint/DTO in the web client
  or OpenAPI. The web admin surface is split across many narrow read endpoints
  (e.g. `src/api/endpoints/adminRateLimits.ts`, `paymentProviderHealth.ts`,
  `jobDashboard.ts`). The combined "alerts + metric tiles" model in this ticket is
  a **client-side aggregation/abstraction**, not a 1:1 backend contract. The
  generic DTO shapes below (`severity`, `created_at`, `key/label/value`) are
  **invented placeholders** with no backing schema and MUST be re-grounded on the
  specific source endpoints chosen during implementation (§5, §13 Q2/Q5).

## 3. Functional Requirements

FR-1. The Admin entry point (route + any nav affordance) is visible **only** when
the current authenticated user has the admin role. **[CORRECTED]** The role is
derived from the decoded JWT access-token `role` claim (`"admin"`/`"root"`) held in
the auth state store — **not** from `GET /ui/me` (which carries no role). Non-admins
never see the entry.

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
// [CORRECTED] The paths "ui/admin/alerts" and "ui/admin/metrics" DO NOT EXIST in
// the backend (verified against openapi.index.txt — no /ui/admin/alerts and no
// /ui/admin/metrics). They are placeholders. Bind each method to a REAL admin read
// endpoint at implementation time. Verified candidates (all GET, role-gated):
//   GET /ui/admin/rate-limits/live-summary   -> RateLimitLiveSummary
//   GET /ui/admin/rate-limits/events         -> (events[], count)  params=hours,limit,status
//   GET /ui/admin/payment-health             -> provider status list  params=hours
//   GET /ui/admin/payment-health/incidents   -> incidents list
//   GET /ui/admin/jobs/health                -> JobHealthOut
//   GET /ui/admin/webhooks/health            -> WebhookHealthSummary
// "Alerts" map from incident/event endpoints; "metric tiles" map from the *health
// /summary endpoints. The DTO names below (AdminAlertListDto/AdminMetricsDto) are
// thus internal client aggregations, not backend schemas.
interface AdminApi {
    @GET("ui/admin/rate-limits/live-summary")   // placeholder mapping — confirm per §13 Q2
    suspend fun getRateLimitSummary(): Response<RateLimitLiveSummaryDto>

    @GET("ui/admin/payment-health/incidents")   // placeholder mapping — confirm per §13 Q2
    suspend fun getPaymentIncidents(@Query("limit") limit: Int? = null): Response<PaymentIncidentListDto>

    @GET("ui/admin/jobs/health")                 // metric tiles source
    suspend fun getJobHealth(): Response<JobHealthDto>

    @GET("ui/admin/webhooks/health")             // metric tiles source
    suspend fun getWebhookHealth(): Response<WebhookHealthSummaryDto>
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
   composable are guarded by `authStateStore.isAdmin()` — where `isAdmin()`
   resolves the decoded access-token `role` claim (`"admin"`/`"root"`), mirroring
   the web client's `getRoleFromAccessToken` (`src/lib/adminCapabilities.ts`), not
   a `/ui/me` field. A non-admin who somehow
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

> **[CORRECTED] Authoritative status:** `GET /ui/admin/alerts` and
> `GET /ui/admin/metrics` **do not exist** (verified: not present in
> `openapi.index.txt`). The JSON below is **illustrative of the client-side
> aggregated model only**, not a backend response. Real implementation must read
> the verified admin endpoints listed in §4 (e.g.
> `GET /ui/admin/rate-limits/live-summary` → `RateLimitLiveSummary`
> { `by_group`, `by_source[]`, `time_series[]`, `total_hits`, `window_hours` };
> `GET /ui/admin/jobs/health` → `JobHealthOut` { `jobs[]`, `timestamp` };
> `GET /ui/admin/webhooks/health` → `WebhookHealthSummary`
> { `total_endpoints`, `enabled_endpoints`, `disabled_endpoints`,
> `success_count_24h`, `failed_count_24h`, `dead_letter_count_24h`,
> `total_deliveries_24h` }). Field names `severity`/`created_at`/`source` are
> **invented** and have no backing schema.

`GET /ui/admin/alerts` (**non-existent — illustrative aggregated shape only**) → 200:

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

`GET /ui/admin/metrics` (**non-existent — illustrative aggregated shape only**) → 200:

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
{ "detail": [{ "msg": "...", "loc": ["..."], "type": "..." }] }
{ "detail": { "code": "forbidden", "message": "..." } }
```

> **[VERIFIED/CORRECTED]** The string form (`{"detail": "..."}`) is the standard
> FastAPI 401/403/404 shape. The **array** form is the `422` `HTTPValidationError`
> shape — verified `components.schemas.HTTPValidationError = { detail:
> ValidationError[] }` and each `ValidationError` has `{ loc, msg, type }` (the
> spec's `[{ msg }]` was an over-simplification; the real items include
> `loc`/`type` too). The **object** form `{ detail: { code, message } }` is
> **NOT** in the OpenAPI schema set and is an **unverified assumption** (kept only
> as a defensive parse branch).

Status handling: `200` success; `401` → authenticator refresh-once-then-retry
(transparent), persistent 401 → `UiError(type=auth)` "Session expired", delegate
re-auth to the auth flow; `403` → `UiState.Forbidden`; `404` on an admin path →
treat as misconfigured endpoint → `UiError(type=server)` (and §13 Q2); `5xx` /
timeout → retryable `UiError(type=network|server)`, retain prior data if any.
All admin paths and field names (`severity` enum string set, role flag) MUST be
verified against `/openapi.json`; Moshi DTOs use `@Json(name=...)` for snake_case.
**[CORRECTED]** The `severity` enum and `alerts`/`metrics` field names have **no**
backing schema and are not placeholders-to-confirm but **client-side inventions** —
they must be derived from the chosen real source endpoints (§4). Note also the real
admin reads accept query params not modeled here (e.g. `hours`, `limit`, `status`).

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

- **MockWebServer (core-testing, AND-046 harness)**: enqueue the configured admin
  read GETs (**[CORRECTED]** the verified real paths from §4 — e.g.
  `/ui/admin/rate-limits/live-summary`, `/ui/admin/jobs/health`,
  `/ui/admin/webhooks/health` — not `/ui/admin/alerts` /`/ui/admin/metrics`)
  fixtures (populated, empty, unknown-severity), and error responses (`403`, `404`,
  `500`, timeout). Assert
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

- Q1: **[RESOLVED — CORRECTED]** Admin role is **not** in `GET /ui/me`. Verified:
  `src/api/types.ts: MeResp = { user_sub, session_id, ip }` and OpenAPI `GET /ui/me`
  200 schema is empty `{}`. The role is the **JWT access-token `role` claim**
  (`"admin"`/`"root"`) decoded client-side
  (`src/lib/adminCapabilities.ts: getRoleFromAccessToken`), with optional
  `admin_profile` (`type: general|scoped`, `scopes[]`). Remaining open item: how the
  Android client obtains/stores that access token (AND-027 territory) and whether a
  bare `admin` scoped-profile suffices for these reads or `general`/`root` is needed.
- Q2: **[RESOLVED — CORRECTED]** `GET /ui/admin/alerts` and `GET /ui/admin/metrics`
  **do not exist** (not in `openapi.index.txt`); there is **no** single combined
  admin dashboard endpoint either. Verified read-only admin sources to aggregate
  client-side: `GET /ui/admin/rate-limits/live-summary`,
  `GET /ui/admin/rate-limits/events`, `GET /ui/admin/payment-health`(+`/incidents`),
  `GET /ui/admin/jobs/health` (`JobHealthOut`), `GET /ui/admin/webhooks/health`
  (`WebhookHealthSummary`). Open product decision: exactly which of these feed the
  first cut of the "alerts" list vs the "metric tiles".
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

AC-1. An admin user navigating to the Admin dashboard issues the configured
admin read GETs and renders the alerts list and metric tiles. **[CORRECTED]** The
GETs are the verified real endpoints (§4), e.g.
`GET /ui/admin/rate-limits/live-summary`, `GET /ui/admin/jobs/health`,
`GET /ui/admin/webhooks/health` — **not** the non-existent `GET /ui/admin/alerts`
/`GET /ui/admin/metrics`. (MockWebServer + Compose UI test — satisfies "Admin sees
read-only alerts".)

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Claim:** Admin alerts are read at `GET /ui/admin/alerts`.
   **VERDICT: Corrected (endpoint does not exist).**
   **Source:** OpenAPI `openapi.index.txt` — no `/ui/admin/alerts` entry; `alert`
   search returns only `/ui/alerts/*` (user notifications) and
   `/ui/agents/accountant/costs/alerts`. No admin alerts path exists.

2. **Claim:** Admin metrics are read at `GET /ui/admin/metrics`.
   **VERDICT: Corrected (endpoint does not exist).**
   **Source:** OpenAPI `openapi.index.txt` — `/ui/admin/metrics` not present; only
   scoped admin metrics like `GET /ui/admin/ad-platform/metrics`
   (`AdminAdPlatformMetricsOut`) exist. No general admin metrics path.

3. **Claim:** Verified read-only admin endpoints to aggregate instead.
   **VERDICT: Verified.**
   **Source:** OpenAPI `openapi.index.txt`:
   `GET /ui/admin/rate-limits/live-summary` (op `live_summary…`, params=hours);
   `GET /ui/admin/rate-limits/events` (params=hours,limit,status);
   `GET /ui/admin/payment-health` (params=hours) and
   `GET /ui/admin/payment-health/incidents`;
   `GET /ui/admin/jobs/health` → `JobHealthOut`;
   `GET /ui/admin/webhooks/health` → `WebhookHealthSummary`. Frontend confirms
   shapes in `src/api/endpoints/adminRateLimits.ts: getRateLimitLiveSummary` /
   `RateLimitLiveSummary`.

4. **Claim:** The admin role flag lives in `GET /ui/me` (e.g. `is_admin`/`roles[]`).
   **VERDICT: Corrected (false).**
   **Source:** `src/api/types.ts: MeResp` = `{ user_sub, session_id, ip }` (no role
   field); OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`) 200 response schema is empty
   `{}`. Frontend never reads a role from `me`.

5. **Claim:** Admin role is derived from the JWT access-token `role` claim
   (`"admin"`/`"root"`) with an `admin_profile` (general/scoped + scopes).
   **VERDICT: Verified.**
   **Source:** `src/lib/adminCapabilities.ts: getRoleFromAccessToken` (decodes
   `claims.role`), `getAdminProfileFromAccessToken`, `canAccessGeneralAdminControls`;
   usage in `src/pages/tickets/TicketsPage.tsx` (`role === "admin" || role === "root"`).
   `src/api/endpoints/adminRoles.ts: AdminProfileType = "general"|"scoped"`,
   `AdminScope`.

6. **Claim:** Auth is cookie-based with `X-CSRF-Token` echoed from the `ui_csrf`
   cookie; requests include credentials.
   **VERDICT: Verified.**
   **Source:** `src/api/client.ts` — `credentials: "include"`, `getCookie("ui_csrf")`
   → `headers.set("X-CSRF-Token", csrf)`.

7. **Claim:** On 401 the client performs `POST /ui/session/refresh` once and retries.
   **VERDICT: Verified (endpoint).**
   **Source:** OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh…`, resp
   200); `src/api/endpoints/auth.ts: refreshSession` → `api.post("/ui/session/refresh")`.
   (The single-retry-then-handoff behavior itself is an AND-027 client policy, not a
   backend contract.)

8. **Claim:** Error envelope is FastAPI `detail` in three forms (string / array of
   `{msg}` / object `{code,...}`).
   **VERDICT: Corrected + partially Unverified.**
   **Source:** OpenAPI `components.schemas.HTTPValidationError` =
   `{ detail: ValidationError[] }`, `ValidationError = { loc, msg, type }` — so the
   array items carry `loc`/`type`, not just `msg`. The string form is the standard
   403/404 `detail`. The object form `{ detail: { code, message } }` is NOT in the
   schema set → unverified assumption.

9. **Claim:** Response fields `severity`, `created_at`, `source`, and metric
   `key/label/value/unit/trend`.
   **VERDICT: Unverified-assumption (invented).**
   **Source:** No matching schema in OpenAPI; no DTO in `src/api/types.ts`. These are
   client-side model fields with no backend backing; must be mapped from the real
   source schemas (`RateLimitLiveSummary`, `JobHealthOut`, `WebhookHealthSummary`).

10. **Claim:** `404` on an admin path means a misconfigured endpoint.
    **VERDICT: Verified (consistent with sources).**
    **Source:** Given §16.1/§16.2 the literal `/ui/admin/alerts|metrics` would 404;
    real endpoints from §16.3 return 200/422. 422 (`HTTPValidationError`) is the
    documented param-validation failure for these GETs.

11. **Framework choice:** MVVM + Hilt + `StateFlow` + Jetpack Compose Material 3.
    **VERDICT: Verified (framework ref).**
    **Source (framework ref):** https://developer.android.com/topic/architecture
    and https://developer.android.com/jetpack/compose/state (StateFlow/UI state).

12. **Framework choice:** Relative timestamps via `DateUtils.getRelativeTimeSpanString`.
    **VERDICT: Verified (framework ref).**
    **Source (framework ref):**
    https://developer.android.com/reference/android/text/format/DateUtils#getRelativeTimeSpanString(long)

13. **Framework choice:** Accessibility — non-color-only severity, `contentDescription`,
    ≥48dp targets, TalkBack.
    **VERDICT: Verified (framework ref).**
    **Source (framework ref):** https://developer.android.com/guide/topics/ui/accessibility/principles
    and https://developer.android.com/jetpack/compose/accessibility

### Corrections made

- C1. `GET /ui/admin/alerts` and `GET /ui/admin/metrics` removed as real endpoints
  (they do not exist). §2, §4 (`AdminApi`), §5, §11, §13 Q2, §14 AC-1 updated to use
  the verified admin read endpoints and to flag the combined model as a client-side
  aggregation.
- C2. Role source corrected from `GET /ui/me` (`is_admin`/`roles[]`) to the decoded
  JWT access-token `role` claim (`"admin"`/`"root"`) + `admin_profile`. §2, §3 FR-1,
  §4 role-gating, §13 Q1 updated.
- C3. `HTTPValidationError` array items corrected to `{ loc, msg, type }` (not just
  `{ msg }`); object-form `detail` flagged as unverified (§5).
- C4. DTO field names (`severity`, `created_at`, `key/label/value`) re-labelled as
  invented placeholders with no backing schema (§2, §5).
- Verified-and-kept (no change needed): cookie + `ui_csrf` → `X-CSRF-Token`
  transport; `POST /ui/session/refresh` existence; read-only/no-mutation design;
  Hilt/Compose/StateFlow framework choices.

### Open assumptions

- A1. The object-form error envelope `{ detail: { code, message } }` — not in
  OpenAPI; kept only as a defensive parse branch. (Why: no schema to confirm.)
- A2. Which specific verified endpoints feed the first-cut "alerts" list vs "metric
  tiles", and the unified client severity taxonomy — product/impl decision; the
  source schemas have heterogeneous shapes (counts vs incident lists). (Why: no
  single backend contract dictates the mapping.)
- A3. How the Android client obtains and stores the JWT access token that carries
  the `role` claim, and whether a `scoped` admin profile (vs `general`/`root`) is
  authorized for these reads. (Why: token issuance is AND-027 scope; the backend
  authorization matrix for each endpoint is not exposed in the OpenAPI doc.)
- A4. The single-`401`-refresh-then-retry authenticator behavior is an AND-027
  client policy assumed present; only the refresh endpoint is verified here. (Why:
  cross-ticket dependency, not a backend contract.)
- A5. Empty-state semantics ("No active alerts") assume the chosen source endpoints
  can legitimately return zero items; verified for list endpoints (events/incidents)
  but `*/health` summaries always return counts. (Why: aggregation rule is undecided.)

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device);
**EMU35** = headless emulator AVD `test35` (x86_64, API 35) on the CI build server;
**DEV-A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android
14 / API 34, arm64-v8a) on the build host. Endpoints below use the **verified**
admin reads from §4/§16.3.

- **TC-AND-403-01 — Happy path: admin loads dashboard.**
  Type: contract/MockWebServer + unit (ViewModel). Target: JVM.
  Preconditions: auth store holds an access token whose decoded `role` claim is
  `"admin"` (general profile); MockWebServer enqueues 200 for each configured admin
  GET (`/ui/admin/rate-limits/live-summary`, `/ui/admin/jobs/health`,
  `/ui/admin/webhooks/health`) with populated fixtures.
  Steps: invoke `viewModel.load()`; collect `state` via Turbine.
  Expected: emissions `Loading → Content`; dashboard has metric tiles (from health
  summaries) and an alerts list; requests carry session cookie + `X-CSRF-Token`;
  request paths exactly match the configured real endpoints. Traces: AC-1.

- **TC-AND-403-02 — Alert ordering + unknown severity mapping.**
  Type: unit (mapper/repository). Target: JVM.
  Preconditions: fixture mixes critical/warning/info plus an unrecognized severity
  string and out-of-order timestamps.
  Steps: map DTO→domain via the repository mapper.
  Expected: alerts sorted severity-desc then `createdAt`-desc; the unrecognized
  string maps to `AlertSeverity.UNKNOWN`; metrics preserve server order. Traces: AC-4.

- **TC-AND-403-03 — Non-admin: zero admin network calls, Forbidden.**
  Type: unit (ViewModel) + contract/MockWebServer. Target: JVM.
  Preconditions: access-token `role` claim is `"member"`/absent (non-admin);
  MockWebServer running with a request recorder.
  Steps: invoke `viewModel.load()`.
  Expected: state emits `Forbidden`; MockWebServer `takeRequest()` times out — **no**
  admin request issued. Traces: AC-2.

- **TC-AND-403-04 — Backend 403 maps to Forbidden (defense in depth).**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: client gate passes (role looks admin) but server returns `403`
  `{"detail":"Admin access required"}` for an admin GET (simulates server-side role
  revocation).
  Steps: `viewModel.load()`.
  Expected: state `Forbidden`; no retry loop; Back offered; no crash. Traces: AC-2.

- **TC-AND-403-05 — Empty alerts, present metrics.**
  Type: unit (ViewModel) + Compose-UI. Target: JVM (logic) / EMU35 (UI).
  Preconditions: alert-source fixtures return zero items; health summaries return
  non-zero counts.
  Steps: load; render `AdminDashboardScreen` in Compose test.
  Expected: "No active alerts" shown; metric tiles still render; state is `Content`
  with empty alert list (not `Empty`). Traces: AC-5.

- **TC-AND-403-06 — Fully empty → Empty state.**
  Type: unit (ViewModel). Target: JVM.
  Preconditions: all sources return zero items/empty.
  Steps: `viewModel.load()`.
  Expected: state `Empty`. Traces: AC-5.

- **TC-AND-403-07 — First-load error (5xx/timeout) → retryable Error.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: one configured admin GET returns `500` (and a variant: socket
  timeout via MockWebServer throttle/no-response, exercising the ~20s budget).
  Steps: `viewModel.load()`.
  Expected: state `Error` with retryable `UiError(type=network|server)`; atomic —
  no partial dashboard rendered. Traces: AC-6.

- **TC-AND-403-08 — Refresh failure retains stale data.**
  Type: unit (ViewModel). Target: JVM.
  Preconditions: first load succeeds (`Content`); refresh enqueues a failure on one
  source.
  Steps: `load()` then `refresh()`.
  Expected: previous `Content` retained with `isStale = true` and a transient
  `error`; data not blanked. Traces: AC-6.

- **TC-AND-403-09 — Persistent 401 after refresh → Session expired handoff.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: admin GET returns `401`; `POST /ui/session/refresh` also returns
  `401` (refresh fails).
  Steps: `viewModel.load()`.
  Expected: a single `POST /ui/session/refresh` attempt is observed; persistent 401
  surfaces `UiError(type=auth)` "Session expired" and hands off to the auth flow
  (no admin-data render). Traces: AC-7.

- **TC-AND-403-10 — Read-only: no mutation affordance anywhere.**
  Type: Compose-UI. Target: EMU35.
  Preconditions: admin `Content` state with alerts + metrics.
  Steps: render screen; assert on the semantics tree.
  Expected: only Refresh and Back actions exist; assert **absence** of any
  acknowledge/dismiss/resolve/edit/delete control (by test tag and by
  contentDescription); confirm `AdminApi` exposes no non-GET method. Traces: AC-3.

- **TC-AND-403-11 — Offline / flaky dev-host path.**
  Type: instrumented/e2e. Target: **DEV-A15 (must run on physical device)**.
  Preconditions: app pointed at the unreliable dev host
  `http://18.222.237.167:8000`; toggle the device to airplane mode (real radio
  behavior) after a prior successful load.
  Steps: load once (online) → enable airplane mode → pull-to-refresh → re-enable →
  retry. Expected: offline banner + Retry; last dashboard retained marked stale (not
  blanked); on reconnect Retry re-fetches both sources and clears stale. Rationale
  for device: real airplane-mode/radio transitions and the cleartext-HTTP dev host
  path differ from emulator network stubbing. Traces: AC-6.

- **TC-AND-403-12 — Accessibility: severity not color-only + TalkBack.**
  Type: Compose-UI (semantics) + manual (TalkBack). Target: EMU35 (semantics) /
  **DEV-A15** (TalkBack manual).
  Preconditions: `Content` with a critical alert.
  Steps: assert each alert exposes a `contentDescription` containing severity label,
  title, source, and relative time; assert a severity icon + text label accompany
  the color; manually verify TalkBack announces severity and Forbidden/Error states;
  verify dynamic-font scaling and ≥48dp touch targets.
  Expected: severity conveyed by icon+label (not color alone); all states announced
  and Dpad/keyboard reachable. Traces: AC-3, AC-4.

- **TC-AND-403-13 — Security: no cookie/CSRF/alert-body leakage in logs.**
  Type: unit (Robolectric, capturing Timber tree) + manual logcat review.
  Target: JVM (assertion) / **DEV-A15** (release-build logcat spot check).
  Preconditions: a populated dashboard load with debug + release logging configs.
  Steps: capture emitted log/telemetry during load/refresh/error.
  Expected: no `Cookie`, `X-CSRF-Token`, session id, or alert message body appears in
  logs, analytics payloads, or crash breadcrumbs; only normalized `UiError.type` is
  recorded. Traces: AC-2 (security property), AC-3.

- **TC-AND-403-14 — Deep-link role gate (navigation layer).**
  Type: instrumented (nav). Target: EMU35.
  Preconditions: non-admin session; attempt to navigate directly to the
  `adminDashboard` route (deep link).
  Steps: trigger the deep link.
  Expected: route guard redirects back / shows `Forbidden` without issuing any admin
  request (asserted via MockWebServer recorder). Traces: AC-2.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (admin loads alerts+metrics via real GETs) | TC-01 |
| AC-2 (role-gated: no call for non-admin, 403→Forbidden, deep-link gate) | TC-03, TC-04, TC-13, TC-14 |
| AC-3 (read-only: no mutation control) | TC-10, TC-12, TC-13 |
| AC-4 (severity render + ordering + UNKNOWN) | TC-02, TC-12 |
| AC-5 (empty alerts / empty dashboard) | TC-05, TC-06 |
| AC-6 (first-load error retryable; refresh keeps stale; offline) | TC-07, TC-08, TC-11 |
| AC-7 (401 transparent refresh; persistent 401 handoff) | TC-09 |
