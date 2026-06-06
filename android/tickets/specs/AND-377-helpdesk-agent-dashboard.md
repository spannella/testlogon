---
id: AND-377
title: Helpdesk agent dashboard
milestone: M8
epic: E49
priority: P2
size: M
status: draft
depends_on: [AND-161]
blocks: []
---

# AND-377 — Helpdesk agent dashboard

## 1. Overview & Goal

Build a native Android **Helpdesk Agent Dashboard** that gives support agents an at-a-glance operational view of the helpdesk: the live conversation queue (reusing the queue surface delivered by AND-161) plus a set of agent-facing **metrics** (open/unassigned/assigned-to-me counts, SLA-at-risk count, average first-response and resolution times, and the agent's own throughput for the day). The dashboard is the agent's landing screen inside the helpdesk feature and is gated to users whose `/ui/me` profile carries an agent (or admin) role.

The goal is a single Compose screen, `HelpdeskDashboardScreen`, backed by `HelpdeskDashboardViewModel`, that:

- Resolves the current user's role and renders the dashboard **only** for agent-capable roles; non-agents see an access-denied state and are routed away.
- Loads metrics from the backend, renders them as a responsive grid of metric cards, and embeds (or links to) the AND-161 queue list.
- Tolerates the unreliable dev backend with explicit loading / stale / offline / empty / error states and pull-to-refresh.

This ticket owns the dashboard composition, the metrics data path, and role gating. It does **not** re-implement the queue list itself (AND-161) nor individual conversation handling (downstream messaging tickets).

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, branch `android-port`, Android app under `android/`. New code lives in `feature-helpdesk` (created by AND-161); shared pieces in `core-network`, `core-model`, `core-data`, `core-ui`. Package base `com.testlogon.android`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Paging 3. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Dependency AND-161 (Helpdesk queue):** provides `HelpdeskQueueScreen`, `HelpdeskQueuePagingSource` over `GET /messaging/helpdesk/queue`, the `HelpdeskApi` Retrofit interface, and `QueueItem`/`HelpdeskAgentRole` models in `core-model`. This ticket **reuses** those rather than duplicating them.
- **Auth/session:** cookie-based session established via `/ui/session/start` → MFA → `/ui/session/finalize`; `ui_csrf` cookie echoed as `X-CSRF-Token`; 401 → single `POST /ui/session/refresh` then retry. Persistent cookie jar already provided by `core-network` (AND-120). Role comes from `GET /ui/me`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`, types in `frontend/src/api/types.ts`. Inspect `frontend/src/api/endpoints/helpdesk.ts` for the canonical metrics endpoint shape; the contract in §5 reflects the expected shape and MUST be reconciled against `/openapi.json` during implementation.
- **Error mapping:** FastAPI `detail` is `string | [{msg}] | {code,...}`; map via the shared `ApiResult<T>` and `detail`-parsing helper in `core-network`.

## 3. Functional Requirements

FR-1. **Role gating.** On entry the dashboard reads the cached `Me` profile. If the user's role is not in `{agent, supervisor, admin}` (helpdesk-capable set), render `AccessDenied` and do not issue metrics requests. Agent-capable users proceed.

FR-2. **Metrics display.** Render a grid of metric cards:
- Open conversations, Unassigned, Assigned to me, SLA at risk (count).
- Avg first-response time and Avg resolution time (durations, formatted `Xm`/`Xh Ym`).
- My resolved today (agent throughput).
Each card shows label, primary value, and an optional delta vs. previous period when supplied.

FR-3. **Embedded queue.** Below the metrics, embed the AND-161 queue list (top N preview, default 25 via Paging 3) with a "View full queue" affordance navigating to the standalone `HelpdeskQueueScreen`. Tapping a queue row navigates to the conversation route (owned downstream); this ticket only wires the callback.

FR-4. **Refresh.** Pull-to-refresh (Material 3 `PullToRefreshBox`) re-fetches metrics and invalidates the queue paging source. A manual retry button appears in error states.

FR-5. **States.** The screen must render distinct UI for: `Loading` (first load shimmer), `Content` (with optional `isStale` banner), `Empty` (agent role but no data yet), `AccessDenied`, and `Error(message, retryable)`.

FR-6. **Staleness/offline.** When metrics come from the Room cache because the network failed or is offline, show a non-blocking "Showing cached data · updated <relative time>" banner.

FR-7. **Navigation.** Reachable at route `helpdesk/dashboard`; registered in the helpdesk nav graph. Deep-linkable via `testlogon://helpdesk/dashboard`.

## 4. Technical Design

### 4.1 Module & files
```
feature-helpdesk/
  dashboard/
    HelpdeskDashboardScreen.kt
    HelpdeskDashboardViewModel.kt
    HelpdeskDashboardUiState.kt
    MetricCard.kt
    components/DashboardMetricsGrid.kt
    components/StaleBanner.kt
  data/
    HelpdeskMetricsRepository.kt      // new
    HelpdeskApi.kt                    // extend (from AND-161) with metrics endpoint
    dto/HelpdeskMetricsDto.kt         // new
    cache/HelpdeskMetricsDao.kt       // new (Room)
    cache/HelpdeskMetricsEntity.kt    // new
core-model/
    HelpdeskMetrics.kt                // new domain model
    HelpdeskAgentRole.kt             // reuse from AND-161
```

### 4.2 UI state
```kotlin
data class HelpdeskMetrics(
    val openCount: Int,
    val unassignedCount: Int,
    val assignedToMeCount: Int,
    val slaAtRiskCount: Int,
    val avgFirstResponseSeconds: Long?,
    val avgResolutionSeconds: Long?,
    val resolvedByMeToday: Int,
    val deltas: Map<String, Int> = emptyMap(),
    val generatedAt: Instant
)

sealed interface HelpdeskDashboardUiState {
    data object Loading : HelpdeskDashboardUiState
    data object AccessDenied : HelpdeskDashboardUiState
    data class Content(
        val metrics: HelpdeskMetrics,
        val isStale: Boolean,
        val cachedAt: Instant?
    ) : HelpdeskDashboardUiState
    data object Empty : HelpdeskDashboardUiState
    data class Error(val message: String, val retryable: Boolean) : HelpdeskDashboardUiState
}
```

### 4.3 ViewModel
```kotlin
@HiltViewModel
class HelpdeskDashboardViewModel @Inject constructor(
    private val metricsRepository: HelpdeskMetricsRepository,
    private val sessionRepository: SessionRepository,      // exposes cached Me / role
    queuePagerFactory: HelpdeskQueuePagerFactory           // from AND-161
) : ViewModel() {

    private val _uiState = MutableStateFlow<HelpdeskDashboardUiState>(Loading)
    val uiState: StateFlow<HelpdeskDashboardUiState> = _uiState.asStateFlow()

    private val _isRefreshing = MutableStateFlow(false)
    val isRefreshing: StateFlow<Boolean> = _isRefreshing.asStateFlow()

    // Preview queue (top page). Full queue lives in HelpdeskQueueScreen.
    val queuePreview: Flow<PagingData<QueueItem>> =
        queuePagerFactory.create(pageSize = 25).flow.cachedIn(viewModelScope)

    init { load(force = false) }

    fun load(force: Boolean) { /* role check -> AccessDenied OR fetch metrics */ }
    fun refresh() { /* set _isRefreshing, force reload + invalidate queue */ }
    fun retry() = load(force = true)
}
```
Role resolution: `sessionRepository.currentRole()` returns `HelpdeskAgentRole` derived from cached `Me.roles`. If not agent-capable → emit `AccessDenied`, skip network. Metrics fetch returns `ApiResult<HelpdeskMetrics>`; on `Success` emit `Content`; on `Failure` fall back to cache (`Content(isStale = true)`) if present, else `Error`. Empty payload (all-zero, no cache history) → `Empty`.

### 4.4 Repository
```kotlin
interface HelpdeskMetricsRepository {
    fun observeMetrics(): Flow<HelpdeskMetrics?>            // from Room
    suspend fun refreshMetrics(): ApiResult<HelpdeskMetrics> // network -> cache
}
```
`refreshMetrics()` calls `HelpdeskApi.getMetrics()`, maps DTO→domain, upserts the single-row `HelpdeskMetricsEntity`, and returns the result. `observeMetrics()` exposes the cached value so `Content` survives process death and offline.

### 4.5 Screen
```kotlin
@Composable
fun HelpdeskDashboardScreen(
    onOpenFullQueue: () -> Unit,
    onOpenConversation: (conversationId: String) -> Unit,
    viewModel: HelpdeskDashboardViewModel = hiltViewModel()
)
```
Layout: `Scaffold` + `TopAppBar("Helpdesk")`; body is `PullToRefreshBox` wrapping a `LazyColumn`: optional `StaleBanner`, `DashboardMetricsGrid` (`LazyVerticalGrid`/`FlowRow`, 2 columns compact / 3+ expanded via `WindowSizeClass`), a "Queue" section header with "View full queue" text button, then the queue preview items collected from `queuePreview`. `AccessDenied`, `Empty`, and `Error` render full-screen via `core-ui` state composables.

### 4.6 Navigation
```kotlin
const val HELPDESK_DASHBOARD_ROUTE = "helpdesk/dashboard"
fun NavGraphBuilder.helpdeskDashboard(
    onOpenFullQueue: () -> Unit,
    onOpenConversation: (String) -> Unit
) = composable(
    route = HELPDESK_DASHBOARD_ROUTE,
    deepLinks = listOf(navDeepLink { uriPattern = "testlogon://helpdesk/dashboard" })
) { HelpdeskDashboardScreen(onOpenFullQueue, onOpenConversation) }
```

## 5. API Contract

**Queue** (owned by AND-161, consumed here): `GET /messaging/helpdesk/queue` — paginated; reused via the existing paging source. Not redefined here.

**Metrics** (new for this ticket): the exact path/shape MUST be confirmed against `/openapi.json` and `frontend/src/api/endpoints/helpdesk.ts`. Expected:

```
GET /messaging/helpdesk/metrics
Headers: X-CSRF-Token: <ui_csrf>   (cookie session)
```
Response `200`:
```json
{
  "open": 42,
  "unassigned": 11,
  "assigned_to_me": 6,
  "sla_at_risk": 3,
  "avg_first_response_seconds": 540,
  "avg_resolution_seconds": 7200,
  "resolved_by_me_today": 9,
  "deltas": { "open": -4, "resolved_by_me_today": 2 },
  "generated_at": "2026-06-05T14:30:00Z"
}
```
Retrofit:
```kotlin
interface HelpdeskApi {
    @GET("messaging/helpdesk/metrics")
    suspend fun getMetrics(): HelpdeskMetricsDto
    // getQueue(...) defined by AND-161
}

@JsonClass(generateAdapter = true)
data class HelpdeskMetricsDto(
    @Json(name = "open") val open: Int,
    @Json(name = "unassigned") val unassigned: Int,
    @Json(name = "assigned_to_me") val assignedToMe: Int,
    @Json(name = "sla_at_risk") val slaAtRisk: Int,
    @Json(name = "avg_first_response_seconds") val avgFirstResponseSeconds: Long? = null,
    @Json(name = "avg_resolution_seconds") val avgResolutionSeconds: Long? = null,
    @Json(name = "resolved_by_me_today") val resolvedByMeToday: Int = 0,
    @Json(name = "deltas") val deltas: Map<String, Int> = emptyMap(),
    @Json(name = "generated_at") val generatedAt: String
)
```
**Error responses:** `401` → OkHttp auth interceptor performs `POST /ui/session/refresh` once then retries; persistent failure surfaces as retryable `Error`. `403` (authenticated but not agent) → non-retryable `Error("You don't have access to the helpdesk dashboard.")`, treated like `AccessDenied`. `4xx/5xx` `detail` parsed via the shared mapper. If the metrics endpoint does not exist server-side, this ticket falls back to deriving the four count metrics client-side from queue items and hides time-based metrics; record as Open Question Q1.

## 6. Data & State Management

- **Source of truth:** Room single-row metrics table + Paging 3 for the queue. `observeMetrics()` (Flow) feeds the ViewModel so cached data renders instantly and offline.
```kotlin
@Entity(tableName = "helpdesk_metrics")
data class HelpdeskMetricsEntity(
    @PrimaryKey val id: Int = 0,   // singleton row
    val open: Int, val unassigned: Int, val assignedToMe: Int, val slaAtRisk: Int,
    val avgFirstResponseSeconds: Long?, val avgResolutionSeconds: Long?,
    val resolvedByMeToday: Int, val deltasJson: String, val generatedAtEpoch: Long,
    val cachedAtEpoch: Long
)
```
```kotlin
@Dao interface HelpdeskMetricsDao {
    @Query("SELECT * FROM helpdesk_metrics WHERE id = 0") fun observe(): Flow<HelpdeskMetricsEntity?>
    @Upsert suspend fun upsert(e: HelpdeskMetricsEntity)
    @Query("DELETE FROM helpdesk_metrics") suspend fun clear()
}
```
- **Staleness:** `isStale = !networkSucceededThisLoad`; `cachedAt = cachedAtEpoch`. Relative time via `DateUtils.getRelativeTimeSpanString`.
- **Cache invalidation:** metrics cache cleared on logout (hook into `SessionRepository` logout) so a different agent never sees another's `assigned_to_me`/`resolved_by_me_today`.
- **State holding:** `StateFlow<UiState>` + separate `isRefreshing` flow; queue as `Flow<PagingData>` `cachedIn(viewModelScope)`. Survives config change via `hiltViewModel()`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call/connect/read 20s (shared `core-network` client). Metrics is an idempotent GET → eligible for bounded backoff retry (max 2 retries, 500ms→1s jitter) in the repository.
- **401:** handled centrally by the auth interceptor (single refresh + retry); ViewModel sees a final `ApiResult`.
- **Offline / failure with cache:** emit `Content(isStale = true)` + banner; never block the screen.
- **Offline / failure without cache:** `Error(message, retryable = true)` with retry button.
- **403 / non-agent:** `AccessDenied` (non-retryable).
- **Partial data:** null time-metrics render as `—`, not crashes. Unknown `deltas` keys ignored.
- **Refresh races:** `load()`/`refresh()` cancel any in-flight job (single `Job` ref) to avoid stale emissions.

## 8. Security & Privacy

- **Role enforcement:** client gating is UX only; the server is authoritative (403 honored). Never render metrics for non-agent roles even from a stale cache — clear cache on logout and re-check role on every entry.
- **Transport:** dev backend is plaintext HTTP; cleartext permitted only for the dev host via network-security-config (AND-120). No tokens in URLs; session rides cookies; `X-CSRF-Token` sent on requests via the shared interceptor.
- **PII:** metrics are aggregate counts/durations — low sensitivity; queue preview may contain requester identifiers (handled per AND-161). Do not log metric payloads at INFO. Room DB is app-private storage.
- **CSRF:** GET metrics still carries `X-CSRF-Token` per the shared client policy.

## 9. Accessibility & i18n

- All metric cards expose a merged `contentDescription` ("Open conversations: 42, down 4 since yesterday"). Numbers and labels meet 4.5:1 contrast (Material 3 tonal cards).
- Touch targets ≥48dp; "View full queue" and retry are focusable, TalkBack-labeled.
- Dynamic type respected (no fixed `sp` overrides on values); grid reflows at large font scales via `FlowRow`.
- All strings in `strings.xml` (`helpdesk_dashboard_*`); durations and relative times via platform formatters for locale correctness; no string concatenation for sentences — use `getString` placeholders. RTL-safe (logical paddings).

## 10. Telemetry & Logging

- Analytics events via the shared `Analytics` facade (core-data): `helpdesk_dashboard_viewed` (role), `helpdesk_dashboard_refreshed` (trigger=pull|retry), `helpdesk_dashboard_error` (code, retryable), `helpdesk_dashboard_full_queue_opened`.
- Logging via Timber: WARN on metrics fetch failure with HTTP code + parsed `detail` (no payload body); DEBUG for cache hit/stale fallback. No PII or full response bodies in logs.
- Surface `generated_at`/`cachedAt` in a debug overlay only in debug builds.

## 11. Testing Strategy

- **Unit (ViewModel, `core-testing` + Turbine):** non-agent role → `AccessDenied`, no API call; success → `Content(isStale=false)`; network fail with cache → `Content(isStale=true)`; network fail no cache → `Error(retryable=true)`; 403 → `AccessDenied`/non-retryable error; empty payload → `Empty`; `refresh()` toggles `isRefreshing` and invalidates queue. Use a fake `HelpdeskMetricsRepository` and `SessionRepository`.
- **Repository:** MockWebServer for `GET /messaging/helpdesk/metrics` — happy path maps DTO→domain→entity; 500 returns `Failure`; backoff retries idempotent GET; cache upsert/observe round-trip (Robolectric Room).
- **DAO:** in-memory Room upsert/observe/clear.
- **Compose UI tests:** each state renders its node (`Loading`/`Content`/`Empty`/`AccessDenied`/`Error`); pull-to-refresh invokes `refresh()`; "View full queue" invokes callback; metric card `contentDescription` assertions.
- **Acceptance test:** seeded agent `Me` + stubbed metrics → assert metric grid and queue preview render (covers §14).
- Targets: ViewModel/repository ≥85% line coverage; all UI states covered.

## 12. Dependencies & Sequencing

- **Depends on AND-161** (Helpdesk queue): provides `HelpdeskApi`, queue paging source/factory, `QueueItem`, `HelpdeskAgentRole`, and `feature-helpdesk` scaffolding. This ticket extends `HelpdeskApi` with `getMetrics()` and adds the dashboard layer above the queue.
- **Transitively** depends on AND-120 (network/session/cookie jar) via AND-161.
- **Sequencing:** land after AND-161 merges. Confirm the metrics endpoint exists in `/openapi.json`; if absent, implement client-side derivation fallback (Q1) and file a backend ticket.
- **Blocks:** none recorded in backlog.

## 13. Risks & Open Questions

- **Q1 (metrics endpoint existence):** `GET /messaging/helpdesk/metrics` is assumed. If the dev backend lacks it, ship count-only metrics derived from the queue and gate time-based cards behind the endpoint. Reconcile with `/openapi.json` before coding.
- **Q2 (role taxonomy):** exact `Me.roles` values for agent/supervisor/admin must be confirmed against `/ui/me`; gating set is a single source-of-truth constant.
- **Q3 (assigned_to_me / resolved_by_me_today scope):** server must scope these to the calling agent; verify, else they leak across agents.
- **Risk:** unreliable dev host → mitigated by 20s timeouts, bounded GET retry, cache-backed stale UI.
- **Risk:** SLA/duration semantics (seconds vs ms, business hours) — confirm units with backend; DTO assumes seconds.

## 14. Acceptance Criteria

1. **(Backlog) Dashboard renders for agent role:** an authenticated user whose `/ui/me` role is agent-capable, navigating to `helpdesk/dashboard`, sees the metric grid populated from `GET /messaging/helpdesk/metrics` and the embedded queue preview.
2. A non-agent authenticated user sees `AccessDenied` and no metrics request is issued.
3. Metric cards display open, unassigned, assigned-to-me, SLA-at-risk counts plus avg first-response, avg resolution, and resolved-by-me-today (null durations show `—`).
4. Pull-to-refresh re-fetches metrics and invalidates the queue; `isRefreshing` reflects progress.
5. With no network but a prior cache, the dashboard renders cached metrics with a stale/cached banner.
6. With no network and no cache, a retryable error state with a working Retry button is shown.
7. "View full queue" navigates to `HelpdeskQueueScreen`; tapping a preview row invokes `onOpenConversation`.
8. 401 during metrics fetch triggers a single session refresh + retry transparently.

## 15. Definition of Done

- Code merged to `android-port` under `feature-helpdesk/dashboard` with package base `com.testlogon.android`, building on Gradle 8.9 / AGP 8.7.3 / JDK 17.
- All 15 functional requirements and acceptance criteria met; metric contract reconciled with `/openapi.json` (or Q1 fallback implemented and documented).
- Unit, repository, DAO, and Compose UI tests pass in CI; coverage targets met.
- Lint/detekt/ktlint clean; no new cleartext exemptions beyond the dev host; strings externalized; TalkBack pass on all states.
- No PII or response bodies logged; telemetry events firing; cache cleared on logout.
- PR reviewed; demo on dev backend showing agent dashboard, refresh, stale, and access-denied states.
