---
id: AND-377
title: Helpdesk agent dashboard
milestone: M8
epic: E49
priority: P2
size: M
depends_on: [AND-161]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-377 — Helpdesk agent dashboard

## 1. Overview & Goal

Build a native Android **Helpdesk Agent Dashboard** that gives support agents an at-a-glance operational view of the helpdesk: the live conversation queue (reusing the queue surface delivered by AND-161) plus a set of agent-facing **metrics** (open/unassigned/assigned-to-me counts, SLA-at-risk count, average first-response and resolution times, and the agent's own throughput for the day). The dashboard is the agent's landing screen inside the helpdesk feature and is gated to agent-capable users. **Correction (review):** the web reference does **not** derive helpdesk role from `/ui/me` — `MeResp` only carries `{user_sub, session_id, ip}` (see `src/api/types.ts: MeResp`; OpenAPI `GET /ui/me` documents an untyped `{}` body). The canonical signal is the **queue 403**: the web client treats a successful `GET /messaging/helpdesk/queue` as "is an agent" and a `403` as "not an agent" (`isAgent = !queueError`, with `silent403`). The Android gate MUST mirror this (attempt the agent-scoped fetch; `403` ⇒ AccessDenied), not a client-cached role list. See §16 Corrections.

The goal is a single Compose screen, `HelpdeskDashboardScreen`, backed by `HelpdeskDashboardViewModel`, that:

- Resolves whether the current user is agent-capable (via the queue-403 probe — see §1 correction) and renders the dashboard **only** for agents; non-agents see an access-denied state and are routed away.
- Loads metrics from the backend, renders them as a responsive grid of metric cards, and embeds (or links to) the AND-161 queue list.
- Tolerates the unreliable dev backend with explicit loading / stale / offline / empty / error states and pull-to-refresh.

This ticket owns the dashboard composition, the metrics data path, and role gating. It does **not** re-implement the queue list itself (AND-161) nor individual conversation handling (downstream messaging tickets).

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, branch `android-port`, Android app under `android/`. New code lives in `feature-helpdesk` (created by AND-161); shared pieces in `core-network`, `core-model`, `core-data`, `core-ui`. Package base `com.testlogon.android`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Paging 3. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Dependency AND-161 (Helpdesk queue):** provides `HelpdeskQueueScreen`, the queue data source over `GET /messaging/helpdesk/queue`, the `HelpdeskApi` Retrofit interface, and the queue item model. This ticket **reuses** those rather than duplicating them.
  - **Correction (review):** `GET /messaging/helpdesk/queue` returns a **plain JSON array of `ConversationOut`** (no cursor/page envelope); query params are `group_id` (**required**, maxLength 128), `state` (optional), `limit` (optional, default **50**, max **200**). The web client (`src/api/endpoints/messaging.ts: getHelpdeskQueue`) passes only `group_id` (+ optional `state`) and is **not** paginated. Therefore the "`HelpdeskQueuePagingSource` / `QueueItem` / Paging 3 default 25 / cursor" details are **unverified assumptions about AND-161's internal design** — the underlying endpoint is a bounded-`limit` array, not a true paged feed. Treat the queue item type as AND-161's domain model mapped from `ConversationOut` (web uses `Conversation`). The required `group_id` (web default `e2e-helpdesk` from `VITE_HELPDESK_GROUP_ID`) MUST be supplied by AND-161; this ticket inherits it.
- **Auth/session:** session established via `/ui/session/start` → MFA → `/ui/session/finalize`; transport is **both** an `Authorization: Bearer <accessToken>` header (from the auth store) **and** cookies (`credentials: include`). The `ui_csrf` cookie is echoed as `X-CSRF-Token` on every request including GETs (verified `src/api/client.ts`). 401 → single `POST /ui/session/refresh` then retry once (verified `client.ts: refreshSession`/retry path; OpenAPI `POST /ui/session/refresh`). Persistent cookie jar provided by `core-network` (AND-120). **Correction (review):** role does **not** come from `GET /ui/me` (it returns only `{user_sub, session_id, ip}`); agent capability is inferred from the queue-403 probe (see §1).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference: `src/api/endpoints/*.ts`, types in `src/api/types.ts`. **Correction (review):** there is **no** `frontend/src/api/endpoints/helpdesk.ts`; helpdesk calls live in `src/api/endpoints/messaging.ts` (`getHelpdeskQueue`, `claimHelpdeskConversation`, `startHelpdeskConversation`). There is **no helpdesk metrics endpoint** anywhere in the OpenAPI index or the web client — see §5 / Q1; the metrics data path in §5 is an unverified assumption and the Q1 client-side-derivation fallback is the realistic primary path.
- **Error mapping:** FastAPI `detail` is `string | [{msg}] | {code,...}`; map via the shared `ApiResult<T>` and `detail`-parsing helper in `core-network`.

## 3. Functional Requirements

FR-1. **Role gating.** **Corrected (review):** because `/ui/me` does not expose a helpdesk role (`MeResp = {user_sub, session_id, ip}`), gating cannot be a pure client-side cached-role check. Mirror the web contract: the dashboard issues the agent-scoped queue fetch (`GET /messaging/helpdesk/queue`, with `silent403`-equivalent suppression); a **`403`** ⇒ `AccessDenied`, a `200` ⇒ agent ⇒ proceed. If/when the server later exposes a role on `/ui/me` or a dedicated capability endpoint, gating MAY be hardened to read it, but the 403 remains authoritative. The `{agent, supervisor, admin}` set is an **unverified assumption** (Q2) — do not hardcode role strings as the gate.

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
Role resolution: **Corrected (review)** — `Me.roles` does not exist, so there is no `currentRole()` derivable from `/ui/me`. Instead the ViewModel attempts the agent-scoped fetch; a `403` ⇒ `AccessDenied`. (If AND-161 already exposes an "am I an agent" signal from its own queue probe, reuse it rather than issuing a duplicate request.) Metrics fetch returns `ApiResult<HelpdeskMetrics>`; on `Success` emit `Content`; on `Failure` fall back to cache (`Content(isStale = true)`) if present, else `Error`. Empty payload (all-zero, no cache history) → `Empty`.

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

**Queue** (owned by AND-161, consumed here): `GET /messaging/helpdesk/queue` — **Corrected (review):** returns a plain `ConversationOut[]` array (not a paged envelope); params `group_id` (required), `state` (optional), `limit` (default 50, max 200). Reused via AND-161's data source. Not redefined here.

> **CRITICAL CORRECTION (review):** The metrics endpoint below **does not exist**. A grep of `reference/openapi.index.txt` for `helpdesk` returns exactly two operations — `GET /messaging/helpdesk/queue` and `POST /messaging/helpdesk/conversations/{conversation_id}/claim` — and no `metrics` path under `/messaging/helpdesk/*` exists anywhere in the index (the only `metrics` endpoints are unrelated: ad-platform, agents, kyc, compute). The web client has no metrics call and no dashboard (`src/pages/helpdesk/HelpdeskPage.tsx` shows a queue + the user's own support chats only). **Therefore the JSON/DTO below is an UNVERIFIED, SPECULATIVE contract.** Implementation MUST either (a) confirm a real metrics endpoint is added server-side (file the backend ticket per Q1) before consuming it, or (b) ship the **Q1 fallback as the primary path**: derive the four count metrics (open/unassigned/assigned-to-me/SLA-at-risk) client-side from queue `ConversationOut.routing_state`/`active_agent_user_id`, and hide all time-based and throughput cards (no client source exists for `avg_first_response`, `avg_resolution`, `resolved_by_me_today`).

**Metrics** (new for this ticket — SPECULATIVE, see correction above): the exact path/shape MUST be confirmed against `/openapi.json`. Speculative expected shape:

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
**Error responses:** `401` → auth interceptor performs `POST /ui/session/refresh` once then retries (verified against `src/api/client.ts`: single shared `refreshPromise`, retry once, logout on second 401). Persistent failure surfaces as retryable `Error`. `403` (authenticated but not agent) → treated like `AccessDenied` (this is the canonical agent gate per §1; web uses `silent403` so no toast). Validation `4xx` (`422`) `detail` is a FastAPI **array of `{loc, msg, type}`** objects (verified: `components.schemas.HTTPValidationError` → `ValidationError[]`); other authorization errors may instead return `detail` as a **string** or a **`{code, ...}` object** (e.g. `role_required`, `helpdesk_claim_required`; verified `client.ts: mapAuthorizationError`). Parse all three shapes via the shared `detail` mapper (mirror `normalizeErrorDetail`). Per the correction above, if the metrics endpoint does not exist server-side (the current reality), the Q1 client-side-derivation fallback is the primary path.

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
- **Transport:** dev backend is plaintext HTTP; cleartext permitted only for the dev host via network-security-config (AND-120). No tokens in URLs. **Corrected (review):** the web client authenticates with **both** an `Authorization: Bearer <accessToken>` header **and** cookies (`credentials: include`); the Android client (AND-120) should match that dual scheme. `X-CSRF-Token` (value from the `ui_csrf` cookie) is sent on **every** request including GETs via the shared interceptor (verified `src/api/client.ts`).
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
- **Q2 (role taxonomy):** **Resolved by review — `/ui/me` exposes NO roles** (`MeResp = {user_sub, session_id, ip}`; OpenAPI body `{}`). There is no client-readable agent/supervisor/admin role list. Gating is therefore the queue-403 probe (see §1/FR-1), not a role constant. The `{agent, supervisor, admin}` set remains an unverified assumption and must not be the gate.
- **Q3 (assigned_to_me / resolved_by_me_today scope):** server must scope these to the calling agent; verify, else they leak across agents.
- **Risk:** unreliable dev host → mitigated by 20s timeouts, bounded GET retry, cache-backed stale UI.
- **Risk:** SLA/duration semantics (seconds vs ms, business hours) — confirm units with backend; DTO assumes seconds.

## 14. Acceptance Criteria

1. **(Backlog) Dashboard renders for agent role:** an authenticated agent-capable user (i.e. `GET /messaging/helpdesk/queue` returns `200`, not `403` — see §1 correction; **not** a `/ui/me` role), navigating to `helpdesk/dashboard`, sees the metric grid (populated from a confirmed metrics endpoint **or** the Q1 client-derived counts — see §5 critical correction) and the embedded queue preview.
2. A non-agent authenticated user (queue probe returns `403`) sees `AccessDenied`; no further agent-scoped/metrics request is issued after the gating `403`.
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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer. Sources: OpenAPI = `reference/openapi.index.txt` / `reference/openapi.pretty.json`; frontend paths are under `reference/src/`.

1. **Helpdesk queue endpoint is `GET /messaging/helpdesk/queue`.** VERIFIED. OpenAPI `GET /messaging/helpdesk/queue` (index line 394, op `get_helpdesk_queue_messaging_helpdesk_queue_get`); `src/api/endpoints/messaging.ts: getHelpdeskQueue`.
2. **Queue params: `group_id` (required, maxLength 128), `state` (optional), `limit` (optional, default 50, max 200).** VERIFIED. `openapi.pretty.json` operation `get_helpdesk_queue_*` parameters block; web passes `group_id` (+ optional `state`) only.
3. **Queue response is a plain `ConversationOut[]` array, not a paged envelope.** VERIFIED → **CORRECTED** spec (§2/§5 had "paginated"). OpenAPI 200 schema = array of `#/components/schemas/ConversationOut`; `getHelpdeskQueue` returns `Conversation[]` (`src/api/types.ts: Conversation`).
4. **Web client requires a helpdesk group id (`VITE_HELPDESK_GROUP_ID`, default `e2e-helpdesk`).** VERIFIED. `src/pages/helpdesk/HelpdeskPage.tsx` (`HELPDESK_GROUP_ID`).
5. **`GET /messaging/helpdesk/metrics` exists.** **CORRECTED → does NOT exist.** Grep of `openapi.index.txt` for `helpdesk` yields only the queue and claim ops; grep for `metrics` yields only unrelated paths (ad-platform/agents/kyc/compute). No helpdesk metrics call in the web client; `HelpdeskPage.tsx` has no dashboard/metrics. The §5 DTO is speculative.
6. **No `frontend/src/api/endpoints/helpdesk.ts` file.** CORRECTED. Helpdesk calls live in `src/api/endpoints/messaging.ts` (`getHelpdeskQueue`, `claimHelpdeskConversation`, `startHelpdeskConversation`).
7. **Role comes from `GET /ui/me` / `Me.roles`.** **CORRECTED → false.** `src/api/types.ts: MeResp` = `{user_sub, session_id, ip}` (no roles); OpenAPI `GET /ui/me` (index line 1638) documents an untyped `{}` 200 body. No client-readable role.
8. **Agent gating is the queue-403 probe.** VERIFIED (now the spec's gate). `src/pages/helpdesk/HelpdeskPage.tsx`: `isAgent = !queueError`, `getHelpdeskQueue(..., { silent403: true })`; `src/api/endpoints/messaging.ts: getHelpdeskQueue` (`silent403`).
9. **`ui_csrf` cookie echoed as `X-CSRF-Token` on all requests (incl. GET).** VERIFIED. `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)` unconditionally).
10. **Transport uses `Authorization: Bearer` header in addition to cookies.** VERIFIED → spec amended (§2/§8 said cookie-only). `src/api/client.ts` sets `Authorization: Bearer <accessToken>` and `credentials: "include"`.
11. **401 → single `POST /ui/session/refresh` then retry once.** VERIFIED. `src/api/client.ts` (`refreshSession`, shared `refreshPromise`, single retry, logout on second 401); OpenAPI `POST /ui/session/refresh` (index line 1847).
12. **Session start/finalize endpoints.** VERIFIED. OpenAPI `POST /ui/session/start` (req `UiSessionStartReq`, resp `UiSessionStartResp`, index line 1848); `POST /ui/session/finalize` (req `UiSessionFinalizeReq`, index line 1845).
13. **403 for non-agents is surfaced silently (no toast) on the queue.** VERIFIED. `src/api/client.ts` 403 branch honors `silent403`; `getHelpdeskQueue` passes it.
14. **FastAPI validation `detail` is an array of `{loc,msg,type}`; other auth errors use string or `{code,...}`.** VERIFIED. `components.schemas.HTTPValidationError` → `detail: ValidationError[]`; `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError` handle string, array-of-`{msg}`, and `{code}` (e.g. `helpdesk_claim_required`).
15. **Claim endpoint `POST /messaging/helpdesk/conversations/{conversation_id}/claim` → `HelpdeskClaimOut`.** VERIFIED (context for AND-161 reuse). OpenAPI index line 393; `src/api/types.ts: HelpdeskClaimOut`; `src/api/endpoints/messaging.ts: claimHelpdeskConversation`.
16. **AND-161 exposes `QueueItem` / `HelpdeskAgentRole` / `HelpdeskQueuePagingSource` / Paging 3 (page 25).** UNVERIFIED-ASSUMPTION. These are internal to the (not-yet-merged) AND-161; no source available here, and the underlying endpoint is a bounded-`limit` array, not a cursor feed — so a true `PagingSource` is not implied by the backend.
17. **Stack/build versions (Kotlin 2.0.21, AGP 8.7.3, Gradle 8.9, Compose M3, Hilt, Room, Paging 3), `PullToRefreshBox`, `WindowSizeClass`, `DateUtils.getRelativeTimeSpanString`.** UNVERIFIED-ASSUMPTION for the repo (no Android sources provided); these are standard Android framework/Jetpack APIs (framework ref: developer.android.com — `androidx.compose.material3.pulltorefresh.PullToRefreshBox`, `androidx.paging`, `android.text.format.DateUtils#getRelativeTimeSpanString`).
18. **Metrics units are seconds; `assigned_to_me`/`resolved_by_me_today` are per-agent; SLA semantics.** UNVERIFIED-ASSUMPTION. No metrics endpoint exists to confirm (see #5); carried as Q3/Q1/§13 risks.
19. **Dev host `http://18.222.237.167:8000`, plaintext HTTP.** UNVERIFIED here (not in OpenAPI/frontend sources provided); carried from AND-120/ticket context as an assumption.

### Corrections made

- §1, §2, FR-1, §4.3, §13-Q2: role is **not** from `/ui/me` (`MeResp` has no roles; `/ui/me` body is `{}`). Gating is the queue-403 probe (`isAgent = !queueError`).
- §2, §5: queue is a **`ConversationOut[]` array** with `limit` (default 50/max 200), **not** a paged envelope; required `group_id`. "Paging 3 / `QueueItem` / cursor" demoted to AND-161-internal assumptions.
- §2, §5, §14: **no `/messaging/helpdesk/metrics` endpoint exists**; the metrics DTO is speculative; Q1 client-side derivation is the primary realistic path.
- §2: corrected the helpdesk file path (`messaging.ts`, not `helpdesk.ts`).
- §2, §8: transport is `Authorization: Bearer` **plus** cookies + `X-CSRF-Token` on all requests, not cookie-only.
- §5: refined the error-`detail` shapes to the verified union (array `{loc,msg,type}` | string | `{code,...}`).

### Open assumptions

- **Metrics contract (path, fields, units, per-agent scoping).** Unverifiable: the endpoint does not exist in the provided OpenAPI/frontend; cannot be confirmed until backend adds it (Q1/Q3). Until then, only client-derived counts from queue items are sound.
- **AND-161 internals** (`QueueItem`, paging source/factory, `HelpdeskAgentRole`, `feature-helpdesk` scaffolding). Unverifiable: dependency not merged and no Android source in the reference set.
- **Android repo build configuration and module layout.** Unverifiable: no `android/` sources provided; taken from ticket context.
- **Role taxonomy `{agent, supervisor, admin}`.** Unverifiable and contradicted by the absence of any role field; must not be hardcoded as the gate.
- **Dev host address / cleartext exemption.** Not present in provided sources; inherited from AND-120 context.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless emulator AVD `test35` (x86_64, Android 15 / API 35); **deviceA15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). For this ticket (data/UI, no camera/biometrics/WebRTC/FCM), most instrumented/Compose cases run fine on **emu35**; one ABI/API-skew sanity pass is pinned to **deviceA15**.

- **TC-AND-377-01 — Agent happy path renders metrics + queue preview.** Type: unit (ViewModel, Turbine). Target: JVM. Preconditions: fake gate returns agent (queue probe `200`); fake metrics source returns a populated `HelpdeskMetrics`; queue preview emits items. Steps: construct ViewModel, collect `uiState`. Expected: terminal state `Content(isStale=false)` with all counts; `queuePreview` emits non-empty `PagingData`. Traces: AC-1, AC-3.
- **TC-AND-377-02 — Non-agent gating (403) ⇒ AccessDenied, no metrics fetch.** Type: unit (ViewModel). Target: JVM. Preconditions: gate/queue probe returns `403`. Steps: init ViewModel; collect state; inspect fake metrics source call count. Expected: `AccessDenied`; metrics fetch invoked 0 times after the gating 403. Traces: AC-2.
- **TC-AND-377-03 — Queue contract (MockWebServer): array response, correct params.** Type: contract/MockWebServer. Target: JVM (Robolectric). Preconditions: MockWebServer enqueues a `200` JSON **array** of `ConversationOut`. Steps: call the queue fetch via the real Retrofit/OkHttp stack. Expected: request path `/messaging/helpdesk/queue` with query `group_id` present (and `limit`≤200 if sent); response deserializes to a list (no envelope); `X-CSRF-Token` header present. Traces: AC-1, AC-7.
- **TC-AND-377-04 — Metrics fallback (Q1): endpoint 404 ⇒ counts derived from queue, time cards hidden.** Type: contract/MockWebServer. Target: JVM (Robolectric). Preconditions: metrics request returns `404`; queue returns a known array with mixed `routing_state`/`active_agent_user_id`. Steps: refresh metrics. Expected: `Content` with open/unassigned/assigned-to-me/SLA counts derived from queue items; `avgFirstResponseSeconds`/`avgResolutionSeconds`/`resolvedByMeToday` null/hidden (render `—`). Traces: AC-1, AC-3.
- **TC-AND-377-05 — 422 validation error detail parsing.** Type: contract/MockWebServer. Target: JVM. Preconditions: server returns `422` with `{"detail":[{"loc":["query","group_id"],"msg":"field required","type":"missing"}]}`. Steps: trigger fetch; map via shared `detail` parser. Expected: `Error` carries the joined `msg` ("field required"); no crash on array shape. Traces: AC-6.
- **TC-AND-377-06 — Offline/failure WITH cache ⇒ stale Content + banner.** Type: unit + Robolectric Room round-trip. Target: JVM. Preconditions: Room has a prior metrics row; network call fails (IOException). Steps: refresh. Expected: `Content(isStale=true, cachedAt=...)`; stale banner data present; screen not blocked. Traces: AC-5.
- **TC-AND-377-07 — Offline/failure WITHOUT cache ⇒ retryable Error; retry works.** Type: unit (ViewModel). Target: JVM. Preconditions: empty Room cache; first network call fails, second succeeds. Steps: init ⇒ assert `Error(retryable=true)`; call `retry()` ⇒ assert `Content`. Expected: error then recovery; `isRefreshing` toggles. Traces: AC-6, AC-4.
- **TC-AND-377-08 — 401 ⇒ single session refresh + retry transparent.** Type: contract/MockWebServer. Target: JVM (Robolectric). Preconditions: enqueue `401`, then `200` for the retried request; refresh interceptor wired (single-flight). Steps: issue the GET. Expected: exactly one `POST /ui/session/refresh`, original request retried once, caller sees `200`/`Content`; a second consecutive `401` ⇒ terminal auth `Error` (no infinite loop). Traces: AC-8.
- **TC-AND-377-09 — Pull-to-refresh re-fetches metrics and invalidates queue.** Type: Compose-UI. Target: emu35. Preconditions: ViewModel in `Content`; spy on `refresh()` and queue invalidation. Steps: perform `PullToRefreshBox` swipe gesture. Expected: `refresh()` invoked once; `isRefreshing` shows then clears; queue paging invalidated. Traces: AC-4.
- **TC-AND-377-10 — Each UI state renders its node.** Type: Compose-UI. Target: emu35. Preconditions: drive ViewModel/state into `Loading`, `Content`, `Empty`, `AccessDenied`, `Error`. Steps: assert the distinguishing node/test-tag per state; "View full queue" and Retry are clickable in the relevant states. Expected: correct composable shown for each; "View full queue" invokes `onOpenFullQueue`, a preview row invokes `onOpenConversation`. Traces: AC-3, AC-5, AC-6, AC-7.
- **TC-AND-377-11 — Accessibility: metric card contentDescription + touch targets + TalkBack.** Type: Compose-UI (a11y assertions). Target: emu35. Preconditions: `Content` with deltas. Steps: assert each card exposes a merged `contentDescription` (e.g. "Open conversations: 42, down 4 since yesterday"); assert actionable elements ≥48dp and are focusable/labeled. Expected: a11y assertions pass; dynamic-type reflow does not clip. Traces: AC-3.
- **TC-AND-377-12 — Security: cache cleared on logout (no cross-agent leakage).** Type: integration (Robolectric Room + SessionRepository hook). Target: JVM. Preconditions: agent A's metrics cached (assigned-to-me/resolved-by-me populated). Steps: trigger logout. Expected: `helpdesk_metrics` table cleared; a subsequent observe returns null so agent B never sees A's per-agent values. Traces: AC-2, AC-5.
- **TC-AND-377-13 — Deep link + flaky dev host e2e on physical device.** Type: instrumented/e2e. Target: **deviceA15 (MUST)**. Preconditions: app installed on the A15; signed-in agent session; dev host reachable but intermittently failing (toggle Wi-Fi mid-test to exercise offline/stale). Rationale for device: validates arm64-v8a / API-34 behavior vs the x86_64/API-35 emulator and real-network flakiness. Steps: open `testlogon://helpdesk/dashboard`; observe load; disable network and pull-to-refresh; re-enable and retry. Expected: dashboard opens via deep link; offline shows cached/stale banner (or retryable error if no cache); recovery on retry; no ANR/crash under flaky network. Traces: AC-1, AC-4, AC-5, AC-6.
- **TC-AND-377-14 — Empty payload ⇒ Empty state.** Type: unit (ViewModel). Target: JVM. Preconditions: agent; metrics source returns all-zero counts with no cache history (and, in Q1 mode, an empty queue). Steps: init. Expected: `Empty` state (not `Content`/`Error`). Traces: AC-1, AC-3.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 Dashboard renders for agent (queue 200) + metrics/derived + queue preview | TC-01, TC-03, TC-04, TC-13, TC-14 |
| AC-2 Non-agent (403) ⇒ AccessDenied, no further fetch | TC-02, TC-12 |
| AC-3 Metric cards incl. null durations show `—` | TC-01, TC-04, TC-10, TC-11, TC-14 |
| AC-4 Pull-to-refresh re-fetches + invalidates queue; `isRefreshing` | TC-07, TC-09, TC-13 |
| AC-5 No network + cache ⇒ stale/cached banner | TC-06, TC-10, TC-12, TC-13 |
| AC-6 No network + no cache ⇒ retryable Error + Retry | TC-05, TC-07, TC-10, TC-13 |
| AC-7 "View full queue" / row tap callbacks | TC-03, TC-10 |
| AC-8 401 ⇒ single refresh + retry transparently | TC-08 |
