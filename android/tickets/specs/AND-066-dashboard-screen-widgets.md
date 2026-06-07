---
id: AND-066
title: Dashboard screen + widgets
milestone: M2
epic: E09
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-065, AND-024]
blocks: []
---

# AND-066 — Dashboard screen + widgets

## 1. Overview & Goal

Implement the authenticated **Dashboard** as the post-login landing destination of the TestLogon Android app. The screen is the `Home` tab of the bottom-nav scaffold delivered in AND-024 and consumes the `DashboardRepository` / `DashboardApi` data layer delivered in AND-065. It renders real backend data as a vertical list of **widget cards** (summary KPIs, recent activity, and quick-link shortcuts), supports **pull-to-refresh**, and exposes resilient loading / empty / error / offline-stale states appropriate for the unreliable dev backend.

This ticket owns the **presentation layer only**: the `DashboardViewModel`, its `DashboardUiState`, the Compose `DashboardScreen`, and the individual widget composables. It must not introduce new networking or DTO-mapping code — all I/O flows through the repository from AND-065. Success means: opening the app after login shows the dashboard populated with live data from `GET /ui/dashboard/summary` (the endpoint exposed by `dashboard.ts`; **note: there is no `GET /ui/dashboard`** — corrected during review), and pulling down re-fetches and visibly updates the cards.

Goal acceptance (from backlog): *Renders real data; refresh works.*

## 2. Context & References

- **Module:** `feature-dashboard` (new screen-layer additions; data layer already created in AND-065).
- **Layering:** `app → feature-dashboard → core-* (core-ui, core-model, core-data)`. The screen depends on `core-ui` (theme, shared scaffolding, `ApiResult` mapping helpers) and `core-model` (domain `Dashboard` types). It must NOT depend on `core-network` directly.
- **Namespace:** `com.testlogon.android.feature.dashboard`.
- **Dependencies:**
  - **AND-065 — Dashboard data layer:** provides `DashboardRepository`, `DashboardApi`, and the domain model `Dashboard` mapped from `dashboard.ts` DTOs. This ticket consumes `repository.observeDashboard()` / `repository.refresh()`.
  - **AND-024 — Authenticated nav graph + bottom nav skeleton:** provides the `Home` route placeholder that this screen replaces and the `NavController` wiring used by quick-link navigation.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`. Auth (per web `src/api/client.ts`): cookie session (`credentials: include`) **plus** an `Authorization: Bearer <accessToken>` header from the auth store **plus** an `X-CSRF-Token` header read from the `ui_csrf` cookie (corrected during review — the web client uses bearer + cookie + CSRF, not cookie-only). 401 → single `POST /ui/session/refresh` retry, then the original request is replayed (handled by the OkHttp `Authenticator`/interceptor stack in core-network; out of scope here). Network/offline failures surface from the client as a status-0 error (`ApiError(0, "Network error")`).
- **Web reference:** `src/api/endpoints/dashboard.ts` (calls `getDashboardSummary` → `GET /ui/dashboard/summary` and `refreshDashboard` → `POST /ui/dashboard/refresh`), shared types in `src/api/types.ts` (`DashboardSummary`). NOTE: the web `src/pages/Dashboard.tsx` screen does **not** call `/ui/dashboard/summary`; it aggregates several feature endpoints (messaging, billing, files, alerts, cart, calendar) and renders Recent Activity from the **alerts** endpoint. The Android port instead consumes the consolidated `/ui/dashboard/summary` DTO via AND-065. AND-065 is the authority for the exact DTO→domain mapping.

## 3. Functional Requirements

1. **Landing destination.** The dashboard is the default selected tab (`Home`) of the authenticated bottom-nav graph. Navigating to it triggers an automatic initial load if no cached data is present.
2. **Widget cards.** Render an ordered, scrollable list of cards driven by domain data:
   - **Summary / KPI card(s):** headline metrics (e.g., total sessions, active count) shown as a labeled value grid.
   - **Recent activity card:** a bounded list (max 5 rows) of recent activity items with title + relative timestamp; an overflow row links to the full list (quick link).
   - **Quick links card:** a row/grid of shortcut buttons (e.g., Profile/Me, Sessions, Settings) that navigate within the authenticated graph.
3. **Pull-to-refresh.** A Material 3 `PullToRefreshBox` wraps the list. Pulling triggers `viewModel.refresh()`; the indicator is visible while the refresh is in flight and dismisses on completion (success or failure).
4. **Initial load state.** Before first data arrives, show skeleton placeholders (shimmer) for the card layout, not a bare spinner over a blank screen.
5. **Stale data on refresh failure.** If cached/previous data exists and a refresh fails, keep showing the data and surface a non-blocking error (Snackbar / inline banner) — never blank the screen.
6. **Empty state.** If the backend returns a well-formed but empty payload, show a friendly empty state with a Retry action.
7. **Hard error state.** If there is no cached data and the load fails, show a full-screen error with a Retry button that calls `viewModel.refresh()`.
8. **Quick-link navigation.** Each quick link / overflow row invokes a typed navigation callback hoisted from the screen; the screen does not hold a `NavController` reference directly.
9. **Reads + a rate-limited refresh trigger.** The summary read is an idempotent `GET /ui/dashboard/summary`. Pull-to-refresh additionally fires `POST /ui/dashboard/refresh` (corrected during review — refresh is a non-idempotent, **rate-limited** POST, not just a GET re-fetch), then re-reads the summary. No other mutating calls originate from this screen, and refresh must be debounced/guarded so it cannot be hammered into 429s.

## 4. Technical Design

### 4.1 State model

```kotlin
package com.testlogon.android.feature.dashboard

import com.testlogon.android.core.model.Dashboard

data class DashboardUiState(
    val data: Dashboard? = null,          // last-known good payload (may be stale)
    val isInitialLoading: Boolean = false, // true only before first data
    val isRefreshing: Boolean = false,     // pull-to-refresh in flight
    val isStale: Boolean = false,          // showing cached data after a failed refresh
    val errorMessage: String? = null,      // user-facing, mapped from ApiResult
    val transientError: String? = null,    // one-shot banner/snackbar after refresh failure
) {
    val isEmpty: Boolean get() = data?.isEmpty == true
    val showFullScreenError: Boolean get() = data == null && errorMessage != null
}
```

### 4.2 ViewModel

```kotlin
@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val repository: DashboardRepository, // from AND-065
) : ViewModel() {

    private val _uiState = MutableStateFlow(DashboardUiState(isInitialLoading = true))
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    init {
        // Observe cached (Room/DataStore-backed) dashboard from the repository.
        viewModelScope.launch {
            repository.observeDashboard().collect { cached ->
                _uiState.update { it.copy(data = cached ?: it.data) }
            }
        }
        refresh(isInitial = true)
    }

    fun refresh(isInitial: Boolean = false) {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isRefreshing = !isInitial,
                    isInitialLoading = isInitial && it.data == null,
                )
            }
            when (val result = repository.refresh()) { // ApiResult<Dashboard>
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        data = result.value,
                        isInitialLoading = false,
                        isRefreshing = false,
                        isStale = false,
                        errorMessage = null,
                        transientError = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    val msg = result.toUserMessage() // core-ui error mapper
                    it.copy(
                        isInitialLoading = false,
                        isRefreshing = false,
                        isStale = it.data != null,
                        errorMessage = if (it.data == null) msg else it.errorMessage,
                        transientError = if (it.data != null) msg else null,
                    )
                }
            }
        }
    }

    fun consumeTransientError() = _uiState.update { it.copy(transientError = null) }
}
```

`repository.refresh()` returns `ApiResult<Dashboard>` and is expected to write through to the cache, so `observeDashboard()` emits the fresh value. The ViewModel does not parse JSON or touch Retrofit.

### 4.3 Composables

```kotlin
@Composable
fun DashboardRoute(
    onOpenProfile: () -> Unit,
    onOpenSessions: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenActivity: () -> Unit,
    viewModel: DashboardViewModel = hiltViewModel(),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    state: DashboardUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onQuickLink: (QuickLink) -> Unit,
    onErrorShown: () -> Unit,
)
```

`DashboardScreen` is stateless (state hoisted) for previewability and testing. It composes a `PullToRefreshBox` over a `LazyColumn`:

```kotlin
PullToRefreshBox(
    isRefreshing = state.isRefreshing,
    onRefresh = onRefresh,
    state = rememberPullToRefreshState(),
) {
    when {
        state.isInitialLoading -> DashboardSkeleton()
        state.showFullScreenError -> DashboardErrorState(state.errorMessage!!, onRetry)
        state.isEmpty -> DashboardEmptyState(onRetry)
        else -> LazyColumn(Modifier.fillMaxSize().testTag("dashboard_list")) {
            item { SummaryWidget(state.data!!.summary) }
            item { RecentActivityWidget(state.data.recentActivity, onSeeAll = { onQuickLink(QuickLink.Activity) }) }
            item { QuickLinksWidget(onQuickLink = onQuickLink) }
        }
    }
}
```

Widget composables (each in its own file under `feature/dashboard/widgets/`):
`SummaryWidget(summary: DashboardSummary)`, `RecentActivityWidget(items: List<ActivityItem>, onSeeAll: () -> Unit)`, `QuickLinksWidget(onQuickLink: (QuickLink) -> Unit)`, plus `DashboardSkeleton()`, `DashboardEmptyState`, `DashboardErrorState`.

```kotlin
enum class QuickLink { Profile, Sessions, Settings, Activity }
```

`DashboardRoute` maps `QuickLink` to the hoisted nav callbacks, keeping `NavController` ownership in the nav graph (AND-024).

> Review note: the illustrative `state.data.recentActivity` / `state.data.summary` accessors above are placeholders. The verified server payload (`DashboardSummary`) has no `summary` sub-object or `recentActivity`/`recent_activity` field — KPIs are top-level (`today_earnings_cents`, `period_views`, `total_subscribers`, …) and the "recent activity" widget is fed by `recent_milestones` (and optionally `active_broadcasts` / `top_content`). The final domain accessor names come from AND-065's `core-model` mapping; align the widget signatures to those once AND-065 lands.

### 4.4 Navigation integration

Replace the `Home` placeholder route from AND-024 with `DashboardRoute`. In the authenticated `NavGraphBuilder`:

```kotlin
composable(route = AuthedRoute.Home.path) {
    DashboardRoute(
        onOpenProfile = { navController.navigate(AuthedRoute.Profile.path) },
        onOpenSessions = { navController.navigate(AuthedRoute.Sessions.path) },
        onOpenSettings = { navController.navigate(AuthedRoute.Settings.path) },
        onOpenActivity = { navController.navigate(AuthedRoute.Activity.path) },
    )
}
```

Routes not yet implemented (Sessions/Activity/Settings) navigate to existing placeholders; this ticket only wires the callbacks.

## 5. API Contract

This screen issues **no direct HTTP calls** — all access is through `DashboardRepository` (AND-065). The contract below documents the upstream shape the screen relies on, for traceability; **AND-065 is the authority** for the endpoint and DTO mapping.

- **Read endpoint:** `GET /ui/dashboard/summary` (corrected during review; OpenAPI op `dashboard_summary_ui_dashboard_summary_get`, tag `creator-dashboard`, "Unified dashboard summary: earnings + analytics + broadcasts + milestones"). Optional params (all sent by the network layer / AND-065, not this screen): `user_sub` (query), `X-SESSION-ID` (header), `X-IMPERSONATION-TOKEN` (header).
- **Refresh endpoint:** `POST /ui/dashboard/refresh` (corrected during review — refresh is a **POST**, "Proxy to analytics refresh — rate limited", NOT an idempotent GET re-fetch). Web `refreshDashboard()` returns `{ ok: boolean; message: string; refreshed_at: number }`. After triggering refresh, the consolidated summary is re-read via `GET /ui/dashboard/summary`. Because refresh is rate-limited, rapid pull gestures may receive 429 — the screen must tolerate this (see §7).
- **Auth:** cookie session (`credentials: include`) + `Authorization: Bearer` + `X-CSRF-Token` (from `ui_csrf` cookie); all handled by the network layer.
- **Timeout/retry:** ~20s timeout; bounded backoff retry is acceptable for the GET summary read. The POST refresh is rate-limited and is NOT freely retryable — implemented in core-network/AND-065, not here.

Actual `DashboardSummary` response shape (verified against `src/api/types.ts: DashboardSummary`; the OpenAPI 200 schema for this path is untyped `{}`, so the frontend interface is the authority). The earlier draft fields (`total_sessions`, `active_sessions`, `mfa_enrolled`, `recent_activity`, `quick_links`) were invented and have been **corrected** to the real shape:

```json
{
  "today_earnings_cents": 12345,
  "earnings_breakdown": { "subscriptions": 0, "tips": 0, "unlocks": 0, "vod_purchases": 0, "other": 0 },
  "period_views": 0,
  "period_revenue_cents": 0,
  "total_subscribers": 0,
  "top_content": [ { "content_id": "c_1", "content_type": "video", "title": "Clip", "views": 10, "revenue_cents": 500 } ],
  "active_broadcasts": [ { "session_id": "s_1", "status": "live", "name": "Show", "started_at": "2026-06-05T14:02:11Z" } ],
  "recent_milestones": [ { "milestone_id": "m_1", "user_id": "u_1", "metric": "subscribers", "threshold": 100, "current_value": 101, "formatted": "100 subscribers", "achieved_at": 1749132131, "acknowledged": false } ],
  "currency": "USD",
  "generated_at": 1749132131,
  "warnings": []
}
```

Notes on the corrected shape: monetary values are integer **cents**; timestamps `generated_at` / `achieved_at` are Unix **epoch seconds** (numbers), while `active_broadcasts[].started_at` is an ISO-8601 string. There is no server-provided `recent_activity` or `quick_links` array — the **Summary/KPI** widget maps the earnings/views/subscribers fields, the **Recent activity / highlights** widget maps `recent_milestones` (and optionally `active_broadcasts`/`top_content`), and **Quick links** are a client-defined static set (Profile/Sessions/Settings/Activity), not server-driven.

FastAPI error bodies surface a `detail` field. For 422 the verified shape is `HTTPValidationError` = `{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }` (array of `ValidationError`); other handlers may return `detail` as a plain `string` or an authorization object `{ code, ... }` (see `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`). These are mapped to `ApiResult.Failure` and then to a user message by `core-ui` `toUserMessage()`. The screen never inspects raw `detail` directly.

The domain types (`Dashboard`, `DashboardSummary`, `ActivityItem`/highlights) and the `Dashboard.isEmpty` derivation are defined in `core-model` by AND-065. A representative `isEmpty` rule: true when all of `top_content`, `active_broadcasts`, and `recent_milestones` are empty AND the headline KPIs (`today_earnings_cents`, `period_views`, `total_subscribers`) are zero — AND-065 owns the exact derivation.

## 6. Data & State Management

- **Single source of truth:** `repository.observeDashboard()` (Room-backed cache from AND-065) feeds `uiState.data`. The ViewModel layers transient UI flags (`isRefreshing`, `isStale`, `transientError`) on top.
- **StateFlow exposure:** `uiState: StateFlow<DashboardUiState>` collected via `collectAsStateWithLifecycle()` in `DashboardRoute`.
- **Caching / stale-while-revalidate:** on entry, cached data renders immediately; a background `refresh()` updates it. A failed refresh keeps cached data and sets `isStale = true`.
- **Process death:** state rehydrates from the repository cache on recreation; no `SavedStateHandle` needed because the cache is the durable source. Scroll position is preserved via `rememberLazyListState()` within the composition (lost on process death, acceptable).
- **Refresh debounce:** `refresh()` no-ops if `isRefreshing` is already true (guard at the top of the coroutine) to prevent overlapping fetches from rapid pull gestures.
- **Recent activity bound:** the screen renders at most 5 activity rows regardless of payload size; full history is the Activity destination.

## 7. Error Handling & Resilience

| Condition | Has cached data? | UI behavior |
|---|---|---|
| Initial load in progress | no | `DashboardSkeleton()` shimmer |
| Initial load fails (timeout / 5xx / network) | no | Full-screen `DashboardErrorState` + Retry |
| Refresh fails | yes | Keep cards, `isStale = true`, show one-shot Snackbar via `transientError` |
| Refresh rate-limited (429 from `POST /ui/dashboard/refresh`) | yes | Keep cards; treat as a transient failure — one-shot "Refreshing too quickly, try again shortly" message; do NOT blank |
| Empty payload | n/a | `DashboardEmptyState` + Retry |
| 401 | n/a | Handled by network layer (single `POST /ui/session/refresh` + retry); surfaces as success or failure to repository |

- **Timeouts:** the unreliable dev host may take up to ~20s; skeleton/refresh indicators must remain visible the whole time, never freezing the UI thread (all work in `viewModelScope`).
- **Mapping:** `ApiResult.Failure.toUserMessage()` produces messages such as "Couldn't reach the server. Pull down to retry." for network errors and the mapped `detail` text for HTTP errors.
- **Retry:** Retry/refresh both call `refresh()`. The summary re-read is an idempotent GET; the `POST /ui/dashboard/refresh` trigger is rate-limited, so the `isRefreshing` guard (§6) must prevent overlapping/rapid calls and a 429 must be handled gracefully (see table above) rather than treated as a hard error.
- **One-shot errors:** `transientError` is cleared via `onErrorShown` → `consumeTransientError()` after the Snackbar is shown, preventing re-display on recomposition/rotation.

## 8. Security & Privacy

- No credentials, tokens, or cookies are handled in this layer; the session rides on the OkHttp cookie jar and CSRF interceptor (core-network).
- Dashboard payload may contain account-related metadata (recent activity, counts). Do **not** log payload contents; telemetry is limited to counts/state transitions (see §10).
- No data is persisted by this ticket beyond the repository cache (owned by AND-065). The screen holds data only in memory.
- Quick links navigate only to in-app authenticated destinations; no external `Intent`/URL handling, so no deep-link injection surface.
- Plaintext HTTP to the dev host is a known dev-only condition (network layer); release builds enforce HTTPS via network security config (separate ticket). This screen adds no new transport.

## 9. Accessibility & i18n

- All visible strings live in `feature-dashboard/src/main/res/values/strings.xml` (e.g., `dashboard_title`, `dashboard_summary_sessions`, `dashboard_quick_link_profile`, `dashboard_error_retry`, `dashboard_empty`). No hardcoded UI text.
- Each card has a `Modifier.semantics { contentDescription = ... }` heading; KPI values use combined `contentDescription` pairing label + value (e.g., "Total sessions: 128") so TalkBack reads a coherent phrase rather than orphan numbers.
- Quick-link buttons expose `Role.Button` and ≥48dp touch targets; icon-only links carry text content descriptions.
- Pull-to-refresh exposes the standard Material 3 refresh semantics; Retry/empty actions are reachable and announced.
- Relative timestamps formatted via `android.text.format.DateUtils.getRelativeTimeSpanString` (locale-aware); absolute times use the device locale/timezone. NOTE (verified during review): `recent_milestones[].achieved_at` and `generated_at` are Unix **epoch seconds** and must be multiplied by 1000 before being passed to `getRelativeTimeSpanString` (which expects millis); `active_broadcasts[].started_at` is an ISO-8601 string and must be parsed instead. Mapping is owned by AND-065, but the widget must not assume millis.
- Layout supports font scaling and dynamic width (cards use `fillMaxWidth`, `LazyColumn` scrolls); verified at 200% font scale with no clipping.

## 10. Telemetry & Logging

- Emit analytics events through the shared `Analytics` interface (core-ui/core-data) — no PII, counts/states only:
  - `dashboard_viewed` — on first composition.
  - `dashboard_refreshed { trigger: "pull" | "retry", outcome: "success" | "failure" }`.
  - `dashboard_quick_link_tapped { key }`.
  - `dashboard_load_failed { reason: "timeout" | "network" | "http", has_cache: Boolean }`.
- Logging: use `Timber` at `d`/`w` for state transitions and failure reasons (mapped category only), never payload bodies. No `Log` calls with raw response data.
- Latency: optionally record refresh duration as `dashboard_refresh_ms` to surface dev-host slowness; bucketed, no payload.

## 11. Testing Strategy

**Unit (core-testing, JVM, `kotlinx-coroutines-test`):**
- `DashboardViewModelTest` with a fake `DashboardRepository`:
  - emits `isInitialLoading = true` then `data` on success.
  - cached emission renders before refresh completes.
  - refresh success clears `isStale`/`errorMessage` and updates `data`.
  - refresh failure **with** cache → `isStale = true`, `transientError != null`, data retained.
  - load failure **without** cache → `showFullScreenError == true`.
  - overlapping refresh guarded (second call no-ops while `isRefreshing`).
  - `consumeTransientError()` clears the one-shot error.

**Compose UI (`createAndroidComposeRule`, Robolectric or instrumented):**
- skeleton shows when `isInitialLoading`.
- cards render summary/activity/quick-link content for a sample `Dashboard`.
- pull-to-refresh gesture invokes `onRefresh` (assert via callback spy).
- error state shows Retry and invokes `onRetry`.
- empty state shows for `isEmpty` payload.
- quick-link tap invokes `onQuickLink(QuickLink.Profile)` etc.
- Snackbar shown for `transientError` and `onErrorShown` fired.

**Screenshot (optional, if Paparazzi configured):** loading, populated, empty, error, stale states.

Acceptance-mapped assertions: a populated-state test proves "renders real data" (against a representative fixture mirroring the verified `DashboardSummary` shape from `GET /ui/dashboard/summary`); the pull-to-refresh and refresh-success tests prove "refresh works." See §17 for the enumerated, traceable test plan.

## 12. Dependencies & Sequencing

- **Blocked by AND-065** (Dashboard data layer): must merge first — provides `DashboardRepository`, `observeDashboard()`, `refresh(): ApiResult<Dashboard>`, and `core-model` domain types. If repo signatures differ, align this screen to them (do not re-implement networking).
- **Blocked by AND-024** (Authenticated nav graph + bottom nav): provides the `Home` route, `NavController`, and `AuthedRoute` destinations to wire quick links into.
- **Downstream:** full Sessions/Activity/Settings screens (separate epics) consume the quick-link routes wired here; until they land, links target placeholders.
- **Build order:** AND-024 → AND-065 → **AND-066**. No new Gradle dependencies expected beyond `androidx.compose.material3` pull-to-refresh (already on the Compose BOM) and Hilt navigation compose (already present).

## 13. Risks & Open Questions

1. **DTO field shape:** exact `dashboard.ts` field names and which widgets the payload supports are owned by AND-065; if the payload lacks `summary`/`recent_activity`/`quick_links`, the widget set must be trimmed to match. *Mitigation:* drive widget rendering off nullable domain fields; hide absent sections.
2. **Quick-link targets:** which destinations exist at M2 is uncertain; some routes may be placeholders. *Open question:* confirm the canonical quick-link set with product.
3. **Dev-host slowness:** ~20s timeouts make the skeleton/refresh UX critical; risk of users perceiving a hang. *Mitigation:* always-visible progress, stale-while-revalidate.
4. **`PullToRefreshBox` API:** Material 3 pull-to-refresh moved out of experimental across versions; confirm against the pinned Compose BOM and adjust `@OptIn` accordingly.
5. **Empty vs. error ambiguity:** a 200 with empty body vs. a failure must be distinguished by AND-065's mapping so the screen picks empty vs. error state correctly.

## 14. Acceptance Criteria

1. After login, the `Home` tab shows `DashboardScreen` (replacing the AND-024 placeholder).
2. On entry, the screen fetches `GET /ui/dashboard/summary` via `DashboardRepository` and renders **real data** in the summary/KPI widget (earnings, views, subscribers), the highlights widget (`recent_milestones` / `active_broadcasts` / `top_content`), and the client-defined quick-link widget (verified against a representative payload mirroring `DashboardSummary`).
3. While the first load is in flight with no cache, a skeleton/shimmer is shown (not a blank screen).
4. **Pull-to-refresh** re-fetches; the refresh indicator is visible during the call and the cards update with the new data on success.
5. A refresh failure while cached data is present keeps the data on screen and shows a one-shot error (Snackbar/banner); no blanking.
6. A load failure with no cache shows a full-screen error with a working Retry.
7. An empty payload shows an empty state with Retry.
8. Quick-link taps navigate via hoisted callbacks (Profile/Sessions/Settings/Activity).
9. No direct Retrofit/OkHttp usage in `feature-dashboard` screen code; all I/O via the repository.
10. ViewModel exposes a single `StateFlow<DashboardUiState>`; UI is collected with `collectAsStateWithLifecycle`.

## 15. Definition of Done

- All §14 acceptance criteria met and demonstrated on the dev backend.
- `DashboardViewModel`, `DashboardUiState`, `DashboardRoute`/`DashboardScreen`, and widget composables implemented under `com.testlogon.android.feature.dashboard`.
- Unit tests (ViewModel) and Compose UI tests from §11 written and green in CI; coverage includes success, stale-on-refresh-failure, hard-error, empty, and pull-to-refresh paths.
- All strings externalized; TalkBack pass on the populated screen; 200% font-scale check passes.
- Telemetry events wired per §10; no payload/PII logging.
- No new lint/detekt warnings; module respects `app → feature → core` layering (no `core-network` dependency from the screen).
- Nav graph from AND-024 updated to route `Home` → `DashboardRoute`; quick links wired (placeholders acceptable for unbuilt destinations).
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Claim:** The dashboard read endpoint is `GET /ui/dashboard`. — **Corrected.** No such path exists. The real read is `GET /ui/dashboard/summary`. Source: OpenAPI `GET /ui/dashboard/summary` (op `dashboard_summary_ui_dashboard_summary_get`, tag `creator-dashboard`); frontend `src/api/endpoints/dashboard.ts: getDashboardSummary`.
2. **Claim:** Refresh is an idempotent GET re-fetch. — **Corrected.** Refresh is a non-idempotent, rate-limited POST: `POST /ui/dashboard/refresh` ("Proxy to analytics refresh — rate limited"). Source: OpenAPI `POST /ui/dashboard/refresh` (op `dashboard_refresh_ui_dashboard_refresh_post`); frontend `src/api/endpoints/dashboard.ts: refreshDashboard`.
3. **Claim:** `refreshDashboard` returns a plain payload. — **Verified.** Web typing is `{ ok: boolean; message: string; refreshed_at: number }`. Source: `src/api/endpoints/dashboard.ts: refreshDashboard`. (OpenAPI 200 schema for this path is untyped `{}`, so the frontend typing is the authority.)
4. **Claim:** Response contains `summary.{total_sessions,active_sessions,mfa_enrolled}`, `recent_activity[]`, `quick_links[]`. — **Corrected.** None of those fields exist. The real `DashboardSummary` is `{ today_earnings_cents, earnings_breakdown{subscriptions,tips,unlocks,vod_purchases,other}, period_views, period_revenue_cents, total_subscribers, top_content[], active_broadcasts[], recent_milestones[], currency, generated_at, warnings[] }`. Source: `src/api/types.ts: DashboardSummary`, `DashboardEarningsBreakdown`, `DashboardTopContentItem`, `DashboardActiveBroadcast`, `DashboardMilestone`.
5. **Claim:** Money values and timestamps. — **Verified/Corrected detail.** Money is integer **cents** (`*_cents`); `generated_at` and `recent_milestones[].achieved_at` are Unix **epoch seconds** (number); `active_broadcasts[].started_at` is an ISO-8601 string. Source: `src/api/types.ts: DashboardSummary`, `DashboardMilestone`, `DashboardActiveBroadcast`. (Corrects the §9 implication that all timestamps feed `getRelativeTimeSpanString`, which expects millis.)
6. **Claim:** Auth is "cookie-based session with `X-CSRF-Token`" only. — **Corrected.** The web client sends cookie (`credentials: include`) **plus** `Authorization: Bearer <accessToken>` **plus** `X-CSRF-Token` read from the `ui_csrf` cookie. Source: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `Authorization: Bearer`).
7. **Claim:** 401 → single `POST /ui/session/refresh` retry, then replay. — **Verified.** Source: `src/api/client.ts: refreshSession` (`POST /ui/session/refresh`) and the 401 branch that retries the original request once and logs out on a second 401.
8. **Claim:** Network/offline error shape. — **Verified.** Client throws `ApiError(0, "Network error")` on `fetch` failure. Source: `src/api/client.ts` catch block.
9. **Claim:** FastAPI error body has a `detail` field of shape `string | [{msg}] | {code,...}`. — **Verified.** 422 = `HTTPValidationError` = `{ detail: ValidationError[] }`, each `{ loc, msg, type }`; client also handles `detail` as string and as an authorization object `{ code, ... }`. Source: OpenAPI `components.schemas.HTTPValidationError` + `components.schemas.ValidationError`; `src/api/client.ts: normalizeErrorDetail` / `mapAuthorizationError`.
10. **Claim:** The web app's dashboard screen calls the dashboard summary endpoint. — **Corrected.** `src/pages/Dashboard.tsx` does NOT call `/ui/dashboard/summary`; it aggregates messaging/billing/files/alerts/cart/calendar endpoints and renders "Recent Activity" from the **alerts** feed. The Android port deliberately uses the consolidated `/ui/dashboard/summary` DTO via AND-065 instead. Source: `src/pages/Dashboard.tsx` (imports `getConversations`, `getBalance`, `listFiles`, `getAlerts`, `getCarts`, `getCalendars/getEvents`).
11. **Claim:** Quick links are server-driven (`quick_links[]`). — **Corrected.** No server quick-link list exists; the web app hardcodes navigation targets (`navigate("/messages" | "/billing" | "/files" | "/calendar" | "/alerts" | "/cart")`). Android quick links are a client-defined static set. Source: `src/pages/Dashboard.tsx` `onClick` handlers.
12. **Claim:** A real-time stream exists. — **Verified (new info).** `GET /ui/dashboard/stream` is an SSE endpoint for real-time updates (out of scope for this ticket but noted). Source: OpenAPI `GET /ui/dashboard/stream` (op `dashboard_stream_ui_dashboard_stream_get`, "SSE stream for real-time dashboard updates").
13. **Claim:** Optional request params on the dashboard endpoints. — **Verified.** All three dashboard paths accept `user_sub` (query), `X-SESSION-ID` (header), `X-IMPERSONATION-TOKEN` (header). Source: OpenAPI `GET /ui/dashboard/summary`, `POST /ui/dashboard/refresh`, `GET /ui/dashboard/stream` parameter lists.
14. **Claim:** `PullToRefreshBox` / `rememberPullToRefreshState` are the Material 3 pull-to-refresh APIs. — **Unverified-assumption (framework ref).** Not checkable from backend/frontend sources; verify against the pinned Compose BOM. framework ref: https://developer.android.com/reference/kotlin/androidx/compose/material3/pulltorefresh/package-summary
15. **Claim:** `collectAsStateWithLifecycle` is the correct lifecycle-aware StateFlow collector. — **Unverified-assumption (framework ref).** framework ref: https://developer.android.com/topic/libraries/architecture/compose#lifecycle-aware
16. **Claim:** `DateUtils.getRelativeTimeSpanString` is locale-aware and expects millis. — **Verified (framework ref).** framework ref: https://developer.android.com/reference/android/text/format/DateUtils#getRelativeTimeSpanString(long)
17. **Claim:** Hilt (`@HiltViewModel`, `hiltViewModel()`) and the `DashboardRepository`/`observeDashboard()`/`refresh(): ApiResult<Dashboard>` contract from AND-065. — **Unverified-assumption.** AND-065 is not in the reviewed sources; this is a dependency contract owned by AND-065. Align signatures when AND-065 lands.

### Corrections made

- §1, §2, §5, §14: `GET /ui/dashboard` → `GET /ui/dashboard/summary` (endpoint did not exist).
- §3, §5, §7: refresh reclassified from "idempotent GET" to "non-idempotent, rate-limited `POST /ui/dashboard/refresh`"; added 429 handling to the §7 resilience table.
- §1, §5: response shape replaced — invented fields (`total_sessions`, `active_sessions`, `mfa_enrolled`, `recent_activity`, `quick_links`) → real `DashboardSummary` fields.
- §2: auth corrected from "cookie + CSRF only" to "cookie + Bearer + CSRF (`ui_csrf` cookie → `X-CSRF-Token`)"; added status-0 network-error fact.
- §2: clarified the web `Dashboard.tsx` aggregates feature endpoints and is not a 1:1 consumer of `/ui/dashboard/summary`; quick links are client-defined, not server-driven.
- §4.3: added a review note that `state.data.recentActivity`/`.summary` are placeholders not present on the server DTO.
- §5, §9: timestamp units corrected (epoch seconds vs ISO string vs millis); money is integer cents.

### Open assumptions

- **AND-065 repository contract** (`DashboardRepository`, `observeDashboard()`, `refresh(): ApiResult<Dashboard>`, `core-model` domain types, `Dashboard.isEmpty`): not present in the reviewed sources; assumed from the dependency. Why unverifiable: AND-065 spec/code not in the provided reference set.
- **Compose Material 3 pull-to-refresh API surface & `@OptIn` status** at the pinned BOM (Risk §13.4): framework-version dependent; verify against the project's Compose BOM.
- **Exact domain field/accessor names** after AND-065 mapping (e.g., whether `recent_milestones` surfaces as `highlights`/`recentActivity`): owned by AND-065.
- **Backend 200 response is untyped in OpenAPI** (`schema: {}` for `/ui/dashboard/summary` and `/ui/dashboard/refresh`): the field shapes rely on the frontend TypeScript interface as the authority, not a server schema. Risk that backend drift is invisible to contract tests until exercised against the live dev host.
- **Whether `POST /ui/dashboard/refresh` returns 429 or another status when rate-limited**, and any `Retry-After` header: not specified in OpenAPI (only 200/422 documented); 429 handling in §7 is a defensive assumption.

## 17. Test Plan

Test target legend: **JVM** = local JVM unit/Robolectric (no device); **Emu35** = headless AVD `test35` (x86_64, API 35); **Phys** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Use **Phys** only where real hardware/behavior matters; this ticket is pure presentation/state UI with no camera/biometrics/WebRTC/FCM, so almost everything runs on JVM/Emu35. ABI/API-skew smoke is the one case suited to **Phys**.

| ID | Type | Target | Title |
|---|---|---|---|
| TC-AND-066-01 | unit | JVM | Initial load: loading → success populates data |
| TC-AND-066-02 | unit | JVM | Cached emission renders before refresh completes |
| TC-AND-066-03 | unit | JVM | Refresh success clears stale/error and updates data |
| TC-AND-066-04 | unit | JVM | Refresh failure WITH cache → stale + transient error, data retained |
| TC-AND-066-05 | unit | JVM | Load failure WITHOUT cache → full-screen error |
| TC-AND-066-06 | unit | JVM | Overlapping refresh guarded (no-op while refreshing) |
| TC-AND-066-07 | unit | JVM | `consumeTransientError()` clears one-shot error |
| TC-AND-066-08 | contract/MockWebServer | JVM/Robolectric | Summary DTO parses to real `DashboardSummary` shape |
| TC-AND-066-09 | contract/MockWebServer | JVM/Robolectric | 422 `HTTPValidationError` body maps to failure message |
| TC-AND-066-10 | contract/MockWebServer | JVM/Robolectric | Refresh 429 (rate-limited) → transient error, cards kept |
| TC-AND-066-11 | contract/MockWebServer | JVM/Robolectric | Offline/flaky dev host (status-0 / timeout) path |
| TC-AND-066-12 | Compose-UI | Emu35 | Populated dashboard renders all widgets ("real data") |
| TC-AND-066-13 | Compose-UI | Emu35 | Skeleton, empty, full-screen-error, stale states |
| TC-AND-066-14 | Compose-UI | Emu35 | Pull-to-refresh gesture invokes `onRefresh`; indicator visible |
| TC-AND-066-15 | Compose-UI | Emu35 | Quick-link taps invoke hoisted callbacks |
| TC-AND-066-16 | Compose-UI (a11y) | Emu35 | TalkBack semantics, 48dp targets, 200% font scale |
| TC-AND-066-17 | instrumented/e2e | Phys | API-34/arm64 smoke against live dev host |
| TC-AND-066-18 | manual | Phys | No-direct-Retrofit/OkHttp + no payload logging audit |

---

**TC-AND-066-01 — Initial load happy path** · unit · JVM
- Precond: fake `DashboardRepository`; `observeDashboard()` empty, `refresh()` returns `ApiResult.Success(sample)`.
- Steps: construct `DashboardViewModel`; collect `uiState`.
- Expected: first state `isInitialLoading == true, data == null`; final state `data == sample, isInitialLoading == false, isRefreshing == false, isStale == false, errorMessage == null`.
- Traces: AC-2, AC-3.

**TC-AND-066-02 — Cached-before-refresh** · unit · JVM
- Precond: `observeDashboard()` emits a cached `Dashboard` immediately; `refresh()` suspends (controllable).
- Steps: construct VM; advance until cached emission; assert before refresh completes.
- Expected: `uiState.data == cached` is visible before refresh resolves (stale-while-revalidate).
- Traces: AC-2, AC-3.

**TC-AND-066-03 — Refresh success updates data** · unit · JVM
- Precond: VM seeded with stale cache and `isStale = true`; `refresh()` returns `Success(fresh)`.
- Steps: call `refresh()` (pull trigger, `isInitial=false`).
- Expected: during call `isRefreshing == true`; after: `data == fresh, isStale == false, errorMessage == null, transientError == null, isRefreshing == false`.
- Traces: AC-4.

**TC-AND-066-04 — Refresh failure WITH cache** · unit · JVM
- Precond: VM has non-null `data`; `refresh()` returns `ApiResult.Failure` (network).
- Steps: call `refresh()`.
- Expected: `data` retained (unchanged), `isStale == true`, `transientError != null`, `errorMessage == previous (unchanged)`, `showFullScreenError == false`.
- Traces: AC-5.

**TC-AND-066-05 — Load failure WITHOUT cache** · unit · JVM
- Precond: empty cache; `refresh(isInitial=true)` returns `Failure`.
- Steps: construct VM (init triggers initial refresh).
- Expected: `data == null`, `errorMessage != null`, `showFullScreenError == true`, `isInitialLoading == false`.
- Traces: AC-6.

**TC-AND-066-06 — Overlapping refresh guarded** · unit · JVM
- Precond: `refresh()` suspends; spy counts repository calls.
- Steps: call `refresh()` twice rapidly while first in flight.
- Expected: second call no-ops (repository invoked once); prevents 429-inducing pull spam (§6/§7).
- Traces: AC-4.

**TC-AND-066-07 — Consume transient error** · unit · JVM
- Precond: state has `transientError != null`.
- Steps: call `consumeTransientError()`.
- Expected: `transientError == null`; no other fields change; not re-emitted on recomposition.
- Traces: AC-5.

**TC-AND-066-08 — Summary DTO contract** · contract/MockWebServer · JVM/Robolectric
- Precond: MockWebServer enqueues a 200 body matching the verified `DashboardSummary` JSON (§5).
- Steps: drive the AND-065 api/parser (or the screen's fixture loader) against the canned response.
- Expected: parses without loss; `today_earnings_cents`, `earnings_breakdown.*`, `period_views`, `total_subscribers`, `top_content[]`, `active_broadcasts[]`, `recent_milestones[]`, `currency`, `generated_at`, `warnings[]` all mapped; epoch-seconds fields not mistaken for millis.
- Traces: AC-2.

**TC-AND-066-09 — 422 validation error mapping** · contract/MockWebServer · JVM/Robolectric
- Precond: MockWebServer returns 422 with `{ "detail": [ { "loc":["query","user_sub"], "msg":"field required", "type":"value_error.missing" } ] }`.
- Steps: trigger a read; capture mapped failure.
- Expected: produces `ApiResult.Failure`; `toUserMessage()` yields the `msg` text (not raw JSON); no crash on array `detail`.
- Traces: AC-6.

**TC-AND-066-10 — Refresh rate-limit (429)** · contract/MockWebServer · JVM/Robolectric
- Precond: VM/repo has cached data; MockWebServer answers `POST /ui/dashboard/refresh` with 429.
- Steps: trigger pull-to-refresh.
- Expected: cards remain, `isStale == true`, one-shot `transientError` (e.g. "Refreshing too quickly…"); NOT a full-screen error; original data not blanked.
- Traces: AC-4, AC-5.

**TC-AND-066-11 — Offline / flaky dev host** · contract/MockWebServer · JVM/Robolectric
- Precond: MockWebServer configured to drop the socket / delay > timeout (simulating status-0 network error and the unreliable dev host).
- Steps: (a) initial load with no cache; (b) refresh with cache.
- Expected: (a) full-screen error + Retry, no ANR (work off main thread); (b) cards kept, stale + transient error; Retry/refresh re-issues the call.
- Traces: AC-5, AC-6.

**TC-AND-066-12 — Populated UI renders real data** · Compose-UI · Emu35
- Precond: `DashboardScreen` with a sample `DashboardUiState(data = sample)`.
- Steps: set content; assert nodes.
- Expected: summary/KPI values shown; highlights rows from `recent_milestones` (≤5); quick-link buttons present; `testTag("dashboard_list")` exists.
- Traces: AC-2.

**TC-AND-066-13 — State variants render** · Compose-UI · Emu35
- Precond: separate states: `isInitialLoading=true`; `isEmpty` payload; `showFullScreenError`; stale (data + transientError).
- Steps: render each; assert.
- Expected: skeleton (not blank); empty state + Retry; full-screen error + Retry (invokes `onRetry`); stale shows cards + Snackbar.
- Traces: AC-3, AC-5, AC-6, AC-7.

**TC-AND-066-14 — Pull-to-refresh gesture** · Compose-UI · Emu35
- Precond: populated state; `onRefresh` spy.
- Steps: perform swipe-down on `dashboard_list`; also render with `isRefreshing=true`.
- Expected: `onRefresh` invoked once; refresh indicator visible while `isRefreshing`, dismissed otherwise.
- Traces: AC-4.

**TC-AND-066-15 — Quick-link navigation callbacks** · Compose-UI · Emu35
- Precond: populated state; `onQuickLink` spy; highlights overflow present.
- Steps: tap Profile, Sessions, Settings, Activity, and the activity "see all" overflow.
- Expected: `onQuickLink(QuickLink.Profile/Sessions/Settings/Activity)` fired with correct enum; screen holds no `NavController`.
- Traces: AC-8, AC-9, AC-10.

**TC-AND-066-16 — Accessibility & font scaling** · Compose-UI (a11y) · Emu35
- Precond: populated state.
- Steps: enable accessibility checks (`enableAccessibilityChecks()` / Espresso a11y); set font scale 2.0; inspect semantics.
- Expected: KPI cards expose combined `contentDescription` (label+value); quick-link buttons `Role.Button` with ≥48dp targets and non-empty descriptions; no clipping at 200%; pull-to-refresh & Retry announced.
- Traces: AC-2, AC-8.

**TC-AND-066-17 — Live dev-host smoke on physical device** · instrumented/e2e · Phys (MUST run on physical device)
- Precond: app installed on SM-A156U (API 34, arm64-v8a); valid logged-in session; dev host reachable. Rationale for Phys: validates arm64-v8a ABI and API-34 behavior vs the API-35 x86_64 emulator (Risk: ABI/API skew), against the real unreliable backend.
- Steps: launch → land on Home; observe initial render; pull to refresh; toggle airplane mode and pull again.
- Expected: real `/ui/dashboard/summary` data renders; refresh triggers `POST /ui/dashboard/refresh` then re-read and updates cards; offline pull keeps cards + shows transient error; no crash on arm64/API-34.
- Traces: AC-1, AC-2, AC-4, AC-5.

**TC-AND-066-18 — Layering & logging audit** · manual · Phys (or code review + logcat on device)
- Precond: built `feature-dashboard` module; device attached for logcat.
- Steps: grep module for `retrofit`/`okhttp`/`core-network` imports; exercise load+refresh+error while watching logcat.
- Expected: no direct Retrofit/OkHttp/`core-network` references in screen code (all I/O via repository); no payload/PII in logs (only counts/state transitions per §10); telemetry events emitted.
- Traces: AC-9, AC-10.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 Home shows DashboardScreen | TC-17 |
| AC-2 Fetches summary + renders real data | TC-01, TC-02, TC-08, TC-12, TC-16, TC-17 |
| AC-3 Skeleton on first load | TC-01, TC-02, TC-13 |
| AC-4 Pull-to-refresh updates cards | TC-03, TC-06, TC-10, TC-14, TC-17 |
| AC-5 Refresh-fail keeps data + one-shot error | TC-04, TC-07, TC-10, TC-11, TC-13, TC-17 |
| AC-6 No-cache load failure → full-screen error + Retry | TC-05, TC-09, TC-11, TC-13 |
| AC-7 Empty payload → empty state + Retry | TC-13 |
| AC-8 Quick-link nav via hoisted callbacks | TC-15, TC-16 |
| AC-9 No direct Retrofit/OkHttp; I/O via repository | TC-15, TC-18 |
| AC-10 Single StateFlow collected with lifecycle | TC-13, TC-15, TC-18 |
