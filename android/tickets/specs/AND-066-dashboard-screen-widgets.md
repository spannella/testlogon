---
id: AND-066
title: Dashboard screen + widgets
milestone: M2
epic: E09
priority: P0
size: M
status: draft
depends_on: [AND-065, AND-024]
blocks: []
---

# AND-066 — Dashboard screen + widgets

## 1. Overview & Goal

Implement the authenticated **Dashboard** as the post-login landing destination of the TestLogon Android app. The screen is the `Home` tab of the bottom-nav scaffold delivered in AND-024 and consumes the `DashboardRepository` / `DashboardApi` data layer delivered in AND-065. It renders real backend data as a vertical list of **widget cards** (summary KPIs, recent activity, and quick-link shortcuts), supports **pull-to-refresh**, and exposes resilient loading / empty / error / offline-stale states appropriate for the unreliable dev backend.

This ticket owns the **presentation layer only**: the `DashboardViewModel`, its `DashboardUiState`, the Compose `DashboardScreen`, and the individual widget composables. It must not introduce new networking or DTO-mapping code — all I/O flows through the repository from AND-065. Success means: opening the app after login shows the dashboard populated with live data from `GET /ui/dashboard`, and pulling down re-fetches and visibly updates the cards.

Goal acceptance (from backlog): *Renders real data; refresh works.*

## 2. Context & References

- **Module:** `feature-dashboard` (new screen-layer additions; data layer already created in AND-065).
- **Layering:** `app → feature-dashboard → core-* (core-ui, core-model, core-data)`. The screen depends on `core-ui` (theme, shared scaffolding, `ApiResult` mapping helpers) and `core-model` (domain `Dashboard` types). It must NOT depend on `core-network` directly.
- **Namespace:** `com.testlogon.android.feature.dashboard`.
- **Dependencies:**
  - **AND-065 — Dashboard data layer:** provides `DashboardRepository`, `DashboardApi`, and the domain model `Dashboard` mapped from `dashboard.ts` DTOs. This ticket consumes `repository.observeDashboard()` / `repository.refresh()`.
  - **AND-024 — Authenticated nav graph + bottom nav skeleton:** provides the `Home` route placeholder that this screen replaces and the `NavController` wiring used by quick-link navigation.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext, unreliable). OpenAPI at `/openapi.json`. Cookie-based session with `X-CSRF-Token`; 401 → single `POST /ui/session/refresh` retry handled by the OkHttp `Authenticator`/interceptor stack (out of scope here).
- **Web reference:** `frontend/src/api/endpoints/dashboard.ts`, shared types in `frontend/src/api/types.ts`. The DTO field names below mirror that reference; AND-065 is the authority for the exact DTO→domain mapping.

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
9. **Idempotent reads only.** All dashboard fetches are GETs; refresh is safe to retry. No mutating calls originate from this screen.

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

- **Endpoint:** `GET /ui/dashboard`
- **Auth:** cookie session + `X-CSRF-Token` header (handled by the network layer).
- **Timeout/retry:** ~20s timeout; bounded backoff retry permitted (idempotent GET) — implemented in core-network/AND-065, not here.

Expected response (representative; field names per `dashboard.ts`):

```json
{
  "summary": {
    "total_sessions": 128,
    "active_sessions": 3,
    "mfa_enrolled": true
  },
  "recent_activity": [
    { "id": "act_01H...", "title": "Login from Chrome", "occurred_at": "2026-06-05T14:02:11Z", "kind": "login" }
  ],
  "quick_links": [
    { "key": "profile", "label": "My Profile" }
  ]
}
```

FastAPI error bodies surface a `detail` field (`string | [{msg}] | {code,...}`); these are mapped to `ApiResult.Failure` and then to a user message by `core-ui` `toUserMessage()`. The screen never inspects raw `detail` directly.

The domain types (`Dashboard`, `DashboardSummary`, `ActivityItem`) and the `Dashboard.isEmpty` derivation are defined in `core-model` by AND-065. If `recent_activity` and `summary` are both absent/empty, `isEmpty == true`.

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
| Empty payload | n/a | `DashboardEmptyState` + Retry |
| 401 | n/a | Handled by network layer (single `/ui/session/refresh` + retry); surfaces as success or failure to repository |

- **Timeouts:** the unreliable dev host may take up to ~20s; skeleton/refresh indicators must remain visible the whole time, never freezing the UI thread (all work in `viewModelScope`).
- **Mapping:** `ApiResult.Failure.toUserMessage()` produces messages such as "Couldn't reach the server. Pull down to retry." for network errors and the mapped `detail` text for HTTP errors.
- **Retry:** Retry/refresh both call `refresh()`. Because the call is an idempotent GET, repeated taps are safe.
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
- Relative timestamps formatted via `android.text.format.DateUtils.getRelativeTimeSpanString` (locale-aware); absolute times use the device locale/timezone.
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

Acceptance-mapped assertions: a populated-state test proves "renders real data" (against a representative fixture mirroring `GET /ui/dashboard`); the pull-to-refresh and refresh-success tests prove "refresh works."

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
2. On entry, the screen fetches `GET /ui/dashboard` via `DashboardRepository` and renders **real data** in summary, recent-activity, and quick-link widgets (verified against a representative payload).
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
