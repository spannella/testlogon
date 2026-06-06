---
id: AND-399
title: Analytics dashboards (read)
milestone: M8
epic: E52
priority: P2
size: M
status: draft
depends_on: [AND-027, AND-255]
blocks: []
---

# AND-399 — Analytics dashboards (read)

## 1. Overview & Goal

Deliver the top-level **read-only analytics dashboards** screen for the TestLogon
Android app (`com.testlogon.android`). This is the account/site-wide analytics
surface — the native equivalent of the web reference's `analytics.ts` API layer —
not the ads-campaign-specific dashboard owned by AND-368. It presents the
authenticated user's aggregate platform metrics (views, watch time, unique
viewers, subscriber/follower deltas, engagement) as summary KPI tiles plus
time-series charts over a selectable date range, with optional per-dimension
breakdown rows (e.g., top content, traffic by source).

The ticket is strictly a **consumer** of the `/ui/analytics/*` read endpoints.
There is no mutation, export, or scheduling capability here. The screen reuses
the shared chart composable from AND-255 and the authenticated cookie session
established by AND-027 (no new auth logic).

The goal is a `feature-analytics` screen that:

- Loads the signed-in user's aggregate analytics over a selectable date range.
- Renders KPI tiles and line/bar charts via the shared `Tl*Chart` composables.
- Behaves correctly against the unreliable plaintext dev backend (loading,
  empty, error, offline/stale states) with bounded retry on idempotent GETs.

Success = dashboards render for a seeded account with real data, degrade
gracefully when the backend is slow/unreachable, and the screen is fully covered
by ViewModel unit tests and Compose UI tests. This satisfies the source
ticket's single acceptance bullet ("Analytics render") with the rigor expected
of a production M8 feature.

## 2. Context & References

- **Module:** `feature-analytics` (new dashboards screen + ViewModel), consuming
  `core-network`, `core-model`, `core-data`, `core-ui`, `core-testing`.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 +
  Moshi 1.15, Room 2.6 (cache), DataStore (prefs), Coil, Paging 3. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9 wrapper.
- **Layering:** app → feature-analytics → core-*. ViewModels expose
  `StateFlow<UiState>`; typed `ApiResult<T>`; FastAPI `detail` mapping
  (string | `[{msg}]` | `{code,...}`).
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000`
  (PLAINTEXT HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based session
  with the `ui_csrf` cookie echoed as the `X-CSRF-Token` header; on 401 the
  shared client performs one `POST /ui/session/refresh` then retries. Persistent
  cookie jar required (all established by core-network + AND-027).
- **Dependencies:**
  - **AND-027 (AuthApi — session endpoints)** establishes the authenticated
    session (`session/start|finalize|refresh`, `me`) and the CSRF/refresh
    interceptor + persistent cookie jar that every `/ui/*` GET in this ticket
    rides on. This ticket adds **no** auth logic; it depends on a live session.
  - **AND-255 (Reusable charts component)** provides the line/bar chart
    composables (`TlLineChart` / `TlBarChart`) and the `ChartSeries` /
    `ChartPoint` models. Dashboard charts MUST reuse these — no second charting
    library is introduced.
- **Web reference:** `frontend/src/api/endpoints/analytics.ts` (endpoint paths
  and query params) and `frontend/src/api/types.ts` (metric DTO shapes). Mirror
  field names and the FastAPI `detail` error contract. Exact paths/fields are
  confirmed against `/openapi.json` and `analytics.ts` during implementation.
- **Sibling, not this ticket:** AND-368 (Ad analytics) covers `/ui/ads/*`
  campaign analytics. This ticket owns only the general `/ui/analytics/*`
  dashboards. The two share the AND-255 chart composables but no domain code.

## 3. Functional Requirements

FR-1. The signed-in user can open an **Analytics** dashboards screen from the
app's main navigation (top-level destination; no entity id required — scope is
the current session's account, resolved server-side from the cookie).

FR-2. The screen presents a **date-range selector** with presets: Last 7 days,
Last 28 days, Last 90 days. Default = Last 28 days. Range changes re-query the
backend and update every metric on the screen.

FR-3. The screen renders a **summary row of KPI tiles**: Views, Watch time,
Unique viewers, Subscribers (net delta over range), Engagement rate. Each tile
shows the value plus the period-over-period delta versus the immediately
preceding equal-length window (e.g., the prior 28 days), formatted as a signed
percentage with up/down affordance. Numbers/durations are locale-formatted.

FR-4. The screen renders **time-series charts** (reusing AND-255), bucketed
daily over the selected range: a Views line chart and a Watch-time line chart.
Where the day count is small (≤ 14), a bar chart variant may be used.

FR-5. The screen renders one or more **breakdown sections** (read-only rows):
Top content (title + views + watch time) and Traffic by source (source + share),
each capped/sorted server- or client-side. Rows have no actions.

FR-6. **States:** Loading (skeleton tiles + chart placeholders), Success, Empty
(account has no analytics in range — distinct copy), and Error (with Retry).
When cached data exists but the network fetch fails, show the cached data with a
**Stale** banner ("Showing saved data") instead of a blocking error.

FR-7. **Pull-to-refresh** re-fetches the current range and bypasses the cache.

FR-8. The last-selected range preset persists per device and is restored on
re-entry.

FR-9. All values are read-only. No mutation, export, or share endpoints are
called by this ticket.

## 4. Technical Design

### 4.1 Module & package layout

```
feature-analytics/
  src/main/java/com/testlogon/android/feature/analytics/dashboards/
    AnalyticsRoute.kt            // route + nav wiring
    AnalyticsScreen.kt           // stateless Composable(state, onEvent)
    AnalyticsViewModel.kt
    AnalyticsUiState.kt
    components/
      KpiTileRow.kt
      MetricChartCard.kt
      BreakdownSection.kt
      DateRangeSelector.kt
core-model/.../analytics/
    AnalyticsDashboard.kt        // domain models
core-network/.../analytics/
    AnalyticsService.kt          // Retrofit service + DTOs
    AnalyticsDtoMappers.kt
core-data/.../analytics/
    AnalyticsRepository.kt
    AnalyticsRepositoryImpl.kt
    local/AnalyticsDao.kt        // Room cache
    local/AnalyticsEntities.kt
```

### 4.2 Navigation

Top-level destination (no path argument; account derived from session):

```kotlin
const val ANALYTICS_ROUTE = "analytics"

fun NavController.navigateToAnalytics() = navigate(ANALYTICS_ROUTE)

fun NavGraphBuilder.analyticsScreen() {
    composable(route = ANALYTICS_ROUTE) { AnalyticsRoute() }
}
```

`AnalyticsRoute` collects `viewModel.uiState` with
`collectAsStateWithLifecycle()` and forwards `onEvent`.

### 4.3 ViewModel & UiState

```kotlin
enum class DateRangePreset(val days: Int) { LAST_7(7), LAST_28(28), LAST_90(90) }

data class KpiTile(
    val key: MetricKey,
    val value: Double,
    val unit: MetricUnit,          // COUNT, DURATION_SECONDS, PERCENT
    val deltaFraction: Double?,    // vs prior equal window; null if unknown
)

data class BreakdownRow(val label: String, val primary: Double, val secondary: Double?)

data class AnalyticsUiState(
    val isLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val range: DateRangePreset = DateRangePreset.LAST_28,
    val tiles: List<KpiTile> = emptyList(),
    val viewsSeries: ChartSeries = ChartSeries.EMPTY,       // from AND-255
    val watchTimeSeries: ChartSeries = ChartSeries.EMPTY,   // from AND-255
    val topContent: List<BreakdownRow> = emptyList(),
    val trafficSources: List<BreakdownRow> = emptyList(),
    val isStale: Boolean = false,
    val error: UiError? = null,
) {
    val isEmpty: Boolean
        get() = !isLoading && error == null && tiles.isEmpty() &&
            viewsSeries.points.isEmpty() && topContent.isEmpty()
}

sealed interface AnalyticsEvent {
    data class RangeSelected(val preset: DateRangePreset) : AnalyticsEvent
    data object Refresh : AnalyticsEvent
    data object Retry : AnalyticsEvent
}

@HiltViewModel
class AnalyticsViewModel @Inject constructor(
    private val repository: AnalyticsRepository,
    private val rangePrefs: AnalyticsRangePrefs,   // DataStore-backed
    private val clock: Clock,
) : ViewModel() {
    val uiState: StateFlow<AnalyticsUiState>
    fun onEvent(event: AnalyticsEvent)
}
```

The ViewModel holds a `MutableStateFlow<DateRangePreset>` (seeded from
`rangePrefs`) and `flatMapLatest`s it onto `repository.observeDashboard(range)`,
projecting `ApiResult` into `AnalyticsUiState`, exposed via
`stateIn(SharingStarted.WhileSubscribed(5_000), AnalyticsUiState())`.
`RangeSelected` updates the flow and persists the preset; `Refresh`/`Retry`
launch `repository.refresh(range)` in `viewModelScope`.

### 4.4 Repository

```kotlin
interface AnalyticsRepository {
    /** Cache-first; emits cached (stale=true) then fresh, or error if no cache. */
    fun observeDashboard(range: DateRangePreset): Flow<ApiResult<AnalyticsDashboard>>

    suspend fun refresh(range: DateRangePreset): ApiResult<Unit>
}
```

`AnalyticsDashboard` bundles the summary tiles, the daily timeseries, and the
breakdown rows. The impl computes `endDate = LocalDate.now(clock)` and
`startDate = endDate.minusDays(preset.days - 1L)` (ISO `yyyy-MM-dd`), requests
the dashboard endpoint, maps DTO → domain via `AnalyticsDtoMappers`, writes to
Room with a `fetchedAt` timestamp, and emits. The prior-window delta is computed
from the same payload if the backend returns a `previous` block; otherwise the
repository issues a second GET for `[startDate - days, startDate - 1]` and
diffs. On `IOException`/5xx-after-retry with a non-empty cache it emits the
cached value with `stale = true`.

### 4.5 Chart mapping (AND-255 reuse)

Daily metric points map to `ChartSeries` (`List<ChartPoint(x: Long, y: Float)>`,
`x` = epoch day). Views and watch-time each render via `TlLineChart` with a
`valueFormatter` lambda from `core-ui` (count formatter for views, duration
formatter for watch time). No charting code is added here; if AND-255 lacks a
needed capability (e.g., dual axis), raise a follow-up against AND-255 rather
than forking charts.

## 5. API Contract

All endpoints are read-only GETs requiring the authenticated cookie session and
the `X-CSRF-Token` header (attached by the shared interceptor). Base = dev host
above. Exact field names are confirmed against `/openapi.json` and
`frontend/src/api/endpoints/analytics.ts` during implementation; the shapes
below are the contract this ticket codes against.

### 5.1 Dashboard summary + timeseries

`GET /ui/analytics/dashboard?start=YYYY-MM-DD&end=YYYY-MM-DD&granularity=day`

200:
```json
{
  "range": { "start": "2026-05-09", "end": "2026-06-05" },
  "summary": {
    "views": 184320,
    "watch_time_seconds": 9421800,
    "unique_viewers": 51240,
    "subscribers_net": 1372,
    "engagement_rate": 0.0613
  },
  "previous": {
    "views": 161002,
    "watch_time_seconds": 8730500,
    "unique_viewers": 49110,
    "subscribers_net": 980,
    "engagement_rate": 0.0588
  },
  "timeseries": [
    { "date": "2026-05-09", "views": 6210, "watch_time_seconds": 318400,
      "unique_viewers": 2110 }
  ]
}
```

### 5.2 Breakdown sections

`GET /ui/analytics/breakdown?start=YYYY-MM-DD&end=YYYY-MM-DD&dimension={content|source}&limit=10`

200 (`dimension=content`):
```json
{
  "dimension": "content",
  "items": [
    { "id": "vid_77", "label": "Launch Recap", "views": 41200,
      "watch_time_seconds": 1882000 }
  ]
}
```

200 (`dimension=source`):
```json
{
  "dimension": "source",
  "items": [ { "id": "search", "label": "Search", "views": 70110, "share": 0.38 } ]
}
```

`engagement_rate` and `share` are fractions (0–1); render as percentages.
Durations are integer **seconds**; format as `h m`. If the dev backend exposes a
single combined dashboard payload (breakdowns embedded) rather than the separate
`/breakdown` path, consume that and skip the second call; the actual path chosen
is documented in the PR. If a dedicated `previous`/delta block is absent, fall
back to the second-window GET described in §4.4.

### 5.3 Retrofit service

```kotlin
interface AnalyticsService {
    @GET("ui/analytics/dashboard")
    suspend fun getDashboard(
        @Query("start") start: String,
        @Query("end") end: String,
        @Query("granularity") granularity: String = "day",
    ): Response<DashboardDto>

    @GET("ui/analytics/breakdown")
    suspend fun getBreakdown(
        @Query("start") start: String,
        @Query("end") end: String,
        @Query("dimension") dimension: String,
        @Query("limit") limit: Int = 10,
    ): Response<BreakdownDto>
}
```

### 5.4 Error contract

The shared `errorBody → UiError` mapper handles FastAPI `detail` in all three
shapes (string, `[{ "msg": "..." }]`, `{ "code": "...", ... }`).
- **401** → handled by the auth interceptor (refresh-once-then-retry); not
  re-implemented here.
- **403** (CSRF/forbidden) → non-recoverable error state.
- **404 / empty** → Empty state (account with no analytics), not Error.
- **5xx / I/O** → retried per §7, then Error (or Stale if cache present).

## 6. Data & State Management

- **Source of truth:** `AnalyticsRepository` flow → ViewModel `StateFlow`
  → stateless `AnalyticsScreen(state, onEvent)`. The screen is pure; it never
  touches Retrofit/Room.
- **Cache (Room 2.6):** one row per `rangePreset` (the account is the current
  session) storing serialized summary, timeseries, and breakdowns plus
  `fetchedAt` epoch-ms. TTL = 15 min for "fresh"; older cache is served as
  **stale** while a refresh runs, enabling the offline / unreliable-host UI.

```kotlin
@Entity(tableName = "analytics_dashboard")
data class AnalyticsDashboardEntity(
    @PrimaryKey val rangePreset: String,
    val summaryJson: String,
    val previousJson: String?,
    val timeseriesJson: String,
    val topContentJson: String,
    val trafficSourcesJson: String,
    val fetchedAt: Long,
)
```

JSON blobs are (de)serialized with the injected Moshi instance; storing blobs
keeps the cache schema stable as the metric set evolves.

- **Prefs (DataStore):** `AnalyticsRangePrefs` persists the last-selected
  `DateRangePreset` so re-entry restores the user's choice (FR-8).
- **Threading:** all I/O on `Dispatchers.IO` via the repository; mappers are
  pure functions; date math uses an injected `Clock` for deterministic tests.
- **Date math:** `LocalDate.now(clock.withZone(ZoneId.systemDefault()))`,
  formatted with `DateTimeFormatter.ISO_LOCAL_DATE`.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp connect/read/call ~20s (core-network default for the dev
  host). The screen shows skeletons up to that bound rather than hanging.
- **Retry:** Idempotent GETs only — bounded exponential backoff (3 attempts,
  base 500ms, jitter) for transient I/O and 5xx, via the shared core-network
  retry policy. **No** retry on 4xx (the 401 refresh path is the interceptor's,
  not a retry).
- **Offline / unreachable host:** on `IOException` with cache present → emit
  cached data with `isStale = true` and a dismissible "Showing saved data"
  banner; with no cache → Error state with Retry.
- **Partial failure:** if the dashboard summary succeeds but a breakdown call
  fails, render tiles + charts and show an inline error/retry on the affected
  breakdown section only — the page is not blocked.
- **Malformed JSON:** Moshi mapping is non-fail-fast with defaults (missing
  numeric → 0, missing list → empty). A payload that parses to all-zero/empty is
  surfaced as **Empty**, not a crash or Error.

## 8. Security & Privacy

- Read-only; no PII entry on this screen. Analytics may be commercially
  sensitive — never log raw metric values or full response bodies above debug
  level.
- The session rides cookies via the persistent cookie jar; `X-CSRF-Token` is
  attached by the shared interceptor. This ticket adds **no** new auth logic and
  no new headers.
- The dev backend is plaintext HTTP; the cleartext exemption is the existing
  dev-only `network-security-config`. This ticket adds **no** new cleartext
  domains. Production builds use HTTPS (owned by core-network).
- Cached analytics live only in app-private Room storage and are **cleared on
  logout** via the existing session-clear hook (the analytics cache registers a
  `clear()` callback with that path).

## 9. Accessibility & i18n

- KPI tiles, breakdown rows, and chart cards expose `contentDescription` /
  `semantics` (e.g., a tile reads "Views, 184,320, up 14 percent"). Each chart
  card includes a text-equivalent summary semantics node because the chart
  canvas is not natively accessible to screen readers.
- Date-range chips are `selectable` with `role = Tab`; touch targets ≥ 48dp.
- Dynamic type / font-scale respected; tiles wrap rather than truncate at large
  scales. Light + dark via Material 3 tokens.
- All copy in `strings.xml` (no hardcoded UI text). Numbers, durations,
  percentages, and dates are locale-aware via `NumberFormat` /
  `DateTimeFormatter`; the up/down delta affordance is not color-only (icon +
  sign).

## 10. Telemetry & Logging

- Screen-view event `analytics_dashboard_viewed` with the selected `range` only
  — no metric values.
- Latency timing around the dashboard fetch (success/failure + duration bucket)
  to monitor the unreliable host.
- Error events tagged with the mapped error code/category (never the raw body).
- Debug-level structured logs gated behind `BuildConfig.DEBUG`; cookies, the
  CSRF token, and response bodies are never logged in release.

## 11. Testing Strategy

**Unit (core-testing + Turbine + MockWebServer):**

- `AnalyticsViewModelTest`: default range = LAST_28; `RangeSelected` persists
  the preset and triggers re-fetch; success → tiles + both series + breakdowns
  populated and delta computed; empty payload → `isEmpty`; error → `error` set;
  `Refresh` toggles `isRefreshing` on then off; injected `Clock` yields
  deterministic start/end query params.
- `AnalyticsRepositoryImplTest` (MockWebServer): DTO→domain mapping incl.
  seconds→duration and fraction→percent; cache-first emits stale-then-fresh;
  network fail with cache → stale; without cache → error; backoff retry on 503
  then 200; no retry on 400; prior-window delta path (embedded `previous` vs
  fallback second GET).
- Mapper tests for the three FastAPI `detail` shapes → `UiError`.

**Compose UI (`createAndroidComposeRule`):**

- Loading shows skeleton tiles + chart placeholders; Success renders tile labels
  and breakdown rows; Empty shows empty copy; Error shows Retry and tapping it
  re-queries; Stale banner visible when `isStale`; range chip selection updates
  rendered values.
- Accessibility assertions: tiles/rows have content descriptions; each chart
  card exposes a text-summary semantics node.

**Acceptance fixture:** a seeded dashboard JSON (from `/openapi.json` examples or
a captured dev response) drives a deterministic UI test proving "analytics
render" (the source ticket's acceptance bullet).

## 12. Dependencies & Sequencing

- **Blocked by AND-027 (AuthApi)** — the screen requires an authenticated cookie
  session plus the CSRF/refresh interceptor and persistent cookie jar that
  AND-027 establishes. No analytics GET succeeds without it.
- **Blocked by AND-255 (Reusable charts)** — the `TlLineChart`/`TlBarChart`
  composables and `ChartSeries`/`ChartPoint` models must exist; dashboard charts
  reuse them with no second charting library.
- **Transitively** relies on core-network (timeouts, retry policy, error mapper)
  and core-data (Room + DataStore) already established by earlier M-series work.
- **Sequencing:** confirm `/ui/analytics/*` paths and field names against
  `/openapi.json` + `analytics.ts` ➝ add `AnalyticsService` + DTOs + mappers ➝
  repository + Room cache + DataStore range-pref ➝ ViewModel ➝ Compose screen
  wiring AND-255 charts ➝ states + tests.
- **Blocks:** none. AND-368 (Ad analytics) is a sibling and is not blocked by
  this ticket (they share only the AND-255 charts).

## 13. Risks & Open Questions

- **R1 (API shape):** The dedicated `/ui/analytics/dashboard` and `/breakdown`
  paths must be confirmed against `/openapi.json` / `analytics.ts`; the backend
  may return a single combined payload. Resolve before coding; consume whatever
  the contract exposes and document in the PR. *Open: exact paths, query params,
  and whether timeseries/delta is server- or client-computed.*
- **R2 (Delta window):** Whether the API returns a `previous` block. If not, the
  fallback second-window GET (§4.4) doubles request count on the unreliable
  host. *Open: confirm; if absent, consider hiding deltas rather than a second
  call.*
- **R3 (Duration units):** Watch time may be seconds, ms, or minutes. Confirm to
  avoid unit errors; default assumption is integer seconds.
- **R4 (Host reliability):** ~20s timeouts may make the screen feel slow;
  mitigated by stale-cache rendering. *Open: acceptable freshness TTL (default
  15 min).*
- **R5 (Chart fit):** AND-255 charts must support a value-formatter and the
  series counts used here; if not, raise a follow-up on AND-255 rather than
  forking charts.

## 14. Acceptance Criteria

- **AC-1 (Renders — primary, maps to source "Analytics render"):** For a seeded
  account with data, opening the Analytics screen renders the KPI tile row, both
  time-series charts, and the breakdown sections with correctly formatted
  count/duration/percent values.
- **AC-2:** Default range is Last 28 days; selecting Last 7 / Last 90 re-queries
  and updates tiles, charts, and breakdowns; the chosen preset persists across
  re-entry.
- **AC-3:** Loading shows skeletons; an account with no analytics in range shows
  the Empty state (not an Error).
- **AC-4:** On network failure with cached data, the screen shows cached data
  plus a Stale banner; with no cache, it shows an Error state whose Retry
  re-queries successfully when the host recovers.
- **AC-5:** Durations rendered as `h m`; engagement rate and source share shown
  as percentages; per-tile delta shown as a signed percentage with a
  non-color-only up/down affordance.
- **AC-6:** Only read GETs are issued (verified via MockWebServer recorded
  requests); no mutation calls.
- **AC-7:** ViewModel unit tests and Compose UI tests cover loading / success /
  empty / error / stale and pass in CI.
- **AC-8:** KPI tiles, breakdown rows, and charts expose accessibility
  descriptions; all strings localized.

## 15. Definition of Done

- Code merged to `android-port` under `feature-analytics`, package
  `com.testlogon.android.feature.analytics.dashboards`, following
  app → feature → core layering.
- `AnalyticsViewModel` exposes `StateFlow<AnalyticsUiState>`; the screen is a
  stateless `(state, onEvent)` Composable; the Hilt graph compiles with KSP.
- `AnalyticsService` + DTOs + mappers added in core-network/core-model; Room
  cache and DataStore range-pref implemented; cache cleared on logout.
- AND-255 chart composables reused (no second charting dependency added); the
  session/CSRF/refresh path from AND-027 is consumed unchanged.
- All ACs demonstrably met; unit + Compose tests green in CI; ktlint/detekt and
  the project lint baseline clean.
- No cleartext or security regressions; no secrets or response bodies logged in
  release.
- PR documents the actual confirmed API paths, duration units, delta-window
  strategy, and combined-vs-split payload decision (resolving R1–R3).
