---
id: AND-399
title: Analytics dashboards (read)
milestone: M8
epic: E52
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference (verified):** `src/api/endpoints/analytics.ts` (the six
  per-metric GETs + `refreshAnalytics`), `src/api/types.ts` (`Analytics*` DTOs),
  and `src/pages/analytics/AnalyticsPage.tsx` (screen layout, `RANGE_PRESETS`
  7/30/90/365, `from_date`/`to_date`/`granularity` params, formatting). Mirror
  field names and the FastAPI `detail` error contract. Paths/fields were
  confirmed against `openapi.pretty.json` (`components.schemas.Analytics*Out`,
  `EngagementRateOut`) during this review — see §16.
- **Sibling, not this ticket:** AND-368 (Ad analytics) covers `/ui/ads/*`
  campaign analytics. This ticket owns only the general `/ui/analytics/*`
  dashboards. The two share the AND-255 chart composables but no domain code.

## 3. Functional Requirements

FR-1. The signed-in user can open an **Analytics** dashboards screen from the
app's main navigation (top-level destination; no entity id required — scope is
the current session's account, resolved server-side from the cookie).

FR-2. The screen presents a **date-range selector** with presets matching the
web reference (`AnalyticsPage.tsx` `RANGE_PRESETS`): Last 7 days, Last 30 days,
Last 90 days, Last 1 year. Default = Last 30 days. (CORRECTED from the prior
"7/28/90, default 28" — the web uses 7/30/90/365 default 30.) Range changes
re-query every endpoint via `from_date`/`to_date`. A `granularity`
(day/week/month) selector is optional and defaults to `day`.

FR-3. The screen renders a **summary row of KPI tiles** sourced from
`AnalyticsOverviewOut`: **Views** (`period_views`), **Revenue**
(`period_revenue_cents`, integer cents), **New subscribers**
(`period_new_subscribers`), **Total subscribers** (`total_subscribers`). An
**Engagement rate** tile may additionally be shown from the separate
`/ui/analytics/engagement` (`EngagementRateOut.engagement_rate`). (CORRECTED:
the prior "Watch time / Unique viewers / Subscribers net delta / Engagement
rate" tile set is not what the overview payload exposes.) Period-over-period
delta is **not** part of the overview payload; only `EngagementRateOut` carries a
`trend`/`trend_delta`. Numbers/cents/durations are locale-formatted.

FR-4. The screen renders **time-series charts** (reusing AND-255) over the
selected range: a **Views** line chart (`AnalyticsViewsOut.time_series[].views`)
and a **Subscriber growth** chart (`AnalyticsSubscribersOut.time_series` —
new/churned bars + total line in the web). A watch-time series is available from
the same views payload (`watch_time_seconds`). Where the day count is small
(≤ 14), a bar chart variant may be used.

FR-5. The screen renders **breakdown sections** (read-only rows): **Top content**
(`AnalyticsTopContentOut.items` → title + content_type + views + revenue + the
0–1 `engagement_rate`) and **Audience** (`AnalyticsAudienceOut.countries` and
`.devices` → name/type + viewers + 0–100 `percentage`). (CORRECTED: there is no
"Traffic by source / share" dimension; audience by country/device is the real
breakdown.) Rows are read-only (the web makes top-content rows tappable to a
content-detail route; that detail screen is out of scope for this ticket).

FR-6. **States:** Loading (skeleton tiles + chart placeholders), Success, Empty
(account has no analytics in range — distinct copy), and Error (with Retry).
When cached data exists but the network fetch fails, show the cached data with a
**Stale** banner ("Showing saved data") instead of a blocking error.

FR-7. **Pull-to-refresh** calls `POST /ui/analytics/refresh` (the backend's
recompute endpoint, mirroring the web Refresh button), then re-fetches the
current range bypassing the local cache. (CORRECTED: the prior "no mutation/POST"
absolute is relaxed — `/refresh` is a documented POST the web client uses; it is
not an analytics *write* but a recompute trigger. No metric-mutating endpoints
are called.)

FR-8. The last-selected range preset persists per device and is restored on
re-entry.

FR-9. All displayed values are read-only. The only non-GET call is the idempotent
`POST /ui/analytics/refresh` recompute (FR-7); no analytics-mutating, export
(`/ui/analytics/content-revenue/export`), or share endpoints are called.

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
    val key: MetricKey,            // VIEWS, REVENUE, NEW_SUBSCRIBERS, TOTAL_SUBSCRIBERS, ENGAGEMENT
    val value: Double,
    val unit: MetricUnit,          // COUNT, CURRENCY_CENTS, PERCENT
    val deltaFraction: Double?,    // only populated for ENGAGEMENT (trend_delta); null elsewhere
)

data class BreakdownRow(val label: String, val primary: Double, val secondary: Double?)

data class AnalyticsUiState(
    val isLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val range: DateRangePreset = DateRangePreset.LAST_28,
    val tiles: List<KpiTile> = emptyList(),
    val viewsSeries: ChartSeries = ChartSeries.EMPTY,       // from AND-255
    val watchTimeSeries: ChartSeries = ChartSeries.EMPTY,   // from AND-255
    val topContent: List<BreakdownRow> = emptyList(),       // AnalyticsTopContentOut.items
    val audienceCountries: List<BreakdownRow> = emptyList(),// AnalyticsAudienceOut.countries
    val audienceDevices: List<BreakdownRow> = emptyList(),  // AnalyticsAudienceOut.devices
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
breakdown rows. The impl computes `toDate = LocalDate.now(clock)` (web uses
`todayStr()`) and `fromDate = toDate.minusDays(preset.days.toLong())` (web
`daysAgo(days)`; both ISO `yyyy-MM-dd`), then **fans out** across the verified
per-metric endpoints (§5.1) — `overview`, `views`, `subscribers`, `top-content`,
`audience`, and optionally `revenue`/`engagement` — in parallel
(`coroutineScope { async {…} }`), maps each DTO → domain via
`AnalyticsDtoMappers`, assembles the dashboard, writes to Room with a `fetchedAt`
timestamp, and emits.

> **CORRECTION:** There is **no** single dashboard endpoint and **no** `previous`
> delta block in any payload. Period-over-period deltas for the overview KPIs are
> therefore **not derivable from the API as specified**. Options (decide in PR):
> (a) drop KPI deltas (recommended — matches the web, which shows no delta on the
> overview SummaryCards); or (b) for the Engagement tile only, use the supplied
> `EngagementRateOut.trend`/`trend_delta`; or (c) issue a second fan-out for the
> prior `[fromDate-days, fromDate-1]` window and diff (doubles request count on
> the unreliable host — see R2).

On `IOException`/5xx-after-retry with a non-empty cache it emits the cached value
with `stale = true`. Because the fetch is a fan-out, **partial success** is
expected behaviour (§7): a dashboard renders from whichever sections succeeded.

### 4.5 Chart mapping (AND-255 reuse)

Daily metric points map to `ChartSeries` (`List<ChartPoint(x: Long, y: Float)>`,
`x` = epoch day). Views and watch-time each render via `TlLineChart` with a
`valueFormatter` lambda from `core-ui` (count formatter for views, duration
formatter for watch time). No charting code is added here; if AND-255 lacks a
needed capability (e.g., dual axis), raise a follow-up against AND-255 rather
than forking charts.

## 5. API Contract

All endpoints are read-only GETs requiring the authenticated session. The shared
client attaches a `Bearer` access token (from the auth store), the
`X-CSRF-Token` header (echoed from the `ui_csrf` cookie), and the session
cookies — all via the AND-027 interceptor + persistent cookie jar. Base = dev
host above. The shapes below are **verified** against
`reference/openapi.index.txt`, `reference/openapi.pretty.json`
(`components.schemas.Analytics*Out`), and
`reference/src/api/endpoints/analytics.ts` + `reference/src/api/types.ts`.

> **CORRECTION (review AND-399):** The previously specified single
> `GET /ui/analytics/dashboard` and `GET /ui/analytics/breakdown` endpoints **do
> not exist** in the backend or the web client. The real surface is a set of
> **separate per-metric GETs** under `/ui/analytics/*`, all taking
> `from_date`/`to_date` (NOT `start`/`end`). The repository fans out across these
> endpoints and assembles the dashboard domain model client-side. See §16 for the
> citation/verdict audit.

### 5.1 Endpoint set (verified)

All take `from_date=YYYY-MM-DD&to_date=YYYY-MM-DD` unless noted. Responses
documented as `200:<Schema>;422:HTTPValidationError`.

| Purpose | Endpoint | Extra params | Response schema |
|---|---|---|---|
| KPI summary + embedded top content | `GET /ui/analytics/overview` | — | `AnalyticsOverviewOut` |
| Revenue total + breakdown + series | `GET /ui/analytics/revenue` | `granularity` | `AnalyticsRevenueOut` |
| Views/watch-time daily series | `GET /ui/analytics/views` | `granularity` | `AnalyticsViewsOut` |
| Subscriber growth series | `GET /ui/analytics/subscribers` | `granularity` | `AnalyticsSubscribersOut` |
| Top content rows | `GET /ui/analytics/top-content` | `sort_by`, `limit` | `AnalyticsTopContentOut` |
| Audience by country/device | `GET /ui/analytics/audience` | — | `AnalyticsAudienceOut` |
| Engagement rate KPI | `GET /ui/analytics/engagement` | `period_days` (NOT from/to) | `EngagementRateOut` |
| Force recompute (pull-to-refresh) | `POST /ui/analytics/refresh` | — | `AnalyticsRefreshOut` |

`granularity` ∈ `{day, week, month}` (web default `day`). `period_days` defaults
to 30 server-side.

### 5.2 Overview payload (KPI tiles + top content)

`GET /ui/analytics/overview?from_date=YYYY-MM-DD&to_date=YYYY-MM-DD` → 200
`AnalyticsOverviewOut`:
```json
{
  "period_views": 184320,
  "period_revenue_cents": 942180,
  "period_new_subscribers": 1372,
  "total_subscribers": 51240,
  "currency": "USD",
  "top_content": [
    { "content_id": "vid_77", "content_type": "video", "title": "Launch Recap",
      "views": 41200, "revenue_cents": 188200, "engagement_rate": 0.0613 }
  ]
}
```

> **CORRECTION:** KPI tiles are **Views, Revenue, New subscribers, Total
> subscribers** (per `AnalyticsOverviewOut` and the web `SummaryCard`s), NOT the
> previously listed "Watch time / Unique viewers / Subscribers net delta /
> Engagement rate". Watch-time and unique-viewer totals come from
> `AnalyticsViewsOut` (`total_watch_time_seconds`, per-point `unique_viewers`);
> engagement rate is a **separate** `EngagementRateOut`.

### 5.3 Time-series payloads (charts)

`GET /ui/analytics/views` → `AnalyticsViewsOut`:
```json
{
  "time_series": [
    { "date": "2026-05-09", "views": 6210, "unique_viewers": 2110,
      "watch_time_seconds": 318400 }
  ],
  "total_views": 184320,
  "total_watch_time_seconds": 9421800
}
```

`GET /ui/analytics/subscribers` → `AnalyticsSubscribersOut`: `time_series[]` of
`{ date, new, churned, net, total }`, plus `current_total`, `net_change`.

`GET /ui/analytics/revenue` → `AnalyticsRevenueOut`: `total_cents`,
`breakdown { tips, subscriptions, unlocks, vod, ads, calls }`, `time_series[]` of
`{ date, total_cents, tips_cents, subscriptions_cents, unlocks_cents, vod_cents,
ads_cents, calls_cents }`, `currency`. (Revenue values are integer **cents**.)

### 5.4 Breakdown / audience payloads

> **CORRECTION:** There is no `dimension`-parameterised `/breakdown` endpoint and
> no `{id,label,share}` shape. The two real breakdown sources are:

`GET /ui/analytics/top-content?from_date=..&to_date=..&sort_by=views&limit=10` →
`AnalyticsTopContentOut`:
```json
{ "items": [ { "content_id": "vid_77", "content_type": "video",
  "title": "Launch Recap", "views": 41200, "revenue_cents": 188200,
  "engagement_rate": 0.0613 } ], "total_items": 1 }
```
Note: `engagement_rate` is computed server-side and is **not** a valid
`sort_by` key (web sorts that column client-side; valid `sort_by` is `views`).

`GET /ui/analytics/audience` → `AnalyticsAudienceOut`:
```json
{
  "countries": [ { "code": "US", "name": "United States", "viewers": 70110,
    "percentage": 38.0 } ],
  "devices": [ { "type": "mobile", "viewers": 51240, "percentage": 61.0 } ],
  "total_unique_viewers": 51240
}
```
`percentage` fields here are already **0–100 numbers** (web renders `{pct}%`
directly), unlike `engagement_rate` which is a **0–1 fraction** (rendered
`(rate*100).toFixed(1)%`). Revenue is integer **cents**; watch time is integer
**seconds** (format `h m`).

### 5.5 Engagement payload

`GET /ui/analytics/engagement?period_days=30` → `EngagementRateOut`:
`{ engagement_rate (0–1), engagement_rate_bps, likes, comments, shares, tips,
total_interactions, follower_count, posts_in_period, period_days, trend,
trend_delta }`. `trend`/`trend_delta` are the only period-over-period signal the
backend supplies (see §16 delta correction).

### 5.6 Retrofit service (corrected)

```kotlin
interface AnalyticsService {
    @GET("ui/analytics/overview")
    suspend fun getOverview(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
    ): Response<OverviewDto>

    @GET("ui/analytics/views")
    suspend fun getViews(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
        @Query("granularity") granularity: String = "day",
    ): Response<ViewsDto>

    @GET("ui/analytics/subscribers")
    suspend fun getSubscribers(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
        @Query("granularity") granularity: String = "day",
    ): Response<SubscribersDto>

    @GET("ui/analytics/revenue")
    suspend fun getRevenue(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
        @Query("granularity") granularity: String = "day",
    ): Response<RevenueDto>

    @GET("ui/analytics/top-content")
    suspend fun getTopContent(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
        @Query("sort_by") sortBy: String = "views",
        @Query("limit") limit: Int = 10,
    ): Response<TopContentDto>

    @GET("ui/analytics/audience")
    suspend fun getAudience(
        @Query("from_date") fromDate: String,
        @Query("to_date") toDate: String,
    ): Response<AudienceDto>

    @GET("ui/analytics/engagement")
    suspend fun getEngagement(
        @Query("period_days") periodDays: Int,
    ): Response<EngagementDto>

    /** Pull-to-refresh recompute; followed by a re-query of the GETs above. */
    @POST("ui/analytics/refresh")
    suspend fun refresh(): Response<RefreshDto>
}
```

### 5.7 Error contract

The shared `errorBody → UiError` mapper handles FastAPI `detail` in all three
shapes (string, `[{ "msg": "..." }]`, `{ "code": "...", ... }`). The
`normalizeErrorDetail` helper in the web `client.ts` confirms this multi-shape
handling.
- **422 HTTPValidationError** → the documented validation response for every
  endpoint (e.g. malformed `from_date`). Body is `{ "detail": [{ "loc": [...],
  "msg": "...", "type": "..." }] }`. Treated as a non-recoverable Error (bad
  query construction is a client bug); surface the first `msg`.
- **401** → handled by the auth interceptor: one `POST /ui/session/refresh` then
  a single retry (verified in `client.ts`); not re-implemented here.
- **403** (CSRF/forbidden) → non-recoverable error state.
- **Empty payload** (e.g. `top_content`/`items`/`time_series` all empty) →
  Empty state, not Error. (Note: a dedicated **404** is NOT documented for these
  `/ui/analytics/*` GETs — "no data" surfaces as 200 with empty arrays, matching
  the web client's `length === 0` empty rendering. The earlier "404 → Empty"
  claim is corrected to "empty 200 → Empty".)
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
    val overviewJson: String,        // AnalyticsOverviewOut (KPI tiles + top_content)
    val viewsJson: String,           // AnalyticsViewsOut (views/watch-time series)
    val subscribersJson: String,     // AnalyticsSubscribersOut (growth series)
    val topContentJson: String,      // AnalyticsTopContentOut.items
    val audienceJson: String,        // AnalyticsAudienceOut (countries + devices)
    val engagementJson: String?,     // EngagementRateOut (nullable; optional tile)
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
  seconds→duration, cents→currency, 0–1 fraction→percent, and 0–100
  `percentage` passthrough; correct `from_date`/`to_date` query params from the
  injected `Clock`; multi-endpoint fan-out assembly; **partial-failure** (one
  endpoint 5xx, others 200 → dashboard still renders); cache-first emits
  stale-then-fresh; network fail with cache → stale; without cache → error;
  backoff retry on 503 then 200; no retry on 422; engagement `trend_delta`
  mapped to the engagement tile delta.
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

- **R1 (API shape) — RESOLVED in review:** There is **no** combined
  `/ui/analytics/dashboard` or `/breakdown` endpoint. The surface is six
  per-metric GETs + `POST /refresh` (§5.1), confirmed against
  `openapi.index.txt`, the `Analytics*Out` schemas, and `analytics.ts`. The
  client fans out and assembles the dashboard. Timeseries are server-computed
  (`time_series[]`); deltas are not (see R2).
- **R2 (Delta window) — RESOLVED in review:** No `previous` block exists in any
  payload. Overview KPIs have no period-over-period delta from the API; the web
  shows none. Only `EngagementRateOut` carries `trend`/`trend_delta`.
  *Decision needed in PR:* drop overview-tile deltas (recommended) vs. a costly
  second-window fan-out on the unreliable host.
- **R3 (Duration units) — RESOLVED in review:** Watch time is integer
  **seconds** (`AnalyticsViewsTimeSeriesItem.watch_time_seconds`,
  `total_watch_time_seconds`). Revenue is integer **cents**
  (`*_cents`). Engagement rate is a **0–1 fraction**; audience `percentage` is a
  **0–100** number — do not double-scale.
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
- **AC-2:** Default range is Last 30 days; selecting Last 7 / Last 90 / Last 1y
  re-queries (with `from_date`/`to_date`) and updates tiles, charts, and
  breakdowns; the chosen preset persists across re-entry.
- **AC-3:** Loading shows skeletons; an account with no analytics in range shows
  the Empty state (not an Error).
- **AC-4:** On network failure with cached data, the screen shows cached data
  plus a Stale banner; with no cache, it shows an Error state whose Retry
  re-queries successfully when the host recovers.
- **AC-5:** Watch-time durations rendered as `h m`; revenue rendered from integer
  cents as currency; engagement rate (0–1 fraction) and audience `percentage`
  (0–100) shown as percentages with correct scaling; where a delta exists
  (Engagement `trend_delta`) it is a signed percentage with a non-color-only
  up/down affordance.
- **AC-6:** Only read GETs and the idempotent `POST /ui/analytics/refresh`
  recompute are issued (verified via MockWebServer recorded requests); no
  analytics-mutating/export calls. Each GET carries `from_date`/`to_date` (not
  `start`/`end`).
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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer. Schema names
refer to `reference/openapi.pretty.json` → `components.schemas.<Name>`; index
lines refer to `reference/openapi.index.txt`; frontend pointers are under
`reference/src/`.

1. **Claim:** A single `GET /ui/analytics/dashboard?start=&end=&granularity=`
   returns summary+timeseries.
   **VERDICT: Corrected (does not exist).** No such path in the index.
   **SOURCE:** `openapi.index.txt` lines 1144–1158 list only per-metric
   `/ui/analytics/*` paths; `src/api/endpoints/analytics.ts` defines six GETs +
   `refreshAnalytics`. Replaced by the §5.1 endpoint set.

2. **Claim:** A `GET /ui/analytics/breakdown?...&dimension={content|source}`
   exists with `{ id, label, share }` items.
   **VERDICT: Corrected (does not exist).**
   **SOURCE:** No `/ui/analytics/breakdown` in `openapi.index.txt`. Real
   breakdowns: `GET /ui/analytics/top-content` (`AnalyticsTopContentOut`) and
   `GET /ui/analytics/audience` (`AnalyticsAudienceOut`) —
   index lines 1157, 1144; `src/api/types.ts: AnalyticsTopContentItem`,
   `AnalyticsAudience`.

3. **Claim:** Query params are `start` / `end`.
   **VERDICT: Corrected.** Params are `from_date` / `to_date`.
   **SOURCE:** `openapi.index.txt:1144-1158` (`params=from_date,to_date,...`);
   `src/api/endpoints/analytics.ts: AnalyticsDateRangeParams`;
   `src/pages/analytics/AnalyticsPage.tsx` (`from_date`/`to_date`/`granularity`).

4. **Claim:** KPI tiles = Views, Watch time, Unique viewers, Subscribers net
   delta, Engagement rate.
   **VERDICT: Corrected.** Overview tiles = `period_views`,
   `period_revenue_cents`, `period_new_subscribers`, `total_subscribers`;
   Engagement is a separate endpoint.
   **SOURCE:** schema `AnalyticsOverviewOut`;
   `src/pages/analytics/AnalyticsPage.tsx` SummaryCards (Views/Revenue/New
   Subscribers/Total Subscribers); schema `EngagementRateOut`.

5. **Claim:** Payload contains a `previous` block for period-over-period deltas;
   else issue a second-window GET.
   **VERDICT: Corrected / Unverified-assumption.** No `previous` field on any
   analytics `*Out` schema; web shows no overview delta. Only
   `EngagementRateOut.trend`/`trend_delta` exists.
   **SOURCE:** schemas `AnalyticsOverviewOut`, `AnalyticsViewsOut`,
   `AnalyticsSubscribersOut` (no `previous` property); `EngagementRateOut`
   (`trend`, `trend_delta`). The optional second-window fan-out is an unverified
   design fallback, not an API feature.

6. **Claim:** Watch time is integer seconds; durations format `h m`.
   **VERDICT: Verified.**
   **SOURCE:** schema `AnalyticsViewsTimeSeriesItem.watch_time_seconds` (integer),
   `AnalyticsViewsOut.total_watch_time_seconds`; `src/api/types.ts:3484,3490`.

7. **Claim:** `engagement_rate` and `share` are 0–1 fractions, render as percent.
   **VERDICT: Corrected (partly).** `engagement_rate` is 0–1
   (web renders `(rate*100).toFixed(1)%`). There is no `share`; audience
   `percentage` is already a **0–100** number (web renders `{pct}%` directly).
   **SOURCE:** schema `EngagementRateOut.engagement_rate` (number, default 0.0);
   `AnalyticsCountryItem.percentage` / `AnalyticsDeviceItem.percentage`;
   `src/pages/analytics/AnalyticsPage.tsx:457` (`*100`) vs `:507` (`{c.percentage}%`).

8. **Claim:** Revenue exists and is integer cents.
   **VERDICT: Verified (added).** `period_revenue_cents`, `revenue_cents`,
   `total_cents`, `*_cents` are all integer cents.
   **SOURCE:** schemas `AnalyticsOverviewOut`, `AnalyticsRevenueOut`,
   `AnalyticsRevenueTimeSeriesItem`; `src/pages/analytics/AnalyticsPage.tsx`
   `formatCents` (`cents/100`).

9. **Claim:** Date-range presets are 7 / 28 / 90, default 28.
   **VERDICT: Corrected.** Presets are 7 / 30 / 90 / 365, default 30.
   **SOURCE:** `src/pages/analytics/AnalyticsPage.tsx: RANGE_PRESETS` and
   `daysAgo(30)` default.

10. **Claim:** No mutation/POST is called; pull-to-refresh just bypasses cache.
    **VERDICT: Corrected.** A `POST /ui/analytics/refresh` recompute exists and
    the web Refresh button calls it.
    **SOURCE:** `openapi.index.txt:1154` (`POST /ui/analytics/refresh` →
    `AnalyticsRefreshOut`); `src/api/endpoints/analytics.ts: refreshAnalytics`;
    `AnalyticsPage.tsx` `refreshMut`.

11. **Claim:** Session is cookie-based; `ui_csrf` echoed as `X-CSRF-Token`; on
    401 a `POST /ui/session/refresh` then one retry.
    **VERDICT: Verified (with addition).** Confirmed; the client ALSO sends a
    `Bearer` access token from the auth store (not cookie-only).
    **SOURCE:** `src/api/client.ts:122-124` (`POST /ui/session/refresh`),
    `:168-171` (`ui_csrf`→`X-CSRF-Token`), `:204-221` (refresh-once-then-retry),
    `:157-160` (`Authorization: Bearer`), `:183` (`credentials: include`).

12. **Claim:** FastAPI `detail` arrives in three shapes (string / `[{msg}]` /
    `{code}`) and is mapped to `UiError`.
    **VERDICT: Verified.**
    **SOURCE:** `src/api/client.ts: normalizeErrorDetail` (lines ~200, 230);
    all `/ui/analytics/*` index entries document `422:HTTPValidationError`.

13. **Claim:** "No data" returns 404 → Empty state.
    **VERDICT: Corrected / Unverified-assumption.** No 404 is documented for
    these GETs; web treats empty arrays (200) as the empty state.
    **SOURCE:** `openapi.index.txt:1144-1158` (responses only `200`/`422`);
    `AnalyticsPage.tsx:415,479,524` (`length === 0` empty rendering).

14. **Claim:** Top-content can be server-sorted by engagement.
    **VERDICT: Corrected.** `engagement_rate` is computed server-side and is not a
    valid `sort_by`; sort by `views`, sort engagement client-side.
    **SOURCE:** `AnalyticsPage.tsx:108-111,159` (`sort_by: "views"`, client-side
    engagement sort comment).

15. **Claim (framework):** Jetpack Compose, Hilt, Retrofit/OkHttp/Moshi, Room,
    DataStore, Navigation-Compose on minSdk 24 / compileSdk 35.
    **VERDICT: Unverified-assumption (framework ref).** Stack/versions are
    project conventions, not checkable from the backend/frontend sources.
    **SOURCE (framework ref):** Compose <https://developer.android.com/jetpack/compose>;
    Hilt <https://developer.android.com/training/dependency-injection/hilt-android>;
    Room <https://developer.android.com/training/data-storage/room>; carried from
    AND-027/AND-255 module conventions.

16. **Claim:** Engagement endpoint uses `from_date`/`to_date`.
    **VERDICT: Corrected.** `/ui/analytics/engagement` uses `period_days` (default
    30), not a date range.
    **SOURCE:** `openapi.index.txt:1150` (`params=period_days,...`);
    schema `EngagementRateOut.period_days` (default 30).

### Corrections made

- Replaced the non-existent `/ui/analytics/dashboard` + `/breakdown` design with
  the real six-endpoint fan-out + `POST /refresh` (§5.1–§5.6, §4.4).
- `start`/`end` → `from_date`/`to_date` throughout; engagement uses `period_days`.
- KPI tile set → Views / Revenue / New subscribers / Total subscribers (+ optional
  Engagement); removed the unsupported per-tile delta (kept Engagement
  `trend_delta` only).
- Breakdowns → Top content + Audience (country/device); removed "Traffic by
  source / share".
- Presets 7/28/90 (def 28) → 7/30/90/365 (def 30).
- Pull-to-refresh now calls `POST /ui/analytics/refresh`; FR-9/AC-6 relaxed
  accordingly.
- Units pinned: watch time = seconds, revenue = cents, `engagement_rate` = 0–1,
  audience `percentage` = 0–100.
- Error contract: documented `422:HTTPValidationError`; "404→Empty" corrected to
  "empty 200→Empty".
- Room entity/UiState fields realigned (overview/views/subscribers/topContent/
  audience/engagement; removed `previous`/`trafficSources`).
- Auth note: added the `Bearer` token alongside cookie + CSRF.

### Open assumptions

- **Delta strategy:** whether to drop overview deltas, surface only Engagement
  `trend_delta`, or do a second-window fan-out — a design decision, not derivable
  from the API (no `previous` block). *Why unverifiable:* the backend exposes no
  prior-window data for the overview KPIs.
- **Stale-cache / TTL (15 min) and ~20s timeouts / 3-attempt backoff:** local
  resilience policy from core-network; not specified by backend/frontend sources.
- **Top-level navigation placement** of the Analytics destination: app shell
  decision; the web mounts it at `/analytics` but Android nav is app-owned.
- **Framework/library versions** (Compose/Hilt/Room/etc.): project convention,
  not checkable from backend/frontend (framework ref only).
- **`granularity` use for charts:** backend accepts day/week/month; whether the
  Android screen exposes a granularity selector (web does) is a UX choice.

## 17. Test Plan

Test target keys: **JVM** = local JVM/Robolectric unit (no device); **emu35** =
headless AVD `test35` (x86_64, API 35); **deviceA15** = physical Samsung Galaxy
A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). MockWebServer cases run
on JVM. Compose-UI/instrumented run on emu35 unless real-hardware/ABI behaviour
is required (then deviceA15).

- **TC-AND-399-01 — Happy path: dashboard assembles from fan-out**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer queued 200s for `overview`, `views`,
  `subscribers`, `top-content`, `audience` (engagement optional) with seeded
  `Analytics*Out` bodies; `Clock` fixed at 2026-06-05.
  Steps: call `repository.observeDashboard(LAST_30)`; collect terminal emission.
  Expected: each recorded request path is the §5.1 path with
  `from_date=2026-05-06&to_date=2026-06-05` (engagement uses `period_days=30`);
  domain has KPI tiles (Views/Revenue/New subs/Total subs), views & subscriber
  series, top-content rows, audience country/device rows.
  Traces: AC-1, AC-2, AC-6.

- **TC-AND-399-02 — Range change re-queries with correct dates & persists**
  Type: unit (JVM). Target: JVM.
  Preconditions: ViewModel with fake repo + in-memory DataStore; fixed Clock.
  Steps: emit `RangeSelected(LAST_7)`, then `LAST_90`; recreate ViewModel.
  Expected: repo invoked with 7-day then 90-day `from_date`/`to_date`; persisted
  preset restored on recreation; default before any selection is LAST_30.
  Traces: AC-2.

- **TC-AND-399-03 — Unit/format mapping (seconds, cents, fraction, percentage)**
  Type: unit (JVM). Target: JVM.
  Preconditions: mapper with a payload: `watch_time_seconds=318400`,
  `revenue_cents=188200`, `engagement_rate=0.0613`, audience `percentage=38.0`.
  Steps: map DTO→domain→formatted strings.
  Expected: `318400s` → `88h 26m` (h m); cents → currency `$1,882.00`;
  engagement → `6.1%` (×100); audience percentage rendered `38%` (no ×100).
  Traces: AC-5.

- **TC-AND-399-04 — Validation error (422 HTTPValidationError)**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer returns 422 with
  `{"detail":[{"loc":["query","from_date"],"msg":"invalid date","type":"value_error"}]}`.
  Steps: trigger a fetch.
  Expected: no retry on 422; `UiError` carries the first `msg`; Error state (not
  Empty/crash). Verifies the three-shape `detail` mapper on the list form.
  Traces: AC-6, AC-7.

- **TC-AND-399-05 — Empty 200 → Empty state (not Error)**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: all endpoints 200 with empty arrays / zero totals.
  Steps: fetch; inspect `uiState.isEmpty`.
  Expected: Empty state; no 404 expected/relied on.
  Traces: AC-3.

- **TC-AND-399-06 — Partial failure: one section 5xx, page still renders**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `audience` returns 503 (after backoff still 503); others 200.
  Steps: fetch.
  Expected: tiles + charts + top-content render; audience section shows inline
  error/retry; page not blocked.
  Traces: AC-1, AC-4, AC-7.

- **TC-AND-399-07 — Retry/backoff on 503-then-200; no retry on 4xx**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: `views` queued 503, 503, 200; separately a 422 case.
  Steps: fetch.
  Expected: succeeds within 3 attempts for 503; 422/4xx makes exactly one
  request (no retry).
  Traces: AC-4, AC-6.

- **TC-AND-399-08 — Offline/flaky host: stale cache + banner**
  Type: integration (JVM/Robolectric with Room + MockWebServer). Target: JVM.
  Preconditions: prime Room cache (fetchedAt older than 15-min TTL); next fetch
  throws `IOException` (host unreachable).
  Steps: `observeDashboard(LAST_30)`.
  Expected: cached dashboard emitted with `isStale=true`; "Showing saved data"
  banner; no blocking Error. With cache cleared → Error + Retry.
  Traces: AC-4.

- **TC-AND-399-09 — Pull-to-refresh issues POST /ui/analytics/refresh then re-queries**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: queued `AnalyticsRefreshOut` 200 then fresh metric 200s.
  Steps: emit `Refresh`.
  Expected: a `POST ui/analytics/refresh` recorded request precedes the metric
  GETs; `isRefreshing` toggles true→false; no analytics-mutating/export calls.
  Traces: AC-6, AC-7.

- **TC-AND-399-10 — Compose states: loading/success/empty/error/stale**
  Type: Compose-UI. Target: emu35.
  Preconditions: `createAndroidComposeRule`; drive each `AnalyticsUiState`.
  Steps: render each state; for Error tap Retry → asserts re-query callback;
  toggle range chip → asserts `RangeSelected`.
  Expected: skeletons in Loading; tile labels + chart cards + breakdown rows in
  Success; empty copy in Empty; Retry in Error; Stale banner when `isStale`.
  Traces: AC-1, AC-2, AC-3, AC-4, AC-7.

- **TC-AND-399-11 — Accessibility & i18n**
  Type: Compose-UI (a11y assertions). Target: emu35.
  Preconditions: Success state; TalkBack-style semantics assertions; pseudo-locale
  for i18n.
  Steps: assert each KPI tile/breakdown row has a contentDescription; each chart
  card exposes a text-summary semantics node; range chips have `role=Tab` and
  ≥48dp targets; up/down delta affordance is icon+sign (not color-only); no
  hardcoded strings (all from `strings.xml`).
  Traces: AC-8, AC-5.

- **TC-AND-399-12 — Auth/CSRF headers present; logout clears cache (security)**
  Type: integration/instrumented. Target: emu35.
  Preconditions: MockWebServer + seeded `ui_csrf` cookie + Bearer token via the
  AND-027 interceptor; primed Room cache.
  Steps: perform a fetch; then invoke the session-clear/logout hook.
  Expected: recorded requests carry `X-CSRF-Token` (= cookie) and
  `Authorization: Bearer …`; on a 401 the client does one `POST
  /ui/session/refresh` then retries once; after logout the analytics Room cache
  is empty.
  Traces: AC-6, AC-7.

- **TC-AND-399-13 — Real-host smoke + accessibility on physical device**
  Type: instrumented/e2e. Target: **deviceA15 (MUST run on physical device)**.
  Preconditions: signed-in session against the dev host
  `http://18.222.237.167:8000` (cleartext dev exemption); seeded analytics data.
  Steps: open Analytics on the A15; switch presets; pull-to-refresh; toggle
  airplane mode mid-load to exercise the real flaky/offline path; run TalkBack.
  Expected: dashboards render with real data on arm64-v8a/API 34; offline shows
  stale banner; TalkBack reads tiles/charts. Justification: validates real
  network behaviour against the unreliable plaintext host and arm64-vs-x86 /
  API-34-vs-35 differences not observable on emu35.
  Traces: AC-1, AC-4, AC-8.

- **TC-AND-399-14 — Manual visual check: charts, dark mode, large font scale**
  Type: manual. Target: deviceA15 (or emu35 for theme-only).
  Preconditions: Success state with multi-series data.
  Steps: inspect Views/Subscriber charts vs raw values; switch light/dark; set
  font scale to max; rotate.
  Expected: AND-255 charts render correct shapes; tiles wrap not truncate at
  large scale; dark/light via M3 tokens; no clipping on rotation.
  Traces: AC-1, AC-5, AC-8.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (renders) | TC-01, TC-06, TC-10, TC-13, TC-14 |
| AC-2 (range default/persist/re-query) | TC-01, TC-02, TC-10 |
| AC-3 (loading + empty) | TC-05, TC-10 |
| AC-4 (stale/error/retry, offline) | TC-06, TC-07, TC-08, TC-10, TC-13 |
| AC-5 (formatting + delta affordance) | TC-03, TC-11, TC-14 |
| AC-6 (read GETs + refresh; correct params; no mutation/export) | TC-01, TC-04, TC-07, TC-09, TC-12 |
| AC-7 (unit + Compose coverage green) | TC-04, TC-06, TC-08, TC-09, TC-10, TC-12 |
| AC-8 (a11y + i18n) | TC-11, TC-13, TC-14 |
