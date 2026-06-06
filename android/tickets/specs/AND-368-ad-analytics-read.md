---
id: AND-368
title: Ad analytics (read)
milestone: M8
epic: E47
priority: P2
size: M
status: draft
depends_on: [AND-363, AND-255]
blocks: []
---

# AND-368 — Ad analytics (read)

## 1. Overview & Goal

Deliver a read-only campaign analytics dashboard inside the TestLogon Android app
(`com.testlogon.android`). The feature surfaces performance metrics for a user's
ad campaigns — impressions, clicks, spend, CTR, CPC, and conversions — as
summary KPI tiles plus time-series charts, broken down per campaign and
aggregated per account. There is no create/edit/pause capability in this ticket;
it is strictly a consumer of the `/ui/ads/*` read endpoints.

The goal is a `feature-ads` analytics screen that:

- Loads an account's campaigns and their aggregated metrics over a selectable
  date range.
- Renders KPI tiles and line/bar charts using the shared chart composable from
  AND-255.
- Behaves correctly against the unreliable plaintext dev backend (loading,
  empty, error, offline/stale states), with bounded retry on idempotent GETs.

Success = analytics render for a seeded account with real data, degrade
gracefully when the backend is slow/unreachable, and the screen is fully
covered by ViewModel unit tests and Compose UI tests.

## 2. Context & References

- **Module:** `feature-ads` (new analytics screen + ViewModel), consuming
  `core-network`, `core-model`, `core-data`, `core-ui`.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15,
  Room 2.6 (cache), DataStore (prefs), Paging 3. minSdk 24, compile/target 35,
  JDK 17, AGP 8.7.3, Gradle 8.9.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000`
  (PLAINTEXT HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based session
  with `X-CSRF-Token` echo of the `ui_csrf` cookie; on 401 the client performs
  one `POST /ui/session/refresh` then retries (owned by core-network auth
  interceptor; not re-implemented here).
- **Dependencies:**
  - **AND-363 (Ads accounts API)** — provides the `/ui/ads/accounts*` DTOs and
    Retrofit service for accounts, billing, and campaigns (read). This ticket
    extends/consumes that service for the analytics/metrics payloads.
  - **AND-255 (Reusable charts component)** — provides the line/bar chart
    composable (`TlLineChart` / `TlBarChart`) and `ChartSeries` model. Analytics
    charts MUST reuse this rather than introduce a second charting path.
- **Web reference:** `frontend/src/api/endpoints/ads.ts` and
  `frontend/src/api/types.ts` (campaign + analytics shapes). Mirror field names
  and the FastAPI `detail` error contract (string | `[{msg}]` | `{code,...}`).

## 3. Functional Requirements

FR-1. The user can open an **Ad Analytics** screen for a selected ads account
(account id passed via the navigation route).

FR-2. The screen presents a **date-range selector** with presets: Last 7 days,
Last 28 days, Last 90 days. Default = Last 28 days. Range changes re-query the
backend.

FR-3. The screen renders an **account-level summary row** of KPI tiles:
Impressions, Clicks, Spend, CTR, CPC, Conversions. Currency formatted via the
account's currency; CTR as a percentage; CPC as currency.

FR-4. The screen renders **time-series charts** (reusing AND-255): a spend
line chart and an impressions-vs-clicks chart over the selected range, bucketed
daily.

FR-5. The screen lists **per-campaign rows** showing campaign name, status, and
its key metrics for the range. Rows are read-only (no actions). The list is
paginated when the account has many campaigns (Paging 3 if the endpoint is
paged; otherwise a single bounded fetch).

FR-6. **States:** Loading (skeleton tiles + chart placeholders), Success,
Empty (account has no campaigns or no data in range — distinct copy), and Error
(with Retry). When cached data exists but the network fetch fails, show the
cached data with a **Stale** banner instead of a blocking error.

FR-7. Pull-to-refresh re-fetches the current range and bypasses the cache.

FR-8. All values are read-only. No mutation endpoints are called.

## 4. Technical Design

### 4.1 Module & package layout

```
feature-ads/
  src/main/java/com/testlogon/android/feature/ads/analytics/
    AdAnalyticsRoute.kt          // route + nav wiring
    AdAnalyticsScreen.kt         // stateless Composable(state, onEvent)
    AdAnalyticsViewModel.kt
    AdAnalyticsUiState.kt
    components/
      KpiTileRow.kt
      CampaignRow.kt
      DateRangeSelector.kt
core-model/.../ads/
    AdAnalytics.kt               // domain models
core-data/.../ads/
    AdsAnalyticsRepository.kt
    AdsAnalyticsRepositoryImpl.kt
    local/AdMetricsDao.kt        // Room cache
```

### 4.2 Navigation

```kotlin
const val AD_ANALYTICS_ROUTE = "ads/{accountId}/analytics"

fun NavController.navigateToAdAnalytics(accountId: String) =
    navigate("ads/$accountId/analytics")

fun NavGraphBuilder.adAnalyticsScreen(onBack: () -> Unit) {
    composable(
        route = AD_ANALYTICS_ROUTE,
        arguments = listOf(navArgument("accountId") { type = NavType.StringType }),
    ) { AdAnalyticsRoute(onBack = onBack) }
}
```

`accountId` is read in the ViewModel via `SavedStateHandle`.

### 4.3 ViewModel & UiState

```kotlin
enum class DateRangePreset(val days: Int) { LAST_7(7), LAST_28(28), LAST_90(90) }

data class AdAnalyticsUiState(
    val isLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val range: DateRangePreset = DateRangePreset.LAST_28,
    val summary: AdSummary? = null,
    val spendSeries: ChartSeries = ChartSeries.EMPTY,      // from AND-255
    val trafficSeries: List<ChartSeries> = emptyList(),    // impressions + clicks
    val campaigns: List<CampaignMetricsRow> = emptyList(),
    val isStale: Boolean = false,
    val error: UiError? = null,
) {
    val isEmpty: Boolean
        get() = !isLoading && error == null && summary == null && campaigns.isEmpty()
}

sealed interface AdAnalyticsEvent {
    data class RangeSelected(val preset: DateRangePreset) : AdAnalyticsEvent
    data object Refresh : AdAnalyticsEvent
    data object Retry : AdAnalyticsEvent
}

@HiltViewModel
class AdAnalyticsViewModel @Inject constructor(
    private val repository: AdsAnalyticsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {
    private val accountId: String = checkNotNull(savedStateHandle["accountId"])
    val uiState: StateFlow<AdAnalyticsUiState>
    fun onEvent(event: AdAnalyticsEvent)
}
```

The ViewModel exposes `StateFlow<AdAnalyticsUiState>` (seeded with
`stateIn(SharingStarted.WhileSubscribed(5_000), AdAnalyticsUiState())`). Range
changes and refresh are funneled through `onEvent`; each triggers a repository
call scoped to `viewModelScope`.

### 4.4 Repository

```kotlin
interface AdsAnalyticsRepository {
    /** Cache-first; emits cached (stale=true) then fresh, or error if no cache. */
    fun observeAnalytics(
        accountId: String,
        range: DateRangePreset,
    ): Flow<ApiResult<AdAnalytics>>

    suspend fun refresh(accountId: String, range: DateRangePreset): ApiResult<Unit>
}
```

`AdAnalytics` bundles the account summary, daily metric points, and per-campaign
rows. The impl computes `startDate = today - preset.days` and `endDate = today`
(device local date → ISO `yyyy-MM-dd`), calls the analytics endpoint, maps DTOs
to domain via mappers from AND-363, writes to Room, and emits. On network
failure with a non-empty cache it emits the cached value with `stale=true`.

### 4.5 Chart mapping (AND-255 reuse)

Daily metric points map to `ChartSeries` (`List<ChartPoint(x: Long, y: Float)>`,
where `x` = epoch day). The spend chart uses `TlLineChart`; impressions vs
clicks use a two-series `TlLineChart` (or `TlBarChart` for low day counts).
Currency/number formatting uses `core-ui` formatters; charts receive raw numeric
values and a `valueFormatter` lambda.

## 5. API Contract

All endpoints are read-only GETs requiring the authenticated cookie session and
`X-CSRF-Token`. Base = dev host above. Exact field names confirmed against
`/openapi.json` and `frontend/src/api/endpoints/ads.ts` during implementation;
the shapes below are the contract this ticket codes against.

### 5.1 Account summary metrics

`GET /ui/ads/accounts/{accountId}/analytics?start=YYYY-MM-DD&end=YYYY-MM-DD&granularity=day`

200:
```json
{
  "account_id": "acct_123",
  "currency": "USD",
  "range": { "start": "2026-05-08", "end": "2026-06-05" },
  "summary": {
    "impressions": 482190,
    "clicks": 9134,
    "spend_micros": 1342500000,
    "ctr": 0.0189,
    "cpc_micros": 147000,
    "conversions": 318
  },
  "timeseries": [
    { "date": "2026-05-08", "impressions": 14210, "clicks": 271,
      "spend_micros": 41200000, "conversions": 9 }
  ]
}
```

### 5.2 Per-campaign metrics

`GET /ui/ads/accounts/{accountId}/campaigns/analytics?start=YYYY-MM-DD&end=YYYY-MM-DD&page=1&page_size=25`

200:
```json
{
  "items": [
    { "campaign_id": "camp_9", "name": "Spring Promo", "status": "ACTIVE",
      "impressions": 120400, "clicks": 2310, "spend_micros": 410000000,
      "ctr": 0.0192, "cpc_micros": 177000, "conversions": 88 }
  ],
  "page": 1, "page_size": 25, "total": 12
}
```

Money is integer **micros** (1 USD = 1_000_000); convert client-side to
`BigDecimal`. `ctr` is a fraction (0–1); render as percentage. If the dev
backend lacks a dedicated analytics path, fall back to the AND-363 campaigns
list plus its embedded metric fields and bucket client-side; document the actual
path chosen in the PR.

### 5.3 Retrofit service

```kotlin
interface AdsService {  // extends/co-located with AND-363 service
    @GET("ui/ads/accounts/{accountId}/analytics")
    suspend fun getAccountAnalytics(
        @Path("accountId") accountId: String,
        @Query("start") start: String,
        @Query("end") end: String,
        @Query("granularity") granularity: String = "day",
    ): Response<AccountAnalyticsDto>

    @GET("ui/ads/accounts/{accountId}/campaigns/analytics")
    suspend fun getCampaignAnalytics(
        @Path("accountId") accountId: String,
        @Query("start") start: String,
        @Query("end") end: String,
        @Query("page") page: Int,
        @Query("page_size") pageSize: Int,
    ): Response<CampaignAnalyticsPageDto>
}
```

### 5.4 Error contract

FastAPI `detail` is mapped by the shared `errorBody → UiError` mapper:
`detail` may be a string, `[{ "msg": "..." }]`, or `{ "code": "...", ... }`.
401 → handled by the auth interceptor (refresh-once-then-retry). 403 (CSRF) →
non-recoverable error. 404 (unknown account) → Empty/NotFound state.

## 6. Data & State Management

- **Source of truth:** `AdsAnalyticsRepository` flow → ViewModel `StateFlow`
  → stateless `AdAnalyticsScreen(state, onEvent)`.
- **Cache (Room 2.6):** `ad_metrics` tables keyed by
  `(accountId, rangePreset)` storing the serialized summary, timeseries, and
  campaign rows plus a `fetchedAt` epoch-ms. TTL = 15 min for "fresh"; older
  cache is served as **stale** while a refresh runs. Cache enables the offline
  / unreliable-host stale UI.

```kotlin
@Entity(tableName = "ad_account_metrics", primaryKey-equivalent via composite)
data class AdAccountMetricsEntity(
    val accountId: String,
    val rangePreset: String,
    val summaryJson: String,
    val timeseriesJson: String,
    val fetchedAt: Long,
)
```

- **Prefs (DataStore):** persist the last-selected `DateRangePreset` per device
  so re-entry restores the user's choice.
- **Threading:** all I/O on `Dispatchers.IO` via repository; mappers pure;
  ViewModel never touches Retrofit/Room directly.
- **Date math:** `LocalDate.now(ZoneId.systemDefault())`; formatted with
  `DateTimeFormatter.ISO_LOCAL_DATE`. Injected `Clock` for testability.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call/read/connect ~20s (core-network default for the
  dev host). The screen shows a skeleton up to that bound.
- **Retry:** Idempotent GETs only — bounded exponential backoff (3 attempts,
  base 500ms, jitter) for transient I/O / 5xx, applied in the repository (or
  the shared core-network retry policy). No retry on 4xx (except the 401
  refresh path).
- **Offline / unreachable host:** If `IOException` and cache present → emit
  cached data with `isStale = true` and a dismissible "Showing saved data"
  banner. If no cache → Error state with Retry.
- **Partial failure:** If account summary succeeds but campaign metrics fail,
  render the summary + charts and show an inline error/retry on the campaign
  list section only.
- **No crashes** on malformed/missing JSON fields: Moshi non-fail-fast mapping
  with defaults (missing numeric → 0, missing list → empty), surfaced as Empty
  rather than Error.

## 8. Security & Privacy

- Read-only; no PII entry. Analytics may be commercially sensitive — never log
  raw spend/metric values or full response bodies at non-debug levels.
- Session rides cookies via the persistent cookie jar; `X-CSRF-Token` header is
  attached by the shared interceptor. This ticket adds **no** new auth logic.
- The dev backend is plaintext HTTP; the cleartext exemption is the existing
  dev-only `network-security-config`. No new cleartext domains added. Production
  builds must use HTTPS (tracked by core-network).
- No analytics data persisted beyond the Room cache; cache is app-private
  storage and cleared on logout (hook into the existing session-clear path).

## 9. Accessibility & i18n

- All KPI tiles, chart summaries, and campaign rows expose
  `contentDescription` / `semantics` (e.g., tile reads "Impressions, 482,190").
  Charts include a text-equivalent summary node for screen readers since the
  chart canvas itself is not natively accessible.
- Touch targets ≥ 48dp; date-range chips are `selectable` with `role = Tab`.
- Dynamic type / font-scale respected; tiles wrap rather than truncate at large
  scales. Light + dark theme via Material 3 tokens.
- All copy in `strings.xml` (no hardcoded UI text). Numbers/currency/dates via
  locale-aware `NumberFormat` / `DateTimeFormatter`; currency code from the
  account payload, not hardcoded.

## 10. Telemetry & Logging

- Screen-view event `ad_analytics_viewed` with `account_id` (hashed/opaque) and
  selected `range` — no metric values.
- Latency timing around the analytics fetch (success/failure, duration bucket)
  to monitor the unreliable host.
- Error events tagged with mapped error code/category (not raw body).
- Debug-level structured logs gated behind `BuildConfig.DEBUG`; never log
  cookies, CSRF tokens, or response bodies in release.

## 11. Testing Strategy

**Unit (core-testing + Turbine + MockWebServer):**

- `AdAnalyticsViewModelTest`: range default = LAST_28; `RangeSelected` triggers
  re-fetch; success → tiles + series populated; empty payload → `isEmpty`;
  error → `error` set; refresh sets/clears `isRefreshing`.
- `AdsAnalyticsRepositoryImplTest` (MockWebServer): DTO→domain mapping incl.
  micros→BigDecimal and ctr→percent; cache-first emits stale-then-fresh; network
  fail with cache → stale; without cache → error; backoff retry on 503 then 200;
  no retry on 400.
- Mapper tests for the three FastAPI `detail` shapes.

**Compose UI (`createAndroidComposeRule`):**

- Loading shows skeletons; Success renders tile labels and campaign names;
  Empty shows empty copy; Error shows Retry and tapping it re-queries; Stale
  banner visible when `isStale`.
- Accessibility assertions: tiles/rows have content descriptions; chart has a
  text-summary semantics node.

**Acceptance fixture:** a seeded account JSON (from `/openapi.json` examples or
captured dev response) drives a deterministic UI test proving "analytics
render."

## 12. Dependencies & Sequencing

- **Blocked by AND-363** — must land first to provide ads DTOs / Retrofit
  service and the account currency. This ticket extends that service with the
  two analytics endpoints.
- **Blocked by AND-255** — the chart composable + `ChartSeries` model must exist;
  analytics charts reuse them with no second charting library.
- **Transitively** relies on core-network auth/CSRF/refresh interceptor and the
  persistent cookie jar (already established by earlier M-series tickets).
- **Sequencing:** verify AND-363 DTOs ➝ add analytics endpoints + mappers ➝
  repository + Room cache ➝ ViewModel ➝ Compose screen wiring AND-255 charts ➝
  states + tests. No ticket is blocked by this one.

## 13. Risks & Open Questions

- **R1 (API shape):** Dedicated `/analytics` endpoints may not exist on the dev
  backend; metrics may be embedded in the AND-363 campaign list. Resolve by
  inspecting `/openapi.json` before coding; fall back to client-side bucketing.
  *Open: confirm exact paths, query params, and whether timeseries is server- or
  client-computed.*
- **R2 (Money units):** Spend may be micros, cents, or float currency. Confirm
  units to avoid 1e6 errors; default assumption is integer micros.
- **R3 (Pagination):** Whether campaign analytics is paged. If yes, wire
  Paging 3; if not, a single bounded fetch (cap N) — decided once API confirmed.
- **R4 (Host reliability):** ~20s timeouts may make the screen feel slow;
  mitigated by stale-cache rendering. *Open: acceptable freshness TTL (default
  15 min).*
- **R5 (Chart fit):** AND-255 charts must support multi-series + value
  formatter; if not, raise a follow-up on AND-255 rather than forking charts.

## 14. Acceptance Criteria

- **AC-1 (Renders — primary):** For a seeded ads account with data, opening the
  Ad Analytics screen renders the KPI tile row, both time-series charts, and the
  per-campaign list with correctly formatted currency/percent values.
- **AC-2:** Default range is Last 28 days; selecting Last 7 / Last 90 re-queries
  and updates tiles, charts, and rows.
- **AC-3:** Loading shows skeletons; an account with no campaigns/data shows the
  Empty state (not an error).
- **AC-4:** On network failure with cached data, the screen shows cached data
  plus a Stale banner; with no cache, it shows an Error state whose Retry
  re-queries successfully when the host recovers.
- **AC-5:** Money parsed from micros to correct currency display; CTR shown as a
  percentage; CPC shown as currency.
- **AC-6:** Only read GETs are issued (verified via MockWebServer recorded
  requests); no mutation calls.
- **AC-7:** ViewModel unit tests and Compose UI tests cover loading / success /
  empty / error / stale and pass in CI.
- **AC-8:** KPI tiles, campaign rows, and charts expose accessibility
  descriptions; all strings localized.

## 15. Definition of Done

- Code merged to `android-port` under `feature-ads`, package
  `com.testlogon.android.feature.ads.analytics`, following app → feature → core
  layering.
- `AdAnalyticsViewModel` exposes `StateFlow<AdAnalyticsUiState>`; screen is a
  stateless `(state, onEvent)` Composable; Hilt graph compiles with KSP.
- Analytics endpoints + DTOs + mappers added on top of AND-363; Room cache and
  DataStore range-pref implemented.
- AND-255 chart composable reused (no second charting dependency added).
- All ACs demonstrably met; unit + Compose tests green in CI; ktlint/detekt and
  the project lint baseline clean.
- No cleartext/security regressions; no secrets or response bodies logged in
  release; cache cleared on logout.
- PR documents the actual confirmed API paths, money units, and pagination
  decision (resolving R1–R3).
