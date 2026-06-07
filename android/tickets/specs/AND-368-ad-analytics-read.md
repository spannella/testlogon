---
id: AND-368
title: Ad analytics (read)
milestone: M8
epic: E47
priority: P2
size: M
depends_on: [AND-363, AND-255]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-368 — Ad analytics (read)

## 1. Overview & Goal

Deliver a read-only campaign analytics dashboard inside the TestLogon Android app
(`com.testlogon.android`). The feature surfaces performance metrics for a user's
ad campaigns — impressions, clicks, spend, CTR, plus completion/skip metrics and
period-over-period change — as summary KPI tiles plus time-series charts, with a
dimension breakdown (creative / surface / targeting) and per-campaign filtering.
There is no create/edit/pause capability in this ticket; it is strictly a
consumer of the `/ui/ads/analytics/*` read endpoints.

> NOTE (review correction): The real backend does **not** return `CPC` or
> `conversions` for ads analytics. The summary DTO exposes `cpa_cents`,
> `effective_cpm_cents`, `completes`, `skips`, `completion_rate_pct`, and
> `*_change_pct` deltas instead. KPI tiles must be derived from the actual
> fields (see §5 and §16). Per-campaign metrics come from the breakdown endpoint
> (with `dimension`) and/or the AND-363 campaign list, not a paged
> `campaigns/analytics` endpoint (which does not exist).

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
- **Web reference (verified):** `src/api/endpoints/ads.ts`
  (`getAnalyticsSummary` / `getAnalyticsTimeseries` / `getAnalyticsBreakdown` /
  `exportAnalyticsCsv`) and `src/api/types.ts` (`AdAnalyticsSummary`,
  `AdTimeSeriesPoint`, `AdBreakdownEntry`, `AdAccount`, `Campaign`). Mirror these
  exact field names (cents, `*_pct`) and the FastAPI `detail` error contract
  (string | `[{msg}]` | `{code,...}`); auth/CSRF/refresh in `src/api/client.ts`.

## 3. Functional Requirements

FR-1. The user can open an **Ad Analytics** screen for a selected ads account
(account id passed via the navigation route).

FR-2. The screen presents a **date-range selector** with presets: Last 7 days,
Last 28 days, Last 90 days. Default = Last 28 days. Range changes re-query the
backend.

FR-3. The screen renders an **account-level summary row** of KPI tiles built
from the real `AdAnalyticsSummary` DTO: Impressions, Clicks, Spend, CTR, plus
secondary tiles for CPA, eCPM, and Completion rate. Each tile also surfaces the
period-over-period change (`*_change_pct`) where the DTO provides it.
**Correction:** `ctr_pct` and `completion_rate_pct` are returned **already as
percentages** (do NOT multiply by 100). Money fields are integer **cents**
(`spend_cents`, `cpa_cents`, `effective_cpm_cents`) — NOT micros. There is **no
`currency` field** anywhere in the ads/analytics or account DTOs; format money
with a configured default (assume USD) and track the currency-source gap as an
open assumption (§16). There are no `CPC` or `conversions` fields.

FR-4. The screen renders **time-series charts** (reusing AND-255): a spend
line chart and an impressions-vs-clicks chart over the selected range, bucketed
daily.

FR-5. The screen lists **per-campaign / breakdown rows** showing the dimension
key (or campaign name) and its key metrics for the range. Rows are read-only (no
actions). **Correction:** there is no paged `campaigns/analytics` endpoint and
no `items/page/page_size/total` envelope; `GET /ui/ads/analytics/breakdown`
returns a **bare JSON array** of `AdBreakdownEntry`. Campaign names/status (not
present in breakdown entries) come from the AND-363 campaign list
(`GET /ui/ads/accounts/{account_id}/campaigns`). Because both responses are
unpaged arrays, this ticket uses a **single bounded fetch** (cap N rows
client-side); Paging 3 is **not** wired (the server does not page these).

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

Daily `AdTimeSeriesPoint` entries map to `ChartSeries`
(`List<ChartPoint(x: Long, y: Float)>`, where `x` = epoch day from the `date`
field, `y` = the metric). The spend chart uses `TlLineChart` over
`spend_cents/100`; impressions vs clicks use a two-series `TlLineChart` (or
`TlBarChart` for low day counts). Currency/number formatting uses `core-ui`
formatters; charts receive raw numeric values and a `valueFormatter` lambda.
Note the timeseries response is a bare array, so no envelope unwrap is needed.

## 5. API Contract

All endpoints are read-only GETs requiring the authenticated cookie session and
`X-CSRF-Token` (echo of the `ui_csrf` cookie). Base = dev host above. The shapes
below were **verified during this review** against `openapi.index.txt`,
`openapi.pretty.json`, `frontend/src/api/endpoints/ads.ts`, and
`frontend/src/api/types.ts`. The original draft of this section was substantially
WRONG (wrong paths, path-vs-query params, `start`/`end` vs `days`, micros vs
cents, fictional fields and envelopes); the corrected contract follows. See §16
for the full audit.

> **Review correction (paths & params):** There are NO per-account/per-campaign
> analytics sub-resources. The real endpoints are flat under
> `/ui/ads/analytics/*`, and `account_id` / `campaign_id` are **query
> parameters**, not path segments. The time window is a single integer `days`
> param — there are **no** `start`/`end` date params. `granularity` exists only
> on `timeseries`.

### 5.1 Account summary metrics

`GET /ui/ads/analytics/summary?account_id={id}&days={n}[&campaign_id={cid}]`
(op `analytics_summary_endpoint_ui_ads_analytics_summary_get`)

200 — bare `AdAnalyticsSummary` object (no `account_id`/`currency`/`range`
envelope):
```json
{
  "impressions": 482190,
  "clicks": 9134,
  "ctr_pct": 1.89,
  "spend_cents": 1342500,
  "cpa_cents": 4220,
  "effective_cpm_cents": 278,
  "completes": 31800,
  "skips": 9120,
  "completion_rate_pct": 77.7,
  "previous_period": { "impressions": 460100, "clicks": 8800, "spend_cents": 1290000 },
  "impressions_change_pct": 4.8,
  "clicks_change_pct": 3.8,
  "spend_change_pct": 4.1,
  "days": 28
}
```

### 5.2 Time series (for charts)

`GET /ui/ads/analytics/timeseries?account_id={id}&days={n}[&campaign_id={cid}][&granularity={g}]`
(op `analytics_timeseries_endpoint_ui_ads_analytics_timeseries_get`)

200 — **bare JSON array** of `AdTimeSeriesPoint` (NOT wrapped in `{timeseries:…}`):
```json
[
  { "date": "2026-05-08", "impressions": 14210, "clicks": 271,
    "spend_cents": 41200, "completes": 980, "ctr_pct": 1.91 }
]
```

### 5.3 Dimension / per-campaign breakdown

`GET /ui/ads/analytics/breakdown?account_id={id}&days={n}[&campaign_id={cid}][&dimension={d}]`
(op `analytics_breakdown_endpoint_ui_ads_analytics_breakdown_get`;
`dimension` ∈ creative / surface / targeting per the web client docstring)

200 — **bare JSON array** of `AdBreakdownEntry`:
```json
[
  { "dimension_key": "creative_42", "dimension": "creative",
    "impressions": 120400, "clicks": 2310, "spend_cents": 410000, "ctr_pct": 1.92 }
]
```

`GET /ui/ads/analytics/export?account_id={id}&days={n}[&campaign_id={cid}]` also
exists (CSV download) but is **out of scope** for this read-only dashboard.

Money is integer **cents** (1 USD = 100); convert client-side to `BigDecimal`
via `cents/100`. `ctr_pct` / `completion_rate_pct` are **already percentages** —
render directly, do not multiply. There is **no `currency` field** in any ads
DTO (`AdAccount` only has `balance_cents` / `lifetime_spend_cents`); see §16
open assumptions. Campaign name/status come from the AND-363 campaign list
(`GET /ui/ads/accounts/{account_id}/campaigns` → `Campaign{ name, status, … }`).

### 5.4 Retrofit service

```kotlin
interface AdsAnalyticsService {  // co-located with AND-363 AdsService
    @GET("ui/ads/analytics/summary")
    suspend fun getAccountAnalytics(
        @Query("account_id") accountId: String,
        @Query("days") days: Int,
        @Query("campaign_id") campaignId: String? = null,
    ): Response<AdAnalyticsSummaryDto>

    @GET("ui/ads/analytics/timeseries")
    suspend fun getTimeseries(
        @Query("account_id") accountId: String,
        @Query("days") days: Int,
        @Query("granularity") granularity: String? = "day",
        @Query("campaign_id") campaignId: String? = null,
    ): Response<List<AdTimeSeriesPointDto>>   // bare array

    @GET("ui/ads/analytics/breakdown")
    suspend fun getBreakdown(
        @Query("account_id") accountId: String,
        @Query("days") days: Int,
        @Query("dimension") dimension: String? = null,
        @Query("campaign_id") campaignId: String? = null,
    ): Response<List<AdBreakdownEntryDto>>    // bare array
}
```

### 5.5 Error contract

FastAPI `detail` is mapped by the shared `errorBody → UiError` mapper:
`detail` may be a string, `[{ "msg": "..." }]`, or `{ "code": "...", ... }`.
The dominant documented failure in OpenAPI for these endpoints is **422
`HTTPValidationError`** (e.g. missing/invalid `account_id` or `days`), whose body
is `{ "detail": [{ "loc": [...], "msg": "...", "type": "..." }] }` — the
array-of-`{msg}` shape the mapper must handle.
**Correction:** the original draft asserted a `403 (CSRF) → non-recoverable` and
`404 → Empty/NotFound` contract; OpenAPI only documents `200` and `422` for
these ops, so 403/404 handling is a **defensive assumption**, not a documented
contract (see §16). 401 → handled by the auth interceptor (confirmed
refresh-once-then-retry in `src/api/client.ts`). The web client uses
`X-CSRF-Token` = `ui_csrf` cookie (confirmed); note the OpenAPI declares header
params `user_sub` / `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` on these ops, which
are managed by core-network, not this ticket.

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
  **cents→BigDecimal** (`/100`) and **`ctr_pct` used as-is** (no ×100);
  bare-array deserialization for timeseries/breakdown; cache-first emits
  stale-then-fresh; network fail with cache → stale; without cache → error;
  backoff retry on 503 then 200; no retry on 422 (the real validation error).
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

- **R1 (API shape):** **RESOLVED in this review.** Dedicated analytics endpoints
  DO exist but are flat (`/ui/ads/analytics/{summary,timeseries,breakdown,export}`)
  with `account_id`/`campaign_id` as query params and a `days` window (no
  `start`/`end`). Timeseries is server-computed (bare array of dated points). No
  client-side bucketing fallback is needed.
- **R2 (Money units):** **RESOLVED.** Spend is integer **cents** (`spend_cents`,
  `cpa_cents`, `effective_cpm_cents`, and account `balance_cents`) — NOT micros.
  Divide by 100. The earlier micros assumption was wrong.
- **R3 (Pagination):** **RESOLVED.** Neither timeseries nor breakdown is paged
  (both return bare arrays; no `page`/`page_size`/`total`). Use a single bounded
  fetch (cap N client-side). Paging 3 is NOT used.
- **R6 (Currency display):** No analytics or account DTO carries a `currency`
  code. Money must be formatted with a default (assume USD) until a currency
  source is identified. *Open — see §16.*
- **R7 (CPC/conversions gap):** The product ask mentioned CPC and conversions,
  but the API returns neither. Tiles use CPA/eCPM/completion-rate instead;
  confirm with product whether that satisfies the intent. *Open — see §16.*
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
- **AC-5:** Money parsed from **cents** (`/100`) to correct currency display
  (default USD; no currency field in DTO); `ctr_pct` / `completion_rate_pct`
  shown as percentages **without** re-multiplying; CPA/eCPM shown as currency.
  (Corrected from the original micros/CPC wording.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
`idx` = `reference/openapi.index.txt`; `oas` = `reference/openapi.pretty.json`;
frontend paths are under `reference/src/`.

1. **Ads analytics endpoints exist as flat `/ui/ads/analytics/{summary,timeseries,breakdown,export}`.**
   VERDICT: Corrected (draft claimed `/ui/ads/accounts/{accountId}/analytics`
   and `/ui/ads/accounts/{accountId}/campaigns/analytics`, which do NOT exist).
   SOURCE: idx `GET /ui/ads/analytics/summary`, `GET /ui/ads/analytics/timeseries`,
   `GET /ui/ads/analytics/breakdown`, `GET /ui/ads/analytics/export`;
   frontend `src/api/endpoints/ads.ts: getAnalyticsSummary / getAnalyticsTimeseries
   / getAnalyticsBreakdown / exportAnalyticsCsv`.
2. **`account_id` and `campaign_id` are query params, not path segments.**
   VERDICT: Corrected. SOURCE: idx params for the three ops
   (`params=account_id,campaign_id,...`); `src/api/endpoints/ads.ts`
   (`new URLSearchParams({ account_id: accountId })`).
3. **Time window is an integer `days` param; there are no `start`/`end` params.**
   VERDICT: Corrected (draft used `start=YYYY-MM-DD&end=YYYY-MM-DD`).
   SOURCE: idx (`params=...,days,...`); `src/api/endpoints/ads.ts` (`qp.set("days", …)`).
4. **`granularity` exists only on the timeseries op.**
   VERDICT: Verified. SOURCE: idx `GET /ui/ads/analytics/timeseries`
   (`params=...,granularity,...`); absent from summary/breakdown ops.
5. **Summary response is a flat `AdAnalyticsSummary` (no account_id/currency/range envelope).**
   VERDICT: Corrected. SOURCE: `src/api/types.ts: AdAnalyticsSummary`
   (impressions, clicks, ctr_pct, spend_cents, cpa_cents, effective_cpm_cents,
   completes, skips, completion_rate_pct, previous_period, *_change_pct, days).
6. **Money is integer CENTS, not micros.** VERDICT: Corrected.
   SOURCE: `src/api/types.ts: AdAnalyticsSummary.spend_cents / cpa_cents /
   effective_cpm_cents`, `AdTimeSeriesPoint.spend_cents`, `AdBreakdownEntry.spend_cents`,
   `AdAccount.balance_cents / lifetime_spend_cents`.
7. **CTR is `ctr_pct` (already a percentage), not a 0–1 fraction `ctr`.**
   VERDICT: Corrected. SOURCE: `src/api/types.ts: AdAnalyticsSummary.ctr_pct`,
   `AdTimeSeriesPoint.ctr_pct`, `AdBreakdownEntry.ctr_pct`; also `completion_rate_pct`.
8. **There are no `cpc`/`cpc_micros` or `conversions` fields.** VERDICT: Corrected.
   SOURCE: `src/api/types.ts: AdAnalyticsSummary` (exposes cpa_cents / effective_cpm_cents
   / completes / skips instead; no cpc, no conversions).
9. **Timeseries response is a bare JSON array (`AdTimeSeriesPoint[]`), not `{timeseries:[…]}`.**
   VERDICT: Corrected. SOURCE: `src/api/endpoints/ads.ts: getAnalyticsTimeseries`
   (`api.get<AdTimeSeriesPoint[]>`); `src/api/types.ts: AdTimeSeriesPoint`.
10. **Breakdown response is a bare array (`AdBreakdownEntry[]`) with `dimension_key`/`dimension`; NOT a paged `{items,page,page_size,total}` campaign list.**
    VERDICT: Corrected. SOURCE: `src/api/endpoints/ads.ts: getAnalyticsBreakdown`
    (`api.get<AdBreakdownEntry[]>`); `src/api/types.ts: AdBreakdownEntry`.
11. **No campaign-analytics pagination endpoint exists; campaign analytics is via `campaign_id` filter.**
    VERDICT: Corrected. SOURCE: idx (no `/campaigns/analytics` op); breakdown/summary
    accept optional `campaign_id` (`src/api/endpoints/ads.ts`).
12. **Campaign name/status come from the AND-363 campaign list, not analytics DTOs.**
    VERDICT: Verified. SOURCE: idx `GET /ui/ads/accounts/{account_id}/campaigns`;
    `src/api/types.ts: Campaign { name, status, … }` (analytics DTOs lack name/status).
13. **No `currency` field anywhere in ads/account DTOs.** VERDICT: Corrected
    (draft said currency comes from the account payload / appears in summary).
    SOURCE: `src/api/types.ts: AdAccount` (no currency; only *_cents),
    `AdAnalyticsSummary` (no currency).
14. **Auth = cookie session + `X-CSRF-Token` echo of `ui_csrf` cookie.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
15. **On 401, client refreshes once via `POST /ui/session/refresh` then retries.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`refreshSession()` →
    `fetch(withApiBase("/ui/session/refresh"))`; 401 branch awaits one
    `refreshPromise` then re-fetches; second 401 throws).
16. **FastAPI error `detail` may be string | `[{msg}]` | `{code,…}`; documented failure for these ops is 422 HTTPValidationError.**
    VERDICT: Verified (shape) / Corrected (403/404 specifics — undocumented).
    SOURCE: idx (`resp=200:;422:HTTPValidationError` for all three ops);
    `oas` `components.schemas.HTTPValidationError` (`detail: [{loc,msg,type}]`);
    `src/api/client.errorMapping.test.ts` for the mapper shapes.
17. **OpenAPI declares header params `user_sub` / `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` on these ops (managed by core-network).**
    VERDICT: Verified. SOURCE: idx params suffix on the three analytics ops;
    `src/api/client.ts` sets `X-IMPERSONATION-TOKEN` when impersonating.
18. **Reuse AND-255 `TlLineChart`/`TlBarChart` + `ChartSeries`; minSdk 24 / target 35; Compose + Hilt(KSP).**
    VERDICT: Unverified-assumption (cross-ticket / build-config; not checkable
    from backend/frontend sources). SOURCE: this spec §2/§4 + AND-255 (out of band).
19. **Retrofit `@Query`/bare-`List<…>` body + Moshi non-fail-fast defaults; Room cache TTL 15 min; OkHttp ~20s timeouts; bounded backoff on 5xx/IO.**
    VERDICT: Unverified-assumption (Android framework/impl choices; not in the
    backend/frontend contract). SOURCE: framework ref —
    https://square.github.io/retrofit/ , https://github.com/square/moshi ,
    https://developer.android.com/training/data-storage/room .

### Corrections made

- Endpoint paths rewritten from non-existent `/ui/ads/accounts/{id}/analytics`
  and `/.../campaigns/analytics` to the real flat `/ui/ads/analytics/{summary,
  timeseries,breakdown,export}` (claims 1–2).
- Query params fixed: `account_id`/`campaign_id` are query (not path); `days`
  replaces `start`/`end`; `granularity` only on timeseries (claims 2–4).
- Money unit corrected micros → **cents** (`/100`) throughout §1, §3, §4.5, §5,
  §11, §13-R2, AC-5 (claim 6).
- CTR corrected from 0–1 fraction (`ctr`) to already-percentage `ctr_pct`; added
  `completion_rate_pct` handling (claim 7).
- Removed fictional `cpc_micros` / `conversions`; KPI tiles now use real
  `cpa_cents` / `effective_cpm_cents` / `completes` / `skips` /
  `completion_rate_pct` / `*_change_pct` (claims 5, 8).
- Response envelopes corrected: summary is flat (no account_id/currency/range);
  timeseries and breakdown are bare arrays (claims 5, 9, 10).
- Pagination removed (no paged endpoint → single bounded fetch, no Paging 3)
  (claims 10–11; §3 FR-5, §13-R3).
- Currency-source claim corrected: no `currency` field exists; default to USD
  (claim 13; §3 FR-3, §5, AC-5).
- Error contract: 422 elevated as the documented failure; 403/404 marked as
  defensive assumptions (claim 16; §5.5).
- Retrofit service block rewritten to `@Query` params and bare-array response
  types (§5.4).

### Open assumptions

- **Currency display (R6):** No DTO carries a currency code; defaulting to USD.
  WHY unverifiable: neither backend (idx/oas) nor frontend exposes a currency
  field for ads; web client formats cents without an explicit currency source.
- **CPC/conversions product gap (R7):** API has no CPC or conversions; spec
  substitutes CPA/eCPM/completion-rate. WHY: not derivable from the available
  fields without a click-cost/conversion source the API does not provide.
- **403 (CSRF) / 404 (unknown account) handling:** treated defensively; OpenAPI
  only documents 200/422 for these ops. WHY: not in the documented contract.
- **`days` ↔ preset mapping (7/28/90) and `granularity="day"` default:** the UI
  presets are an Android-side choice; the backend accepts arbitrary `days`. WHY:
  preset values are product/UX, not a backend constraint.
- **Android framework choices** (Retrofit/Moshi/Room/OkHttp/Paging/Hilt, TTL,
  timeouts, backoff, AND-255 chart API): impl decisions, not verifiable against
  the backend/frontend contract.

## 17. Test Plan

Test IDs `TC-AND-368-NN`. Targets: **JVM** (JVM/Robolectric unit, no device),
**emu35** (headless AVD `test35`, x86_64, API 35), **A15** (physical Samsung
Galaxy A15 5G, SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). This ticket is
read-only data + Compose UI with no camera/biometric/WebRTC/FCM/Telecom
behavior, so most cases run on JVM or emu35; A15 is used only for the real-device
ABI/API-34 and real-flaky-host smoke (see TC-13, TC-14).

- **TC-AND-368-01 — Happy-path mapping (contract/MockWebServer).** Target: JVM.
  Preconditions: MockWebServer queued with real-shaped `summary` (flat,
  `spend_cents`/`ctr_pct`), `timeseries` (bare array), `breakdown` (bare array).
  Steps: repository `observeAnalytics(account, LAST_28)`. Expected: GETs hit
  `/ui/ads/analytics/summary?account_id=…&days=28`, `…/timeseries?…&granularity=day`,
  `…/breakdown?…`; DTO→domain maps `spend_cents/100` to BigDecimal, `ctr_pct`
  unchanged; KPI tiles populated; spend & impressions/clicks series non-empty.
  Traces: AC-1, AC-5.

- **TC-AND-368-02 — Default range & re-query on change (unit).** Target: JVM.
  Preconditions: ViewModel with fake repo recording calls. Steps: collect
  initial state; emit `RangeSelected(LAST_7)` then `LAST_90`. Expected: initial
  `range == LAST_28`; each selection issues a fetch with `days=7` then `days=90`
  and updates summary/series/rows. Traces: AC-2.

- **TC-AND-368-03 — Money/percent formatting (unit).** Target: JVM.
  Preconditions: summary `spend_cents=1342500`, `ctr_pct=1.89`,
  `cpa_cents=4220`, `completion_rate_pct=77.7`. Steps: run formatters/mappers.
  Expected: spend renders `$13,425.00` (cents/100, default USD), CTR `1.89%`
  (NOT 189%), CPA `$42.20`, completion `77.7%`. Traces: AC-5.

- **TC-AND-368-04 — Empty state (unit + Compose-UI).** Targets: JVM + emu35.
  Preconditions: summary all-zero / empty timeseries & breakdown arrays. Steps:
  load screen. Expected: `isEmpty == true`; Empty copy shown (distinct from
  error); no crash on empty arrays. Traces: AC-3.

- **TC-AND-368-05 — Loading skeletons (Compose-UI).** Target: emu35.
  Preconditions: repo suspended (in-flight). Steps: render with `isLoading`.
  Expected: skeleton tiles + chart placeholders shown; no data nodes. Traces:
  AC-3, AC-7.

- **TC-AND-368-06 — Error + Retry recovery (contract/MockWebServer + unit).**
  Target: JVM. Preconditions: no cache; MockWebServer returns 503 then, after
  retry exhaustion, surfaces error; second user `Retry` enqueues a 200. Steps:
  load (→ Error), then `Retry`. Expected: bounded backoff (3 attempts) on 503;
  Error state with Retry; Retry re-queries and renders data. Traces: AC-4, AC-7.

- **TC-AND-368-07 — Offline/flaky-host stale cache (contract/MockWebServer).**
  Target: JVM. Preconditions: Room seeded with prior result; network throws
  `IOException`. Steps: `observeAnalytics`. Expected: emits cached value with
  `isStale=true`; no blocking error; with cache cleared, same failure → Error.
  Traces: AC-4.

- **TC-AND-368-08 — 422 validation error mapping (contract/MockWebServer + unit).**
  Target: JVM. Preconditions: MockWebServer returns 422 with
  `{"detail":[{"loc":["query","days"],"msg":"…","type":"…"}]}`. Steps: fetch.
  Expected: mapper handles the `[{msg}]` shape → `UiError`; NO retry on 4xx;
  Error state (not stale). Also assert string-`detail` and `{code}` shapes map.
  Traces: AC-4, AC-6.

- **TC-AND-368-09 — Read-only / no mutation (contract/MockWebServer).** Target:
  JVM. Preconditions: full screen flow incl. range change + pull-to-refresh.
  Steps: drive all interactions; inspect `RecordedRequest`s. Expected: every
  request is GET to `/ui/ads/analytics/*` (or AND-363 campaigns GET); zero
  POST/PUT/PATCH/DELETE. Traces: AC-6.

- **TC-AND-368-10 — Pull-to-refresh bypasses cache (unit + Compose-UI).**
  Targets: JVM + emu35. Preconditions: cached data present. Steps: emit
  `Refresh`. Expected: `isRefreshing` set then cleared; a fresh network fetch is
  issued bypassing the 15-min freshness; UI updates. Traces: AC-4, AC-7.

- **TC-AND-368-11 — Success UI render & state coverage (Compose-UI).** Target:
  emu35. Preconditions: seeded fixture (from captured dev response). Steps:
  render Success. Expected: KPI tile labels, both charts, and breakdown/campaign
  rows visible with formatted values; Stale banner shown when `isStale`. Traces:
  AC-1, AC-7.

- **TC-AND-368-12 — Accessibility & i18n (Compose-UI / instrumented).** Target:
  emu35. Preconditions: Success state; TalkBack-style semantics assertions.
  Steps: query semantics tree. Expected: each KPI tile has a contentDescription
  (e.g. "Impressions, 482,190"); breakdown rows labeled; chart has a text-summary
  semantics node; date chips `role=Tab` & `selectable`; touch targets ≥48dp; no
  hardcoded strings (all from `strings.xml`); renders at large font scale without
  truncation. Traces: AC-8.

- **TC-AND-368-13 — Real-device smoke on physical hardware (instrumented/e2e).**
  Target: **A15 (MUST run on physical device)**. Preconditions: app installed on
  SM-A156U (arm64-v8a, API 34); authenticated session. Steps: open Ad Analytics
  for a seeded account; change range; pull-to-refresh. Expected: analytics render
  correctly on arm64/API-34 (no ABI/desugaring/date-format divergence vs emu35
  API-35); device-locale `NumberFormat`/`DateTimeFormatter` produce correct
  currency/percent/date output. Rationale: catch arm64-vs-x86 and API-34-vs-35
  differences per test-target guidance. Traces: AC-1, AC-2, AC-5.

- **TC-AND-368-14 — Flaky plaintext dev-host behavior on real network (manual/e2e).**
  Target: **A15 (physical device, real cellular/Wi-Fi)**. Preconditions: device
  pointed at the plaintext dev host `http://18.222.237.167:8000` via the dev
  `network-security-config`. Steps: load the screen while the host is slow/
  intermittently unreachable; toggle airplane mode after a successful load.
  Expected: ~20s skeleton bound respected; on timeout/offline with cache →
  Stale banner over cached data; cleartext permitted only for the dev domain;
  recovery on reconnect. Rationale: real-network flakiness/cleartext is best
  exercised on hardware. Traces: AC-4.

- **TC-AND-368-15 — Cache cleared on logout (security; instrumented).** Target:
  emu35. Preconditions: analytics cached in Room. Steps: invoke the session-clear
  / logout path. Expected: `ad_account_metrics` (and metric tables) purged; no
  spend/metric residue in app-private storage; no raw spend/body logged at
  release log level. Traces: AC-6.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (analytics render — primary) | TC-01, TC-11, TC-13 |
| AC-2 (default + range re-query) | TC-02, TC-13 |
| AC-3 (loading / empty states) | TC-04, TC-05 |
| AC-4 (stale cache / error+retry) | TC-06, TC-07, TC-08, TC-10, TC-14 |
| AC-5 (cents→currency, percent, CPA/eCPM) | TC-01, TC-03, TC-13 |
| AC-6 (read-only GETs, no mutation) | TC-08, TC-09, TC-15 |
| AC-7 (VM + Compose tests: load/success/empty/error/stale) | TC-05, TC-06, TC-10, TC-11 |
| AC-8 (accessibility + i18n) | TC-12 |
