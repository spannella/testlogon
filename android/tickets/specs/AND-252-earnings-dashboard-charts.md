---
id: AND-252
title: Earnings dashboard + charts
milestone: M6
epic: E34
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-251, AND-255]
blocks: []
---

# AND-252 — Earnings dashboard + charts

## 1. Overview & Goal

Build the **Earnings dashboard** screen for the TestLogon native Android app: the primary creator-finance surface that renders real earnings data fetched from the FastAPI backend. The screen presents three coordinated regions — (a) **totals** (lifetime, current period, and pending payout headline figures), (b) **time-series charts** (a selectable-range line/bar chart of earnings over time), and (c) **breakdowns** (per-source attribution: the backend's fixed source set is `subscriptions`, `tips`, `unlocks`, `vod_purchases`, `other` — there is no `ads`/`payouts` source in this contract; corrected during review).

This ticket owns the `feature-earnings` UI module: the `EarningsViewModel`, the `EarningsUiState` model, the Compose screen and its sub-composables, range/segment selection logic, and wiring to the data layer. It consumes the typed API + DTOs delivered by **AND-251** (`EarningsApi`, summary/series DTOs and their Moshi mapping) and the reusable chart composable delivered by **AND-255**. The acceptance bar is that the dashboard **renders real earnings** from the dev backend, with correct loading/empty/error/offline states and a working range selector.

Out of scope: the API surface and DTO mapping (AND-251), the chart rendering primitive itself (AND-255), payout-initiation / withdrawal flows, ad-revenue drill-down screens (separate E34 tickets), and CSV/export.

## 2. Context & References

- **Module layering:** `app -> feature-earnings -> core-network, core-model, core-ui, core-data, core-testing`. This ticket creates `feature-earnings`.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 (cache), DataStore (prefs). minSdk 24 / compile+target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Package base:** `com.testlogon.android` (all packages below are under `com.testlogon.android.feature.earnings`).
- **Upstream dependencies:**
  - **AND-251** — `EarningsApi` Retrofit interface + summary/series/breakdown DTOs and domain models (`EarningsSummary`, `EarningsSeries`, `EarningsBreakdown`). This ticket treats those as authoritative; it does not redefine DTOs.
  - **AND-255** — `LineChart` / `BarChart` composables (Vico-backed) accepting a normalized `ChartModel`. This ticket maps domain series into that model.
- **Web reference:** `frontend/src/api/endpoints/earnings.ts` and shared types in `frontend/src/api/types.ts` define the canonical request/response shapes mirrored by AND-251. OpenAPI at `http://18.222.237.167:8000/openapi.json`.
- **Cross-cutting infra:** auth/CSRF cookie jar and 401-refresh (AND-011/012/013), `ApiResult<T>` (AND-018), retry/backoff for idempotent GETs (AND-016), FastAPI `detail` error mapping (AND-015), shared state composables loading/empty/error/offline (AND-021), Material 3 theme (AND-019), authenticated nav graph + bottom nav (AND-024).
- **Backend reliability:** dev host is plaintext HTTP and unreliable; ~20s timeouts, bounded backoff retry on idempotent GETs only, offline/stale UI required.

## 3. Functional Requirements

1. **Totals header.** Display primary KPI cards. The backend (`/ui/earnings/quick-stats`) supplies `today_cents`, `this_week_cents`, `this_month_cents`, `all_time_cents`, and `pending_payout_cents`. The web client renders four cards (Today / This Week / This Month / All Time) and does **not** surface pending-payout; this ticket may additionally surface *Pending payout* (open question §13) and a *This period* total from the summary call's `total_cents`. **CORRECTED:** there is **no** `period_change_pct` / delta field in either response — the "% change vs. previous period" delta indicator is **not backend-supported**; either drop it or compute it client-side from a second summary call for the prior period (treat as out of scope unless confirmed). Values are localized via `NumberFormat.getCurrencyInstance`.
2. **Range selector.** A segmented control offering `7D`, `30D`, `90D`, `1Y`, `ALL` (web uses labels `7d/30d/90d/1y/All`; corrected from `12M`). **CORRECTED:** the range is NOT a backend param — it is converted client-side to `from_date`/`to_date` (`today - days`; `ALL` omits both). A separate `granularity` control (`day`/`week`/`month`) drives the chart bucketing. Changing the range re-queries quick-stats (unchanged, no range) + summary and updates totals, chart, and breakdown atomically. Default range is `30D`. The selection is persisted to DataStore so it survives process death and is restored on next visit.
3. **Time-series chart.** Render a line chart (default) of earnings amount over time for the selected range, using the AND-255 chart composable. Support a chart-type toggle to a bar chart for granularity that is naturally discrete (daily/weekly buckets). The chart shows axis labels, a currency-formatted Y axis, and date-formatted X axis. Tapping/selecting a data point surfaces a tooltip with the exact date + value.
4. **Breakdowns.** Render a list of earnings sources with per-source amount, share-of-total percentage, and a proportional inline bar. Sorted descending by amount. If a source is zero for the range, hide its row rather than show zero noise (web filters `v > 0`). **CORRECTED:** the source set is the fixed `EarningsBreakdown` keys — `subscriptions`, `tips`, `unlocks`, `vod_purchases`, `other` (not `ads`/`payouts`). Localized labels per the web map: Subscriptions / Tips / Unlocks / VOD Purchases / Other.
5. **Loading state.** First load shows skeleton placeholders for totals, chart, and breakdown (via AND-021 primitives).
6. **Empty state.** When the account has no earnings in the selected range (all zero / empty series), show a friendly empty state with the range selector still interactive.
7. **Error state.** On a non-recoverable failure, show the shared error state with a Retry action that re-triggers the load.
8. **Offline / stale state.** If the network is unavailable but a cached snapshot exists, render cached data with a "Showing saved data" banner and a timestamp; if no cache exists, show the offline state.
9. **Pull-to-refresh** re-fetches the current range, bypassing cache.
10. **Navigation.** Reachable from the authenticated graph (bottom-nav "Earnings" entry or More hub). Route: `earnings`. Deep-linkable to a specific range via `earnings?range={range}`.

## 4. Technical Design

New module `feature-earnings`. Packages under `com.testlogon.android.feature.earnings`.

**Repository (this ticket; thin orchestration over AND-251 `EarningsApi`).**

```kotlin
package com.testlogon.android.feature.earnings.data

interface EarningsRepository {
    fun observeDashboard(range: EarningsRange): Flow<ApiResult<EarningsDashboard>>
    suspend fun refresh(range: EarningsRange): ApiResult<EarningsDashboard>
}

data class EarningsDashboard(
    val summary: EarningsSummary,            // from core-model (AND-251)
    val series: EarningsSeries,              // from core-model (AND-251)
    val breakdown: List<EarningsBreakdown>,  // from core-model (AND-251)
    val currency: String,
    val asOf: Instant,                       // server "as of" or fetch time
    val isStale: Boolean = false,
)

// CORRECTED: the backend has no `range` param. Each range maps to a day-count
// used to compute from_date = today - days (null days = all-time, omit dates).
// Web presets are 7d/30d/90d/1y/All (note "1y", not "12m").
enum class EarningsRange(val days: Int?) {
    D7(7), D30(30), D90(90), Y1(365), ALL(null)
}
```

`EarningsRepositoryImpl` (Hilt `@Singleton`) issues **two** GETs concurrently (`coroutineScope { async {} }`): `EarningsApi.getQuickStats()` (for lifetime / pending-payout / period headline figures) and `EarningsApi.getSummary(fromDate, toDate, granularity)` where `fromDate`/`toDate` are derived from the selected `EarningsRange` (`today - days`, or omitted for `ALL`) and `granularity` defaults to `day` (client may choose `week`/`month` for wide ranges). It combines them into `EarningsDashboard`, writes the result to a Room cache keyed by range, and emits cache-first then network via `observeDashboard`. **CORRECTED:** there is no `/ui/earnings/series` endpoint and no summary `by_source` array — the chart's time series comes from `EarningsSummaryOut.time_series` and the breakdown from the `EarningsSummaryOut.breakdown` fixed-key object (both in the single summary call). Quick-stats is a separate call because the lifetime/pending figures are not in the summary payload.

**Caching.** Room entity `EarningsSnapshotEntity(range: String PK, payloadJson: String, currency: String, fetchedAtEpochMs: Long)` in `core-data` or module-local DAO. `observeDashboard` emits the cached snapshot immediately (flagged `isStale = true` if older than 15 min), then fetches fresh and re-emits.

**ViewModel.**

```kotlin
@HiltViewModel
class EarningsViewModel @Inject constructor(
    private val repo: EarningsRepository,
    private val prefs: EarningsPrefs,        // DataStore-backed range persistence
    savedState: SavedStateHandle,
) : ViewModel() {

    val uiState: StateFlow<EarningsUiState>          // see §6
    fun onRangeSelected(range: EarningsRange)
    fun onChartTypeToggled()
    fun onRefresh()                                   // pull-to-refresh, force network
    fun onRetry()
    fun onPointSelected(index: Int?)                  // tooltip selection
}
```

The VM holds a `MutableStateFlow<EarningsRange>` (seeded from deep-link arg → DataStore → default `D30`) and `flatMapLatest`s it into `repo.observeDashboard(range)`, mapping `ApiResult` into `EarningsUiState`. Range/chart-type changes update internal flows; `onRangeSelected` also persists to DataStore.

**Screen.**

```kotlin
@Composable
fun EarningsRoute(viewModel: EarningsViewModel = hiltViewModel(), onBack: () -> Unit)

@Composable
fun EarningsScreen(
    state: EarningsUiState,
    onRangeSelected: (EarningsRange) -> Unit,
    onChartTypeToggled: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onPointSelected: (Int?) -> Unit,
)
```

Sub-composables: `TotalsRow(totals, modifier)`, `RangeSelector(selected, onSelect)`, `EarningsChartCard(series, chartType, selectedIndex, currency, onPointSelected)` (delegates to AND-255 `LineChart`/`BarChart`), `BreakdownList(items, currency)`. The chart card maps `EarningsSeries.points` to the AND-255 `ChartModel`:

```kotlin
// CORRECTED: time-series points come from EarningsSummaryOut.time_series.
// Each point's date field is "date" (ISO YYYY-MM-DD string) and the plotted
// value is the per-point "total" (cents). Per-source fields (subscriptions,
// tips, unlocks, vod_purchases, other) are available for a stacked chart,
// which is what the web client renders (stacked area by source).
fun List<TimeSeriesPoint>.toChartModel(): ChartModel =
    ChartModel(
        x = map { LocalDate.parse(it.date).toEpochDay().toFloat() },
        y = map { it.totalCents / 100f },           // "total" cents -> major units
        xLabeler = { epochDay -> formatBucketLabel(LocalDate.ofEpochDay(it.toLong())) },
        yLabeler = { currencyShort(it) },
    )
```

**Money handling.** Amounts are integer **cents** (e.g. `total_cents`, `*_cents`, breakdown values; field naming corrected from `*_minor`) from the backend; convert to major units only at format time to avoid float drift in computation. Percentage shares computed in integer cents (share = round(sourceCents / totalCents * 100), matching the web client).

**Navigation registration** (in authenticated nav graph, AND-024):

```kotlin
composable(
    route = "earnings?range={range}",
    arguments = listOf(navArgument("range") { nullable = true; defaultValue = null }),
) { EarningsRoute(onBack = navController::popBackStack) }
```

## 5. API Contract

Endpoints are **owned and tested by AND-251**; this ticket consumes them. Documented here for the consuming contract. **CORRECTED during review** — verified against `openapi.index.txt`, `openapi.pretty.json` (`EarningsSummaryOut`, `EarningsQuickStatsOut`, `EarningsBreakdown`, `TimeSeriesPoint`) and the web client (`src/api/endpoints/earnings.ts`, `src/api/types.ts`, `src/pages/earnings/EarningsPage.tsx`).

> **Important corrections:** There is **no** `range` query param and **no** `/ui/earnings/series` endpoint. The dashboard is assembled from **two** GETs: `/ui/earnings/quick-stats` (lifetime / pending-payout / period headline figures) and `/ui/earnings/summary` (total, breakdown, and embedded time-series for the chart). Range is expressed as `from_date`/`to_date` (YYYY-MM-DD) computed client-side; chart granularity is the `granularity` param (`day|week|month`). All money fields are integer **cents** (`*_cents`), not `*_minor`. There is **no** `as_of`, no `totals` object, no `period_change_pct`, and the breakdown is a **fixed-key object** (`subscriptions`/`tips`/`unlocks`/`vod_purchases`/`other`), not an array of `{source, amount_minor, share_pct}`. There is **no** `ads` or `payouts` earnings source in this contract.

**GET `/ui/earnings/quick-stats`** (`EarningsQuickStatsOut`) → 200:

```json
{
  "today_cents": 4200,
  "this_week_cents": 31800,
  "this_month_cents": 120500,
  "all_time_cents": 4827310,
  "pending_payout_cents": 120000,
  "currency": "USD"
}
```

All numeric fields default to `0` and `currency` defaults to `"USD"` server-side. The web app renders four KPI cards from this (`Today`, `This Week`, `This Month`, `All Time`); `pending_payout_cents` exists in the schema but is **not** surfaced by the web client (see §13 open question on whether to show it).

**GET `/ui/earnings/summary?from_date={YYYY-MM-DD}&to_date={YYYY-MM-DD}&granularity={day|week|month}`** (`EarningsSummaryOut`) → 200:

```json
{
  "total_cents": 318900,
  "transaction_count": 87,
  "currency": "USD",
  "breakdown": {
    "subscriptions": 98500,
    "tips": 40000,
    "unlocks": 12000,
    "vod_purchases": 8000,
    "other": 1500
  },
  "time_series": [
    { "date": "2026-05-07", "total": 10200, "subscriptions": 6000, "tips": 3000, "unlocks": 800, "vod_purchases": 400, "other": 0 },
    { "date": "2026-05-08", "total": 9800,  "subscriptions": 5500, "tips": 2800, "unlocks": 1000, "vod_purchases": 500, "other": 0 }
  ]
}
```

Notes: `granularity` defaults to `day` server-side; `from_date`/`to_date` are optional (omitting both = all-time, matching the web "All" preset). `from_ts`/`to_ts` (Unix seconds) are accepted alternatives but the web client uses the date form. Each `TimeSeriesPoint` carries per-source cents plus `total`; the only required field is `date`. The `EarningsBreakdown` object's keys are the canonical source set. (Caveat: the frontend `EarningsSummary` TS interface omits `time_series`, but `EarningsPage.tsx` reads `summary.time_series` and the OpenAPI schema includes it — treat `time_series` as present.)

Both are **idempotent GETs** → eligible for bounded backoff retry (AND-016) and for the 401→refresh→retry path. Requests ride the persistent cookie session (`credentials: include`); the web client also attaches an `Authorization: Bearer <token>` header and a CSRF header named **`X-CSRF-Token`** read from the `ui_csrf` cookie — attached uniformly to all requests including GETs (verified `src/api/client.ts`). CSRF is not strictly required for these safe GETs but is sent. The 401-refresh path calls **`POST /ui/session/refresh`** then retries once. Granularity is chosen client-side and sent as `granularity`; there is no server "bucket" echo field.

**Error envelope** (FastAPI `detail`, mapped by AND-015): `422` validation returns `HTTPValidationError` with `detail: [{loc, msg, type}]` (verified — both endpoints declare `422:HTTPValidationError`); `401` handled by refresh authenticator; `5xx`/timeout → recoverable error surfaced as Retry. **Note:** the OpenAPI declares only `200` and `422` for these endpoints — `401`/`5xx` are runtime/transport realities, not documented responses. Empty/zero data is a **200 with empty `time_series` / zeroed `total_cents` and breakdown**, not an error → empty state.

## 6. Data & State Management

```kotlin
sealed interface EarningsUiState {
    val range: EarningsRange
    data class Loading(override val range: EarningsRange) : EarningsUiState
    data class Empty(override val range: EarningsRange) : EarningsUiState
    data class Error(
        override val range: EarningsRange,
        val message: String,
        val recoverable: Boolean,
    ) : EarningsUiState
    data class Offline(override val range: EarningsRange) : EarningsUiState
    data class Ready(
        override val range: EarningsRange,
        val totals: TotalsUi,
        val chart: ChartUi,
        val breakdown: List<BreakdownRowUi>,
        val chartType: ChartType,
        val selectedPoint: Int?,
        val isStale: Boolean,
        val asOfLabel: String,
        val isRefreshing: Boolean,
    ) : EarningsUiState
}

// periodChangePct is nullable and currently always null: no backend field supplies it (see §5/§3.1 correction).
data class TotalsUi(val lifetime: String, val period: String, val pending: String, val periodChangePct: Float?)
data class ChartUi(val model: ChartModel, val pointDates: List<LocalDate>, val pointValues: List<String>)
data class BreakdownRowUi(val source: String, val label: String, val amount: String, val sharePct: Float)
enum class ChartType { LINE, BAR }
```

- VM exposes a single `StateFlow<EarningsUiState>` (started `WhileSubscribed(5_000)`, initial `Loading(initialRange)`).
- Range and chart-type are held in the VM; range is persisted via `EarningsPrefs` (DataStore `Preferences`, key `earnings_range`). Chart type is session-only.
- `Ready.isStale` drives the "Showing saved data" banner; `asOfLabel` is the formatted `asOf`.
- Selected-point state is UI-only and reset when range/chart-type changes.
- Room snapshot is the single source of truth for offline; the repo never returns partial dashboards (both summary+series must resolve, else error/offline).

## 7. Error Handling & Resilience

- **Timeouts:** rely on the global OkHttp ~20s timeouts (AND-009); a timeout surfaces as recoverable `Error` (or `Offline` if connectivity probe says no network, AND-017).
- **Retry/backoff:** both endpoints are idempotent GETs and go through the AND-016 retry interceptor; the UI Retry/refresh is the user-facing fallback after automatic retries are exhausted.
- **401:** handled transparently by the refresh authenticator (AND-013); a second 401 propagates as auth failure and the auth-gated router (AND-025) ejects to login — the earnings VM does not special-case it.
- **Partial failure:** if summary succeeds but series fails (or vice versa), the combined call fails → fall back to cache if present (stale `Ready`) else `Error`/`Offline`. No half-rendered dashboard.
- **Stale data:** cached snapshot older than 15 min is shown with the stale banner while a background refresh runs; success replaces it silently.
- **Malformed/missing fields:** Moshi mapping (AND-251) defaults absent numeric fields to 0 (matches the backend, where all `*_cents` and breakdown fields default to 0); `currency` defaults to `"USD"` server-side and as a client fallback. (The earlier claim of deriving currency from `/ui/me` is an unverified assumption — both earnings schemas already carry `currency` with a `"USD"` default, so a `/ui/me` lookup is unnecessary.)
- **Empty series with non-zero totals** (rare): render totals + breakdown, show an in-chart "No revenue data for this period" placeholder (web wording) rather than the full-screen empty state.

## 8. Security & Privacy

- Earnings figures are sensitive financial PII. **Never log raw amounts** — telemetry uses only ranges, counts, and outcome enums (§10).
- All requests are authenticated via the existing cookie session; no tokens or amounts are placed in URLs beyond the `range`/`bucket` query params.
- The Room snapshot persists earnings JSON on-device. It lives in app-private storage; the DAO must be cleared on logout — `EarningsRepository.clear()` is invoked by the central logout cleanup (AND-032). No earnings cache may survive a session change.
- No earnings values in crash reports, screenshots of analytics, or `toString()` of DTOs that could reach logs. Disable `FLAG_SECURE`? Not required by this ticket, but mark the screen as a candidate for screenshot suppression in a later hardening ticket (open question §13).
- Dev backend is plaintext HTTP (cleartext permitted only for the dev flavor per AND-006); no change here.

## 9. Accessibility & i18n

- All KPI cards, chart, and breakdown rows expose `contentDescription`/`semantics`. Each totals card reads as "All time, 48,273 dollars 10 cents" (web uses `aria-label="<title>: $48,273.10"` on each card). The chart exposes a textual `stateDescription` summary (e.g. "Revenue over time, 30 days, total 3,189 dollars" — note: no backend % change field exists, so avoid an "up 14 percent" claim) plus a data-table fallback reachable via a "View as table" affordance for screen-reader users (chart canvases are not natively traversable).
- Range segmented control uses `Tab`/`selectable` semantics with `selected` state and role.
- Currency and dates formatted via `NumberFormat`/`DateTimeFormatter` with the device locale; all strings in `strings.xml` (`feature-earnings`), no hardcoded UI text. Source labels (`ads`, `tips`, …) mapped through a localized label table, not raw API enums.
- Color is not the sole signal for the delta indicator (up/down arrow glyph accompanies the green/red). Meets 4.5:1 contrast on Material 3 theme tokens (AND-019). Supports dynamic type / large font scaling without truncating KPI values (auto-size or wrap).
- RTL-safe layouts (logical start/end paddings).

## 10. Telemetry & Logging

Events via the app analytics facade (no raw monetary values):

- `earnings_view_opened { range }`
- `earnings_range_changed { from, to }`
- `earnings_chart_type_changed { type }`
- `earnings_load_result { range, outcome: success|empty|error|offline|stale, latency_ms, source_count }`
- `earnings_refresh_invoked { range, trigger: pull|retry }`
- `earnings_point_selected { range }` (no value, no date payload beyond bucket index count)

Logging: redacted, structured logs at `Timber` debug for cache hit/miss and stale decisions; **amounts and currency totals are never logged** (only field presence and counts). Network logging follows the OkHttp logging interceptor policy (AND-009) which redacts bodies in release.

## 11. Testing Strategy

**Unit (core-testing + JUnit/Turbine/MockK):**
- `EarningsViewModelTest`: initial `Loading` → `Ready` on success; success-with-empty → `Empty`; error → `Error(recoverable=true)`; offline w/ cache → stale `Ready` + banner; range change re-queries and persists to prefs; chart-type toggle flips and resets selected point; refresh sets `isRefreshing` then clears.
- `EarningsRepositoryImplTest`: concurrent summary+series combine; cache-first emission then network re-emit; partial failure → falls back to cache/error; stale threshold (15 min) computation; `clear()` empties DAO.
- Mapper tests: `EarningsSeries.toChartModel()` axis/value mapping; minor→major conversion; share-pct sort order and zero-row filtering.

**MockWebServer (AND-046 harness + fixtures):** golden JSON fixtures for `EarningsQuickStatsOut` and `EarningsSummaryOut` per range (populated, empty/zeroed, 422 `HTTPValidationError`, 500, slow/timeout). Assert correct query params on the summary call (`from_date`, `to_date`, `granularity`) — and that quick-stats carries no range params — and that retry fires on 500 then succeeds.

**Compose UI tests:** `EarningsScreen` renders totals/chart/breakdown for `Ready`; skeletons for `Loading`; empty/error/offline states show correct affordances; range segmented control selection updates; Retry invokes callback; semantics nodes present for accessibility (table fallback exists). Chart presence asserted via test tag (chart internals owned by AND-255 tests).

**CI:** runs under unit (AND-050) and instrumented headless-emulator (AND-051) jobs.

## 12. Dependencies & Sequencing

- **Hard deps:** **AND-251** (API + DTOs/models — must land first; this module imports its `EarningsApi` and domain models) and **AND-255** (chart composable — required for the chart card). Both P0 in M6/E34.
- **Transitive infra (already planned, must exist):** AND-018 (`ApiResult`), AND-015 (error mapping), AND-016 (GET retry), AND-013/012/011 (auth/CSRF/cookie jar), AND-021 (state composables), AND-019 (theme), AND-024 (authenticated nav graph), AND-032 (logout cleanup hook for cache clear), AND-046 (MockWebServer harness).
- **Sequencing:** AND-251 → AND-255 → **AND-252**. This ticket **blocks** nothing in the source bullets but is the reference consumer that later finance screens (payouts/ads detail) follow; the AND-255 chart and AND-251 DTOs are validated end-to-end here.
- New module wiring: register `feature-earnings` in `settings.gradle.kts` and add to `app` dependencies; Hilt module `EarningsModule` provides `EarningsRepository` binding.

## 13. Risks & Open Questions

- **Bucket/granularity authority:** RESOLVED during review — the backend accepts a `granularity` query param (`day|week|month`, default `day`) and does **not** echo a `bucket` field. The client sends `granularity`; the web exposes it as a separate selector. No client-side override-vs-server reconciliation is needed.
- **`period_change_pct` availability:** RESOLVED during review — there is **no** such field in `EarningsSummaryOut` or `EarningsQuickStatsOut`. The delta/% change indicator is not backend-supported. Decision needed: drop it, or compute client-side via a second summary call for the prior equal-length period (currently treated as out of scope; `TotalsUi.periodChangePct` stays null).
- **Currency mixing:** Assumes a single account currency. If the backend can return multi-currency earnings, the totals/chart aggregation model needs revision — out of scope, flag for product.
- **Chart performance for `ALL`:** month-bucketed series should be small, but a creator with years of daily data on `ALL` without bucketing could be large; rely on server bucketing — verify max point count.
- **Screenshot suppression:** Should the earnings screen set `FLAG_SECURE`? Deferred to a security-hardening ticket; noted in §8.
- **Pending payout placement:** Whether "pending payout" belongs on this dashboard or only on a payouts screen — current design includes it as a headline; confirm with design.

## 14. Acceptance Criteria

1. Navigating to `earnings` from the authenticated graph fetches and **renders real earnings** from the dev backend: totals (from `/ui/earnings/quick-stats` + summary `total_cents`), a time-series chart (summary `time_series`), and a source breakdown (summary `breakdown`).
2. The range selector (`7D/30D/90D/1Y/ALL`, mapped to `from_date`/`to_date`) re-queries and updates all three regions atomically; the selected range is persisted across process death (DataStore).
3. The chart renders the returned `time_series` points via the AND-255 composable with currency-formatted Y axis and date X axis; the line/bar toggle works; selecting a point shows date + exact value.
4. Breakdown rows show per-source amount, share %, and proportional bar, sorted descending, with zero/empty sources hidden.
5. Loading shows skeletons; a 200 with empty data shows the empty state; a 5xx/timeout shows a recoverable error with a working Retry; offline-with-cache shows stale data + "Showing saved data" banner + timestamp; offline-no-cache shows the offline state.
6. Pull-to-refresh forces a network fetch bypassing cache.
7. No monetary values appear in logs or telemetry (verified by test asserting redaction); earnings cache is cleared on logout.
8. Money is computed in integer **cents** and only formatted to major units at display, with locale-correct currency formatting.
9. Unit, MockWebServer, and Compose UI tests for the states above pass in CI (AND-050/AND-051).

## 15. Definition of Done

- `feature-earnings` module created, wired into `settings.gradle.kts` and `app`, builds under AGP 8.7.3 / Gradle 8.9 / JDK 17.
- `EarningsRepository`(+Impl), `EarningsViewModel`, `EarningsUiState`, `EarningsScreen` and sub-composables, Room snapshot DAO/entity, and `EarningsPrefs` implemented per §4–§6.
- Consumes AND-251 `EarningsApi`/models and AND-255 chart composable without redefining either.
- All five UI states (loading/ready/empty/error/offline+stale), range persistence, chart toggle, point selection, and pull-to-refresh function against the dev backend.
- Telemetry events emitted per §10 with redaction; cache-clear-on-logout wired (AND-032).
- Accessibility: semantics on all interactive/data nodes, chart table fallback, dynamic type safe, localized strings — verified.
- Tests in §11 written and green in CI; lint/detekt/ktlint (AND-005) clean.
- Code reviewed and merged to `android-port`; spec acceptance criteria (§14) demonstrably met.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Source shorthand: `index` = `reference/openapi.index.txt`; `schema:<Name>` = `components.schemas.<Name>` in `reference/openapi.pretty.json`; frontend paths are under `reference/src/`.

1. **Dashboard data comes from `/ui/earnings/summary`.** VERIFIED (but contract was wrong — see corrections). Source: `index` line `GET /ui/earnings/summary | op=earnings_summary_ui_earnings_summary_get | resp=200:EarningsSummaryOut;422:HTTPValidationError`; `src/api/endpoints/earnings.ts: getEarningsSummary`.
2. **Spec claimed a second `/ui/earnings/series` endpoint.** CORRECTED — no such endpoint exists. Source: `index` (earnings endpoints are only `quick-stats`, `summary`, `transactions`; plus `/api/creators/{creator_id}/earnings` and a syndicate one). Time series is embedded in `schema:EarningsSummaryOut.time_series`.
3. **Spec claimed `?range={7d|30d|90d|12m|all}` query param.** CORRECTED — the summary endpoint takes `from_date`, `to_date`, `granularity` (and `from_ts`/`to_ts`), no `range`. Source: summary `parameters` block in `schema`/path (`openapi.pretty.json` ~L205903-206040); `src/api/endpoints/earnings.ts: getEarningsSummary` params `{from_date, to_date, granularity}`; `src/pages/earnings/EarningsPage.tsx` computes `fromDate=daysAgo(n)`, `toDate=isoDate(new Date())`.
4. **Range presets `7D/30D/90D/12M/ALL`.** CORRECTED label — web presets are `7d/30d/90d/1y/All` (note "1y" not "12m"). Source: `src/pages/earnings/EarningsPage.tsx: PRESETS`.
5. **`granularity` param `day|week|month`, default `day`.** VERIFIED. Source: summary path param "Time series grouping: day, week, month", default `day` (`openapi.pretty.json` ~L205944); `src/pages/earnings/EarningsPage.tsx: granularity` selector.
6. **Lifetime / pending-payout / period headline figures.** CORRECTED — these are NOT in the summary payload; they come from `/ui/earnings/quick-stats` (`all_time_cents`, `pending_payout_cents`, `this_month_cents`, `this_week_cents`, `today_cents`, `currency`). Source: `schema:EarningsQuickStatsOut`; `index` `GET /ui/earnings/quick-stats`; `src/pages/earnings/EarningsPage.tsx` QuickStatCards.
7. **Money fields are `*_minor` units.** CORRECTED to integer **cents** (`total_cents`, `all_time_cents`, breakdown int values, etc.). Source: `schema:EarningsSummaryOut.total_cents`, `schema:EarningsQuickStatsOut.*_cents`, `schema:EarningsTransactionOut.amount_cents`; `src/pages/earnings/EarningsPage.tsx: formatCents = cents/100`.
8. **Breakdown is an array of `{source, amount_minor, share_pct}` incl. `ads`/`payouts`.** CORRECTED — `EarningsBreakdown` is a fixed-key object with integer-cents fields `subscriptions`, `tips`, `unlocks`, `vod_purchases`, `other`; no `ads`/`payouts`; no `share_pct` (share computed client-side). Source: `schema:EarningsBreakdown`; `src/api/types.ts: EarningsBreakdown`; `src/pages/earnings/EarningsPage.tsx: BreakdownList` (`pct = round(cents/total*100)`, filter `v>0`, sort desc).
9. **Time-series point shape `{bucket_start, amount_minor}`.** CORRECTED — `TimeSeriesPoint` has `date` (string, required), per-source cents (`subscriptions`/`tips`/`unlocks`/`vod_purchases`/`other`) and `total` (cents). Source: `schema:TimeSeriesPoint`; `src/pages/earnings/EarningsPage.tsx: RevenueChart` maps `pt.date` + per-source `/100`.
10. **Response includes `as_of` timestamp.** CORRECTED — no `as_of` in either schema. The `asOf` in `EarningsDashboard` must use fetch time, not a server field. Source: `schema:EarningsSummaryOut`, `schema:EarningsQuickStatsOut`.
11. **Response includes a `totals` object with `period_change_pct`.** CORRECTED — no `totals` object and no `period_change_pct`/delta field anywhere. Source: `schema:EarningsSummaryOut`, `schema:EarningsQuickStatsOut`; no delta logic in `src/pages/earnings/EarningsPage.tsx`.
12. **`currency` defaults / `USD` fallback.** VERIFIED — `currency` defaults to `"USD"` server-side in both schemas. The earlier `/ui/me`-derived-currency claim is unnecessary. Source: `schema:EarningsSummaryOut.currency` (default "USD"), `schema:EarningsQuickStatsOut.currency` (default "USD").
13. **Both endpoints are idempotent GETs.** VERIFIED. Source: `index` (both `GET`).
14. **401 → refresh → retry once.** VERIFIED (transport behavior). Web refreshes via `POST /ui/session/refresh` then retries the original request once; a second 401 logs out. Source: `src/api/client.ts: refreshSession` + 401 branch.
15. **CSRF header attached uniformly including GETs.** VERIFIED with correction to header name — the header is `X-CSRF-Token`, read from the `ui_csrf` cookie, set on every request. Auth also rides `Authorization: Bearer <token>` + cookies (`credentials: include`). Source: `src/api/client.ts` (lines setting `Authorization`, `X-CSRF-Token`, `credentials: "include"`).
16. **422 validation error shape `detail: [{msg}]`.** VERIFIED — `HTTPValidationError` with `detail` array of `{loc, msg, type}`; web `normalizeErrorDetail` reads `item.msg`. Source: `index` (`422:HTTPValidationError` on both); `schema:HTTPValidationError`; `src/api/client.ts: normalizeErrorDetail`.
17. **Empty data is 200 (empty `time_series` / zeroed fields), not an error.** VERIFIED — fields default to 0 / arrays empty; web renders "No revenue data" / "No earnings yet" placeholders on empty. Source: defaults in `schema:EarningsSummaryOut`/`schema:EarningsBreakdown`; `src/pages/earnings/EarningsPage.tsx` empty branches.
18. **Web chart is a single-total line/bar.** UNVERIFIED-ASSUMPTION (app design choice) — the web renders a **stacked area chart by source** (`RevenueChart` stacks Tips/Subscriptions/Unlocks/VOD/Other). The Android single-total line+bar toggle is an acceptable design variation; per-source fields are available if a stacked chart is preferred. Source: `src/pages/earnings/EarningsPage.tsx: RevenueChart`.
19. **`pending_payout` shown as a headline KPI.** UNVERIFIED-ASSUMPTION — the field exists (`schema:EarningsQuickStatsOut.pending_payout_cents`) but the web client does NOT render a pending-payout card (only Today/Week/Month/AllTime). Whether to surface it is an open product question (§13). Source: `schema:EarningsQuickStatsOut`; absence in `src/pages/earnings/EarningsPage.tsx` cards.
20. **Stack/tooling choices** (Compose, Hilt, Retrofit/Moshi, Room, DataStore, Vico chart via AND-255, Navigation-Compose). UNVERIFIED here — not derivable from backend/frontend sources; these are Android-side decisions owned by the project's architecture tickets (framework refs: Jetpack Compose, Hilt, Retrofit, Room — standard AndroidX docs). Treated as project conventions, not re-verified.
21. **`feature-earnings` consumes AND-251 `EarningsApi`/DTOs and AND-255 chart.** UNVERIFIED-ASSUMPTION — depends on sibling tickets not present in these sources; the DTO field names assumed from AND-251 must match the corrected backend shapes above (cents, `time_series`, fixed breakdown keys).

### Corrections made

- §5 API Contract: removed the nonexistent `/ui/earnings/series` endpoint and the `?range=` param; documented the real two-call model (`/ui/earnings/quick-stats` + `/ui/earnings/summary` with `from_date`/`to_date`/`granularity`); replaced both JSON examples with the real `EarningsQuickStatsOut` / `EarningsSummaryOut` shapes; fixed CSRF header name to `X-CSRF-Token` and noted Bearer+cookie auth and `POST /ui/session/refresh`.
- §1 / §3.4: corrected breakdown source set to `subscriptions/tips/unlocks/vod_purchases/other` (removed `ads`/`payouts`); added localized labels.
- §3.1: removed the backend-supported delta/% change claim (no field exists); clarified KPI sources (quick-stats + summary `total_cents`).
- §3.2 / §14.2: range labels `12M`→`1Y`; clarified range→`from_date`/`to_date` and separate `granularity` control.
- §4: corrected the repository to call `getQuickStats()` + `getSummary(fromDate,toDate,granularity)`; fixed `EarningsRange` enum (day-counts, no `apiValue`); rewrote `toChartModel` to map `TimeSeriesPoint.date`/`total` (cents) instead of `bucketStart`/`amountMinor`.
- §4 / §8 (money): `*_minor` → cents throughout; share computed in integer cents.
- §6: noted `TotalsUi.periodChangePct` is always null (no backend source).
- §7: removed `/ui/me` currency-derivation; `currency` defaults to `"USD"` from the payload.
- §9: corrected the chart `stateDescription` example to drop the fabricated "up 14 percent"; aligned card aria-label with the web pattern.
- §11: MockWebServer param assertions changed from `range`/`bucket` to `from_date`/`to_date`/`granularity` and split quick-stats vs summary fixtures.
- §13: resolved the bucket-authority and `period_change_pct` open questions with verified findings.
- §14: ACs realigned to the corrected contract (sources, cents, `time_series`, `1Y`).

### Open assumptions

- **AND-251 DTO names** (`EarningsSummary`, `EarningsSeries`, `EarningsBreakdown` domain models): not present in these sources; assumed to be regenerated to match the corrected backend shapes. If AND-251 already shipped `*_minor`/`series`/`by_source` names, this ticket and AND-251 must be reconciled. Note the upstream `EarningsSeries` model is dubious since there is no series endpoint — the chart series lives inside summary.
- **AND-255 chart API** (`ChartModel`, `LineChart`/`BarChart`, stacked support): unverifiable here; assumed to accept the mapping in §4. If only single-series is supported, the per-source stacked option (claim 18) is deferred.
- **Android stack/tooling versions** (Kotlin 2.0.21, AGP 8.7.3, etc.): project conventions, not verifiable from backend/frontend sources.
- **`pending_payout` placement and any delta indicator**: product decisions; backend supplies the pending field but not a delta. Left as §13 open questions.
- **Telemetry facade and AND-0xx infra tickets**: referenced but outside these sources; assumed to exist as described.

## 17. Test Plan

Test target legend — `JVM` = JVM unit/Robolectric (local, no device); `EMU` = headless emulator AVD `test35` (x86_64, API 35) on the Ubuntu CI server; `DEVICE` = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). For this ticket no case strictly requires the physical device (no camera/biometrics/FCM/WebRTC/Telecom/streaming); instrumented UI runs on `EMU`. TC-AND-252-13 is the one case that SHOULD additionally run on `DEVICE` to validate arm64 + API-34 behavior vs the API-35 emulator.

- **TC-AND-252-01 — Happy path: dashboard renders real earnings.** Type: integration (MockWebServer). Target: JVM. Preconditions: MockWebServer enqueues 200 `EarningsQuickStatsOut` (populated) and 200 `EarningsSummaryOut` (populated `breakdown` + `time_series`), default range `30D`. Steps: launch `EarningsViewModel`/repo against MockWebServer; collect `uiState`. Expected: state transitions `Loading`→`Ready`; totals reflect quick-stats cents + summary `total_cents`; chart model has N points from `time_series`; breakdown rows present. Verify summary request path `/ui/earnings/summary` with `from_date`/`to_date` (today−30) and `granularity=day`, and quick-stats request has no range params. Traces: AC-1, AC-2.
- **TC-AND-252-02 — Currency/cents formatting.** Type: unit. Target: JVM. Preconditions: `total_cents=318900`, `currency=USD`. Steps: run formatter mapping. Expected: displays `$3,189.00` (cents/100, locale-correct via `NumberFormat`); no float drift; breakdown shares = round(sourceCents/totalCents*100). Traces: AC-8.
- **TC-AND-252-03 — `TimeSeriesPoint` → ChartModel mapping.** Type: unit. Target: JVM. Preconditions: list of points with `date` ISO strings and `total` cents. Steps: call `toChartModel()`. Expected: X = epoch-day of `LocalDate.parse(date)`, Y = `total/100f`; X/Y labelers produce date and currency-short strings; order preserved. Traces: AC-3, AC-8.
- **TC-AND-252-04 — Breakdown sort + zero filtering + labels.** Type: unit. Target: JVM. Preconditions: `breakdown={subscriptions:98500, tips:40000, unlocks:0, vod_purchases:8000, other:0}`. Steps: map to `BreakdownRowUi`. Expected: rows for subscriptions, tips, vod_purchases only (zeros hidden), sorted desc by cents; localized labels (Subscriptions/Tips/VOD Purchases); share % from cents. Traces: AC-4.
- **TC-AND-252-05 — Range change re-queries + persists.** Type: unit. Target: JVM. Preconditions: VM at `30D`, fake `EarningsPrefs`. Steps: `onRangeSelected(D7)`. Expected: new summary call with `from_date`=today−7; `granularity` retained; selected point reset; `earnings_range` persisted to DataStore; quick-stats not re-fetched with a range param. Traces: AC-2.
- **TC-AND-252-06 — Range persistence survives process death.** Type: unit/Robolectric. Target: JVM. Preconditions: DataStore seeded `earnings_range=90d`. Steps: construct a fresh VM (simulating recreate) with no deep-link arg. Expected: initial range `D90` restored from prefs before default. Traces: AC-2.
- **TC-AND-252-07 — Empty data → Empty state.** Type: integration (MockWebServer). Target: JVM. Preconditions: 200 summary with `total_cents=0`, empty `time_series`, all-zero `breakdown`; quick-stats zeroed. Steps: load. Expected: `Empty` state (not error); range selector still interactive; in-chart "No revenue data for this period" if totals zero. Traces: AC-5.
- **TC-AND-252-08 — 5xx/timeout → recoverable Error + Retry.** Type: integration (MockWebServer). Target: JVM. Preconditions: summary returns 500 (after AND-016 retries exhausted) or socket timeout. Steps: load; then enqueue 200 and invoke `onRetry()`. Expected: `Error(recoverable=true)`; after Retry → `Ready`. Asserts retry interceptor fired on 500 then the user Retry recovers. Traces: AC-5.
- **TC-AND-252-09 — 422 validation error mapping.** Type: contract (MockWebServer). Target: JVM. Preconditions: summary returns 422 `HTTPValidationError` `{detail:[{loc,msg,type}]}` (e.g. bad `granularity`). Steps: load. Expected: error message derived from `detail[].msg`; recoverable Error surfaced (matches AND-015 mapping). Traces: AC-5.
- **TC-AND-252-10 — Offline with cache → stale Ready + banner; partial failure falls back.** Type: integration (MockWebServer + connectivity fake). Target: JVM. Preconditions: Room snapshot exists (>15 min old); network unavailable OR summary succeeds but quick-stats fails. Steps: load offline / partial. Expected: cached `Ready(isStale=true)` with "Showing saved data" banner + `asOfLabel` from fetch time; no half-rendered dashboard. Traces: AC-5.
- **TC-AND-252-11 — Offline no cache → Offline state.** Type: integration. Target: JVM. Preconditions: empty Room cache; connectivity probe = offline. Steps: load. Expected: `Offline` state (not Error); Retry available. Traces: AC-5.
- **TC-AND-252-12 — Pull-to-refresh bypasses cache.** Type: integration (MockWebServer). Target: JVM. Preconditions: fresh cache present. Steps: `onRefresh()`. Expected: `isRefreshing=true` then network fetch issued (force-network, cache bypassed), `isRefreshing` clears; new data replaces cached. Traces: AC-6.
- **TC-AND-252-13 — Compose UI: Ready/Loading/Empty/Error/Offline render + range selector + Retry.** Type: Compose-UI / instrumented. Target: EMU (primary) and DEVICE (re-run to confirm arm64/API-34 parity). Preconditions: each state injected as `EarningsUiState`. Steps: assert totals/chart(test-tag)/breakdown for `Ready`; skeletons for `Loading`; correct affordances for Empty/Error/Offline; tap a range segment → `onRangeSelected` callback; tap Retry → `onRetry`. Expected: all assertions pass identically on EMU and DEVICE. Traces: AC-1, AC-2, AC-3, AC-5, AC-9.
- **TC-AND-252-14 — Accessibility semantics.** Type: Compose-UI. Target: EMU. Preconditions: `Ready` state. Steps: query semantics tree. Expected: each KPI card exposes contentDescription with title + currency value; range control nodes have `selectable`/`selected` role; chart exposes `stateDescription` summary and a "View as table" affordance; no fabricated % change text; delta has glyph + color (not color-only). Traces: AC-1, AC-3.
- **TC-AND-252-15 — Security: no monetary values in logs/telemetry; cache cleared on logout.** Type: unit + instrumented. Target: JVM (redaction) + EMU (logout cleanup). Preconditions: spy on analytics facade + Timber tree; populated cache. Steps: trigger load + range change; then invoke logout cleanup (AND-032) calling `EarningsRepository.clear()`. Expected: emitted events (`earnings_load_result`, etc.) and logs contain only ranges/counts/outcomes — no cents/currency totals; after logout the Room snapshot DAO is empty. Traces: AC-7.

### Coverage matrix (§14 AC → TCs)

- AC-1 (renders real earnings: totals, chart, breakdown): TC-01, TC-13, TC-14.
- AC-2 (range selector re-queries atomically + persists across process death): TC-01, TC-05, TC-06, TC-13.
- AC-3 (chart renders `time_series`, currency Y / date X, toggle, point selection): TC-03, TC-13, TC-14.
- AC-4 (breakdown amount/share/bar, sorted desc, zeros hidden): TC-04.
- AC-5 (loading/empty/error+Retry/offline-with-cache+banner/offline-no-cache): TC-07, TC-08, TC-09, TC-10, TC-11, TC-13.
- AC-6 (pull-to-refresh bypasses cache): TC-12.
- AC-7 (no monetary values in logs/telemetry; cache cleared on logout): TC-15.
- AC-8 (integer cents; format to major units at display; locale-correct): TC-02, TC-03.
- AC-9 (unit/MockWebServer/Compose tests green in CI): TC-01 through TC-15 collectively (JVM + EMU jobs).
