---
id: AND-252
title: Earnings dashboard + charts
milestone: M6
epic: E34
priority: P0
size: L
status: draft
depends_on: [AND-251, AND-255]
blocks: []
---

# AND-252 — Earnings dashboard + charts

## 1. Overview & Goal

Build the **Earnings dashboard** screen for the TestLogon native Android app: the primary creator-finance surface that renders real earnings data fetched from the FastAPI backend. The screen presents three coordinated regions — (a) **totals** (lifetime, current period, and pending payout headline figures), (b) **time-series charts** (a selectable-range line/bar chart of earnings over time), and (c) **breakdowns** (per-source attribution such as ads, subscriptions, tips, and payouts).

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

1. **Totals header.** Display three primary KPI cards: *Total earnings* (lifetime), *This period* (current selected range), and *Pending payout*. Each shows a formatted currency value, the currency code, and a delta indicator (% change vs. previous comparable period) when the backend provides one. Values are localized via `NumberFormat.getCurrencyInstance`.
2. **Range selector.** A segmented control offering `7D`, `30D`, `90D`, `12M`, `ALL`. Changing the range re-queries the series + summary and updates totals, chart, and breakdown atomically. Default range is `30D`. The selection is persisted to DataStore so it survives process death and is restored on next visit.
3. **Time-series chart.** Render a line chart (default) of earnings amount over time for the selected range, using the AND-255 chart composable. Support a chart-type toggle to a bar chart for granularity that is naturally discrete (daily/weekly buckets). The chart shows axis labels, a currency-formatted Y axis, and date-formatted X axis. Tapping/selecting a data point surfaces a tooltip with the exact date + value.
4. **Breakdowns.** Render a list of earnings sources (e.g., `ads`, `subscriptions`, `tips`, `payouts`) with per-source amount, share-of-total percentage, and a proportional inline bar. Sorted descending by amount. If a breakdown is empty for the range, hide its row rather than show zero noise.
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

enum class EarningsRange(val apiValue: String, val days: Int?) {
    D7("7d", 7), D30("30d", 30), D90("90d", 90), M12("12m", 365), ALL("all", null)
}
```

`EarningsRepositoryImpl` (Hilt `@Singleton`) calls `EarningsApi.getSummary(range)` and `EarningsApi.getSeries(range)` concurrently (`coroutineScope { async {} }`), combines them into `EarningsDashboard`, writes the result to a Room cache keyed by `range`, and emits cache-first then network via `observeDashboard`. The breakdown is derived from the summary payload's `by_source` field (single call) so only two network calls are made per range.

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
fun EarningsSeries.toChartModel(): ChartModel =
    ChartModel(
        x = points.map { it.bucketStart.toEpochDay().toFloat() },
        y = points.map { it.amountMinor / 100f },
        xLabeler = { epochDay -> formatBucketLabel(LocalDate.ofEpochDay(it.toLong())) },
        yLabeler = { currencyShort(it) },
    )
```

**Money handling.** Amounts are integer minor units (`amountMinor: Long`) from the backend; convert to major units only at format time to avoid float drift in computation. Percentage shares computed in minor units.

**Navigation registration** (in authenticated nav graph, AND-024):

```kotlin
composable(
    route = "earnings?range={range}",
    arguments = listOf(navArgument("range") { nullable = true; defaultValue = null }),
) { EarningsRoute(onBack = navController::popBackStack) }
```

## 5. API Contract

Endpoints are **owned and tested by AND-251**; this ticket consumes them. Documented here for the consuming contract.

**GET `/ui/earnings/summary?range={7d|30d|90d|12m|all}`** → 200:

```json
{
  "currency": "USD",
  "as_of": "2026-06-05T12:00:00Z",
  "totals": {
    "lifetime_minor": 4827310,
    "period_minor": 318900,
    "pending_payout_minor": 120000,
    "period_change_pct": 0.142
  },
  "by_source": [
    { "source": "ads",           "amount_minor": 180400, "share_pct": 0.566 },
    { "source": "subscriptions", "amount_minor": 98500,  "share_pct": 0.309 },
    { "source": "tips",          "amount_minor": 40000,  "share_pct": 0.125 }
  ]
}
```

**GET `/ui/earnings/series?range={...}&bucket={day|week|month}`** → 200:

```json
{
  "currency": "USD",
  "bucket": "day",
  "points": [
    { "bucket_start": "2026-05-07", "amount_minor": 10200 },
    { "bucket_start": "2026-05-08", "amount_minor": 9800 }
  ]
}
```

Both are **idempotent GETs** → eligible for bounded backoff retry (AND-016) and for the 401→refresh→retry path (AND-013). Requests ride the persistent cookie jar; mutating requests are absent here so the CSRF header is not required, though the OkHttp stack attaches it uniformly. Bucket granularity is chosen client-side by range (`7d/30d`→day, `90d/12m`→week, `all`→month) unless the backend overrides via the returned `bucket`.

**Error envelope** (FastAPI `detail`, mapped by AND-015): `401` (handled by refresh authenticator), `422` validation (`detail: [{msg}]`), `5xx`/timeout → recoverable error surfaced as Retry. Empty/zero data is a **200 with empty `points` / zeroed totals**, not an error → empty state.

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
- **Malformed/missing fields:** Moshi mapping (AND-251) defaults absent numeric fields to 0; a missing `currency` defaults to the account currency from `/ui/me`, falling back to `USD`.
- **Empty series with non-zero totals** (rare): render totals + breakdown, show an in-chart "No data points for this range" placeholder rather than the full-screen empty state.

## 8. Security & Privacy

- Earnings figures are sensitive financial PII. **Never log raw amounts** — telemetry uses only ranges, counts, and outcome enums (§10).
- All requests are authenticated via the existing cookie session; no tokens or amounts are placed in URLs beyond the `range`/`bucket` query params.
- The Room snapshot persists earnings JSON on-device. It lives in app-private storage; the DAO must be cleared on logout — `EarningsRepository.clear()` is invoked by the central logout cleanup (AND-032). No earnings cache may survive a session change.
- No earnings values in crash reports, screenshots of analytics, or `toString()` of DTOs that could reach logs. Disable `FLAG_SECURE`? Not required by this ticket, but mark the screen as a candidate for screenshot suppression in a later hardening ticket (open question §13).
- Dev backend is plaintext HTTP (cleartext permitted only for the dev flavor per AND-006); no change here.

## 9. Accessibility & i18n

- All KPI cards, chart, and breakdown rows expose `contentDescription`/`semantics`. Each totals card reads as "Total earnings, 48,273 dollars 10 cents". The chart exposes a textual `stateDescription` summary ("Earnings trend, 30 days, up 14 percent") plus a data-table fallback reachable via an "View as table" affordance for screen-reader users (chart canvases are not natively traversable).
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

**MockWebServer (AND-046 harness + fixtures):** golden JSON fixtures for each range (populated, empty, 422, 500, slow/timeout). Assert correct query params (`range`, `bucket`) and that retry fires on 500 then succeeds.

**Compose UI tests:** `EarningsScreen` renders totals/chart/breakdown for `Ready`; skeletons for `Loading`; empty/error/offline states show correct affordances; range segmented control selection updates; Retry invokes callback; semantics nodes present for accessibility (table fallback exists). Chart presence asserted via test tag (chart internals owned by AND-255 tests).

**CI:** runs under unit (AND-050) and instrumented headless-emulator (AND-051) jobs.

## 12. Dependencies & Sequencing

- **Hard deps:** **AND-251** (API + DTOs/models — must land first; this module imports its `EarningsApi` and domain models) and **AND-255** (chart composable — required for the chart card). Both P0 in M6/E34.
- **Transitive infra (already planned, must exist):** AND-018 (`ApiResult`), AND-015 (error mapping), AND-016 (GET retry), AND-013/012/011 (auth/CSRF/cookie jar), AND-021 (state composables), AND-019 (theme), AND-024 (authenticated nav graph), AND-032 (logout cleanup hook for cache clear), AND-046 (MockWebServer harness).
- **Sequencing:** AND-251 → AND-255 → **AND-252**. This ticket **blocks** nothing in the source bullets but is the reference consumer that later finance screens (payouts/ads detail) follow; the AND-255 chart and AND-251 DTOs are validated end-to-end here.
- New module wiring: register `feature-earnings` in `settings.gradle.kts` and add to `app` dependencies; Hilt module `EarningsModule` provides `EarningsRepository` binding.

## 13. Risks & Open Questions

- **Bucket selection authority:** Does the backend honor the client `bucket` query param, or always decide server-side? If server-side only, drop the param and trust the returned `bucket`. (Confirm against `/openapi.json` during AND-251.)
- **`period_change_pct` availability:** Field may be absent for `ALL` range; UI must hide the delta gracefully (handled), but confirm semantics (vs. previous period of equal length).
- **Currency mixing:** Assumes a single account currency. If the backend can return multi-currency earnings, the totals/chart aggregation model needs revision — out of scope, flag for product.
- **Chart performance for `ALL`:** month-bucketed series should be small, but a creator with years of daily data on `ALL` without bucketing could be large; rely on server bucketing — verify max point count.
- **Screenshot suppression:** Should the earnings screen set `FLAG_SECURE`? Deferred to a security-hardening ticket; noted in §8.
- **Pending payout placement:** Whether "pending payout" belongs on this dashboard or only on a payouts screen — current design includes it as a headline; confirm with design.

## 14. Acceptance Criteria

1. Navigating to `earnings` from the authenticated graph fetches and **renders real earnings** from the dev backend: totals (lifetime/period/pending), a time-series chart, and a source breakdown.
2. The range selector (`7D/30D/90D/12M/ALL`) re-queries and updates all three regions atomically; the selected range is persisted across process death (DataStore).
3. The chart renders the returned `points` via the AND-255 composable with currency-formatted Y axis and date X axis; the line/bar toggle works; selecting a point shows date + exact value.
4. Breakdown rows show per-source amount, share %, and proportional bar, sorted descending, with zero/empty sources hidden.
5. Loading shows skeletons; a 200 with empty data shows the empty state; a 5xx/timeout shows a recoverable error with a working Retry; offline-with-cache shows stale data + "Showing saved data" banner + timestamp; offline-no-cache shows the offline state.
6. Pull-to-refresh forces a network fetch bypassing cache.
7. No monetary values appear in logs or telemetry (verified by test asserting redaction); earnings cache is cleared on logout.
8. Money is computed in integer minor units and only formatted to major units at display, with locale-correct currency formatting.
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
