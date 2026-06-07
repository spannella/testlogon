---
id: AND-255
title: Reusable charts component
milestone: M6
epic: E34
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-019]
blocks: [AND-256, AND-257]
---

# AND-255 — Reusable charts component

## 1. Overview & Goal

Deliver a single, reusable charting capability inside the `core-ui` library
module so that every finance-facing screen in the TestLogon native Android app
renders line and bar charts from one canonical, theme-aware implementation.
Finance screens — payouts history, ads/revenue dashboards, and any later
analytics surface — currently have no native chart primitive; this ticket is the
authoritative source for one. Success means a feature screen can pass a typed
series of data points to a `TestLogonLineChart` or `TestLogonBarChart` composable
and get a correctly axis-labelled, themed, accessible chart with zero per-screen
charting code.

The deliverable is the chart composables, their public state/model types, axis
and value formatters, the loading/empty/error visual states, and Compose previews
plus a screenshot/UI test proving a sample series renders. The charting
foundation must consume the Material 3 theme from AND-019 (`MaterialTheme.colorScheme`,
`MaterialTheme.typography`) and must not hard-code colors or text styles. We
adopt **Vico 2.x** (the Compose-native charting library) rather than hand-rolling
a Canvas renderer, because Vico already provides axis rendering, value
formatting, animations, and Compose interop; a thin TestLogon wrapper around Vico
gives us a stable internal API and isolates the third-party dependency behind our
own surface so it can be swapped later without touching feature modules.

Explicitly out of scope: fetching finance data, the payouts and ads screens
themselves, pagination of series, and pan/zoom/scrubbing interactions. Those are
owned by the consuming feature tickets (AND-256 payouts screen, AND-257 ads
dashboard). This ticket guarantees those screens a correct, tested chart
component to build on. Pie/donut and candlestick chart types are also out of
scope; only line and bar are required by the acceptance criteria.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Monorepo; web reference app under `frontend/`.
- Namespace / package base: `com.testlogon.android`. This component lives at
  `com.testlogon.android.core.ui.chart` in the `core-ui` module.
- Module layering: `app -> feature-* -> core-*`. Charts belong in `core-ui`
  (alongside the theme from AND-019) so both `feature-payouts` and `feature-ads`
  can depend on it without depending on each other.
- Stack relevant here: Kotlin 2.0.21, Jetpack Compose + Material 3, Coroutines/
  Flow, minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Vico** `com.patrykandpatrick.vico:compose-m3:2.0.x` (Compose Multiplatform/
  Material 3 artifact) plus `vico:core`. Pin the exact version in the version
  catalog; verify it targets Compose Compiler compatible with Kotlin 2.0.21.
- Depends on **AND-019** (Material 3 theme): chart colors, typography, and shapes
  are derived from `TestLogonTheme`. Do not introduce a separate palette.
- Web reference: the React app renders finance charts using **recharts**
  (verified: `src/pages/earnings/EarningsPage.tsx` and
  `src/pages/analytics/AnalyticsPage.tsx` import `BarChart`/`Bar`/`Line`/
  `ComposedChart`/`CartesianGrid`/`Tooltip`/`Legend`/`ResponsiveContainer` from
  `recharts`). A few simpler surfaces hand-roll div-based bars instead
  (`src/components/shared/VolumeChart.tsx`, `FunnelChart.tsx`). Treat recharts'
  axis formatting, currency formatting, legend, and series semantics as the
  design reference for parity, but the data shapes here are defined locally
  because no backend call is made by this ticket.
- No backend interaction in this ticket; FastAPI/DynamoDB and the dev host
  `http://18.222.237.167:8000` are not contacted (see §5).

## 3. Functional Requirements

FR-1. Provide a public line chart composable `TestLogonLineChart` that renders
one or more named series of `(x, y)` points with an X axis (categorical or time)
and a Y axis (numeric, formatted).

FR-2. Provide a public bar chart composable `TestLogonBarChart` that renders one
or more named series as grouped/stacked vertical bars over a categorical X axis.

FR-3. Both charts accept a typed, immutable model (`ChartData`) and a
`ChartConfig` describing axis formatting, legend visibility, and animation. No
feature module may pass raw Vico types.

FR-4. Charts render correct axis labels: Y values formatted via a pluggable
`AxisValueFormatter` (default: compact numeric; finance screens supply a currency
formatter). X labels formatted via a pluggable label provider (default: index;
finance screens supply date/category labels).

FR-5. Both charts expose three non-data visual states driven by an enclosing
`ChartUiState`: `Loading` (shimmer/placeholder of the chart frame), `Empty`
("No data" message), and `Content(data)`. An error message variant is supported
via `Empty(message=...)` so a screen can surface a load failure inside the chart
frame.

FR-6. Charts are theme-driven: line/bar colors come from a deterministic palette
derived from `MaterialTheme.colorScheme` (primary, secondary, tertiary, plus
container variants), supporting at least 4 distinct series colors with stable
ordering. Text uses `MaterialTheme.typography.labelSmall`/`bodySmall`.

FR-7. Charts are reused by at least two consumers in this codebase via shared
previews/sample data (`SampleChartData`) so the "reused by payouts/ads" criterion
is demonstrable before those feature screens exist.

FR-8. Charts must render at a caller-controlled height (default 220.dp) and fill
available width; they must not crash on a single point, empty series, or all-zero
series.

FR-9. Legend is optional and, when enabled, lists each series name with its
swatch color; legend wraps on narrow widths.

## 4. Technical Design

New package `com.testlogon.android.core.ui.chart` in module `core-ui`.

Public model types (immutable, Compose-stable):

```kotlin
@Immutable
data class ChartPoint(val x: Float, val y: Float, val label: String? = null)

@Immutable
data class ChartSeries(
    val id: String,
    val name: String,
    val points: List<ChartPoint>,
)

@Immutable
data class ChartData(val series: List<ChartSeries>) {
    val isEmpty: Boolean get() = series.isEmpty() || series.all { it.points.isEmpty() }
    companion object { val EMPTY = ChartData(emptyList()) }
}

fun interface AxisValueFormatter { fun format(value: Float): String }
fun interface AxisLabelProvider { fun labelAt(index: Int): String }

@Immutable
data class ChartConfig(
    val yFormatter: AxisValueFormatter = CompactNumberFormatter,
    val xLabels: AxisLabelProvider = IndexLabelProvider,
    val showLegend: Boolean = true,
    val animate: Boolean = true,
    val maxYTicks: Int = 5,
)

@Immutable
sealed interface ChartUiState {
    data object Loading : ChartUiState
    data class Empty(val message: String) : ChartUiState
    data class Content(val data: ChartData) : ChartUiState
}
```

Public composables:

```kotlin
@Composable
fun TestLogonLineChart(
    state: ChartUiState,
    modifier: Modifier = Modifier,
    height: Dp = 220.dp,
    config: ChartConfig = ChartConfig(),
    contentDescription: String? = null,
)

@Composable
fun TestLogonBarChart(
    state: ChartUiState,
    modifier: Modifier = Modifier,
    height: Dp = 220.dp,
    config: ChartConfig = ChartConfig(),
    contentDescription: String? = null,
)
```

Internal architecture:

- A private `ChartFrame(state, height, modifier, content: @Composable (ChartData) -> Unit)`
  composable owns the shared state machine: it renders the shimmer placeholder
  for `Loading`, a centered message for `Empty`, and delegates to `content(data)`
  for `Content`. Both public charts call `ChartFrame` and supply their Vico body.
- `rememberChartPalette(): ChartPalette` reads `MaterialTheme.colorScheme` and
  returns an ordered `List<Color>` (primary, tertiary, secondary, error-container
  variants) plus axis/grid colors; pure function of the current theme, memoized
  with `remember`.
- Vico interop is confined to two private functions, `LineChartBody` and
  `BarChartBody`, that map `ChartData` -> Vico `CartesianChartModel` via
  `CartesianChartModelProducer`, build `rememberCartesianChart` with
  `LineCartesianLayer`/`ColumnCartesianLayer`, and attach `VerticalAxis.rememberStart`
  / `HorizontalAxis.rememberBottom` with our formatters bridged to Vico's
  `CartesianValueFormatter`. The model producer is built and updated inside a
  `LaunchedEffect(data)` so series changes recompute off the main frame.
- Default formatters: `CompactNumberFormatter` (1.2K / 3.4M via `NumberFormat`
  with rounding), `IndexLabelProvider`, and a provided
  `CurrencyAxisValueFormatter(currencyCode: String)` and
  `EpochDayLabelProvider(epochDays: List<Long>, pattern: String)` for finance
  consumers.
- `SampleChartData` object exposes `payoutsLine`, `payoutsBar`, and `adsLine`
  sample `ChartData` for previews and tests.

Build wiring: add Vico to `gradle/libs.versions.toml`; `core-ui/build.gradle.kts`
adds `implementation(libs.vico.compose.m3)` and `implementation(libs.vico.core)`.
Vico stays an `implementation` (not `api`) dependency so it does not leak to
feature modules — only TestLogon types are exported.

## 5. API Contract

Not applicable. This is a pure UI/library component; it performs no network I/O
and contacts no FastAPI endpoint. There is no request/response JSON, no cookie/
CSRF handling, and no `ApiResult<T>` involvement in this ticket.

The only "contract" is the in-process boundary between feature modules and this
component: features map their already-fetched domain models into `ChartData`/
`ChartUiState` and pass them in. Mapping backend payout/ads payloads into
`ChartData` is owned by the consuming tickets AND-256 (payouts) and AND-257
(ads), which depend on this one. For reference, the relevant backend endpoints
those tickets will call are (verified against the OpenAPI index):
`GET /ui/payouts` (resp `PayoutListOut`) and `GET /ui/payouts/balance` (resp
`PayoutBalanceOut`) for payouts; and for ads time-series charts
`GET /ui/ads/analytics/timeseries` (params `account_id,campaign_id,days,
granularity,...`) and `GET /ui/ads/analytics/summary` (resp shapes inline).
NOTE: the earlier draft cited `GET /ui/ads/stats` as the ads chart source — that
bare path does not exist; the only `stats` ads endpoint is
`GET /ui/ads/stats/{campaign_id}` (per-campaign serving stats), which is not the
time-series source. These `/ui/...` endpoints authenticate via session headers
(`X-SESSION-ID`, optional `X-IMPERSONATION-TOKEN`), not via this component.
Those tickets are responsible for the dev-host resilience concerns (20s timeouts,
bounded backoff for idempotent GETs, offline/stale states); this component merely
renders whatever `ChartUiState` it is handed, including a failure surfaced as
`ChartUiState.Empty("Couldn't load chart")`.

## 6. Data & State Management

The component is stateless with respect to business data: it holds no
`ViewModel`, no `StateFlow`, and no repository. State flows in one direction —
the caller's `ViewModel` exposes `StateFlow<UiState>` that contains a
`ChartUiState`, collects it with `collectAsStateWithLifecycle()`, and passes it
to the chart composable.

Internal, ephemeral state:

- `CartesianChartModelProducer` is created with `remember { … }` and updated in a
  `LaunchedEffect(data)` keyed on the incoming `ChartData`; this is presentation
  state only and is not persisted.
- `rememberChartPalette()` recomputes when the theme changes (dark/light toggle).
- Animation progress is owned by Vico and reset when `ChartData.series` identity
  changes.

No Room, DataStore, or Paging usage. `ChartData` and friends are `@Immutable`
data classes so Compose can skip recomposition when references are unchanged;
callers should hoist `ChartData` construction out of the composable (or memoize
with `remember(rawData)`) to avoid rebuilding series each recomposition. All
public types are stable to satisfy Compose strong-skipping. Configuration changes
(rotation) preserve nothing here because state is owned upstream; the chart simply
re-renders from the recreated `ChartUiState`.

## 7. Error Handling & Resilience

Because there is no I/O, "errors" are limited to malformed or degenerate inputs
and renderer failures:

- Empty data: `ChartData.isEmpty` -> `ChartFrame` renders the `Empty` state; the
  Vico body is never constructed. A `Content(ChartData.EMPTY)` is normalized to
  the empty visual.
- Single point / single series: must render without throwing; line layer with one
  point draws a marker; bar layer draws one column. Covered by unit/UI tests.
- All-zero or negative Y values: Y axis must still compute a sane range; rely on
  Vico auto-ranging but clamp `maxYTicks >= 2`. Negative values render below a
  zero baseline for bars.
- NaN/Infinite values: `ChartSeries` construction filters out non-finite points
  defensively in the mapping function (`points.filter { it.x.isFinite() && it.y.isFinite() }`);
  if filtering empties a series it is dropped.
- Caller load failure: surfaced as `ChartUiState.Empty(message)` so the chart
  frame shows the message rather than the screen showing a blank box. The
  component never retries — retry/backoff for idempotent GETs is the consuming
  feature's responsibility per project policy.
- Defensive rendering: the Vico body is wrapped so a renderer exception logs at
  warn and falls back to the `Empty("Chart unavailable")` state rather than
  crashing the screen.

## 8. Security & Privacy

Low surface. The component handles only numeric series and display labels passed
by callers; it must not log raw series values or user-identifying labels (payout
amounts, revenue figures) at any level above `DEBUG`, and production logging of
values is disabled. No cookies, tokens, CSRF, credentials, or PII are processed
here. No data is persisted to disk, cache, or DataStore. No network egress, so no
TLS/cleartext concerns for this module (the cleartext dev-host concern belongs to
`core-network`). Content descriptions generated for accessibility must not embed
sensitive exact amounts unless the caller opts in via `contentDescription`,
keeping the decision with the screen that owns the data classification.

## 9. Accessibility & i18n

- Each chart exposes a single semantic node with a meaningful
  `contentDescription`: if the caller supplies one it is used verbatim; otherwise
  a generated summary like "Line chart, {n} series, latest value {formatted}" is
  produced using the configured formatters. The decorative inner canvas is marked
  `Modifier.clearAndSetSemantics {}` so TalkBack announces one coherent
  description, not every tick.
- Color is never the only differentiator: line charts vary point markers and the
  legend pairs each series name with its swatch; minimum contrast for axis text
  follows Material 3 `onSurfaceVariant`.
- Touch targets: the optional legend rows meet 48.dp minimum height when
  interactive (legend is non-interactive by default, so this applies only if a
  consumer makes it tappable).
- i18n: all user-visible strings ("No data", default fallback descriptions) live
  in `core-ui` `strings.xml` and are localizable; no concatenated strings — use
  parameterized resources. Number/currency/date formatting uses `java.text`/
  `NumberFormat`/`DateTimeFormatter` honoring the device `Locale`; the currency
  formatter takes an ISO-4217 code. RTL is supported by relying on Compose layout
  direction; axis start/bottom map correctly under RTL.

## 10. Telemetry & Logging

Minimal. No analytics events are emitted by the component itself (chart-view
events, if any, belong to the consuming screens). Internal logging uses the
project logger at `core-ui` tag `TLChart`:

- `DEBUG`: composition with series count and point counts (counts only, never
  values).
- `WARN`: defensive fallback to `Empty` after a renderer exception, with the
  exception class.

No timing/performance telemetry in scope; if the consuming dashboards need
chart-render timing, they add it at the screen level. Logging must be stripped or
no-op in release per the project's logging setup.

## 11. Testing Strategy

Unit tests (`core-ui` test source set, JUnit + Truth):

- `ChartData.isEmpty` for empty list, list of empty series, and populated data.
- `CompactNumberFormatter` outputs (999 -> "999", 1_200 -> "1.2K",
  3_400_000 -> "3.4M") under a fixed `Locale.US`.
- `CurrencyAxisValueFormatter` formats `1234.5f` to "$1,234.50" for `USD`.
- Non-finite filtering drops NaN/Infinite points and empty-after-filter series.
- `rememberChartPalette` ordering is deterministic and yields >= 4 distinct
  colors (tested via a Robolectric/Compose test reading theme).

Compose UI / screenshot tests (`androidTest`, Compose UI test + screenshot
harness from `core-testing`):

- `TestLogonLineChart` and `TestLogonBarChart` render `SampleChartData` without
  throwing (smoke) — directly satisfies "Chart renders sample series".
- Loading state shows the placeholder; Empty state shows the "No data" node;
  Content shows axis label nodes.
- Single-point and empty-series inputs render without crashing.
- Semantics: the chart node exposes a non-empty `contentDescription`.
- "Reused by payouts/ads" is proven by a test that renders both
  `SampleChartData.payoutsBar` and `SampleChartData.adsLine` through the same
  composables.

Previews: `@Preview` light/dark for line, bar, loading, and empty states.

## 12. Dependencies & Sequencing

- Hard dependency: **AND-019 (Material 3 theme)** — must merge first; chart
  palette and typography read `TestLogonTheme`. (P0, in `depends_on`.)
- Implicitly relies on the `core-ui` module and `core-testing` screenshot harness
  already existing (established in M1 foundation tickets).
- Adds Vico to the version catalog; coordinate the version bump so it does not
  conflict with the Compose Compiler tied to Kotlin 2.0.21.
- Blocks: **AND-256 (payouts screen)** and **AND-257 (ads/revenue dashboard)**,
  which consume `TestLogonLineChart`/`TestLogonBarChart` and supply real
  `ChartData`. Those tickets own data fetching, mapping, and dev-host resilience.
- No backend or `core-network` dependency.

## 13. Risks & Open Questions

- R-1 Vico API churn: Vico 2.x changed package/API significantly across minor
  versions. Mitigation: pin an exact version, keep all Vico types behind
  `LineChartBody`/`BarChartBody`, and cover with screenshot tests so an upgrade
  surfaces visual diffs.
- R-2 Compose Compiler compatibility with Kotlin 2.0.21: verify the chosen Vico
  artifact is built against a compatible compiler; fallback is a custom Canvas
  renderer (larger effort, would push size to L).
- R-3 Palette legibility in dynamic color (Android 12+): theme-derived series
  colors may collide on certain wallpapers. Open question: do we cap series at 4
  and define a fixed extended chart palette in `core-ui` instead of pure
  `colorScheme` derivation? Recommend a hybrid: first 3 from theme, remainder
  from a fixed accessible palette.
- R-4 Stale-data UX: should the chart show a "stale" badge when the screen is
  offline? Deferred to consuming tickets; this component only exposes
  `Empty(message)`.
- R-5 Time-axis formatting: time granularity differs by source. The ads/earnings
  time-series endpoints take a `granularity` query param (a free-form string,
  backend default `"daily"`/`"day"` — verified in `openapi.pretty.json`, not a
  strict enum), while `GET /ui/payouts` returns a cursor-paginated list with no
  built-in time bucketing. So the x-axis bucketing/labels must be decided by the
  consuming screen. `AxisLabelProvider` keeps this the caller's concern, so no
  blocker here.

## 14. Acceptance Criteria

AC-1. `TestLogonLineChart` and `TestLogonBarChart` exist in
`com.testlogon.android.core.ui.chart` (module `core-ui`) with the signatures in
§4 and render a sample series (`SampleChartData`) correctly in light and dark
themes — directly satisfying "Chart renders sample series".

AC-2. The same composables are exercised by both a payouts sample
(`SampleChartData.payoutsBar`) and an ads sample (`SampleChartData.adsLine`) in
tests/previews, demonstrating "reused by payouts/ads".

AC-3. Charts read colors and typography exclusively from `TestLogonTheme`; no
hard-coded `Color(...)` or `TextStyle(...)` literals exist in the chart package
(verified by review/lint).

AC-4. `Loading`, `Empty`, and `Content` states each render the correct visual,
and degenerate inputs (empty data, single point, non-finite values) render
without crashing.

AC-5. Each chart exposes a single semantic node with a non-empty
`contentDescription`; user-visible strings are in `strings.xml` and localizable.

AC-6. Vico is an `implementation`-scope dependency of `core-ui` only; feature
modules can use the charts without referencing any Vico type.

AC-7. Unit and Compose UI tests from §11 are present and green in CI.

## 15. Definition of Done

- Code merged to `android-port` under `android/core-ui/.../chart/` with public
  API limited to the types/composables in §4.
- Vico pinned in `gradle/libs.versions.toml`; `core-ui/build.gradle.kts` updated;
  `./gradlew :core-ui:assemble` and `:core-ui:lint` pass with no new warnings.
- All §11 unit and instrumented tests pass in CI; screenshot baselines committed.
- `@Preview`s for line/bar/loading/empty in light and dark render in Android
  Studio.
- No hard-coded colors/typography; no network, persistence, or PII logging.
- Public types documented with KDoc; `SampleChartData` available for downstream
  AND-256/AND-257.
- Code review approved; ticket linked to AND-256 and AND-257 as blocked-by.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. Claim: This ticket performs no network I/O and contacts no backend endpoint.
   VERDICT: Verified (by scope). SOURCE: ticket scope `specs-src/AND-255.md`
   ("Line/bar charts composable … for finance screens") plus §1/§3 — no endpoint
   is referenced as a deliverable. The component only consumes `ChartUiState`.

2. Claim: The web app renders finance charts using a JS charting library.
   VERDICT: Verified (and named). SOURCE: `src/pages/earnings/EarningsPage.tsx`
   (imports from `recharts`) and `src/pages/analytics/AnalyticsPage.tsx`
   (`BarChart, Bar, Line, ComposedChart, Legend` from `recharts`). It is
   **recharts**, not an unspecified lib.

3. Claim: Some web finance surfaces use hand-rolled (non-library) charts.
   VERDICT: Verified (additional context). SOURCE:
   `src/components/shared/VolumeChart.tsx` and `src/components/shared/FunnelChart.tsx`
   render div/flex bars directly (no recharts import). Used as parity reference for
   the simple bar case.

4. Claim (original draft): the ads chart data comes from `GET /ui/ads/stats`.
   VERDICT: Corrected. SOURCE: OpenAPI index — no `GET /ui/ads/stats` collection
   path exists. Only `GET /ui/ads/stats/{campaign_id}`
   (op `serving_stats_endpoint_ui_ads_stats__campaign_id__get`) exists, which is
   per-campaign serving stats, not a chart time-series. The chart time-series
   source is `GET /ui/ads/analytics/timeseries`
   (op `analytics_timeseries_endpoint_ui_ads_analytics_timeseries_get`,
   params `account_id,campaign_id,days,granularity,...`) and
   `GET /ui/ads/analytics/summary`.

5. Claim: payouts chart data comes from `GET /ui/payouts`.
   VERDICT: Verified. SOURCE: OpenAPI index
   `GET /ui/payouts | op=list_payouts_ui_payouts_get | resp=200:PayoutListOut`,
   plus `GET /ui/payouts/balance` (resp `PayoutBalanceOut`). Note: ownership of
   this call is downstream (AND-256), not this ticket.

6. Claim: the `/ui/...` finance endpoints authenticate via session headers.
   VERDICT: Verified. SOURCE: OpenAPI index params for `/ui/payouts`,
   `/ui/earnings/summary`, `/ui/ads/analytics/timeseries` all list
   `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`. (Not consumed by this
   component; recorded for downstream parity.)

7. Claim: time granularity for finance series is a fixed/known shape.
   VERDICT: Corrected/clarified. SOURCE: `openapi.pretty.json` — `granularity`
   query param is a free-form `string` with backend default `"daily"`/`"day"`
   (not an enum). `GET /ui/payouts` has no time bucketing at all. Hence x-axis
   bucketing is a caller concern (§13 R-5).

8. Claim: charts must consume Material 3 theme (colorScheme/typography) from
   AND-019 and not hard-code colors/text. VERDICT: Verified (dependency).
   SOURCE: ticket `Deps: AND-019` in `specs-src/AND-255.md`; framework ref for
   `MaterialTheme.colorScheme`/`typography`:
   https://developer.android.com/develop/ui/compose/designsystems/material3

9. Claim: Vico 2.x is the chosen Compose-native charting library
   (`com.patrykandpatrick.vico:compose-m3` + `vico:core`).
   VERDICT: Unverified-assumption (framework choice). SOURCE: framework ref
   https://patrykandpatrick.com/vico/ — exact artifact/version vs. Kotlin 2.0.21
   Compose Compiler compatibility is not verifiable from the repo sources here and
   must be confirmed at implementation time (see §13 R-1/R-2).

10. Claim: `@Immutable` data classes enable Compose strong-skipping; one semantic
    node per chart via `clearAndSetSemantics`. VERDICT: Verified (framework).
    SOURCE: framework refs
    https://developer.android.com/develop/ui/compose/performance/stability and
    https://developer.android.com/develop/ui/compose/accessibility

11. Claim: dev host `http://18.222.237.167:8000` / cleartext concerns are out of
    scope here. VERDICT: Verified (by scope). SOURCE: §5/§8 — no I/O in this
    module; cleartext belongs to `core-network` (a different module/ticket). The
    host string itself is from the project environment, not sources reviewed here.

### Corrections made

- §2 (Context): replaced "uses a JS charting lib" with the verified, named
  library **recharts**, with exact file pointers, and noted the div-based
  hand-rolled charts as additional parity context.
- §5 (API Contract): removed the incorrect `GET /ui/ads/stats` citation;
  replaced with the real ads time-series endpoints
  (`/ui/ads/analytics/timeseries`, `/ui/ads/analytics/summary`) and confirmed
  `/ui/payouts`(+`/balance`); added the verified `X-SESSION-ID` auth note. These
  are downstream-owned and informational only.
- §13 R-5: corrected the time-axis claim to reflect that `granularity` is a
  free-form string (default `daily`/`day`) on ads/earnings endpoints and that
  `/ui/payouts` has no bucketing, so axis bucketing is a caller concern.

### Open assumptions

- The Vico artifact coordinate/version and its Compose Compiler compatibility
  with Kotlin 2.0.21 cannot be verified from the provided sources (no Android
  build files in `reference/`); confirm during implementation. (§13 R-1, R-2.)
- The exact downstream `ChartData` mapping from `PayoutListOut` /
  `/ui/ads/analytics/timeseries` response fields is owned by AND-256/AND-257 and
  is intentionally not specified here; the response field shapes were not deeply
  mapped because this ticket renders only `ChartUiState`.
- Dynamic-color palette legibility (§13 R-3) is an empirical/visual concern not
  resolvable from sources; flagged for screenshot-test coverage.

## 17. Test Plan

Test targets legend: JVM = JVM unit/Robolectric (local, no device);
EMU = headless emulator AVD `test35` (x86_64, API 35); DEV = physical Samsung
Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Because this is a pure rendering
library with no hardware dependency (no camera/biometrics/network/WebRTC), nearly
all cases run on JVM or EMU; one ABI-difference smoke is noted for DEV.

- TC-AND-255-01 — Happy path: line chart renders sample series
  Type: Compose-UI (screenshot + smoke). Target: EMU (CI). Preconditions:
  `TestLogonTheme` applied (light); `SampleChartData.payoutsLine`.
  Steps: set content `TestLogonLineChart(ChartUiState.Content(SampleChartData.payoutsLine))`;
  let composition settle. Expected: chart draws, Y-axis tick nodes and X labels
  present, no exception; screenshot matches baseline. Traces: AC-1.

- TC-AND-255-02 — Happy path: bar chart renders sample series (light + dark)
  Type: Compose-UI (screenshot). Target: EMU (CI). Preconditions:
  `SampleChartData.payoutsBar`, run once in light and once in dark theme.
  Steps: render `TestLogonBarChart(Content(payoutsBar))` under each theme.
  Expected: columns render; colors derive from `colorScheme` (differ light vs
  dark); both screenshots match their baselines. Traces: AC-1, AC-3.

- TC-AND-255-03 — Reused by payouts AND ads through the same composables
  Type: Compose-UI (integration). Target: EMU (CI). Preconditions:
  `SampleChartData.payoutsBar` and `SampleChartData.adsLine`.
  Steps: render `TestLogonBarChart(Content(payoutsBar))` and
  `TestLogonLineChart(Content(adsLine))` in one test tree. Expected: both render
  without throwing, proving reuse across two finance series. Traces: AC-2.

- TC-AND-255-04 — Visual states: Loading / Empty / Content
  Type: Compose-UI. Target: EMU. Preconditions: a test tag/semantics on each
  state node. Steps: render `ChartUiState.Loading` (assert shimmer/placeholder
  node), then `Empty("No data")` (assert message node with "No data"), then
  `Content(payoutsLine)` (assert axis nodes). Expected: each state shows its
  correct visual and only that visual. Traces: AC-4.

- TC-AND-255-05 — Degenerate inputs do not crash
  Type: Compose-UI + JVM. Target: EMU (render) / JVM (mapping). Preconditions:
  inputs: empty `ChartData.EMPTY`, single-point series, all-zero series, all-
  negative series. Steps: render each through both line and bar charts.
  Expected: empty -> Empty visual (Vico body not built); single point ->
  marker/one column; zero/negative -> sane Y range (maxYTicks>=2), no
  exception. Traces: AC-4.

- TC-AND-255-06 — Non-finite values filtered (mapping)
  Type: unit (JVM, JUnit+Truth). Target: JVM. Preconditions: a series containing
  NaN and +/-Infinity points. Steps: run the mapping
  `points.filter { x.isFinite() && y.isFinite() }`; build `ChartData`.
  Expected: non-finite points dropped; a series emptied by filtering is dropped;
  resulting `ChartData.isEmpty` true when all filtered out. Traces: AC-4.

- TC-AND-255-07 — `ChartData.isEmpty` logic
  Type: unit (JVM). Target: JVM. Preconditions: three inputs: `emptyList()`,
  list of series each with `emptyList()` points, populated data.
  Steps: read `isEmpty`. Expected: true, true, false respectively. Traces: AC-4.

- TC-AND-255-08 — `CompactNumberFormatter` outputs (Locale.US)
  Type: unit (JVM). Target: JVM. Preconditions: `Locale.US`.
  Steps: format 999, 1_200, 3_400_000. Expected: "999", "1.2K", "3.4M".
  Traces: AC-1 (axis labels correct).

- TC-AND-255-09 — `CurrencyAxisValueFormatter` USD output
  Type: unit (JVM/Robolectric for `NumberFormat`). Target: JVM. Preconditions:
  currency code "USD", Locale.US. Steps: format `1234.5f`. Expected:
  "$1,234.50". Traces: AC-1.

- TC-AND-255-10 — Theme-only colors/typography (no hard-coded literals)
  Type: unit/static (JVM) + Robolectric palette check. Target: JVM.
  Preconditions: chart package sources. Steps: (a) lint/regex assertion that no
  `Color(` literal or `TextStyle(` literal exists in the chart package; (b)
  `rememberChartPalette()` under a known theme yields >= 4 distinct colors with
  deterministic ordering. Expected: no literals found; palette deterministic and
  >= 4 distinct. Traces: AC-3, AC-6 (palette derives from theme only).

- TC-AND-255-11 — Accessibility: single semantic node with contentDescription
  Type: Compose-UI (semantics) + accessibility check. Target: EMU.
  Preconditions: render line chart without an explicit `contentDescription`.
  Steps: query semantics tree. Expected: exactly one merged semantic node for the
  chart with a non-empty generated description (e.g. "Line chart, {n} series,
  latest value {formatted}"); inner canvas not separately announced
  (`clearAndSetSemantics`). When a caller supplies `contentDescription`, it is
  used verbatim. Traces: AC-5.

- TC-AND-255-12 — i18n strings come from resources, not literals
  Type: unit/static (JVM). Target: JVM. Preconditions: `core-ui` strings.xml.
  Steps: assert "No data" and default-description fallbacks resolve via
  `stringResource`/parameterized resources, not concatenated string literals in
  Kotlin. Expected: strings sourced from `strings.xml`; parameterized, no
  concatenation. Traces: AC-5.

- TC-AND-255-13 — Vico-scope isolation (no Vico types leak to feature modules)
  Type: contract/static (JVM, dependency-config assertion). Target: JVM.
  Preconditions: `core-ui/build.gradle.kts` declares Vico as `implementation`.
  Steps: assert Vico is `implementation` (not `api`); assert public chart API
  exposes only TestLogon types (no `com.patrykandpatrick.vico.*` in public
  signatures). Expected: Vico not on the API surface; a feature module can use
  charts without a Vico dependency. Traces: AC-6.

- TC-AND-255-14 — Defensive renderer-failure fallback
  Type: Compose-UI / integration. Target: EMU. Preconditions: inject a chart body
  that throws (or feed input that forces a Vico render exception via a test seam).
  Steps: render and let it throw inside the body. Expected: caught, logged at
  WARN with exception class, falls back to `Empty("Chart unavailable")` rather
  than crashing the screen. Traces: AC-4.

- TC-AND-255-15 — ABI/API smoke on physical device
  Type: instrumented/e2e (smoke). Target: DEV (Samsung A15, arm64-v8a, API 34) —
  MUST run on the physical device to catch arm64-vs-x86 and API-34-vs-35 rendering
  differences not seen on the x86_64 API-35 emulator. Preconditions: app/test APK
  installed on SM-A156U via adb. Steps: render line+bar `SampleChartData` and the
  Loading/Empty/Content states. Expected: renders identically (within screenshot
  tolerance) to the EMU baselines; no ABI/API crash. Traces: AC-1, AC-4.

### Coverage matrix (section-14 ACs -> test cases)

- AC-1 (charts exist + render sample series, light/dark): TC-01, TC-02, TC-08,
  TC-09, TC-15.
- AC-2 (reused by payouts + ads samples): TC-03.
- AC-3 (theme-only colors/typography, no literals): TC-02, TC-10.
- AC-4 (Loading/Empty/Content + degenerate inputs render without crashing):
  TC-04, TC-05, TC-06, TC-07, TC-14, TC-15.
- AC-5 (single semantic node + non-empty contentDescription; localizable
  strings): TC-11, TC-12.
- AC-6 (Vico implementation-scope only; no Vico type in feature modules):
  TC-10, TC-13.
- AC-7 (unit + Compose-UI tests present and green in CI): satisfied collectively
  by TC-01..TC-15 (all run in CI; TC-15 on the connected device).
