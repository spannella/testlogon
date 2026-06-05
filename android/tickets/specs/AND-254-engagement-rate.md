---
id: AND-254
title: Engagement rate
milestone: M6
epic: E34
priority: P2
size: M
status: draft
depends_on: [AND-251]
blocks: []
---

# AND-254 — Engagement rate

## 1. Overview & Goal

This ticket delivers the **engagement-rate metrics** surface for the Creator
Analytics area of epic E34: a pure computation module that derives engagement
rate and supporting interaction ratios, the `EngagementApi` transport for
`/ui/analytics/engagement`, and a thin Compose card that renders the metrics in
the analytics dashboard.

Scope, verbatim from the backlog: *`engagementRate.ts` metrics.* The single
acceptance criterion is: *Engagement metrics render.* The web reference
`frontend/src/api/endpoints/engagementRate.ts` is a derivation + formatting
module: it pulls interaction counts (likes, comments, shares, saves, views,
reach) over a window and computes the rate plus a few derived ratios. This port
preserves that contract — the math is a pure, deterministic, unit-tested Kotlin
function; the UI is a thin renderer over the computed model.

This ticket owns:

- the `EngagementApi` Retrofit interface for the analytics-engagement endpoint;
- the wire DTOs (`@JsonClass(generateAdapter = true)`) in `core-model`;
- the pure metric calculator `EngagementRate` (the port of `engagementRate.ts`)
  and its domain models;
- a `feature-analytics` ViewModel exposing `StateFlow<EngagementUiState>`;
- a Compose `EngagementRateCard` that renders the computed metrics into the
  dashboard, with loading / empty / error / offline states.

It does **not** own the earnings transport/DTOs (AND-251), the earnings charts
or dashboard scaffold (AND-252), or per-content revenue (AND-253). It depends on
AND-251 for the analytics Retrofit/Hilt/mapping conventions it mirrors.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`.
  - Calculator + domain models + DTOs + mappers: module **`core-model`**,
    package `com.testlogon.android.core.model.engagement`.
  - Retrofit interface + Hilt provider: module **`core-network`**, package
    `com.testlogon.android.core.network.engagement`.
  - ViewModel + Compose: module **`feature-analytics`**, package
    `com.testlogon.android.feature.analytics.engagement`.
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Jetpack Compose + Material 3,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11.0, OkHttp 4.12.0, Moshi 1.15.x
  (KSP codegen), JDK 17, minSdk 24 / compileSdk 35.
- **Module layering:** `app -> feature-* -> core-*`. The calculator and DTOs sit
  in `core-model`; the API in `core-network`; the ViewModel/UI in
  `feature-analytics`. No `feature-*`/`app` symbols leak into `core-*`.
- **Upstream dependency — AND-251 (Earnings API + DTOs):** establishes the
  session-gated analytics Retrofit usage, the Moshi-codegen DTO style, the
  pure-mapper convention, and the defensive-defaults decoding pattern reused here.
- **Cross-cutting (already attached to the shared `OkHttpClient`/`Retrofit`):**
  persistent cookie jar (AND-011), CSRF header (AND-012), 401→refresh
  `Authenticator` (AND-013), `ApiResult<T>` wrapping (AND-018), FastAPI `detail`
  error mapping (AND-015), idempotent-GET retry/backoff (AND-016), state
  composables (AND-021). These apply without changes here.
- **Backend contract:** FastAPI + DynamoDB, OpenAPI at
  `http://18.222.237.167:8000/openapi.json` (dev, **plaintext HTTP**,
  unreliable, ~20s timeouts). Relevant operation:
  `engagement_metrics_ui_analytics_engagement_get` returning
  `EngagementMetricsOut` (and optional `EngagementSeriesPoint`).
- **Web reference:** `frontend/src/api/endpoints/engagementRate.ts` (call shape,
  query params, the exact engagement-rate formula and rounding) and
  `frontend/src/api/types.ts` (field names). Where the web formula and the
  backend differ, the **backend `/openapi.json` is authoritative** for field
  names and the web file is authoritative for the derivation formula.

## 3. Functional Requirements

FR-1. Fetch raw engagement aggregates for the authenticated creator over a date
window via a suspend Retrofit call to `GET /ui/analytics/engagement`, accepting
the same optional `from_date`/`to_date`/`granularity`/`from_ts`/`to_ts` window
params as the earnings summary (AND-251), with `null` params omitted from the
query string.

FR-2. Compute, in a **pure deterministic function**, the engagement rate and its
supporting ratios from the raw counts. The primary engagement rate is:

```
engagementRate = (likes + comments + shares + saves) / reach * 100
```

where `reach` is impressions/reach as supplied by the backend. When the backend
already provides a precomputed `engagement_rate`, the calculator MUST prefer the
server value and expose the locally computed value only as a cross-check
(reconciliation), never overriding the server number in the UI.

FR-3. The calculator MUST be **divide-by-zero safe**: when `reach == 0` (no
audience in the window) the engagement rate is `null` (rendered as an em dash
"—" / "No data"), not `NaN`, `Infinity`, or `0%`.

FR-4. The engagement rate MUST be rounded to **one decimal place**
(half-up / `RoundingMode.HALF_UP`) for display, matching the web reference, while
the unrounded ratio is retained on the domain model for any downstream charting.

FR-5. Compute and expose these derived sub-metrics for the same window:
total interactions, like rate, comment rate, share rate, save rate (each as a
percentage of reach), and average interactions per post when `post_count > 0`.
Each sub-rate is divide-by-zero safe and one-decimal rounded for display.

FR-6. Expose a period-over-period **delta** (current window vs. the previous
equal-length window) when the backend supplies a `previous` block: the absolute
change in percentage points and a direction (`UP`/`DOWN`/`FLAT`), with `FLAT`
when |delta| < 0.05 pp. Absent a `previous` block, the delta is `null`.

FR-7. The ViewModel MUST expose `StateFlow<EngagementUiState>` with `Loading`,
`Empty` (zero reach / no interactions), `Error(message)`, and `Success(model)`,
plus an `isStale` flag for offline/last-known display.

FR-8. The `EngagementRateCard` Compose MUST **render the computed engagement
metrics** (headline rate + delta chip + the sub-metric rows) inside the analytics
dashboard, and render the loading/empty/error/offline states using the shared
state composables (AND-021). This satisfies the acceptance "Engagement metrics
render."

FR-9. All percentage formatting MUST be locale-aware (`NumberFormat.getPercent`
/ `getNumberInstance(locale)`); no hard-coded `%` glyph or `.`-decimal
assumption in the data layer.

## 4. Technical Design

**Module placement.** Calculator, DTOs, domain models, mappers → `core-model`
(Moshi KSP already applied). Retrofit interface + Hilt provider → `core-network`.
ViewModel + Compose → `feature-analytics`.

**Retrofit interface** (`core-network/.../engagement/EngagementApi.kt`):

```kotlin
package com.testlogon.android.core.network.engagement

import com.testlogon.android.core.model.engagement.dto.EngagementMetricsDto
import retrofit2.http.GET
import retrofit2.http.Query

interface EngagementApi {

    @GET("ui/analytics/engagement")
    suspend fun getEngagement(
        @Query("from_date") fromDate: String? = null,
        @Query("to_date") toDate: String? = null,
        @Query("granularity") granularity: String = "day",
        @Query("from_ts") fromTs: Long? = null,
        @Query("to_ts") toTs: Long? = null,
    ): EngagementMetricsDto
}
```

Retrofit omits `null` `@Query` params, satisfying FR-1. Operator/impersonation
params (`user_sub`, `X-IMPERSONATION-TOKEN`) are deliberately not exposed; the
session cookie identifies the principal.

**Hilt provider** (`core-network/.../engagement/EngagementNetworkModule.kt`):

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object EngagementNetworkModule {
    @Provides @Singleton
    fun provideEngagementApi(retrofit: Retrofit): EngagementApi =
        retrofit.create(EngagementApi::class.java)
}
```

`Retrofit` is the qualified session-scoped instance (cookie jar, CSRF,
authenticator, Moshi) from AND-010/AND-027.

**The calculator — port of `engagementRate.ts`**
(`core-model/.../engagement/EngagementRate.kt`). Pure, no Android/IO deps:

```kotlin
package com.testlogon.android.core.model.engagement

import java.math.BigDecimal
import java.math.RoundingMode

object EngagementRate {

    /** Reach-based engagement rate as a percentage, or null when reach == 0. */
    fun rate(counts: InteractionCounts): Double? {
        if (counts.reach <= 0L) return null
        val interactions = counts.totalInteractions().toDouble()
        return interactions / counts.reach.toDouble() * 100.0
    }

    /** Rounds a percentage to one decimal (HALF_UP); null passes through. */
    fun displayPercent(value: Double?): Double? =
        value?.let {
            BigDecimal(it).setScale(1, RoundingMode.HALF_UP).toDouble()
        }

    fun compute(
        current: EngagementAggregate,
        previous: EngagementAggregate? = null,
    ): EngagementMetrics {
        val c = current.counts
        val computed = rate(c)
        // Prefer the server value when present (FR-2), keep local as reconcile.
        val effective = current.serverRate ?: computed
        val prevRate = previous?.let { it.serverRate ?: rate(it.counts) }
        val deltaPp = if (effective != null && prevRate != null)
            effective - prevRate else null
        return EngagementMetrics(
            engagementRate = effective,
            engagementRateDisplay = displayPercent(effective),
            localComputedRate = computed,
            likeRate = ratio(c.likes, c.reach),
            commentRate = ratio(c.comments, c.reach),
            shareRate = ratio(c.shares, c.reach),
            saveRate = ratio(c.saves, c.reach),
            totalInteractions = c.totalInteractions(),
            avgInteractionsPerPost =
                if (c.postCount > 0) c.totalInteractions().toDouble() / c.postCount else null,
            deltaPercentagePoints = displayPercent(deltaPp),
            trend = trendOf(deltaPp),
            currencyHint = current.currencyHint, // unused for rates; carried for parity
        )
    }

    private fun ratio(numer: Long, reach: Long): Double? =
        if (reach <= 0L) null else numer.toDouble() / reach.toDouble() * 100.0

    private fun trendOf(deltaPp: Double?): Trend = when {
        deltaPp == null -> Trend.UNKNOWN
        kotlin.math.abs(deltaPp) < 0.05 -> Trend.FLAT
        deltaPp > 0 -> Trend.UP
        else -> Trend.DOWN
    }
}

enum class Trend { UP, DOWN, FLAT, UNKNOWN }
```

`InteractionCounts.totalInteractions()` = `likes + comments + shares + saves`.

**Mapping layer** (`core-model/.../engagement/EngagementMappers.kt`): pure
extension `fun EngagementMetricsDto.toAggregate(): EngagementAggregate` (and the
`previous` block), null-safe with backend defaults (`0` counts, `"USD"`
currency). `EngagementMetricsDto.toMetrics()` chains `toAggregate()` →
`EngagementRate.compute(...)`. Series points (if present) map order-preserving
exactly as AND-251's series mapper.

**ViewModel** (`feature-analytics/.../engagement/EngagementViewModel.kt`):

```kotlin
@HiltViewModel
class EngagementViewModel @Inject constructor(
    private val repo: EngagementRepository, // thin wrapper over EngagementApi + apiCall{}
) : ViewModel() {
    private val _state = MutableStateFlow<EngagementUiState>(EngagementUiState.Loading)
    val state: StateFlow<EngagementUiState> = _state.asStateFlow()

    fun load(window: AnalyticsWindow = AnalyticsWindow.last30Days()) {
        viewModelScope.launch {
            _state.value = EngagementUiState.Loading
            _state.value = when (val r = repo.engagement(window)) {
                is ApiResult.Success -> r.data.toUiState()
                is ApiResult.Failure -> EngagementUiState.Error(r.message, isStale = false)
            }
        }
    }
    fun retry() = load()
}
```

`EngagementRepository` lives in `core-data` (or co-located in `feature-analytics`
if E34 has not yet created the analytics repo seam) and wraps the suspend API in
the shared `apiCall { }` → `ApiResult<EngagementMetrics>` helper (AND-018),
applying the idempotent-GET retry (AND-016).

**Compose** (`feature-analytics/.../engagement/EngagementRateCard.kt`):

```kotlin
@Composable
fun EngagementRateCard(
    state: EngagementUiState,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
)
```

It is a Material 3 `Card` placed by AND-252's dashboard. It shows the headline
`engagementRateDisplay` (or "—" when null), a `TrendChip` for the delta, and a
`Column` of sub-metric rows (`MetricRow(label, value)`). `Loading`→shimmer/
spinner, `Empty`→"No engagement data for this period", `Error`→error+Retry,
`isStale`→stale banner, all via AND-021 composables.

## 5. API Contract

Base URL: runtime-selected host (dev `http://18.222.237.167:8000`). Path relative
to base; session-authenticated (cookies + `X-CSRF-Token`).

**GET `/ui/analytics/engagement`** → `200 EngagementMetricsOut`

Query (all optional): `from_date`, `to_date` (`YYYY-MM-DD`),
`granularity` (`day`|`week`|`month`, default `day`), `from_ts`, `to_ts` (Unix s).

```json
{
  "window": { "from_date": "2026-05-06", "to_date": "2026-06-05", "granularity": "day" },
  "currency": "USD",
  "post_count": 42,
  "reach": 18450,
  "impressions": 24310,
  "likes": 1320,
  "comments": 210,
  "shares": 96,
  "saves": 188,
  "views": 9740,
  "engagement_rate": 9.83,
  "previous": {
    "reach": 16100,
    "likes": 1010,
    "comments": 175,
    "shares": 70,
    "saves": 140,
    "post_count": 38,
    "engagement_rate": 8.66
  },
  "series": [
    { "date": "2026-05-06", "reach": 600, "likes": 40, "comments": 6,
      "shares": 2, "saves": 5, "engagement_rate": 8.83 }
  ]
}
```

Notes:
- `engagement_rate` is a **percentage already** (e.g. `9.83` = 9.83%), not a
  fraction. The local calculator produces the same scale for reconciliation.
- `previous` is optional; absent → delta is `null` / `Trend.UNKNOWN`.
- `series` is optional; included for an upstream sparkline (E34 charts, AND-252)
  but this ticket only needs to decode and preserve it.
- All count fields default to `0`; `currency` defaults to `"USD"`. `engagement_rate`
  may be `null` when reach is `0` server-side.

Error envelope (via AND-015): FastAPI `detail` is `string | [{msg}] | {code,...}`.
`401` triggers the shared `Authenticator` (one refresh + retry). `422` validation
bodies are mapped by AND-015 and surfaced as `EngagementUiState.Error`. This
ticket adds no error re-mapping.

## 6. Data & State Management

**DTOs** in `com.testlogon.android.core.model.engagement.dto` (Moshi codegen):

```kotlin
@JsonClass(generateAdapter = true)
data class EngagementMetricsDto(
    val window: AnalyticsWindowDto? = null,
    val currency: String = "USD",
    @Json(name = "post_count") val postCount: Int = 0,
    val reach: Long = 0,
    val impressions: Long = 0,
    val likes: Long = 0,
    val comments: Long = 0,
    val shares: Long = 0,
    val saves: Long = 0,
    val views: Long = 0,
    @Json(name = "engagement_rate") val engagementRate: Double? = null,
    val previous: EngagementPreviousDto? = null,
    val series: List<EngagementSeriesPointDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class EngagementPreviousDto(
    val reach: Long = 0, val likes: Long = 0, val comments: Long = 0,
    val shares: Long = 0, val saves: Long = 0,
    @Json(name = "post_count") val postCount: Int = 0,
    @Json(name = "engagement_rate") val engagementRate: Double? = null,
)

@JsonClass(generateAdapter = true)
data class EngagementSeriesPointDto(
    val date: String,
    val reach: Long = 0, val likes: Long = 0, val comments: Long = 0,
    val shares: Long = 0, val saves: Long = 0,
    @Json(name = "engagement_rate") val engagementRate: Double? = null,
)

@JsonClass(generateAdapter = true)
data class AnalyticsWindowDto(
    @Json(name = "from_date") val fromDate: String? = null,
    @Json(name = "to_date") val toDate: String? = null,
    val granularity: String = "day",
)
```

**Domain models** in `com.testlogon.android.core.model.engagement`:

```kotlin
data class InteractionCounts(
    val reach: Long, val impressions: Long, val likes: Long, val comments: Long,
    val shares: Long, val saves: Long, val views: Long, val postCount: Int,
) { fun totalInteractions(): Long = likes + comments + shares + saves }

data class EngagementAggregate(
    val counts: InteractionCounts,
    val serverRate: Double?,        // backend engagement_rate (percentage) or null
    val currencyHint: String,
)

data class EngagementMetrics(
    val engagementRate: Double?,            // effective, unrounded (percentage)
    val engagementRateDisplay: Double?,     // HALF_UP to 1 dp, null-safe
    val localComputedRate: Double?,         // reconciliation only
    val likeRate: Double?, val commentRate: Double?,
    val shareRate: Double?, val saveRate: Double?,
    val totalInteractions: Long,
    val avgInteractionsPerPost: Double?,
    val deltaPercentagePoints: Double?,     // current - previous, 1 dp
    val trend: Trend,
    val currencyHint: String,
)

data class EngagementSeriesPoint(
    val date: LocalDate?, val rawDate: String,
    val reach: Long, val engagementRate: Double?,
)
```

**UI state** (`feature-analytics/.../engagement/EngagementUiState.kt`):

```kotlin
sealed interface EngagementUiState {
    data object Loading : EngagementUiState
    data class Success(val metrics: EngagementMetrics, val isStale: Boolean = false) : EngagementUiState
    data object Empty : EngagementUiState                 // reach == 0 / no interactions
    data class Error(val message: String, val isStale: Boolean = false) : EngagementUiState
}
```

`EngagementMetrics.toUiState()` maps to `Empty` when `reach == 0` **and**
`totalInteractions == 0`, else `Success`. Models are immutable value objects.
No Room/DataStore writes in this ticket; any caching is owned by the E34 analytics
repository seam (mirrors AND-251→AND-252 split). `series` is decoded and
preserved for AND-252 sparklines but not rendered here.

## 7. Error Handling & Resilience

- The suspend `EngagementApi.getEngagement` is wrapped in the shared `apiCall { }`
  → `ApiResult<T>` (AND-018); transport failures, the ~20s OkHttp timeout, and
  HTTP error codes become `ApiResult.Failure` mapped through AND-015.
- The call is an **idempotent GET**, so bounded-backoff retry (AND-016) applies;
  this ticket adds nothing beyond honouring it.
- **Divide-by-zero / NaN safety is the central resilience concern** (FR-3): every
  ratio is computed only when `reach > 0`; otherwise the value is `null` and the
  UI renders "—". A reflection/property guard test asserts no `Double` in the
  metrics graph can be `NaN` or `Infinity` for any non-negative count input.
- Moshi decoding is defensive: all counts default to `0`, `engagement_rate`/
  `previous`/`series` are nullable/empty-tolerant, so a partial `200 {}` body
  decodes to an all-zero aggregate → `Empty` state rather than a crash.
- `series[i].date` parsing uses `runCatching { LocalDate.parse(...) }`; weekly/
  monthly bucket labels that are not `YYYY-MM-DD` degrade to `date == null` with
  `rawDate` retained (mirrors AND-251).
- Server/local rate divergence: if `localComputedRate` and `serverRate` differ by
  more than 0.5 pp, log a single non-PII debug line (counts redacted) and keep the
  **server** value in the UI; never block render on reconciliation.
- Offline/stale: when the repository serves a last-known value (E34 cache), the
  ViewModel sets `isStale = true` and the card shows the stale banner (AND-021).

## 8. Security & Privacy

- The endpoint is session-gated; auth rides the persistent cookie jar (AND-011)
  and `X-CSRF-Token` header (AND-012). No tokens/credentials are handled here.
- Engagement aggregates are business-sensitive creator analytics. Raw counts and
  computed rates MUST NOT be logged (see §10) and MUST NOT be written to any
  plaintext store in this ticket (no caching here; the E34 repo owns at-rest
  decisions).
- Operator/impersonation params (`user_sub`, `X-IMPERSONATION-TOKEN`) are
  deliberately not exposed on the mobile interface, preventing a client from
  requesting another principal's analytics.
- Dev traffic is plaintext HTTP on the dev host only; release builds target HTTPS.
  No cleartext exemption is widened by this ticket.

## 9. Accessibility & i18n

- The headline rate, delta chip, and each sub-metric row carry a
  `contentDescription` / `semantics` merge so a screen reader announces a single
  meaningful phrase (e.g. "Engagement rate 9.8 percent, up 1.2 points") rather
  than disjoint number/label fragments.
- The `TrendChip` does not rely on colour alone: it pairs the up/down arrow icon
  and a sign-prefixed value, satisfying colour-independence; touch targets ≥ 48dp.
- Layout supports Dynamic Type and the largest font scale without truncating the
  headline; numbers wrap rather than clip.
- All percentages/numbers are formatted with `NumberFormat.getNumberInstance(
  locale)` / `getPercentInstance(locale)`; the data layer never hard-codes `%`
  or a `.` decimal separator (FR-9). The em-dash "no data" placeholder uses a
  localized string resource. RTL-ready (AND-114): no hard-coded start/end.
- All visible strings live in `feature-analytics` `strings.xml` (i18n plumbing
  AND-111), not literals in Compose.

## 10. Telemetry & Logging

- Reuse the redacted-logging policy (AND-052). Engagement counts and computed
  rates MUST be redacted from any HTTP log; the OkHttp logging interceptor stays
  at `BASIC` (`NONE` in release) so bodies are never emitted.
- Permitted analytics event: `engagement_metrics_viewed` with **non-PII**
  attributes only — `granularity`, window length in days, and a coarse
  `has_data` boolean. Never log the rate value or any raw count.
- A single non-PII debug line on (a) decode failure (`EngagementApi: decode
  failed` — no body) and (b) server/local rate divergence > 0.5 pp (delta
  magnitude bucketed, no counts) is permitted to aid contract debugging.

## 11. Testing Strategy

**Calculator (pure JVM unit tests, `core-model`)** — the core of correctness:

- **T-1 Formula:** `compute` over a known aggregate yields
  `(likes+comments+shares+saves)/reach*100`; e.g. counts (1320,210,96,188) over
  reach 18450 → `localComputedRate ≈ 9.834…`.
- **T-2 Rounding:** `engagementRateDisplay` is HALF_UP to 1 dp (e.g. `9.834…`→`9.8`,
  `9.85`→`9.9`).
- **T-3 Divide-by-zero:** `reach == 0` → `engagementRate == null`, all sub-rates
  `null`, no `NaN`/`Infinity`; `toUiState()` → `Empty`.
- **T-4 Server preference:** when `serverRate` present it is the `engagementRate`,
  `localComputedRate` is still populated for reconciliation.
- **T-5 Delta/trend:** with a `previous` block, `deltaPercentagePoints` =
  current−previous (1 dp) and `trend` is UP/DOWN/FLAT per the 0.05 pp threshold;
  absent `previous` → delta `null`, `Trend.UNKNOWN`.
- **T-6 Per-post average:** `postCount > 0` → average; `postCount == 0` → `null`.
- **T-7 NaN/Infinity guard:** property/reflection test asserts no metric is
  `NaN`/`Infinity` across randomized non-negative inputs including zero reach.

**API + mapping (`MockWebServer`, `core-network`/`core-model`, AND-046 fixtures):**

- **T-8 Path/verb/query:** enqueue 200; assert `GET /ui/analytics/engagement`,
  null params absent from query string, `granularity=day` default present.
- **T-9 Full mapping:** `engagement_full.json` decodes; every count, `previous`,
  and `series` order preserved; `series[0].date == LocalDate.parse("2026-05-06")`.
- **T-10 Defaults tolerance:** `engagement_empty.json` (`{}`/partial) decodes to
  all-zero aggregate → `Empty`.
- **T-11 Series date degradation:** weekly labels (`2026-W19`) → `date == null`,
  `rawDate` retained, no throw.

**ViewModel (`core-testing`, coroutine test rule):**

- **T-12 State flow:** `load()` emits `Loading` → `Success`; `ApiResult.Failure`
  → `Error`; zero-reach payload → `Empty`; `retry()` re-issues the call.

**Compose UI tests (`feature-analytics`, AND-048 harness) — proves acceptance:**

- **T-13 Render success:** given a `Success` state, the headline rate text, the
  trend chip, and at least the like/comment/share/save rows are displayed
  (`assertIsDisplayed`) — **"Engagement metrics render."**
- **T-14 Render non-success:** `Loading`/`Empty`/`Error`(+Retry click)/stale
  states each render their expected node; "—" shown when rate is `null`.
- **T-15 a11y:** the headline node exposes a merged `contentDescription`.

Coverage gate: 100% of `EngagementRate` calculator branches exercised.

## 12. Dependencies & Sequencing

- **Depends on AND-251 (Earnings API + DTOs):** provides the established
  analytics-domain Retrofit/Hilt provider pattern, the Moshi-codegen DTO style,
  the pure-mapper convention, the `Money`/series patterns, and the defensive-
  defaults decoding this ticket mirrors. Transitively depends on AND-027
  (session/AuthApi), AND-010 (Retrofit+Moshi), AND-009 (OkHttp), AND-011/012/013
  (cookies/CSRF/refresh), AND-015 (error mapping), AND-016 (idempotent-GET
  retry), AND-018 (`ApiResult`), AND-021 (state composables), AND-046
  (MockWebServer harness), AND-048 (Compose UI test harness), AND-111
  (i18n plumbing).
- **Relationship to siblings:** AND-252 (earnings dashboard + charts) is the
  natural host that places `EngagementRateCard`; this ticket should land its card
  as a self-contained, droppable composable so AND-252 can mount it without
  rework. If AND-252 has not yet created an analytics repository seam, this ticket
  introduces a minimal `EngagementRepository` that AND-252 can later absorb.
  AND-253 (per-content revenue) is a sibling metrics surface and shares no code
  beyond the conventions.
- **Blocks:** none recorded in the backlog.
- **Sequencing:** land calculator + DTOs + mappers + API + provider + ViewModel +
  card + tests together; merge to `android-port` after AND-251.

## 13. Risks & Open Questions

- **Denominator definition.** The engagement-rate denominator may be `reach`,
  `impressions`, or `views` depending on the platform's definition. This spec uses
  `reach` to match the web `engagementRate.ts`. **Open question:** confirm the
  exact denominator and formula against `frontend/src/api/endpoints/engagementRate.ts`
  and `/openapi.json`; if the backend returns a precomputed `engagement_rate`, the
  UI uses it and the formula choice only affects reconciliation.
- **Endpoint path/shape.** `/ui/analytics/engagement` and `EngagementMetricsOut`
  are inferred from the E34 analytics grouping and the AND-251 conventions; the
  web reference may expose engagement under a different path (e.g.
  `/ui/earnings/engagement` or a combined analytics summary). **Confirm the path
  and field names against `/openapi.json` before implementation**; the DTO field
  names are the only thing that must change if it differs.
- **`previous` availability.** If the backend does not return a `previous` block,
  the delta/trend feature is silently disabled (delta `null`). A follow-up could
  issue a second windowed call for the prior period; out of scope here.
- **Rounding parity.** Confirm the web app rounds to 1 dp HALF_UP (vs. banker's
  rounding/`toFixed`); a mismatch is a display-only nit fixed by changing the
  `RoundingMode`.
- **Empty vs. error ambiguity** on the unreliable dev host: a partial/empty `200`
  maps to `Empty` (all-zero), which is acceptable but indistinguishable from a
  genuine zero-engagement window — surfaced as "No engagement data."

## 14. Acceptance Criteria

1. `EngagementApi.getEngagement` exists in `core-network` at the exact path
   `ui/analytics/engagement`, GET verb, with the §4 window query params; null
   params are omitted from the wire request (proved by `MockWebServer`
   `RecordedRequest`).
2. All DTOs and domain models in §5–§6 exist in `core-model` with Moshi codegen;
   the module compiles with no hand-written adapters.
3. `EngagementRate.compute` produces the engagement rate per the §3 formula,
   prefers the server value when present, rounds the display value HALF_UP to
   1 dp, and is divide-by-zero/NaN-safe (T-1…T-7 pass).
4. Sub-metrics (like/comment/share/save rates, total interactions, avg per post)
   and the period-over-period delta + trend are computed exactly as specified.
5. `EngagementViewModel` exposes `StateFlow<EngagementUiState>` emitting
   `Loading → Success/Empty/Error`, with `retry()` and an `isStale` flag (T-12).
6. `EngagementRateCard` **renders the computed engagement metrics** in the
   dashboard — headline rate, trend chip, and sub-metric rows — and renders the
   loading/empty/error/offline states; "—" is shown when the rate is `null`
   (T-13/T-14). This satisfies the backlog acceptance "Engagement metrics render."
7. Percentages/numbers are locale-formatted; no hard-coded `%`/decimal in the data
   layer; the headline exposes a merged a11y description (T-15).
8. No engagement counts or rates appear in any log output (manual review against
   §10).
9. The full test suite (§11, T-1…T-15) passes in CI (AND-050 unit, AND-051
   instrumented).

## 15. Definition of Done

- Code merged to `android-port`: `EngagementApi`, `EngagementNetworkModule`,
  engagement DTOs, domain models (`InteractionCounts`, `EngagementAggregate`,
  `EngagementMetrics`, `EngagementSeriesPoint`, `Trend`), `EngagementRate`
  calculator, `EngagementMappers`, `EngagementUiState`, `EngagementViewModel`,
  and `EngagementRateCard`, under the canonical
  `com.testlogon.android.core.{network,model}.engagement` and
  `com.testlogon.android.feature.analytics.engagement` packages.
- Unit + ViewModel + Compose UI tests (T-1…T-15) green locally and on CI
  (AND-050/AND-051); calculator branch coverage 100%.
- ktlint/detekt clean (AND-005); no new lint baselines added.
- No engagement counts or rates appear in any log output (manual review against
  the §10 policy).
- KDoc on `EngagementApi`, the `EngagementRate` calculator (documenting formula,
  rounding rule, and divide-by-zero contract), and the mappers (pure/total).
- `EngagementRateCard` is droppable into the AND-252 dashboard with no further
  changes to this module (verified by mounting it in the dashboard preview or a
  throwaway host).
- PR description references AND-254 and AND-251, and notes the §13 open questions
  (denominator/formula, endpoint path/field names) for confirmation against
  `/openapi.json` and the web reference before/at code review.
