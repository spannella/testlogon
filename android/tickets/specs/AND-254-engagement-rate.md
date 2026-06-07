---
id: AND-254
title: Engagement rate
milestone: M6
epic: E34
priority: P2
size: M
depends_on: [AND-251]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-254 — Engagement rate

## 1. Overview & Goal

This ticket delivers the **engagement-rate metrics** surface for the Creator
Analytics area of epic E34: a pure computation module that derives engagement
rate and supporting interaction ratios, the `EngagementApi` transport for
`/ui/analytics/engagement`, and a thin Compose card that renders the metrics in
the analytics dashboard.

Scope, verbatim from the backlog: *`engagementRate.ts` metrics.* The single
acceptance criterion is: *Engagement metrics render.*

**[CORRECTED after source review]** The web reference
`frontend/src/api/endpoints/engagementRate.ts` is **not** a derivation/formatting
module — it is a thin endpoint-call wrapper. `getEngagementRate(periodDays = 30)`
issues `api.get<EngagementRate>("/ui/analytics/engagement", { period_days })`.
**The backend pre-computes the engagement rate** (`engagement_rate`,
`engagement_rate_bps`), the `trend` string, and `trend_delta`; the web client does
**no** math — it only formats (`(engagement_rate).toFixed(2)%`) and renders the
server-supplied breakdown counts (likes / comments / shares / **tips**),
`total_interactions`, `posts_in_period`, and `follower_count`. There is therefore
**no client-side engagement-rate formula** to port. This Android port should
mirror the web contract: fetch the server-computed values, format/round for
display, and render. A local recompute (interactions / follower_count × 100) MAY
be retained only as an optional non-authoritative reconciliation cross-check; it
must never override the server value. See §16 for the full audit.

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
  unreliable, ~20s timeouts). Relevant operation **[CORRECTED]**:
  `analytics_engagement_ui_analytics_engagement_get`
  (`GET /ui/analytics/engagement`) returning **`EngagementRateOut`** (a flat
  object — there is no `EngagementMetricsOut` schema in the spec). The
  separate `GET /ui/analytics/engagement/history`
  (`analytics_engagement_history_ui_analytics_engagement_history_get`) returns
  `EngagementTimeSeriesOut` (`{ items: EngagementTimeSeriesItem[] }`) and is the
  source of any time series; the engagement-rate endpoint itself returns **no
  `series` array**. History is out of scope for this card (owned by AND-252) but
  noted so the DTO surface is not invented.
- **Web reference:** `frontend/src/api/endpoints/engagementRate.ts` (call shape:
  single `period_days` query param, default 30; no formula — the rate is
  server-computed), `frontend/src/api/types.ts` (`EngagementRate` interface =
  exact field names) and `frontend/src/pages/analytics/EngagementRateSection.tsx`
  (render behavior: `engagement_rate.toFixed(2)%` headline, trend indicator from
  `trend`/`trend_delta`, likes/comments/shares/tips breakdown). The backend
  `/openapi.json` (`EngagementRateOut`) and `types.ts` agree field-for-field and
  are jointly authoritative. **[CORRECTED]** There is no client derivation
  formula to port and no `reach`-based denominator (see §16).

## 3. Functional Requirements

FR-1. **[CORRECTED]** Fetch the server-computed engagement summary for the
authenticated creator via a suspend Retrofit call to `GET /ui/analytics/engagement`,
accepting a **single** optional `period_days` query param (integer, default `30`;
the web period selector offers 7/14/30/60/90). There are **no**
`from_date`/`to_date`/`granularity`/`from_ts`/`to_ts` params on this endpoint
(those belong to the separate `/ui/analytics/engagement/history` endpoint, out of
scope). `period_days` is always sent (default 30); it is never null-omitted.

FR-2. **[CORRECTED]** The engagement rate is **computed server-side** and returned
as `engagement_rate` (a percentage, e.g. `9.83` = 9.83%) plus
`engagement_rate_bps` (basis points). There is **no client formula** in the web
reference. The Android client MUST surface the server `engagement_rate` verbatim;
it MUST NOT invent a `(likes+comments+shares+saves)/reach*100` formula — the
backend exposes no `reach`/`impressions`/`saves`/`views` fields on this endpoint
and the denominator is `follower_count`, not reach. An **optional** local
reconciliation cross-check (`total_interactions / follower_count * 100`) MAY be
retained for debug logging only and MUST NOT override the server value in the UI.

FR-3. **[CORRECTED]** Defensive/divide-by-zero safety: the server already returns
`engagement_rate: 0.0` by default, so a zero rate renders as `0.00%`. The optional
local reconciliation cross-check MUST be divide-by-zero safe — when
`follower_count == 0` the local value is `null` (no `NaN`/`Infinity`) and the
reconciliation is simply skipped; this never changes what the UI shows.

FR-4. **[CORRECTED]** The engagement rate MUST be formatted to **two decimal
places** to match the web reference (`engagement_rate.toFixed(2)` → `"9.83%"`).
Use `RoundingMode.HALF_UP` at scale 2 (the JS `toFixed` semantics are
round-half-away-from-zero, equivalent to HALF_UP for the non-negative values
here). The unrounded server value is retained on the domain model for any
downstream use.

FR-5. **[CORRECTED]** Expose the server-supplied breakdown for the period — the
counts the web renders: **likes, comments, shares, tips** (NOT `saves`),
`total_interactions`, `posts_in_period`, and `follower_count`. These are
server-provided integers rendered as localized counts; this endpoint returns **no
per-interaction sub-rates** (like/comment/share/save rate) and **no
average-interactions-per-post** field, so those derived ratios are dropped from
scope. If a per-post average is still desired it can be derived locally as
`total_interactions / posts_in_period` (divide-by-zero safe, null when
`posts_in_period == 0`) as a non-authoritative convenience only.

FR-6. **[CORRECTED]** Surface the **server-supplied** trend, not a locally
computed period-over-period delta. The endpoint returns `trend` (a lowercase
string: `"up"` / `"down"` / `"stable"`, or `""` when unknown) and `trend_delta`
(a percentage-point number; the web renders `Math.abs(trend_delta).toFixed(2)%`).
There is **no `previous` block** on the wire. Map `trend` to a `Trend` enum
(`UP`/`DOWN`/`FLAT`/`UNKNOWN`) and carry `trend_delta` through unchanged. The
client performs no delta arithmetic.

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

import com.testlogon.android.core.model.engagement.dto.EngagementRateDto
import retrofit2.http.GET
import retrofit2.http.Query

interface EngagementApi {

    // [CORRECTED] Endpoint takes a single `period_days` param (default 30).
    @GET("ui/analytics/engagement")
    suspend fun getEngagement(
        @Query("period_days") periodDays: Int = 30,
    ): EngagementRateDto
}
```

`period_days` is always serialized (it is non-null with a default). Operator/
impersonation params (`user_sub`, `X-IMPERSONATION-TOKEN`) and the legacy
`Authorization: Bearer` header used by the web client are deliberately not exposed
on the mobile interface; the session cookie identifies the principal.

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

**The formatter/mapper — [CORRECTED: no derivation formula to port]**
(`core-model/.../engagement/EngagementRate.kt`). Pure, no Android/IO deps. The
server is authoritative for the rate, the trend, and the delta; this object only
maps the flat DTO into the domain model, parses the `trend` string, formats the
rate, and (optionally) computes a non-authoritative reconciliation value:

```kotlin
package com.testlogon.android.core.model.engagement

import java.math.BigDecimal
import java.math.RoundingMode

object EngagementRate {

    /** Formats a percentage to two decimals (HALF_UP), matching web toFixed(2). */
    fun displayPercent(value: Double?): Double? =
        value?.let { BigDecimal(it).setScale(2, RoundingMode.HALF_UP).toDouble() }

    /**
     * Optional, NON-AUTHORITATIVE reconciliation cross-check only (debug logging).
     * Denominator is follower_count (NOT reach — that field does not exist here).
     * Null-safe: returns null when follower_count <= 0 (no NaN/Infinity).
     */
    fun reconcileRate(counts: InteractionCounts): Double? {
        if (counts.followerCount <= 0L) return null
        return counts.totalInteractions().toDouble() / counts.followerCount.toDouble() * 100.0
    }

    /** Maps the server "up"/"down"/"stable"/"" trend string to the enum. */
    fun trendOf(serverTrend: String): Trend = when (serverTrend.trim().lowercase()) {
        "up" -> Trend.UP
        "down" -> Trend.DOWN
        "stable", "flat" -> Trend.FLAT
        else -> Trend.UNKNOWN
    }

    /** Builds the display model from the server-computed aggregate. */
    fun compute(agg: EngagementAggregate): EngagementMetrics {
        val c = agg.counts
        return EngagementMetrics(
            engagementRate = agg.serverRate,                 // server-authoritative
            engagementRateDisplay = displayPercent(agg.serverRate),
            engagementRateBps = agg.serverRateBps,
            localReconcileRate = reconcileRate(c),           // debug cross-check only
            likes = c.likes, comments = c.comments,
            shares = c.shares, tips = c.tips,
            totalInteractions = c.totalInteractions,
            followerCount = c.followerCount,
            postsInPeriod = c.postsInPeriod,
            avgInteractionsPerPost =
                if (c.postsInPeriod > 0)
                    c.totalInteractions.toDouble() / c.postsInPeriod else null,
            trendDelta = agg.serverTrendDelta,               // server-supplied pp
            trendDeltaDisplay = displayPercent(agg.serverTrendDelta),
            trend = trendOf(agg.serverTrend),
        )
    }
}

enum class Trend { UP, DOWN, FLAT, UNKNOWN }
```

**Mapping layer** (`core-model/.../engagement/EngagementMappers.kt`): pure
extension `fun EngagementRateDto.toAggregate(): EngagementAggregate`, null-safe
with backend defaults (all counts default `0`, `engagement_rate`/`trend_delta`
default `0.0`, `trend` default `""`). `EngagementRateDto.toMetrics()` chains
`toAggregate()` → `EngagementRate.compute(...)`. There is **no `previous` block
and no `series` array** on this endpoint, so there are no nested/series mappers
here (the AND-251 series mapper applies to the separate `/history` endpoint owned
by AND-252).

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

**GET `/ui/analytics/engagement`** → `200 EngagementRateOut` **[CORRECTED schema]**

Query: `period_days` (integer, default `30`). This is the only param the endpoint
declares (verified against the OpenAPI index `params=period_days,user_sub,
X-SESSION-ID,X-IMPERSONATION-TOKEN`; the latter three are operator/transport
concerns not exposed to the mobile client). There are **no** date-range or
granularity params on this endpoint.

Exact `EngagementRateOut` body (every field, with OpenAPI defaults):

```json
{
  "engagement_rate": 9.83,
  "engagement_rate_bps": 983,
  "period_days": 30,
  "total_interactions": 1626,
  "follower_count": 18450,
  "posts_in_period": 42,
  "likes": 1320,
  "comments": 210,
  "shares": 96,
  "tips": 0,
  "trend": "up",
  "trend_delta": 1.17
}
```

Notes **[CORRECTED]**:
- The body is **flat** — no `window`, `currency`, `reach`, `impressions`,
  `saves`, `views`, `previous`, or `series`. Those were invented by the draft and
  do not exist on this endpoint.
- `engagement_rate` is a **percentage** (e.g. `9.83` = 9.83%) and is
  **server-computed**; `engagement_rate_bps` is the same value in basis points
  (integer). The denominator is `follower_count`, not reach.
- `trend` is a **lowercase string** (`"up"`/`"down"`/`"stable"`, default `""`);
  `trend_delta` is a server-supplied percentage-point delta (default `0.0`). The
  client does no delta math.
- Breakdown counts are `likes`, `comments`, `shares`, **`tips`** (integers,
  default `0`) — `saves`/`views` are absent.
- All numeric fields have server defaults (`0` / `0.0`), so a partial/empty `200`
  body decodes to an all-zero summary; `engagement_rate` is never `null` (it
  defaults to `0.0`).
- The separate `GET /ui/analytics/engagement/history` → `EngagementTimeSeriesOut`
  (`{ items: [{date, engagement_rate, engagement_rate_bps, interactions,
  post_count}] }`, params `from_date`/`to_date`) is the only source of a series;
  it is out of scope for this card (AND-252).

Error envelope (via AND-015): FastAPI `detail` is `string | [{msg}] | {code,...}`.
`401` triggers the shared `Authenticator` (one refresh + retry). `422` validation
bodies are mapped by AND-015 and surfaced as `EngagementUiState.Error`. This
ticket adds no error re-mapping.

## 6. Data & State Management

**DTOs** in `com.testlogon.android.core.model.engagement.dto` (Moshi codegen):

**[CORRECTED]** A single flat DTO mirrors `EngagementRateOut` exactly (counts are
`Int` per the OpenAPI `integer` type). There is no `previous`, `series`, or
`window` DTO, and no `EngagementSeriesPointDto`/`AnalyticsWindowDto` on this
endpoint:

```kotlin
@JsonClass(generateAdapter = true)
data class EngagementRateDto(
    @Json(name = "engagement_rate") val engagementRate: Double = 0.0,
    @Json(name = "engagement_rate_bps") val engagementRateBps: Int = 0,
    @Json(name = "period_days") val periodDays: Int = 0,
    @Json(name = "total_interactions") val totalInteractions: Int = 0,
    @Json(name = "follower_count") val followerCount: Int = 0,
    @Json(name = "posts_in_period") val postsInPeriod: Int = 0,
    val likes: Int = 0,
    val comments: Int = 0,
    val shares: Int = 0,
    val tips: Int = 0,
    val trend: String = "",
    @Json(name = "trend_delta") val trendDelta: Double = 0.0,
)
```

> If AND-252 later needs the history series, it owns a separate
> `EngagementTimeSeriesDto` (`items: List<EngagementTimeSeriesItemDto>`) for
> `/ui/analytics/engagement/history`; it is intentionally not declared here.

**Domain models** in `com.testlogon.android.core.model.engagement`:

**[CORRECTED]** Domain models match the real wire fields (counts are `Int`; the
total comes from the server but is kept consistent locally):

```kotlin
data class InteractionCounts(
    val likes: Int, val comments: Int, val shares: Int, val tips: Int,
    val totalInteractions: Int,   // server total_interactions
    val followerCount: Int,       // denominator for the (server) rate
    val postsInPeriod: Int,
)

data class EngagementAggregate(
    val counts: InteractionCounts,
    val serverRate: Double,          // backend engagement_rate (percentage)
    val serverRateBps: Int,          // engagement_rate_bps
    val serverTrend: String,         // "up"/"down"/"stable"/""
    val serverTrendDelta: Double,    // trend_delta (percentage points)
    val periodDays: Int,
)

data class EngagementMetrics(
    val engagementRate: Double?,            // server-authoritative (percentage)
    val engagementRateDisplay: Double?,     // HALF_UP to 2 dp, null-safe
    val engagementRateBps: Int,
    val localReconcileRate: Double?,        // debug cross-check only (nullable)
    val likes: Int, val comments: Int, val shares: Int, val tips: Int,
    val totalInteractions: Int,
    val followerCount: Int,
    val postsInPeriod: Int,
    val avgInteractionsPerPost: Double?,    // total/posts, null when posts == 0
    val trendDelta: Double?,                // server trend_delta (pp)
    val trendDeltaDisplay: Double?,         // 2 dp
    val trend: Trend,
)
```

> `EngagementSeriesPoint` is removed — this endpoint returns no series. The
> equivalent type for `/history` is owned by AND-252 if/when that card is built.

**UI state** (`feature-analytics/.../engagement/EngagementUiState.kt`):

```kotlin
sealed interface EngagementUiState {
    data object Loading : EngagementUiState
    data class Success(val metrics: EngagementMetrics, val isStale: Boolean = false) : EngagementUiState
    data object Empty : EngagementUiState                 // no followers AND no interactions
    data class Error(val message: String, val isStale: Boolean = false) : EngagementUiState
}
```

**[CORRECTED]** `EngagementMetrics.toUiState()` maps to `Empty` when
`followerCount == 0` **and** `totalInteractions == 0` (the closest analogue to the
draft's reach-based test), else `Success`. Models are immutable value objects.
No Room/DataStore writes in this ticket; any caching is owned by the E34 analytics
repository seam (mirrors AND-251→AND-252 split). No `series` is decoded here — the
endpoint returns none; the `/history` series is AND-252's concern.

## 7. Error Handling & Resilience

- The suspend `EngagementApi.getEngagement` is wrapped in the shared `apiCall { }`
  → `ApiResult<T>` (AND-018); transport failures, the ~20s OkHttp timeout, and
  HTTP error codes become `ApiResult.Failure` mapped through AND-015.
- The call is an **idempotent GET**, so bounded-backoff retry (AND-016) applies;
  this ticket adds nothing beyond honouring it.
- **[CORRECTED] Divide-by-zero / NaN safety** (FR-3) applies only to the optional
  local reconciliation cross-check: it is computed only when `followerCount > 0`
  (denominator is followers, not reach); otherwise it is `null`. The displayed rate
  is the server value, which defaults to `0.0` and is never `null`. A guard test
  asserts the reconciliation value is never `NaN`/`Infinity` for any non-negative
  count input.
- Moshi decoding is defensive: all fields have defaults (`0`/`0.0`/`""`), so a
  partial `200 {}` body decodes to an all-zero summary → `Empty` state rather than
  a crash. There is **no `previous` or `series`** to be empty-tolerant about.
- **[CORRECTED — removed]** No `series[i].date` parsing in this ticket: the
  engagement endpoint returns no series, so there are no weekly/monthly bucket
  labels to degrade. (Series date degradation belongs to AND-252's `/history`
  mapper.)
- **[CORRECTED]** Server/local divergence: if the optional `localReconcileRate`
  differs from `serverRate` by more than 0.5 pp, log a single non-PII debug line
  (counts redacted) and keep the **server** value in the UI; never block render on
  reconciliation. Divergence is expected and benign — the server denominator/window
  logic is the source of truth.
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
  attributes only — `period_days` (the window length; **[CORRECTED]** there is no
  `granularity` on this endpoint) and a coarse `has_data` boolean. Never log the
  rate value or any raw count.
- A single non-PII debug line on (a) decode failure (`EngagementApi: decode
  failed` — no body) and (b) server/local rate divergence > 0.5 pp (delta
  magnitude bucketed, no counts) is permitted to aid contract debugging.

## 11. Testing Strategy

**Calculator (pure JVM unit tests, `core-model`)** — the core of correctness:

**[CORRECTED — no client formula]**
- **T-1 Server rate surfaced:** `compute` over a known aggregate sets
  `engagementRate` to the **server** `engagement_rate` verbatim (e.g. `9.83`); no
  client recompute overrides it.
- **T-2 Rounding:** `engagementRateDisplay` is HALF_UP to **2 dp** matching web
  `toFixed(2)` (e.g. `9.834…`→`9.83`, `9.835`→`9.84`).
- **T-3 Reconciliation divide-by-zero:** `followerCount == 0` →
  `localReconcileRate == null`, no `NaN`/`Infinity`; display rate is still the
  server value; `toUiState()` → `Empty` when followers and interactions are both 0.
- **T-4 Reconciliation populated:** when `followerCount > 0`, `localReconcileRate`
  = `total_interactions / follower_count * 100` and is exposed for debug only; it
  never replaces `engagementRate`.
- **T-5 Trend mapping:** `trend` string `"up"`→`Trend.UP`, `"down"`→`Trend.DOWN`,
  `"stable"`/`"flat"`→`Trend.FLAT`, `""`/unknown→`Trend.UNKNOWN`; `trendDelta`
  carried through unchanged and formatted to 2 dp. No client delta arithmetic.
- **T-6 Per-post average:** `postsInPeriod > 0` → `total_interactions/postsInPeriod`;
  `postsInPeriod == 0` → `null`.
- **T-7 NaN/Infinity guard:** property/reflection test asserts no metric is
  `NaN`/`Infinity` across randomized non-negative inputs including zero followers
  and zero posts.

**API + mapping (`MockWebServer`, `core-network`/`core-model`, AND-046 fixtures):**

- **T-8 Path/verb/query:** enqueue 200; assert `GET /ui/analytics/engagement`,
  `period_days` present (default `30` when not overridden, custom value when
  passed). No date/granularity params on the wire.
- **T-9 Full mapping:** `engagement_full.json` (the §5 body) decodes; every field
  (`engagement_rate`, `engagement_rate_bps`, `total_interactions`,
  `follower_count`, `posts_in_period`, `likes`/`comments`/`shares`/`tips`,
  `trend`, `trend_delta`) maps to the correct domain field.
- **T-10 Defaults tolerance:** `engagement_empty.json` (`{}`/partial) decodes to
  all-zero/`""` summary → `Empty` (no crash, no missing-field exception).
- **T-11 Trend-string edge cases:** unexpected `trend` values (`"UP"`, `"rising"`,
  `null`-absent) map to `Trend.UNKNOWN` without throwing; `engagement_rate` absent
  → `0.0`.

**ViewModel (`core-testing`, coroutine test rule):**

- **T-12 State flow:** `load()` emits `Loading` → `Success`; `ApiResult.Failure`
  → `Error`; all-zero (no followers/interactions) payload → `Empty`; `retry()`
  re-issues the call.

**Compose UI tests (`feature-analytics`, AND-048 harness) — proves acceptance:**

- **T-13 Render success:** given a `Success` state, the headline rate text, the
  trend chip, and the **likes/comments/shares/tips** breakdown rows are displayed
  (`assertIsDisplayed`) — **"Engagement metrics render."** (web renders tips, not
  saves.)
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

- **[RESOLVED] Denominator definition.** The rate is **server-computed**; the
  client does not pick a denominator. The implicit server denominator is
  `follower_count` (the only ratio base on the wire). Verified against
  `EngagementRateOut` and `types.ts: EngagementRate` — there is no
  `reach`/`impressions`/`views` field. The optional local reconciliation uses
  `follower_count`. No open question remains.
- **[RESOLVED] Endpoint path/shape.** Verified: `GET /ui/analytics/engagement` →
  `EngagementRateOut` (op `analytics_engagement_ui_analytics_engagement_get`),
  single `period_days` param. There is no `EngagementMetricsOut` schema. The
  earlier guess of `/ui/earnings/engagement` or a combined summary is wrong.
- **[RESOLVED] `previous`/delta.** There is **no `previous` block** on the wire.
  The trend is fully server-supplied (`trend` string + `trend_delta`). The client
  performs no delta arithmetic. A second windowed call is unnecessary.
- **[RESOLVED] Rounding parity.** The web uses `engagement_rate.toFixed(2)` →
  **2 decimal places** (not 1). Spec corrected to 2 dp HALF_UP (matches
  `toFixed` for the non-negative values in play).
- **[OPEN] Series source for charts.** A trend chart exists on web but is fed by
  the **separate** `/ui/analytics/engagement/history` (`EngagementTimeSeriesOut`),
  not this endpoint. This card decodes/renders only the summary; the history series
  is deferred to AND-252. Confirm with AND-252 which ticket owns the history call.
- **[OPEN] `trend` string vocabulary.** Verified values from the web are
  `"up"`/`"down"`/`"stable"` (and empty default), but the OpenAPI types it as a
  free `string` with default `""`. Mapping treats any unrecognized value as
  `Trend.UNKNOWN`; a backend that emits other tokens would silently fall through —
  worth a contract confirmation.
- **Empty vs. error ambiguity** on the unreliable dev host: a partial/empty `200`
  maps to `Empty` (all-zero), which is acceptable but indistinguishable from a
  genuine zero-engagement window — surfaced as "No engagement data."

## 14. Acceptance Criteria

1. **[CORRECTED]** `EngagementApi.getEngagement` exists in `core-network` at the
   exact path `ui/analytics/engagement`, GET verb, with a single `period_days`
   query param (default `30`); the param appears on the wire request (proved by
   `MockWebServer` `RecordedRequest`).
2. All DTOs and domain models in §5–§6 exist in `core-model` with Moshi codegen
   (`EngagementRateDto` matching `EngagementRateOut` exactly); the module compiles
   with no hand-written adapters.
3. **[CORRECTED]** `EngagementRate.compute` surfaces the **server** `engagement_rate`
   verbatim, rounds the display value HALF_UP to **2 dp** (web `toFixed(2)` parity),
   maps the `trend` string to the `Trend` enum, and the optional reconciliation is
   divide-by-zero/NaN-safe (T-1…T-7 pass).
4. **[CORRECTED]** The server-supplied breakdown (likes/comments/shares/**tips**,
   `total_interactions`, `follower_count`, `posts_in_period`), the locally derived
   avg-interactions-per-post, and the server `trend`/`trend_delta` are mapped
   exactly as specified. (No client-computed per-interaction sub-rates or delta —
   those fields do not exist on the wire.)
5. `EngagementViewModel` exposes `StateFlow<EngagementUiState>` emitting
   `Loading → Success/Empty/Error`, with `retry()` and an `isStale` flag (T-12).
6. `EngagementRateCard` **renders the engagement metrics** in the
   dashboard — headline rate, trend chip, and the likes/comments/shares/tips
   breakdown — and renders the loading/empty/error/offline states; "—" is shown
   when the rate is unavailable (T-13/T-14). This satisfies the backlog acceptance
   "Engagement metrics render."
7. Percentages/numbers are locale-formatted; no hard-coded `%`/decimal in the data
   layer; the headline exposes a merged a11y description (T-15).
8. No engagement counts or rates appear in any log output (manual review against
   §10).
9. The full test suite (§11, T-1…T-15) passes in CI (AND-050 unit, AND-051
   instrumented).

## 15. Definition of Done

- Code merged to `android-port`: `EngagementApi`, `EngagementNetworkModule`,
  engagement DTO (`EngagementRateDto`), domain models (`InteractionCounts`,
  `EngagementAggregate`, `EngagementMetrics`, `Trend`) — **[CORRECTED]** no
  `EngagementSeriesPoint` (this endpoint returns no series), `EngagementRate`
  mapper/formatter, `EngagementMappers`, `EngagementUiState`, `EngagementViewModel`,
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
  (history series ownership, `trend` vocabulary) for confirmation against
  `/openapi.json` and the web reference before/at code review.

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and an exact source pointer.

1. **Endpoint path is `GET /ui/analytics/engagement`.** VERIFIED.
   Source: OpenAPI `GET /ui/analytics/engagement`
   (op `analytics_engagement_ui_analytics_engagement_get`); frontend
   `src/api/endpoints/engagementRate.ts: getEngagementRate`
   (`api.get("/ui/analytics/engagement", …)`).
2. **HTTP verb is GET.** VERIFIED. Source: OpenAPI index line for the op;
   `engagementRate.ts: getEngagementRate` uses `api.get`.
3. **Response schema is `EngagementRateOut` (not `EngagementMetricsOut`).**
   CORRECTED. Source: OpenAPI `resp=200:EngagementRateOut`;
   `components.schemas.EngagementRateOut`; frontend `src/api/types.ts: EngagementRate`.
   The draft's `EngagementMetricsOut` does not exist in the spec.
4. **Query param is a single `period_days` (int, default 30), no
   `from_date`/`to_date`/`granularity`/`from_ts`/`to_ts`.** CORRECTED.
   Source: OpenAPI index `params=period_days,user_sub,X-SESSION-ID,
   X-IMPERSONATION-TOKEN`; `engagementRate.ts: getEngagementRate(periodDays = 30)`
   sends `{ period_days }`; period selector `[7,14,30,60,90]` in
   `src/pages/analytics/EngagementRateSection.tsx`.
5. **Response body is flat — no `window`/`currency`/`reach`/`impressions`/`saves`/
   `views`/`previous`/`series`.** CORRECTED. Source:
   `components.schemas.EngagementRateOut` (full property list); `types.ts:
   EngagementRate`. None of those fields are present.
6. **Engagement rate is server-computed, returned as `engagement_rate`
   (percentage) + `engagement_rate_bps` (int).** VERIFIED/CORRECTED. Source:
   `EngagementRateOut.engagement_rate` (number, default 0.0) and
   `engagement_rate_bps` (integer); web renders `(data.engagement_rate).toFixed(2)%`
   in `EngagementRateSection.tsx` (no client formula). The draft's
   `(likes+comments+shares+saves)/reach*100` client formula is removed.
7. **Denominator is `follower_count`, not `reach`.** CORRECTED. Source:
   `EngagementRateOut.follower_count`; no `reach` field exists. (The exact server
   formula is not exposed; `follower_count` is the only ratio base on the wire —
   see Open assumptions.)
8. **Breakdown counts are likes/comments/shares/`tips` (not `saves`).** CORRECTED.
   Source: `EngagementRateOut` props `likes`,`comments`,`shares`,`tips`;
   `EngagementRateSection.tsx` `BreakdownStat` rows render Likes/Comments/Shares/Tips.
9. **`trend` is a lowercase string (`up`/`down`/`stable`/`""`) and `trend_delta`
   is server-supplied (pp); there is no client delta math or `previous` block.**
   CORRECTED. Source: `EngagementRateOut.trend` (string, default `""`),
   `trend_delta` (number); `EngagementRateSection.tsx: TrendIndicator` switches on
   `trend === "up"/"down"` else "stable" and renders
   `Math.abs(delta).toFixed(2)%`.
10. **Display rounding is 2 dp (HALF_UP), not 1 dp.** CORRECTED. Source:
    `EngagementRateSection.tsx` `(data?.engagement_rate ?? 0).toFixed(2)` and
    `Math.abs(delta).toFixed(2)`.
11. **Counts are integers (`Int`), not `Long`.** CORRECTED. Source:
    `EngagementRateOut` props typed `"type": "integer"`; `types.ts: EngagementRate`
    fields typed `number`.
12. **All fields have server defaults; partial/empty `200` decodes safely;
    `engagement_rate` is never null (defaults `0.0`).** VERIFIED. Source:
    `EngagementRateOut` per-property `default` values; web uses `?? 0` fallbacks.
13. **Auth is session cookie + `X-CSRF-Token` header.** VERIFIED. Source:
    `src/api/client.ts` — `credentials: "include"` (lines 124/183/220),
    `X-CSRF-Token` from `ui_csrf` cookie (lines 167–171). Note the web client also
    attaches `Authorization: Bearer` from an auth store (client.ts 156–160); the
    Android port intentionally relies on the cookie jar (cross-cutting AND-011/012).
14. **401 triggers a single session refresh + one retry.** VERIFIED. Source:
    `src/api/client.ts` 191–221 (refresh-once guarded by `refreshPromise`, then one
    retry). Matches the spec's AND-013 Authenticator behavior.
15. **422 validation error envelope is `{ detail: ValidationError[] }`.** VERIFIED.
    Source: OpenAPI `resp=…;422:HTTPValidationError`;
    `components.schemas.HTTPValidationError.detail` → array of
    `#/components/schemas/ValidationError`. The spec's AND-015 mapping handles this.
16. **A separate history endpoint exists for the series.** VERIFIED. Source:
    OpenAPI `GET /ui/analytics/engagement/history` → `EngagementTimeSeriesOut`
    (`{ items: EngagementTimeSeriesItem[] }`, params `from_date`,`to_date`);
    `engagementRate.ts: getEngagementHistory`; rendered as the trend chart in
    `EngagementRateSection.tsx`. Out of scope for this card.
17. **A public-toggle endpoint exists.** VERIFIED (context only, out of scope).
    Source: OpenAPI `PUT /ui/analytics/engagement/public`
    (`req=EngagementPublicToggleIn`, `resp=EngagementPublicOut`);
    `engagementRate.ts: setEngagementPublic`. The web section has a public toggle;
    this Android card does not implement it (acceptance is render-only).
18. **Compose / Material 3 / Hilt / Retrofit transport choices.** UNVERIFIED-
    assumption (framework ref). These are project-stack pins (§2), not derivable
    from backend/frontend sources. Android refs: Compose
    https://developer.android.com/jetpack/compose ; ViewModel + StateFlow
    https://developer.android.com/topic/libraries/architecture/viewmodel ;
    Retrofit https://square.github.io/retrofit/ ;
    `NumberFormat` https://developer.android.com/reference/java/text/NumberFormat .

### Corrections made

- **Schema name:** `EngagementMetricsOut` → `EngagementRateOut` (does not exist as
  drafted). DTO renamed `EngagementMetricsDto` → `EngagementRateDto`.
- **Query params:** removed `from_date`/`to_date`/`granularity`/`from_ts`/`to_ts`;
  replaced with the single `period_days` (default 30).
- **Response shape:** removed invented nested `window`/`currency`/`reach`/
  `impressions`/`saves`/`views`/`previous`/`series`; replaced §5 JSON with the real
  flat `EngagementRateOut` body.
- **Formula:** removed the client `(likes+comments+shares+saves)/reach*100`
  derivation — the rate is server-computed. Denominator corrected reach →
  `follower_count`. Local recompute demoted to an optional debug reconciliation.
- **Breakdown field:** `saves` → `tips`; dropped `views`. Removed per-interaction
  sub-rates (no such fields on the wire).
- **Trend/delta:** removed `previous`-block delta arithmetic; trend now mapped from
  the server `trend` string and `trend_delta`.
- **Rounding:** 1 dp HALF_UP → 2 dp HALF_UP (web `toFixed(2)`).
- **Types:** count fields `Long` → `Int`.
- **Domain model:** removed `EngagementSeriesPoint`; reworked `InteractionCounts`/
  `EngagementAggregate`/`EngagementMetrics` to the real fields.
- **Tests/AC/DoD/telemetry/§13** updated to the corrected contract throughout
  (notably T-1/T-2/T-3/T-5/T-9/T-11, AC-1/3/4, telemetry `granularity`→`period_days`).

### Open assumptions

- **Exact server rate formula/denominator.** The backend pre-computes
  `engagement_rate`; the precise inputs are not exposed in the OpenAPI schema. We
  treat `follower_count` as the denominator for the optional reconciliation because
  it is the only ratio base present, but the server may use a different/rolling base.
  Unverifiable from the available sources — backend code would be required.
- **`trend` token vocabulary.** OpenAPI types `trend` as a free `string` (default
  `""`); only `up`/`down`/`stable` are observed in the web. Any other token maps to
  `Trend.UNKNOWN`. Cannot be exhaustively verified from the schema.
- **`isStale`/offline last-known cache.** No frontend equivalent exists (web uses
  react-query `staleTime`, not an offline store). The Android stale behavior relies
  on the E34 cache seam (AND-251→AND-252) which is not yet implemented; treated as
  a cross-ticket assumption.
- **`engagement_metrics_viewed` analytics event.** No backend/frontend source —
  internal telemetry convention (AND-052). Assumption.

## 17. Test Plan

Acceptance-criteria references (AC-#) point to §14. Test targets: **JVM**
(local JVM/Robolectric unit), **emu35** (headless AVD `test35`, API 35 x86_64),
**device** (physical Samsung Galaxy A15 5G, SM-A156U, API 34, arm64-v8a). This is
a non-hardware analytics UI feature, so most cases run on JVM/emulator; the
physical device is used only to validate real-device rendering/a11y/locale at
API 34 arm64 (vs. the API 35 x86 emulator).

- **TC-AND-254-01** — Type: contract/MockWebServer. Target: JVM (MockWebServer).
  Preconditions: `EngagementApi` wired to MockWebServer; enqueue `200`
  `engagement_full.json` (§5 body). Steps: call `getEngagement()` with no arg, then
  with `periodDays = 90`; capture `RecordedRequest`. Expected: path is
  `/ui/analytics/engagement`, method `GET`; query is `period_days=30` (default) then
  `period_days=90`; no `from_date`/`to_date`/`granularity` keys present.
  Traces: AC-1.
- **TC-AND-254-02** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  enqueue `200` `engagement_full.json`. Steps: decode to `EngagementRateDto`,
  map `toMetrics()`. Expected: `engagementRate==9.83`, `engagementRateBps==983`,
  `totalInteractions==1626`, `followerCount==18450`, `postsInPeriod==42`,
  `likes==1320`, `comments==210`, `shares==96`, `tips==0`, `trend==Trend.UP`,
  `trendDelta==1.17`. Traces: AC-2, AC-4.
- **TC-AND-254-03** — Type: unit. Target: JVM. Preconditions: aggregate with
  server `engagement_rate=9.834`. Steps: `compute(...)`. Expected: `engagementRate`
  is the server value verbatim (`9.834`); `engagementRateDisplay==9.83`
  (HALF_UP, 2 dp); a `9.835` input rounds to `9.84`. Traces: AC-3.
- **TC-AND-254-04** — Type: unit. Target: JVM. Preconditions: counts with
  `followerCount==0`, `totalInteractions==0`, server `engagement_rate=0.0`.
  Steps: `compute(...)` then `toUiState()`. Expected: `localReconcileRate==null`
  (no `NaN`/`Infinity`), displayed rate is the server `0.0`, `toUiState()==Empty`.
  Traces: AC-3, AC-5.
- **TC-AND-254-05** — Type: unit. Target: JVM. Preconditions: `followerCount=18450`,
  `totalInteractions=1626`. Steps: `compute(...)`. Expected: `localReconcileRate`
  ≈ `1626/18450*100 = 8.81…` and is exposed only as the reconciliation value; it
  does NOT replace `engagementRate`. Traces: AC-3, AC-4.
- **TC-AND-254-06** — Type: unit. Target: JVM. Preconditions: vary `trend` string.
  Steps: map `"up"`,`"down"`,`"stable"`,`""`,`"rising"`,`"UP"`. Expected:
  `UP`,`DOWN`,`FLAT`,`UNKNOWN`,`UNKNOWN`,`UNKNOWN` respectively; `trendDelta`
  carried through and formatted to 2 dp. Traces: AC-4.
- **TC-AND-254-07** — Type: unit. Target: JVM. Preconditions: (a) `postsInPeriod=42`,
  `totalInteractions=1626`; (b) `postsInPeriod=0`. Steps: read
  `avgInteractionsPerPost`. Expected: (a) `≈38.71`; (b) `null` (divide-by-zero
  safe). Traces: AC-4.
- **TC-AND-254-08** — Type: unit (property). Target: JVM. Preconditions: randomized
  non-negative `Int` counts incl. zero followers and zero posts. Steps: `compute`
  over N cases; reflect over all `Double` fields. Expected: no field is `NaN` or
  `Infinity`. Traces: AC-3.
- **TC-AND-254-09** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  enqueue `200 {}` (`engagement_empty.json`). Steps: decode + map + `toUiState()`.
  Expected: all fields default (`0`/`0.0`/`""`), no decode exception,
  `engagementRate==0.0` (not null), `toUiState()==Empty`. Traces: AC-2, AC-5.
- **TC-AND-254-10** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  enqueue `401` then a successful `200` on the refreshed retry (or assert mapping
  if refresh is owned by the shared Authenticator). Steps: call `getEngagement()`.
  Expected: a single refresh + one retry occurs and `Success` is produced; a
  persistent `401` surfaces `EngagementUiState.Error`. (Security/session case.)
  Traces: AC-5. Note: validates the cross-cutting AND-013 path is honoured, not
  re-implemented here.
- **TC-AND-254-11** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  enqueue `422` with `{"detail":[{"loc":["query","period_days"],"msg":"...",
  "type":"int_parsing"}]}`. Steps: call `getEngagement()`. Expected: mapped via
  AND-015 to `ApiResult.Failure` → `EngagementUiState.Error(message)`; no crash.
  Traces: AC-5.
- **TC-AND-254-12** — Type: integration (offline/flaky-host). Target: JVM
  (MockWebServer with `SocketPolicy.NO_RESPONSE`/disconnect, ~20s timeout).
  Steps: trigger `load()` against a non-responding host; if the repo serves a
  last-known value, assert `Success(isStale=true)`; otherwise assert
  `Error`. Expected: timeout becomes `Failure`→`Error`, or stale `Success` with the
  stale banner flagged. Traces: AC-5. (Maps the unreliable dev-host §7 path.)
- **TC-AND-254-13** — Type: Compose-UI. Target: emu35 (fast CI). Preconditions:
  `EngagementRateCard` hosted with a `Success` state (rate 9.83, trend UP,
  likes/comments/shares/tips). Steps: render; query nodes. Expected: headline
  `9.83%`, trend chip with up-arrow + `1.17%` (not colour-only), and the four
  breakdown rows (Likes/Comments/Shares/Tips) `assertIsDisplayed`. This proves
  "Engagement metrics render." Traces: AC-6.
- **TC-AND-254-14** — Type: Compose-UI. Target: emu35. Preconditions: drive the
  card through `Loading`, `Empty`, `Error`, and stale `Success`. Steps: render each;
  click Retry in `Error`. Expected: shimmer/spinner for `Loading`; "No engagement
  data" for `Empty`; error text + Retry that invokes `onRetry`; stale banner when
  `isStale`; "—" shown where a value is unavailable. Traces: AC-6.
- **TC-AND-254-15** — Type: instrumented/accessibility. Target: **device** (must
  run on the physical A15 — validates real TalkBack semantics and large-font /
  locale rendering at API 34 arm64, complementing the API 35 x86 emulator). Steps:
  enable TalkBack-style semantics check; inspect the headline node; set system
  font scale to max and a non-`.`-decimal locale (e.g. de-DE). Expected: headline
  exposes a single merged `contentDescription` (e.g. "Engagement rate 9.83 percent,
  up 1.17 points"); number formatted per locale (comma decimal); headline does not
  truncate at max font scale; touch targets ≥ 48dp. Traces: AC-7.
- **TC-AND-254-16** — Type: manual (log review). Target: device or emu35.
  Preconditions: debug build, OkHttp logging at `BASIC`. Steps: load the card,
  inspect logcat + analytics events. Expected: no `engagement_rate`/count values in
  any log line; the only permitted event is `engagement_metrics_viewed` with
  `period_days` + `has_data` only. Traces: AC-8.

### Coverage matrix

| AC (§14) | Covered by |
|---|---|
| AC-1 (path/verb/`period_days` param) | TC-01 |
| AC-2 (DTOs/domain models, Moshi codegen) | TC-02, TC-09 |
| AC-3 (server rate verbatim, 2 dp HALF_UP, divide-by-zero/NaN-safe) | TC-03, TC-04, TC-05, TC-08 |
| AC-4 (breakdown, avg/post, trend mapping) | TC-02, TC-05, TC-06, TC-07 |
| AC-5 (ViewModel states + retry + isStale, errors) | TC-04, TC-09, TC-10, TC-11, TC-12 |
| AC-6 (card renders metrics + non-success states) | TC-13, TC-14 |
| AC-7 (locale formatting + merged a11y description) | TC-15 |
| AC-8 (no counts/rates in logs) | TC-16 |
| AC-9 (full suite green in CI) | TC-01…TC-16 (CI run) |
