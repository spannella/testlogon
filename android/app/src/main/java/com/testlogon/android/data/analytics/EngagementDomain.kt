package com.testlogon.android.data.analytics

import com.testlogon.android.data.earnings.toEpochDayOrNull
import java.math.BigDecimal
import java.math.RoundingMode

/**
 * AND-254 — framework-free engagement domain models, the PURE [EngagementRate] calculator/formatter,
 * and total DTO -> domain mappers. NO Compose / android / java.time imports (java.math.BigDecimal is
 * JVM-safe and API-level-safe).
 *
 * The engagement RATE is server-authoritative: [EngagementRate.compute] surfaces engagement_rate
 * verbatim and only formats it (HALF_UP, 2 dp, to match the web `toFixed(2)`), maps the server trend
 * string to the [Trend] enum, carries trend_delta through unchanged, and derives a NON-authoritative
 * reconciliation cross-check + a per-post average (both divide-by-zero safe). It never invents a
 * client rate formula.
 */

/** Server trend direction; any unrecognized wire token -> [UNKNOWN]. */
enum class Trend { UP, DOWN, FLAT, UNKNOWN }

/** Server-supplied interaction counts for the period. */
data class InteractionCounts(
    val likes: Int,
    val comments: Int,
    val shares: Int,
    val tips: Int,
    val totalInteractions: Int, // server total_interactions
    val followerCount: Int,     // denominator for the (server) rate
    val postsInPeriod: Int,
)

/** The decoded server aggregate before formatting. */
data class EngagementAggregate(
    val counts: InteractionCounts,
    val serverRate: Double,       // backend engagement_rate (percentage)
    val serverRateBps: Int,       // engagement_rate_bps
    val serverTrend: String,      // "up"/"down"/"stable"/""
    val serverTrendDelta: Double, // trend_delta (percentage points)
    val periodDays: Int,
)

/** The render-ready engagement metrics for the card. */
data class EngagementMetrics(
    val engagementRate: Double?,            // server-authoritative (percentage)
    val engagementRateDisplay: Double?,     // HALF_UP to 2 dp, null-safe
    val engagementRateBps: Int,
    val localReconcileRate: Double?,        // debug cross-check only (nullable)
    val likes: Int,
    val comments: Int,
    val shares: Int,
    val tips: Int,
    val totalInteractions: Int,
    val followerCount: Int,
    val postsInPeriod: Int,
    val avgInteractionsPerPost: Double?,    // total/posts, null when posts == 0
    val trendDelta: Double?,                // server trend_delta (pp)
    val trendDeltaDisplay: Double?,         // 2 dp
    val trend: Trend,
    val periodDays: Int,
)

/** One point of the engagement-rate trend (from /history). [dateEpochDay] is null for non-ISO labels. */
data class EngagementTrendPoint(
    val rawDate: String,
    val dateEpochDay: Long?,
    val engagementRate: Double,
    val engagementRateBps: Int,
    val interactions: Int,
    val postCount: Int,
)

/** The combined engagement surface: the metrics card + the trend series for the chart. */
data class Engagement(
    val metrics: EngagementMetrics,
    val trend: List<EngagementTrendPoint>,
) {
    /** No followers AND no interactions -> the "no engagement data" empty state. */
    val isEmpty: Boolean
        get() = metrics.followerCount == 0 && metrics.totalInteractions == 0
}

/** Pure calculator / formatter — the port of engagementRate.ts (the rate is server-computed). */
object EngagementRate {

    /** Formats a percentage to two decimals (HALF_UP), matching the web `toFixed(2)`. */
    fun displayPercent(value: Double?): Double? =
        value?.let { BigDecimal(it).setScale(2, RoundingMode.HALF_UP).toDouble() }

    /**
     * Optional, NON-AUTHORITATIVE reconciliation cross-check only (debug logging). Denominator is
     * follower_count (NOT reach — that field does not exist here). Null-safe: returns null when
     * follower_count <= 0 (no NaN/Infinity), so display never depends on it.
     */
    fun reconcileRate(counts: InteractionCounts): Double? {
        if (counts.followerCount <= 0) return null
        return counts.totalInteractions.toDouble() / counts.followerCount.toDouble() * 100.0
    }

    /** Maps the server "up"/"down"/"stable"/"" trend string to the [Trend] enum. */
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
            engagementRate = agg.serverRate,
            engagementRateDisplay = displayPercent(agg.serverRate),
            engagementRateBps = agg.serverRateBps,
            localReconcileRate = reconcileRate(c),
            likes = c.likes,
            comments = c.comments,
            shares = c.shares,
            tips = c.tips,
            totalInteractions = c.totalInteractions,
            followerCount = c.followerCount,
            postsInPeriod = c.postsInPeriod,
            avgInteractionsPerPost =
                if (c.postsInPeriod > 0) c.totalInteractions.toDouble() / c.postsInPeriod else null,
            trendDelta = agg.serverTrendDelta,
            trendDeltaDisplay = displayPercent(agg.serverTrendDelta),
            trend = trendOf(agg.serverTrend),
            periodDays = agg.periodDays,
        )
    }
}

// ---- Mappers (DTO -> domain). TOTAL: absent optionals default per the backend schema. ----

internal fun EngagementRateDto.toAggregate(): EngagementAggregate = EngagementAggregate(
    counts = InteractionCounts(
        likes = likes,
        comments = comments,
        shares = shares,
        tips = tips,
        totalInteractions = totalInteractions,
        followerCount = followerCount,
        postsInPeriod = postsInPeriod,
    ),
    serverRate = engagementRate,
    serverRateBps = engagementRateBps,
    serverTrend = trend,
    serverTrendDelta = trendDelta,
    periodDays = periodDays,
)

internal fun EngagementRateDto.toMetrics(): EngagementMetrics =
    EngagementRate.compute(toAggregate())

internal fun EngagementTimeSeriesItemDto.toDomain(): EngagementTrendPoint = EngagementTrendPoint(
    rawDate = date,
    dateEpochDay = date.toEpochDayOrNull(),
    engagementRate = engagementRate,
    engagementRateBps = engagementRateBps,
    interactions = interactions,
    postCount = postCount,
)

internal fun EngagementTimeSeriesDto.toDomain(): List<EngagementTrendPoint> =
    items.map { it.toDomain() }
