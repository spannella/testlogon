package com.testlogon.android.data.analytics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-254 / AND-257 — pure tests for the [EngagementRate] calculator (T-1..T-7): server rate surfaced
 * verbatim, HALF_UP 2dp rounding, divide-by-zero/NaN-safe reconciliation + per-post average, trend
 * string mapping, and a NaN/Infinity guard over randomized non-negative inputs.
 */
class EngagementRateTest {

    private fun counts(
        likes: Int = 0,
        comments: Int = 0,
        shares: Int = 0,
        tips: Int = 0,
        total: Int = 0,
        followers: Int = 0,
        posts: Int = 0,
    ) = InteractionCounts(likes, comments, shares, tips, total, followers, posts)

    private fun agg(
        rate: Double = 0.0,
        bps: Int = 0,
        trend: String = "",
        delta: Double = 0.0,
        counts: InteractionCounts = counts(),
        period: Int = 30,
    ) = EngagementAggregate(counts, rate, bps, trend, delta, period)

    @Test
    fun serverRate_isSurfacedVerbatim_noClientRecompute() {
        val m = EngagementRate.compute(
            agg(rate = 9.834, bps = 983, counts = counts(total = 1626, followers = 18450)),
        )
        // server value verbatim, NOT the reconciliation (which would be ~8.81).
        assertEquals(9.834, m.engagementRate!!, 1e-9)
    }

    @Test
    fun displayRate_roundsHalfUpTo2dp() {
        assertEquals(9.83, EngagementRate.displayPercent(9.834)!!, 1e-9)
        assertEquals(9.84, EngagementRate.displayPercent(9.835)!!, 1e-9)
        assertNull(EngagementRate.displayPercent(null))
    }

    @Test
    fun reconcileRate_nullWhenNoFollowers_displayStillServerValue() {
        val m = EngagementRate.compute(agg(rate = 0.0, counts = counts(total = 0, followers = 0)))
        assertNull(m.localReconcileRate)
        assertEquals(0.0, m.engagementRate!!, 1e-9)
    }

    @Test
    fun reconcileRate_populatedWhenFollowers_butDoesNotReplaceServerRate() {
        val m = EngagementRate.compute(
            agg(rate = 9.83, counts = counts(total = 1626, followers = 18450)),
        )
        assertEquals(8.81, m.localReconcileRate!!, 0.01)
        assertEquals(9.83, m.engagementRate!!, 1e-9) // unchanged
    }

    @Test
    fun trend_stringMapsToEnum_andDeltaCarriedThrough() {
        assertEquals(Trend.UP, EngagementRate.trendOf("up"))
        assertEquals(Trend.DOWN, EngagementRate.trendOf("down"))
        assertEquals(Trend.FLAT, EngagementRate.trendOf("stable"))
        assertEquals(Trend.FLAT, EngagementRate.trendOf("flat"))
        assertEquals(Trend.UNKNOWN, EngagementRate.trendOf(""))
        assertEquals(Trend.UNKNOWN, EngagementRate.trendOf("rising"))
        assertEquals(Trend.UP, EngagementRate.trendOf("UP"))
        val m = EngagementRate.compute(agg(trend = "up", delta = 1.17))
        assertEquals(Trend.UP, m.trend)
        assertEquals(1.17, m.trendDelta!!, 1e-9)
        assertEquals(1.17, m.trendDeltaDisplay!!, 1e-9)
    }

    @Test
    fun avgInteractionsPerPost_dividesOrNull() {
        val withPosts = EngagementRate.compute(agg(counts = counts(total = 1626, posts = 42)))
        assertEquals(1626.0 / 42.0, withPosts.avgInteractionsPerPost!!, 1e-9)
        val noPosts = EngagementRate.compute(agg(counts = counts(total = 5, posts = 0)))
        assertNull(noPosts.avgInteractionsPerPost)
    }

    @Test
    fun noMetricIsNaNorInfinity_acrossRandomNonNegativeInputs() {
        val rnd = java.util.Random(42)
        repeat(500) {
            val m = EngagementRate.compute(
                agg(
                    rate = rnd.nextInt(10_000) / 100.0,
                    counts = counts(
                        total = rnd.nextInt(100_000),
                        followers = if (rnd.nextBoolean()) 0 else rnd.nextInt(1_000_000),
                        posts = if (rnd.nextBoolean()) 0 else rnd.nextInt(1_000),
                    ),
                ),
            )
            listOfNotNull(
                m.engagementRate,
                m.engagementRateDisplay,
                m.localReconcileRate,
                m.avgInteractionsPerPost,
                m.trendDelta,
                m.trendDeltaDisplay,
            ).forEach { v ->
                assertFalse("NaN", v.isNaN())
                assertFalse("Inf", v.isInfinite())
            }
        }
    }

    @Test
    fun toAggregate_thenCompute_mapsAllCounts() {
        val dto = EngagementRateDto(
            engagementRate = 9.83, engagementRateBps = 983, periodDays = 30,
            totalInteractions = 1626, followerCount = 18450, postsInPeriod = 42,
            likes = 1320, comments = 210, shares = 96, tips = 0, trend = "up", trendDelta = 1.17,
        )
        val m = dto.toMetrics()
        assertEquals(1320, m.likes)
        assertEquals(210, m.comments)
        assertEquals(96, m.shares)
        assertEquals(0, m.tips)
        assertEquals(1626, m.totalInteractions)
        assertEquals(18450, m.followerCount)
        assertEquals(42, m.postsInPeriod)
        assertEquals(983, m.engagementRateBps)
        assertEquals(30, m.periodDays)
    }

    @Test
    fun engagementIsEmpty_whenNoFollowersAndNoInteractions() {
        val empty = Engagement(EngagementRateDto().toMetrics(), emptyList())
        assertTrue(empty.isEmpty)
        val nonEmpty = Engagement(EngagementRateDto(followerCount = 10).toMetrics(), emptyList())
        assertFalse(nonEmpty.isEmpty)
    }
}
