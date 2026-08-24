package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.TradingRewards

/**
 * Pure, dependency-free (Android/Compose/Hilt-free) math for the TRADING-REWARDS card on the Rewards
 * surface. Trading earns reward POINTS by executed volume; points accrue SERVER-SIDE, so the client
 * only shows the earn RATE + an ESTIMATE of points from the caller's own 30-day trading volume, and
 * swaps to the AUTHORITATIVE numbers when GET me/rewards/trading ships.
 *
 * CONVENTIONS: money is INTEGER USD CENTS; points are WHOLE integers. This is an EXACT mirror of the
 * web client's frontend/src/lib/tradingRewards.ts (same [POINTS_PER_DOLLAR], same floor-to-whole-points
 * rule, same authoritative-preferred resolution) — do NOT change the rate here without changing both.
 * Trivially unit-testable (see TradingRewardsMathTest).
 */
object TradingRewardsMath {

    /** Canonical earn rate: reward points granted per whole US dollar of executed volume. */
    const val POINTS_PER_DOLLAR: Long = 1L

    /** Where the trading-rewards numbers came from. */
    enum class Source { AUTHORITATIVE, ESTIMATED }

    /** Resolved trading-rewards summary backing the card. Points are whole; volume is USD cents. */
    data class Summary(
        /** Earn rate, points per whole US dollar of volume. */
        val pointsPerDollar: Long,
        /** 30-day trading volume backing the estimate/read, USD cents. */
        val volume30dCents: Long,
        /** Points earned from the last-30-day volume. */
        val pointsEarned30d: Long,
        /** Lifetime trading points (authoritative only; 0 when estimating). */
        val lifetimeTradingPoints: Long,
        /** Whether the numbers are authoritative or a client estimate. */
        val source: Source,
    ) {
        /** True when the numbers came from the authoritative backend read. */
        val isAuthoritative: Boolean get() = source == Source.AUTHORITATIVE
    }

    /**
     * Whole reward points earned for a given trading [volumeCents] (integer USD cents) at
     * [pointsPerDollar]. Floors to whole points; guards non-positive volume / rate -> 0. Never negative.
     */
    fun tradingPointsForVolumeCents(
        volumeCents: Long,
        pointsPerDollar: Long = POINTS_PER_DOLLAR,
    ): Long {
        if (volumeCents <= 0L || pointsPerDollar <= 0L) return 0L
        // dollars = cents / 100 (floored); points = floor(dollars * rate). Integer math throughout.
        return (volumeCents / 100L) * pointsPerDollar
    }

    /**
     * Inverse of [tradingPointsForVolumeCents]: the minimum trading volume (integer USD cents) required
     * to earn [points] at [pointsPerDollar]. Guards non-positive input -> 0. Never negative.
     */
    fun volumeForPoints(
        points: Long,
        pointsPerDollar: Long = POINTS_PER_DOLLAR,
    ): Long {
        if (points <= 0L || pointsPerDollar <= 0L) return 0L
        // dollars = ceil(points / rate); volume cents = dollars * 100 (least volume that reaches points).
        val dollars = (points + pointsPerDollar - 1L) / pointsPerDollar
        return dollars * 100L
    }

    /**
     * Resolve the trading-rewards [Summary]. Prefers the AUTHORITATIVE payload when it is present and
     * carries a positive rate; otherwise falls back to a client ESTIMATE from the caller's [volumeCents]
     * 30-day volume at [POINTS_PER_DOLLAR]. Never throws.
     */
    fun tradingRewardsSummary(
        volumeCents: Long,
        authoritative: TradingRewards? = null,
    ): Summary {
        if (authoritative != null && authoritative.available && authoritative.pointsPerDollar > 0L) {
            val vol = authoritative.volume30dCents.coerceAtLeast(0L)
            val earned = authoritative.pointsEarned30d
                .takeIf { it > 0L }
                ?: tradingPointsForVolumeCents(vol, authoritative.pointsPerDollar)
            return Summary(
                pointsPerDollar = authoritative.pointsPerDollar,
                volume30dCents = vol,
                pointsEarned30d = earned.coerceAtLeast(0L),
                lifetimeTradingPoints = authoritative.lifetimeTradingPoints.coerceAtLeast(0L),
                source = Source.AUTHORITATIVE,
            )
        }
        val vol = volumeCents.coerceAtLeast(0L)
        return Summary(
            pointsPerDollar = POINTS_PER_DOLLAR,
            volume30dCents = vol,
            pointsEarned30d = tradingPointsForVolumeCents(vol, POINTS_PER_DOLLAR),
            lifetimeTradingPoints = 0L,
            source = Source.ESTIMATED,
        )
    }
}
