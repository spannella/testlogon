package com.testlogon.android.feature.rewards

import com.testlogon.android.data.rewards.TradingRewards
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure JVM tests for the TRADING-REWARDS math (points earned by trading volume). Mirrors the web
 * frontend/src/lib/tradingRewards.test.ts: canonical rate, floor-to-whole-points, negative/zero guards,
 * the volume<->points inverse, and the authoritative-preferred / estimate-fallback resolution. No
 * Android / Compose / Hilt.
 */
class TradingRewardsMathTest {

    private fun authoritative(
        rate: Long = 1L,
        volumeCents: Long = 0L,
        earned30d: Long = 0L,
        lifetime: Long = 0L,
        available: Boolean = true,
    ) = TradingRewards(
        pointsPerDollar = rate,
        volume30dCents = volumeCents,
        pointsEarned30d = earned30d,
        lifetimeTradingPoints = lifetime,
        available = available,
    )

    // ---- canonical rate ----

    @Test
    fun pointsPerDollar_isOne_mirroringWeb() {
        assertEquals(1L, TradingRewardsMath.POINTS_PER_DOLLAR)
    }

    // ---- tradingPointsForVolumeCents ----

    @Test
    fun points_floorWholeDollars_atCanonicalRate() {
        // $1,234.56 -> floor 1234 dollars * 1 pt = 1234 pts
        assertEquals(1234L, TradingRewardsMath.tradingPointsForVolumeCents(123456L))
        // exact dollar
        assertEquals(100L, TradingRewardsMath.tradingPointsForVolumeCents(10000L))
        // sub-dollar volume rounds down to 0 points
        assertEquals(0L, TradingRewardsMath.tradingPointsForVolumeCents(99L))
    }

    @Test
    fun points_honorCustomRate() {
        // 3 pts per $ on $500 volume = 1500 pts
        assertEquals(1500L, TradingRewardsMath.tradingPointsForVolumeCents(50000L, pointsPerDollar = 3L))
    }

    @Test
    fun points_guardNegativeAndZero() {
        assertEquals(0L, TradingRewardsMath.tradingPointsForVolumeCents(0L))
        assertEquals(0L, TradingRewardsMath.tradingPointsForVolumeCents(-500L))
        assertEquals(0L, TradingRewardsMath.tradingPointsForVolumeCents(10000L, pointsPerDollar = 0L))
        assertEquals(0L, TradingRewardsMath.tradingPointsForVolumeCents(10000L, pointsPerDollar = -2L))
    }

    // ---- volumeForPoints (inverse) ----

    @Test
    fun volumeForPoints_isInverseAtCanonicalRate() {
        // 1234 pts at 1/$ needs $1234 = 123400 cents
        assertEquals(123400L, TradingRewardsMath.volumeForPoints(1234L))
        // round-trip: points for that volume is at least the requested points
        val v = TradingRewardsMath.volumeForPoints(1234L)
        assertTrue(TradingRewardsMath.tradingPointsForVolumeCents(v) >= 1234L)
    }

    @Test
    fun volumeForPoints_guardNonPositive() {
        assertEquals(0L, TradingRewardsMath.volumeForPoints(0L))
        assertEquals(0L, TradingRewardsMath.volumeForPoints(-10L))
        assertEquals(0L, TradingRewardsMath.volumeForPoints(100L, pointsPerDollar = 0L))
    }

    // ---- tradingRewardsSummary: estimate ----

    @Test
    fun summary_estimate_whenNoAuthoritative() {
        val s = TradingRewardsMath.tradingRewardsSummary(volumeCents = 250000L, authoritative = null)
        assertEquals(TradingRewardsMath.Source.ESTIMATED, s.source)
        assertFalse(s.isAuthoritative)
        assertEquals(1L, s.pointsPerDollar)
        assertEquals(250000L, s.volume30dCents)
        assertEquals(2500L, s.pointsEarned30d)
        assertEquals(0L, s.lifetimeTradingPoints)
    }

    @Test
    fun summary_estimate_whenAuthoritativeUnavailableOrZeroRate() {
        // degraded 404 -> unavailable domain
        val degraded = TradingRewardsMath.tradingRewardsSummary(10000L, TradingRewards.unavailable())
        assertEquals(TradingRewardsMath.Source.ESTIMATED, degraded.source)
        assertEquals(100L, degraded.pointsEarned30d)
        // available but non-positive rate also falls back to estimate
        val zeroRate = TradingRewardsMath.tradingRewardsSummary(10000L, authoritative(rate = 0L, volumeCents = 999999L))
        assertEquals(TradingRewardsMath.Source.ESTIMATED, zeroRate.source)
        assertEquals(10000L, zeroRate.volume30dCents)
    }

    @Test
    fun summary_estimate_clampsNegativeVolume() {
        val s = TradingRewardsMath.tradingRewardsSummary(volumeCents = -5000L, authoritative = null)
        assertEquals(0L, s.volume30dCents)
        assertEquals(0L, s.pointsEarned30d)
    }

    // ---- tradingRewardsSummary: authoritative ----

    @Test
    fun summary_prefersAuthoritative_whenPresentWithPositiveRate() {
        val a = authoritative(rate = 2L, volumeCents = 500000L, earned30d = 9999L, lifetime = 42000L)
        val s = TradingRewardsMath.tradingRewardsSummary(volumeCents = 1L, authoritative = a)
        assertEquals(TradingRewardsMath.Source.AUTHORITATIVE, s.source)
        assertTrue(s.isAuthoritative)
        assertEquals(2L, s.pointsPerDollar)
        assertEquals(500000L, s.volume30dCents)
        assertEquals(9999L, s.pointsEarned30d) // server-provided earned wins
        assertEquals(42000L, s.lifetimeTradingPoints)
    }

    @Test
    fun summary_authoritative_computesEarnedWhenServerOmitsIt() {
        // earned30d = 0 (absent in our lenient mapper) -> compute from volume * rate
        val a = authoritative(rate = 1L, volumeCents = 300000L, earned30d = 0L)
        val s = TradingRewardsMath.tradingRewardsSummary(volumeCents = 0L, authoritative = a)
        assertEquals(TradingRewardsMath.Source.AUTHORITATIVE, s.source)
        assertEquals(3000L, s.pointsEarned30d)
    }

    @Test
    fun summary_authoritative_clampsNegatives() {
        val a = authoritative(rate = 1L, volumeCents = -10L, earned30d = -5L, lifetime = -7L)
        val s = TradingRewardsMath.tradingRewardsSummary(volumeCents = 0L, authoritative = a)
        assertEquals(0L, s.volume30dCents)
        assertEquals(0L, s.pointsEarned30d)
        assertEquals(0L, s.lifetimeTradingPoints)
    }
}
