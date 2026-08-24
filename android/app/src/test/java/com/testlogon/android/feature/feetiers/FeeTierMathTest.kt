package com.testlogon.android.feature.feetiers

import com.testlogon.android.feature.feetiers.FeeTierMath.VolumeFill
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure JVM tests for the client-side maker/taker fee-tier engine. */
class FeeTierMathTest {

    private val nowMs = 1_700_000_000_000L // fixed "now" in ms
    private fun daysAgoMs(d: Long) = nowMs - d * 24L * 60L * 60L * 1000L

    @Test
    fun schedule_isCanonical_sixTiersAscending() {
        val t = FeeTierMath.FEE_TIERS
        assertEquals(6, t.size)
        assertEquals(listOf("standard", "bronze", "silver", "gold", "platinum", "diamond"), t.map { it.id })
        // thresholds strictly ascending
        for (i in 1 until t.size) assertTrue(t[i].minVolumeCents > t[i - 1].minVolumeCents)
        // exact canonical thresholds + rates
        assertEquals(0L, t[0].minVolumeCents); assertEquals(10, t[0].makerBps); assertEquals(15, t[0].takerBps)
        assertEquals(50_000_00L, t[1].minVolumeCents); assertEquals(9, t[1].makerBps); assertEquals(14, t[1].takerBps)
        assertEquals(250_000_00L, t[2].minVolumeCents); assertEquals(8, t[2].makerBps); assertEquals(12, t[2].takerBps)
        assertEquals(1_000_000_00L, t[3].minVolumeCents); assertEquals(6, t[3].makerBps); assertEquals(10, t[3].takerBps)
        assertEquals(5_000_000_00L, t[4].minVolumeCents); assertEquals(4, t[4].makerBps); assertEquals(8, t[4].takerBps)
        assertEquals(25_000_000_00L, t[5].minVolumeCents); assertEquals(2, t[5].makerBps); assertEquals(6, t[5].takerBps)
    }

    @Test
    fun volume_emptyIsZero() {
        assertEquals(0L, FeeTierMath.volume30dCents(emptyList(), nowMs))
    }

    @Test
    fun volume_sumsNotionalInWindow() {
        val fills = listOf(
            VolumeFill(daysAgoMs(1), 100_00L, 3), // 300_00
            VolumeFill(daysAgoMs(10), 50_00L, 2), // 100_00
        )
        assertEquals(400_00L, FeeTierMath.volume30dCents(fills, nowMs))
    }

    @Test
    fun volume_excludesOutsideWindowAndFuture() {
        val fills = listOf(
            VolumeFill(daysAgoMs(1), 100_00L, 1),   // in
            VolumeFill(daysAgoMs(31), 100_00L, 1),  // too old
            VolumeFill(nowMs + 5_000L, 100_00L, 1), // future
        )
        assertEquals(100_00L, FeeTierMath.volume30dCents(fills, nowMs))
    }

    @Test
    fun volume_ignoresNonPositivePriceOrQty() {
        val fills = listOf(
            VolumeFill(daysAgoMs(1), 0L, 5),
            VolumeFill(daysAgoMs(1), 100_00L, 0),
            VolumeFill(daysAgoMs(1), -100_00L, 5),
            VolumeFill(daysAgoMs(1), 100_00L, 2), // only this counts: 200_00
        )
        assertEquals(200_00L, FeeTierMath.volume30dCents(fills, nowMs))
    }

    @Test
    fun volume_acceptsSecondsTimestamps() {
        val nowSec = nowMs / 1000L
        val oneDayAgoSec = nowSec - 24L * 60L * 60L
        val fills = listOf(VolumeFill(oneDayAgoSec, 100_00L, 4)) // 400_00
        assertEquals(400_00L, FeeTierMath.volume30dCents(fills, nowMs))
    }

    @Test
    fun volume_customWindowDays() {
        val fills = listOf(
            VolumeFill(daysAgoMs(3), 100_00L, 1),
            VolumeFill(daysAgoMs(10), 100_00L, 1),
        )
        // 7-day window keeps only the 3-day-ago fill
        assertEquals(100_00L, FeeTierMath.volume30dCents(fills, nowMs, windowDays = 7))
    }

    @Test
    fun tierForVolume_boundariesAndBelowZero() {
        assertEquals("standard", FeeTierMath.tierForVolume(0L).id)
        assertEquals("standard", FeeTierMath.tierForVolume(-100L).id)
        assertEquals("standard", FeeTierMath.tierForVolume(49_999_99L).id)
        assertEquals("bronze", FeeTierMath.tierForVolume(50_000_00L).id) // inclusive boundary
        assertEquals("silver", FeeTierMath.tierForVolume(300_000_00L).id)
        assertEquals("diamond", FeeTierMath.tierForVolume(99_000_000_00L).id)
    }

    @Test
    fun nextTier_walksUpAndCapsAtTop() {
        assertEquals("bronze", FeeTierMath.nextTier(FeeTierMath.tierById("standard")!!)!!.id)
        assertEquals("diamond", FeeTierMath.nextTier(FeeTierMath.tierById("platinum")!!)!!.id)
        assertNull(FeeTierMath.nextTier(FeeTierMath.tierById("diamond")!!))
    }

    @Test
    fun tierById_unknownIsNull() {
        assertNull(FeeTierMath.tierById("nope"))
        assertEquals("gold", FeeTierMath.tierById("gold")!!.id)
    }

    @Test
    fun progress_zeroAtTierStart_halfMidway_oneAtTop() {
        // exactly at bronze start -> 0 toward silver
        assertEquals(0.0, FeeTierMath.progressToNextFraction(50_000_00L), 1e-9)
        // midway bronze(50k)->silver(250k) span 200k, +100k => 0.5
        assertEquals(0.5, FeeTierMath.progressToNextFraction(150_000_00L), 1e-9)
        // at/above top tier => 1.0
        assertEquals(1.0, FeeTierMath.progressToNextFraction(25_000_000_00L), 1e-9)
        assertEquals(1.0, FeeTierMath.progressToNextFraction(99_000_000_00L), 1e-9)
        // negative => 0 (standard, 0% toward bronze)
        assertEquals(0.0, FeeTierMath.progressToNextFraction(-5L), 1e-9)
    }

    @Test
    fun volumeToNextTier_remainderAndZeroAtTop() {
        assertEquals(50_000_00L, FeeTierMath.volumeToNextTierCents(0L))
        assertEquals(100_000_00L, FeeTierMath.volumeToNextTierCents(150_000_00L)) // to silver 250k
        assertEquals(0L, FeeTierMath.volumeToNextTierCents(25_000_000_00L))
    }

    @Test
    fun makerTakerFee_roundsHalfUpAndGuards() {
        // 1_000_00 cents @ 15bps = 150_00 * ... 100000*15/10000 = 150
        assertEquals(150L, FeeTierMath.makerTakerFeeCents(100_000L, 15))
        // 12345 * 10 / 10000 = 12.345 -> round to 12
        assertEquals(12L, FeeTierMath.makerTakerFeeCents(12345L, 10))
        // half-up: 5000 * 10 / 10000 = 5.0 exact
        assertEquals(5L, FeeTierMath.makerTakerFeeCents(5000L, 10))
        // 7500 * 10 / 10000 = 7.5 -> 8 (half up)
        assertEquals(8L, FeeTierMath.makerTakerFeeCents(7500L, 10))
        assertEquals(0L, FeeTierMath.makerTakerFeeCents(0L, 15))
        assertEquals(0L, FeeTierMath.makerTakerFeeCents(100_000L, 0))
        assertEquals(0L, FeeTierMath.makerTakerFeeCents(-1L, 15))
    }

    @Test
    fun isTakerOrderType_makerVsTaker_andNormalization() {
        // Market + stop/take-profit market triggers REMOVE liquidity -> taker.
        assertTrue(FeeTierMath.isTakerOrderType("market"))
        assertTrue(FeeTierMath.isTakerOrderType("MARKET"))
        assertTrue(FeeTierMath.isTakerOrderType("stop"))
        assertTrue(FeeTierMath.isTakerOrderType("Take-Profit"))
        // Resting limit + limit-priced legs ADD liquidity -> maker.
        assertTrue(!FeeTierMath.isTakerOrderType("limit"))
        assertTrue(!FeeTierMath.isTakerOrderType("LIMIT"))
        assertTrue(!FeeTierMath.isTakerOrderType("Stop-Limit"))
        assertTrue(!FeeTierMath.isTakerOrderType("stop_limit"))
        assertTrue(!FeeTierMath.isTakerOrderType("quote"))
        assertTrue(!FeeTierMath.isTakerOrderType("oto"))
        // Unknown / null default to taker (never under-quote a fee estimate).
        assertTrue(FeeTierMath.isTakerOrderType(null))
        assertTrue(FeeTierMath.isTakerOrderType("mystery"))
    }

    @Test
    fun orderFeeEstimate_picksTakerRateForMarket() {
        // Standard tier: maker 10bps, taker 15bps. Market = taker: 1_000_00 * 15 / 10000 = 150.
        assertEquals(150L, FeeTierMath.orderFeeEstimateCents(1_000_00L, 10, 15, "market"))
    }

    @Test
    fun orderFeeEstimate_picksMakerRateForLimit() {
        // Limit = maker: 1_000_00 * 10 / 10000 = 100.
        assertEquals(100L, FeeTierMath.orderFeeEstimateCents(1_000_00L, 10, 15, "limit"))
        // Stop-limit is a maker leg too.
        assertEquals(100L, FeeTierMath.orderFeeEstimateCents(1_000_00L, 10, 15, "Stop-Limit"))
    }

    @Test
    fun orderFeeEstimate_guardsAndTierRates() {
        // Non-positive notional -> 0 regardless of type.
        assertEquals(0L, FeeTierMath.orderFeeEstimateCents(0L, 10, 15, "market"))
        assertEquals(0L, FeeTierMath.orderFeeEstimateCents(-5L, 10, 15, "limit"))
        // Diamond tier: maker 2 / taker 6 bps on 1_000_000_00 notional.
        // taker: 1_000_000_00 * 6 / 10000 = 60000 ; maker: * 2 / 10000 = 20000.
        assertEquals(60_000L, FeeTierMath.orderFeeEstimateCents(1_000_000_00L, 2, 6, "market"))
        assertEquals(20_000L, FeeTierMath.orderFeeEstimateCents(1_000_000_00L, 2, 6, "limit"))
    }
}
