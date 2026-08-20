package com.testlogon.android.feature.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

class MarketStatsTest {

    private fun close(a: Double, b: Double, eps: Double = 1e-9) =
        assertTrue("expected $a ~= $b", abs(a - b) < eps)

    @Test
    fun periodReturn_basic() {
        close(MarketStats.periodReturn(listOf(100.0, 110.0))!!, 0.10)
    }

    @Test
    fun periodReturn_emptyAndSingle_null() {
        assertNull(MarketStats.periodReturn(emptyList()))
        assertNull(MarketStats.periodReturn(listOf(100.0)))
    }

    @Test
    fun periodReturn_zeroBaseline_null() {
        assertNull(MarketStats.periodReturn(listOf(0.0, 100.0)))
    }

    @Test
    fun cumulativeReturnPct_isPercent() {
        close(MarketStats.cumulativeReturnPct(listOf(100.0, 150.0))!!, 50.0)
    }

    @Test
    fun logReturns_lengthIsNMinusOne() {
        val r = MarketStats.logReturns(listOf(100.0, 105.0, 102.0))
        assertEquals(2, r.size)
    }

    @Test
    fun logReturns_emptyForSingle() {
        assertTrue(MarketStats.logReturns(listOf(100.0)).isEmpty())
    }

    @Test
    fun stdev_singleIsNull_andKnownValue() {
        assertNull(MarketStats.stdev(listOf(1.0)))
        // sample stdev of [2,4,4,4,5,5,7,9] = 2.138... (sample, n-1)
        close(MarketStats.stdev(listOf(2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0))!!, 2.1380899353, 1e-6)
    }

    @Test
    fun annualizedVolatility_nullForTooFewBars() {
        // 1 bar -> no returns -> no stdev -> null
        assertNull(MarketStats.annualizedVolatility(listOf(100.0)))
    }

    @Test
    fun annualizedVolatility_positiveForVaryingSeries() {
        val v = MarketStats.annualizedVolatility(listOf(100.0, 101.0, 99.0, 102.0, 98.0))
        assertTrue(v != null && v > 0.0)
    }

    @Test
    fun maxDrawdown_dipHalf() {
        close(MarketStats.maxDrawdown(listOf(100.0, 120.0, 60.0, 80.0))!!, 0.5)
    }

    @Test
    fun maxDrawdown_monotonicIsZero_andEmptyNull() {
        close(MarketStats.maxDrawdown(listOf(1.0, 2.0, 3.0))!!, 0.0)
        assertNull(MarketStats.maxDrawdown(emptyList()))
    }

    @Test
    fun hiLo_avgTotal() {
        val s = listOf(3.0, 1.0, 4.0, 2.0)
        close(MarketStats.high(s)!!, 4.0)
        close(MarketStats.low(s)!!, 1.0)
        close(MarketStats.average(s)!!, 2.5)
        close(MarketStats.total(s), 10.0)
        assertNull(MarketStats.high(emptyList()))
        assertNull(MarketStats.average(emptyList()))
        close(MarketStats.total(emptyList()), 0.0)
    }

    @Test
    fun correlation_perfectPositive() {
        close(MarketStats.correlation(listOf(1.0, 2.0, 3.0), listOf(2.0, 4.0, 6.0))!!, 1.0, 1e-9)
    }

    @Test
    fun correlation_perfectNegative() {
        close(MarketStats.correlation(listOf(1.0, 2.0, 3.0), listOf(6.0, 4.0, 2.0))!!, -1.0, 1e-9)
    }

    @Test
    fun correlation_zeroVarianceOrTooShort_null() {
        assertNull(MarketStats.correlation(listOf(1.0, 1.0, 1.0), listOf(2.0, 4.0, 6.0)))
        assertNull(MarketStats.correlation(listOf(1.0), listOf(2.0)))
    }

    @Test
    fun normalizeToBase_startsAt100() {
        val n = MarketStats.normalizeToBase(listOf(50.0, 75.0, 100.0))
        close(n.first(), 100.0)
        close(n.last(), 200.0)
        assertTrue(MarketStats.normalizeToBase(emptyList()).isEmpty())
        assertTrue(MarketStats.normalizeToBase(listOf(0.0, 1.0)).isEmpty())
    }

    @Test
    fun backtest_degenerateInputs_flat() {
        val r = MarketStats.backtestMaCross(listOf(1.0, 2.0), fast = 2, slow = 5)
        assertEquals(0, r.trades)
        close(r.totalReturn, 0.0)
        assertEquals(listOf(1.0), r.equityCurve)
    }

    @Test
    fun backtest_uptrend_profitsAndTrades() {
        // A rising series: fast SMA crosses above slow, position held -> positive return, >=1 trade.
        val closes = (1..40).map { 100.0 + it * 2.0 }
        val r = MarketStats.backtestMaCross(closes, fast = 3, slow = 8)
        assertTrue("expected >=1 trade", r.trades >= 1)
        assertTrue("expected positive return", r.totalReturn > 0.0)
        assertTrue(r.winRate in 0.0..1.0)
        // equity curve grows to closes.size length (starts at 1.0).
        assertEquals(closes.size, r.equityCurve.size)
        close(r.equityCurve.first(), 1.0)
    }

    @Test
    fun backtest_invalidFastSlow_flat() {
        val closes = (1..40).map { 100.0 + it.toDouble() }
        val r = MarketStats.backtestMaCross(closes, fast = 8, slow = 3) // fast >= slow
        assertEquals(0, r.trades)
    }

    @Test
    fun sma_alignmentAndWarmup() {
        val s = MarketStats.sma(listOf(1.0, 2.0, 3.0, 4.0), 2)
        assertNull(s[0])
        close(s[1]!!, 1.5)
        close(s[2]!!, 2.5)
        close(s[3]!!, 3.5)
    }
}
