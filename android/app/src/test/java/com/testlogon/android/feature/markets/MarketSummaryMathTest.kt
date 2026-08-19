package com.testlogon.android.feature.markets

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [MarketSummaryMath] — the pure sparkline-window + percent-change math that backs
 * each Markets-list row's sparkline and its green/red % change pill.
 */
class MarketSummaryMathTest {

    private val eps = 1e-9

    @Test
    fun spark_empty_returnsEmpty() {
        assertTrue(MarketSummaryMath.spark(emptyList(), points = 30).isEmpty())
    }

    @Test
    fun spark_takesTrailingWindow_inOrder() {
        val closes = listOf(1.0, 2.0, 3.0, 4.0, 5.0)
        val out = MarketSummaryMath.spark(closes, points = 3)
        assertEquals(listOf(3f, 4f, 5f), out)
    }

    @Test
    fun spark_windowLargerThanSeries_returnsAll() {
        val closes = listOf(10.0, 11.0)
        assertEquals(listOf(10f, 11f), MarketSummaryMath.spark(closes, points = 30))
    }

    @Test
    fun spark_nonPositivePoints_returnsEmpty() {
        assertTrue(MarketSummaryMath.spark(listOf(1.0, 2.0), points = 0).isEmpty())
    }

    @Test
    fun changePct_positiveMove() {
        // 100 -> 110 over the window = +10%.
        assertEquals(10.0, MarketSummaryMath.changePct(100.0, 110.0, windowSize = 2)!!, eps)
    }

    @Test
    fun changePct_negativeMove() {
        // 200 -> 150 = -25%.
        assertEquals(-25.0, MarketSummaryMath.changePct(200.0, 150.0, windowSize = 5)!!, eps)
    }

    @Test
    fun changePct_singlePoint_isNull() {
        assertNull(MarketSummaryMath.changePct(100.0, 100.0, windowSize = 1))
    }

    @Test
    fun changePct_zeroBaseline_isNull() {
        assertNull(MarketSummaryMath.changePct(0.0, 5.0, windowSize = 4))
    }

    @Test
    fun changePctOf_usesFirstAndLastOfTrailingWindow() {
        // Trailing 3 closes are 4,5,6 -> (6-4)/4*100 = +50%.
        val closes = listOf(1.0, 2.0, 4.0, 5.0, 6.0)
        assertEquals(50.0, MarketSummaryMath.changePctOf(closes, points = 3)!!, eps)
    }

    @Test
    fun changePctOf_emptyOrSingle_isNull() {
        assertNull(MarketSummaryMath.changePctOf(emptyList(), points = 30))
        assertNull(MarketSummaryMath.changePctOf(listOf(42.0), points = 30))
    }
}
