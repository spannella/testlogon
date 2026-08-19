package com.testlogon.android.feature.markets.chart

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the pure indicator math in [ChartIndicators] (SMA / EMA / RSI, plus stdDev + MACD).
 * These back the MA/EMA overlays and the RSI sub-pane added to [CandlestickChart].
 */
class ChartIndicatorsTest {

    private val eps = 1e-9

    @Test
    fun sma_hasLeadingNulls_thenTrailingAverage() {
        val out = ChartIndicators.sma(listOf(1.0, 2.0, 3.0, 4.0, 5.0), period = 3)
        assertEquals(5, out.size)
        assertNull(out[0])
        assertNull(out[1])
        assertEquals(2.0, out[2]!!, eps) // (1+2+3)/3
        assertEquals(3.0, out[3]!!, eps) // (2+3+4)/3
        assertEquals(4.0, out[4]!!, eps) // (3+4+5)/3
    }

    @Test
    fun sma_constantSeries_returnsConstant() {
        val out = ChartIndicators.sma(List(6) { 10.0 }, period = 4)
        assertNull(out[2])
        for (i in 3..5) assertEquals(10.0, out[i]!!, eps)
    }

    @Test
    fun ema_leadingNulls_thenConvergesTowardConstant() {
        // For a constant series the EMA equals the constant everywhere it emits.
        val out = ChartIndicators.ema(List(10) { 5.0 }, period = 5)
        for (i in 0 until 4) assertNull(out[i])
        for (i in 4 until 10) assertEquals(5.0, out[i]!!, eps)
    }

    @Test
    fun ema_matchesRecurrenceForPeriod3() {
        // k = 2/(3+1) = 0.5. Seeded at closes[0], emitted from index period-1 = 2 onward.
        val closes = listOf(2.0, 4.0, 6.0, 8.0)
        val out = ChartIndicators.ema(closes, period = 3)
        assertNull(out[0])
        assertNull(out[1])
        // e0=2; e1=4*.5+2*.5=3; e2=6*.5+3*.5=4.5; e3=8*.5+4.5*.5=6.25
        assertEquals(4.5, out[2]!!, eps)
        assertEquals(6.25, out[3]!!, eps)
    }

    @Test
    fun rsi_allGains_is100() {
        val closes = (1..20).map { it.toDouble() } // strictly increasing -> no losses
        val out = ChartIndicators.rsi(closes, period = 14)
        // First 14 are null (need period+1 samples before the first value at index=period).
        for (i in 0 until 14) assertNull(out[i])
        assertEquals(100.0, out[14]!!, eps)
        assertEquals(100.0, out[19]!!, eps)
    }

    @Test
    fun rsi_flatSeries_neitherGainNorLoss_is100ByConvention() {
        // No gains and no losses -> avgLoss == 0 -> convention returns 100.
        val out = ChartIndicators.rsi(List(20) { 50.0 }, period = 14)
        assertEquals(100.0, out[14]!!, eps)
    }

    @Test
    fun rsi_staysInRange_forMixedSeries() {
        val closes = listOf(
            44.0, 44.25, 44.5, 43.75, 44.5, 45.0, 47.0, 46.75, 46.5, 46.25,
            47.75, 47.5, 47.0, 44.0, 44.25, 44.5, 45.0, 43.5, 42.0, 43.0,
        )
        val out = ChartIndicators.rsi(closes, period = 14)
        out.filterNotNull().forEach { assertTrue("rsi in [0,100]: $it", it in 0.0..100.0) }
    }

    @Test
    fun rsi_tooShort_isAllNull() {
        val out = ChartIndicators.rsi(listOf(1.0, 2.0, 3.0), period = 14)
        assertEquals(3, out.size)
        assertTrue(out.all { it == null })
    }

    @Test
    fun vwap_singleBar_isTypicalPrice() {
        val out = ChartIndicators.vwap(typical = listOf(10.0), volume = listOf(3.0))
        assertEquals(10.0, out[0]!!, eps)
    }

    @Test
    fun vwap_isVolumeWeighted() {
        // typical [10, 20], volume [1, 3] -> cum at idx1 = (10*1 + 20*3)/(1+3) = 70/4 = 17.5
        val out = ChartIndicators.vwap(typical = listOf(10.0, 20.0), volume = listOf(1.0, 3.0))
        assertEquals(10.0, out[0]!!, eps)
        assertEquals(17.5, out[1]!!, eps)
    }

    @Test
    fun stdDev_ofConstant_isZero() {
        val out = ChartIndicators.stdDev(List(6) { 7.0 }, period = 3)
        assertNull(out[1])
        for (i in 2..5) assertEquals(0.0, out[i]!!, eps)
    }

    @Test
    fun macd_returnsAlignedSeries_histIsLineMinusSignal() {
        val closes = (1..40).map { 100.0 + it }
        val (line, signal, hist) = ChartIndicators.macd(closes)
        assertEquals(closes.size, line.size)
        assertEquals(closes.size, signal.size)
        assertEquals(closes.size, hist.size)
        for (i in closes.indices) {
            val m = line[i]; val s = signal[i]; val h = hist[i]
            if (m != null && s != null) assertEquals(m - s, h!!, 1e-6) else assertNull(h)
        }
    }
}
