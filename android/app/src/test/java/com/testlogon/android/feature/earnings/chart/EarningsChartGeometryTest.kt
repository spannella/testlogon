package com.testlogon.android.feature.earnings.chart

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-252 — pure chart-math tests (scaling / point-mapping / bucketing / empty / single / all-zero). */
class EarningsChartGeometryTest {

    @Test
    fun emptyList_isEmptyGeometry() {
        val g = EarningsChartGeometry.compute(emptyList())
        assertTrue(g.isEmpty)
        assertTrue(g.points.isEmpty())
        assertTrue(g.bars.isEmpty())
    }

    @Test
    fun allZero_isEmptyGeometry() {
        val g = EarningsChartGeometry.compute(listOf(0L, 0L, 0L))
        assertTrue(g.isEmpty)
    }

    @Test
    fun singleNonZeroPoint_isCenteredHorizontally_andTopOfAxis() {
        val g = EarningsChartGeometry.compute(listOf(500L))
        assertFalse(g.isEmpty)
        assertEquals(1, g.points.size)
        assertEquals(0.5f, g.points[0].x, EPS)
        // axisMax niceCeil(500) == 500 -> value sits at the top (y == 1.0)
        assertEquals(500L, g.axisMaxCents)
        assertEquals(1.0f, g.points[0].y, EPS)
    }

    @Test
    fun pointMapping_spreadsEdgeToEdge_andScalesByAxisMax() {
        // values 0..1000, niceCeil(1000)=1000 -> y == value/1000
        val g = EarningsChartGeometry.compute(listOf(0L, 500L, 1000L))
        assertEquals(0f, g.points[0].x, EPS)
        assertEquals(0.5f, g.points[1].x, EPS)
        assertEquals(1f, g.points[2].x, EPS)
        assertEquals(0f, g.points[0].y, EPS)
        assertEquals(0.5f, g.points[1].y, EPS)
        assertEquals(1f, g.points[2].y, EPS)
        assertEquals(1000L, g.axisMaxCents)
    }

    @Test
    fun niceCeil_roundsToOneTwoFiveTimesPowerOfTen() {
        assertEquals(1L, EarningsChartGeometry.niceCeil(1))
        assertEquals(2L, EarningsChartGeometry.niceCeil(2))
        assertEquals(5L, EarningsChartGeometry.niceCeil(3))
        assertEquals(10L, EarningsChartGeometry.niceCeil(7))
        assertEquals(200L, EarningsChartGeometry.niceCeil(150))
        assertEquals(500L, EarningsChartGeometry.niceCeil(420))
        assertEquals(1000L, EarningsChartGeometry.niceCeil(999))
    }

    @Test
    fun bars_haveCenteredSpansWithinSlots_andBaselineZero() {
        val g = EarningsChartGeometry.compute(listOf(100L, 200L))
        assertEquals(2, g.bars.size)
        // two slots of 0.5 each; bar 0 centered at 0.25, bar 1 at 0.75
        val b0 = g.bars[0]
        assertEquals(0.25f, (b0.left + b0.right) / 2f, EPS)
        assertTrue(b0.left >= 0f && b0.right <= 1f)
        assertEquals(0f, b0.baseline, EPS)
        val b1 = g.bars[1]
        assertEquals(0.75f, (b1.left + b1.right) / 2f, EPS)
    }

    @Test
    fun ticks_spanZeroToAxisMax() {
        val g = EarningsChartGeometry.compute(listOf(1000L), tickCount = 4)
        assertEquals(5, g.ticks.size) // 0..4 inclusive
        assertEquals(0L, g.ticks.first().cents)
        assertEquals(1000L, g.ticks.last().cents)
        assertEquals(0f, g.ticks.first().y, EPS)
        assertEquals(1f, g.ticks.last().y, EPS)
    }

    @Test
    fun xForIndex_singlePointCentered() {
        assertEquals(0.5f, EarningsChartGeometry.xForIndex(0, 1), EPS)
        assertEquals(0f, EarningsChartGeometry.xForIndex(0, 4), EPS)
        assertEquals(1f, EarningsChartGeometry.xForIndex(3, 4), EPS)
    }

    private companion object {
        const val EPS = 0.0001f
    }
}
