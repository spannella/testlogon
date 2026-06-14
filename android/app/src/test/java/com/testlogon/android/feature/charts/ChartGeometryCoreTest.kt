package com.testlogon.android.feature.charts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-255 / AND-257 — pure tests for the REUSABLE chart-math core across series shapes (cents and bps),
 * covering empty / all-zero / single / multi / negative inputs, axis scaling, ticks, bar spans, and the
 * nearest-index tap mapping shared by earnings and engagement.
 */
class ChartGeometryCoreTest {

    @Test
    fun emptyList_isEmptyGeometry() {
        val g = ChartGeometryCore.compute(emptyList())
        assertTrue(g.isEmpty)
        assertTrue(g.points.isEmpty())
        assertTrue(g.bars.isEmpty())
        assertTrue(g.ticks.isEmpty())
    }

    @Test
    fun allZero_isEmptyGeometry() {
        assertTrue(ChartGeometryCore.compute(listOf(0L, 0L, 0L)).isEmpty)
    }

    @Test
    fun singleNonZeroPoint_isCenteredHorizontally_andTopOfAxis() {
        val g = ChartGeometryCore.compute(listOf(500L))
        assertFalse(g.isEmpty)
        assertEquals(1, g.points.size)
        assertEquals(0.5f, g.points[0].x, EPS)
        assertEquals(500L, g.axisMax)
        assertEquals(1.0f, g.points[0].y, EPS)
    }

    @Test
    fun pointMapping_spreadsEdgeToEdge_andScalesByAxisMax() {
        val g = ChartGeometryCore.compute(listOf(0L, 500L, 1000L))
        assertEquals(0f, g.points[0].x, EPS)
        assertEquals(0.5f, g.points[1].x, EPS)
        assertEquals(1f, g.points[2].x, EPS)
        assertEquals(0f, g.points[0].y, EPS)
        assertEquals(0.5f, g.points[1].y, EPS)
        assertEquals(1f, g.points[2].y, EPS)
        assertEquals(1000L, g.axisMax)
    }

    @Test
    fun engagementBpsSeries_scalesLikeAnyUnit() {
        // Engagement rate stored in basis points: 9.83% -> 983 bps. niceCeil(983) == 1000.
        val g = ChartGeometryCore.compute(listOf(500L, 983L))
        assertFalse(g.isEmpty)
        assertEquals(1000L, g.axisMax)
        assertEquals(0.5f, g.points[0].y, EPS)
        assertEquals(0.983f, g.points[1].y, EPS)
    }

    @Test
    fun negativeValues_clampToBaseline_noNanOrOutOfRange() {
        val g = ChartGeometryCore.compute(listOf(-100L, 200L))
        assertFalse(g.isEmpty)
        // -100 clamps to the zero baseline.
        assertEquals(0f, g.points[0].y, EPS)
        g.points.forEach { p ->
            assertTrue(p.y in 0f..1f)
            assertFalse(p.y.isNaN())
        }
    }

    @Test
    fun niceCeil_roundsToOneTwoFiveTimesPowerOfTen() {
        assertEquals(1L, ChartGeometryCore.niceCeil(1))
        assertEquals(2L, ChartGeometryCore.niceCeil(2))
        assertEquals(5L, ChartGeometryCore.niceCeil(3))
        assertEquals(10L, ChartGeometryCore.niceCeil(7))
        assertEquals(200L, ChartGeometryCore.niceCeil(150))
        assertEquals(1000L, ChartGeometryCore.niceCeil(983))
        assertEquals(1L, ChartGeometryCore.niceCeil(-5))
    }

    @Test
    fun bars_haveCenteredSpansWithinSlots_andBaselineZero() {
        val g = ChartGeometryCore.compute(listOf(100L, 200L))
        assertEquals(2, g.bars.size)
        val b0 = g.bars[0]
        assertEquals(0.25f, (b0.left + b0.right) / 2f, EPS)
        assertTrue(b0.left >= 0f && b0.right <= 1f)
        assertEquals(0f, b0.baseline, EPS)
        assertEquals(0.75f, (g.bars[1].left + g.bars[1].right) / 2f, EPS)
    }

    @Test
    fun ticks_spanZeroToAxisMax() {
        val g = ChartGeometryCore.compute(listOf(1000L), tickCount = 4)
        assertEquals(5, g.ticks.size)
        assertEquals(0L, g.ticks.first().value)
        assertEquals(1000L, g.ticks.last().value)
        assertEquals(0f, g.ticks.first().y, EPS)
        assertEquals(1f, g.ticks.last().y, EPS)
    }

    @Test
    fun xForIndex_singlePointCentered() {
        assertEquals(0.5f, ChartGeometryCore.xForIndex(0, 1), EPS)
        assertEquals(0f, ChartGeometryCore.xForIndex(0, 4), EPS)
        assertEquals(1f, ChartGeometryCore.xForIndex(3, 4), EPS)
    }

    @Test
    fun nearestIndex_mapsTapToNearestBucket() {
        val g = ChartGeometryCore.compute(listOf(0L, 500L, 1000L))
        assertEquals(0, ChartGeometryCore.nearestIndex(g, 0.05f))
        assertEquals(1, ChartGeometryCore.nearestIndex(g, 0.49f))
        assertEquals(2, ChartGeometryCore.nearestIndex(g, 0.95f))
        assertNull(ChartGeometryCore.nearestIndex(SeriesGeometry.EMPTY, 0.5f))
    }

    private companion object {
        const val EPS = 0.0001f
    }
}
