package com.testlogon.android.data.inframonitoring

import com.testlogon.android.data.inframonitoring.MonitoringMath.HealthLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure JVM tests for [MonitoringMath] — metric aggregation, health derivation, and series downsample
 * for the instance-monitoring dashboard. No Android / Retrofit dependencies.
 */
class MonitoringMathTest {

    @Test
    fun healthLevel_mapsKnownStrings() {
        assertEquals(HealthLevel.HEALTHY, MonitoringMath.healthLevel("healthy"))
        assertEquals(HealthLevel.WARNING, MonitoringMath.healthLevel("  Degraded "))
        assertEquals(HealthLevel.CRITICAL, MonitoringMath.healthLevel("UNHEALTHY"))
    }

    @Test
    fun healthLevel_unknownForNullOrGarbage() {
        assertEquals(HealthLevel.UNKNOWN, MonitoringMath.healthLevel(null))
        assertEquals(HealthLevel.UNKNOWN, MonitoringMath.healthLevel("wat"))
    }

    @Test
    fun deriveHealth_empty_isUnknown() {
        assertEquals(HealthLevel.UNKNOWN, MonitoringMath.deriveHealth(null, null, null))
    }

    @Test
    fun deriveHealth_thresholds() {
        assertEquals(HealthLevel.HEALTHY, MonitoringMath.deriveHealth(10, 20, 30))
        assertEquals(HealthLevel.WARNING, MonitoringMath.deriveHealth(10, 80, 30))
        assertEquals(HealthLevel.CRITICAL, MonitoringMath.deriveHealth(95, 20, 30))
    }

    @Test
    fun deriveHealth_ignoresNullChannels() {
        assertEquals(HealthLevel.WARNING, MonitoringMath.deriveHealth(null, 77, null))
    }

    @Test
    fun effectiveHealth_picksWorse() {
        assertEquals(
            HealthLevel.CRITICAL,
            MonitoringMath.effectiveHealth(HealthLevel.WARNING, HealthLevel.CRITICAL),
        )
        assertEquals(
            HealthLevel.WARNING,
            MonitoringMath.effectiveHealth(HealthLevel.WARNING, HealthLevel.HEALTHY),
        )
    }

    @Test
    fun effectiveHealth_unknownReportedFallsToDerived() {
        assertEquals(
            HealthLevel.HEALTHY,
            MonitoringMath.effectiveHealth(HealthLevel.UNKNOWN, HealthLevel.HEALTHY),
        )
    }

    @Test
    fun stats_empty_isEmptyStruct() {
        assertEquals(MonitoringMath.SeriesStats.EMPTY, MonitoringMath.stats(emptyList()))
    }

    @Test
    fun stats_computesMinAvgMaxLast() {
        val s = MonitoringMath.stats(listOf(10, 20, 30, 40))
        assertEquals(4, s.count)
        assertEquals(10, s.min)
        assertEquals(40, s.max)
        assertEquals(25, s.avg)
        assertEquals(40, s.last)
    }

    @Test
    fun stats_avgRounds() {
        // (1+2)/2 = 1.5 -> rounds to 2
        assertEquals(2, MonitoringMath.stats(listOf(1, 2)).avg)
    }

    @Test
    fun downsample_shortListUnchanged() {
        val v = listOf(1, 2, 3)
        assertEquals(v, MonitoringMath.downsample(v, 10))
    }

    @Test
    fun downsample_capsAndKeepsLast() {
        val v = (1..100).toList()
        val out = MonitoringMath.downsample(v, 10)
        assertEquals(10, out.size)
        assertEquals(100, out.last())
        assertEquals(1, out.first())
    }

    @Test
    fun downsample_clampsMaxPointsToAtLeastOne() {
        val out = MonitoringMath.downsample(listOf(5, 6, 7), 0)
        assertEquals(1, out.size)
        assertEquals(7, out.last())
    }

    @Test
    fun orderTimelineDesc_newestFirst() {
        val events = listOf(1L to "a", 3L to "b", 2L to "c")
        val ordered = MonitoringMath.orderTimelineDesc(events) { it.first }
        assertEquals(listOf(3L, 2L, 1L), ordered.map { it.first })
    }

    @Test
    fun restartPolicySummary_offAndOn() {
        assertEquals("Off", MonitoringMath.restartPolicySummary(false, 2, 3))
        assertEquals("On · 2/3 used", MonitoringMath.restartPolicySummary(true, 2, 3))
        assertTrue(MonitoringMath.restartPolicySummary(true, -1, -1).startsWith("On"))
    }
}
