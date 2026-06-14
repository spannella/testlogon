package com.testlogon.android.data.analytics

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-399 — pure date-window math for the dashboard ranges. CORRECTED presets are 7 / 30 / 90 / 365
 * (default 30). The inclusive window is to = today, from = today - (days - 1).
 */
class AnalyticsDashboardRangeTest {

    private val today = 20609L // 2026-06-05

    @Test
    fun default_isLast30() {
        assertEquals(AnalyticsDashboardRange.LAST_30, AnalyticsDashboardRange.DEFAULT)
    }

    @Test
    fun fromKey_lenient() {
        assertEquals(AnalyticsDashboardRange.LAST_7, AnalyticsDashboardRange.fromKey("7"))
        assertEquals(AnalyticsDashboardRange.LAST_365, AnalyticsDashboardRange.fromKey("365"))
        assertEquals(AnalyticsDashboardRange.DEFAULT, AnalyticsDashboardRange.fromKey("bogus"))
        assertEquals(AnalyticsDashboardRange.DEFAULT, AnalyticsDashboardRange.fromKey(null))
    }

    @Test
    fun last30_window_isInclusive30Days() {
        val w = AnalyticsDashboardRange.LAST_30.toDateWindow(today)
        assertEquals("2026-05-07", w.fromDate) // 20609 - 29 = 20580 -> 2026-05-07
        assertEquals("2026-06-05", w.toDate)
    }

    @Test
    fun last7_window() {
        val w = AnalyticsDashboardRange.LAST_7.toDateWindow(today)
        assertEquals("2026-05-30", w.fromDate) // 20609 - 6 = 20603
        assertEquals("2026-06-05", w.toDate)
    }

    @Test
    fun last365_window() {
        val w = AnalyticsDashboardRange.LAST_365.toDateWindow(today)
        assertEquals("2025-06-06", w.fromDate) // 20609 - 364 = 20245
        assertEquals("2026-06-05", w.toDate)
    }
}
