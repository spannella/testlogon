package com.testlogon.android.data.analytics

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale

/**
 * AND-399 — TC-AND-399-03: unit/format mapping under a fixed (US) locale. Verifies the pinned units:
 * watch time = seconds -> "h m"; revenue = cents -> currency; engagement = 0..1 fraction -> percent
 * (×100); audience percentage = 0..100 -> percent (NO ×100). All assertions use a fixed locale so the
 * grouping/currency glyphs are deterministic.
 */
class AnalyticsDashboardFormatTest {

    private val us = Locale.US

    @Test
    fun formatCount_groupsThousands() {
        assertEquals("184,320", formatCount(184320L, us))
        assertEquals("0", formatCount(0L, us))
    }

    @Test
    fun formatCents_rendersCurrency() {
        assertEquals("$1,882.00", formatCents(188200L, "USD", us))
        assertEquals("$0.00", formatCents(0L, "USD", us))
    }

    @Test
    fun formatCents_blankCurrency_fallsBackToLocaleDefault() {
        // US locale default currency is USD -> still a dollar string, no crash.
        assertEquals("$94.21", formatCents(9421L, "", us))
    }

    @Test
    fun formatWatchTime_secondsToHoursMinutes() {
        assertEquals("88h 26m", formatWatchTime(318400L, us)) // 318400s = 88h 26m 40s -> "88h 26m"
        assertEquals("26m", formatWatchTime(1560L, us))        // under an hour
        assertEquals("0m", formatWatchTime(0L, us))
        assertEquals("0m", formatWatchTime(-5L, us))           // negative clamps to zero
    }

    @Test
    fun formatFractionPercent_scalesByHundred() {
        assertEquals("6.1%", formatFractionPercent(0.0613, us))
        assertEquals("0.0%", formatFractionPercent(0.0, us))
    }

    @Test
    fun formatPercentNumber_noExtraScaling() {
        assertEquals("38%", formatPercentNumber(38.0, us))
        assertEquals("61%", formatPercentNumber(61.0, us))
        assertEquals("12.5%", formatPercentNumber(12.5, us))
    }
}
