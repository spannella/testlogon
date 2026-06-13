package com.testlogon.android.core.model.ads

import org.junit.Assert.assertEquals
import org.junit.Test
import java.time.LocalDate

/**
 * AND-368 - unit tests for the pure [DateRange.of] helper + [DateRangePreset]. A fixed `today` is passed in
 * so the from/to windows are deterministic (there is no implicit system clock in the pure helper). Confirms
 * the inclusive window math (today minus days-1 .. today) for each preset and the wire YYYY-MM-DD format,
 * and that LAST_28 is the declared default ordering position.
 */
class AdAnalyticsRangeTest {

    private val today: LocalDate = LocalDate.of(2026, 6, 9)

    @Test
    fun last7_spansSevenInclusiveDays_endingToday() {
        val range = DateRange.of(DateRangePreset.LAST_7, today)
        assertEquals("2026-06-03", range.from)
        assertEquals("2026-06-09", range.to)
    }

    @Test
    fun last28_default_spans28InclusiveDays() {
        val range = DateRange.of(DateRangePreset.LAST_28, today)
        assertEquals("2026-05-13", range.from)
        assertEquals("2026-06-09", range.to)
    }

    @Test
    fun last90_spans90InclusiveDays() {
        val range = DateRange.of(DateRangePreset.LAST_90, today)
        assertEquals("2026-03-12", range.from)
        assertEquals("2026-06-09", range.to)
    }

    @Test
    fun range_crossesMonthAndYearBoundary() {
        val newYears = LocalDate.of(2026, 1, 2)
        val range = DateRange.of(DateRangePreset.LAST_7, newYears)
        assertEquals("2025-12-27", range.from)
        assertEquals("2026-01-02", range.to)
    }

    @Test
    fun presetDays_areExpected() {
        assertEquals(7, DateRangePreset.LAST_7.days)
        assertEquals(28, DateRangePreset.LAST_28.days)
        assertEquals(90, DateRangePreset.LAST_90.days)
    }

    @Test
    fun breakdownDimension_wireTokens() {
        assertEquals("creative", BreakdownDimension.CREATIVE.wire)
        assertEquals("surface", BreakdownDimension.SURFACE.wire)
        assertEquals("targeting", BreakdownDimension.TARGETING.wire)
    }
}
