package com.testlogon.android.feature.calendar

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale

/**
 * AND-271/AND-272 — pure display-formatting tests (java.text, JVM-safe). Verifies zone-correct time
 * rendering (the AC-3 acceptance pair) and that all-day rendering does not shift across zones.
 */
class CalendarDateFormatTest {

    private fun millis(y: Int, mo: Int, d: Int, h: Int, mi: Int): Long {
        val days = CalendarMath.toEpochDay(y, mo, d)
        return days * CalendarMath.MILLIS_PER_DAY + (h * 60L + mi) * CalendarMath.MILLIS_PER_MINUTE
    }

    @Test
    fun time_rendersInZone_ny_and_tokyo() {
        val utc = millis(2026, 6, 8, 13, 30)
        val ny = CalendarDateFormat.formatTime(utc, "America/New_York", Locale.US)
        val tokyo = CalendarDateFormat.formatTime(utc, "Asia/Tokyo", Locale.US)
        assertEquals("9:30 AM", ny)
        assertEquals("10:30 PM", tokyo)
    }

    @Test
    fun range_sameDay_isCompact() {
        val start = millis(2026, 6, 8, 13, 30)
        val end = millis(2026, 6, 8, 14, 0)
        val range = CalendarDateFormat.formatRange(start, end, "America/New_York", Locale.US)
        assertEquals("Jun 8, 2026, 9:30 AM - 10:00 AM", range)
    }

    @Test
    fun allDay_doesNotShiftAcrossZones() {
        val epochDay = CalendarMath.toEpochDay(2026, 7, 3)
        assertEquals("Jul 3, 2026", CalendarDateFormat.formatAllDay(epochDay, Locale.US))
    }

    @Test
    fun monthYear_label() {
        val utc = millis(2026, 6, 15, 12, 0)
        assertTrue(CalendarDateFormat.formatMonthYear(utc, "UTC", Locale.US).startsWith("June 2026"))
    }
}
