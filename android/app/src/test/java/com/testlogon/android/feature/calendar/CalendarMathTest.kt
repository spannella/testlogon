package com.testlogon.android.feature.calendar

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-271 — pure date-math tests (JVM, no Android, no java.time). Covers epoch-day round trips, the
 * 6x7 month grid for short/long/edge months, day-of-week, week days, ranges, stepping, and
 * timezone-correct day bucketing (incl. midnight-crossing).
 */
class CalendarMathTest {

    @Test
    fun epochDay_knownAnchors() {
        assertEquals(0L, CalendarMath.toEpochDay(1970, 1, 1))
        assertEquals(19_517L, CalendarMath.toEpochDay(2023, 6, 9))
        // 2026-06-10
        val ed = CalendarMath.toEpochDay(2026, 6, 10)
        assertEquals(CalendarMath.Ymd(2026, 6, 10), CalendarMath.fromEpochDay(ed))
    }

    @Test
    fun epochDay_roundTrip_acrossDecades() {
        var ed = CalendarMath.toEpochDay(1999, 12, 31)
        repeat(20_000) {
            val ymd = CalendarMath.fromEpochDay(ed)
            assertEquals(ed, CalendarMath.toEpochDay(ymd))
            ed += 1
        }
    }

    @Test
    fun dayOfWeek_1970_01_01_isThursday() {
        // ISO: Thursday = 4.
        assertEquals(4, CalendarMath.dayOfWeekIso(0L))
        // 2026-06-08 is a Monday.
        assertEquals(1, CalendarMath.dayOfWeekIso(CalendarMath.toEpochDay(2026, 6, 8)))
    }

    @Test
    fun leapYear_andMonthLengths() {
        assertTrue(CalendarMath.isLeapYear(2024))
        assertFalse(CalendarMath.isLeapYear(2023))
        assertFalse(CalendarMath.isLeapYear(1900))
        assertTrue(CalendarMath.isLeapYear(2000))
        assertEquals(29, CalendarMath.lengthOfMonth(2024, 2))
        assertEquals(28, CalendarMath.lengthOfMonth(2023, 2))
        assertEquals(31, CalendarMath.lengthOfMonth(2026, 1))
        assertEquals(30, CalendarMath.lengthOfMonth(2026, 4))
    }

    @Test
    fun monthGrid_isAlways42Cells_startingOnWeekStart() {
        val focus = CalendarMath.toEpochDay(2026, 6, 15)
        val grid = CalendarMath.monthGridDays(focus, weekStartIso = 1)
        assertEquals(42, grid.size)
        // First cell is a Monday on or before June 1.
        assertEquals(1, CalendarMath.dayOfWeekIso(grid.first()))
        val firstYmd = CalendarMath.fromEpochDay(grid.first())
        // June 1 2026 is a Monday, so the grid starts exactly on June 1.
        assertEquals(CalendarMath.Ymd(2026, 6, 1), firstYmd)
    }

    @Test
    fun monthGrid_february2026_padsLeadingDays() {
        // Feb 1 2026 is a Sunday; with Monday week-start the grid backs up to Jan 26.
        val focus = CalendarMath.toEpochDay(2026, 2, 10)
        val grid = CalendarMath.monthGridDays(focus, weekStartIso = 1)
        assertEquals(42, grid.size)
        assertEquals(CalendarMath.Ymd(2026, 1, 26), CalendarMath.fromEpochDay(grid.first()))
        assertEquals(1, CalendarMath.dayOfWeekIso(grid.first()))
    }

    @Test
    fun monthGrid_sundayWeekStart() {
        val focus = CalendarMath.toEpochDay(2026, 6, 15)
        val grid = CalendarMath.monthGridDays(focus, weekStartIso = 7)
        assertEquals(7, CalendarMath.dayOfWeekIso(grid.first()))
    }

    @Test
    fun weekDays_sevenContiguousFromWeekStart() {
        val focus = CalendarMath.toEpochDay(2026, 6, 10) // Wednesday
        val week = CalendarMath.weekDays(focus, weekStartIso = 1)
        assertEquals(7, week.size)
        assertEquals(CalendarMath.Ymd(2026, 6, 8), CalendarMath.fromEpochDay(week.first()))
        assertEquals(CalendarMath.Ymd(2026, 6, 14), CalendarMath.fromEpochDay(week.last()))
    }

    @Test
    fun step_month_clampsDayOfMonth() {
        // Jan 31 + 1 month -> Feb 28 (2026 not a leap year).
        val jan31 = CalendarMath.toEpochDay(2026, 1, 31)
        val next = CalendarMath.step(CalendarViewMode.MONTH, jan31, +1)
        assertEquals(CalendarMath.Ymd(2026, 2, 28), CalendarMath.fromEpochDay(next))
    }

    @Test
    fun step_week_and_agenda() {
        val focus = CalendarMath.toEpochDay(2026, 6, 10)
        assertEquals(focus + 7, CalendarMath.step(CalendarViewMode.WEEK, focus, +1))
        assertEquals(focus - 1, CalendarMath.step(CalendarViewMode.AGENDA, focus, -1))
    }

    @Test
    fun rangeFor_month_spansFullGrid() {
        val focus = CalendarMath.toEpochDay(2026, 6, 15)
        val range = CalendarMath.rangeFor(CalendarViewMode.MONTH, focus)
        assertEquals(42L, range.endEpochDayExclusive - range.startEpochDay)
    }

    @Test
    fun localEpochDay_convertsByZoneOffset() {
        // 2026-06-08T13:30:00Z = UTC epoch millis.
        val utcMillis = isoToMillis(2026, 6, 8, 13, 30)
        // America/New_York in June is UTC-4 (-240 min): local 09:30 same day.
        assertEquals(CalendarMath.toEpochDay(2026, 6, 8), CalendarMath.localEpochDay(utcMillis, -240))
        assertEquals(570, CalendarMath.localMinuteOfDay(utcMillis, -240)) // 9*60+30
        // Asia/Tokyo UTC+9 (+540 min): local 22:30 same day.
        assertEquals(CalendarMath.toEpochDay(2026, 6, 8), CalendarMath.localEpochDay(utcMillis, 540))
        assertEquals(1350, CalendarMath.localMinuteOfDay(utcMillis, 540)) // 22*60+30
    }

    @Test
    fun localEpochDay_midnightCrossing_eastOfUtc() {
        // 2026-06-08T16:00:00Z in Tokyo (+540) = 01:00 next local day (June 9).
        val utcMillis = isoToMillis(2026, 6, 8, 16, 0)
        assertEquals(CalendarMath.toEpochDay(2026, 6, 9), CalendarMath.localEpochDay(utcMillis, 540))
    }

    @Test
    fun spannedDays_multiDay_dropsTrailingMidnightEnd() {
        val start = isoToMillis(2026, 6, 8, 22, 0)
        val end = isoToMillis(2026, 6, 9, 1, 0)
        val days = CalendarMath.spannedDays(start, end, 0, 0)
        assertEquals(
            listOf(CalendarMath.toEpochDay(2026, 6, 8), CalendarMath.toEpochDay(2026, 6, 9)),
            days,
        )
    }

    @Test
    fun spannedDays_eventEndingExactlyAtMidnight_doesNotLeakNextDay() {
        val start = isoToMillis(2026, 6, 8, 22, 0)
        val end = isoToMillis(2026, 6, 9, 0, 0)
        val days = CalendarMath.spannedDays(start, end, 0, 0)
        assertEquals(listOf(CalendarMath.toEpochDay(2026, 6, 8)), days)
    }

    /** Builds UTC epoch millis from a y/m/d h:m using pure epoch-day math (no java.time). */
    private fun isoToMillis(y: Int, mo: Int, d: Int, h: Int, mi: Int): Long {
        val days = CalendarMath.toEpochDay(y, mo, d)
        return days * CalendarMath.MILLIS_PER_DAY + (h * 60L + mi) * CalendarMath.MILLIS_PER_MINUTE
    }
}
