package com.testlogon.android.data.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-137 — pure countdown remaining-time + formatting logic (no clock, no java.time). */
class CountdownLogicTest {

    @Test
    fun remainingSeconds_clampsToZero_neverNegative() {
        assertEquals(10L, CountdownLogic.remainingSeconds(targetEpochSeconds = 110, nowEpochSeconds = 100))
        assertEquals(0L, CountdownLogic.remainingSeconds(targetEpochSeconds = 100, nowEpochSeconds = 100))
        assertEquals(0L, CountdownLogic.remainingSeconds(targetEpochSeconds = 90, nowEpochSeconds = 100))
    }

    @Test
    fun isDone_trueAtOrAfterTarget() {
        assertFalse(CountdownLogic.isDone(targetEpochSeconds = 101, nowEpochSeconds = 100))
        assertTrue(CountdownLogic.isDone(targetEpochSeconds = 100, nowEpochSeconds = 100))
        assertTrue(CountdownLogic.isDone(targetEpochSeconds = 95, nowEpochSeconds = 100))
    }

    @Test
    fun format_daysOnlyWhenAtLeastOneDay() {
        // 2d 04:12:09 = 2*86400 + 4*3600 + 12*60 + 9
        assertEquals("2d 04:12:09", CountdownLogic.format(2L * 86400 + 4 * 3600 + 12 * 60 + 9))
        // < 1 day -> no days prefix
        assertEquals("04:12:09", CountdownLogic.format(4L * 3600 + 12 * 60 + 9))
        assertEquals("00:00:09", CountdownLogic.format(9))
        assertEquals("00:00:00", CountdownLogic.format(0))
        assertEquals("00:00:00", CountdownLogic.format(-5))
    }

    @Test
    fun format_exactly24hShowsOneDay() {
        assertEquals("1d 00:00:00", CountdownLogic.format(86400))
        // 23:59:59 stays under a day
        assertEquals("23:59:59", CountdownLogic.format(86399))
    }

    @Test
    fun format_handlesFarFutureWithoutOverflow() {
        // ~3 years of seconds formats with the right day count.
        val threeYears = 3L * 365 * 86400
        val out = CountdownLogic.format(threeYears)
        assertTrue(out.startsWith("1095d "))
    }

    @Test
    fun accessibilityRemaining_isCoarse() {
        assertEquals("0 minutes", CountdownLogic.accessibilityRemaining(0))
        assertEquals("2 days 4 hours", CountdownLogic.accessibilityRemaining(2L * 86400 + 4 * 3600 + 12 * 60))
        assertEquals("4 hours 12 minutes", CountdownLogic.accessibilityRemaining(4L * 3600 + 12 * 60))
        assertEquals("1 hour", CountdownLogic.accessibilityRemaining(3600))
    }
}
