package com.testlogon.android.data.earnings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AND-252 — pure range -> from_date/to_date window math + epoch-day <-> ISO round-trip. */
class EarningsRangeTest {

    // 2026-06-09 == epoch day 20613 (verified).
    private val today = 20613L

    @Test
    fun d7_windowIsInclusiveSevenDays() {
        val w = EarningsRange.D7.toDateWindow(today)
        assertEquals("2026-06-09", w.toDate)
        assertEquals("2026-06-03", w.fromDate) // today - 6 -> inclusive 7-day window
    }

    @Test
    fun d30_window() {
        val w = EarningsRange.D30.toDateWindow(today)
        assertEquals("2026-06-09", w.toDate)
        assertEquals("2026-05-11", w.fromDate)
    }

    @Test
    fun all_omitsBothDates() {
        val w = EarningsRange.ALL.toDateWindow(today)
        assertNull(w.fromDate)
        assertNull(w.toDate)
    }

    @Test
    fun isoDateFromEpochDay_roundTrips() {
        assertEquals("2026-05-01", isoDateFromEpochDay(20574L))
        assertEquals("1970-01-01", isoDateFromEpochDay(0L))
        assertEquals(20574L, epochDay(2026, 5, 1))
        assertEquals(0L, epochDay(1970, 1, 1))
    }

    @Test
    fun fromKey_lenient() {
        assertEquals(EarningsRange.D90, EarningsRange.fromKey("90d"))
        assertEquals(EarningsRange.ALL, EarningsRange.fromKey("all"))
        assertEquals(EarningsRange.DEFAULT, EarningsRange.fromKey("bogus"))
        assertEquals(EarningsRange.DEFAULT, EarningsRange.fromKey(null))
    }
}
