package com.testlogon.android.feature.calendar.detail

import com.testlogon.android.data.calendar.Recurrence
import com.testlogon.android.data.calendar.RecurrenceFreq
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-272 — pure recurrence-summary + share-URL tests. */
class RecurrenceSummaryAndShareTest {

    @Test
    fun daily_simple() {
        assertEquals("Daily", RecurrenceSummary.build(Recurrence(freq = RecurrenceFreq.DAILY)))
    }

    @Test
    fun weekly_withInterval_andByDay_andCount() {
        val summary = RecurrenceSummary.build(
            Recurrence(
                freq = RecurrenceFreq.WEEKLY, interval = 2,
                byDay = listOf("MO", "WE"), count = 10,
            ),
        )
        assertEquals("Every 2 weeks on MO, WE, 10 times", summary)
    }

    @Test
    fun monthly_simple() {
        assertEquals("Monthly", RecurrenceSummary.build(Recurrence(freq = RecurrenceFreq.MONTHLY)))
    }

    @Test
    fun unknown_freq_returnsNull() {
        assertNull(RecurrenceSummary.build(Recurrence(freq = RecurrenceFreq.UNKNOWN)))
    }

    @Test
    fun shareUrl_usesHttpsHost_neverDevHost() {
        val url = EventShareUrl.build("app.testlogon.example.com", "cal_55", "evt_1")
        assertEquals("https://app.testlogon.example.com/event/cal_55/evt_1", url)
        assertTrue(url.startsWith("https://"))
        assertTrue(!url.contains("18.222.237.167"))
    }
}
