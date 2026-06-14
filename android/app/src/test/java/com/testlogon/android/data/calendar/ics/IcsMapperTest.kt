package com.testlogon.android.data.calendar.ics

import com.testlogon.android.data.calendar.CalendarEvent
import com.testlogon.android.data.calendar.Recurrence
import com.testlogon.android.data.calendar.RecurrenceFreq
import com.testlogon.android.feature.calendar.CalendarMath
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.time.LocalDate

/**
 * AND-276 — pure domain -> IcsEvent mapper tests. RRULE construction from the structured Recurrence,
 * UNTIL/COUNT precedence, status normalization, all-day epoch-day mapping, EXDATE carry-through, and
 * DESCRIPTION/URL omission. Combined with the serializer this proves the full export pipeline.
 */
class IcsMapperTest {

    private fun event(
        status: String = "confirmed",
        recurrence: Recurrence? = null,
        allDay: Boolean = false,
        allDayDate: LocalDate? = null,
        description: String = "Daily sync",
    ) = CalendarEvent(
        eventId = "evt_1",
        calendarId = "cal_main",
        name = "Standup",
        description = description,
        timezone = "America/New_York",
        startAt = if (allDay) null else Instant.parse("2026-06-08T13:30:00Z"),
        endAt = if (allDay) null else Instant.parse("2026-06-08T14:00:00Z"),
        allDay = allDay,
        allDayDate = allDayDate,
        status = status,
        recurrence = recurrence,
        exDatesUtc = if (recurrence != null) listOf(Instant.parse("2026-06-15T13:30:00Z")) else emptyList(),
    )

    @Test
    fun timedEvent_mapsCoreFields_uidSuffix() {
        val ics = IcsMapper.toIcsEvent(event(), publicUrl = "https://app.testlogon.example.com/event/cal_main/evt_1")
        assertEquals("evt_1@testlogon.android", ics.uid)
        assertEquals("Standup", ics.summary)
        assertEquals("Daily sync", ics.description)
        assertEquals("https://app.testlogon.example.com/event/cal_main/evt_1", ics.url)
        assertEquals(Instant.parse("2026-06-08T13:30:00Z").toEpochMilli(), ics.startEpochMillis)
        assertEquals(IcsStatus.CONFIRMED, ics.status)
    }

    @Test
    fun blankDescription_andNullUrl_omitted() {
        val ics = IcsMapper.toIcsEvent(event(description = ""), publicUrl = null)
        assertNull(ics.description)
        assertNull(ics.url)
    }

    @Test
    fun status_normalization() {
        assertEquals(IcsStatus.CANCELLED, IcsMapper.normalizeStatus("cancelled"))
        assertEquals(IcsStatus.CANCELLED, IcsMapper.normalizeStatus("Canceled"))
        assertEquals(IcsStatus.TENTATIVE, IcsMapper.normalizeStatus("open"))
        assertEquals(IcsStatus.TENTATIVE, IcsMapper.normalizeStatus("pending"))
        assertEquals(IcsStatus.CONFIRMED, IcsMapper.normalizeStatus("confirmed"))
        assertEquals(IcsStatus.CONFIRMED, IcsMapper.normalizeStatus("weird-unknown"))
    }

    @Test
    fun rrule_weekly_byday_count() {
        val rrule = IcsMapper.buildRrule(
            Recurrence(freq = RecurrenceFreq.WEEKLY, byDay = listOf("MO", "WE", "FR"), count = 8),
        )
        assertEquals("FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=8", rrule)
    }

    @Test
    fun rrule_interval_and_untilWinsOverCount() {
        val rrule = IcsMapper.buildRrule(
            Recurrence(
                freq = RecurrenceFreq.DAILY,
                interval = 2,
                count = 5,
                untilUtc = Instant.parse("2026-07-31T13:00:00Z"),
            ),
        )
        // UNTIL and COUNT are mutually exclusive; UNTIL wins.
        assertEquals("FREQ=DAILY;INTERVAL=2;UNTIL=20260731T130000Z", rrule)
    }

    @Test
    fun rrule_monthly_bymonthday_bysetpos() {
        val rrule = IcsMapper.buildRrule(
            Recurrence(freq = RecurrenceFreq.MONTHLY, byMonthDay = listOf(1, 15), bySetPos = listOf(-1)),
        )
        assertEquals("FREQ=MONTHLY;BYMONTHDAY=1,15;BYSETPOS=-1", rrule)
    }

    @Test
    fun rrule_unknownFreq_returnsNull() {
        assertNull(IcsMapper.buildRrule(Recurrence(freq = RecurrenceFreq.UNKNOWN)))
    }

    @Test
    fun recurringEvent_carriesRruleAndExdates() {
        val ics = IcsMapper.toIcsEvent(
            event(recurrence = Recurrence(freq = RecurrenceFreq.WEEKLY, byDay = listOf("MO"), count = 8)),
            publicUrl = null,
        )
        assertEquals("FREQ=WEEKLY;BYDAY=MO;COUNT=8", ics.rrule)
        assertEquals(1, ics.exDatesEpochMillis.size)
        assertEquals(Instant.parse("2026-06-15T13:30:00Z").toEpochMilli(), ics.exDatesEpochMillis.first())
    }

    @Test
    fun allDayEvent_mapsToEpochDay_nullTimestamps() {
        val ics = IcsMapper.toIcsEvent(
            event(allDay = true, allDayDate = LocalDate.of(2026, 7, 3)),
            publicUrl = null,
        )
        assertTrue(ics.allDay)
        assertNull(ics.startEpochMillis)
        assertEquals(CalendarMath.toEpochDay(2026, 7, 3), ics.allDayEpochDay)
    }
}
