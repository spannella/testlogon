package com.testlogon.android.data.calendar

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.time.LocalDate

/**
 * AND-270 — pure DTO -> domain mapper tests. Recurrence, all-day (no off-by-one, no throw on absent
 * start), enum/optional tolerance, and the reduced public payload.
 */
class CalendarMapperTest {

    @Test
    fun recurrence_weekly_mapsAllStructuredFields() {
        val dto = CalendarEventDto(
            eventId = "evt_92", calendarId = "cal_55", name = "Standup", timezone = "America/New_York",
            startUtc = "2026-06-08T13:00:00Z", endUtc = "2026-06-08T13:15:00Z",
            recurrenceRule = RecurrenceRuleDto(
                freq = "WEEKLY", interval = 1, byday = listOf("MO", "TU", "WE", "TH", "FR"),
                untilUtc = "2026-07-31T13:00:00Z",
            ),
            exdatesUtc = listOf("2026-06-19T13:00:00Z"),
            createdAtUtc = "2026-06-01T09:00:00Z",
        )
        val domain = dto.toDomain()
        val recurrence = requireNotNull(domain.recurrence)
        assertEquals(RecurrenceFreq.WEEKLY, recurrence.freq)
        assertEquals(1, recurrence.interval)
        assertEquals(listOf("MO", "TU", "WE", "TH", "FR"), recurrence.byDay)
        assertEquals(Instant.parse("2026-07-31T13:00:00Z"), recurrence.untilUtc)
        assertEquals(1, domain.exDatesUtc.size)
        assertEquals(Instant.parse("2026-06-19T13:00:00Z"), domain.exDatesUtc.first())
    }

    @Test
    fun allDay_mapsToLocalDate_nullStart_noThrow() {
        val dto = CalendarEventDto(
            eventId = "evt_93", calendarId = "cal_55", name = "Company holiday",
            timezone = "America/New_York", allDay = true, allDayDate = "2026-07-03",
            createdAtUtc = "2026-06-01T09:00:00Z",
        )
        val domain = dto.toDomain()
        assertTrue(domain.allDay)
        assertEquals(LocalDate.of(2026, 7, 3), domain.allDayDate)
        assertNull(domain.startAt)
    }

    @Test
    fun unknownFreq_andMissingOptionals_tolerated() {
        val dto = CalendarEventDto(
            eventId = "evt_x", calendarId = "cal_55", name = "Odd", timezone = "UTC",
            recurrenceRule = RecurrenceRuleDto(freq = "HOURLY"),
            createdAtUtc = "2026-06-01T09:00:00Z",
        )
        val domain = dto.toDomain()
        assertEquals(RecurrenceFreq.UNKNOWN, domain.recurrence?.freq)
        assertNull(domain.category)
        assertTrue(domain.attendees.isEmpty())
    }

    @Test
    fun missingRecurrence_andMissingAttendees_default() {
        val dto = CalendarEventDto(
            eventId = "evt_1", calendarId = "cal_55", name = "Sprint review", timezone = "UTC",
            startUtc = "2026-06-10T17:00:00Z", endUtc = "2026-06-10T18:00:00Z",
            attendees = null, recurrenceRule = null, createdAtUtc = "2026-06-05T12:00:00Z",
        )
        val domain = dto.toDomain()
        assertNull(domain.recurrence)
        assertTrue(domain.attendees.isEmpty())
        assertEquals(Instant.parse("2026-06-10T17:00:00Z"), domain.startAt)
    }

    @Test
    fun publicEvent_mapsReducedPayload_isPublic_noAttendees() {
        val dto = PublicEventDto(
            eventId = "evt_1", calendarId = "cal_main", name = "Standup",
            startUtc = "2026-06-08T13:30:00Z", endUtc = "2026-06-08T14:00:00Z",
            timezone = "America/New_York", description = "Daily sync", owner = "u-sam",
        )
        val domain = dto.toDomain()
        assertTrue(domain.isPublic)
        assertEquals("u-sam", domain.owner)
        assertTrue(domain.attendees.isEmpty())
        assertNull(domain.recurrence)
        assertEquals("Daily sync", domain.description)
    }

    @Test
    fun calendar_mapsFields() {
        val dto = CalendarDto(
            calendarId = "cal_55", name = "Team On-call", timezone = "America/New_York",
            ownerUserId = "usr_7", conflictDetection = true, createdAtUtc = "2026-05-01T12:00:00Z",
        )
        val domain = dto.toDomain()
        assertEquals("cal_55", domain.calendarId)
        assertEquals("usr_7", domain.ownerUserId)
        assertTrue(domain.conflictDetection)
        assertFalse(domain.bufferBeforeMinutes != 0)
    }

    @Test
    fun eventsPage_mapsAndForwardsCursor() {
        val page = EventsPageDto(
            events = listOf(
                CalendarEventDto(eventId = "e1", calendarId = "c", name = "A", timezone = "UTC"),
            ),
            nextCursor = "cur2",
        )
        val domain = page.toDomain()
        assertEquals(1, domain.events.size)
        assertEquals("cur2", domain.nextCursor)
    }
}
