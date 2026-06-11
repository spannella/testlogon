package com.testlogon.android.data.calendar

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * AND-277 — calendar recurrence-mapper GAP FILL. The existing [CalendarMapperTest] covers the WEEKLY
 * happy path, all-day, unknown-freq, and the public payload; it does NOT cover: the interval<=0 guard,
 * BYMONTHDAY/BYSETPOS structured fields, UNTIL parsing alongside COUNT, multiple/blank EXDATE tolerance,
 * and malformed timestamps degrading to null (no throw). Those are filled here without duplication.
 */
class CalendarRecurrenceMapperGapTest {

    @Test
    fun intervalZeroOrNegative_guardedToOne() {
        val r0 = RecurrenceRuleDto(freq = "DAILY", interval = 0).toDomain()
        assertEquals(1, r0.interval)
        val rNeg = RecurrenceRuleDto(freq = "WEEKLY", interval = -3).toDomain()
        assertEquals(1, rNeg.interval)
    }

    @Test
    fun monthly_byMonthDay_bySetPos_mapped() {
        val r = RecurrenceRuleDto(
            freq = "MONTHLY",
            interval = 2,
            bymonthday = listOf(1, 15),
            bysetpos = listOf(-1),
        ).toDomain()
        assertEquals(RecurrenceFreq.MONTHLY, r.freq)
        assertEquals(2, r.interval)
        assertEquals(listOf(1, 15), r.byMonthDay)
        assertEquals(listOf(-1), r.bySetPos)
    }

    @Test
    fun until_and_count_bothPreserved_onDomain() {
        // The mapper preserves both; precedence is an emission concern (see IcsMapper), not the mapper's.
        val r = RecurrenceRuleDto(
            freq = "WEEKLY",
            count = 5,
            untilUtc = "2026-07-31T13:00:00Z",
        ).toDomain()
        assertEquals(5, r.count)
        assertEquals(Instant.parse("2026-07-31T13:00:00Z"), r.untilUtc)
    }

    @Test
    fun exdates_multiple_andBlankEntriesTolerated() {
        val dto = CalendarEventDto(
            eventId = "evt_e", calendarId = "cal", name = "Series", timezone = "UTC",
            startUtc = "2026-06-08T13:00:00Z",
            recurrenceRule = RecurrenceRuleDto(freq = "WEEKLY", byday = listOf("MO")),
            exdatesUtc = listOf("2026-06-15T13:00:00Z", "", "2026-06-22T13:00:00Z", "garbage"),
        )
        val domain = dto.toDomain()
        // Blank + unparseable entries are dropped (mapNotNull); valid instants survive.
        assertEquals(2, domain.exDatesUtc.size)
        assertTrue(domain.exDatesUtc.contains(Instant.parse("2026-06-15T13:00:00Z")))
        assertTrue(domain.exDatesUtc.contains(Instant.parse("2026-06-22T13:00:00Z")))
    }

    @Test
    fun malformedStartTimestamp_degradesToNull_noThrow() {
        val dto = CalendarEventDto(
            eventId = "evt_m", calendarId = "cal", name = "Bad time", timezone = "UTC",
            startUtc = "not-a-timestamp", endUtc = "2026-06-10T18:00:00Z",
        )
        val domain = dto.toDomain()
        assertNull(domain.startAt)
        assertEquals(Instant.parse("2026-06-10T18:00:00Z"), domain.endAt)
    }

    @Test
    fun untilParse_malformed_degradesToNull() {
        val r = RecurrenceRuleDto(freq = "DAILY", untilUtc = "bogus").toDomain()
        assertNull(r.untilUtc)
        assertEquals(RecurrenceFreq.DAILY, r.freq)
    }
}
