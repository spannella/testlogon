package com.testlogon.android.feature.calendar

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.time.ZoneId

/**
 * AND-277 — timezone slotting matrix GAP FILL (the critical acceptance surface). The existing
 * [EventSlotterTest] asserts minute-of-day for NY/Tokyo and all-day anchoring on ONE day; it does NOT
 * assert the full 13:30Z day+minute matrix across NY/Tokyo/UTC, a WEST-of-UTC midnight-crossing landing
 * on the previous local day, DST-day offsets (resolved exactly as the ViewModel does — via java.time),
 * nor all-day non-shift across three zones at once. Those are filled here.
 *
 * The slotter is pure (it takes a display-zone offset in minutes); these tests resolve that offset the
 * same way the production ViewModel does — through java.time, including DST — and feed it in, so the DST
 * assertions exercise the real tzdb the app relies on.
 */
class EventSlotterTimezoneGapTest {

    private val NY = ZoneId.of("America/New_York")
    private val TOKYO = ZoneId.of("Asia/Tokyo")
    private val LA = ZoneId.of("America/Los_Angeles")
    private val UTC = ZoneId.of("UTC")

    /** The display-zone total offset (minutes) at [instant] — exactly the ViewModel's resolution. */
    private fun offsetMinutes(instant: Instant, zone: ZoneId): Int =
        zone.rules.getOffset(instant).totalSeconds / 60

    private fun millis(iso: String): Long = Instant.parse(iso).toEpochMilli()

    private fun timedEvent(iso: String, durationMin: Long = 30) = SlottedEvent(
        calendarId = "cal", eventId = "e", title = "Standup",
        startMillis = millis(iso),
        endMillis = millis(iso) + durationMin * CalendarMath.MILLIS_PER_MINUTE,
        isAllDay = false,
    )

    @Test
    fun standup_1330Z_dayAndMinute_acrossZones() {
        val instant = Instant.parse("2026-06-08T13:30:00Z")
        val event = timedEvent("2026-06-08T13:30:00Z")
        // NY summer = -240 -> 09:30 (minute 570), same calendar day.
        val nyOff = offsetMinutes(instant, NY)
        assertEquals(-240, nyOff)
        assertEquals(CalendarMath.toEpochDay(2026, 6, 8), CalendarMath.localEpochDay(event.startMillis, nyOff))
        assertEquals(570, CalendarMath.localMinuteOfDay(event.startMillis, nyOff))
        // Tokyo = +540 -> 22:30 (minute 1350), same calendar day.
        val tkOff = offsetMinutes(instant, TOKYO)
        assertEquals(540, tkOff)
        assertEquals(1350, CalendarMath.localMinuteOfDay(event.startMillis, tkOff))
        // UTC -> 13:30 (minute 810).
        assertEquals(810, CalendarMath.localMinuteOfDay(event.startMillis, offsetMinutes(instant, UTC)))
    }

    @Test
    fun westOfUtc_earlyMorning_landsOnPreviousLocalDay() {
        // 02:00Z on 2026-06-09 in Los Angeles (-420 summer) = 19:00 on 2026-06-08 (previous local day).
        val instant = Instant.parse("2026-06-09T02:00:00Z")
        val laOff = offsetMinutes(instant, LA)
        assertEquals(-420, laOff)
        val event = timedEvent("2026-06-09T02:00:00Z")
        val day = CalendarMath.localEpochDay(event.startMillis, laOff)
        assertEquals(CalendarMath.toEpochDay(2026, 6, 8), day)
        // Slotted into a range that includes both candidate days, it lands on the 8th only.
        val range = CalendarMath.DayRange(
            CalendarMath.toEpochDay(2026, 6, 7),
            CalendarMath.toEpochDay(2026, 6, 11),
        )
        val slots = EventSlotter.toDaySlots(listOf(event), range, offsetMinutes = laOff)
        val withEvent = slots.filter { it.events.isNotEmpty() }.map { it.epochDay }
        assertEquals(listOf(CalendarMath.toEpochDay(2026, 6, 8)), withEvent)
    }

    @Test
    fun dstForward_and_backward_offsetsDiffer_andSlotCorrectly() {
        // US DST forward 2026-03-08 (EST -300 before, EDT -240 after); backward 2026-11-01.
        val beforeForward = Instant.parse("2026-03-08T06:00:00Z") // 01:00 EST
        val afterForward = Instant.parse("2026-03-08T08:00:00Z") // 04:00 EDT (03:00 skipped)
        assertEquals(-300, offsetMinutes(beforeForward, NY))
        assertEquals(-240, offsetMinutes(afterForward, NY))

        val beforeBack = Instant.parse("2026-11-01T05:00:00Z") // 01:00 EDT
        val afterBack = Instant.parse("2026-11-01T07:00:00Z") // 02:00 EST
        assertEquals(-240, offsetMinutes(beforeBack, NY))
        assertEquals(-300, offsetMinutes(afterBack, NY))

        // A 10:00Z meeting on the DST-forward day slots at 06:00 EDT (minute 360), on 2026-03-08.
        val meeting = timedEvent("2026-03-08T10:00:00Z")
        val off = offsetMinutes(Instant.parse("2026-03-08T10:00:00Z"), NY)
        assertEquals(-240, off)
        assertEquals(360, CalendarMath.localMinuteOfDay(meeting.startMillis, off))
        assertEquals(CalendarMath.toEpochDay(2026, 3, 8), CalendarMath.localEpochDay(meeting.startMillis, off))
    }

    @Test
    fun allDay_doesNotShift_acrossThreeZones() {
        val epochDay = CalendarMath.toEpochDay(2026, 6, 8)
        val midnight = epochDay * CalendarMath.MILLIS_PER_DAY
        val allDay = SlottedEvent(
            calendarId = "cal", eventId = "ad", title = "Holiday",
            startMillis = midnight, endMillis = midnight + CalendarMath.MILLIS_PER_DAY,
            isAllDay = true, allDayEpochDay = epochDay,
        )
        val range = CalendarMath.DayRange(epochDay - 1, epochDay + 2)
        for (off in listOf(-240, 540, 0)) {
            val slots = EventSlotter.toDaySlots(listOf(allDay), range, offsetMinutes = off)
            assertEquals(1, slots.first { it.epochDay == epochDay }.events.size)
            assertTrue(slots.first { it.epochDay == epochDay - 1 }.events.isEmpty())
            assertTrue(slots.first { it.epochDay == epochDay + 1 }.events.isEmpty())
        }
    }
}
