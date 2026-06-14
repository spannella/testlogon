package com.testlogon.android.feature.calendar

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-271 — pure slotting tests (JVM). Covers day bucketing within a range, chip cap + overflow,
 * multi-day spanning, all-day anchoring (no zone shift), timezone-correct minute-of-day positioning,
 * and greedy lane assignment for overlapping vs touching blocks.
 */
class EventSlotterTest {

    private fun millis(y: Int, mo: Int, d: Int, h: Int, mi: Int): Long {
        val days = CalendarMath.toEpochDay(y, mo, d)
        return days * CalendarMath.MILLIS_PER_DAY + (h * 60L + mi) * CalendarMath.MILLIS_PER_MINUTE
    }

    private fun timed(id: String, y: Int, mo: Int, d: Int, sh: Int, sm: Int, eh: Int, em: Int) =
        SlottedEvent(
            calendarId = "cal",
            eventId = id,
            title = id,
            startMillis = millis(y, mo, d, sh, sm),
            endMillis = millis(y, mo, d, eh, em),
            isAllDay = false,
        )

    @Test
    fun toDaySlots_bucketsAndCapsChips() {
        val day = CalendarMath.toEpochDay(2026, 6, 10)
        val events = (1..5).map { timed("e$it", 2026, 6, 10, 9 + it, 0, 10 + it, 0) }
        val range = CalendarMath.DayRange(day, day + 1)
        val slots = EventSlotter.toDaySlots(events, range, offsetMinutes = 0, maxChips = 3)
        assertEquals(1, slots.size)
        assertEquals(3, slots[0].events.size)
        assertEquals(2, slots[0].overflowCount)
    }

    @Test
    fun toDaySlots_allDay_anchoredNoZoneShift() {
        val epochDay = CalendarMath.toEpochDay(2026, 6, 8)
        val midnight = epochDay * CalendarMath.MILLIS_PER_DAY
        val allDay = SlottedEvent(
            calendarId = "cal", eventId = "ad", title = "Holiday",
            startMillis = midnight, endMillis = midnight + CalendarMath.MILLIS_PER_DAY,
            isAllDay = true, allDayEpochDay = epochDay,
        )
        val range = CalendarMath.DayRange(epochDay - 1, epochDay + 2)
        // Even with a large offset the anchored day does not shift.
        val ny = EventSlotter.toDaySlots(listOf(allDay), range, offsetMinutes = -240)
        val tokyo = EventSlotter.toDaySlots(listOf(allDay), range, offsetMinutes = 540)
        assertEquals(1, ny.first { it.epochDay == epochDay }.events.size)
        assertEquals(1, tokyo.first { it.epochDay == epochDay }.events.size)
        // Not on adjacent days.
        assertTrue(ny.first { it.epochDay == epochDay - 1 }.events.isEmpty())
    }

    @Test
    fun toDaySlots_multiDayTimed_appearsOnEachSpannedDay() {
        val start = millis(2026, 6, 8, 22, 0)
        val end = millis(2026, 6, 10, 2, 0)
        val event = SlottedEvent("cal", "multi", "Conf", start, end, isAllDay = false)
        val range = CalendarMath.DayRange(
            CalendarMath.toEpochDay(2026, 6, 8),
            CalendarMath.toEpochDay(2026, 6, 12),
        )
        val slots = EventSlotter.toDaySlots(listOf(event), range, offsetMinutes = 0)
        val withEvent = slots.filter { it.events.isNotEmpty() }.map { it.epochDay }
        assertEquals(
            listOf(
                CalendarMath.toEpochDay(2026, 6, 8),
                CalendarMath.toEpochDay(2026, 6, 9),
                CalendarMath.toEpochDay(2026, 6, 10),
            ),
            withEvent,
        )
    }

    @Test
    fun toWeekGrid_positionsTimedBlock_byZone() {
        val event = SlottedEvent(
            "cal", "e", "Standup",
            startMillis = millis(2026, 6, 8, 13, 30),
            endMillis = millis(2026, 6, 8, 14, 0),
            isAllDay = false,
        )
        val week = CalendarMath.weekDays(CalendarMath.toEpochDay(2026, 6, 8))
        // America/New_York (-240): 09:30 local => minute 570.
        val gridNy = EventSlotter.toWeekGrid(listOf(event), week, offsetMinutes = -240)
        val blockNy = gridNy.columns.flatMap { it.blocks }.single()
        assertEquals(570, blockNy.startMinuteOfDay)
        // Asia/Tokyo (+540): 22:30 local => minute 1350.
        val gridTokyo = EventSlotter.toWeekGrid(listOf(event), week, offsetMinutes = 540)
        val blockTokyo = gridTokyo.columns.flatMap { it.blocks }.single()
        assertEquals(1350, blockTokyo.startMinuteOfDay)
    }

    @Test
    fun toWeekGrid_allDayGoesToLane() {
        val epochDay = CalendarMath.toEpochDay(2026, 6, 8)
        val midnight = epochDay * CalendarMath.MILLIS_PER_DAY
        val allDay = SlottedEvent(
            "cal", "ad", "Holiday", midnight, midnight + CalendarMath.MILLIS_PER_DAY,
            isAllDay = true, allDayEpochDay = epochDay,
        )
        val grid = EventSlotter.toWeekGrid(listOf(allDay), CalendarMath.weekDays(epochDay), 0)
        assertEquals(1, grid.allDayLane.size)
        assertTrue(grid.columns.all { it.blocks.isEmpty() })
    }

    @Test
    fun assignLanes_overlappingSplit_touchingShareLane() {
        // a [9-10], b [9:30-10:30] overlap -> 2 lanes; c [10-11] touches a (back-to-back) -> shares.
        val a = TimedBlock(timed("a", 2026, 6, 10, 9, 0, 10, 0), 540, 600, 0, 1)
        val b = TimedBlock(timed("b", 2026, 6, 10, 9, 30, 10, 30), 570, 630, 0, 1)
        val c = TimedBlock(timed("c", 2026, 6, 10, 10, 0, 11, 0), 600, 660, 0, 1)
        val lanes = EventSlotter.assignLanes(listOf(a, b, c))
        val byId = lanes.associateBy { it.event.eventId }
        // a and b overlap -> different lanes.
        assertTrue(byId.getValue("a").laneIndex != byId.getValue("b").laneIndex)
        // a and c touch but do not overlap -> c reuses a's lane (0).
        assertEquals(byId.getValue("a").laneIndex, byId.getValue("c").laneIndex)
        // Overlap cluster reports laneCount >= 2.
        assertTrue(byId.getValue("a").laneCount >= 2)
    }
}
