package com.testlogon.android.feature.calendar

/**
 * AND-271 — PURE slotting logic. No Android, no java.time: the display-zone offset (minutes) is
 * supplied per instant by the caller (resolved once in the ViewModel via java.time), so every method
 * here is deterministic and JVM-unit-testable. Covers timezone-correct day bucketing (incl.
 * midnight-crossing), all-day anchoring (no zone shift), month chip caps + overflow, and greedy
 * interval-graph lane assignment for overlapping week-view blocks.
 */
object EventSlotter {

    /**
     * Buckets [events] into [DaySlots] for every day in the half-open [range], capping visible chips at
     * [maxChips] and recording an overflow count. [offsetMinutes] is the display-zone total offset for
     * the events' instants (a single offset is sufficient for the typical no-DST-boundary window; the
     * caller may pass the offset at the window's focus instant). Multi-day timed events appear on every
     * spanned local day; all-day events appear on their anchored day only.
     */
    fun toDaySlots(
        events: List<SlottedEvent>,
        range: CalendarMath.DayRange,
        offsetMinutes: Int,
        maxChips: Int = DEFAULT_MAX_CHIPS,
    ): List<DaySlots> {
        val byDay = HashMap<Long, MutableList<SlottedEvent>>()
        for (event in events) {
            for (day in daysForEvent(event, offsetMinutes)) {
                if (day < range.startEpochDay || day >= range.endEpochDayExclusive) continue
                byDay.getOrPut(day) { mutableListOf() }.add(event)
            }
        }
        val result = ArrayList<DaySlots>()
        var day = range.startEpochDay
        while (day < range.endEpochDayExclusive) {
            val dayEvents = byDay[day].orEmpty().sortedBy { it.startMillis }
            val visible = if (maxChips <= 0) dayEvents else dayEvents.take(maxChips)
            val overflow = (dayEvents.size - visible.size).coerceAtLeast(0)
            result.add(DaySlots(epochDay = day, events = visible, overflowCount = overflow))
            day += 1L
        }
        return result
    }

    /** The local epoch days an event occupies (anchored day for all-day; spanned days for timed). */
    fun daysForEvent(event: SlottedEvent, offsetMinutes: Int): List<Long> = when {
        event.isAllDay && event.allDayEpochDay != null -> listOf(event.allDayEpochDay)
        else -> CalendarMath.spannedDays(
            startMillis = event.startMillis,
            endMillis = event.endMillis,
            startOffsetMinutes = offsetMinutes,
            endOffsetMinutes = offsetMinutes,
        )
    }

    /**
     * Builds the week grid for the 7 [weekDays] (epoch days): all-day / multi-day events go to the
     * pinned all-day lane; timed events are positioned by local minute-of-day and lane-assigned so
     * overlaps split the column.
     */
    fun toWeekGrid(
        events: List<SlottedEvent>,
        weekDays: List<Long>,
        offsetMinutes: Int,
    ): WeekGrid {
        val allDayLane = ArrayList<SlottedEvent>()
        val timedByDay = HashMap<Long, MutableList<SlottedEvent>>()
        val weekSet = weekDays.toHashSet()

        for (event in events) {
            val days = daysForEvent(event, offsetMinutes)
            val touchesWeek = days.any { it in weekSet }
            if (!touchesWeek) continue
            val multiDay = days.size > 1
            if (event.isAllDay || multiDay) {
                allDayLane.add(event)
            } else {
                val day = days.first()
                if (day in weekSet) timedByDay.getOrPut(day) { mutableListOf() }.add(event)
            }
        }

        val columns = weekDays.map { day ->
            val dayEvents = timedByDay[day].orEmpty().sortedBy { it.startMillis }
            val blocks = dayEvents.map { e ->
                TimedBlock(
                    event = e,
                    startMinuteOfDay = CalendarMath.localMinuteOfDay(e.startMillis, offsetMinutes),
                    endMinuteOfDay = endMinuteOfDay(e, offsetMinutes),
                    laneIndex = 0,
                    laneCount = 1,
                )
            }
            DayColumn(epochDay = day, blocks = assignLanes(blocks))
        }
        return WeekGrid(
            days = weekDays,
            allDayLane = allDayLane.sortedBy { it.startMillis },
            columns = columns,
        )
    }

    /** End minute-of-day for a same-day timed block; an event ending at/after midnight clamps to 1440. */
    private fun endMinuteOfDay(event: SlottedEvent, offsetMinutes: Int): Int {
        val startDay = CalendarMath.localEpochDay(event.startMillis, offsetMinutes)
        val endDay = CalendarMath.localEpochDay(event.endMillis, offsetMinutes)
        val rawEnd = CalendarMath.localMinuteOfDay(event.endMillis, offsetMinutes)
        val end = if (endDay > startDay || rawEnd == 0) MINUTES_PER_DAY else rawEnd
        val start = CalendarMath.localMinuteOfDay(event.startMillis, offsetMinutes)
        // Guard end <= start with a 1-minute minimum block.
        return end.coerceAtLeast(start + 1).coerceAtMost(MINUTES_PER_DAY)
    }

    /**
     * Greedy interval-graph lane assignment: blocks are sorted by start, each placed in the first lane
     * whose last block has ended (touching/back-to-back events do NOT overlap), and laneCount is set per
     * overlap cluster. Returns blocks with [TimedBlock.laneIndex]/[TimedBlock.laneCount] filled in.
     */
    fun assignLanes(blocks: List<TimedBlock>): List<TimedBlock> {
        if (blocks.isEmpty()) return blocks
        val sorted = blocks.sortedWith(compareBy({ it.startMinuteOfDay }, { it.endMinuteOfDay }))
        val laneEnds = ArrayList<Int>() // laneEnds[i] = end minute of the last block in lane i
        val laneOf = IntArray(sorted.size)

        // First pass: assign each block a lane (first lane that is free, i.e. ended <= this start).
        for ((i, block) in sorted.withIndex()) {
            var lane = -1
            for (l in laneEnds.indices) {
                if (laneEnds[l] <= block.startMinuteOfDay) {
                    lane = l
                    break
                }
            }
            if (lane == -1) {
                lane = laneEnds.size
                laneEnds.add(block.endMinuteOfDay)
            } else {
                laneEnds[lane] = block.endMinuteOfDay
            }
            laneOf[i] = lane
        }

        // Second pass: laneCount per block = max concurrent lanes over its overlap cluster.
        val result = ArrayList<TimedBlock>(sorted.size)
        for ((i, block) in sorted.withIndex()) {
            var concurrent = 1
            for ((j, other) in sorted.withIndex()) {
                if (i == j) continue
                if (overlaps(block, other)) concurrent = maxOf(concurrent, laneOf[j] + 1)
            }
            concurrent = maxOf(concurrent, laneOf[i] + 1)
            result.add(block.copy(laneIndex = laneOf[i], laneCount = concurrent))
        }
        return result
    }

    private fun overlaps(a: TimedBlock, b: TimedBlock): Boolean =
        a.startMinuteOfDay < b.endMinuteOfDay && b.startMinuteOfDay < a.endMinuteOfDay

    const val DEFAULT_MAX_CHIPS = 3
    private const val MINUTES_PER_DAY = 1440
}
