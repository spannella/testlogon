package com.testlogon.android.feature.calendar

/**
 * AND-271 — view-layer models for the calendar screen. These are pure (no Android) so the slotting
 * math is JVM-unit-testable. Timestamps are carried as UTC epoch millis (Long) and resolved to the
 * display zone by [EventSlotter] using a caller-supplied offset, keeping all bucketing math pure.
 */

enum class CalendarViewMode { MONTH, WEEK, AGENDA }

/**
 * A flattened event ready for slotting. [startMillis]/[endMillis] are UTC epoch millis; for all-day
 * events they bracket the all-day date and [isAllDay] is true (anchored, never zone-shifted).
 */
data class SlottedEvent(
    val calendarId: String,
    val eventId: String,
    val title: String,
    val startMillis: Long,
    val endMillis: Long,
    val isAllDay: Boolean,
    /** For all-day events, the anchored local epoch day (never zone-shifted). */
    val allDayEpochDay: Long? = null,
    val hasRecurrence: Boolean = false,
)

/** One day's bucket for month / agenda views. */
data class DaySlots(
    val epochDay: Long,
    val events: List<SlottedEvent>,
    val overflowCount: Int = 0,
)

/** One positioned timed block in the week grid (minute-of-day positioning + overlap lane split). */
data class TimedBlock(
    val event: SlottedEvent,
    val startMinuteOfDay: Int,
    val endMinuteOfDay: Int,
    val laneIndex: Int,
    val laneCount: Int,
)

/** One day-column of the week grid. */
data class DayColumn(
    val epochDay: Long,
    val blocks: List<TimedBlock>,
)

/** The full week grid: the 7 days, the pinned all-day lane, and the per-day timed columns. */
data class WeekGrid(
    val days: List<Long>,
    val allDayLane: List<SlottedEvent>,
    val columns: List<DayColumn>,
)
