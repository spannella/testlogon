package com.testlogon.android.feature.calendar

/**
 * AND-271 — PURE calendar date math for building the month grid, bucketing events into days, and
 * computing query ranges. Fully JVM-unit-testable with NO Android, NO java.time (LocalDate/Instant are
 * API 26+ and are deliberately avoided here per the project gotcha), NO android.text.format. Everything
 * is computed on proleptic-Gregorian "epoch day" (days since 1970-01-01) Longs and millisecond epochs.
 *
 * The algorithms (epoch-day <-> y/m/d) are the standard proleptic-Gregorian conversions also used by
 * java.time.LocalDate, reimplemented here so the math is unit-testable on a plain JVM without desugaring.
 */
object CalendarMath {

    const val DAYS_PER_WEEK = 7
    const val MONTH_GRID_WEEKS = 6
    const val MONTH_GRID_CELLS = MONTH_GRID_WEEKS * DAYS_PER_WEEK
    const val MILLIS_PER_DAY = 86_400_000L
    const val MILLIS_PER_MINUTE = 60_000L

    /** A calendar date as plain ints (no java.time). */
    data class Ymd(val year: Int, val month: Int, val day: Int)

    /** A half-open [startEpochDay, endEpochDayExclusive) range of dates. */
    data class DayRange(val startEpochDay: Long, val endEpochDayExclusive: Long)

    // ---- epoch-day <-> y/m/d (proleptic Gregorian) ----

    /** Converts a calendar date to its epoch day (days since 1970-01-01). */
    fun toEpochDay(year: Int, month: Int, day: Int): Long {
        val y = year.toLong()
        val m = month.toLong()
        var total = 0L
        total += 365L * y
        total += if (y >= 0) {
            (y + 3L) / 4L - (y + 99L) / 100L + (y + 399L) / 400L
        } else {
            -(y / -4L - y / -100L + y / -400L)
        }
        total += (367L * m - 362L) / 12L
        total += (day - 1).toLong()
        if (m > 2) {
            total -= 1L
            if (!isLeapYear(year)) total -= 1L
        }
        return total - DAYS_0000_TO_1970
    }

    fun toEpochDay(date: Ymd): Long = toEpochDay(date.year, date.month, date.day)

    /** Converts an epoch day back to a calendar date. */
    fun fromEpochDay(epochDay: Long): Ymd {
        var zeroDay = epochDay + DAYS_0000_TO_1970
        // Shift to a 0000-03-01 based year so leap day is at the end.
        zeroDay -= 60L
        var adjust = 0L
        if (zeroDay < 0) {
            val adjustCycles = (zeroDay + 1L) / DAYS_PER_CYCLE - 1L
            adjust = adjustCycles * 400L
            zeroDay += -adjustCycles * DAYS_PER_CYCLE
        }
        var yearEst = (400L * zeroDay + 591L) / DAYS_PER_CYCLE
        var doyEst = zeroDay - (365L * yearEst + yearEst / 4L - yearEst / 100L + yearEst / 400L)
        if (doyEst < 0) {
            yearEst -= 1
            doyEst = zeroDay - (365L * yearEst + yearEst / 4L - yearEst / 100L + yearEst / 400L)
        }
        yearEst += adjust
        val marchDoy0 = doyEst.toInt()
        val marchMonth0 = (marchDoy0 * 5 + 2) / 153
        val month = (marchMonth0 + 2) % 12 + 1
        val dom = marchDoy0 - (marchMonth0 * 306 + 5) / 10 + 1
        yearEst += (marchMonth0 / 10).toLong()
        return Ymd(yearEst.toInt(), month, dom)
    }

    fun isLeapYear(year: Int): Boolean =
        (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0)

    /** Number of days in [month] of [year] (month 1..12). */
    fun lengthOfMonth(year: Int, month: Int): Int = when (month) {
        2 -> if (isLeapYear(year)) 29 else 28
        4, 6, 9, 11 -> 30
        else -> 31
    }

    /**
     * ISO day-of-week for an epoch day: 1 = Monday .. 7 = Sunday (matches java.time.DayOfWeek.value).
     * 1970-01-01 was a Thursday (=4).
     */
    fun dayOfWeekIso(epochDay: Long): Int {
        val dow0 = Math.floorMod(epochDay + 3L, 7L) // 0 = Monday
        return (dow0 + 1L).toInt()
    }

    /** Adds [days] to an epoch day. */
    fun addDays(epochDay: Long, days: Long): Long = epochDay + days

    /** Adds whole calendar [months] to a date, clamping the day-of-month to the target month length. */
    fun addMonths(date: Ymd, months: Int): Ymd {
        val totalMonths = (date.year * 12L + (date.month - 1)) + months
        val newYear = Math.floorDiv(totalMonths, 12L).toInt()
        val newMonth0 = Math.floorMod(totalMonths, 12L).toInt()
        val newMonth = newMonth0 + 1
        val maxDom = lengthOfMonth(newYear, newMonth)
        return Ymd(newYear, newMonth, date.day.coerceAtMost(maxDom))
    }

    // ---- grids & ranges ----

    /**
     * The 6x7 = 42 epoch days of the month grid for the month containing [focusEpochDay], padded so the
     * first cell is the [weekStartIso] (1=Mon..7=Sun) on or before the 1st of the month and the grid is
     * always six full weeks (stable height across short/long months).
     */
    fun monthGridDays(focusEpochDay: Long, weekStartIso: Int = 1): List<Long> {
        val focus = fromEpochDay(focusEpochDay)
        val firstOfMonth = toEpochDay(focus.year, focus.month, 1)
        val firstDow = dayOfWeekIso(firstOfMonth)
        // Days to back up so the grid starts on weekStart.
        val lead = Math.floorMod(firstDow - weekStartIso, DAYS_PER_WEEK)
        val gridStart = firstOfMonth - lead
        return (0 until MONTH_GRID_CELLS).map { gridStart + it }
    }

    /** The half-open date range [gridStart, gridStart+42) covering the focus month's grid. */
    fun monthGridRange(focusEpochDay: Long, weekStartIso: Int = 1): DayRange {
        val days = monthGridDays(focusEpochDay, weekStartIso)
        return DayRange(days.first(), days.last() + 1L)
    }

    /** The 7 epoch days of the week containing [focusEpochDay], starting on [weekStartIso]. */
    fun weekDays(focusEpochDay: Long, weekStartIso: Int = 1): List<Long> {
        val dow = dayOfWeekIso(focusEpochDay)
        val lead = Math.floorMod(dow - weekStartIso, DAYS_PER_WEEK)
        val start = focusEpochDay - lead
        return (0 until DAYS_PER_WEEK).map { start + it }
    }

    /** The half-open day range for the active [mode] around [focusEpochDay]. */
    fun rangeFor(mode: CalendarViewMode, focusEpochDay: Long, weekStartIso: Int = 1): DayRange =
        when (mode) {
            CalendarViewMode.MONTH -> monthGridRange(focusEpochDay, weekStartIso)
            CalendarViewMode.WEEK -> {
                val days = weekDays(focusEpochDay, weekStartIso)
                DayRange(days.first(), days.last() + 1L)
            }
            // Day view loads exactly the focus day.
            CalendarViewMode.DAY -> DayRange(focusEpochDay, focusEpochDay + 1L)
            // Agenda loads an initial window of focus +/- 7 days.
            CalendarViewMode.AGENDA -> DayRange(focusEpochDay - 7L, focusEpochDay + 8L)
        }

    /** Steps the focus by one unit of [mode] in [direction] (-1 back, +1 forward). */
    fun step(mode: CalendarViewMode, focusEpochDay: Long, direction: Int): Long = when (mode) {
        CalendarViewMode.MONTH -> toEpochDay(addMonths(fromEpochDay(focusEpochDay), direction))
        CalendarViewMode.WEEK -> focusEpochDay + direction.toLong() * DAYS_PER_WEEK
        CalendarViewMode.DAY -> focusEpochDay + direction.toLong()
        CalendarViewMode.AGENDA -> focusEpochDay + direction.toLong()
    }

    // ---- event <-> day bucketing (timezone-correct via a millis offset) ----

    /**
     * The local epoch day for a UTC-epoch-millis [utcMillis] given the display zone's total offset in
     * minutes [zoneOffsetMinutes] at that instant. Pure: the caller resolves the offset (the only place
     * that needs java.time, kept out of here). Handles midnight-crossing because the local day is derived
     * after applying the offset.
     */
    fun localEpochDay(utcMillis: Long, zoneOffsetMinutes: Int): Long =
        Math.floorDiv(utcMillis + zoneOffsetMinutes.toLong() * MILLIS_PER_MINUTE, MILLIS_PER_DAY)

    /** The local minute-of-day [0,1440) for [utcMillis] under [zoneOffsetMinutes]. */
    fun localMinuteOfDay(utcMillis: Long, zoneOffsetMinutes: Int): Int {
        val local = utcMillis + zoneOffsetMinutes.toLong() * MILLIS_PER_MINUTE
        val minutes = Math.floorMod(local, MILLIS_PER_DAY) / MILLIS_PER_MINUTE
        return minutes.toInt()
    }

    /** The inclusive span of local epoch days a [startMillis, endMillis] event touches. */
    fun spannedDays(
        startMillis: Long,
        endMillis: Long,
        startOffsetMinutes: Int,
        endOffsetMinutes: Int,
    ): List<Long> {
        val first = localEpochDay(startMillis, startOffsetMinutes)
        // An event ending exactly at local midnight does not occupy the following day.
        val rawEnd = localEpochDay(endMillis, endOffsetMinutes)
        val endMinute = localMinuteOfDay(endMillis, endOffsetMinutes)
        val last = if (rawEnd > first && endMinute == 0) rawEnd - 1L else rawEnd
        if (last < first) return listOf(first)
        return (first..last).toList()
    }

    private const val DAYS_0000_TO_1970 = 719_528L
    private const val DAYS_PER_CYCLE = 146_097L
}
