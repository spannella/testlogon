package com.testlogon.android.feature.calendar

import com.testlogon.android.data.calendar.CalendarEvent
import com.testlogon.android.data.calendar.Recurrence
import com.testlogon.android.data.calendar.RecurrenceFreq
import java.time.Instant

/**
 * SC19 #9 - PURE recurrence expander used by [CalendarViewModel] to surface recurring events on every
 * occurrence day within the visible window. No Android-only API, no java.time math: it operates on the
 * event's absolute UTC start/end millis (or all-day epoch day) and the display-zone offset (minutes),
 * reusing the project's pure [CalendarMath] date arithmetic, so it is JVM-unit-testable.
 *
 * The backend stores a single master event + a structured [Recurrence] and (today) does NOT expand
 * occurrences in the list response, so the grid would otherwise only show the first instance. This
 * generates the extra occurrence instants client-side for the requested window. Supports DAILY, WEEKLY
 * (incl. BYDAY), MONTHLY (same day-of-month) and YEARLY with INTERVAL, COUNT and UNTIL; an UNKNOWN freq
 * yields only the master event. Occurrences whose local day is an EXDATE are skipped. Bounded by
 * [MAX_OCCURRENCES] as a safety cap.
 */
object RecurrenceExpander {

    private const val MAX_OCCURRENCES = 366
    private val ISO_BYDAY = listOf("MO", "TU", "WE", "TH", "FR", "SA", "SU")

    /**
     * Returns [event] repeated onto each occurrence whose local start day falls within
     * [windowStartDay, windowEndDayExclusive). The original master is returned for the anchor day; each
     * other occurrence is a copy with shifted start/end (timed) or all-day date. Non-recurring events
     * (or UNKNOWN freq) return just the event.
     */
    fun expand(
        event: CalendarEvent,
        windowStartDay: Long,
        windowEndDayExclusive: Long,
        offsetMinutes: Int,
    ): List<CalendarEvent> {
        val rec = event.recurrence
        if (rec == null || rec.freq == RecurrenceFreq.UNKNOWN) {
            return listOf(event)
        }
        val interval = rec.interval.coerceAtLeast(1)
        val exDays = event.exDatesUtc
            .map { CalendarMath.localEpochDay(it.toEpochMilli(), offsetMinutes) }
            .toHashSet()

        val allDay = event.allDay && event.allDayDate != null
        val anchorDay: Long = if (allDay) {
            event.allDayDate!!.toEpochDay()
        } else {
            val startMillis = event.startAt?.toEpochMilli() ?: return listOf(event)
            CalendarMath.localEpochDay(startMillis, offsetMinutes)
        }
        val startMillis = event.startAt?.toEpochMilli() ?: 0L
        val durationMillis: Long =
            if (allDay) 0L else (event.endAt?.toEpochMilli() ?: startMillis) - startMillis
        val untilDay: Long? = rec.untilUtc?.let { CalendarMath.localEpochDay(it.toEpochMilli(), offsetMinutes) }

        val occurrenceDays = occurrenceDays(
            rec = rec,
            anchorDay = anchorDay,
            interval = interval,
            windowStartDay = windowStartDay,
            windowEndDayExclusive = windowEndDayExclusive,
            untilDay = untilDay,
        )

        val out = ArrayList<CalendarEvent>(occurrenceDays.size)
        for (day in occurrenceDays) {
            if (day in exDays) continue
            if (day == anchorDay) {
                out.add(event)
                continue
            }
            val shiftDays = day - anchorDay
            out.add(
                if (allDay) {
                    event.copy(allDayDate = event.allDayDate!!.plusDays(shiftDays))
                } else {
                    val newStart = startMillis + shiftDays * CalendarMath.MILLIS_PER_DAY
                    event.copy(
                        startAt = Instant.ofEpochMilli(newStart),
                        endAt = Instant.ofEpochMilli(newStart + durationMillis),
                    )
                },
            )
        }
        return out
    }

    private fun occurrenceDays(
        rec: Recurrence,
        anchorDay: Long,
        interval: Int,
        windowStartDay: Long,
        windowEndDayExclusive: Long,
        untilDay: Long?,
    ): List<Long> {
        val days = ArrayList<Long>()
        val count = rec.count
        when (rec.freq) {
            RecurrenceFreq.DAILY -> {
                var index = 0
                while (index < MAX_OCCURRENCES) {
                    if (count != null && index >= count) break
                    val day = anchorDay + index.toLong() * interval
                    if (untilDay != null && day > untilDay) break
                    if (day >= windowEndDayExclusive) break
                    if (day >= windowStartDay) days.add(day)
                    index++
                }
            }
            RecurrenceFreq.WEEKLY -> {
                val byDayIdx = rec.byDay
                    .mapNotNull { label -> ISO_BYDAY.indexOf(label.uppercase()).takeIf { it >= 0 } }
                    .ifEmpty { listOf(CalendarMath.dayOfWeekIso(anchorDay) - 1) }
                    .sorted()
                val anchorWeekStart = anchorDay - (CalendarMath.dayOfWeekIso(anchorDay) - 1)
                var emitted = 0
                var weekIndex = 0
                var stop = false
                while (weekIndex < MAX_OCCURRENCES && !stop) {
                    val weekStart = anchorWeekStart + weekIndex.toLong() * 7L * interval
                    if (weekStart >= windowEndDayExclusive + 7L) break
                    for (dow in byDayIdx) {
                        val day = weekStart + dow
                        if (day < anchorDay) continue
                        if (count != null && emitted >= count) { stop = true; break }
                        if (untilDay != null && day > untilDay) { stop = true; break }
                        emitted++
                        if (day in windowStartDay until windowEndDayExclusive) days.add(day)
                    }
                    weekIndex++
                }
            }
            RecurrenceFreq.MONTHLY -> {
                val ymd = CalendarMath.fromEpochDay(anchorDay)
                var index = 0
                while (index < MAX_OCCURRENCES) {
                    if (count != null && index >= count) break
                    val occ = CalendarMath.addMonths(ymd, index * interval)
                    val day = CalendarMath.toEpochDay(occ)
                    if (untilDay != null && day > untilDay) break
                    if (day >= windowEndDayExclusive) break
                    if (day >= windowStartDay) days.add(day)
                    index++
                }
            }
            RecurrenceFreq.YEARLY -> {
                val ymd = CalendarMath.fromEpochDay(anchorDay)
                var index = 0
                while (index < MAX_OCCURRENCES) {
                    if (count != null && index >= count) break
                    val occ = CalendarMath.addMonths(ymd, index * interval * 12)
                    val day = CalendarMath.toEpochDay(occ)
                    if (untilDay != null && day > untilDay) break
                    if (day >= windowEndDayExclusive) break
                    if (day >= windowStartDay) days.add(day)
                    index++
                }
            }
            RecurrenceFreq.UNKNOWN -> Unit
        }
        return days
    }
}
