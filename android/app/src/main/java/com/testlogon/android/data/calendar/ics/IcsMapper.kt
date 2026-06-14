package com.testlogon.android.data.calendar.ics

import com.testlogon.android.data.calendar.CalendarEvent
import com.testlogon.android.data.calendar.Recurrence
import com.testlogon.android.data.calendar.RecurrenceFreq
import com.testlogon.android.feature.calendar.CalendarMath

/**
 * AND-276 — PURE mapper: domain [CalendarEvent] -> [IcsEvent] for the [Rfc5545IcsSerializer]. JVM-only
 * (no java.time / Android): Instant epoch millis are read via [java.time.Instant.toEpochMilli] only at
 * the boundary; all RRULE / EXDATE / status logic is pure string/int work and individually unit-tested.
 *
 * The RRULE value is built from the STRUCTURED domain [Recurrence] (there is no raw rrule on the wire);
 * `exdates_utc` becomes a single EXDATE line; the free-form server status normalizes to [IcsStatus].
 */
object IcsMapper {

    /** Opaque, PII-free UID domain suffix (matches the spec's `evt_…@testlogon.android` shape). */
    const val UID_DOMAIN = "testlogon.android"

    /**
     * Adapts an [event] to an [IcsEvent]. [publicUrl] is the canonical public App Link (the ICS URL
     * line); pass null to omit. All-day events use [CalendarEvent.allDayDate] (mapped to an epoch day via
     * [CalendarMath]); timed events use [CalendarEvent.startAt]/[CalendarEvent.endAt].
     */
    fun toIcsEvent(event: CalendarEvent, publicUrl: String?): IcsEvent {
        // LocalDate.toEpochDay() is a desugared member (mirrors CalendarViewModel's usage); the
        // serializer renders it back to YYYYMMDD via CalendarMath.fromEpochDay (pure, no java.time).
        val allDayEpochDay = event.allDayDate?.toEpochDay()
        return IcsEvent(
            uid = "${event.eventId}@$UID_DOMAIN",
            summary = event.name,
            description = event.description.takeIf { it.isNotBlank() },
            url = publicUrl?.takeIf { it.isNotBlank() },
            startEpochMillis = if (event.allDay) null else event.startAt?.toEpochMilli(),
            endEpochMillis = if (event.allDay) null else event.endAt?.toEpochMilli(),
            allDay = event.allDay,
            allDayEpochDay = allDayEpochDay,
            rrule = event.recurrence?.let { buildRrule(it) },
            exDatesEpochMillis = event.exDatesUtc.map { it.toEpochMilli() },
            status = normalizeStatus(event.status),
        )
    }

    /**
     * Serializes a structured [Recurrence] into an RFC 5545 RRULE value (e.g.
     * "FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE;COUNT=8"). UNTIL takes a UTC date-time; COUNT and UNTIL are
     * mutually exclusive in RFC 5545, so UNTIL wins when both are present. Returns null for an UNKNOWN
     * freq (the rule is unrepresentable rather than emitting an invalid RRULE).
     */
    fun buildRrule(recurrence: Recurrence): String? {
        val freq = when (recurrence.freq) {
            RecurrenceFreq.DAILY -> "DAILY"
            RecurrenceFreq.WEEKLY -> "WEEKLY"
            RecurrenceFreq.MONTHLY -> "MONTHLY"
            RecurrenceFreq.UNKNOWN -> return null
        }
        val parts = ArrayList<String>()
        parts += "FREQ=$freq"
        if (recurrence.interval > 1) parts += "INTERVAL=${recurrence.interval}"
        if (recurrence.byDay.isNotEmpty()) parts += "BYDAY=${recurrence.byDay.joinToString(",")}"
        if (recurrence.byMonthDay.isNotEmpty()) {
            parts += "BYMONTHDAY=${recurrence.byMonthDay.joinToString(",")}"
        }
        if (recurrence.bySetPos.isNotEmpty()) parts += "BYSETPOS=${recurrence.bySetPos.joinToString(",")}"
        // UNTIL and COUNT are mutually exclusive; prefer UNTIL when both are present.
        when {
            recurrence.untilUtc != null -> parts += "UNTIL=${formatUtcBasic(recurrence.untilUtc.toEpochMilli())}"
            recurrence.count != null -> parts += "COUNT=${recurrence.count}"
        }
        return parts.joinToString(";")
    }

    /** Maps the free-form server status to a normalized [IcsStatus] (default CONFIRMED). */
    fun normalizeStatus(status: String): IcsStatus = when (status.trim().lowercase()) {
        "cancelled", "canceled" -> IcsStatus.CANCELLED
        "tentative", "pending", "open" -> IcsStatus.TENTATIVE
        else -> IcsStatus.CONFIRMED
    }

    // Local pure UTC formatter for UNTIL (same shape as the serializer; kept here to keep the mapper
    // self-contained for unit tests). YYYYMMDDTHHMMSSZ.
    private fun formatUtcBasic(epochMillis: Long): String {
        val epochDay = Math.floorDiv(epochMillis, CalendarMath.MILLIS_PER_DAY)
        val msOfDay = Math.floorMod(epochMillis, CalendarMath.MILLIS_PER_DAY)
        val secOfDay = (msOfDay / 1000L).toInt()
        val ymd = CalendarMath.fromEpochDay(epochDay)
        fun two(v: Int) = if (v < 10) "0$v" else v.toString()
        val date = ymd.year.toString().padStart(4, '0') + two(ymd.month) + two(ymd.day)
        return date + "T" + two(secOfDay / 3600) + two((secOfDay % 3600) / 60) + two(secOfDay % 60) + "Z"
    }
}
