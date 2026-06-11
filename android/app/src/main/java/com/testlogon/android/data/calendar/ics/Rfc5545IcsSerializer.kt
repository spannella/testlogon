package com.testlogon.android.data.calendar.ics

import com.testlogon.android.feature.calendar.CalendarMath
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-276 — PURE RFC 5545 (iCalendar) serializer. No Android, no java.time (API 26+), no
 * android.text.format: timestamps are formatted from UTC epoch millis via pure proleptic-Gregorian
 * arithmetic (reusing the project's [CalendarMath] epoch-day math), so output is identical on any JVM
 * regardless of the host default timezone — fully JVM-unit-testable.
 *
 * Emits CRLF line endings, a VCALENDAR wrapper (VERSION:2.0 / PRODID / CALSCALE:GREGORIAN), and one
 * VEVENT per input. TEXT values are escaped per RFC 5545 section 3.3.11 (backslash, semicolon, comma,
 * newline) and content lines are folded at 75 OCTETS (UTF-8 aware — a fold never splits a multibyte
 * sequence), per section 3.1. Timed events emit UTC "...Z" DTSTART/DTEND; all-day events emit
 * DTSTART;VALUE=DATE / DTEND;VALUE=DATE (the day after). Recurring events emit RRULE and one EXDATE
 * line; STATUS is the normalized value.
 *
 * Timezone note: this serializer intentionally emits UTC instants only (no VTIMEZONE/TZID block). The
 * verified domain stores absolute instants and an IANA zone name for DISPLAY; importers handle UTC
 * losslessly, which is the spec's default path. (A per-event VTIMEZONE block would require an embedded
 * tzdb and is out of scope for the pure path.)
 */
@Singleton
class Rfc5545IcsSerializer @Inject constructor() {

    /** Returns a complete VCALENDAR document (CRLF line endings) for [events]. */
    fun serialize(events: List<IcsEvent>): String {
        val lines = ArrayList<String>()
        lines += "BEGIN:VCALENDAR"
        lines += "VERSION:2.0"
        lines += "PRODID:$PRODID"
        lines += "CALSCALE:GREGORIAN"
        for (event in events) appendVEvent(lines, event)
        lines += "END:VCALENDAR"
        // Fold each content line, join with CRLF, and terminate with a trailing CRLF.
        return lines.joinToString(separator = CRLF, postfix = CRLF) { foldLine(it) }
    }

    private fun appendVEvent(out: MutableList<String>, event: IcsEvent) {
        require(event.uid.isNotBlank()) { "ICS event requires a non-blank UID" }
        out += "BEGIN:VEVENT"
        out += "UID:${escapeText(event.uid)}"
        out += "DTSTAMP:${formatUtc(dtStampMillis(event))}"
        appendStartEnd(out, event)
        out += "SUMMARY:${escapeText(event.summary)}"
        event.description?.takeIf { it.isNotEmpty() }?.let { out += "DESCRIPTION:${escapeText(it)}" }
        event.url?.takeIf { it.isNotEmpty() }?.let { out += "URL:${escapeText(it)}" }
        event.rrule?.takeIf { it.isNotBlank() }?.let { out += "RRULE:$it" }
        if (event.exDatesEpochMillis.isNotEmpty()) {
            out += "EXDATE:${event.exDatesEpochMillis.joinToString(",") { formatUtc(it) }}"
        }
        out += "STATUS:${event.status.ics}"
        out += "END:VEVENT"
    }

    private fun appendStartEnd(out: MutableList<String>, event: IcsEvent) {
        if (event.allDay) {
            val startDay = requireNotNull(event.allDayEpochDay) {
                "All-day ICS event requires allDayEpochDay"
            }
            out += "DTSTART;VALUE=DATE:${formatDate(startDay)}"
            // DTEND for an all-day event is the EXCLUSIVE next day (RFC 5545), avoiding off-by-one.
            out += "DTEND;VALUE=DATE:${formatDate(startDay + 1L)}"
        } else {
            val start = requireNotNull(event.startEpochMillis) {
                "Timed ICS event requires startEpochMillis"
            }
            out += "DTSTART:${formatUtc(start)}"
            event.endEpochMillis?.let { out += "DTEND:${formatUtc(it)}" }
        }
    }

    private fun dtStampMillis(event: IcsEvent): Long =
        event.startEpochMillis
            ?: event.allDayEpochDay?.let { it * CalendarMath.MILLIS_PER_DAY }
            ?: 0L

    // ---- pure UTC formatting (no java.time / SimpleDateFormat) ----

    /** Formats UTC epoch millis as RFC 5545 date-time `YYYYMMDDTHHMMSSZ`. */
    internal fun formatUtc(epochMillis: Long): String {
        val epochDay = Math.floorDiv(epochMillis, CalendarMath.MILLIS_PER_DAY)
        val msOfDay = Math.floorMod(epochMillis, CalendarMath.MILLIS_PER_DAY)
        val secOfDay = (msOfDay / 1000L).toInt()
        val hh = secOfDay / 3600
        val mm = (secOfDay % 3600) / 60
        val ss = secOfDay % 60
        return formatDate(epochDay) + "T" + two(hh) + two(mm) + two(ss) + "Z"
    }

    /** Formats an epoch day as RFC 5545 date `YYYYMMDD`. */
    internal fun formatDate(epochDay: Long): String {
        val ymd = CalendarMath.fromEpochDay(epochDay)
        return four(ymd.year) + two(ymd.month) + two(ymd.day)
    }

    // ---- escaping & folding ----

    /** Escapes a TEXT value per RFC 5545 section 3.3.11. Backslash FIRST so it is not double-escaped. */
    internal fun escapeText(value: String): String {
        val sb = StringBuilder(value.length + 8)
        for (ch in value) {
            when (ch) {
                '\\' -> sb.append("\\\\")
                ';' -> sb.append("\\;")
                ',' -> sb.append("\\,")
                '\n' -> sb.append("\\n")
                '\r' -> { /* drop bare CR; a CRLF becomes a single \n via the \n branch */ }
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }

    /**
     * Folds one content line to <=75 OCTETS per line (UTF-8), inserting CRLF + a single leading space at
     * each fold. A fold boundary never splits a multibyte UTF-8 sequence. The continuation space counts
     * toward the 75-octet budget of continuation lines (so they carry <=74 octets of content).
     */
    internal fun foldLine(line: String): String {
        val bytes = line.toByteArray(Charsets.UTF_8)
        if (bytes.size <= MAX_OCTETS) return line
        val sb = StringBuilder(bytes.size + bytes.size / MAX_OCTETS + 8)
        var index = 0
        var first = true
        while (index < bytes.size) {
            val budget = if (first) MAX_OCTETS else MAX_OCTETS - 1
            var take = minOf(budget, bytes.size - index)
            // Back off so we do not split a UTF-8 continuation byte (10xxxxxx).
            while (take > 0 && index + take < bytes.size &&
                (bytes[index + take].toInt() and 0xC0) == 0x80
            ) {
                take--
            }
            if (take <= 0) take = 1 // defensive; should not happen for valid UTF-8
            if (!first) sb.append(CRLF).append(' ')
            sb.append(String(bytes, index, take, Charsets.UTF_8))
            index += take
            first = false
        }
        return sb.toString()
    }

    private fun two(v: Int): String = if (v < 10) "0$v" else v.toString()

    private fun four(v: Int): String = when {
        v >= 1000 -> v.toString()
        v >= 0 -> v.toString().padStart(4, '0')
        else -> v.toString()
    }

    companion object {
        const val PRODID = "-//com.testlogon.android//TestLogon//EN"
        const val CRLF = "\r\n"
        const val MAX_OCTETS = 75
    }
}
