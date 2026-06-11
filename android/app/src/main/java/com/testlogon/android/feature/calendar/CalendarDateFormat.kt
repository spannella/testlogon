package com.testlogon.android.feature.calendar

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * AND-271/AND-272 — PURE display formatting for calendar UI. Uses java.text.SimpleDateFormat/Date
 * (JVM-safe, available on all API levels) rather than java.time formatters, so it is fully
 * JVM-unit-testable. Takes a UTC epoch-millis + an IANA zone id and renders in that zone. All-day
 * rendering takes an epoch day and never shifts across zones.
 *
 * No date FORMAT strings are hardcoded for the user-facing parts beyond locale-aware patterns; the
 * caller passes [Locale]/[TimeZone] so output respects the effective display zone and locale.
 */
object CalendarDateFormat {

    /** "Jun 10, 2026" style medium date in [zoneId]. */
    fun formatDate(utcMillis: Long, zoneId: String, locale: Locale = Locale.getDefault()): String {
        val fmt = SimpleDateFormat("MMM d, yyyy", locale).apply { timeZone = tz(zoneId) }
        return fmt.format(Date(utcMillis))
    }

    /** "9:30 AM" style short time in [zoneId]. */
    fun formatTime(utcMillis: Long, zoneId: String, locale: Locale = Locale.getDefault()): String {
        val fmt = SimpleDateFormat("h:mm a", locale).apply { timeZone = tz(zoneId) }
        return fmt.format(Date(utcMillis))
    }

    /** "Jun 10, 2026, 9:30 AM" combined date + time in [zoneId]. */
    fun formatDateTime(utcMillis: Long, zoneId: String, locale: Locale = Locale.getDefault()): String =
        "${formatDate(utcMillis, zoneId, locale)}, ${formatTime(utcMillis, zoneId, locale)}"

    /**
     * A start-end range. Same-day timed events render "Jun 10, 2026, 9:30 AM - 10:00 AM"; multi-day
     * render the full date-time on both sides.
     */
    fun formatRange(
        startMillis: Long,
        endMillis: Long,
        zoneId: String,
        locale: Locale = Locale.getDefault(),
    ): String {
        val startDate = formatDate(startMillis, zoneId, locale)
        val endDate = formatDate(endMillis, zoneId, locale)
        return if (startDate == endDate) {
            "$startDate, ${formatTime(startMillis, zoneId, locale)} - ${formatTime(endMillis, zoneId, locale)}"
        } else {
            "${formatDateTime(startMillis, zoneId, locale)} - ${formatDateTime(endMillis, zoneId, locale)}"
        }
    }

    /** An all-day date rendered from its anchored epoch day (UTC midnight), never zone-shifted. */
    fun formatAllDay(epochDay: Long, locale: Locale = Locale.getDefault()): String {
        val utcMidnight = epochDay * CalendarMath.MILLIS_PER_DAY
        return formatDate(utcMidnight, "UTC", locale)
    }

    /** "June 2026" month-year label in [zoneId]. */
    fun formatMonthYear(utcMillis: Long, zoneId: String, locale: Locale = Locale.getDefault()): String {
        val fmt = SimpleDateFormat("MMMM yyyy", locale).apply { timeZone = tz(zoneId) }
        return fmt.format(Date(utcMillis))
    }

    private fun tz(zoneId: String): TimeZone = TimeZone.getTimeZone(zoneId)
}
