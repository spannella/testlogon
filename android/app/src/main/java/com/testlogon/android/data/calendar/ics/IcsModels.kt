package com.testlogon.android.data.calendar.ics

/**
 * AND-276 — input model for the pure RFC 5545 ICS serializer.
 *
 * All timestamps are UTC epoch milliseconds ([Long]) so the serializer (and its JVM unit tests) never
 * touch java.time (API 26+) nor any Android type. All-day events carry an [allDayEpochDay] (days since
 * 1970-01-01, computed by the mapper via the project's pure [com.testlogon.android.feature.calendar.CalendarMath])
 * and omit the timestamps. The recurrence/exdate values are pre-serialized RFC 5545 strings built by the
 * mapper from the structured domain [com.testlogon.android.data.calendar.Recurrence].
 */
data class IcsEvent(
    val uid: String,
    val summary: String,
    val description: String? = null,
    val url: String? = null,
    /** Start instant (UTC epoch millis); null only for all-day events (use [allDayEpochDay]). */
    val startEpochMillis: Long? = null,
    /** End instant (UTC epoch millis); null when absent / all-day. */
    val endEpochMillis: Long? = null,
    val allDay: Boolean = false,
    /** All-day start day (days since 1970-01-01); the event's single date. Required when [allDay]. */
    val allDayEpochDay: Long? = null,
    /** RFC 5545 RRULE value (e.g. "FREQ=WEEKLY;BYDAY=MO;COUNT=8"); null when not recurring. */
    val rrule: String? = null,
    /** Excluded occurrence instants (UTC epoch millis) -> EXDATE; empty when none. */
    val exDatesEpochMillis: List<Long> = emptyList(),
    val status: IcsStatus = IcsStatus.CONFIRMED,
)

/** Normalized VEVENT STATUS. The mapper folds the free-form server status string into one of these. */
enum class IcsStatus(val ics: String) {
    CONFIRMED("CONFIRMED"),
    TENTATIVE("TENTATIVE"),
    CANCELLED("CANCELLED"),
}
