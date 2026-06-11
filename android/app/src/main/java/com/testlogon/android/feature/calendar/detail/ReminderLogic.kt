package com.testlogon.android.feature.calendar.detail

/**
 * AND-276 — PURE, JVM-testable reminder logic for the event-detail "Add reminder" action.
 *
 * No Android, no java.time: everything is Long epoch milliseconds and minute math, so the trigger-time
 * computation, the past-event guard, and the preset table are deterministic and unit-testable. The
 * actual scheduling (device calendar reminder via CalendarContract, or a notification alarm) is a
 * side-effecting seam in [EventIntents]; this object owns only the decisions.
 */
object ReminderLogic {

    private const val MILLIS_PER_MINUTE = 60_000L

    /** Lead-time presets offered in the UI (FR-4). [minutes] is the lead before the event start. */
    enum class Lead(val minutes: Int) {
        AT_START(0),
        FIVE_MIN(5),
        FIFTEEN_MIN(15),
        THIRTY_MIN(30),
        ONE_HOUR(60),
        ONE_DAY(60 * 24),
    }

    /** The default preset when no persisted preference exists. */
    val DEFAULT_LEAD: Lead = Lead.THIRTY_MIN

    /** The notification trigger instant (epoch millis): event start minus the lead. */
    fun triggerEpochMillis(eventStartEpochMillis: Long, lead: Lead): Long =
        eventStartEpochMillis - lead.minutes.toLong() * MILLIS_PER_MINUTE

    /**
     * Whether a reminder can be scheduled: the event must have a known start that is strictly in the
     * future relative to [nowEpochMillis] (FR-6 — past events disable the action). All-day events with
     * no start instant cannot carry a timed reminder here.
     */
    fun canSchedule(eventStartEpochMillis: Long?, nowEpochMillis: Long): Boolean =
        eventStartEpochMillis != null && eventStartEpochMillis > nowEpochMillis

    /** Resolves a persisted lead-minutes preference back to a [Lead], falling back to [DEFAULT_LEAD]. */
    fun leadFromMinutes(minutes: Int?): Lead =
        Lead.entries.firstOrNull { it.minutes == minutes } ?: DEFAULT_LEAD
}
