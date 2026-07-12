package com.testlogon.android.feature.calendar

import com.testlogon.android.data.calendar.RecurrenceFreq

/**
 * AND-271 / SC19 — UI state for the calendar screen. Loading / Content / Error, with the resolved
 * display zone, a zone-mismatch flag for the banner, the period header label, weekday headers, the
 * "today" anchor for highlighting, the Day-view bucket, and the add/edit event editor state.
 */
sealed interface CalendarUiState {
    data object Loading : CalendarUiState

    data class Content(
        val mode: CalendarViewMode,
        val focusEpochDay: Long,
        val todayEpochDay: Long,
        val headerLabel: String,
        val weekdayHeaders: List<String>,
        val displayZoneId: String,
        val deviceZoneId: String,
        val zoneMismatch: Boolean,
        val monthDays: List<DaySlots>,
        val weekGrid: WeekGrid?,
        val agendaDays: List<DaySlots>,
        /** Day-view bucket (events on [focusEpochDay]); empty in other modes. */
        val dayEvents: List<SlottedEvent> = emptyList(),
        val isEmpty: Boolean,
        /** True when at least one calendar exists so add/edit is allowed. */
        val canAddEvents: Boolean = false,
        /** Non-null while the add/edit dialog is open. */
        val editor: EventEditorState? = null,
        /** Non-null while the long-press event action sheet is open. */
        val actionSheet: EventActionSheet? = null,
        /** #13 - non-null while the "delete a recurring event" choice dialog is open. */
        val recurringDelete: RecurringDeletePrompt? = null,
    ) : CalendarUiState

    data class Error(
        val message: String,
        val offline: Boolean = false,
    ) : CalendarUiState
}

/** SC19 — the add/edit event form state (pure; UI binds directly to it). */
data class EventEditorState(
    /** Null = creating a new event; non-null = editing this event. */
    val eventId: String?,
    val calendarId: String,
    val calendarOptions: List<CalendarOption>,
    val name: String = "",
    val description: String = "",
    val allDay: Boolean = false,
    /** The day the event lives on (epoch day). */
    val epochDay: Long,
    /** "HH:MM" 24h local start/end for timed events. */
    val startTime: String = "09:00",
    val endTime: String = "10:00",
    /** SC19 #10 — IANA timezone the start/end times are interpreted in (default = device zone). */
    val timezone: String = "UTC",
    /** Available timezones for the picker (device zone first, then a common set). */
    val timezoneOptions: List<String> = emptyList(),
    /** SC19 #9 — recurrence frequency; null = does not repeat. */
    val recurrenceFreq: RecurrenceFreq? = null,
    /** Recurrence interval (every N days/weeks/months/years); >=1. */
    val recurrenceInterval: Int = 1,
    /** Optional "ends after N occurrences"; null = no end. */
    val recurrenceCount: Int? = null,
    /**
     * #12 - WEEKLY BYDAY weekday selection (ISO codes MO,TU,WE,TH,FR,SA,SU). Empty = "use the start
     * day" (the backend defaults BYDAY to the series start weekday). Only meaningful when freq=WEEKLY.
     */
    val recurrenceByDay: List<String> = emptyList(),
    val saving: Boolean = false,
    val nameError: Boolean = false,
) {
    val isEditing: Boolean get() = eventId != null
}

/** A selectable calendar in the editor dropdown. */
data class CalendarOption(val calendarId: String, val name: String)

/** SC19 — the per-event action sheet (Edit / Delete) opened on long-press. */
data class EventActionSheet(
    val calendarId: String,
    val eventId: String,
    val title: String,
    /** #13 - ISO-8601 UTC start of the long-pressed occurrence (for the recurring-delete choices). */
    val occurrenceStartUtc: String,
    /** #13 - true when the underlying event has a recurrence rule (gates the delete-choice dialog). */
    val recurring: Boolean = false,
)

/**
 * #13 - the "delete a recurring event" choice prompt. Carries the tapped occurrence's UTC start
 * (ISO-8601) so the VM can EXDATE just this occurrence or set the series UNTIL to before it. Only shown
 * for events that actually recur; a non-recurring event deletes directly.
 */
data class RecurringDeletePrompt(
    val calendarId: String,
    val eventId: String,
    val title: String,
    /** ISO-8601 UTC start of the tapped occurrence (the EXDATE key / the UNTIL boundary). */
    val occurrenceStartUtc: String,
)
