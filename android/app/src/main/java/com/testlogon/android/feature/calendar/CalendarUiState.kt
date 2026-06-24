package com.testlogon.android.feature.calendar

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
)
