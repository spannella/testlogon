package com.testlogon.android.feature.calendar

/**
 * AND-271 — UI state for the calendar screen. Loading / Content / Empty / Error, with the resolved
 * display zone and a zone-mismatch flag for the banner.
 */
sealed interface CalendarUiState {
    data object Loading : CalendarUiState

    data class Content(
        val mode: CalendarViewMode,
        val focusEpochDay: Long,
        val displayZoneId: String,
        val deviceZoneId: String,
        val zoneMismatch: Boolean,
        val monthDays: List<DaySlots>,
        val weekGrid: WeekGrid?,
        val agendaDays: List<DaySlots>,
        val isEmpty: Boolean,
    ) : CalendarUiState

    data class Error(
        val message: String,
        val offline: Boolean = false,
    ) : CalendarUiState
}
