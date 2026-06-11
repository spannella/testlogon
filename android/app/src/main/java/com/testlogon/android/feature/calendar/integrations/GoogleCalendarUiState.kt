package com.testlogon.android.feature.calendar.integrations

import com.testlogon.android.data.calendar.Calendar
import com.testlogon.android.data.gcal.ProviderCalendar

/**
 * AND-273 — UI state for the Google Calendar Connect screen (one-of: Loading / Disconnected /
 * Connecting / Connected / Error). The Connected state lists the flat Google provider calendars plus the
 * AND-270 internal calendars for the per-row mapping picker.
 */
sealed interface GoogleCalendarUiState {
    data object Loading : GoogleCalendarUiState

    data class Disconnected(val message: String? = null) : GoogleCalendarUiState

    /** Transient: the Custom Tab is open / status is being re-read after return. */
    data object Connecting : GoogleCalendarUiState

    data class Connected(
        val accountEmail: String?,
        val calendars: List<ProviderCalendar>,
        val internalCalendars: List<Calendar>,
        val listState: ListState,
        val reauthRequired: Boolean,
        val stale: Boolean,
        val syncRunning: Boolean = false,
    ) : GoogleCalendarUiState

    data class Error(val message: String, val isOffline: Boolean) : GoogleCalendarUiState
}

/** The provider-calendar list sub-state inside Connected. */
enum class ListState { LOADING, LOADED, EMPTY, ERROR }

/** One-shot effects (never state) consumed by the composable: open the Custom Tab / show a snackbar. */
sealed interface GoogleCalendarEffect {
    data class OpenCustomTab(val authorizationUrl: String) : GoogleCalendarEffect
    data class ShowMessage(val message: String) : GoogleCalendarEffect
}
