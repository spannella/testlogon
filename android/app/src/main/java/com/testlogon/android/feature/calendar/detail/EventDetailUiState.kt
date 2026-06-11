package com.testlogon.android.feature.calendar.detail

import com.testlogon.android.data.calendar.CalendarEvent

/**
 * AND-272 — UI state for the event detail screen. Distinguishes not-found / forbidden as dedicated
 * terminal states (FR-6); transient errors keep a Retry affordance.
 */
sealed interface EventDetailUiState {
    data object Loading : EventDetailUiState

    data class Content(
        val event: CalendarEvent,
        val displayZoneId: String,
        val deviceZoneId: String,
        val zoneMismatch: Boolean,
        val isPublic: Boolean,
        val publicShareUrl: String,
    ) : EventDetailUiState

    /** 404 / 422-for-display — the event is missing or the link expired. */
    data object Unavailable : EventDetailUiState

    /** 403 — the event is private. */
    data object Forbidden : EventDetailUiState

    /** Transient network/server error with a working Retry. */
    data class Error(val message: String, val offline: Boolean = false) : EventDetailUiState
}
