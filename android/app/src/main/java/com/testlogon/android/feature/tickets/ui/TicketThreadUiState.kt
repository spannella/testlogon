package com.testlogon.android.feature.tickets.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.tickets.Ticket

/**
 * AND-372 - the exhaustive UI state for the READ-ONLY ticket THREAD (screen 3 of the 3-screen flow).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Loading] is the first-load spinner; [Content] carries the loaded ticket (with its embedded messages,
 * oldest-first) plus the viewer's own [currentSub] (so the bubble alignment can distinguish mine vs other by
 * sender_sub == currentSub) and an in-memory [isStale] flag (last-good kept on a refresh failure); [Empty] is a
 * loaded ticket with NO messages; [Error] carries the [ApiError] for the retry surface. A terminal 401 is NOT a
 * variant - it is emitted as a one-shot [TicketsEffect.NavigateToLogin].
 */
sealed interface TicketThreadUiState {

    data object Loading : TicketThreadUiState

    data class Content(
        val ticket: Ticket,
        val currentSub: String?,
        val isStale: Boolean = false,
    ) : TicketThreadUiState

    data object Empty : TicketThreadUiState

    data class Error(val error: ApiError) : TicketThreadUiState
}
