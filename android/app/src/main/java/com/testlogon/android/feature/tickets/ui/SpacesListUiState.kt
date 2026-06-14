package com.testlogon.android.feature.tickets.ui

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.tickets.TicketSpace

/**
 * AND-372 - the exhaustive UI state for the READ-ONLY ticket-spaces LIST (screen 1 of the 3-screen flow).
 *
 * Sealed so the screen renders mutually-exclusive surfaces; a new variant forces an exhaustive `when`.
 * [Loading] is the first-load spinner; [Content] carries the spaces plus an in-memory [isStale] flag (last-good
 * kept on a refresh failure - FR-6 stale banner) and an [isRefreshing] flag (pull-to-refresh spinner); [Empty]
 * is the zero-spaces state; [Error] carries the [ApiError] for the retry surface. A terminal 401 is NOT a
 * variant here - it is emitted as a one-shot [TicketsEffect.NavigateToLogin].
 */
sealed interface SpacesListUiState {

    data object Loading : SpacesListUiState

    data class Content(
        val spaces: List<TicketSpace>,
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
    ) : SpacesListUiState

    data object Empty : SpacesListUiState

    data class Error(val error: ApiError) : SpacesListUiState
}

/**
 * AND-372 - one-shot navigation effects shared by the tickets ViewModels.
 *
 * [NavigateToLogin] is emitted on a TERMINAL 401 (ApiError.status == 401, after the shared client's one auth
 * refresh) so the screen routes to the login / unauthenticated graph (re-auth handoff) instead of rendering a
 * generic error. Delivered via a Channel (one-shot, never re-delivered on rotation).
 */
sealed interface TicketsEffect {
    data object NavigateToLogin : TicketsEffect
}
