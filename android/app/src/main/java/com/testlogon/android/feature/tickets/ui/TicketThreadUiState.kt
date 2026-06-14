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
 * read-only ticket with NO messages; [Error] carries the [ApiError] for the retry surface. A terminal 401 is NOT
 * a variant - it is emitted as a one-shot [TicketsEffect.NavigateToLogin].
 *
 * AND-373 - [Content] now also carries the REPLY composer state ([composer]). When a ticket has no messages
 * BUT the viewer canPost (editor / owner + non-terminal), the screen renders [Content] (so the composer shows)
 * rather than [Empty] - [Empty] remains the truly read-only no-messages surface.
 */
sealed interface TicketThreadUiState {

    data object Loading : TicketThreadUiState

    data class Content(
        val ticket: Ticket,
        val currentSub: String?,
        val isStale: Boolean = false,
        val composer: ComposerState = ComposerState(),
    ) : TicketThreadUiState

    data object Empty : TicketThreadUiState

    data class Error(val error: ApiError) : TicketThreadUiState
}

/**
 * AND-373 - the ticket REPLY composer state (TEXT only). [canPost] is ADVISORY (editor / owner member AND a
 * non-terminal ticket status; the server 403 is authoritative). [sending] guards a double-send of the same
 * in-flight draft and disables the input. [sendError] is a general (non-field) error banner; [fieldError] is a
 * 422 body-field error pinned under the input. The send button is enabled only when [canPost], the trimmed
 * [draft] is within 1..[maxLength], and not [sending] (see [sendEnabled]).
 */
data class ComposerState(
    val draft: String = "",
    val sending: Boolean = false,
    val canPost: Boolean = false,
    val sendError: String? = null,
    val fieldError: String? = null,
    val maxLength: Int = 4000,
) {
    /** The trimmed draft length used for validation + the char counter. */
    val trimmedLength: Int get() = draft.trim().length

    /** True when the trimmed draft exceeds [maxLength] (the counter / button reflect this). */
    val overLimit: Boolean get() = trimmedLength > maxLength

    /** The send affordance is enabled only when posting is allowed, the draft is in 1..maxLength, and idle. */
    val sendEnabled: Boolean get() = canPost && !sending && trimmedLength in 1..maxLength
}
