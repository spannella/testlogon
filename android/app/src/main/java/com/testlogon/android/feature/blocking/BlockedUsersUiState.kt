package com.testlogon.android.feature.blocking

import com.testlogon.android.core.model.blocking.BlockedUser

/**
 * P0-BLOCK — exhaustive UI state for the Blocked Users management screen.
 *
 * Sealed so the screen renders mutually-exclusive surfaces, mirroring the API-keys list playbook.
 * [Loading] is the first-load spinner; [Content] carries the blocked list plus an in-memory [isStale]
 * flag (last-good kept on a refresh failure) and an [isRefreshing] flag; [Empty] is the zero-blocked
 * state; [Error] carries the message for the retry surface. [unblockingId] is the user id whose
 * unblock is in flight (its row shows a spinner + disables actions). [pendingUnblock] holds the user
 * staged for the confirm dialog (null = dialog closed). [actionError] is a transient per-action error.
 */
sealed interface BlockedUsersUiState {

    data object Loading : BlockedUsersUiState

    data class Content(
        val items: List<BlockedUser>,
        val isStale: Boolean = false,
        val isRefreshing: Boolean = false,
        val unblockingId: String? = null,
        val pendingUnblock: BlockedUser? = null,
        val actionError: String? = null,
    ) : BlockedUsersUiState

    data object Empty : BlockedUsersUiState

    data class Error(val message: String, val retryable: Boolean) : BlockedUsersUiState
}

/** One-shot effects for the Blocked Users screen (Channel-backed, not replayed on rotation). */
sealed interface BlockedUsersEffect {
    /** A transient, non-blocking message (e.g. "Couldn't update — tap to retry"). */
    data class ShowMessage(val resId: Int) : BlockedUsersEffect
}
