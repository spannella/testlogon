package com.testlogon.android.feature.broadcast.moderation

import com.testlogon.android.data.broadcast.chat.ChatMessage

/**
 * AND-313 - presentation contract for chat moderation: the open moderation sheet, in-flight action keys, the
 * one-shot event (snackbar), and the currently pinned message banner state.
 */
data class ModerationUiState(
    /** The open moderation sheet (a message sheet or a user sheet), or null when none is open. */
    val sheet: ModerationSheet? = null,
    /** Keys of in-flight optimistic actions, e.g. "mute:usr_9", "delete:cm_1", "pin:cm_3". */
    val inFlight: Set<String> = emptySet(),
    /** One-shot event surfaced as a snackbar; cleared via consumeEvent(). */
    val event: ModerationEvent? = null,
    /** The currently pinned message (drives the PinnedMessageBanner atop the chat panel), or null. */
    val pinnedMessage: ChatMessage? = null,
)

/** Which moderation sheet is open. */
sealed interface ModerationSheet {
    /** Message-scoped actions (delete / pin-or-unpin / moderate author). */
    data class Message(val message: ChatMessage) : ModerationSheet

    /** User-scoped actions (mute / ban / unban). [displayName] is best-effort for the sheet header. */
    data class User(val userId: String, val displayName: String) : ModerationSheet
}

/** A one-shot moderation outcome surfaced to the user (snackbar). */
sealed interface ModerationEvent {
    data class Success(val action: ModerationActionType) : ModerationEvent
    data class Failure(val message: String) : ModerationEvent

    /** A 403 (or 401) auth error: controls should hide; the user is not (or no longer) a moderator. */
    data object AuthDenied : ModerationEvent
}

/** Loadable state for the moderation-log surface (one-shot load + pull-to-refresh; NO paging, NO poll). */
sealed interface ModerationLogUiState {
    data object Loading : ModerationLogUiState
    data class Content(
        val entries: List<ModerationLogEntry>,
        val bans: List<ModerationBan>,
        val isRefreshing: Boolean = false,
    ) : ModerationLogUiState

    data object Empty : ModerationLogUiState
    data class Error(val message: String, val offline: Boolean = false) : ModerationLogUiState
}
