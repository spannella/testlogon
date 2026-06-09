package com.testlogon.android.feature.messaging.thread

import com.testlogon.android.data.messaging.SendStatus

/**
 * AND-123 / AND-124 — thread (message list) UI state.
 *
 * `messages` is oldest-first (rendered with the newest at the bottom). Each [ThreadMessageUi] knows
 * whether it is the current user's (for sent/received bubble alignment), derived from the current
 * user_sub vs the message sender_id.
 */
data class ThreadUiState(
    val conversationId: String,
    val title: String = "",
    val messages: List<ThreadMessageUi> = emptyList(),
    val isLoadingInitial: Boolean = true,
    val isLoadingOlder: Boolean = false,
    val endOfHistory: Boolean = false,
    val errorMessage: String? = null,
    val composer: ComposerState = ComposerState(),
)

data class ThreadMessageUi(
    /** Stable list key: server message id when present, else the local clientId. */
    val key: String,
    val text: String,
    val isOwn: Boolean,
    val createdAtEpochSeconds: Long,
    val sendStatus: SendStatus,
) {
    val isFailed: Boolean get() = sendStatus == SendStatus.FAILED
    val isSending: Boolean get() = sendStatus == SendStatus.SENDING
}

data class ComposerState(
    val draft: String = "",
    val charCount: Int = 0,
    val overLimit: Boolean = false,
) {
    val isSendEnabled: Boolean get() = draft.isNotBlank() && !overLimit

    companion object {
        const val MAX_LENGTH = 4000
    }
}
