package com.testlogon.android.feature.messaging.list

import com.testlogon.android.data.messaging.Conversation

/**
 * AND-121 — screen state for the conversation (inbox) list.
 *
 * `rows` are render-ready, sorted newest-first. The screen is a pure function of this state.
 */
data class ConversationRow(
    val id: String,
    val title: String,
    val iconUrl: String?,
    /** null -> "No messages yet" at render. */
    val preview: String?,
    /** Epoch SECONDS, formatted relative-to-now at render time. */
    val lastActivityEpochSeconds: Long,
    val unreadCount: Int,
) {
    val isUnread: Boolean get() = unreadCount > 0
}

sealed interface ConversationListUiState {
    data object Loading : ConversationListUiState
    data class Content(
        val rows: List<ConversationRow>,
        val isRefreshing: Boolean = false,
        val staleReason: StaleReason? = null,
    ) : ConversationListUiState
    data object Empty : ConversationListUiState
    data class Error(val message: String, val offline: Boolean) : ConversationListUiState
}

enum class StaleReason { OFFLINE, SERVER_ERROR }

internal fun Conversation.toRow(): ConversationRow = ConversationRow(
    id = id,
    title = title,
    iconUrl = iconUrl,
    preview = lastMessagePreview,
    lastActivityEpochSeconds = lastActivityEpochSeconds,
    unreadCount = unreadCount,
)
