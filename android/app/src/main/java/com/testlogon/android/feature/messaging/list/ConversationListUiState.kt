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
    /** FE-140 - muted_until epoch SECONDS (0 = not muted); rendered as a bell-off on the row. */
    val mutedUntil: Long = 0L,
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
    // FE-120 (EPIC C) — mask a reveal-wrapped last message so the raw TLRVL1 sentinel never
    // leaks into the inbox row; the inner content is never shown here (viewer-agnostic).
    // FE-130 (EPIC D) - mask a location-card last message so the raw TLLOC1 sentinel never leaks into
    // the inbox row; falls through the reveal mask, then to the server text preview.
    preview = com.testlogon.android.feature.messaging.LiveLocationModel.previewForBody(lastMessagePreview)
        ?: com.testlogon.android.feature.messaging.LocationCardModel.previewForBody(lastMessagePreview)
        ?: com.testlogon.android.feature.messaging.RevealAtMath.previewForBody(lastMessagePreview)
        ?: lastMessagePreview,
    lastActivityEpochSeconds = lastActivityEpochSeconds,
    unreadCount = unreadCount,
)
