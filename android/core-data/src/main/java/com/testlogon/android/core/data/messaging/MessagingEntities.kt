package com.testlogon.android.core.data.messaging

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * AND-115 / AND-121..124 — Room entities backing the offline messaging cache and the optimistic
 * send outbox.
 *
 * Timestamps are epoch SECONDS (the wire unit). Message bodies live only in the app-private DB and
 * are never logged. The outbox survives process death so a FAILED/pending send is recoverable.
 */

@Entity(tableName = "conversations")
data class ConversationEntity(
    @PrimaryKey val conversationId: String,
    val title: String,
    val iconUrl: String?,
    val lastMessagePreview: String?,
    val lastActivityEpochSeconds: Long,
    val unreadCount: Int,
)

@Entity(tableName = "messages")
data class MessageEntity(
    @PrimaryKey val messageId: String,
    val conversationId: String,
    val senderId: String,
    val text: String,
    val createdAtEpochSeconds: Long,
    /** Locally-attached client correlation id (for outbox cleanup); the server never returns it. */
    val clientId: String?,
)

@Entity(tableName = "outbox_messages")
data class OutboxMessageEntity(
    @PrimaryKey val clientId: String,
    val conversationId: String,
    val text: String,
    val createdAtEpochSeconds: Long,
    /** "SENDING" | "FAILED" (mirrors com.testlogon.android.data.messaging.SendStatus). */
    val status: String,
    val attemptCount: Int = 0,
)
