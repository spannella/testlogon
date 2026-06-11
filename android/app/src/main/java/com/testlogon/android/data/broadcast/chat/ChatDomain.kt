package com.testlogon.android.data.broadcast.chat

/**
 * AND-281 — broadcast live-chat domain models (DTO-free).
 *
 * Shapes mirror the VERIFIED BroadcastChatMessageOut (reference/openapi.index.txt;
 * src/api/endpoints/broadcast-chat.ts ChatMessage): the server message is FLAT — `message_id`,
 * `sender_id`, `sender_display_name`, `text` (nullable), `kind`, `created_at` (epoch SECONDS int),
 * `reactions_counts` map + `my_reactions` array. There is NO nested author, NO avatar/is_host field,
 * and NO client_id/nonce on the wire (dedup is by server `message_id` + a heuristic; FR-5). Timestamps
 * are epoch Long; money would be Long cents (not used here).
 */
data class ChatMessage(
    /** Server message_id; for an optimistic local entry this equals [clientNonce] until reconciled. */
    val id: String,
    /** LOCAL-ONLY optimistic key; never sent to / returned by the server (FR-5). */
    val clientNonce: String? = null,
    val sessionId: String,
    val senderId: String,
    val senderDisplayName: String,
    val isSelf: Boolean = false,
    val isHost: Boolean = false,
    /** Nullable on the wire (locked/deleted messages have null text). */
    val text: String?,
    val kind: String = "text",
    /** Derived from created_at epoch SECONDS. */
    val createdAtEpochSeconds: Long,
    val deleted: Boolean = false,
    val reactions: List<ChatReaction> = emptyList(),
    val deliveryState: DeliveryState = DeliveryState.SENT,
)

/** Optimistic send lifecycle of a local outbound message. */
enum class DeliveryState { SENDING, SENT, FAILED }

/** Derived view of the server reactions_counts map + my_reactions array (no per-emoji self flag). */
data class ChatReaction(
    val emoji: String,
    val count: Int,
    val reactedBySelf: Boolean,
)

/**
 * A decoded broadcast-chat domain event (parsed from an SSE frame). Its OWN sealed type — deliberately
 * NOT an extension of the messaging MessagingEvent (which would force exhaustive-when updates in the
 * thread/conversation-list ViewModels).
 */
sealed interface ChatStreamEvent {
    data class MessageReceived(val message: ChatMessage) : ChatStreamEvent
    data class MessageDeleted(val messageId: String) : ChatStreamEvent
    /** chat:reaction frame -> {message_id, counts:Map<emoji,int>} (whole-message counts). */
    data class ReactionUpdated(val messageId: String, val counts: Map<String, Int>) : ChatStreamEvent
    /** chat:unlock frame -> reveal previously-locked text. */
    data class MessageUnlocked(val messageId: String, val text: String) : ChatStreamEvent
    /** Unrecognized event name / malformed data; ignored by the reducer. */
    data object Unknown : ChatStreamEvent
}

/** Connection lifecycle of the live-chat SSE stream, surfaced to the panel. */
enum class ChatConnectionState { CONNECTING, LIVE, RECONNECTING, OFFLINE }

/** A stream emission: a lifecycle [Connection] change or a parsed [Decoded] domain event. */
sealed interface ChatStreamSignal {
    data class Connection(val state: ChatConnectionState) : ChatStreamSignal
    data class Decoded(val event: ChatStreamEvent) : ChatStreamSignal
}
