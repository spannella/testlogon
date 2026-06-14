package com.testlogon.android.data.broadcast.chat

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.testlogon.android.data.messaging.realtime.SseFrame
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-281 — pure DTO -> domain mapping for chat. Reactions are derived from `reactions_counts`
 * (counts) + `my_reactions` (the self-highlight, since no per-emoji self flag exists on the wire).
 * `isSelf`/`isHost` are derived by the repository/VM (passed in), not on the wire.
 */
fun ChatMessageDto.toDomain(selfId: String?): ChatMessage = ChatMessage(
    id = messageId,
    clientNonce = null,
    sessionId = sessionId,
    senderId = senderId,
    senderDisplayName = senderDisplayName,
    isSelf = selfId != null && senderId == selfId,
    isHost = false,
    text = text,
    kind = kind ?: "text",
    createdAtEpochSeconds = createdAt,
    deleted = deleted,
    reactions = buildReactions(reactionsCounts, myReactions),
    deliveryState = DeliveryState.SENT,
)

/** Builds the derived reaction list from the counts map + the caller's my_reactions set. */
fun buildReactions(counts: Map<String, Int>?, myReactions: List<String>?): List<ChatReaction> {
    if (counts.isNullOrEmpty()) return emptyList()
    val mine = myReactions?.toSet() ?: emptySet()
    return counts.entries
        .filter { it.value > 0 }
        .map { (emoji, count) -> ChatReaction(emoji = emoji, count = count, reactedBySelf = emoji in mine) }
}

/**
 * AND-281 — parses a decoded SSE frame into a [ChatStreamEvent] by event name (colon-delimited, per
 * BroadcastChat.tsx). Malformed `data` or an unknown event name maps to [ChatStreamEvent.Unknown]
 * (logged-equivalent) — a single bad frame must NEVER tear down a live session. Pure / transport-free
 * so it is fully JVM-unit-tested.
 */
@Singleton
class ChatEventParser @Inject constructor(private val moshi: Moshi) {

    /** [selfId] lets received messages be flagged as the caller's own for styling. */
    fun parse(frame: SseFrame, selfId: String?): ChatStreamEvent = try {
        when (frame.event) {
            EVENT_MESSAGE, EVENT_LOTTERY -> moshi.adapter(ChatMessageDto::class.java)
                .fromJson(frame.data)?.let { ChatStreamEvent.MessageReceived(it.toDomain(selfId)) }
                ?: ChatStreamEvent.Unknown
            EVENT_REACTION -> moshi.adapter(ChatReactionEventDto::class.java)
                .fromJson(frame.data)?.let { ChatStreamEvent.ReactionUpdated(it.messageId, it.counts) }
                ?: ChatStreamEvent.Unknown
            EVENT_DELETE -> moshi.adapter(ChatDeletedDto::class.java)
                .fromJson(frame.data)?.let { ChatStreamEvent.MessageDeleted(it.messageId) }
                ?: ChatStreamEvent.Unknown
            EVENT_UNLOCK -> moshi.adapter(ChatUnlockDto::class.java)
                .fromJson(frame.data)?.let { ChatStreamEvent.MessageUnlocked(it.messageId, it.text) }
                ?: ChatStreamEvent.Unknown
            else -> ChatStreamEvent.Unknown
        }
    } catch (_: JsonDataException) {
        ChatStreamEvent.Unknown
    } catch (_: Exception) {
        ChatStreamEvent.Unknown
    }

    companion object {
        const val EVENT_MESSAGE = "chat:message"
        const val EVENT_LOTTERY = "chat:lottery"
        const val EVENT_REACTION = "chat:reaction"
        const val EVENT_DELETE = "chat:delete"
        const val EVENT_UNLOCK = "chat:unlock"
    }
}
