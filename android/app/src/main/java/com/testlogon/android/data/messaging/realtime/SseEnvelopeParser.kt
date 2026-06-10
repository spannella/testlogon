package com.testlogon.android.data.messaging.realtime

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-123 (realtime) — pure parser turning an SSE frame (event type + JSON `data` line) into a typed
 * [MessagingEvent]. Kept transport-free so it is fully JVM-unit-testable without a live socket.
 *
 * The event type comes from the SSE `event:` field when present, else from a `type` key inside the
 * JSON `data` (mirroring reference/src/hooks/useMessagingStream.ts, which reads
 * `event.type || data.type`). Malformed JSON yields null (the caller ignores it, like heartbeats).
 */
@Singleton
class SseEnvelopeParser @Inject constructor(moshi: Moshi) {

    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    /**
     * @param eventType the SSE `event:` field value (may be blank/"message" for untyped frames).
     * @param dataJson the raw JSON from the SSE `data:` field.
     */
    fun parse(eventType: String, dataJson: String): MessagingEvent? {
        val data = runCatching { mapAdapter.fromJson(dataJson) }.getOrNull() ?: return null
        val type = eventType.takeIf { it.isNotBlank() && it != "message" }
            ?: (data["type"] as? String).orEmpty()
        val conversationId = data["conversation_id"] as? String

        return when (type) {
            "message:new" -> MessagingEvent.NewMessage(
                conversationId = conversationId ?: return null,
                messageId = data["message_id"] as? String ?: return null,
                senderId = data["sender_id"] as? String ?: "",
                text = data["text"] as? String,
                kind = data["kind"] as? String ?: "text",
                createdAtEpochSeconds = (data["created_at"] as? Number)?.toLong() ?: 0L,
            )
            "conversation_updated" -> MessagingEvent.ConversationUpdated(conversationId)
            // AND-140 — reaction / edit / revoke mutations on an existing message. The web client
            // (useMessagingStream.ts) reads only conversation_id + message_id from these frames.
            "message:reaction", "message:edited", "message:revoked" -> MessagingEvent.MessageMutated(
                conversationId = conversationId ?: return null,
                messageId = data["message_id"] as? String ?: return null,
                kind = type.removePrefix("message:"),
            )
            "" -> null
            else -> MessagingEvent.Other(type, conversationId)
        }
    }
}
