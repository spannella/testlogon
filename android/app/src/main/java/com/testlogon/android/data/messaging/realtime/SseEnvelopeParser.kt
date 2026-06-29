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
            // #14 (B-COUNTDOWN2) — "message:updated" is the backend's generic "this message changed,
            // re-fetch it" event; the countdown-reveal sweep emits it (reason="countdown_revealed")
            // once a countdown hits its target so connected clients re-render with the revealed
            // text/media WITHOUT a manual refresh. Unlike the reaction/edit frames the message_id is
            // carried inside `payload` (not at the top level) on this event, so read it from there
            // as a fallback. Routed to the SAME MessageMutated re-fetch+reconcile path.
            "message:reaction", "message:edited", "message:revoked", "message:updated" -> {
                @Suppress("UNCHECKED_CAST")
                val payload = data["payload"] as? Map<String, Any?>
                MessagingEvent.MessageMutated(
                    conversationId = conversationId
                        ?: (payload?.get("conversation_id") as? String)
                        ?: return null,
                    messageId = (data["message_id"] as? String)
                        ?: (payload?.get("message_id") as? String)
                        ?: return null,
                    kind = type.removePrefix("message:"),
                )
            }
            // AND-145 — single-user presence update: { user_id, online, last_seen_at } (epoch seconds).
            "presence:update" -> MessagingEvent.PresenceUpdate(
                userId = data["user_id"] as? String ?: return null,
                online = data["online"] as? Boolean ?: false,
                lastSeenAtEpochSeconds = (data["last_seen_at"] as? Number)?.toLong(),
            )
            // AND-147 — read receipt: { conversation_id, message_id, viewer_id, viewed_at } (epoch
            // seconds). The web client (useMessagingStream.ts) reads message_id + viewer_id and
            // invalidates; we model it as a typed event for the live "seen" reflection.
            "message:viewed" -> MessagingEvent.MessageViewed(
                conversationId = conversationId ?: return null,
                messageId = data["message_id"] as? String ?: return null,
                viewerId = data["viewer_id"] as? String ?: return null,
                viewedAtEpochSeconds = (data["viewed_at"] as? Number)?.toLong() ?: 0L,
            )
            // AND-146 — typing start/stop: { conversation_id, user_id, is_typing, updated_at }. The web
            // client fails open to is_typing=true (expiry clears it) and defaults a missing updated_at.
            "typing:update" -> MessagingEvent.Typing(
                conversationId = conversationId ?: return null,
                userId = data["user_id"] as? String ?: return null,
                isTyping = data["is_typing"] as? Boolean ?: true,
                updatedAtEpochSeconds = (data["updated_at"] as? Number)?.toLong() ?: 0L,
            )
            "" -> null
            else -> if (type.startsWith("webrtc.") || type.startsWith("call.")) {
                @Suppress("UNCHECKED_CAST")
                MessagingEvent.CallSignal(
                    type = type,
                    callId = data["call_id"] as? String ?: return null,
                    conversationId = (data["conversation_id"] as? String) ?: conversationId ?: "",
                    senderId = data["sender_id"] as? String,
                    payload = (data["payload"] as? Map<String, Any?>) ?: emptyMap(),
                )
            } else {
                MessagingEvent.Other(type, conversationId)
            }
        }
    }
}
