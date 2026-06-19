package com.testlogon.android.data.messaging.realtime

/**
 * AND-123 (realtime) — parsed inbound realtime events from the messaging stream.
 *
 * The REAL transport is Server-Sent Events (SSE), NOT a WebSocket: the web client opens an
 * `EventSource` on `GET /messaging/events/stream` (reference/src/hooks/useMessagingStream.ts) with
 * `withCredentials: true` (cookie auth). The backend sends typed SSE frames, e.g.
 * `event: message:new\ndata: {json}\n\n`. Each `data` payload is a JSON object that may carry a
 * `type`, a `conversation_id`, and (for `message:new`) the message fields.
 *
 * This sealed model is the testable envelope the parser produces; only the event types the Android
 * thread / conversation-list features act on are modelled, the rest collapse to [Other].
 */
sealed interface MessagingEvent {

    /** A new message was delivered to a conversation. */
    data class NewMessage(
        val conversationId: String,
        val messageId: String,
        val senderId: String,
        val text: String?,
        val kind: String,
        val createdAtEpochSeconds: Long,
    ) : MessagingEvent

    /** A conversation's summary changed (unread counts / last-message preview). */
    data class ConversationUpdated(val conversationId: String?) : MessagingEvent

    /**
     * AND-140 — an existing message changed server-side (a reaction toggled, an edit, or a revoke).
     * The web client only reads `conversation_id` + `message_id` from these frames and refetches; we
     * mirror that by re-fetching the affected message to reconcile the cache for live reflection.
     * [kind] ∈ "reaction" | "edited" | "revoked" (parsed from the SSE event type).
     */
    data class MessageMutated(
        val conversationId: String,
        val messageId: String,
        val kind: String,
    ) : MessagingEvent

    /**
     * AND-145 — a peer's presence changed. The web stream (useMessagingStream.ts) reads a single
     * user per `presence:update` frame: `{ user_id, online, last_seen_at }` (epoch seconds, may be 0).
     */
    data class PresenceUpdate(
        val userId: String,
        val online: Boolean,
        val lastSeenAtEpochSeconds: Long?,
    ) : MessagingEvent

    /**
     * AND-146 — a participant started/stopped typing in a conversation. The web stream reads
     * `{ conversation_id, user_id, is_typing, updated_at }` (epoch seconds) on a `typing:update` frame;
     * there is no display name on the wire (resolved client-side from the participant roster).
     */
    data class Typing(
        val conversationId: String,
        val userId: String,
        val isTyping: Boolean,
        val updatedAtEpochSeconds: Long,
    ) : MessagingEvent

    /**
     * AND-147 — a counterpart viewed (read) a message. The web stream (useMessagingStream.ts) reads
     * a single `message:viewed` frame carrying `{ message_id, viewer_id, viewed_at }` (epoch seconds);
     * `conversation_id` is present on the frame too. This drives the live "seen" marker on the local
     * user's own outbound messages and the viewer roster. The event NEVER carries a display name —
     * identity is resolved client-side from the participant cache.
     */
    data class MessageViewed(
        val conversationId: String,
        val messageId: String,
        val viewerId: String,
        val viewedAtEpochSeconds: Long,
    ) : MessagingEvent

    /**
     * A WebRTC/call signaling envelope (`call.*` lifecycle or `webrtc.offer|answer|ice_candidate`),
     * routed to the call orchestrator. [payload] carries the event-specific body (SDP / ICE / mode).
     */
    data class CallSignal(
        val type: String,
        val callId: String,
        val conversationId: String,
        val senderId: String?,
        val payload: Map<String, Any?>,
    ) : MessagingEvent

    /** Any other event type we observe but do not act on directly (used to refresh lists). */
    data class Other(val type: String, val conversationId: String?) : MessagingEvent
}

/** Connection lifecycle of the realtime stream, surfaced for an optional "reconnecting" affordance. */
enum class StreamConnectionState { CONNECTING, CONNECTED, DISCONNECTED }
