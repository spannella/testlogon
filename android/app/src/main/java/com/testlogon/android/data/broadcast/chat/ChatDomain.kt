package com.testlogon.android.data.broadcast.chat

/**
 * AND-281 / BCAST-016 — broadcast live-chat domain models (DTO-free).
 *
 * Shapes mirror the VERIFIED BroadcastChatMessageOut. The server message is FLAT — `message_id`,
 * `sender_id`, `sender_display_name`, `text` (nullable), `kind`, `created_at` (epoch SECONDS int),
 * `reactions_counts` map + `my_reactions` array. BCAST-016 adds the rich-type fields: reply preview,
 * media (image/video + thumbnail + media_kind), locked/PPV (lock_price_cents/lock_description/
 * is_unlocked), view-once (view_once/view_once_consumed), expiring (expires_at/expired) and scheduled
 * (scheduled/send_at). `isSelf`/`isHost` are derived by the repository/VM (passed in), not on the wire.
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
    /** Nullable on the wire (locked/deleted/expired messages have null text). */
    val text: String?,
    val kind: String = "text",
    /** Derived from created_at epoch SECONDS. */
    val createdAtEpochSeconds: Long,
    val deleted: Boolean = false,
    val reactions: List<ChatReaction> = emptyList(),
    val deliveryState: DeliveryState = DeliveryState.SENT,

    // ---- BCAST-016 rich types ----
    /** Reply: the message this one replies to + a small quoted preview {sender, text}. */
    val replyToMessageId: String? = null,
    val replyPreviewSender: String? = null,
    val replyPreviewText: String? = null,

    /** Media: image_url / video_url (+ poster thumbnail_url) and the server-classified media_kind. */
    val imageUrl: String? = null,
    val videoUrl: String? = null,
    val thumbnailUrl: String? = null,
    val mediaKind: String? = null,

    /** Locked / PPV (broadcaster-only send). [isUnlocked] is false while withheld pending payment. */
    val lockPriceCents: Long? = null,
    val lockDescription: String? = null,
    val isUnlocked: Boolean = true,

    /** View-once: delivered inline once, then redacted after the viewer calls /view. */
    val viewOnce: Boolean = false,
    val viewOnceConsumed: Boolean = false,

    /** Expiring (broadcaster-only): absolute TTL; content nulled after [expiresAtEpochSeconds]. */
    val expiresAtEpochSeconds: Long? = null,
    val expired: Boolean = false,

    /** Scheduled: held then promoted when [sendAtEpochSeconds] is due while the session is still live. */
    val scheduled: Boolean = false,
    val sendAtEpochSeconds: Long? = null,

    /** LOCAL-ONLY: the viewer chose to reveal this view-once message this session (never on the wire). */
    val locallyRevealed: Boolean = false,
) {
    /** A locked PPV message whose content is still withheld (viewer has not paid). */
    val isLocked: Boolean get() = (lockPriceCents ?: 0L) > 0L && !isUnlocked

    /** True when this row carries a photo attachment. */
    val hasImage: Boolean get() = !imageUrl.isNullOrBlank() || mediaKind == "image"

    /** True when this row carries a video attachment. */
    val hasVideo: Boolean get() = !videoUrl.isNullOrBlank() || mediaKind == "video"
}

/** Optimistic send lifecycle of a local outbound message. */
enum class DeliveryState { SENDING, SENT, FAILED }

/** Derived view of the server reactions_counts map + my_reactions array (no per-emoji self flag). */
data class ChatReaction(
    val emoji: String,
    val count: Int,
    val reactedBySelf: Boolean,
)

/** Result of uploading a picked video for a broadcast chat message (a servable url + poster). */
data class BroadcastVideoUpload(
    val videoUrl: String,
    val thumbnailUrl: String?,
)

/**
 * BCAST-016 — the composer's staged rich-send options (reply target + gating). Carried in the panel
 * view-state and folded into the send request. Media is uploaded separately (image_url/video_url).
 */
data class ChatComposeOptions(
    val replyToMessageId: String? = null,
    val replyPreviewSender: String? = null,
    val replyPreviewText: String? = null,
    val viewOnce: Boolean = false,
    val lockPriceCents: Long? = null,
    val lockDescription: String? = null,
    val expiresInSeconds: Long? = null,
    val sendAtEpochSeconds: Long? = null,
) {
    val hasReply: Boolean get() = replyToMessageId != null
    /** True when any gating option is set (drives the composer "options active" affordance). */
    val hasGating: Boolean get() =
        viewOnce || lockPriceCents != null || expiresInSeconds != null || sendAtEpochSeconds != null
}

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

    /**
     * Emitted by the poll backstop each time a history poll succeeds (HTTP 2xx). Lets the panel enable
     * send + treat the transport as usable even while the long-lived SSE is stuck RECONNECTING on-device
     * (mirrors how messaging keeps realtime alive via /events/poll when the stream will not connect).
     */
    data class PollAlive(val alive: Boolean) : ChatStreamSignal
}
