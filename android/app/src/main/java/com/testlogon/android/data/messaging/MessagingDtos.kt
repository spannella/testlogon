package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-120 — wire DTOs for the TestLogon messaging domain.
 *
 * Shapes verified against reference/src/api/types.ts (Conversation, Message, ParticipantOut,
 * SendTextMessageReq, MessagingConfig), reference/src/api/endpoints/messaging.ts, the
 * reference adapter (messagingAdapter.ts: adaptConversation / adaptMessage), and OpenAPI
 * components.schemas (ConversationOut, MessageOut, app__routers__messaging__ParticipantOut,
 * SendTextMessageIn, MessagingConfigOut).
 *
 * Field-name notes (verified):
 *  - conversation id is "conversation_id" (NOT "id"); message id is "message_id" (NOT "id").
 *  - message text field is "text" (NOT "body"); message author is "sender_id" (NOT "author_id").
 *  - timestamps (created_at / last_message_at) are epoch-SECONDS integers (NOT ISO-8601 strings).
 *  - avatar-ish field on a conversation is "icon" (there is NO "avatar_url").
 *  - last-message preview is the top-level "last_message_preview" else last_message.preview.
 *  - messages are polymorphic via a required "kind" discriminator; "text" is null for non-text kinds.
 *  - list endpoints return BARE JSON ARRAYS (no {items,next_cursor} envelope).
 *  - the send request carries "text" only — there is NO client_id on the wire.
 *  - markRead body is { last_read_message_id?, last_read_at? } and returns an empty 200 body.
 *
 * Uses Moshi codegen (@JsonClass(generateAdapter = true)), consistent with the other app DTOs.
 */

/** GET messaging/config -> MessagingConfigOut (boolean feature flags only). */
@JsonClass(generateAdapter = true)
data class MessagingConfigDto(
    @Json(name = "messaging_encrypted_messages_enabled") val encryptedMessagesEnabled: Boolean = false,
    @Json(name = "messaging_gallery_enabled") val galleryEnabled: Boolean = false,
    @Json(name = "messaging_dm_lottery_enabled") val dmLotteryEnabled: Boolean = false,
    @Json(name = "messaging_hide_controls_enabled") val hideControlsEnabled: Boolean = false,
    @Json(name = "messaging_pins_enabled") val pinsEnabled: Boolean = false,
    @Json(name = "messaging_reporting_enabled") val reportingEnabled: Boolean = false,
    @Json(name = "messaging_mass_send_enabled") val massSendEnabled: Boolean = false,
)

/** app__routers__messaging__ParticipantOut. Required: user_id, status, role. */
@JsonClass(generateAdapter = true)
data class ParticipantDto(
    @Json(name = "user_id") val userId: String,
    val status: String = "active",
    val role: String = "member",
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "last_read_at") val lastReadAt: Long = 0L,
    // AND-158 / AND-159 — additive membership fields (epoch SECONDS; 0 = unset). `joined_at` orders
    // the roster; `left_at > 0` means the user has left; `muted_until` mirrors per-participant mute.
    @Json(name = "joined_at") val joinedAt: Long = 0L,
    @Json(name = "left_at") val leftAt: Long = 0L,
    @Json(name = "muted_until") val mutedUntil: Long = 0L,
)

/**
 * MessageOut. Required: conversation_id, message_id, sender_id, created_at, kind.
 * `text` is null for non-text kinds; `preview` is a server-rendered single-line summary.
 */
@JsonClass(generateAdapter = true)
data class MessageDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "conversation_id") val conversationId: String = "",
    @Json(name = "sender_id") val senderId: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    val kind: String = "text",
    val text: String? = null,
    val preview: String? = null,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
    @Json(name = "edited_at") val editedAt: Long? = null,
    @Json(name = "edited_by") val editedBy: String? = null,
    @Json(name = "read_by_count") val readByCount: Int? = null,
    // AND-147 — delivery/read receipt fields on the message payload (verified src/api/types.ts: Message).
    @Json(name = "read_by_user_ids") val readByUserIds: List<String>? = null,
    @Json(name = "delivered_to_count") val deliveredToCount: Int? = null,
    @Json(name = "delivered_to_user_ids") val deliveredToUserIds: List<String>? = null,
    // Self-destruct expiry: epoch-seconds deadline + server-confirmed expired flag.
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "expired") val expired: Boolean? = null,
    // AND-140 — reaction summary on the message itself: emoji -> count, plus the emojis I reacted with.
    @Json(name = "reactions_counts") val reactionsCounts: Map<String, Int>? = null,
    @Json(name = "my_reactions") val myReactions: List<String>? = null,
    // AND-140 — revoke ("unsend") markers (epoch-INTEGER seconds). edited_at above doubles as the edit marker.
    @Json(name = "revoked_at") val revokedAt: Long? = null,
    @Json(name = "revoked_by") val revokedBy: String? = null,
    /** AND-130 — present on kind="image". The display url is `url` else `bucket`/`key`-derived. */
    val image: MessageImageDto? = null,
    /** C6 — present on kind="gallery". Sender always sees all free_images; recipient sees free + unlocked. */
    @Json(name = "free_images") val freeImages: List<GalleryImageDto>? = null,
    /** AND-131 — present on kind="video_share". Carries the HLS manifest + short-lived token. */
    @Json(name = "video_share") val videoShare: VideoShareDto? = null,
    /** AND-132 — present on kind="file"/"audio"/"video" (generic file attachment). */
    val file: MessageFileDto? = null,
    /** AND-132 — present on kind="file_share" (shared owned file, no re-upload). */
    @Json(name = "file_share") val fileShare: MessageFileDto? = null,
    /** AND-133 — present on kind="voice_message". Signed audio url + duration + waveform. */
    @Json(name = "voice_message") val voiceMessage: VoiceMessageDto? = null,
    /** AND-134 — present on kind="voicemail". Nested object (audio_url/video_url + call metadata). */
    val voicemail: VoicemailDto? = null,
    /** AND-135 — FLAT fields present on kind="gif" (no nested object on the wire). */
    @Json(name = "gif_url") val gifUrl: String? = null,
    @Json(name = "gif_alt_text") val gifAltText: String? = null,
    @Json(name = "gif_width") val gifWidth: Int? = null,
    @Json(name = "gif_height") val gifHeight: Int? = null,
    @Json(name = "gif_provider") val gifProvider: String? = null,
    /** AND-135 — FLAT fields present on kind="sticker". */
    @Json(name = "sticker_id") val stickerId: String? = null,
    @Json(name = "sticker_collection_id") val stickerCollectionId: String? = null,
    @Json(name = "sticker_url") val stickerUrl: String? = null,
    @Json(name = "sticker_alt_text") val stickerAltText: String? = null,
    /** AND-136 — present on kind="meeting_poll": the poll envelope (slots come from the polls GET). */
    @Json(name = "meeting_poll") val meetingPoll: MeetingPollAttachmentDto? = null,
    /** AND-137 — FLAT countdown fields present on kind="countdown". target_datetime is UTC seconds. */
    @Json(name = "countdown_title") val countdownTitle: String? = null,
    @Json(name = "target_datetime") val targetDatetime: Long? = null,
    @Json(name = "associated_event_type") val associatedEventType: String? = null,
    @Json(name = "associated_event_id") val associatedEventId: String? = null,
    /** AND-138 — present on kind="calendar_event"/"calendar_share" (nested attachment objects). */
    @Json(name = "calendar_event") val calendarEvent: CalendarEventAttachmentDto? = null,
    @Json(name = "calendar_share") val calendarShare: CalendarShareAttachmentDto? = null,
    @Json(name = "find_datetime") val findDatetime: FindDateTimeAttachmentDto? = null,
    /** AND-139 — FLAT fixed-price paid-message fields (gated content is NEVER shipped while locked). */
    @Json(name = "lock_price_cents") val lockPriceCents: Long? = null,
    @Json(name = "lock_description") val lockDescription: String? = null,
    val locked: Boolean? = null,
    @Json(name = "is_unlocked") val isUnlocked: Boolean? = null,
    @Json(name = "tip_amount_cents") val tipAmountCents: Long? = null,
    @Json(name = "tip_currency") val tipCurrency: String? = null,
    /** AND-139 — nested lottery sub-object present on a kind="lottery_dm" message. */
    val lottery: LotteryAttachmentDto? = null,
    /** AND-132/133 — "none" | "view_once" | "listen_once"; gates once-media cache reuse. */
    @Json(name = "consumption_policy") val consumptionPolicy: String? = null,
    @Json(name = "view_once") val viewOnce: Boolean? = null,
    /** "unconsumed" | "consumed" | null — server view-once consumption state for the current user. */
    @Json(name = "consumption_state") val consumptionState: String? = null,
    @Json(name = "is_encrypted") val isEncrypted: Boolean? = null,
    /** MSG — client-side encryption envelope echoed back by the server on an encrypted message. */
    val encryption: MessageEncryptionEnvelopeDto? = null,
)

/** MessageOut.image (MessageImage). All inner fields are optional per the free-form schema. */
@JsonClass(generateAdapter = true)
data class MessageImageDto(
    val bucket: String? = null,
    val key: String? = null,
    val url: String? = null,
    @Json(name = "content_type") val contentType: String? = null,
    val width: Int? = null,
    val height: Int? = null,
    val filename: String? = null,
    val filesize: Long? = null,
)

/** MessageOut.video_share — server-resolved shared library video (AND-131). */
@JsonClass(generateAdapter = true)
data class VideoShareDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "owner_user_id") val ownerUserId: String? = null,
    val title: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Int? = null,
    val width: Int? = null,
    val height: Int? = null,
    val visibility: String? = null,
    @Json(name = "drm_enabled") val drmEnabled: Boolean = false,
    @Json(name = "hls_manifest_url") val hlsManifestUrl: String? = null,
    @Json(name = "playback_token") val playbackToken: String? = null,
    @Json(name = "playback_expires_at") val playbackExpiresAt: Long? = null,
)

/** ConversationOut (returned bare-array by list, and singly by get). */
@JsonClass(generateAdapter = true)
data class ConversationDto(
    @Json(name = "conversation_id") val conversationId: String,
    val type: String = "dm",
    val title: String? = null,
    val icon: String? = null,
    val status: String = "active",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "created_by") val createdBy: String = "",
    @Json(name = "participant_count") val participantCount: Int = 0,
    val participants: List<ParticipantDto> = emptyList(),
    @Json(name = "last_message") val lastMessage: MessageDto? = null,
    @Json(name = "last_message_at") val lastMessageAt: Long? = null,
    @Json(name = "last_message_preview") val lastMessagePreview: String? = null,
    @Json(name = "unread_count") val unreadCount: Int = 0,
    @Json(name = "last_read_at") val lastReadAt: Long = 0L,
    // AND-159 — conversation-level mute (epoch SECONDS; default 0 = not muted, NOT nullable per schema).
    @Json(name = "muted_until") val mutedUntil: Long = 0L,
    // AND-161/AND-162 — helpdesk routing/assignment fields on ConversationOut (all nullable/optional;
    // present when the conversation is a helpdesk-bridge convo). Verified against
    // reference/openapi.pretty.json components.schemas.ConversationOut.
    @Json(name = "routing_mode") val routingMode: String? = null,
    @Json(name = "routing_group_id") val routingGroupId: String? = null,
    @Json(name = "routing_state") val routingState: String? = null,
    @Json(name = "active_agent_user_id") val activeAgentUserId: String? = null,
    @Json(name = "active_agent_claimed_at") val activeAgentClaimedAt: Long? = null,
    @Json(name = "assignment_version") val assignmentVersion: Int? = null,
)

/**
 * POST messages body = SendTextMessageIn. Field is `text` (1..4000); NO client_id on the wire.
 * Optional message-option fields (all default null/absent for a plain send): self-destruct
 * ([viewOnce]), pay-to-unlock ([lockPriceCents]/[lockDescription]), and schedule ([sendAt], epoch
 * seconds) — all accepted server-side on the same endpoint.
 */
@JsonClass(generateAdapter = true)
data class SendTextMessageReq(
    // Server requires EXACTLY one of text / encryption (text absent when an encryption envelope is set).
    val text: String? = null,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
    @Json(name = "view_once") val viewOnce: Boolean? = null,
    @Json(name = "lock_price_cents") val lockPriceCents: Long? = null,
    @Json(name = "lock_description") val lockDescription: String? = null,
    @Json(name = "send_at") val sendAt: Long? = null,
    @Json(name = "expires_in_seconds") val expiresInSeconds: Long? = null,
    val encryption: MessageEncryptionEnvelopeDto? = null,
)

/**
 * MessageEncryptionEnvelope — client-side encryption envelope (AES-256-GCM / PBKDF2-SHA256).
 * salt_b64 must decode to exactly 16 bytes; iv_b64 to exactly 12 bytes; ciphertext_b64 must be
 * >16 bytes (ciphertext + GCM tag). iterations 100000..2000000.
 */
@JsonClass(generateAdapter = true)
data class MessageEncryptionEnvelopeDto(
    val version: Int = 1,
    val alg: String = "AES-256-GCM",
    val kdf: String = "PBKDF2-SHA256",
    val iterations: Int = 100000,
    @Json(name = "salt_b64") val saltB64: String,
    @Json(name = "iv_b64") val ivB64: String,
    @Json(name = "ciphertext_b64") val ciphertextB64: String? = null,
)

/** POST read body = app__routers__messaging__MarkReadIn (both fields optional). */
@JsonClass(generateAdapter = true)
data class MarkReadReq(
    @Json(name = "last_read_message_id") val lastReadMessageId: String? = null,
    @Json(name = "last_read_at") val lastReadAt: Long? = null,
)

/**
 * POST dm/find-or-create body = FindOrCreateDmIn. Single required field `user_id` (the peer).
 * Verified: reference/src/api/endpoints/messaging.ts findOrCreateDm posts `{ user_id }`;
 * OpenAPI op find_or_create_dm req=FindOrCreateDmIn resp=200:ConversationOut.
 */
@JsonClass(generateAdapter = true)
data class FindOrCreateDmReq(
    @Json(name = "user_id") val userId: String,
)

/**
 * AND-153 — one contact (people-search) result row.
 *
 * Verified against OpenAPI components.schemas.Contact (required `user_id`, `display_name` — no other
 * fields) and reference src/api/types.ts:1393 UserSearchResult ({ user_id, display_name }). The
 * endpoint returns a bare JSON array of these.
 */
@JsonClass(generateAdapter = true)
data class ContactDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String,
)
