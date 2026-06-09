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
    @Json(name = "edited_at") val editedAt: Long? = null,
    @Json(name = "read_by_count") val readByCount: Int? = null,
    /** AND-130 — present on kind="image". The display url is `url` else `bucket`/`key`-derived. */
    val image: MessageImageDto? = null,
    /** AND-131 — present on kind="video_share". Carries the HLS manifest + short-lived token. */
    @Json(name = "video_share") val videoShare: VideoShareDto? = null,
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
)

/** POST messages body = SendTextMessageIn. Field is `text` (1..4000); NO client_id on the wire. */
@JsonClass(generateAdapter = true)
data class SendTextMessageReq(
    val text: String,
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
