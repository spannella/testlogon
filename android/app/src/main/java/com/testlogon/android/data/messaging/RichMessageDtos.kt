package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-134 / AND-135 / AND-136 — wire DTOs for the rich message kinds (voicemail, GIF, sticker,
 * custom-emoji catalog, meeting poll). Shapes verified against reference/openapi.index.txt,
 * reference/src/api/endpoints/{messaging,stickers,customEmojis}.ts and reference/src/api/types.ts
 * (2026-06-09). All use Moshi codegen, consistent with the other app DTOs.
 *
 * Conventions reused from the established per-kind pattern:
 *  - conversation_id is a PATH param (never a body field); message_id is the server id.
 *  - created_at is epoch-SECONDS integer (NOT ISO-8601).
 *  - list endpoints that return a bare array deserialize to List<…> directly.
 *  - MessageOut is a flat object discriminated by `kind`; per-kind data is flat columns or a nested
 *    object. The shared [MessageDto] carries the new optional fields/objects.
 */

// ─── AND-135: GIF & sticker send requests (SendGifMessageIn / SendStickerMessageIn) ───

/**
 * SendGifMessageIn. Only `gif_url` is required (maxLength 2048). There is NO conversation_id,
 * client_id, preview_url, provider, or nested gif object on the wire.
 * Verified: reference/src/api/endpoints/messaging.ts: sendGifMessage; OpenAPI SendGifMessageIn.
 */
@JsonClass(generateAdapter = true)
data class SendGifMessageReq(
    @Json(name = "gif_url") val gifUrl: String,
    @Json(name = "gif_alt_text") val gifAltText: String? = null,
    @Json(name = "gif_width") val gifWidth: Int? = null,
    @Json(name = "gif_height") val gifHeight: Int? = null,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
)

/**
 * SendStickerMessageIn. Both ids required; field is `sticker_collection_id` (NOT pack_id).
 * Verified: reference/src/api/endpoints/messaging.ts: sendStickerMessage; OpenAPI SendStickerMessageIn.
 */
@JsonClass(generateAdapter = true)
data class SendStickerMessageReq(
    @Json(name = "sticker_id") val stickerId: String,
    @Json(name = "sticker_collection_id") val stickerCollectionId: String,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
)

// ─── AND-135: GIF search / trending (bare arrays; NO cursor) ───

/** GifSearchResult `{id,url,alt_text,width,height}` (no preview_url/provider). */
@JsonClass(generateAdapter = true)
data class GifSearchResultDto(
    val id: String,
    val url: String,
    @Json(name = "alt_text") val altText: String? = null,
    val width: Int? = null,
    val height: Int? = null,
)

// ─── AND-135: sticker collections / stickers ───

/** GET /ui/stickers/collections -> StickerCollectionListOut. */
@JsonClass(generateAdapter = true)
data class StickerCollectionListRespDto(
    val collections: List<StickerCollectionDto> = emptyList(),
)

/** GET /ui/stickers/collections/{id}/stickers -> StickerListOut. */
@JsonClass(generateAdapter = true)
data class StickerListRespDto(
    val stickers: List<StickerDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class StickerCollectionDto(
    @Json(name = "collection_id") val collectionId: String,
    val name: String = "",
    val description: String = "",
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "sticker_count") val stickerCount: Int = 0,
    @Json(name = "is_active") val isActive: Boolean = true,
    val stickers: List<StickerDto> = emptyList(),
)

/** StickerOut `{sticker_id,image_url,alt_text,width,height,sort_order}` (no `name`, no `url`). */
@JsonClass(generateAdapter = true)
data class StickerDto(
    @Json(name = "sticker_id") val stickerId: String,
    @Json(name = "image_url") val imageUrl: String = "",
    @Json(name = "alt_text") val altText: String? = null,
    val width: Int? = null,
    val height: Int? = null,
    @Json(name = "sort_order") val sortOrder: Int = 0,
)

// ─── AND-135: custom emoji catalog + resolve ───

/** GET /ui/emojis/custom -> CustomEmojiListOut. Wrapper field is `emojis` (NOT `emoji`). */
@JsonClass(generateAdapter = true)
data class CustomEmojiListRespDto(
    val emojis: List<CustomEmojiDto> = emptyList(),
    @Json(name = "personal_count") val personalCount: Int = 0,
    @Json(name = "global_count") val globalCount: Int = 0,
)

/**
 * CustomEmojiOut. Image field is `image_url` (NOT `url`); there is NO `animated` boolean —
 * animation is inferred from `content_type` (image/gif | image/webp).
 */
@JsonClass(generateAdapter = true)
data class CustomEmojiDto(
    @Json(name = "emoji_id") val emojiId: String,
    val shortcode: String,
    val name: String = "",
    @Json(name = "image_url") val imageUrl: String = "",
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "owner_scope") val ownerScope: String = "global",
    @Json(name = "alt_text") val altText: String? = null,
)

/** GET /ui/emojis/custom/resolve?codes=a,b,c -> ResolveShortcodesOut `{resolved:{shortcode:url}}`. */
@JsonClass(generateAdapter = true)
data class ResolveShortcodesRespDto(
    val resolved: Map<String, String> = emptyMap(),
)

// ─── AND-135: MessageOut nested objects / flat fields for gif & sticker ───
// (gif/sticker fields are FLAT on MessageOut — declared on [MessageDto], not a nested object.)

// ─── AND-134: voicemail presign + create ───

/** PresignVoicemailRequest `{call_id, content_type(^(audio|video)/(webm|mp4|ogg|wav)), size_bytes, mode}`. */
@JsonClass(generateAdapter = true)
data class PresignVoicemailReq(
    @Json(name = "call_id") val callId: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "size_bytes") val sizeBytes: Long,
    val mode: String = "audio",
)

/** Presign response (untyped in OpenAPI; shape from the web client presignVoicemail). */
@JsonClass(generateAdapter = true)
data class PresignVoicemailResp(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "upload_url") val uploadUrl: String,
    @Json(name = "s3_key") val s3Key: String,
)

/**
 * CreateVoicemailRequest — required: message_id (^m_[a-f0-9]{32}$), call_id, s3_key, content_type,
 * size_bytes, duration_seconds (0.5..60), waveform_data (10..200). mode default "audio".
 */
@JsonClass(generateAdapter = true)
data class CreateVoicemailReq(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "call_id") val callId: String,
    @Json(name = "s3_key") val s3Key: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "size_bytes") val sizeBytes: Long,
    @Json(name = "duration_seconds") val durationSeconds: Double,
    @Json(name = "waveform_data") val waveformData: List<Float>,
    val mode: String = "audio",
)

/** MessageOut.voicemail (nested). audio_url for audio, video_url for video. */
@JsonClass(generateAdapter = true)
data class VoicemailDto(
    @Json(name = "call_id") val callId: String = "",
    val mode: String = "audio",
    @Json(name = "audio_url") val audioUrl: String? = null,
    @Json(name = "video_url") val videoUrl: String? = null,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "size_bytes") val sizeBytes: Long? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "waveform_data") val waveformData: List<Float>? = null,
    @Json(name = "call_state") val callState: String? = null,
    @Json(name = "caller_user_id") val callerUserId: String? = null,
    @Json(name = "callee_user_id") val calleeUserId: String? = null,
)

// ─── AND-136: meeting poll ───

/** MeetingPollSlotIn `{start_utc, end_utc}` (ISO-8601). */
@JsonClass(generateAdapter = true)
data class MeetingPollSlotInDto(
    @Json(name = "start_utc") val startUtc: String,
    @Json(name = "end_utc") val endUtc: String,
)

/**
 * CreateMeetingPollMessageIn `{title(1..200), duration_minutes(15..1440, def 30), slots(2..5), text?}`.
 * conversation_id is a PATH param; there is no kind/allow_multiple/options.
 */
@JsonClass(generateAdapter = true)
data class CreateMeetingPollReq(
    val title: String,
    @Json(name = "duration_minutes") val durationMinutes: Int = 30,
    val slots: List<MeetingPollSlotInDto>,
    val text: String? = null,
)

/** PollVoteIn `{votes: {slot_id: "yes"|"no"|"maybe"}}` (omit a slot to clear it). */
@JsonClass(generateAdapter = true)
data class PollVoteReq(
    val votes: Map<String, String>,
)

/** PollConfirmIn `{slot_id, calendar_id?}` (calendar_id omitted here). */
@JsonClass(generateAdapter = true)
data class PollConfirmReq(
    @Json(name = "slot_id") val slotId: String,
    @Json(name = "calendar_id") val calendarId: String? = null,
)

/** Vote/confirm responses are `{ok:true}` / `{ok, event_id?}` (NOT a poll DTO). */
@JsonClass(generateAdapter = true)
data class OkResp(
    val ok: Boolean = false,
    @Json(name = "event_id") val eventId: String? = null,
)

/** MeetingPollState — the GET response carrying authoritative per-slot counts + my_vote. */
@JsonClass(generateAdapter = true)
data class MeetingPollStateDto(
    @Json(name = "poll_id") val pollId: String,
    val title: String = "",
    @Json(name = "duration_minutes") val durationMinutes: Int = 30,
    @Json(name = "creator_id") val creatorId: String = "",
    val status: String = "open",
    @Json(name = "confirmed_slot_id") val confirmedSlotId: String? = null,
    val slots: List<MeetingPollSlotStateDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class MeetingPollSlotStateDto(
    @Json(name = "slot_id") val slotId: String,
    @Json(name = "start_utc") val startUtc: String = "",
    @Json(name = "end_utc") val endUtc: String = "",
    @Json(name = "yes_count") val yesCount: Int = 0,
    @Json(name = "maybe_count") val maybeCount: Int = 0,
    @Json(name = "no_count") val noCount: Int = 0,
    @Json(name = "my_vote") val myVote: String? = null,
)

/**
 * MessageOut.meeting_poll (the nested attachment carried on a kind="meeting_poll" message). It has
 * the poll envelope but NOT the slots (slots/counts come from the polls GET). Used to render the
 * card shell + GET the canonical state.
 */
@JsonClass(generateAdapter = true)
data class MeetingPollAttachmentDto(
    @Json(name = "poll_id") val pollId: String,
    @Json(name = "creator_id") val creatorId: String = "",
    val title: String = "",
    @Json(name = "duration_minutes") val durationMinutes: Int = 30,
    val status: String = "open",
    @Json(name = "confirmed_slot_id") val confirmedSlotId: String? = null,
)
