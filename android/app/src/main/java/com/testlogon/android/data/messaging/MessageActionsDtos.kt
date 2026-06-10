package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-140 — wire DTOs for the per-message action surface (reactions / pins / edits / delete /
 * revoke / hide).
 *
 * Shapes verified against the backend OpenAPI (reference/openapi.pretty.json) and the web client
 * (reference/src/api/endpoints/messaging.ts):
 *  - react      -> POST   .../messages/{mid}/reactions   ReactIn{emoji, action} -> 200 (empty)
 *  - details    -> GET    .../messages/{mid}/reactions/details -> ReactionDetailsOut
 *  - pin/unpin  -> POST/DELETE .../messages/{mid}/pin     -> MessageControlActionOut
 *  - pins list  -> GET    .../conversations/{cid}/pins     -> ConversationPinsPageOut
 *  - edit       -> PATCH  .../messages/{mid}               EditMessageIn{text} -> MessageOut
 *  - delete     -> DELETE .../messages/{mid}               -> 200 (empty)  [delete_message_for_me]
 *  - revoke     -> DELETE .../messages/{mid}/revoke        -> MessageOut    [revoke_message_for_all]
 *  - hide/unhide-> POST/DELETE .../messages/{mid}/hide     -> MessageControlActionOut
 *  - hidden list-> GET    .../conversations/{cid}/hidden-messages -> HiddenMessagesPageOut
 *
 * The reaction summary + lifecycle markers ride on MessageOut itself: `reactions_counts`
 * (emoji -> count), `my_reactions` (emojis the current user reacted with), `edited_at`/`edited_by`
 * and `revoked_at`/`revoked_by` (epoch-INTEGER timestamps). Those fields are declared on
 * [MessageDto] in MessagingDtos.kt via the extension below would not work, so they live there.
 */

/** POST .../reactions body = ReactIn. `action` ∈ {add, remove} (default add server-side). */
@JsonClass(generateAdapter = true)
data class ReactIn(
    val emoji: String,
    val action: String = "add",
)

/** GET .../reactions/details -> ReactionDetailsOut: emoji -> list of reactors. */
@JsonClass(generateAdapter = true)
data class ReactionDetailsOut(
    val reactions: Map<String, List<ReactionUserOut>> = emptyMap(),
)

/** A single reactor for an emoji. Reactor id is `user_sub` (the backend's id field). */
@JsonClass(generateAdapter = true)
data class ReactionUserOut(
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
)

/** pin / unpin / hide / unhide -> MessageControlActionOut. action ∈ {hidden,visible,pinned,unpinned}. */
@JsonClass(generateAdapter = true)
data class MessageControlActionOut(
    val ok: Boolean = true,
    @Json(name = "conversation_id") val conversationId: String = "",
    @Json(name = "message_id") val messageId: String = "",
    val action: String = "",
    @Json(name = "updated_at") val updatedAt: Long = 0L,
)

/** GET .../pins -> ConversationPinsPageOut: pin REFS (not messages), cursor-paginated. */
@JsonClass(generateAdapter = true)
data class ConversationPinsPageOut(
    val items: List<ConversationPinOut> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/** A pin reference. `message_id` resolves against the message cache; `pinned_at` is epoch seconds. */
@JsonClass(generateAdapter = true)
data class ConversationPinOut(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "message_id") val messageId: String,
    @Json(name = "pinned_by_user_id") val pinnedByUserId: String,
    @Json(name = "pinned_at") val pinnedAt: Long,
    @Json(name = "is_active") val isActive: Boolean = true,
)

/** PATCH .../messages/{mid} body = EditMessageIn. Required field is `text` (NOT `body`). */
@JsonClass(generateAdapter = true)
data class EditMessageIn(
    val text: String,
)

/** GET .../hidden-messages -> HiddenMessagesPageOut: full MessageOut items, cursor-paginated. */
@JsonClass(generateAdapter = true)
data class HiddenMessagesPageOut(
    val items: List<MessageDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/**
 * GET .../messages/{mid}/edits — the OpenAPI response schema is an empty 200 (unpinned). We model a
 * tolerant envelope that accepts either a bare array or an {items:[...]} object; the mapper handles
 * both shapes. Each entry carries the prior body + when it was edited.
 */
@JsonClass(generateAdapter = true)
data class EditHistoryEntryDto(
    val revision: Int? = null,
    val text: String? = null,
    val body: String? = null,
    @Json(name = "edited_at") val editedAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

/** Tolerant wrapper for the GET .../edits response when it is enveloped as {items:[...]}. */
@JsonClass(generateAdapter = true)
data class EditHistoryPageOut(
    val items: List<EditHistoryEntryDto> = emptyList(),
)
