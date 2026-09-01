package com.testlogon.android.core.network.delegates

import com.squareup.moshi.Json

/**
 * AND-360 - transport DTOs for the delegate-PATH feed / messaging / broadcast surfaces (manage-as-creator
 * traffic). These are DISTINCT from the AND-359 delegation-management DTOs (DelegateDtos.kt) - they model
 * the per-creator delegate endpoints under ui/newsfeed/delegate, messaging/delegate and
 * ui/broadcast/delegate.
 *
 * CODEGEN NOTE (identical to AND-359 DelegateDtos / AND-353 OrgDtos): core-network does NOT apply the
 * Moshi KSP codegen plugin, so these decode via the reflective KotlinJsonAdapterFactory on the shared
 * Moshi. The reflective factory maps property names to JSON keys VERBATIM (no auto snake_case), so every
 * wire key is pinned with an explicit @Json(name = ...). @JsonClass(generateAdapter = true) is OMITTED.
 *
 * Optional fields are nullable with null defaults so a missing key never crashes; extra / unknown keys are
 * tolerated leniently. List endpoints return BARE ARRAYS (no paged envelope).
 *
 * APPROVAL NOTE: when the creator has require_post_approval set, a delegate-created post may carry an
 * approval_status (e.g. "pending"). The delegate CANNOT self-approve, so the approve / reject action is
 * creator-only and intentionally NOT modeled here - only the read-back [DelegatedPostOut.approvalStatus]
 * field exists so the UI can surface the pending state.
 */

// ---- Feed delegate ----

/**
 * AND-360 - body to create a post on the managed creator's feed (delegate path). [text] is the post body.
 * Kept minimal; richer post composition (media, visibility) is owned by the feed epic and deferred.
 */
data class DelegatedPostCreateIn(
    @Json(name = "text") val text: String,
)

/**
 * AND-360 - a post on the managed creator's feed as returned by the delegate path. [postId] is required;
 * the rest is optional. [approvalStatus] is present only when the creator requires post approval (the
 * delegate can not self-approve; the approve / reject action is creator-only and not built here).
 */
data class DelegatedPostOut(
    @Json(name = "post_id") val postId: String,
    @Json(name = "text") val text: String? = null,
    @Json(name = "approval_status") val approvalStatus: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
)

// ---- Messaging delegate ----

/**
 * AND-360 - one conversation in the managed creator's inbox (delegate path). [conversationId] is required;
 * the optional fields are best-effort metadata for the focused demonstration list.
 */
data class DelegatedConversationOut(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "last_message_preview") val lastMessagePreview: String? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
)

/**
 * AND-360 - one message in a managed creator's conversation (delegate path). When the delegate is the
 * author, the server echoes [sentByDelegate] true plus the [delegateDisplayName] / [delegateTag]
 * attribution. An end-to-end-encrypted message the delegate is not keyed for arrives with
 * [delegateCannotDecrypt] true so the UI can render a "can't decrypt" placeholder instead of plaintext.
 */
data class DelegatedMessageOut(
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "text") val text: String? = null,
    @Json(name = "sent_by_delegate") val sentByDelegate: Boolean? = null,
    @Json(name = "delegate_display_name") val delegateDisplayName: String? = null,
    @Json(name = "delegate_tag") val delegateTag: String? = null,
    @Json(name = "delegate_cannot_decrypt") val delegateCannotDecrypt: Boolean? = null,
    @Json(name = "created_at") val createdAt: String? = null,
)

/**
 * AND-360 - body to send a message in a managed creator's conversation (delegate path). [text] is the
 * message; [replyToMessageId] optionally threads the reply.
 */
data class DelegatedSendMessageIn(
    @Json(name = "text") val text: String,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
)

// ---- Broadcast delegate ----

/**
 * AND-360 - body to schedule a managed creator's broadcast session (delegate path, broadcast_control).
 * Lenient / minimal: [title] + [scheduledAt] are the only modeled fields; the response is ignored
 * (Response of Unit), so the broadcast epic stays the owner of the rich scheduling surface.
 */
data class DelegatedScheduleSessionIn(
    @Json(name = "title") val title: String? = null,
    @Json(name = "scheduled_at") val scheduledAt: String? = null,
)

/**
 * AND-360 - body for a delegate broadcast MODERATION action targeting a viewer (mute / ban / unban;
 * broadcast_moderate). [userId] identifies the target; [reason] is optional. Kept minimal - the full
 * moderation console is owned by the broadcast epic.
 */
data class DelegatedModerationIn(
    @Json(name = "user_id") val userId: String,
    @Json(name = "reason") val reason: String? = null,
)

/**
 * AND-360 - body to post an ANNOUNCEMENT in the managed creator's broadcast chat (delegate path,
 * broadcast_moderate). [text] is the announcement copy. Mirrors the web BroadcastAnnouncementReq.
 */
data class DelegatedAnnouncementIn(
    @Json(name = "text") val text: String,
)

/**
 * AND-360 - one active MODERATOR of a managed creator's broadcast session (delegate path, read). Mirrors
 * the web BroadcastModeratorOut. [delegateId] is required; the rest is best-effort metadata that defaults
 * leniently so a sparse row never crashes decoding.
 */
data class DelegatedBroadcastModeratorOut(
    @Json(name = "delegate_id") val delegateId: String,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "connected_at") val connectedAt: Long? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "actions_count") val actionsCount: Int? = null,
)

/**
 * AND-360 - one BANNED viewer of a managed creator's broadcast session (delegate path, read). Mirrors the
 * web BroadcastBanOut. [userId] + [bannedBy] are required; the rest defaults leniently.
 */
data class DelegatedBroadcastBanOut(
    @Json(name = "user_id") val userId: String,
    @Json(name = "banned_by") val bannedBy: String,
    @Json(name = "banned_by_display_name") val bannedByDisplayName: String? = null,
    @Json(name = "banned_at") val bannedAt: Long? = null,
    @Json(name = "reason") val reason: String? = null,
)

/**
 * AND-360 - one entry in a managed creator's broadcast MODERATION LOG (delegate path, read). Mirrors the
 * web BroadcastModerationLogEntry. [eventId] + [moderatorId] are required; targets / details are optional.
 */
data class DelegatedBroadcastModLogEntry(
    @Json(name = "event_id") val eventId: String,
    @Json(name = "moderator_id") val moderatorId: String,
    @Json(name = "moderator_display_name") val moderatorDisplayName: String? = null,
    @Json(name = "moderation_type") val moderationType: String? = null,
    @Json(name = "target_user_id") val targetUserId: String? = null,
    @Json(name = "target_message_id") val targetMessageId: String? = null,
    @Json(name = "ts") val ts: Long? = null,
)
