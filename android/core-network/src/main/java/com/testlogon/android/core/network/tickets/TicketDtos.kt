package com.testlogon.android.core.network.tickets

import com.squareup.moshi.Json

/**
 * AND-371 - transport DTOs for the TICKET SPACES (support / helpdesk) READ surface.
 *
 * CODEGEN NOTE (identical to AND-353 OrgDtos / AND-365 SponsorshipDtos): core-network does NOT apply the
 * Moshi KSP codegen plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on
 * the shared Moshi in NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON
 * keys VERBATIM (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit
 * @Json(name = ...). @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Required wire keys (space_id, ticket_id, user_sub) have NO default, so a missing key surfaces a
 * JsonDataException. Everything else is nullable with a null default (or an empty-list default for embedded
 * collections); extra / unknown wire keys are tolerated leniently by the reflective adapter.
 *
 * ENUM-LIKE FIELDS: status, role, visibility and sender_role are decoded as RAW Strings (see
 * [TicketConstants] for the documented constants). They are NOT Kotlin enums, so an unexpected / unknown
 * server value NEVER fails deserialization - no custom Moshi adapter is registered and NO provideMoshi
 * change is needed.
 *
 * TIME: created_at / updated_at are EPOCH integers typed as Long.
 *
 * WIRE CONTRACT (OpenAPI / frontend-verified; relative paths, NO leading slash):
 *   GET ticket-spaces                                  -> TicketSpaceListEnvelope { items, next_cursor }
 *   GET ticket-spaces/{spaceId}                        -> TicketSpaceEnvelope     { space }
 *   GET ticket-spaces/{spaceId}/tickets                -> SpaceTicketListEnvelope { items, next_cursor }
 *   GET ticket-spaces/{spaceId}/tickets/{ticketId}     -> SpaceTicketEnvelope     { ticket }
 *
 * EMBEDDING: a space embeds members[]; a ticket embeds messages[] + activity[]. There are NO standalone
 * members / messages endpoints. List envelopes carry ONLY items + next_cursor (there is NO total).
 */

/**
 * One ticket space (a support / helpdesk space). `space_id` is required. `visibility` is an enum-like raw
 * String (see [TicketConstants.SpaceVisibility]). The detail fetch embeds [members]; the list fetch may omit
 * it (defaults to an empty list).
 */
data class TicketSpaceOut(
    @Json(name = "space_id") val spaceId: String,
    @Json(name = "name") val name: String? = null,
    @Json(name = "visibility") val visibility: String? = null,
    @Json(name = "members") val members: List<SpaceMemberOut> = emptyList(),
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/**
 * One member of a ticket space (embedded in [TicketSpaceOut.members]; there is NO standalone members
 * endpoint). Identity is `user_sub` (required). `role` is an enum-like raw String (see
 * [TicketConstants.SpaceRole]).
 */
data class SpaceMemberOut(
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "role") val role: String? = null,
)

/**
 * One ticket within a space. `ticket_id` is required. `status` is an enum-like raw String (see
 * [TicketConstants.TicketStatus]). The detail fetch embeds [messages] + [activity]; the list fetch may omit
 * both (each defaults to an empty list).
 */
data class SpaceTicketOut(
    @Json(name = "ticket_id") val ticketId: String,
    @Json(name = "space_id") val spaceId: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "messages") val messages: List<SpaceTicketMessage> = emptyList(),
    @Json(name = "activity") val activity: List<SpaceTicketActivity> = emptyList(),
)

/**
 * One message on a ticket (embedded in [SpaceTicketOut.messages]; there is NO standalone messages
 * endpoint). The author is modeled as `sender_sub` (opaque subject id) + `sender_role` (an enum-like FREE
 * String - there is NO author_type). The message text wire key is `body`. All fields are optional / nullable
 * (the row renders defensively). `created_at` is an EPOCH Long.
 */
data class SpaceTicketMessage(
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "sender_sub") val senderSub: String? = null,
    @Json(name = "sender_role") val senderRole: String? = null,
    @Json(name = "body") val body: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

/**
 * One activity / audit event on a ticket (embedded in [SpaceTicketOut.activity]). The documented fields are
 * modeled; unknown wire keys are tolerated leniently. `created_at` is an EPOCH Long.
 */
data class SpaceTicketActivity(
    @Json(name = "activity_id") val activityId: String? = null,
    @Json(name = "activity_type") val activityType: String? = null,
    @Json(name = "actor_sub") val actorSub: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

/**
 * AND-373 - request body for POST ticket-spaces/{spaceId}/tickets/{ticketId}/messages (a ticket REPLY).
 * The only field is `body` (the message text; server-validated minLength 1, maxLength 4000 - the client also
 * pre-validates 1..4000 in the composer). TEXT only this wave (no media). The response is the WHOLE updated
 * ticket ([SpaceTicketEnvelope]), NOT a single message - the new message is ticket.messages.last().
 */
data class SpaceTicketMessageReq(
    @Json(name = "body") val body: String,
)

/**
 * NAMED envelope for GET ticket-spaces/{spaceId} (the body is {"space": {...}}, NOT a bare object).
 */
data class TicketSpaceEnvelope(
    @Json(name = "space") val space: TicketSpaceOut,
)

/**
 * NAMED envelope for GET ticket-spaces/{spaceId}/tickets/{ticketId} (the body is {"ticket": {...}}).
 */
data class SpaceTicketEnvelope(
    @Json(name = "ticket") val ticket: SpaceTicketOut,
)

/**
 * Paginated envelope for GET ticket-spaces. Carries ONLY items + next_cursor (there is NO total). A null /
 * absent next_cursor means there is no further page.
 */
data class TicketSpaceListEnvelope(
    @Json(name = "items") val items: List<TicketSpaceOut> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/**
 * Paginated envelope for GET ticket-spaces/{spaceId}/tickets. Carries ONLY items + next_cursor (NO total).
 */
data class SpaceTicketListEnvelope(
    @Json(name = "items") val items: List<SpaceTicketOut> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/**
 * AND-371 - documented constants for the enum-like wire fields. These are plain String constants (NOT Kotlin
 * enums) so an unexpected server value never fails deserialization; callers compare against these names but
 * tolerate any other value. Grouped into nested objects to mirror the wire fields they describe.
 */
object TicketConstants {

    /** Values for [SpaceTicketOut.status]. `reopened` is writable only (mutations are AND-373, out of scope). */
    object TicketStatus {
        const val OPEN = "open"
        const val IN_PROGRESS = "in_progress"
        const val WAITING_ON_USER = "waiting_on_user"
        const val DONE = "done"
        const val REOPENED = "reopened"
    }

    /** Values for [SpaceMemberOut.role]. */
    object SpaceRole {
        const val OWNER = "owner"
        const val EDITOR = "editor"
        const val VIEWER = "viewer"
    }

    /** Values for [TicketSpaceOut.visibility]. */
    object SpaceVisibility {
        const val PRIVATE = "private"
        const val SHARED = "shared"
    }
}
