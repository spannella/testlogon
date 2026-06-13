package com.testlogon.android.core.model.tickets

/**
 * AND-372 - domain models for the READ-ONLY ticket-spaces (support / helpdesk) surface.
 *
 * core-model has NO Moshi / core-network dependency: these are plain domain types. The wire DTOs (core-network
 * AND-371 TicketDtos) carry enum-like fields (visibility / status / role) as RAW Strings; we keep them RAW here
 * too (unknown-safe - an unexpected server token never crashes the UI; the screen renders a label or falls back
 * to the raw value). The DTO -> domain bridge lives in the :app feature (TicketMappers) since core-model cannot
 * depend on core-network.
 *
 * TIME: every timestamp is an EPOCH-seconds [Long] (relative-time formatting happens at the UI). Identity ids
 * (spaceId / ticketId / userSub) are opaque, required Strings; everything else is nullable / defaulted because
 * the list fetch may omit detail-only fields (e.g. members on a list row, messages on a list row).
 */

/**
 * One ticket space (a support / helpdesk space). [memberCount] is derived from [members].size at mapping time
 * (the wire has NO member_count field - see AND-372 wire notes); the list fetch may carry an empty [members]
 * list, in which case [memberCount] is 0. [visibility] is a RAW String (private / shared, unknown-safe).
 */
data class TicketSpace(
    val spaceId: String,
    val name: String? = null,
    val visibility: String? = null,
    val members: List<SpaceMember> = emptyList(),
    val memberCount: Int = members.size,
    val updatedAt: Long? = null,
)

/** One member of a ticket space (embedded in [TicketSpace.members]). [role] is a RAW String (unknown-safe). */
data class SpaceMember(
    val userSub: String,
    val role: String? = null,
)

/**
 * One ticket within a space. [subject] is the human title (the wire key is `title`; see the AND-372 assumption
 * note - the verified DTO exposes only `title`, NOT a separate `subject`, and has NO owner_sub /
 * assigned_to_sub). [status] is a RAW String (open / in_progress / waiting_on_user / done / reopened,
 * unknown-safe). The detail fetch embeds [messages] oldest-first; the list fetch may carry an empty list.
 */
data class Ticket(
    val ticketId: String,
    val spaceId: String? = null,
    val subject: String? = null,
    val status: String? = null,
    val ownerSub: String? = null,
    val assignedToSub: String? = null,
    val updatedAt: Long? = null,
    val messages: List<TicketMessage> = emptyList(),
)

/**
 * One message on a ticket (embedded in [Ticket.messages]). The author is the opaque [senderSub] (no display
 * name on the wire - the UI renders the sub). [senderRole] is a RAW String. [createdAt] is an EPOCH-seconds
 * [Long].
 */
data class TicketMessage(
    val messageId: String? = null,
    val senderSub: String? = null,
    val senderRole: String? = null,
    val body: String? = null,
    val createdAt: Long? = null,
)
