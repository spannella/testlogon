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
 * AND-373 - the client-side lifecycle of an OPTIMISTIC ticket reply. Server-confirmed messages are always
 * [SENT]; an in-flight optimistic reply starts [SENDING] and either reconciles to the server-confirmed message
 * (still [SENT]) or, on a non-cancellation failure, flips to [FAILED] (the user may tap retry - there is NO
 * auto-retry because the reply POST is non-idempotent). This enum lives in core-model so both the ViewModel and
 * the UI bubble can switch on it exhaustively.
 */
enum class TicketSendState { SENDING, FAILED, SENT }

/**
 * One message on a ticket (embedded in [Ticket.messages]). The author is the opaque [senderSub] (no display
 * name on the wire - the UI renders the sub). [senderRole] is a RAW String. [createdAt] is an EPOCH-seconds
 * [Long].
 *
 * AND-373 - augmented with an OPTIMISTIC SEND lifecycle so the SAME type renders both server messages and the
 * member's in-flight reply (the AND-372 thread already renders [TicketMessage], so we reuse it rather than fork
 * onto a separate messaging Message model - see the AND-373 reconciliation note). Both fields are DEFAULTED so
 * every existing AND-371/372 mapper, fake and test is unaffected: [sendState] defaults to [TicketSendState.SENT]
 * (the wire mapper leaves it at SENT) and [clientId] (the optimistic-dedupe key) defaults to null on a wire
 * message. An optimistic reply is created with a generated [clientId] + [TicketSendState.SENDING]; on reconcile
 * it is replaced by the canonical server message (matched by [messageId]).
 */
data class TicketMessage(
    val messageId: String? = null,
    val senderSub: String? = null,
    val senderRole: String? = null,
    val body: String? = null,
    val createdAt: Long? = null,
    val sendState: TicketSendState = TicketSendState.SENT,
    val clientId: String? = null,
)
