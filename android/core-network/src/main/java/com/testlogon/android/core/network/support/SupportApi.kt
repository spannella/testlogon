package com.testlogon.android.core.network.support

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * B-SUP (batch 7) — Retrofit interface for the role-aware SUPPORT TICKET surface (the simple async-ticket
 * API `/tickets`, distinct from the AND-371 collaborative `ticket-spaces` surface).
 *
 * The SAME endpoints serve both roles; the SERVER branches on the caller's admin role (verified live):
 *  - USER  `GET /tickets`  -> only the caller's own tickets (owner_sub = self).
 *  - ADMIN `GET /tickets`  -> the full queue (+ status / assignee / priority filters).
 *  - USER + ADMIN can `POST /tickets`, `GET /tickets/{id}`, `POST /tickets/{id}/messages`.
 *  - ADMIN only: `GET /tickets/admin/summary`, `POST /tickets/{id}/assign`, `POST /tickets/{id}/status`
 *    (these 403 for a non-admin — defence in depth).
 *
 * Paths have NO leading slash (relative to the shared authenticated Retrofit base URL); the session cookie +
 * X-CSRF-Token are attached by the global interceptors. The list endpoint returns `{items,next_cursor}`;
 * every single-ticket call returns a NAMED `{ticket}` envelope.
 */
interface SupportApi {

    /** Create a ticket (the [SupportCreateTicketReq.description] becomes the first message). */
    @POST("tickets")
    suspend fun createTicket(@Body body: SupportCreateTicketReq): SupportTicketEnvelope

    /**
     * List tickets. For a USER the server returns only their own tickets regardless of args. For an ADMIN the
     * [status] / [assigneeAdminSub] / [priority] filters apply. Pass [cursor] for the next page.
     */
    @GET("tickets")
    suspend fun listTickets(
        @Query("status") status: String? = null,
        @Query("priority") priority: String? = null,
        @Query("assignee_admin_sub") assigneeAdminSub: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): SupportTicketListEnvelope

    /** GET one ticket (NAMED {ticket} envelope; embeds messages[] + activity[]). */
    @GET("tickets/{ticketId}")
    suspend fun getTicket(@Path("ticketId") ticketId: String): SupportTicketEnvelope

    /** POST a reply/message to a ticket. Returns the WHOLE updated ticket (message = messages.last()). */
    @POST("tickets/{ticketId}/messages")
    suspend fun addMessage(
        @Path("ticketId") ticketId: String,
        @Body body: SupportTicketMessageReq,
    ): SupportTicketEnvelope

    /** ADMIN-only: change a ticket's status (open|in_progress|waiting_on_user|done|reopened). 403 for users. */
    @POST("tickets/{ticketId}/status")
    suspend fun setStatus(
        @Path("ticketId") ticketId: String,
        @Body body: SupportTicketStatusReq,
    ): SupportTicketEnvelope

    /** ADMIN-only: assign a ticket to an admin. 403 for users. */
    @POST("tickets/{ticketId}/assign")
    suspend fun assign(
        @Path("ticketId") ticketId: String,
        @Body body: SupportAssignTicketReq,
    ): SupportTicketEnvelope

    /** ADMIN-only: the queue summary (counts by status, unassigned, stale). 403 for users. */
    @GET("tickets/admin/summary")
    suspend fun adminSummary(): SupportAdminSummaryEnvelope

    /**
     * B8 B-SUP2 #15: the ticket OWNER (or an admin) closes/cancels their OWN ticket. action=close -> status
     * "done"; action=cancel -> status "cancelled". Distinct from the admin-only POST /tickets/{id}/status
     * (which 403s for a normal user). Returns the WHOLE updated ticket ({ticket} envelope).
     */
    @POST("tickets/{ticketId}/close")
    suspend fun closeTicket(
        @Path("ticketId") ticketId: String,
        @Body body: SupportCloseTicketReq,
    ): SupportTicketEnvelope

    /**
     * Helpdesk #17 (B-HELP2): the ticket OWNER (or an admin) REOPENS a closed/cancelled ticket. The
     * terminal status (done|cancelled) goes back to "open" so the owner can reply again. Empty POST body.
     * Returns the WHOLE updated ticket ({ticket} envelope).
     */
    @POST("tickets/{ticketId}/reopen")
    suspend fun reopenTicket(
        @Path("ticketId") ticketId: String,
    ): SupportTicketEnvelope
}

// ------------------------------- request bodies -------------------------------

@JsonClass(generateAdapter = true)
data class SupportCreateTicketReq(
    @Json(name = "subject") val subject: String,
    @Json(name = "description") val description: String,
    @Json(name = "priority") val priority: String? = "medium",
    /** Helpdesk #14 (B-HELP2): an optional image attached to the opening message. Omitted when null. */
    @Json(name = "image_url") val imageUrl: String? = null,
    /**
     * B10 B-HELPMEDIA #5: an ordered LIST of media/attachments (like a newsfeed post) on the opening
     * message: images + videos + uploaded files + file-manager file refs. Max 10. Omitted when empty.
     */
    @Json(name = "media") val media: List<SupportTicketMediaDto>? = null,
)

@JsonClass(generateAdapter = true)
data class SupportTicketMessageReq(
    @Json(name = "body") val body: String,
    /** Helpdesk #14 (B-HELP2): an optional image attached to this reply. Omitted when null. */
    @Json(name = "image_url") val imageUrl: String? = null,
    /** B10 B-HELPMEDIA #5: an ordered LIST of media/attachments on this reply (see create req). */
    @Json(name = "media") val media: List<SupportTicketMediaDto>? = null,
)

/**
 * B10 B-HELPMEDIA #5: one media/attachment item on a ticket or reply, mirroring the backend
 * `TicketMediaIn` / projected media item. Used for BOTH the request (what the client sends) and the
 * response (what the server echoes back per message). `kind` is one of:
 *  - "image" / "video" / "file": an uploaded asset addressed by [url] (a platform upload URL).
 *  - "file_ref": a file-manager VFS file addressed by [path] (the server resolves it to name /
 *    content_type / size / thumbnail on read, so the response carries those fields).
 * All non-kind fields are optional; the client sends only what it has, the server fills the rest.
 */
@JsonClass(generateAdapter = true)
data class SupportTicketMediaDto(
    @Json(name = "kind") val kind: String = "image",
    @Json(name = "url") val url: String? = null,
    @Json(name = "path") val path: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "content_type") val contentType: String? = null,
    @LenientLong @Json(name = "size_bytes") val sizeBytes: Long? = null,
    @LenientInt @Json(name = "width") val width: Int? = null,
    @LenientInt @Json(name = "height") val height: Int? = null,
    /** Server-resolved (file_ref) preview/thumbnail URL, when present. */
    @Json(name = "thumbnail") val thumbnail: String? = null,
)

@JsonClass(generateAdapter = true)
data class SupportTicketStatusReq(
    @Json(name = "status") val status: String,
)

@JsonClass(generateAdapter = true)
data class SupportAssignTicketReq(
    @Json(name = "assignee_admin_sub") val assigneeAdminSub: String,
)

@JsonClass(generateAdapter = true)
data class SupportCloseTicketReq(
    /** "close" -> done, "cancel" -> cancelled. */
    @Json(name = "action") val action: String,
)

// ------------------------------- response DTOs --------------------------------

@JsonClass(generateAdapter = true)
data class SupportTicketEnvelope(
    @Json(name = "ticket") val ticket: SupportTicketDto,
)

@JsonClass(generateAdapter = true)
data class SupportTicketListEnvelope(
    @Json(name = "items") val items: List<SupportTicketDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class SupportTicketDto(
    @Json(name = "ticket_id") val ticketId: String? = null,
    @Json(name = "subject") val subject: String? = null,
    @Json(name = "owner_sub") val ownerSub: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "priority") val priority: String? = null,
    @Json(name = "case_number") val caseNumber: String? = null,
    @Json(name = "assigned_admin_sub") val assignedAdminSub: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "messages") val messages: List<SupportTicketMessageDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SupportTicketMessageDto(
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "sender_sub") val senderSub: String? = null,
    @Json(name = "sender_role") val senderRole: String? = null,
    @Json(name = "body") val body: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    /** Helpdesk #14 (B-HELP2): an image attached to this message (rendered in the thread), or null. */
    @Json(name = "image_url") val imageUrl: String? = null,
    /** B10 B-HELPMEDIA #5: the ordered media/attachment list projected back per message. */
    @Json(name = "media") val media: List<SupportTicketMediaDto>? = null,
)

@JsonClass(generateAdapter = true)
data class SupportAdminSummaryEnvelope(
    @Json(name = "summary") val summary: SupportAdminSummaryDto,
)

@JsonClass(generateAdapter = true)
data class SupportAdminSummaryDto(
    @Json(name = "by_status") val byStatus: Map<String, Int> = emptyMap(),
    @Json(name = "unassigned_count") val unassignedCount: Int = 0,
    @Json(name = "stale_count") val staleCount: Int = 0,
    @Json(name = "stale_after_seconds") val staleAfterSeconds: Int = 0,
    @Json(name = "total_count") val totalCount: Int = 0,
)
