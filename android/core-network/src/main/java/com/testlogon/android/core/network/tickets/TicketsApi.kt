package com.testlogon.android.core.network.tickets

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-371 - Retrofit interface for the TICKET SPACES (support / helpdesk) READ surface. Transport only; a
 * later repository layer wraps these RAW DTO returns. All four calls are idempotent suspend GETs.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase).
 * @Path tokens are EXACTLY {spaceId} and {ticketId}. The shared authenticated client attaches the session
 * cookie via the global interceptors - there is NO cookieless client here.
 *
 * RETURN SHAPES (OpenAPI / frontend-verified):
 *  - listSpaces / listTickets return PAGINATED list envelopes { items, next_cursor } (NO total).
 *  - getSpace / getTicket return NAMED envelopes ({space} / {ticket}), NOT bare objects.
 *  - A space embeds members[]; a ticket embeds messages[] + activity[] (NO standalone members / messages
 *    endpoints). Member mutation + message posting are AND-373 (out of scope here).
 *
 * The optional `cursor` query is sent only when non-null (Retrofit drops a null @Query); a `limit` query is
 * NOT modeled (the web client is not confirmed to send one - see the AND-371 open assumption).
 */
interface TicketsApi {

    /** GET the caller's ticket spaces (paginated envelope). Pass [cursor] to fetch the next page. */
    @GET("ticket-spaces")
    suspend fun listSpaces(
        @Query("cursor") cursor: String? = null,
    ): TicketSpaceListEnvelope

    /** GET one ticket space (NAMED {space} envelope; the space embeds members[]). */
    @GET("ticket-spaces/{spaceId}")
    suspend fun getSpace(
        @Path("spaceId") spaceId: String,
    ): TicketSpaceEnvelope

    /** GET the tickets in a space (paginated envelope). Pass [cursor] to fetch the next page. */
    @GET("ticket-spaces/{spaceId}/tickets")
    suspend fun listTickets(
        @Path("spaceId") spaceId: String,
        @Query("cursor") cursor: String? = null,
    ): SpaceTicketListEnvelope

    /** GET one ticket (NAMED {ticket} envelope; the ticket embeds messages[] + activity[]). */
    @GET("ticket-spaces/{spaceId}/tickets/{ticketId}")
    suspend fun getTicket(
        @Path("spaceId") spaceId: String,
        @Path("ticketId") ticketId: String,
    ): SpaceTicketEnvelope
}
