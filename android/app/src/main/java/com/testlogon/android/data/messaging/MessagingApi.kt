package com.testlogon.android.data.messaging

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-120 — Retrofit interface for the TestLogon messaging surface.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL;
 * cookies, Authorization and `X-CSRF-Token` are attached by the core-network interceptor chain.
 * All methods are `suspend` and return the typed DTO body; non-2xx surfaces as
 * `retrofit2.HttpException`.
 *
 * Endpoints verified against reference/src/api/endpoints/messaging.ts and OpenAPI:
 *  - config           -> GET  messaging/config                                (op messaging_config)
 *  - listConversations-> GET  messaging/conversations                        (BARE array, no params)
 *  - getConversation  -> GET  messaging/conversations/{id}
 *  - listMessages     -> GET  messaging/conversations/{id}/messages?limit=&before= (BARE array)
 *  - sendMessage      -> POST messaging/conversations/{id}/messages          (200 MessageOut)
 *  - markRead         -> POST messaging/conversations/{id}/read              (empty 200 body)
 *
 * Reverse history: pass the oldest loaded message id/timestamp as `before`; a short/empty array
 * signals end-of-history (there is no next_cursor).
 */
interface MessagingApi {

    /** Messaging feature config (boolean feature flags). Idempotent GET. */
    @GET("messaging/config")
    suspend fun config(): MessagingConfigDto

    /** Full conversation list (bare array, NOT paged). Idempotent GET. */
    @GET("messaging/conversations")
    suspend fun listConversations(): List<ConversationDto>

    /** Single conversation by id. Idempotent GET. */
    @GET("messaging/conversations/{id}")
    suspend fun getConversation(@Path("id") id: String): ConversationDto

    /** Messages in a conversation (bare array); reverse history via `before`. Idempotent GET. */
    @GET("messaging/conversations/{id}/messages")
    suspend fun listMessages(
        @Path("id") id: String,
        @Query("limit") limit: Int? = null,
        @Query("before") before: String? = null,
    ): List<MessageDto>

    /** Send a text message; returns the persisted MessageOut (HTTP 200). */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages")
    suspend fun sendMessage(
        @Path("id") id: String,
        @Body body: SendTextMessageReq,
    ): MessageDto

    /** Mark a conversation read up to a message id / timestamp. Empty 200 body. */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/read")
    suspend fun markRead(
        @Path("id") id: String,
        @Body body: MarkReadReq,
    )
}
