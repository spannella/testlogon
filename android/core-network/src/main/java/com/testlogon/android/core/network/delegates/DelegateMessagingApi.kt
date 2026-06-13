package com.testlogon.android.core.network.delegates

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-360 - Retrofit interface for the delegate-PATH MESSAGING surface (manage-as-creator messaging).
 *
 * ATTRIBUTION IS THE PATH: the managed creator id is the {creatorId} @Path segment, NOT a header. These
 * endpoints are DISTINCT from the self messaging endpoints. Paths have NO leading slash. The shared CSRF /
 * Bearer / 401-refresh interceptors already cover these calls (NO new header interceptor). All calls are
 * suspend; the repository wraps the RAW DTO returns in ApiResult.
 *
 * LIST IS A PLAIN ARRAY: [conversations] / [messages] return BARE Lists, NOT paged envelopes. @Path
 * tokens are EXACTLY {creatorId} / {cid}.
 */
interface DelegateMessagingApi {

    /** GET the managed creator's conversations as a BARE ARRAY (gated by chat_read). */
    @GET("messaging/delegate/{creatorId}/conversations")
    suspend fun conversations(
        @Path("creatorId") creatorId: String,
    ): List<DelegatedConversationOut>

    /** GET the messages in one of the managed creator's conversations as a BARE ARRAY (gated by chat_read). */
    @GET("messaging/delegate/{creatorId}/conversations/{cid}/messages")
    suspend fun messages(
        @Path("creatorId") creatorId: String,
        @Path("cid") cid: String,
    ): List<DelegatedMessageOut>

    /**
     * POST a message into one of the managed creator's conversations (gated by chat_respond). The response
     * echoes the delegate attribution (sent_by_delegate / delegate_display_name / delegate_tag) and may
     * carry delegate_cannot_decrypt for an encrypted thread.
     */
    @Headers("Content-Type: application/json")
    @POST("messaging/delegate/{creatorId}/conversations/{cid}/messages")
    suspend fun send(
        @Path("creatorId") creatorId: String,
        @Path("cid") cid: String,
        @Body body: DelegatedSendMessageIn,
    ): DelegatedMessageOut
}
