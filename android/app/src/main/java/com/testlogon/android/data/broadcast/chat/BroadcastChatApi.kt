package com.testlogon.android.data.broadcast.chat

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-281 — dedicated Retrofit interface for the broadcast live-chat mutations + history seed.
 *
 * VERIFIED against reference/openapi.index.txt + src/api/endpoints/broadcast-chat.ts:
 *  - GET  broadcast/sessions/{id}/chat?limit=&before=   -> BroadcastChatHistoryOut
 *  - POST broadcast/sessions/{id}/chat (BroadcastChatSendIn) -> 201 BroadcastChatMessageOut
 *  - POST broadcast/sessions/{id}/chat/{messageId}/react (BroadcastChatReactIn) -> { ok, reactions_counts }
 *
 * The SSE stream (GET .../chat/stream) is NOT a Retrofit call — it is consumed by [SseBroadcastChatStream].
 * There is NO room-level reaction endpoint and NO client_id on the send body. This is a DEDICATED chat
 * API distinct from MessagingApi (the messaging FakeApi is untouched).
 */
interface BroadcastChatApi {

    @GET("broadcast/sessions/{id}/chat")
    suspend fun history(
        @Path("id") sessionId: String,
        @Query("limit") limit: Int = 100,
        @Query("before") before: String? = null,
    ): Response<ChatHistoryDto>

    @POST("broadcast/sessions/{id}/chat")
    suspend fun send(
        @Path("id") sessionId: String,
        @Body body: SendChatDto,
    ): Response<ChatMessageDto>

    @POST("broadcast/sessions/{id}/chat/{messageId}/react")
    suspend fun reactToMessage(
        @Path("id") sessionId: String,
        @Path("messageId") messageId: String,
        @Body body: ReactionDto,
    ): Response<ReactResultDto>
}

/** BroadcastChatMessageOut (== the chat:message frame data). `created_at` is epoch SECONDS. */
@JsonClass(generateAdapter = true)
data class ChatMessageDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "sender_id") val senderId: String = "",
    @Json(name = "sender_display_name") val senderDisplayName: String = "",
    @Json(name = "text") val text: String? = null,
    @Json(name = "kind") val kind: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "deleted") val deleted: Boolean = false,
    @Json(name = "reactions_counts") val reactionsCounts: Map<String, Int>? = null,
    @Json(name = "my_reactions") val myReactions: List<String>? = null,
)

/** BroadcastChatHistoryOut — { messages, has_more, oldest_sort_key }. */
@JsonClass(generateAdapter = true)
data class ChatHistoryDto(
    @Json(name = "messages") val messages: List<ChatMessageDto> = emptyList(),
    @Json(name = "has_more") val hasMore: Boolean = false,
    @Json(name = "oldest_sort_key") val oldestSortKey: String? = null,
)

/** BroadcastChatSendIn — { text } (+ optional fields not used by the viewer composer). NO client_id. */
@JsonClass(generateAdapter = true)
data class SendChatDto(
    @Json(name = "text") val text: String,
)

/** BroadcastChatReactIn — { emoji, action: add|remove }. */
@JsonClass(generateAdapter = true)
data class ReactionDto(
    @Json(name = "emoji") val emoji: String,
    @Json(name = "action") val action: String = "add",
)

/** React POST 200 body — { ok, reactions_counts }. */
@JsonClass(generateAdapter = true)
data class ReactResultDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "reactions_counts") val reactionsCounts: Map<String, Int> = emptyMap(),
)

/** chat:reaction frame data — { message_id, counts }. */
@JsonClass(generateAdapter = true)
data class ChatReactionEventDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "counts") val counts: Map<String, Int> = emptyMap(),
)

/** chat:delete frame data — { message_id }. */
@JsonClass(generateAdapter = true)
data class ChatDeletedDto(
    @Json(name = "message_id") val messageId: String,
)

/** chat:unlock frame data — { message_id, text }. */
@JsonClass(generateAdapter = true)
data class ChatUnlockDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "text") val text: String = "",
)
