package com.testlogon.android.data.messaging.typing

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-146 — typing send/poll Retrofit interface.
 *
 * Verified against openapi.index.txt + reference/src/api/endpoints/messaging.ts:
 *  - POST messaging/conversations/{id}/typing  (req TypingIn { is_typing: bool, default true })
 *  - GET  messaging/conversations/{id}/typing  -> TypingUser[] ({ user_id, updated_at })
 * The POST is state-changing → the shared CSRF interceptor attaches X-CSRF-Token. The success body
 * is ignored (best-effort, FR-8); any 2xx is success.
 */
interface TypingApi {

    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/typing")
    suspend fun setTyping(
        @Path("id") conversationId: String,
        @Body body: TypingReq,
    )

    @GET("messaging/conversations/{id}/typing")
    suspend fun getTyping(@Path("id") conversationId: String): List<TypingUserDto>
}

/** TypingIn { is_typing }. */
@JsonClass(generateAdapter = true)
data class TypingReq(@Json(name = "is_typing") val isTyping: Boolean)

/** TypingUser { user_id, updated_at } (epoch seconds). No display name on the wire. */
@JsonClass(generateAdapter = true)
data class TypingUserDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
)
