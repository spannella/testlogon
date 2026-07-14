package com.testlogon.android.data.feed

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * SOCIAL-002 — Retrofit interface for public reposting (share a post to your own feed, with an optional
 * ≤500-char quote / commentary). Mirrors the already-shipped web client
 * (reference/src/api/endpoints/newsfeed.ts: repostPost / undoRepost / getReposts) and the backend
 * SOCIAL-002 block in app/routers/newsfeed.py.
 *
 * Paths are relative (no leading slash, NO `/ui` prefix) so they resolve against the shared Retrofit
 * base URL; the cookie jar, Authorization: Bearer and X-CSRF-Token headers are attached by the
 * core-network interceptor chain (these are mutating POST/DELETE requests, so CSRF is mandatory).
 *
 * Contract:
 *  - POST   /posts/{post_id}/repost  RepostRequest{ quote? }  -> 201 { ok, repost_id, repost_count }.
 *    Guards: 404 unpublished, 400 self-repost, 403 locked, 403 blocked, 409 already-reposted.
 *  - DELETE /posts/{post_id}/repost                            -> 200 { ok, repost_count }. 404 if not reposted.
 * Both parse a small DTO (rather than Unit) so the JSON body is consumed and the authoritative
 * repost_count can reconcile the optimistic overlay.
 */
interface RepostApi {

    @Headers("Content-Type: application/json")
    @POST("posts/{post_id}/repost")
    suspend fun repost(
        @Path("post_id") postId: String,
        @Body body: RepostRequest,
    ): RepostResponseDto

    @DELETE("posts/{post_id}/repost")
    suspend fun undoRepost(@Path("post_id") postId: String): RepostResponseDto
}

/** POST /posts/{post_id}/repost request. [quote] is an optional ≤500-char commentary (server strips HTML). */
@JsonClass(generateAdapter = true)
data class RepostRequest(
    @Json(name = "quote") val quote: String? = null,
)

/** { ok, repost_id?, repost_count } echoed by create/undo repost. */
@JsonClass(generateAdapter = true)
data class RepostResponseDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "repost_id") val repostId: String? = null,
    @Json(name = "repost_count") val repostCount: Int? = null,
)
