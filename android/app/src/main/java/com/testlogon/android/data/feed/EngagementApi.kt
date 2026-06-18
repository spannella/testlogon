package com.testlogon.android.data.feed

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-173 / AND-174 / AND-175 — Retrofit interface for feed content-engagement mutations + comment reads.
 *
 * Paths are relative (no leading slash, NO `/ui` prefix) so they resolve against the shared Retrofit
 * base URL; the cookie jar, Authorization: Bearer and X-CSRF-Token headers are attached by the
 * core-network interceptor chain (these are mutating POST/DELETE requests, so CSRF is mandatory and
 * they are NOT eligible for the idempotent-GET backoff). Ack-only mutations (like/unlike,
 * delete-comment, hide/unhide) return Unit: a 2xx (even an empty body) completes normally and any
 * non-2xx surfaces as retrofit2.HttpException (the repository maps it to ApiResult.Failure). Comment
 * list/add return the typed body and likewise surface non-2xx as HttpException.
 *
 * Verified contract — reference/src/api/endpoints/newsfeed.ts:
 *  - likePost   -> POST /posts/{post_id}/like        (newsfeed.ts:64)
 *  - unlikePost -> POST /posts/{post_id}/unlike      (newsfeed.ts:67)
 *  - getComments-> GET  /posts/{post_id}/comments    (newsfeed.ts:70; params cursor[, limit])
 *  - createComment -> POST /posts/{post_id}/comments (newsfeed.ts:76; resp FeedComment, status 200)
 *  - deleteComment -> DELETE /posts/{post_id}/comments/{comment_id} (newsfeed.ts:122)
 *  - hidePost   -> POST /feed/hide                   (newsfeed.ts:127; body HidePostReq)
 *  - unhide     -> POST /feed/unhide                 (postHide.ts: unhidePost; idempotent)
 */
interface EngagementApi {

    // ---- Likes (AND-173) ----

    @POST("posts/{post_id}/like")
    suspend fun like(@Path("post_id") postId: String)

    @POST("posts/{post_id}/unlike")
    suspend fun unlike(@Path("post_id") postId: String)

    // ---- Comments (AND-174) ----

    @GET("posts/{post_id}/comments")
    suspend fun getComments(
        @Path("post_id") postId: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): CommentPageDto

    @POST("posts/{post_id}/comments")
    suspend fun addComment(
        @Path("post_id") postId: String,
        @Body body: CreateCommentRequest,
    ): CommentDto

    @retrofit2.http.PATCH("posts/{post_id}/comments/{comment_id}")
    suspend fun editComment(
        @Path("post_id") postId: String,
        @Path("comment_id") commentId: String,
        @Body body: EditCommentRequest,
    ): CommentDto

    @DELETE("posts/{post_id}/comments/{comment_id}")
    suspend fun deleteComment(
        @Path("post_id") postId: String,
        @Path("comment_id") commentId: String,
    )

    /** Tip a comment (creator monetization). 2xx ack; amount is integer cents. */
    @POST("posts/{post_id}/comments/{comment_id}/tip")
    suspend fun tipComment(
        @Path("post_id") postId: String,
        @Path("comment_id") commentId: String,
        @Body body: TipRequest,
    )

    // ---- Hide / not-interested (AND-175) ----

    @POST("feed/hide")
    suspend fun hide(@Body body: HidePostRequest)

    @POST("feed/unhide")
    suspend fun unhide(@Body body: HidePostRequest)

    companion object {
        const val COMMENTS_PAGE_SIZE = 20
    }
}
