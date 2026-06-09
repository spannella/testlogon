package com.testlogon.android.data.feed

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-097 / AND-100 — Retrofit interface for the consumer newsfeed and single-post read.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; cookies,
 * Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor chain. Methods
 * are suspend and return the typed DTO body; non-2xx surfaces as retrofit2.HttpException.
 *
 * Verified contract:
 *  - GET /feed (op view_feed_feed_get) — reference/src/api/endpoints/newsfeed.ts: getFeed.
 *    Params: cursor, limit (OpenAPI default 20 / min 1 / max 50; web omits it), author_id, q, from,
 *    to, has_media. There is NO `filter` param. Response { items, next_cursor } (no has_more).
 *  - GET /posts/{post_id} (op get_post_posts__post_id__get) — newsfeed.ts: getPost. Response is FeedPost.
 */
interface FeedApi {

    /** One cursor page of the authenticated user's feed. Idempotent GET. */
    @GET("feed")
    suspend fun getFeed(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("author_id") authorId: String? = null,
        @Query("q") q: String? = null,
        @Query("from") from: String? = null,
        @Query("to") to: String? = null,
        @Query("has_media") hasMedia: Boolean? = null,
    ): FeedPageDto

    /** A single post by id. Idempotent GET. */
    @GET("posts/{post_id}")
    suspend fun getPost(@Path("post_id") postId: String): PostDto

    companion object {
        const val DEFAULT_PAGE_SIZE = 20
    }
}
