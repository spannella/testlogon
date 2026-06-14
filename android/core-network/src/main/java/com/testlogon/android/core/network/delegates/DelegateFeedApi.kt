package com.testlogon.android.core.network.delegates

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-360 - Retrofit interface for the delegate-PATH FEED surface (manage-as-creator feed traffic).
 *
 * ATTRIBUTION IS THE PATH: the managed creator id is the {creatorId} @Path segment, NOT a header. These
 * endpoints are DISTINCT from the self feed endpoints. Paths have NO leading slash (relative to the shared
 * Retrofit base URL). The shared CSRF / Bearer / 401-refresh interceptors already cover these calls - this
 * ticket adds NO new header interceptor. All calls are suspend; the repository wraps the RAW DTO returns
 * in ApiResult.
 *
 * LIST IS A PLAIN ARRAY: [listPosts] returns a BARE List of DelegatedPostOut filtered by ?limit=, NOT a
 * paged envelope. Mutations that have an empty / 204 body are typed Response of Unit and folded by
 * isSuccessful. @Path tokens are EXACTLY {creatorId} / {postId}.
 */
interface DelegateFeedApi {

    /**
     * POST a new post to the managed creator's feed (gated by feed_post at the repository). The created
     * post may carry an approval_status when the creator requires post approval - the delegate can not
     * self-approve.
     */
    @Headers("Content-Type: application/json")
    @POST("ui/newsfeed/delegate/{creatorId}/posts")
    suspend fun createPost(
        @Path("creatorId") creatorId: String,
        @Body body: DelegatedPostCreateIn,
    ): DelegatedPostOut

    /** GET the managed creator's recent feed posts as a BARE ARRAY (gated by feed_read). */
    @GET("ui/newsfeed/delegate/{creatorId}/posts")
    suspend fun listPosts(
        @Path("creatorId") creatorId: String,
        @Query("limit") limit: Int = 50,
    ): List<DelegatedPostOut>

    /** DELETE one of the managed creator's feed posts (gated by feed_post). 204 -> Response of Unit. */
    @DELETE("ui/newsfeed/delegate/{creatorId}/posts/{postId}")
    suspend fun deletePost(
        @Path("creatorId") creatorId: String,
        @Path("postId") postId: String,
    ): Response<Unit>
}
