package com.testlogon.android.data.feed

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.HTTP
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-179 — Retrofit interface for poll voting.
 *
 * Verified contract (OpenAPI + reference/src/api/endpoints/polls.ts):
 *  - vote       -> POST   posts/{post_id}/vote   (body VoteIn {question_id, option_id} -> VoteResponse)
 *  - removeVote -> DELETE posts/{post_id}/vote   (body {question_id} -> VoteResponse)
 *  - results    -> GET    posts/{post_id}/poll-results?question_id=... (PollResultsResponse; not used
 *                  by this single-select slice but defined for completeness / future reconcile)
 *
 * Mutating POST/DELETE: cookies, Authorization: Bearer and X-CSRF-Token are attached by the
 * core-network interceptor chain; non-2xx surfaces as retrofit2.HttpException. Voting is a
 * state-changing POST and is NOT eligible for idempotent-GET backoff.
 */
interface PollApi {

    @Headers("Content-Type: application/json")
    @POST("posts/{post_id}/vote")
    suspend fun vote(
        @Path("post_id") postId: String,
        @Body body: PollVoteRequestDto,
    ): PollVoteResponseDto

    // Retrofit @HTTP allows a body on DELETE (vote-change / un-vote when allow_vote_change is true).
    @Headers("Content-Type: application/json")
    @HTTP(method = "DELETE", path = "posts/{post_id}/vote", hasBody = true)
    suspend fun removeVote(
        @Path("post_id") postId: String,
        @Body body: PollRemoveVoteRequestDto,
    ): PollVoteResponseDto

    @GET("posts/{post_id}/poll-results")
    suspend fun results(
        @Path("post_id") postId: String,
        @Query("question_id") questionId: String,
    ): PollVoteResponseDto

    /** Paginated results for a question (options sorted by count desc, write-in flags). */
    @GET("posts/{post_id}/poll-results")
    suspend fun pollResults(
        @Path("post_id") postId: String,
        @Query("question_id") questionId: String,
        @Query("top_n") topN: Int?,
        @Query("offset") offset: Int,
    ): PollResultsResponseDto

    /** Submit a voter write-in; returns the cast result + the fresh paginated results. */
    @Headers("Content-Type: application/json")
    @POST("posts/{post_id}/write-in")
    suspend fun writeIn(
        @Path("post_id") postId: String,
        @Body body: PollWriteInRequestDto,
    ): PollWriteInResponseDto
}
