package com.testlogon.android.data.poll

import com.testlogon.android.core.network.poll.PollSnapshotDto
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.HTTP
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Surface-agnostic arbitrary-poll vote / results / close client (backend app/routers/polls.py). One
 * client drives voting for MESSAGING, GROUP and SYNDICATE polls (each embeds a poll_id snapshot).
 * Every mutating call returns the updated poll snapshot.
 */
interface ArbitraryPollApi {

    @GET("ui/polls/{poll_id}")
    suspend fun get(@Path("poll_id") pollId: String): PollSnapshotDto

    @Headers("Content-Type: application/json")
    @POST("ui/polls/{poll_id}/vote")
    suspend fun vote(
        @Path("poll_id") pollId: String,
        @Body body: ArbitraryPollVoteReq,
    ): PollSnapshotDto

    @Headers("Content-Type: application/json")
    @HTTP(method = "DELETE", path = "ui/polls/{poll_id}/vote", hasBody = false)
    suspend fun unvote(
        @Path("poll_id") pollId: String,
        @Query("question_id") questionId: String?,
    ): PollSnapshotDto

    @Headers("Content-Type: application/json")
    @POST("ui/polls/{poll_id}/close")
    suspend fun close(@Path("poll_id") pollId: String): PollSnapshotDto
}
