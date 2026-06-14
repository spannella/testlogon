package com.testlogon.android.data.feed

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-179 — contract tests for [PollRepositoryImpl]. Verifies the vote path/body/CSRF-free wire shape,
 * VoteResponse parsing into the per-question [PollVoteResult], no auto-retry on POST failure, and the
 * remove-vote DELETE-with-body contract.
 */
class PollRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): PollRepositoryImpl {
        val api = backend.retrofit(moshi).create(PollApi::class.java)
        return PollRepositoryImpl(api, ApiErrorParser(moshi))
    }

    @Test
    fun vote_postsQuestionAndOption_parsesVoteResponse() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"question_id":"q_1","option_id":"opt_2",
                   "vote_counts":{"opt_1":12,"opt_2":41,"opt_3":7},"total_votes":60,
                   "my_vote":"opt_2","my_votes":["opt_2"]}""".trimIndent(),
            ),
        )
        val r = repo().vote("post_1", "q_1", "opt_2")
        assertTrue(r is ApiResult.Success)
        val result = (r as ApiResult.Success).data
        assertEquals("q_1", result.questionId)
        assertEquals(60, result.totalVotes)
        assertEquals(41, result.voteCounts["opt_2"])
        assertEquals(listOf("opt_2"), result.myVoteOptionIds)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/posts/post_1/vote", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("q_1", body["question_id"])
        assertEquals("opt_2", body["option_id"])
    }

    @Test
    fun vote_500_isFailure_andNotRetried() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        val r = repo().vote("post_1", "q_1", "opt_2")
        assertTrue(r is ApiResult.Failure)
        assertEquals(1, backend.requestCount) // non-idempotent POST: exactly one request
    }

    @Test
    fun removeVote_issuesDeleteWithQuestionBody() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"question_id":"q_1","vote_counts":{"opt_1":12},"total_votes":12}""",
            ),
        )
        val r = repo().removeVote("post_1", "q_1")
        assertTrue(r is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/posts/post_1/vote", req.requestUrl?.encodedPath)
        assertEquals("q_1", req.bodyJson()["question_id"])
    }
}
