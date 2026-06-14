package com.testlogon.android.data.broadcast.qna

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-284 — contract tests for [LiveQaRepositoryImpl]: list maps the {questions, has_more} envelope +
 * derives featured (de-duped from list); ask posts {text} and parses 200; upvote/un-upvote use
 * POST/DELETE on the SAME .../vote path and adopt the server vote_count; viewer status is NOT pending.
 */
class LiveQaRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): LiveQaRepositoryImpl {
        val api = backend.retrofit(moshi).create(LiveQaApi::class.java)
        return LiveQaRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private fun question(id: String, status: String, votes: Int) =
        """{"question_id":"$id","session_id":"s1","submitter_id":"u","submitter_display_name":"Mira",
           "text":"q $id","status":"$status","vote_count":$votes,"pinned":false,"created_at":1749142544}"""

    @Test
    fun questions_mapsEnvelope_derivesFeatured_excludesFromList() = runTest {
        // list GET (status=featured)
        backend.enqueue(
            Fixtures.okBody(
                """{"questions":[${question("q1", "featured", 12)},${question("q2", "answered", 3)}],
                   "has_more":false}""",
            ),
        )
        // featured GET
        backend.enqueue(Fixtures.okBody(question("q1", "featured", 12)))

        val result = repo().questions("s1")
        assertTrue(result is ApiResult.Success)
        val snapshot = (result as ApiResult.Success).data
        assertEquals("q1", snapshot.featured?.id)
        assertEquals(12, snapshot.featured?.upvotes)
        // q1 is de-duplicated out of the list.
        assertEquals(listOf("q2"), snapshot.questions.map { it.id })

        // The viewer list request never asks for pending.
        val listReq = backend.takeRequest()
        assertEquals("featured", listReq.requestUrl?.queryParameter("status"))
        assertFalse(listReq.requestUrl?.queryParameter("status") == "pending")
    }

    @Test
    fun questions_tolerates_nullFeaturedBody() = runTest {
        backend.enqueue(Fixtures.okBody("""{"questions":[${question("q2", "answered", 1)}],"has_more":false}"""))
        backend.enqueue(Fixtures.okBody("null"))
        val snapshot = (repo().questions("s1") as ApiResult.Success).data
        assertNull(snapshot.featured)
        assertEquals(1, snapshot.questions.size)
    }

    @Test
    fun ask_postsText_parses200() = runTest {
        backend.enqueue(Fixtures.okBody(question("q9", "pending", 0)))
        val result = repo().ask("s1", "Can you show the setup?")
        assertTrue(result is ApiResult.Success)
        assertEquals("q9", (result as ApiResult.Success).data.id)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/live-qa/sessions/s1/questions", req.requestUrl?.encodedPath)
        assertTrue(req.body.readUtf8().contains("\"text\":\"Can you show the setup?\""))
    }

    @Test
    fun setUpvote_true_postsVote_adoptsServerCount() = runTest {
        backend.enqueue(Fixtures.okBody(question("q1", "featured", 13)))
        val result = repo().setUpvote("s1", "q1", voted = true)
        assertEquals(13, (result as ApiResult.Success).data.upvotes)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/live-qa/sessions/s1/questions/q1/vote", req.requestUrl?.encodedPath)
    }

    @Test
    fun setUpvote_false_deletesVote_sameePath() = runTest {
        backend.enqueue(Fixtures.okBody(question("q1", "featured", 12)))
        val result = repo().setUpvote("s1", "q1", voted = false)
        assertEquals(12, (result as ApiResult.Success).data.upvotes)

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/live-qa/sessions/s1/questions/q1/vote", req.requestUrl?.encodedPath)
    }

    @Test
    fun ask_422_mapsFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["body","text"],"msg":"too long","type":"value_error"}]""", 422))
        val result = repo().ask("s1", "x")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
