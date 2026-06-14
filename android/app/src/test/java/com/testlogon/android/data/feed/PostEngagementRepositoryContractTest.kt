package com.testlogon.android.data.feed

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-173 — contract tests for [PostEngagementRepositoryImpl] against MockWebServer (real
 * Retrofit/Moshi). Verifies POST /posts/{id}/like + /unlike paths, that the empty ack body is NOT
 * read for state (the desired count is carried forward), and error/timeout folding.
 */
class PostEngagementRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): PostEngagementRepositoryImpl {
        val api = backend.retrofit(moshi).create(EngagementApi::class.java)
        return PostEngagementRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun like_postsCorrectPath_carriesDesiredCount() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().setLiked("p1", liked = true, desiredCount = 43)

        assertTrue(result is ApiResult.Success)
        val state = (result as ApiResult.Success).data
        assertEquals(true, state.liked)
        assertEquals(43, state.likeCount) // from desiredCount, not the body

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/posts/p1/like", req.requestUrl?.encodedPath)
    }

    @Test
    fun unlike_postsCorrectPath() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().setLiked("p1", liked = false, desiredCount = 41)

        assertTrue(result is ApiResult.Success)
        assertEquals(false, (result as ApiResult.Success).data.liked)
        assertEquals(41, result.data.likeCount)
        assertEquals("/posts/p1/unlike", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun like_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["path","post_id"],"msg":"bad","type":"value_error"}]""", 422))
        val result = repo().setLiked("p1", liked = true, desiredCount = 10)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun like_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().setLiked("p1", liked = true, desiredCount = 10)
        assertTrue(result is ApiResult.NetworkError)
    }
}
