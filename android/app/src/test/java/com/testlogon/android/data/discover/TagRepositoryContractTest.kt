package com.testlogon.android.data.discover

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-183 — contract tests for [TagRepositoryImpl] against MockWebServer. Verifies path/params, the
 * { tag, posts, next_cursor } envelope, FeedPost mapping (incl. video thumbnail), cursor forwarding,
 * empty-tag (200) -> empty page, and 422 mapping.
 */
class TagRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): TagRepositoryImpl {
        val api = backend.retrofit(moshi).create(DiscoverApi::class.java)
        return TagRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getTagPage_page1_noCursor_decodesPosts_andMapsVideoThumb() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"tag":"kotlin","posts":[
                   {"post_id":"post_1","author_id":"u_1","created_at":"2026-06-01T12:00:00Z","body":"Coroutines",
                    "video":{"video_id":"vid_1","title":"Intro","thumbnail_url":"http://h/t.jpg","duration_seconds":612}}
                ],"next_cursor":"c1"}""",
            ),
        )
        val result = repo().getTagPage(tag = "kotlin", cursor = null, limit = 24)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals("post_1", page.posts.single().id)
        assertEquals("c1", page.nextCursor)
        val media = page.posts.single().media.single()
        assertEquals("http://h/t.jpg", media.thumbnailUrl)
        assertEquals(612L, media.durationSeconds)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/discover/tags/kotlin", req.requestUrl?.encodedPath)
        assertEquals("24", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun getTagPage_forwardsCursor_andTerminatesOnNull() = runTest {
        backend.enqueue(Fixtures.okBody("""{"tag":"art","posts":[],"next_cursor":null}"""))
        val result = repo().getTagPage(tag = "art", cursor = "c1", limit = 24)
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.posts.isEmpty())
        assertNull(result.data.nextCursor)
        assertEquals("c1", backend.takeRequest().requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun getTagPage_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","tag"],"msg":"bad","type":"value_error"}]""", 422))
        val result = repo().getTagPage(tag = "bad", cursor = null, limit = 24)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getTagPage_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().getTagPage(tag = "kotlin", cursor = null, limit = 24)
        assertTrue(result is ApiResult.NetworkError)
    }
}
