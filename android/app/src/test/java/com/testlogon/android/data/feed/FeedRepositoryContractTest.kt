package com.testlogon.android.data.feed

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
 * AND-097 / AND-100 / AND-104 — contract tests for [FeedRepositoryImpl] against MockWebServer (real
 * Retrofit/Moshi). Verifies path/params/verb, the { items, next_cursor } envelope, locked redaction
 * over the wire (the server over-shares body/image_urls; the mapper drops them), and error folding.
 */
class FeedRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): FeedRepositoryImpl {
        val api = backend.retrofit(moshi).create(FeedApi::class.java)
        return FeedRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getFeed_decodesPage_mapsDomain_andSendsParams() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"items":[
                  {"post_id":"post_1","author_id":"u_1","created_at":"2026-06-01T12:00:00Z",
                   "body":"hello","image_urls":["http://h/1.jpg"],"locked":false,"unlocked":true,
                   "like_count":2,"comment_count":1},
                  {"post_id":"post_2","author_id":"u_2","created_at":"2026-06-01T11:00:00Z",
                   "body":"secret body","image_urls":["http://h/paid.jpg"],
                   "locked":true,"unlocked":false,"lock_type":"fixed_price","unlock_price_cents":999}
                ],"next_cursor":"CURSOR_P2"}
                """.trimIndent(),
            ),
        )
        val result = repo().getFeedPage(cursor = "c1", limit = 20)

        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(2, page.posts.size)
        assertEquals("CURSOR_P2", page.nextCursor)

        // Open post keeps content.
        assertEquals("hello", page.posts[0].body)
        assertEquals(1, page.posts[0].media.size)

        // Locked post: redacted (no leaked body / paid url) even though the wire sent them.
        val locked = page.posts[1]
        assertTrue(locked.isLocked)
        assertNull(locked.body)
        assertTrue(locked.media.isEmpty())

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/feed", req.requestUrl?.encodedPath)
        assertEquals("c1", req.requestUrl?.queryParameter("cursor"))
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
        // No invented `filter` param is ever sent.
        assertNull(req.requestUrl?.queryParameter("filter"))
    }

    @Test
    fun getFeed_endOfFeed_nullCursor() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"next_cursor":null}"""))
        val result = repo().getFeedPage(cursor = "c2", limit = 20)
        assertTrue(result is ApiResult.Success)
        assertNull((result as ApiResult.Success).data.nextCursor)
        assertEquals("c2", backend.takeRequest().requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun getFeed_unknownFields_ignored() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[{"post_id":"p","author_id":"a","created_at":"2026-06-01T12:00:00Z",
                   "totally_new_field":123,"body":"x"}],"next_cursor":null}""",
            ),
        )
        val result = repo().getFeedPage()
        assertTrue(result is ApiResult.Success)
        assertEquals("p", (result as ApiResult.Success).data.posts[0].id)
    }

    @Test
    fun getFeed_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"msg":"invalid cursor","type":"value_error"}]""", 422))
        val result = repo().getFeedPage()
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getFeed_403_objectDetail_mapsToFailure_withCode() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"geo_blocked","message":"nope"}""", 403))
        val result = repo().getFeedPage()
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
        assertEquals("geo_blocked", result.error.code)
    }

    @Test
    fun getFeed_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().getFeedPage()
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
    }

    @Test
    fun getFeed_malformedBody_mapsToFailure_orNetwork_neverThrows() = runTest {
        backend.enqueue(Fixtures.malformed())
        val result = repo().getFeedPage()
        // A decode error surfaces as a non-success result; the repository never throws.
        assertTrue(result !is ApiResult.Success)
    }

    @Test
    fun getPost_hitsCorrectPath_mapsDomain() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"post_id":"p_9","author_id":"u_9","created_at":"2026-06-01T12:00:00Z",
                   "body":"detail body","locked":false,"unlocked":true}""",
            ),
        )
        val result = repo().getPost("p_9")
        assertTrue(result is ApiResult.Success)
        assertEquals("p_9", (result as ApiResult.Success).data.id)
        assertEquals("/posts/p_9", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun getPost_404_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error(""""not found"""", 404))
        val result = repo().getPost("missing")
        assertTrue(result is ApiResult.Failure)
        assertEquals(404, (result as ApiResult.Failure).error.status)
    }
}
