package com.testlogon.android.data.videos

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
 * AND-189 / AND-190 — contract tests for [VideosRepositoryImpl] against MockWebServer. Verifies
 * path/verb/params for ui/videos and ui/videos/{video_id}, the VideoListOut / VideoDetailOut envelopes,
 * cursor forwarding, the tokenized playback URL, and 404/422/timeout mapping.
 */
class VideosRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): VideosRepositoryImpl {
        val api = backend.retrofit(moshi).create(VideosApi::class.java)
        return VideosRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun listVideos_page1_decodesItems_andRequestLine() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"video_id":"vid_1","title":"Intro","status":"ready","visibility":"public",
                    "created_at":1746100800,"updated_at":1746100800,"thumbnail_url":"http://h/t.jpg",
                    "duration_seconds":372.0}
                ],"cursor":"c2"}""",
            ),
        )
        val result = repo().listVideos(cursor = null, limit = 24)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals("vid_1", page.items.single().id)
        assertEquals(372, page.items.single().durationSec)
        assertEquals("c2", page.cursor)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/videos", req.requestUrl?.encodedPath)
        assertEquals("24", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("cursor"))
        assertNull(req.requestUrl?.queryParameter("sort"))
    }

    @Test
    fun listVideos_forwardsCursor_andTerminatesOnNull() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"cursor":null}"""))
        val result = repo().listVideos(cursor = "c2", limit = 24)
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.items.isEmpty())
        assertNull(result.data.cursor)
        assertEquals("c2", backend.takeRequest().requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun getVideoDetail_decodesDetail_buildsPlaybackUrl_andRequestLine() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"video_id":"vid_1","owner_user_id":"u1","title":"Intro","description":"d",
                   "status":"ready","visibility":"public","created_at":1,"updated_at":2,
                   "duration_seconds":372.0,"thumbnail_url":"http://h/t.jpg",
                   "hls_manifest_url":"http://h/master.m3u8","playback_token":"tok"}""",
            ),
        )
        val result = repo().getVideoDetail("vid_1")
        assertTrue(result is ApiResult.Success)
        val detail = (result as ApiResult.Success).data
        assertEquals("vid_1", detail.id)
        assertEquals("http://h/master.m3u8?token=tok", detail.playbackUrl)
        assertEquals("/ui/videos/vid_1", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun getVideoDetail_404_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"Not found\"", 404))
        val result = repo().getVideoDetail("missing")
        assertTrue(result is ApiResult.Failure)
        assertEquals(404, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun listVideos_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","limit"],"msg":"too big","type":"less_than_equal"}]""", 422))
        val result = repo().listVideos(cursor = null, limit = 999)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun listVideos_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        assertTrue(repo().listVideos(cursor = null, limit = 24) is ApiResult.NetworkError)
    }

    @Test
    fun toggleLike_postsAndDecodes() = runTest {
        backend.enqueue(Fixtures.okBody("""{"liked":true,"like_count":5}"""))
        val result = repo().toggleLike("vid_1")
        assertTrue(result is ApiResult.Success)
        assertEquals(LikeState(liked = true, likeCount = 5), (result as ApiResult.Success).data)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/videos/vid_1/like", req.requestUrl?.encodedPath)
    }
}
