package com.testlogon.android.data.clips

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.feature.videos.FakeVideosRepository
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-196 / AND-198 — contract tests for [ClipsRepositoryImpl] against MockWebServer. Verifies
 * path/verb/params for ui/clips and broadcast/(public/)clips/{clip_id}, the ClipListOut /
 * ClipOut / PublicClipOut envelopes, `next_cursor` forwarding, the public no-auth path, and
 * 404/422/timeout mapping. The videos dependency is faked (playback-url resolution is unit-tested
 * separately).
 */
class ClipsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): ClipsRepositoryImpl {
        val api = backend.retrofit(moshi).create(ClipsApi::class.java)
        return ClipsRepositoryImpl(
            api = api,
            videosRepository = FakeVideosRepository(),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun feed_decodesClips_nextCursor_andRequestLine() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"clips":[
                   {"clip_id":"clp_1","session_id":"ses_1","broadcaster_user_id":"b1",
                    "creator_user_id":"c1","creator_display_name":"Alex","video_id":"vid_1",
                    "title":"behind the scenes","start_seconds":12.0,"end_seconds":26.2,
                    "duration_seconds":14.2,"status":"ready","view_count":5400,"share_count":12,
                    "thumbnail_url":"http://h/p.jpg","created_at":1733443200}
                ],"next_cursor":"cur2"}""",
            ),
        )
        val result = repo().feed(cursor = null, sort = ClipsApi.SORT_RECENT, limit = 10)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        val clip = page.items.single()
        assertEquals("clp_1", clip.clipId)
        assertEquals("vid_1", clip.videoId)
        assertEquals("behind the scenes", clip.title)
        assertEquals(ClipStatus.READY, clip.status)
        assertEquals(14, clip.durationSec)
        assertEquals("cur2", page.nextCursor)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/clips", req.requestUrl?.encodedPath)
        assertEquals("recent", req.requestUrl?.queryParameter("sort"))
        assertEquals("10", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun feed_forwardsCursor_andTerminatesOnNull() = runTest {
        backend.enqueue(Fixtures.okBody("""{"clips":[],"next_cursor":null}"""))
        val result = repo().feed(cursor = "cur2", sort = ClipsApi.SORT_RECENT, limit = 10)
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.items.isEmpty())
        assertNull(result.data.nextCursor)
        assertEquals("cur2", backend.takeRequest().requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun publicClip_decodesAttribution_andRequestLine_noAuthHeader() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"clip_id":"clp_1","session_id":"ses_1","broadcaster_user_id":"b1",
                   "creator_user_id":"c1","creator_display_name":"Alex","video_id":"vid_1",
                   "title":"public clip","start_seconds":0.0,"end_seconds":10.0,"duration_seconds":10.0,
                   "status":"ready","view_count":1,"share_count":0,"thumbnail_url":"http://h/p.jpg",
                   "created_at":1733443200,"broadcaster_display_name":"Casey","profile_id":"prof_9"}""",
            ),
        )
        val result = repo().publicClip("clp_1")
        assertTrue(result is ApiResult.Success)
        val clip = (result as ApiResult.Success).data
        assertEquals("Casey", clip.broadcasterDisplayName)
        assertEquals("prof_9", clip.profileId)

        val req = backend.takeRequest()
        assertEquals("/broadcast/public/clips/clp_1", req.requestUrl?.encodedPath)
        // The test client attaches no auth headers; assert the request is genuinely unauthenticated.
        assertNull(req.getHeader("Authorization"))
    }

    @Test
    fun getClip_authedSingle_decodes_andRequestLine() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"clip_id":"clp_1","video_id":"vid_1","title":"t","start_seconds":0.0,
                   "end_seconds":5.0,"duration_seconds":5.0,"status":"ready","created_at":1}""",
            ),
        )
        val result = repo().clip("clp_1")
        assertTrue(result is ApiResult.Success)
        assertEquals("/broadcast/clips/clp_1", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun publicClip_404_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"Not found\"", 404))
        val result = repo().publicClip("missing")
        assertTrue(result is ApiResult.Failure)
        assertEquals(404, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun feed_422_mapsToFailure() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["query","limit"],"msg":"too big","type":"less_than_equal"}]""", 422),
        )
        val result = repo().feed(cursor = null, limit = 999)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun feed_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        assertTrue(repo().feed(cursor = null, limit = 10) is ApiResult.NetworkError)
    }
}
