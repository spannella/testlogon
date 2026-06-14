package com.testlogon.android.data.stories

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
 * AND-199 / AND-200 — contract tests for [StoriesRepositoryImpl] against MockWebServer. Verifies the
 * bar/user paths + envelopes, media_type/duration mapping, unknown-type fallback, recordView path +
 * dedupe + no-retry, and 422 mapping.
 */
class StoriesRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): StoriesRepositoryImpl {
        val api = backend.retrofit(moshi).create(StoriesApi::class.java)
        return StoriesRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun refreshTray_parsesBar_andPath() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"bar":[
                   {"user_id":"u1","latest_story_id":"s1","latest_media_url":"http://h/1.jpg","story_count":3,"has_unseen":true,"is_own":false},
                   {"user_id":"u2","latest_story_id":"s2","latest_media_url":null,"story_count":1,"has_unseen":false,"is_own":true}
                ]}""",
            ),
        )
        val result = repo().refreshTray()
        assertTrue(result is ApiResult.Success)
        val bar = (result as ApiResult.Success).data
        assertEquals(2, bar.size)
        assertEquals("u1", bar[0].userId)
        assertEquals(3, bar[0].storyCount)
        assertTrue(bar[0].hasUnseen)
        assertTrue(bar[1].isOwn)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/stories/bar", req.requestUrl?.encodedPath)
    }

    @Test
    fun loadAuthorStories_mapsImageVideoDuration() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"stories":[
                   {"story_id":"s1","author_id":"u1","media_type":"image","media_url":"http://h/1.jpg","expires_at":10,"view_count":4,"highlighted":false},
                   {"story_id":"s2","author_id":"u1","media_type":"video","media_url":"http://h/2.m3u8","duration_seconds":12,"expires_at":20,"view_count":2,"highlighted":false}
                ]}""",
            ),
        )
        val result = repo().loadAuthorStories("u1")
        assertTrue(result is ApiResult.Success)
        val segs = (result as ApiResult.Success).data
        assertEquals(SegmentKind.IMAGE, segs[0].kind)
        assertEquals(5_000L, segs[0].durationMs) // image always default 5000
        assertEquals(SegmentKind.VIDEO, segs[1].kind)
        assertEquals(12_000L, segs[1].durationMs) // video uses duration_seconds*1000

        assertEquals("/ui/stories/user/u1", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun loadAuthorStories_unknownType_fallsBackToImage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"stories":[{"story_id":"s1","author_id":"u1","media_type":"gif","media_url":"http://h/1.gif","expires_at":1,"view_count":0,"highlighted":false}]}""",
            ),
        )
        val result = repo().loadAuthorStories("u1")
        val seg = (result as ApiResult.Success).data.single()
        assertEquals(SegmentKind.IMAGE, seg.kind)
        assertEquals(5_000L, seg.durationMs)
    }

    @Test
    fun recordView_postsCorrectPath_dedupes_andNotRetried() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"already_viewed":false}"""))
        val r = repo()
        val first = r.recordView("s1")
        assertTrue(first is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/stories/s1/view", req.requestUrl?.encodedPath)
        assertEquals("", req.body.readUtf8())

        // Second call for the same id is deduped: no further POST is issued.
        val second = r.recordView("s1")
        assertTrue(second is ApiResult.Success)
        assertEquals(1, backend.requestCount)

        // A different id 500s; failure is swallowed into a result (not thrown) and not retried.
        backend.enqueue(Fixtures.okBody("""{"detail":"boom"}""", code = 500))
        val third = r.recordView("s2")
        assertTrue(third is ApiResult.Failure)
        assertEquals(2, backend.requestCount)
    }

    @Test
    fun refreshTray_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","x"],"msg":"bad","type":"value_error"}]""", 422))
        val result = repo().refreshTray()
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun refreshTray_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        assertTrue(repo().refreshTray() is ApiResult.NetworkError)
    }

    @Test
    fun recordView_marksLocalViewedSet() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"already_viewed":false}"""))
        val r = repo()
        assertTrue(!r.isViewed("s1"))
        r.recordView("s1")
        assertTrue(r.isViewed("s1"))
    }
}
