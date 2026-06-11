package com.testlogon.android.data.broadcast

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
 * AND-278 — MockWebServer contract tests for [BroadcastRepositoryImpl]. Verifies verb + resolved path +
 * query for each endpoint, the { items, has_more } / { items, count } envelopes, the top-level
 * cloudfront HLS URL carry-through, the mint POST, error propagation, and timeout -> NetworkError.
 */
class BroadcastRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): BroadcastRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return BroadcastRepositoryImpl(
            api = retrofit.create(BroadcastApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun listSessions_live_sendsStatusQueryAndDecodes() = runTest {
        backend.enqueue(Fixtures.okBody(LIVE_LIST_JSON))
        val result = repo().sessions(status = "live", limit = 50)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        val session = page.items.single()
        assertEquals(BroadcastSessionStatus.LIVE, session.status)
        assertEquals("https://stream.testlogon.dev/bcs_01HX1/index.m3u8", session.playbackUrl)
        assertEquals("Friday Night Live", session.name)
        assertFalse(page.hasMore)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions", req.requestUrl?.encodedPath)
        assertEquals("live", req.requestUrl?.queryParameter("status"))
        assertEquals("50", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun listSessions_noStatus_omitsQuery() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"has_more":false}"""))
        repo().sessions()
        val req = backend.takeRequest()
        assertEquals("/broadcast/sessions", req.requestUrl?.encodedPath)
        assertNull(req.requestUrl?.queryParameter("status"))
        assertNull(req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun listScheduled_dedicatedRoute_countEnvelope() = runTest {
        backend.enqueue(Fixtures.okBody(SCHEDULED_LIST_JSON))
        val result = repo().scheduledSessions(limit = 50)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(1, page.count)
        assertEquals(BroadcastSessionStatus.SCHEDULED, page.items.single().status)
        assertNull(page.items.single().playbackUrl)

        val req = backend.takeRequest()
        assertEquals("/broadcast/sessions/scheduled", req.requestUrl?.encodedPath)
        assertEquals("50", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun listUpcoming_dedicatedRoute() = runTest {
        backend.enqueue(Fixtures.okBody(SCHEDULED_LIST_JSON))
        val result = repo().upcomingSessions()
        assertTrue(result is ApiResult.Success)
        assertEquals("/broadcast/sessions/upcoming", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun getSession_interpolatesPath_decodesDetail() = runTest {
        backend.enqueue(Fixtures.okBody(SINGLE_SESSION_JSON))
        val result = repo().session("bcs_01HX1")
        assertTrue(result is ApiResult.Success)
        assertEquals("bcs_01HX1", (result as ApiResult.Success).data.id)
        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_01HX1", req.requestUrl?.encodedPath)
    }

    @Test
    fun mintPlaybackUrl_post_decodes() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"session_id":"bcs_01HX1","playback_url":"https://stream.testlogon.dev/bcs_01HX1/index.m3u8?token=t","expires_at":1749322800}""",
            ),
        )
        val result = repo().mintPlaybackUrl("bcs_01HX1")
        assertTrue(result is ApiResult.Success)
        assertEquals("bcs_01HX1", (result as ApiResult.Success).data.sessionId)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_01HX1/playback-url", req.requestUrl?.encodedPath)
    }

    @Test
    fun listSessions_401_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"unauthorized\"", 401))
        val result = repo().sessions(status = "live")
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getSession_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().session("bcs_x")
        assertTrue(result is ApiResult.NetworkError)
    }

    private companion object {
        const val LIVE_LIST_JSON = """
            {"items":[
              {"id":"bcs_01HX1","profile_id":"prof_9","status":"live","name":"Friday Night Live",
               "description":"Weekly Q&A","created_by":"usr_42","created_at":"2026-06-05T22:00:00Z",
               "updated_at":"2026-06-05T23:00:05Z","started_at":"2026-06-05T23:00:00Z",
               "cloudfront_playback_url":"https://stream.testlogon.dev/bcs_01HX1/index.m3u8",
               "mediapackage_endpoint":"https://mp.testlogon.dev/bcs_01HX1",
               "thumbnail_url":"https://cdn.testlogon.dev/t/bcs_01HX1.jpg",
               "tip_total_cents":12500,"tip_count":37}
            ],"has_more":false}
        """

        const val SCHEDULED_LIST_JSON = """
            {"items":[
              {"id":"bcs_01HX2","profile_id":"prof_9","status":"scheduled","name":"Album listening party",
               "created_by":"usr_42","created_at":"2026-06-01T10:00:00Z","updated_at":"2026-06-01T10:00:00Z",
               "scheduled_at":1749319200,"schedule_status":"scheduled",
               "thumbnail_url":"https://cdn.testlogon.dev/t/bcs_01HX2.jpg"}
            ],"count":1}
        """

        const val SINGLE_SESSION_JSON = """
            {"id":"bcs_01HX1","profile_id":"prof_9","status":"live","name":"Friday Night Live",
             "created_by":"usr_42","created_at":"2026-06-05T22:00:00Z","updated_at":"2026-06-05T23:00:05Z",
             "started_at":"2026-06-05T23:00:00Z",
             "cloudfront_playback_url":"https://stream.testlogon.dev/bcs_01HX1/index.m3u8"}
        """
    }
}
