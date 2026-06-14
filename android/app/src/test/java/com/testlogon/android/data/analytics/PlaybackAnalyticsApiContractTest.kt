package com.testlogon.android.data.analytics

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-171 / AND-172 — MockWebServer contract test for the VERIFIED playback-analytics endpoints.
 * Asserts request path/method, the query-param transport for viewer_id (NOT a JSON body), empty POST
 * bodies, and parsing of the thin ViewRecordOut / ViewerJoinOut / ViewerHeartbeatOut shapes.
 */
class PlaybackAnalyticsApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): PlaybackAnalyticsApi =
        backend.retrofit(moshi).create(PlaybackAnalyticsApi::class.java)

    // TC-AND-171-06 — VOD one-shot view: path, empty body, parse.
    @Test
    fun recordVideoView_oneShot() = runTest {
        backend.enqueue(Fixtures.okBody("""{"view_count":42,"is_new_view":true}"""))
        val response = api().recordVideoView("vid_1")
        assertTrue(response.isSuccessful)
        assertEquals(42, response.body()?.viewCount)
        assertEquals(true, response.body()?.isNewView)

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/videos/vid_1/view", recorded.requestUrl?.encodedPath)
        assertEquals("", recorded.body.readUtf8()) // no JSON telemetry body
    }

    // TC-AND-171-05 — broadcast join + heartbeat: viewer_id is a query param, no body.
    @Test
    fun viewerJoinThenHeartbeat() = runTest {
        backend.enqueue(Fixtures.okBody("""{"viewer_id":"vwr_9","session_id":"sess_1","viewer_count":3}"""))
        val join = api().viewerJoin("sess_1")
        assertEquals("vwr_9", join.body()?.viewerId)
        assertEquals(3, join.body()?.viewerCount)
        val joinReq = backend.takeRequest()
        assertEquals("POST", joinReq.method)
        assertEquals("/broadcast/sessions/sess_1/viewers/join", joinReq.requestUrl?.encodedPath)

        backend.enqueue(Fixtures.okBody("""{"ok":true,"viewer_count":4}"""))
        val hb = api().viewerHeartbeat("sess_1", "vwr_9")
        assertEquals(true, hb.body()?.ok)
        assertEquals(4, hb.body()?.viewerCount)
        val hbReq = backend.takeRequest()
        assertEquals("/broadcast/sessions/sess_1/viewers/heartbeat", hbReq.requestUrl?.encodedPath)
        assertEquals("vwr_9", hbReq.requestUrl?.queryParameter("viewer_id"))
        assertEquals("", hbReq.body.readUtf8())
    }

    @Test
    fun viewerLeave_queryParam() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"viewer_count":2}"""))
        val leave = api().viewerLeave("sess_1", "vwr_9")
        assertTrue(leave.isSuccessful)
        val req = backend.takeRequest()
        assertEquals("/broadcast/sessions/sess_1/viewers/leave", req.requestUrl?.encodedPath)
        assertEquals("vwr_9", req.requestUrl?.queryParameter("viewer_id"))
    }
}
