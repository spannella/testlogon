package com.testlogon.android.data.vod.adsupported

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-194 — contract tests for [VodAdSupportedRepositoryImpl] against MockWebServer
 * (TC-AND-194-01/02/03). Asserts paths/methods, seconds->millis mapping, single creative per break,
 * default event_type, and the server-authoritative gating fields.
 */
class VodAdSupportedRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): VodAdSupportedRepositoryImpl {
        val api = backend.retrofit(moshi).create(VodAdSupportedApi::class.java)
        return VodAdSupportedRepositoryImpl(api, ApiErrorParser(moshi), VodAdBaseUrlProvider { "http://localhost/" })
    }

    @Test
    fun start_parsesPlaybackGrant_andSchedule() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"session_id":"avod_1","video_id":"v1","status":"active",
                   "playback_url":"https://cdn/master.m3u8","manifest_key":"k","mode":"ad_supported",
                   "token_expires_at":1733446800,"breaks_total":2,"breaks_completed":0,
                   "next_required_break_id":"br_pre","playback_unlocked":false,"ads_free":false,
                   "created_at":1,"updated_at":1,
                   "ad_schedule":[
                     {"break_id":"br_pre","slot_type":"pre_roll","position_seconds":0,
                      "duration_seconds":15,"creative_id":"cr_a","creative_url":"a.m3u8",
                      "creative_type":"video","skip_after_seconds":5,"slot_index":0,"completed":false},
                     {"break_id":"br_mid1","slot_type":"mid_roll","position_seconds":900,
                      "duration_seconds":30,"creative_id":"cr_b","creative_url":"b.m3u8",
                      "creative_type":"video","skip_after_seconds":5,"slot_index":1,"completed":false}]}""".trimIndent(),
            ),
        )
        val r = repo().start("v1")
        assertTrue(r is ApiResult.Success)
        val s = (r as ApiResult.Success).data
        assertEquals("https://cdn/master.m3u8", s.playbackUrl)
        assertEquals(2, s.adSchedule.size)
        assertEquals(0L, s.adSchedule[0].positionMs)        // pre_roll
        assertEquals(900_000L, s.adSchedule[1].positionMs)  // 900s -> ms
        // AND-194: relative creative URLs are absolutized against the runtime base URL.
        assertEquals("http://localhost/a.m3u8", s.adSchedule[0].creativeUrl)
        assertEquals("http://localhost/b.m3u8", s.adSchedule[1].creativeUrl)
        assertFalse(s.playbackUnlocked)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/vod/ad-supported/v1/start", req.requestUrl?.encodedPath)
    }

    @Test
    fun getSession_isGet_noPlaybackGrant() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"session_id":"avod_1","video_id":"v1","status":"active","ad_schedule":[],
                   "breaks_total":2,"breaks_completed":0,"next_required_break_id":"br_pre",
                   "playback_unlocked":false,"ads_free":false,"created_at":1,"updated_at":1}""".trimIndent(),
            ),
        )
        val r = repo().getSession("v1")
        assertTrue(r is ApiResult.Success)
        assertEquals("", (r as ApiResult.Success).data.playbackUrl)
        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/vod/ad-supported/v1/session", req.requestUrl?.encodedPath)
    }

    @Test
    fun reportBreak_postsEventType_andAppliesUnlock() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"session_id":"avod_1","video_id":"v1","break_id":"br_mid1",
                   "event_type":"complete","completed":true,"breaks_completed":2,"breaks_total":2,
                   "next_required_break_id":null,"playback_unlocked":true,"status":"active"}""".trimIndent(),
            ),
        )
        val r = repo().reportBreak("v1", "br_mid1", "complete")
        assertTrue(r is ApiResult.Success)
        val report = (r as ApiResult.Success).data
        assertTrue(report.playbackUnlocked)
        assertNull(report.nextRequiredBreakId)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/vod/ad-supported/v1/break", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("br_mid1", body["break_id"])
        assertEquals("complete", body["event_type"])
    }

    @Test
    fun start_422_mapsFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["x"],"msg":"bad","type":"value_error"}]""", 422))
        assertTrue(repo().start("v1") is ApiResult.Failure)
    }
}
