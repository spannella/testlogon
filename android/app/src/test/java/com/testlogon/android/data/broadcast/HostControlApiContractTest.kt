package com.testlogon.android.data.broadcast

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-309 — MockWebServer contract tests for [HostControlRepositoryImpl] over [HostControlApi]. Verifies
 * verb + resolved path + body for start / stop / resume / reschedule, that reschedule's scheduled_at is an
 * INTEGER epoch second (not ISO / not scheduled_start_at), the health decode (updated_at epoch -> Instant,
 * level derived from connection_quality), and 422 -> Failure with the normalized detail[].msg. Each request
 * body is read exactly ONCE.
 */
class HostControlApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): HostControlRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return HostControlRepositoryImpl(
            api = retrofit.create(HostControlApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun start_postsReason_decodesLive() = runTest {
        backend.enqueue(Fixtures.okBody(LIVE_SESSION_JSON, code = 202))
        val result = repo().start("bcs_1")
        assertTrue(result is ApiResult.Success)
        assertEquals(BroadcastSessionStatus.LIVE, (result as ApiResult.Success).data.status)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/start", req.requestUrl?.encodedPath)
        assertEquals("operator-request", req.bodyJson()["reason"])
    }

    @Test
    fun stop_postsReason_decodesStopped() = runTest {
        backend.enqueue(Fixtures.okBody(STOPPED_SESSION_JSON, code = 202))
        val result = repo().stop("bcs_1")
        assertTrue(result is ApiResult.Success)
        assertEquals(BroadcastSessionStatus.STOPPED, (result as ApiResult.Success).data.status)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/stop", req.requestUrl?.encodedPath)
        assertEquals("operator-request", req.bodyJson()["reason"])
    }

    @Test
    fun resume_postsNoBody_decodesSession() = runTest {
        backend.enqueue(Fixtures.okBody(LIVE_SESSION_JSON))
        val result = repo().resume("bcs_1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/resume", req.requestUrl?.encodedPath)
        assertTrue(req.bodyJson().isEmpty())
    }

    @Test
    fun reschedule_postsIntegerScheduledAt_decodesSession() = runTest {
        backend.enqueue(Fixtures.okBody(SCHEDULED_SESSION_JSON))
        val result = repo().reschedule("bcs_1", scheduledAtEpochSeconds = 1749319200L)
        assertTrue(result is ApiResult.Success)
        assertEquals(BroadcastSessionStatus.SCHEDULED, (result as ApiResult.Success).data.status)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/reschedule", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        // scheduled_at decodes to a JSON number (Double via Moshi's loose map) — NOT a string / ISO.
        assertEquals(1749319200.0, body["scheduled_at"])
        assertTrue("scheduled_at must be numeric (epoch seconds)", body["scheduled_at"] is Double)
        // The wire key is scheduled_at, NOT scheduled_start_at.
        assertTrue(!body.containsKey("scheduled_start_at"))
    }

    @Test
    fun health_decodesLiteralOut_derivesLevel_epochToInstant() = runTest {
        backend.enqueue(Fixtures.okBody(HEALTH_JSON))
        val result = repo().health("bcs_1")
        assertTrue(result is ApiResult.Success)
        val report = (result as ApiResult.Success).data
        assertEquals("bcs_1", report.sessionId)
        assertEquals(HealthLevel.DEGRADED, report.level)
        assertEquals(4200, report.ingestBitrateKbps)
        assertEquals(29.97, report.ingestFramerate, 0.001)
        assertEquals(12, report.droppedFrames)
        assertEquals(0.4, report.droppedFramesPct, 0.001)
        assertEquals(1, report.outputErrors)
        assertEquals(2.5, report.inputLossSeconds, 0.001)
        assertEquals(318, report.viewerCount)
        assertEquals(Instant.ofEpochSecond(1749322800L), report.updatedAt)
        // Media is FLAGGED — no client-derived RTCStats.
        assertEquals(null, report.rttMs)
        assertEquals(null, report.ingestConnected)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_1/health", req.requestUrl?.encodedPath)
    }

    @Test
    fun start_422_mapsToFailureWithNormalizedDetail() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","reason"],"msg":"not allowed in this state","type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().start("bcs_1")
        assertTrue(result is ApiResult.Failure)
        val error = (result as ApiResult.Failure).error
        assertEquals(422, error.status)
        assertTrue(error.message.contains("not allowed in this state"))
    }

    private companion object {
        const val LIVE_SESSION_JSON = """
            {"id":"bcs_1","profile_id":"prof_9","status":"live","created_by":"usr_42",
             "name":"Friday Night Live","created_at":"2026-06-05T22:00:00Z",
             "updated_at":"2026-06-05T23:00:05Z","started_at":"2026-06-05T23:00:00Z"}
        """

        const val STOPPED_SESSION_JSON = """
            {"id":"bcs_1","profile_id":"prof_9","status":"stopped","created_by":"usr_42",
             "name":"Friday Night Live","created_at":"2026-06-05T22:00:00Z",
             "updated_at":"2026-06-05T23:30:00Z","started_at":"2026-06-05T23:00:00Z",
             "stopped_at":"2026-06-05T23:30:00Z"}
        """

        const val SCHEDULED_SESSION_JSON = """
            {"id":"bcs_1","profile_id":"prof_9","status":"scheduled","created_by":"usr_42",
             "name":"Album party","created_at":"2026-06-01T10:00:00Z","updated_at":"2026-06-01T10:05:00Z",
             "scheduled_at":1749319200,"schedule_status":"scheduled"}
        """

        const val HEALTH_JSON = """
            {"session_id":"bcs_1","connection_quality":"degraded","ingest_bitrate_kbps":4200,
             "ingest_framerate":29.97,"dropped_frames":12,"dropped_frames_pct":0.4,"output_errors":1,
             "input_loss_seconds":2.5,"viewer_count":318,"updated_at":1749322800}
        """
    }
}
