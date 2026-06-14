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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-315 — MockWebServer contract tests for [BroadcastMonetizationRepositoryImpl]. Verifies the tip-config
 * PATCH body + session decode -> TipConfig, getSession tip-field extraction, the private-requests list parse
 * (epoch -> Instant, flat viewer fields), getPrivateStatus, accept POST body {"behavior":"pause"}, decline
 * (both an {ok} ack and an empty 200 succeed via Response<Unit>), end -> summary, and 422 detail mapping.
 * Each request body is read ONCE.
 */
class BroadcastMonetizationRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): BroadcastMonetizationRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return BroadcastMonetizationRepositoryImpl(
            api = retrofit.create(BroadcastMonetizationApi::class.java),
            broadcastApi = retrofit.create(BroadcastApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun saveTipConfig_patchesBody_andMapsSessionToTipConfig() = runTest {
        backend.enqueue(Fixtures.okBody(SESSION_JSON))
        val result = repo().saveTipConfig("bcs_1", enabled = true, minCents = 200, maxCents = 5_000)
        assertTrue(result is ApiResult.Success)
        val config = (result as ApiResult.Success).data
        assertTrue(config.tipsEnabled)
        assertEquals(200L, config.minCents)
        assertEquals(5_000L, config.maxCents)

        val req = backend.takeRequest()
        assertEquals("PATCH", req.method)
        assertEquals("/broadcast/sessions/bcs_1/tips/config", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals(true, body["tip_enabled"])
        // Moshi serializes JSON numbers as Double in the loosely-typed map.
        assertEquals(200.0, body["tip_min_cents"])
        assertEquals(5_000.0, body["tip_max_cents"])
    }

    @Test
    fun getSessionTipConfig_readsTipFieldsFromSession() = runTest {
        backend.enqueue(Fixtures.okBody(SESSION_JSON))
        val result = repo().getSessionTipConfig("bcs_1")
        assertTrue(result is ApiResult.Success)
        val config = (result as ApiResult.Success).data
        assertTrue(config.tipsEnabled)
        assertEquals(200L, config.minCents)
        assertEquals(5_000L, config.maxCents)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_1", req.requestUrl?.encodedPath)
    }

    @Test
    fun listPrivateRequests_decodes_epochToInstant_flatViewerFields() = runTest {
        backend.enqueue(Fixtures.okBody(REQUESTS_JSON))
        val result = repo().listPrivateRequests("bcs_1")
        assertTrue(result is ApiResult.Success)
        val requests = (result as ApiResult.Success).data
        assertEquals(1, requests.size)
        val r = requests.single()
        assertEquals("req_1", r.requestId)
        assertEquals("viewer_9", r.viewerId)
        assertEquals("Jordan", r.viewerDisplayName)
        assertEquals(500L, r.ratePerMinuteCents)
        assertEquals("pending", r.status)
        assertEquals(Instant.ofEpochSecond(1_700_000_000L), r.requestedAt)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_1/private/requests", req.requestUrl?.encodedPath)
    }

    @Test
    fun getPrivateStatus_decodes() = runTest {
        backend.enqueue(Fixtures.okBody(STATUS_JSON))
        val result = repo().getPrivateStatus("bcs_1")
        assertTrue(result is ApiResult.Success)
        val status = (result as ApiResult.Success).data
        assertEquals("active", status.status)
        assertEquals("ps_1", status.privateSessionId)
        assertEquals(500L, status.ratePerMinuteCents)

        val req = backend.takeRequest()
        assertEquals("/broadcast/sessions/bcs_1/private/status", req.requestUrl?.encodedPath)
    }

    @Test
    fun accept_postsBehaviorBody_andMapsAcceptOut() = runTest {
        backend.enqueue(Fixtures.okBody(ACCEPT_JSON))
        val result = repo().acceptPrivateRequest("bcs_1", "req_1", behavior = "pause")
        assertTrue(result is ApiResult.Success)
        val session = (result as ApiResult.Success).data
        assertEquals("ps_1", session.privateSessionId)
        assertEquals("active", session.status)
        assertEquals(500L, session.ratePerMinuteCents)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/private/req_1/accept", req.requestUrl?.encodedPath)
        assertEquals("pause", req.bodyJson()["behavior"])
    }

    @Test
    fun decline_ackBody_succeeds() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"request_id":"req_1"}"""))
        val result = repo().declinePrivateRequest("bcs_1", "req_1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/private/req_1/decline", req.requestUrl?.encodedPath)
    }

    @Test
    fun decline_emptyBody_succeeds() = runTest {
        // Empty 200 body -> Response<Unit> success-by-isSuccessful (no Moshi parse on an empty body).
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().declinePrivateRequest("bcs_1", "req_1")
        assertTrue(result is ApiResult.Success)
    }

    @Test
    fun end_postsToPrivateSessionId_mapsSummary() = runTest {
        backend.enqueue(Fixtures.okBody(END_JSON))
        val result = repo().endPrivateSession("bcs_1", "ps_1")
        assertTrue(result is ApiResult.Success)
        val summary = (result as ApiResult.Success).data
        assertEquals("ps_1", summary.privateSessionId)
        assertEquals(180, summary.durationSeconds)
        assertEquals(1_500L, summary.totalBilledCents)
        assertEquals("host", summary.endedBy)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        // The end path uses the PRIVATE_SESSION_ID, not the request id.
        assertEquals("/broadcast/sessions/bcs_1/private/ps_1/end", req.requestUrl?.encodedPath)
    }

    @Test
    fun saveTipConfig_422_mapsDetail() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","tip_min_cents"],"msg":"too small","type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().saveTipConfig("bcs_1", enabled = true, minCents = 1, maxCents = 5_000)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getSessionTipConfig_absentTipFields_defaultDisabled_nullBounds() = runTest {
        backend.enqueue(Fixtures.okBody("""{"id":"bcs_1","status":"live"}"""))
        val result = repo().getSessionTipConfig("bcs_1")
        assertTrue(result is ApiResult.Success)
        val config = (result as ApiResult.Success).data
        assertFalse(config.tipsEnabled)
        assertNull(config.minCents)
        assertNull(config.maxCents)
    }

    private companion object {
        const val SESSION_JSON = """
            {"id":"bcs_1","profile_id":"prof_1","status":"live","created_by":"usr_1",
             "tip_enabled":true,"tip_min_cents":200,"tip_max_cents":5000,
             "created_at":"2026-06-05T22:00:00Z","updated_at":"2026-06-05T22:05:00Z"}
        """

        const val REQUESTS_JSON = """
            {"requests":[
              {"request_id":"req_1","private_session_id":null,"session_id":"bcs_1","viewer_id":"viewer_9",
               "viewer_display_name":"Jordan","rate_per_minute_cents":500,"status":"pending",
               "max_duration_minutes":30,"requested_at":1700000000,"total_billed_cents":0}
            ]}
        """

        const val STATUS_JSON = """
            {"status":"active","request_id":"req_1","private_session_id":"ps_1","session_id":"bcs_1",
             "viewer_id":"viewer_9","viewer_display_name":"Jordan","rate_per_minute_cents":500,
             "behavior":"pause","call_id":"call_1","started_at":1700000000}
        """

        const val ACCEPT_JSON = """
            {"private_session_id":"ps_1","session_id":"bcs_1","status":"active","behavior":"pause",
             "call_id":"call_1","rate_per_minute_cents":500,"started_at":1700000000}
        """

        const val END_JSON = """
            {"private_session_id":"ps_1","session_id":"bcs_1","status":"ended","duration_seconds":180,
             "total_billed_cents":1500,"ended_by":"host"}
        """
    }
}
