package com.testlogon.android.data.call

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-295 — contract tests for [CallRepositoryImpl] against MockWebServer (real Retrofit/Moshi).
 *
 * Verifies the control-plane wire contract: verbs/paths (call_id substituted), default request bodies,
 * DTO -> domain mapping (epoch seconds, money cents, minutes_remaining Double), the invite request-field
 * spelling (`rate_cents_per_min`), and error/timeout folding. Body JSON is read ONCE per request.
 */
class CallRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): CallRepositoryImpl {
        val api = backend.retrofit(moshi).create(CallApi::class.java)
        return CallRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun invite_postsBody_mapsDomain() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"call_id":"c_1","conversation_id":"conv_1","caller_user_id":"u_self",
                 "callee_user_id":"u_peer","state":"ringing","initial_mode":"audio",
                 "start_ts":1733400000,"paid":false,"rate_cents_per_minute":null}
                """.trimIndent(),
            ),
        )
        val result = repo().invite(
            callId = "c_1",
            conversationId = "conv_1",
            calleeUserId = "u_peer",
            mode = CallMode.AUDIO,
            idempotencyKey = "idk_1",
        )
        assertTrue(result is ApiResult.Success)
        val invited = (result as ApiResult.Success).data
        assertEquals("c_1", invited.callId)
        assertEquals(CallMode.AUDIO, invited.mode)
        assertEquals(1733400000L, invited.startTsEpochSeconds)
        assertNull(invited.rateCentsPerMinute)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/messages/calls/invite", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("c_1", body["call_id"])
        assertEquals("u_peer", body["callee_user_id"])
        assertEquals("audio", body["initial_mode"])
        assertEquals("idk_1", body["idempotency_key"])
        // The REQUEST field is rate_cents_per_min (not ...minute).
        assertTrue(body.containsKey("rate_cents_per_min"))
    }

    @Test
    fun accept_substitutesCallId_andMapsActionOut() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"call_id":"c_9","conversation_id":"conv_9","state":"accepted","event_ts":1733400100,
                    "from_state":"ringing","reason":null,"voicemail_eligible":false}""",
            ),
        )
        val result = repo().accept("c_9", idempotencyKey = "k")
        assertTrue(result is ApiResult.Success)
        assertEquals("accepted", (result as ApiResult.Success).data.state)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/messages/calls/c_9/accept", req.requestUrl?.encodedPath)
    }

    @Test
    fun decline_default_sendsDeclinedReason() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"call_id":"c_2","conversation_id":"conv_2","state":"declined","event_ts":1}""",
            ),
        )
        val result = repo().decline("c_2")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("/messaging/messages/calls/c_2/decline", req.requestUrl?.encodedPath)
        assertEquals("declined", req.bodyJson()["reason"])
    }

    @Test
    fun end_sendsReasonAndIdempotencyKey() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"call_id":"c_3","conversation_id":"conv_3","state":"ended","event_ts":2}""",
            ),
        )
        val result = repo().end("c_3", reason = "hangup", idempotencyKey = "idk-end")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("/messaging/messages/calls/c_3/end", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("hangup", body["reason"])
        assertEquals("idk-end", body["idempotency_key"])
    }

    @Test
    fun timeout_default_sendsNoAnswer() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"call_id":"c_4","conversation_id":"conv_4","state":"ended","event_ts":3}""",
            ),
        )
        repo().timeout("c_4")
        val req = backend.takeRequest()
        assertEquals("/messaging/messages/calls/c_4/timeout", req.requestUrl?.encodedPath)
        assertEquals("no_answer", req.bodyJson()["reason"])
    }

    @Test
    fun heartbeat_usesPatch_mapsNumericFields() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"call_id":"c_5","elapsed_seconds":42,"total_cost_cents":0,
                    "balance_remaining_cents":0,"rate_cents_per_minute":0,"next_bill_in_seconds":18,
                    "warn_low_balance":false,"minutes_remaining":2.5,"max_duration_warning":false,
                    "action":"ok"}""",
            ),
        )
        val result = repo().heartbeat("c_5", clientTsEpochSeconds = 1733400100)
        assertTrue(result is ApiResult.Success)
        val hb = (result as ApiResult.Success).data
        assertEquals(42L, hb.elapsedSeconds)
        assertEquals(2.5, hb.minutesRemaining, 0.0001)
        assertEquals(false, hb.shouldTerminate)

        val req = backend.takeRequest()
        assertEquals("PATCH", req.method)
        assertEquals("/messaging/messages/calls/c_5/heartbeat", req.requestUrl?.encodedPath)
    }

    @Test
    fun heartbeat_terminateAction_marksShouldTerminate() = runTest {
        backend.enqueue(Fixtures.okBody("""{"call_id":"c_6","action":"terminate"}"""))
        val result = repo().heartbeat("c_6")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.shouldTerminate)
    }

    @Test
    fun billing_usesGet() = runTest {
        backend.enqueue(Fixtures.okBody("""{"call_id":"c_7","paid":true,"rate_cents_per_minute":50}"""))
        val result = repo().billing("c_7")
        assertTrue(result is ApiResult.Success)
        assertEquals(50L, (result as ApiResult.Success).data.rateCentsPerMinute)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/messages/calls/c_7/billing", req.requestUrl?.encodedPath)
    }

    @Test
    fun history_decodesPage_mapsDomain_andSendsParams() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"items":[
                  {"call_id":"c_a","caller_id":"u1","callee_id":"u2","call_type":"video",
                   "direction":"incoming","status":"missed","duration_seconds":0,"created_at":1733400000},
                  {"call_id":"c_b","caller_id":"u2","callee_id":"u1","call_type":"audio"}
                ],"next_cursor":"cur2"}
                """.trimIndent(),
            ),
        )
        val result = repo().history(cursor = null, limit = 20)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(2, page.entries.size)
        assertEquals("cur2", page.nextCursor)
        assertEquals(CallMode.VIDEO, page.entries[0].mode)
        assertEquals(CallDirection.INCOMING, page.entries[0].direction)
        assertEquals(CallStatus.MISSED, page.entries[0].status)
        // Defaults tolerate absent fields.
        assertEquals(CallDirection.OUTGOING, page.entries[1].direction)
        assertEquals(CallStatus.COMPLETED, page.entries[1].status)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/calls/history", req.requestUrl?.encodedPath)
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun invite_422_mapsToFailure_neverThrows() = runTest {
        backend.enqueue(Fixtures.error("""[{"msg":"field required","type":"value_error.missing"}]""", 422))
        val result = repo().invite("c", "conv", "callee")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun accept_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().accept("c")
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
    }
}
