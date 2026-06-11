package com.testlogon.android.data.webrtc

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

/**
 * AND-290 — MockWebServer contract tests for [SignalingRepositoryImpl]. Verifies the verb + resolved path
 * + body for the host broadcast publish SDP exchange and the 1:1 call signaling send, plus DTO->domain
 * mapping and error/timeout propagation. Each request body is read ONCE via [bodyJson] (readUtf8 consumes
 * the buffer).
 */
class SignalingRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): SignalingRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return SignalingRepositoryImpl(
            api = retrofit.create(SignalingApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun exchangeBroadcastOffer_postsSdpOffer_mapsAnswer() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"sdp_answer":"v=0 answer","session_id":"bcs_1","input_id":"in_1"}""",
            ),
        )
        val result = repo().exchangeBroadcastOffer("bcs_1", "in_1", "v=0 offer")
        assertTrue(result is ApiResult.Success)
        val answer = (result as ApiResult.Success).data
        assertEquals("bcs_1", answer.sessionId)
        assertEquals("in_1", answer.inputId)
        assertEquals(SdpType.ANSWER, answer.answer.type)
        assertEquals("v=0 answer", answer.answer.sdp)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals(
            "/broadcast/sessions/bcs_1/inputs/in_1/webrtc-offer",
            req.requestUrl?.encodedPath,
        )
        assertEquals("v=0 offer", req.bodyJson()["sdp_offer"])
    }

    @Test
    fun sendCallSignal_offer_buildsFlatEnvelope() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"event_id":"evt_1","call_id":"call_1","conversation_id":"conv_1",
                    "event_type":"webrtc.offer","delivered_to":"user_B","status":"delivered"}""",
            ),
        )
        val result = repo().sendCallSignal(
            callId = "call_1",
            conversationId = "conv_1",
            recipientUserId = "user_B",
            eventId = "evt_1",
            nonce = "nonce1234",
            sentAtEpochSeconds = 1_717_603_200L,
            message = SignalingMessage.Offer(SdpDescription(SdpType.OFFER, "v=0 offer")),
        )
        assertTrue(result is ApiResult.Success)
        val ack = (result as ApiResult.Success).data
        assertEquals(SignalingStatus.DELIVERED, ack.status)
        assertEquals("user_B", ack.deliveredTo)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/messages/calls/call_1/signal", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("webrtc.offer", body["type"])
        assertEquals("evt_1", body["event_id"])
        assertEquals("conv_1", body["conversation_id"])
        assertEquals("user_B", body["recipient_user_id"])
        assertEquals("nonce1234", body["nonce"])
        assertEquals(1_717_603_200.0, body["sent_at"])

        @Suppress("UNCHECKED_CAST")
        val payload = body["payload"] as Map<String, Any?>
        assertEquals("v=0 offer", payload["sdp"])
        assertEquals("offer", payload["type"])
    }

    @Test
    fun sendCallSignal_ice_payloadHasCandidateFields() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"event_id":"evt_2","call_id":"call_1","conversation_id":"conv_1",
                    "event_type":"webrtc.ice_candidate","delivered_to":"user_B","status":"duplicate"}""",
            ),
        )
        val result = repo().sendCallSignal(
            callId = "call_1",
            conversationId = "conv_1",
            recipientUserId = "user_B",
            eventId = "evt_2",
            nonce = "nonce5678",
            sentAtEpochSeconds = 1_717_603_201L,
            message = SignalingMessage.Ice(IceCandidate("0", 0, "candidate:842163049 1 udp")),
        )
        assertTrue(result is ApiResult.Success)
        assertEquals(SignalingStatus.DUPLICATE, (result as ApiResult.Success).data.status)

        val body = backend.takeRequest().bodyJson()
        assertEquals("webrtc.ice_candidate", body["type"])

        @Suppress("UNCHECKED_CAST")
        val payload = body["payload"] as Map<String, Any?>
        assertEquals("candidate:842163049 1 udp", payload["candidate"])
        assertEquals("0", payload["sdpMid"])
        assertEquals(0.0, payload["sdpMLineIndex"])
    }

    @Test
    fun exchangeBroadcastOffer_403_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"forbidden\"", 403))
        val result = repo().exchangeBroadcastOffer("bcs_1", "in_1", "v=0")
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun exchangeBroadcastOffer_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().exchangeBroadcastOffer("bcs_1", "in_1", "v=0")
        assertTrue(result is ApiResult.NetworkError)
    }
}
