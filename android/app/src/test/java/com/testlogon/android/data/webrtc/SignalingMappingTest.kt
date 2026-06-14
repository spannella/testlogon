package com.testlogon.android.data.webrtc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-294 — pure signaling/SDP mapping coverage filling the gaps left by [SignalingRepositoryContractTest]
 * (which exercises Offer + Ice over MockWebServer). Covers the Answer payload, every SdpType wire string,
 * the dotted call wire types for all three message kinds, and the status-string -> enum mapping incl. the
 * UNKNOWN/null fallbacks. Pure helpers; no network, no SDK.
 */
class SignalingMappingTest {

    @Test
    fun callWireType_isDottedPerMessageKind() {
        assertEquals(
            "webrtc.offer",
            SignalingMessage.Offer(SdpDescription(SdpType.OFFER, "v=0")).callWireType(),
        )
        assertEquals(
            "webrtc.answer",
            SignalingMessage.Answer(SdpDescription(SdpType.ANSWER, "v=0")).callWireType(),
        )
        assertEquals(
            "webrtc.ice_candidate",
            SignalingMessage.Ice(IceCandidate("0", 0, "candidate:1")).callWireType(),
        )
    }

    @Test
    fun callPayload_answer_carriesSdpAndLowercaseType() {
        val payload = SignalingMessage.Answer(SdpDescription(SdpType.ANSWER, "v=0 ans")).callPayload()
        assertEquals("v=0 ans", payload["sdp"])
        assertEquals("answer", payload["type"])
    }

    @Test
    fun callPayload_ice_carriesCandidateFields_inclNullMid() {
        val payload = SignalingMessage.Ice(IceCandidate(null, 2, "candidate:9")).callPayload()
        assertEquals("candidate:9", payload["candidate"])
        assertNull(payload["sdpMid"])
        assertEquals(2, payload["sdpMLineIndex"])
    }

    @Test
    fun sdpType_wire_isLowercaseLibwebrtcValue() {
        assertEquals("offer", SdpType.OFFER.wire())
        assertEquals("answer", SdpType.ANSWER.wire())
        assertEquals("pranswer", SdpType.PRANSWER.wire())
    }

    @Test
    fun toSignalingStatus_mapsDeliveredDuplicate_elseUnknown() {
        assertEquals(SignalingStatus.DELIVERED, "delivered".toSignalingStatus())
        assertEquals(SignalingStatus.DELIVERED, "DELIVERED".toSignalingStatus())
        assertEquals(SignalingStatus.DUPLICATE, "duplicate".toSignalingStatus())
        assertEquals(SignalingStatus.UNKNOWN, "queued".toSignalingStatus())
        assertEquals(SignalingStatus.UNKNOWN, (null as String?).toSignalingStatus())
    }
}
