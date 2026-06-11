package com.testlogon.android.data.webrtc

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-288/289/290 — asserts the FLAGGED engine stubs return NotConfigured from every op and NEVER start a
 * capture/peer/media/transport session (no state ever leaves the "unavailable / idle" baseline except the
 * deterministic Closed transition on explicit teardown).
 */
class WebRtcStubsTest {

    @Test
    fun broadcastPublisher_isUnavailable_andNeverStarts() = runTest {
        val publisher = StubBroadcastPublisher()
        assertSame(PublishState.Unavailable, publisher.state.value)

        val result = publisher.goLive(sessionId = "bcs_1", inputId = "in_1")
        assertSame(GoLiveResult.NotConfigured, result)

        // The publisher never opened capture/peer: state stays Unavailable; stop() is a safe no-op.
        assertSame(PublishState.Unavailable, publisher.state.value)
        publisher.stop()
        assertSame(PublishState.Unavailable, publisher.state.value)
    }

    @Test
    fun peerConnectionController_allOpsNotConfigured_neverLeavesIdleUntilClose() = runTest {
        val controller = StubPeerConnectionController()
        assertSame(PeerLifecycle.Idle, controller.lifecycle.value)

        assertSame(PeerResult.NotConfigured, controller.init(PeerConfig()))
        assertSame(PeerResult.NotConfigured, controller.createOffer())
        assertSame(
            PeerResult.NotConfigured,
            controller.setRemoteDescription(SdpDescription(SdpType.OFFER, "v=0")),
        )
        assertSame(
            PeerResult.NotConfigured,
            controller.addIceCandidate(IceCandidate("0", 0, "candidate:1")),
        )

        // No peer was created => still Idle until an explicit close.
        assertSame(PeerLifecycle.Idle, controller.lifecycle.value)
        controller.close()
        assertSame(PeerLifecycle.Closed, controller.lifecycle.value)
        // Idempotent close.
        controller.close()
        assertSame(PeerLifecycle.Closed, controller.lifecycle.value)
    }

    @Test
    fun signalingTransport_neverConnects_neverSends() = runTest {
        val transport = StubSignalingTransport()
        assertSame(TransportResult.NotConfigured, transport.connect("call_1", "self"))
        assertSame(
            TransportResult.NotConfigured,
            transport.sendOffer(SignalingMessage.Offer(SdpDescription(SdpType.OFFER, "v=0"))),
        )
        assertSame(
            TransportResult.NotConfigured,
            transport.onAnswer(SignalingMessage.Answer(SdpDescription(SdpType.ANSWER, "v=0"))),
        )
        assertSame(
            TransportResult.NotConfigured,
            transport.onIce(SignalingMessage.Ice(IceCandidate("0", 0, "candidate:1"))),
        )
        // close() is a safe no-op (nothing was opened).
        transport.close()
    }

    @Test
    fun peerLifecycleReducer_mapsRawSignals() {
        assertEquals(
            PeerLifecycle.Connected,
            PeerLifecycleReducer.reduce(
                PeerLifecycleReducer.RawPeerState.CONNECTED,
                PeerLifecycleReducer.RawIceState.CONNECTED,
            ),
        )
        assertEquals(
            PeerLifecycle.Connecting,
            PeerLifecycleReducer.reduce(
                PeerLifecycleReducer.RawPeerState.CONNECTING,
                PeerLifecycleReducer.RawIceState.CHECKING,
            ),
        )
        assertTrue(
            PeerLifecycleReducer.reduce(
                PeerLifecycleReducer.RawPeerState.FAILED,
                PeerLifecycleReducer.RawIceState.FAILED,
                reason = "ice failed",
            ) is PeerLifecycle.Failed,
        )
        assertEquals(
            PeerLifecycle.Closed,
            PeerLifecycleReducer.reduce(
                PeerLifecycleReducer.RawPeerState.CLOSED,
                PeerLifecycleReducer.RawIceState.CLOSED,
            ),
        )
        assertEquals(
            PeerLifecycle.Idle,
            PeerLifecycleReducer.reduce(
                PeerLifecycleReducer.RawPeerState.NEW,
                PeerLifecycleReducer.RawIceState.NEW,
            ),
        )
    }
}
