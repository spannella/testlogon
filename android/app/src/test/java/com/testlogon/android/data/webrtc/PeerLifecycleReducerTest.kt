package com.testlogon.android.data.webrtc

import com.testlogon.android.data.webrtc.PeerLifecycleReducer.RawIceState
import com.testlogon.android.data.webrtc.PeerLifecycleReducer.RawPeerState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-294 — exhaustive [PeerLifecycleReducer] coverage filling the gaps left by [WebRtcStubsTest] (which
 * spot-checks only Connected/Connecting/Failed/Closed/Idle). Focuses on the merge PRECEDENCE rules and the
 * mixed-signal + DISCONNECTED cases that the spot-check omits. Pure; no SDK, no native callbacks.
 */
class PeerLifecycleReducerTest {

    @Test
    fun closed_takesPrecedenceOverFailed() {
        // CLOSED is checked before FAILED, so a peer that closed while ice failed reports Closed.
        assertEquals(
            PeerLifecycle.Closed,
            PeerLifecycleReducer.reduce(RawPeerState.CLOSED, RawIceState.FAILED),
        )
        assertEquals(
            PeerLifecycle.Closed,
            PeerLifecycleReducer.reduce(RawPeerState.FAILED, RawIceState.CLOSED),
        )
    }

    @Test
    fun iceFailed_aloneMapsToFailed_evenWhenPeerConnected() {
        val r = PeerLifecycleReducer.reduce(RawPeerState.CONNECTED, RawIceState.FAILED, reason = "ice down")
        assertTrue(r is PeerLifecycle.Failed)
        assertEquals("ice down", (r as PeerLifecycle.Failed).reason)
    }

    @Test
    fun failed_carriesReason() {
        val r = PeerLifecycleReducer.reduce(RawPeerState.FAILED, RawIceState.NEW, reason = "connect_timeout")
        assertEquals(PeerLifecycle.Failed("connect_timeout"), r)
    }

    @Test
    fun connected_whenPeerConnected_andIceNotFailed() {
        assertEquals(
            PeerLifecycle.Connected,
            PeerLifecycleReducer.reduce(RawPeerState.CONNECTED, RawIceState.COMPLETED),
        )
    }

    @Test
    fun connecting_fromIceCheckingOrCompleted_whilePeerNotYetConnected() {
        assertEquals(
            PeerLifecycle.Connecting,
            PeerLifecycleReducer.reduce(RawPeerState.NEW, RawIceState.CHECKING),
        )
        assertEquals(
            PeerLifecycle.Connecting,
            PeerLifecycleReducer.reduce(RawPeerState.NEW, RawIceState.COMPLETED),
        )
        assertEquals(
            PeerLifecycle.Connecting,
            PeerLifecycleReducer.reduce(RawPeerState.CONNECTING, RawIceState.NEW),
        )
    }

    @Test
    fun disconnected_signalsCollapseToIdle_notConnected() {
        // DISCONNECTED is not CONNECTED/CONNECTING/CHECKING/COMPLETED/FAILED/CLOSED -> falls through to Idle.
        assertEquals(
            PeerLifecycle.Idle,
            PeerLifecycleReducer.reduce(RawPeerState.DISCONNECTED, RawIceState.DISCONNECTED),
        )
    }

    @Test
    fun newNew_mapsToIdle() {
        assertEquals(
            PeerLifecycle.Idle,
            PeerLifecycleReducer.reduce(RawPeerState.NEW, RawIceState.NEW),
        )
    }
}
