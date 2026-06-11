package com.testlogon.android.data.webrtc

/**
 * AND-289 — pure state-machine reducer that collapses the raw libwebrtc state signals (peer-connection
 * state + ICE-connection state) into the small sealed [PeerLifecycle]. Kept SDK-free (the raw signals are
 * modeled as local enums, not org.webrtc types) so the merge rules are unit-testable without the native
 * SDK. The real PeerConnectionController will translate org.webrtc callbacks into these enums and call
 * [PeerLifecycleReducer.reduce]; the stub never produces non-Idle signals.
 *
 * Mapping (per spec §6):
 *  - PeerConnectionState.CONNECTED -> Connected
 *  - PeerConnectionState.FAILED or IceConnectionState.FAILED -> Failed
 *  - PeerConnectionState.CLOSED -> Closed
 *  - signaling in progress / ICE checking -> Connecting
 *  - otherwise -> Idle
 */
object PeerLifecycleReducer {

    /** Raw native PeerConnection state (SDK-free mirror of org.webrtc PeerConnection.PeerConnectionState). */
    enum class RawPeerState { NEW, CONNECTING, CONNECTED, DISCONNECTED, FAILED, CLOSED }

    /** Raw native ICE connection state (SDK-free mirror of org.webrtc PeerConnection.IceConnectionState). */
    enum class RawIceState { NEW, CHECKING, CONNECTED, COMPLETED, DISCONNECTED, FAILED, CLOSED }

    /**
     * Collapses the two raw signals into a single [PeerLifecycle]. [reason] is used only for the Failed
     * branch and must already be redaction-safe (no SDP / no credentials).
     */
    fun reduce(
        peer: RawPeerState,
        ice: RawIceState,
        reason: String = "connection failed",
    ): PeerLifecycle = when {
        peer == RawPeerState.CLOSED || ice == RawIceState.CLOSED -> PeerLifecycle.Closed
        peer == RawPeerState.FAILED || ice == RawIceState.FAILED -> PeerLifecycle.Failed(reason)
        peer == RawPeerState.CONNECTED -> PeerLifecycle.Connected
        peer == RawPeerState.CONNECTING ||
            ice == RawIceState.CHECKING ||
            ice == RawIceState.CONNECTED ||
            ice == RawIceState.COMPLETED -> PeerLifecycle.Connecting
        else -> PeerLifecycle.Idle
    }
}
