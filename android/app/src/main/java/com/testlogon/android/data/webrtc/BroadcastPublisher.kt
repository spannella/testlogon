package com.testlogon.android.data.webrtc

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-288 — host "go-live" broadcasting engine seam (SCAFFOLD ONLY — FLAGGED, native WebRTC SDK not
 * configured).
 *
 * STOP-AND-FLAG (the native WebRTC SDK is a HUMAN-DECISION vendor SDK): host broadcasting needs the native
 * WebRTC SDK (`io.getstream:stream-webrtc-android`) to open the camera/mic, build a `PeerConnection`, and
 * publish media to the SFU. That Gradle dependency is deliberately NOT added and NO real camera/mic
 * capture, NO `PeerConnectionFactory`/`EglBase`, and NO peer is created here. This mirrors the existing
 * [com.testlogon.android.data.billing.CardTokenizer] / [com.testlogon.android.data.payouts.KycVerifier]
 * stub-seam pattern: the seam stops at "would need the native WebRTC SDK".
 *
 * [BroadcastPublisher] is the contract the real engine (a future ticket) will satisfy: with permissions
 * granted, capture the front camera + mic, create a `PeerConnection` (configured with ICE servers from
 * AND-291's [IceServersProvider]), produce an SDP offer, exchange it via the AND-290
 * [SignalingRepository.exchangeBroadcastOffer] host publish path, apply the SFU answer, and publish. Until
 * then [StubBroadcastPublisher] is bound and ALWAYS returns [GoLiveResult.NotConfigured]: it NEVER opens a
 * camera/mic, NEVER creates a peer, NEVER starts capture/media, and NEVER reaches a "live" state. The
 * go-live UI surfaces a clear "broadcasting unavailable / not configured" state.
 */
interface BroadcastPublisher {

    /** Current publish state. Hot; the stub never leaves [PublishState.Unavailable]. */
    val state: StateFlow<PublishState>

    /**
     * Begin publishing to [sessionId] / [inputId] (assumes CAMERA + RECORD_AUDIO already granted). The
     * stub returns [GoLiveResult.NotConfigured] and starts nothing.
     */
    suspend fun goLive(sessionId: String, inputId: String): GoLiveResult

    /** Stop publishing and release capture/peer. Idempotent. The stub is a no-op. */
    fun stop()
}

/** The host publish state. */
sealed interface PublishState {
    /** Not publishing; nothing started. */
    data object Idle : PublishState

    /** Acquiring camera/mic + negotiating (a real engine would pass through here). */
    data object Starting : PublishState

    /** Live and publishing media. */
    data object Live : PublishState

    /** A publish attempt failed; [reason] is a redaction-safe summary. */
    data class Failed(val reason: String) : PublishState

    /**
     * Broadcasting is unavailable because the native WebRTC engine is FLAGGED / not configured. The stub
     * stays here. The UI shows "broadcasting unavailable".
     */
    data object Unavailable : PublishState
}

/** Result of a go-live attempt. [NotConfigured] is what the FLAGGED stub always returns. */
sealed interface GoLiveResult {
    /** Publishing started (a real engine reached [PublishState.Live]). */
    data object Started : GoLiveResult

    /** A non-config failure (capture/peer/negotiation error). */
    data class Failed(val reason: String) : GoLiveResult

    /**
     * No real broadcasting engine is wired (native WebRTC SDK FLAGGED, not integrated). The go-live flow
     * MUST surface a "broadcasting unavailable / not configured" state and MUST NOT open a camera/mic,
     * create a peer, or start media. [StubBroadcastPublisher] always returns this.
     */
    data object NotConfigured : GoLiveResult
}

/**
 * AND-288 — default (FLAGGED) publisher. NEVER opens a camera/mic, NEVER creates a peer, NEVER starts
 * capture/media, NEVER reaches Live: always returns [GoLiveResult.NotConfigured] and stays in
 * [PublishState.Unavailable]. The real native-WebRTC-backed binding replaces this @Binds when the SDK
 * decision is made.
 */
@Singleton
class StubBroadcastPublisher @Inject constructor() : BroadcastPublisher {

    private val _state = MutableStateFlow<PublishState>(PublishState.Unavailable)
    override val state: StateFlow<PublishState> = _state.asStateFlow()

    override suspend fun goLive(sessionId: String, inputId: String): GoLiveResult =
        GoLiveResult.NotConfigured

    override fun stop() { /* no-op: nothing was ever started */ }
}
