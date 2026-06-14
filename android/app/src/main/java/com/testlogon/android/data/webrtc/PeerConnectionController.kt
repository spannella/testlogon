package com.testlogon.android.data.webrtc

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-289 — PeerConnection wrapper lifecycle seam (SCAFFOLD ONLY — FLAGGED, native WebRTC not configured).
 *
 * STOP-AND-FLAG (the native WebRTC SDK is a HUMAN-DECISION vendor SDK): a real implementation would wrap
 * `org.webrtc.PeerConnection` (from the `io.getstream:stream-webrtc-android` artifact) and own the
 * offer/answer/ICE negotiation + native teardown. That Gradle dependency is deliberately NOT added and NO
 * real `PeerConnection`/`PeerConnectionFactory`/`EglBase` is created here. This mirrors the existing
 * [com.testlogon.android.data.billing.CardTokenizer] / [com.testlogon.android.data.payouts.KycVerifier]
 * stub-seam pattern: the seam stops at "would need the native WebRTC SDK".
 *
 * [PeerConnectionController] is the contract the real wrapper (a future ticket) will satisfy. Until then
 * [StubPeerConnectionController] is bound and is a pure no-op: every lifecycle method returns
 * [PeerResult.NotConfigured] and the controller NEVER creates a peer, NEVER opens media, and NEVER leaves
 * [PeerLifecycle.Idle] (after [close] it reports [PeerLifecycle.Closed]).
 *
 * The lifecycle model ([PeerLifecycle]) and the result type ([PeerResult]) are pure sealed types so the
 * state machine and the seam contract are fully unit-testable without the SDK.
 */
interface PeerConnectionController {

    /** The merged peer-connection lifecycle. Hot; starts at [PeerLifecycle.Idle]. */
    val lifecycle: StateFlow<PeerLifecycle>

    /** Initialize the peer with [config]. The stub never creates a peer; returns NotConfigured. */
    suspend fun init(config: PeerConfig): PeerResult<Unit>

    /** Offerer role: produce a local SDP offer. The stub returns NotConfigured (no SDP generated). */
    suspend fun createOffer(): PeerResult<SdpDescription>

    /** Apply a remote SDP description (offer or answer). The stub returns NotConfigured. */
    suspend fun setRemoteDescription(sdp: SdpDescription): PeerResult<Unit>

    /** Accept a remote ICE candidate (buffered until remote SDP in a real impl). Stub: NotConfigured. */
    suspend fun addIceCandidate(candidate: IceCandidate): PeerResult<Unit>

    /** Idempotent teardown. Disposes native refs in a real impl; the stub only sets [PeerLifecycle.Closed]. */
    fun close()
}

/** Configuration for a peer session. [iceServers] are populated by AND-291's provider. */
data class PeerConfig(
    val iceServers: List<IceServer> = emptyList(),
    val role: PeerRole = PeerRole.OFFERER,
    val enableAudio: Boolean = true,
    val enableVideo: Boolean = true,
)

enum class PeerRole { OFFERER, ANSWERER }

/**
 * AND-289 — the pure, sealed peer-connection lifecycle. Order: Idle -> Connecting -> Connected, with
 * Failed/Closed as terminal off-ramps. No SDK types; safe to assert in JVM unit tests.
 */
sealed interface PeerLifecycle {
    /** Created, no negotiation started yet. */
    data object Idle : PeerLifecycle

    /** Negotiating / ICE checking. */
    data object Connecting : PeerLifecycle

    /** Peer connection established. */
    data object Connected : PeerLifecycle

    /** Non-recoverable failure; [reason] is a redaction-safe summary (never SDP/credentials). */
    data class Failed(val reason: String) : PeerLifecycle

    /** Disposed. After [PeerConnectionController.close]. */
    data object Closed : PeerLifecycle
}

/** Result of a controller lifecycle op. [NotConfigured] is what the FLAGGED stub always returns. */
sealed interface PeerResult<out T> {
    data class Ok<out T>(val value: T) : PeerResult<T>
    data class Failed(val reason: String) : PeerResult<Nothing>

    /**
     * No real PeerConnection wrapper is wired (native WebRTC SDK FLAGGED, not integrated). The go-live
     * flow MUST surface a "broadcasting unavailable / not configured" state and MUST NOT start a peer or
     * media. [StubPeerConnectionController] always returns this.
     */
    data object NotConfigured : PeerResult<Nothing>
}

/**
 * AND-289 — default (FLAGGED) controller. NEVER creates a peer, NEVER opens camera/mic/media, NEVER
 * leaves [PeerLifecycle.Idle] (until [close] -> [PeerLifecycle.Closed]). Every op returns
 * [PeerResult.NotConfigured]. The real native-WebRTC-backed binding replaces this @Binds when the SDK
 * decision is made.
 */
@Singleton
class StubPeerConnectionController @Inject constructor() : PeerConnectionController {

    private val _lifecycle = MutableStateFlow<PeerLifecycle>(PeerLifecycle.Idle)
    override val lifecycle: StateFlow<PeerLifecycle> = _lifecycle.asStateFlow()

    override suspend fun init(config: PeerConfig): PeerResult<Unit> = PeerResult.NotConfigured

    override suspend fun createOffer(): PeerResult<SdpDescription> = PeerResult.NotConfigured

    override suspend fun setRemoteDescription(sdp: SdpDescription): PeerResult<Unit> =
        PeerResult.NotConfigured

    override suspend fun addIceCandidate(candidate: IceCandidate): PeerResult<Unit> =
        PeerResult.NotConfigured

    override fun close() {
        _lifecycle.value = PeerLifecycle.Closed
    }
}
