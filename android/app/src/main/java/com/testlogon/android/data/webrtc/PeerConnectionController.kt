package com.testlogon.android.data.webrtc

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-289 — PeerConnection wrapper lifecycle seam.
 *
 * The real implementation ([RealPeerConnectionController]) wraps `org.webrtc.PeerConnection` (from the
 * `io.getstream:stream-webrtc-android` artifact) and owns the offer/answer/ICE negotiation, local
 * audio+video capture, remote track delivery, and native teardown. [StubPeerConnectionController] is kept
 * for JVM unit tests (no SDK on the test classpath) and returns [PeerResult.NotConfigured] from every op.
 *
 * The lifecycle model ([PeerLifecycle]) and the result type ([PeerResult]) are pure sealed types so the
 * state machine and the seam contract are unit-testable without the SDK. SDP/ICE bodies are carried as the
 * pure [SdpDescription]/[IceCandidate] value types (no org.webrtc types cross this interface).
 */
interface PeerConnectionController {

    /** The merged peer-connection lifecycle. Hot; starts at [PeerLifecycle.Idle]. */
    val lifecycle: StateFlow<PeerLifecycle>

    /**
     * Locally-gathered (trickled) ICE candidates to forward to the peer over signaling. Hot; the real impl
     * emits one per `onIceCandidate`. The stub never emits.
     */
    val localIceCandidates: SharedFlow<IceCandidate>

    /** Initialize the peer with [config] (creates the PeerConnection + local media tracks). */
    suspend fun init(config: PeerConfig): PeerResult<Unit>

    /** Offerer role: produce a local SDP offer (and set it as the local description). */
    suspend fun createOffer(): PeerResult<SdpDescription>

    /** Answerer role: produce a local SDP answer (after the remote offer was applied). */
    suspend fun createAnswer(): PeerResult<SdpDescription>

    /** Apply a remote SDP description (offer or answer) as the remote description. */
    suspend fun setRemoteDescription(sdp: SdpDescription): PeerResult<Unit>

    /** Accept a remote ICE candidate. */
    suspend fun addIceCandidate(candidate: IceCandidate): PeerResult<Unit>

    /** Idempotent teardown. Disposes native refs + stops capture. */
    fun close()
}

/** Configuration for a peer session. [iceServers] are populated by AND-291's provider. */
data class PeerConfig(
    val iceServers: List<IceServer> = emptyList(),
    val role: PeerRole = PeerRole.OFFERER,
    val enableAudio: Boolean = true,
    val enableVideo: Boolean = true,
    // Force ICE to use only TURN relay candidates (skip host/srflx). Used to guarantee connectivity on
    // restrictive networks where the direct path is unreliable; default false keeps production ALL.
    val relayOnly: Boolean = false,
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

/** Result of a controller lifecycle op. [NotConfigured] is what the stub returns (no SDK in unit tests). */
sealed interface PeerResult<out T> {
    data class Ok<out T>(val value: T) : PeerResult<T>
    data class Failed(val reason: String) : PeerResult<Nothing>
    data object NotConfigured : PeerResult<Nothing>
}

/**
 * Stub controller for JVM unit tests (no org.webrtc on the test classpath). NEVER creates a peer or opens
 * media; every op returns [PeerResult.NotConfigured]; [localIceCandidates] never emits.
 */
@Singleton
class StubPeerConnectionController @Inject constructor() : PeerConnectionController {

    private val _lifecycle = MutableStateFlow<PeerLifecycle>(PeerLifecycle.Idle)
    override val lifecycle: StateFlow<PeerLifecycle> = _lifecycle.asStateFlow()

    private val _ice = MutableSharedFlow<IceCandidate>()
    override val localIceCandidates: SharedFlow<IceCandidate> = _ice.asSharedFlow()

    override suspend fun init(config: PeerConfig): PeerResult<Unit> = PeerResult.NotConfigured
    override suspend fun createOffer(): PeerResult<SdpDescription> = PeerResult.NotConfigured
    override suspend fun createAnswer(): PeerResult<SdpDescription> = PeerResult.NotConfigured
    override suspend fun setRemoteDescription(sdp: SdpDescription): PeerResult<Unit> = PeerResult.NotConfigured
    override suspend fun addIceCandidate(candidate: IceCandidate): PeerResult<Unit> = PeerResult.NotConfigured

    override fun close() {
        _lifecycle.value = PeerLifecycle.Closed
    }
}
