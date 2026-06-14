package com.testlogon.android.data.webrtc

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-299 — group-call MESH lifecycle seam (SCAFFOLD ONLY — FLAGGED, native WebRTC not configured).
 *
 * STOP-AND-FLAG (the native WebRTC SDK is a HUMAN-DECISION vendor SDK): a real implementation would hold a
 * Map of userId -> org.webrtc.PeerConnection (one full-mesh peer per remote participant), drive the
 * per-peer offer/answer/ICE negotiation through the AND-299 signal-relay endpoint, attach/detach remote
 * VideoTracks, sample per-peer stats for quality, and run audio-level detection for the active-speaker
 * highlight. That Gradle dependency is deliberately NOT added and NO real PeerConnection /
 * PeerConnectionFactory / EglBase is created here. This mirrors the existing
 * [PeerConnectionController] / [BroadcastPublisher] / [SignalingTransport] stub-seam pattern: the seam
 * stops at "would need the native WebRTC SDK".
 *
 * [MeshConnectionManager] is the contract the real mesh (a future ticket) will satisfy. Until then
 * [StubMeshConnectionManager] is bound and is a pure no-op: every peer op returns [MeshResult.NotConfigured],
 * the manager NEVER creates a peer / opens media, and [events] never emits.
 *
 * [MeshEvent] / [MeshResult] are pure sealed types so the consuming reducer + view model are fully
 * JVM-unit-testable without the SDK.
 */
interface MeshConnectionManager {

    /** Hot stream of mesh events. The stub NEVER emits (no real peers). */
    val events: SharedFlow<MeshEvent>

    /** Add a peer for [userId] (offerer role when [isInitiator]). The stub returns NotConfigured. */
    suspend fun addPeer(userId: String, isInitiator: Boolean): MeshResult

    /** Tear down a peer. The stub is a no-op (it never created one). */
    suspend fun removePeer(userId: String)

    /** Mute/unmute the local audio track. The stub records nothing (no track). */
    fun setLocalMute(muted: Boolean)

    /** Enable/disable the local video track. The stub records nothing (no track). */
    fun setLocalVideo(on: Boolean)

    /** Idempotent teardown of every peer. The stub is a no-op. */
    suspend fun closeAll()
}

/**
 * AND-299 — pure, sealed mesh events. No SDK types; safe to assert in JVM unit tests. A real mesh emits
 * these as per-peer connections come and go, quality is sampled, audio levels cross the speaking threshold,
 * and remote tracks attach.
 */
sealed interface MeshEvent {
    /** A peer's connection reached the connected state. */
    data class PeerConnected(val userId: String) : MeshEvent

    /** A peer disconnected / failed. */
    data class PeerDisconnected(val userId: String) : MeshEvent

    /** A peer's sampled connection quality changed (free-form token mapped by the feature layer). */
    data class QualityChanged(val userId: String, val quality: String) : MeshEvent

    /** A peer started/stopped speaking (audio-level threshold crossing). */
    data class Speaking(val userId: String, val speaking: Boolean) : MeshEvent

    /** A remote media track became available for a peer (rendered by the placeholder while FLAGGED). */
    data class RemoteTrack(val userId: String, val hasVideo: Boolean) : MeshEvent
}

/** Result of a mesh peer op. [NotConfigured] is what the FLAGGED stub always returns. */
sealed interface MeshResult {
    data object Ok : MeshResult

    /**
     * No real mesh is wired (native WebRTC SDK FLAGGED, not integrated). The group-call flow MUST surface a
     * "call media unavailable" state and MUST NOT start a peer or media. [StubMeshConnectionManager] always
     * returns this.
     */
    data object NotConfigured : MeshResult
}

/**
 * AND-299 — default (FLAGGED) mesh manager. NEVER creates a peer, NEVER opens camera/mic/media, [events]
 * NEVER emits. Every peer op returns [MeshResult.NotConfigured]. The real native-WebRTC-backed binding
 * replaces this @Binds when the SDK decision is made.
 */
@Singleton
class StubMeshConnectionManager @Inject constructor() : MeshConnectionManager {

    // No replay, no buffer: a never-emitting hot flow (collectors simply suspend forever).
    private val _events = MutableSharedFlow<MeshEvent>()
    override val events: SharedFlow<MeshEvent> = _events.asSharedFlow()

    override suspend fun addPeer(userId: String, isInitiator: Boolean): MeshResult = MeshResult.NotConfigured

    override suspend fun removePeer(userId: String) = Unit

    override fun setLocalMute(muted: Boolean) = Unit

    override fun setLocalVideo(on: Boolean) = Unit

    override suspend fun closeAll() = Unit
}
