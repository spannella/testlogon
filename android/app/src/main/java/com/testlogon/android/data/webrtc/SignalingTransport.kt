package com.testlogon.android.data.webrtc

import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-290 — signaling transport seam (SCAFFOLD ONLY — FLAGGED, native WebRTC engine not configured).
 *
 * STOP-AND-FLAG: this transport carries SDP/ICE between the local [PeerConnectionController] and the
 * backend signaling endpoints. The REAL send DTOs + repository ([SignalingRepository] over the verified
 * /broadcast/.../webrtc-offer and /messaging/.../signal endpoints) ARE implemented and testable. The
 * TRANSPORT SEAM itself is FLAGGED because it can only meaningfully connect once the native WebRTC SDK
 * exists to produce/consume SDP/ICE — so [StubSignalingTransport] never connects: it returns
 * [TransportResult.NotConfigured] from every method and NEVER opens a stream, NEVER sends, NEVER emits
 * inbound messages. This mirrors the [com.testlogon.android.data.billing.CardTokenizer] /
 * [com.testlogon.android.data.payouts.KycVerifier] stub-seam pattern.
 *
 * The real transport (a future ticket) will: drive [SignalingRepository.exchangeBroadcastOffer] for the
 * host publish path; for the 1:1 call path send via [SignalingRepository.sendCallSignal] and receive over
 * the shared messaging SSE stream. None of that runs in the stub.
 */
interface SignalingTransport {

    /** Open the signaling channel for [callId]/[selfId]. The stub never connects. */
    suspend fun connect(callId: String, selfId: String): TransportResult<Unit>

    /** Send a local SDP offer. The stub returns NotConfigured (nothing sent). */
    suspend fun sendOffer(offer: SignalingMessage.Offer): TransportResult<Unit>

    /** Deliver a received remote answer to the caller. The stub returns NotConfigured. */
    suspend fun onAnswer(answer: SignalingMessage.Answer): TransportResult<Unit>

    /** Deliver/forward a trickled ICE candidate. The stub returns NotConfigured. */
    suspend fun onIce(ice: SignalingMessage.Ice): TransportResult<Unit>

    /** Close the channel and release resources. Idempotent. The stub is a no-op. */
    fun close()
}

/** Result of a transport op. [NotConfigured] is what the FLAGGED stub always returns. */
sealed interface TransportResult<out T> {
    data class Ok<out T>(val value: T) : TransportResult<T>
    data class Failed(val reason: String) : TransportResult<Nothing>

    /**
     * No real signaling transport is wired (native WebRTC engine FLAGGED). The flow MUST surface a
     * "broadcasting unavailable / not configured" state and MUST NOT connect or send.
     * [StubSignalingTransport] always returns this.
     */
    data object NotConfigured : TransportResult<Nothing>
}

/**
 * AND-290 — default (FLAGGED) transport. NEVER connects, NEVER sends, NEVER emits inbound signaling.
 * Every op returns [TransportResult.NotConfigured]. The real binding replaces this @Binds when the native
 * WebRTC SDK decision is made.
 */
@Singleton
class StubSignalingTransport @Inject constructor() : SignalingTransport {
    override suspend fun connect(callId: String, selfId: String): TransportResult<Unit> =
        TransportResult.NotConfigured

    override suspend fun sendOffer(offer: SignalingMessage.Offer): TransportResult<Unit> =
        TransportResult.NotConfigured

    override suspend fun onAnswer(answer: SignalingMessage.Answer): TransportResult<Unit> =
        TransportResult.NotConfigured

    override suspend fun onIce(ice: SignalingMessage.Ice): TransportResult<Unit> =
        TransportResult.NotConfigured

    override fun close() { /* no-op: nothing was ever opened */ }
}
