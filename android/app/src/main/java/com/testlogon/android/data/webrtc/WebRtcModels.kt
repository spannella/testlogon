package com.testlogon.android.data.webrtc

/**
 * AND-289/290/291 — pure (SDK-free) value types for the WebRTC host-broadcasting seam.
 *
 * These types are deliberately free of any org.webrtc / vendor-SDK types so that the engine seams
 * ([BroadcastPublisher], [PeerConnectionController], [SignalingTransport]) and the real network reads
 * (signaling + TURN/STUN credential fetch) stay JVM-unit-testable and never pull in a native WebRTC
 * dependency. SDP/ICE bodies are carried as opaque strings; timestamps are epoch Long; the ICE
 * credential ttl is a Long of seconds. No android.* types here (JVM-testable on minSdk 24).
 */

/** An SDP session description. [type] is the lowercase libwebrtc value (offer|answer|pranswer). */
data class SdpDescription(val type: SdpType, val sdp: String)

/** SDP type discriminator; serializes lowercase. */
enum class SdpType { OFFER, ANSWER, PRANSWER }

/** A trickled ICE candidate. [sdpMid] may be null on the wire. */
data class IceCandidate(
    val sdpMid: String?,
    val sdpMLineIndex: Int,
    val candidate: String,
)

/**
 * A STUN/TURN ICE server entry. Matches the AND-291 backend `TurnIceServerOut` shape and the
 * AND-289 `RtcConfig.iceServers` element. [username]/[credential] are null for plain STUN entries
 * (only used by the local fallback list — the backend always returns credentialed entries).
 */
data class IceServer(
    val urls: List<String>,
    val username: String? = null,
    val credential: String? = null,
)

/**
 * AND-291 — domain model for a fetched, TTL-bounded set of ICE servers.
 *
 * @param servers           the STUN/TURN entries to feed into the PeerConnection config.
 * @param ttlSeconds        granted TTL in seconds (Long).
 * @param expiresAtEpochMs  authoritative expiry (backend `expires_at` seconds * 1000).
 * @param fetchedAtEpochMs  device epoch millis when the set was obtained.
 */
data class IceServers(
    val servers: List<IceServer>,
    val ttlSeconds: Long,
    val expiresAtEpochMs: Long,
    val fetchedAtEpochMs: Long,
) {
    /** Fresh while at least [skewSeconds] of TTL remains at [nowMs]. */
    fun isFreshAt(nowMs: Long, skewSeconds: Long): Boolean =
        nowMs < expiresAtEpochMs - skewSeconds * 1_000L
}
